use crate::{
    config::ScanLimits,
    engine::{EngineInfo, GeneralEngine},
    error::RedflagError,
    protected_values::ProtectedValues,
    scanner::{FindingHandler, Scanner},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactTarget {
    pub root: PathBuf,
    pub kind: TargetKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactFile {
    pub target: usize,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Serialize)]
pub(crate) struct ArtifactCoverage {
    pub engine: EngineInfo,
    pub targets: Vec<ArtifactTarget>,
    pub files: Vec<ArtifactFile>,
    pub total_bytes: u64,
    pub private_env: Vec<String>,
    pub symlinks: &'static str,
    pub private_value_representation: &'static str,
    pub native_detector_representation: &'static str,
    pub private_decoding: crate::decoding::Coverage,
    pub archive_inspection: crate::archives::Coverage,
    pub limits: ScanLimits,
}

pub(crate) struct ArtifactSet {
    pub targets: Vec<ArtifactTarget>,
    pub(crate) files: Vec<(usize, PathBuf)>,
}

impl crate::report::ReportCoverage for ArtifactCoverage {
    fn summary_facts(&self) -> Vec<(&'static str, String)> {
        let mut facts = vec![
            ("Targets", self.targets.len().to_string()),
            ("Inspected files", self.files.len().to_string()),
            ("Inspected bytes", self.total_bytes.to_string()),
            (
                "Inspected archives",
                self.archive_inspection.archives.to_string(),
            ),
            (
                "Archive members",
                self.archive_inspection.members.to_string(),
            ),
            (
                "Expanded archive bytes",
                self.archive_inspection.expanded_bytes.to_string(),
            ),
            ("Declared private variables", self.private_env.join(", ")),
            (
                "Decoded private-value candidates",
                self.private_decoding.candidates.to_string(),
            ),
            (
                "Decoded bytes",
                self.private_decoding.decoded_bytes.to_string(),
            ),
            (
                "Engine",
                format!("{} {}", self.engine.name, self.engine.version),
            ),
        ];
        for (index, target) in self.targets.iter().take(10).enumerate() {
            facts.push(("Target", format!("{index}: {}", target.root.display())));
        }
        if self.targets.len() > 10 {
            facts.push((
                "Additional targets",
                format!(
                    "{}; use --format json for every root",
                    self.targets.len() - 10
                ),
            ));
        }
        facts
    }
}

impl ArtifactSet {
    pub fn collect(paths: &[PathBuf], limits: &ScanLimits) -> Result<Self, RedflagError> {
        if paths.is_empty() {
            return Err(RedflagError::Config(
                "Select at least one artifact file or directory".into(),
            ));
        }
        let mut targets: Vec<ArtifactTarget> = Vec::new();
        let mut files = Vec::new();
        let mut total = 0u64;
        for path in paths {
            let meta = metadata(path)?;
            let root = fs::canonicalize(path).map_err(|source| RedflagError::PathIo {
                path: path.clone(),
                source,
            })?;
            if targets
                .iter()
                .any(|target| root.starts_with(&target.root) || target.root.starts_with(&root))
            {
                return Err(RedflagError::Config(format!(
                    "Artifact targets overlap at {}. Select each file once.",
                    path.display()
                )));
            }
            let kind = if meta.is_dir() {
                TargetKind::Directory
            } else {
                TargetKind::File
            };
            let index = targets.len();
            let mut target_bytes = 0u64;
            for entry in WalkDir::new(&root).follow_links(false).sort_by_file_name() {
                let entry = entry?;
                let meta = metadata(entry.path())?;
                if meta.is_dir() {
                    continue;
                }
                if meta.len() > limits.max_file_bytes {
                    return Err(RedflagError::Incomplete(format!(
                        "{} exceeds limits.max_file_bytes ({})",
                        entry.path().display(),
                        limits.max_file_bytes
                    )));
                }
                target_bytes = target_bytes.checked_add(meta.len()).ok_or_else(|| {
                    RedflagError::Incomplete("Artifact byte count overflow".into())
                })?;
                total = total.checked_add(meta.len()).ok_or_else(|| {
                    RedflagError::Incomplete("Artifact byte count overflow".into())
                })?;
                if total > limits.max_total_bytes {
                    return Err(RedflagError::Incomplete(format!(
                        "Artifact bytes exceed limits.max_total_bytes ({})",
                        limits.max_total_bytes
                    )));
                }
                if files.len() >= limits.max_files {
                    return Err(RedflagError::Incomplete(format!(
                        "Artifact files exceed limits.max_files ({})",
                        limits.max_files
                    )));
                }
                let relative = if kind == TargetKind::File {
                    PathBuf::from(".")
                } else {
                    entry
                        .path()
                        .strip_prefix(&root)
                        .expect("walk stays under root")
                        .to_path_buf()
                };
                files.push((index, relative));
            }
            if target_bytes == 0 {
                return Err(RedflagError::Incomplete(format!(
                    "Artifact target {} is empty. Build the output before scanning.",
                    path.display()
                )));
            }
            targets.push(ArtifactTarget { root, kind });
        }
        Ok(Self { targets, files })
    }

    pub fn scan<H: FindingHandler>(
        self,
        scanner: &Scanner,
        protected: &ProtectedValues,
        mut engine: GeneralEngine,
        handler: &mut H,
    ) -> Result<ArtifactCoverage, RedflagError> {
        let mut coverage = ArtifactCoverage {
            engine: engine.info().clone(),
            targets: self.targets,
            files: Vec::new(),
            total_bytes: 0,
            private_env: protected.names().to_vec(),
            symlinks: "reject",
            private_value_representation: "exact_raw_bytes",
            native_detector_representation: "lines_of_utf8_with_invalid_sequences_replaced",
            private_decoding: crate::decoding::Coverage::new(!protected.names().is_empty()),
            archive_inspection: crate::archives::Coverage::new(),
            limits: scanner.limits().clone(),
        };
        for (target, relative) in self.files {
            let path = file_path(&coverage.targets[target], &relative);
            let bytes = read_file(&path, &coverage.limits)?;
            coverage.total_bytes = coverage
                .total_bytes
                .checked_add(bytes.len() as u64)
                .filter(|&total| total <= coverage.limits.max_total_bytes)
                .ok_or_else(|| {
                    RedflagError::Incomplete(
                        "Artifact bytes exceed limits.max_total_bytes while reading".into(),
                    )
                })?;
            let mut inspect = |bytes: &[u8], members: &[crate::archives::Member]| {
                let mut located = MemberHandler {
                    root: &path,
                    members,
                    protected,
                    handler,
                };
                protected.scan(&path, bytes, &mut located)?;
                crate::decoding::scan(
                    &path,
                    bytes,
                    protected,
                    &coverage.limits,
                    &mut coverage.private_decoding,
                    &mut located,
                )?;
                engine.add_archive(&path, bytes, members)?;
                let code_path = members
                    .last()
                    .map(|member| Path::new(&member.path))
                    .unwrap_or(&path);
                for (index, line) in bytes.split(|&byte| byte == b'\n').enumerate() {
                    scanner.scan_artifact_line(
                        code_path,
                        index + 1,
                        line.strip_suffix(b"\r").unwrap_or(line),
                        &mut located,
                    )?;
                }
                Ok(())
            };
            inspect(&bytes, &[])?;
            crate::archives::inspect(
                &path,
                &bytes,
                &coverage.limits,
                &mut coverage.archive_inspection,
                &mut inspect,
            )?;
            coverage.files.push(ArtifactFile {
                target,
                path: relative,
                bytes: bytes.len() as u64,
                sha256: digest(&bytes),
            });
        }
        engine.finish(&mut ArchiveRedaction { protected, handler })?;
        // Detect inventory or content changes during inspection before declaring
        // completeness. Publication still needs its own verification afterwards.
        verify_inventory(&coverage.targets, &coverage.files, &coverage.limits)?;
        Ok(coverage)
    }
}

struct MemberHandler<'a, H> {
    root: &'a Path,
    members: &'a [crate::archives::Member],
    protected: &'a ProtectedValues,
    handler: &'a mut H,
}
impl<H: FindingHandler> FindingHandler for MemberHandler<'_, H> {
    fn handle(&mut self, mut finding: crate::scanner::Finding) -> Result<(), RedflagError> {
        finding.file = self.root.to_path_buf();
        finding.archive = self.members.to_vec();
        ArchiveRedaction {
            protected: self.protected,
            handler: self.handler,
        }
        .handle(finding)
    }
}

struct ArchiveRedaction<'a, H> {
    protected: &'a ProtectedValues,
    handler: &'a mut H,
}
impl<H: FindingHandler> FindingHandler for ArchiveRedaction<'_, H> {
    fn handle(&mut self, mut finding: crate::scanner::Finding) -> Result<(), RedflagError> {
        for member in &mut finding.archive {
            if self.protected.contains(&member.path) {
                member.path = "[REDACTED PRIVATE VALUE]".into();
            }
        }
        self.handler.handle(finding)
    }
}

pub(crate) fn verify_inventory(
    targets: &[ArtifactTarget],
    expected: &[ArtifactFile],
    limits: &ScanLimits,
) -> Result<u64, RedflagError> {
    let paths: Vec<_> = targets.iter().map(|target| target.root.clone()).collect();
    let current = ArtifactSet::collect(&paths, limits)?;
    if current.targets != targets
        || current.files.len() != expected.len()
        || current
            .files
            .iter()
            .zip(expected)
            .any(|((target, path), file)| *target != file.target || path != &file.path)
    {
        return Err(RedflagError::Incomplete(
            "Artifact inventory changed. Scan the exact publication inputs again.".into(),
        ));
    }
    let mut total = 0u64;
    for file in expected {
        let path = file_path(&targets[file.target], &file.path);
        let bytes = read_file(&path, limits)?;
        if bytes.len() as u64 != file.bytes || digest(&bytes) != file.sha256 {
            return Err(RedflagError::Incomplete(format!(
                "Artifact {} changed. Scan the publication inputs again.",
                path.display()
            )));
        }
        total = total
            .checked_add(file.bytes)
            .filter(|&total| total <= limits.max_total_bytes)
            .ok_or_else(|| {
                RedflagError::Incomplete(
                    "Artifact bytes exceed limits.max_total_bytes during verification".into(),
                )
            })?;
    }
    Ok(total)
}

fn metadata(path: &Path) -> Result<fs::Metadata, RedflagError> {
    let meta = fs::symlink_metadata(path).map_err(|source| RedflagError::PathIo {
        path: path.to_path_buf(),
        source,
    })?;
    if !meta.is_file() && !meta.is_dir() {
        return Err(RedflagError::Incomplete(format!(
            "Artifact {} is a symlink or special file. Select regular files and directories.",
            path.display()
        )));
    }
    Ok(meta)
}

pub(crate) fn read_file(path: &Path, limits: &ScanLimits) -> Result<Vec<u8>, RedflagError> {
    let meta = metadata(path)?;
    if !meta.is_file() || meta.len() > limits.max_file_bytes {
        return Err(RedflagError::Incomplete(format!(
            "Artifact {} is not a regular file within limits.max_file_bytes",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| {
            file.take(limits.max_file_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(|source| RedflagError::PathIo {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > limits.max_file_bytes {
        return Err(RedflagError::Incomplete(format!(
            "Artifact {} grew beyond limits.max_file_bytes while reading",
            path.display()
        )));
    }
    Ok(bytes)
}

pub(crate) fn file_path(target: &ArtifactTarget, relative: &Path) -> PathBuf {
    match target.kind {
        TargetKind::File => target.root.clone(),
        TargetKind::Directory => target.root.join(relative),
    }
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
