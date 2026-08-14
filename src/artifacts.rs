use crate::{
    config::ScanLimits,
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
    pub targets: Vec<ArtifactTarget>,
    pub files: Vec<ArtifactFile>,
    pub total_bytes: u64,
    pub private_env: Vec<String>,
    pub symlinks: &'static str,
    pub private_value_representation: &'static str,
    pub native_detector_representation: &'static str,
    pub limits: ScanLimits,
}

pub(crate) struct ArtifactSet {
    pub targets: Vec<ArtifactTarget>,
    pub(crate) files: Vec<(usize, PathBuf)>,
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
        handler: &mut H,
    ) -> Result<ArtifactCoverage, RedflagError> {
        let mut coverage = ArtifactCoverage {
            targets: self.targets,
            files: Vec::new(),
            total_bytes: 0,
            private_env: protected.names().to_vec(),
            symlinks: "reject",
            private_value_representation: "exact_raw_bytes",
            native_detector_representation: "lines_of_utf8_with_invalid_sequences_replaced",
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
            protected.scan(&path, &bytes, handler)?;
            for (index, line) in bytes.split(|&byte| byte == b'\n').enumerate() {
                scanner.scan_artifact_line(
                    &path,
                    index + 1,
                    line.strip_suffix(b"\r").unwrap_or(line),
                    handler,
                )?;
            }
            coverage.files.push(ArtifactFile {
                target,
                path: relative,
                bytes: bytes.len() as u64,
                sha256: digest(&bytes),
            });
        }
        // Detect inventory or content changes during inspection before declaring
        // completeness. Publication still needs its own verification afterwards.
        verify_inventory(&coverage.targets, &coverage.files, &coverage.limits)?;
        Ok(coverage)
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
