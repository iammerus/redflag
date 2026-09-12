use crate::{
    artifacts::{self, ArtifactCoverage, ArtifactFile, ArtifactTarget},
    config::{Config, ScanLimits},
    engine::EngineInfo,
    error::RedflagError,
    exceptions::{self, ArtifactApproval, ExceptionKind, ReviewStatus},
    report::PreparedReport,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
};
use tempfile::NamedTempFile;

const SCHEMA_VERSION: u32 = 5;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    scanner_version: String,
    engine: String,
    detector: EngineInfo,
    config_sha256: String,
    complete: bool,
    findings_count: usize,
    blocking_occurrences_count: usize,
    approval: ArtifactApproval,
    targets: Vec<ArtifactTarget>,
    files: Vec<ArtifactFile>,
    total_bytes: u64,
    private_env: Vec<String>,
    symlinks: String,
    representations: Vec<String>,
    private_decoding: crate::decoding::Coverage,
    archive_inspection: crate::archives::Coverage,
    limits: ScanLimits,
}

/// A failed rescan must not leave an earlier approved manifest available for upload.
/// Stage outside publication inputs and persist only after a complete scan without blockers.
pub(crate) struct ManifestOutput {
    destination: PathBuf,
    staged: NamedTempFile,
}

impl ManifestOutput {
    pub fn prepare(
        path: &Path,
        inputs: &[PathBuf],
        policy_inputs: &[&Path],
    ) -> Result<Self, RedflagError> {
        let name = path.file_name().ok_or_else(|| {
            RedflagError::Config("Choose a manifest filename outside artifact targets".into())
        })?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = fs::canonicalize(parent).map_err(|source| RedflagError::PathIo {
            path: parent.to_path_buf(),
            source,
        })?;
        let destination = parent.join(name);
        for input in policy_inputs {
            if fs::canonicalize(input).is_ok_and(|input| input == destination) {
                return Err(RedflagError::Config("Manifest output must be separate from configuration and exception policy inputs".into()));
            }
        }
        for input in inputs {
            if fs::canonicalize(input).is_ok_and(|root| destination.starts_with(root)) {
                return Err(RedflagError::Config(
                    "Store the manifest outside all artifact targets".into(),
                ));
            }
        }
        match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.is_file() => fs::remove_file(&destination)?,
            Ok(_) => {
                return Err(RedflagError::Config(
                    "Manifest output must be a regular file, not a symlink or directory".into(),
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(RedflagError::PathIo {
                    path: destination,
                    source,
                })
            }
        }
        Ok(Self {
            destination,
            staged: NamedTempFile::new_in(parent)?,
        })
    }

    pub fn write(
        mut self,
        coverage: &ArtifactCoverage,
        config_sha256: String,
        report: &PreparedReport,
    ) -> Result<(), RedflagError> {
        let (findings_count, approval) = report.artifact_approval()?;
        coverage.archive_inspection.validate(&coverage.limits)?;
        coverage
            .private_decoding
            .validate(!coverage.private_env.is_empty(), &coverage.limits)?;
        validate_approval(
            &approval,
            findings_count,
            &coverage.files,
            &coverage.limits,
            Utc::now(),
        )?;
        let manifest = Manifest {
            schema_version: SCHEMA_VERSION,
            scanner_version: env!("CARGO_PKG_VERSION").into(),
            engine: coverage.engine.name.clone(),
            detector: coverage.engine.clone(),
            config_sha256,
            complete: true,
            findings_count,
            blocking_occurrences_count: 0,
            approval,
            targets: coverage.targets.clone(),
            files: coverage.files.clone(),
            total_bytes: coverage.total_bytes,
            private_env: coverage.private_env.clone(),
            symlinks: coverage.symlinks.into(),
            representations: vec![
                coverage.private_value_representation.into(),
                coverage.native_detector_representation.into(),
            ],
            private_decoding: coverage.private_decoding.clone(),
            archive_inspection: coverage.archive_inspection.clone(),
            limits: coverage.limits.clone(),
        };
        serde_json::to_writer_pretty(&mut self.staged, &manifest)?;
        self.staged.write_all(b"\n")?;
        self.staged.flush()?;
        self.staged.as_file().sync_all()?;
        self.staged
            .persist(&self.destination)
            .map_err(|error| RedflagError::PathIo {
                path: self.destination,
                source: error.error,
            })?;
        Ok(())
    }
}

#[derive(Serialize)]
pub(crate) struct Verification {
    pub manifest: PathBuf,
    pub files: usize,
    pub total_bytes: u64,
    pub targets: Vec<ArtifactTarget>,
    pub config_sha256: String,
    pub engine: String,
    pub detector: EngineInfo,
    pub private_env: Vec<String>,
    pub findings_count: usize,
    pub accepted_occurrences_count: usize,
    pub exception_policy: exceptions::Audit,
    pub private_decoding: crate::decoding::Coverage,
    pub archive_inspection: crate::archives::Coverage,
}

pub(crate) fn verify(path: &Path, overrides: &[PathBuf]) -> Result<Verification, RedflagError> {
    let bytes = artifacts::read_file(
        path,
        &ScanLimits {
            max_file_bytes: MAX_MANIFEST_BYTES,
            ..ScanLimits::default()
        },
    )?;
    let mut manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| {
        RedflagError::Config(
            "Manifest is not a supported schema 5 scan; scan the publication inputs again".into(),
        )
    })?;
    if manifest.schema_version != SCHEMA_VERSION
        || manifest.scanner_version != env!("CARGO_PKG_VERSION")
        || manifest.engine != manifest.detector.name
        || !manifest.detector.supported()
        || (manifest.detector.name == "redflag-native"
            && manifest.detector.config_sha256 != manifest.config_sha256)
        || !manifest.complete
        || manifest.blocking_occurrences_count != 0
        || manifest.symlinks != "reject"
        || manifest.total_bytes == 0
        || manifest.files.is_empty()
        || manifest.representations
            != [
                "exact_raw_bytes",
                "lines_of_utf8_with_invalid_sequences_replaced",
            ]
        || !valid_digest(&manifest.config_sha256)
    {
        return Err(RedflagError::Config(
            "Manifest is not a supported complete scan without blockers. Scan the publication inputs again."
                .into(),
        ));
    }
    let mut config = Config {
        limits: manifest.limits.clone(),
        ..Config::default()
    };
    config.validate()?;
    manifest.archive_inspection.validate(&manifest.limits)?;
    manifest
        .private_decoding
        .validate(!manifest.private_env.is_empty(), &manifest.limits)?;
    validate_approval(
        &manifest.approval,
        manifest.findings_count,
        &manifest.files,
        &manifest.limits,
        Utc::now(),
    )?;
    if manifest.targets.is_empty()
        || manifest.targets.len() > manifest.files.len()
        || manifest.files.len() > manifest.limits.max_files
    {
        return Err(RedflagError::Config("Manifest inventory is invalid".into()));
    }
    for file in &manifest.files {
        let Some(target) = manifest.targets.get(file.target) else {
            return Err(RedflagError::Config(
                "Manifest file references an unknown target".into(),
            ));
        };
        let valid_path = match target.kind {
            artifacts::TargetKind::File => file.path == Path::new("."),
            artifacts::TargetKind::Directory => {
                !file.path.as_os_str().is_empty()
                    && file
                        .path
                        .components()
                        .all(|part| matches!(part, Component::Normal(_)))
            }
        };
        if !valid_path
            || !target.root.is_absolute()
            || !valid_digest(&file.sha256)
            || file.bytes > manifest.limits.max_file_bytes
        {
            return Err(RedflagError::Config(
                "Manifest contains an invalid path, size or digest".into(),
            ));
        }
    }
    if !overrides.is_empty() {
        if overrides.len() != manifest.targets.len() {
            return Err(RedflagError::Config(
                "Repeat --target once per manifest target, in the original selection order".into(),
            ));
        }
        // Collection enforces the same symlink, file-type and nonempty policies.
        let selected = artifacts::ArtifactSet::collect(overrides, &manifest.limits)?;
        if selected
            .targets
            .iter()
            .zip(&manifest.targets)
            .any(|(current, original)| current.kind != original.kind)
        {
            return Err(RedflagError::Config("Replacement artifact targets must retain each original target's file or directory kind".into()));
        }
        manifest.targets = selected.targets;
    }
    let total_bytes =
        artifacts::verify_inventory(&manifest.targets, &manifest.files, &manifest.limits)?;
    if total_bytes != manifest.total_bytes {
        return Err(RedflagError::Config(
            "Manifest total does not match its files".into(),
        ));
    }
    // Inventory verification may take time. Approval must still be active when
    // verification finishes, not just when it began.
    validate_approval(
        &manifest.approval,
        manifest.findings_count,
        &manifest.files,
        &manifest.limits,
        Utc::now(),
    )?;
    Ok(Verification {
        manifest: fs::canonicalize(path)?,
        files: manifest.files.len(),
        total_bytes,
        targets: manifest.targets,
        config_sha256: manifest.config_sha256,
        engine: manifest.engine,
        detector: manifest.detector,
        private_env: manifest.private_env,
        findings_count: manifest.findings_count,
        accepted_occurrences_count: manifest.approval.occurrences.len(),
        exception_policy: manifest.approval.policy,
        private_decoding: manifest.private_decoding,
        archive_inspection: manifest.archive_inspection,
    })
}

fn validate_approval(
    approval: &ArtifactApproval,
    findings_count: usize,
    files: &[ArtifactFile],
    limits: &ScanLimits,
    now: DateTime<Utc>,
) -> Result<(), RedflagError> {
    let policy = &approval.policy;
    let count = approval.occurrences.len();
    let invalid = || {
        RedflagError::Config("Manifest does not contain a consistent artifact review; scan the publication inputs again".into())
    };
    if policy.mode != "artifacts"
        || policy.entry_count > exceptions::MAX_ENTRIES
        || policy.matched_entries != count
        || policy.accepted_occurrences != count
        || policy.entry_count < count
        || policy.unmatched_entries != policy.entry_count - count
        || policy.expired_entries > policy.unmatched_entries
        || policy.rejected_private_occurrences != 0
        || findings_count > limits.max_findings
        || findings_count < count
        || (findings_count > 0 && count == 0)
        || policy
            .sha256
            .as_ref()
            .is_some_and(|hash| !valid_digest(hash))
        || (policy.sha256.is_none() && policy.entry_count != 0)
        || policy.origin.trim().is_empty()
    {
        return Err(invalid());
    }
    let evaluated = DateTime::parse_from_rfc3339(&policy.evaluated_at)
        .map_err(|_| invalid())?
        .with_timezone(&Utc);
    if evaluated > now {
        return Err(invalid());
    }
    if count == 0 {
        return Ok(());
    }
    let inventory: BTreeMap<_, _> = files
        .iter()
        .map(|file| ((file.target, file.path.as_path()), file.sha256.as_str()))
        .collect();
    let mut ids = BTreeSet::new();
    for accepted in &approval.occurrences {
        if !exceptions::valid_occurrence_id(&accepted.occurrence_id)
            || !ids.insert(&accepted.occurrence_id)
            || accepted.review.status != ReviewStatus::Accepted
            || accepted.review.kind != ExceptionKind::FalsePositive
            || inventory
                .get(&(accepted.target, accepted.path.as_path()))
                .copied()
                != Some(accepted.file_sha256.as_str())
        {
            return Err(invalid());
        }
        let expires = exceptions::validate_review_fields(
            &accepted.review.reason,
            &accepted.review.reviewed_by,
            &accepted.review.expires_at,
        )?;
        if expires <= evaluated || expires <= now {
            return Err(RedflagError::Config("An artifact review in the manifest has expired; review and rescan before publication".into()));
        }
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn artifact_approval_expires_at_the_exact_boundary() {
        let now = DateTime::parse_from_rfc3339("2026-09-12T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let file = ArtifactFile {
            target: 0,
            path: "bundle.js".into(),
            bytes: 10,
            sha256: "b".repeat(64),
        };
        let approval = ArtifactApproval {
            policy: exceptions::Audit {
                mode: "artifacts".into(),
                origin: "fixture".into(),
                sha256: Some("a".repeat(64)),
                evaluated_at: now.to_rfc3339(),
                entry_count: 1,
                matched_entries: 1,
                unmatched_entries: 0,
                expired_entries: 0,
                accepted_occurrences: 1,
                rejected_private_occurrences: 0,
            },
            occurrences: vec![exceptions::AcceptedArtifact {
                occurrence_id: format!("rf-occurrence-v1:{}", "c".repeat(64)),
                target: 0,
                path: file.path.clone(),
                file_sha256: file.sha256.clone(),
                review: exceptions::Review {
                    status: ReviewStatus::Accepted,
                    kind: ExceptionKind::FalsePositive,
                    reason: "Reviewed fixture".into(),
                    reviewed_by: "reviewer".into(),
                    expires_at: "2026-09-12T12:01:00Z".into(),
                },
            }],
        };
        let files = vec![file];
        assert!(validate_approval(
            &approval,
            1,
            &files,
            &ScanLimits::default(),
            now + chrono::Duration::seconds(59)
        )
        .is_ok());
        assert!(validate_approval(
            &approval,
            1,
            &files,
            &ScanLimits::default(),
            now + chrono::Duration::seconds(60)
        )
        .is_err());
    }
}
