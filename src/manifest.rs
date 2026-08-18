use crate::{
    artifacts::{self, ArtifactCoverage, ArtifactFile, ArtifactTarget},
    config::{Config, ScanLimits},
    engine::EngineInfo,
    error::RedflagError,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
};
use tempfile::NamedTempFile;

const SCHEMA_VERSION: u32 = 2;
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
    targets: Vec<ArtifactTarget>,
    files: Vec<ArtifactFile>,
    total_bytes: u64,
    private_env: Vec<String>,
    symlinks: String,
    representations: Vec<String>,
    limits: ScanLimits,
}

/// A failed rescan must not leave an earlier clean manifest available for upload.
/// Stage outside publication inputs and persist only after a complete clean scan.
pub(crate) struct ManifestOutput {
    destination: PathBuf,
    staged: NamedTempFile,
}

impl ManifestOutput {
    pub fn prepare(path: &Path, inputs: &[PathBuf]) -> Result<Self, RedflagError> {
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
    ) -> Result<(), RedflagError> {
        let manifest = Manifest {
            schema_version: SCHEMA_VERSION,
            scanner_version: env!("CARGO_PKG_VERSION").into(),
            engine: coverage.engine.name.clone(),
            detector: coverage.engine.clone(),
            config_sha256,
            complete: true,
            findings_count: 0,
            targets: coverage.targets.clone(),
            files: coverage.files.clone(),
            total_bytes: coverage.total_bytes,
            private_env: coverage.private_env.clone(),
            symlinks: coverage.symlinks.into(),
            representations: vec![
                coverage.private_value_representation.into(),
                coverage.native_detector_representation.into(),
            ],
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
}

pub(crate) fn verify(path: &Path, overrides: &[PathBuf]) -> Result<Verification, RedflagError> {
    let bytes = artifacts::read_file(
        path,
        &ScanLimits {
            max_file_bytes: MAX_MANIFEST_BYTES,
            ..ScanLimits::default()
        },
    )?;
    let mut manifest: Manifest = serde_json::from_slice(&bytes)?;
    if manifest.schema_version != SCHEMA_VERSION
        || manifest.scanner_version != env!("CARGO_PKG_VERSION")
        || manifest.engine != manifest.detector.name
        || !manifest.detector.supported()
        || (manifest.detector.name == "redflag-native"
            && manifest.detector.config_sha256 != manifest.config_sha256)
        || !manifest.complete
        || manifest.findings_count != 0
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
            "Manifest is not a supported complete clean scan. Scan the publication inputs again."
                .into(),
        ));
    }
    let mut config = Config {
        limits: manifest.limits.clone(),
        ..Config::default()
    };
    config.validate()?;
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
    Ok(Verification {
        manifest: fs::canonicalize(path)?,
        files: manifest.files.len(),
        total_bytes,
        targets: manifest.targets,
        config_sha256: manifest.config_sha256,
        engine: manifest.engine,
        detector: manifest.detector,
        private_env: manifest.private_env,
    })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
