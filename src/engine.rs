//! Pinned offline detector, isolated from user environment and file-selection policy.
use crate::{
    artifacts::digest,
    config::Severity,
    error::RedflagError,
    scanner::{CommitMetadata, Finding, FindingHandler, FindingSpan},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const PINS: &str = include_str!("../engines/pins.json");
const POLICY: &str = include_str!("../engines/betterleaks.toml");
const REPORT: &str = include_str!("../engines/report.tmpl");
const NORMALIZATION: &str = include_str!("../engines/normalization.json");
const WINDOW: usize = 64 * 1024;
const STRIDE: usize = WINDOW / 2;
const MAX_REPORT: u64 = 64 * 1024 * 1024;
const MAX_LOG: u64 = 4 * 1024 * 1024;
const PREFIX: &[u8] = b"\n";

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EngineChoice {
    Betterleaks,
    Native,
}

pub(crate) enum GeneralEngine {
    Native(EngineInfo),
    Betterleaks(Box<Betterleaks>),
}

impl GeneralEngine {
    pub fn prepare(
        choice: EngineChoice,
        path: Option<PathBuf>,
        timeout: u64,
        config_digest: String,
    ) -> Result<Self, RedflagError> {
        match choice {
            EngineChoice::Native if path.is_some() => Err(RedflagError::Config(
                "--betterleaks-path requires --engine betterleaks".into(),
            )),
            EngineChoice::Native => Ok(Self::Native(EngineInfo::native(config_digest))),
            EngineChoice::Betterleaks => Betterleaks::prepare(path, timeout)
                .map(|engine| Self::Betterleaks(Box::new(engine))),
        }
    }
    pub fn info(&self) -> &EngineInfo {
        match self {
            Self::Native(info) => info,
            Self::Betterleaks(engine) => &engine.info,
        }
    }
    pub fn add(&mut self, path: &Path, bytes: &[u8]) -> Result<(), RedflagError> {
        self.add_snapshot(path, bytes, None)
    }
    pub fn add_snapshot(
        &mut self,
        path: &Path,
        bytes: &[u8],
        commit: Option<CommitMetadata>,
    ) -> Result<(), RedflagError> {
        match self {
            Self::Native(_) => Ok(()),
            Self::Betterleaks(engine) => engine.add(path, bytes, commit),
        }
    }
    pub fn finish<H: FindingHandler>(self, handler: &mut H) -> Result<(), RedflagError> {
        match self {
            Self::Native(_) => Ok(()),
            Self::Betterleaks(engine) => engine.finish(handler),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EngineInfo {
    pub name: String,
    pub version: String,
    pub binary_sha256: Option<String>,
    pub config_sha256: String,
    pub adapter_sha256: Option<String>,
    pub validation: bool,
    pub window_bytes: usize,
    pub overlap_bytes: usize,
}

impl EngineInfo {
    pub fn native(config_sha256: String) -> Self {
        Self {
            name: "redflag-native".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            binary_sha256: None,
            config_sha256,
            adapter_sha256: None,
            validation: false,
            window_bytes: 0,
            overlap_bytes: 0,
        }
    }

    pub fn supported(&self) -> bool {
        if self.validation {
            return false;
        }
        if self.name == "redflag-native" {
            return self.version == env!("CARGO_PKG_VERSION")
                && self.binary_sha256.is_none()
                && self.adapter_sha256.is_none()
                && self.window_bytes == 0
                && self.overlap_bytes == 0;
        }
        let Ok(pins) = serde_json::from_str::<Pins>(PINS) else {
            return false;
        };
        self.name == "betterleaks"
            && self.version == pins.version
            && self.config_sha256 == digest(POLICY.as_bytes())
            && self.adapter_sha256.as_deref() == Some(adapter_digest().as_str())
            && self.window_bytes == WINDOW
            && self.overlap_bytes == WINDOW - STRIDE
            && pins
                .assets
                .values()
                .any(|pin| Some(&pin.binary_sha256) == self.binary_sha256.as_ref())
    }
}

#[derive(Deserialize)]
struct Pins {
    version: String,
    assets: HashMap<String, Pin>,
}
#[derive(Deserialize)]
struct Pin {
    binary_sha256: String,
}

struct Window {
    input: usize,
    line: usize,
    column: usize,
    len: usize,
    last_line: usize,
    last_column: usize,
    final_window: bool,
    first_window: bool,
}

struct Input {
    path: PathBuf,
    commit: Option<CommitMetadata>,
    code: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Normalization {
    schema_version: u32,
    code_extensions: Vec<String>,
    example_suffixes: Vec<String>,
    generic_password_placeholders: Vec<String>,
}

impl Normalization {
    fn is_code(&self, path: &Path) -> bool {
        let extension = |path: &Path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("")
                .to_ascii_lowercase()
        };
        let mut ext = extension(path);
        if self.example_suffixes.contains(&ext) {
            if let Some(stem) = path.file_stem() {
                ext = extension(Path::new(stem));
            }
        }
        self.code_extensions.contains(&ext)
    }
}

fn adapter_digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(REPORT.as_bytes());
    hasher.update([0]);
    hasher.update(NORMALIZATION.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Snapshot windows stay below the upstream reader's chunk size. Each byte is
/// covered with 32 KiB of overlap; candidates reaching an inspection edge fail.
pub(crate) struct Betterleaks {
    binary: PathBuf,
    workspace: TempDir,
    windows: Vec<Window>,
    inputs: Vec<Input>,
    staged_bytes: u64,
    timeout: Duration,
    normalization: Normalization,
    password_placeholders: BTreeSet<String>,
    pub info: EngineInfo,
}

impl Betterleaks {
    pub fn prepare(explicit: Option<PathBuf>, timeout_seconds: u64) -> Result<Self, RedflagError> {
        if timeout_seconds == 0 {
            return Err(RedflagError::Config(
                "Engine timeout must be positive".into(),
            ));
        }
        let normalization: Normalization = serde_json::from_str(NORMALIZATION)?;
        if normalization.schema_version != 1 {
            return Err(RedflagError::Config(
                "Unsupported built-in engine normalization policy".into(),
            ));
        }
        let password_placeholders = normalization
            .generic_password_placeholders
            .iter()
            .map(|value| digest(value.as_bytes()))
            .collect();
        let pins: Pins = serde_json::from_str(PINS)?;
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            other => other,
        };
        let arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "x64",
            other => other,
        };
        let pin = pins.assets.get(&format!("{os}_{arch}")).ok_or_else(|| RedflagError::Config("No pinned Betterleaks build supports this platform. Use --engine native for the compatibility detector.".into()))?;
        let name = if cfg!(windows) {
            "betterleaks.exe"
        } else {
            "betterleaks"
        };
        let binary = explicit
            .or_else(|| std::env::var_os("REDFLAG_BETTERLEAKS_PATH").map(PathBuf::from))
            .unwrap_or(
                std::env::current_exe()?
                    .parent()
                    .expect("executable parent")
                    .join("engines")
                    .join(name),
            );
        let binary = fs::canonicalize(&binary).map_err(|_| RedflagError::Config(format!("Pinned Betterleaks is unavailable at {}. Run scripts/install_engine.py --directory <redflag-binary-directory>/engines, or supply --betterleaks-path.", binary.display())))?;
        // Verify before executing: a matching version string alone is insufficient.
        let metadata = fs::metadata(&binary)?;
        if !metadata.is_file() || metadata.len() > 256 * 1024 * 1024 {
            return Err(RedflagError::Config(
                "Betterleaks executable is not a regular file within the binary size limit".into(),
            ));
        }
        let mut hash = Sha256::new();
        std::io::copy(&mut File::open(&binary)?, &mut hash)?;
        let actual = format!("{:x}", hash.finalize());
        if actual != pin.binary_sha256 {
            return Err(RedflagError::Config("Betterleaks executable checksum differs from the reviewed pin. Reinstall the pinned engine.".into()));
        }
        let workspace = tempfile::tempdir()?;
        fs::create_dir(workspace.path().join("inputs"))?;
        fs::write(workspace.path().join("policy.toml"), POLICY)?;
        fs::write(workspace.path().join("report.tmpl"), REPORT)?;
        fs::write(workspace.path().join("empty.ignore"), "")?;
        Ok(Self {
            binary,
            workspace,
            windows: Vec::new(),
            inputs: Vec::new(),
            staged_bytes: 0,
            timeout: Duration::from_secs(timeout_seconds),
            normalization,
            password_placeholders,
            info: EngineInfo {
                name: "betterleaks".into(),
                version: pins.version,
                binary_sha256: Some(actual),
                config_sha256: digest(POLICY.as_bytes()),
                adapter_sha256: Some(adapter_digest()),
                validation: false,
                window_bytes: WINDOW,
                overlap_bytes: WINDOW - STRIDE,
            },
        })
    }

    fn add(
        &mut self,
        original: &Path,
        bytes: &[u8],
        commit: Option<CommitMetadata>,
    ) -> Result<(), RedflagError> {
        let input = self.inputs.len();
        let code = self.normalization.is_code(original);
        self.inputs.push(Input {
            path: original.to_path_buf(),
            commit,
            code,
        });
        let mut line = 1usize;
        let mut column = 1usize;
        let mut previous = 0;
        for start in (0..bytes.len()).step_by(STRIDE) {
            let advanced = &bytes[previous..start];
            advance(&mut line, &mut column, advanced);
            previous = start;
            let end = (start + WINDOW).min(bytes.len());
            let content = &bytes[start..end];
            let path = self
                .workspace
                .path()
                .join("inputs")
                .join(window_name(self.windows.len(), code));
            let mut file = File::create(path)?;
            file.write_all(PREFIX)?;
            file.write_all(content)?;
            self.staged_bytes += (PREFIX.len() + content.len()) as u64;
            let mut last_line = 2;
            let mut last_column = 1;
            advance(&mut last_line, &mut last_column, content);
            self.windows.push(Window {
                input,
                line,
                column,
                len: content.len(),
                last_line,
                last_column,
                final_window: end == bytes.len(),
                first_window: start == 0,
            });
            if end == bytes.len() {
                break;
            }
        }
        Ok(())
    }

    pub fn finish<H: FindingHandler>(self, handler: &mut H) -> Result<(), RedflagError> {
        if self.windows.is_empty() {
            return Ok(());
        }
        let root = self.workspace.path();
        let report_path = root.join("findings.jsonl");
        let log_path = root.join("engine.log");
        let mut command = Command::new(&self.binary);
        command
            .env_clear()
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(File::create(&report_path)?)
            .stderr(File::create(&log_path)?)
            .env("GOMAXPROCS", "2")
            .env("GOMEMLIMIT", "256MiB");
        // Windows process startup needs these OS locations; no credential-bearing
        // variables, home, proxy, engine config or validation variables are passed.
        if cfg!(windows) {
            for name in ["SystemRoot", "WINDIR"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
        }
        command.args([
            "dir",
            "inputs",
            "--config",
            "policy.toml",
            "--report-template",
            "report.tmpl",
            "--report-format",
            "template",
            "--report-path",
            "-",
            "--gitleaks-ignore-path",
            "empty.ignore",
            "--ignore-gitleaks-allow",
            "--no-banner",
            "--no-color",
            // The metadata-only template hashes captures in child memory. Raw
            // captures and stderr never enter Redflag's public output.
            "--redact=0",
            "--validation=false",
            "--max-archive-depth=0",
            "--max-decode-depth=0",
            "--max-target-megabytes=0",
            "--log-level=info",
            "--exit-code=10",
        ]);
        let mut child = command
            .spawn()
            .map_err(|_| RedflagError::Incomplete("Could not start pinned Betterleaks".into()))?;
        let started = Instant::now();
        let status = loop {
            let oversized = fs::metadata(&report_path)
                .map(|m| m.len() > MAX_REPORT)
                .unwrap_or(true)
                || fs::metadata(&log_path)
                    .map(|m| m.len() > MAX_LOG)
                    .unwrap_or(true);
            if oversized || started.elapsed() > self.timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RedflagError::Incomplete("Betterleaks exceeded its time or output budget. Increase the reviewed scan scope budget or split the publication targets.".into()));
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RedflagError::Incomplete(
                        "Could not observe Betterleaks completion".into(),
                    ));
                }
            }
        };
        if fs::metadata(&log_path)?.len() > MAX_LOG {
            return Err(protocol_error());
        }
        let logs = fs::read_to_string(&log_path)?;
        validate_completion(status.code(), &logs, self.staged_bytes)?;
        let file = File::open(report_path)?;
        if file.metadata()?.len() > MAX_REPORT {
            return Err(protocol_error());
        }
        let mut keys = BTreeSet::new();
        let mut reader = BufReader::new(file);
        let mut record = String::new();
        let mut raw_count = 0;
        loop {
            record.clear();
            if reader.by_ref().take(16 * 1024 + 1).read_line(&mut record)? == 0 {
                break;
            }
            if record.len() > 16 * 1024 {
                return Err(protocol_error());
            }
            if record.trim().is_empty() {
                continue;
            }
            let found: EngineFinding =
                serde_json::from_str(&record).map_err(|_| protocol_error())?;
            raw_count += 1;
            let placeholder = found.rule_id == "generic-password"
                && self.password_placeholders.contains(&found.secret_digest);
            // Validate locations and completeness even for a reviewed placeholder.
            let located = self.locate(found)?;
            if !placeholder {
                for key in located {
                    keys.insert(key);
                }
            }
        }
        if (status.code() == Some(10)) != (raw_count > 0) {
            return Err(protocol_error());
        }
        for (input, primary, evidence, rule, grouping_key) in keys {
            let input = &self.inputs[input];
            let commit = input.commit.as_ref();
            handler.handle(Finding {
                file: input.path.clone(), line: primary.start_line,
                pattern_name: format!("betterleaks:{rule}"),
                description: "Credential candidate detected. Remove it from the inspected content; rotate it if it was exposed.".into(),
                snippet: "[REDACTED]".into(), severity: Severity::High, evidence,
                primary: Some(primary),
                grouping_key: Some(grouping_key),
                commit_hash: commit.map(|c| c.hash.clone()),
                commit_author: commit.map(|c| c.author.clone()),
                commit_date: commit.map(|c| c.date.clone()),
            })?;
        }
        Ok(())
    }

    fn locate(&self, found: EngineFinding) -> Result<Vec<FindingKey>, RedflagError> {
        let name = Path::new(&found.file)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(protocol_error)?;
        let index: usize = name
            .strip_suffix(".txt")
            .or_else(|| name.strip_suffix(".js"))
            .ok_or_else(protocol_error)?
            .parse()
            .map_err(|_| protocol_error())?;
        let window = self.windows.get(index).ok_or_else(protocol_error)?;
        if name != window_name(index, self.inputs[window.input].code) {
            return Err(protocol_error());
        }
        if !valid_digest(&found.secret_digest)
            || found.rule_id.is_empty()
            || !found
                .rule_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(protocol_error());
        }
        // Upstream caps combinations at 100 without signaling truncation. At
        // that boundary, completeness cannot be established from its report.
        if found.component_sets.len() >= 100 {
            return Err(RedflagError::Incomplete(
                "Betterleaks reached its multipart combination limit".into(),
            ));
        }
        let sets = if found.component_sets.is_empty() {
            vec![Vec::new()]
        } else {
            found.component_sets
        };
        let mut keys = Vec::new();
        for set in sets {
            let mut digests = vec![("primary".to_string(), found.secret_digest.clone())];
            let mut locations = vec![found.location.clone()];
            for component in set {
                if !valid_digest(&component.secret_digest) || component.rule_id.is_empty() {
                    return Err(protocol_error());
                }
                digests.push((component.rule_id, component.secret_digest));
                locations.push(component.location);
            }
            let grouping_key = if digests.len() == 1 {
                found.secret_digest.clone()
            } else {
                digests.sort();
                format!("multipart:{}", digest(&serde_json::to_vec(&digests)?))
            };
            let mapped: Vec<_> = locations
                .iter()
                .map(|span| self.locate_span(window, name, span))
                .collect::<Result<_, _>>()?;
            if mapped.iter().any(Option::is_none) {
                // Re-evaluation in an adjacent window is safe only when ALL
                // required pieces fit together inside the overlap.
                let staged = fs::read(self.workspace.path().join("inputs").join(name))?;
                let mut first = usize::MAX;
                let mut last = 0;
                for span in &locations {
                    first = first.min(offset(&staged, span.start_line, span.start_column - 1)?);
                    last = last.max(offset(&staged, span.end_line, span.end_column)?);
                }
                if last.saturating_sub(first) >= STRIDE {
                    return Err(RedflagError::Incomplete(
                        "Multipart credential evidence exceeds the Betterleaks window overlap"
                            .into(),
                    ));
                }
            } else {
                let mut evidence: Vec<_> = mapped.into_iter().flatten().collect();
                let primary = evidence[0].clone();
                evidence.sort();
                evidence.dedup();
                keys.push((
                    window.input,
                    primary.clone(),
                    evidence,
                    found.rule_id.clone(),
                    grouping_key,
                ));
            }
        }
        Ok(keys)
    }

    fn locate_span(
        &self,
        window: &Window,
        name: &str,
        found: &FindingSpan,
    ) -> Result<Option<FindingSpan>, RedflagError> {
        if found.start_line < 2
            || found.start_column == 0
            || found.end_line < found.start_line
            || (found.end_line == found.start_line && found.end_column < found.start_column)
            || found.end_line > window.last_line
            || found.start_column > window.len + 1
            || found.end_column > window.len + 1
            || (found.end_line == window.last_line && found.end_column >= window.last_column)
        {
            return Err(protocol_error());
        }
        // The preceding overlapping window supplies real left-hand context.
        if !window.first_window && found.start_line == 2 && found.start_column == 1 {
            return Ok(None);
        }
        // An unbounded upstream regex must not certify a truncated long value.
        if !window.final_window
            && found.end_line == window.last_line
            && found.end_column + 1 == window.last_column
        {
            let staged = fs::read(self.workspace.path().join("inputs").join(name))?;
            let line_offset = if found.start_line == 1 {
                0
            } else {
                staged
                    .iter()
                    .enumerate()
                    .filter(|(_, byte)| **byte == b'\n')
                    .nth(found.start_line - 2)
                    .map(|(offset, _)| offset + 1)
                    .ok_or_else(protocol_error)?
            };
            let start_offset = line_offset + found.start_column - 1;
            // Short candidates touching the right edge are re-evaluated with
            // complete right-hand context in the next overlapping window.
            if staged.len() - start_offset < STRIDE {
                return Ok(None);
            }
            return Err(RedflagError::Incomplete("A credential candidate reaches the Betterleaks window boundary. Inspect or split this unusually long value before publication.".into()));
        }
        let line = window.line + found.start_line - 2;
        let end_line = window.line + found.end_line - 2;
        let column = found.start_column
            + if found.start_line == 2 {
                window.column - 1
            } else {
                0
            };
        let end_column = found.end_column
            + if found.end_line == 2 {
                window.column - 1
            } else {
                0
            };
        Ok(Some(FindingSpan {
            start_line: line,
            start_column: column,
            end_line,
            end_column,
        }))
    }
}

type FindingKey = (usize, FindingSpan, Vec<FindingSpan>, String, String);

fn window_name(index: usize, code: bool) -> String {
    // The upstream password/username rules use a code-file class to distinguish
    // expressions from unquoted configuration scalars. Neutral basenames and
    // fixed extensions preserve that class without inheriting user path skips.
    format!("{index:08}.{}", if code { "js" } else { "txt" })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn offset(bytes: &[u8], line: usize, column: usize) -> Result<usize, RedflagError> {
    let start = if line == 1 {
        0
    } else {
        bytes
            .iter()
            .enumerate()
            .filter(|(_, b)| **b == b'\n')
            .nth(line - 2)
            .map(|(i, _)| i + 1)
            .ok_or_else(protocol_error)?
    };
    start
        .checked_add(column)
        .filter(|&v| v <= bytes.len())
        .ok_or_else(protocol_error)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineFinding {
    rule_id: String,
    file: String,
    location: FindingSpan,
    secret_digest: String,
    component_sets: Vec<Vec<EngineComponent>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineComponent {
    rule_id: String,
    location: FindingSpan,
    secret_digest: String,
}

fn advance(line: &mut usize, column: &mut usize, bytes: &[u8]) {
    let count = bytes.iter().filter(|&&byte| byte == b'\n').count();
    *line += count;
    *column = bytes
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(*column + bytes.len(), |last| bytes.len() - last);
}

fn protocol_error() -> RedflagError {
    RedflagError::Incomplete("Betterleaks returned an invalid or inconsistent report".into())
}

fn validate_completion(
    code: Option<i32>,
    logs: &str,
    expected_bytes: u64,
) -> Result<(), RedflagError> {
    if !matches!(code, Some(0 | 10)) {
        return Err(RedflagError::Incomplete(
            "Betterleaks did not complete successfully".into(),
        ));
    }
    let mut observed = None;
    for line in logs.lines() {
        if let Some((_, rest)) = line.split_once("scanned ~") {
            let (bytes, _) = rest.split_once(" bytes ").ok_or_else(protocol_error)?;
            if observed
                .replace(bytes.parse::<u64>().map_err(|_| protocol_error())?)
                .is_some()
            {
                return Err(protocol_error());
            }
        }
        if line.contains(" ERR ")
            || (line.contains(" WRN ") && !line.contains("leaks found:"))
            || line.contains("partial scan")
        {
            return Err(protocol_error());
        }
    }
    if observed != Some(expected_bytes) {
        return Err(RedflagError::Incomplete(
            "Betterleaks did not inspect every staged byte".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_exit_without_exact_inspected_bytes_is_incomplete() {
        assert!(validate_completion(Some(0), "1:00PM INF no leaks found\n", 50).is_err());
        assert!(validate_completion(
            Some(0),
            "1:00PM INF scanned ~49 bytes (49 bytes) in 10ms\n",
            50
        )
        .is_err());
        assert!(validate_completion(
            Some(0),
            "1:00PM INF scanned ~50 bytes (50 bytes) in 10ms\n1:00PM INF no leaks found\n",
            50
        )
        .is_ok());
    }

    #[test]
    fn partial_scans_and_engine_warnings_cannot_become_clean_reports() {
        let summary = "1:00PM INF scanned ~50 bytes (50 bytes) in 10ms\n";
        for problem in [
            "1:00PM WRN skipping file: too large\n",
            "1:00PM ERR could not read\n",
            "1:00PM WRN partial scan completed\n",
        ] {
            assert!(validate_completion(Some(0), &format!("{summary}{problem}"), 50).is_err());
        }
        assert!(validate_completion(
            Some(10),
            &format!("{summary}1:00PM WRN leaks found: 2\n"),
            50
        )
        .is_ok());
        assert!(validate_completion(Some(1), summary, 50).is_err());
        assert!(validate_completion(None, summary, 50).is_err());
    }
}
