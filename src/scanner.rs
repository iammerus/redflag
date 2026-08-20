use crate::{
    config::{
        is_default_pattern, Config, EntropyConfig, ExclusionPolicy, ScanLimits, SecretPattern,
        Severity,
    },
    error::RedflagError,
};
use glob::Pattern;
use regex::Regex;
use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader, Read},
    ops::Range,
    path::{Path, PathBuf},
    sync::LazyLock,
};
use walkdir::WalkDir;

pub(crate) use crate::suppression::SuppressionState;

#[derive(Debug, serde::Serialize, Clone)]
pub struct Finding {
    pub file: PathBuf,
    pub line: usize,
    pub pattern_name: String,
    pub description: String,
    pub snippet: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_date: Option<String>,
    /// Required match spans, in 1-based lines and inclusive byte columns.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<FindingSpan>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct FindingSpan {
    pub start_line: usize,
    pub end_line: usize,
    pub start_column: usize,
    pub end_column: usize,
}

#[derive(Clone)]
pub(crate) struct CommitMetadata {
    pub hash: String,
    pub author: String,
    pub date: String,
}

#[derive(Default)]
pub(crate) struct ScanStats {
    pub files: usize,
    pub findings: usize,
    pub commits: usize,
}

#[derive(Debug)]
pub(crate) enum ScanProgress {
    Preparing {
        phase: &'static str,
    },
    Item {
        phase: &'static str,
        current: usize,
        total: usize,
        detail: String,
    },
    Finished {
        phase: &'static str,
        total: usize,
    },
}

pub struct Scanner {
    patterns: Vec<CompiledPattern>,
    entropy_config: EntropyConfig,
    extensions: Vec<String>,
    exclusions: Vec<ExclusionRule>,
    show_secrets: bool,
    limits: ScanLimits,
}

struct CompiledPattern {
    regex: Regex,
    rule: SecretPattern,
    builtin: bool,
}

impl CompiledPattern {
    fn new(rule: SecretPattern) -> Result<Self, RedflagError> {
        Ok(Self {
            regex: Regex::new(&rule.pattern).map_err(|error| {
                RedflagError::Config(format!("Invalid regex for '{}': {error}", rule.name))
            })?,
            builtin: is_default_pattern(&rule),
            rule,
        })
    }

    fn ranges(&self, line: &str, path: &Path) -> Vec<Range<usize>> {
        self.regex
            .captures_iter(line)
            .filter_map(|captures| {
                let full_match = captures.get(0)?;
                let found = captures.name("secret").unwrap_or(full_match);
                let mut range = found.range();
                if self.builtin {
                    if captures.name("key").is_some_and(|key| {
                        !credential_key_boundary(line, key.start(), key.as_str())
                    }) {
                        return None;
                    }
                    // The colon in ${PASSWORD:-value} is a shell operator,
                    // not an object assignment to PASSWORD.
                    if found.start() > full_match.start()
                        && inside_shell_parameter(&line[..full_match.start()])
                    {
                        return None;
                    }
                    let mut quoted = is_quoted(found.as_str());
                    if quoted {
                        range = range.start + 1..range.end - 1;
                    }
                    if let Some(default) = shell_default_range(line, &range) {
                        range = default;
                        quoted = is_quoted(&line[range.clone()]);
                        if quoted {
                            range = range.start + 1..range.end - 1;
                        }
                    }
                    if !valid_builtin(&self.rule.name, line, &range, quoted, path) {
                        return None;
                    }
                }
                Some(range)
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
struct ExclusionRule {
    pattern: Pattern,
    literal_prefix: String,
    policy: ExclusionPolicy,
}

pub(crate) struct Detection<'a> {
    pub range: Range<usize>,
    pub name: &'a str,
    pub description: &'a str,
    pub severity: Severity,
}

pub(crate) struct ContentLine<'a> {
    pub path: &'a Path,
    pub policy: ExclusionPolicy,
    pub number: usize,
    pub content: &'a str,
    pub commit: Option<&'a CommitMetadata>,
    pub emit_findings: bool,
}

pub trait FindingHandler {
    fn handle(&mut self, finding: Finding) -> Result<(), RedflagError>;

    fn warning(&mut self, _finding: Finding) -> Result<(), RedflagError> {
        Ok(())
    }

    fn progress(&mut self, _progress: ScanProgress) -> Result<(), RedflagError> {
        Ok(())
    }
}

impl Scanner {
    pub fn with_config(mut config: Config) -> Result<Self, RedflagError> {
        config.validate()?;
        let patterns = config
            .patterns
            .into_iter()
            .map(CompiledPattern::new)
            .collect::<Result<Vec<_>, RedflagError>>()?;
        let exclusions = config
            .exclusions
            .into_iter()
            .map(|rule| {
                Ok(ExclusionRule {
                    pattern: Pattern::new(&rule.pattern).map_err(|error| {
                        RedflagError::Config(format!(
                            "Invalid exclusion glob '{}': {error}",
                            rule.pattern
                        ))
                    })?,
                    literal_prefix: rule
                        .pattern
                        .split(['*', '?', '[', '{'])
                        .next()
                        .unwrap_or_default()
                        .trim_start_matches("./")
                        .trim_end_matches('/')
                        .replace('\\', "/"),
                    policy: rule.policy,
                })
            })
            .collect::<Result<Vec<_>, RedflagError>>()?;

        Ok(Scanner {
            patterns,
            entropy_config: config.entropy,
            extensions: config.extensions,
            exclusions,
            show_secrets: false,
            limits: config.limits,
        })
    }

    pub fn show_secrets(mut self, show_secrets: bool) -> Self {
        self.show_secrets = show_secrets;
        self
    }

    pub fn for_external_engine(mut self) -> Self {
        // Preserve explicit TOML rules and the format-specific netrc check,
        // which the pinned general engine does not currently cover.
        self.patterns
            .retain(|pattern| !pattern.builtin || pattern.rule.name == "Netrc Password");
        self.entropy_config.enabled = false;
        self
    }

    pub(crate) fn limits(&self) -> &ScanLimits {
        &self.limits
    }

    pub(crate) fn check_file_limit(&self, path: &Path, length: u64) -> Result<(), RedflagError> {
        if length > self.limits.max_file_bytes {
            return Err(RedflagError::Incomplete(format!(
                "{} exceeds the {}-byte file limit. Increase limits.max_file_bytes to inspect this content.",
                path.display(), self.limits.max_file_bytes
            )));
        }
        Ok(())
    }

    pub fn scan_with_handler<H: FindingHandler>(
        &self,
        path: &str,
        handler: &mut H,
    ) -> Result<ScanStats, RedflagError> {
        let path = Path::new(path);
        let metadata = fs::metadata(path).map_err(|source| RedflagError::PathIo {
            path: path.to_path_buf(),
            source,
        })?;

        if metadata.is_file() {
            let policy_path = path.file_name().map(Path::new).unwrap_or(path);
            handler.progress(ScanProgress::Item {
                phase: "Working tree",
                current: 1,
                total: 1,
                detail: path.display().to_string(),
            })?;
            let findings = self.scan_file(path, policy_path, handler)?;
            handler.progress(ScanProgress::Finished {
                phase: "Working tree",
                total: 1,
            })?;
            return Ok(ScanStats {
                files: 1,
                findings,
                commits: 0,
            });
        }

        if !metadata.is_dir() {
            return Err(RedflagError::InvalidTarget(path.to_path_buf()));
        }

        handler.progress(ScanProgress::Preparing {
            phase: "working tree",
        })?;
        let mut files_to_scan = Vec::new();
        for entry in WalkDir::new(path).into_iter().filter_entry(|entry| {
            if !entry.file_type().is_dir() || entry.path() == path {
                return true;
            }
            let relative = entry.path().strip_prefix(path).unwrap_or(entry.path());
            self.should_descend(relative)
        }) {
            let entry = entry?;
            let relative = entry
                .path()
                .strip_prefix(path)
                .unwrap_or(entry.path())
                .to_path_buf();
            if entry.file_type().is_file()
                && self.file_policy(&relative, false) != ExclusionPolicy::Ignore
                && self.should_scan_path(entry.path())
            {
                files_to_scan.push((entry.into_path(), relative));
                if files_to_scan.len() > self.limits.max_files {
                    return Err(RedflagError::Incomplete(format!(
                        "The scan exceeds the {}-file limit. Narrow the target or increase limits.max_files.",
                        self.limits.max_files
                    )));
                }
            }
        }
        files_to_scan.sort_by(|left, right| left.0.cmp(&right.0));

        let mut stats = ScanStats::default();
        let total = files_to_scan.len();
        for (index, (file_path, policy_path)) in files_to_scan.into_iter().enumerate() {
            handler.progress(ScanProgress::Item {
                phase: "Working tree",
                current: index + 1,
                total,
                detail: file_path.display().to_string(),
            })?;
            stats.findings += self.scan_file(&file_path, &policy_path, handler)?;
            stats.files += 1;
        }
        handler.progress(ScanProgress::Finished {
            phase: "Working tree",
            total,
        })?;
        Ok(stats)
    }

    pub(crate) fn file_policy(&self, path: &Path, is_dir: bool) -> ExclusionPolicy {
        self.matching_exclusion(path, is_dir)
            .map(|(_, rule)| rule.policy)
            .unwrap_or(ExclusionPolicy::ScanButAllow)
    }

    fn matching_exclusion(&self, path: &Path, is_dir: bool) -> Option<(usize, &ExclusionRule)> {
        let path = normalised_path(path);
        self.exclusions.iter().enumerate().rev().find(|(_, rule)| {
            rule.pattern.matches(&path) || (is_dir && rule.pattern.matches(&format!("{path}/")))
        })
    }

    fn should_descend(&self, path: &Path) -> bool {
        let Some((index, rule)) = self.matching_exclusion(path, true) else {
            return true;
        };
        if rule.policy != ExclusionPolicy::Ignore {
            return true;
        }

        let directory = normalised_path(path);
        self.exclusions[index + 1..].iter().any(|later| {
            if later.policy == ExclusionPolicy::Ignore || later.literal_prefix.is_empty() {
                return later.policy != ExclusionPolicy::Ignore;
            }
            later.literal_prefix == directory
                || later.literal_prefix.starts_with(&format!("{directory}/"))
                || directory.starts_with(&format!("{}/", later.literal_prefix))
        })
    }

    pub(crate) fn should_scan_path(&self, path: &Path) -> bool {
        let file_name = path.file_name().and_then(|name| name.to_str());
        if is_lockfile(path) || is_known_extensionless_file(path) {
            return true;
        }
        if file_name == Some(".env") || file_name.is_some_and(|name| name.starts_with(".env.")) {
            return true;
        }

        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| self.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext)))
            .unwrap_or(false)
    }

    fn scan_file<H: FindingHandler>(
        &self,
        path: &Path,
        policy_path: &Path,
        handler: &mut H,
    ) -> Result<usize, RedflagError> {
        let policy = self.file_policy(policy_path, false);
        if policy == ExclusionPolicy::Ignore {
            return Ok(0);
        }
        let file = fs::File::open(path).map_err(|source| RedflagError::PathIo {
            path: path.to_path_buf(),
            source,
        })?;
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        let mut state = SuppressionState::default();
        let mut findings_count = 0;
        let mut number = 0;
        let mut bytes_read = 0u64;
        loop {
            buffer.clear();
            let remaining_file_bytes = self
                .limits
                .max_file_bytes
                .saturating_sub(bytes_read)
                .saturating_add(1);
            let read = (&mut reader)
                .take(((self.limits.max_line_bytes + 3) as u64).min(remaining_file_bytes))
                .read_until(b'\n', &mut buffer)
                .map_err(|source| RedflagError::PathIo {
                    path: path.to_path_buf(),
                    source,
                })?;
            if read == 0 {
                break;
            }
            bytes_read += read as u64;
            self.check_file_limit(path, bytes_read)?;
            number += 1;
            let bytes = buffer.strip_suffix(b"\n").unwrap_or(&buffer);
            let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
            self.check_line_limit(path, number, bytes.len())?;
            let line = std::str::from_utf8(bytes).map_err(|_| RedflagError::Incomplete(format!(
                "{}:{number} is not UTF-8. Convert the file or explicitly exclude unsupported content.", path.display()
            )))?;
            findings_count += self.scan_line_with_handler(
                ContentLine {
                    path,
                    policy,
                    number,
                    content: line,
                    commit: None,
                    emit_findings: true,
                },
                &mut state,
                handler,
            )?;
        }
        Ok(findings_count)
    }

    pub(crate) fn check_line_limit(
        &self,
        path: &Path,
        number: usize,
        length: usize,
    ) -> Result<(), RedflagError> {
        if length > self.limits.max_line_bytes {
            return Err(RedflagError::Incomplete(format!(
                "{}:{number} exceeds the {}-byte line limit. Increase limits.max_line_bytes to inspect this content.",
                path.display(), self.limits.max_line_bytes
            )));
        }
        Ok(())
    }

    pub(crate) fn scan_line_with_handler<H: FindingHandler>(
        &self,
        input: ContentLine<'_>,
        state: &mut SuppressionState,
        handler: &mut H,
    ) -> Result<usize, RedflagError> {
        if input.policy == ExclusionPolicy::Ignore {
            return Ok(0);
        }
        self.check_line_limit(input.path, input.number, input.content.len())?;
        if !input.emit_findings {
            state.consume(input.path, input.content);
            return Ok(0);
        }
        let findings = self.scan_line(input.path, input.number, input.content, state, input.commit);

        let mut count = 0;
        for finding in findings {
            if input.policy == ExclusionPolicy::ScanButWarn {
                handler.warning(finding)?;
            } else {
                handler.handle(finding)?;
                count += 1;
            }
        }
        Ok(count)
    }

    fn scan_line(
        &self,
        path: &Path,
        line_number: usize,
        line: &str,
        state: &mut SuppressionState,
        commit: Option<&CommitMetadata>,
    ) -> Vec<Finding> {
        if state.consume(path, line) {
            return Vec::new();
        }

        self.detect_line(path, line_number, line, commit, false)
    }

    /// Inspect published content without source exclusions or comment directives.
    /// Byte matching of declared values is handled before this text projection.
    pub(crate) fn scan_artifact_line<H: FindingHandler>(
        &self,
        path: &Path,
        line_number: usize,
        bytes: &[u8],
        handler: &mut H,
    ) -> Result<usize, RedflagError> {
        self.check_line_limit(path, line_number, bytes.len())?;
        let line = String::from_utf8_lossy(bytes);
        let findings = self.detect_line(path, line_number, &line, None, true);
        let count = findings.len();
        for mut finding in findings {
            // Nearby opaque private values must never appear as context.
            finding.snippet = "[REDACTED]".into();
            handler.handle(finding)?;
        }
        Ok(count)
    }

    fn detect_line(
        &self,
        path: &Path,
        line_number: usize,
        line: &str,
        commit: Option<&CommitMetadata>,
        include_evidence: bool,
    ) -> Vec<Finding> {
        let mut detections: Vec<Detection<'_>> = Vec::new();
        let mut builtin_indices: HashMap<(usize, usize), usize> = HashMap::new();
        for pattern in &self.patterns {
            for range in pattern.ranges(line, path) {
                // Keep independent values on a line, but report a literal only
                // once when several built-in rules recognize the same value.
                if pattern.builtin {
                    if let Some(index) = builtin_indices.get(&(range.start, range.end)) {
                        let previous = &mut detections[*index];
                        if severity_rank(pattern.rule.severity) < severity_rank(previous.severity) {
                            previous.name = &pattern.rule.name;
                            previous.description = &pattern.rule.description;
                            previous.severity = pattern.rule.severity;
                        }
                        continue;
                    }
                    builtin_indices.insert((range.start, range.end), detections.len());
                }
                detections.push(Detection {
                    range,
                    name: &pattern.rule.name,
                    description: &pattern.rule.description,
                    severity: pattern.rule.severity,
                });
            }
        }

        if self.entropy_config.enabled && !is_lockfile(path) {
            let known_ranges = merged_ranges(detections.iter().map(|item| item.range.clone()));
            for candidate in extract_entropy_candidates(line, self.entropy_config.min_length) {
                let preceding =
                    known_ranges.partition_point(|range| range.start <= candidate.start);
                let covered = preceding
                    .checked_sub(1)
                    .is_some_and(|index| known_ranges[index].end >= candidate.end);
                if covered
                    || is_checksum_context(&line[..candidate.start])
                    || is_reference(&line[candidate.clone()])
                    || is_publishable_key(&line[candidate.clone()])
                {
                    continue;
                }
                if calculate_shannon_entropy(&line[candidate.clone()])
                    >= self.entropy_config.threshold
                {
                    detections.push(Detection {
                        range: candidate,
                        name: "high-entropy",
                        description: "High entropy string detected",
                        severity: Severity::Medium,
                    });
                }
            }
        }

        let redactions = merged_ranges(detections.iter().map(|detection| detection.range.clone()));
        detections
            .into_iter()
            .map(|detection| {
                let evidence = if include_evidence {
                    vec![FindingSpan {
                        start_line: line_number,
                        end_line: line_number,
                        start_column: detection.range.start + 1,
                        end_column: detection.range.end,
                    }]
                } else {
                    Vec::new()
                };
                let mut finding =
                    self.create_finding(path, line_number, line, detection, &redactions, commit);
                finding.evidence = evidence;
                finding
            })
            .collect()
    }

    fn create_finding(
        &self,
        path: &Path,
        line: usize,
        text: &str,
        detection: Detection<'_>,
        redactions: &[Range<usize>],
        commit: Option<&CommitMetadata>,
    ) -> Finding {
        Finding {
            file: path.to_path_buf(),
            line,
            pattern_name: detection.name.to_string(),
            description: detection.description.to_string(),
            evidence: Vec::new(),
            snippet: finding_snippet(text, detection.range, redactions, self.show_secrets),
            severity: detection.severity,
            commit_hash: commit.map(|metadata| metadata.hash.clone()),
            commit_author: commit.map(|metadata| metadata.author.clone()),
            commit_date: commit.map(|metadata| metadata.date.clone()),
        }
    }
}

pub(crate) fn finding_snippet(
    text: &str,
    secret_range: Range<usize>,
    redactions: &[Range<usize>],
    show_secrets: bool,
) -> String {
    let context_length: usize = if show_secrets { 3 } else { 20 };
    let start = text[..secret_range.start]
        .char_indices()
        .rev()
        .nth(context_length.saturating_sub(1))
        .map_or(0, |(index, _)| index);
    let end = text[secret_range.end..]
        .char_indices()
        .nth(context_length)
        .map_or(text.len(), |(index, _)| secret_range.end + index);
    if show_secrets {
        text[start..end].chars().take(50).collect()
    } else {
        let mut snippet = String::new();
        let mut cursor = start;
        let first = redactions.partition_point(|range| range.end <= start);
        for range in redactions[first..]
            .iter()
            .take_while(|range| range.start < end)
        {
            if range.start > cursor {
                snippet.push_str(&text[cursor..range.start.min(end)]);
            }
            snippet.push_str("[REDACTED]");
            cursor = cursor.max(range.end).min(end);
        }
        if cursor < end {
            snippet.push_str(&text[cursor..end]);
        }
        snippet
    }
}

fn merged_ranges(ranges: impl Iterator<Item = Range<usize>>) -> Vec<Range<usize>> {
    let mut ranges: Vec<_> = ranges.collect();
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in ranges {
        if let Some(previous) = merged.last_mut() {
            if range.start <= previous.end {
                previous.end = previous.end.max(range.end);
                continue;
            }
        }
        merged.push(range);
    }
    merged
}

fn normalised_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            std::path::Component::ParentDir => Some("..".to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_lockfile(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(
            "package-lock.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "Cargo.lock"
                | "Gemfile.lock"
                | "poetry.lock"
                | "composer.lock"
                | "go.sum"
                | "flake.lock"
                | "bun.lock"
        )
    )
}

fn is_known_extensionless_file(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(
            ".npmrc"
                | ".yarnrc"
                | ".netrc"
                | ".pypirc"
                | "Dockerfile"
                | "Containerfile"
                | "Makefile"
                | "Jenkinsfile"
                | "credentials"
                | "id_rsa"
                | "id_dsa"
                | "id_ecdsa"
                | "id_ed25519"
        )
    )
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    }
}

fn is_quoted(value: &str) -> bool {
    value.len() >= 2
        && matches!(value.as_bytes()[0], b'"' | b'\'' | b'`')
        && value.as_bytes().first() == value.as_bytes().last()
}

fn is_reference(value: &str) -> bool {
    static REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$\{\{\s*(?:secrets|env|vars)(?:\.[A-Za-z_][A-Za-z0-9_]*)+\s*\}\}|\$[A-Za-z_][A-Za-z0-9_]*|process\.env\.[A-Za-z_][A-Za-z0-9_]*|var\.[A-Za-z_][A-Za-z0-9_]*|os\.(?:environ\[.*\]|(?:getenv|environ\.get)\([^,]*\)))$"#,
        )
        .unwrap()
    });
    REFERENCE.is_match(value)
}

fn shell_default_range(line: &str, range: &Range<usize>) -> Option<Range<usize>> {
    static DEFAULT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\$\{[A-Za-z_][A-Za-z0-9_]*(?::-|:=|-|=)(?P<default>[^{}]*)\}$").unwrap()
    });
    let captures = DEFAULT.captures(&line[range.clone()])?;
    let value = captures.name("default")?;
    Some(range.start + value.start()..range.start + value.end())
}

fn inside_shell_parameter(prefix: &str) -> bool {
    let name_length = prefix
        .bytes()
        .rev()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    prefix[..prefix.len() - name_length].ends_with("${")
}

fn credential_key_boundary(line: &str, start: usize, key: &str) -> bool {
    match line[..start].chars().next_back() {
        None => true,
        // Underscores/hyphens delimit credential suffixes in environment names.
        Some(previous) if !previous.is_alphanumeric() => true,
        // Camel-case suffixes such as clientSecret and databasePassword are
        // credential names; arbitrary substrings such as notpassword are not.
        Some(previous) => {
            previous.is_ascii_lowercase()
                && key.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        }
    }
}

fn source_requires_quoted_values(path: &Path) -> bool {
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    [
        "js", "mjs", "cjs", "ts", "jsx", "tsx", "rs", "py", "rb", "php", "java", "go", "cs", "c",
        "cpp", "h", "hpp", "kt", "swift",
    ]
    .iter()
    .any(|expected| extension.eq_ignore_ascii_case(expected))
}

fn is_placeholder(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "your_password_here"
            | "your_api_key_here"
            | "your_secret_here"
            | "your_token_here"
            | "your_github_token_here"
            | "<password>"
            | "<api_key>"
            | "<secret>"
            | "<token>"
    )
}

fn is_publishable_key(value: &str) -> bool {
    value
        .strip_prefix("pk_live_")
        .or_else(|| value.strip_prefix("pk_test_"))
        .is_some_and(|suffix| {
            suffix.len() >= 24 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn is_checksum_context(prefix: &str) -> bool {
    // Inspect the adjacent assignment, not the entire prefix for every string
    // in a minified bundle. Only remove one optional opening/closing quote.
    let prefix = prefix
        .strip_suffix(['"', '\'', '`'])
        .unwrap_or(prefix)
        .trim_end();
    let Some(prefix) = prefix.strip_suffix([':', '=']) else {
        return false;
    };
    let prefix = prefix.trim_end();
    let prefix = prefix.strip_suffix(['"', '\'', '`']).unwrap_or(prefix);
    let name_length = prefix
        .bytes()
        .rev()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    let name = &prefix[prefix.len() - name_length..];
    [
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "md5",
        "checksum",
        "digest",
        "integrity",
    ]
    .iter()
    .any(|expected| name.eq_ignore_ascii_case(expected))
}

fn token_boundary(line: &str, range: &Range<usize>) -> bool {
    let token_character = |character: char| character.is_ascii_alphanumeric() || character == '_';
    !line[..range.start]
        .chars()
        .next_back()
        .is_some_and(token_character)
        && !line[range.end..]
            .chars()
            .next()
            .is_some_and(token_character)
}

fn valid_builtin(name: &str, line: &str, range: &Range<usize>, quoted: bool, path: &Path) -> bool {
    let value = &line[range.clone()];
    if matches!(
        name,
        "GitHub Token" | "Stripe Secret Key" | "npm Access Token" | "AWS Access Key" | "JWT Token"
    ) {
        return token_boundary(line, range);
    }
    if name == "Private Key" {
        return true;
    }
    if name == "Database Connection String" {
        let Some((_, authority)) = value.split_once("://") else {
            return false;
        };
        let Some((userinfo, _)) = authority.split_once('@') else {
            return false;
        };
        let Some((_, password)) = userinfo.split_once(':') else {
            return false;
        };
        return !is_reference(password) && !is_placeholder(password);
    }
    if is_reference(value) || is_placeholder(value) || is_publishable_key(value) {
        return false;
    }
    // In programming languages, unquoted assignment values are expressions,
    // symbols or scalars, not string credentials. Environment/configuration
    // files deliberately retain support for unquoted literal values. Provider
    // formats above remain detectable anywhere, independently of assignments.
    if !quoted && source_requires_quoted_values(path) {
        return false;
    }
    // Unquoted program expressions are references, not string literals. Quoted
    // passphrases and hardcoded values combined with interpolation still count.
    if !quoted
        && (value.contains(['(', '[', '{'])
            || [
                "process.env.",
                "config.",
                "settings.",
                "secrets.",
                "this.",
                "self.",
            ]
            .iter()
            .any(|prefix| value.starts_with(prefix)))
    {
        return false;
    }
    let aws_secret = || {
        value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'='))
    };
    match name {
        "AWS Secret Key"
        | "AWS Secret in Object"
        | "AWS Direct Secret Assignment"
        | "AWS Secret with Fallback" => aws_secret(),
        "AWS Key in Object" | "AWS Direct Key Assignment" | "AWS Access Key with Fallback" => {
            value.len() == 20
                && (value.starts_with("AKIA") || value.starts_with("ASIA"))
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        }
        "Generic API Key" => {
            value.len() >= 32
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'_' | b'-' | b'+' | b'/' | b'=' | b'.')
                })
                && value
                    .bytes()
                    .any(|byte| Some(&byte) != value.as_bytes().first())
        }
        "Netrc Password" => {
            path.file_name().is_some_and(|file| file == ".netrc") && !value.is_empty()
        }
        _ => value.len() >= 8,
    }
}

fn extract_entropy_candidates(line: &str, min_length: usize) -> Vec<Range<usize>> {
    let mut candidates = Vec::new();
    for quote in ['"', '\'', '`'] {
        let mut offset = 0;
        while let Some(open) = line[offset..].find(quote).map(|index| offset + index) {
            let value_start = open + quote.len_utf8();
            let mut close = value_start;
            while close < line.len() {
                match line.as_bytes()[close] {
                    b'\\' => close += 2,
                    byte if byte == quote as u8 => break,
                    _ => close += 1,
                }
            }
            if close >= line.len() {
                break;
            }
            if is_entropy_token(&line[value_start..close], min_length) {
                candidates.push(value_start..close);
            }
            offset = close + quote.len_utf8();
        }
    }

    if candidates.is_empty() {
        if let Some(separator) = line.find(['=', ':']) {
            let value = line[separator + 1..].trim();
            let value = value.trim_end_matches([',', ';']);
            if is_entropy_token(value, min_length) {
                let start = line.find(value).unwrap_or(separator + 1);
                candidates.push(start..start + value.len());
            }
        }
    }

    candidates.sort_by_key(|range| range.start);
    candidates.dedup();
    candidates
}

fn is_entropy_token(value: &str, min_length: usize) -> bool {
    value.len() >= min_length
        && !(value.contains('/') && value.contains('.'))
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b'+' | b'/' | b'=' | b':' | b'%')
        })
}

pub(crate) fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    let length = s.len() as f64;

    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }

    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / length;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ExclusionRule as ConfigExclusionRule, SecretPattern};

    #[derive(Default)]
    struct TestHandler {
        findings: Vec<Finding>,
        progress: Vec<ScanProgress>,
    }

    impl FindingHandler for TestHandler {
        fn handle(&mut self, finding: Finding) -> Result<(), RedflagError> {
            self.findings.push(finding);
            Ok(())
        }

        fn progress(&mut self, progress: ScanProgress) -> Result<(), RedflagError> {
            self.progress.push(progress);
            Ok(())
        }
    }

    #[test]
    fn test_regex_pattern() {
        let pattern = r#"api_key\s*=\s*"test_key_\d{10}""#;
        let re = Regex::new(pattern).unwrap();

        let test_input = r#"let api_key = "test_key_1234567890";"#;
        assert!(
            re.is_match(test_input),
            "Regex pattern did not match test input"
        );
    }

    #[test]
    fn test_entropy_calculation() {
        // Test known values
        let random = "mR7hJ8q$Lz@w!bE5"; // 16 random chars
        let low_entropy = "aaaaaaaaaaaaaaaa"; // 16 identical chars

        let random_entropy = calculate_shannon_entropy(random);
        let low_entropy_val = calculate_shannon_entropy(low_entropy);

        // Check relative values without fixed thresholds
        assert!(
            random_entropy > 3.0,
            "Random entropy was {}",
            random_entropy
        );
        assert!(low_entropy_val < 1.5, "Low entropy was {}", low_entropy_val);
        assert!(random_entropy > low_entropy_val);
    }

    #[test]
    fn entropy_candidates_are_token_shaped() {
        let token = "AbCdEf0123456789_-+/=%AbCdEfXYZ";
        let json = format!(r#""value": "{token}""#);
        let ranges = extract_entropy_candidates(&json, 30);

        assert_eq!(&json[ranges[0].clone()], token);
        let jwt = ["eyJhbGciOiJIUzI1NiJ9.", "AbCdEf0123456789", ".signature"].concat();
        assert!(is_entropy_token(&jwt, 30));
        assert!(extract_entropy_candidates(
            r#""Bash(GIT_AUTHOR_DATE=2026-01-01 git commit --amend)""#,
            30
        )
        .is_empty());
        assert!(extract_entropy_candidates(
            "const prompts = [`first long source expression`, `second expression`];",
            30
        )
        .is_empty());
        assert!(
            extract_entropy_candidates(r#""platform.example.io/qualified-resource-name""#, 30)
                .is_empty()
        );
    }

    #[test]
    fn snippets_centre_the_matched_range() {
        let line = format!("{}{}", "context ".repeat(10), "secret-value");
        let start = line.find("secret-value").unwrap();
        let secret_range = start..line.len();
        let redactions = std::slice::from_ref(&secret_range);

        assert!(
            finding_snippet(&line, secret_range.clone(), redactions, false).contains("[REDACTED]")
        );
        assert!(
            finding_snippet(&line, secret_range.clone(), redactions, true).contains("secret-value")
        );
    }

    #[test]
    fn every_secret_is_detected_and_redacted() {
        let scanner = Scanner::with_config(Config {
            patterns: vec![
                SecretPattern {
                    name: "api-key".to_string(),
                    pattern: r#"api_key="[^"]+""#.to_string(),
                    description: "API key".to_string(),
                    severity: Severity::High,
                },
                SecretPattern {
                    name: "password".to_string(),
                    pattern: r#"pwd="[^"]+""#.to_string(),
                    description: "Password".to_string(),
                    severity: Severity::High,
                },
            ],
            entropy: EntropyConfig {
                enabled: false,
                ..Default::default()
            },
            ..Config::default()
        })
        .unwrap();
        let first = ["first-api-", "value-123456"].concat();
        let second = ["second-api-", "value-654321"].concat();
        let password = ["password-", "123456"].concat();
        let line = ["api_key=\"", &first, "\"; ", "pwd", "=\"", &password, "\""].concat();
        let mut state = SuppressionState::default();
        let findings = scanner.scan_line(Path::new("test.rs"), 1, &line, &mut state, None);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(
            |finding| !finding.snippet.contains(&first) && !finding.snippet.contains(&password)
        ));

        let repeated = format!(r#"api_key="{first}"; api_key="{second}""#);
        let findings = scanner.scan_line(Path::new("test.rs"), 1, &repeated, &mut state, None);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn descendant_exclusion_can_override_ignored_parent() {
        let scanner = Scanner::with_config(Config {
            exclusions: vec![
                ConfigExclusionRule {
                    pattern: "private/**".to_string(),
                    policy: ExclusionPolicy::Ignore,
                },
                ConfigExclusionRule {
                    pattern: "private/allowed/**".to_string(),
                    policy: ExclusionPolicy::ScanButAllow,
                },
            ],
            ..Config::default()
        })
        .unwrap();

        assert!(scanner.should_descend(Path::new("private")));
        assert!(scanner.should_descend(Path::new("private/allowed")));
        assert_eq!(
            scanner.file_policy(Path::new("private/allowed/secret.rs"), false),
            ExclusionPolicy::ScanButAllow
        );
    }

    #[test]
    fn entropy_checks_later_candidates() {
        let low = "a".repeat(40);
        let high = [
            "ABCDEFGHIJKLMNOPQRST",
            "UVWXYZabcdefghijklmn",
            "opqrstuvwxyz0123456789",
        ]
        .concat();
        let line = format!(r#""{low}" "{high}""#);
        let detected: Vec<_> = extract_entropy_candidates(&line, 30)
            .into_iter()
            .filter(|range| calculate_shannon_entropy(&line[range.clone()]) >= 4.8)
            .collect();

        assert_eq!(detected.len(), 1);
        assert_eq!(&line[detected[0].clone()], high);
    }

    #[test]
    fn test_file_scanning() -> Result<(), RedflagError> {
        let dir = tempfile::tempdir()?;
        let file_path = dir.path().join("secrets.rs");

        fs::write(&file_path, r#"let api_key = "test_key_1234567890";"#)?;

        let config = Config {
            patterns: vec![SecretPattern {
                name: "test-key".to_string(),
                pattern: r#"api_key\s*=\s*"[^"]*""#.to_string(),
                description: "Test key pattern".to_string(),
                severity: Severity::High,
            }],
            extensions: vec!["rs".to_string()],
            exclusions: vec![], // Clear default exclusions
            entropy: EntropyConfig {
                enabled: false,
                ..Default::default()
            },
            ..Config::default()
        };

        let scanner = Scanner::with_config(config)?;
        let mut handler = TestHandler::default();
        scanner.scan_with_handler(dir.path().to_str().unwrap(), &mut handler)?;

        assert!(!handler.findings.is_empty(), "No findings detected");
        assert!(matches!(
            handler.progress.first(),
            Some(ScanProgress::Preparing {
                phase: "working tree"
            })
        ));
        assert!(handler.progress.iter().any(|progress| matches!(
            progress,
            ScanProgress::Item {
                current: 1,
                total: 1,
                ..
            }
        )));
        assert!(matches!(
            handler.progress.last(),
            Some(ScanProgress::Finished {
                phase: "Working tree",
                total: 1
            })
        ));
        Ok(())
    }
}
