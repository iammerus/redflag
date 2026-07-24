use crate::{
    config::{Config, EntropyConfig, ExclusionPolicy, Severity},
    error::RedflagError,
};
use glob::Pattern;
use regex::Regex;
use std::{
    fs,
    ops::Range,
    path::{Path, PathBuf},
    sync::LazyLock,
};
use walkdir::WalkDir;

const IGNORE_COMMENT_PATTERN: &str = r"(?i)//\s*redflag-ignore(?:-next)?(?:\s+.*)?$";
static IGNORE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(IGNORE_COMMENT_PATTERN).unwrap());

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
}

pub struct Scanner {
    patterns: Vec<(Regex, String, String, Severity)>,
    entropy_config: EntropyConfig,
    extensions: Vec<String>,
    exclusions: Vec<ExclusionRule>,
    show_secrets: bool,
}

#[derive(Debug, Clone)]
struct ExclusionRule {
    pattern: Pattern,
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
    pub number: usize,
    pub content: &'a str,
    pub commit: Option<&'a CommitMetadata>,
    pub emit_findings: bool,
}

#[derive(Default)]
pub(crate) struct SuppressionState {
    ignore_next_line: bool,
}

pub trait FindingHandler {
    fn handle(&mut self, finding: Finding) -> Result<(), RedflagError>;
}

impl Scanner {
    pub fn with_config(config: Config) -> Result<Self, RedflagError> {
        let patterns = config
            .patterns
            .into_iter()
            .map(|pattern| {
                Ok((
                    Regex::new(&pattern.pattern)?,
                    pattern.name,
                    pattern.description,
                    pattern.severity,
                ))
            })
            .collect::<Result<Vec<_>, RedflagError>>()?;
        let exclusions = config
            .exclusions
            .into_iter()
            .map(|rule| {
                Ok(ExclusionRule {
                    pattern: Pattern::new(&rule.pattern)
                        .map_err(|error| RedflagError::Config(error.to_string()))?,
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
        })
    }

    pub fn show_secrets(mut self, show_secrets: bool) -> Self {
        self.show_secrets = show_secrets;
        self
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
            let findings = self.scan_file(path, handler)?;
            return Ok(ScanStats { files: 1, findings });
        }

        if !metadata.is_dir() {
            return Err(RedflagError::InvalidTarget(path.to_path_buf()));
        }

        let mut files_to_scan = Vec::new();
        for entry in WalkDir::new(path).into_iter().filter_entry(|entry| {
            !entry.file_type().is_dir()
                || entry.path() == path
                || self.file_policy(entry.path()) != ExclusionPolicy::Ignore
        }) {
            let entry = entry?;
            if entry.file_type().is_file()
                && self.file_policy(entry.path()) != ExclusionPolicy::Ignore
                && self.should_scan_path(entry.path())
            {
                files_to_scan.push(entry.into_path());
            }
        }
        files_to_scan.sort();

        let mut stats = ScanStats::default();
        for file_path in files_to_scan {
            stats.findings += self.scan_file(&file_path, handler)?;
            stats.files += 1;
        }
        Ok(stats)
    }

    pub(crate) fn file_policy(&self, path: &Path) -> ExclusionPolicy {
        let path_str = path.to_string_lossy();
        self.exclusions
            .iter()
            .rev()
            .find(|r| {
                r.pattern.matches(&path_str)
                    || (path.is_dir() && r.pattern.matches(&format!("{path_str}/")))
            })
            .map(|r| r.policy)
            .unwrap_or(ExclusionPolicy::ScanButAllow)
    }

    pub(crate) fn should_scan_path(&self, path: &Path) -> bool {
        let file_name = path.file_name().and_then(|name| name.to_str());
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
        handler: &mut H,
    ) -> Result<usize, RedflagError> {
        let content = fs::read_to_string(path).map_err(|source| RedflagError::PathIo {
            path: path.to_path_buf(),
            source,
        })?;
        self.scan_content_with_handler(path, &content, None, handler)
    }

    pub(crate) fn scan_content_with_handler<H: FindingHandler>(
        &self,
        path: &Path,
        content: &str,
        commit: Option<&CommitMetadata>,
        handler: &mut H,
    ) -> Result<usize, RedflagError> {
        let policy = self.file_policy(path);
        if policy == ExclusionPolicy::Ignore {
            return Ok(0);
        }

        let mut state = SuppressionState::default();
        let mut findings_count = 0;
        for (line_num, line) in content.lines().enumerate() {
            findings_count += self.scan_line_with_handler(
                ContentLine {
                    path,
                    number: line_num + 1,
                    content: line,
                    commit,
                    emit_findings: true,
                },
                &mut state,
                handler,
            )?;
        }
        Ok(findings_count)
    }

    pub(crate) fn scan_line_with_handler<H: FindingHandler>(
        &self,
        input: ContentLine<'_>,
        state: &mut SuppressionState,
        handler: &mut H,
    ) -> Result<usize, RedflagError> {
        let policy = self.file_policy(input.path);
        let findings = self.scan_line(input.path, input.number, input.content, state, input.commit);
        if !input.emit_findings || policy == ExclusionPolicy::Ignore {
            return Ok(0);
        }

        let mut count = 0;
        for finding in findings {
            if policy == ExclusionPolicy::ScanButWarn {
                eprintln!("WARNING: Potential secret found but allowed: {finding:?}");
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
        if IGNORE_REGEX.is_match(line) {
            if line.to_ascii_lowercase().contains("ignore-next") {
                state.ignore_next_line = true;
            }
            return Vec::new();
        }
        if state.ignore_next_line {
            state.ignore_next_line = false;
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (pattern, name, description, severity) in &self.patterns {
            if let Some(secret_match) = pattern.find(line) {
                findings.push(self.create_finding(
                    path,
                    line_number,
                    line,
                    Detection {
                        range: secret_match.range(),
                        name,
                        description,
                        severity: *severity,
                    },
                    commit,
                ));
            }
        }

        if self.entropy_config.enabled {
            if let Some(candidate) = extract_entropy_candidate(line, self.entropy_config.min_length)
            {
                if calculate_shannon_entropy(&line[candidate.clone()])
                    >= self.entropy_config.threshold
                {
                    findings.push(self.create_finding(
                        path,
                        line_number,
                        line,
                        Detection {
                            range: candidate,
                            name: "high-entropy",
                            description: "High entropy string detected",
                            severity: Severity::Medium,
                        },
                        commit,
                    ));
                }
            }
        }
        findings
    }

    fn create_finding(
        &self,
        path: &Path,
        line: usize,
        text: &str,
        detection: Detection<'_>,
        commit: Option<&CommitMetadata>,
    ) -> Finding {
        Finding {
            file: path.to_path_buf(),
            line,
            pattern_name: detection.name.to_string(),
            description: detection.description.to_string(),
            snippet: finding_snippet(text, detection.range, self.show_secrets),
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
    show_secrets: bool,
) -> String {
    let context_length = if show_secrets { 3 } else { 20 };
    let prefix: String = text[..secret_range.start]
        .chars()
        .rev()
        .take(context_length)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let suffix: String = text[secret_range.end..]
        .chars()
        .take(context_length)
        .collect();
    if show_secrets {
        format!("{prefix}{}{suffix}", &text[secret_range])
            .chars()
            .take(50)
            .collect()
    } else {
        format!("{prefix}[REDACTED]{suffix}")
    }
}

fn extract_entropy_candidate(line: &str, min_length: usize) -> Option<Range<usize>> {
    for quote in ['"', '\''] {
        let mut offset = 0;
        while let Some(open) = line[offset..].find(quote).map(|index| offset + index) {
            let value_start = open + quote.len_utf8();
            let Some(close) = line[value_start..]
                .find(quote)
                .map(|index| value_start + index)
            else {
                break;
            };
            if is_entropy_token(&line[value_start..close], min_length) {
                return Some(value_start..close);
            }
            offset = close + quote.len_utf8();
        }
    }

    let separator = line.find(['=', ':'])?;
    let value = line[separator + 1..].trim();
    let value = value.trim_end_matches([',', ';']);
    if !is_entropy_token(value, min_length) {
        return None;
    }

    let start = line.find(value)?;
    Some(start..start + value.len())
}

fn is_entropy_token(value: &str, min_length: usize) -> bool {
    value.len() >= min_length
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
    use crate::config::SecretPattern;

    #[derive(Default)]
    struct TestHandler {
        findings: Vec<Finding>,
    }

    impl FindingHandler for TestHandler {
        fn handle(&mut self, finding: Finding) -> Result<(), RedflagError> {
            self.findings.push(finding);
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
        let token = "AbCdEf0123456789._-+/=%AbCdEfXYZ";
        let json = format!(r#""value": "{token}""#);
        let range = extract_entropy_candidate(&json, 30).unwrap();

        assert_eq!(&json[range], token);
        assert!(extract_entropy_candidate(
            r#""Bash(GIT_AUTHOR_DATE=2026-01-01 git commit --amend)""#,
            30
        )
        .is_none());
        assert!(extract_entropy_candidate(
            "const prompts = [`first long source expression`, `second expression`];",
            30
        )
        .is_none());
    }

    #[test]
    fn snippets_centre_the_matched_range() {
        let line = format!("{}{}", "context ".repeat(10), "secret-value");
        let start = line.find("secret-value").unwrap();

        assert!(finding_snippet(&line, start..line.len(), false).contains("[REDACTED]"));
        assert!(finding_snippet(&line, start..line.len(), true).contains("secret-value"));
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
        Ok(())
    }
}
