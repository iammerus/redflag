use crate::{
    config::{Config, EntropyConfig, ExclusionPolicy, Severity},
    error::RedflagError,
};
use glob::Pattern;
use once_cell::sync::Lazy;
use regex::Regex;
use std::{
    collections::HashSet,
    fs,
    ops::Range,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

const IGNORE_COMMENT_PATTERN: &str = r"(?i)//\s*redflag-ignore(?:-next)?(?:\s+.*)?$";
static IGNORE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(IGNORE_COMMENT_PATTERN).unwrap());

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

#[derive(Default)]
struct SuppressionState {
    ignore_next_line: bool,
}

pub trait FindingHandler {
    fn handle(&mut self, finding: Finding) -> Result<(), RedflagError>;
}

impl Scanner {
    pub fn with_config(config: Config) -> Self {
        let mut patterns = Vec::new();
        let mut seen = HashSet::new();

        // Process all patterns
        for p in config.patterns {
            if seen.contains(&p.name) {
                continue;
            }
            match Regex::new(&p.pattern) {
                Ok(re) => {
                    seen.insert(p.name.clone());
                    patterns.push((re, p.name, p.description, p.severity));
                }
                Err(e) => eprintln!("Invalid pattern {}: {}", p.name, e),
            }
        }

        // Compile exclusion patterns
        let exclusions = config
            .exclusions
            .into_iter()
            .filter_map(|r| match Pattern::new(&r.pattern) {
                Ok(pattern) => Some(ExclusionRule {
                    pattern,
                    policy: r.policy,
                }),
                Err(e) => {
                    eprintln!("Invalid exclusion pattern '{}': {}", r.pattern, e);
                    None
                }
            })
            .collect();

        Scanner {
            patterns,
            entropy_config: config.entropy,
            extensions: config.extensions,
            exclusions,
            show_secrets: false,
        }
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
            for finding in self.scan_line(path, line_num + 1, line, &mut state, commit) {
                if policy == ExclusionPolicy::ScanButWarn {
                    eprintln!("WARNING: Potential secret found but allowed: {finding:?}");
                } else {
                    handler.handle(finding)?;
                    findings_count += 1;
                }
            }
        }
        Ok(findings_count)
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
    let display = if show_secrets {
        text.to_string()
    } else {
        format!(
            "{}[REDACTED]{}",
            &text[..secret_range.start],
            &text[secret_range.end..]
        )
    };
    display.chars().take(50).collect()
}

fn extract_entropy_candidate(line: &str, min_length: usize) -> Option<Range<usize>> {
    for quote in ['"', '\''] {
        let Some(open) = line.find(quote) else {
            continue;
        };
        let value_start = open + quote.len_utf8();
        let Some(close) = line[value_start..].find(quote) else {
            continue;
        };
        let range = value_start..value_start + close;
        if range.len() >= min_length {
            return Some(range);
        }
    }

    let separator = line.find(['=', ':'])?;
    let value_start = separator + 1;
    let value = line[value_start..].trim();
    let value = value.trim_end_matches([',', ';']);
    if value.len() < min_length {
        return None;
    }

    let start = line.find(value)?;
    Some(start..start + value.len())
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
    fn entropy_candidate_tracks_quoted_value() {
        let line = r#"token = "mR7hJ8q$Lz@w!bE5""#;
        let range = extract_entropy_candidate(line, 16).unwrap();

        assert_eq!(&line[range], "mR7hJ8q$Lz@w!bE5");
        assert!(extract_entropy_candidate(r#"token = "short""#, 16).is_none());
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

        let scanner = Scanner::with_config(config);
        let mut handler = TestHandler::default();
        scanner.scan_with_handler(dir.path().to_str().unwrap(), &mut handler)?;

        assert!(!handler.findings.is_empty(), "No findings detected");
        Ok(())
    }
}
