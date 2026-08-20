use crate::error::RedflagError;
use chrono::NaiveDate;
#[cfg(test)]
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Config {
    pub patterns: Vec<SecretPattern>,
    pub extensions: Vec<String>,
    pub exclusions: Vec<ExclusionRule>,
    pub entropy: EntropyConfig,
    pub git: GitConfig,
    pub limits: ScanLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanLimits {
    /// Maximum UTF-8 content bytes in one source line, excluding CR/LF.
    pub max_line_bytes: usize,
    pub max_file_bytes: u64,
    pub max_files: usize,
    /// Maximum total bytes selected for an artifact scan.
    pub max_total_bytes: u64,
    pub engine_timeout_seconds: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: 16 * 1024 * 1024,
            max_file_bytes: 64 * 1024 * 1024,
            max_files: 100_000,
            max_total_bytes: 1024 * 1024 * 1024,
            engine_timeout_seconds: 120,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct GitConfig {
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    #[serde(default)]
    pub branches: Vec<String>,
    #[serde(default)]
    pub since_date: Option<String>,
    #[serde(default)]
    pub until_date: Option<String>,
    #[serde(skip)]
    pub(crate) since_timestamp: Option<i64>,
    #[serde(skip)]
    pub(crate) until_timestamp: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
pub enum ExclusionPolicy {
    #[default]
    Ignore,
    ScanButWarn,
    ScanButAllow,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ExclusionRule {
    pub pattern: String,
    pub policy: ExclusionPolicy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum Severity {
    Critical,
    High,
    #[default]
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SecretPattern {
    pub name: String,
    pub pattern: String,
    pub description: String,
    #[serde(default)]
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntropyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    #[serde(default = "default_min_length")]
    pub min_length: usize,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialConfig {
    #[serde(default)]
    patterns: Vec<SecretPattern>,
    #[serde(default)]
    extensions: Vec<String>,
    #[serde(default)]
    exclusions: Vec<ExclusionRule>,
    entropy: Option<EntropyConfig>,
    git: Option<GitConfig>,
    limits: Option<ScanLimits>,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        EntropyConfig {
            enabled: default_true(),
            threshold: default_threshold(),
            min_length: default_min_length(),
        }
    }
}

// Capture the complete literal, including its quotes, so validation and redaction
// never operate on a truncated prefix. Custom rules may also capture `secret`.
const LITERAL: &str = r#"(?P<secret>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|\$\{[^{}\r\n]*\}|[^\s"'`,;}\]]+)"#;

fn assignment_pattern(key: &str, operator: &str) -> String {
    format!(r#"(?i)(?P<key>{key})["'`]?\s*(?:{operator})\s*{LITERAL}"#)
}

fn fallback_pattern(key: &str, source: &str) -> String {
    format!(r#"(?i)(?P<key>{key})["'`]?\s*(?::|=)\s*(?:{source})\s*(?:\|\||\?\?)\s*{LITERAL}"#)
}

static DEFAULT_PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    let rule = |name: &str, pattern: String, description: &str, severity| SecretPattern {
        name: name.to_string(),
        pattern,
        description: description.to_string(),
        severity,
    };
    let environment = r"process\.env\.[A-Za-z0-9_]+";
    let expression = r"[^,;\r\n]+?";
    vec![
        rule("AWS Access Key",
            r"(?P<secret>(?:AKIA|ASIA)[A-Z0-9]{16})".to_string(),
            "AWS Access Key ID detected", Severity::Critical),
        rule("AWS Secret Key",
            assignment_pattern(r"(?:AWS|AMAZON)_?SECRET_?(?:ACCESS_?)?KEY", ":=|=>|=|:"),
            "AWS Secret Access Key detected", Severity::Critical),
        rule("AWS Key in Object", assignment_pattern("key", ":"),
            "AWS Access Key ID in object property detected", Severity::Critical),
        rule("AWS Secret in Object", assignment_pattern("secret", ":"),
            "Possible AWS Secret Access Key in object property", Severity::High),
        rule("AWS Direct Key Assignment", fallback_pattern("key", environment),
            "AWS Access Key ID with direct assignment detected", Severity::Critical),
        rule("AWS Direct Secret Assignment", fallback_pattern("secret", environment),
            "Possible AWS Secret Access Key with direct assignment", Severity::High),
        rule("AWS Access Key with Fallback", fallback_pattern("key", expression),
            "AWS Access Key ID with environment fallback detected", Severity::Critical),
        rule("AWS Secret with Fallback", fallback_pattern("secret", expression),
            "Possible AWS Secret Access Key with environment fallback", Severity::High),
        rule("Password with Fallback", fallback_pattern("password|passwd|pwd", expression),
            "Possible hardcoded password with environment fallback", Severity::High),
        rule("Generic Fallback Secret", fallback_pattern(r"secret|token|credential|api[_\-\s]*key", environment),
            "Possible hardcoded secret with environment fallback", Severity::High),
        rule("GitHub Token",
            r"(?P<secret>gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})".to_string(),
            "GitHub token detected", Severity::Critical),
        rule("Stripe Secret Key",
            r"(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,})".to_string(),
            "Stripe secret or restricted API key detected", Severity::Critical),
        rule("npm Access Token", r"(?P<secret>npm_[A-Za-z0-9]{36})".to_string(),
            "npm access token detected", Severity::Critical),
        rule("Generic API Key", assignment_pattern(r"api[_\-\s]*key", ":=|=>|=|:"),
            "Generic API key detected", Severity::High),
        rule("Private Key",
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----".to_string(),
            "Private key file detected", Severity::Critical),
        rule("Password Assignment", assignment_pattern("password|passwd|pwd", ":=|=>|="),
            "Possible hardcoded password", Severity::High),
        rule("Password in Object", assignment_pattern("password|passwd|pwd", ":"),
            "Possible hardcoded password in object property", Severity::High),
        rule("Netrc Password", format!(r"(?i)\bpassword\s+{LITERAL}"),
            "Password in netrc credentials file", Severity::High),
        rule("Database Connection String",
            r#"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^\s<>/:'"`]+:[^\s<>@'"`]+@[^\s<>'"`]+"#.to_string(),
            "Database connection string with password detected", Severity::Critical),
        rule("JWT Token",
            r"(?P<secret>eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)".to_string(),
            "JWT token detected", Severity::High),
    ]
});

fn default_patterns() -> Vec<SecretPattern> {
    DEFAULT_PATTERNS.clone()
}

pub(crate) fn is_default_pattern(pattern: &SecretPattern) -> bool {
    DEFAULT_PATTERNS
        .iter()
        .any(|default| default.name == pattern.name && default.pattern == pattern.pattern)
}

fn default_extensions() -> Vec<String> {
    vec![
        "php".to_string(),
        "js".to_string(),
        "ts".to_string(),
        "jsx".to_string(),
        "tsx".to_string(),
        "py".to_string(),
        "rb".to_string(),
        "java".to_string(),
        "go".to_string(),
        "rs".to_string(),
        "cs".to_string(),
        "cpp".to_string(),
        "c".to_string(),
        "h".to_string(),
        "hpp".to_string(),
        "xml".to_string(),
        "yaml".to_string(),
        "yml".to_string(),
        "json".to_string(),
        "config".to_string(),
        "conf".to_string(),
        "ini".to_string(),
        "env".to_string(),
        "properties".to_string(),
        "toml".to_string(),
        "sql".to_string(),
        "md".to_string(),
        "txt".to_string(),
        "sh".to_string(),
        "bash".to_string(),
        "zsh".to_string(),
        "tf".to_string(),
        "tfvars".to_string(),
        "hcl".to_string(),
        "pem".to_string(),
        "key".to_string(),
        "map".to_string(),
        "mjs".to_string(),
        "cjs".to_string(),
    ]
}

fn default_exclusions() -> Vec<ExclusionRule> {
    vec![
        // Package manager folders
        ExclusionRule {
            pattern: "**/node_modules/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/vendor/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/.git/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/target/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        // Additional package manager folders
        ExclusionRule {
            pattern: "**/.venv/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/venv/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/__pypackages__/**".to_string(), // PDM package folder
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/.renv/**".to_string(), // R environment
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/.cargo/**".to_string(), // Rust cargo cache
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/.gradle/**".to_string(), // Gradle cache
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/.m2/**".to_string(), // Maven repository
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/bower_components/**".to_string(), // Bower components
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/.bundle/**".to_string(), // Ruby bundle
            policy: ExclusionPolicy::Ignore,
        },
        // Other common directories to ignore
        ExclusionRule {
            pattern: "**/coverage/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/__pycache__/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/.pytest_cache/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/.cache/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
    ]
}

fn default_true() -> bool {
    true
}
fn default_threshold() -> f64 {
    4.8
}
fn default_min_length() -> usize {
    30
}

fn default_max_depth() -> usize {
    1000
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            max_depth: default_max_depth(),
            branches: Vec::new(),
            since_date: None,
            until_date: None,
            since_timestamp: None,
            until_timestamp: None,
        }
    }
}

impl Config {
    /// Find the nearest policy up to the repository boundary. Callers choose the
    /// search origin: source target for source scans, cwd for publication scans.
    pub fn resolve_path(
        explicit: Option<PathBuf>,
        start: &Path,
        no_config: bool,
    ) -> Result<Option<PathBuf>, RedflagError> {
        if let Some(path) = explicit {
            return fs::canonicalize(&path)
                .map(Some)
                .map_err(|source| RedflagError::PathIo { path, source });
        }
        if no_config {
            return Ok(None);
        }
        let mut directory = fs::canonicalize(start).map_err(|source| RedflagError::PathIo {
            path: start.to_path_buf(),
            source,
        })?;
        if directory.is_file() {
            directory.pop();
        }
        loop {
            let candidate = directory.join("redflag.toml");
            match fs::symlink_metadata(&candidate) {
                Ok(_) => return Ok(Some(candidate)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(RedflagError::PathIo {
                        path: candidate,
                        source,
                    })
                }
            }
            match fs::symlink_metadata(directory.join(".git")) {
                Ok(_) => return Ok(None),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(RedflagError::PathIo {
                        path: directory.join(".git"),
                        source,
                    })
                }
            }
            if !directory.pop() {
                return Ok(None);
            }
        }
    }

    pub fn load(path: Option<PathBuf>) -> Result<Self, RedflagError> {
        match path {
            Some(path) => Self::from_toml(&fs::read_to_string(path)?),
            None => Self::from_toml(""),
        }
    }

    pub(crate) fn from_toml(content: &str) -> Result<Self, RedflagError> {
        let mut config = Config::default();
        let user: PartialConfig = toml::from_str(content)?;

        for pattern in user.patterns {
            if let Some(existing) = config
                .patterns
                .iter()
                .position(|current| current.name == pattern.name)
            {
                config.patterns[existing] = pattern;
            } else {
                config.patterns.push(pattern);
            }
        }
        for extension in user.extensions {
            if !config
                .extensions
                .iter()
                .any(|current| current.eq_ignore_ascii_case(&extension))
            {
                config.extensions.push(extension);
            }
        }
        for exclusion in user.exclusions {
            // Keep the last occurrence at its original precedence. Removing
            // a later duplicate can leave an intervening Ignore rule active.
            config.exclusions.retain(|existing| existing != &exclusion);
            config.exclusions.push(exclusion);
        }
        if let Some(entropy) = user.entropy {
            config.entropy = entropy;
        }
        if let Some(git) = user.git {
            config.git = git;
        }
        if let Some(limits) = user.limits {
            config.limits = limits;
        }
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&mut self) -> Result<(), RedflagError> {
        if self.limits.engine_timeout_seconds == 0 {
            return Err(RedflagError::Config(
                "limits.engine_timeout_seconds must be positive".into(),
            ));
        }
        // Regexes and globs are validated by compiling them once in Scanner.
        if self.limits.max_line_bytes == 0 || self.limits.max_line_bytes.checked_add(3).is_none() {
            return Err(RedflagError::Config(
                "limits.max_line_bytes must be positive and leave room for a line terminator"
                    .to_string(),
            ));
        }
        if self.limits.max_file_bytes == 0
            || self.limits.max_files == 0
            || self.limits.max_total_bytes == 0
        {
            return Err(RedflagError::Config(
                "limits.max_file_bytes, limits.max_files and limits.max_total_bytes must be positive".to_string(),
            ));
        }
        if !(0.0..=8.0).contains(&self.entropy.threshold) {
            return Err(RedflagError::Config(
                "Entropy threshold must be between 0.0 and 8.0".to_string(),
            ));
        }
        if self.entropy.min_length == 0 {
            return Err(RedflagError::Config(
                "Entropy minimum length must be greater than zero".to_string(),
            ));
        }
        if self.git.max_depth == 0 {
            return Err(RedflagError::Config(
                "Git maximum depth must be greater than zero".to_string(),
            ));
        }

        let since = parse_date("git.since_date", self.git.since_date.as_deref())?;
        let until = parse_date("git.until_date", self.git.until_date.as_deref())?;
        if since.zip(until).is_some_and(|(start, end)| start > end) {
            return Err(RedflagError::Config(
                "git.since_date must not be after git.until_date".to_string(),
            ));
        }
        self.git.since_timestamp = since
            .and_then(|date| date.and_hms_opt(0, 0, 0))
            .map(|date| date.and_utc().timestamp());
        self.git.until_timestamp = until
            .and_then(|date| date.and_hms_opt(23, 59, 59))
            .map(|date| date.and_utc().timestamp());
        if let Some(branch) = self.git.branches.iter().find(|branch| branch.is_empty()) {
            return Err(RedflagError::Config(format!(
                "Git revision must not be empty: '{branch}'"
            )));
        }
        Ok(())
    }

    pub fn save(&self, path: &PathBuf) -> Result<(), RedflagError> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn generate_default_config(path: &PathBuf) -> Result<(), RedflagError> {
        let default_config = Config::default();
        default_config.save(path)
    }
}

fn parse_date(name: &str, value: Option<&str>) -> Result<Option<NaiveDate>, RedflagError> {
    value
        .map(|date| {
            if date.len() != 10 {
                return Err(RedflagError::Config(format!(
                    "{name} must use YYYY-MM-DD: '{date}'"
                )));
            }
            NaiveDate::parse_from_str(date, "%Y-%m-%d")
                .map_err(|_| RedflagError::Config(format!("{name} must use YYYY-MM-DD: '{date}'")))
        })
        .transpose()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            patterns: default_patterns(),
            extensions: default_extensions(),
            exclusions: default_exclusions(),
            entropy: EntropyConfig::default(),
            git: GitConfig::default(),
            limits: ScanLimits::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn load(contents: &str) -> Result<Config, RedflagError> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("redflag.toml");
        fs::write(&path, contents).unwrap();
        let config = Config::load(Some(path))?;
        crate::scanner::Scanner::with_config(config.clone())?;
        Ok(config)
    }

    #[test]
    fn present_entropy_section_replaces_defaults() {
        let disabled = load("[entropy]\nenabled = false\n").unwrap();
        assert!(!disabled.entropy.enabled);

        let partial = load("[entropy]\nthreshold = 3.2\n").unwrap();
        assert!(partial.entropy.enabled);
        assert_eq!(partial.entropy.threshold, 3.2);
        assert_eq!(partial.entropy.min_length, default_min_length());
    }

    #[test]
    fn custom_patterns_replace_by_name() {
        let config = load(
            r#"
[[patterns]]
name = "Generic API Key"
pattern = "custom"
description = "Custom rule"
severity = "Low"
"#,
        )
        .unwrap();
        let patterns: Vec<_> = config
            .patterns
            .iter()
            .filter(|pattern| pattern.name == "Generic API Key")
            .collect();

        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].pattern, "custom");
        assert_eq!(patterns[0].severity, Severity::Low);
    }

    #[test]
    fn fallback_secret_requires_secret_field() {
        let pattern = default_patterns()
            .into_iter()
            .find(|pattern| pattern.name == "Generic Fallback Secret")
            .unwrap();
        let regex = Regex::new(&pattern.pattern).unwrap();
        let fallback = ["development-", "secret"].concat();
        let source = [
            "client",
            "Secret: process.env.CLIENT_SECRET || \"",
            &fallback,
            "\"",
        ]
        .concat();

        assert!(regex.is_match(&source));
        assert!(!regex.is_match(r#"baseURL: process.env.BASE_URL || "http://127.0.0.1:8000""#));
    }

    #[test]
    fn aws_secret_requires_credential_name() {
        let pattern = default_patterns()
            .into_iter()
            .find(|pattern| pattern.name == "AWS Secret Key")
            .unwrap();
        let regex = Regex::new(&pattern.pattern).unwrap();
        let value = ["ABCDEFGHIJKLMNOPQRST", "UVWXYZ0123456789ABCD"].concat();

        assert!(regex.is_match(&format!("AWS_SECRET_ACCESS_KEY={value}")));
        assert!(!regex.is_match(&format!(r#"integrity="sha512-aAWS{value}""#)));
    }

    #[test]
    fn extensions_are_deduplicated() {
        let config = load("extensions = [\"RS\", \"custom\"]\n").unwrap();

        assert_eq!(
            config
                .extensions
                .iter()
                .filter(|extension| extension.eq_ignore_ascii_case("rs"))
                .count(),
            1
        );
        assert!(config.extensions.contains(&"custom".to_string()));
    }

    #[test]
    fn invalid_values_are_rejected() {
        for (contents, expected) in [
            (
                r#"[[patterns]]
name = "broken"
pattern = "["
description = "Broken"
"#,
                "Invalid regex",
            ),
            (
                r#"[[exclusions]]
pattern = "["
policy = "Ignore"
"#,
                "Invalid exclusion glob",
            ),
            ("[git]\nsince_date = \"24-07-2026\"\n", "YYYY-MM-DD"),
            (
                "[git]\nsince_date = \"2026-07-25\"\nuntil_date = \"2026-07-24\"\n",
                "must not be after",
            ),
            ("[entropy]\nthreshold = 9.0\n", "between 0.0 and 8.0"),
        ] {
            let error = load(contents).unwrap_err().to_string();
            assert!(error.contains(expected), "Unexpected error: {error}");
        }
    }

    #[test]
    fn generated_config_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("redflag.toml");
        Config::generate_default_config(&path).unwrap();

        assert_eq!(Config::load(Some(path)).unwrap(), Config::default());
    }
}
