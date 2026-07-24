use crate::error::RedflagError;
use chrono::NaiveDate;
use glob::Pattern;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Config {
    pub patterns: Vec<SecretPattern>,
    pub extensions: Vec<String>,
    pub exclusions: Vec<ExclusionRule>,
    pub entropy: EntropyConfig,
    pub git: GitConfig,
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
struct PartialConfig {
    #[serde(default)]
    patterns: Vec<SecretPattern>,
    #[serde(default)]
    extensions: Vec<String>,
    #[serde(default)]
    exclusions: Vec<ExclusionRule>,
    entropy: Option<EntropyConfig>,
    git: Option<GitConfig>,
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

static DEFAULT_PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    vec![
        SecretPattern {
            name: "AWS Access Key".to_string(),
            pattern: r"(?i)(AWS|AMAZON)_?(ACCESS|SECRET)?_?(KEY)?_?ID\s*=?\s*[A-Z0-9]{20}".to_string(),
            description: "AWS Access Key ID detected".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "AWS Secret Key".to_string(),
            pattern: r"(?i)(AWS|AMAZON)_?(ACCESS|SECRET)?_?(KEY)?\s*=?\s*[A-Za-z0-9/+=]{40}".to_string(),
            description: "AWS Secret Access Key detected".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "AWS Key in Object".to_string(),
            pattern: r#"key\s*:\s*['""]AKIA[A-Z0-9]{16}['""]"#.to_string(),
            description: "AWS Access Key ID in object property detected".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "AWS Secret in Object".to_string(),
            pattern: r#"secret\s*:\s*['""][A-Za-z0-9/+=]{40}['""]"#.to_string(),
            description: "AWS Secret Access Key in object property detected".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "AWS Direct Key Assignment".to_string(),
            pattern: r#"key\s*:\s*process\.env\.AWS_ACCESS_KEY_ID\s*\|\|\s*['"]AKIA[A-Z0-9]{16}['"]"#.to_string(),
            description: "AWS Access Key ID with direct assignment detected".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "AWS Direct Secret Assignment".to_string(),
            pattern: r#"secret\s*:\s*process\.env\.AWS_SECRET_ACCESS_KEY\s*\|\|\s*['"][A-Za-z0-9/+=]{40}['"]"#.to_string(),
            description: "AWS Secret Access Key with direct assignment detected".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "AWS Access Key with Fallback".to_string(),
            pattern: r#"(?i)key\s*:\s*.*\|\|\s*['"]AKIA[A-Z0-9]{16}['"]"#.to_string(),
            description: "AWS Access Key ID with environment fallback detected".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "AWS Secret with Fallback".to_string(),
            pattern: r#"(?i)secret\s*:\s*.*\|\|\s*['"][A-Za-z0-9/+=]{40}['"]"#.to_string(),
            description: "AWS Secret Access Key with environment fallback detected".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Password with Fallback".to_string(),
            pattern: r#"(?i)(password|passwd|pwd)\s*:\s*.*\|\|\s*['""][^'""]{8,}['""]"#.to_string(),
            description: "Possible hardcoded password with environment fallback".to_string(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "Generic Fallback Secret".to_string(),
            pattern: r#"(?i):\s*process\.env\.[A-Za-z0-9_]+\s*\|\|\s*['""][^'""]{8,}['""]"#.to_string(),
            description: "Possible hardcoded secret with environment fallback".to_string(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "GitHub Token".to_string(),
            pattern: r"(?i)github[_\-\s]*(pat|token|key)\s*=?\s*gh[pousr]_[a-zA-Z0-9]{36}".to_string(),
            description: "GitHub Personal Access Token detected".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Generic API Key".to_string(),
            pattern: r#"(?i)api[_\-\s]*key\s*=?\s*['""][a-zA-Z0-9]{32,}['""]"#.to_string(),
            description: "Generic API key detected".to_string(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "Private Key".to_string(),
            pattern: r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE\s+KEY(\s+ENCRYPTED)?-----".to_string(),
            description: "Private key file detected".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Password Assignment".to_string(),
            pattern: r#"(?i)(password|passwd|pwd)\s*=\s*['""][^'""]{8,}['""]"#.to_string(),
            description: "Possible hardcoded password".to_string(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "Password in Object".to_string(),
            pattern: r#"(?i)(password|passwd|pwd)\s*:\s*['""][^'""]{8,}['""]"#.to_string(),
            description: "Possible hardcoded password in object property".to_string(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "Database Connection String".to_string(),
            pattern: r#"(?i)(mongodb|postgresql|mysql)://[^\s<>'"""]+"#.to_string(),
            description: "Database connection string detected".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "JWT Token".to_string(),
            pattern: r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*".to_string(),
            description: "JWT token detected".to_string(),
            severity: Severity::High,
        },
    ]
});

fn default_patterns() -> Vec<SecretPattern> {
    DEFAULT_PATTERNS.clone()
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
        ExclusionRule {
            pattern: "**/dist/**".to_string(),
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
            pattern: "**/.env/**".to_string(), // Python virtual env folder
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/env/**".to_string(), // Python virtual env folder
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
        // Package lock files
        ExclusionRule {
            pattern: "**/package-lock.json".to_string(), // npm
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/yarn.lock".to_string(), // yarn
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/pnpm-lock.yaml".to_string(), // pnpm
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/Cargo.lock".to_string(), // Rust
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/Gemfile.lock".to_string(), // Ruby
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/poetry.lock".to_string(), // Python Poetry
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/composer.lock".to_string(), // PHP
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/go.sum".to_string(), // Go
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/flake.lock".to_string(), // Nix
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/bun.lockb".to_string(), // Bun
            policy: ExclusionPolicy::Ignore,
        },
        // Build directories
        ExclusionRule {
            pattern: "**/build/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/out/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/.next/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/.nuxt/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        // Other common directories to ignore
        ExclusionRule {
            pattern: "**/.idea/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
        ExclusionRule {
            pattern: "**/.vscode/**".to_string(),
            policy: ExclusionPolicy::Ignore,
        },
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
        ExclusionRule {
            pattern: "**/*.min.js".to_string(),
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
        }
    }
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> Result<Self, RedflagError> {
        let mut config = Config::default();

        if let Some(config_path) = path {
            let user: PartialConfig = toml::from_str(&fs::read_to_string(config_path)?)?;

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
                if !config.exclusions.contains(&exclusion) {
                    config.exclusions.push(exclusion);
                }
            }
            if let Some(entropy) = user.entropy {
                config.entropy = entropy;
            }
            if let Some(git) = user.git {
                config.git = git;
            }
        }

        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<(), RedflagError> {
        for pattern in &self.patterns {
            Regex::new(&pattern.pattern).map_err(|error| {
                RedflagError::Config(format!("Invalid regex for '{}': {error}", pattern.name))
            })?;
        }
        for exclusion in &self.exclusions {
            Pattern::new(&exclusion.pattern).map_err(|error| {
                RedflagError::Config(format!(
                    "Invalid exclusion glob '{}': {error}",
                    exclusion.pattern
                ))
            })?;
        }
        if !self.entropy.threshold.is_finite() || self.entropy.threshold < 0.0 {
            return Err(RedflagError::Config(
                "Entropy threshold must be finite and nonnegative".to_string(),
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
        Config::load(Some(path))
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
