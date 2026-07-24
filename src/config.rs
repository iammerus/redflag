use crate::error::RedflagError;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_patterns")]
    pub patterns: Vec<SecretPattern>,
    #[serde(default = "default_extensions")]
    pub extensions: Vec<String>,
    #[serde(default = "default_exclusions")]
    pub exclusions: Vec<ExclusionRule>,
    #[serde(default)]
    pub entropy: EntropyConfig,
    #[serde(default)]
    pub git: GitConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretPattern {
    pub name: String,
    pub pattern: String,
    pub description: String,
    #[serde(default)]
    pub severity: Severity,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EntropyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    #[serde(default = "default_min_length")]
    pub min_length: usize,
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

static DEFAULT_PATTERNS: Lazy<Vec<SecretPattern>> = Lazy::new(|| {
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
        ExclusionRule {
            pattern: "**/*.test.*".to_string(),
            policy: ExclusionPolicy::ScanButWarn,
        },
        ExclusionRule {
            pattern: "**/*.spec.*".to_string(),
            policy: ExclusionPolicy::ScanButWarn,
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
            branches: vec!["main".to_string(), "master".to_string()],
            since_date: None,
            until_date: None,
        }
    }
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> Result<Self, RedflagError> {
        let mut config = Config::default();

        if let Some(config_path) = path {
            let user_config: Config = toml::from_str(&fs::read_to_string(config_path)?)?;

            // Merge user config with defaults
            config.patterns.extend(user_config.patterns);
            config.extensions.extend(user_config.extensions);
            config.exclusions.extend(user_config.exclusions);

            // Override entropy and git configs if specified
            if user_config.entropy.enabled {
                config.entropy = user_config.entropy;
            }
            if user_config.git.max_depth != default_max_depth()
                || !user_config.git.branches.is_empty()
                || user_config.git.since_date.is_some()
                || user_config.git.until_date.is_some()
            {
                config.git = user_config.git;
            }
        }

        Ok(config)
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
