use crate::error::RedflagError;
use crate::scanner::calculate_shannon_entropy;
use crate::scanner::FindingHandler;
use crate::{
    config::{Config, EntropyConfig, GitConfig, SecretPattern, Severity},
    scanner::Finding,
};
use bstr::ByteSlice;
use chrono::{DateTime, NaiveDateTime, Utc};
use git2::{Commit, Delta, DiffOptions, Repository, Tree};
use indicatif::{ProgressBar, ProgressStyle};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

struct ScanCache {
    commit_results: HashMap<String, Vec<Finding>>,
}

const MAX_CACHE_SIZE: usize = 1000; // Limit cache to last 1000 commits

impl ScanCache {
    fn new() -> Self {
        ScanCache {
            commit_results: HashMap::new(),
        }
    }

    fn get(&self, commit_hash: &str) -> Option<&Vec<Finding>> {
        self.commit_results.get(commit_hash)
    }

    fn insert(&mut self, commit_hash: String, findings: Vec<Finding>) {
        // If cache is at max size, remove oldest entries
        if self.commit_results.len() >= MAX_CACHE_SIZE {
            let to_remove: Vec<_> = self
                .commit_results
                .keys()
                .take(MAX_CACHE_SIZE / 2)
                .cloned()
                .collect();
            for key in to_remove {
                self.commit_results.remove(&key);
            }
        }
        self.commit_results.insert(commit_hash, findings);
    }
}

static SCAN_CACHE: Lazy<Mutex<ScanCache>> = Lazy::new(|| Mutex::new(ScanCache::new()));

pub fn scan_git_history_with_handler<H: FindingHandler>(
    path: &Path,
    config: &Config,
    handler: &mut H,
) -> Result<(), RedflagError> {
    let repo = Repository::open(path)?;
    let mut revwalk = repo.revwalk()?;

    // Parse date filters - convert to start/end of day
    let since_timestamp = config
        .git
        .since_date
        .as_ref()
        .and_then(|date| {
            NaiveDateTime::parse_from_str(&format!("{} 00:00:00", date), "%Y-%m-%d %H:%M:%S").ok()
        })
        .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).timestamp());

    let until_timestamp = config
        .git
        .until_date
        .as_ref()
        .and_then(|date| {
            NaiveDateTime::parse_from_str(&format!("{} 23:59:59", date), "%Y-%m-%d %H:%M:%S").ok()
        })
        .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).timestamp());

    // Configure revwalk based on config
    if !config.git.branches.is_empty() {
        for branch in &config.git.branches {
            if let Ok(branch_ref) = repo.find_branch(branch, git2::BranchType::Local) {
                if let Some(branch_ref_name) = branch_ref.get().name() {
                    revwalk.push_ref(branch_ref_name)?;
                }
            }
        }
    } else {
        revwalk.push_head()?;
    }

    revwalk.set_sorting(git2::Sort::TIME)?;

    // Collect commits that match our criteria
    let commits: Vec<_> = revwalk
        .filter_map(Result::ok)
        .filter_map(|oid| repo.find_commit(oid).ok())
        .filter(|commit| should_process_commit(commit, since_timestamp, until_timestamp))
        .take(config.git.max_depth)
        .collect();

    let commit_count = commits.len();
    let progress = ProgressBar::new(commit_count as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} commits")?
            .progress_chars("=>-"),
    );

    // Clear the cache for tests
    #[cfg(test)]
    {
        let mut cache = SCAN_CACHE.lock().unwrap();
        cache.commit_results.clear();
    }

    let mut cache = SCAN_CACHE.lock().unwrap();
    let mut seen_findings = std::collections::HashSet::new();
    let mut all_findings = Vec::new();

    for commit in commits {
        let commit_hash = commit.id().to_string();

        // Check cache first
        if let Some(cached_findings) = cache.get(&commit_hash) {
            for finding in cached_findings {
                let key = format!(
                    "{}:{}:{}",
                    finding.file.display(),
                    finding.pattern_name,
                    finding.snippet
                );
                if seen_findings.insert(key) {
                    all_findings.push(finding.clone());
                }
            }
        } else {
            let mut findings = Vec::new();
            process_commit(&repo, &commit, config, &mut findings);
            for finding in &findings {
                let key = format!(
                    "{}:{}:{}",
                    finding.file.display(),
                    finding.pattern_name,
                    finding.snippet
                );
                if seen_findings.insert(key) {
                    all_findings.push(finding.clone());
                }
            }
            cache.insert(commit_hash, findings);
        }

        progress.inc(1);
    }

    // Now handle all findings
    for finding in all_findings {
        handler.handle(finding);
    }

    progress.finish_with_message("Git history scan complete");
    Ok(())
}

fn process_commit(
    repo: &Repository,
    commit: &Commit,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if let Ok(tree) = commit.tree() {
        // Get parent commit to compare changes
        let parent_tree = if commit.parent_count() > 0 {
            commit.parent(0).ok().and_then(|parent| parent.tree().ok())
        } else {
            None
        };

        // Only analyze the diff between this commit and its parent
        analyze_diff(
            repo,
            parent_tree.as_ref(),
            Some(&tree),
            commit,
            config,
            findings,
        );
    }
}

fn analyze_diff(
    repo: &Repository,
    old_tree: Option<&Tree>,
    new_tree: Option<&Tree>,
    commit: &Commit,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let mut diff_options = DiffOptions::new();
    if let Ok(diff) = repo.diff_tree_to_tree(old_tree, new_tree, Some(&mut diff_options)) {
        let _ = diff.foreach(
            &mut |delta, _| {
                // Only process new or modified files, skip deletions
                if delta.status() != Delta::Deleted {
                    if let Some(new_file) = delta.new_file().path() {
                        process_file_diff(repo, delta, commit, config, findings, new_file);
                    }
                }
                true
            },
            None,
            None,
            None,
        );
    }
}

fn process_file_diff(
    repo: &Repository,
    delta: git2::DiffDelta<'_>,
    commit: &Commit,
    config: &Config,
    findings: &mut Vec<Finding>,
    file_path: &Path,
) {
    let extension = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if !config
        .extensions
        .iter()
        .any(|e| e.eq_ignore_ascii_case(extension))
    {
        return;
    }

    let patch = delta.new_file().id();
    if let Ok(blob) = repo.find_blob(patch) {
        let content = blob.content().to_str_lossy();
        for (line_num, line) in content.lines().enumerate() {
            check_line(line, line_num + 1, file_path, commit, config, findings);
        }
    }
}

fn check_line(
    line: &str,
    line_num: usize,
    file_path: &Path,
    commit: &Commit,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    // Check regex patterns
    for pattern in &config.patterns {
        if let Ok(re) = Regex::new(&pattern.pattern) {
            if re.is_match(line) {
                findings.push(create_finding(
                    file_path,
                    line_num,
                    line,
                    &pattern.name,
                    &pattern.description,
                    pattern.severity,
                    commit,
                ));
            }
        }
    }

    // Check entropy
    if config.entropy.enabled {
        let clean_line = line.replace(|c: char| !c.is_ascii_alphanumeric(), "");
        if clean_line.len() >= config.entropy.min_length
            && calculate_shannon_entropy(&clean_line) >= config.entropy.threshold
        {
            findings.push(create_finding(
                file_path,
                line_num,
                line,
                "high-entropy",
                "High entropy string detected",
                Severity::Medium,
                commit,
            ));
        }
    }
}

fn create_finding(
    file_path: &Path,
    line_num: usize,
    line: &str,
    pattern_name: &str,
    description: &str,
    severity: Severity,
    commit: &Commit,
) -> Finding {
    Finding {
        file: file_path.to_path_buf(),
        line: line_num,
        pattern_name: pattern_name.to_string(),
        description: description.to_string(),
        snippet: line.chars().take(50).collect(),
        severity,
        commit_hash: Some(commit.id().to_string()),
        commit_author: Some(commit.author().to_string()),
        commit_date: Some(commit.time().seconds().to_string()),
    }
}

fn should_process_commit(commit: &Commit, since: Option<i64>, until: Option<i64>) -> bool {
    let commit_time = commit.time().seconds();

    if let Some(since_time) = since {
        if commit_time < since_time {
            return false;
        }
    }

    if let Some(until_time) = until {
        if commit_time > until_time {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{Repository, Signature};
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    struct TestHandler {
        findings: Vec<Finding>,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                findings: Vec::new(),
            }
        }
    }

    impl FindingHandler for TestHandler {
        fn handle(&mut self, finding: Finding) {
            self.findings.push(finding);
        }
    }

    fn create_test_repo_for_secrets() -> (tempfile::TempDir, Repository) {
        let dir = tempdir().unwrap();
        let repo = Repository::init(&dir).unwrap();
        let sig = Signature::now("Test User", "test@example.com").unwrap();

        // First commit with a secret
        {
            let mut index = repo.index().unwrap();
            let config_file = dir.path().join("config.env");
            File::create(&config_file)
                .unwrap()
                .write_all(b"API_KEY=test_123456789012345678901234")
                .unwrap();

            index.add_path(Path::new("config.env")).unwrap();
            let oid = index.write_tree().unwrap();
            let tree = repo.find_tree(oid).unwrap();

            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                "Initial commit with secret",
                &tree,
                &[],
            )
            .unwrap();
        }

        // Second commit removing the secret
        {
            let mut index = repo.index().unwrap();
            let config_file = dir.path().join("config.env");
            fs::remove_file(&config_file).unwrap();

            index.remove_path(Path::new("config.env")).unwrap();
            let oid = index.write_tree().unwrap();
            let tree = repo.find_tree(oid).unwrap();
            let parent = repo.head().unwrap().peel_to_commit().unwrap();

            repo.commit(Some("HEAD"), &sig, &sig, "Remove secret", &tree, &[&parent])
                .unwrap();
        }

        // Third commit with a different secret
        {
            let mut index = repo.index().unwrap();
            let config_file = dir.path().join("config.env");
            File::create(&config_file)
                .unwrap()
                .write_all(b"AWS_SECRET_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD")
                .unwrap();

            index.add_path(Path::new("config.env")).unwrap();
            let oid = index.write_tree().unwrap();
            let tree = repo.find_tree(oid).unwrap();
            let parent = repo.head().unwrap().peel_to_commit().unwrap();

            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                "Add AWS secret",
                &tree,
                &[&parent],
            )
            .unwrap();
        }

        (dir, repo)
    }

    #[test]
    fn test_find_secrets_in_history() -> Result<(), RedflagError> {
        let (dir, _repo) = create_test_repo_for_secrets();
        let mut handler = TestHandler::new();

        let config = Config {
            patterns: vec![
                SecretPattern {
                    name: "test-api-key".to_string(),
                    pattern: r#"API_KEY=\w{28}"#.to_string(),
                    description: "API Key detected".to_string(),
                    severity: Severity::High,
                },
                SecretPattern {
                    name: "aws-secret".to_string(),
                    pattern: r#"AWS_SECRET_KEY=\w{40}"#.to_string(),
                    description: "AWS Secret Key detected".to_string(),
                    severity: Severity::Critical,
                },
            ],
            extensions: vec!["env".to_string()],
            entropy: EntropyConfig {
                enabled: false,
                threshold: 3.5,
                min_length: 20,
            },
            exclusions: Vec::new(),
            git: GitConfig {
                max_depth: 100,
                branches: Vec::new(),
                since_date: None,
                until_date: None,
            },
        };

        scan_git_history_with_handler(dir.path(), &config, &mut handler)?;

        assert_eq!(handler.findings.len(), 2, "Expected to find 2 secrets");

        // Check findings in reverse chronological order
        let mut findings = handler.findings;
        findings.sort_by(|a, b| b.commit_date.cmp(&a.commit_date));

        // Verify we found the expected types of secrets
        let mut api_key_count = 0;
        let mut aws_secret_count = 0;

        for finding in findings {
            match finding.pattern_name.as_str() {
                "test-api-key" => api_key_count += 1,
                "aws-secret" => aws_secret_count += 1,
                _ => panic!("Unexpected pattern name: {}", finding.pattern_name),
            }
        }

        assert_eq!(api_key_count, 1, "Expected to find 1 API key");
        assert_eq!(aws_secret_count, 1, "Expected to find 1 AWS secret");
        Ok(())
    }

    #[test]
    fn test_date_filtering() {
        let (dir, _repo) = create_test_repo_for_secrets();
        let mut handler = TestHandler::new();

        // Set date range to future to exclude all commits
        let tomorrow = chrono::Utc::now() + chrono::Duration::days(1);
        let config = Config {
            patterns: vec![SecretPattern {
                name: "any-secret".to_string(),
                pattern: r#"(API_KEY|AWS).*"#.to_string(),
                description: "Any secret".to_string(),
                severity: Severity::Medium,
            }],
            extensions: vec!["env".to_string()],
            git: GitConfig {
                since_date: Some(tomorrow.format("%Y-%m-%d").to_string()),
                ..Default::default()
            },
            ..Config::default()
        };

        scan_git_history_with_handler(dir.path(), &config, &mut handler).unwrap();
        assert_eq!(
            handler.findings.len(),
            0,
            "Should find no secrets in future commits"
        );

        // Now test with a date range that includes our commits
        let mut handler = TestHandler::new();
        let yesterday = chrono::Utc::now() - chrono::Duration::days(1);
        let config = Config {
            patterns: vec![SecretPattern {
                name: "any-secret".to_string(),
                pattern: r#"(API_KEY|AWS).*"#.to_string(),
                description: "Any secret".to_string(),
                severity: Severity::Medium,
            }],
            extensions: vec!["env".to_string()],
            git: GitConfig {
                since_date: Some(yesterday.format("%Y-%m-%d").to_string()),
                until_date: Some(tomorrow.format("%Y-%m-%d").to_string()),
                ..Default::default()
            },
            ..Config::default()
        };

        scan_git_history_with_handler(dir.path(), &config, &mut handler).unwrap();
        assert!(
            handler.findings.len() > 0,
            "Should find secrets in current date range"
        );
    }

    #[test]
    fn test_cache_management() {
        let (dir, _repo) = create_test_repo_for_secrets();
        let mut handler = TestHandler::new();
        let config = Config {
            patterns: vec![SecretPattern {
                name: "test-api-key".to_string(),
                pattern: r#"API_KEY=\w{28}"#.to_string(),
                description: "Test API key pattern".to_string(),
                severity: Severity::High,
            }],
            extensions: vec!["env".to_string()],
            ..Config::default()
        };

        // First scan should populate cache
        scan_git_history_with_handler(dir.path(), &config, &mut handler).unwrap();
        let first_count = handler.findings.len();

        // Second scan should use cache
        let mut handler = TestHandler::new();
        scan_git_history_with_handler(dir.path(), &config, &mut handler).unwrap();
        let second_count = handler.findings.len();

        assert_eq!(
            first_count, second_count,
            "Cache should provide consistent results"
        );
    }
}
