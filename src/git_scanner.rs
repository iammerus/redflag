use crate::{
    config::GitConfig,
    error::RedflagError,
    scanner::{CommitMetadata, FindingHandler, ScanStats, Scanner},
};
use bstr::ByteSlice;
use chrono::{DateTime, NaiveDateTime, Utc};
use git2::{Commit, Delta, DiffOptions, Repository};
use std::path::Path;

pub fn scan_git_history_with_handler<H: FindingHandler>(
    path: &Path,
    scanner: &Scanner,
    config: &GitConfig,
    handler: &mut H,
) -> Result<ScanStats, RedflagError> {
    let repo = Repository::open(path)?;
    let mut revwalk = repo.revwalk()?;

    let since_timestamp = config
        .since_date
        .as_ref()
        .and_then(|date| {
            NaiveDateTime::parse_from_str(&format!("{date} 00:00:00"), "%Y-%m-%d %H:%M:%S").ok()
        })
        .map(|date| DateTime::<Utc>::from_naive_utc_and_offset(date, Utc).timestamp());
    let until_timestamp = config
        .until_date
        .as_ref()
        .and_then(|date| {
            NaiveDateTime::parse_from_str(&format!("{date} 23:59:59"), "%Y-%m-%d %H:%M:%S").ok()
        })
        .map(|date| DateTime::<Utc>::from_naive_utc_and_offset(date, Utc).timestamp());

    if config.branches.is_empty() {
        revwalk.push_head()?;
    } else {
        for branch in &config.branches {
            if let Ok(branch_ref) = repo.find_branch(branch, git2::BranchType::Local) {
                if let Some(name) = branch_ref.get().name() {
                    revwalk.push_ref(name)?;
                }
            }
        }
    }
    revwalk.set_sorting(git2::Sort::TIME)?;

    let mut stats = ScanStats::default();
    let mut inspected = 0;
    for oid in revwalk {
        let commit = repo.find_commit(oid?)?;
        if !should_process_commit(&commit, since_timestamp, until_timestamp) {
            continue;
        }
        if inspected == config.max_depth {
            break;
        }
        let commit_stats = process_commit(&repo, &commit, scanner, handler)?;
        stats.files += commit_stats.files;
        stats.findings += commit_stats.findings;
        inspected += 1;
    }
    Ok(stats)
}

fn process_commit<H: FindingHandler>(
    repo: &Repository,
    commit: &Commit,
    scanner: &Scanner,
    handler: &mut H,
) -> Result<ScanStats, RedflagError> {
    let tree = commit.tree()?;
    let parent_tree = if commit.parent_count() > 0 {
        Some(commit.parent(0)?.tree()?)
    } else {
        None
    };
    let mut options = DiffOptions::new();
    let diff = repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut options))?;
    let metadata = CommitMetadata {
        hash: commit.id().to_string(),
        author: commit.author().to_string(),
        date: DateTime::<Utc>::from_timestamp(commit.time().seconds(), 0)
            .map(|date| date.to_rfc3339())
            .unwrap_or_else(|| commit.time().seconds().to_string()),
    };

    let mut stats = ScanStats::default();
    for delta in diff.deltas() {
        if delta.status() == Delta::Deleted {
            continue;
        }
        let Some(path) = delta.new_file().path() else {
            continue;
        };
        if !scanner.should_scan_path(path) {
            continue;
        }

        let blob = repo.find_blob(delta.new_file().id())?;
        let content = blob.content().to_str_lossy();
        stats.findings +=
            scanner.scan_content_with_handler(path, &content, Some(&metadata), handler)?;
        stats.files += 1;
    }
    Ok(stats)
}

fn should_process_commit(commit: &Commit, since: Option<i64>, until: Option<i64>) -> bool {
    let commit_time = commit.time().seconds();
    since.is_none_or(|start| commit_time >= start) && until.is_none_or(|end| commit_time <= end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Config, EntropyConfig, GitConfig, SecretPattern, Severity},
        scanner::Finding,
    };
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
        fn handle(&mut self, finding: Finding) -> Result<(), RedflagError> {
            self.findings.push(finding);
            Ok(())
        }
    }

    fn scan(
        path: &Path,
        config: &Config,
        handler: &mut TestHandler,
    ) -> Result<ScanStats, RedflagError> {
        let scanner = Scanner::with_config(config.clone())?;
        scan_git_history_with_handler(path, &scanner, &config.git, handler)
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

        scan(dir.path(), &config, &mut handler)?;

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

        scan(dir.path(), &config, &mut handler).unwrap();
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

        scan(dir.path(), &config, &mut handler).unwrap();
        assert!(
            !handler.findings.is_empty(),
            "Should find secrets in current date range"
        );
    }

    #[test]
    fn repeated_scans_are_consistent() {
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

        scan(dir.path(), &config, &mut handler).unwrap();
        let first_count = handler.findings.len();

        let mut handler = TestHandler::new();
        scan(dir.path(), &config, &mut handler).unwrap();
        let second_count = handler.findings.len();

        assert_eq!(
            first_count, second_count,
            "Repeated scans should provide consistent results"
        );
    }

    #[test]
    fn working_tree_and_history_use_the_same_detector() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(&dir).unwrap();
        let signature = Signature::now("Test User", "test@example.com").unwrap();
        fs::write(
            dir.path().join("secret.rs"),
            "// redflag-ignore-next\napi_key = \"ignored_value_12345678901234567890\"\n\
             api_key = \"reported_value_1234567890123456789\"\n",
        )
        .unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("secret.rs")).unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Add secret",
            &tree,
            &[],
        )
        .unwrap();

        let config = Config {
            patterns: vec![SecretPattern {
                name: "api-key".to_string(),
                pattern: r#"api_key\s*=\s*"[^"]+""#.to_string(),
                description: "API key detected".to_string(),
                severity: Severity::High,
            }],
            extensions: vec!["rs".to_string()],
            exclusions: Vec::new(),
            entropy: EntropyConfig {
                enabled: false,
                ..Default::default()
            },
            git: GitConfig {
                branches: Vec::new(),
                ..Default::default()
            },
        };
        let scanner = Scanner::with_config(config.clone()).unwrap();
        let mut working = TestHandler::new();
        scanner
            .scan_with_handler(dir.path().to_str().unwrap(), &mut working)
            .unwrap();
        let mut history = TestHandler::new();
        scan_git_history_with_handler(dir.path(), &scanner, &config.git, &mut history).unwrap();

        assert_eq!(working.findings.len(), 1);
        assert_eq!(history.findings.len(), 1);
        let working = &working.findings[0];
        let history = &history.findings[0];
        assert_eq!(working.pattern_name, history.pattern_name);
        assert_eq!(working.description, history.description);
        assert_eq!(working.severity, history.severity);
        assert_eq!(working.snippet, history.snippet);
    }
}
