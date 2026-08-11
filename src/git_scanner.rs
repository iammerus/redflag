use crate::{
    config::{ExclusionPolicy, GitConfig},
    error::RedflagError,
    scanner::{
        CommitMetadata, ContentLine, FindingHandler, ScanProgress, ScanStats, Scanner,
        SuppressionState,
    },
};
use chrono::{DateTime, Utc};
use git2::{Commit, DiffOptions, Oid, Patch, Repository, Revwalk, Sort};
use std::path::Path;

pub(crate) struct HistoryScan {
    repo: Repository,
    commits: Vec<Oid>,
}

impl HistoryScan {
    /// Resolve the complete requested history before emitting any scan results.
    pub(crate) fn prepare(path: &Path, config: &GitConfig) -> Result<Self, RedflagError> {
        let repo = Repository::open(path)?;
        if repo.is_shallow() {
            return Err(RedflagError::Incomplete(
                "Git history is shallow. Fetch the full history (actions/checkout fetch-depth: 0) and retry."
                    .to_string(),
            ));
        }
        let mut revwalk = repo.revwalk()?;
        push_revisions(&repo, &mut revwalk, config)?;
        revwalk.set_sorting(Sort::TOPOLOGICAL | Sort::TIME)?;
        let mut commits = Vec::new();
        for (index, oid) in revwalk.enumerate() {
            let oid = oid?;
            if index >= config.max_depth {
                return Err(RedflagError::Incomplete(format!(
                    "Git history exceeds the {}-commit limit. Increase --git-max-depth to inspect the requested history.",
                    config.max_depth
                )));
            }
            let commit = repo.find_commit(oid)?;
            if should_process_commit(&commit, config.since_timestamp, config.until_timestamp) {
                commits.push(oid);
            }
        }
        Ok(Self { repo, commits })
    }

    pub(crate) fn scan<H: FindingHandler>(
        &self,
        scanner: &Scanner,
        handler: &mut H,
    ) -> Result<ScanStats, RedflagError> {
        scan_prepared_history(&self.repo, &self.commits, scanner, handler)
    }
}

#[cfg(test)]
pub fn scan_git_history_with_handler<H: FindingHandler>(
    path: &Path,
    scanner: &Scanner,
    config: &GitConfig,
    handler: &mut H,
) -> Result<ScanStats, RedflagError> {
    HistoryScan::prepare(path, config)?.scan(scanner, handler)
}

fn scan_prepared_history<H: FindingHandler>(
    repo: &Repository,
    commits: &[Oid],
    scanner: &Scanner,
    handler: &mut H,
) -> Result<ScanStats, RedflagError> {
    handler.progress(ScanProgress::Preparing {
        phase: "Git history",
    })?;
    let mut stats = ScanStats::default();
    let total = commits.len();
    stats.commits = total;
    for (index, oid) in commits.iter().enumerate() {
        let commit = repo.find_commit(*oid)?;
        let current = index + 1;
        let short_hash = commit.id().to_string()[..8].to_string();
        let subject = commit.summary().unwrap_or("<no subject>");
        handler.progress(ScanProgress::Item {
            phase: "History",
            current,
            total,
            detail: format!("{short_hash} {subject}"),
        })?;
        let commit_stats =
            process_commit(repo, &commit, scanner, handler, current, total, &short_hash)?;
        stats.files += commit_stats.files;
        if stats.files > scanner.limits().max_files {
            return Err(RedflagError::Incomplete(format!(
                "Git history exceeds the {}-file limit. Narrow the range or increase limits.max_files.",
                scanner.limits().max_files
            )));
        }
        stats.findings += commit_stats.findings;
    }
    handler.progress(ScanProgress::Finished {
        phase: "History",
        total,
    })?;
    Ok(stats)
}

fn push_revisions<'repo>(
    repo: &'repo Repository,
    revwalk: &mut Revwalk<'repo>,
    config: &GitConfig,
) -> Result<(), RedflagError> {
    let revisions: Vec<&str> = if config.branches.is_empty() {
        vec!["HEAD"]
    } else {
        config.branches.iter().map(String::as_str).collect()
    };
    for revision in revisions {
        let object = repo.revparse_single(revision).map_err(|error| {
            RedflagError::Config(format!(
                "Git revision '{revision}' cannot be resolved: {error}"
            ))
        })?;
        revwalk.push(object.id())?;
    }
    Ok(())
}

fn process_commit<H: FindingHandler>(
    repo: &Repository,
    commit: &Commit,
    scanner: &Scanner,
    handler: &mut H,
    current: usize,
    total: usize,
    short_hash: &str,
) -> Result<ScanStats, RedflagError> {
    let tree = commit.tree()?;
    let parent_tree = if commit.parent_count() > 0 {
        Some(commit.parent(0)?.tree()?)
    } else {
        None
    };
    let mut options = DiffOptions::new();
    // NUL bytes and Git attributes must not silently turn selected content into
    // an uninspected binary delta. Unsupported encodings fail below.
    options.force_text(true);
    let diff = repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut options))?;
    let metadata = CommitMetadata {
        hash: commit.id().to_string(),
        author: commit.author().to_string(),
        date: DateTime::<Utc>::from_timestamp(commit.time().seconds(), 0)
            .map(|date| date.to_rfc3339())
            .unwrap_or_else(|| commit.time().seconds().to_string()),
    };

    let mut stats = ScanStats::default();
    for delta_index in 0..diff.deltas().len() {
        let Some(delta) = diff.get_delta(delta_index) else {
            continue;
        };
        let Some(path) = delta.new_file().path() else {
            continue;
        };
        let policy = scanner.file_policy(path, false);
        if delta.new_file().id().is_zero()
            || policy == ExclusionPolicy::Ignore
            || !scanner.should_scan_path(path)
        {
            continue;
        }
        handler.progress(ScanProgress::Item {
            phase: "History",
            current,
            total,
            detail: format!("{short_hash} {}", path.display()),
        })?;
        // Check object sizes without materializing large blobs or patches.
        let odb = repo.odb()?;
        for oid in [delta.old_file().id(), delta.new_file().id()] {
            if !oid.is_zero() {
                let (length, _) = odb.read_header(oid)?;
                scanner.check_file_limit(path, length as u64)?;
            }
        }
        let patch = Patch::from_diff(&diff, delta_index)?.ok_or_else(|| {
            RedflagError::Incomplete(format!(
                "Cannot inspect Git change {} in {short_hash}.",
                path.display()
            ))
        })?;

        stats.files += 1;
        let mut added_lines = Vec::new();
        for hunk_index in 0..patch.num_hunks() {
            let (_, line_count) = patch.hunk(hunk_index)?;
            for line_index in 0..line_count {
                let line = patch.line_in_hunk(hunk_index, line_index)?;
                if line.origin() == '+' {
                    if let Some(number) = line.new_lineno() {
                        added_lines.push(number as usize);
                    }
                }
            }
        }
        if added_lines.is_empty() {
            continue;
        }
        let blob = repo.find_blob(delta.new_file().id())?;
        let content = std::str::from_utf8(blob.content()).map_err(|_| {
            RedflagError::Incomplete(format!(
                "Git file {} in {short_hash} is not UTF-8. Convert the file or explicitly exclude unsupported content.",
                path.display()
            ))
        })?;
        let mut added_lines = added_lines.into_iter().peekable();
        let mut state = SuppressionState::default();
        // Read lexical context from the beginning of the actual new blob. A
        // hunk can begin inside a template/raw string or block comment.
        for (index, line) in content.lines().enumerate() {
            let number = index + 1;
            let emit_findings = added_lines.peek() == Some(&number);
            if emit_findings {
                added_lines.next();
            }
            stats.findings += scanner.scan_line_with_handler(
                ContentLine {
                    path,
                    policy,
                    number,
                    content: line,
                    commit: Some(&metadata),
                    emit_findings,
                },
                &mut state,
                handler,
            )?;
            if added_lines.peek().is_none() {
                break;
            }
        }
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
        progress: Vec<ScanProgress>,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                findings: Vec::new(),
                progress: Vec::new(),
            }
        }
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

    fn scan(
        path: &Path,
        config: &Config,
        handler: &mut TestHandler,
    ) -> Result<ScanStats, RedflagError> {
        let mut config = config.clone();
        config.validate()?;
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
            let secret = [
                "AWS_SECRET_KEY=",
                "ABCDEFGHIJKLMNOPQRST",
                "UVWXYZ0123456789ABCD",
            ]
            .concat();
            File::create(&config_file)
                .unwrap()
                .write_all(secret.as_bytes())
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
            limits: Default::default(),
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
                since_timestamp: None,
                until_timestamp: None,
            },
        };

        let stats = scan(dir.path(), &config, &mut handler)?;

        assert_eq!(handler.findings.len(), 2, "Expected to find 2 secrets");
        assert_eq!(stats.commits, 3);
        assert!(matches!(
            handler.progress.first(),
            Some(ScanProgress::Preparing {
                phase: "Git history"
            })
        ));
        assert!(handler.progress.iter().any(|progress| matches!(
            progress,
            ScanProgress::Item {
                current: 1,
                total: 3,
                ..
            }
        )));
        assert!(matches!(
            handler.progress.last(),
            Some(ScanProgress::Finished {
                phase: "History",
                total: 3
            })
        ));

        // Check findings in reverse chronological order
        let mut findings = handler.findings;
        findings.sort_by(|a, b| b.commit_date.cmp(&a.commit_date));
        assert_ne!(findings[0].commit_hash, findings[1].commit_hash);

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
            limits: Default::default(),
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

    #[test]
    fn unchanged_lines_are_not_attributed_to_later_commits() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(&dir).unwrap();
        let signature = Signature::now("Test User", "test@example.com").unwrap();
        fs::write(
            dir.path().join("secret.rs"),
            "api_key = \"reported_value\"\n",
        )
        .unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("secret.rs")).unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let introduction = repo
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "Add secret",
                &tree,
                &[],
            )
            .unwrap();
        drop(tree);

        fs::write(dir.path().join("clean.rs"), "fn main() {}\n").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("clean.rs")).unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let parent = repo.find_commit(introduction).unwrap();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Add clean file",
            &tree,
            &[&parent],
        )
        .unwrap();

        let config = Config {
            limits: Default::default(),
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
        let mut handler = TestHandler::new();
        scan_git_history_with_handler(dir.path(), &scanner, &config.git, &mut handler).unwrap();

        assert_eq!(handler.findings.len(), 1);
        assert_eq!(
            handler.findings[0].commit_hash.as_deref(),
            Some(introduction.to_string().as_str())
        );
    }
}
