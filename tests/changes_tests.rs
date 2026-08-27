use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::{tempdir, TempDir};

fn token() -> String {
    ["ghp_", "aB3dE6gH9jK2mN5pQ8", "sT1vW4xY7zA0cD3fG6"].concat()
}

struct Repo {
    dir: TempDir,
    git: Repository,
}
impl Repo {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let git = Repository::init(dir.path()).unwrap();
        Self { dir, git }
    }
    fn commit(&self, parents: &[Oid], files: &[(&str, &[u8])]) -> Oid {
        let entries: Vec<_> = files
            .iter()
            .map(|(name, bytes)| (*name, self.git.blob(bytes).unwrap(), 0o100644))
            .collect();
        self.commit_entries(parents, &entries)
    }
    fn commit_entries(&self, parents: &[Oid], entries: &[(&str, Oid, i32)]) -> Oid {
        let mut builder = self.git.treebuilder(None).unwrap();
        for (name, oid, mode) in entries {
            builder.insert(*name, *oid, *mode).unwrap();
        }
        let tree_id = builder.write().unwrap();
        let tree = self.git.find_tree(tree_id).unwrap();
        let parents: Vec<_> = parents
            .iter()
            .map(|oid| self.git.find_commit(*oid).unwrap())
            .collect();
        let refs: Vec<_> = parents.iter().collect();
        let signature = Signature::now("Fixture", "fixture@example.invalid").unwrap();
        self.git
            .commit(None, &signature, &signature, "Fixture commit", &tree, &refs)
            .unwrap()
    }
    fn scan(&self, base: Option<Oid>, head: Oid, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_redflag"));
        command.arg("changes").arg(self.dir.path()).args([
            "--head",
            &head.to_string(),
            "--format",
            "json",
        ]);
        match base {
            Some(base) => {
                command.args(["--base", &base.to_string()]);
            }
            None => {
                command.arg("--new-branch");
            }
        }
        if !args.contains(&"--betterleaks-path") {
            command.args(["--engine", "native"]);
        }
        command.args(args).output().unwrap()
    }
    fn remove_object(&self, oid: Oid) {
        let id = oid.to_string();
        fs::remove_file(
            self.git
                .path()
                .join("objects")
                .join(&id[..2])
                .join(&id[2..]),
        )
        .unwrap();
    }

    fn event(&self, name: &str, payload: Value, args: &[&str]) -> Output {
        let path = self.dir.path().join("event.json");
        fs::write(&path, serde_json::to_vec(&payload).unwrap()).unwrap();
        Command::new(env!("CARGO_BIN_EXE_redflag"))
            .arg("changes")
            .arg(self.dir.path())
            .arg("--github-event")
            .arg(path)
            .args(["--engine", "native", "--format", "json"])
            .args(args)
            .env("GITHUB_EVENT_NAME", name)
            .env("GITHUB_SHA", "not-the-event-head")
            .env_remove("GITHUB_TOKEN")
            .env_remove("GH_TOKEN")
            .output()
            .unwrap()
    }
}

fn report(output: Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&token()));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["complete"], true);
    result
}

fn incomplete(output: Output) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(output.stdout.is_empty());
}

fn finding_commits(result: &Value) -> BTreeSet<String> {
    result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["commit_hash"].as_str().unwrap().to_string())
        .collect()
}

fn engine_path() -> String {
    std::env::var("REDFLAG_BETTERLEAKS_PATH").unwrap_or_else(|_| {
        Path::new(env!("CARGO_BIN_EXE_redflag"))
            .parent()
            .unwrap()
            .join("engines")
            .join(if cfg!(windows) {
                "betterleaks.exe"
            } else {
                "betterleaks"
            })
            .to_str()
            .unwrap()
            .to_string()
    })
}

fn reviewed_policy(result: &Value) -> Value {
    let expires = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
    let entries: Vec<_> = result["logical_findings"].as_array().unwrap().iter()
        .flat_map(|g| g["occurrences"].as_array().unwrap())
        .map(|o| serde_json::json!({"occurrence_id":o["id"],"kind":"accepted_debt","reason":"Tracked synthetic source debt","reviewed_by":"fixture-reviewer","expires_at":expires})).collect();
    serde_json::json!({"schema_version":1,"mode":"changes","exceptions":entries})
}

#[test]
fn reviewed_exceptions_accept_only_exact_occurrences_and_expiry_restores_blocking() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let add = repo.commit(&[base], &[("original", token().as_bytes())]);
    let original = report(repo.scan(Some(base), add, &[]), 1);
    let dir = tempdir().unwrap();
    let file = dir.path().join("review.json");
    let mut policy = reviewed_policy(&original);
    fs::write(&file, serde_json::to_vec(&policy).unwrap()).unwrap();
    let accepted = report(
        repo.scan(Some(base), add, &["--exceptions", file.to_str().unwrap()]),
        0,
    );
    assert_eq!(accepted["findings_count"], 1);
    assert_eq!(accepted["blocking_occurrences_count"], 0);
    assert_eq!(accepted["accepted_occurrences_count"], 1);
    assert_eq!(
        accepted["logical_findings"][0]["occurrences"][0]["status"],
        "accepted"
    );
    assert_eq!(accepted["exception_policy"]["matched_entries"], 1);
    assert_eq!(accepted["exception_policy"]["unmatched_entries"], 0);
    assert_eq!(
        accepted["logical_findings"][0]["id"],
        original["logical_findings"][0]["id"]
    );
    let copy = repo.commit(
        &[add],
        &[
            ("original", token().as_bytes()),
            ("copy", token().as_bytes()),
        ],
    );
    let copied = report(
        repo.scan(Some(base), copy, &["--exceptions", file.to_str().unwrap()]),
        1,
    );
    assert_eq!(copied["accepted_occurrences_count"], 1);
    assert_eq!(copied["blocking_occurrences_count"], 1);
    assert_eq!(copied["logical_findings_count"], 1);
    policy["exceptions"][0]["expires_at"] = "2000-01-01T00:00:00Z".into();
    fs::write(&file, serde_json::to_vec(&policy).unwrap()).unwrap();
    let expired = report(
        repo.scan(Some(base), add, &["--exceptions", file.to_str().unwrap()]),
        1,
    );
    assert_eq!(expired["accepted_occurrences_count"], 0);
    assert_eq!(expired["exception_policy"]["expired_entries"], 1);
    assert_eq!(
        expired["logical_findings"][0]["occurrences"][0]["exception"]["status"],
        "expired"
    );
}

#[test]
fn proposed_or_checkout_exception_files_cannot_authorize_their_own_source_range() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let add = repo.commit(&[base], &[("secret", token().as_bytes())]);
    let policy = serde_json::to_vec(&reviewed_policy(&report(
        repo.scan(Some(base), add, &[]),
        1,
    )))
    .unwrap();
    fs::write(repo.dir.path().join("redflag-exceptions.json"), &policy).unwrap();
    let proposed = repo.commit(
        &[add],
        &[
            ("secret", token().as_bytes()),
            ("redflag-exceptions.json", &policy),
        ],
    );
    let self_approved = report(repo.scan(Some(base), proposed, &[]), 1);
    assert_eq!(self_approved["accepted_occurrences_count"], 0);
    assert_eq!(self_approved["exception_policy"]["entry_count"], 0);
    // The same file becomes authoritative only on an independently trusted base/ref.
    let trusted = repo.commit(&[base], &[("redflag-exceptions.json", &policy)]);
    let accepted = report(repo.scan(Some(trusted), proposed, &[]), 0);
    assert_eq!(accepted["accepted_occurrences_count"], 1);
    assert_eq!(
        accepted["exception_policy"]["origin"],
        format!("git:{trusted}:redflag-exceptions.json")
    );
    let explicit = report(
        repo.scan(
            Some(base),
            proposed,
            &["--policy-ref", &trusted.to_string()],
        ),
        0,
    );
    assert_eq!(explicit["accepted_occurrences_count"], 1);
    let disabled = report(repo.scan(Some(trusted), proposed, &["--no-exceptions"]), 1);
    assert_eq!(disabled["accepted_occurrences_count"], 0);
    let new_branch = report(repo.scan(None, proposed, &[]), 1);
    assert_eq!(new_branch["accepted_occurrences_count"], 0);
    let reviewed_branch = report(
        repo.scan(None, proposed, &["--policy-ref", &trusted.to_string()]),
        0,
    );
    assert_eq!(reviewed_branch["accepted_occurrences_count"], 1);
}

#[test]
fn missing_malformed_wrong_scope_and_oversized_exception_policy_fail_closed() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let head = repo.commit(&[base], &[("secret", token().as_bytes())]);
    let valid = reviewed_policy(&report(repo.scan(Some(base), head, &[]), 1));
    let dir = tempdir().unwrap();
    let file = dir.path().join("review.json");
    incomplete(repo.scan(Some(base), head, &["--exceptions", file.to_str().unwrap()]));
    for (key, value) in [
        ("schema_version", serde_json::json!(999)),
        ("mode", serde_json::json!("artifacts")),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut bad = valid.clone();
        bad[key] = value;
        fs::write(&file, serde_json::to_vec(&bad).unwrap()).unwrap();
        incomplete(repo.scan(Some(base), head, &["--exceptions", file.to_str().unwrap()]));
    }
    fs::write(&file, vec![b' '; 1024 * 1024 + 1]).unwrap();
    incomplete(repo.scan(Some(base), head, &["--exceptions", file.to_str().unwrap()]));
    for bytes in [b"not JSON".to_vec(), vec![b' '; 1024 * 1024 + 1]] {
        let bad_base = repo.commit(&[], &[("redflag-exceptions.json", &bytes)]);
        let bad_head = repo.commit(
            &[bad_base],
            &[
                ("redflag-exceptions.json", &bytes),
                ("secret", token().as_bytes()),
            ],
        );
        incomplete(repo.scan(Some(bad_base), bad_head, &[]));
        report(repo.scan(Some(bad_base), bad_head, &["--no-exceptions"]), 1);
    }
    let target = repo.git.blob(b"elsewhere").unwrap();
    let symlink = repo.commit_entries(&[], &[("redflag-exceptions.json", target, 0o120000)]);
    incomplete(repo.scan(Some(symlink), head, &[]));
}

#[test]
fn additional_detector_evidence_requires_a_new_reviewed_occurrence() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let head = repo.commit(&[base], &[("secret", token().as_bytes())]);
    let dir = tempdir().unwrap();
    let policy = dir.path().join("review.json");
    fs::write(
        &policy,
        serde_json::to_vec(&reviewed_policy(&report(
            repo.scan(Some(base), head, &[]),
            1,
        )))
        .unwrap(),
    )
    .unwrap();
    let config = dir.path().join("config.toml");
    fs::write(&config, "[[patterns]]\nname = 'second-provider-rule'\npattern = 'ghp_[A-Za-z0-9]{36}'\ndescription = 'Independent evidence'\nseverity = 'Critical'\n").unwrap();
    let result = report(
        repo.scan(
            Some(base),
            head,
            &[
                "--exceptions",
                policy.to_str().unwrap(),
                "--config",
                config.to_str().unwrap(),
            ],
        ),
        1,
    );
    assert_eq!(result["findings_count"], 2);
    assert_eq!(result["blocking_occurrences_count"], 1);
    assert_eq!(result["accepted_occurrences_count"], 0);
    assert_eq!(result["exception_policy"]["unmatched_entries"], 1);
}

#[test]
fn reviewed_source_debt_never_becomes_an_artifact_exception() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let head = repo.commit(&[base], &[("secret", token().as_bytes())]);
    let policy = reviewed_policy(&report(repo.scan(Some(base), head, &[]), 1));
    fs::write(
        repo.dir.path().join("redflag-exceptions.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    let dist = repo.dir.path().join("dist");
    fs::create_dir(&dist).unwrap();
    fs::write(dist.join("secret"), token()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .current_dir(repo.dir.path())
        .arg("artifacts")
        .arg(&dist)
        .args([
            "--engine",
            "native",
            "--no-config",
            "--format",
            "json",
            "--private-env",
            "RF_PUBLICATION",
        ])
        .env("RF_PUBLICATION", token())
        .output()
        .unwrap();
    let result = report(output, 1);
    assert_eq!(result["accepted_occurrences_count"], 0);
    assert_eq!(result["blocking_occurrences_count"], 1);
    assert_eq!(result["findings_count"], 2);
    assert_eq!(result["exception_policy"]["entry_count"], 0);
    assert_eq!(result["exception_policy"]["mode"], "artifacts");
}

#[test]
fn github_reviewed_occurrences_stay_visible_without_error_annotations() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let head = repo.commit(&[base], &[("secret", token().as_bytes())]);
    let dir = tempdir().unwrap();
    let policy_file = dir.path().join("review.json");
    let mut policy = reviewed_policy(&report(repo.scan(Some(base), head, &[]), 1));
    policy["exceptions"][0]["reason"] = "Tracked debt\n::error::injected [link](url)".into();
    fs::write(&policy_file, serde_json::to_vec(&policy).unwrap()).unwrap();
    let summary = dir.path().join("summary.md");
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("changes")
        .arg(repo.dir.path())
        .args([
            "--engine",
            "native",
            "--format",
            "github",
            "--base",
            &base.to_string(),
            "--head",
            &head.to_string(),
        ])
        .arg("--exceptions")
        .arg(&policy_file)
        .arg("--github-summary")
        .arg(&summary)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("::notice "));
    assert!(!stdout.contains("::error"));
    let text = fs::read_to_string(summary).unwrap();
    assert!(text.contains("Accepted by reviewed exception: 1"));
    assert!(text.contains("accepted"));
    assert!(text.contains("Tracked debt"));
    assert!(!text.contains("[link](url)"));
    assert!(!text.contains(&token()));
}

#[test]
fn introduced_commits_retain_deleted_and_reintroduced_secrets() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let add = repo.commit(&[base], &[("secret.txt", token().as_bytes())]);
    let remove = repo.commit(&[add], &[]);
    let reintroduce = repo.commit(&[remove], &[("secret.txt", token().as_bytes())]);
    let result = report(repo.scan(Some(base), reintroduce, &[]), 1);
    assert_eq!(
        finding_commits(&result),
        BTreeSet::from([add.to_string(), reintroduce.to_string()])
    );
    assert_eq!(
        result["coverage"]["commits"],
        serde_json::json!([add.to_string(), remove.to_string(), reintroduce.to_string()])
    );
    assert_eq!(result["coverage"]["base"], base.to_string());
    assert_eq!(result["coverage"]["skipped"][0]["reason"], "deleted");
    assert_eq!(result["schema_version"], 3);
    assert_eq!(result["logical_findings_count"], 1);
    assert_eq!(result["occurrences_count"], 2);
    let occurrences = result["logical_findings"][0]["occurrences"]
        .as_array()
        .unwrap();
    assert_ne!(occurrences[0]["id"], occurrences[1]["id"]);
    for occurrence in occurrences {
        assert_eq!(
            occurrence["location"]["version"],
            occurrence["location"]["commit"]
        );
        assert_eq!(occurrence["location"]["path"], "secret.txt");
        assert!(occurrence["location"].get("target").is_none());
    }
    let deleted = report(repo.scan(Some(base), remove, &[]), 1);
    assert_eq!(finding_commits(&deleted), BTreeSet::from([add.to_string()]));
    let original = &deleted["logical_findings"][0]["occurrences"][0]["id"];
    assert!(occurrences.iter().any(|o| &o["id"] == original));
}

#[test]
fn github_source_annotations_require_matching_checked_blobs_and_worktree_bytes() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let value = format!("// synthetic fixture\n{}\n", token());
    let add = repo.commit(
        &[base],
        &[("kept.rs", value.as_bytes()), ("gone.rs", value.as_bytes())],
    );
    let head = repo.commit(&[add], &[("kept.rs", value.as_bytes())]);
    repo.git.set_head_detached(head).unwrap();
    repo.git
        .checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
        .unwrap();
    let output_dir = tempdir().unwrap();
    let summary = output_dir.path().join("summary.md");
    let run = |workspace: &Path| {
        Command::new(env!("CARGO_BIN_EXE_redflag"))
            .arg("changes")
            .arg(repo.dir.path())
            .args([
                "--engine",
                "native",
                "--format",
                "github",
                "--base",
                &base.to_string(),
                "--head",
                &head.to_string(),
            ])
            .arg("--github-summary")
            .arg(&summary)
            .env("GITHUB_SHA", head.to_string())
            .env("GITHUB_WORKSPACE", workspace)
            .env("GITHUB_REPOSITORY", "fixture/project")
            .env("GITHUB_SERVER_URL", "https://github.com")
            .env_remove("GITHUB_TOKEN")
            .env_remove("GH_TOKEN")
            .output()
            .unwrap()
    };
    let output = run(repo.dir.path());
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.lines().filter(|s| s.starts_with("::error ")).count(),
        2
    );
    assert_eq!(stdout.matches(",file=").count(), 1);
    assert!(stdout.contains("file=kept.rs,line=2,endLine=2"));
    assert!(!stdout.contains("file=gone.rs"));
    let text = fs::read_to_string(&summary).unwrap();
    assert!(text.contains(&format!(
        "https://github.com/fixture/project/blob/{add}/gone.rs#L2"
    )));
    assert!(text.contains(&base.to_string()));
    assert!(text.contains(&head.to_string()));
    assert!(!text.contains(&token()));
    let nested = run(repo.dir.path().parent().unwrap());
    assert_eq!(nested.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&nested.stdout).contains(",file="));
    fs::write(
        repo.dir.path().join("kept.rs"),
        format!("// moved\n{value}"),
    )
    .unwrap();
    let output = run(repo.dir.path());
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(",file="));
}

#[cfg(unix)]
#[test]
fn github_source_paths_cannot_inject_commands_or_markdown() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let unusual = "a,b:c%.rs";
    let hostile = "line\n::error::forged[link](url).rs";
    let head = repo.commit(
        &[base],
        &[(unusual, token().as_bytes()), (hostile, token().as_bytes())],
    );
    repo.git.set_head_detached(head).unwrap();
    repo.git
        .checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
        .unwrap();
    let output_dir = tempdir().unwrap();
    let summary = output_dir.path().join("summary.md");
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("changes")
        .arg(repo.dir.path())
        .args([
            "--engine",
            "native",
            "--format",
            "github",
            "--base",
            &base.to_string(),
            "--head",
            &head.to_string(),
        ])
        .arg("--github-summary")
        .arg(&summary)
        .env("GITHUB_SHA", head.to_string())
        .env("GITHUB_WORKSPACE", repo.dir.path())
        .env("GITHUB_REPOSITORY", "fixture/project")
        .env("GITHUB_SERVER_URL", "https://github.com")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.lines().filter(|s| s.starts_with("::error ")).count(),
        2
    );
    assert!(!stdout.contains("\n::error::forged"));
    assert!(stdout.contains("file=a%2Cb%3Ac%25.rs,line=1"));
    let text = fs::read_to_string(&summary).unwrap();
    assert!(text.contains("/line%0A%3A%3Aerror%3A%3Aforged%5Blink%5D%28url%29.rs#L1"));
    assert!(!text.contains("[link](url)"));
}

#[test]
fn unrelated_edits_do_not_report_old_debt_but_new_occurrences_do() {
    let repo = Repo::new();
    let old = format!("{}\n", token());
    let base = repo.commit(&[], &[("old.txt", old.as_bytes())]);
    let changed = format!("public content\n{old}");
    let harmless = repo.commit(&[base], &[("old.txt", changed.as_bytes())]);
    report(repo.scan(Some(base), harmless, &[]), 0);
    let copied = repo.commit(
        &[harmless],
        &[
            ("old.txt", changed.as_bytes()),
            ("copied.txt", old.as_bytes()),
        ],
    );
    let result = report(repo.scan(Some(base), copied, &[]), 1);
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["file"] == "copied.txt"));
    let twice = format!("{changed}{old}");
    let duplicate = repo.commit(&[harmless], &[("old.txt", twice.as_bytes())]);
    let result = report(repo.scan(Some(base), duplicate, &[]), 1);
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["line"] == 3));
}

fn same_line_occurrences(args: &[&str]) {
    let repo = Repo::new();
    let old = format!("const items=[1,\"{}\",2];", token());
    let base = repo.commit(&[], &[("bundle.js", old.as_bytes())]);
    let edited = format!("const items=[3,\"{}\",4];", token());
    let harmless = repo.commit(&[base], &[("bundle.js", edited.as_bytes())]);
    let result = report(repo.scan(Some(base), harmless, args), 0);
    assert_eq!(
        result["coverage"]["occurrence_comparison"]["existing_parent_occurrences"],
        1
    );
    let two = format!("const items=[3,\"{}\",\"{}\",4];", token(), token());
    let copied = repo.commit(&[harmless], &[("bundle.js", two.as_bytes())]);
    let result = report(repo.scan(Some(harmless), copied, args), 1);
    assert_eq!(result["findings_count"], 1);
    // The identical bytes already existed in a non-credential context, but that
    // is not a parent detector finding and cannot authorize this new occurrence.
    let hidden = format!("const items=[\"{}\",\"X{}\"]", token(), token());
    let before = repo.commit(&[], &[("boundary.js", hidden.as_bytes())]);
    let revealed = format!("const items=[\"{}\",\"{}\"]", token(), token());
    let after = repo.commit(&[before], &[("boundary.js", revealed.as_bytes())]);
    let result = report(repo.scan(Some(before), after, args), 1);
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["pattern_name"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("github")));
    assert_eq!(result["findings_count"], 1);
}

#[test]
fn native_same_line_edits_preserve_old_debt_without_hiding_a_new_occurrence() {
    same_line_occurrences(&[]);
}

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn engine_same_line_edits_preserve_old_debt_without_hiding_a_new_occurrence() {
    same_line_occurrences(&["--betterleaks-path", &engine_path()]);
}

#[test]
fn comparison_budgets_fail_atomically_instead_of_guessing_occurrence_identity() {
    let repo = Repo::new();
    let old = format!("a \"{}\" b", token());
    let base = repo.commit(&[], &[("bundle.js", old.as_bytes())]);
    let edited = format!("c \"{}\" d", token());
    let head = repo.commit(&[base], &[("bundle.js", edited.as_bytes())]);
    let path = repo.dir.path().join("policy.toml");
    for setting in [
        "max_diff_bytes = 8",
        "max_findings = 1",
        "max_files = 1",
        "max_diff_bytes = 0",
        "diff_timeout_seconds = 0",
        "max_findings = 0",
    ] {
        fs::write(&path, format!("[limits]\n{setting}\n")).unwrap();
        incomplete(repo.scan(Some(base), head, &["--config", path.to_str().unwrap()]));
    }
    fs::write(
        &path,
        "[limits]\nmax_diff_bytes = 1000\nmax_findings = 2\nmax_files = 2\n",
    )
    .unwrap();
    report(
        repo.scan(Some(base), head, &["--config", path.to_str().unwrap()]),
        0,
    );
}

#[test]
fn binary_projection_uses_original_byte_columns_for_parent_evidence() {
    let repo = Repo::new();
    let empty = repo.commit(&[], &[]);
    for prefix in [
        b"\xff ".as_slice(),
        b"\xe2\x82 ",
        b"\xffA\xf0\x90B ",
        "🙂 \u{fffd}".as_bytes(),
    ] {
        let bytes = [prefix, token().as_bytes()].concat();
        let head = repo.commit(&[empty], &[("binary.bin", &bytes)]);
        let result = report(repo.scan(Some(empty), head, &[]), 1);
        assert_eq!(
            result["findings"][0]["evidence"][0]["start_column"],
            prefix.len() + 1
        );
        assert_eq!(
            result["findings"][0]["evidence"][0]["end_column"],
            prefix.len() + token().len()
        );
    }
    let bytes = [b"\xff ".as_slice(), token().as_bytes(), b" public"].concat();
    let base = repo.commit(&[empty], &[("binary.bin", &bytes)]);
    let result = report(repo.scan(Some(empty), base, &[]), 1);
    assert_eq!(result["findings"][0]["evidence"][0]["start_column"], 3);
    assert_eq!(
        result["findings"][0]["evidence"][0]["end_column"],
        2 + token().len()
    );
    let changed = [b"\xff\xfe ".as_slice(), token().as_bytes(), b" changed"].concat();
    let head = repo.commit(&[base], &[("binary.bin", &changed)]);
    report(repo.scan(Some(base), head, &[]), 0);
}

#[test]
fn dense_parent_evidence_preserves_each_occurrence_on_a_minified_line() {
    let repo = Repo::new();
    let old = format!("{} public", format!("\"{}\",", token()).repeat(4096));
    let base = repo.commit(&[], &[("bundle.js", old.as_bytes())]);
    let new = format!("{} changed", format!("\"{}\",", token()).repeat(4096));
    let head = repo.commit(&[base], &[("bundle.js", new.as_bytes())]);
    let result = report(repo.scan(Some(base), head, &[]), 0);
    assert_eq!(
        result["coverage"]["occurrence_comparison"]["existing_parent_occurrences"],
        4096
    );
}

#[test]
fn merge_imports_do_not_become_new_debt_but_merge_resolutions_are_inspected() {
    let repo = Repo::new();
    let root = repo.commit(&[], &[]);
    let old = format!("{}\n", token());
    let base = repo.commit(&[root], &[("shared.txt", old.as_bytes())]);
    let head = repo.commit(&[root], &[("shared.txt", b"public\n")]);
    let merged = format!("{old}public\n");
    let merge = repo.commit(&[head, base], &[("shared.txt", merged.as_bytes())]);
    report(repo.scan(Some(base), merge, &[]), 0);
    let novel = repo.commit(&[head, base], &[("new.txt", token().as_bytes())]);
    let result = report(
        repo.scan(Some(base), head, &["--merge-result", &novel.to_string()]),
        1,
    );
    assert_eq!(
        finding_commits(&result),
        BTreeSet::from([novel.to_string()])
    );
    incomplete(repo.scan(Some(root), head, &["--merge-result", &novel.to_string()]));
}

#[test]
fn proposed_configuration_and_working_tree_cannot_authorize_their_own_exclusions() {
    let repo = Repo::new();
    let policy = b"[[exclusions]]\npattern = 'ignored.txt'\npolicy = 'Ignore'\n";
    let base = repo.commit(&[], &[("redflag.toml", policy)]);
    let proposed = b"[[exclusions]]\npattern = '*.txt'\npolicy = 'Ignore'\n";
    let head = repo.commit(
        &[base],
        &[
            ("redflag.toml", proposed),
            ("ignored.txt", token().as_bytes()),
            ("new.txt", token().as_bytes()),
        ],
    );
    fs::write(repo.dir.path().join("redflag.toml"), proposed).unwrap();
    fs::write(repo.dir.path().join("working-only.txt"), token()).unwrap();
    let result = report(repo.scan(Some(base), head, &[]), 1);
    assert_eq!(
        result["coverage"]["policy_origin"],
        format!("git:{base}:redflag.toml")
    );
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["file"] == "new.txt"));
    let defaults = report(repo.scan(Some(base), head, &["--no-config"]), 1);
    assert!(defaults["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["file"] == "ignored.txt"));
}

#[test]
fn limits_apply_to_complete_introduced_scope_and_errors_are_atomic() {
    let repo = Repo::new();
    let root = repo.commit(&[], &[]);
    let base = repo.commit(&[root], &[]);
    let one = repo.commit(&[base], &[("a.txt", token().as_bytes())]);
    let two = repo.commit(&[one], &[]);
    report(repo.scan(Some(base), one, &["--max-commits", "1"]), 1);
    incomplete(repo.scan(Some(base), two, &["--max-commits", "1"]));
    incomplete(repo.scan(Some(base), one, &["--max-commits", "0"]));
    fs::write(repo.git.path().join("shallow"), format!("{base}\n")).unwrap();
    incomplete(repo.scan(Some(base), one, &[]));
    fs::remove_file(repo.git.path().join("shallow")).unwrap();
    let policy = repo.dir.path().join("limits.toml");
    fs::write(&policy, "[limits]\nmax_file_bytes = 10\n").unwrap();
    incomplete(repo.scan(Some(base), one, &["--config", policy.to_str().unwrap()]));
    fs::write(&policy, "[limits]\nmax_total_bytes = 10\n").unwrap();
    incomplete(repo.scan(Some(base), one, &["--config", policy.to_str().unwrap()]));
    fs::write(&policy, "[limits]\nmax_line_bytes = 10\n").unwrap();
    incomplete(repo.scan(Some(base), one, &["--config", policy.to_str().unwrap()]));
}

#[test]
fn missing_objects_do_not_truncate_the_range_or_skip_a_parent() {
    let repo = Repo::new();
    let root = repo.commit(&[], &[]);
    let missing = repo.commit(&[root], &[("gone.txt", b"public")]);
    let head = repo.commit(&[missing], &[("secret.txt", token().as_bytes())]);
    repo.remove_object(missing);
    incomplete(repo.scan(Some(root), head, &[]));
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let head = repo.commit(&[base], &[("secret.txt", token().as_bytes())]);
    repo.remove_object(repo.git.blob(token().as_bytes()).unwrap());
    incomplete(repo.scan(Some(base), head, &[]));
}

#[test]
fn new_branches_and_empty_ranges_have_explicit_scope() {
    let repo = Repo::new();
    let root = repo.commit(&[], &[("secret.txt", token().as_bytes())]);
    let result = report(repo.scan(None, root, &[]), 1);
    assert_eq!(result["coverage"]["new_branch"], true);
    assert!(result["coverage"]["base"].is_null());
    let result = report(repo.scan(Some(root), root, &[]), 0);
    assert_eq!(result["coverage"]["commits"], serde_json::json!([]));
    let other = repo.commit(&[], &[("public.txt", b"public")]);
    report(repo.scan(Some(root), other, &[]), 0);
}

#[test]
fn selected_symlinks_and_submodules_fail_explicitly() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let link = repo.git.blob(b"target.txt").unwrap();
    for (id, mode) in [(link, 0o120000), (base, 0o160000)] {
        let head = repo.commit_entries(&[base], &[("unsupported", id, mode)]);
        incomplete(repo.scan(Some(base), head, &[]));
    }
}

#[test]
fn github_push_uses_exact_event_range_even_when_payload_commit_list_is_empty() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let add = repo.commit(&[base], &[("secret.txt", token().as_bytes())]);
    let remove = repo.commit(&[add], &[]);
    repo.git.set_head_detached(base).unwrap();
    let payload = serde_json::json!({"ref": "refs/heads/feature", "before": base.to_string(), "after": remove.to_string(), "created": false, "deleted": false, "commits": []});
    let result = report(repo.event("push", payload.clone(), &[]), 1);
    assert_eq!(finding_commits(&result), BTreeSet::from([add.to_string()]));
    assert_eq!(result["coverage"]["head"], remove.to_string());
    assert_eq!(result["coverage"]["event"]["kind"], "push");
    assert_eq!(
        result["coverage"]["event"]["payload_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    incomplete(repo.event("push", payload, &["--base", &base.to_string()]));
}

#[test]
fn github_new_branch_is_explicit_and_unsupported_pushes_do_not_report_clean() {
    let repo = Repo::new();
    let head = repo.commit(&[], &[("secret.txt", token().as_bytes())]);
    let mut payload = serde_json::json!({"ref": "refs/heads/new", "before": "0".repeat(40), "after": head.to_string(), "created": true, "deleted": false});
    let result = report(repo.event("push", payload.clone(), &[]), 1);
    assert_eq!(result["coverage"]["new_branch"], true);
    assert!(result["coverage"]["base"].is_null());
    payload["ref"] = serde_json::json!("refs/tags/v1");
    incomplete(repo.event("push", payload.clone(), &[]));
    payload["ref"] = serde_json::json!("refs/heads/new");
    payload["deleted"] = serde_json::json!(true);
    incomplete(repo.event("push", payload, &[]));
}

#[test]
fn github_fork_pull_request_inspects_branch_and_merge_without_tokens() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let add = repo.commit(&[base], &[("deleted.txt", token().as_bytes())]);
    let head = repo.commit(&[add], &[]);
    let merge = repo.commit(&[base, head], &[("merge-only.txt", token().as_bytes())]);
    let payload = serde_json::json!({"number": 17, "action": "synchronize", "pull_request": {
        "state": "open", "base": {"sha": base.to_string(), "repo": {"id": 100}},
        "head": {"sha": head.to_string(), "repo": {"id": 200}}, "merge_commit_sha": merge.to_string()
    }});
    let result = report(repo.event("pull_request", payload.clone(), &[]), 1);
    assert_eq!(
        finding_commits(&result),
        BTreeSet::from([add.to_string(), merge.to_string()])
    );
    assert_eq!(result["coverage"]["event"]["fork"], true);
    assert_eq!(result["coverage"]["event"]["pull_request"], 17);
    incomplete(repo.event("pull_request_target", payload.clone(), &[]));
    repo.remove_object(merge);
    incomplete(repo.event("pull_request", payload, &[]));
}

#[test]
fn github_merge_queue_uses_group_base_and_head_and_includes_merge_resolution() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let branch = repo.commit(&[base], &[("public.txt", b"public")]);
    let head = repo.commit(&[base, branch], &[("merge-only.txt", token().as_bytes())]);
    let payload = serde_json::json!({"action": "checks_requested", "merge_group": {
        "base_sha": base.to_string(), "head_sha": head.to_string()
    }});
    let result = report(repo.event("merge_group", payload, &[]), 1);
    assert_eq!(finding_commits(&result), BTreeSet::from([head.to_string()]));
    assert_eq!(result["coverage"]["base"], base.to_string());
    assert_eq!(result["coverage"]["head"], head.to_string());
    assert_eq!(result["coverage"]["event"]["kind"], "merge_group");
}

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn pinned_engine_keeps_revision_identity_and_inspects_binary_and_hidden_source() {
    let repo = Repo::new();
    let base = repo.commit(&[], &[]);
    let bytes = [
        b"\0\xff\n".as_slice(),
        token().as_bytes(),
        b" // betterleaks:allow redflag:ignore\n",
    ]
    .concat();
    let first = repo.commit(&[base], &[(".hidden", &bytes), ("asset.png", &bytes)]);
    let removed = repo.commit(&[first], &[]);
    let last = repo.commit(&[removed], &[(".hidden", &bytes), ("asset.png", &bytes)]);
    let engine = engine_path();
    let result = report(
        repo.scan(Some(base), last, &["--betterleaks-path", &engine]),
        1,
    );
    assert_eq!(result["findings_count"], 4);
    assert_eq!(
        finding_commits(&result),
        BTreeSet::from([first.to_string(), last.to_string()])
    );
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["line"] == 2));
    report(
        repo.scan(Some(base), base, &["--betterleaks-path", &engine]),
        0,
    );
}

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn multipart_credentials_use_added_component_evidence_in_commits_and_merges() {
    let repo = Repo::new();
    let key = ["AKIA", "Q7W2E5R3T6Y4U2I7"].concat();
    let secret = ["mP9xR2vL7kN4qW6tY3cB8dF5", "hJ1sA0uE9gZ2iO4p"].concat();
    let key_line = format!("{key}\n");
    let secret_line = format!("aws_secret_access_key = {secret}\n");
    let both = format!("{key}\n{secret_line}");
    let root = repo.commit(&[], &[]);
    let base = repo.commit(&[root], &[("pair.txt", key_line.as_bytes())]);
    let added = repo.commit(&[base], &[("pair.txt", both.as_bytes())]);
    let args = ["--betterleaks-path", &engine_path()];
    let result = report(repo.scan(Some(base), added, &args), 1);
    let aws = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["pattern_name"] == "betterleaks:aws-access-token")
        .unwrap();
    assert_eq!(aws["line"], 1);
    assert_eq!(aws["evidence"].as_array().unwrap().len(), 2);
    assert_eq!(aws["evidence"][1]["start_line"], 2);
    let other = repo.commit(&[root], &[("pair.txt", secret_line.as_bytes())]);
    let merge = repo.commit(&[base, other], &[("pair.txt", both.as_bytes())]);
    let result = report(repo.scan(Some(base), merge, &args), 1);
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["pattern_name"] == "betterleaks:aws-access-token"
            && f["commit_hash"] == merge.to_string()));
    // Only context is deleted: the primary and component lines themselves are
    // unchanged, but bringing them within the rule's range creates a credential.
    let separated = format!("{key_line}{}{secret_line}", "public content\n".repeat(12));
    let before = repo.commit(&[root], &[("pair.txt", separated.as_bytes())]);
    let after = repo.commit(&[before], &[("pair.txt", both.as_bytes())]);
    let result = report(repo.scan(Some(before), after, &args), 1);
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["pattern_name"] == "betterleaks:aws-access-token"));
}
