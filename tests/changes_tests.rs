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
    let deleted = report(repo.scan(Some(base), remove, &[]), 1);
    assert_eq!(finding_commits(&deleted), BTreeSet::from([add.to_string()]));
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
}
