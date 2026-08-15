use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn run(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_redflag"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

fn show(cwd: &Path, path: &Path, args: &[&str]) -> serde_json::Value {
    let mut full = vec!["show-config", path.to_str().unwrap(), "--format", "json"];
    full.extend_from_slice(args);
    let output = run(cwd, &full);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn nearest_policy_is_resolved_for_files_and_directories() {
    let dir = tempdir().unwrap();
    let nested = dir.path().join("src/sub");
    fs::create_dir_all(&nested).unwrap();
    fs::write(
        dir.path().join("redflag.toml"),
        "[entropy]\nenabled = false\n",
    )
    .unwrap();
    let file = nested.join("file.rs");
    fs::write(&file, "hello").unwrap();
    for path in [&file, &nested] {
        let result = show(dir.path(), path, &[]);
        assert_eq!(result["effective"]["entropy"]["enabled"], false);
        assert_eq!(
            result["config_path"],
            fs::canonicalize(dir.path().join("redflag.toml"))
                .unwrap()
                .to_str()
                .unwrap()
        );
    }
    fs::write(nested.join("redflag.toml"), "[limits]\nmax_files = 23\n").unwrap();
    let result = show(dir.path(), &nested, &[]);
    assert_eq!(result["effective"]["limits"]["max_files"], 23);
    assert_eq!(result["effective"]["entropy"]["enabled"], true); // nearest policy replaces parent selection
}

#[test]
fn repository_boundary_including_worktrees_stops_parent_discovery() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("redflag.toml"),
        "[entropy]\nenabled = false\n",
    )
    .unwrap();
    let repo = dir.path().join("repo");
    fs::create_dir(&repo).unwrap();
    for worktree in [false, true] {
        let marker = repo.join(".git");
        if worktree {
            fs::write(&marker, "gitdir: elsewhere").unwrap();
        } else {
            fs::create_dir(&marker).unwrap();
        }
        let result = show(dir.path(), &repo, &[]);
        assert!(result["config_path"].is_null());
        assert_eq!(result["effective"]["entropy"]["enabled"], true);
        if worktree {
            fs::remove_file(marker).unwrap();
        } else {
            fs::remove_dir(marker).unwrap();
        }
    }
}

#[test]
fn explicit_policy_and_no_config_override_discovery() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("redflag.toml"), "broken syntax!!").unwrap();
    fs::write(dir.path().join("chosen.toml"), "[limits]\nmax_files = 17\n").unwrap();
    let explicit = show(dir.path(), dir.path(), &["--config", "chosen.toml"]);
    assert_eq!(explicit["effective"]["limits"]["max_files"], 17);
    let defaults = show(dir.path(), dir.path(), &["--no-config"]);
    assert!(defaults["config_path"].is_null());
    assert_eq!(defaults["effective"]["limits"]["max_files"], 100000);
    let output = run(
        dir.path(),
        &["show-config", "--config", "chosen.toml", "--no-config"],
    );
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn invalid_discovered_rules_and_unknown_sections_fail_before_output() {
    let dir = tempdir().unwrap();
    for contents in [
        "[entrophy]\nenabled = false\n",
        "[[patterns]]\nname = 'bad'\npattern = '['\ndescription = 'invalid'\nseverity = 'High'\n",
    ] {
        fs::write(dir.path().join("redflag.toml"), contents).unwrap();
        for command in ["show-config", "scan", "artifacts"] {
            let output = run(dir.path(), &[command, ".", "--format", "json"]);
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
        }
    }
}

#[test]
fn source_scan_uses_discovered_custom_policy() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("redflag.toml"), "[[patterns]]\nname = 'reviewed-custom'\npattern = 'synthetic-marker'\ndescription = 'Test fixture rule'\nseverity = 'High'\n").unwrap();
    let file = dir.path().join("sample.rs");
    fs::write(&file, "synthetic-marker").unwrap();
    let output = run(
        dir.path(),
        &["scan", file.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(output.status.code(), Some(1));
    let findings: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(findings[0]["pattern_name"], "reviewed-custom");
    assert!(
        run(dir.path(), &["scan", file.to_str().unwrap(), "--no-config"])
            .status
            .success()
    );
}

#[test]
fn artifact_policy_comes_from_workflow_directory_and_digest_matches_show_config() {
    let dir = tempdir().unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir(&dist).unwrap();
    fs::write(dir.path().join("redflag.toml"), "[limits]\nmax_files = 5\n").unwrap();
    fs::write(dist.join("redflag.toml"), "this is output, not a policy").unwrap();
    let manifest = dir.path().join("manifest.json");
    let output = run(
        dir.path(),
        &[
            "artifacts",
            dist.to_str().unwrap(),
            "--manifest",
            manifest.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual: serde_json::Value = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
    let shown = show(dir.path(), dir.path(), &[]);
    assert_eq!(actual["config_sha256"], shown["sha256"]);
    assert_eq!(actual["limits"]["max_files"], 5);
}
