use git2::{Repository, Signature};
use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
};
use tempfile::tempdir;

fn redflag(path: &Path) -> Output {
    redflag_with_args(&["scan", path.to_str().unwrap()])
}

fn redflag_with_args(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_redflag"))
        .args(args)
        .output()
        .unwrap()
}

fn write_secret(path: &Path) {
    let secret = synthetic_secret();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, format!("api_key = \"{secret}\"\n")).unwrap();
}

fn synthetic_secret() -> String {
    ["0123456789abcdef", "FEDCBA9876543210"].concat()
}

fn trunk_repo_with_deleted_secret() -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    let repo = Repository::init(&dir).unwrap();
    repo.set_head("refs/heads/trunk").unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    let path = dir.path().join("secret.rs");
    write_secret(&path);

    let mut index = repo.index().unwrap();
    index.add_path(Path::new("secret.rs")).unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let first = repo
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

    fs::remove_file(path).unwrap();
    let mut index = repo.index().unwrap();
    index.remove_path(Path::new("secret.rs")).unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let parent = repo.find_commit(first).unwrap();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "Remove secret",
        &tree,
        &[&parent],
    )
    .unwrap();
    drop(parent);
    drop(tree);
    drop(repo);
    dir
}

#[test]
fn missing_target_is_an_error() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("missing");
    let output = redflag(&path);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains(path.to_str().unwrap()));
}

#[test]
fn install_hook_is_not_available() {
    let output = redflag_with_args(&["install-hook"]);

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn version_matches_package() {
    let output = redflag_with_args(&["--version"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("redflag {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn generates_loadable_config() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("generated.toml");
    let output = redflag_with_args(&["generate-config", config.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(0));
    assert!(config.is_file());
    let source = dir.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("main.rs"), "fn main() {}\n").unwrap();
    assert_eq!(
        redflag_with_args(&[
            "scan",
            source.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ])
        .status
        .code(),
        Some(0)
    );
}

#[test]
fn clean_directory_exits_successfully() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    assert_eq!(redflag(dir.path()).status.code(), Some(0));
}

#[test]
fn clean_json_is_valid() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    let output = redflag_with_args(&["scan", dir.path().to_str().unwrap(), "--format", "json"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
}

#[test]
fn finding_json_is_valid() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join(".env"));
    let output = redflag_with_args(&["scan", dir.path().to_str().unwrap(), "--format", "json"]);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(!json.as_array().unwrap().is_empty());
}

#[test]
fn output_redacts_secrets_by_default() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join(".env"));

    for format in ["text", "json"] {
        let output = redflag_with_args(&["scan", dir.path().to_str().unwrap(), "--format", format]);
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(!stdout.contains(&synthetic_secret()));
        assert!(stdout.contains("[REDACTED]"));
    }
}

#[test]
fn show_secrets_is_explicit() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join(".env"));
    let output = redflag_with_args(&["scan", dir.path().to_str().unwrap(), "--show-secrets"]);

    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains(&synthetic_secret()));
}

#[test]
fn entropy_can_be_disabled() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("value.rs"),
        "opaque = \"abcdefghijklmnopqrstuvwxyzABCDEF\"\n",
    )
    .unwrap();
    let config = dir.path().join("redflag.toml");
    fs::write(&config, "[entropy]\nenabled = false\n").unwrap();
    let output = redflag_with_args(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn invalid_config_is_an_error() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    let config = dir.path().join("redflag.toml");
    fs::write(
        &config,
        "[[patterns]]\nname = \"broken\"\npattern = \"[\"\ndescription = \"Broken\"\n",
    )
    .unwrap();
    let output = redflag_with_args(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid regex"));
}

#[test]
fn history_defaults_to_head_on_trunk() {
    let dir = trunk_repo_with_deleted_secret();
    let output = redflag_with_args(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--git-history",
        "--format",
        "json",
    ]);
    let findings: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(!findings.as_array().unwrap().is_empty());
}

#[test]
fn missing_git_revision_is_an_error() {
    let dir = trunk_repo_with_deleted_secret();
    let output = redflag_with_args(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--git-history",
        "--git-branches",
        "does-not-exist",
        "--format",
        "json",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does-not-exist"));
}

#[test]
fn closed_output_pipe_is_an_error() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join(".env"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .args(["scan", dir.path().to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Broken pipe"));
}

#[test]
fn scans_env_dotfile() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join(".env"));

    assert_eq!(redflag(dir.path()).status.code(), Some(1));
}

#[test]
fn scans_test_named_file() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join("credentials_test.rs"));

    assert_eq!(redflag(dir.path()).status.code(), Some(1));
}

#[test]
fn scans_test_suffix_file() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join("credentials.test.rs"));

    assert_eq!(redflag(dir.path()).status.code(), Some(1));
}

#[test]
fn scans_packages_directory() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join("packages/service/config.rs"));

    assert_eq!(redflag(dir.path()).status.code(), Some(1));
}

#[test]
fn scans_explicit_extensionless_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("credentials");
    write_secret(&path);

    assert_eq!(redflag(&path).status.code(), Some(1));
}

#[test]
fn last_exclusion_rule_wins() {
    for (last_policy, expected) in [("ScanButAllow", 1), ("Ignore", 0)] {
        let dir = tempdir().unwrap();
        write_secret(&dir.path().join("secret.rs"));
        let config = dir.path().join("redflag.toml");
        fs::write(
            &config,
            format!(
                r#"
[[exclusions]]
pattern = "**/secret.rs"
policy = "Ignore"

[[exclusions]]
pattern = "**/secret.rs"
policy = "{last_policy}"
"#
            ),
        )
        .unwrap();
        let output = redflag_with_args(&[
            "scan",
            dir.path().to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ]);

        assert_eq!(output.status.code(), Some(expected));
    }
}

#[test]
fn scan_but_warn_uses_stderr() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join("warning.rs"));
    let config = dir.path().join("redflag.toml");
    fs::write(
        &config,
        r#"
[[exclusions]]
pattern = "**/warning.rs"
policy = "ScanButWarn"
"#,
    )
    .unwrap();
    let output = redflag_with_args(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("No secrets found"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("WARNING"));
}

#[test]
fn repeated_output_is_stable() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join("b.rs"));
    write_secret(&dir.path().join("a.rs"));
    let args = ["scan", dir.path().to_str().unwrap(), "--format", "json"];

    assert_eq!(
        redflag_with_args(&args).stdout,
        redflag_with_args(&args).stdout
    );
}

#[cfg(unix)]
#[test]
fn unreadable_file_is_an_error() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let path = dir.path().join("config.rs");
    fs::write(&path, "clean\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

    let output = redflag(&path);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains(path.to_str().unwrap()));
}
