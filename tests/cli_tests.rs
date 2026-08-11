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
fn redirected_progress_is_quiet() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    for extra in [None, Some("--no-progress")] {
        let mut args = vec!["scan", dir.path().to_str().unwrap()];
        args.extend(extra);
        let output = redflag_with_args(&args);

        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
    }
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
fn every_same_line_secret_is_found_and_redacted() {
    let dir = tempdir().unwrap();
    let first = ["0123456789abcdef", "FEDCBA9876543210"].concat();
    let second = ["abcdef0123456789", "0123456789FEDCBA"].concat();
    let password = ["password-", "123456"].concat();
    let contents = [
        "api_key = \"",
        &first,
        "\"; api_key = \"",
        &second,
        "\"; ",
        "pwd",
        " = \"",
        &password,
        "\"",
    ]
    .concat();
    fs::write(dir.path().join("secrets.rs"), contents).unwrap();
    let config = dir.path().join("redflag.toml");
    fs::write(&config, "[entropy]\nenabled = false\n").unwrap();
    let output = redflag_with_args(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding["pattern_name"] == "Generic API Key")
            .count(),
        2
    );
    assert!(findings.iter().all(|finding| {
        let snippet = finding["snippet"].as_str().unwrap();
        !snippet.contains(&first) && !snippet.contains(&second) && !snippet.contains(&password)
    }));
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
fn entropy_ignores_command_strings() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("settings.local.json"),
        r#"{
  "allow": [
    "Bash(GIT_AUTHOR_DATE=2026-01-01 git commit --amend --no-edit)",
    "A long prose permission containing spaces, punctuation, and numbers 12345"
  ]
}
"#,
    )
    .unwrap();

    assert_eq!(redflag(dir.path()).status.code(), Some(0));
}

#[test]
fn entropy_detects_opaque_json_value() {
    let dir = tempdir().unwrap();
    let token = [
        "ABCDEFGHIJKLMNOPQRST",
        "UVWXYZabcdefghijklmn",
        "opqrstuvwxyz0123456789",
    ]
    .concat();
    fs::write(
        dir.path().join("session.json"),
        format!(r#"{{"value": "{token}"}}"#),
    )
    .unwrap();

    assert_eq!(redflag(dir.path()).status.code(), Some(1));
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
fn repeated_exclusions_preserve_the_last_policy() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join("assets/secret.rs"));
    write_secret(&dir.path().join("node_modules/secret.rs"));
    let config = dir.path().join("redflag.toml");
    for (glob, policies, expected) in [
        (
            "**/assets/**",
            ["ScanButAllow", "Ignore", "ScanButAllow"],
            1,
        ),
        ("**/assets/**", ["Ignore", "ScanButAllow", "Ignore"], 0),
        (
            "**/node_modules/**",
            ["ScanButAllow", "Ignore", "ScanButAllow"],
            1,
        ),
    ] {
        // Restrict the target so the other fixture cannot conceal a missed rule.
        let target = if glob.contains("node_modules") {
            dir.path().join("node_modules/secret.rs")
        } else {
            dir.path().join("assets/secret.rs")
        };
        let other = if glob.contains("node_modules") {
            "**/assets/**"
        } else {
            "**/node_modules/**"
        };
        let mut contents = format!("[[exclusions]]\npattern = \"{other}\"\npolicy = \"Ignore\"\n");
        for policy in policies {
            contents.push_str(&format!(
                "[[exclusions]]\npattern = \"{glob}\"\npolicy = \"{policy}\"\n"
            ));
        }
        fs::write(&config, contents).unwrap();
        let output = redflag_with_args(&[
            "scan",
            dir.path().to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--format",
            "json",
        ]);
        assert_eq!(output.status.code(), Some(expected));
        let findings: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(findings.as_array().unwrap().len(), expected as usize);
        if expected == 1 {
            assert_eq!(findings[0]["file"], target.to_str().unwrap());
        }
    }
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
fn history_limits_fail_before_emitting_results() {
    let dir = trunk_repo_with_deleted_secret();
    for (limit, expected) in [(1, 2), (2, 1), (3, 1)] {
        let output = redflag_with_args(&[
            "scan",
            dir.path().to_str().unwrap(),
            "--git-history",
            "--git-max-depth",
            &limit.to_string(),
            "--format",
            "json",
        ]);
        assert_eq!(output.status.code(), Some(expected));
        if expected == 2 {
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("exceeds"));
        }
    }
}

#[test]
fn shallow_history_is_an_operational_failure() {
    let dir = trunk_repo_with_deleted_secret();
    let repo = Repository::open(dir.path()).unwrap();
    let head = repo.head().unwrap().target().unwrap();
    // Git's shallow boundary must be respected even when older objects happen
    // to remain locally (for example, after a partial fetch).
    fs::write(repo.path().join("shallow"), format!("{head}\n")).unwrap();
    drop(repo);
    let output = redflag_with_args(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--git-history",
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("shallow"));
}

#[test]
fn binary_classification_cannot_hide_history_content() {
    for (folder, prefix, expected) in [("app", 0u8, 1), ("app", 255u8, 2), ("vendor", 255u8, 0)] {
        let dir = tempdir().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        let signature = Signature::now("Test User", "test@example.com").unwrap();
        let path = Path::new(folder).join("secret.js");
        fs::create_dir_all(dir.path().join(folder)).unwrap();
        let mut bytes = vec![prefix];
        bytes.extend_from_slice(format!("api_key = \"{}\"\n", synthetic_secret()).as_bytes());
        fs::write(dir.path().join(&path), bytes).unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(&path).unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let first = repo
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "Add fixture",
                &tree,
                &[],
            )
            .unwrap();
        fs::remove_file(dir.path().join(&path)).unwrap();
        index.remove_path(&path).unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let parent = repo.find_commit(first).unwrap();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Remove fixture",
            &tree,
            &[&parent],
        )
        .unwrap();
        let output = redflag_with_args(&[
            "scan",
            dir.path().to_str().unwrap(),
            "--git-history",
            "--format",
            "json",
        ]);
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if expected == 2 {
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("not UTF-8"));
        } else {
            let findings: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(findings.as_array().unwrap().len(), expected as usize);
            if expected == 1 {
                assert_eq!(findings[0]["commit_hash"], first.to_string());
            }
        }
    }
}

#[test]
fn streaming_input_limits_fail_without_partial_json() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input.env");
    let config = dir.path().join("redflag.toml");
    fs::write(&config, "[limits]\nmax_line_bytes = 80\n").unwrap();
    let first = format!("api_key=\"{}\"\n", synthetic_secret());
    for (length, ending, expected) in [(80, "\n", 1), (80, "\r\n", 1), (81, "", 2)] {
        fs::write(&file, format!("{first}{}{ending}", "a".repeat(length))).unwrap();
        let output = redflag_with_args(&[
            "scan",
            file.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--format",
            "json",
        ]);
        assert_eq!(output.status.code(), Some(expected));
        if expected == 2 {
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("line limit"));
        } else {
            let findings: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(findings.as_array().unwrap().len(), 1);
        }
    }
    // Invalid text after a finding must also leave the final report unpublished.
    let mut invalid = first.into_bytes();
    invalid.push(255);
    fs::write(&file, invalid).unwrap();
    let output = redflag_with_args(&[
        "scan",
        file.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn file_and_discovery_limits_are_operational_failures() {
    let dir = tempdir().unwrap();
    let settings = tempdir().unwrap();
    let config = settings.path().join("redflag.toml");
    fs::write(&config, "[limits]\nmax_file_bytes = 10\nmax_files = 2\n").unwrap();
    let file = dir.path().join("large.txt");
    fs::write(&file, "a\n".repeat(6)).unwrap();
    let arguments = |path: &Path| {
        redflag_with_args(&[
            "scan",
            path.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--format",
            "json",
        ])
    };
    let output = arguments(&file);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("file limit"));
    fs::remove_file(file).unwrap();
    for index in 0..3 {
        fs::write(dir.path().join(format!("file-{index}.txt")), "safe").unwrap();
    }
    let output = arguments(dir.path());
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("2-file limit"));
    let history = trunk_repo_with_deleted_secret();
    let output = redflag_with_args(&[
        "scan",
        history.path().to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--git-history",
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("secret.rs exceeds"));
}

#[test]
fn history_preserves_template_context_before_diff_hunks() {
    let dir = tempdir().unwrap();
    let repo = Repository::init(dir.path()).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    let path = dir.path().join("template.js");
    let prefix = format!("const template = `\n{}", "ordinary text\n".repeat(20));
    fs::write(&path, format!("{prefix}old text\n`;\n")).unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("template.js")).unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let first = repo
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Start template",
            &tree,
            &[],
        )
        .unwrap();
    let marker = ["// redflag-", "ignore example"].concat();
    let token = ["ghp_", "aB3dE6gH9jK2mN5p", "Q8sT1vW4xY7zA0cD3fG6"].concat();
    fs::write(&path, format!("{prefix}{marker} {token}\n`;\n")).unwrap();
    index.add_path(Path::new("template.js")).unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let parent = repo.find_commit(first).unwrap();
    let second = repo
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Add literal",
            &tree,
            &[&parent],
        )
        .unwrap();
    let output = redflag_with_args(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--git-history",
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let findings: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(findings.as_array().unwrap().len(), 2);
    assert_eq!(findings[1]["commit_hash"], second.to_string());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&token));
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
fn git_options_require_history_scanning() {
    let dir = tempdir().unwrap();
    for arguments in [
        vec!["--git-max-depth", "10"],
        vec!["--git-since", "2026-01-01"],
        vec!["--git-until", "2026-12-31"],
        vec!["--git-branches", "missing"],
    ] {
        let mut command = vec!["scan", dir.path().to_str().unwrap()];
        command.extend(arguments);
        let output = redflag_with_args(&command);

        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--git-history"));
    }
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
fn default_exclusions_keep_secret_bearing_configuration() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join("env/secret.rs"));
    write_secret(&dir.path().join(".vscode/settings.json"));
    write_secret(&dir.path().join("package-lock.json"));
    let output = redflag_with_args(&["scan", dir.path().to_str().unwrap(), "--format", "json"]);
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();

    for path in [
        "env/secret.rs",
        ".vscode/settings.json",
        "package-lock.json",
    ] {
        assert!(findings
            .iter()
            .any(|finding| finding["file"].as_str().unwrap().ends_with(path)));
    }
    assert!(!findings.iter().any(|finding| {
        finding["file"]
            .as_str()
            .unwrap()
            .ends_with("package-lock.json")
            && finding["pattern_name"] == "high-entropy"
    }));
}

#[test]
fn scans_explicit_extensionless_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("credentials");
    write_secret(&path);

    assert_eq!(redflag(&path).status.code(), Some(1));
}

#[test]
fn scans_known_extensionless_files_in_directories() {
    let dir = tempdir().unwrap();
    let names = [
        ".npmrc",
        ".yarnrc",
        ".netrc",
        ".pypirc",
        "Dockerfile",
        "Containerfile",
        "Makefile",
        "Jenkinsfile",
    ];
    for name in names {
        write_secret(&dir.path().join(name));
    }
    let output = redflag_with_args(&["scan", dir.path().to_str().unwrap(), "--format", "json"]);
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();

    for name in names {
        assert!(findings
            .iter()
            .any(|finding| finding["file"].as_str().unwrap().ends_with(name)));
    }
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
fn exclusions_use_scan_root_relative_paths() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join("docs/examples/secret.rs"));
    let config = dir.path().join("redflag.toml");
    fs::write(
        &config,
        r#"
[[exclusions]]
pattern = "docs/examples/**"
policy = "Ignore"
"#,
    )
    .unwrap();

    let absolute = redflag_with_args(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    let relative = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .current_dir(dir.path())
        .args(["scan", ".", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(absolute.status.code(), Some(0));
    assert_eq!(relative.status.code(), Some(0));
}

#[test]
fn allowed_child_is_visited_inside_ignored_parent() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join("private/blocked/secret.rs"));
    write_secret(&dir.path().join("private/allowed/secret.rs"));
    let config = dir.path().join("redflag.toml");
    fs::write(
        &config,
        r#"
[[exclusions]]
pattern = "private/**"
policy = "Ignore"

[[exclusions]]
pattern = "private/allowed/**"
policy = "ScanButAllow"
"#,
    )
    .unwrap();
    let output = redflag_with_args(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(findings.len(), 1);
    assert!(findings[0]["file"]
        .as_str()
        .unwrap()
        .contains("private/allowed/secret.rs"));
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

#[cfg(unix)]
#[test]
fn json_input_error_leaves_stdout_empty() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    write_secret(&dir.path().join("a.rs"));
    let unreadable = dir.path().join("b.rs");
    fs::write(&unreadable, "clean\n").unwrap();
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();

    let output = redflag_with_args(&["scan", dir.path().to_str().unwrap(), "--format", "json"]);

    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
