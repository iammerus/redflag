use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn scan(path: &Path, args: &[&str], vars: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_redflag"));
    command
        .arg("artifacts")
        .arg(path)
        .args(["--format", "json"])
        .args(args);
    for (name, value) in vars {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn report(output: &Output, exit: i32) -> serde_json::Value {
    assert_eq!(
        output.status.code(),
        Some(exit),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn incomplete(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(output.stdout.is_empty());
}

fn provider_token() -> String {
    ["ghp_", "abcdefghijklmnopqrstuvwxyz", "1234567890AB"].concat()
}

#[test]
fn artifacts_inspect_hidden_html_unknown_and_source_ignored_paths() {
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join("node_modules")).unwrap();
    for name in [
        "index.html",
        ".hidden",
        "unknown.extension",
        "node_modules/file.js",
    ] {
        fs::write(
            dir.path().join(name),
            format!(
                "// redflag-ignore-next\nconst token = '{}'; // redflag-ignore",
                provider_token()
            ),
        )
        .unwrap();
    }
    let result = report(&scan(dir.path(), &[], &[]), 1);
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["mode"], "artifacts");
    assert_eq!(result["complete"], true);
    assert_eq!(result["coverage"]["files"].as_array().unwrap().len(), 4);
    assert_eq!(result["findings_count"], 4);
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|finding| finding["snippet"] == "[REDACTED]"));
}

#[test]
fn exact_values_include_binary_multiline_overlap_and_read_boundaries() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("binary.data");
    let mut bytes = vec![b'!'; 65532];
    bytes.extend_from_slice(b"abcabcabc\nfirst\nsecond\xff\0ABCabcabc");
    fs::write(&file, bytes).unwrap();
    let result = report(
        &scan(
            &file,
            &[
                "--private-env",
                "RF_OVERLAP",
                "--allow-short-private-value",
                "RF_OVERLAP",
                "--private-env",
                "RF_MULTILINE",
            ],
            &[("RF_OVERLAP", "abcabc"), ("RF_MULTILINE", "first\nsecond")],
        ),
        1,
    );
    let findings = result["findings"].as_array().unwrap();
    let overlap: Vec<_> = findings
        .iter()
        .filter(|f| f["pattern_name"] == "private-env:RF_OVERLAP")
        .collect();
    assert_eq!(overlap.len(), 3);
    assert_eq!(overlap[0]["line"], 1);
    assert_eq!(overlap[2]["line"], 3);
    let multiline = findings
        .iter()
        .find(|f| f["pattern_name"] == "private-env:RF_MULTILINE")
        .unwrap();
    assert_eq!(multiline["line"], 2);
}

#[test]
fn exact_matching_does_not_normalize_case_or_search_undeclared_environment() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("output");
    fs::write(&file, "privatevalue somethingelse").unwrap();
    let result = report(
        &scan(
            &file,
            &["--private-env", "RF_CASE"],
            &[
                ("RF_CASE", "PrivateValue"),
                ("RF_UNDECLARED", "somethingelse"),
            ],
        ),
        0,
    );
    assert_eq!(
        result["coverage"]["private_env"],
        serde_json::json!(["RF_CASE"])
    );
}

#[test]
fn private_values_are_absent_even_from_nearby_native_snippets() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("index.html");
    let private = "nearby-private-output";
    fs::write(&file, format!("{private} {}", provider_token())).unwrap();
    for format in ["json", "text"] {
        let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
            .arg("artifacts")
            .arg(&file)
            .args(["--format", format, "--private-env", "RF_PRIVATE"])
            .env("RF_PRIVATE", private)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(private));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(private));
    }
}

#[test]
fn missing_empty_short_and_invalid_declarations_fail_closed() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("ok"), "ordinary prose").unwrap();
    let absent = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(dir.path())
        .args(["--format", "json", "--private-env", "RF_MISSING"])
        .env_remove("RF_MISSING")
        .output()
        .unwrap();
    incomplete(&absent);
    for value in ["", "short"] {
        let output = scan(
            dir.path(),
            &["--private-env", "RF_EMPTY"],
            &[("RF_EMPTY", value)],
        );
        incomplete(&output);
    }
    incomplete(&scan(dir.path(), &["--private-env", "9INVALID"], &[]));
    incomplete(&scan(
        dir.path(),
        &["--allow-short-private-value", "UNDECLARED"],
        &[],
    ));
    incomplete(&scan(
        dir.path(),
        &[
            "--private-env",
            "RF_EMPTY",
            "--allow-short-private-value",
            "RF_EMPTY",
        ],
        &[("RF_EMPTY", "")],
    ));
}

#[test]
fn missing_empty_targets_and_overlapping_selections_are_errors() {
    let dir = tempdir().unwrap();
    incomplete(&scan(&dir.path().join("missing"), &[], &[]));
    incomplete(&scan(dir.path(), &[], &[]));
    let empty = dir.path().join("empty");
    fs::write(&empty, "").unwrap();
    incomplete(&scan(&empty, &[], &[]));
    incomplete(&scan(dir.path(), &[], &[]));
    fs::write(&empty, "hello").unwrap();
    incomplete(&scan(dir.path(), &[empty.to_str().unwrap()], &[]));
}

#[cfg(unix)]
#[test]
fn symlinks_broken_links_and_special_files_are_errors() {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    let dir = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let file = outside.path().join("data");
    fs::write(&file, "hello").unwrap();
    let link = dir.path().join("link");
    symlink(&file, &link).unwrap();
    incomplete(&scan(dir.path(), &[], &[]));
    incomplete(&scan(&link, &[], &[]));
    fs::remove_file(&file).unwrap();
    incomplete(&scan(dir.path(), &[], &[]));
    fs::remove_file(&link).unwrap();
    let _socket = UnixListener::bind(dir.path().join("socket")).unwrap();
    incomplete(&scan(dir.path(), &[], &[]));
}

#[test]
fn artifact_limits_are_explicit_and_fail_before_json_output() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("dist");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("one"), "hello").unwrap();
    fs::write(input.join("two"), "world").unwrap();
    let config = dir.path().join("policy.toml");
    for limit in [
        "max_files = 1",
        "max_total_bytes = 9",
        "max_file_bytes = 4",
        "max_line_bytes = 4",
    ] {
        fs::write(&config, format!("[limits]\n{limit}\n")).unwrap();
        incomplete(&scan(&input, &["--config", config.to_str().unwrap()], &[]));
    }
    fs::write(
        &config,
        "[limits]\nmax_files = 2\nmax_total_bytes = 10\nmax_file_bytes = 5\nmax_line_bytes = 5\n",
    )
    .unwrap();
    assert_eq!(
        report(
            &scan(&input, &["--config", config.to_str().unwrap()], &[]),
            0
        )["coverage"]["total_bytes"],
        10
    );
}
