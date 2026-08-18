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
        .args(["--engine", "native"])
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
    ["ghp_", "abcdefghijklmnopqrstuvwxyz", "1234567890"].concat()
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
            .args(["--engine", "native"])
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

fn verify(manifest: &Path, targets: &[&Path]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_redflag"));
    command
        .arg("verify-artifacts")
        .arg(manifest)
        .args(["--format", "json"]);
    for target in targets {
        command.arg("--target").arg(target);
    }
    command.output().unwrap()
}

#[test]
fn clean_manifest_verifies_original_and_relocated_bytes() {
    let dir = tempdir().unwrap();
    let dist = dir.path().join("dist");
    let upload = dir.path().join("upload");
    fs::create_dir(&dist).unwrap();
    fs::create_dir(&upload).unwrap();
    for root in [&dist, &upload] {
        fs::write(root.join("index.html"), "<h1>Hello</h1>").unwrap();
        fs::write(root.join(".empty"), "").unwrap();
    }
    let manifest = dir.path().join("manifest.json");
    report(
        &scan(
            &dist,
            &[
                "--manifest",
                manifest.to_str().unwrap(),
                "--private-env",
                "RF_MANIFEST",
            ],
            &[("RF_MANIFEST", "unpublished-private-value")],
        ),
        0,
    );
    let text = fs::read_to_string(&manifest).unwrap();
    assert!(!text.contains("unpublished-private-value"));
    let result = report(&verify(&manifest, &[]), 0);
    assert_eq!(result["mode"], "verify_artifacts");
    assert_eq!(result["coverage"]["files"], 2);
    report(&verify(&manifest, &[&upload]), 0);
    // Metadata-only changes do not invalidate byte identity.
    fs::write(upload.join("index.html"), "<h1>Hello</h1>").unwrap();
    report(&verify(&manifest, &[&upload]), 0);
}

#[test]
fn changed_added_removed_and_retyped_files_invalidate_manifest() {
    let dir = tempdir().unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir(&dist).unwrap();
    let file = dist.join("data");
    fs::write(&file, "hello").unwrap();
    let manifest = dir.path().join("manifest.json");
    report(
        &scan(&dist, &["--manifest", manifest.to_str().unwrap()], &[]),
        0,
    );
    fs::write(&file, "world").unwrap(); // Same size, different digest.
    incomplete(&verify(&manifest, &[]));
    fs::write(&file, "hello").unwrap();
    fs::write(dist.join("extra"), "").unwrap();
    incomplete(&verify(&manifest, &[]));
    fs::remove_file(dist.join("extra")).unwrap();
    fs::remove_file(&file).unwrap();
    incomplete(&verify(&manifest, &[]));
    fs::create_dir(&file).unwrap();
    fs::write(file.join("replacement"), "hello").unwrap();
    incomplete(&verify(&manifest, &[]));
}

#[test]
fn failed_rescans_invalidate_prior_manifest_without_destroying_input() {
    let dir = tempdir().unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir(&dist).unwrap();
    let file = dist.join("data");
    fs::write(&file, "hello").unwrap();
    let manifest = dir.path().join("manifest.json");
    let args = ["--manifest", manifest.to_str().unwrap()];
    report(&scan(&dist, &args, &[]), 0);
    fs::write(&file, provider_token()).unwrap();
    report(&scan(&dist, &args, &[]), 1);
    assert!(!manifest.exists());
    fs::write(&manifest, "stale").unwrap();
    incomplete(&scan(
        &dist,
        &[
            "--manifest",
            manifest.to_str().unwrap(),
            "--config",
            "missing-policy.toml",
        ],
        &[],
    ));
    assert!(!manifest.exists());
    fs::write(&manifest, "stale").unwrap();
    incomplete(&scan(&dist.join("missing"), &args, &[]));
    assert!(!manifest.exists());
    incomplete(&scan(&dist, &["--manifest", file.to_str().unwrap()], &[]));
    assert_eq!(fs::read_to_string(file).unwrap(), provider_token());
}

#[test]
fn malformed_and_unsafe_manifests_are_rejected() {
    let dir = tempdir().unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir(&dist).unwrap();
    fs::write(dist.join("data"), "hello").unwrap();
    let manifest = dir.path().join("manifest.json");
    report(
        &scan(&dist, &["--manifest", manifest.to_str().unwrap()], &[]),
        0,
    );
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    for (field, value) in [
        ("schema_version", serde_json::json!(999)),
        ("complete", serde_json::json!(false)),
        ("findings_count", serde_json::json!(1)),
        ("total_bytes", serde_json::json!(6)),
    ] {
        let mut bad = original.clone();
        bad[field] = value;
        fs::write(&manifest, serde_json::to_vec(&bad).unwrap()).unwrap();
        incomplete(&verify(&manifest, &[]));
    }
    for path in ["../outside", "/absolute/path", ""] {
        let mut bad = original.clone();
        bad["files"][0]["path"] = path.into();
        fs::write(&manifest, serde_json::to_vec(&bad).unwrap()).unwrap();
        incomplete(&verify(&manifest, &[]));
    }
}

#[cfg(unix)]
#[test]
fn manifest_verification_rejects_symlink_replacements() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir(&dist).unwrap();
    let file = dist.join("data");
    fs::write(&file, "hello").unwrap();
    let manifest = dir.path().join("manifest.json");
    report(
        &scan(&dist, &["--manifest", manifest.to_str().unwrap()], &[]),
        0,
    );
    let outside = dir.path().join("outside");
    fs::rename(&file, &outside).unwrap();
    symlink(&outside, &file).unwrap();
    incomplete(&verify(&manifest, &[]));
    let manifest_link = dir.path().join("link");
    symlink(&manifest, &manifest_link).unwrap();
    incomplete(&scan(
        &dist,
        &["--manifest", manifest_link.to_str().unwrap()],
        &[],
    ));
    assert!(manifest.exists());
}
