use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn token() -> String {
    ["ghp_", "aB3dE6gH9jK2mN5pQ8", "sT1vW4xY7zA0cD3fG6"].concat()
}
fn scan(path: &Path, args: &[&str], private: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_redflag"));
    command
        .arg("artifacts")
        .arg(path)
        .args(["--engine", "native", "--no-config", "--format", "json"])
        .args(args);
    if let Some(value) = private {
        command
            .args(["--private-env", "RF_REVIEW_PRIVATE"])
            .env("RF_REVIEW_PRIVATE", value);
    }
    command.output().unwrap()
}
fn verify(path: &Path, target: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_redflag"));
    command
        .arg("verify-artifacts")
        .arg(path)
        .args(["--format", "json"]);
    if let Some(target) = target {
        command.arg("--target").arg(target);
    }
    command.output().unwrap()
}
fn report(output: Output, expected: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&token()));
    serde_json::from_slice(&output.stdout).unwrap()
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
fn policy(report: &Value) -> Value {
    let expires = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
    let entries: Vec<_> = report["logical_findings"].as_array().unwrap().iter()
        .flat_map(|g| g["occurrences"].as_array().unwrap())
        .map(|o| json!({"occurrence_id":o["id"],"kind":"false_positive","reason":"Reviewed synthetic public example","reviewed_by":"fixture-reviewer","expires_at":expires})).collect();
    json!({"schema_version":1,"mode":"artifacts","exceptions":entries})
}
fn write(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

#[test]
fn artifact_reviews_authorize_exact_versions_and_manifests_retain_the_review() {
    let dir = tempdir().unwrap();
    let dist = dir.path().join("dist");
    let copy = dir.path().join("copy");
    for root in [&dist, &copy] {
        fs::create_dir(root).unwrap();
        fs::write(
            root.join("example.js"),
            format!("// synthetic example\n{}\n", token()),
        )
        .unwrap();
    }
    let before = report(scan(&dist, &[], None), 1);
    let review = dir.path().join("review.json");
    write(&review, &policy(&before));
    let manifest = dir.path().join("manifest.json");
    let args = [
        "--exceptions",
        review.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
    ];
    let accepted = report(scan(&dist, &args, None), 0);
    assert_eq!(accepted["findings_count"], 1);
    assert_eq!(accepted["blocking_occurrences_count"], 0);
    assert_eq!(accepted["accepted_occurrences_count"], 1);
    let saved: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(saved["schema_version"], 4);
    assert_eq!(saved["findings_count"], 1);
    assert_eq!(saved["blocking_occurrences_count"], 0);
    assert_eq!(saved["approval"]["policy"], accepted["exception_policy"]);
    assert_eq!(
        saved["approval"]["policy"]["sha256"],
        format!("{:x}", Sha256::digest(fs::read(&review).unwrap()))
    );
    assert_eq!(
        saved["approval"]["occurrences"][0]["occurrence_id"],
        before["logical_findings"][0]["occurrences"][0]["id"]
    );
    assert_eq!(saved["approval"]["occurrences"][0]["path"], "example.js");
    assert!(!fs::read_to_string(&manifest).unwrap().contains(&token()));
    for target in [None, Some(copy.as_path())] {
        let verified = report(verify(&manifest, target), 0);
        assert_eq!(verified["coverage"]["accepted_occurrences_count"], 1);
        assert_eq!(verified["coverage"]["findings_count"], 1);
    }
    fs::write(dist.join("new.js"), format!("{}\n", token())).unwrap();
    let new = report(scan(&dist, &args, None), 1);
    assert_eq!(new["accepted_occurrences_count"], 1);
    assert_eq!(new["blocking_occurrences_count"], 1);
    assert!(!manifest.exists());
    fs::remove_file(dist.join("new.js")).unwrap();
    fs::write(
        dist.join("example.js"),
        format!("// changed example\n{}\n", token()),
    )
    .unwrap();
    let changed = report(scan(&dist, &args, None), 1);
    assert_eq!(changed["accepted_occurrences_count"], 0);
    assert!(!manifest.exists());
}

#[test]
fn source_scope_and_accepted_debt_cannot_authorize_publication() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input");
    fs::write(&file, token()).unwrap();
    let valid = policy(&report(scan(&file, &[], None), 1));
    let review = dir.path().join("review.json");
    let manifest = dir.path().join("manifest.json");
    let args = [
        "--exceptions",
        review.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
    ];
    let mut bad = valid.clone();
    bad["mode"] = "changes".into();
    write(&review, &bad);
    fs::write(&manifest, "old manifest").unwrap();
    incomplete(scan(&file, &args, None));
    assert!(!manifest.exists());
    let mut bad = valid.clone();
    bad["exceptions"][0]["kind"] = "accepted_debt".into();
    write(&review, &bad);
    incomplete(scan(&file, &args, None));
    write(&review, &valid);
    report(scan(&file, &args, None), 0);
    report(scan(&file, &["--no-exceptions"], None), 1);
    // Even an artifact-labelled policy is not auto-discovered from the workflow directory.
    write(&dir.path().join("redflag-exceptions.json"), &valid);
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .current_dir(dir.path())
        .arg("artifacts")
        .arg(&file)
        .args(["--engine", "native", "--no-config", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(report(output, 1)["accepted_occurrences_count"], 0);
}

#[test]
fn exact_private_values_cannot_be_exempted_and_review_metadata_is_redacted() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input");
    let value = token();
    fs::write(&file, format!("private: {value}\n")).unwrap();
    let before = report(scan(&file, &[], Some(&value)), 1);
    let mut reviewed = policy(&before);
    reviewed["exceptions"][0]["reason"] = format!("Review includes {value}").into();
    reviewed["exceptions"][0]["reviewed_by"] = value.clone().into();
    let review = dir.path().join("review.json");
    write(&review, &reviewed);
    let manifest = dir.path().join("manifest.json");
    fs::write(&manifest, "old manifest").unwrap();
    let result = report(
        scan(
            &file,
            &[
                "--exceptions",
                review.to_str().unwrap(),
                "--manifest",
                manifest.to_str().unwrap(),
            ],
            Some(&value),
        ),
        1,
    );
    assert_eq!(result["accepted_occurrences_count"], 0);
    assert_eq!(result["blocking_occurrences_count"], 1);
    assert_eq!(
        result["exception_policy"]["rejected_private_occurrences"],
        1
    );
    let decision = &result["logical_findings"][0]["occurrences"][0]["exception"];
    assert_eq!(decision["status"], "rejected_private_value");
    assert_eq!(decision["reason"], "[REDACTED PRIVATE VALUE]");
    assert_eq!(decision["reviewed_by"], "[REDACTED PRIVATE VALUE]");
    assert!(!manifest.exists());
    // A private value present only in policy metadata must not reach a permitted manifest.
    for format in ["text", "github"] {
        let summary = dir.path().join("summary.md");
        let mut command = Command::new(env!("CARGO_BIN_EXE_redflag"));
        command
            .arg("artifacts")
            .arg(&file)
            .args(["--engine", "native", "--no-config", "--format", format])
            .arg("--exceptions")
            .arg(&review)
            .args(["--private-env", "RF_REVIEW_PRIVATE"])
            .env("RF_REVIEW_PRIVATE", &value);
        if format == "github" {
            command.arg("--github-summary").arg(&summary);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains(&value));
        if format == "github" {
            assert!(text.starts_with("::error "));
            let text = fs::read_to_string(summary).unwrap();
            assert!(text.contains("REJECTED"));
            assert!(!text.contains(&value));
        } else {
            assert!(text.contains("cannot authorize a declared private value"));
        }
    }
    let metadata_private = "review-only-opaque-material";
    let mut reviewed = policy(&report(scan(&file, &[], Some(metadata_private)), 1));
    reviewed["exceptions"][0]["reason"] = format!("Review includes {metadata_private}").into();
    write(&review, &reviewed);
    let output = scan(
        &file,
        &[
            "--exceptions",
            review.to_str().unwrap(),
            "--manifest",
            manifest.to_str().unwrap(),
        ],
        Some(metadata_private),
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(metadata_private));
    report(output, 0);
    assert!(!fs::read_to_string(&manifest)
        .unwrap()
        .contains(metadata_private));
    report(verify(&manifest, None), 0);
}

#[test]
fn expired_reviews_block_rescans_and_manifest_verification() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input");
    fs::write(&file, token()).unwrap();
    let mut reviewed = policy(&report(scan(&file, &[], None), 1));
    let review = dir.path().join("review.json");
    write(&review, &reviewed);
    let manifest = dir.path().join("manifest.json");
    let args = [
        "--exceptions",
        review.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
    ];
    report(scan(&file, &args, None), 0);
    let mut saved: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    saved["approval"]["occurrences"][0]["review"]["expires_at"] = "2000-01-01T00:00:00Z".into();
    write(&manifest, &saved);
    let expired = verify(&manifest, None);
    assert!(String::from_utf8_lossy(&expired.stderr).contains("expired"));
    incomplete(expired);
    reviewed["exceptions"][0]["expires_at"] = "2000-01-01T00:00:00Z".into();
    write(&review, &reviewed);
    let result = report(scan(&file, &args, None), 1);
    assert_eq!(result["blocking_occurrences_count"], 1);
    assert_eq!(result["exception_policy"]["expired_entries"], 1);
    assert!(!manifest.exists());
}

#[test]
fn inconsistent_manifest_review_scope_counts_and_locations_are_rejected() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input");
    fs::write(&file, token()).unwrap();
    let review = dir.path().join("review.json");
    write(&review, &policy(&report(scan(&file, &[], None), 1)));
    let manifest = dir.path().join("manifest.json");
    report(
        scan(
            &file,
            &[
                "--exceptions",
                review.to_str().unwrap(),
                "--manifest",
                manifest.to_str().unwrap(),
            ],
            None,
        ),
        0,
    );
    let valid: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    for (pointer, value) in [
        ("/schema_version", json!(2)),
        ("/blocking_occurrences_count", json!(1)),
        ("/approval/policy/mode", json!("changes")),
        ("/approval/policy/accepted_occurrences", json!(0)),
        ("/approval/policy/rejected_private_occurrences", json!(1)),
        ("/approval/policy/sha256", Value::Null),
        ("/approval/occurrences/0/target", json!(99)),
        ("/approval/occurrences/0/path", json!("../escape")),
        ("/approval/occurrences/0/file_sha256", json!("0".repeat(64))),
        (
            "/approval/occurrences/0/review/kind",
            json!("accepted_debt"),
        ),
        (
            "/approval/occurrences/0/review/status",
            json!("rejected_private_value"),
        ),
        ("/approval/occurrences/0/review/reason", json!("")),
    ] {
        let mut bad = valid.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        write(&manifest, &bad);
        incomplete(verify(&manifest, None));
    }
    let mut duplicate = valid.clone();
    duplicate["findings_count"] = json!(2);
    for field in ["entry_count", "matched_entries", "accepted_occurrences"] {
        duplicate["approval"]["policy"][field] = json!(2);
    }
    let record = duplicate["approval"]["occurrences"][0].clone();
    duplicate["approval"]["occurrences"]
        .as_array_mut()
        .unwrap()
        .push(record);
    write(&manifest, &duplicate);
    incomplete(verify(&manifest, None));
}

#[test]
fn output_paths_cannot_destroy_policy_inputs() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input");
    fs::write(&input, "public bytes").unwrap();
    let review = dir.path().join("review.json");
    write(
        &review,
        &json!({"schema_version":1,"mode":"artifacts","exceptions":[]}),
    );
    let bytes = fs::read(&review).unwrap();
    incomplete(scan(
        &input,
        &[
            "--exceptions",
            review.to_str().unwrap(),
            "--manifest",
            review.to_str().unwrap(),
        ],
        None,
    ));
    assert_eq!(fs::read(&review).unwrap(), bytes);
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(&input)
        .args(["--engine", "native", "--no-config", "--format", "github"])
        .arg("--exceptions")
        .arg(&review)
        .arg("--github-summary")
        .arg(&review)
        .output()
        .unwrap();
    incomplete(output);
    assert_eq!(fs::read(&review).unwrap(), bytes);
    let config = dir.path().join("redflag.toml");
    fs::write(&config, "[entropy]\nenabled=false\n").unwrap();
    let bytes = fs::read(&config).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .current_dir(dir.path())
        .arg("artifacts")
        .arg(&input)
        .args(["--engine", "native"])
        .arg("--manifest")
        .arg(&config)
        .output()
        .unwrap();
    incomplete(output);
    assert_eq!(fs::read(&config).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn fifo_exception_inputs_fail_without_waiting_for_a_writer() {
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };
    let dir = tempdir().unwrap();
    let input = dir.path().join("input");
    fs::write(&input, "public bytes").unwrap();
    let fifo = dir.path().join("policy.fifo");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let mut child = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(input)
        .args(["--engine", "native", "--no-config", "--format", "json"])
        .arg("--exceptions")
        .arg(fifo)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > Duration::from_secs(2) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("Reading an exception policy blocked on a FIFO");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    incomplete(child.wait_with_output().unwrap());
}
