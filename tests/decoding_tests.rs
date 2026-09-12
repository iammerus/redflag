use base64::{engine::general_purpose, Engine};
use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn percent(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("%{byte:02X}")).collect()
}
fn escaped(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .encode_utf16()
            .map(|unit| format!("\\u{unit:04x}"))
            .collect::<String>()
    )
}
fn scan(path: &Path, value: &str, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_redflag"));
    command
        .arg("artifacts")
        .arg(path)
        .args([
            "--engine",
            "native",
            "--format",
            "json",
            "--private-env",
            "RF_DECODE_PRIVATE",
        ])
        .env("RF_DECODE_PRIVATE", value);
    if !args.contains(&"--config") {
        command.arg("--no-config");
    }
    if value.len() < 8 {
        command.args(["--allow-short-private-value", "RF_DECODE_PRIVATE"]);
    }
    command.args(args).output().unwrap()
}
fn report(output: Output, expected: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn private(report: &Value) -> Vec<&Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["pattern_name"] == "private-env:RF_DECODE_PRIVATE")
        .collect()
}
fn policy(path: &Path, limits: &str) {
    fs::write(
        path,
        format!("[entropy]\nenabled=false\nthreshold=4.5\nmin_length=20\n[limits]\n{limits}\n"),
    )
    .unwrap();
}
fn verify(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("verify-artifacts")
        .arg(path)
        .args(["--format", "json"])
        .output()
        .unwrap()
}

#[test]
fn decoded_private_values_retain_unicode_binary_and_transform_provenance() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("payload.bin");
    let value = "opaque☃😀/λ\nvalue!";
    let wrapped = [b"\xffuser:".as_slice(), value.as_bytes(), b"\x80suffix"].concat();
    let cases = [
        (escaped(value), "json_string"),
        (percent(value.as_bytes()), "url_percent"),
        (general_purpose::STANDARD.encode(&wrapped), "base64"),
        (general_purpose::STANDARD_NO_PAD.encode(&wrapped), "base64"),
        (general_purpose::URL_SAFE.encode(&wrapped), "base64"),
        (general_purpose::URL_SAFE_NO_PAD.encode(&wrapped), "base64"),
    ];
    for (encoded, kind) in cases {
        fs::write(&file, format!("header\n{encoded}\n")).unwrap();
        let output = scan(&file, value, &[]);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(value));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(&encoded));
        let report = report(output, 1);
        let found = private(&report);
        assert_eq!(
            found.len(),
            1,
            "{kind}: {}",
            report["coverage"]["private_decoding"]
        );
        assert_eq!(found[0]["line"], 2);
        assert_eq!(found[0]["representation"][0]["kind"], kind);
        assert_eq!(found[0]["representation"][0]["encoded"]["start_line"], 2);
        assert_eq!(found[0]["representation"][0]["decoded"]["end_line"], 2);
        assert_eq!(found[0]["snippet"], "[REDACTED]");
        let occurrence = report["logical_findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| {
                group["private_env"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|name| name == "RF_DECODE_PRIVATE")
            })
            .unwrap();
        assert_eq!(
            occurrence["occurrences"][0]["location"]["representation"],
            found[0]["representation"]
        );
    }
}

#[test]
fn recursive_candidate_decoding_finds_values_encoded_together_with_a_prefix() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input");
    let value = "opaque-Pvt!42";
    let encoded = escaped(&percent(
        general_purpose::STANDARD
            .encode(format!("user:{value}:suffix"))
            .as_bytes(),
    ));
    fs::write(&file, &encoded).unwrap();
    let found = report(scan(&file, value, &[]), 1);
    let private = private(&found);
    assert_eq!(private.len(), 1);
    let kinds: Vec<_> = private[0]["representation"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| step["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["json_string", "url_percent", "base64"]);
    assert!(
        private[0]["representation"][2]["decoded"]["start_column"]
            .as_u64()
            .unwrap()
            > 1
    );

    let copied = dir.path().join("copy");
    fs::write(&copied, &encoded).unwrap();
    let relocated = report(scan(&copied, value, &[]), 1);
    assert_eq!(found["logical_findings"], relocated["logical_findings"]);
    let summary = dir.path().join("summary.md");
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(&file)
        .args([
            "--no-config",
            "--engine",
            "native",
            "--format",
            "github",
            "--github-summary",
        ])
        .arg(&summary)
        .args(["--private-env", "RF_DECODE_PRIVATE"])
        .env("RF_DECODE_PRIVATE", value)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let summary = fs::read_to_string(summary).unwrap();
    assert!(summary.contains("json&#x5F;string"));
    assert!(summary.contains("base64"));
    assert!(!summary.contains(value));
    assert!(!summary.contains("opaque"));
    assert!(!summary.contains(&encoded));
}

#[test]
fn form_encoding_overlaps_and_unchanged_raw_regions_have_distinct_contracts() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input");
    let value = "opaque value +!";
    fs::write(&file, "opaque+value+%2B%21").unwrap();
    let result = report(scan(&file, value, &[]), 1);
    assert_eq!(private(&result)[0]["representation"][0]["kind"], "url_form");

    fs::write(&file, general_purpose::STANDARD.encode("ababa")).unwrap();
    let result = report(scan(&file, "aba", &[]), 1);
    assert_eq!(private(&result).len(), 2);
    let group = result["logical_findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| !group["private_env"].as_array().unwrap().is_empty())
        .unwrap();
    assert_eq!(group["occurrences"].as_array().unwrap().len(), 2);
    assert_ne!(group["occurrences"][0]["id"], group["occurrences"][1]["id"]);

    let value = "opaque-Pvt!42";
    fs::write(&file, format!("\"{value}\\nmore\"\n")).unwrap();
    let result = report(scan(&file, value, &[]), 1);
    assert_eq!(private(&result).len(), 1);
    assert!(private(&result)[0].get("representation").is_none());
}

#[test]
fn decoding_limits_fail_before_output_and_invalidate_requested_manifests() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input");
    let config = dir.path().join("policy.toml");
    let manifest = dir.path().join("manifest.json");
    let value = "opaque-Pvt!42";
    let encoded = general_purpose::STANDARD.encode(value);
    fs::write(&file, &encoded).unwrap();
    policy(&config, "");
    let result = report(
        scan(&file, value, &["--config", config.to_str().unwrap()]),
        1,
    );
    let coverage = &result["coverage"]["private_decoding"];
    for (key, maximum) in [
        (
            "max_decode_candidates",
            coverage["candidates"].as_u64().unwrap(),
        ),
        (
            "max_decoded_bytes",
            coverage["decoded_bytes"].as_u64().unwrap(),
        ),
        (
            "max_decode_work_bytes",
            coverage["work_bytes"].as_u64().unwrap(),
        ),
    ] {
        policy(&config, &format!("{key}={maximum}"));
        report(
            scan(&file, value, &["--config", config.to_str().unwrap()]),
            1,
        );
        policy(&config, &format!("{key}={}", maximum - 1));
        fs::write(&manifest, "old approval").unwrap();
        let output = scan(
            &file,
            value,
            &[
                "--config",
                config.to_str().unwrap(),
                "--manifest",
                manifest.to_str().unwrap(),
            ],
        );
        assert_eq!(output.status.code(), Some(2), "{key}");
        assert!(output.stdout.is_empty());
        assert!(!manifest.exists());
    }
    fs::write(&file, general_purpose::STANDARD.encode(encoded)).unwrap();
    policy(&config, "max_decode_depth=2");
    report(
        scan(&file, value, &["--config", config.to_str().unwrap()]),
        1,
    );
    policy(&config, "max_decode_depth=1");
    let output = scan(&file, value, &["--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    fs::write(&file, "\"a\\u0062a\\u0062a\\u0062a\\u0062\"").unwrap();
    policy(&config, "max_decode_map_runs=8");
    report(
        scan(&file, "abababab", &["--config", config.to_str().unwrap()]),
        1,
    );
    policy(&config, "max_decode_map_runs=7");
    let output = scan(&file, "abababab", &["--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn clean_manifests_bind_decoding_coverage_and_private_reviews_cannot_override_it() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input");
    let config = dir.path().join("policy.toml");
    let manifest = dir.path().join("manifest.json");
    let review = dir.path().join("review.json");
    policy(&config, "");
    let value = "opaque-Pvt!42";
    fs::write(&file, escaped("ordinary public output")).unwrap();
    let result = report(
        scan(
            &file,
            value,
            &[
                "--config",
                config.to_str().unwrap(),
                "--manifest",
                manifest.to_str().unwrap(),
            ],
        ),
        0,
    );
    let verified = report(verify(&manifest), 0);
    assert_eq!(
        verified["coverage"]["private_decoding"],
        result["coverage"]["private_decoding"]
    );
    let saved: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(saved["schema_version"], 5);
    for (pointer, replacement) in [
        ("/schema_version", json!(3)),
        ("/private_decoding/enabled", json!(false)),
        ("/private_decoding/formats", json!([])),
        ("/private_decoding/max_depth_reached", json!(17)),
        ("/private_decoding/candidates", json!(u64::MAX)),
    ] {
        let mut invalid = saved.clone();
        *invalid.pointer_mut(pointer).unwrap() = replacement;
        fs::write(&manifest, serde_json::to_vec(&invalid).unwrap()).unwrap();
        let output = verify(&manifest);
        assert_eq!(output.status.code(), Some(2), "{pointer}");
        assert!(output.stdout.is_empty());
    }
    fs::write(&file, escaped(value)).unwrap();
    let result = report(
        scan(&file, value, &["--config", config.to_str().unwrap()]),
        1,
    );
    let id = &result["logical_findings"][0]["occurrences"][0]["id"];
    fs::write(&review, serde_json::to_vec(&json!({"schema_version":1,"mode":"artifacts","exceptions":[{
        "occurrence_id": id,"kind":"false_positive","reason":"Synthetic fixture review","reviewed_by":"Fixture",
        "expires_at":(chrono::Utc::now()+chrono::Duration::days(1)).to_rfc3339()
    }]})).unwrap()).unwrap();
    let rejected = report(
        scan(
            &file,
            value,
            &[
                "--config",
                config.to_str().unwrap(),
                "--exceptions",
                review.to_str().unwrap(),
                "--manifest",
                manifest.to_str().unwrap(),
            ],
        ),
        1,
    );
    assert_eq!(
        rejected["exception_policy"]["rejected_private_occurrences"],
        1
    );
    assert!(!manifest.exists());
}

#[test]
fn candidate_budgets_are_shared_across_files_and_fragments_are_not_joined() {
    let dir = tempdir().unwrap();
    let inputs = dir.path().join("inputs");
    fs::create_dir(&inputs).unwrap();
    let first = inputs.join("first");
    let second = inputs.join("second");
    let config = dir.path().join("policy.toml");
    let value = "opaque-Pvt!42";
    let encoded = general_purpose::STANDARD.encode(value);
    fs::write(&first, &encoded).unwrap();
    fs::write(&second, &encoded).unwrap();
    policy(&config, "max_decode_candidates=2");
    let result = report(
        scan(&inputs, value, &["--config", config.to_str().unwrap()]),
        1,
    );
    assert_eq!(result["coverage"]["private_decoding"]["candidates"], 2);
    assert_eq!(private(&result).len(), 2);
    policy(&config, "max_decode_candidates=1");
    let output = scan(&inputs, value, &["--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("max_decode_candidates"));

    fs::remove_file(second).unwrap();
    policy(&config, "");
    let fragments = format!(
        "{}\n{}",
        general_purpose::STANDARD.encode("prefix-opaque-"),
        general_purpose::STANDARD.encode("Pvt!42-suffix")
    );
    fs::write(&first, fragments).unwrap();
    let result = report(
        scan(&inputs, value, &["--config", config.to_str().unwrap()]),
        0,
    );
    assert!(private(&result).is_empty());
    assert_eq!(result["coverage"]["private_decoding"]["candidates"], 2);

    // Reject the complete malformed segment instead of a valid padded prefix.
    fs::write(
        &first,
        format!("{}=", general_purpose::STANDARD.encode("opaque-Pvt!42x")),
    )
    .unwrap();
    report(
        scan(
            &inputs,
            "opaque-Pvt!42x",
            &["--config", config.to_str().unwrap()],
        ),
        0,
    );
}

#[test]
fn shorter_decoded_candidates_have_a_valid_clean_receipt() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input");
    let manifest = dir.path().join("manifest.json");
    fs::write(&file, escaped("tiny")).unwrap();
    let result = report(
        scan(
            &file,
            "opaque-Pvt!42",
            &["--manifest", manifest.to_str().unwrap()],
        ),
        0,
    );
    let coverage = &result["coverage"]["private_decoding"];
    assert_eq!(coverage["decoded_bytes"], 4);
    assert_eq!(coverage["max_depth_reached"], 0);
    let verified = report(verify(&manifest), 0);
    assert_eq!(verified["coverage"]["private_decoding"], *coverage);
}
