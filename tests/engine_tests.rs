use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::tempdir;

fn token() -> String {
    ["ghp_", "aB3dE6gH9jK2mN5pQ8", "sT1vW4xY7zA0cD3fG6"].concat()
}

fn engine_path() -> PathBuf {
    let name = if cfg!(windows) {
        "betterleaks.exe"
    } else {
        "betterleaks"
    };
    let path = std::env::var_os("REDFLAG_BETTERLEAKS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_BIN_EXE_redflag"))
                .parent()
                .unwrap()
                .join("engines")
                .join(name)
        });
    assert!(path.is_file(), "Install the pinned engine with scripts/install_engine.py before running engine integration tests");
    path
}

fn scan(path: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(path)
        .args(["--no-config", "--format", "json", "--betterleaks-path"])
        .arg(engine_path())
        .args(args)
        .output()
        .unwrap()
}

fn report(output: Output, expected: i32) -> serde_json::Value {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn unpinned_executable_is_rejected_before_execution() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input");
    fs::write(&input, "hello").unwrap();
    let counterfeit = dir.path().join("engine");
    fs::write(&counterfeit, "not the pinned binary").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(input)
        .arg("--betterleaks-path")
        .arg(counterfeit)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("checksum"));
}

#[test]
fn missing_engine_does_not_fall_back_to_native() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("input"), "hello").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(dir.path())
        .arg("--betterleaks-path")
        .arg(dir.path().join("missing"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Pinned Betterleaks is unavailable"));
}

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn pinned_engine_inspects_all_selected_types_and_ignores_untrusted_policy() {
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join("node_modules")).unwrap();
    for path in [
        "index.html",
        ".hidden",
        "data.bin",
        "node_modules/a.txt",
        "asset.png",
    ] {
        let bytes = [
            b"SQLite format 3\0\xff\n".as_slice(),
            token().as_bytes(),
            b" // betterleaks:allow\n",
        ]
        .concat();
        fs::write(dir.path().join(path), bytes).unwrap();
    }
    fs::write(dir.path().join(".betterleaks.toml"), "prefilter = 'true'\n").unwrap();
    let result = report(
        Command::new(env!("CARGO_BIN_EXE_redflag"))
            .arg("artifacts")
            .arg(dir.path())
            .args(["--no-config", "--format", "json", "--betterleaks-path"])
            .arg(engine_path())
            .env("BETTERLEAKS_CONFIG", "/nonexistent/untrusted-policy")
            .env("GITLEAKS_CONFIG_TOML", "prefilter = 'true'")
            .output()
            .unwrap(),
        1,
    );
    assert_eq!(result["coverage"]["files"].as_array().unwrap().len(), 6);
    assert_eq!(result["coverage"]["engine"]["name"], "betterleaks");
    assert_eq!(result["coverage"]["engine"]["version"], "1.8.1");
    assert_eq!(result["coverage"]["engine"]["validation"], false);
    assert_eq!(result["findings_count"], 5);
    for finding in result["findings"].as_array().unwrap() {
        assert_eq!(finding["pattern_name"], "betterleaks:github-pat");
        assert_eq!(finding["line"], 2);
        assert_eq!(finding["snippet"], "[REDACTED]");
    }
}

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn engine_windows_preserve_locations_and_remove_overlap_duplicates() {
    let dir = tempdir().unwrap();
    for offset in [0, 32768, 65536, 125000, 196599] {
        let mut bytes = vec![b' '; offset];
        bytes.extend_from_slice(token().as_bytes());
        bytes.extend_from_slice(b"\n");
        fs::write(dir.path().join(format!("{offset}.js")), bytes).unwrap();
    }
    let result = report(scan(dir.path(), &[]), 1);
    assert_eq!(result["findings_count"], 5);
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["line"] == 1));
    let multibyte = dir.path().join("unicode.js");
    fs::write(&multibyte, format!("{}\n{}", "é\n".repeat(22000), token())).unwrap();
    let result = report(scan(&multibyte, &[]), 1);
    assert_eq!(result["findings_count"], 1);
    assert_eq!(result["findings"][0]["line"], 22002);
    let long = dir.path().join("long.js");
    fs::write(
        &long,
        format!(
            "{}{}",
            ["xoxb-", "752016349821-572019482631-"].concat(),
            "aB3dE6gH9jK2mN5pQ8".repeat(6000)
        ),
    )
    .unwrap();
    let output = scan(&long, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("window boundary"));
}

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn artificial_window_boundaries_cannot_create_provider_tokens() {
    let dir = tempdir().unwrap();
    let mut left = vec![b' '; 32767];
    left.extend_from_slice(format!("X{} ", token()).as_bytes());
    fs::write(dir.path().join("left.js"), left).unwrap();
    let mut right = vec![b' '; 65536 - token().len()];
    right.extend_from_slice(format!("{}X ", token()).as_bytes());
    fs::write(dir.path().join("right.js"), right).unwrap();
    report(scan(dir.path(), &[]), 0);
}

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn multipart_evidence_that_cannot_fit_an_adjacent_window_fails_explicitly() {
    let dir = tempdir().unwrap();
    let key = ["AKIA", "Q7W2E5R3T6Y4U2I7"].concat();
    let secret = ["mP9xR2vL7kN4qW6tY3cB8dF5", "hJ1sA0uE9gZ2iO4p"].concat();
    let component = format!("aws_secret_access_key = {secret}");
    let mut bytes = format!("{key} ").into_bytes();
    bytes.resize(65536 - component.len(), b' ');
    bytes.extend_from_slice(component.as_bytes());
    bytes.extend_from_slice(b"\npublic data\n");
    fs::write(dir.path().join("pair.txt"), bytes).unwrap();
    let result = scan(dir.path(), &[]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("window overlap"));
}

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn private_values_and_custom_rules_remain_redacted_and_manifests_record_engine() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("output.js");
    let private = "ci-sensitive-opaque-material";
    fs::write(&file, format!("{private} {}", token())).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(&file)
        .args([
            "--no-config",
            "--format",
            "json",
            "--private-env",
            "RF_PRIVATE",
            "--betterleaks-path",
        ])
        .arg(engine_path())
        .env("RF_PRIVATE", private)
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains(private));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&token()));
    let result = report(output, 1);
    assert_eq!(result["findings_count"], 2);
    let policy = dir.path().join("policy.toml");
    fs::write(&policy, "[[patterns]]\nname = 'custom-test'\npattern = 'custom-marker'\ndescription = 'Custom rule'\nseverity = 'High'\n").unwrap();
    fs::write(&file, "custom-marker").unwrap();
    let result = report(
        Command::new(env!("CARGO_BIN_EXE_redflag"))
            .arg("artifacts")
            .arg(&file)
            .arg("--config")
            .arg(&policy)
            .args(["--format", "json", "--betterleaks-path"])
            .arg(engine_path())
            .output()
            .unwrap(),
        1,
    );
    assert_eq!(result["findings"][0]["pattern_name"], "custom-test");
    fs::write(&file, "public output").unwrap();
    let netrc = dir.path().join(".netrc");
    fs::write(
        &netrc,
        [
            "machine service.invalid login robot password ",
            "synthetic",
            "-password",
        ]
        .concat(),
    )
    .unwrap();
    let netrc_result = report(scan(&netrc, &[]), 1);
    assert!(netrc_result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["pattern_name"] == "Netrc Password"));
    let manifest = dir.path().join("manifest.json");
    report(scan(&file, &["--manifest", manifest.to_str().unwrap()]), 0);
    let manifest_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(manifest_json["schema_version"], 2);
    assert_eq!(manifest_json["detector"]["name"], "betterleaks");
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("verify-artifacts")
        .arg(manifest)
        .args(["--format", "json"])
        .env("REDFLAG_BETTERLEAKS_PATH", "/nonexistent")
        .output()
        .unwrap();
    report(output, 0);
}
