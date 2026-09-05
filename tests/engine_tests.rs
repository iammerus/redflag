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
#[ignore = "requires the pinned Betterleaks executable"]
fn pinned_engine_artifacts_also_inspect_encoded_private_values() {
    use base64::{engine::general_purpose, Engine};
    let dir = tempdir().unwrap();
    let file = dir.path().join("payload.bin");
    let value = "opaque-Pvt!42";
    let percent: String = format!("user:{value}:suffix")
        .bytes()
        .map(|byte| format!("%{byte:02X}"))
        .collect();
    let encoded = general_purpose::STANDARD.encode(percent);
    fs::write(&file, &encoded).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(&file)
        .args(["--no-config", "--format", "json", "--betterleaks-path"])
        .arg(engine_path())
        .args(["--private-env", "RF_ENCODED_PRIVATE"])
        .env("RF_ENCODED_PRIVATE", value)
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains(value));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&encoded));
    let result = report(output, 1);
    let found = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["pattern_name"] == "private-env:RF_ENCODED_PRIVATE")
        .unwrap();
    assert_eq!(found["representation"][0]["kind"], "base64");
    assert_eq!(found["representation"][1]["kind"], "url_percent");
    assert_eq!(result["coverage"]["engine"]["name"], "betterleaks");
}

#[test]
#[ignore = "requires the pinned Betterleaks executable"]
fn pinned_engine_inspects_archive_members_with_their_filename_context() {
    use std::io::{Cursor, Write};
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};
    let dir = tempdir().unwrap();
    let file = dir.path().join("release.zip");
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in [
        ("dist/token.bin", format!("fixture\n{}\n", token())),
        (
            "dist/component.js",
            "function render(props) { return login({password: props.password}); }".into(),
        ),
        (
            "dist/.netrc",
            "machine example.invalid login fixture password synthetic-value".into(),
        ),
    ] {
        writer
            .start_file(
                name,
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(content.as_bytes()).unwrap();
    }
    fs::write(&file, writer.finish().unwrap().into_inner()).unwrap();
    let result = report(scan(&file, &[]), 1);
    let found = result["findings"].as_array().unwrap();
    assert!(found.iter().any(
        |finding| finding["pattern_name"] == "betterleaks:github-pat"
            && finding["archive"][0]["path"] == "dist/token.bin"
    ));
    assert!(found
        .iter()
        .any(|finding| finding["pattern_name"] == "Netrc Password"
            && finding["archive"][0]["path"] == "dist/.netrc"));
    assert!(!found
        .iter()
        .any(|finding| finding["archive"][0]["path"] == "dist/component.js"));
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
fn engine_preserves_code_context_and_limits_placeholder_policy_to_exact_values() {
    let dir = tempdir().unwrap();
    let code = dir.path().join("code");
    fs::create_dir(&code).unwrap();
    for filename in ["app.js", "app.TS", "app.rs", "app.py", "app.js.example"] {
        fs::write(
            code.join(filename),
            "setCredentials({password: password, username});\nconst password = getPassword;\nconst notpassword = \"not-a-credential\";\nconst PASSWORD_FIELD = \"public field label\";\n",
        )
        .unwrap();
    }
    fs::write(
        code.join("object-reference.txt"),
        "setCredentials({password: password, username});\n",
    )
    .unwrap();
    let clean = report(scan(&code, &[]), 0);
    assert_eq!(clean["findings_count"], 0);
    let adapter = clean["coverage"]["engine"]["adapter_sha256"]
        .as_str()
        .unwrap();
    assert_eq!(adapter.len(), 64);

    let literals = dir.path().join("literals");
    fs::create_dir(&literals).unwrap();
    for (filename, text) in [
        ("quoted.js", "const password = \"getPassword\";\n"),
        ("unquoted.env", "password=getPassword\n"),
        ("unknown.data", "password=getPassword\n"),
        ("weak.js", "const password = \"admin123\";\n"),
        ("marker-suffix.env", "password=YOUR_PASSWORD_HERE!\n"),
        ("marker-prefix.env", "password=X_YOUR_PASSWORD_HERE\n"),
        ("other-case.env", "password=Your_Password_Here\n"),
        ("camel.js", "const databasePassword = \"admin123\";\n"),
        ("delimited.env", "DATABASE_PASSWORD=admin123\n"),
        ("literal-scalar.yaml", "password: password\n"),
        (
            "quoted-object.txt",
            "setCredentials({password: \"password\", username});\n",
        ),
    ] {
        fs::write(literals.join(filename), text).unwrap();
    }
    let findings = report(scan(&literals, &[]), 1);
    let files: std::collections::BTreeSet<_> = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| {
            Path::new(finding["file"].as_str().unwrap())
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(files.len(), 11, "{files:?}");
    assert_eq!(findings["coverage"]["engine"]["adapter_sha256"], adapter);

    let placeholders = dir.path().join("placeholders");
    fs::create_dir(&placeholders).unwrap();
    for (index, value) in ["YOUR_PASSWORD_HERE", "your_password_here"]
        .iter()
        .enumerate()
    {
        fs::write(
            placeholders.join(format!("{index}.env")),
            format!("password=\"{value}\"\n"),
        )
        .unwrap();
    }
    let manifest = dir.path().join("manifest.json");
    report(
        scan(&placeholders, &["--manifest", manifest.to_str().unwrap()]),
        0,
    );
    let verified = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("verify-artifacts")
        .arg(&manifest)
        .output()
        .unwrap();
    assert_eq!(verified.status.code(), Some(0));
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    for adapter in [
        serde_json::Value::Null,
        serde_json::Value::String("0".repeat(64)),
    ] {
        let mut stale = saved.clone();
        stale["detector"]["adapter_sha256"] = adapter;
        fs::write(&manifest, serde_json::to_vec(&stale).unwrap()).unwrap();
        let rejected = Command::new(env!("CARGO_BIN_EXE_redflag"))
            .arg("verify-artifacts")
            .arg(&manifest)
            .args(["--format", "json"])
            .output()
            .unwrap();
        assert_eq!(rejected.status.code(), Some(2));
        assert!(rejected.stdout.is_empty());
    }
    fs::write(&manifest, serde_json::to_vec(&saved).unwrap()).unwrap();
    let private = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(&placeholders)
        .args([
            "--no-config",
            "--format",
            "json",
            "--private-env",
            "RF_PRIVATE_MARKER",
            "--manifest",
        ])
        .arg(&manifest)
        .arg("--betterleaks-path")
        .arg(engine_path())
        .env("RF_PRIVATE_MARKER", "YOUR_PASSWORD_HERE")
        .output()
        .unwrap();
    let private = report(private, 1);
    assert_eq!(private["blocking_occurrences_count"], 1);
    assert!(!manifest.exists());
    assert!(!private.to_string().contains("YOUR_PASSWORD_HERE"));
}

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn source_engine_context_keeps_literal_password_additions_blocking() {
    let dir = tempdir().unwrap();
    let repo = git2::Repository::init(dir.path()).unwrap();
    let signature = git2::Signature::now("Fixture", "fixture@example.invalid").unwrap();
    let commit = |text: &str| {
        fs::write(dir.path().join("app.js"), text).unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("app.js")).unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let parents: Vec<_> = repo
            .head()
            .ok()
            .map(|head| head.peel_to_commit().unwrap())
            .into_iter()
            .collect();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Fixture",
            &tree,
            &parents.iter().collect::<Vec<_>>(),
        )
        .unwrap()
    };
    let base = commit("// clean application\n");
    let reference = commit("setCredentials({password: password, username});\n");
    let scan = |base: git2::Oid, head: git2::Oid| {
        Command::new(env!("CARGO_BIN_EXE_redflag"))
            .arg("changes")
            .arg(dir.path())
            .args([
                "--no-config",
                "--format",
                "json",
                "--base",
                &base.to_string(),
                "--head",
                &head.to_string(),
                "--betterleaks-path",
            ])
            .arg(engine_path())
            .output()
            .unwrap()
    };
    report(scan(base, reference), 0);
    let literal = commit("setCredentials({password: \"getPassword\", username});\n");
    assert_eq!(
        report(scan(reference, literal), 1)["blocking_occurrences_count"],
        1
    );
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
    assert_eq!(manifest_json["schema_version"], 5);
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

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn engine_groups_captured_values_with_native_and_private_evidence() {
    let dir = tempdir().unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir(&dist).unwrap();
    let value = token();
    fs::write(
        dist.join("first"),
        format!("const credential = '{value}';\n"),
    )
    .unwrap();
    fs::write(dist.join("second"), format!("{value}\n")).unwrap();
    let policy = dir.path().join("policy.toml");
    fs::write(&policy, "[[patterns]]\nname = 'custom-provider'\npattern = 'ghp_[a-zA-Z0-9]{36}'\ndescription = 'Custom provider'\nseverity = 'High'\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(&dist)
        .arg("--config")
        .arg(&policy)
        .args([
            "--format",
            "json",
            "--private-env",
            "RF_PROVIDER",
            "--betterleaks-path",
        ])
        .arg(engine_path())
        .env("RF_PROVIDER", &value)
        .output()
        .unwrap();
    let serialized = String::from_utf8_lossy(&output.stdout);
    use sha2::{Digest, Sha256};
    assert!(!serialized.contains(&value));
    assert!(!serialized.contains(&format!("{:x}", Sha256::digest(value.as_bytes()))));
    let result = report(output, 1);
    assert_eq!(result["logical_findings_count"], 1);
    assert_eq!(result["occurrences_count"], 2);
    assert_eq!(result["findings_count"], 6);
    for occurrence in result["logical_findings"][0]["occurrences"]
        .as_array()
        .unwrap()
    {
        assert_eq!(occurrence["evidence"].as_array().unwrap().len(), 3);
    }
    // Assignment context is detector evidence, not credential identity.
    fs::remove_file(dist.join("first")).unwrap();
    fs::remove_file(dist.join("second")).unwrap();
    let private = ["qL8m", "W3kN7pT9vR2x"].concat();
    fs::write(dist.join("first.env"), format!("password={private}\n")).unwrap();
    fs::write(
        dist.join("second.env"),
        format!("password = \"{private}\"\n"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(&dist)
        .args([
            "--no-config",
            "--format",
            "json",
            "--private-env",
            "RF_GENERIC",
            "--betterleaks-path",
        ])
        .arg(engine_path())
        .env("RF_GENERIC", &private)
        .output()
        .unwrap();
    let result = report(output, 1);
    assert_eq!(result["logical_findings_count"], 1);
    assert_eq!(result["occurrences_count"], 2);
    assert!(result["findings_count"].as_u64().unwrap() >= 4);
}

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn multipart_group_identity_includes_every_required_value() {
    let dir = tempdir().unwrap();
    let key = ["AKIA", "Q7W2E5R3T6Y4U2I7"].concat();
    let secret = ["mP9xR2vL7kN4qW6tY3cB8dF5", "hJ1sA0uE9gZ2iO4p"].concat();
    for (name, secret) in [
        ("one", secret.clone()),
        ("copy", secret.clone()),
        ("different", secret.replace('m', "n")),
    ] {
        fs::write(
            dir.path().join(name),
            format!("aws_access_key_id = {key}\naws_secret_access_key = {secret}\n"),
        )
        .unwrap();
    }
    let result = report(scan(dir.path(), &[]), 1);
    let groups: Vec<_> = result["logical_findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["rules"].get("betterleaks:aws-access-token").is_some())
        .collect();
    assert_eq!(groups.len(), 2);
    let mut counts: Vec<_> = groups
        .iter()
        .map(|g| g["occurrence_count"].as_u64().unwrap())
        .collect();
    counts.sort();
    assert_eq!(counts, [1, 2]);
    for group in groups {
        for occurrence in group["occurrences"].as_array().unwrap() {
            let evidence = occurrence["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["rule_id"] == "betterleaks:aws-access-token")
                .unwrap();
            assert_eq!(evidence["spans"].as_array().unwrap().len(), 2);
        }
    }
}

#[test]
#[ignore = "requires the checksum-verified engine; CI installs it and includes ignored tests"]
fn pinned_engine_artifact_reviews_cannot_override_declared_private_values() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("example.js");
    fs::write(
        &input,
        format!("// synthetic public example\n{}\n", token()),
    )
    .unwrap();
    let review = dir.path().join("review.json");
    let manifest = dir.path().join("manifest.json");
    let run = |private: bool, reviewed: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_redflag"));
        command
            .arg("artifacts")
            .arg(&input)
            .args(["--no-config", "--format", "json", "--betterleaks-path"])
            .arg(engine_path())
            .arg("--manifest")
            .arg(&manifest);
        if private {
            command
                .args(["--private-env", "RF_PINNED_PRIVATE"])
                .env("RF_PINNED_PRIVATE", token());
        }
        if reviewed {
            command.arg("--exceptions").arg(&review);
        }
        command.output().unwrap()
    };
    let save_review = |result: &serde_json::Value| {
        fs::write(&review, serde_json::to_vec(&serde_json::json!({"schema_version":1,"mode":"artifacts","exceptions":[{
            "occurrence_id":result["logical_findings"][0]["occurrences"][0]["id"], "kind":"false_positive", "reason":"Reviewed public synthetic example", "reviewed_by":"fixture-reviewer", "expires_at":(chrono::Utc::now()+chrono::Duration::hours(24)).to_rfc3339()
        }]})).unwrap()).unwrap();
    };
    save_review(&report(run(false, false), 1));
    let accepted = report(run(false, true), 0);
    assert_eq!(accepted["accepted_occurrences_count"], 1);
    assert!(manifest.exists());
    save_review(&report(run(true, false), 1));
    let rejected = run(true, true);
    assert!(!String::from_utf8_lossy(&rejected.stdout).contains(&token()));
    let rejected = report(rejected, 1);
    assert_eq!(
        rejected["exception_policy"]["rejected_private_occurrences"],
        1
    );
    assert_eq!(rejected["accepted_occurrences_count"], 0);
    assert!(!manifest.exists());
}
