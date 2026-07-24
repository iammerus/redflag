//! Generated, offline detection fixtures. No provider-issued credentials.
//! Check each file and rule, so duplicates cannot hide a missed credential.
use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::tempdir;

fn token_body(length: usize) -> String {
    ["aB3dE6gH9jK2mN5p", "Q8sT1vW4xY7zA0cD"]
        .concat()
        .chars()
        .cycle()
        .take(length)
        .collect()
}

fn scan(path: &Path, config: Option<&Path>, history: bool) -> (i32, Vec<Value>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_redflag"));
    command.args([
        "scan",
        path.to_str().unwrap(),
        "--format",
        "json",
        "--no-progress",
    ]);
    if let Some(config) = config {
        command.args(["--config", config.to_str().unwrap()]);
    }
    if history {
        command.arg("--git-history");
    }
    let output = command.output().unwrap();
    let code = output.status.code().unwrap();
    assert!(
        code == 0 || code == 1,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (code, serde_json::from_slice(&output.stdout).unwrap())
}

fn entropy_off(directory: &Path) -> std::path::PathBuf {
    let path = directory.join("redflag.toml");
    fs::write(&path, "[entropy]\nenabled = false\n").unwrap();
    path
}

fn assignment(context: usize, key: &str, value: &str) -> String {
    match context {
        0 => format!("{key}={value}\n"),
        1 => format!("{key}=\"{value}\"\n"),
        2 => format!(r#"{{"{key}":"{value}"}}"#),
        3 => format!("{key}: '{value}'\n"),
        4 => format!("{key} = `{value}`;\n"),
        5 => format!("'{key}' => '{value}',\n"),
        6 => format!("{key} := \"{value}\"\n"),
        _ => unreachable!(),
    }
}

#[test]
fn known_tokens_are_detected_without_variable_name_or_entropy() {
    let dir = tempdir().unwrap();
    let config = entropy_off(dir.path());
    let mut cases = Vec::new();
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        cases.push((format!("{prefix}{}", token_body(36)), "GitHub Token"));
    }
    cases.push((
        format!("github_pat_{}_{}", token_body(22), token_body(59)),
        "GitHub Token",
    ));
    cases.push((format!("npm_{}", token_body(36)), "npm Access Token"));
    for prefix in ["sk_live_", "sk_test_", "rk_live_", "rk_test_"] {
        for length in [24, 99] {
            cases.push((
                format!("{prefix}{}", token_body(length)),
                "Stripe Secret Key",
            ));
        }
    }
    for prefix in ["AKIA", "ASIA"] {
        cases.push((
            format!("{prefix}{}", token_body(16).to_ascii_uppercase()),
            "AWS Access Key",
        ));
    }
    for (index, (value, _)) in cases.iter().enumerate() {
        for context in 0..7 {
            fs::write(
                dir.path().join(format!("case-{index}-{context}.txt")),
                assignment(context, "payload", value),
            )
            .unwrap();
        }
        fs::write(dir.path().join(format!("bare-{index}.md")), value).unwrap();
    }
    let (code, findings) = scan(dir.path(), Some(&config), false);
    assert_eq!(code, 1);
    assert_eq!(findings.len(), cases.len() * 8);
    for (index, (value, rule)) in cases.iter().enumerate() {
        for filename in (0..7)
            .map(|context| format!("case-{index}-{context}.txt"))
            .chain([format!("bare-{index}.md")])
        {
            let file_findings: Vec<_> = findings
                .iter()
                .filter(|finding| Path::new(finding["file"].as_str().unwrap()).ends_with(&filename))
                .collect();
            assert_eq!(file_findings.len(), 1, "{filename}");
            assert_eq!(file_findings[0]["pattern_name"], *rule, "{filename}");
        }
        assert!(!serde_json::to_string(&findings).unwrap().contains(value));
    }
}

#[test]
fn generic_credentials_support_assignment_syntax_and_hex_without_lowering_entropy() {
    let dir = tempdir().unwrap();
    let config = entropy_off(dir.path());
    let cases = [
        (
            "api_key",
            ["a31c5e709bd2468f", "47bf086e1a3c925d"].concat(),
            "Generic API Key",
        ),
        (
            "api_key",
            format!("{}/{}+=", token_body(20), token_body(20)),
            "Generic API Key",
        ),
        ("password", format!("{}!7", token_body(18)), "Password"),
        ("AWS_SECRET_ACCESS_KEY", token_body(40), "AWS Secret Key"),
    ];
    for (index, (key, value, _)) in cases.iter().enumerate() {
        for context in 0..7 {
            fs::write(
                dir.path().join(format!("case-{index}-{context}.txt")),
                assignment(context, key, value),
            )
            .unwrap();
        }
    }
    let (_, findings) = scan(dir.path(), Some(&config), false);
    assert_eq!(findings.len(), cases.len() * 7);
    for (index, (_, value, rule)) in cases.iter().enumerate() {
        for context in 0..7 {
            let filename = format!("case-{index}-{context}.txt");
            let finding = findings
                .iter()
                .find(|finding| Path::new(finding["file"].as_str().unwrap()).ends_with(&filename))
                .expect(&filename);
            assert!(
                finding["pattern_name"].as_str().unwrap().starts_with(rule),
                "{filename}"
            );
        }
        assert!(!serde_json::to_string(&findings).unwrap().contains(value));
    }
}

#[test]
fn fallback_literals_and_mixed_interpolation_are_not_treated_as_references() {
    let dir = tempdir().unwrap();
    let config = entropy_off(dir.path());
    let password_field = "password";
    let password = format!("{}!7", token_body(18));
    let secret_field = "clientSecret";
    let protocol = "postgres";
    let source = [
        format!("{password_field}: process.env.PASSWORD || '{password}'"),
        format!("\"{password_field}\": process.env.PASSWORD ?? `{password}`"),
        format!("{secret_field}: process.env.CLIENT_SECRET || '{password}'"),
        assignment(4, password_field, &format!("${{PREFIX}}-{password}")),
        assignment(1, password_field, "correct horse battery staple"),
        assignment(1, password_field, r#"before\"escaped-quote-after"#),
        format!("db = \"{protocol}://user:{password}@host/app\""),
        assignment(0, password_field, &format!("${{PASSWORD:-{password}}}")),
        assignment(1, password_field, &format!("${{PASSWORD:-{password}}}")),
        format!("{password_field}: config.password || '{password}'"),
        assignment(
            0,
            "AWS_SECRET_ACCESS_KEY",
            &format!("${{KEY:-{}}}", token_body(40)),
        ),
    ]
    .iter()
    .map(|line| line.trim_end())
    .collect::<Vec<_>>()
    .join("\n");
    fs::write(dir.path().join("settings.txt"), source).unwrap();
    let (_, findings) = scan(dir.path(), Some(&config), false);
    assert_eq!(findings.len(), 11, "{findings:?}");
    for line in 1..=11 {
        assert!(findings.iter().any(|finding| finding["line"] == line));
    }
    let output = serde_json::to_string(&findings).unwrap();
    assert!(!output.contains(&password));
    assert!(!output.contains("escaped-quote-after"));
    assert!(!output.contains("horse battery"));
}

#[test]
fn fixed_length_provider_matches_do_not_accept_truncated_tokens() {
    let dir = tempdir().unwrap();
    let config = entropy_off(dir.path());
    let token = format!("ghp_{}", token_body(36));
    fs::write(
        dir.path().join("invalid.txt"),
        format!("prefix{token}\n{token}suffix\n{token}_suffix\n"),
    )
    .unwrap();
    assert_eq!(scan(dir.path(), Some(&config), false).0, 0);
    fs::write(dir.path().join("adjacent.txt"), format!("{token},{token}")).unwrap();
    let (_, findings) = scan(dir.path(), Some(&config), false);
    assert_eq!(findings.len(), 2);
    assert!(!serde_json::to_string(&findings).unwrap().contains(&token));
}
