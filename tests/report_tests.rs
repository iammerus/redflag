use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn token() -> String {
    ["ghp_", "aB3dE6gH9jK2mN5pQ8", "sT1vW4xY7zA0cD3fG6"].concat()
}

fn scan(path: &Path, args: &[&str], vars: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_redflag"));
    command
        .arg("artifacts")
        .arg(path)
        .args(["--engine", "native", "--format", "json", "--no-config"])
        .args(args);
    for (name, value) in vars {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn report(output: &Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema_version"], 2);
    assert_eq!(result["identity_schema"], "redflag-occurrence-v1");
    result
}

fn occurrence_ids(result: &Value) -> BTreeSet<String> {
    result["logical_findings"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|group| group["occurrences"].as_array().unwrap())
        .map(|occurrence| occurrence["id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn repeated_values_group_across_files_without_exporting_private_digests() {
    let dir = tempdir().unwrap();
    let token = token();
    fs::write(
        dir.path().join("first"),
        format!("first: {token}\nagain: {token}\n"),
    )
    .unwrap();
    fs::write(dir.path().join("second"), format!("last: {token}\n")).unwrap();
    let output = scan(
        dir.path(),
        &["--private-env", "RF_ONE", "--private-env", "RF_TWO"],
        &[("RF_ONE", &token), ("RF_TWO", &token)],
    );
    let result = report(&output);
    assert_eq!(result["findings_count"], 9);
    assert_eq!(result["logical_findings_count"], 1);
    assert_eq!(result["occurrences_count"], 3);
    let group = &result["logical_findings"][0];
    assert_eq!(
        group["private_env"],
        serde_json::json!(["RF_ONE", "RF_TWO"])
    );
    assert_eq!(group["severity"], "Critical");
    assert!(group["remediation"].as_str().unwrap().contains("rebuild"));
    for occurrence in group["occurrences"].as_array().unwrap() {
        assert_eq!(occurrence["evidence"].as_array().unwrap().len(), 3);
        assert_eq!(occurrence["location"]["target"], 0);
        assert!(!Path::new(occurrence["location"]["path"].as_str().unwrap()).is_absolute());
    }
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(&token));
    assert!(!stdout.contains(&format!("{:x}", Sha256::digest(token.as_bytes()))));
    for forbidden in ["grouping_key", "secret_digest", "component_sets"] {
        assert!(!stdout.contains(forbidden));
    }
}

#[test]
fn identities_survive_root_relocation_and_distinguish_new_occurrences() {
    let first = tempdir().unwrap();
    let copy = tempdir().unwrap();
    let token = token();
    for root in [first.path(), copy.path()] {
        fs::write(root.join("asset.js"), format!("// token\n{token}\n")).unwrap();
    }
    let before = report(&scan(first.path(), &[], &[]));
    let repeated = report(&scan(first.path(), &[], &[]));
    let relocated = report(&scan(copy.path(), &[], &[]));
    assert_eq!(before["logical_findings"], repeated["logical_findings"]);
    assert_eq!(before["logical_findings"], relocated["logical_findings"]);
    fs::write(copy.path().join("extra.js"), format!("{token}\n")).unwrap();
    let extra = report(&scan(copy.path(), &[], &[]));
    assert_eq!(extra["logical_findings_count"], 1);
    assert_eq!(extra["occurrences_count"], 2);
    assert!(occurrence_ids(&before).is_subset(&occurrence_ids(&extra)));
    assert_ne!(
        before["logical_findings"][0]["id"],
        extra["logical_findings"][0]["id"]
    );
    // An equal-length replacement at identical coordinates is a new version.
    fs::write(
        first.path().join("asset.js"),
        format!("// token\n{}\n", token.replace('a', "b")),
    )
    .unwrap();
    let changed = report(&scan(first.path(), &[], &[]));
    assert!(occurrence_ids(&before).is_disjoint(&occurrence_ids(&changed)));
}

#[test]
fn distinct_values_and_overlapping_repetitions_keep_their_own_occurrences() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("output");
    fs::write(&file, "abcabcabc\nother-private-material\n").unwrap();
    let result = report(&scan(
        &file,
        &[
            "--private-env",
            "RF_OVERLAP",
            "--allow-short-private-value",
            "RF_OVERLAP",
            "--private-env",
            "RF_OTHER",
        ],
        &[
            ("RF_OVERLAP", "abcabc"),
            ("RF_OTHER", "other-private-material"),
        ],
    ));
    assert_eq!(result["logical_findings_count"], 2);
    assert_eq!(result["occurrences_count"], 3);
    let overlap = result["logical_findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["private_env"] == serde_json::json!(["RF_OVERLAP"]))
        .unwrap();
    let starts: Vec<_> = overlap["occurrences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["primary"]["start_column"].as_u64().unwrap())
        .collect();
    assert_eq!(starts, [1, 4]);
}

#[test]
fn private_byte_locations_handle_backward_starts_newlines_and_long_gaps() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("bytes");
    let mut bytes = vec![b'\n'; 500_000];
    bytes.extend_from_slice(b"\xff\0abc\ndef\nabc\ndef\n");
    fs::write(&file, bytes).unwrap();
    let result = report(&scan(
        &file,
        &[
            "--private-env",
            "RF_LONG",
            "--private-env",
            "RF_SHORT",
            "--allow-short-private-value",
            "RF_SHORT",
        ],
        &[("RF_LONG", "abc\ndef\n"), ("RF_SHORT", "def\n")],
    ));
    let spans: Vec<_> = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["pattern_name"] == "private-env:RF_LONG")
        .map(|f| f["evidence"][0].clone())
        .collect();
    assert_eq!(
        spans,
        vec![
            serde_json::json!({"start_line":500001,"start_column":3,"end_line":500003,"end_column":0}),
            serde_json::json!({"start_line":500003,"start_column":1,"end_line":500005,"end_column":0}),
        ]
    );
    assert_eq!(result["occurrences_count"], 4);
}

#[test]
fn findings_limit_fails_without_output_or_a_stale_manifest() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("dist");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("input"), format!("{}\n{}\n", token(), token())).unwrap();
    let config = dir.path().join("policy.toml");
    fs::write(&config, "[limits]\nmax_findings = 1\n").unwrap();
    let manifest = dir.path().join("manifest.json");
    for format in ["text", "json"] {
        fs::write(&manifest, "previous manifest").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
            .arg("artifacts")
            .arg(&input)
            .args(["--engine", "native", "--format", format])
            .arg("--config")
            .arg(&config)
            .arg("--manifest")
            .arg(&manifest)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!manifest.exists());
    }
}

#[cfg(unix)]
#[test]
fn text_reports_escape_control_characters_in_paths() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("asset\n::error::injected\u{1b}[31m"),
        token(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(dir.path())
        .args(["--engine", "native", "--no-config"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("\n::error::"));
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("asset\\n::error::injected\\u{1b}[31m"));
    assert!(!text.contains(&token()));
}

fn github(path: &Path, summary: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(path)
        .args(["--engine", "native", "--no-config", "--format", "github"])
        .arg("--github-summary")
        .arg(summary)
        .args(args)
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .output()
        .unwrap()
}

#[test]
fn github_reports_bound_display_append_summary_and_keep_secrets_private() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("dist.js");
    fs::write(&file, format!("{}\n", token()).repeat(101)).unwrap();
    let summary = dir.path().join("summary.md");
    fs::write(&summary, "Earlier step content\n").unwrap();
    let output = github(&file, &summary, &[]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with("::error "))
            .count(),
        10
    );
    assert!(!stdout.contains(",file=")); // Build outputs have no source annotation mapping.
    assert!(stdout.contains("10 of 101"));
    let summary = fs::read_to_string(&summary).unwrap();
    assert!(summary.starts_with("Earlier step content\n"));
    assert!(summary.contains("1 logical finding(s), 101 occurrence(s)"));
    assert!(summary.contains("Showing 100 of 101 occurrences"));
    assert!(summary.contains("Remove the credential from publication inputs"));
    assert!(summary.len() < 1024 * 1024);
    for text in [&summary, &stdout] {
        assert!(!text.contains(&token()));
        assert!(!text.contains(&format!("{:x}", Sha256::digest(token().as_bytes()))));
        assert!(!text.contains("grouping_key"));
    }
}

#[test]
fn github_clean_results_use_runner_summary_environment_and_failures_leave_it_untouched() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("output");
    fs::write(&file, "public content").unwrap();
    let summary = dir.path().join("summary.md");
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("artifacts")
        .arg(&file)
        .args(["--engine", "native", "--no-config", "--format", "github"])
        .env("GITHUB_STEP_SUMMARY", &summary)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("::notice "));
    let before = fs::read(&summary).unwrap();
    assert!(String::from_utf8_lossy(&before).contains("No findings in the selected scope"));
    let failed = github(&dir.path().join("missing"), &summary, &[]);
    assert_eq!(failed.status.code(), Some(2));
    assert!(failed.stdout.is_empty());
    assert_eq!(fs::read(&summary).unwrap(), before);
}

#[test]
fn github_summary_cannot_mutate_publication_inputs_or_manifests() {
    let dir = tempdir().unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir(&dist).unwrap();
    fs::write(dist.join("index"), "public output").unwrap();
    let inside = dist.join("summary.md");
    let failed = github(&dist, &inside, &[]);
    assert_eq!(failed.status.code(), Some(2));
    assert!(failed.stdout.is_empty());
    assert!(!inside.exists());
    let manifest = dir.path().join("manifest.json");
    let failed = github(
        &dist,
        &manifest,
        &["--manifest", manifest.to_str().unwrap()],
    );
    assert_eq!(failed.status.code(), Some(2));
    assert!(failed.stdout.is_empty());
    assert!(!manifest.exists());
    // A full runner summary must not erase existing content or certify publication.
    let summary = dir.path().join("summary.md");
    let existing = vec![b'x'; 1024 * 1024];
    fs::write(&summary, &existing).unwrap();
    let failed = github(&dist, &summary, &["--manifest", manifest.to_str().unwrap()]);
    assert_eq!(failed.status.code(), Some(2));
    assert!(failed.stdout.is_empty());
    assert_eq!(fs::read(&summary).unwrap(), existing);
    assert!(!manifest.exists());
}

#[cfg(unix)]
#[test]
fn github_summary_rejects_symlinks_hardlinks_and_special_files() {
    use std::os::unix::{fs::symlink, net::UnixListener};
    let dir = tempdir().unwrap();
    let input = dir.path().join("input");
    fs::write(&input, "public input").unwrap();
    let summary = dir.path().join("summary");
    symlink(&input, &summary).unwrap();
    assert_eq!(github(&input, &summary, &[]).status.code(), Some(2));
    fs::remove_file(&summary).unwrap();
    fs::hard_link(&input, &summary).unwrap();
    assert_eq!(github(&input, &summary, &[]).status.code(), Some(2));
    fs::remove_file(&summary).unwrap();
    let _listener = UnixListener::bind(&summary).unwrap();
    assert_eq!(github(&input, &summary, &[]).status.code(), Some(2));
    assert_eq!(fs::read_to_string(&input).unwrap(), "public input");
}

#[test]
fn github_arguments_are_explicit_and_legacy_formats_stay_compatible() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input");
    fs::write(&input, "public input").unwrap();
    for (format, summary) in [("github", false), ("json", true), ("text", true)] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_redflag"));
        command
            .arg("artifacts")
            .arg(&input)
            .args(["--engine", "native", "--no-config", "--format", format])
            .env_remove("GITHUB_STEP_SUMMARY");
        if summary {
            command
                .arg("--github-summary")
                .arg(dir.path().join("summary.md"));
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_redflag"))
        .arg("scan")
        .arg(&input)
        .args(["--format", "github"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
