use base64::{engine::general_purpose, Engine};
use flate2::{write::GzEncoder, Compression};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Cursor, Write},
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut writer = GzEncoder::new(Vec::new(), Compression::default());
    writer.write_all(bytes).unwrap();
    writer.finish().unwrap()
}
fn zip(entries: &[(&str, &[u8])], method: CompressionMethod) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in entries {
        writer
            .start_file(
                *name,
                SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}
fn tar(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut writer = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    writer.append_data(&mut header, name, bytes).unwrap();
    writer.into_inner().unwrap()
}
fn scan(path: &Path, args: &[&str]) -> Output {
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
            "RF_ARCHIVE_PRIVATE",
        ])
        .env("RF_ARCHIVE_PRIVATE", "opaque-Pvt!42");
    if !args.contains(&"--config") {
        command.arg("--no-config");
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
    assert!(!String::from_utf8_lossy(&output.stdout).contains("opaque-Pvt!42"));
    serde_json::from_slice(&output.stdout).unwrap()
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
fn archives_inspect_nested_encoded_values_and_preserve_member_locations() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input.bin");
    let private = general_purpose::STANDARD.encode("prefix:opaque-Pvt!42:suffix");
    let inner = gzip(format!("header\n{private}\n").as_bytes());
    let bundle = zip(
        &[("dist/public.txt.gz", &inner)],
        CompressionMethod::Deflated,
    );
    fs::write(&file, &bundle).unwrap();
    let result = report(scan(&file, &[]), 1);
    let finding = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| {
            finding["pattern_name"] == "private-env:RF_ARCHIVE_PRIVATE"
                && finding["archive"]
                    .as_array()
                    .is_some_and(|chain| chain.len() == 2)
        })
        .unwrap();
    assert_eq!(finding["archive"][0]["format"], "zip");
    assert_eq!(finding["archive"][0]["path"], "dist/public.txt.gz");
    assert_eq!(finding["archive"][1]["format"], "gzip");
    assert_eq!(finding["archive"][1]["path"], "public.txt");
    assert_eq!(finding["line"], 2);
    assert_eq!(finding["representation"][0]["kind"], "base64");
    assert_eq!(result["coverage"]["archive_inspection"]["archives"], 2);
    assert_eq!(result["coverage"]["archive_inspection"]["members"], 2);
    let copy = dir.path().join("relocated.bin");
    fs::write(&copy, bundle).unwrap();
    assert_eq!(
        result["logical_findings"],
        report(scan(&copy, &[]), 1)["logical_findings"]
    );
}

#[test]
fn tar_and_gzip_concatenation_inspect_complete_logical_content() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input.tgz");
    fs::write(&file, gzip(&tar("dist/.private", b"opaque-Pvt!42"))).unwrap();
    let result = report(scan(&file, &[]), 1);
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["archive"]
            .as_array()
            .is_some_and(|chain| chain.len() == 2)
            && finding["archive"][1]["path"] == "dist/.private"));
    let file = dir.path().join("input.gz");
    fs::write(&file, [gzip(b"opaque-"), gzip(b"Pvt!42")].concat()).unwrap();
    let result = report(scan(&file, &[]), 1);
    let finding = &result["findings"][0];
    assert_eq!(finding["archive"][0]["bytes"], 13);
    assert_eq!(finding["primary"]["start_column"], 1);
    assert_eq!(finding["primary"]["end_column"], 13);
}

#[test]
fn archive_limits_fail_atomically_and_are_cumulative() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input");
    let config = dir.path().join("policy.toml");
    let manifest = dir.path().join("manifest.json");
    let bundle = zip(
        &[("first", b"ordinary"), ("second", b"public")],
        CompressionMethod::Stored,
    );
    fs::write(&file, bundle).unwrap();
    for (limit, pass, fail) in [
        ("max_archive_members", 2, 1),
        ("max_expanded_bytes", 14, 13),
        ("max_archive_member_bytes", 8, 7),
    ] {
        policy(&config, &format!("{limit}={pass}"));
        report(scan(&file, &["--config", config.to_str().unwrap()]), 0);
        policy(&config, &format!("{limit}={fail}"));
        fs::write(&manifest, "stale approval").unwrap();
        let output = scan(
            &file,
            &[
                "--config",
                config.to_str().unwrap(),
                "--manifest",
                manifest.to_str().unwrap(),
            ],
        );
        assert_eq!(output.status.code(), Some(2), "{limit}");
        assert!(output.stdout.is_empty());
        assert!(!manifest.exists());
        assert!(String::from_utf8_lossy(&output.stderr).contains(limit));
    }
    fs::write(&file, gzip(&gzip(b"ordinary public"))).unwrap();
    policy(&config, "max_archive_depth=2");
    report(scan(&file, &["--config", config.to_str().unwrap()]), 0);
    policy(&config, "max_archive_depth=1");
    assert_eq!(
        scan(&file, &["--config", config.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
    fs::write(&file, gzip(&vec![b'.'; 65536])).unwrap();
    policy(&config, "max_archive_ratio=2");
    let output = scan(&file, &["--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("max_archive_ratio"));

    let inputs = dir.path().join("inputs");
    fs::create_dir(&inputs).unwrap();
    fs::write(inputs.join("one.gz"), gzip(b"ordinary")).unwrap();
    fs::write(inputs.join("two.gz"), gzip(b"ordinary")).unwrap();
    policy(&config, "max_archive_members=1");
    assert_eq!(
        scan(&inputs, &["--config", config.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn corrupt_unsupported_and_ambiguous_archives_cannot_pass() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input.bin");
    let valid = gzip(b"ordinary public");
    let mut crc = valid.clone();
    let offset = crc.len() - 8;
    crc[offset] ^= 1;
    let mut broken_tar = tar("public", b"ordinary");
    broken_tar[0] ^= 1;
    let mut duplicated = zip(
        &[("a.txt", b"ordinary"), ("b.txt", b"public")],
        CompressionMethod::Stored,
    );
    while let Some(at) = duplicated.windows(5).position(|window| window == b"b.txt") {
        duplicated[at] = b'a';
    }
    let mut bad_zip_crc = zip(&[("public", b"ordinary")], CompressionMethod::Stored);
    let central = bad_zip_crc
        .windows(4)
        .position(|bytes| bytes == b"PK\x01\x02")
        .unwrap();
    bad_zip_crc[central + 16] ^= 1;
    let mut tar_trailing = tar("public", b"ordinary");
    tar_trailing.push(b'x');
    for bytes in [
        crc,
        valid[..valid.len() - 1].to_vec(),
        [valid, b"trailing".to_vec()].concat(),
        broken_tar,
        duplicated,
        bad_zip_crc,
        tar_trailing,
        zip(&[("../escape", b"public")], CompressionMethod::Stored),
        b"\xfd7zXZ\0rest".to_vec(),
    ] {
        fs::write(&file, bytes).unwrap();
        let output = scan(&file, &[]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(output.stdout.is_empty());
    }
    let misnamed = dir.path().join("input.zip");
    fs::write(&misnamed, "public bytes").unwrap();
    assert_eq!(scan(&misnamed, &[]).status.code(), Some(2));
}

#[test]
fn clean_archive_manifests_require_the_inspection_receipt_and_exact_container_bytes() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input.zip");
    let manifest = dir.path().join("manifest.json");
    fs::write(
        &file,
        zip(
            &[("public.txt", b"ordinary public")],
            CompressionMethod::Deflated,
        ),
    )
    .unwrap();
    let result = report(scan(&file, &["--manifest", manifest.to_str().unwrap()]), 0);
    assert_eq!(
        report(verify(&manifest), 0)["coverage"]["archive_inspection"],
        result["coverage"]["archive_inspection"]
    );
    let saved: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(saved["schema_version"], 5);
    for (pointer, replacement) in [
        ("/schema_version", json!(4)),
        ("/archive_inspection/formats", json!([])),
        ("/archive_inspection/members", json!(10001)),
        ("/archive_inspection/archives", json!(0)),
    ] {
        let mut invalid = saved.clone();
        *invalid.pointer_mut(pointer).unwrap() = replacement;
        fs::write(&manifest, serde_json::to_vec(&invalid).unwrap()).unwrap();
        let output = verify(&manifest);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    fs::write(&manifest, serde_json::to_vec(&saved).unwrap()).unwrap();
    fs::write(
        &file,
        zip(
            &[("public.txt", b"changed public")],
            CompressionMethod::Deflated,
        ),
    )
    .unwrap();
    assert_eq!(verify(&manifest).status.code(), Some(2));
}

#[test]
fn empty_archives_are_complete_but_links_and_extensions_are_rejected() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input.bin");
    for bytes in [
        zip(&[], CompressionMethod::Stored),
        vec![0; 1024],
        gzip(b""),
    ] {
        let name = if bytes.iter().all(|&byte| byte == 0) {
            dir.path().join("empty.tar")
        } else {
            file.clone()
        };
        fs::write(&name, bytes).unwrap();
        let result = report(scan(&name, &[]), 0);
        assert_eq!(result["coverage"]["archive_inspection"]["archives"], 1);
    }
    for kind in [
        tar::EntryType::Symlink,
        tar::EntryType::Link,
        tar::EntryType::XHeader,
    ] {
        let mut writer = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(kind);
        header.set_size(0);
        header.set_path("entry").unwrap();
        header.set_link_name("outside").unwrap();
        header.set_cksum();
        writer.append(&header, &b""[..]).unwrap();
        fs::write(&file, writer.into_inner().unwrap()).unwrap();
        let output = scan(&file, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    let mut encrypted = zip(&[("public", b"ordinary")], CompressionMethod::Stored);
    let central = encrypted
        .windows(4)
        .position(|bytes| bytes == b"PK\x01\x02")
        .unwrap();
    encrypted[6] |= 1;
    encrypted[central + 8] |= 1;
    fs::write(&file, encrypted).unwrap();
    assert_eq!(scan(&file, &[]).status.code(), Some(2));
}

#[test]
fn member_names_cannot_republish_declared_private_values_in_reports() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("input.zip");
    fs::write(
        &file,
        zip(
            &[("dist/opaque-Pvt!42.txt", b"opaque-Pvt!42")],
            CompressionMethod::Deflated,
        ),
    )
    .unwrap();
    let result = report(scan(&file, &[]), 1);
    assert!(result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["archive"][0]["path"] == "[REDACTED PRIVATE VALUE]"));
}
