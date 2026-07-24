use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn redflag(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_redflag"))
        .args(["scan", path.to_str().unwrap()])
        .output()
        .unwrap()
}

fn write_secret(path: &Path) {
    let secret = ["0123456789abcdef", "FEDCBA9876543210"].concat();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, format!("api_key = \"{secret}\"\n")).unwrap();
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
fn clean_directory_exits_successfully() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

    assert_eq!(redflag(dir.path()).status.code(), Some(0));
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
fn scans_packages_directory() {
    let dir = tempdir().unwrap();
    write_secret(&dir.path().join("packages/service/config.rs"));

    assert_eq!(redflag(dir.path()).status.code(), Some(1));
}

#[test]
fn scans_explicit_extensionless_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("credentials");
    write_secret(&path);

    assert_eq!(redflag(&path).status.code(), Some(1));
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
