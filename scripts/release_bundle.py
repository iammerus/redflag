#!/usr/bin/env python3
"""Build and verify bounded release bundles before installing any executable."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = json.loads((ROOT / "release/platforms.json").read_text())
PINS_BYTES = (ROOT / "engines/pins.json").read_bytes()
PINS = json.loads(PINS_BYTES)
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_FILES = 4096
HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def version():
    package = re.search(r"(?ms)^\[package\]\s*(.*?)(?=^\[|\Z)", (ROOT / "Cargo.toml").read_text())[1]
    result = re.search(r'(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', package)
    if result is None:
        raise ValueError("Release package version must have major.minor.patch form")
    return result[1]


def platform_key():
    system = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}.get(platform.system())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}.get(platform.machine().lower())
    key = f"{system}_{arch}"
    if key not in PLATFORMS:
        raise ValueError("No Redflag release is supported on this operating system/architecture")
    return key


def executable_names(key):
    suffix = ".exe" if key.startswith("windows_") else ""
    return "redflag" + suffix, "engines/betterleaks" + suffix


def archive_name(key):
    return f"redflag-{version()}-{key}.tar.gz"


def read_regular(path, maximum=MAX_MEMBER):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Release input must be a regular file, without symlinks")
    with path.open("rb") as source:
        result = source.read(maximum + 1)
    if len(result) > maximum:
        raise ValueError("Release input exceeds its size limit")
    return result


def check_machine(data, key):
    valid = False
    if key == "linux_x64":
        valid = data[:6] == b"\x7fELF\x02\x01" and data[18:20] == b"\x3e\x00"
    elif key.startswith("darwin_"):
        cpu = b"\x0c\x00\x00\x01" if key.endswith("arm64") else b"\x07\x00\x00\x01"
        valid = data[:4] == b"\xcf\xfa\xed\xfe" and data[4:8] == cpu
    elif key == "windows_x64" and len(data) >= 64 and data[:2] == b"MZ":
        offset = int.from_bytes(data[60:64], "little")
        valid = data[offset:offset + 6] == b"PE\0\0\x64\x86"
    if not valid:
        raise ValueError("Executable architecture does not match the release platform")


def notices(metadata):
    """Preserve package notices, including bundled native dependency notices."""
    resolved = {node["id"] for node in metadata["resolve"]["nodes"]}
    files = {"LICENSE": read_regular(ROOT / "LICENSE"),
             "licenses/betterleaks/LICENSE": read_regular(ROOT / "engines/LICENSE.betterleaks")}
    inventory = []
    for package in sorted(metadata["packages"], key=lambda item: (item["name"], item["version"])):
        if package["id"] not in resolved or package["name"] == "redflag":
            continue
        root = Path(package["manifest_path"]).parent
        selected = set()
        # Native dependency source trees carry notices separate from their Rust
        # bindings. Include every license/notice file there, without source code.
        for current, directories, names in os.walk(root, followlinks=False):
            directories[:] = [name for name in directories if name not in (".git", "target")]
            for name in names:
                if name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE")):
                    selected.add(Path(current) / name)
        if package.get("license_file"):
            selected.add(root / package["license_file"])
        if not selected:
            raise ValueError(f"No license notice found for {package['name']}")
        paths = []
        prefix = f"licenses/rust/{package['name']}-{package['version']}/"
        for path in sorted(selected):
            # Neither declared notice paths nor symlinks may leave the crate.
            resolved_path = path.resolve()
            resolved_path.relative_to(root.resolve())
            name = prefix + path.relative_to(root).as_posix()
            files[name] = read_regular(resolved_path, 4 * 1024 * 1024)
            paths.append(name)
        inventory.append({"name": package["name"], "version": package["version"],
                          "license": package.get("license"), "notices": paths})
    files["licenses/dependencies.json"] = canonical(inventory)
    return files


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def make_bundle(binary, engine, key, source_commit, metadata, destination):
    if key not in PLATFORMS or not COMMIT.fullmatch(source_commit):
        raise ValueError("Release requires a supported platform and exact source commit")
    head = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    if head != source_commit:
        raise ValueError("Release source commit differs from the current checkout")
    dirty = bool(subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"]))
    redflag_name, engine_name = executable_names(key)
    files = notices(metadata)
    files[redflag_name] = read_regular(binary)
    files[engine_name] = read_regular(engine)
    check_machine(files[redflag_name], key)
    check_machine(files[engine_name], key)
    if digest(files[engine_name]) != PINS["assets"][key]["binary_sha256"]:
        raise ValueError("Release engine does not match its reviewed platform pin")
    if key == platform_key():
        reported = subprocess.run([str(binary.resolve()), "--version"], capture_output=True, check=True, timeout=10)
        if reported.stdout.strip() != f"redflag {version()}".encode():
            raise ValueError("Built Redflag version does not match Cargo.toml")
    manifest = {"schema_version": 1, "version": version(), "platform": key,
                "target": PLATFORMS[key]["target"], "source_commit": source_commit, "source_dirty": dirty,
                "engine_version": PINS["version"], "engine_pins_sha256": digest(PINS_BYTES),
                "files": {name: {"bytes": len(data), "sha256": digest(data),
                    "executable": name in (redflag_name, engine_name)} for name, data in files.items()}}
    files["manifest.json"] = canonical(manifest)
    if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_TOTAL:
        raise ValueError("Release bundle exceeds its inventory limit")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise ValueError("Release destination already exists")
    staged = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
            staged = Path(output.name)
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    for name, data in sorted(files.items()):
                        header = tarfile.TarInfo(name)
                        header.size = len(data)
                        header.mode = 0o755 if name in (redflag_name, engine_name) else 0o644
                        archive.addfile(header, io.BytesIO(data))
            output.flush()
            os.fsync(output.fileno())
        data = read_regular(staged, MAX_ARCHIVE)
        checksum = digest(data)
        # Verify the exact package before making it available to the release job.
        verify_bundle(data, checksum, key)
        os.replace(staged, destination)
        staged = None
        return checksum
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def safe_member(name):
    path = PurePosixPath(name)
    return (isinstance(name, str) and len(name) <= 1024 and path.as_posix() == name
            and not path.is_absolute() and all(part not in (".", "..") for part in path.parts)
            and bool(path.parts) and not any(ord(char) < 32 or char in "\\:" for char in name))


def verify_bundle(data, checksum, key, source_commit=None):
    if not HEX.fullmatch(checksum) or len(data) > MAX_ARCHIVE or digest(data) != checksum:
        raise ValueError("Release archive checksum or size does not match the trusted input")
    if key not in PLATFORMS:
        raise ValueError("Unsupported release platform")
    files = {}
    total = 0
    # Bound decompression before metadata parsing. High-level tar iteration can
    # consume arbitrarily large PAX/GNU headers before yielding a file to inspect.
    maximum = MAX_TOTAL + MAX_FILES * 1024 + 10240
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as compressed:
        expanded = compressed.read(maximum + 1)
    if len(expanded) > maximum:
        raise ValueError("Release expanded bytes exceed the size limit")
    cursor = 0
    while True:
        block = expanded[cursor:cursor + 512]
        if block == bytes(512):
            tail = expanded[cursor:]
            if len(tail) < 1024 or len(tail) % 512 or any(tail):
                raise ValueError("Release archive has an incomplete terminator or trailing data")
            break
        if len(block) != 512:
            raise ValueError("Release archive header is truncated")
        entry = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
        if (len(files) >= MAX_FILES or entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                or not safe_member(entry.name) or entry.name in files
                or entry.size < 0 or entry.size > MAX_MEMBER):
            raise ValueError("Release archive has an invalid or oversized member")
        total += entry.size
        if total > MAX_TOTAL:
            raise ValueError("Release expanded bytes exceed the size limit")
        start = cursor + 512
        end = start + entry.size
        cursor = start + ((entry.size + 511) // 512) * 512
        if cursor > len(expanded) or any(expanded[end:cursor]):
            raise ValueError("Release archive member is truncated or has invalid padding")
        files[entry.name] = expanded[start:end]
    if "manifest.json" not in files or len(files["manifest.json"]) > 4 * 1024 * 1024:
        raise ValueError("Release manifest is missing or oversized")
    manifest = json.loads(files.pop("manifest.json"))
    expected = {"schema_version", "version", "platform", "target", "source_commit", "source_dirty",
                "engine_version", "engine_pins_sha256", "files"}
    if (set(manifest) != expected or manifest["schema_version"] != 1
            or manifest["version"] != version() or manifest["platform"] != key
            or manifest["target"] != PLATFORMS[key]["target"]
            or not COMMIT.fullmatch(manifest["source_commit"])
            or type(manifest["source_dirty"]) is not bool
            or (source_commit is not None and (manifest["source_commit"] != source_commit or manifest["source_dirty"]))
            or manifest["engine_version"] != PINS["version"]
            or manifest["engine_pins_sha256"] != digest(PINS_BYTES)
            or set(manifest["files"]) != set(files)):
        raise ValueError("Release manifest does not match the requested version, platform or source")
    redflag_name, engine_name = executable_names(key)
    required = {redflag_name, engine_name, "LICENSE", "licenses/betterleaks/LICENSE", "licenses/dependencies.json"}
    if not required.issubset(files):
        raise ValueError("Release is missing an executable or license inventory")
    if (files["LICENSE"] != (ROOT / "LICENSE").read_bytes()
            or files["licenses/betterleaks/LICENSE"] != (ROOT / "engines/LICENSE.betterleaks").read_bytes()):
        raise ValueError("Release license notices differ from the reviewed notices")
    for name, content in files.items():
        record = manifest["files"][name]
        if record != {"bytes": len(content), "sha256": digest(content),
                      "executable": name in (redflag_name, engine_name)}:
            raise ValueError("Release member integrity check failed")
        if name not in required and not name.startswith("licenses/rust/"):
            raise ValueError("Release contains an unexpected payload")
    check_machine(files[redflag_name], key)
    if digest(files[engine_name]) != PINS["assets"][key]["binary_sha256"]:
        raise ValueError("Bundled engine differs from the reviewed executable pin")
    return manifest, files


def install_bundle(archive, directory, checksum, key=None, source_commit=None):
    key = key or platform_key()
    _, files = verify_bundle(read_regular(archive, MAX_ARCHIVE), checksum, key, source_commit)
    if directory.exists() or directory.is_symlink():
        raise ValueError("Installation destination must not already exist")
    directory.parent.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(dir=directory.parent, prefix=".redflag-install-"))
    try:
        for name, data in files.items():
            path = staged / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o755 if name in executable_names(key) else 0o644)
        os.replace(staged, directory)
    finally:
        if staged.exists():
            shutil.rmtree(staged)
    return directory / executable_names(key)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--binary", type=Path, required=True)
    build.add_argument("--engine", type=Path, required=True)
    build.add_argument("--platform", choices=PLATFORMS, required=True)
    build.add_argument("--source-commit", required=True)
    build.add_argument("--metadata", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    install = commands.add_parser("install")
    install.add_argument("--archive", type=Path, required=True)
    install.add_argument("--directory", type=Path, required=True)
    install.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "build":
            checksum = make_bundle(args.binary, args.engine, args.platform, args.source_commit,
                json.loads(read_regular(args.metadata, MAX_TOTAL)), args.output)
            print(f"{checksum}  {args.output.name}")
        else:
            print(install_bundle(args.archive, args.directory, args.sha256).resolve())
    except (OSError, EOFError, ValueError, TypeError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(2, f"Release bundle failed: {error}\n")


if __name__ == "__main__":
    main()
