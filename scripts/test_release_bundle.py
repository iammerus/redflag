#!/usr/bin/env python3
"""Adversarial release installation tests; no downloaded programs execute."""
import copy
import gzip
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import release_bundle as release


def machine(key):
    data = bytearray(128)
    if key == "linux_x64":
        data[:6] = b"\x7fELF\x02\x01"; data[18:20] = b"\x3e\x00"
    elif key.startswith("darwin_"):
        data[:4] = b"\xcf\xfa\xed\xfe"
        data[4:8] = b"\x0c\x00\x00\x01" if key.endswith("arm64") else b"\x07\x00\x00\x01"
    else:
        data[:2] = b"MZ"; data[60:64] = (64).to_bytes(4, "little"); data[64:70] = b"PE\0\0\x64\x86"
    return bytes(data)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="redflag-bundle-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.key = "darwin_arm64"
        self.binary, self.engine = release.executable_names(self.key)
        self.files = {self.binary: machine(self.key), self.engine: machine(self.key) + b"engine",
            "LICENSE": (release.ROOT / "LICENSE").read_bytes(),
            "licenses/betterleaks/LICENSE": (release.ROOT / "engines/LICENSE.betterleaks").read_bytes(),
            "licenses/dependencies.json": b"[]\n"}
        pins = copy.deepcopy(release.PINS)
        pins["assets"][self.key]["binary_sha256"] = release.digest(self.files[self.engine])
        patched = patch.object(release, "PINS", pins)
        patched.start(); self.addCleanup(patched.stop)

    def bundle(self, files=None, mutate=None, extra=()):
        files = dict(self.files if files is None else files)
        manifest = {"schema_version": 1, "version": release.version(), "platform": self.key,
            "target": release.PLATFORMS[self.key]["target"], "source_commit": "a" * 40,
            "source_dirty": False, "engine_version": release.PINS["version"],
            "engine_pins_sha256": release.digest(release.PINS_BYTES),
            "files": {name: {"bytes": len(data), "sha256": release.digest(data),
                "executable": name in (self.binary, self.engine)} for name, data in files.items()}}
        if mutate:
            mutate(manifest)
        files["manifest.json"] = release.canonical(manifest)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in files.items():
                header = tarfile.TarInfo(name); header.size = len(data)
                archive.addfile(header, io.BytesIO(data))
            for header, data in extra:
                archive.addfile(header, io.BytesIO(data))
        return gzip.compress(buffer.getvalue(), mtime=0)

    def verify(self, data, source=None):
        return release.verify_bundle(data, release.digest(data), self.key, source)

    def test_success_installs_only_verified_files_and_preserves_existing_destination(self):
        data = self.bundle(); archive = self.root / "bundle.tar.gz"; archive.write_bytes(data)
        destination = self.root / "installation"
        result = release.install_bundle(archive, destination, release.digest(data), self.key, "a" * 40)
        self.assertEqual(result.read_bytes(), self.files[self.binary])
        self.assertEqual({path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()}, set(self.files))
        with self.assertRaises(ValueError):
            release.install_bundle(archive, destination, release.digest(data), self.key)
        self.assertEqual(result.read_bytes(), self.files[self.binary])

    def test_checksum_failure_has_no_installation_side_effect(self):
        archive = self.root / "bundle.tar.gz"; archive.write_bytes(self.bundle())
        destination = self.root / "absent" / "installation"
        with self.assertRaises(ValueError):
            release.install_bundle(archive, destination, "0" * 64, self.key)
        self.assertFalse(destination.parent.exists())

    def test_manifest_requires_version_platform_source_and_exact_inventory(self):
        for field, value in [("schema_version", 2), ("version", "0.0.0"), ("platform", "linux_x64"),
                ("target", "wrong"), ("source_commit", "not-a-commit"), ("engine_version", "wrong"),
                ("engine_pins_sha256", "0" * 64)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(self.bundle(mutate=lambda record: record.update({field: value})))
        with self.assertRaises(ValueError):
            self.verify(self.bundle(), "b" * 40)
        dirty = self.bundle(mutate=lambda record: record.update(source_dirty=True))
        self.verify(dirty)  # A caller-supplied digest can authorize development bytes.
        with self.assertRaises(ValueError):
            self.verify(dirty, "a" * 40)
        with self.assertRaises(ValueError):
            self.verify(self.bundle(mutate=lambda record: record["files"].pop("LICENSE")))
        with self.assertRaises(ValueError):
            self.verify(self.bundle(mutate=lambda record: record["files"][self.binary].update(sha256="0" * 64)))

    def test_engine_pin_machine_and_license_checks_are_independent_of_manifest_hashes(self):
        for key, replacement in [(self.engine, b"replacement"), (self.binary, machine("linux_x64")),
                ("LICENSE", b"missing notice"), ("licenses/betterleaks/LICENSE", b"missing notice")]:
            files = dict(self.files, **{key: replacement})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(self.bundle(files))
        files = dict(self.files, **{"unexpected.exe": b"payload"})
        with self.assertRaises(ValueError):
            self.verify(self.bundle(files))

    def test_archive_structure_rejects_links_duplicates_traversal_and_extensions(self):
        for name, kind in [(self.binary, tarfile.REGTYPE), ("../escape", tarfile.REGTYPE),
                ("/absolute", tarfile.REGTYPE), ("bad\\path", tarfile.REGTYPE),
                ("alias", tarfile.SYMTYPE), ("alias", tarfile.LNKTYPE), ("metadata", tarfile.XHDTYPE)]:
            header = tarfile.TarInfo(name); header.type = kind
            with self.subTest(name=name, kind=kind), self.assertRaises((ValueError, tarfile.TarError)):
                self.verify(self.bundle(extra=[(header, b"")]))

    def test_truncation_crc_and_resource_limits_fail_before_install(self):
        data = self.bundle()
        broken = bytearray(data); broken[-8] ^= 1
        for payload in [data[:-1], bytes(broken), data + b"trailing"]:
            with self.assertRaises((ValueError, OSError, EOFError)):
                self.verify(payload)
        for limit, value in [("MAX_FILES", 2), ("MAX_MEMBER", 64), ("MAX_TOTAL", 64), ("MAX_ARCHIVE", 64)]:
            with patch.object(release, limit, value), self.subTest(limit=limit), self.assertRaises(ValueError):
                self.verify(data)

    def test_machine_headers_distinguish_all_release_targets(self):
        for expected in release.PLATFORMS:
            for actual in release.PLATFORMS:
                if expected == actual:
                    release.check_machine(machine(actual), expected)
                else:
                    with self.assertRaises(ValueError):
                        release.check_machine(machine(actual), expected)

    def test_notice_collection_preserves_native_dependency_licenses_and_rejects_escape(self):
        crate = self.root / "crate"; crate.mkdir()
        (crate / "native").mkdir(); (crate / "native/COPYING").write_text("native notice")
        package = {"id": "fixture", "name": "fixture", "version": "1.0.0", "license": "MIT",
                   "manifest_path": str(crate / "Cargo.toml")}
        metadata = {"resolve": {"nodes": [{"id": "fixture"}]}, "packages": [package]}
        result = release.notices(metadata)
        self.assertEqual(result["licenses/rust/fixture-1.0.0/native/COPYING"], b"native notice")
        (self.root / "outside").write_text("outside")
        package["license_file"] = "../outside"
        with self.assertRaises(ValueError):
            release.notices(metadata)


if __name__ == "__main__":
    unittest.main()
