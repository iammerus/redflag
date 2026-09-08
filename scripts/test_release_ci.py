#!/usr/bin/env python3
"""Release publication gates; every publishing command is mocked."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import install_release
import release_bundle as bundle
import release_ci


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="redflag-release-gate-")
        self.addCleanup(self.temporary.cleanup)
        self.environment = {"GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": install_release.REPOSITORY, "GITHUB_REF": "refs/tags/v" + bundle.version(),
            "GITHUB_SHA": "a" * 40, "RUNNER_TEMP": self.temporary.name, "REDFLAG_PLATFORM": "darwin_arm64",
            "REDFLAG_TARGET": bundle.PLATFORMS["darwin_arm64"]["target"],
            "GITHUB_WORKFLOW_REF": install_release.REPOSITORY + "/.github/workflows/release.yml@refs/tags/v" + bundle.version()}
        self.directory = Path(self.temporary.name) / "redflag-release"
        self.directory.mkdir()

    def populate(self):
        for key in bundle.PLATFORMS:
            path = self.directory / bundle.archive_name(key)
            path.write_bytes(key.encode())
            path.with_name(path.name + ".sha256").write_text(f"{bundle.digest(path.read_bytes())}  {path.name}\n")

    def test_release_context_rejects_wrong_origin_tag_workflow_or_runner(self):
        with patch.object(bundle, "platform_key", return_value="darwin_arm64"):
            release_ci.release_context(self.environment)
            for name, value in [("GITHUB_ACTIONS", "false"), ("GITHUB_SERVER_URL", "https://enterprise.invalid"),
                    ("GITHUB_REPOSITORY", "fork/redflag"), ("GITHUB_REF", "refs/heads/main"),
                    ("GITHUB_WORKFLOW_REF", "other-workflow"), ("GITHUB_SHA", "short"),
                    ("REDFLAG_PLATFORM", "linux_x64"), ("REDFLAG_TARGET", "wrong"), ("RUNNER_TEMP", "")]:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    release_ci.release_context(dict(self.environment, **{name: value}))

    def test_incomplete_inventory_and_failed_provenance_never_publish(self):
        with patch.object(release_ci.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                release_ci.publish(self.environment)
            run.assert_not_called()
            self.populate()
            with patch.object(install_release, "verify_provenance", side_effect=ValueError("invalid")):
                with self.assertRaises(ValueError):
                    release_ci.publish(self.environment)
            run.assert_not_called()
            self.assertFalse((self.directory / "SHA256SUMS").exists())

    def test_every_bundle_is_verified_before_draft_creation_and_publication(self):
        self.populate()
        checked = []
        def verify(data, checksum, key, source):
            self.assertEqual(bundle.digest(data), checksum)
            self.assertEqual(source, "a" * 40)
            checked.append(key)
        def command(args, **kwargs):
            self.assertEqual(checked, sorted(bundle.PLATFORMS))
            self.assertTrue(kwargs["check"])
            self.assertEqual(args[:2], ["gh", "release"])
        with patch.object(install_release, "verify_provenance") as attest, \
                patch.object(bundle, "verify_bundle", side_effect=verify), \
                patch.object(release_ci.subprocess, "run", side_effect=command) as run:
            release_ci.publish(self.environment)
            self.assertEqual(attest.call_count, len(bundle.PLATFORMS))
            self.assertEqual(run.call_count, 2)
            self.assertIn("--draft", run.call_args_list[0].args[0])
            self.assertIn("--verify-tag", run.call_args_list[0].args[0])
            self.assertIn("--draft=false", run.call_args_list[1].args[0])
        self.assertEqual(len((self.directory / "SHA256SUMS").read_text().splitlines()), len(bundle.PLATFORMS))


if __name__ == "__main__":
    unittest.main()
