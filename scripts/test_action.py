#!/usr/bin/env python3
"""Action routing and download authorization checks, without remote execution."""
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.request
import install_release as installer
import release_bundle as bundle
import run_action


class RoutingTests(unittest.TestCase):
    def test_legacy_inputs_retain_source_scan_semantics(self):
        self.assertEqual(run_action.arguments({}, {}), ["scan", "--format=text", "--no-progress", "--", "."])
        args = run_action.arguments({"path": "folder with spaces", "config": "--policy.toml", "git-history": "true"}, {})
        self.assertIn("--config=--policy.toml", args)
        self.assertIn("--git-history", args)
        self.assertEqual(args[-2:], ["--", "folder with spaces"])

    def test_changes_defaults_to_the_exact_event_and_accepts_manual_scope(self):
        args = run_action.arguments({"mode": "changes"}, {"GITHUB_EVENT_PATH": "/event.json"})
        self.assertIn("--github-event=/event.json", args)
        self.assertIn("--format=github", args)
        args = run_action.arguments({"mode": "changes", "base": "base", "head": "head", "merge-result": "merge", "policy-ref": "trusted"}, {})
        for arg in ["--base=base", "--head=head", "--merge-result=merge", "--policy-ref=trusted"]:
            self.assertIn(arg, args)
        self.assertFalse(any(arg.startswith("--github-event") for arg in args))

    def test_publication_paths_and_private_names_remain_literal_arguments(self):
        values = {"mode": "artifacts", "paths": "dist folder\n--literal\n$(touch forbidden)\n",
                  "private-env": "PRIVATE_A\nPRIVATE_B", "manifest": "approval.json", "format": "json"}
        args = run_action.arguments(values, {})
        self.assertEqual(args[-4:], ["--", "dist folder", "--literal", "$(touch forbidden)"])
        self.assertIn("--private-env=PRIVATE_A", args)
        self.assertIn("--private-env=PRIVATE_B", args)
        self.assertIn("--manifest=approval.json", args)
        args = run_action.arguments({"mode": "verify-artifacts", "manifest": "approval.json", "paths": "copied one\ncopied two"}, {})
        self.assertEqual(args, ["verify-artifacts", "--format=text", "--target=copied one", "--target=copied two", "--", "approval.json"])

    def test_missing_ambiguous_and_inapplicable_inputs_fail_before_installation(self):
        for values in [{"mode": "other"}, {"git-history": "yes"}, {"config": "file", "no-config": "true"},
                {"mode": "artifacts"}, {"mode": "verify-artifacts"}, {"mode": "changes"},
                {"mode": "changes", "head": "head"}, {"mode": "changes", "merge-result": "merge"},
                {"mode": "changes", "base": "base", "new-branch": "true"},
                {"mode": "changes", "base": "base", "policy-ref": "trusted", "no-config": "true"},
                {"mode": "changes", "base": "base", "max-commits": "0"},
                {"mode": "artifacts", "paths": "dist", "path": "other"},
                {"mode": "scan", "private-env": "PRIVATE"}, {"mode": "scan", "engine": "betterleaks"},
                {"mode": "verify-artifacts", "manifest": "file", "config": "policy"},
                {"mode": "artifacts", "paths": "dist", "git-history": "true"}]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                run_action.arguments(values, {})

    def test_supplied_bundles_require_a_digest_and_preserve_scan_exit_codes(self):
        with patch.object(bundle, "install_bundle", return_value=Path("/verified/redflag")) as install, \
                patch.object(subprocess, "call", return_value=1) as execute:
            environment = {"REDFLAG_INPUT_BUNDLE": "/bundle", "REDFLAG_INPUT_BUNDLE_SHA256": "a" * 64,
                           "REDFLAG_DOWNLOAD_TOKEN": "download-token", "PRIVATE": "private-value"}
            self.assertEqual(run_action.run(environment), 1)
            self.assertEqual(install.call_args.args[0], Path("/bundle"))
            self.assertNotIn("REDFLAG_DOWNLOAD_TOKEN", execute.call_args.kwargs["env"])
            self.assertEqual(execute.call_args.kwargs["env"]["PRIVATE"], "private-value")
        with self.assertRaises(ValueError):
            run_action.run({"REDFLAG_INPUT_BUNDLE": "/bundle"})


class DownloadTests(unittest.TestCase):
    def test_source_pin_requires_an_exact_commit_or_matching_release_tag(self):
        with patch.object(installer, "fetch") as fetch:
            self.assertEqual(installer.source_commit("a" * 40), "a" * 40)
            fetch.assert_not_called()
            fetch.return_value = json.dumps({"sha": "b" * 40}).encode()
            self.assertEqual(installer.source_commit("v" + bundle.version(), "token"), "b" * 40)
            self.assertEqual(fetch.call_args.args[-1], "token")
            for ref in ["main", "../escape", "v0.0.0", ""]:
                with self.assertRaises(ValueError):
                    installer.source_commit(ref)
            fetch.return_value = b"[]"
            with self.assertRaises(ValueError):
                installer.source_commit("v" + bundle.version())

    def test_checksums_require_one_exact_named_digest(self):
        name = bundle.archive_name("darwin_arm64")
        line = f"{'a' * 64}  {name}\n".encode()
        self.assertEqual(installer.expected_checksum(line, name), "a" * 64)
        for data in [line + line, b"invalid\n", f"{'a' * 64}  other.tar.gz\n".encode()]:
            with self.assertRaises(ValueError):
                installer.expected_checksum(data, name)

    def test_verifier_binds_signer_source_release_ref_and_hosted_runner(self):
        command = installer.verification_command(Path("bundle.tar.gz"), "a" * 40)
        for option, value in [("--repo", installer.REPOSITORY), ("--signer-workflow", installer.WORKFLOW),
                ("--source-digest", "a" * 40), ("--signer-digest", "a" * 40),
                ("--source-ref", "refs/tags/v" + bundle.version()), ("--hostname", "github.com")]:
            self.assertEqual(command[command.index(option) + 1], value)
        self.assertIn("--deny-self-hosted-runners", command)
        with patch.dict(os.environ, {"PRIVATE": "private-value", "GH_HOST": "unexpected"}), \
                patch.object(subprocess, "run", return_value=subprocess.CompletedProcess(command, 1)) as run:
            with self.assertRaises(ValueError):
                installer.verify_provenance(Path("bundle"), "a" * 40, "token")
            self.assertNotIn("PRIVATE", run.call_args.kwargs["env"])
            self.assertEqual(run.call_args.kwargs["env"]["GH_TOKEN"], "token")
            self.assertEqual(run.call_args.kwargs["env"]["GH_HOST"], "github.com")

    def test_authentication_never_follows_redirects_or_goes_to_asset_hosts(self):
        request = urllib.request.Request("https://api.github.com/repos/example", headers={"Authorization": "Bearer token"})
        redirect = installer.ReleaseRedirect()
        with self.assertRaises(ValueError):
            redirect.redirect_request(request, None, 302, "", {}, "https://other.invalid/")
        with self.assertRaises(ValueError):
            installer.fetch("https://github.com/release", 100, "token")

    def test_provenance_failure_prevents_install_and_no_asset_request_receives_auth(self):
        key = "darwin_arm64"; name = bundle.archive_name(key); data = b"archive bytes"
        inventory = f"{bundle.digest(data)}  {name}\n".encode()
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(bundle, "platform_key", return_value=key), \
                patch.object(installer, "fetch", side_effect=[inventory, data]) as fetch, \
                patch.object(installer, "verify_provenance", side_effect=ValueError("bad provenance")), \
                patch.object(bundle, "install_bundle") as install:
            with self.assertRaises(ValueError):
                installer.install(Path(temporary) / "absent", "a" * 40, "token")
            install.assert_not_called()
            self.assertTrue(all(len(call.args) == 2 for call in fetch.call_args_list))


if __name__ == "__main__":
    unittest.main()
