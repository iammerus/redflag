#!/usr/bin/env python3
"""Exercise the actual Action entry point with a verified locally built bundle."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    archive = os.environ["REDFLAG_TEST_BUNDLE"]
    checksum = os.environ["REDFLAG_TEST_SHA256"]
    with tempfile.TemporaryDirectory(prefix="redflag-action-integration-") as temporary:
        root = Path(temporary)
        baseline = {name: value for name, value in os.environ.items() if not name.startswith("REDFLAG_INPUT_")}
        baseline.update(REDFLAG_INPUT_BUNDLE=archive, REDFLAG_INPUT_BUNDLE_SHA256=checksum,
                        GIT_AUTHOR_NAME="Release Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                        GIT_COMMITTER_NAME="Release Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")

        def run(expected, extra=None, **inputs):
            env = dict(baseline, **(extra or {}))
            env.update({"REDFLAG_INPUT_" + key.upper(): value for key, value in inputs.items()})
            env["REDFLAG_INPUT_FORMAT"] = "json"
            output = subprocess.run([sys.executable, "-E", "-s", str(ROOT / "scripts/run_action.py")],
                                    cwd=root, env=env, capture_output=True, timeout=180)
            assert output.returncode == expected, output.stderr.decode(errors="replace")
            if expected != 2:
                return json.loads(output.stdout)
            assert not output.stdout
            return None

        public = root / "dist folder"; public.mkdir()
        (public / "index.html").write_text("ordinary public output\n")
        manifest = root / "approval.json"
        result = run(0, mode="artifacts", paths=str(public), manifest=str(manifest), no_config="true")
        assert result["coverage"]["engine"]["name"] == "betterleaks"
        run(0, mode="verify-artifacts", manifest=str(manifest))
        value = "opaque-Pvt!42"
        (public / "index.html").write_text(value)
        blocked = run(1, {"RF_ACTION_PRIVATE": value}, mode="artifacts", paths=str(public),
                      private_env="RF_ACTION_PRIVATE", manifest=str(manifest), no_config="true")
        assert not manifest.exists()
        assert value not in json.dumps(blocked)
        assert any(finding["pattern_name"] == "private-env:RF_ACTION_PRIVATE" for finding in blocked["findings"])
        run(2, mode="artifacts", paths=str(root / "missing"), no_config="true")

        repository = root / "repository"; repository.mkdir()
        def git(*args):
            return subprocess.check_output(["git", "-C", str(repository), *args], env=baseline, stderr=subprocess.PIPE).decode().strip()
        git("init", "-q"); git("checkout", "-qb", "main")
        (repository / "public.txt").write_text("ordinary\n")
        git("add", "."); git("commit", "-qm", "Public base")
        base = git("rev-parse", "HEAD")
        run(0, mode="scan", path=str(repository), no_config="true")
        token = "ghp_" + "aB3dE6gH9jK2mN5pQ8" + "sT1vW4xY7zA0cD3fG6"
        (repository / "client.js").write_text('export const token = "' + token + '";\n')
        git("add", "."); git("commit", "-qm", "Introduce synthetic credential")
        (repository / "client.js").unlink()
        git("add", "-A"); git("commit", "-qm", "Remove synthetic credential")
        head = git("rev-parse", "HEAD")
        run(0, mode="scan", path=str(repository), no_config="true")
        introduced = run(1, mode="changes", path=str(repository), base=base, head=head, no_config="true")
        assert token not in json.dumps(introduced)
        assert introduced["coverage"]["base"] == base
        event = root / "event.json"
        event.write_text(json.dumps({"before": base, "after": head, "created": False, "deleted": False,
                                   "ref": "refs/heads/main", "repository": {"default_branch": "main"}}))
        event_scan = run(1, {"GITHUB_EVENT_PATH": str(event), "GITHUB_EVENT_NAME": "push"},
                         mode="changes", path=str(repository), no_config="true")
        assert event_scan["coverage"]["head"] == head
        assert event_scan["logical_findings"] == introduced["logical_findings"]
        print(json.dumps({"artifact_clean": 0, "artifact_private": 1, "artifact_missing": 2,
                          "manifest_verified": 0, "legacy_clean": 0, "introduced_then_deleted": 1,
                          "event_range": 1, "redacted": True}))


if __name__ == "__main__":
    main()
