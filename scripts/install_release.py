#!/usr/bin/env python3
"""Download a versioned release and verify its GitHub build provenance."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import release_bundle as bundle

REPOSITORY = "iammerus/redflag"
WORKFLOW = f"github.com/{REPOSITORY}/.github/workflows/release.yml"


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        if request.has_header("Authorization") or not new_url.startswith("https://"):
            raise ValueError("Refusing an authenticated or non-HTTPS release redirect")
        return super().redirect_request(request, response, code, message, headers, new_url)


def fetch(url, maximum, token=""):
    headers = {"User-Agent": "redflag-release-installer", "Accept": "application/vnd.github+json"}
    if token:
        # Authentication is only used for the fixed API host, never asset redirects.
        if not url.startswith("https://api.github.com/"):
            raise ValueError("Refusing to send release authentication to a non-API host")
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.build_opener(ReleaseRedirect).open(request, timeout=30) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Release download exceeds its size limit")
    return data


def source_commit(action_ref, token=""):
    if bundle.COMMIT.fullmatch(action_ref):
        return action_ref
    if action_ref != f"v{bundle.version()}":
        raise ValueError("Use this release's version tag or a full commit SHA; local Actions require a trusted supplied bundle")
    data = json.loads(fetch(f"https://api.github.com/repos/{REPOSITORY}/commits/{action_ref}", 1024 * 1024, token))
    commit = data.get("sha", "") if isinstance(data, dict) else ""
    if not isinstance(commit, str) or not bundle.COMMIT.fullmatch(commit):
        raise ValueError("GitHub did not resolve the release tag to a complete source commit")
    return commit


def expected_checksum(data, filename):
    found = []
    for line in data.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None:
            raise ValueError("Release checksum inventory is malformed")
        if match[2] == filename:
            found.append(match[1])
    if len(found) != 1:
        raise ValueError("Release checksum inventory must name this archive exactly once")
    return found[0]


def verification_command(archive, commit):
    return ["gh", "attestation", "verify", str(archive), "--repo", REPOSITORY,
            "--signer-workflow", WORKFLOW, "--source-ref", f"refs/tags/v{bundle.version()}",
            "--source-digest", commit, "--signer-digest", commit,
            "--deny-self-hosted-runners", "--hostname", "github.com"]


def verify_provenance(archive, commit, token=""):
    allowed = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
               "TMP", "TEMP", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "NO_PROXY")
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    environment.update(GH_HOST="github.com", GH_PROMPT_DISABLED="1", NO_COLOR="1")
    if token:
        environment["GH_TOKEN"] = token
    try:
        result = subprocess.run(verification_command(archive, commit), env=environment,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    except FileNotFoundError as error:
        raise ValueError("GitHub CLI with 'gh attestation verify' is required for release downloads") from error
    if result.returncode != 0:
        # Keep child diagnostics and environment out of the scanner's public report.
        raise ValueError("Release build provenance could not be verified for this exact source commit and release workflow")


def install(directory, action_ref, token=""):
    key = bundle.platform_key()
    commit = source_commit(action_ref, token)
    filename = bundle.archive_name(key)
    base = f"https://github.com/{REPOSITORY}/releases/download/v{bundle.version()}"
    checksums = fetch(f"{base}/SHA256SUMS", 1024 * 1024)
    checksum = expected_checksum(checksums, filename)
    data = fetch(f"{base}/{filename}", bundle.MAX_ARCHIVE)
    if bundle.digest(data) != checksum:
        raise ValueError("Downloaded release does not match its published checksum")
    with tempfile.TemporaryDirectory(prefix="redflag-download-") as temporary:
        archive = Path(temporary) / filename
        archive.write_bytes(data)
        verify_provenance(archive, commit, token)
        return bundle.install_bundle(archive, directory, checksum, key, commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--ref", required=True, help="Exact Action source SHA or this release tag")
    args = parser.parse_args()
    try:
        print(install(args.directory, args.ref, os.environ.get("GH_TOKEN", "")).resolve())
    except (OSError, EOFError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(2, f"Release installation failed: {error}\n")


if __name__ == "__main__":
    main()
