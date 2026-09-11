#!/usr/bin/env python3
"""Native release workflow gates. Publishing is restricted to the release tag job."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import install_release
import release_bundle as bundle


def release_context(environment, native=True):
    tag = "v" + bundle.version()
    commit = environment.get("GITHUB_SHA", "")
    expected_workflow = f"{install_release.REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}"
    if (environment.get("GITHUB_ACTIONS") != "true"
            or environment.get("GITHUB_SERVER_URL") != "https://github.com"
            or environment.get("GITHUB_REPOSITORY") != install_release.REPOSITORY
            or environment.get("GITHUB_REF") != "refs/tags/" + tag
            or environment.get("GITHUB_WORKFLOW_REF") != expected_workflow
            or not bundle.COMMIT.fullmatch(commit)):
        raise ValueError("Release jobs require the official version tag and release workflow")
    if native:
        key = environment.get("REDFLAG_PLATFORM", "")
        if key != bundle.platform_key() or environment.get("REDFLAG_TARGET") != bundle.PLATFORMS[key]["target"]:
            raise ValueError("Native release runner does not match its declared platform and target")
    else:
        key = None
    if not environment.get("RUNNER_TEMP"):
        raise ValueError("Release jobs require a private runner temporary directory")
    return tag, commit, key, Path(environment["RUNNER_TEMP"]) / "redflag-release"


def package(environment):
    _, commit, key, directory = release_context(environment)
    target = bundle.PLATFORMS[key]["target"]
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target]))
    redflag_name, engine_name = bundle.executable_names(key)
    archive = directory / bundle.archive_name(key)
    checksum = bundle.make_bundle(bundle.ROOT / "target" / target / "release" / redflag_name,
        bundle.ROOT / "target/debug" / engine_name, key, commit, metadata, archive)
    bundle.verify_bundle(bundle.read_regular(archive, bundle.MAX_ARCHIVE), checksum, key, commit)
    archive.with_name(archive.name + ".sha256").write_text(f"{checksum}  {archive.name}\n")


def ci_package(environment):
    """Package a native CI build for local Action tests, without release writes."""
    key = bundle.platform_key()
    if environment.get("REDFLAG_PLATFORM", key) != key:
        raise ValueError("CI runner does not match its declared native platform")
    target = bundle.PLATFORMS[key]["target"]
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target]))
    target_directory = Path(metadata["target_directory"])
    redflag_name, engine_name = bundle.executable_names(key)
    archive = Path(environment["RUNNER_TEMP"]) / "redflag-ci.tar.gz"
    checksum = bundle.make_bundle(target_directory / "release" / redflag_name,
        target_directory / "debug" / engine_name, key, environment["GITHUB_SHA"], metadata, archive)
    with Path(environment["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"bundle={archive}\nsha256={checksum}\n")


def test(environment):
    _, _, key, directory = release_context(environment)
    archive = directory / bundle.archive_name(key)
    checksum = install_release.expected_checksum(archive.with_name(archive.name + ".sha256").read_bytes(), archive.name)
    child = dict(environment, REDFLAG_TEST_BUNDLE=str(archive), REDFLAG_TEST_SHA256=checksum)
    subprocess.run([sys.executable, "-E", "-s", str(bundle.ROOT / "scripts/test_action_integration.py")], env=child, check=True)


def publish(environment):
    tag, commit, _, directory = release_context(environment, native=False)
    expected = {bundle.archive_name(key) for key in bundle.PLATFORMS}
    if {path.name for path in directory.iterdir()} != expected | {name + ".sha256" for name in expected}:
        raise ValueError("Release publication requires exactly one bundle and checksum for every platform")
    archives = []
    checksums = []
    for key in sorted(bundle.PLATFORMS):
        archive = directory / bundle.archive_name(key)
        checksum = install_release.expected_checksum(bundle.read_regular(archive.with_name(archive.name + ".sha256"), 4096), archive.name)
        data = bundle.read_regular(archive, bundle.MAX_ARCHIVE)
        if bundle.digest(data) != checksum:
            raise ValueError("Release upload artifact checksum differs from its bundle")
        install_release.verify_provenance(archive, commit, environment.get("GH_TOKEN", ""))
        bundle.verify_bundle(data, checksum, key, commit)
        archives.append(str(archive))
        checksums.append(f"{checksum}  {archive.name}\n")
    inventory = directory / "SHA256SUMS"
    inventory.write_text("".join(checksums))
    # Existing releases are never overwritten. A draft is populated completely
    # before publication, including when repository release immutability is enabled.
    subprocess.run(["gh", "release", "create", tag, "--repo", install_release.REPOSITORY,
        "--verify-tag", "--draft", "--title", "Redflag " + tag, "--notes-file",
        str(bundle.ROOT / "RELEASE_NOTES.md"), *archives, str(inventory)], check=True)
    subprocess.run(["gh", "release", "edit", tag, "--repo", install_release.REPOSITORY, "--draft=false"], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("validate", "ci-package", "package", "test", "publish"))
    args = parser.parse_args()
    try:
        if args.operation == "validate":
            release_context(os.environ)
        else:
            {"ci-package": ci_package, "package": package, "test": test, "publish": publish}[args.operation](os.environ)
    except (OSError, EOFError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(2, f"Release workflow failed: {error}\n")
