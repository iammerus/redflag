#!/usr/bin/env python3
"""Select an explicit scan scope, install verified binaries, and preserve exit codes."""
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import install_release
import release_bundle


def boolean(values, name):
    value = values.get(name, "false").strip()
    if value not in ("", "true", "false"):
        raise ValueError(f"{name} must be true or false")
    return value == "true"


def lines(value):
    return [line for line in value.splitlines() if line.strip()]


def arguments(values, environment):
    mode = values.get("mode", "scan") or "scan"
    allowed_modes = {"scan", "changes", "artifacts", "verify-artifacts"}
    if mode not in allowed_modes:
        raise ValueError("mode must be scan, changes, artifacts or verify-artifacts")
    path = values.get("path", ".") or "."
    history = boolean(values, "git-history")
    no_config = boolean(values, "no-config")
    new_branch = boolean(values, "new-branch")
    config = values.get("config", "")
    if config and no_config:
        raise ValueError("config and no-config cannot be combined")
    modern = mode in ("changes", "artifacts")
    formats = {"text", "json", "github"} if modern else {"text", "json"}
    if mode == "scan":
        formats.add("json-report")
    report = values.get("format") or ("github" if modern else "text")
    if report not in formats:
        raise ValueError("format is not supported by the selected mode")
    scoped = {
        "git-history": {"scan"}, "paths": {"artifacts", "verify-artifacts"},
        "private-env": {"artifacts"}, "allow-short-private-value": {"artifacts"},
        "manifest": {"artifacts", "verify-artifacts"}, "engine": {"changes", "artifacts"},
        "exceptions": {"changes", "artifacts"}, "github-summary": {"changes", "artifacts"},
        "config": {"scan", "changes", "artifacts"}, "no-config": {"scan", "changes", "artifacts"},
        "base": {"changes"}, "head": {"changes"}, "new-branch": {"changes"},
        "merge-result": {"changes"}, "policy-ref": {"changes"}, "max-commits": {"changes"},
    }
    booleans = {"git-history": history, "no-config": no_config, "new-branch": new_branch}
    for name, modes in scoped.items():
        if (booleans[name] if name in booleans else values.get(name, "")) and mode not in modes:
            raise ValueError(f"{name} does not apply to {mode}")
    if mode in ("artifacts", "verify-artifacts") and path != ".":
        raise ValueError("Use paths for publication inputs; path selects a source checkout")
    args = [mode, "--format=" + report]
    for name in ("config", "exceptions", "github-summary"):
        if values.get(name):
            args.append(f"--{name}={values[name]}")
    if no_config:
        args.append("--no-config")
    if modern:
        engine = values.get("engine") or "betterleaks"
        if engine not in ("betterleaks", "native"):
            raise ValueError("engine must be betterleaks or native")
        args.append("--engine=" + engine)
    if mode == "scan":
        args.append("--no-progress")
        if history:
            args.append("--git-history")
        return args + ["--", path]
    if mode == "changes":
        base = values.get("base", "")
        if base and new_branch:
            raise ValueError("base and new-branch cannot be combined")
        if values.get("policy-ref") and (config or no_config):
            raise ValueError("policy-ref cannot be combined with config or no-config")
        if values.get("merge-result") and not base:
            raise ValueError("merge-result requires base")
        if base or new_branch:
            args.append("--base=" + base if base else "--new-branch")
            if values.get("head"):
                args.append("--head=" + values["head"])
            if values.get("merge-result"):
                args.append("--merge-result=" + values["merge-result"])
        else:
            if values.get("head"):
                raise ValueError("head requires base or new-branch; otherwise scope comes from the GitHub event")
            event = environment.get("GITHUB_EVENT_PATH", "")
            if not event:
                raise ValueError("changes requires a GitHub event file or an explicit base/new-branch scope")
            args.append("--github-event=" + event)
        if values.get("policy-ref"):
            args.append("--policy-ref=" + values["policy-ref"])
        if values.get("max-commits"):
            maximum = values["max-commits"]
            if not maximum.isascii() or not maximum.isdecimal() or int(maximum) < 1:
                raise ValueError("max-commits must be a positive integer")
            args.append("--max-commits=" + maximum)
        return args + ["--", path]
    paths = lines(values.get("paths", ""))
    manifest = values.get("manifest", "")
    if mode == "verify-artifacts":
        if not manifest:
            raise ValueError("verify-artifacts requires manifest")
        args.extend("--target=" + target for target in paths)
        return args + ["--", manifest]
    if not paths:
        raise ValueError("artifacts requires paths naming the exact publication inputs, one per line")
    if manifest:
        args.append("--manifest=" + manifest)
    for name in ("private-env", "allow-short-private-value"):
        args.extend(f"--{name}={value}" for value in lines(values.get(name, "")))
    return args + ["--", *paths]


INPUTS = ("mode", "path", "paths", "config", "no-config", "git-history", "format", "engine",
          "base", "head", "new-branch", "merge-result", "policy-ref", "max-commits", "exceptions",
          "private-env", "allow-short-private-value", "manifest", "github-summary", "bundle", "bundle-sha256")


def run(environment):
    values = {name: environment.get("REDFLAG_INPUT_" + name.upper().replace("-", "_"), "") for name in INPUTS}
    command = arguments(values, environment)
    archive = values["bundle"]
    checksum = values["bundle-sha256"]
    if bool(archive) != bool(checksum):
        raise ValueError("bundle and bundle-sha256 must be supplied together")
    with tempfile.TemporaryDirectory(prefix="redflag-action-", dir=environment.get("RUNNER_TEMP") or None) as temporary:
        directory = Path(temporary) / "installation"
        if archive:
            binary = release_bundle.install_bundle(Path(archive), directory, checksum)
        else:
            token = environment.get("REDFLAG_DOWNLOAD_TOKEN", "")
            if environment.get("GITHUB_SERVER_URL", "https://github.com") != "https://github.com":
                token = ""
            binary = install_release.install(directory, environment.get("REDFLAG_ACTION_REF", ""),
                                             token)
        child_environment = dict(environment)
        child_environment.pop("REDFLAG_DOWNLOAD_TOKEN", None)
        return subprocess.call([str(binary), *command], env=child_environment)


if __name__ == "__main__":
    try:
        code = run(os.environ)
        sys.exit(code if code in (0, 1, 2) else 2)
    except (OSError, EOFError, ValueError, TypeError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"Redflag Action failed: {error}", file=sys.stderr)
        sys.exit(2)
