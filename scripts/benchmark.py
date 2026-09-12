"""Offline scanner performance probes; run against a release binary.

Reports medians, validates finding counts/redaction, and optionally enforces a
scaling budget. No provider-issued credentials or external repositories are used.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    if args.repeats < 1:
        parser.error("--repeats must be at least 1")
    token = "ghp_" + "aB3dE6gH9jK2mN5p" + "Q8sT1vW4xY7zA0cD3fG6"
    rows = {}
    with tempfile.TemporaryDirectory(prefix="redflag-benchmark-") as temporary:
        root = Path(temporary)

        def measure(name, path, expected, extra=()):
            elapsed = []
            for _ in range(args.repeats):
                start = time.perf_counter()
                result = subprocess.run(
                    [binary, "scan", str(path), "--no-progress", "--format", "json", *extra],
                    capture_output=True, timeout=60,
                )
                findings = json.loads(result.stdout)
                assert result.returncode == int(expected > 0), result.stderr.decode(errors="replace")
                assert len(findings) == expected, (name, len(findings), expected)
                assert token.encode() not in result.stdout, "unredacted fixture"
                elapsed.append(time.perf_counter() - start)
            rows[name] = {"median_seconds": statistics.median(elapsed), "runs_seconds": elapsed}
            print(json.dumps({"case": name, **rows[name]}), flush=True)

        clean = root / "clean.js"
        line = "export function sum(a,b){return a+b;}\n"
        clean.write_text((line * (32 * 1048576 // len(line) + 1))[:32 * 1048576])
        measure("clean_32MiB", clean, 0)
        many = root / "many"
        many.mkdir()
        for number in range(2000):
            (many / f"source-{number}.js").write_text(line)
        measure("2000_clean_files", many, 0)
        for count in (32000, 64000, 128000):
            path = root / f"minified-{count}.js"
            path.write_text("[" + ",".join([f'"{token}"'] * count) + "];\n")
            measure(f"minified_{count}", path, count)
        multiline = root / "multiline.js"
        multiline.write_text("[" + ",\n".join([f'"{token}"'] * 128000) + "];\n")
        measure("multiline_128000", multiline, 128000)

        history = root / "history"
        history.mkdir()
        env = dict(os.environ, GIT_AUTHOR_NAME="Offline Fixture", GIT_COMMITTER_NAME="Offline Fixture",
                   GIT_AUTHOR_EMAIL="fixture@example.invalid", GIT_COMMITTER_EMAIL="fixture@example.invalid")

        def git(*command):
            subprocess.run(["git", "-C", str(history), *command], env=env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        git("init", "-q")
        (history / "vendor").mkdir()
        ignored = history / "vendor" / "bundle.js"
        ignored.write_bytes((root / "minified-128000.js").read_bytes())
        git("add", "-A")
        git("commit", "-qm", "Add synthetic fixture")
        ignored.unlink()
        git("add", "-A")
        git("commit", "-qm", "Remove fixture")
        measure("ignored_history_128000", history, 0, ("--git-history",))

    # Ratios detect the measured quadratic regression without assuming a fixed
    # CPU speed. The floor keeps very fast process launches from amplifying noise.
    budgets = {
        "doubling_64k_to_128k_below_3x": rows["minified_128000"]["median_seconds"]
            < 3 * max(rows["minified_64000"]["median_seconds"], 0.1),
        "minified_below_3x_multiline": rows["minified_128000"]["median_seconds"]
            < 3 * max(rows["multiline_128000"]["median_seconds"], 0.1),
        "ignored_history_below_quarter_of_scan": rows["ignored_history_128000"]["median_seconds"]
            < max(rows["minified_128000"]["median_seconds"] / 4, 0.1),
    }
    report = {"platform": platform.platform(), "processor": platform.processor(),
              "binary": binary, "repeats": args.repeats, "cases": rows, "budgets": budgets}
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    if args.check and not all(budgets.values()):
        raise SystemExit("Performance budget failed: " + str(budgets))


if __name__ == "__main__":
    main()
