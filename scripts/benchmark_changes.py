"""Offline scaling checks for source occurrence comparison against parent snapshots."""
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
    parser.add_argument("--betterleaks-path", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    binary = str(args.binary.resolve())
    engine = str(args.betterleaks_path.resolve())
    token = "ghp_" + "aB3dE6gH9jK2mN5pQ8" + "sT1vW4xY7zA0cD3fG6"
    rows = {}
    env = dict(os.environ, GIT_AUTHOR_NAME="Offline Fixture", GIT_COMMITTER_NAME="Offline Fixture",
               GIT_AUTHOR_EMAIL="fixture@example.invalid", GIT_COMMITTER_EMAIL="fixture@example.invalid")
    with tempfile.TemporaryDirectory(prefix="redflag-change-benchmark-") as temporary:
        for count in (2000, 4000, 8000):
            root = Path(temporary) / str(count)
            root.mkdir()

            def git(*arguments):
                return subprocess.run(["git", "-C", str(root), *arguments], env=env, check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()

            git("init", "-q")
            file = root / "bundle.js"
            tokens = ",".join([json.dumps(token)] * count)
            file.write_text(f"const values=[{tokens}]; const publicFlag=1;\n")
            git("add", "bundle.js")
            git("commit", "-qm", "Existing synthetic debt")
            base = git("rev-parse", "HEAD")
            file.write_text(f"const values=[{tokens}]; const publicFlag=2;\n")
            git("add", "bundle.js")
            git("commit", "-qm", "Unrelated change on the same line")
            head = git("rev-parse", "HEAD")
            for choice in ("native", "betterleaks"):
                detector = ["--engine", choice]
                if choice == "betterleaks":
                    detector += ["--betterleaks-path", engine]
                elapsed = []
                for _ in range(args.repeats):
                    start = time.perf_counter()
                    result = subprocess.run([binary, "changes", str(root), "--base", base, "--head", head,
                                             "--format", "json", *detector], capture_output=True, timeout=90)
                    report = json.loads(result.stdout) if result.stdout else {}
                    assert result.returncode == 0, result.stderr.decode(errors="replace")
                    assert report["findings_count"] == 0
                    assert report["coverage"]["occurrence_comparison"]["existing_parent_occurrences"] == count
                    assert token.encode() not in result.stdout
                    elapsed.append(time.perf_counter() - start)
                key = f"{choice}_{count}"
                rows[key] = {"median_seconds": statistics.median(elapsed), "runs_seconds": elapsed,
                             "snapshot_bytes": file.stat().st_size,
                             "finding_spool_bytes": report["coverage"]["occurrence_comparison"]["finding_spool_bytes"]}
                print(json.dumps({"case": key, **rows[key]}), flush=True)
            # Reusing an old value in one additional slot must still fail.
            file.write_text(f"const values=[{tokens},{json.dumps(token)}]; const publicFlag=2;\n")
            git("add", "bundle.js")
            git("commit", "-qm", "New occurrence of existing value")
            for choice in ("native", "betterleaks"):
                detector = ["--engine", choice]
                if choice == "betterleaks":
                    detector += ["--betterleaks-path", engine]
                result = subprocess.run([binary, "changes", str(root), "--base", head, "--head", "HEAD",
                                         "--format", "json", *detector], capture_output=True, timeout=90)
                assert result.returncode == 1, result.stderr.decode(errors="replace")
                assert json.loads(result.stdout)["findings_count"] == 1
                assert token.encode() not in result.stdout
    budgets = {f"{choice}_doubling_below_3x": rows[f"{choice}_8000"]["median_seconds"]
               < 3 * max(0.1, rows[f"{choice}_4000"]["median_seconds"])
               for choice in ("native", "betterleaks")}
    result = {"platform": platform.platform(), "machine": platform.machine(),
              "repeats": args.repeats, "cases": rows, "budgets": budgets}
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"budgets": budgets}), flush=True)
    if args.check and not all(budgets.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
