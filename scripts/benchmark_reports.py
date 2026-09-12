"""Offline scaling checks for grouped artifact reports, including JSON delivery."""
import argparse
import hashlib
import json
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
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    binary = str(args.binary.resolve())
    token = "ghp_" + "aB3dE6gH9jK2mN5pQ8" + "sT1vW4xY7zA0cD3fG6"
    rows = {}
    with tempfile.TemporaryDirectory(prefix="redflag-report-benchmark-") as temporary:
        path = Path(temporary) / "bundle.js"
        for count, unique in [(16000, False), (32000, False), (64000, False), (16000, True)]:
            values = [("ghp_" + hashlib.sha256(str(i).encode()).hexdigest()[:36])
                      if unique else token for i in range(count)]
            path.write_text("[" + ",".join(json.dumps(v) for v in values) + "];\n")
            elapsed = []
            ids = None
            for _ in range(args.repeats):
                start = time.perf_counter()
                result = subprocess.run([binary, "artifacts", str(path), "--engine", "native",
                                         "--no-config", "--format", "json"],
                                        capture_output=True, timeout=60)
                elapsed.append(time.perf_counter() - start)
                assert result.returncode == 1, result.stderr.decode(errors="replace")
                report = json.loads(result.stdout)
                assert report["schema_version"] == 3
                assert report["findings_count"] == count
                assert report["occurrences_count"] == count
                assert report["logical_findings_count"] == (count if unique else 1)
                assert token.encode() not in result.stdout
                assert b'"grouping_key"' not in result.stdout
                current_ids = [g["id"] for g in report["logical_findings"]]
                assert ids is None or ids == current_ids
                ids = current_ids
            name = f"{'distinct' if unique else 'repeated'}_{count}"
            rows[name] = {"median_seconds": statistics.median(elapsed), "runs_seconds": elapsed,
                          "input_bytes": path.stat().st_size, "output_bytes": len(result.stdout)}
            print(json.dumps({"case": name, **rows[name]}), flush=True)
    budgets = {"repeated_doubling_below_3x": rows["repeated_64000"]["median_seconds"]
               < 3 * max(0.1, rows["repeated_32000"]["median_seconds"])}
    result = {"platform": platform.platform(), "machine": platform.machine(),
              "repeats": args.repeats, "cases": rows, "budgets": budgets}
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"budgets": budgets}), flush=True)
    if args.check and not all(budgets.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
