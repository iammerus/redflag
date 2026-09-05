"""Reproducible bounded-archive scaling checks, using synthetic public bytes."""
import argparse
import gzip
import io
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    cases = {}
    with tempfile.TemporaryDirectory(prefix="redflag-archive-benchmark-") as temporary:
        root = Path(temporary)
        path = root / "input.bin"
        config = root / "policy.toml"
        config.write_text("[entropy]\nenabled=false\nthreshold=4.5\nmin_length=20\n")

        def measure(name, payload, members, expanded):
            path.write_bytes(payload)
            elapsed = []
            for _ in range(args.repeats):
                start = time.perf_counter()
                output = subprocess.run([str(args.binary.resolve()), "artifacts", str(path),
                    "--engine", "native", "--config", str(config), "--format", "json",
                    "--private-env", "RF_ARCHIVE_BENCHMARK"], capture_output=True, timeout=60,
                    env=dict(os.environ, RF_ARCHIVE_BENCHMARK="opaque-Pvt!42"))
                elapsed.append(time.perf_counter() - start)
                assert output.returncode == 0, output.stderr.decode(errors="replace")
                result = json.loads(output.stdout)
                assert result["findings_count"] == 0
                coverage = result["coverage"]["archive_inspection"]
                assert coverage["members"] == members, coverage
                assert coverage["expanded_bytes"] == expanded, coverage
            cases[name] = {"input_bytes": len(payload), "expanded_bytes": expanded,
                           "members": members, "median_seconds": statistics.median(elapsed),
                           "runs_seconds": elapsed}
            print(json.dumps({"case": name, **cases[name]}), flush=True)

        line = b"ordinary public output.\n"
        for mib in (8, 16, 32):
            content = (line * (mib * 1048576 // len(line) + 1))[:mib * 1048576]
            measure(f"gzip_{mib}MiB", gzip.compress(content, mtime=0), 1, len(content))
        for count in (2000, 4000):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for index in range(count):
                    archive.writestr(f"dist/{index}.txt", line)
            measure(f"zip_{count}_members", buffer.getvalue(), count, count * len(line))
    budgets = {
        "gzip_doubling_below_3x": cases["gzip_32MiB"]["median_seconds"]
            < 3 * max(0.1, cases["gzip_16MiB"]["median_seconds"]),
        "zip_members_doubling_below_3x": cases["zip_4000_members"]["median_seconds"]
            < 3 * max(0.1, cases["zip_2000_members"]["median_seconds"]),
    }
    result = {"platform": platform.platform(), "machine": platform.machine(),
              "repeats": args.repeats, "cases": cases, "budgets": budgets}
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"budgets": budgets}), flush=True)
    if args.check and not all(budgets.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
