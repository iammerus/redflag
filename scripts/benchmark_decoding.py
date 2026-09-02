"""Offline private-value decoding and report scaling probes for a release binary."""
import argparse
import base64
import hashlib
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
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    binary = str(args.binary.resolve())
    value = "opaque-Pvt!42"
    env = dict(os.environ, RF_DECODE_BENCHMARK=value)
    cases = {}
    with tempfile.TemporaryDirectory(prefix="redflag-decoding-benchmark-") as temporary:
        root = Path(temporary)
        path = root / "input.bin"
        policy = root / "policy.toml"
        policy.write_text("[entropy]\nenabled=false\nthreshold=4.5\nmin_length=20\n")

        def measure(name, payload, expected, enabled=True):
            path.write_bytes(payload)
            elapsed = []
            coverage = None
            for _ in range(args.repeats):
                command = [binary, "artifacts", str(path), "--engine", "native",
                           "--config", str(policy), "--format", "json"]
                if enabled:
                    command += ["--private-env", "RF_DECODE_BENCHMARK"]
                start = time.perf_counter()
                output = subprocess.run(command, env=env, capture_output=True, timeout=60)
                elapsed.append(time.perf_counter() - start)
                assert output.returncode == int(expected > 0), output.stderr.decode(errors="replace")
                report = json.loads(output.stdout)
                assert report["findings_count"] == expected, (name, report["findings_count"])
                assert report["occurrences_count"] == expected
                assert report["logical_findings_count"] == int(expected > 0)
                assert value.encode() not in output.stdout
                assert b'"grouping_key"' not in output.stdout
                current = report["coverage"]["private_decoding"]
                assert coverage is None or coverage == current
                coverage = current
            cases[name] = {"input_bytes": len(payload), "output_bytes": len(output.stdout),
                           "median_seconds": statistics.median(elapsed), "runs_seconds": elapsed,
                           "decoding": coverage}
            print(json.dumps({"case": name, **cases[name]}), flush=True)

        # One long candidate exercises compact mapping and dense overlapping
        # location lookups; coencoding ensures independent-value encoding fails.
        for count in (4000, 8000, 16000):
            payload = base64.b64encode((f"user:{value}:suffix\n" * count).encode())
            measure(f"base64_{count}", payload, count)
            escaped = '"' + ''.join(f"\\u{ord(char):04x}" for char in value) + '"\n'
            measure(f"json_{count}", (escaped * count).encode(), count)
        clean_line = b"ordinary public output.\n"
        clean = (clean_line * (32 * 1048576 // len(clean_line) + 1))[:32 * 1048576]
        measure("clean_32MiB_disabled", clean, 0, enabled=False)
        measure("clean_32MiB_enabled", clean, 0)

    budgets = {f"{kind}_doubling_below_3x": cases[f"{kind}_16000"]["median_seconds"]
               < 3 * max(0.1, cases[f"{kind}_8000"]["median_seconds"])
               for kind in ("base64", "json")}
    result = {"platform": platform.platform(), "machine": platform.machine(),
              "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              "repeats": args.repeats, "cases": cases, "budgets": budgets}
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"budgets": budgets}), flush=True)
    if args.check and not all(budgets.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
