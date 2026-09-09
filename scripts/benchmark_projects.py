#!/usr/bin/env python3
"""Measure frozen public source/build fixtures; repeated samples are not independent releases."""
import argparse
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import build_project_fixtures as builds
import project_fixtures as fixtures


def sample(command, environment, repeats, report_path, expected):
    times = []
    report = None
    # One untimed warmup; every timed run launches a new scanner and engine process.
    for index in range(repeats + 1):
        started = time.perf_counter()
        result = subprocess.run(command, env=environment, capture_output=True, timeout=180)
        report = json.loads(result.stdout) if result.stdout else {}
        elapsed = time.perf_counter() - started
        if builds.PRIVATE_VALUE.encode() in result.stdout or builds.PROVIDER_VALUE.encode() in result.stdout:
            raise ValueError('Scanner report leaked a synthetic protected value')
        report_path.write_text(json.dumps({'exit_code': result.returncode, 'report': report}, indent=2) + '\n')
        if result.returncode != expected:
            raise ValueError(f'Unexpected scanner result {result.returncode}; inspect {report_path}')
        if expected == 0 and report.get('findings_count') != 0:
            raise ValueError('Clean fixture has findings')
        if expected == 1:
            rules = {finding['pattern_name'] for finding in report['findings']}
            if 'private-env:' + builds.PRIVATE_NAME not in rules or not any('github' in rule.lower() for rule in rules):
                raise ValueError('Leak fixture did not detect both the declared private value and provider token')
        if index:
            times.append(elapsed)
    return {'runs_seconds': times, 'timed_samples': len(times), 'median_seconds': statistics.median(times),
            'p95_seconds': sorted(times)[math.ceil(.95 * len(times)) - 1] if len(times) >= 20 else None,
            'max_seconds': max(times), 'exit_code': expected,
            'findings_count': report['findings_count'], 'coverage': report['coverage']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--betterleaks-path', type=Path, required=True)
    parser.add_argument('--snapshots', type=Path, required=True)
    parser.add_argument('--builds', type=Path, required=True, help='Directory containing builds.json and immutable output copies')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=20)
    parser.add_argument('--p95-budget-seconds', type=float)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--bundle-sha256')
    args = parser.parse_args()
    if args.repeats < 20:
        parser.error('Use at least 20 samples for the empirical nearest-rank p95')
    if args.p95_budget_seconds is not None and (not math.isfinite(args.p95_budget_seconds) or args.p95_budget_seconds <= 0):
        parser.error('p95 budget must be positive and finite')
    if bool(args.bundle) != bool(args.bundle_sha256):
        parser.error('bundle and bundle-sha256 must be supplied together')
    binary = args.binary.resolve(); engine = args.betterleaks_path.resolve()
    projects = fixtures.verify(args.snapshots)
    manifest = json.loads((args.builds / 'builds.json').read_text())
    if manifest['fixture_manifest_sha256'] != fixtures.digest(fixtures.MANIFEST.read_bytes()):
        raise ValueError('Builds came from a different frozen fixture inventory')
    expected_ids = {'vite-react-clean', 'vite-react-leak', 'next-static-clean', 'next-static-leak', 'astro-blog-clean'}
    if len(manifest['builds']) != len(expected_ids) or {item['id'] for item in manifest['builds']} != expected_ids:
        raise ValueError('Benchmark requires every clean and synthetic leak build')
    for item in manifest['builds']:
        if builds.inventory(args.builds / item['target']) != item['files']:
            raise ValueError('Publication inputs changed after their build inventory was recorded')
        locks = fixtures.ROOT / 'fixtures/public-projects/build-locks' / item['project']
        if (fixtures.digest((locks / 'package.json').read_bytes()) != item['package_sha256']
                or fixtures.digest((locks / 'package-lock.json').read_bytes()) != item['lock_sha256']):
            raise ValueError('Build recipe or dependency lock differs from the frozen input')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    reports = args.output.with_suffix('.reports'); reports.mkdir(exist_ok=True)
    environment = {key: value for key, value in os.environ.items()
                   if key in ('PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT')}
    environment[builds.PRIVATE_NAME] = builds.PRIVATE_VALUE
    rows = {}
    result = {'schema_version': 1, 'platform': platform.platform(), 'machine': platform.machine(),
        'scanner_version': subprocess.check_output([str(binary), '--version'], text=True).strip(),
        'binary_sha256': fixtures.digest(binary.read_bytes()), 'engine_sha256': fixtures.digest(engine.read_bytes()),
        'fixture_manifest_sha256': fixtures.digest(fixtures.MANIFEST.read_bytes()),
        'build_manifest_sha256': fixtures.digest((args.builds / 'builds.json').read_bytes()),
        'repeats': args.repeats, 'warmup_runs': 1, 'p95_method': 'nearest rank',
        'timing': 'new process, inspection, report capture and JSON parsing; excludes fixture creation and builds',
        'cases': rows, 'production_releases_observed': 0, 'teams_observed': 0}

    def measure(name, command, expected=0, extra=None):
        row = sample(command, dict(environment, **(extra or {})), args.repeats if expected == 0 else 1,
                     reports / (name + '.json'), expected)
        rows[name] = row
        args.output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'case': name, 'median_seconds': row['median_seconds'],
            'p95_seconds': row['p95_seconds'], 'exit_code': expected, 'findings': row['findings_count']}), flush=True)
        return row

    common = ['--no-config', '--engine=betterleaks', '--betterleaks-path=' + str(engine), '--format=json']
    with tempfile.TemporaryDirectory(prefix='redflag-project-benchmark-') as temporary:
        root = Path(temporary)
        git_env = dict(environment, GIT_AUTHOR_NAME='Public Snapshot Fixture', GIT_COMMITTER_NAME='Public Snapshot Fixture',
            GIT_AUTHOR_EMAIL='fixture@example.invalid', GIT_COMMITTER_EMAIL='fixture@example.invalid',
            GIT_AUTHOR_DATE='2000-01-01T00:00:00Z', GIT_COMMITTER_DATE='2000-01-01T00:00:00Z')
        for project in projects:
            checkout = root / project['id']; checkout.mkdir()
            def git(*values):
                return subprocess.check_output(['git', '-C', str(checkout), '-c', 'commit.gpgsign=false', *values],
                                               env=git_env, stderr=subprocess.PIPE).decode().strip()
            git('init', '-q'); git('commit', '--allow-empty', '-qm', 'Empty fixture base')
            base = git('rev-parse', 'HEAD')
            shutil.copytree(args.snapshots / project['id'], checkout, dirs_exist_ok=True)
            git('add', '--force', '--all'); git('commit', '-qm', 'Import pinned public example')
            row = measure('source-' + project['id'], [str(binary), 'changes', str(checkout),
                '--base=' + base, '--head=' + git('rev-parse', 'HEAD'), *common])
            coverage = row['coverage']
            if (coverage['skipped'] or {file['path'] for file in coverage['files']} != {file['path'] for file in project['files']}
                    or coverage['inspected_bytes'] != sum(file['bytes'] for file in project['files'])):
                raise ValueError('Source selection did not inspect the complete imported snapshot')
        for item in manifest['builds']:
            target = (args.builds / item['target']).resolve()
            clean = item['variant'] == 'clean'
            approval = root / (item['id'] + '-approval.json')
            row = measure('artifact-' + item['id'], [str(binary), 'artifacts', str(target), *common,
                '--private-env=' + builds.PRIVATE_NAME, '--manifest=' + str(approval)], expected=0 if clean else 1)
            if (len(row['coverage']['files']) != len(item['files'])
                    or row['coverage']['total_bytes'] != sum(file['bytes'] for file in item['files'])):
                raise ValueError('Artifact coverage differs from the recorded publication inventory')
            if clean:
                subprocess.run([str(binary), 'verify-artifacts', str(approval), '--format=json'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=30)
                rows['artifact-' + item['id']]['manifest_verified'] = True
            if clean and args.bundle and item['project'] in ('vite-react', 'next-static'):
                measure('action-' + item['id'], [sys.executable, '-E', '-s', str(fixtures.ROOT / 'scripts/run_action.py')],
                    extra={'REDFLAG_INPUT_MODE': 'artifacts', 'REDFLAG_INPUT_PATHS': str(target),
                        'REDFLAG_INPUT_NO_CONFIG': 'true', 'REDFLAG_INPUT_FORMAT': 'json',
                        'REDFLAG_INPUT_PRIVATE_ENV': builds.PRIVATE_NAME, 'REDFLAG_INPUT_MANIFEST': str(approval),
                        'REDFLAG_INPUT_BUNDLE': str(args.bundle.resolve()), 'REDFLAG_INPUT_BUNDLE_SHA256': args.bundle_sha256})
        # Scans and manifest checks must preserve exactly the measured publication bytes.
        for item in manifest['builds']:
            if builds.inventory(args.builds / item['target']) != item['files']:
                raise ValueError('Measured build outputs changed during validation')
    result['compatibility'] = {'reviewed_public_source_snapshots': len(projects), 'clean_build_outputs': 3,
        'flagged_source_snapshots': 0, 'flagged_clean_build_outputs': 0, 'synthetic_leak_builds_blocked': 2}
    if args.bundle:
        result['action_bundle_sha256'] = args.bundle_sha256
        result['action_timing_scope'] = 'local trusted bundle installation plus scan; no download or attestation network latency'
    if args.p95_budget_seconds:
        result['p95_budget_seconds'] = args.p95_budget_seconds
        result['budget_passed'] = all(row['p95_seconds'] <= args.p95_budget_seconds for row in rows.values() if row['exit_code'] == 0)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    if result.get('budget_passed') is False:
        raise SystemExit('Empirical p95 exceeded the explicitly selected local budget')


if __name__ == '__main__':
    main()
