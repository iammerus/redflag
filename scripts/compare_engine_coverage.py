#!/usr/bin/env python3
"""Frozen synthetic holdout for engine choice; never validates or issues credentials."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import statistics
import string
import subprocess
import time


def fixtures():
    randomizer = random.Random(20260911)
    def word(length, alphabet=string.ascii_letters + string.digits):
        return ''.join(randomizer.choice(alphabet) for _ in range(length))
    shapes = {
        'github': lambda: 'ghp_' + word(36),
        'gitlab': lambda: 'glpat-' + word(20),
        'slack': lambda: 'xoxb-' + word(12, string.digits) + '-' + word(12, string.digits) + '-' + word(24),
        'sendgrid': lambda: 'SG.' + word(22) + '.' + word(43),
        'shopify': lambda: 'shpat_' + word(32, '0123456789abcdef'),
        'digitalocean': lambda: 'dop_v1_' + word(64, '0123456789abcdef'),
        'google_api': lambda: 'AIza' + word(35),
        'stripe': lambda: 'sk_live_' + word(24),
        'npm': lambda: 'npm_' + word(36),
    }
    cases = []
    for family, generate in shapes.items():
        for context in ['literal', 'unnamed', 'html']:
            value = generate()
            text = {'literal': f'const credential = "{value}";', 'unnamed': value, 'html': f'<span data-value="{value}">test</span>'}[context]
            cases.append((f'positive/{family}-{context}.txt', True, text))
    benign = {
        'source-reference': 'const apiKey = config.apiKey; const password = requirePassword();',
        'environment': 'API_KEY=${API_KEY}\nPASSWORD=$PASSWORD',
        'public-stripe': 'const value = "pk_live_' + word(24) + '";',
        'asset-name': 'const asset = "image-' + word(48) + '.avif";',
        'base64-public-id': 'const publicId = "' + word(48) + '";',
        'hex-content-id': 'const contentId = "' + word(64, '0123456789abcdef') + '";',
        'uuid': 'const id = "85bfcf94-6d54-4dfd-8cd8-f4de85e3c3b1";',
        'checksum': 'sha256 = "' + word(64, '0123456789abcdef') + '"',
        'integrity': 'integrity="sha384-' + word(64) + '"',
        'request-headers': 'headers: { Authorization: `Bearer ${session.accessToken}` }',
        'password-function': 'const password = passwordFromVault(context);',
        'password-argument': 'setCredentials({password: password, username});',
        'secret-boolean': 'const secret = true;',
        'secret-null': 'const secret = null;',
        'pipeline-reference': 'env: { API_TOKEN: "${{ secrets.BUILD_TOKEN }}" }',
        'template-reference': 'password = "{{ lookup_password(service) }}"',
        'json-schema': '{"password":{"type":"string","minLength":12}}',
        'build-placeholder': 'window.PUBLIC_KEY = "replace-with-your-public-key";',
    }
    cases.extend((f'benign/{name}.txt', False, value) for name, value in benign.items())
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--generate-only', action='store_true')
    parser.add_argument('--betterleaks-path', type=Path)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    corpus = root/'corpus'
    cases = fixtures()
    manifest = []
    for name, positive, value in cases:
        path = corpus/name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = value.encode()
        path.write_bytes(data)
        manifest.append({'file': name, 'positive': positive, 'sha256': hashlib.sha256(data).hexdigest()})
    serialized = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    (root/'manifest.json').write_bytes(serialized)
    manifest_sha = hashlib.sha256(serialized).hexdigest()
    print(f'Frozen cases: {len(cases)}; manifest SHA-256: {manifest_sha}', flush=True)
    if args.generate_only:
        return
    if not args.binary:
        parser.error('--binary is required for comparison')
    results = {'manifest_sha256': manifest_sha, 'cases':len(cases), 'engines':{}}
    for engine in ['native', 'betterleaks']:
        durations = []
        reports = []
        for _ in range(3):
            command = [str(args.binary.resolve()), 'artifacts', str(corpus), '--engine', engine, '--no-config', '--format','json']
            if engine == 'betterleaks' and args.betterleaks_path:
                command += ['--betterleaks-path', str(args.betterleaks_path.resolve())]
            started = time.perf_counter()
            result = subprocess.run(command, capture_output=True)
            durations.append(time.perf_counter() - started)
            if result.returncode not in (0, 1):
                raise RuntimeError(result.stderr.decode())
            report = json.loads(result.stdout)
            assert report['complete'] and len(report['coverage']['files']) == len(cases)
            found = {}
            for finding in report['findings']:
                name = Path(finding['file']).relative_to(corpus).as_posix()
                found.setdefault(name, set()).add(finding['pattern_name'])
                assert finding['snippet'] == '[REDACTED]'
            reports.append({name: sorted(rules) for name, rules in sorted(found.items())})
        assert reports[0] == reports[1] == reports[2]
        detected = sum(positive and name in reports[0] for name, positive, _ in cases)
        false_blocks = sum(not positive and name in reports[0] for name, positive, _ in cases)
        results['engines'][engine] = {'positive_files':sum(p for _, p, _ in cases), 'detected_files':detected,
            'benign_files':sum(not p for _, p, _ in cases), 'false_blocks':false_blocks,
            'median_seconds':round(statistics.median(durations),4), 'findings':reports[0]}
    (root/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))


if __name__ == '__main__':
    main()
