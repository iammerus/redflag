#!/usr/bin/env python3
"""Fetch or verify frozen public examples without executing their source code."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'fixtures/public-projects/manifest.json'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def projects():
    return json.loads(MANIFEST.read_text())['projects']


def verify(directory):
    for project in projects():
        root = directory / project['id']
        expected = {file['path']: file for file in project['files']}
        actual = set()
        for path in root.rglob('*'):
            if path.is_symlink():
                raise ValueError('Fixture snapshots must not contain symlinks')
            if path.is_file():
                relative = path.relative_to(root).as_posix()
                if relative not in expected:
                    raise ValueError('Fixture snapshot contains unexpected files')
                record = expected[relative]
                with path.open('rb') as source:
                    data = source.read(record['bytes'] + 1)
                if len(data) != record['bytes'] or digest(data) != record['sha256']:
                    raise ValueError('Fixture bytes differ from the frozen upstream snapshot')
                actual.add(relative)
            elif not path.is_dir():
                raise ValueError('Fixture snapshot contains a special file')
        if actual != set(expected):
            raise ValueError('Fixture snapshot is incomplete')
    return projects()


def fetch(directory):
    if directory.exists() or directory.is_symlink():
        raise ValueError('Fetch requires a new destination; use verify for existing snapshots')
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='redflag-fixtures-', dir=directory.parent) as temporary:
        staging = Path(temporary) / 'snapshots'; staging.mkdir()
        for project in projects():
            for record in project['files']:
                url = (f"https://raw.githubusercontent.com/{project['repository']}/"
                       f"{project['source_commit']}/{record['upstream_path']}")
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = response.read(record['bytes'] + 1)
                blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                if (len(data) != record['bytes'] or digest(data) != record['sha256']
                        or blob != record['git_blob']):
                    raise ValueError('Downloaded bytes differ from the pinned Git blob and SHA-256')
                target = staging / project['id'] / record['path']
                target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        verify(staging)
        shutil.move(str(staging), directory)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('fetch', 'verify'))
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    try:
        {'fetch': fetch, 'verify': verify}[args.operation](args.directory)
        print(json.dumps({'projects': len(projects()), 'manifest_sha256': digest(MANIFEST.read_bytes())}))
    except (OSError, ValueError) as error:
        parser.exit(2, f'Fixture preparation failed: {error}\n')
