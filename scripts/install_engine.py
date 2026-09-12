#!/usr/bin/env python3
"""Install the reviewed Betterleaks release; never download while scanning."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import tempfile
import urllib.request
import zipfile

MAX_BINARY = 256 * 1024 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def matches_binary(path, expected):
    if not path.is_file() or path.stat().st_size > MAX_BINARY:
        return False
    checksum = hashlib.sha256()
    total = 0
    with path.open('rb') as source:
        while True:
            data = source.read(min(1024 * 1024, MAX_BINARY - total + 1))
            if not data:
                return checksum.hexdigest() == expected
            total += len(data)
            if total > MAX_BINARY:
                return False
            checksum.update(data)


def install(directory, archive_path=None):
    pins = json.loads((Path(__file__).resolve().parents[1] / 'engines/pins.json').read_text())
    system = {'Darwin': 'darwin', 'Linux': 'linux', 'Windows': 'windows'}.get(platform.system())
    arch = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'x64', 'AMD64': 'x64'}.get(platform.machine())
    asset = pins['assets'].get(f'{system}_{arch}')
    if asset is None:
        raise ValueError('No pinned Betterleaks build is available for this OS/architecture')
    name = 'betterleaks.exe' if system == 'windows' else 'betterleaks'
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / name
    if matches_binary(destination, asset['binary_sha256']):
        destination.chmod(0o755)
        return destination
    if archive_path:
        if archive_path.stat().st_size > MAX_ARCHIVE:
            raise ValueError('Betterleaks archive exceeds the 128 MiB size limit')
        with archive_path.open('rb') as source:
            data = source.read(MAX_ARCHIVE + 1)
    else:
        with urllib.request.urlopen(asset['url'], timeout=60) as response:
            data = response.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise ValueError('Betterleaks archive exceeds the 128 MiB size limit')
    if digest(data) != asset['archive_sha256']:
        raise ValueError('Betterleaks archive checksum does not match the reviewed pin')
    # Read only a known member; never extract archive paths onto the filesystem.
    if asset['archive'].endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            with archive.open(name) as member:
                binary = member.read(MAX_BINARY + 1)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            with archive.extractfile(name) as member:
                binary = member.read(MAX_BINARY + 1)
    if len(binary) > MAX_BINARY:
        raise ValueError('Betterleaks binary exceeds the 256 MiB size limit')
    if digest(binary) != asset['binary_sha256']:
        raise ValueError('Betterleaks binary checksum does not match the reviewed pin')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as output:
            temporary = Path(output.name)
            output.write(binary)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o755)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--archive', type=Path, help='Use an already downloaded archive; checksum verification still applies')
    arguments = parser.parse_args()
    try:
        print(install(arguments.directory, arguments.archive).resolve())
    except (OSError, ValueError) as error:
        parser.exit(2, f'Engine installation failed: {error}\n')
