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


def digest(data):
    return hashlib.sha256(data).hexdigest()


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
    if destination.is_file() and digest(destination.read_bytes()) == asset['binary_sha256']:
        return destination
    if archive_path:
        data = archive_path.read_bytes()
    else:
        with urllib.request.urlopen(asset['url'], timeout=60) as response:
            data = response.read(128 * 1024 * 1024 + 1)
    if digest(data) != asset['archive_sha256']:
        raise ValueError('Betterleaks archive checksum does not match the reviewed pin')
    # Read only a known member; never extract archive paths onto the filesystem.
    if asset['archive'].endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            binary = archive.read(name)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            binary = archive.extractfile(name).read()
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
