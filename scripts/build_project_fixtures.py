#!/usr/bin/env python3
"""Build reviewed public examples and synthetic leak variants in a new directory."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import project_fixtures as fixtures

PRIVATE_NAME = 'REDFLAG_PILOT_PRIVATE'
PRIVATE_VALUE = 'opaque-Sunflower!42'
PROVIDER_VALUE = 'ghp_' + 'aB3dE6gH9jK2mN5pQ8' + 'sT1vW4xY7zA0cD3fG6'
OUTPUTS = {'vite-react': 'dist', 'next-static': 'out', 'astro-blog': 'dist'}


def inventory(directory):
    files = []
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ValueError('Build outputs contain unsupported filesystem entries')
        if path.is_file():
            data = path.read_bytes()
            files.append({'path': path.relative_to(directory).as_posix(), 'bytes': len(data),
                          'sha256': fixtures.digest(data)})
    if not files:
        raise ValueError('Build output is empty')
    return files


def environment(root):
    allowed = ('PATH', 'TMPDIR', 'TMP', 'TEMP', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT')
    result = {key: os.environ[key] for key in allowed if key in os.environ}
    home = root / 'build-home'; home.mkdir()
    for name in ('user-npmrc', 'global-npmrc'):
        (root / name).write_text('')
    result.update(HOME=str(home), USERPROFILE=str(home),
        NPM_CONFIG_USERCONFIG=str(root / 'user-npmrc'), NPM_CONFIG_GLOBALCONFIG=str(root / 'global-npmrc'),
        NEXT_TELEMETRY_DISABLED='1', ASTRO_TELEMETRY_DISABLED='1', CI='1',
        VITE_REDFLAG_PROVIDER=PROVIDER_VALUE, VITE_REDFLAG_PRIVATE=PRIVATE_VALUE,
        NEXT_PUBLIC_REDFLAG_PROVIDER=PROVIDER_VALUE, NEXT_PUBLIC_REDFLAG_PRIVATE=PRIVATE_VALUE)
    return result


def build(snapshots, directory):
    projects = fixtures.verify(snapshots)
    if directory.exists() or directory.is_symlink():
        raise ValueError('Build preparation requires a new destination')
    directory.mkdir(parents=True)
    env = environment(directory)
    records = []
    for project in projects:
        name = project['id']
        source = directory / 'work' / name
        shutil.copytree(snapshots / name, source)
        locks = fixtures.ROOT / 'fixtures/public-projects/build-locks' / name
        for file in ('package.json', 'package-lock.json'):
            shutil.copyfile(locks / file, source / file)
        with (directory / (name + '-install.log')).open('wb') as log:
            subprocess.run(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
                           cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=600)
        for variant in ('clean', 'leak') if name in ('vite-react', 'next-static') else ('clean',):
            if variant == 'leak':
                if name == 'vite-react':
                    with (source / 'src/main.jsx').open('a') as script:
                        script.write('\ndocument.body.dataset.redflagProvider = import.meta.env.VITE_REDFLAG_PROVIDER;\n'
                                     'document.body.dataset.redflagPrivate = import.meta.env.VITE_REDFLAG_PRIVATE;\n')
                else:
                    route = source / 'app/redflag-canary/page.tsx'; route.parent.mkdir()
                    route.write_text('"use client";\nexport default function Canary() { return <p '
                        'data-provider={process.env.NEXT_PUBLIC_REDFLAG_PROVIDER}>'
                        '{process.env.NEXT_PUBLIC_REDFLAG_PRIVATE}</p>; }\n')
            # Framework caches are allowed; timing here is recorded separately from scanner overhead.
            output = source / OUTPUTS[name]
            if output.exists():
                shutil.rmtree(output)
            start = time.perf_counter()
            with (directory / (name + '-' + variant + '-build.log')).open('wb') as log:
                subprocess.run(['npm', 'run', 'build'], cwd=source, env=env, stdout=log,
                               stderr=subprocess.STDOUT, check=True, timeout=600)
            elapsed = time.perf_counter() - start
            original_files = inventory(output)
            destination = directory / 'outputs' / (name + '-' + variant)
            shutil.copytree(output, destination)
            files = inventory(destination)
            if files != original_files:
                raise ValueError('Publication copy differs from the framework output')
            contains = {value: any(value.encode() in (destination / file['path']).read_bytes() for file in files)
                        for value in (PRIVATE_VALUE, PROVIDER_VALUE)}
            if any(present != (variant == 'leak') for present in contains.values()):
                raise ValueError('Compiled fixture does not have its declared clean/leak content')
            record = {'id': name + '-' + variant, 'project': name, 'variant': variant,
                'source_commit': project['source_commit'], 'target': destination.relative_to(directory).as_posix(),
                'package_sha256': fixtures.digest((locks / 'package.json').read_bytes()),
                'lock_sha256': fixtures.digest((locks / 'package-lock.json').read_bytes()),
                'build_seconds': elapsed, 'files': files}
            records.append(record)
            (directory / 'builds.json').write_text(json.dumps({'schema_version': 1,
                'fixture_manifest_sha256': fixtures.digest(fixtures.MANIFEST.read_bytes()),
                'node': subprocess.check_output(['node', '--version'], env=env, text=True).strip(),
                'npm': subprocess.check_output(['npm', '--version'], env=env, text=True).strip(),
                'builds': records}, indent=2) + '\n')
            print(json.dumps({'id': record['id'], 'files': len(files), 'bytes': sum(f['bytes'] for f in files),
                              'build_seconds': elapsed}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshots', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.snapshots.resolve(), args.directory.resolve())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, f'Project build failed: {error}; inspect logs in the requested build directory\n')
