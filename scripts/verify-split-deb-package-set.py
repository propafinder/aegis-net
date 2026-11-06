#!/usr/bin/env python3
"""Verify a completed split DEB set before copying, installing or publishing it."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


class Refused(ValueError):
    pass


def regular(path):
    if not path.is_file() or path.is_symlink():
        raise Refused(f'missing or nonregular file: {path}')


def read_json(path):
    regular(path)
    if path.stat().st_size > 1024 * 1024:
        raise Refused(f'oversized manifest: {path}')
    return json.loads(path.read_text(encoding='utf-8'))


def verify(directory, arch, version=None, release_manifest=None, source_sha=None,
           server_deb=None, client_deb=None):
    if not directory.is_dir() or directory.is_symlink():
        raise Refused('package directory is missing or a symlink')
    release = read_json(release_manifest) if release_manifest is not None else None
    deb = release.get('artifacts', {}).get('deb', {}) if release is not None else None
    marker_name = deb.get('manifest_path') if deb is not None else 'split-deb-packages.manifest.json'
    if marker_name not in ('split-deb-packages.manifest.json',
                           'split-deb-packages-aarch64.manifest.json',
                           'split-deb-packages-x86_64.manifest.json'):
        raise Refused('invalid split DEB marker path')
    marker = read_json(directory / marker_name)
    if not isinstance(marker, dict) or not isinstance(marker.get('version'), str):
        raise Refused('split manifest has no version')
    if version is not None and marker['version'] != version:
        raise Refused('split manifest version mismatch')
    version = marker['version']
    if not re.fullmatch(r'[0-9][0-9A-Za-z.+:~-]{0,80}', version):
        raise Refused('invalid split manifest version')
    if marker.get('deb_arch') != arch:
        raise Refused('split manifest architecture mismatch')
    packages = marker.get('packages')
    if not isinstance(packages, dict) or set(packages) != {'aegis-server', 'aegis-client'}:
        raise Refused('split manifest package pair mismatch')
    if (server_deb is None) != (client_deb is None):
        raise Refused('both selected DEB paths are required together')

    if release_manifest is not None:
        upstream = release.get('version')
        if (release.get('schema') != 'aegis_linux_release_manifest_v1' or
                type(upstream) is not str or
                not (version == upstream or re.fullmatch(
                    re.escape(upstream) + r'-[1-9][0-9]{0,17}', version)) or
                deb.get('split_version', upstream) != version):
            raise Refused('release manifest identity mismatch')
        expected_arch = {'amd64': 'x86_64', 'arm64': 'aarch64', 'armhf': 'armv7l'}[arch]
        if release.get('arch') != expected_arch:
            raise Refused('release manifest architecture mismatch')
        if source_sha is not None and release.get('git_sha') != source_sha:
            raise Refused('release manifest source SHA mismatch')
        if deb.get('status') != 'ready':
            raise Refused('release manifest does not bind split DEB marker')
        release = deb.get('split')
        if not isinstance(release, dict):
            raise Refused('release manifest missing split DEB hashes')
    elif source_sha is not None:
        raise Refused('--source-sha requires --release-manifest')

    expected = set()
    checker = Path(__file__).with_name('verify-deb-archive-ownership.py')
    for role in ('server', 'client'):
        package = f'aegis-{role}'
        name = f'{package}_{version}_{arch}.deb'
        if packages[package].get('deb_file') != name:
            raise Refused(f'split manifest {package} filename mismatch')
        expected.add(name)
        path = directory / name
        selected = server_deb if role == 'server' else client_deb
        if selected is not None and selected != path:
            raise Refused(f'selected {role} DEB differs from manifest path')
        sidecar = directory / f'{name}.sha256'
        regular(path)
        regular(sidecar)
        if path.stat().st_size > 512 * 1024 * 1024 or sidecar.stat().st_size > 128:
            raise Refused(f'oversized package or sidecar: {name}')
        hasher = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        if sidecar.read_text(encoding='ascii') != f'{digest}  {name}\n':
            raise Refused(f'original SHA sidecar mismatch: {name}')
        if release is not None:
            entry = release.get(role)
            if not isinstance(entry, dict) or entry.get('path') != name or entry.get('sha256_path') != f'{name}.sha256' or entry.get('sha256') != digest:
                raise Refused(f'release manifest SHA mismatch: {name}')
        result = subprocess.run([sys.executable, '-I', '-B', str(checker), str(path)],
                                capture_output=True, text=True, timeout=45, check=False)
        if result.returncode != 0:
            raise Refused(f'archive ownership refused: {name}: {result.stderr.strip()}')
    present = {path.name for path in directory.glob(f'aegis-*_{arch}.deb')}
    if present != expected:
        raise Refused(f'extra or missing split DEB files: {sorted(present ^ expected)}')
    present_sidecars = {path.name for path in directory.glob(f'aegis-*_{arch}.deb.sha256')}
    expected_sidecars = {name + '.sha256' for name in expected}
    if present_sidecars != expected_sidecars:
        raise Refused(f'extra or missing split DEB sidecars: {sorted(present_sidecars ^ expected_sidecars)}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--arch', required=True, choices=('amd64', 'arm64', 'armhf'))
    parser.add_argument('--version')
    parser.add_argument('--release-manifest', type=Path)
    parser.add_argument('--source-sha')
    parser.add_argument('--server-deb', type=Path)
    parser.add_argument('--client-deb', type=Path)
    args = parser.parse_args()
    try:
        verify(args.directory, args.arch, args.version, args.release_manifest,
               args.source_sha, args.server_deb, args.client_deb)
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(f'split DEB set REFUSED: {error}', file=sys.stderr)
        return 1
    print('PASS: split DEB pair, original sidecars, manifests and archive owners')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
