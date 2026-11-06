#!/usr/bin/env python3
"""Verify a completed split RPM pair before copying, installing or publishing."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


class Refused(ValueError):
    pass


def read_json(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise Refused(f'missing, nonregular or oversized manifest: {path}')
    return json.loads(path.read_text(encoding='utf-8'))


MARKERS = ('rpm-packages.manifest.json', 'rpm-packages-aarch64.manifest.json',
           'rpm-packages-x86_64.manifest.json')
ARCHES = ('x86_64', 'aarch64', 'armv7l')


def verify_pair(directory, arch, version, marker_name, release, source_sha):
    if marker_name not in MARKERS:
        raise Refused('invalid RPM marker path')
    if marker_name.startswith('rpm-packages-') and marker_name != f'rpm-packages-{arch}.manifest.json':
        raise Refused('RPM marker name and architecture mismatch')
    marker = read_json(directory / marker_name)
    version = version or marker.get('version')
    if not isinstance(version, str) or not re.fullmatch(r'[0-9][0-9A-Za-z.+:~-]{0,80}', version):
        raise Refused('invalid RPM version')
    if marker.get('version') != version or marker.get('arch') != arch:
        raise Refused('RPM marker version or architecture mismatch')
    packages = marker.get('packages')
    if not isinstance(packages, dict) or set(packages) != {'aegis-server', 'aegis-client'}:
        raise Refused('RPM marker package pair mismatch')
    if release:
        rpm_release = release.get('artifacts', {}).get('rpm', {})
        if release.get('schema') != 'aegis_linux_release_manifest_v1' or release.get('version') != version or release.get('arch') != arch:
            raise Refused('release identity mismatch')
        if source_sha and release.get('git_sha') != source_sha:
            raise Refused('release source SHA mismatch')
        if rpm_release.get('status') != 'ready' or rpm_release.get('manifest_path') != marker_name:
            raise Refused('release does not bind ready RPM marker')
        release_pair = rpm_release.get('split')
        if not isinstance(release_pair, dict) or set(release_pair) != {'server', 'client'}:
            raise Refused('release missing RPM pair hashes')
    elif source_sha:
        raise Refused('--source-sha requires --release-manifest')
    expected = set()
    for role in ('server', 'client'):
        package = f'aegis-{role}'
        entry = packages[package]
        if not isinstance(entry, dict):
            raise Refused(f'invalid {package} entry')
        name = entry.get('rpm_file')
        if not isinstance(name, str) or not re.fullmatch(
                rf'{package}-{re.escape(version)}-1[^/]*\.{arch}\.rpm', name):
            raise Refused(f'invalid {package} filename')
        if entry.get('sha256_file') != f'{name}.sha256':
            raise Refused(f'invalid {package} sidecar name')
        expected.update((name, f'{name}.sha256'))
        path, sidecar = directory / name, directory / f'{name}.sha256'
        for item, maximum in ((path, 512 * 1024 * 1024), (sidecar, 128)):
            if not item.is_file() or item.is_symlink() or item.stat().st_size > maximum:
                raise Refused(f'missing, nonregular or oversized: {item}')
        hasher = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        if sidecar.read_text(encoding='ascii') != f'{digest}  {name}\n':
            raise Refused(f'SHA sidecar mismatch: {name}')
        if release:
            outer = release_pair.get(role)
            if not isinstance(outer, dict) or outer.get('path') != name or outer.get('sha256_path') != f'{name}.sha256' or outer.get('sha256') != digest:
                raise Refused(f'release SHA mismatch: {name}')
    return expected, version


def verify(directory, arch, version=None, release_manifest=None, source_sha=None):
    if not directory.is_dir() or directory.is_symlink():
        raise Refused('package directory is missing or a symlink')
    release = read_json(release_manifest) if release_manifest else None
    marker_name = release.get('artifacts', {}).get('rpm', {}).get('manifest_path') if release else 'rpm-packages.manifest.json'
    expected, version = verify_pair(directory, arch, version, marker_name, release, source_sha)
    # The final release directory intentionally flattens x86_64 and aarch64.
    # Any other RPM bytes must be bound by a second architecture-specific marker
    # and, when outer release custody is requested, its own release manifest.
    seen_arches = {arch}
    for peer_name in MARKERS:
        peer_path = directory / peer_name
        if peer_name == marker_name or not (peer_path.exists() or peer_path.is_symlink()):
            continue
        peer = read_json(directory / peer_name)
        peer_arch = peer.get('arch')
        if peer_arch not in ARCHES or peer_arch in seen_arches:
            raise Refused('duplicate or invalid peer RPM architecture')
        seen_arches.add(peer_arch)
        peer_release = None
        if release is not None:
            peer_release_name = f'release.manifest-{peer_arch}.json'
            if peer_name == 'rpm-packages.manifest.json' and peer_arch == 'x86_64':
                peer_release_name = 'release.manifest.json'
            peer_release = read_json(directory / peer_release_name)
        peer_expected, peer_version = verify_pair(directory, peer_arch, version, peer_name,
                                                  peer_release, source_sha or (release.get('git_sha') if release else None))
        if peer_version != version or expected & peer_expected:
            raise Refused('peer RPM pair version or filename overlap')
        expected.update(peer_expected)
    present = {path.name for path in directory.iterdir()
               if path.name.endswith('.rpm') or path.name.endswith('.rpm.sha256')}
    if present != expected:
        raise Refused(f'extra or missing RPM/sidecar files: {sorted(present ^ expected)}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--arch', required=True, choices=ARCHES)
    parser.add_argument('--version')
    parser.add_argument('--release-manifest', type=Path)
    parser.add_argument('--source-sha')
    args = parser.parse_args()
    try:
        verify(args.directory, args.arch, args.version, args.release_manifest, args.source_sha)
    except (Refused, OSError, ValueError, KeyError, TypeError) as error:
        print(f'split RPM set REFUSED: {error}', file=sys.stderr)
        return 1
    print('PASS: split RPM pair, completion marker, sidecars and release identity')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
