#!/usr/bin/env python3
"""Package the exact final Linux intake files; never approve, sign or publish.

Input is a flat directory assembled after hosted policy bytes have been frozen.
The printed digests are producer claims and must be pinned by another custodian.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import zipfile

HEX = re.compile(r'[0-9a-f]{64}\Z')
TAG = re.compile(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:rc|nightly)\.(0|[1-9][0-9]*))?\Z')
MANIFESTS = ('release.manifest.json', 'release.manifest-aarch64.json',
             'client-release.manifest.json', 'client-release.manifest-aarch64.json')
MAX_ARCHIVE = 1024**3
MAX_TRANSPORT = 8 * 1024**3


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def load(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
                'input must be a bounded single-link regular file')
        with os.fdopen(fd, 'rb') as source:
            data = source.read(limit + 1)
            after = os.fstat(source.fileno())
        require(len(data) == before.st_size and (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed while read')
        return data
    except BaseException:
        # fdopen owns the descriptor after success; this branch also covers
        # errors before that handoff.
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def hash_file(path, limit, target=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
                'input must be a bounded single-link regular file')
        digest = hashlib.sha256()
        count = 0
        while block := source.read(1024*1024):
            count += len(block)
            require(count <= limit, 'input grew beyond bound')
            digest.update(block)
            if target is not None:
                target.write(block)
        after = os.fstat(source.fileno())
        require(count == before.st_size and (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed while read')
        return digest.hexdigest(), count


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate manifest key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    match = TAG.fullmatch(args.tag)
    require(match is not None, 'invalid release tag')
    version = '.'.join(match.group(i) for i in (1, 2, 3))
    source = args.source_dir
    require(stat.S_ISDIR(source.lstat().st_mode), 'source must be a directory')
    files = set(MANIFESTS) | {'bootstrap-install.sh'}
    manifests = {}
    manifest_hashes = {}
    for arch, suffix in (('x86_64', ''), ('aarch64', '-aarch64')):
        for public in (False, True):
            role = 'client-release' if public else 'release'
            name = role + '.manifest' + suffix + '.json'
            manifest_bytes = load(source/name, 65536)
            manifest_hashes[name] = hashlib.sha256(manifest_bytes).hexdigest()
            manifest = decode(manifest_bytes)
            require(manifest['version'] == version and manifest['arch'] == arch
                    and manifest['platform'] == 'linux' and manifest['target_triple'] == arch+'-unknown-linux-gnu'
                    and isinstance(manifest.get('release_policy'), dict), 'final manifest role/policy mismatch')
            bundle = ('aegis-client' if public else 'aegis') + f'-{version}-linux-{arch}.tar.gz'
            require(manifest['artifacts']['bundle']['archive']['path'] == bundle
                    and HEX.fullmatch(manifest['artifacts']['bundle']['archive']['sha256']),
                    'bundle path/digest mismatch')
            files.add(bundle)
            if public:
                require(manifest['distribution'] == 'public_client'
                        and manifest['bootstrap']['path'] == 'bootstrap-install.sh'
                        and HEX.fullmatch(manifest['bootstrap']['sha256']), 'public role/bootstrap mismatch')
            else:
                research = f'aegis-research-{version}-linux-{arch}'
                identity = manifest['artifacts']['private_research']
                require(manifest['distribution'] == 'private_administrative_operator'
                        and identity['archive']['path'] == research+'.tar.gz'
                        and HEX.fullmatch(identity['archive']['sha256'])
                        and identity['manifest_sha256'] and HEX.fullmatch(identity['manifest_sha256']),
                        'private research identity/digest mismatch')
                files.update((research+'.tar.gz', research+'.manifest.json'))
            manifests[(arch, public)] = manifest
    require(len(files) == 13, 'transport inventory mismatch')
    require(len({m['git_sha'] for m in manifests.values()}) == 1
            and len({json.dumps(m['release_policy'], sort_keys=True) for m in manifests.values()}) == 1,
            'final source or policy mismatch')
    hashes = {}
    total = 0
    for name in sorted(files):
        limit = MAX_ARCHIVE if name.endswith('.tar.gz') else (256*1024 if name == 'bootstrap-install.sh' else 65536)
        digest, size = hash_file(source/name, limit)
        total += size
        require(total <= MAX_TRANSPORT, 'transport input exceeds bound')
        hashes[name] = digest
    require(all(hashes[name] == digest for name, digest in manifest_hashes.items()),
            'final manifest changed after role validation')
    for (arch, public), manifest in manifests.items():
        bundle = manifest['artifacts']['bundle']['archive']
        require(hashes[bundle['path']] == bundle['sha256'], 'bundle digest differs from final manifest')
        if public:
            require(hashes['bootstrap-install.sh'] == manifest['bootstrap']['sha256'], 'bootstrap digest mismatch')
        else:
            research = manifest['artifacts']['private_research']
            require(hashes[research['archive']['path']] == research['archive']['sha256']
                    and hashes[research['directory']+'.manifest.json'] == research['manifest_sha256'],
                    'private research digest mismatch')
    require(not args.output.exists() and not args.output.is_symlink(), 'output already exists')
    with tempfile.NamedTemporaryFile(prefix='.aegis-intake-', suffix='.partial', dir=args.output.parent,
                                     delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with zipfile.ZipFile(temporary_path, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            for name in sorted(files):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o400) << 16
                limit = MAX_ARCHIVE if name.endswith('.tar.gz') else (256*1024 if name == 'bootstrap-install.sh' else 65536)
                with archive.open(info, 'w', force_zip64=True) as target:
                    digest, _ = hash_file(source/name, limit, target)
                require(digest == hashes[name], 'input changed between digest and package')
        require(temporary_path.stat().st_size <= MAX_TRANSPORT, 'transport exceeds bound')
        # link is exclusive: a racing process cannot make us overwrite a receipt.
        os.link(temporary_path, args.output)
    finally:
        temporary_path.unlink(missing_ok=True)
    print(json.dumps({'status': 'PRODUCER_ONLY', 'source_sha': next(iter(manifests.values()))['git_sha'],
                      'transport_sha256': hash_file(args.output, MAX_TRANSPORT)[0],
                      'files': hashes}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print('offline-linux-transport: REFUSED: '+str(error), file=sys.stderr)
        raise SystemExit(1)
