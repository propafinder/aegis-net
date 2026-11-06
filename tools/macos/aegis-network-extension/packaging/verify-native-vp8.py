#!/usr/bin/python3 -I
"""Bind an opt-in Mac release build to the reviewed native VP8 prerequisite.

This checks receipt and exact input bytes. It does not establish a complete
native SBOM, prove a provider links the archive, or admit an SFU route.
"""
import argparse
import hashlib
import json
from pathlib import Path

SOURCE_COMMIT = '6df3ec34557879fff673706f4a1d9fbd0f3a6f0e'
SOURCE_TREE = 'f83d33a1ba18b3a203e43596b5223042b62417a3'
SOURCE_ARCHIVE = 'd7f22e7ca80ba6cfbe16e867400e9cb28e7349efd1eb823836ab45c23a8ee0b1'
RECIPE_COMMIT = '7596ee57cbeb30d151cb3fdb0dbb7d9d59c010c4'
NATIVE_ARCHIVE = 'e4d1a14ab1415f3b57317d104e15661e60c4e31ece6b655ac5353802c3b54dcd'
NATIVE_PC = '313b0f9dc2edb3afbc513191736d38b23c191945d8e64d46b93287a03355d9b8'
OBJECT_ROSTER = '4646e796c8b656d2ece6f77e6eb980e28635f5a8328e678a9f81ae9a33ed30c9'
LICENSE_SHA = '8267348d5af1262c11d1a08de2f5afc77457755f1ac658627dd9acf71011d615'


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def regular(path, limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError('native input missing, linked or oversized')


def verify(receipt_path, prefix, legal_source):
    for path in (receipt_path, prefix, legal_source):
        if not path.is_absolute() or path.is_symlink():
            raise ValueError('absolute unlinked native paths required')
    regular(receipt_path, 1024 * 1024)
    if not prefix.is_dir():
        raise ValueError('native prefix missing')
    regular(legal_source, 2 * 1024 * 1024)
    if sha256(legal_source) != LICENSE_SHA:
        raise ValueError('reviewed libvpx license changed')
    receipt = json.loads(receipt_path.read_text())
    if not isinstance(receipt, dict):
        raise ValueError('native receipt is not an object')
    if (receipt.get('schema') != 'aegis_sfu_libvpx_native_recipe_r1'
            or receipt.get('native_pass') is not True
            or receipt.get('platform') != 'darwin'
            or receipt.get('version') != '1.17.0'
            or receipt.get('tag') != 'v1.17.0'
            or receipt.get('source_commit') != SOURCE_COMMIT
            or receipt.get('source_tree') != SOURCE_TREE
            or receipt.get('source_archive_sha256') != SOURCE_ARCHIVE
            or receipt.get('operator_source_commit') != RECIPE_COMMIT):
        raise ValueError('native recipe identity mismatch')
    deployment = receipt.get('deployment')
    requested = receipt.get('requested_deployment')
    required = {'macos_deployment_target': '14.4', 'target': 'arm64-darwin23-gcc'}
    if (not isinstance(deployment, dict) or not isinstance(requested, dict)
            or any(deployment.get(key) != value or requested.get(key) != value
                   for key, value in required.items())
            or deployment.get('architecture') != 'arm64'
            or deployment.get('macho_objects') != 231
            or deployment.get('archive_members') != 232
            or deployment.get('object_minos') != ['14.4']
            or deployment.get('member_roster_sha256') != OBJECT_ROSTER):
        raise ValueError('native deployment proof mismatch')
    steps = receipt.get('steps')
    if not isinstance(steps, dict) or any(
        not isinstance(steps.get(name), dict)
        or steps[name].get('exit_code') != 0
        or steps[name].get('group_gone') is not True
        for name in ('configure', 'make', 'install', 'symbols')
    ):
        raise ValueError('native step did not close')
    assets = receipt.get('assets')
    if (not isinstance(assets, dict)
            or not isinstance(assets.get('source/LICENSE'), dict)
            or assets['source/LICENSE'].get('sha256') != LICENSE_SHA):
        raise ValueError('native license receipt mismatch')
    checks = {}
    for rel, pinned in (('prefix/lib/libvpx.a', NATIVE_ARCHIVE),
                        ('prefix/lib/pkgconfig/vpx.pc', NATIVE_PC)):
        file = prefix / rel.removeprefix('prefix/')
        regular(file, 32 * 1024 * 1024)
        wanted = assets.get(rel, {}).get('sha256') if isinstance(assets.get(rel), dict) else None
        if wanted != pinned or sha256(file) != pinned:
            raise ValueError('native asset differs from receipt')
        checks[rel] = wanted
    pc = (prefix / 'lib/pkgconfig/vpx.pc').read_text()
    if f'prefix={prefix}\n' not in pc or '\nVersion: 1.17.0\n' not in pc:
        raise ValueError('native pkg-config path or version mismatch')
    return {'receipt_sha256': sha256(receipt_path),
            'receipt_path': str(receipt_path), 'prefix_path': str(prefix),
            'libvpx_a_sha256': checks['prefix/lib/libvpx.a'],
            'vpx_pc_sha256': checks['prefix/lib/pkgconfig/vpx.pc'],
            'license_sha256': LICENSE_SHA, 'recipe_source_commit': RECIPE_COMMIT,
            'deployment_target': 'macos-14.4-arm64'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--prefix', type=Path, required=True)
    args = parser.parse_args()
    legal = Path(__file__).resolve().parents[1] / 'legal/LICENSE-LIBVPX'
    try:
        print(json.dumps(verify(args.receipt, args.prefix, legal), sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        parser.exit(1, f'native VP8 admission refused: {type(error).__name__}\n')


if __name__ == '__main__':
    main()
