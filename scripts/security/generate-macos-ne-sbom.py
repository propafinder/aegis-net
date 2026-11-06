#!/usr/bin/env python3
"""Two-pass, source-bound Cargo metadata SBOM for the opt-in Mac NE feature.

This measures the resolved Cargo graph only. Native/static/driver/shipped payload
closure and release acceptance remain separate, even when a libvpx receipt exists.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time
import tomllib
import uuid

NE = Path('tools/macos/aegis-network-extension')
TARGET = 'aarch64-apple-darwin'
FEATURES = ('apple', 'apple,sfu-media-vp8', 'apple,sfu-media-vp8,enrolled-quic')
VERSION = '0.5.9'
MAX_BOM = 16 << 20
MAX_LOG = 1 << 20
REQUIRED = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
            str(NE / 'Cargo.toml'), str(NE / 'Cargo.lock')}


class Refused(RuntimeError):
    pass


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise Refused(reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path, limit: int) -> str:
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= limit,
         'input_not_regular_or_bounded')
    return sha(path.read_bytes())


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                            timeout=30)
    need(result.returncode == 0, 'git_source_query_failed')
    return result.stdout


def source_inputs(root: Path, commit: str) -> dict[str, str]:
    need(re.fullmatch(r'[0-9a-f]{40}', commit) is not None, 'source_commit_shape')
    need(git(root, 'rev-parse', 'HEAD').decode().strip() == commit, 'source_head_changed')
    need(not git(root, 'status', '--porcelain', '--untracked-files=all'), 'source_dirty')
    tracked = {name.decode() for name in git(root, 'ls-files', '-z').split(b'\0') if name}
    selected = {name for name in tracked if name == 'Cargo.toml' or
                name.endswith('/Cargo.toml') or name.endswith('/Cargo.lock') or
                name == 'Cargo.lock' or name == 'rust-toolchain.toml' or
                name.startswith('.cargo/config') or '/.cargo/config' in name}
    need(REQUIRED <= selected, 'source_lock_or_manifest_missing')
    pins = {}
    for name in sorted(selected):
        path = root / name
        actual = path.read_bytes()
        need(file_sha(path, 4 << 20) == sha(actual) and
             git(root, 'show', commit + ':' + name) == actual,
             'source_input_differs_from_commit:' + name)
        pins[name] = sha(actual)
    ne = tomllib.loads((root / NE / 'Cargo.toml').read_text())
    need(ne.get('package', {}).get('name') == 'aegis-network-extension' and
         'apple' in ne.get('features', {}) and
         'sfu-media-vp8' in ne.get('features', {}) and
         'enrolled-quic' in ne.get('features', {}), 'ne_feature_manifest_changed')
    return pins


def operator_pin(operator_commit: str) -> str:
    script = Path(__file__).resolve()
    root = script.parents[2]
    rel = str(script.relative_to(root))
    need(re.fullmatch(r'[0-9a-f]{40}', operator_commit) is not None,
         'operator_commit_shape')
    need(git(root, 'show', operator_commit + ':' + rel) == script.read_bytes(),
         'operator_source_differs_from_commit')
    return sha(script.read_bytes())


def tool_pin(tool: Path, digest: str) -> str:
    need(tool.is_absolute() and not tool.is_symlink() and
         re.fullmatch(r'[0-9a-f]{64}', digest) is not None,
         'tool_pin_shape')
    need(file_sha(tool, 64 << 20) == digest and os.access(tool, os.X_OK),
         'tool_bytes_changed')
    result = subprocess.run([str(tool), 'cyclonedx', '--version'],
                            capture_output=True, timeout=10, text=True)
    version = result.stdout.strip()
    need(result.returncode == 0 and
         re.fullmatch(r'cargo-cyclonedx(?:-cyclonedx)? 0\.5\.9', version) is not None,
         'tool_version_changed')
    return version


def command(tool: Path, manifest: Path, features: str, filename: str) -> list[str]:
    need(features in FEATURES and re.fullmatch(r'aegis-ne-[0-9a-f]{32}', filename),
         'feature_or_output_changed')
    return [str(tool), 'cyclonedx', '--manifest-path', str(manifest),
            '--format', 'json', '--spec-version', '1.5', '--all', '--target', TARGET,
            '--features', features, '--override-filename', filename]


def run_bounded(argv: list[str], cwd: Path, env: dict[str, str], log: Path) -> int:
    with log.open('xb') as out:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=out,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=180)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            raise Refused('tool_timeout') from None


def canonical_bom(raw: bytes) -> bytes:
    need(len(raw) <= MAX_BOM, 'bom_oversized')
    data = json.loads(raw)
    need(type(data) is dict and data.get('bomFormat') == 'CycloneDX' and
         data.get('specVersion') == '1.5' and
         type(data.get('components')) is list and bool(data['components']) and
         type(data.get('metadata')) is dict,
         'bom_schema_or_components_missing')
    # Preserve timestamps, serial numbers, IDs, all components and every field.
    return json.dumps(data, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--source-commit', required=True)
    p.add_argument('--operator-commit', required=True)
    p.add_argument('--features', choices=FEATURES, required=True)
    p.add_argument('--tool', type=Path, required=True)
    p.add_argument('--tool-sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root = a.source_root.resolve(strict=True)
    need(root.is_dir() and a.source_root.is_absolute(), 'source_root_absolute')
    need(a.output.is_absolute() and not a.output.exists() and
         not a.output.is_symlink() and a.output.parent.is_dir() and
         not a.output.parent.is_symlink(), 'private_unique_output_required')
    pins = source_inputs(root, a.source_commit)
    operator_hash = operator_pin(a.operator_commit)
    version = tool_pin(a.tool, a.tool_sha256)
    epoch = git(root, 'show', '-s', '--format=%ct', a.source_commit).decode().strip()
    need(epoch.isdecimal(), 'source_epoch_missing')
    env = {k: v for k, v in os.environ.items()
           if not (k.startswith('CARGO_CYCLONEDX') or k.startswith('CYCLONEDX_') or
                   k in ('SOURCE_DATE_EPOCH', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'))}
    env.update(SOURCE_DATE_EPOCH=epoch, CARGO_NET_OFFLINE='true')
    a.output.mkdir(mode=0o700)
    receipt = {'schema': 'aegis_macos_ne_cargo_metadata_sbom_v1',
               'source_root': str(root), 'source_commit': a.source_commit,
               'operator_commit': a.operator_commit, 'operator_sha256': operator_hash,
               'manifest': str(NE / 'Cargo.toml'), 'target': TARGET,
               'features': a.features, 'tool_path': str(a.tool),
               'tool_sha256': a.tool_sha256, 'tool_version': version,
               'source_date_epoch': epoch, 'source_inputs': pins,
               'cargo_metadata_only': True, 'native_static_shipping_complete': False,
               'release_acceptance': False, 'passes': [], 'status': 'FAILED'}
    first = None
    try:
        for number in (1, 2):
            name = 'aegis-ne-' + uuid.uuid4().hex
            # cargo-cyclonedx 0.5.9 appends the JSON extension after override.
            transient = root / NE / (name + '.json')
            need(not transient.exists() and not transient.is_symlink(),
                 'transient_output_exists')
            argv = command(a.tool, root / NE / 'Cargo.toml', a.features, name)
            result = None
            try:
                result = run_bounded(argv, root, env,
                                     a.output / f'pass-{number}.log')
            finally:
                if transient.exists() and not transient.is_symlink():
                    need(file_sha(transient, MAX_BOM) is not None,
                         'transient_output_invalid')
                    transient.rename(a.output / f'pass-{number}.cdx.json')
            log = a.output / f'pass-{number}.log'
            need(log.stat().st_size <= MAX_LOG, 'tool_log_oversized')
            saved = a.output / f'pass-{number}.cdx.json'
            need(result == 0 and saved.is_file(), 'producer_failed_or_no_sbom')
            raw = saved.read_bytes()
            normalized = canonical_bom(raw)
            receipt['passes'].append({'returncode': result, 'argv': argv,
                                      'raw_sha256': sha(raw),
                                      'normalized_sha256': sha(normalized),
                                      'log_sha256': file_sha(log, MAX_LOG)})
            need(source_inputs(root, a.source_commit) == pins,
                 'source_changed_during_generation')
            need(tool_pin(a.tool, a.tool_sha256) == version,
                 'tool_changed_during_generation')
            if first is None:
                first = normalized
            else:
                need(first == normalized, 'bom_repeatability_changed')
        receipt['status'] = 'PASS'
    except Exception as error:
        receipt['error'] = type(error).__name__ + ':' + str(error)
        raise
    finally:
        with (a.output / 'receipt.json').open('x') as out:
            json.dump(receipt, out, sort_keys=True, indent=2)
            out.write('\n')
    print(str(a.output / 'receipt.json'))


if __name__ == '__main__':
    main()
