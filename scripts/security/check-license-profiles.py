#!/usr/bin/env python3
"""Enforce the shipping notice graphs with the pinned offline Cargo policy.

All profiles run and keep unique text receipts. This checks source dependency
metadata, not signed artifacts, linked native libraries or legal clearance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def profiles(root):
    rows = []
    for arch, target in (('arm64', 'aarch64-unknown-linux-gnu'), ('x64', 'x86_64-unknown-linux-gnu')):
        rows.extend(((f'linux-{arch}-client', root/'Cargo.toml', target,
                      'raw-socket,chrome-like-tls,chrome-like-quic'),
                     (f'linux-{arch}-server', root/'Cargo.toml', target, '')))
    for arch, target in (('arm64', 'aarch64-apple-darwin'), ('x64', 'x86_64-apple-darwin')):
        rows.extend(((f'macos-{arch}-client', root/'Cargo.toml', target,
                      'chrome-like-tls,chrome-like-quic'),
                     (f'macos-{arch}-extension', root/'tools/macos/aegis-network-extension/Cargo.toml',
                      target, 'apple'),
                     (f'macos-{arch}-extension-vp8', root/'tools/macos/aegis-network-extension/Cargo.toml',
                      target, 'apple,sfu-media-vp8'),
                     (f'macos-{arch}-extension-vp8-quic', root/'tools/macos/aegis-network-extension/Cargo.toml',
                      target, 'apple,sfu-media-vp8,enrolled-quic')))
    return rows


def save(path, value):
    with path.open('x') as out:
        json.dump(value, out, sort_keys=True, indent=2)
        out.write('\n'); out.flush(); os.fsync(out.fileno())


def check_profiles(root, output, runner=subprocess.run):
    deadline = time.monotonic() + 600
    results = []
    for name, manifest, target, features in profiles(root):
        argv = ['cargo', 'deny', '--offline', '--locked', '--format', 'json',
                '--manifest-path', str(manifest), '--target', target,
                '--config', str(root/'deny.toml')]
        if features:
            argv += ['--features', features]
        argv += ['check', 'licenses', 'bans', 'sources']
        remaining = deadline - time.monotonic()
        executed = remaining > 0
        rc = 124
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            if executed:
                try:
                    rc = runner(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=out,
                                stderr=err, timeout=min(180, remaining)).returncode
                except subprocess.TimeoutExpired:
                    rc = 124
        value = dict(profile=name, manifest=str(manifest.relative_to(root)), target=target,
                     features=features, rc=rc, executed=executed, offline=True, locked=True,
                     checks=['licenses', 'bans', 'sources'])
        save(output/(name+'.json'), value)
        results.append(value)
        print(json.dumps(dict(profile=name, rc=rc, executed=executed)), flush=True)
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); os.umask(0o077)
    version = subprocess.check_output(['cargo', 'deny', '--version'], cwd=ROOT,
                                      text=True, timeout=10).strip()
    if version != 'cargo-deny 0.20.2':
        raise ValueError('pinned cargo-deny 0.20.2 required')
    source = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    if subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=no']):
        raise ValueError('committed dependency-policy inputs required')
    files = ('deny.toml', 'Cargo.toml', 'Cargo.lock',
             'tools/macos/aegis-network-extension/Cargo.toml',
             'tools/macos/aegis-network-extension/Cargo.lock')
    inputs = {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in files}
    args.output.mkdir(mode=0o700)
    save(args.output/'source.json', dict(source_sha=source, inputs=inputs, tool_version=version))
    results = check_profiles(ROOT, args.output)
    unchanged = all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == sha for name, sha in inputs.items())
    clean = not subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=no'])
    passed = unchanged and clean and all(v['rc'] == 0 and v['executed'] for v in results)
    save(args.output/'aggregate.json', dict(source_sha=source, tool_version=version, results=results,
         inputs_unchanged=unchanged, tracked_source_clean=clean, all_pass=passed,
         scope='offline source dependency policy', signed_artifact_acceptance=False,
         installed_acceptance=False, legal_clearance=False))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
