#!/usr/bin/env bash
# Real Cargo/Git fixtures only. Never changes the working repository's metadata.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "${ROOT}" <<'PY'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(sys.argv[1])
CARGO = shutil.which('cargo')
GIT = shutil.which('git')
if not CARGO or not GIT:
    raise SystemExit('cargo and git are required for the real rerun contract')

COUNT = 0

def check(value, label):
    global COUNT
    if not value:
        raise AssertionError(label)
    COUNT += 1
    print('PASS:', label, flush=True)

def run(argv, cwd, env, *, ok=True):
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=90)
    if ok and result.returncode:
        raise RuntimeError(f'{argv[0:3]} failed: {result.stderr[-7000:]}')
    return result

with tempfile.TemporaryDirectory(prefix='aegis-build-rerun-') as scratch:
    base = Path(scratch)
    env = dict(os.environ)
    for name in list(env):
        if name.startswith(('AEGIS_BUILD_', 'AEGIS_CARGO_', 'CARGO_ENCODED_', 'GIT_')) or name in ['CARGO_TARGET_DIR', 'RUSTFLAGS', 'RUSTDOCFLAGS']:
            env.pop(name, None)
    env.update({'CARGO_NET_OFFLINE': 'true', 'CARGO_TERM_COLOR': 'never', 'GIT_CONFIG_NOSYSTEM': '1',
                'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_AUTHOR_NAME': 'Fixture',
                'GIT_AUTHOR_EMAIL': 'fixture@example.invalid', 'GIT_COMMITTER_NAME': 'Fixture',
                'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'})

    for role in ['client', 'server']:
        repo = base / role / 'repository'
        repo.mkdir(parents=True)
        package = 'aegis-rerun-' + role
        (repo / 'Cargo.toml').write_text(f'[package]\nname="{package}"\nversion="0.0.0"\nedition="2021"\n[workspace]\n')
        (repo / 'build.rs').write_bytes((ROOT / f'aegis-{role}/build.rs').read_bytes())
        (repo / 'src').mkdir()
        (repo / 'src/main.rs').write_text('fn main() { println!("{}|{}", env!("AEGIS_BUILD_GIT_SHA"), env!("AEGIS_BUILD_TIMESTAMP")); }\n')
        run([CARGO, 'generate-lockfile', '--offline'], repo, env)
        run([GIT, '-c', 'init.defaultBranch=fixture', 'init', '-q'], repo, env)
        run([GIT, 'add', '.'], repo, env)
        run([GIT, 'commit', '-qm', 'initial fixture'], repo, env)
        build_env = dict(env, CARGO_TARGET_DIR=str(base / role / 'target'))

        def build(path, *, fresh=None, metadata_env=None):
            active = build_env if metadata_env is None else metadata_env
            result = run([CARGO, 'build', '--locked', '--offline', '-vv'], path, active)
            compile_marker = 'Compiling ' + package + ' '
            if fresh is not None:
                check((compile_marker not in result.stderr and ('Fresh ' + package + ' ') in result.stderr) if fresh else compile_marker in result.stderr,
                      f'{role}: {path.name} build is ' + ('Fresh' if fresh else 'rebuilt'))
            binary = Path(active['CARGO_TARGET_DIR']) / 'debug' / package
            value = run([str(binary)], path, active).stdout.strip()
            output = list((Path(active['CARGO_TARGET_DIR']) / 'debug/build').glob(package + '-*/output'))
            assert output
            latest = max(output, key=lambda p: p.stat().st_mtime_ns).read_text()
            for line in latest.splitlines():
                if line.startswith('cargo:rerun-if-changed='):
                    watch = Path(line.split('=', 1)[1])
                    if not watch.is_absolute():
                        watch = path / watch
                    check(watch.exists(), f'{role}: tracked metadata input exists')
            return value, latest

        def expected(path):
            sha = run([GIT, 'rev-parse', 'HEAD'], path, env).stdout.strip()
            stamp = run([GIT, 'show', '-s', '--format=%cI', 'HEAD'], path, env).stdout.strip()
            return sha + '|' + stamp

        value, _ = build(repo, fresh=False)
        check(value == expected(repo), role + ': source SHA and commit timestamp match Git')
        check(not (repo / '.git/packed-refs').exists() and not (repo / '.git/refs/heads/main').exists(),
              role + ': normal fixture really lacks optional main/packed-refs')
        build(repo, fresh=True)
        (repo / 'artifacts').mkdir()
        (repo / 'artifacts/aggregate.log').write_text('new log without source changes\n')
        build(repo, fresh=True)
        (repo / 'version.txt').write_text('second\n')
        run([GIT, 'add', 'version.txt'], repo, env)
        run([GIT, 'commit', '-qm', 'second fixture'], repo, env)
        check(build(repo, fresh=False)[0] == expected(repo), role + ': loose current ref update is detected')
        build(repo, fresh=True)
        run([GIT, 'pack-refs', '--all', '--prune'], repo, env)
        check(not (repo / '.git/refs/heads/fixture').exists(), role + ': current ref genuinely packed')
        check(build(repo, fresh=False)[0] == expected(repo), role + ': packing preserves metadata')
        build(repo, fresh=True)
        (repo / 'version.txt').write_text('third\n')
        run([GIT, 'add', 'version.txt'], repo, env)
        run([GIT, 'commit', '-qm', 'third fixture'], repo, env)
        check(build(repo, fresh=False)[0] == expected(repo), role + ': packed-to-loose update is detected')
        build(repo, fresh=True)
        run([GIT, 'checkout', '-q', '--detach', 'HEAD~1'], repo, env)
        check(build(repo, fresh=False)[0] == expected(repo), role + ': detached HEAD metadata is correct')
        build(repo, fresh=True)

        worktree = base / role / 'linked-worktree'
        run([GIT, 'worktree', 'add', '-q', '-b', 'linked', str(worktree), 'HEAD'], repo, env)
        check((worktree / '.git').is_file(), role + ': linked fixture uses .git indirection file')
        build_env = dict(env, CARGO_TARGET_DIR=str(base / role / 'worktree-target'))
        check(build(worktree, fresh=False)[0] == expected(worktree), role + ': linked HEAD resolves correctly')
        build(worktree, fresh=True)
        (worktree / 'artifacts').mkdir()
        (worktree / 'artifacts/aggregate.log').write_text('worktree evidence\n')
        build(worktree, fresh=True)
        (worktree / 'linked.txt').write_text('current linked ref changed\n')
        run([GIT, 'add', 'linked.txt'], worktree, env)
        run([GIT, 'commit', '-qm', 'linked fixture commit'], worktree, env)
        check(build(worktree, fresh=False)[0] == expected(worktree), role + ': shared linked ref update is detected')
        build(worktree, fresh=True)

        archive = base / role / 'source-archive'
        archive.mkdir()
        for name in ['build.rs', 'Cargo.toml', 'Cargo.lock']:
            shutil.copyfile(repo / name, archive / name)
        shutil.copytree(repo / 'src', archive / 'src')
        # Any Git process would leave this marker and fail. Explicit metadata
        # must bypass Git entirely, not merely tolerate its failure.
        shim = base / role / 'shim'
        shim.mkdir()
        marker = base / role / 'git-invoked'
        fake_git = shim / 'git'
        fake_git.write_text('#!/bin/sh\nprintf invoked > "$AEGIS_RERUN_GIT_MARKER"\nexit 99\n')
        fake_git.chmod(0o700)
        explicit = dict(env, CARGO_TARGET_DIR=str(base / role / 'archive-target'),
                        PATH=str(shim) + os.pathsep + env.get('PATH', ''),
                        AEGIS_RERUN_GIT_MARKER=str(marker),
                        AEGIS_BUILD_GIT_SHA='a' * 40, AEGIS_BUILD_TIMESTAMP='2026-09-11T12:34:56+02:00')
        value, output = build(archive, fresh=False, metadata_env=explicit)
        check(value == explicit['AEGIS_BUILD_GIT_SHA'] + '|' + explicit['AEGIS_BUILD_TIMESTAMP'],
              role + ': archive explicit metadata is preserved')
        check('cargo:rerun-if-changed=' not in output and not marker.exists(), role + ': explicit metadata performs no Git query/watch')
        build(archive, fresh=True, metadata_env=explicit)
        explicit['AEGIS_BUILD_GIT_SHA'] = 'b' * 40
        check(build(archive, fresh=False, metadata_env=explicit)[0].startswith('b' * 40 + '|'), role + ': changed explicit SHA reruns')
        build(archive, fresh=True, metadata_env=explicit)
        for key, value in [('AEGIS_BUILD_GIT_SHA', 'bad\ncargo:rustc-cfg=UNTRUSTED'),
                           ('AEGIS_BUILD_TIMESTAMP', 'bad\rseparator'),
                           ('AEGIS_BUILD_TARGET', 'bad\nseparator'),
                           ('AEGIS_BUILD_FEATURES', 'bad\rseparator'),
                           ('AEGIS_CARGO_LOCK_SHA256', 'bad\nseparator')]:
            invalid = dict(explicit, **{key: value})
            result = run([CARGO, 'build', '--locked', '--offline'], archive, invalid, ok=False)
            check(result.returncode != 0 and 'directive separator' in result.stderr,
                  role + ': rejects directive separator in ' + key)
        # An environment variable cannot contain NUL at the OS ABI. Exercise
        # the exact shared Rust predicate directly for that otherwise unreachable case.
        probe = base / role / 'nul-probe.rs'
        probe.write_text('mod subject { include!(' + json.dumps(str(ROOT / f'aegis-{role}/build.rs')) + ');\npub fn probe() { check_directive_value("fixture", "bad\\0value"); } }\nfn main() { subject::probe(); }\n')
        executable = base / role / 'nul-probe'
        run([shutil.which('rustc'), '--edition', '2021', '-A', 'dead_code', str(probe), '-o', str(executable)], archive, env)
        result = run([str(executable)], archive, env, ok=False)
        check(result.returncode != 0 and 'directive separator' in result.stderr, role + ': rejects NUL directive separator')
        check(not marker.exists(), role + ': explicit metadata never consulted Git')

print(f'build-script git rerun contract: PASS ({COUNT} assertions)', flush=True)
PY
