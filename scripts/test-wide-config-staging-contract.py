#!/usr/bin/env python3
"""Prepared QA only: actual shell leaves + actual Rust metadata command.

No execution has been performed. All host paths in independent-disable/root-
state copies are relocated into one owned temporary fixture. Native routing,
services, service identities and chown are recording seams, not acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import signal
import subprocess
import sys
import tempfile
import time


CONFIG = b'''[ingress]
primary = "wide"

[ingress.wide]
enabled = true
dns_preview_listen = "old"
dns_preview_fake_ip_pool = "old"
dns_preview_fake_ip_ttl_secs = 1
keep = "harmless"


'''
EXPECTED = b'''[ingress]
primary = "wide"

[ingress.wide]
dns_preview_listen = "127.0.0.1:53"
dns_preview_fake_ip_pool = "198.18.0.0/15"
dns_preview_fake_ip_ttl_secs = 60
enabled = true
keep = "harmless"


'''
BACKUP = b'# distinct original recovery record\n[ingress]\nprimary = "socks5"\n'
CHANGED = b'# surviving changed recovery record: do not overwrite\n'
SENTINEL = b'harmless sentinel: no overwrite\n'


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def put(path: Path, data: bytes, permissions: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(permissions)


def executable(path: Path, text: str) -> None:
    put(path, text.encode(), 0o700)


STATE_WRAPPER = r'''#!__PYTHON__
import json, os, pathlib, stat, subprocess, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ['AEGIS_TEST_ROOT'])
assert args[:2] == ['profile', 'metadata']
for i, argument in enumerate(args[:-1]):
    if argument in ('--path', '--snapshot'):
        target = pathlib.Path(args[i + 1])
        assert target.is_absolute() and '..' not in target.parts
        assert str(target).startswith(str(root) + '/')
action = args[2] if len(args) > 2 else ''
path = pathlib.Path(args[args.index('--path') + 1]) if '--path' in args else None
cfg = pathlib.Path(os.environ['AEGIS_CONFIG_FILE'])
if action == 'write' and '--help' in args and os.environ.get('AEGIS_TEST_OLD_WRITER') == '1':
    print('Usage: metadata write --path PATH --mode MODE')
    sys.exit(0)
if os.environ.get('AEGIS_TEST_ROLLBACK_PREFLIGHT_FAIL') == '1' and os.environ.get('AEGIS_WIDE_ROLLBACK_PRESERVE_CONFIG_BACKUP') == '1' and action == 'validate':
    sys.exit(94)
if action == 'write' and path == cfg and '--preserve-mode' not in args:
    if os.environ.get('AEGIS_TEST_COMMIT_FAIL') == 'before':
        sys.exit(95)
if action == 'write' and path == pathlib.Path(str(cfg) + '.aegis-wide-bak') and '--exclusive' in args and os.environ.get('AEGIS_TEST_RESTORE_FAIL') == '1':
    # Original backup is pre-created in this case; only missing-after-teardown
    # exclusive recreation reaches this finite refusal.
    sys.exit(96)
result = subprocess.run([os.environ['AEGIS_TEST_REAL_CLIENT'], *args])
if result.returncode == 0 and action == 'write' and path is not None:
    if path.name in ('original.toml', 'render.toml', 'backup.toml'):
        with open(os.environ['AEGIS_TEST_OBSERVATIONS'], 'a') as output:
            output.write(json.dumps({'role': path.name, 'mode': stat.S_IMODE(path.stat().st_mode), 'parent_mode': stat.S_IMODE(path.parent.stat().st_mode)}) + '\n')
    if path == cfg and '--preserve-mode' not in args and os.environ.get('AEGIS_TEST_COMMIT_FAIL') == 'after':
        sys.exit(97)
    if path == cfg and '--preserve-mode' in args and os.environ.get('AEGIS_TEST_FINAL_SYNC_FAIL') == '1' and os.environ.get('AEGIS_WIDE_ROLLBACK_PRESERVE_CONFIG_BACKUP') != '1':
        # Lawful injection AFTER the actual writer returns, not a claim that
        # a native filesystem fsync error was reproduced.
        sys.exit(98)
sys.exit(result.returncode)
'''

SYSTEMCTL = r'''#!__PYTHON__
import os, pathlib, subprocess, sys
args = sys.argv[1:]
with open(os.environ['AEGIS_TEST_CALLS'], 'a') as output:
    output.write('systemctl ' + ' '.join(args) + '\n')
if args[:1] == ['show']:
    print('missing-fixture-group' if os.environ.get('AEGIS_TEST_UNKNOWN_GROUP') == '1' else '0')
    sys.exit(0)
if args == ['stop', 'aegis-wide.service'] and os.environ.get('AEGIS_TEST_RECURSE') == '1' and os.environ.get('AEGIS_WIDE_DISABLE_FROM_UNIT') != '1':
    # Model a fresh ExecStop environment, not an inherited shell child. This
    # executes the actual relocated disable body, with its existing guard.
    env = os.environ.copy()
    env.pop('AEGIS_WIDE_ROLLBACK_PRESERVE_CONFIG_BACKUP', None)
    env['AEGIS_WIDE_DISABLE_FROM_UNIT'] = '1'
    result = subprocess.run([env['AEGIS_TEST_BASH'], env['AEGIS_TEST_DISABLE']], env=env, timeout=15)
    sys.exit(result.returncode)
if args[:1] == ['daemon-reload'] and os.environ.get('AEGIS_TEST_CHANGED_BACKUP') == '1':
    path = pathlib.Path(os.environ['AEGIS_CONFIG_FILE'] + '.aegis-wide-bak')
    path.write_bytes(b'# surviving changed recovery record: do not overwrite\n')
    path.chmod(0o600)
if args[:1] in (['is-active'], ['is-enabled']):
    sys.exit(1)
sys.exit(0)
'''


class Fixture:
    def __init__(self, directory: Path, source: Path, disable: Path, old_disable: Path, root_state: Path, client: Path, original: bool):
        self.root = directory
        self.original = original
        self.old_disable = old_disable
        self.deadline = time.monotonic() + 300
        self.root.mkdir(mode=0o700)
        self.bin = self.root / 'bin'
        self.lib = self.root / 'lib'
        self.bin.mkdir(mode=0o700)
        (self.lib / 'lib').mkdir(parents=True, mode=0o700)
        self.cfg = self.root / 'host/etc/aegis/client/aegis.toml'
        put(self.cfg, CONFIG, 0o600)
        self.cfg.parent.chmod(0o755)
        self.backup = Path(str(self.cfg) + '.aegis-wide-bak')
        self.calls = self.root / 'calls.log'
        self.observations = self.root / 'observations.jsonl'
        put(self.calls, b'')
        put(self.observations, b'')
        self.env = os.environ.copy()
        # A fixture must not inherit operational overrides or failure seams.
        for key in list(self.env):
            if key.startswith('AEGIS_'):
                del self.env[key]
        self.bash = shutil.which('bash')
        assert self.bash
        self.env.update({
            'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
            'AEGIS_TEST_ROOT': str(self.root),
            'AEGIS_TEST_REAL_CLIENT': str(client),
            'AEGIS_TEST_BASH': self.bash,
            'AEGIS_TEST_DISABLE': str(self.lib / 'aegis-wide-disable.sh'),
            'AEGIS_TEST_CALLS': str(self.calls),
            'AEGIS_TEST_OBSERVATIONS': str(self.observations),
            'AEGIS_ROOT_STATE_CLIENT': str(self.bin / 'state-client'),
            'AEGIS_CONFIG_FILE': str(self.cfg),
            'AEGIS_WIDE_SKIP_ROOT_CHECK': '1',
            'AEGIS_WIDE_SYSCTL_FILE': str(self.root / 'host/etc/sysctl.d/wide.conf'),
            'AEGIS_WIDE_SYSCTL_SNAPSHOT': str(self.root / 'host/var/lib/aegis-install/client/wide.txt'),
            'AEGIS_WIDE_RESOLVER_SNAPSHOT': str(self.root / 'host/var/lib/aegis-install/client/resolver.json'),
            'AEGIS_WIDE_PROFILE_STATE': str(self.root / 'host/var/lib/aegis-install/client/wide-profile.json'),
        })
        for target, text in [(self.lib / 'aegis-wide-disable.sh', disable.read_text()), (self.lib / 'lib/root-state.sh', root_state.read_text())]:
            for prefix in ('/etc/', '/var/lib/', '/run/'):
                text = text.replace(prefix, str(self.root / 'host') + prefix)
            executable(target, text)
        executable(self.bin / 'state-client', STATE_WRAPPER.replace('__PYTHON__', sys.executable))
        executable(self.bin / 'systemctl', SYSTEMCTL.replace('__PYTHON__', sys.executable))
        # These record only finite fixture interactions. They never run native
        # firewall, route, sysctl or service commands.
        for command in ('iptables', 'ip6tables', 'nft', 'ip', 'sysctl'):
            executable(self.bin / command, '''#!/usr/bin/env bash
printf '%s %s\\n' "${0##*/}" "$*" >> "${AEGIS_TEST_CALLS}"
exit 1
''')
        for command in ('iptables-save', 'ip6tables-save'):
            executable(self.bin / command, '#!/usr/bin/env bash\nexit 0\n')
        for helper in ('setup-wide-linux-redirect.sh', 'setup-wide-linux-tproxy.sh', 'janitor-wide-linux-tproxy.sh'):
            executable(self.lib / helper, '#!/usr/bin/env bash\nexit 0\n')
        # Darwin's native sed needs an empty backup suffix for Linux's -i
        # spelling. This is a CLI compatibility shim; no validation or awk
        # algorithm is modeled. Native Linux acceptance remains separate.
        real_sed = shutil.which('sed')
        real_awk = shutil.which('awk')
        real_mv = shutil.which('mv')
        real_chmod = shutil.which('chmod')
        assert all((real_sed, real_awk, real_mv, real_chmod))
        executable(self.bin / 'sed', f'''#!/usr/bin/env bash
if [[ "${{OSTYPE:-}}" == darwin* && "${{1:-}}" == -i ]]; then
    shift
    exec {json.dumps(real_sed)} -i '' "$@"
fi
exec {json.dumps(real_sed)} "$@"
''')
        executable(self.bin / 'awk', f'''#!/usr/bin/env bash
if [[ "${{AEGIS_TEST_AWK_FAIL:-0}}" == 1 && "${{1:-}}" != -F: ]]; then
    printf '# partial harmless render\\n'
    exit 73
fi
exec {json.dumps(real_awk)} "$@"
''')
        real_id = shutil.which('id')
        assert real_id
        executable(self.bin / 'id', f'''#!/usr/bin/env bash
# Service identities are recording seams only. No-operand euid reads used by
# trusted-executable validation still run the real current-euid command.
if [[ "${{1:-}}" == -u && ( "${{2:-}}" == 0 || "${{2:-}}" == 1 ) ]]; then
    printf '%s\\n' "$2"
    exit 0
fi
exec {json.dumps(real_id)} "$@"
''')
        executable(self.bin / 'getent', '''#!/usr/bin/env bash
[[ "$*" == 'group 0' ]] || exit 2
printf 'root:x:0:\\n'
''')
        executable(self.bin / 'chown', '''#!/usr/bin/env bash
printf 'chown %s\\n' "$*" >> "${AEGIS_TEST_CALLS}"
[[ "${AEGIS_TEST_CHOWN_FAIL:-0}" != 1 ]]
''')
        executable(self.bin / 'chmod', f'''#!/usr/bin/env bash
if [[ "${{AEGIS_TEST_CHMOD_FAIL:-0}}" == 1 && "${{2:-}}" == "${{AEGIS_CONFIG_FILE}}" ]]; then exit 75; fi
exec {json.dumps(real_chmod)} "$@"
''')
        executable(self.bin / 'mv', f'''#!{sys.executable}
import json, os, pathlib, stat, subprocess, sys
p = pathlib.Path(sys.argv[1])
with open(os.environ['AEGIS_TEST_OBSERVATIONS'], 'a') as output:
    output.write(json.dumps({{'role': 'legacy.tmp', 'mode': stat.S_IMODE(p.stat().st_mode), 'parent_mode': stat.S_IMODE(p.parent.stat().st_mode)}}) + '\\n')
sys.exit(subprocess.run([{real_mv!r}, *sys.argv[1:]]).returncode)
''')
        selected = source.read_text()
        if original:
            self.leaf = selected
        else:
            start = selected.index('# ---------- private DNS-preview configuration ----------')
            end = selected.index('# ---------- end private DNS-preview configuration ----------', start)
            self.leaf = selected[start:end]
        self.driver = self.root / 'driver.sh'

    def run(self, action: str = 'commit', preflight: bool = False) -> int:
        if action == 'disable':
            command = [self.bash, str(self.lib / 'aegis-wide-disable.sh')]
        else:
            head = 'set -uo pipefail\numask 022\nSCRIPT_DIR=' + json.dumps(str(self.lib)) + '\ndns_choice=preview\nAEGIS_UID="${AEGIS_TEST_UID-0}"\n'
            head += '. "${SCRIPT_DIR}/lib/root-state.sh"\n'
            if preflight:
                head += 'aegis_root_network_preflight || exit 1\n'
            if action == 'preflight':
                body = head
            else:
                # Original adapter preserves the complete original leaf body;
                # candidate is the complete actual helper block and wiring.
                body = head + self.leaf + '\n'
                if self.original:
                    body += 'aegis_wide_config_prepare || exit 1\n'
                body += 'aegis_wide_config_commit || aegis_wide_config_failed\n'
            put(self.driver, body.encode(), 0o700)
            command = [self.bash, str(self.driver)]
        with open(self.root / 'stdout.log', 'wb') as output, open(self.root / 'stderr.log', 'wb') as errors:
            child = subprocess.Popen(command, env=self.env, stdout=output, stderr=errors, start_new_session=True)
            try:
                return child.wait(timeout=max(0.001, min(25, self.deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                # Signal only this newly created owned fixture group. There
                # are no pipes to wait on. A bounded kill/reap is attempted;
                # failure is never described as joined/clean acceptance.
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=3)
                raise

    def logged(self) -> str:
        return self.calls.read_text()

    def mutations(self) -> list[str]:
        # The actual preparation may query the service's group read-only.
        # Every other recorded callback is treated as a mutation.
        return [line for line in self.logged().splitlines() if not line.startswith('systemctl show ')]

    def records(self) -> list[dict]:
        return [json.loads(line) for line in self.observations.read_text().splitlines()]

    def retained(self) -> list[Path]:
        return list(self.cfg.parent.glob('.aegis-wide-config.*/backup.toml'))


def shared_case(name: str, f: Fixture) -> None:
    if name == 'private_stage':
        assert f.run() == 0
        records = f.records()
        assert records and all(row['mode'] == 0o600 and row['parent_mode'] == 0o700 for row in records)
        assert not list(f.cfg.parent.glob('.aegis-wide-config.*'))
    elif name == 'legacy_tmp_symlink':
        target = f.root / 'sentinel'
        put(target, SENTINEL, 0o640)
        link = Path(str(f.cfg) + '.tmp')
        link.symlink_to(target)
        assert f.run() == 0
        assert target.read_bytes() == SENTINEL and mode(target) == 0o640
        assert link.is_symlink() and link.resolve() == target
        assert f.cfg.is_file() and not f.cfg.is_symlink() and f.cfg.read_bytes() == EXPECTED
    elif name == 'failed_render_preserves_live':
        f.env['AEGIS_TEST_AWK_FAIL'] = '1'
        assert f.run() != 0
        assert f.cfg.read_bytes() == CONFIG and mode(f.cfg) == 0o600
        assert not f.backup.exists() and not f.mutations() and not list(f.cfg.parent.glob('.aegis-wide-config.*'))
    elif name == 'regular_output_repeat':
        assert f.run() == 0 and f.cfg.read_bytes() == EXPECTED
        assert f.backup.read_bytes() == CONFIG and mode(f.backup) == 0o600
        assert f.run() == 0 and f.cfg.read_bytes() == EXPECTED
        assert f.backup.read_bytes() == CONFIG
    elif name == 'existing_distinct_backup':
        put(f.backup, BACKUP)
        assert f.run() == 0 and f.cfg.read_bytes() == EXPECTED
        assert f.backup.read_bytes() == BACKUP
    elif name == 'no_section':
        original = b'# harmless\nkeep = "same"\n\n\n'
        put(f.cfg, original)
        assert f.run() == 0 and f.cfg.read_bytes() == original
        assert f.backup.read_bytes() == original
        assert b'[ingress.wide] section not found' in (f.root / 'stderr.log').read_bytes()
    elif name == 'missing_preview_config':
        f.cfg.unlink()
        assert f.run() != 0
        assert not f.cfg.exists() and not f.backup.exists() and not f.mutations()
        assert not list(f.cfg.parent.glob('.aegis-wide-config.*'))
    elif name in ('unknown_uid', 'unknown_group', 'missing_exclusive'):

        f.env[{'unknown_uid': 'AEGIS_TEST_UID', 'unknown_group': 'AEGIS_TEST_UNKNOWN_GROUP', 'missing_exclusive': 'AEGIS_TEST_OLD_WRITER'}[name]] = '' if name == 'unknown_uid' else '1'
        assert f.run() != 0
        assert f.cfg.read_bytes() == CONFIG and not f.backup.exists()
        assert not f.mutations()
    else:
        raise AssertionError('unknown shared case')


def controls_case(name: str, f: Fixture) -> None:
    if name in ('full_preflight_symlink', 'full_preflight_hardlink', 'full_preflight_writable', 'full_preflight_ancestor_link'):
        if name == 'full_preflight_symlink':
            target = f.root / 'sentinel'
            put(target, SENTINEL, 0o640)
            Path(str(f.cfg) + '.tmp').symlink_to(target)
        elif name == 'full_preflight_ancestor_link':
            real_parent = f.cfg.parent.with_name('real-client')
            f.cfg.parent.rename(real_parent)
            f.cfg.parent.symlink_to(real_parent, target_is_directory=True)
        elif name == 'full_preflight_hardlink':
            os.link(f.cfg, Path(str(f.cfg) + '.tmp'))
        else:
            put(Path(str(f.cfg) + '.tmp'), SENTINEL, 0o622)
        assert f.run('preflight', preflight=True) != 0
        assert not f.logged() and f.cfg.read_bytes() == CONFIG
        if name == 'full_preflight_symlink':
            assert target.read_bytes() == SENTINEL and mode(target) == 0o640
    elif name in ('old_rollback_helper', 'missing_rollback_helper', 'untrusted_rollback_helper'):
        helper = f.lib / 'aegis-wide-disable.sh'
        if name == 'old_rollback_helper':
            text = f.old_disable.read_text()
            for prefix in ('/etc/', '/var/lib/', '/run/'):
                text = text.replace(prefix, str(f.root / 'host') + prefix)
            executable(helper, text)
        elif name == 'missing_rollback_helper':
            helper.unlink()
        else:
            helper.chmod(0o777)
        assert f.run() != 0 and f.cfg.read_bytes() == CONFIG and mode(f.cfg) == 0o600
        assert not f.backup.exists() and not f.mutations()
        assert not list(f.cfg.parent.glob('.aegis-wide-config.*'))
    elif name == 'actual_exclusive_refusal':

        target = f.root / 'exclusive-sentinel'
        put(target, SENTINEL)
        result = subprocess.run([str(f.bin / 'state-client'), 'profile', 'metadata', 'write', '--path', str(target), '--mode', '0600', '--exclusive'], input=b'# refused harmless replacement\n', env=f.env, capture_output=True, timeout=5)
        assert result.returncode != 0 and target.read_bytes() == SENTINEL and mode(target) == 0o600
    elif name == 'recorded_nonroot_service_mode':
        # UID/GID lookup and chown are recording seams. The actual Rust
        # boundary still checks the fixture process's real administrative euid.
        f.env['AEGIS_TEST_UID'] = '1'
        assert f.run(preflight=True) == 0
        assert mode(f.cfg) == 0o640 and f.backup.read_bytes() == CONFIG
        assert 'chown root:0 ' in f.logged()
    elif name.startswith('late_'):
        put(f.backup, BACKUP)
        if name == 'late_before_publish': f.env['AEGIS_TEST_COMMIT_FAIL'] = 'before'
        if name == 'late_after_publish': f.env['AEGIS_TEST_COMMIT_FAIL'] = 'after'
        if name == 'late_chown': f.env['AEGIS_TEST_CHOWN_FAIL'] = '1'
        if name == 'late_chmod': f.env['AEGIS_TEST_CHMOD_FAIL'] = '1'
        if name == 'late_final_sync': f.env['AEGIS_TEST_FINAL_SYNC_FAIL'] = '1'
        if name in ('late_fresh_unit_restore', 'late_changed_survivor', 'late_restore_refused'):
            f.env['AEGIS_TEST_COMMIT_FAIL'] = 'after'
            f.env['AEGIS_TEST_RECURSE'] = '1'
        if name == 'late_changed_survivor': f.env['AEGIS_TEST_CHANGED_BACKUP'] = '1'
        if name == 'late_restore_refused': f.env['AEGIS_TEST_RESTORE_FAIL'] = '1'
        if name == 'late_rollback_preflight':
            f.env['AEGIS_TEST_COMMIT_FAIL'] = 'after'
            f.env['AEGIS_TEST_ROLLBACK_PREFLIGHT_FAIL'] = '1'
        assert f.run(preflight=True) == 5
        assert 'systemctl disable aegis-wide.service' in f.logged()
        snapshots = f.retained()
        if name in ('late_changed_survivor', 'late_restore_refused'):
            assert len(snapshots) == 1 and snapshots[0].read_bytes() == BACKUP
            assert mode(snapshots[0]) == 0o600 and mode(snapshots[0].parent) == 0o700
            assert sorted(path.name for path in snapshots[0].parent.iterdir()) == ['backup.toml']
            assert str(snapshots[0]).encode() in (f.root / 'stderr.log').read_bytes()
            assert 'systemctl stop aegis-client' in f.logged()
            if name == 'late_changed_survivor': assert f.backup.read_bytes() == CHANGED
            else: assert not f.backup.exists()
        else:
            assert f.backup.read_bytes() == BACKUP and mode(f.backup) == 0o600
            assert not snapshots and not list(f.cfg.parent.glob('.aegis-wide-config.*'))
            if name == 'late_rollback_preflight': assert 'systemctl stop aegis-client' in f.logged()
            else: assert b'primary = "socks5"' in f.cfg.read_bytes()
    elif name in ('disable_default_removes', 'disable_preserves', 'disable_invalid_flag'):
        put(f.backup, BACKUP)
        if name == 'disable_preserves': f.env['AEGIS_WIDE_ROLLBACK_PRESERVE_CONFIG_BACKUP'] = '1'
        if name == 'disable_invalid_flag': f.env['AEGIS_WIDE_ROLLBACK_PRESERVE_CONFIG_BACKUP'] = 'true'
        result = f.run('disable')
        if name == 'disable_invalid_flag':
            assert result == 2 and not f.logged() and f.backup.read_bytes() == BACKUP
            assert f.cfg.read_bytes() == CONFIG
        else:
            assert result == 0 and b'primary = "socks5"' in f.cfg.read_bytes()
            if name == 'disable_preserves': assert f.backup.read_bytes() == BACKUP
            else: assert not f.backup.exists()
    else:
        raise AssertionError('unknown control case')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--leaf', type=Path, required=True, help='Original adapter or candidate full enable source')
    parser.add_argument('--disable', type=Path, required=True)
    parser.add_argument('--original-disable', type=Path, required=True, help='Exact contemporaneous original disable preimage')
    parser.add_argument('--root-state', type=Path, required=True)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--original', action='store_true')
    parser.add_argument('--controls-only', action='store_true')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    client = args.client.resolve(strict=True)
    assert client.is_file() and os.access(client, os.X_OK)
    shared = ['private_stage', 'legacy_tmp_symlink', 'failed_render_preserves_live', 'regular_output_repeat', 'existing_distinct_backup', 'no_section', 'unknown_uid', 'unknown_group', 'missing_exclusive', 'missing_preview_config']
    controls = ['old_rollback_helper', 'missing_rollback_helper', 'untrusted_rollback_helper', 'recorded_nonroot_service_mode', 'full_preflight_symlink', 'full_preflight_hardlink', 'full_preflight_writable', 'full_preflight_ancestor_link', 'actual_exclusive_refusal', 'late_before_publish', 'late_after_publish', 'late_chown', 'late_chmod', 'late_final_sync', 'late_fresh_unit_restore', 'late_changed_survivor', 'late_restore_refused', 'late_rollback_preflight', 'disable_default_removes', 'disable_preserves', 'disable_invalid_flag']
    names = controls if args.controls_only else shared
    assert not (args.original and args.controls_only), 'candidate controls are separate from the paired original leaf'
    started = time.monotonic()
    rows = []
    fixture_root = Path(tempfile.mkdtemp(prefix='aegis44-qa-')).resolve()
    fixture_root.chmod(0o700)
    try:
        for name in names:
            assert time.monotonic() - started < 300, 'original outer QA bound exhausted'
            f = Fixture(fixture_root / name, args.leaf.resolve(), args.disable.resolve(), args.original_disable.resolve(), args.root_state.resolve(), client, args.original)
            f.deadline = started + 300
            row = {'case': name, 'state': 'PASS'}
            try:
                (controls_case if args.controls_only else shared_case)(name, f)
            except Exception as error:
                row['state'] = 'FAIL'
                row['error_type'] = type(error).__name__
                # Only bounded synthetic-fixture logs are copied. No TOML
                # bytes or deployment secrets are emitted into the receipt.
            for filename in ('stdout.log', 'stderr.log', 'calls.log', 'observations.jsonl'):
                path = f.root / filename
                if path.exists():
                    data = path.read_bytes()
                    assert len(data) <= 262144, 'fixture log bound exceeded'
                    put(args.out / name / filename, data)
            row['retained_recovery_copy_count'] = len(f.retained())
            # A test's owned root is eventually deleted by the harness; the
            # assertion proves the PRODUCT EXIT cleanup retained its copy.
            rows.append(row)
            print(name + ': ' + row['state'], flush=True)
    finally:
        shutil.rmtree(fixture_root)
    receipt = {'state': 'PREPARED_QA_RUN_RESULT', 'finding_id': 44, 'original': args.original, 'controls_only': args.controls_only, 'elapsed_seconds': time.monotonic() - started, 'sources': {str(path): digest(path) for path in (args.leaf, args.disable, args.original_disable, args.root_state, args.client)}, 'tests_sha256': digest(Path(__file__)), 'cases': rows, 'native_routing_or_root_identity_acceptance': False, 'limitations': ['Darwin Linux-sed CLI shim only; routing/service/chown/getent are bounded recording seams.', 'Actual metadata command handles fixture custody; leaf hostile.tmp does not bypass existing full preflight.', 'Post-publish error is finite lawful injection after real writer completion, not reproduced native fsync failure.', 'No real cross-UID access, firewall/capture/route acceptance, rollback native success, or beta claim.']}
    put(args.out / 'receipt.json', (json.dumps(receipt, indent=2) + '\n').encode())
    return 0 if all(row['state'] == 'PASS' for row in rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
