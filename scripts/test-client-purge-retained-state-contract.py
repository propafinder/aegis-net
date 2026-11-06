#!/usr/bin/env python3
"""Offline whole-leaf removal/report contract; all seeded state is synthetic."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

CASES = (
    'uninstall_purge_report', 'uninstall_retained_only_report',
    'purge_force_report', 'purge_dry_run_report',
    'uninstall_leftover_refusal', 'selected_ownership_refusal',
    'retained_symlink_metadata',
)
IDENTITY = '/var/lib/aegis-identity/client'
FLOOR = '/var/lib/aegis-install/releases'
RETAINED = {
    IDENTITY + '/synthetic-identity': b'AUDIT81_SYNTHETIC_IDENTITY_PRIVATE\x00\n',
    FLOOR + '/synthetic-floor': b'AUDIT81_SYNTHETIC_FLOOR_PRIVATE\x00\n',
}
INSTALLED = {
    '/usr/local/bin/aegis-client': b'inert-client\n',
    '/etc/aegis/client/aegis.toml': b'synthetic-config\n',
    '/var/lib/aegis-client/runtime': b'synthetic-runtime\n',
    '/var/lib/aegis-install/client/receipt': b'synthetic-receipt\n',
    '/var/log/aegis-client/event': b'synthetic-event\n',
    '/etc/systemd/system/aegis-client.service': b'inert-unit\n',
}
SERVER = '/etc/aegis/server/synthetic-server'
UNRELATED = '/opt/unrelated/sentinel'
MAIN_MARKER = '\ninfo "AEGIS purge scope"\n'


class Invalid(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def put(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as f:
        f.write(data)
    path.chmod(mode)


def members(pgid, deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise Invalid('group_observation_deadline')
    r = subprocess.run(['/bin/ps', '-axo', 'pid=,pgid=,stat='],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       timeout=min(left, 0.5), check=True)
    found = []
    for line in r.stdout.decode('ascii').splitlines():
        row = line.split()
        if len(row) == 3 and int(row[1]) == pgid:
            found.append((int(row[0]), row[2]))
    return found


def run_owned(command, env, directory, label):
    """Retain the child leader until final group signals; one 10s + 4s cleanup."""
    if not all(hasattr(os, n) for n in ('waitid', 'WNOWAIT', 'WEXITED', 'P_PID')):
        raise Invalid('waitid_wnowait_unavailable')
    log = directory / (label + '.log')
    start = time.monotonic()
    body_deadline = start + 10.0
    child = None
    record = {'body_bound_seconds': 10, 'cleanup_bound_seconds': 4,
              'group_confirmed': False, 'reaped': False}
    body_error = None
    cleanup_error = None
    with log.open('xb') as out:
        log.chmod(0o600)
        child = subprocess.Popen(command, env=env, cwd=directory,
                                 stdin=subprocess.DEVNULL, stdout=out, stderr=out,
                                 start_new_session=True)
        record['pid'] = child.pid
        try:
            if os.getpgid(child.pid) != child.pid:
                raise Invalid('child_group_identity_not_owned')
            while True:
                observed = os.waitid(os.P_PID, child.pid,
                                     os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None:
                    record['exit_observed_before_reap'] = True
                    break
                if time.monotonic() >= body_deadline:
                    raise Invalid('whole_leaf_body_timeout')
                time.sleep(0.01)
        except BaseException as err:
            body_error = err
        finally:
            cleanup_deadline = time.monotonic() + 4.0
            try:
                row = members(child.pid, cleanup_deadline)
                if not any(pid == child.pid for pid, _ in row):
                    raise Invalid('reserved_leader_not_observed')
                active = [(pid, state) for pid, state in row
                          if pid != child.pid or not state.startswith('Z')]
                if active:
                    os.killpg(child.pid, signal.SIGTERM)
                    term_until = min(cleanup_deadline, time.monotonic() + 0.25)
                    while active and time.monotonic() < term_until:
                        time.sleep(0.01)
                        row = members(child.pid, cleanup_deadline)
                        active = [(pid, state) for pid, state in row
                                  if pid != child.pid or not state.startswith('Z')]
                    if active:
                        os.killpg(child.pid, signal.SIGKILL)
                    while True:
                        row = members(child.pid, cleanup_deadline)
                        active = [(pid, state) for pid, state in row
                                  if pid != child.pid or not state.startswith('Z')]
                        if not active:
                            break
                        time.sleep(0.01)
                record['observed_group_members_before_reap'] = row
                record['group_confirmed'] = True
                remaining = cleanup_deadline - time.monotonic()
                if remaining <= 0:
                    raise Invalid('cleanup_reap_deadline_exhausted')
                record['returncode'] = child.wait(timeout=remaining)
                record['reaped'] = True
            except BaseException as err:
                cleanup_error = err
                record['cleanup_error_type'] = type(err).__name__
                # Observation failure never establishes group quiescence.
                # Verify the child is still ours and unreaped before signaling;
                # use only what remains of this same original cleanup deadline.
                try:
                    os.waitid(os.P_PID, child.pid,
                              os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    record['fallback_reserved_leader_checked'] = True
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                        record['fallback_kill_sent'] = True
                    except ProcessLookupError:
                        record['fallback_group_signal_missing'] = True
                    left = cleanup_deadline - time.monotonic()
                    if left > 0:
                        record['returncode'] = child.wait(timeout=left)
                        record['reaped'] = True
                    else:
                        record['fallback_reap_deadline_exhausted'] = True
                except BaseException as fallback_err:
                    record['fallback_error_type'] = type(fallback_err).__name__
            record['wall_seconds'] = time.monotonic() - start
            record['log_sha256'] = digest(log.read_bytes())
            put(directory / (label + '-process.json'),
                (json.dumps(record, sort_keys=True, indent=2) + '\n').encode())
    if cleanup_error is not None:
        raise Invalid('cleanup_unconfirmed') from cleanup_error
    if body_error is not None:
        raise Invalid('body_not_accepted') from body_error
    return record['returncode'], log.read_bytes().decode('utf-8')


class Fixture:
    def __init__(self, directory, source, bash):
        self.directory = directory
        self.root = directory / 'root'
        self.root.mkdir(mode=0o700)
        self.runtime = directory / 'runtime-tmp'
        self.runtime.mkdir(mode=0o700)
        self.bin = directory / 'bin'
        self.bin.mkdir(mode=0o700)
        self.source = source
        self.bash = bash
        scripts = {
            'dpkg': '#!/bin/sh\nexit 1\n',
            'systemctl': '#!/bin/sh\ncase "$1" in is-active) exit 3;; esac\nexit 0\n',
            'inert-native': '#!/bin/sh\nexit 1\n',
        }
        for name, text in scripts.items():
            put(self.bin / name, text.encode(), 0o700)
        self.env = {'PATH': str(self.bin) + ':/usr/bin:/bin',
                    'TMPDIR': str(self.runtime), 'LANG': 'C',
                    'AEGIS_UNINSTALL_FAKE_ROOT': str(self.root),
                    'AEGIS_UNINSTALL_SKIP_ROOT_CHECK': '1',
                    'AEGIS_PURGE_ROOT': str(self.root),
                    'AEGIS_PURGE_TMPDIR': str(self.runtime)}
        for name in ('SYSTEMCTL', 'IPTABLES', 'IP6TABLES', 'NFT', 'IP',
                     'PKILL', 'USERDEL', 'GROUPDEL'):
            self.env['AEGIS_PURGE_' + name + '_BIN'] = str(
                self.bin / ('systemctl' if name == 'SYSTEMCTL' else 'inert-native'))
        self.files = dict(RETAINED)
        self.files[SERVER] = b'co-located-server-preserved\n'
        self.files[UNRELATED] = b'unrelated-preserved\n'
        for name, data in self.files.items():
            put(self.path(name), data)

    def path(self, absolute):
        return self.root / absolute.lstrip('/')

    def install(self):
        for name, data in INSTALLED.items():
            put(self.path(name), data)

    def unchanged(self):
        for name, data in self.files.items():
            p = self.path(name)
            assert p.read_bytes() == data, 'retained_or_unrelated_bytes_changed'
            assert stat.S_IMODE(p.stat().st_mode) == 0o600, 'retained_leaf_mode_changed'
        for root, leaf in ((IDENTITY, 'synthetic-identity'), (FLOOR, 'synthetic-floor')):
            parent = self.path(root)
            assert sorted(p.name for p in parent.iterdir()) == [leaf], 'retained_tree_entries_changed'
            assert stat.S_IMODE(parent.stat().st_mode) == 0o700, 'retained_directory_mode_changed'

    def removed(self):
        for name in INSTALLED:
            assert not self.path(name).exists(), 'selected_client_installation_not_removed'

    def uninstall(self, action):
        return run_owned([str(self.bash), str(self.source / 'scripts/aegis-ubuntu-uninstall.sh'), action],
                         self.env, self.directory, 'uninstall-' + action)

    def purge(self, force):
        raw = (self.source / 'scripts/purge-installed-aegis.sh').read_bytes()
        text = raw.decode()
        if text.count(MAIN_MARKER) != 1:
            raise Invalid('actual_main_extraction_not_unique')
        prefix, suffix = text.split(MAIN_MARKER, 1)
        # The original native function contains an unprefixed /run read/removal.
        # Replace only that native callback after the entire actual prefix.
        # Selected filesystem removals and the entire actual main remain real.
        seam = '''
cleanup_client_networking() {
  [[ -f "$(path_in_root /usr/local/bin/aegis-client)" ]] || return 97
  printf '%s\\n' 'native_cleanup_callback_before_selected_deletion' > "$AEGIS_AUDIT81_CALLBACK_LOG"
}
'''
        staged = self.directory / 'actual-purge-with-native-callback-seam.sh'
        put(staged, (prefix + seam + MAIN_MARKER + suffix).encode())
        put(self.directory / 'actual-purge-extraction.json', (json.dumps({
            'source_sha256': digest(raw), 'actual_prefix_sha256': digest(prefix.encode()),
            'actual_main_sha256': digest((MAIN_MARKER + suffix).encode()),
            'native_callback_seam_sha256': digest(seam.encode()),
            'staged_sha256': digest(staged.read_bytes()),
            'no_native_network_teardown_proof': True,
        }, sort_keys=True, indent=2) + '\n').encode())
        env = dict(self.env, AEGIS_AUDIT81_CALLBACK_LOG=str(self.directory / 'callback.log'))
        command = [str(self.bash), str(staged), 'client'] + (['--force'] if force else [])
        rc, output = run_owned(command, env, self.directory, 'purge')
        if rc == 0:
            assert (self.directory / 'callback.log').read_text() == 'native_cleanup_callback_before_selected_deletion\n'
        return rc, output


def report(output, scope, identity_status='present'):
    lines = output.splitlines()
    assert 'removal_scope=' + scope + ' full_erasure=not-claimed' in lines, 'missing_explicit_removal_scope'
    for kind, path, status in (('device-identity', IDENTITY, identity_status),
                               ('release-floor', FLOOR, 'present')):
        assert f'retained_state={kind} path={path} status={status} retention=preserve' in lines, 'missing_retained_state_metadata'
    assert 'retained_state_scope=standard-system-paths custom_identity=not-scanned per_user_state=not-scanned' in lines, 'missing_unscanned_scope'
    for data in RETAINED.values():
        assert data.decode() not in output and data.split(b'\x00')[0].decode() not in output, 'retained_content_disclosed'


def check_case(name, f):
    if name in ('uninstall_purge_report', 'purge_force_report', 'purge_dry_run_report',
                'uninstall_leftover_refusal', 'selected_ownership_refusal'):
        f.install()
    if name == 'uninstall_purge_report':
        rc, out = f.uninstall('purge')
        assert rc == 0 and 'result=PASS' in out.splitlines(), 'supported_removal_failed'
        f.removed(); f.unchanged()
        assert 'verify=PASS leftovers=0 scope=client-installation full_erasure=not-claimed' in out.splitlines(), 'unscoped_zero_leftovers'
        report(out, 'client-installation')
    elif name == 'uninstall_retained_only_report':
        rc, out = f.uninstall('verify')
        assert rc == 0 and any(s.startswith('result=PASS_VACUOUS') for s in out.splitlines()), 'retained_only_scoped_checks_failed'
        f.unchanged()
        report(out, 'client-installation')
        assert 'host is clean' not in out, 'retained_only_full_host_claim'
    elif name in ('purge_force_report', 'purge_dry_run_report'):
        force = name == 'purge_force_report'
        rc, out = f.purge(force)
        assert rc == 0 and 'AEGIS purge helper finished' in out, 'actual_role_removal_failed'
        if force:
            f.removed()
        else:
            for path, data in INSTALLED.items():
                assert f.path(path).read_bytes() == data, 'dry_run_mutated_installation'
            assert 'mode: dry-run' in out, 'dry_run_not_identified'
        f.unchanged()
        report(out, 'selected-installation role=client')
    elif name == 'uninstall_leftover_refusal':
        rc, out = f.uninstall('verify')
        assert rc == 1 and 'result=FAIL' in out.splitlines(), 'leftover_false_success'
        assert not any(s.startswith('verify=PASS ') for s in out.splitlines()), 'leftover_false_zero'
        for path, data in INSTALLED.items():
            assert f.path(path).read_bytes() == data, 'verify_mutated_installation'
        f.unchanged()
    elif name == 'selected_ownership_refusal':
        selected = '/var/lib/aegis-install/client/relay-geneva-profile.json'
        put(f.path(selected), b'inert-selected-ownership\n')
        for rc, out in (f.uninstall('purge'), f.purge(True)):
            assert rc == 1 and 'separately reviewed teardown' in out, 'selected_ownership_not_refused'
        for path, data in INSTALLED.items():
            assert f.path(path).read_bytes() == data, 'selected_ownership_mutated_installation'
        assert f.path(selected).read_bytes() == b'inert-selected-ownership\n', 'selected_ownership_removed'
        f.unchanged()
    elif name == 'retained_symlink_metadata':
        identity = f.path(IDENTITY)
        moved = f.directory / 'identity-target'
        identity.rename(moved)
        identity.symlink_to(moved, target_is_directory=True)
        rc, out = f.uninstall('verify')
        assert rc == 0, 'scoped_verify_failed_for_retained_metadata'
        f.unchanged()
        report(out, 'client-installation', 'symlink')
        assert str(moved) not in out, 'retained_symlink_target_disclosed'
    else:
        raise Invalid('unknown_case')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--bash', required=True, type=Path)
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True)
    bash = args.bash.resolve(strict=True)
    if not bash.is_file() or not os.access(bash, os.X_OK):
        raise Invalid('actual_bash_missing')
    if not args.output.is_absolute() or args.output.parent.is_symlink() or not args.output.parent.is_dir():
        raise Invalid('fresh_absolute_output_parent_required')
    args.output.mkdir(mode=0o700)
    rows = []
    source_pins = {}
    for name in ('scripts/aegis-ubuntu-uninstall.sh', 'scripts/purge-installed-aegis.sh'):
        p = source / name
        if p.is_symlink() or not p.is_file():
            raise Invalid('source_leaf_not_regular')
        source_pins[name] = digest(p.read_bytes())
        put(args.output / ('source-' + p.name), p.read_bytes())
    for name in CASES:
        directory = args.output / name
        directory.mkdir(mode=0o700)
        try:
            check_case(name, Fixture(directory, source, bash))
            rows.append({'case': name, 'status': 'PASS'})
        except AssertionError as err:
            rows.append({'case': name, 'status': 'FAIL', 'assertion': str(err)})
        except BaseException as err:
            rows.append({'case': name, 'status': 'INVALID', 'error_type': type(err).__name__})
            for not_run in CASES[len(rows):]:
                rows.append({'case': not_run, 'status': 'NOT_RUN'})
            break
    stable = all(digest((source / name).read_bytes()) == value
                 for name, value in source_pins.items())
    result = {'schema': 'audit81-retained-state-contract-v1', 'cases': rows,
              'source_pins': source_pins, 'source_unchanged': stable,
              'bash_sha256': digest(bash.read_bytes()),
              'native_cleanup_callback_seamed': True,
              'group_scope': 'observed-owned-process-group; daemon escape not proven',
              'full_erasure_proven': False, 'native_host_teardown_proven': False}
    put(args.output / 'summary.json', (json.dumps(result, indent=2, sort_keys=True) + '\n').encode())
    counts = {status: sum(row['status'] == status for row in rows)
              for status in ('PASS', 'FAIL', 'INVALID', 'NOT_RUN')}
    print(json.dumps({'cases': len(rows), **counts, 'source_unchanged': stable}, sort_keys=True))
    return 0 if stable and counts == {'PASS': len(CASES), 'FAIL': 0, 'INVALID': 0, 'NOT_RUN': 0} else 1


if __name__ == '__main__':
    raise SystemExit(main())
