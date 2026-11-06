#!/usr/bin/env python3
"""Installed B-02 guardian transport and held deny lease.

Only a root-owned installation may run this process.  A response on the
socket is useful only while the caller keeps that socket and its original
stage/install/guard locks open.  Serialized digests do not reconstruct a
lease.  Native proof lives in ``aegis_auto_native_witness`` and must refuse
when a packet trace or independent sink is unavailable.
"""

from __future__ import annotations

import array
import dataclasses
import types
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import select
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
from types import SimpleNamespace
import time
import tomllib
from pathlib import Path


ROOT = Path("/usr/local/lib/aegis/helpers/lib")
SOURCE = ROOT / "aegis_auto_guardian.py"
WITNESS = ROOT / "aegis_auto_native_witness.py"
SINK_SOURCE = ROOT / "aegis_auto_sink.py"
ROLLBACK_SOURCE = ROOT / "aegis_auto_trace_rollback.py"
CAPTURE_SOURCE = ROOT / "aegis_auto_capture.py"
TOPOLOGY_SOURCE = ROOT / "aegis_auto_witness_topology.py"
CAPTURE_TOPOLOGY_SOURCE = ROOT / "aegis_auto_capture_topology.py"
ENDPOINT_SOURCE = ROOT / "aegis_auto_endpoint.py"
POLICY_SOURCE = ROOT / "aegis_auto_guard_policy.py"
LAUNCH_SOURCE = ROOT / "aegis_auto_launch.py"
WATCHDOG_SOURCE = ROOT / "aegis_auto_guardian_watchdog.py"
FOREIGN_SOURCE = ROOT / "aegis_auto_foreign_policy.py"
FOREIGN_MONITOR_SOURCE = ROOT / "aegis_auto_foreign_monitor.py"
UFW_PINS_SOURCE = ROOT / "aegis_auto_ufw_pins.json"
INITRD_SOURCE = ROOT / "aegis_initrd_policy.py"
FOREIGN_UNIT_FILE = Path("/etc/systemd/system") / "aegis-foreign-policy-monitor.service"
GUARD_HELPER = Path("/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh")
GUARD_UNIT_FILE = Path("/etc/systemd/system/aegis-device-egress-guard.service")
DHCP_REFRESH_SERVICE_FILE = Path("/etc/systemd/system/aegis-device-dhcp-refresh.service")
DHCP_REFRESH_TIMER_FILE = Path("/etc/systemd/system/aegis-device-dhcp-refresh.timer")
GUARDIAN_UNIT_FILE = Path("/etc/systemd/system/aegis-auto-guardian.service")
WATCHDOG_UNIT_FILE = Path("/etc/systemd/system/aegis-auto-guardian-watchdog.service")
TOPOLOGY_UNIT_FILE = Path("/etc/systemd/system/aegis-auto-witness-topology.service")
CAPTURE_TOPOLOGY_UNIT_FILE = Path("/etc/systemd/system/aegis-auto-capture-topology.service")
RUNTIME = Path("/run/aegis-auto-guard")
SOCKET = RUNTIME / "authority.sock"
SINGLETON = RUNTIME / "guardian.lock"
INSTALL = Path("/var/lib/aegis-install/client/auto-guardian-install.json")
POLICY = Path("/var/lib/aegis-install/client/auto-guardian-policy.json")
STOP_INTENT = Path("/var/lib/aegis-install/client/auto-stop-intent.json")
TERMINAL_MIGRATION_PENDING = INSTALL.parent / 'terminal-migrations/pending.json'
GUARD_LOCK = Path("/var/lib/aegis-install/client/device-guard.conf.lock")
ASSESSMENT_LOCK = GUARD_LOCK.with_name("device-guard.conf.assessment.lock")
INSTALL_LOCK = Path("/run/aegis-auto-install.lock")
SPLIT = Path("/var/lib/aegis-install/client/device-guard.conf.auto-lease-split")
ROTATION_INTENT = INSTALL.parent / "auto-guard-rotation-intent.json"
ROTATION_DENIED = INSTALL.parent / "auto-guard-rotation-denied.json"
ROTATION_ACTOR_INTENT = INSTALL.parent / "auto-guard-rotation-actor-intent.json"
ROTATION_RETIRED = INSTALL.parent / "auto-guard-rotation-retired.json"
ROTATION_ASSESSMENT = INSTALL.parent / "auto-guard-rotation-assessment.conf"
ROTATION_HANDOFF = INSTALL.parent / "auto-guard-rotation-state-handoff.json"
GUARD_STATE = INSTALL.parent / "device-guard.conf"
CAPTURE_BINDING = INSTALL.parent / "device-guard.conf.capture-binding"
MAIN_BINDING = INSTALL.parent / "device-guard.conf.main-binding"
WATCHDOG_PENDING = INSTALL.parent / "auto-watchdog-pending.json"
SUCCESSOR = Path("/var/lib/aegis-auto/control/generation-successor-current.json")
PASSIVE_PREINST = SUCCESSOR.parent / "passive-package-preinst.json"
PASSIVE_RETIRE_INTENT = SUCCESSOR.parent / "passive-successor-retirement-intent.json"
PASSIVE_RETIRED = SUCCESSOR.parent / "passive-successor-retired.json"
PASSIVE_OLD_STOPPED = SUCCESSOR.parent / "generation-passive-old-stopped.json"
GUARDIAN_UNIT = "aegis-auto-guardian.service"
MAX_REQUEST = 8192
MAX_RECEIPT = 4096
MAX_ROTATION_INTENT = 8192  # bounded full source/actor roster only
LEASE_SECONDS = 90.0
STOPPED_GUARD_MONITOR_WAIT = 2.0  # separate read lease; BIND/Stop budgets unchanged
STOPPED_GUARD_UNIT = 'aegis-foreign-policy-monitor.service'


def _stopped_bounded_read(path, maximum):
    with Path(path).open('rb') as source:
        data = source.read(maximum + 1)
    need(len(data) <= maximum, 'stopped_guard_proc_read_bound')
    return data


BOOT_GUARD_LEASE_SECONDS = 300.0  # boot host assessment is separately bounded at 180s
BOOT_CONTROL = Path('/var/lib/aegis-auto/control')


def _boot_protected_file(path, maximum):
    """Bound a boot lineage read to root-owned non-writable path components."""
    for directory in (Path('/var/lib/aegis-auto'), BOOT_CONTROL, path.parent):
        info = directory.stat(follow_symlinks=False)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
             info.st_mode & 0o022 == 0, 'boot_guard_untrusted_directory')
    return regular(path, maximum)


def _boot_guard_binding(request, expected_active_sha=None):
    """Read the old capsule independently; Rust retains the full lineage proof."""
    need(not TERMINAL_MIGRATION_PENDING.exists() and
         not TERMINAL_MIGRATION_PENDING.is_symlink(),
         'terminal_migration_pending')
    control = BOOT_CONTROL
    snapshot_sha = request['boot_snapshot_sha256']
    snapshot_raw = _boot_protected_file(
        control / 'boot-snapshots' / f'snapshot-{snapshot_sha}.json', 1 << 20)
    need(digest(snapshot_raw) == snapshot_sha, 'boot_guard_snapshot_changed')
    snapshot = json.loads(snapshot_raw, object_pairs_hook=unique)
    need(type(snapshot) is dict and
         snapshot.get('schema') == 'aegis_auto_v2_boot_snapshot_v1' and
         snapshot.get('active_report_sha256') == request['active_report_sha256'] and
         snapshot.get('predecessor_boot_id') == request['predecessor_boot_id'] and
         type(snapshot.get('source')) is dict and
         snapshot['source'].get('candidate_sha256') == request['candidate_sha256'],
         'boot_guard_snapshot_mismatch')
    intent_path = control / 'generation-boot-successor-current.json'
    if expected_active_sha is not None:
        need(type(expected_active_sha) is str and HEX64.fullmatch(expected_active_sha),
             'boot_guard_expected_active_invalid')
    if intent_path.exists() or intent_path.is_symlink():
        intent = json.loads(_boot_protected_file(intent_path, 139264),
                            object_pairs_hook=unique)
        need(type(intent) is dict and
             intent.get('schema') == 'aegis_auto_v2_boot_successor_v1' and
             intent.get('old_snapshot_sha256') == snapshot_sha and
             intent.get('old_boot_id') == request['predecessor_boot_id'] and
             intent.get('new_boot_id') == request['boot_id'] and
             intent.get('candidate_sha256') == request['candidate_sha256'] and
             type(intent.get('old_active_sha256')) is str and
             HEX64.fullmatch(intent['old_active_sha256']),
             'boot_guard_intent_mismatch')
        active_sha = intent['old_active_sha256']
        need(expected_active_sha is None or expected_active_sha == active_sha,
             'boot_guard_expected_active_changed')
        active_path = control / 'generation.json'
        try:
            active_raw = _boot_protected_file(active_path, 139264)
        except FileNotFoundError:
            active_raw = b''
        if digest(active_raw) != active_sha:
            # The old generation can already be archived while a successor
            # owns current.  The exact old SHA comes from the durable intent.
            active_raw = _boot_protected_file(
                control / 'generation-history' / f'active-{active_sha}.json', 139264)
        need(digest(active_raw) == active_sha,
             'boot_guard_active_archive_changed')
    else:
        try:
            active_raw = _boot_protected_file(control / 'generation.json', 139264)
        except FileNotFoundError:
            active_raw = b''
        if expected_active_sha is not None and digest(active_raw) != expected_active_sha:
            active_raw = _boot_protected_file(
                control / 'generation-history' /
                f'active-{expected_active_sha}.json', 139264)
        need(active_raw and (expected_active_sha is None or
             digest(active_raw) == expected_active_sha),
             'boot_guard_active_archive_changed')
    active = json.loads(active_raw, object_pairs_hook=unique)
    need(type(active) is dict and active.get('schema') ==
         'aegis_auto_v2_generation_v1' and
         active.get('boot_snapshot_sha256') == snapshot_sha and
         active.get('report_sha256') == request['active_report_sha256'] and
         type(active.get('report')) is dict,
         'boot_guard_active_changed')
    report = active['report']
    report_raw = json.dumps(report, sort_keys=True,
                            separators=(',',':'), ensure_ascii=False).encode()
    need(digest(report_raw) == request['active_report_sha256'] and
         report.get('schema') == 'aegis_auto_active_stage_inspection_v1' and
         type(report.get('stage')) is dict and
         report['stage'].get('mode') in ('wide-redirect-safe','full-wide-tun') and
         report['stage'].get('phase') == 'finalized' and
         type(report.get('terminal')) is dict and
         report['terminal'].get('boot_id') == request['predecessor_boot_id'] and
         report['terminal'].get('outcome') == 'finalized' and
         report['terminal'].get('private_unit') == request['private_unit'] and
         report['terminal'].get('invocation_id') == request['prior_invocation_id'] and
         type(report.get('input')) is dict and
         report['input'].get('candidate_sha256') == request['candidate_sha256'] and
         snapshot.get('source') == report['input'] and
         snapshot.get('current_fixed') == report.get('current_fixed') and
         request['predecessor_boot_id'] != request['boot_id'],
         'boot_guard_report_changed')
    old_stage = report['stage'].get('path')
    need(type(old_stage) is str and
         Path(old_stage).parent == Path('/run/aegis-installer-config-snapshots') and
         not Path(old_stage).exists() and not Path(old_stage).is_symlink(),
         'boot_guard_old_stage_present')
    return digest(snapshot_raw), digest(active_raw)


def _boot_snapshot_config_sha256(snapshot_sha: str, active_report_sha: str,
                                predecessor_boot: str, candidate_sha: str) -> str:
    """Bind the successor's installed TOML to the exact authenticated capsule.

    Rust captured this closed tree before the reboot and verified it against
    the live installed tree on the new boot. The caller has already matched
    this snapshot and active report through _boot_guard_binding under both
    held authority locks. Reopening by digest prevents a pathname swap from
    substituting another generation here.
    """
    need(type(snapshot_sha) is str and HEX64.fullmatch(snapshot_sha) is not None,
         'boot_guard_snapshot_config_identity')
    raw = _boot_protected_file(
        BOOT_CONTROL / 'boot-snapshots' / f'snapshot-{snapshot_sha}.json',
        1 << 20)
    need(digest(raw) == snapshot_sha, 'boot_guard_snapshot_config_changed')
    snapshot = json.loads(raw, object_pairs_hook=unique)
    need(type(snapshot) is dict and
         snapshot.get('schema') == 'aegis_auto_v2_boot_snapshot_v1' and
         snapshot.get('active_report_sha256') == active_report_sha and
         snapshot.get('predecessor_boot_id') == predecessor_boot and
         type(snapshot.get('source')) is dict and
         snapshot['source'].get('candidate_sha256') == candidate_sha,
         'boot_guard_snapshot_config_mismatch')
    tree = snapshot.get('config')
    need(type(tree) is dict and set(tree) == {'path', 'entries'} and
         tree['path'] == '/etc/aegis/client' and
         type(tree['entries']) is dict, 'boot_guard_snapshot_config_tree')
    node = tree['entries'].get('aegis.toml')
    need(type(node) is dict and
         set(node) == {'device', 'inode', 'mode', 'uid', 'gid', 'links',
                       'size', 'mtime', 'mtime_ns', 'ctime', 'ctime_ns',
                       'content_sha256'} and
         all(type(node[key]) is int for key in
             ('device', 'inode', 'mode', 'uid', 'gid', 'links', 'size',
              'mtime', 'mtime_ns', 'ctime', 'ctime_ns')) and
         type(node['mode']) is int and stat.S_ISREG(node['mode']) and
         node['uid'] == node['gid'] == 0 and node['links'] == 1 and
         type(node['size']) is int and 0 < node['size'] <= 16 << 20 and
         type(node['content_sha256']) is str and
         HEX64.fullmatch(node['content_sha256']) is not None,
         'boot_guard_snapshot_config_leaf')
    return node['content_sha256']

def _stopped_guard_pid1(unit, invocation):
    """Current inactive/failed private invocation, allowing an empty cgroup leaf."""
    need(type(unit) is str and PRIVATE_UNIT.fullmatch(unit) and
         type(invocation) is str and HEX32.fullmatch(invocation),
         'stopped_guard_private_identity_invalid')
    result = subprocess.run(['/usr/bin/systemctl','show',unit,
        '-p','MainPID','-p','ControlPID','-p','ActiveState','-p','ControlGroup',
        '-p','InvocationID','-p','NFileDescriptorStore','-p','LoadState',
        '--no-pager'],capture_output=True,check=False,
        timeout=2,env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
    need(result.returncode == 0 and len(result.stdout) <= 4096 and
         len(result.stderr) <= 4096,'stopped_guard_private_pid1_unavailable')
    rows = {}
    for line in result.stdout.decode('ascii').splitlines():
        key, separator, value = line.partition('=')
        need(separator == '=' and key not in rows,
             'stopped_guard_private_pid1_invalid')
        rows[key] = value
    need(set(rows) == {'MainPID','ControlPID','ActiveState','ControlGroup',
                      'InvocationID','NFileDescriptorStore','LoadState'} and
         rows['MainPID'] == rows['ControlPID'] == '0' and
         rows['NFileDescriptorStore'] == '0' and
         rows['ActiveState'] == 'inactive' and
         rows['LoadState'] in ('loaded','not-found') and
         rows['InvocationID'] in ('',invocation) and
         rows['ControlGroup'] in ('','/system.slice/'+unit),
         'stopped_guard_private_pid1_changed')
    if rows['LoadState'] == 'not-found':
        need(rows['InvocationID'] == '' and rows['ControlGroup'] == '' and
             not (Path('/sys/fs/cgroup/system.slice')/unit).exists(),
             'stopped_guard_collected_unit_changed')
    if rows['ControlGroup']:
        leaf = Path('/sys/fs/cgroup/system.slice')/unit
        if leaf.exists():
            events = _stopped_bounded_read(leaf/'cgroup.events', 4096).decode('ascii')
            need('populated 0\n' in events and 'populated 1\n' not in events,
                 'stopped_guard_private_cgroup_populated')
    return rows


def _stopped_monitor_has_same_lock(proc, lock_identity, first_row, deadline):
    """Authenticate monitor custody of the *same* kernel FLOCK via fdinfo.

    A borrowed OFD's /proc/locks PID can name its original guardian/watchdog
    locker after that actor released its copy.  The pinned monitor may wait
    only if one of its own live descriptors contains the same substantive lock
    fields (presentation ordinals are local to each proc listing),
    full-file WRITE FLOCK and protected inode.  An open unlocked FD is
    never enough.  The caller rechecks PID1, birth and pidfd afterwards.
    """
    need(len(first_row) == 8 and
         re.fullmatch(r'[1-9][0-9]*:', first_row[0]) is not None,
         'stopped_guard_unknown_writer')
    matching = []
    for protected in (GUARD_LOCK, ASSESSMENT_LOCK):
        try:
            candidate = protected.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        if (candidate.st_dev, candidate.st_ino) == lock_identity:
            matching.append((protected, candidate))
    need(len(matching) == 1, 'stopped_guard_inode_changed')
    protected, named = matching[0]
    need(stat.S_ISREG(named.st_mode) and named.st_uid == named.st_gid == 0 and
         named.st_nlink == 1 and stat.S_IMODE(named.st_mode) == 0o600 and
         (protected != ASSESSMENT_LOCK or named.st_size == 0),
         'stopped_guard_inode_changed')
    count = 0
    for path in (proc/'fd').iterdir():
        count += 1
        need(count <= 4096 and time.monotonic() < deadline,
             'stopped_guard_monitor_fd_bound')
        if not path.name.isdecimal():
            continue
        try:
            current = path.stat()
        except FileNotFoundError:
            continue
        if (current.st_dev, current.st_ino) != lock_identity:
            continue
        try:
            info = _stopped_bounded_read(proc/'fdinfo'/path.name, 4096).decode('ascii')
        except FileNotFoundError:
            continue
        lock_rows = [line.split() for line in info.splitlines()
                     if line.startswith('lock:')]
        if (len(lock_rows) == 1 and len(lock_rows[0]) == 9 and
                lock_rows[0][2:] == first_row[1:] and
                _exclusive_flock_fdinfo(info, named)):
            latest = _stopped_bounded_read('/proc/locks', 1 << 20)
            need(time.monotonic() < deadline,
                 'stopped_guard_monitor_wait_expired')
            same = []
            for line in latest.decode('ascii').splitlines():
                row = line.split()
                if len(row) < 6:
                    continue
                parts = row[5].split(':')
                if len(parts) != 3:
                    continue
                try:
                    identity = (os.makedev(int(parts[0],16),int(parts[1],16)),
                                int(parts[2]))
                except ValueError:
                    continue
                if identity == lock_identity:
                    same.append(row)
            if not same:
                return None  # Authenticated OFD released; caller tries one immediate NB claim.
            need(len(same) == 1 and len(same[0]) == 8 and
                 same[0][1:] == first_row[1:],
                 'stopped_guard_unknown_writer')
            return True
    return False


def _stopped_monitor_owner(guard_identity, deadline):
    """Prove one busy FLOCK is held by the exact pinned PID1 monitor.

    A mismatched row PID is allowed only when the monitor's own fdinfo proves
    custody of the same substantive lock fields and inode. Unknown or ambiguous locks,
    transient PID1 owners and parser errors never authorize waiting.
    """
    need(time.monotonic() < deadline, 'stopped_guard_monitor_wait_expired')
    install = record(INSTALL)
    need(digest(regular(FOREIGN_MONITOR_SOURCE, 1 << 20, 0o500)) ==
         install['foreign_monitor_source_sha256'] and
         digest(regular(FOREIGN_UNIT_FILE, 1 << 16, 0o644)) ==
         install['foreign_monitor_unit_sha256'],
         'stopped_guard_monitor_source_changed')
    need(time.monotonic() < deadline, 'stopped_guard_monitor_wait_expired')
    args = ['MainPID', 'ControlPID', 'ActiveState', 'SubState',
            'InvocationID', 'ControlGroup', 'FragmentPath', 'DropInPaths',
            'NeedDaemonReload', 'ExecStart']
    def facts():
        command = ['/usr/bin/systemctl', 'show', STOPPED_GUARD_UNIT]
        for key in args:
            command += ['-p', key]
        command += ['--no-pager']
        remaining = deadline-time.monotonic()
        need(remaining > 0, 'stopped_guard_monitor_wait_expired')
        result = subprocess.run(command, capture_output=True, check=False,
                                timeout=min(2,remaining), env={'PATH':'/usr/sbin:/usr/bin',
                                                'LANG':'C','LC_ALL':'C'})
        need(time.monotonic() < deadline and result.returncode == 0 and
             len(result.stdout) <= 8192 and len(result.stderr) <= 4096,
             'stopped_guard_monitor_pid1_unavailable')
        rows = {}
        for line in result.stdout.decode('ascii').splitlines():
            key, separator, value = line.partition('=')
            need(separator == '=' and key not in rows,
                 'stopped_guard_monitor_pid1_invalid')
            rows[key] = value
        need(set(rows) == set(args) and rows['MainPID'].isdecimal() and
             int(rows['MainPID']) > 1 and rows['ControlPID'] == '0' and
             rows['ActiveState'] == 'active' and rows['SubState'] == 'running' and
             HEX32.fullmatch(rows['InvocationID']) is not None and
             rows['ControlGroup'] == '/system.slice/' + STOPPED_GUARD_UNIT,
             'stopped_guard_monitor_pid1_changed')
        expected_exec = ('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 '
                         '-I -B ' + str(FOREIGN_MONITOR_SOURCE) +
                         ' ; ignore_errors=no ;')
        need(rows['FragmentPath'] == str(FOREIGN_UNIT_FILE) and
             rows['DropInPaths'] == '' and rows['NeedDaemonReload'] == 'no' and
             rows['ExecStart'].startswith(expected_exec) and
             rows['ExecStart'].count('{') == 1 and
             rows['ExecStart'].count('}') == 1 and
             rows['ExecStart'].endswith(' }'),
             'stopped_guard_monitor_loaded_unit_changed')
        return rows
    before = facts()
    pid = int(before['MainPID'])
    pidfd = os.pidfd_open(pid, 0)
    try:
        need(_pid_alive(pidfd) and
             any(row == f'Pid:\t{pid}' for row in
                 _stopped_bounded_read(f'/proc/self/fdinfo/{pidfd}',4096)
                 .decode('ascii').splitlines()),
             'stopped_guard_monitor_pidfd_changed')
        proc = Path('/proc') / str(pid)
        stat_fields = _stopped_bounded_read(proc/'stat',4096).decode('ascii').rsplit(')',1)[1].split()
        birth = int(stat_fields[19])
        need(_stopped_bounded_read(proc/'cgroup',16384).decode('ascii') == '0::' +
             before['ControlGroup'] + '\n' and
             os.stat(proc/'ns/net').st_ino == os.stat('/proc/self/ns/net').st_ino and
             _stopped_bounded_read(proc/'cmdline',16384) ==
             (b'/usr/bin/python3\0-I\0-B\0' +
              str(FOREIGN_MONITOR_SOURCE).encode() + b'\0') and
             os.path.samefile(proc/'exe', '/usr/bin/python3') and
             any(row.split() == ['Uid:','0','0','0','0'] for row in
                 _stopped_bounded_read(proc/'status',16384)
                 .decode('ascii').splitlines()),
             'stopped_guard_monitor_process_changed')
        raw = _stopped_bounded_read('/proc/locks',1 << 20)
        need(time.monotonic() < deadline, 'stopped_guard_monitor_wait_expired')
        held = []
        for line in raw.decode('ascii').splitlines():
            row = line.split()
            if len(row) != 8 or row[1:4] != ['FLOCK','ADVISORY','WRITE']:
                continue
            parts = row[5].split(':')
            if len(parts) != 3:
                continue
            try:
                identity = (os.makedev(int(parts[0],16),int(parts[1],16)),
                            int(parts[2]))
            except ValueError:
                continue
            if identity == guard_identity:
                held.append(row)
        if not held:
            return False  # Original monitor OFD released during authentication.
        # Never classify an unknown or ambiguous holder as a monitor transition.
        if len(held) != 1:
            print('aegis_auto_guardian_stopped_guard_refusal:row_count',
                  file=sys.stderr, flush=True)
            raise Refused('stopped_guard_unknown_writer')
        if held[0][6:] != ['0','EOF']:
            print('aegis_auto_guardian_stopped_guard_refusal:row_range',
                  file=sys.stderr, flush=True)
            raise Refused('stopped_guard_unknown_writer')
        if held[0][4] != str(pid):
            borrowed = _stopped_monitor_has_same_lock(
                proc, guard_identity, held[0], deadline)
            if borrowed is None:
                return False  # Same original lock vanished after proven fdinfo custody.
            if borrowed is False:
                print('aegis_auto_guardian_stopped_guard_refusal:borrowed_fd_custody_missing',
                      file=sys.stderr, flush=True)
                raise Refused('stopped_guard_unknown_writer')
        try:
            after = facts()
        except Refused as error:
            # Only PID1's exact monitor becoming inactive/collected qualifies.
            # A changed source, unit, parser or a timed-out query still refuses.
            if error.args != ('stopped_guard_monitor_pid1_changed',):
                raise
            print('aegis_auto_guardian_stopped_monitor_transition:pid1',
                  file=sys.stderr, flush=True)
            return False
        if after != before:
            print('aegis_auto_guardian_stopped_monitor_transition:pid1',
                  file=sys.stderr, flush=True)
            return False
        need(time.monotonic() < deadline,
             'stopped_guard_monitor_wait_expired')
        try:
            later_birth = int(_stopped_bounded_read(proc/'stat',4096)
                              .decode('ascii').rsplit(')',1)[1].split()[19])
        except FileNotFoundError:
            need(not _pid_alive(pidfd),
                 'stopped_guard_monitor_proc_disappeared_while_alive')
            print('aegis_auto_guardian_stopped_monitor_transition:birth',
                  file=sys.stderr, flush=True)
            return False
        if later_birth != birth:
            print('aegis_auto_guardian_stopped_monitor_transition:birth',
                  file=sys.stderr, flush=True)
            return False
        if not _pid_alive(pidfd):
            print('aegis_auto_guardian_stopped_monitor_transition:pidfd',
                  file=sys.stderr, flush=True)
            return False
        return True
    finally:
        os.close(pidfd)


def _stop_assessment_reservation(guard_fd: int) -> int:
    """Serialize owned nft/receipt transitions with full monitor snapshots."""
    _held_lock(guard_fd, GUARD_LOCK)
    fd=os.open(ASSESSMENT_LOCK,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        named=ASSESSMENT_LOCK.stat(follow_symlinks=False)
        value=os.fstat(fd)
        need(stat.S_ISREG(value.st_mode) and value.st_uid==value.st_gid==0 and
             value.st_nlink==1 and stat.S_IMODE(value.st_mode)==0o600 and
             value.st_size==0 and (value.st_dev,value.st_ino)==
             (named.st_dev,named.st_ino),'stop assessment lock changed')
        deadline=time.monotonic()+30.0  # inside existing 60s socket/90s actor lease
        while True:
            need(time.monotonic()<deadline,'stop assessment wait expired')
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                _held_lock(fd,ASSESSMENT_LOCK)
                return fd
            except BlockingIOError:
                try:
                    known=_stopped_monitor_owner((value.st_dev,value.st_ino),deadline)
                except Refused:
                    # A watchdog can independently retire this same stopped
                    # owner after loss of its original guardian.  The pinned
                    # monitor module performs a second complete PID1/source/
                    # journal/deny proof; no error text grants authority.
                    observer=verified_module(FOREIGN_MONITOR_SOURCE,
                                             'aegis_auto_foreign_monitor')
                    known=observer._authenticated_stopped_retirement_holder(
                        value,deadline)
                if not known:
                    continue  # authenticated holder released during proof
                need(time.monotonic()<deadline,'stop assessment wait expired')
                time.sleep(min(0.01,max(0,deadline-time.monotonic())))
    except BaseException:
        os.close(fd)
        raise


def _stopped_guard_claim():
    """Acquire a fresh independent OFD; only exact monitor contention waits."""
    fd = os.open(GUARD_LOCK, os.O_RDONLY | os.O_CLOEXEC |
                 os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        held = os.fstat(fd)
        named = GUARD_LOCK.stat(follow_symlinks=False)
        need(stat.S_ISREG(held.st_mode) and held.st_uid == held.st_gid == 0 and
             held.st_nlink == 1 and stat.S_IMODE(held.st_mode) == 0o600 and
             (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
             'stopped_guard_inode_changed')
        deadline = time.monotonic() + STOPPED_GUARD_MONITOR_WAIT
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                # Never wait without a fresh proof of the sole busy owner.
                monitor_still_holds = _stopped_monitor_owner(
                    (held.st_dev, held.st_ino), deadline)
                if not monitor_still_holds:
                    # No waiting after a disappearing owner. Acquire now or
                    # treat the next holder as unknown and refuse.
                    try:
                        need(time.monotonic() < deadline,
                             'stopped_guard_monitor_wait_expired')
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        raise Refused('stopped_guard_busy_after_monitor_transition')
                need(time.monotonic() < deadline,
                     'stopped_guard_monitor_wait_expired')
                time.sleep(min(0.025, max(0, deadline-time.monotonic())))
        need(_held_lock(fd, GUARD_LOCK) == (held.st_dev, held.st_ino),
             'stopped_guard_acquired_inode_changed')
        result = fd
        fd = None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def _stopped_peer_guard_closed(pid, pidfd, guard_identity):
    """Peer is gone, or no peer descriptor still names this guard inode."""
    if not _pid_alive(pidfd):
        return True
    entries = (Path('/proc')/str(pid)/'fd').iterdir()
    for count, path in enumerate(entries, 1):
        need(count <= 4096, 'stopped_guard_peer_fd_bound')
        if not path.name.isdecimal():
            continue
        try:
            current = path.stat()
        except FileNotFoundError:
            continue
        if (current.st_dev,current.st_ino) == guard_identity:
            return False
    return True



# Includes the fixed shell validation and both complete host semantic reads.
# No ACK is permitted beyond this absolute bound; the original OFD stays held.
BIND_TRANSACTION_SECONDS = 25.0
_VERIFIED_MODULE_LOCK = threading.RLock()
_VERIFIED_MODULES: dict[str, tuple[Path, str, types.ModuleType]] = {}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
PRIVATE_UNIT = re.compile(r"aegis-auto@[0-9a-f]{64}\.service\Z")
RETAINED_RELEASE = re.compile(r"(?:source-)?[0-9a-f]{64}\Z")
ROTATION_SOURCES = (
    ("guardian_sha256", "scripts/lib/aegis_auto_guardian.py", 0o444),
    ("witness_sha256", "scripts/lib/aegis_auto_native_witness.py", 0o444),
    ("sink_sha256", "scripts/lib/aegis_auto_sink.py", 0o444),
    ("rollback_sha256", "scripts/lib/aegis_auto_trace_rollback.py", 0o444),
    ("capture_sha256", "scripts/lib/aegis_auto_capture.py", 0o444),
    ("topology_sha256", "scripts/lib/aegis_auto_witness_topology.py", 0o444),
    ("capture_topology_sha256", "scripts/lib/aegis_auto_capture_topology.py", 0o444),
    ("endpoint_sha256", "scripts/lib/aegis_auto_endpoint.py", 0o444),
    ("guard_policy_source_sha256", "scripts/lib/aegis_auto_guard_policy.py", 0o444),
    ("foreign_policy_source_sha256", "scripts/lib/aegis_auto_foreign_policy.py", 0o444),
    ("foreign_monitor_source_sha256", "scripts/lib/aegis_auto_foreign_monitor.py", 0o444),
    ("ufw_pins_sha256", "scripts/lib/aegis_auto_ufw_pins.json", 0o444),
    ("initrd_policy_source_sha256", "scripts/lib/aegis_initrd_policy.py", 0o444),
    ("foreign_monitor_unit_sha256", "packaging/systemd/aegis-foreign-policy-monitor.service", 0o444),
    ("launch_source_sha256", "scripts/lib/aegis_auto_launch.py", 0o444),
    ("watchdog_sha256", "scripts/lib/aegis_auto_guardian_watchdog.py", 0o444),
    ("watchdog_unit_sha256", "packaging/systemd/aegis-auto-guardian-watchdog.service", 0o444),
    ("topology_unit_sha256", "packaging/systemd/aegis-auto-witness-topology.service", 0o444),
    ("capture_topology_unit_sha256", "packaging/systemd/aegis-auto-capture-topology.service", 0o444),
    ("guard_helper_sha256", "scripts/aegis-device-egress-guard.sh", 0o555),
    ("guardian_unit_sha256", "packaging/systemd/aegis-auto-guardian.service", 0o444),
)
TERMINAL_INSTALLED_SOURCES = (
    ('terminal_register_sha256', ROOT/'aegis_auto_terminal_register.py', 0o500),
    ('terminal_witness_sha256', ROOT/'aegis_auto_terminal_witness.py', 0o500),
    ('terminal_boot_store_sha256', ROOT/'aegis_auto_terminal_boot_store.py', 0o500),
    ('terminal_transition_sha256', ROOT/'aegis_auto_boot_transition.py', 0o500),
    ('terminal_a_unit_sha256', Path('/etc/systemd/system/aegis-auto-terminal-a@.service'), 0o644),
    ('terminal_b_unit_sha256', Path('/etc/systemd/system/aegis-auto-terminal-b@.service'), 0o644),
    ('terminal_observer_unit_sha256', Path('/etc/systemd/system/aegis-auto-terminal-observer.service'), 0o644),
    ('terminal_transition_unit_sha256', Path('/etc/systemd/system/aegis-auto-terminal-transition.service'), 0o644),
    ('terminal_hook_staged_sha256', ROOT/'aegis-auto-terminal-hook', 0o500),
)
TERMINAL_RETAINED_SOURCES = (
    ('terminal_register_sha256', 'scripts/lib/aegis_auto_terminal_register.py', 0o444),
    ('terminal_witness_sha256', 'scripts/lib/aegis_auto_terminal_witness.py', 0o444),
    ('terminal_boot_store_sha256', 'scripts/lib/aegis_auto_terminal_boot_store.py', 0o444),
    ('terminal_transition_sha256', 'scripts/lib/aegis_auto_boot_transition.py', 0o444),
    ('terminal_a_unit_sha256', 'packaging/systemd/aegis-auto-terminal-a@.service', 0o444),
    ('terminal_b_unit_sha256', 'packaging/systemd/aegis-auto-terminal-b@.service', 0o444),
    ('terminal_observer_unit_sha256', 'packaging/systemd/aegis-auto-terminal-observer.service', 0o444),
    ('terminal_transition_unit_sha256', 'packaging/systemd/aegis-auto-terminal-transition.service', 0o444),
    ('terminal_hook_staged_sha256', 'packaging/systemd/system-shutdown/aegis-auto-terminal-hook', 0o555),
)
ROTATION_ACTORS = (
    ("aegis-foreign-policy-monitor.service", FOREIGN_MONITOR_SOURCE,
     FOREIGN_UNIT_FILE),
    ("aegis-auto-guardian.service", ROOT / "aegis_auto_guardian.py",
     GUARDIAN_UNIT_FILE),
    ("aegis-auto-guardian-watchdog.service",
     ROOT / "aegis_auto_guardian_watchdog.py", WATCHDOG_UNIT_FILE),
    ("aegis-auto-witness-topology.service",
     ROOT / "aegis_auto_witness_topology.py", TOPOLOGY_UNIT_FILE),
    ("aegis-auto-capture-topology.service",
     ROOT / "aegis_auto_capture_topology.py", CAPTURE_TOPOLOGY_UNIT_FILE),
    ("aegis-auto-trace-rollback-actor.service",
     ROOT / "aegis_auto_trace_rollback.py",
     Path("/etc/systemd/system/aegis-auto-trace-rollback-actor.service")),
)
PASSIVE_SUCCESSOR_ACTORS = (
    ("aegis-auto-guardian.service", "/run/aegis-auto-guard/authority.sock",
     ROOT / "aegis_auto_guardian.py"),
    ("aegis-auto-guardian-watchdog.service",
     "/run/aegis-auto-guardian-watchdog/authority.sock",
     ROOT / "aegis_auto_guardian_watchdog.py"),
    ("aegis-auto-witness-topology.service", "/run/aegis-auto-topology/authority.sock",
     ROOT / "aegis_auto_witness_topology.py"),
    ("aegis-auto-trace-rollback-actor.service", "/run/aegis-auto-rollback/authority.sock",
     ROOT / "aegis_auto_trace_rollback.py"),
)
ROTATION_STATIC_UNITS = (
    ("aegis-auto-trace-rollback.timer",
     "packaging/systemd/aegis-auto-trace-rollback.timer"),
    ("aegis-auto-trace-rollback.service",
     "packaging/systemd/aegis-auto-trace-rollback.service"),
)
EXPECTED_GUARD_UNIT = b"""[Unit]
Description=AEGIS device persistent egress block
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service ufw.service
Before=network-pre.target
Wants=network-pre.target aegis-foreign-policy-monitor.service aegis-device-dhcp-refresh.timer
[Service]
Type=oneshot
RemainAfterExit=yes
Environment=AEGIS_DEVICE_GUARD_STATE=/var/lib/aegis-install/client/device-guard.conf
ExecStart=/bin/bash /usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh block
# No ExecStop: failure/stop/restart must never release the independent guard.
[Install]
WantedBy=multi-user.target
"""
EXPECTED_DHCP_REFRESH_SERVICE = b"""[Unit]
Description=Refresh the AEGIS manager DHCP server destination pin
Requires=aegis-device-egress-guard.service
After=aegis-device-egress-guard.service systemd-networkd.service NetworkManager.service

[Service]
Type=oneshot
Environment=AEGIS_DEVICE_GUARD_STATE=/var/lib/aegis-install/client/device-guard.conf
TimeoutStartSec=210s
ExecStart=/bin/bash /usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh refresh-manager-lease-service
"""
EXPECTED_DHCP_REFRESH_TIMER = b"""[Unit]
Description=Check the AEGIS manager DHCP lease pin

[Timer]
OnBootSec=5s
OnUnitActiveSec=5s
AccuracySec=1s
Unit=aegis-device-dhcp-refresh.service

[Install]
WantedBy=timers.target
"""


class Refused(RuntimeError):
    """The installed deny or actor authority could not be established."""


class RotationActorJobPending(Refused):
    """A complete PID1 readback found our pending DHCP refresh start."""


SAFE_REFUSAL_REASON = re.compile(r"[A-Za-z0-9_]{1,96}\Z")
# Explicit source-owned request reasons. A syntactically safe caller value is
# not enough to be safe for the journal: an alphanumeric secret is also safe
# ASCII. New reasons remain unclassified until independently reviewed here.
STATIC_REQUEST_REASONS = frozenset({
    "stopped_guard_unknown_writer",
    "stopped_guard_busy_after_monitor_transition",
    "stopped_guard_monitor_wait_expired",
    "stopped_guard_monitor_pid1_changed",
    "stopped_guard_monitor_proc_disappeared_while_alive",
    "local_guard_state_changed", "local_guard_policy_changed",
    "local_current_policy_missing", "local_producer_owner_changed",
    "foreign_policy_drift", "bind_seal_deadline_elapsed",
    "bounded_file_changed", "duplicate_json_key", "exclusive_flock_not_held",
    "file_replaced", "foreign_or_ambiguous_unit", "foreign_peer",
    "guardian_not_in_host_namespace", "guardian_root_mount_changed",
    "held_lock_changed", "host_pid1_required", "host_systemd_pid1_required",
    "installed_host_identity_changed", "installed_main_bytes_changed",
    "installed_main_generation_invalid", "installed_main_inode_changed",
    "installed_main_parent_changed", "installed_main_path_invalid",
    "installed_main_stage_generation_changed", "installed_main_too_large",
    "installed_module_changed", "installed_source_changed",
    "invalid_guardian_request", "invalid_install_receipt",
    "invalid_launch_registration", "invalid_machine_identity",
    "invalid_record", "invalid_source_digest", "inverse_header_changed",
    "inverse_marker_archive_not_sealed", "inverse_marker_archive_invalid",
    "inverse_marker_archive_changed", "inverse_owned_stop_chain_changed",
    "inverse_stage_header_invalid",
    "launch_fulltun_runtime_identity_changed", "launch_pid1_facts_invalid",
    "launch_pid1_identity_changed", "launch_pid1_unavailable",
    "launch_redirect_runtime_identity_changed", "launch_runtime_binding_missing",
    "launch_runtime_identity_invalid", "launch_socks_runtime_identity_changed",
    "launch_three_fds_required", "linux_root_required",
    "peer_exited_before_admission", "peer_pidfd_identity_changed",
    "peer_pidfd_unavailable", "peer_role_executable_changed",
    "private_main_generation_already_registered", "request_truncated",
    "socks_launch_has_wide_deny_lease", "stage_binding_changed",
    "stage_header_changed", "unadmitted_module", "unit_cgroup_changed",
    "unit_facts_invalid", "unit_identity_unavailable", "untrusted_file",
    "untrusted_inverse_header", "untrusted_machine_identity",
    "untrusted_parent", "untrusted_source_directory", "untrusted_stage_fd",
    "untrusted_stage_header", "untrusted_worker",
    "untrusted_worker_executable", "wide_launch_missing_held_guard",
    "worker_executable_changed", "worker_executable_too_large",
    "wrong_installed_source",
    # Exact launch-session, protected one-use claim, and terminal handoff
    # refusals. These are fixed source literals; no stage content is logged.
    "unadmitted_stage_leaf", "untrusted_stage_leaf", "stage_leaf_changed",
    "launch_owner_marker_invalid", "launch_ticket_not_bound_to_owner",
    "launch_one_use_claim_missing", "invalid_launch_unit",
    "launch_registration_stage_not_metadata",
    "launch_projection_header_not_owned",
    "launch_projection_header_delta_invalid",
    "launch_projection_leaves_invalid", "launch_projection_leaf_changed",
    "launch_projection_active_identity_changed",
    "launch_projection_one_use_chain_changed",
    "launch_projection_record_delta_invalid",
    "launch_projection_directory_changed",
    "launch_projection_lineage_changed",
    "launch_projection_chain_invalid",
    "launch_capture_successor_unproved",
    "launch_capture_header_delta_invalid", "capture_launch_owner_changed",
    "capture_initial_header_changed", "capture_owner_consumption_changed",
    "capture_main_pid_changed", "capture_main_identity_changed",
    "capture_registration_stage_not_metadata",
    "launch_recipe_parent_changed", "launch_recipe_identity_changed",
    "launch_recipe_size_changed",
    "stop_receipt_parent_changed",
    "invalid_launch_probe", "launch_installed_main_generation_changed",
    "launch_terminal_request_invalid", "launch_already_retained",
    "launch_terminal_handoff_missing", "launch_terminal_not_sealed_for_owner",
    "launch_marker_archive_not_sealed", "launch_terminal_handoff_not_owned",
    "launch_owner_handoff_incomplete",
})

# Exact literal reasons in the digest-pinned installed launch actor. Its
# RuntimeError subclass is otherwise journalled as a generic runtime error;
# neither exception text nor a caller-supplied alphanumeric string is logged.
STATIC_LAUNCH_REASONS = frozenset({
    "foreign_launch_control", "foreign_main_executable", "foreign_main_uid",
    "foreign_main_identity", "invalid_main_runtime_policy", "invalid_main_status",
    "invalid_launch_binding", "invalid_launch_channel", "invalid_main_hello",
    "invalid_main_start_tick", "invalid_main_stat", "invalid_worker_digest",
    "kernel_launch_identity_unavailable", "launch_channel_closed",
    "launch_check_expired", "launch_identity_changed",
    "launch_packet_truncated", "launch_peer_changed",
    "launch_pidfd_mismatch", "launch_process_exited",
    "launch_ticket_already_consumed", "launch_ticket_proof_mismatch",
    "main_executable_changed", "main_exited_or_invalid",
    "main_invocation_changed", "main_runtime_identity_changed",
    "main_supplementary_groups_changed", "main_no_new_privs_changed",
    "main_capabilities_changed", "oversize_main_executable",
    "oversize_main_status", "short_main_stat",
})


def _request_refusal_tag(error: Exception) -> str:
    """Return only a bounded static reason or fixed class, never exception data."""
    if type(error) is Refused:
        reason = error.args[0] if len(error.args) == 1 else None
        return (reason if type(reason) is str and
                reason in STATIC_REQUEST_REASONS and
                SAFE_REFUSAL_REASON.fullmatch(reason) is not None else
                "refused_unclassified")
    launch_module = sys.modules.get("aegis_auto_launch")
    launch_refusal = getattr(launch_module, "LaunchRefused", None)
    if type(error) is launch_refusal:
        reason = error.args[0] if len(error.args) == 1 else None
        return ("launch_actor_" + reason if type(reason) is str and
                reason in STATIC_LAUNCH_REASONS and
                SAFE_REFUSAL_REASON.fullmatch(reason) is not None else
                "launch_actor_unclassified")
    if isinstance(error, TimeoutError):
        return "timeout_error"
    if isinstance(error, OSError):
        return "os_error"
    if isinstance(error, ValueError):
        return "value_error"
    if isinstance(error, subprocess.SubprocessError):
        return "subprocess_error"
    if isinstance(error, RuntimeError):
        return "runtime_error"
    return "unexpected_exception"


def _pinned_error_location(error: Exception,
                           *, skip_assertion_helper: bool = False) -> tuple[str, int]:
    """Use only exact installed source coordinates, never traceback contents."""
    sources = {
        str(SOURCE): "guardian",
        str(WITNESS): "witness",
        str(TOPOLOGY_SOURCE): "topology",
        str(ROLLBACK_SOURCE): "rollback",
        str(POLICY_SOURCE): "policy",
        str(ENDPOINT_SOURCE): "endpoint",
        str(CAPTURE_SOURCE): "capture",
        str(CAPTURE_TOPOLOGY_SOURCE): "capture_topology",
        str(FOREIGN_SOURCE): "foreign_policy",
        str(WATCHDOG_SOURCE): "watchdog",
        str(LAUNCH_SOURCE): "launch",
    }
    source_id = "unknown"
    line = 0
    trace = error.__traceback__
    while trace is not None:
        candidate = sources.get(trace.tb_frame.f_code.co_filename)
        candidate_line = trace.tb_lineno
        if (candidate is not None and type(candidate_line) is int and
                1 <= candidate_line <= 10000 and
                (not skip_assertion_helper or
                 trace.tb_frame.f_code.co_name not in ("need", "_need"))):
            source_id = candidate
            line = candidate_line
        trace = trace.tb_next
    return source_id, line


def _os_error_location(error: OSError) -> str:
    """Report only bounded kernel and pinned-source coordinates."""
    errno_value = error.errno
    errno_code = (errno_value if type(errno_value) is int and
                  0 <= errno_value <= 4095 else 0)
    source_id, line = _pinned_error_location(error)
    return f" errno={errno_code} source={source_id} line={line}"


def _runtime_error_location(error: RuntimeError) -> str:
    source_id, line = _pinned_error_location(error, skip_assertion_helper=True)
    return f" source={source_id} line={line}"


def need(value: bool, reason: str) -> None:
    if not value:
        raise Refused(reason)


def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def regular(path: Path, maximum: int, mode: int = 0o600) -> bytes:
    parent = path.parent.stat(follow_symlinks=False)
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
         parent.st_mode & 0o022 == 0, "untrusted_parent")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        actual = os.fstat(fd)
        named = path.stat(follow_symlinks=False)
        need(stat.S_ISREG(actual.st_mode) and actual.st_uid == 0 and
             actual.st_nlink == 1 and stat.S_IMODE(actual.st_mode) == mode and
             (actual.st_dev, actual.st_ino) == (named.st_dev, named.st_ino) and
             0 < actual.st_size <= maximum, "untrusted_file")
        data = os.read(fd, maximum + 1)
        need(len(data) == actual.st_size and len(data) <= maximum,
             "bounded_file_changed")
        need((os.fstat(fd).st_dev, os.fstat(fd).st_ino) ==
             (named.st_dev, named.st_ino), "file_replaced")
        return data
    finally:
        os.close(fd)


def record(path: Path, maximum: int = MAX_RECEIPT) -> dict[str, object]:
    value = json.loads(regular(path, maximum), object_pairs_hook=unique)
    need(type(value) is dict, "invalid_record")
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def host_anchor() -> dict[str, object]:
    """Bind this process to the administrator-installed host identity."""
    need(Path("/proc/1/exe").resolve().name == "systemd",
         "host_systemd_pid1_required")
    for namespace in ("pid", "user", "mnt", "net"):
        need(os.stat(f"/proc/self/ns/{namespace}").st_ino ==
             os.stat(f"/proc/1/ns/{namespace}").st_ino,
             "guardian_not_in_host_namespace")
    root = os.stat("/")
    pid1_root = os.stat("/proc/1/root")
    need((root.st_dev, root.st_ino) ==
         (pid1_root.st_dev, pid1_root.st_ino),
         "guardian_root_mount_changed")
    return {
        "boot_id": Path("/proc/sys/kernel/random/boot_id")
                   .read_text(encoding="ascii").strip(),
        "pid_ns_ino": os.stat("/proc/self/ns/pid").st_ino,
        "user_ns_ino": os.stat("/proc/self/ns/user").st_ino,
        "mnt_ns_ino": os.stat("/proc/self/ns/mnt").st_ino,
        "netns_ino": os.stat("/proc/self/ns/net").st_ino,
        "root_dev": root.st_dev,
        "root_ino": root.st_ino,
    }


def installation_anchor() -> dict[str, object]:
    """Stable host identity; boot and namespace inodes are checked live."""
    host_anchor()
    machine = Path("/etc/machine-id")
    fd = os.open(machine, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             info.st_mode & 0o022 == 0 and info.st_nlink == 1 and
             32 <= info.st_size <= 33, "untrusted_machine_identity")
        identity = os.read(fd, 34).strip()
        need(re.fullmatch(rb"[0-9a-f]{32}", identity) is not None,
             "invalid_machine_identity")
    finally:
        os.close(fd)
    root = os.stat("/")
    return {"machine_id_sha256": digest(identity),
            "root_dev": root.st_dev, "root_ino": root.st_ino}


def executable_digest(path: Path) -> str:
    """Hash a held executable in bounded chunks while its PIDFD remains live."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and 0 < first.st_size <= 512 << 20,
             "untrusted_worker_executable")
        h = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            need(total <= 512 << 20, "worker_executable_too_large")
            h.update(chunk)
        after = os.fstat(fd)
        need(total == first.st_size and
             (first.st_dev, first.st_ino, first.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_mtime_ns),
             "worker_executable_changed")
        return h.hexdigest()
    finally:
        os.close(fd)


def own_source(*, pending_guard_unit: bool = False) -> None:
    need(os.geteuid() == 0 and os.name == "posix" and
         Path("/proc/self/ns/net").exists(), "linux_root_required")
    need(Path(__file__).resolve() == SOURCE, "wrong_installed_source")
    root = ROOT.stat(follow_symlinks=False)
    need(stat.S_ISDIR(root.st_mode) and root.st_uid == 0 and
         root.st_mode & 0o022 == 0, "untrusted_source_directory")
    installation = record(INSTALL)
    need(set(installation) == {"schema", "guardian_sha256", "witness_sha256",
                               "sink_sha256", "rollback_sha256", "capture_sha256",
                               "topology_sha256", "topology_unit_sha256",
                               "capture_topology_sha256", "capture_topology_unit_sha256",
                               "endpoint_sha256",
                               "guard_policy_source_sha256",
                               "foreign_policy_source_sha256",
                               "foreign_monitor_source_sha256",
                               "ufw_pins_sha256",
                               "initrd_policy_source_sha256",
                               "foreign_monitor_unit_sha256",
                               "launch_source_sha256", "watchdog_sha256",
                               "watchdog_unit_sha256",
                               "guardian_unit_sha256", "guard_helper_sha256",
                               "guard_unit_sha256", "worker_sha256",
                               "guardian_unit", "installation_anchor"} |
         {field for field, _path, _mode in TERMINAL_INSTALLED_SOURCES} and
         installation["schema"] == "aegis_auto_guardian_install_v1" and
         installation["guardian_unit"] == GUARDIAN_UNIT and
         type(installation["worker_sha256"]) is str and
         HEX64.fullmatch(installation["worker_sha256"]) is not None and
         installation["installation_anchor"] == installation_anchor(),
         "invalid_install_receipt")
    for path, field, mode in (
            (SOURCE, "guardian_sha256", 0o500),
            (WITNESS, "witness_sha256", 0o500),
            (SINK_SOURCE, "sink_sha256", 0o500),
            (ROLLBACK_SOURCE, "rollback_sha256", 0o500),
            (CAPTURE_SOURCE, "capture_sha256", 0o500),
            (TOPOLOGY_SOURCE, "topology_sha256", 0o500),
            (CAPTURE_TOPOLOGY_SOURCE, "capture_topology_sha256", 0o500),
            (ENDPOINT_SOURCE, "endpoint_sha256", 0o500),
            (POLICY_SOURCE, "guard_policy_source_sha256", 0o500),
            (FOREIGN_SOURCE, "foreign_policy_source_sha256", 0o500),
            (FOREIGN_MONITOR_SOURCE, "foreign_monitor_source_sha256", 0o500),
            (UFW_PINS_SOURCE, "ufw_pins_sha256", 0o500),
            (INITRD_SOURCE, "initrd_policy_source_sha256", 0o500),
            (FOREIGN_UNIT_FILE, "foreign_monitor_unit_sha256", 0o644),
            (LAUNCH_SOURCE, "launch_source_sha256", 0o500),
            (WATCHDOG_SOURCE, "watchdog_sha256", 0o500),
            (WATCHDOG_UNIT_FILE, "watchdog_unit_sha256", 0o644),
            (TOPOLOGY_UNIT_FILE, "topology_unit_sha256", 0o644),
            (CAPTURE_TOPOLOGY_UNIT_FILE, "capture_topology_unit_sha256", 0o644),
            (GUARD_HELPER, "guard_helper_sha256", 0o755),
            (GUARDIAN_UNIT_FILE, "guardian_unit_sha256", 0o644)):
        expected = installation[field]
        need(type(expected) is str and HEX64.fullmatch(expected) is not None,
             "invalid_source_digest")
        # Source files are installed 0500.  Python never imports a writable
        # module from a daemon-writable directory.
        need(digest(regular(path, 1 << 20, mode)) == expected,
             "installed_source_changed")
    for field, path, mode in TERMINAL_INSTALLED_SOURCES:
        expected = installation[field]
        need(type(expected) is str and HEX64.fullmatch(expected) is not None and
             digest(regular(path, 1 << 20, mode)) == expected,
             'installed_terminal_source_changed')
    guard_unit_sha = installation["guard_unit_sha256"]
    if pending_guard_unit or guard_unit_sha is not None:
        need(regular(DHCP_REFRESH_SERVICE_FILE, 1 << 16, 0o644) ==
             EXPECTED_DHCP_REFRESH_SERVICE and
             regular(DHCP_REFRESH_TIMER_FILE, 1 << 16, 0o644) ==
             EXPECTED_DHCP_REFRESH_TIMER,
             "installed_dhcp_refresh_unit_changed")
    if guard_unit_sha is None:
        if pending_guard_unit:
            need(regular(GUARD_UNIT_FILE, 1 << 16, 0o644) ==
                 EXPECTED_GUARD_UNIT, "pending_guard_unit_foreign")
        else:
            need(not GUARD_UNIT_FILE.exists() and not GUARD_UNIT_FILE.is_symlink(),
                 "unadmitted_guard_unit_present")
    else:
        need(not pending_guard_unit, "guard_unit_already_admitted")
        need(type(guard_unit_sha) is str and
             HEX64.fullmatch(guard_unit_sha) is not None and
             regular(GUARD_UNIT_FILE, 1 << 16, 0o644) ==
             EXPECTED_GUARD_UNIT and
             digest(EXPECTED_GUARD_UNIT) == guard_unit_sha,
             "installed_guard_unit_changed")


def upgrade_guard_receipt() -> bool:
    """One-way passive-to-wide source admission during production first arm.

    The old passive generation is archived, and a changed guard unit cannot
    become accepted without checking every existing installed source pin.
    The independent kernel block is already applied by the installer helper.
    """
    try:
        own_source()
        return False
    except Refused:
        pass
    if not RUNTIME.exists() and not RUNTIME.is_symlink():
        RUNTIME.mkdir(mode=0o700)
    runtime = RUNTIME.stat(follow_symlinks=False)
    need(stat.S_ISDIR(runtime.st_mode) and runtime.st_uid == 0 and
         stat.S_IMODE(runtime.st_mode) == 0o700,
         "guardian_runtime_untrusted_during_upgrade")
    singleton_fd = os.open(SINGLETON, os.O_RDWR | os.O_CREAT |
                           os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        lock = os.fstat(singleton_fd)
        named = SINGLETON.stat(follow_symlinks=False)
        need(stat.S_ISREG(lock.st_mode) and lock.st_uid == 0 and
             lock.st_nlink == 1 and stat.S_IMODE(lock.st_mode) == 0o600 and
             (lock.st_dev, lock.st_ino) == (named.st_dev, named.st_ino),
             "guardian_upgrade_singleton_untrusted")
        try:
            fcntl.flock(singleton_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Refused("guardian_active_during_guard_upgrade") from error
        own_source(pending_guard_unit=True)
        installation = record(INSTALL)
        need(installation["guard_unit_sha256"] is None,
             "guardian_upgrade_requires_passive_generation")
        parent = INSTALL.parent
        p = parent.stat(follow_symlinks=False)
        need(stat.S_ISDIR(p.st_mode) and p.st_uid == 0 and
             p.st_mode & 0o022 == 0, "guardian_install_parent_untrusted")
        old_raw = regular(INSTALL, MAX_RECEIPT)
        need(json.loads(old_raw, object_pairs_hook=unique) == installation,
             "passive_install_changed_during_upgrade")
        installation["guard_unit_sha256"] = digest(regular(
            GUARD_UNIT_FILE, 1 << 16, 0o644))
        new_raw = (json.dumps(installation, sort_keys=True,
                              separators=(",", ":")) + "\n").encode()
        temporary = parent / (".auto-guardian-upgrade-" + secrets.token_hex(12))
        archive = parent / ("auto-guardian-install-passive-" +
                            secrets.token_hex(12) + ".json")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            need(os.write(fd, new_raw) == len(new_raw),
                 "guardian_upgrade_short_write")
            os.fsync(fd)
        finally:
            os.close(fd)
        archive_fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            need(os.write(archive_fd, old_raw) == len(old_raw),
                 "guardian_archive_short_write")
            os.fsync(archive_fd)
        finally:
            os.close(archive_fd)
        try:
            need(regular(INSTALL, MAX_RECEIPT) == old_raw,
                 "passive_install_replaced_during_upgrade")
            os.replace(temporary, INSTALL)
            directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            if temporary.exists():
                temporary.unlink()
            raise
        own_source()
        return True
    finally:
        os.close(singleton_fd)


def verified_module(path: Path, name: str) -> types.ModuleType:
    """Execute only the installed source bytes checked by own_source.

    Isolated Python still reads sibling bytecode cache on import.  Compiling
    the protected bytes directly makes the checked generation executable.
    Keep one module identity per installed generation: concurrent requests
    must never replace a dependency with a partially initialized module.
    """
    fields = {WITNESS: "witness_sha256", SINK_SOURCE: "sink_sha256",
              ROLLBACK_SOURCE: "rollback_sha256",
              CAPTURE_SOURCE: "capture_sha256"}
    fields[TOPOLOGY_SOURCE] = "topology_sha256"
    fields[CAPTURE_TOPOLOGY_SOURCE] = "capture_topology_sha256"
    fields[ENDPOINT_SOURCE] = "endpoint_sha256"
    fields[POLICY_SOURCE] = "guard_policy_source_sha256"
    fields[FOREIGN_SOURCE] = "foreign_policy_source_sha256"
    fields[FOREIGN_MONITOR_SOURCE] = "foreign_monitor_source_sha256"
    fields[INITRD_SOURCE] = "initrd_policy_source_sha256"
    fields[LAUNCH_SOURCE] = "launch_source_sha256"
    fields[WATCHDOG_SOURCE] = "watchdog_sha256"
    fields[ROOT/'aegis_auto_terminal_witness.py'] = 'terminal_witness_sha256'
    fields[ROOT/'aegis_auto_boot_transition.py'] = 'terminal_transition_sha256'
    dependencies = {
        ENDPOINT_SOURCE: ((CAPTURE_SOURCE, "aegis_auto_capture"),),
        POLICY_SOURCE: ((WITNESS, "aegis_auto_native_witness"),),
        WITNESS: ((FOREIGN_SOURCE, "aegis_auto_foreign_policy"),),
        FOREIGN_MONITOR_SOURCE: ((FOREIGN_SOURCE, "aegis_auto_foreign_policy"),),
    }
    need(path in fields and name == path.stem, "unadmitted_module")
    with _VERIFIED_MODULE_LOCK:
        installed = record(INSTALL)
        raw = regular(path, 1 << 20, 0o500)
        expected = installed[fields[path]]
        need(digest(raw) == expected, "installed_module_changed")
        # Both imports are executed by the installed source itself. Verify
        # their current bytes and identity even when the parent is cached.
        for dependency_path, dependency_name in dependencies.get(path, ()):
            verified_module(dependency_path, dependency_name)
        if path in dependencies:
            need(record(INSTALL) == installed,
                 "installed_module_generation_changed")
        cached = _VERIFIED_MODULES.get(name)
        if cached is not None:
            need(cached[:2] == (path, expected),
                 "installed_module_generation_changed")
            need(sys.modules.get(name) is cached[2],
                 "installed_module_identity_changed")
            return cached[2]
        need(name not in sys.modules, "installed_module_identity_changed")
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        try:
            exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
            if path == FOREIGN_SOURCE:
                # Global BPF link inventory needs SYS_ADMIN. The independent
                # watchdog already owns it; never add it to a private client.
                module._privileged_bpf_query = lambda interfaces: verified_module(
                    WATCHDOG_SOURCE, "aegis_auto_guardian_watchdog").privileged_bpf_query(interfaces)
            need(sys.modules.get(name) is module,
                 "installed_module_identity_changed")
        except BaseException:
            if sys.modules.get(name) is module:
                sys.modules.pop(name, None)
            raise
        _VERIFIED_MODULES[name] = (path, expected, module)
        return module


def provision_receipt(worker_path: Path) -> dict[str, object]:
    need(os.geteuid() == 0 and SOURCE.samefile(__file__),
         "installed_root_provision_required")
    need(Path("/proc/1/exe").resolve().name == "systemd" and
         os.stat("/proc/self/ns/pid").st_ino ==
         os.stat("/proc/1/ns/pid").st_ino,
         "host_pid1_required")
    worker = worker_path.stat(follow_symlinks=False)
    need(worker_path.is_absolute() and not worker_path.is_symlink() and
         stat.S_ISREG(worker.st_mode) and worker.st_uid == 0 and
         worker.st_nlink == 1 and worker.st_mode & 0o022 == 0 and
         worker.st_mode & 0o111 != 0, "untrusted_worker")
    if GUARD_UNIT_FILE.exists() or GUARD_UNIT_FILE.is_symlink():
        need(regular(GUARD_UNIT_FILE, 1 << 16, 0o644) ==
             EXPECTED_GUARD_UNIT, "foreign_guard_unit_at_provision")
    result = {
        "schema": "aegis_auto_guardian_install_v1",
        "guardian_sha256": digest(regular(SOURCE, 1 << 20, 0o500)),
        "witness_sha256": digest(regular(WITNESS, 1 << 20, 0o500)),
        "sink_sha256": digest(regular(SINK_SOURCE, 1 << 20, 0o500)),
        "rollback_sha256": digest(regular(ROLLBACK_SOURCE, 1 << 20, 0o500)),
        "capture_sha256": digest(regular(CAPTURE_SOURCE, 1 << 20, 0o500)),
        "topology_sha256": digest(regular(TOPOLOGY_SOURCE, 1 << 20, 0o500)),
        "capture_topology_sha256": digest(regular(CAPTURE_TOPOLOGY_SOURCE, 1 << 20, 0o500)),
        "endpoint_sha256": digest(regular(ENDPOINT_SOURCE, 1 << 20, 0o500)),
        "guard_policy_source_sha256": digest(regular(POLICY_SOURCE, 1 << 20, 0o500)),
        "foreign_policy_source_sha256": digest(regular(FOREIGN_SOURCE, 1 << 20, 0o500)),
        "foreign_monitor_source_sha256": digest(regular(FOREIGN_MONITOR_SOURCE, 1 << 20, 0o500)),
        "ufw_pins_sha256": digest(regular(UFW_PINS_SOURCE, 1 << 20, 0o500)),
        "initrd_policy_source_sha256": digest(regular(INITRD_SOURCE, 1 << 20, 0o500)),
        "foreign_monitor_unit_sha256": digest(regular(FOREIGN_UNIT_FILE, 1 << 20, 0o644)),
        "launch_source_sha256": digest(regular(LAUNCH_SOURCE, 1 << 20, 0o500)),
        "watchdog_sha256": digest(regular(WATCHDOG_SOURCE, 1 << 20, 0o500)),
        "watchdog_unit_sha256": digest(regular(WATCHDOG_UNIT_FILE, 1 << 16, 0o644)),
        "topology_unit_sha256": digest(regular(TOPOLOGY_UNIT_FILE, 1 << 16, 0o644)),
        "capture_topology_unit_sha256": digest(regular(CAPTURE_TOPOLOGY_UNIT_FILE, 1 << 16, 0o644)),
        "guard_helper_sha256": digest(regular(GUARD_HELPER, 1 << 20, 0o755)),
        "guard_unit_sha256": (
            digest(EXPECTED_GUARD_UNIT)
            if GUARD_UNIT_FILE.exists() and not GUARD_UNIT_FILE.is_symlink()
            else None),
        "guardian_unit_sha256": digest(regular(GUARDIAN_UNIT_FILE,
                                               1 << 16, 0o644)),
        "worker_sha256": executable_digest(worker_path),
        "guardian_unit": GUARDIAN_UNIT,
        "installation_anchor": installation_anchor(),
    }
    for field, path, mode in TERMINAL_INSTALLED_SOURCES:
        result[field] = digest(regular(path, 1 << 20, mode))
    return result


def seal_policy_receipt(guard_fd: int, *,
                        deadline: float | None = None) -> dict[str, object]:
    own_source()
    need(record(INSTALL)["guard_unit_sha256"] is not None,
         "wide_guard_unit_not_installed")
    guard_dev, guard_ino = _held_lock(guard_fd, GUARD_LOCK)
    state, projection = _semantic_policy_readback(deadline=deadline)
    return {
        "schema": "aegis_auto_guardian_policy_v1",
        "boot_id": host_anchor()["boot_id"],
        "netns_ino": host_anchor()["netns_ino"],
        "guard_dev": guard_dev,
        "guard_ino": guard_ino,
        "state_sha256": digest(state),
        "policy_sha256": digest(projection),
    }


def _publish_guard_binding(path: Path, value: dict[str, object]) -> None:
    """Atomically publish a small root-owned launch/capture authority receipt."""
    parent = path.parent
    info = parent.stat(follow_symlinks=False)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
         not info.st_mode & 0o022, "capture_binding_parent_untrusted")
    if path.exists() or path.is_symlink():
        regular(path, 4096)
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    need(len(raw) <= 4096, "capture_binding_too_large")
    temporary = parent / (".aegis-capture-binding-" + secrets.token_hex(12))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), "capture_binding_short_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    need(record(path, 4096) == value, "capture_binding_publish_changed")


def _remove_guard_binding(path: Path) -> None:
    """Durably revoke a protected launch receipt after the inverse proof."""
    parent = path.parent
    info = parent.stat(follow_symlinks=False)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
         not info.st_mode & 0o022, "capture_binding_parent_untrusted")
    record(path, 4096)
    path.unlink()
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    need(not path.exists() and not path.is_symlink(),
         "capture_binding_remove_changed")


def capture_binding_index(guard_fd: int) -> int:
    """Return the late FullTun ifindex only while the exact worker still owns it."""
    own_source()
    _held_lock(guard_fd, GUARD_LOCK)
    binding = record(CAPTURE_BINDING, 4096)
    client = record(Path(str(GUARD_STATE) + ".client-binding"), 4096)
    need(type(binding) is dict and set(binding) == {
        "schema", "boot_id", "netns_ino", "private_unit", "invocation_id",
        "main_pid", "ifindex", "worker_sha256", "client_path", "client_inode",
        "client_invocation"} and
        binding["schema"] == "aegis_device_guard_capture_binding_v1" and
        binding["boot_id"] == host_anchor()["boot_id"] and
        binding["netns_ino"] == host_anchor()["netns_ino"] and
        binding["private_unit"] == binding["client_path"].rsplit("/", 1)[-1] and
        PRIVATE_UNIT.fullmatch(binding["private_unit"]) is not None and
        (binding["client_path"], binding["client_inode"],
         binding["client_invocation"]) ==
        (client["path"], client["inode"], client["invocation"]) and
        client["boot_id"] == binding["boot_id"] and
        binding["invocation_id"] == client["invocation"] and
        type(binding["main_pid"]) is int and binding["main_pid"] > 1 and
        type(binding["ifindex"]) is int and binding["ifindex"] > 0 and
        type(binding["worker_sha256"]) is str and
        HEX64.fullmatch(binding["worker_sha256"]) is not None,
        "capture_binding_identity_invalid")
    capture = verified_module(CAPTURE_SOURCE, "aegis_auto_capture")
    pid = binding["main_pid"]
    pidfd = os.pidfd_open(pid, 0)
    try:
        facts = capture._service(binding["private_unit"])
        need(facts["ActiveState"] == "active" and
             facts["SubState"] == "running" and
             facts["MainPID"] == str(pid) and
             facts["InvocationID"] == binding["invocation_id"] and
             facts["ControlPID"] == "0", "capture_binding_pid1_changed")
        capture._pidfd_identity(pidfd, pid)
        capture._pid_live(pid, binding["worker_sha256"],
                          capture._cgroup(binding["private_unit"]))
        capture._tun_owned_by_pid(pid)
        detail = capture._json([str(capture.IP), "-j", "-d", "link", "show",
                                "dev", "aegis-tun0"])
        need(len(detail) == 1 and
             detail[0].get("linkinfo", {}).get("info_kind") == "tun" and
             detail[0].get("linkinfo", {}).get("info_data", {}).get("type") == "tun" and
             detail[0].get("linkinfo", {}).get("info_data", {}).get("persist") is False and
             detail[0].get("ifindex") == binding["ifindex"],
             "capture_binding_interface_type_changed")
        need(Path(f"/proc/{pid}/ns/net").stat().st_ino == binding["netns_ino"] and
             socket.if_nametoindex("aegis-tun0") == binding["ifindex"] and
             capture._link()[0] == binding["ifindex"],
             "capture_binding_link_changed")
        need(not select.select([pidfd], [], [], 0)[0] and
             capture._service(binding["private_unit"]) == facts and
             socket.if_nametoindex("aegis-tun0") == binding["ifindex"],
             "capture_binding_worker_exited")
        return binding["ifindex"]
    finally:
        os.close(pidfd)


def stopping_deny_readback(guard_fd: int) -> dict:
    """An idempotent block may retain only independently proven current deny."""
    own_source()
    _held_lock(guard_fd, GUARD_LOCK)
    policy = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    intent = record(STOP_INTENT)
    need(type(intent) is dict and type(intent.get("service")) is str and
         PRIVATE_UNIT.fullmatch(intent["service"]) is not None,
         "stopping_deny_owner_invalid")
    proof = policy.verify_stopping_guard(intent["service"],
                                         intent.get("invocation_id"))
    _held_lock(guard_fd, GUARD_LOCK)
    return proof


def _manager_live_facts(manager: dict, deadline: float) -> tuple[int, dict[str, str]]:
    """Recheck the protected manager's live PID1 owner and exact cgroup."""
    remaining = deadline - time.monotonic()
    need(remaining > 0, "guard_readback_deadline_elapsed")
    unit = manager["path"].rsplit("/", 1)[-1]
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", unit, "-p", "MainPID", "-p",
         "ControlGroup", "-p", "InvocationID", "-p", "ActiveState",
         "-p", "SubState", "--no-pager"], capture_output=True,
        timeout=min(2.0, remaining), check=False,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 4096 and
         len(result.stderr) <= 4096,
         "guard_readback_manager_unavailable")
    facts: dict[str, str] = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        need(separator == "=" and key not in facts,
             "guard_readback_manager_invalid")
        facts[key] = value
    need(set(facts) == {"MainPID", "ControlGroup", "InvocationID",
                        "ActiveState", "SubState"} and
         facts["MainPID"].isascii() and facts["MainPID"].isdecimal() and
         int(facts["MainPID"]) > 1 and
         facts["ControlGroup"] == "/" + manager["path"] and
         facts["InvocationID"] == manager["invocation"] and
         facts["ActiveState"] == "active" and
         facts["SubState"] == "running" and
         Path(f'/proc/{facts["MainPID"]}/cgroup').read_text(
             encoding="ascii") == "0::" + facts["ControlGroup"] + "\n",
         "guard_readback_manager_changed")
    info = (Path("/sys/fs/cgroup") / manager["path"]).stat(
        follow_symlinks=False)
    need(stat.S_ISDIR(info.st_mode) and
         info.st_ino == int(manager["inode"]) and
         time.monotonic() < deadline,
         "guard_readback_manager_changed")
    return int(facts["MainPID"]), facts


def read_guard_policy() -> dict[str, str | None]:
    """Read current installed deny semantics without changing any lease."""
    own_source()
    installed = record(INSTALL)
    need(installed["guard_unit_sha256"] is not None and
         installed["installation_anchor"] == installation_anchor(),
         "guard_readback_install_changed")
    saved = record(POLICY)
    guard = GUARD_LOCK.stat(follow_symlinks=False)
    need(type(saved) is dict and set(saved) ==
         {"schema", "boot_id", "netns_ino", "guard_dev", "guard_ino",
          "state_sha256", "policy_sha256"} and
         saved["schema"] == "aegis_auto_guardian_policy_v1" and
         saved["boot_id"] == host_anchor()["boot_id"] and
         saved["netns_ino"] == host_anchor()["netns_ino"] and
         stat.S_ISREG(guard.st_mode) and guard.st_uid == 0 and
         guard.st_nlink == 1 and stat.S_IMODE(guard.st_mode) == 0o600 and
         (saved["guard_dev"], saved["guard_ino"]) ==
         (guard.st_dev, guard.st_ino),
         "guard_readback_owner_changed")
    deadline = time.monotonic() + 7.0
    state_path = Path("/var/lib/aegis-install/client/device-guard.conf")
    state_before = regular(state_path, 1 << 15)
    manager_path = Path(str(state_path) + ".manager-binding")
    need(not manager_path.is_symlink(), "guard_readback_manager_changed")
    manager_raw = (regular(manager_path, 4096, 0o600)
                   if manager_path.exists() else None)
    guard_policy = verified_module(POLICY_SOURCE,
                                   "aegis_auto_guard_policy")
    parsed = guard_policy.parse_state(state_before)
    manager = (json.loads(manager_raw, object_pairs_hook=unique)
               if manager_raw is not None else None)
    guard_policy._binding(manager, "manager",
                          digest(state_before.rstrip(b"\n")),
                          parsed["manager"])
    if manager is not None:
        need(manager.get("schema") == "aegis_device_guard_binding_v2" and
             manager.get("ifindex") == socket.if_nametoindex(parsed["uplink"]),
             "guard_readback_manager_ifindex_changed")
    manager_pidfd = None
    first_manager = None
    try:
        if manager is not None:
            need(manager["boot_id"] == host_anchor()["boot_id"],
                 "guard_readback_manager_changed")
            manager_pid, first_manager = _manager_live_facts(manager, deadline)
            manager_pidfd = os.pidfd_open(manager_pid, 0)
            need(_pid_alive(manager_pidfd),
                 "guard_readback_manager_changed")
        state, projection = _semantic_policy_readback(deadline=deadline)
        need(state == state_before and
             digest(state) == saved["state_sha256"] and
             digest(projection) == saved["policy_sha256"] and
             _no_client_grant(projection),
             "guard_readback_not_denied")
        if manager is not None:
            _pid, second_manager = _manager_live_facts(manager, deadline)
            need(second_manager == first_manager and
                 _pid_alive(manager_pidfd) and
                 regular(manager_path, 4096, 0o600) == manager_raw,
                 "guard_readback_manager_changed")
        else:
            need(not manager_path.exists() and
                 not manager_path.is_symlink(),
                 "guard_readback_manager_changed")
    finally:
        if manager_pidfd is not None:
            os.close(manager_pidfd)
    return {"state_sha256": saved["state_sha256"],
            "policy_sha256": saved["policy_sha256"],
            "manager_binding_sha256": (digest(manager_raw)
                                       if manager_raw is not None else None)}


def _deny_without_bindings(deadline: float) -> tuple[bytes, bytes]:
    """Authenticate the just-applied restrictive batch before retiring a receipt."""
    witness = verified_module(WITNESS, "aegis_auto_native_witness")
    policy = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    state = regular(Path("/var/lib/aegis-install/client/device-guard.conf"), 1 << 15)
    client = Path("/var/lib/aegis-install/client/device-guard.conf.client-binding")
    need(not client.exists() and not client.is_symlink(),
         "stale_manager_client_binding_present")
    first = witness.read_policy_raw(Path("/usr/sbin/nft"), deadline=deadline)
    text = witness.read_policy_raw(Path("/usr/sbin/nft"), text=True,
                                   deadline=deadline)
    second = witness.read_policy_raw(Path("/usr/sbin/nft"), deadline=deadline)
    projection, _handles, _counters = witness.policy_projection(first)
    confirmed, _handles2, _counters2 = witness.policy_projection(second)
    need(projection == confirmed and _no_client_grant(projection) and
         policy.verify_expected_policy(state, first, text, None, None,
                                       boot_id=host_anchor()["boot_id"]) ==
         digest(projection), "stale_manager_kernel_not_denied")
    return state, projection


def archive_stale_manager_binding(guard_fd: int) -> str:
    """Retire an old-boot manager receipt only after the kernel is denied.

    The guard helper retains the original OFD across its atomic nft batch,
    this archive, and the following current-boot policy seal. A current-boot
    binding, even a broken one, is never silently retired here.
    """
    own_source()
    _held_lock(guard_fd, GUARD_LOCK)
    manager_path = Path(str(GUARD_STATE) + ".manager-binding")
    need(not manager_path.is_symlink(), "stale_manager_binding_untrusted")
    if not manager_path.exists():
        return "absent"
    old_raw = regular(manager_path, 4096)
    old = json.loads(old_raw, object_pairs_hook=unique)
    policy = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    need(type(old) is dict and old.get("schema") in
         ("aegis_device_guard_binding_v1", "aegis_device_guard_binding_v2") and
         set(old) == ({"schema", "boot_id", "state_sha256", "path", "inode", "invocation"} |
                      ({"ifindex", "dhcp4_server", "dhcp6_server"} if
                       old["schema"] == "aegis_device_guard_binding_v2" else set())) and
         type(old["boot_id"]) is str and
         policy.BOOT.fullmatch(old["boot_id"]) is not None and
         old["boot_id"] != host_anchor()["boot_id"] and
         type(old["state_sha256"]) is str and
         HEX64.fullmatch(old["state_sha256"]),
         "stale_manager_requires_old_boot")
    saved = record(POLICY)
    guard = GUARD_LOCK.stat(follow_symlinks=False)
    need(saved.get("schema") == "aegis_auto_guardian_policy_v1" and
         saved.get("boot_id") == old["boot_id"] and
         saved.get("state_sha256") == digest(regular(GUARD_STATE, 1 << 15)) and
         (saved.get("guard_dev"), saved.get("guard_ino")) ==
         (guard.st_dev, guard.st_ino), "stale_manager_prior_policy_changed")
    deadline = time.monotonic() + 7.0
    state, projection = _deny_without_bindings(deadline)
    parsed = policy.parse_state(state)
    policy._binding(old, "manager", old["state_sha256"], parsed["manager"])
    need(old["state_sha256"] == digest(state.rstrip(b"\n")) and
         regular(manager_path, 4096) == old_raw and
         time.monotonic() < deadline,
         "stale_manager_binding_changed")
    archive = manager_path.parent / ("device-guard-manager-oldboot-" +
                                     digest(old_raw) + ".json")
    if old["schema"] == "aegis_device_guard_binding_v2":
        # A previous BOOT marker seals the old kernel rule set. Preserve the
        # old policy receipt while the held OFD also proves the newly applied
        # no-manager table. The transition later matches both seals and this
        # exact old binding; a changed rule cannot be called retirement.
        count = int(parsed["dhcp4"] == "1") + int(parsed["dhcp6"] == "1")
        if count == 0:
            need(saved.get("policy_sha256") == digest(projection),
                 "stale_manager_zero_dhcp_seal_changed")
        else:
            policy.prove_manager_only_retirement(state, old)
            need(type(saved.get("policy_sha256")) is str and
                 HEX64.fullmatch(saved["policy_sha256"]) is not None and
                 saved["policy_sha256"] != digest(projection),
                 "stale_manager_policy_not_distinct")
            retirement = {
                "schema": "aegis_manager_oldboot_retirement_v1",
                "old_boot_id": old["boot_id"],
                "new_boot_id": host_anchor()["boot_id"],
                "old_policy_sha256": saved["policy_sha256"],
                "current_policy_sha256": digest(projection),
                "state_sha256": digest(state),
                "binding_sha256": digest(old_raw),
                "guard_dev": guard.st_dev, "guard_ino": guard.st_ino,
            }
            retirement_path = manager_path.parent / (
                "device-guard-manager-retired-" + old["boot_id"] + "-" +
                digest(old_raw) + ".json")
            _rotation_write_once(retirement_path, retirement)
    try:
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        need(regular(archive, 4096) == old_raw,
             "stale_manager_archive_conflict")
    else:
        try:
            need(os.write(fd, old_raw) == len(old_raw),
                 "stale_manager_archive_short_write")
            os.fsync(fd)
        finally:
            os.close(fd)
    need(regular(archive, 4096) == old_raw and
         regular(manager_path, 4096) == old_raw,
         "stale_manager_archive_changed")
    parent = os.open(manager_path.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
        os.unlink(manager_path)
        os.fsync(parent)
    finally:
        os.close(parent)
    need(not manager_path.exists() and not manager_path.is_symlink(),
         "stale_manager_retirement_incomplete")
    return digest(old_raw)


def _crossboot_policy_seals(old_boot: str, old_policy_sha: str,
                            base_policy_sha: str, projection: bytes) -> None:
    """Prove an old marker and current deny without equating different boots.

    Equality retains the historical v1 path. A different seal is admitted
    only through the exact old-manager retirement witnessed under GuardLock
    by the new boot's guard helper. The current full JSON/text table is always
    checked by the caller and against the current protected policy receipt.
    """
    need(type(old_boot) is str and type(old_policy_sha) is str and
         type(base_policy_sha) is str and
         HEX64.fullmatch(old_policy_sha) is not None and
         HEX64.fullmatch(base_policy_sha) is not None and
         _no_client_grant(projection),
         "crossboot_policy_input_invalid")
    saved = record(POLICY)
    anchor = host_anchor()
    current = anchor["boot_id"]
    guard = GUARD_LOCK.stat(follow_symlinks=False)
    state = regular(GUARD_STATE, 1 << 15)
    live_sha = digest(projection)
    need(type(saved) is dict and set(saved) ==
         {"schema", "boot_id", "netns_ino", "guard_dev", "guard_ino",
          "state_sha256", "policy_sha256"} and
         saved["schema"] == "aegis_auto_guardian_policy_v1" and
         saved["boot_id"] == current and
         saved["netns_ino"] == anchor["netns_ino"] and
         saved.get("policy_sha256") == live_sha and
         saved.get("state_sha256") == digest(state) and
         (saved.get("guard_dev"), saved.get("guard_ino")) ==
         (guard.st_dev, guard.st_ino), "crossboot_current_policy_changed")
    manager_path = GUARD_STATE.with_name(GUARD_STATE.name + ".manager-binding")
    client_path = GUARD_STATE.with_name(GUARD_STATE.name + ".client-binding")
    need(not manager_path.is_symlink() and
         not client_path.exists() and not client_path.is_symlink() and
         not CAPTURE_BINDING.exists() and not CAPTURE_BINDING.is_symlink(),
         "crossboot_owner_binding_retained")
    policy = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    if manager_path.exists():
        # Networkd may have obtained a fresh new-boot DHCP lease after the
        # managerless transition. Reprove its PID1 owner and full live table;
        # compare only a projection with its exact DHCP rule pairs removed.
        manager_raw = regular(manager_path, 4096, 0o600)
        manager = json.loads(manager_raw, object_pairs_hook=unique)
        need(manager.get("boot_id") == current and
             read_guard_policy()["policy_sha256"] == live_sha and
             regular(manager_path, 4096, 0o600) == manager_raw,
             "crossboot_current_manager_changed")
        base_projection = policy.without_current_manager(projection, state,
                                                         manager)
    else:
        base_projection = projection
    need(digest(base_projection) == base_policy_sha,
         "crossboot_deny_base_changed")
    if old_policy_sha == base_policy_sha:
        return
    need(policy.BOOT.fullmatch(old_boot) is not None and
         old_boot != current, "crossboot_old_boot_invalid")
    candidates = sorted(INSTALL.parent.glob(
        "device-guard-manager-retired-" + old_boot + "-*.json"))
    need(len(candidates) == 1, "crossboot_manager_retirement_not_unique")
    witness_path = candidates[0]
    witness = record(witness_path)
    binding_sha = witness.get("binding_sha256")
    need(type(binding_sha) is str and HEX64.fullmatch(binding_sha) is not None and
         witness_path.name == "device-guard-manager-retired-" + old_boot +
         "-" + binding_sha + ".json", "crossboot_manager_retirement_name_changed")
    archive = INSTALL.parent / ("device-guard-manager-oldboot-" +
                                binding_sha + ".json")
    old_raw = regular(archive, 4096, 0o600)
    old = json.loads(old_raw, object_pairs_hook=unique)
    need(old.get("boot_id") == old_boot and digest(old_raw) == binding_sha,
         "crossboot_manager_archive_changed")
    policy.prove_manager_only_retirement(state, old)
    need(witness == {
        "schema": "aegis_manager_oldboot_retirement_v1",
        "old_boot_id": old_boot, "new_boot_id": current,
        "old_policy_sha256": old_policy_sha,
        "current_policy_sha256": base_policy_sha,
        "state_sha256": digest(state), "binding_sha256": digest(old_raw),
        "guard_dev": guard.st_dev, "guard_ino": guard.st_ino,
    } and regular(witness_path, 4096, 0o600) ==
         (json.dumps(witness, sort_keys=True, separators=(",", ":")) + "\n").encode() and
         regular(archive, 4096, 0o600) == old_raw,
         "crossboot_manager_retirement_changed")


def _rotation_write_once(path: Path, value: dict[str, object]) -> bytes:
    """Create a protected phase record; an exact retry is read-only."""
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    maximum = MAX_ROTATION_INTENT if path == ROTATION_INTENT else MAX_RECEIPT
    need(0 < len(raw) <= maximum, "rotation_receipt_oversize")
    parent = path.parent.stat(follow_symlinks=False)
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
         parent.st_mode & 0o022 == 0, "rotation_parent_untrusted")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        need(regular(path, maximum) == raw,
             "rotation_receipt_conflict")
    else:
        try:
            need(os.write(fd, raw) == len(raw), "rotation_receipt_short_write")
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    need(regular(path, maximum) == raw,
         "rotation_receipt_changed")
    return raw


def _rotation_archive(path: Path, raw: bytes, label: str,
                      suffix: str = ".json", mode: int = 0o600,
                      maximum: int = MAX_RECEIPT) -> Path:
    need(re.fullmatch(r"[a-z-]{1,48}", label) is not None and
         suffix in (".json", ".sealed") and
         regular(path, maximum, mode) == raw, "rotation_archive_source_changed")
    archive = INSTALL.parent / (label + "-" + digest(raw) + suffix)
    try:
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        need(regular(archive, maximum) == raw,
             "rotation_archive_conflict")
    else:
        try:
            need(os.write(fd, raw) == len(raw),
                 "rotation_archive_short_write")
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(archive.parent, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    need(regular(archive, maximum) == raw,
         "rotation_archive_changed")
    return archive


def _retained_rotation_source(root: Path, relative: str, mode: int,
                              maximum: int = 1 << 20) -> bytes:
    need(root.is_absolute() and root.parent ==
         Path("/var/lib/aegis-auto/releases") and
         RETAINED_RELEASE.fullmatch(root.name) is not None,
         "rotation_release_root_invalid")
    current = Path("/")
    for component in (root / relative).parts[1:-1]:
        current /= component
        info = current.stat(follow_symlinks=False)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
             info.st_gid == 0 and info.st_mode & 0o022 == 0,
             "rotation_release_parent_changed")
    return regular(root / relative, maximum, mode)


def _rotation_sources(root: Path) -> dict[str, str]:
    return {field: digest(_retained_rotation_source(root, relative, mode))
            for field, relative, mode in ROTATION_SOURCES}

def _terminal_successor_sources(root: Path) -> dict[str, str]:
    # Next-generation-only check. Historical predecessor receipts have no
    # terminal fields and retain their original finite source schema.
    return {field: digest(_retained_rotation_source(root, relative, mode))
            for field, relative, mode in TERMINAL_RETAINED_SOURCES}


def _rotation_predecessor_sources(root: Path) -> dict[str, str]:
    """Rotation source digests of an already retained predecessor root.

    Installers before ee8816f5 kept the release bundle's exec bit, and the
    bundle chmods every helper script to 0755, so a predecessor may hold its
    read-only policy data at 0555 instead of 0444. Both are root-owned and
    unwritable, the exact mode is still re-checked on the opened file, and
    the digests still bind to the predecessor's install receipt. Every other
    mode refuses; a successor root is read with _rotation_sources only.
    """
    need(root.is_absolute() and root.parent ==
         Path("/var/lib/aegis-auto/releases") and
         RETAINED_RELEASE.fullmatch(root.name) is not None,
         "rotation_release_root_invalid")
    sources: dict[str, str] = {}
    for field, relative, mode in ROTATION_SOURCES:
        actual = stat.S_IMODE(os.lstat(root / relative).st_mode)
        need(actual == mode or mode == 0o444 and actual == 0o555,
             "untrusted_file")
        sources[field] = digest(_retained_rotation_source(root, relative, actual))
    return sources


def _retained_rotation_executable_digest(root: Path) -> str:
    candidate = root / "bin/aegis-client"
    need(root.is_absolute() and root.parent ==
         Path("/var/lib/aegis-auto/releases") and
         RETAINED_RELEASE.fullmatch(root.name) is not None,
         "rotation_release_root_invalid")
    current = Path("/")
    for component in candidate.parts[1:-1]:
        current /= component
        info = current.stat(follow_symlinks=False)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
             info.st_gid == 0 and info.st_mode & 0o022 == 0,
             "rotation_release_parent_changed")
    info = candidate.stat(follow_symlinks=False)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
         info.st_gid == 0 and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == 0o555,
         "rotation_candidate_invalid")
    return executable_digest(candidate)


def _rotation_static_sources(root: Path) -> dict[str, str]:
    return {unit: digest(_retained_rotation_source(root, relative, 0o444))
            for unit, relative in ROTATION_STATIC_UNITS}


def _rotation_guard_assets(state_raw: bytes) -> dict[str, tuple[Path, bytes]]:
    policy = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    state = policy.parse_state(state_raw)
    manager_dropin = (Path("/etc/systemd/system") /
                      (state["manager"] + ".d") /
                      "30-aegis-device-guard.conf")
    return {
        "state": (GUARD_STATE, state_raw),
        "guard_unit": (GUARD_UNIT_FILE,
                       regular(GUARD_UNIT_FILE, 1 << 16, 0o644)),
        "manager_dropin": (manager_dropin,
                           regular(manager_dropin, 1 << 16, 0o644)),
    }


def _rotation_prior_entries() -> tuple[tuple[str, Path, str, str, int], ...]:
    return (
        ("intent", ROTATION_INTENT, "auto-guard-prior-intent", ".json",
         MAX_ROTATION_INTENT),
        ("denied", ROTATION_DENIED, "auto-guard-prior-denied", ".json",
         MAX_RECEIPT),
        ("actor_intent", ROTATION_ACTOR_INTENT,
         "auto-guard-prior-actor-intent", ".json", MAX_RECEIPT),
        ("retired", ROTATION_RETIRED, "auto-guard-prior-retired", ".json",
         MAX_RECEIPT),
        ("assessment", ROTATION_ASSESSMENT,
         "auto-guard-prior-assessment", ".sealed", 1 << 15),
        ("handoff", ROTATION_HANDOFF, "auto-guard-prior-handoff", ".json",
         MAX_RECEIPT),
    )


def _rotation_advance_previous(verified: dict[str, object],
                               old_install_raw: bytes,
                               old_root: Path) -> None:
    """Archive a completed predecessor, never infer live state from its boot."""
    successor = verified["successor"]
    prior_sha = successor["prior_successor_intent_sha256"]
    if prior_sha is None:
        if ROTATION_INTENT.exists() or ROTATION_INTENT.is_symlink():
            existing = record(ROTATION_INTENT, MAX_ROTATION_INTENT)
            need(existing.get("successor", {}).get("intent_sha256") ==
                 successor["intent_sha256"],
                 "rotation_unrelated_prior_phase")
        else:
            need(not any(path.exists() or path.is_symlink()
                         for _name, path, _label, _suffix, _maximum
                         in _rotation_prior_entries()[1:]),
                 "rotation_orphan_prior_phase")
        return
    need(type(prior_sha) is str and HEX64.fullmatch(prior_sha) is not None,
         "rotation_prior_successor_invalid")
    advance = INSTALL.parent / ("auto-guard-rotation-advance-" +
                                successor["intent_sha256"] + ".json")
    previous: dict[str, bytes] = {}
    if advance.exists() or advance.is_symlink():
        manifest = record(advance)
        need(set(manifest) == {"schema", "prior_successor_intent_sha256",
                                "next_successor_intent_sha256",
                                "old_install_sha256", "old_public_payload_root",
                                "phase_sha256"} and
             manifest["schema"] == "aegis_auto_guard_rotation_advance_v1" and
             manifest["prior_successor_intent_sha256"] == prior_sha and
             manifest["next_successor_intent_sha256"] ==
             successor["intent_sha256"] and
             manifest["old_install_sha256"] == digest(old_install_raw) and
             manifest["old_public_payload_root"] == str(old_root) and
             type(manifest["phase_sha256"]) is dict and
             set(manifest["phase_sha256"]) ==
             {name for name, _path, _label, _suffix, _maximum
              in _rotation_prior_entries()},
             "rotation_prior_advance_changed")
        for name, _path, label, suffix, maximum in _rotation_prior_entries():
            sha = manifest["phase_sha256"][name]
            need(type(sha) is str and HEX64.fullmatch(sha) is not None,
                 "rotation_prior_advance_changed")
            previous[name] = regular(INSTALL.parent /
                                     (label + "-" + sha + suffix), maximum)
            need(digest(previous[name]) == sha,
                 "rotation_prior_archive_changed")
    else:
        previous = {name: regular(path, maximum)
                    for name, path, _label, _suffix, maximum
                    in _rotation_prior_entries()}
        prior_intent = json.loads(previous["intent"], object_pairs_hook=unique)
        prior_denied = json.loads(previous["denied"], object_pairs_hook=unique)
        handoff = json.loads(previous["handoff"], object_pairs_hook=unique)
        need(type(prior_intent) is dict and
             prior_intent.get("schema") ==
             "aegis_auto_guard_rotation_intent_v1" and
             type(prior_intent.get("successor")) is dict and
             prior_intent["successor"].get("intent_sha256") == prior_sha and
             prior_intent["successor"].get("next_public_payload_root") ==
             str(old_root) and
             prior_intent["successor"].get("next_candidate_sha256") ==
             record(INSTALL)["worker_sha256"] and
             type(prior_denied) is dict and
             set(prior_denied) ==
             {"schema", "boot_id", "intent_sha256", "old_install_sha256",
              "old_manager_sha256", "old_policy_sha256", "old_state_sha256",
              "deny_policy_sha256", "guard_device", "guard_inode"} and
             prior_denied["schema"] ==
             "aegis_auto_guard_rotation_denied_v1" and
             prior_denied["intent_sha256"] == digest(previous["intent"]) and
             prior_denied["boot_id"] == prior_intent["boot_id"] and
             all(prior_denied[key] == prior_intent[key] for key in
                 ("old_install_sha256", "old_manager_sha256",
                  "old_policy_sha256", "old_state_sha256", "guard_device",
                  "guard_inode")) and
             type(handoff) is dict and
             set(handoff) ==
             {"schema", "boot_id", "kind", "intent_sha256",
              "denied_sha256", "retired_sha256", "assessment_sha256",
              "state_sha256", "policy_sha256", "new_install_sha256",
              "candidate_sha256", "guard_device", "guard_inode",
              "no_client_grant", "no_manager_binding"} and
             handoff["schema"] ==
             "aegis_auto_guard_rotation_state_handoff_v1" and
             handoff["boot_id"] == prior_intent["boot_id"] and
             handoff["kind"] == prior_intent["successor"]["kind"] and
             handoff["intent_sha256"] == digest(previous["intent"]) and
             handoff["denied_sha256"] == digest(previous["denied"]) and
             handoff["retired_sha256"] == digest(previous["retired"]) and
             handoff["assessment_sha256"] == digest(previous["assessment"]) and
             handoff["state_sha256"] == handoff["assessment_sha256"] and
             handoff["new_install_sha256"] == digest(old_install_raw) and
             handoff["candidate_sha256"] ==
             prior_intent["successor"]["next_candidate_sha256"] and
             handoff["guard_device"] == prior_intent["guard_device"] and
             handoff["guard_inode"] == prior_intent["guard_inode"] and
             handoff["no_client_grant"] is True and
             handoff["no_manager_binding"] is True,
             "rotation_prior_phase_unverified")
        _rotation_retired_shape(prior_intent, prior_denied)
        for name, path, label, suffix, maximum in _rotation_prior_entries():
            _rotation_archive(path, previous[name], label, suffix, 0o600,
                              maximum)
        manifest = {
            "schema": "aegis_auto_guard_rotation_advance_v1",
            "prior_successor_intent_sha256": prior_sha,
            "next_successor_intent_sha256": successor["intent_sha256"],
            "old_install_sha256": digest(old_install_raw),
            "old_public_payload_root": str(old_root),
            "phase_sha256": {name: digest(raw)
                             for name, raw in previous.items()},
        }
        _rotation_write_once(advance, manifest)
    # An interruption after the manifest leaves only source-authenticated
    # predecessor leaves. Never remove a different or newly begun phase.
    # A retried prepare may already have published its own intent.  Never
    # mistake that new phase for a leftover predecessor or retire it.
    if ROTATION_INTENT.exists() or ROTATION_INTENT.is_symlink():
        current_intent = record(ROTATION_INTENT, MAX_ROTATION_INTENT)
        if (type(current_intent.get("successor")) is dict and
                current_intent["successor"].get("intent_sha256") ==
                successor["intent_sha256"]):
            need(advance.exists() and not advance.is_symlink(),
                 "rotation_prior_advance_missing")
            return
    directory = os.open(INSTALL.parent, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        for name, path, _label, _suffix, maximum in _rotation_prior_entries():
            need(not path.is_symlink(), "rotation_prior_phase_changed")
            if path.exists():
                need(regular(path, maximum) == previous[name],
                     "rotation_prior_phase_changed")
                os.unlink(path)
                os.fsync(directory)
    finally:
        os.close(directory)


def _rotation_coordinator(root: Path, install_fd: int) -> dict[str, object]:
    """Register only the exact retained incoming coordinator holding InstallLock."""
    pid = os.getppid()
    proc = Path('/proc') / str(pid)
    pidfd = os.pidfd_open(pid, 0)
    try:
        need(_pid_alive(pidfd), 'rotation_coordinator_exited')
        argv = proc.joinpath('cmdline').read_bytes()
        words = argv.rstrip(b'\0').split(b'\0')
        source = root / 'scripts/lib/aegis_installer_auto_v2.py'
        need(words[:5] == [b'/usr/bin/python3', b'-I', b'-B', os.fsencode(source),
                          b'upgrade-package'] and
             any(line.split() == ['Uid:', '0', '0', '0', '0'] for line in
                 proc.joinpath('status').read_text().splitlines()),
             'rotation_coordinator_identity_changed')
        executable = executable_digest(proc / 'exe')
        need(executable == executable_digest(Path('/usr/bin/python3')),
             'rotation_coordinator_interpreter_changed')
        install_identity = _held_lock(install_fd, INSTALL_LOCK)
        parent_info = proc.joinpath('fd/9').stat()
        need((parent_info.st_dev, parent_info.st_ino) == install_identity and
             _exclusive_flock_fdinfo(proc.joinpath('fdinfo/9').read_text(), parent_info),
             'rotation_coordinator_install_ofd_changed')
        birth = _passive_actor_tick(pid)
        result = {'pid': pid, 'birth': birth, 'argv_sha256': digest(argv),
                  'exe_sha256': executable, 'source': str(source),
                  'source_sha256': digest(_retained_rotation_source(
                      root, 'scripts/lib/aegis_installer_auto_v2.py', 0o444)),
                  'cgroup': proc.joinpath('cgroup').read_text(),
                  'install_device': install_identity[0], 'install_inode': install_identity[1]}
        need(_pid_alive(pidfd) and _passive_actor_tick(pid) == birth and
             proc.joinpath('cmdline').read_bytes() == argv, 'rotation_coordinator_changed')
        return result
    finally:
        os.close(pidfd)


def prepare_guard_rotation(install_fd: int, root: Path,
                           candidate: Path) -> dict[str, object]:
    """Bind old stopped authority to exact retained new source before guard lock."""
    own_source()
    _held_lock(install_fd, INSTALL_LOCK)
    old_install_raw = regular(INSTALL, MAX_RECEIPT)
    old = record(INSTALL)
    need(old["guard_unit_sha256"] is not None and
         candidate == root / "bin/aegis-client" and
         _retained_rotation_executable_digest(root) ==
         executable_digest(candidate), "rotation_candidate_invalid")
    installed = Path("/usr/local/bin/aegis-client")
    need(executable_digest(installed) == old["worker_sha256"],
         "rotation_old_client_changed")
    result = subprocess.run(
        [str(installed), "verify-stopped-successor", "--lock-fd",
         str(install_fd)], pass_fds=(install_fd,), stdin=subprocess.DEVNULL,
        capture_output=True, timeout=30, check=False,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and 0 < len(result.stdout) <= 128 << 10 and
         len(result.stderr) <= 4096, "rotation_successor_unverified")
    verified = json.loads(result.stdout, object_pairs_hook=unique)
    need(type(verified) is dict and set(verified) ==
         {"schema", "stopped", "successor"} and
         verified["schema"] ==
         "aegis_auto_v2_stopped_successor_verification_v1" and
         type(verified["stopped"]) is dict and
         type(verified["successor"]) is dict and
         set(verified["successor"]) ==
         {"intent_sha256", "old_active_sha256", "old_stopped_sha256",
          "next_public_payload_root", "next_candidate_binary",
          "next_candidate_sha256", "next_installer_sha256",
          "next_bundle_manifest_sha256", "next_sums_sha256", "kind",
          "prior_successor_intent_sha256"} and
         verified["successor"]["next_public_payload_root"] == str(root) and
         verified["successor"]["next_candidate_binary"] == str(candidate) and
         verified["successor"]["next_candidate_sha256"] ==
         _retained_rotation_executable_digest(root) and
         verified["successor"]["next_installer_sha256"] ==
         digest(_retained_rotation_source(root, "install.sh", 0o555)) and
         verified["successor"]["next_bundle_manifest_sha256"] ==
         digest(_retained_rotation_source(root, "bundle.manifest.json", 0o444)) and
         verified["successor"]["next_sums_sha256"] ==
         digest(_retained_rotation_source(root, "SHA256SUMS", 0o444)),
         "rotation_successor_changed")
    for name in ("intent_sha256", "old_active_sha256", "old_stopped_sha256",
                 "next_candidate_sha256", "next_installer_sha256",
                 "next_bundle_manifest_sha256", "next_sums_sha256"):
        need(type(verified["successor"][name]) is str and
             HEX64.fullmatch(verified["successor"][name]) is not None,
             "rotation_successor_digest_invalid")
    prior_successor = verified["successor"]["prior_successor_intent_sha256"]
    need(prior_successor is None or
         type(prior_successor) is str and
         HEX64.fullmatch(prior_successor) is not None,
         "rotation_prior_successor_invalid")
    # The Rust verifier is the authority for the stopped stage. The Python
    # intent stores only its canonical digest, never a caller-supplied hash.
    verified_raw = json.dumps(verified, sort_keys=True,
                              separators=(",", ":")).encode()
    old_root_value = verified["stopped"].get("input", {}).get(
        "public_payload_root")
    need(type(old_root_value) is str and
         RETAINED_RELEASE.fullmatch(Path(old_root_value).name) is not None and
         Path(old_root_value).parent == Path("/var/lib/aegis-auto/releases"),
         "rotation_old_payload_unavailable")
    old_root = Path(old_root_value)
    need(verified["successor"]["kind"] ==
         ("restart" if old_root == root else "upgrade"),
         "rotation_successor_kind_changed")
    old_rollback_unit = _retained_rotation_source(
        old_root, "packaging/systemd/aegis-auto-trace-rollback-actor.service",
        0o444)
    policy_raw = regular(POLICY, MAX_RECEIPT)
    policy = record(POLICY)
    current = read_guard_policy()
    need(current["manager_binding_sha256"] is not None and
         policy["policy_sha256"] == current["policy_sha256"],
         "rotation_old_policy_not_denied")
    manager = Path("/var/lib/aegis-install/client/device-guard.conf.manager-binding")
    manager_raw = regular(manager, 4096)
    state_raw = regular(Path("/var/lib/aegis-install/client/device-guard.conf"),
                        1 << 15)
    assets = _rotation_guard_assets(state_raw)
    need(digest(manager_raw) == current["manager_binding_sha256"] and
         digest(state_raw) == current["state_sha256"] and
         regular(INSTALL, MAX_RECEIPT) == old_install_raw,
         "rotation_old_generation_changed")
    guard = GUARD_LOCK.stat(follow_symlinks=False)
    intent = {
        "schema": "aegis_auto_guard_rotation_intent_v1",
        "boot_id": host_anchor()["boot_id"],
        "stopped_successor_sha256": digest(verified_raw),
        "old_public_payload_root": str(old_root),
        "old_rollback_unit_sha256": digest(old_rollback_unit),
        "old_static_units": _rotation_static_sources(old_root),
        "successor": verified["successor"],
        "next_sources": _rotation_sources(root),
        "next_static_units": _rotation_static_sources(root),
        "next_rollback_unit_sha256": digest(_retained_rotation_source(
            root, "packaging/systemd/aegis-auto-trace-rollback-actor.service",
            0o444)),
        "old_install_sha256": digest(old_install_raw),
        "old_policy_sha256": digest(policy_raw),
        "old_manager_sha256": digest(manager_raw),
        "old_state_sha256": digest(state_raw),
        "old_guard_unit_sha256": digest(assets["guard_unit"][1]),
        "old_manager_dropin_sha256": digest(assets["manager_dropin"][1]),
        "guard_device": guard.st_dev, "guard_inode": guard.st_ino,
        "coordinator": _rotation_coordinator(root, install_fd),
    }
    if prior_successor is not None:
        # This independent, short-lived acquisition is only for retiring
        # immutable predecessor records.  The coordinator takes the original
        # guard OFD for kernel mutation after this command returns.
        temporary_guard = os.open(GUARD_LOCK, os.O_RDONLY | os.O_CLOEXEC |
                                  os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            fcntl.flock(temporary_guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _held_lock(temporary_guard, GUARD_LOCK)
            need(read_guard_policy() == current and
                 regular(INSTALL, MAX_RECEIPT) == old_install_raw,
                 "rotation_old_generation_changed")
            _rotation_advance_previous(verified, old_install_raw, old_root)
            need(read_guard_policy() == current and
                 _held_lock(temporary_guard, GUARD_LOCK) ==
                 (guard.st_dev, guard.st_ino),
                 "rotation_advance_policy_changed")
        finally:
            os.close(temporary_guard)
    else:
        _rotation_advance_previous(verified, old_install_raw, old_root)
    _rotation_write_once(ROTATION_INTENT, intent)
    _held_lock(install_fd, INSTALL_LOCK)
    need(regular(INSTALL, MAX_RECEIPT) == old_install_raw,
         "rotation_old_generation_changed")
    return intent


def _rotation_intent(guard_fd: int) -> dict[str, object]:
    """Reopen only the protected verifier-derived source transition."""
    _held_lock(guard_fd, GUARD_LOCK)
    intent = record(ROTATION_INTENT, MAX_ROTATION_INTENT)
    need(set(intent) == {"schema", "boot_id", "stopped_successor_sha256",
                         "old_public_payload_root", "old_rollback_unit_sha256",
                         "old_static_units", "next_static_units",
                         "next_rollback_unit_sha256",
                         "successor", "next_sources", "old_install_sha256",
                         "old_policy_sha256", "old_manager_sha256",
                         "old_state_sha256", "old_guard_unit_sha256",
                         "old_manager_dropin_sha256", "guard_device",
                         "guard_inode", "coordinator"} and
         intent["schema"] == "aegis_auto_guard_rotation_intent_v1" and
         intent["boot_id"] == host_anchor()["boot_id"] and
         type(intent["successor"]) is dict and
         set(intent["successor"]) ==
         {"intent_sha256", "old_active_sha256", "old_stopped_sha256",
          "next_public_payload_root", "next_candidate_binary",
          "next_candidate_sha256", "next_installer_sha256",
          "next_bundle_manifest_sha256", "next_sums_sha256", "kind",
          "prior_successor_intent_sha256"} and
         intent["successor"]["kind"] in ("restart", "upgrade") and
         (intent["successor"]["prior_successor_intent_sha256"] is None or
          type(intent["successor"]["prior_successor_intent_sha256"]) is str and
          HEX64.fullmatch(intent["successor"]
                           ["prior_successor_intent_sha256"]) is not None) and
         type(intent["next_sources"]) is dict and
         set(intent["next_sources"]) ==
         {field for field, _relative, _mode in ROTATION_SOURCES} and
         type(intent["old_static_units"]) is dict and
         type(intent["next_static_units"]) is dict and
         set(intent["old_static_units"]) ==
         {unit for unit, _relative in ROTATION_STATIC_UNITS} and
         set(intent["next_static_units"]) ==
         {unit for unit, _relative in ROTATION_STATIC_UNITS} and
         all(type(value) is str and HEX64.fullmatch(value) is not None
             for source_set in (intent["old_static_units"],
                                intent["next_static_units"])
             for value in source_set.values()) and
         all(type(value) is str and HEX64.fullmatch(value) is not None
             for value in intent["next_sources"].values()) and
         all(type(intent[key]) is str and HEX64.fullmatch(intent[key]) is not None
             for key in ("stopped_successor_sha256", "old_rollback_unit_sha256",
                         "next_rollback_unit_sha256",
                         "old_install_sha256",
                         "old_policy_sha256", "old_manager_sha256",
                         "old_state_sha256", "old_guard_unit_sha256",
                         "old_manager_dropin_sha256")) and
         all(type(intent["successor"][key]) is str and
             HEX64.fullmatch(intent["successor"][key]) is not None
             for key in ("intent_sha256", "old_active_sha256",
                         "old_stopped_sha256", "next_candidate_sha256",
                         "next_installer_sha256",
                         "next_bundle_manifest_sha256", "next_sums_sha256")) and
         (intent["guard_device"], intent["guard_inode"]) ==
         _held_lock(guard_fd, GUARD_LOCK),
         "rotation_intent_changed")
    successor_raw = regular(SUCCESSOR, MAX_RECEIPT)
    need(digest(successor_raw) == intent["successor"]["intent_sha256"],
         "rotation_successor_intent_changed")
    root = Path(intent["successor"]["next_public_payload_root"])
    candidate = Path(intent["successor"]["next_candidate_binary"])
    need(candidate == root / "bin/aegis-client" and
         _rotation_sources(root) == intent["next_sources"] and
         _retained_rotation_executable_digest(root) ==
         intent["successor"]["next_candidate_sha256"] and
         digest(_retained_rotation_source(root, "install.sh", 0o555)) ==
         intent["successor"]["next_installer_sha256"] and
         digest(_retained_rotation_source(root, "bundle.manifest.json", 0o444)) ==
         intent["successor"]["next_bundle_manifest_sha256"] and
         digest(_retained_rotation_source(root, "SHA256SUMS", 0o444)) ==
         intent["successor"]["next_sums_sha256"],
         "rotation_retained_source_changed")
    old_root = Path(intent["old_public_payload_root"])
    need(intent["successor"]["kind"] ==
         ("restart" if old_root == root else "upgrade"),
         "rotation_successor_kind_changed")
    need(digest(_retained_rotation_source(
        old_root, "packaging/systemd/aegis-auto-trace-rollback-actor.service",
        0o444)) == intent["old_rollback_unit_sha256"],
        "rotation_old_actor_source_changed")
    need(digest(_retained_rotation_source(
        root, "packaging/systemd/aegis-auto-trace-rollback-actor.service",
        0o444)) == intent["next_rollback_unit_sha256"],
        "rotation_new_actor_source_changed")
    need(_rotation_static_sources(old_root) == intent["old_static_units"] and
         _rotation_static_sources(root) == intent["next_static_units"],
         "rotation_static_source_changed")
    return intent


def _rotation_manager_archive(intent: dict[str, object]) -> bytes:
    current = Path("/var/lib/aegis-install/client/device-guard.conf.manager-binding")
    archived = current.parent / ("auto-guard-manager-rotation-" +
                                 intent["old_manager_sha256"] + ".json")
    need(not current.is_symlink(), "rotation_manager_changed")
    raw = regular(current, 4096) if current.exists() else regular(archived, 4096)
    need(digest(raw) == intent["old_manager_sha256"],
         "rotation_manager_changed")
    return raw


def rotation_preflight(guard_fd: int) -> str:
    own_source()
    intent = _rotation_intent(guard_fd)
    need(digest(regular(INSTALL, MAX_RECEIPT)) ==
         intent["old_install_sha256"] and
         digest(regular(Path("/var/lib/aegis-install/client/device-guard.conf"),
                        1 << 15)) == intent["old_state_sha256"],
         "rotation_old_generation_changed")
    _rotation_manager_archive(intent)
    if ROTATION_DENIED.exists() or ROTATION_DENIED.is_symlink():
        denied = record(ROTATION_DENIED)
        need(denied.get("schema") == "aegis_auto_guard_rotation_denied_v1" and
             denied.get("intent_sha256") == digest(regular(ROTATION_INTENT, MAX_ROTATION_INTENT)) and
             denied.get("old_manager_sha256") == intent["old_manager_sha256"],
             "rotation_denied_phase_changed")
        state, projection = _deny_without_bindings(time.monotonic() + 7.0)
        need(digest(state) == intent["old_state_sha256"] and
             digest(projection) == denied.get("deny_policy_sha256"),
             "rotation_denied_kernel_changed")
        return "denied"
    need(digest(regular(POLICY, MAX_RECEIPT)) ==
         intent["old_policy_sha256"] and
         read_guard_policy()["manager_binding_sha256"] ==
         intent["old_manager_sha256"], "rotation_old_policy_changed")
    return "prepared"


def commit_rotation_deny(guard_fd: int) -> dict[str, object]:
    """Archive old authority only after the no-grant nft batch is verified."""
    own_source()
    intent = _rotation_intent(guard_fd)
    old_install = regular(INSTALL, MAX_RECEIPT)
    old_policy = regular(POLICY, MAX_RECEIPT)
    manager_raw = _rotation_manager_archive(intent)
    need(digest(old_install) == intent["old_install_sha256"] and
         digest(regular(Path("/var/lib/aegis-install/client/device-guard.conf"),
                        1 << 15)) == intent["old_state_sha256"],
         "rotation_old_generation_changed")
    state, projection = _deny_without_bindings(time.monotonic() + 7.0)
    need(digest(state) == intent["old_state_sha256"],
         "rotation_state_changed_after_deny")
    _rotation_archive(INSTALL, old_install, "auto-guardian-install-guarded")
    _rotation_archive(POLICY, old_policy, "auto-guardian-policy-guarded")
    assets = _rotation_guard_assets(state)
    need(digest(assets["guard_unit"][1]) ==
         intent["old_guard_unit_sha256"] and
         digest(assets["manager_dropin"][1]) ==
         intent["old_manager_dropin_sha256"],
         "rotation_old_guard_assets_changed")
    for name, label, mode, maximum in (
            ("state", "auto-guard-state-rotation", 0o600, 1 << 15),
            ("guard_unit", "auto-guard-unit-rotation", 0o644, 1 << 16),
            ("manager_dropin", "auto-guard-manager-dropin-rotation",
             0o644, 1 << 16)):
        path, raw = assets[name]
        _rotation_archive(path, raw, label, ".sealed", mode, maximum)
    manager = Path("/var/lib/aegis-install/client/device-guard.conf.manager-binding")
    archive = manager.parent / ("auto-guard-manager-rotation-" +
                                intent["old_manager_sha256"] + ".json")
    if manager.exists():
        _rotation_archive(manager, manager_raw, "auto-guard-manager-rotation")
        need(regular(archive, 4096) == manager_raw and
             regular(manager, 4096) == manager_raw,
             "rotation_manager_archive_changed")
        directory = os.open(manager.parent, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.unlink(manager)
            os.fsync(directory)
        finally:
            os.close(directory)
    need(not manager.exists() and not manager.is_symlink() and
         regular(archive, 4096) == manager_raw,
         "rotation_manager_not_retired")
    denied = {"schema": "aegis_auto_guard_rotation_denied_v1",
              "boot_id": intent["boot_id"],
              "intent_sha256": digest(regular(ROTATION_INTENT, MAX_ROTATION_INTENT)),
              "old_install_sha256": intent["old_install_sha256"],
              "old_manager_sha256": intent["old_manager_sha256"],
              "old_policy_sha256": intent["old_policy_sha256"],
              "old_state_sha256": intent["old_state_sha256"],
              "deny_policy_sha256": digest(projection),
              "guard_device": intent["guard_device"],
              "guard_inode": intent["guard_inode"]}
    # The policy receipt is deliberately resealed by the old helper after
    # this phase. A retry may observe either the old receipt or that exact
    # current deny seal, and never accepts unrelated policy bytes.
    saved_policy = record(POLICY)
    need(digest(old_policy) == intent["old_policy_sha256"] or
         (ROTATION_DENIED.exists() and
          saved_policy.get("schema") == "aegis_auto_guardian_policy_v1" and
          saved_policy.get("boot_id") == intent["boot_id"] and
          saved_policy.get("state_sha256") == intent["old_state_sha256"] and
          saved_policy.get("policy_sha256") == digest(projection)),
         "rotation_policy_invalid")
    _rotation_write_once(ROTATION_DENIED, denied)
    return denied


def _rotation_denied(intent: dict[str, object]) -> dict[str, object]:
    denied = record(ROTATION_DENIED)
    need(set(denied) == {"schema", "boot_id", "intent_sha256",
                         "old_install_sha256", "old_manager_sha256",
                         "old_policy_sha256", "old_state_sha256",
                         "deny_policy_sha256", "guard_device", "guard_inode"} and
         denied["schema"] == "aegis_auto_guard_rotation_denied_v1" and
         denied["boot_id"] == intent["boot_id"] and
         denied["intent_sha256"] == digest(regular(ROTATION_INTENT, MAX_ROTATION_INTENT)) and
         all(denied[key] == intent[key] for key in
             ("old_install_sha256", "old_manager_sha256",
              "old_policy_sha256", "old_state_sha256", "guard_device",
              "guard_inode")) and
         type(denied["deny_policy_sha256"]) is str and
         HEX64.fullmatch(denied["deny_policy_sha256"]) is not None,
         "rotation_denied_record_changed")
    manager = Path("/var/lib/aegis-install/client/device-guard.conf.manager-binding")
    client = Path("/var/lib/aegis-install/client/device-guard.conf.client-binding")
    need(not manager.exists() and not manager.is_symlink() and
         not client.exists() and not client.is_symlink() and
         digest(regular(INSTALL.parent /
                        ("auto-guardian-install-guarded-" +
                         intent["old_install_sha256"] + ".json"),
                        MAX_RECEIPT)) == intent["old_install_sha256"] and
         digest(regular(manager.parent /
                        ("auto-guard-manager-rotation-" +
                         intent["old_manager_sha256"] + ".json"),
                        4096)) == intent["old_manager_sha256"],
         "rotation_old_archive_changed")
    for name, label, key, maximum in (
            ("state", "auto-guard-state-rotation", "old_state_sha256",
             1 << 15),
            ("guard_unit", "auto-guard-unit-rotation",
             "old_guard_unit_sha256", 1 << 16),
            ("manager_dropin", "auto-guard-manager-dropin-rotation",
             "old_manager_dropin_sha256", 1 << 16)):
        archive = INSTALL.parent / (label + "-" + intent[key] + ".sealed")
        need(digest(regular(archive, maximum)) == intent[key],
             "rotation_old_archive_changed")
    need(digest(regular(INSTALL.parent /
                        ("auto-guardian-policy-guarded-" +
                         intent["old_policy_sha256"] + ".json"),
                        MAX_RECEIPT)) == intent["old_policy_sha256"],
         "rotation_old_archive_changed")
    return denied


def _rotation_verified_witness(intent: dict[str, object]) -> types.ModuleType:
    """Load only retained and installed byte-identical witness source."""
    raw = regular(WITNESS, 1 << 20, 0o500)
    need(digest(raw) == intent["next_sources"]["witness_sha256"],
         "rotation_new_witness_changed")
    module = types.ModuleType("aegis_auto_rotation_witness")
    module.__file__ = str(WITNESS)
    missing = object()
    previous = sys.modules.get(module.__name__, missing)
    sys.modules[module.__name__] = module
    try:
        exec(compile(raw, str(WITNESS), "exec", dont_inherit=True), module.__dict__)
    finally:
        if previous is missing:
            sys.modules.pop(module.__name__, None)
        else:
            sys.modules[module.__name__] = previous
    return module


def _rotation_verified_policy(intent: dict[str, object],
                              witness: types.ModuleType) -> types.ModuleType:
    raw = regular(POLICY_SOURCE, 1 << 20, 0o500)
    need(digest(raw) == intent["next_sources"]["guard_policy_source_sha256"],
         "rotation_new_policy_source_changed")
    module = types.ModuleType("aegis_auto_rotation_policy")
    module.__file__ = str(POLICY_SOURCE)
    previous = sys.modules.get("aegis_auto_native_witness")
    sys.modules["aegis_auto_native_witness"] = witness
    try:
        exec(compile(raw, str(POLICY_SOURCE), "exec", dont_inherit=True), module.__dict__)
    finally:
        if previous is None:
            sys.modules.pop("aegis_auto_native_witness", None)
        else:
            sys.modules["aegis_auto_native_witness"] = previous
    return module


def _rotation_current_deny(intent: dict[str, object],
                           denied: dict[str, object]) -> None:
    witness = _rotation_verified_witness(intent)
    policy = _rotation_verified_policy(intent, witness)
    deadline = time.monotonic() + 7.0
    first = witness.read_policy_raw(Path("/usr/sbin/nft"), deadline=deadline)
    text = witness.read_policy_raw(Path("/usr/sbin/nft"), text=True,
                                   deadline=deadline)
    second = witness.read_policy_raw(Path("/usr/sbin/nft"), deadline=deadline)
    projection, _handles, _counters = witness.policy_projection(first)
    confirmed, _handles2, _counters2 = witness.policy_projection(second)
    state = regular(Path("/var/lib/aegis-install/client/device-guard.conf"),
                    1 << 15)
    need(type(text) is bytes and 0 < len(text) <= 1 << 20 and
         projection == confirmed and _no_client_grant(projection) and
         policy.verify_expected_policy(state, first, text, None, None,
                                       boot_id=intent["boot_id"]) ==
         digest(projection) and
         digest(projection) == denied["deny_policy_sha256"] and
         digest(state) == intent["old_state_sha256"] and
         time.monotonic() < deadline,
         "rotation_kernel_deny_changed")
    saved = record(POLICY)
    need(saved.get("schema") == "aegis_auto_guardian_policy_v1" and
         saved.get("boot_id") == intent["boot_id"] and
         saved.get("state_sha256") == intent["old_state_sha256"] and
         saved.get("policy_sha256") == denied["deny_policy_sha256"],
         "rotation_policy_not_sealed")


def admit_guarded_rotation(install_fd: int, guard_fd: int) -> str:
    """Publish the exact new guarded source while both original locks live."""
    _held_lock(install_fd, INSTALL_LOCK)
    intent = _rotation_intent(guard_fd)
    denied = _rotation_denied(intent)
    _rotation_retired_shape(intent, denied)
    _rotation_actors_stopped(time.monotonic() + 20.0)
    _rotation_static_stopped(time.monotonic() + 20.0)
    _rotation_current_deny(intent, denied)
    root = Path(intent["successor"]["next_public_payload_root"])
    candidate = Path(intent["successor"]["next_candidate_binary"])
    need(_rotation_sources(root) == intent["next_sources"] and
         _rotation_static_sources(root) == intent["next_static_units"] and
         _retained_rotation_executable_digest(root) ==
         intent["successor"]["next_candidate_sha256"],
         "rotation_candidate_changed")
    new_install = provision_receipt(candidate)
    need(new_install["guard_unit_sha256"] == digest(EXPECTED_GUARD_UNIT) and
         new_install["worker_sha256"] ==
         intent["successor"]["next_candidate_sha256"] and
         all(new_install[field] == expected for field, expected in
             intent["next_sources"].items()) and
         all(new_install[field] == expected for field, expected in
             _terminal_successor_sources(root).items()) and
         digest(regular(INSTALL, MAX_RECEIPT)) == intent["old_install_sha256"] and
         digest(regular(SOURCE, 1 << 20, 0o500)) ==
         intent["next_sources"]["guardian_sha256"] and
         digest(regular(Path("/etc/systemd/system/"
                             "aegis-auto-trace-rollback-actor.service"),
                        1 << 16, 0o644)) ==
         intent["next_rollback_unit_sha256"] and
         all(digest(regular(Path("/etc/systemd/system") / unit,
                            1 << 16, 0o644)) == expected
             for unit, expected in intent["next_static_units"].items()),
         "rotation_installed_source_not_candidate")
    raw = (json.dumps(new_install, sort_keys=True,
                      separators=(",", ":")) + "\n").encode()
    need(len(raw) <= MAX_RECEIPT, "rotation_new_install_oversize")
    temporary = INSTALL.parent / (".auto-guard-rotation-" +
                                  secrets.token_hex(12))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), "rotation_install_short_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        _held_lock(install_fd, INSTALL_LOCK)
        _held_lock(guard_fd, GUARD_LOCK)
        need(digest(regular(INSTALL, MAX_RECEIPT)) ==
             intent["old_install_sha256"],
             "rotation_old_install_changed")
        _rotation_current_deny(intent, denied)
        os.replace(temporary, INSTALL)
        directory = os.open(INSTALL.parent, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise
    own_source()
    need(regular(INSTALL, MAX_RECEIPT) == raw,
         "rotation_new_install_changed")
    return digest(raw)


def _rotation_actor_facts(unit: str, *, deadline: float) -> dict[str, str]:
    need(any(unit == item[0] for item in ROTATION_ACTORS),
         "rotation_actor_unknown")
    remaining = deadline - time.monotonic()
    need(remaining > 0, "rotation_actor_deadline_elapsed")
    names = ("Id", "LoadState", "FragmentPath", "ActiveState", "SubState",
             "MainPID", "ControlPID", "ControlGroup", "InvocationID",
             "NFileDescriptorStore")
    command = ["/usr/bin/systemctl", "show", unit, "--no-pager"]
    for name in names:
        command.extend(("-p", name))
    result = subprocess.run(command, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=min(3.0, remaining),
                            check=False,
                            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C",
                                 "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 8192 and
         len(result.stderr) <= 4096, "rotation_actor_pid1_unavailable")
    facts: dict[str, str] = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        need(sep == "=" and key not in facts,
             "rotation_actor_pid1_invalid")
        facts[key] = value
    expected_path = next(str(path) for name, _source, path in
                         ROTATION_ACTORS if name == unit)
    need(set(facts) == set(names) and facts["Id"] == unit and
         facts["LoadState"] == "loaded" and
         facts["FragmentPath"] == expected_path and
         all(facts[name].isascii() and facts[name].isdecimal()
             for name in ("MainPID", "ControlPID", "NFileDescriptorStore")),
         "rotation_actor_pid1_changed")
    return facts


def _rotation_actor_command(unit: str, source: Path) -> bytes:
    need(any((unit, source) == (name, path) for name, path, _unit in
             ROTATION_ACTORS), "rotation_actor_unknown")
    suffix = (b"\0" if unit == "aegis-foreign-policy-monitor.service"
              else b"\0serve\0")
    return b"/usr/bin/python3\0-I\0-B\0" + os.fsencode(source) + suffix


def _rotation_actor_source(unit: str, intent: dict[str, object]) -> None:
    name, source, unit_path = next(item for item in ROTATION_ACTORS
                                   if item[0] == unit)
    installed = record(INSTALL)
    source_field = {
        "aegis-auto-guardian.service": ("guardian_sha256", "guardian_unit_sha256"),
        "aegis-auto-guardian-watchdog.service": ("watchdog_sha256", "watchdog_unit_sha256"),
        "aegis-auto-witness-topology.service": ("topology_sha256", "topology_unit_sha256"),
        "aegis-auto-capture-topology.service":
            ("capture_topology_sha256", "capture_topology_unit_sha256"),
        "aegis-auto-trace-rollback-actor.service": ("rollback_sha256", None),
        "aegis-foreign-policy-monitor.service":
            ("foreign_monitor_source_sha256", "foreign_monitor_unit_sha256"),
    }[name]
    need(digest(regular(source, 1 << 20, 0o500)) ==
         installed[source_field[0]], "rotation_actor_source_changed")
    actual_unit = digest(regular(unit_path, 1 << 16, 0o644))
    if source_field[1] is None:
        need(actual_unit == intent["old_rollback_unit_sha256"],
             "rotation_actor_unit_changed")
    else:
        need(actual_unit == installed[source_field[1]],
             "rotation_actor_unit_changed")


def _rotation_actor_jobs(deadline: float) -> None:
    remaining = deadline - time.monotonic()
    need(remaining > 0, "rotation_actor_deadline_elapsed")
    result = subprocess.run(
        ["/usr/bin/systemctl", "list-jobs", "--no-legend", "--no-pager",
         "--plain"], stdin=subprocess.DEVNULL, capture_output=True,
        timeout=min(3.0, remaining), check=False,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 1 << 16 and
         len(result.stderr) <= 4096, "rotation_actor_job_pending")
    need(result.stderr == b"", "rotation_actor_job_pending")
    lines = result.stdout.decode("ascii").splitlines()
    pending = [line.split() for line in lines if "aegis-" in line]
    if pending:
        # Only an exact, successful PID1 job row is a transient boot condition.
        # A command error, warning or malformed row retains fail-closed refusal.
        need(all(
            len(row) == 4 and row[0].isdecimal() and 0 < int(row[0]) < 1 << 31 and
            re.fullmatch(r"aegis-[A-Za-z0-9_.@-]{1,180}"
                         r"\.(?:service|timer|target|socket|path)", row[1]) and
            row[2] in {"start", "stop", "restart", "reload", "try-restart",
                       "reload-or-restart"} and row[3] in {"waiting", "running"}
            for row in pending), "rotation_actor_job_pending")
        # Boot readiness may wait only for this source-owned refresh start.
        # own_source authenticates its installed service/timer, and the boot
        # caller first authenticates its current manager policy and binding.
        # An unrelated Aegis job cannot become transient admission evidence.
        need(all(row[1] == "aegis-device-dhcp-refresh.service" and
                 row[2] == "start" for row in pending),
             "rotation_actor_job_pending")
        raise RotationActorJobPending("rotation_actor_job_pending")


def _rotation_static_facts(unit: str, *, deadline: float) -> dict[str, str]:
    need(unit in {name for name, _relative in ROTATION_STATIC_UNITS},
         "rotation_static_unit_unknown")
    remaining = deadline - time.monotonic()
    need(remaining > 0, "rotation_static_deadline_elapsed")
    common = ("Id", "LoadState", "FragmentPath", "ActiveState", "SubState",
              "InvocationID", "UnitFileState", "Triggers", "TriggeredBy")
    timer = unit.endswith(".timer")
    names = (common + ("NextElapseUSecRealtime", "NextElapseUSecMonotonic")
             if timer else common + ("MainPID", "ControlPID", "ControlGroup",
                                     "NFileDescriptorStore"))
    command = ["/usr/bin/systemctl", "show", unit, "--no-pager"]
    for name in names:
        command.extend(("-p", name))
    result = subprocess.run(command, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=min(3.0, remaining),
                            check=False,
                            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C",
                                 "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 8192 and
         len(result.stderr) <= 4096, "rotation_static_pid1_unavailable")
    facts: dict[str, str] = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        need(sep == "=" and key not in facts,
             "rotation_static_pid1_invalid")
        facts[key] = value
    need(set(facts) == set(names) and facts["Id"] == unit and
         facts["LoadState"] == "loaded" and
         facts["FragmentPath"] == "/etc/systemd/system/" + unit and
         (timer or all(facts[name].isascii() and facts[name].isdecimal()
                       for name in ("MainPID", "ControlPID",
                                    "NFileDescriptorStore"))),
         "rotation_static_pid1_changed")
    if timer:
        need(facts["Triggers"] == "aegis-auto-trace-rollback.service" and
             facts["TriggeredBy"] == "",
             "rotation_static_timer_changed")
    else:
        # PID1 garbage-collects the inactive static timer (it has no
        # [Install]); the service then has no loaded reverse trigger and
        # prints an empty TriggeredBy (systemd 252/255, recorded readbacks in
        # scripts/tests/fixtures/rotation_static_pid1_readbacks.json). Any
        # other trigger still refuses.
        need(facts["TriggeredBy"] in ("", "aegis-auto-trace-rollback.timer") and
             facts["Triggers"] == "",
             "rotation_static_service_changed")
    return facts


def _rotation_static_source(unit: str, intent: dict[str, object]) -> None:
    need(unit in intent["old_static_units"], "rotation_static_unit_unknown")
    path = Path("/etc/systemd/system") / unit
    need(digest(regular(path, 1 << 16, 0o644)) ==
         intent["old_static_units"][unit],
         "rotation_static_source_changed")


def _rotation_static_stopped(deadline: float,
                             prior: list[dict[str, object]] | None = None) -> None:
    for index, (unit, _relative) in enumerate(ROTATION_STATIC_UNITS):
        facts = _rotation_static_facts(unit, deadline=deadline)
        timer = unit.endswith(".timer")
        need(facts["ActiveState"] == "inactive" and
             facts["SubState"] == "dead" and
             (timer or
              facts["MainPID"] == "0" and facts["ControlPID"] == "0" and
              facts["NFileDescriptorStore"] == "0" and
              facts["ControlGroup"] in ("", "/system.slice/" + unit)),
             "rotation_static_not_stopped")
        if timer:
            # systemctl prints USEC_INFINITY as "infinity" for an inactive
            # timer's monotonic elapse; any finite span is a pending elapse.
            need(facts["NextElapseUSecRealtime"] in ("", "n/a") and
                 facts["NextElapseUSecMonotonic"] in ("", "n/a", "infinity"),
                 "rotation_static_timer_pending")
        if prior is not None:
            need(facts["UnitFileState"] == prior[index]["unit_file_state"],
                 "rotation_static_enablement_changed")
        if not timer and facts["ControlGroup"]:
            group = Path("/sys/fs/cgroup") / facts["ControlGroup"].lstrip("/")
            need(not group.exists() or
                 group.joinpath("cgroup.procs").read_text(encoding="ascii") == "",
                 "rotation_static_cgroup_not_empty")
    _rotation_actor_jobs(deadline)


def _rotation_actors_stopped(deadline: float) -> None:
    for unit, _source, _unit_path in ROTATION_ACTORS:
        facts = _rotation_actor_facts(unit, deadline=deadline)
        need(facts["ActiveState"] == "inactive" and
             facts["SubState"] == "dead" and
             facts["MainPID"] == "0" and facts["ControlPID"] == "0" and
             facts["NFileDescriptorStore"] == "0" and
             facts["ControlGroup"] in ("", "/system.slice/" + unit),
             "rotation_actor_not_stopped")
        if facts["ControlGroup"]:
            group = Path("/sys/fs/cgroup") / facts["ControlGroup"].lstrip("/")
            need(not group.exists() or
                 group.joinpath("cgroup.procs").read_text(encoding="ascii") == "",
                 "rotation_actor_cgroup_not_empty")
    _rotation_actor_jobs(deadline)


def _rotation_retired_shape(intent: dict[str, object],
                            denied: dict[str, object]) -> dict[str, object]:
    retired = record(ROTATION_RETIRED)
    actor_intent = record(ROTATION_ACTOR_INTENT)
    need(set(retired) == {"schema", "boot_id", "intent_sha256",
                          "denied_sha256", "stopped_successor_sha256",
                          "old_install_sha256", "old_manager_sha256",
                          "guard_device", "guard_inode",
                          "deny_policy_sha256", "actors", "static_units"} and
         retired["schema"] == "aegis_auto_guard_rotation_retired_v1" and
         retired["boot_id"] == intent["boot_id"] and
         retired["intent_sha256"] == digest(regular(ROTATION_INTENT, MAX_ROTATION_INTENT)) and
         retired["denied_sha256"] == digest(regular(ROTATION_DENIED,
                                                  MAX_RECEIPT)) and
         retired["stopped_successor_sha256"] ==
         intent["stopped_successor_sha256"] and
         retired["old_install_sha256"] == intent["old_install_sha256"] and
         retired["old_manager_sha256"] == intent["old_manager_sha256"] and
         retired["guard_device"] == intent["guard_device"] and
         retired["guard_inode"] == intent["guard_inode"] and
         retired["deny_policy_sha256"] == denied["deny_policy_sha256"] and
         type(actor_intent) is dict and
         set(actor_intent) == {"schema", "boot_id", "intent_sha256",
                               "denied_sha256", "actors", "static_units"} and
         actor_intent["schema"] ==
         "aegis_auto_guard_rotation_actor_intent_v1" and
         actor_intent["boot_id"] == intent["boot_id"] and
         actor_intent["intent_sha256"] == retired["intent_sha256"] and
         actor_intent["denied_sha256"] == retired["denied_sha256"] and
         type(actor_intent["actors"]) is list and
         type(retired["actors"]) is list and
         type(actor_intent["static_units"]) is list and
         type(retired["static_units"]) is list and
         [entry.get("unit") for entry in actor_intent["static_units"]] ==
         [unit for unit, _relative in ROTATION_STATIC_UNITS] and
         all(type(entry) is dict and set(entry) ==
             {"unit", "unit_file_state", "prior_active_state",
              "prior_main_pid", "prior_control_pid",
              "prior_invocation_id"} and
             type(entry["unit_file_state"]) is str and
             entry["unit_file_state"] in ("enabled", "disabled", "static") and
             entry["prior_active_state"] in ("active", "activating",
                                              "inactive", "failed") and
             type(entry["prior_main_pid"]) is int and
             type(entry["prior_control_pid"]) is int and
             entry["prior_main_pid"] >= 0 and
             entry["prior_control_pid"] >= 0 and
             (entry["prior_invocation_id"] is None or
              type(entry["prior_invocation_id"]) is str and
              HEX32.fullmatch(entry["prior_invocation_id"]) is not None)
             for entry in actor_intent["static_units"]) and
         [entry.get("unit") for entry in actor_intent["actors"]] ==
         [unit for unit, _source, _path in ROTATION_ACTORS] and
         all(type(entry) is dict and set(entry) ==
             {"unit", "prior_main_pid", "prior_invocation_id",
              "prior_cgroup"} and
             type(entry["prior_main_pid"]) is int and
             (entry["prior_main_pid"] == 0 and
              entry["prior_invocation_id"] is None and
              entry["prior_cgroup"] is None or
              entry["prior_main_pid"] > 1 and
              type(entry["prior_invocation_id"]) is str and
              HEX32.fullmatch(entry["prior_invocation_id"]) is not None and
              entry["prior_cgroup"] == "/system.slice/" + entry["unit"])
             for entry in actor_intent["actors"]) and
         retired["actors"] ==
         [dict(entry, stopped_verified=True, fdstore_empty_verified=True)
          for entry in actor_intent["actors"]] and
         retired["static_units"] ==
         [dict(entry, stopped_verified=True, no_next_elapse_verified=True)
          for entry in actor_intent["static_units"]],
         "rotation_retired_receipt_changed")
    return retired


def _rotation_monitor_resume_name() -> str:
    return 'aegis-foreign-policy-rotation-resume-' + digest(regular(ROTATION_INTENT, MAX_ROTATION_INTENT))[:32]


def _rotation_monitor_resume_live() -> bool:
    name = _rotation_monitor_resume_name()
    result = subprocess.run(['/usr/bin/systemctl','show',name+'.timer',
        '-pLoadState','-pActiveState','-pTriggers','-pFragmentPath','-pDropInPaths',
        '-pNextElapseUSecMonotonic'], capture_output=True, timeout=3)
    need(result.returncode == 0 and len(result.stdout) <= 8192, 'rotation resume timer unavailable')
    facts = dict(line.split('=',1) for line in result.stdout.decode('ascii').splitlines())
    if facts.get('LoadState') == 'not-found':
        return False
    timer_path = Path('/run/systemd/transient')/(name+'.timer')
    need(facts.get('LoadState') == 'loaded' and facts.get('ActiveState') == 'active' and
         facts.get('Triggers') == name+'.service' and facts.get('DropInPaths') == '' and
         facts.get('FragmentPath') == str(timer_path), 'rotation resume timer changed')
    raw = regular(timer_path, 16384, 0o644).decode('ascii')
    duration = re.findall(r'(?m)^OnActiveSec=(.+)$', raw)
    # systemctl renders monotonic usec values as human durations. Read the
    # typed uint64 from PID1 rather than interpreting that lossy presentation.
    object_path = '/org/freedesktop/systemd1/unit/' + ''.join(
        char if char.isascii() and char.isalnum() else '_'+format(ord(char),'02x')
        for char in name+'.timer')
    deadline = subprocess.run(['/usr/bin/busctl','--system','get-property',
        'org.freedesktop.systemd1',object_path,'org.freedesktop.systemd1.Timer',
        'NextElapseUSecMonotonic'],capture_output=True,timeout=3)
    value = re.fullmatch(rb't ([0-9]{1,20})\n',deadline.stdout)
    need(duration in (['600s'], ['10min']) and
         deadline.returncode == 0 and value is not None and
         0 < int(value[1])-time.monotonic_ns()//1000 <= 602_000_000,
         'rotation resume timer deadline changed')
    path = Path('/run/systemd/transient')/(name+'.service')
    service = regular(path, 16384, 0o644).decode('ascii')
    commands = re.findall(r'(?m)^ExecStart=(.+)$', service)
    import shlex
    need(len(commands) == 1 and shlex.split(commands[0]) ==
         ['/usr/bin/systemctl','start','aegis-foreign-policy-monitor.service'] and
         not re.search(r'(?m)^(ExecStartPre|ExecStartPost|ExecCondition|ExecStop|ExecStopPost)=', service),
         'rotation resume command changed')
    props = subprocess.run(['/usr/bin/systemctl','show',name+'.service','-pFragmentPath',
        '-pDropInPaths','-pUser','-pGroup'], capture_output=True, timeout=3)
    need(props.returncode == 0 and len(props.stdout) <= 8192, 'rotation resume service unavailable')
    values = dict(line.split('=',1) for line in props.stdout.decode('ascii').splitlines())
    need(values.get('FragmentPath') == str(path) and values.get('DropInPaths') == '' and
         values.get('User') in ('','root') and values.get('Group') in ('','root'),
         'rotation resume service changed')
    return True


def _arm_rotation_monitor_resume(guard_fd: int) -> None:
    _held_lock(guard_fd, GUARD_LOCK)
    if _rotation_monitor_resume_live():
        return
    name = _rotation_monitor_resume_name()
    result = subprocess.run(['/usr/bin/systemd-run','--unit='+name,'--on-active=600s',
        '--timer-property=AccuracySec=1s','--property=Type=oneshot',
        '/usr/bin/systemctl','start','aegis-foreign-policy-monitor.service'],
        capture_output=True, timeout=5)
    need(result.returncode == 0 and _rotation_monitor_resume_live(),
         'rotation monitor independent resume unavailable')


def verify_rotation_monitor_stop(guard_fd: int) -> dict[str, object]:
    own_source()
    intent = _rotation_intent(guard_fd)
    need(digest(regular(INSTALL, MAX_RECEIPT)) == intent['old_install_sha256'],
         'rotation monitor generation changed')
    denied = _rotation_denied(intent)
    state, projection = _deny_without_bindings(time.monotonic()+10)
    need(digest(state) == intent['old_state_sha256'] and
         digest(projection) == denied['deny_policy_sha256'] and
         _rotation_monitor_resume_live(), 'rotation monitor deny or resume unproved')
    return {'schema':'aegis_rotation_monitor_quiesced_v1',
            'intent_sha256':digest(regular(ROTATION_INTENT, MAX_ROTATION_INTENT)),
            'deny_proven':True,'independent_resume_seconds':600}


def retire_rotation_actors(install_fd: int, guard_fd: int) -> dict[str, object]:
    """Stop pinned old actors only after durable verified kernel deny."""
    own_source()
    _held_lock(install_fd, INSTALL_LOCK)
    intent = _rotation_intent(guard_fd)
    denied = _rotation_denied(intent)
    current = read_guard_policy()
    need(current["manager_binding_sha256"] is None and
         current["state_sha256"] == intent["old_state_sha256"] and
         current["policy_sha256"] == denied["deny_policy_sha256"],
         "rotation_deny_not_sealed")
    _arm_rotation_monitor_resume(guard_fd)
    if ROTATION_RETIRED.exists() or ROTATION_RETIRED.is_symlink():
        retired = _rotation_retired_shape(intent, denied)
        for unit, _relative in ROTATION_STATIC_UNITS:
            _rotation_static_source(unit, intent)
        _rotation_actors_stopped(time.monotonic() + 20.0)
        _rotation_static_stopped(time.monotonic() + 20.0,
                                 record(ROTATION_ACTOR_INTENT)["static_units"])
        return retired
    deadline = time.monotonic() + 120.0
    actor_intent = (record(ROTATION_ACTOR_INTENT)
                    if ROTATION_ACTOR_INTENT.exists() or
                    ROTATION_ACTOR_INTENT.is_symlink() else None)
    need(actor_intent is None or
         (set(actor_intent) == {"schema", "boot_id", "intent_sha256",
                                "denied_sha256", "actors", "static_units"} and
          actor_intent["schema"] == "aegis_auto_guard_rotation_actor_intent_v1" and
          actor_intent["boot_id"] == intent["boot_id"] and
          actor_intent["intent_sha256"] ==
          digest(regular(ROTATION_INTENT, MAX_ROTATION_INTENT)) and
          actor_intent["denied_sha256"] ==
          digest(regular(ROTATION_DENIED, MAX_RECEIPT)) and
          type(actor_intent["actors"]) is list and
          type(actor_intent["static_units"]) is list and
          [entry.get("unit") for entry in actor_intent["static_units"]] ==
          [unit for unit, _relative in ROTATION_STATIC_UNITS] and
          [entry.get("unit") for entry in actor_intent["actors"]] ==
          [unit for unit, _source, _path in ROTATION_ACTORS] and
          all(type(entry) is dict and set(entry) ==
              {"unit", "prior_main_pid", "prior_invocation_id",
               "prior_cgroup"} and
              type(entry["prior_main_pid"]) is int and
              entry["prior_main_pid"] >= 0 and
              (entry["prior_main_pid"] == 0 and
               entry["prior_invocation_id"] is None and
               entry["prior_cgroup"] is None or
               entry["prior_main_pid"] > 1 and
               type(entry["prior_invocation_id"]) is str and
               HEX32.fullmatch(entry["prior_invocation_id"]) is not None and
               entry["prior_cgroup"] == "/system.slice/" + entry["unit"])
              for entry in actor_intent["actors"])),
         "rotation_actor_intent_changed")
    prior: list[dict[str, object]] = []
    static_prior: list[dict[str, object]] = []
    pidfds: list[int] = []
    try:
        for index, (unit, _relative) in enumerate(ROTATION_STATIC_UNITS):
            _rotation_static_source(unit, intent)
            facts = _rotation_static_facts(unit, deadline=deadline)
            main_pid = 0 if unit.endswith(".timer") else int(facts["MainPID"])
            control_pid = 0 if unit.endswith(".timer") else int(facts["ControlPID"])
            need(facts["UnitFileState"] in ("enabled", "disabled", "static") and
                 (unit.endswith(".service") or
                  main_pid == 0 and control_pid == 0) and
                 facts["ActiveState"] in ("active", "activating", "inactive",
                                           "failed"),
                 "rotation_static_prior_invalid")
            for pid in {main_pid, control_pid} - {0}:
                need(unit.endswith(".service") and pid > 1 and
                     facts["ControlGroup"] == "/system.slice/" + unit and
                     Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
                     "0::" + facts["ControlGroup"] + "\n" and
                     Path(f"/proc/{pid}/cmdline").read_bytes() ==
                     (b"/usr/bin/python3\0-I\0-B\0" +
                      os.fsencode(ROOT / "aegis_auto_trace_rollback.py") +
                      b"\0cleanup\0"),
                     "rotation_static_prior_identity_changed")
                handle = os.pidfd_open(pid, 0)
                need(_pid_alive(handle), "rotation_static_prior_exited")
                pidfds.append(handle)
            observed_static = {
                "unit": unit, "unit_file_state": facts["UnitFileState"],
                "prior_active_state": facts["ActiveState"],
                "prior_main_pid": main_pid, "prior_control_pid": control_pid,
                "prior_invocation_id": facts["InvocationID"] or None,
            }
            if actor_intent is not None:
                recorded_static = actor_intent["static_units"][index]
                need(observed_static == recorded_static or
                     main_pid == 0 and control_pid == 0 and
                     facts["UnitFileState"] ==
                     recorded_static["unit_file_state"],
                     "rotation_static_changed_after_intent")
                static_prior.append(recorded_static)
            else:
                static_prior.append(observed_static)
        for index, (unit, source, _path) in enumerate(ROTATION_ACTORS):
            _rotation_actor_source(unit, intent)
            facts = _rotation_actor_facts(unit, deadline=deadline)
            pid = int(facts["MainPID"])
            need(facts["ControlPID"] == "0" and
                 (pid > 1 and facts["ActiveState"] == "active" and
                  facts["SubState"] == "running" and
                  HEX32.fullmatch(facts["InvocationID"]) is not None or
                  pid == 0 and facts["ActiveState"] == "inactive" and
                  facts["SubState"] == "dead"),
                 "rotation_actor_prior_invalid")
            if pid > 1:
                need(facts["ControlGroup"] == "/system.slice/" + unit and
                     Path(f"/proc/{pid}/cgroup").read_text(
                         encoding="ascii") ==
                     "0::" + facts["ControlGroup"] + "\n" and
                     Path(f"/proc/{pid}/cmdline").read_bytes() ==
                     _rotation_actor_command(unit, source),
                     "rotation_actor_prior_identity_changed")
                handle = os.pidfd_open(pid, 0)
                need(_pid_alive(handle), "rotation_actor_prior_exited")
                pidfds.append(handle)
            observed = {"unit": unit, "prior_main_pid": pid,
                        "prior_invocation_id": facts["InvocationID"] if pid else None,
                        "prior_cgroup": facts["ControlGroup"] if pid else None}
            if actor_intent is not None:
                recorded = actor_intent["actors"][index]
                need(pid == 0 or observed == recorded,
                     "rotation_actor_changed_after_intent")
                prior.append(recorded)
            else:
                prior.append(observed)
        _rotation_actor_jobs(deadline)
        _rotation_write_once(ROTATION_ACTOR_INTENT, {
            "schema": "aegis_auto_guard_rotation_actor_intent_v1",
            "boot_id": intent["boot_id"],
            "intent_sha256": digest(regular(ROTATION_INTENT, MAX_ROTATION_INTENT)),
            "denied_sha256": digest(regular(ROTATION_DENIED, MAX_RECEIPT)),
            "actors": prior, "static_units": static_prior})
        for unit, _relative in ROTATION_STATIC_UNITS:
            result = subprocess.run(
                ["/usr/bin/systemctl", "stop", unit],
                stdin=subprocess.DEVNULL, capture_output=True,
                timeout=max(1.0, deadline - time.monotonic()), check=False,
                env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
            need(result.returncode == 0 and len(result.stdout) <= 8192 and
                 len(result.stderr) <= 4096, "rotation_static_stop_refused")
        _rotation_static_stopped(deadline, static_prior)
        result = subprocess.run(
            ["/usr/bin/systemctl", "stop", *(unit for unit, _source, _path
                                                in ROTATION_ACTORS)],
            stdin=subprocess.DEVNULL, capture_output=True,
            timeout=max(1.0, deadline - time.monotonic()), check=False,
            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
        need(result.returncode == 0 and len(result.stdout) <= 8192 and
             len(result.stderr) <= 4096, "rotation_actor_stop_refused")
        clean = subprocess.run(
            ["/usr/bin/systemctl", "clean", "--what=fdstore",
             "aegis-auto-guardian-watchdog.service"],
            stdin=subprocess.DEVNULL, capture_output=True,
            timeout=min(10.0, max(1.0, deadline - time.monotonic())),
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
        need(clean.returncode == 0 and len(clean.stdout) <= 4096 and
             len(clean.stderr) <= 4096,
             "rotation_watchdog_fdstore_retained")
        need(all(not _pid_alive(fd) for fd in pidfds),
             "rotation_actor_pid_remained")
        _rotation_actors_stopped(deadline)
        _rotation_static_stopped(deadline, static_prior)
        _held_lock(install_fd, INSTALL_LOCK)
        _held_lock(guard_fd, GUARD_LOCK)
        current = read_guard_policy()
        need(current["manager_binding_sha256"] is None and
             current["policy_sha256"] == denied["deny_policy_sha256"],
             "rotation_deny_changed_after_actor_stop")
        retired = {
            "schema": "aegis_auto_guard_rotation_retired_v1",
            "boot_id": intent["boot_id"],
            "intent_sha256": digest(regular(ROTATION_INTENT, MAX_ROTATION_INTENT)),
            "denied_sha256": digest(regular(ROTATION_DENIED, MAX_RECEIPT)),
            "stopped_successor_sha256": intent["stopped_successor_sha256"],
            "old_install_sha256": intent["old_install_sha256"],
            "old_manager_sha256": intent["old_manager_sha256"],
            "guard_device": intent["guard_device"],
            "guard_inode": intent["guard_inode"],
            "deny_policy_sha256": denied["deny_policy_sha256"],
            "actors": [dict(entry, stopped_verified=True,
                            fdstore_empty_verified=True) for entry in prior],
            "static_units": [dict(entry, stopped_verified=True,
                                  no_next_elapse_verified=True)
                             for entry in static_prior],
        }
        _rotation_write_once(ROTATION_RETIRED, retired)
        return retired
    finally:
        for fd in pidfds:
            os.close(fd)


def rotation_retired_readback(guard_fd: int) -> dict[str, object]:
    """Read-only phase proof for the source pinned package preinstall hook."""
    own_source()
    intent = _rotation_intent(guard_fd)
    denied = _rotation_denied(intent)
    retired = _rotation_retired_shape(intent, denied)
    for unit, _relative in ROTATION_STATIC_UNITS:
        _rotation_static_source(unit, intent)
    _rotation_actors_stopped(time.monotonic() + 20.0)
    _rotation_static_stopped(time.monotonic() + 20.0,
                             record(ROTATION_ACTOR_INTENT)["static_units"])
    current = read_guard_policy()
    need(current["manager_binding_sha256"] is None and
         current["policy_sha256"] == denied["deny_policy_sha256"] and
         current["state_sha256"] == intent["old_state_sha256"],
         "rotation_retired_deny_changed")
    return {"schema": "aegis_auto_guard_rotation_retired_readback_v1",
            "boot_id": intent["boot_id"],
            "intent_sha256": retired["intent_sha256"],
            "denied_sha256": retired["denied_sha256"],
            "stopped_successor_sha256": retired["stopped_successor_sha256"],
            "retired_sha256": digest(regular(ROTATION_RETIRED, MAX_RECEIPT)),
            "deny_policy_sha256": denied["deny_policy_sha256"],
            "no_live_actors": True}


def _cold_archive_fixed_cgroup_empty(unit: str) -> None:
    path=Path('/sys/fs/cgroup/system.slice')/unit
    need(not path.is_symlink(),'cold_archive_cgroup_alias')
    if not path.exists():
        need(not path.is_symlink(),'cold_archive_cgroup_alias')
        return
    before=path.lstat()
    need(stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0,
         'cold_archive_cgroup_foreign')
    directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|
                      os.O_CLOEXEC)
    try:
        held=os.fstat(directory)
        need((held.st_dev,held.st_ino,held.st_mode,held.st_uid,held.st_gid)==
             (before.st_dev,before.st_ino,before.st_mode,before.st_uid,
              before.st_gid),'cold_archive_cgroup_replaced')
        for leaf,maximum in (('cgroup.procs',4096),('cgroup.events',4096)):
            fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,
                       dir_fd=directory)
            try:
                first=os.fstat(fd)
                need(stat.S_ISREG(first.st_mode) and first.st_uid==0,
                     'cold_archive_cgroup_leaf_foreign')
                raw=os.read(fd,maximum+1)
                after=os.fstat(fd)
                need(len(raw)<=maximum and
                     (first.st_dev,first.st_ino,first.st_mode,first.st_uid)==
                     (after.st_dev,after.st_ino,after.st_mode,after.st_uid),
                     'cold_archive_cgroup_leaf_changed')
                named_fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|
                    os.O_CLOEXEC,dir_fd=directory)
                try:
                    named=os.fstat(named_fd)
                    need((named.st_dev,named.st_ino,named.st_mode,named.st_uid)==
                         (first.st_dev,first.st_ino,first.st_mode,first.st_uid),
                         'cold_archive_cgroup_leaf_replaced')
                finally:os.close(named_fd)
            finally:os.close(fd)
            if leaf=='cgroup.procs':
                need(raw==b'','cold_archive_cgroup_process_present')
            else:
                lines=raw.decode('ascii').splitlines()
                need(sum(line.startswith('populated ') for line in lines)==1 and
                     'populated 0' in lines,
                     'cold_archive_cgroup_populated')
        named=path.lstat()
        need((named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid)==
             (before.st_dev,before.st_ino,before.st_mode,before.st_uid,
              before.st_gid),'cold_archive_cgroup_replaced')
    finally:os.close(directory)


def _cold_archive_rotation_units_absent(deadline: float) -> list[str]:
    """Admit a missing unit only as an explicit native package-roster fact."""
    missing=[]
    units=([unit for unit,_source,_path in ROTATION_ACTORS] +
           [unit for unit,_relative in ROTATION_STATIC_UNITS])
    need(len(units)==len(set(units))==8,'cold_archive_unit_roster')
    prior=record(ROTATION_ACTOR_INTENT)['static_units']
    need(type(prior) is list and len(prior)==len(ROTATION_STATIC_UNITS) and
         [item.get('unit') for item in prior]==
         [unit for unit,_relative in ROTATION_STATIC_UNITS],
         'cold_archive_static_roster_changed')
    for unit in units:
        timer=unit.endswith('.timer')
        actor=unit in {name for name,_source,_path in ROTATION_ACTORS}
        common=('Id','LoadState','FragmentPath','ActiveState','SubState',
                'InvocationID')
        names=(common+('MainPID','ControlPID','ControlGroup',
                       'NFileDescriptorStore') if actor else
               common+('UnitFileState','Triggers','TriggeredBy')+
               (('NextElapseUSecRealtime','NextElapseUSecMonotonic') if timer
                else ('MainPID','ControlPID','ControlGroup',
                      'NFileDescriptorStore')))
        remaining=deadline-time.monotonic()
        need(remaining>0,'cold_archive_unit_deadline')
        command=['/usr/bin/systemctl','show',unit,'--no-pager']
        for name in names:command.extend(('-p',name))
        result=subprocess.run(command,stdin=subprocess.DEVNULL,
            capture_output=True,timeout=min(3.0,remaining),check=False,
            env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
        need(result.returncode==0 and len(result.stdout)<=8192 and
             len(result.stderr)<=4096,'cold_archive_pid1_unavailable')
        facts={}
        for line in result.stdout.decode('ascii').splitlines():
            key,sep,value=line.partition('=')
            need(sep=='=' and key not in facts,'cold_archive_pid1_invalid')
            facts[key]=value
        need(set(facts)==set(names) and facts['Id']==unit and
             facts['ActiveState']=='inactive' and facts['SubState']=='dead',
             'cold_archive_unit_live')
        if facts['LoadState']=='loaded':
            if actor:
                strict=_rotation_actor_facts(unit,deadline=deadline)
                expected=next(str(path) for name,_source,path in
                              ROTATION_ACTORS if name==unit)
            else:
                strict=_rotation_static_facts(unit,deadline=deadline)
                expected='/etc/systemd/system/'+unit
            need(strict==facts and facts['FragmentPath']==expected,
                 'cold_archive_unit_changed')
            if not actor:
                index=next(index for index,(name,_relative) in
                           enumerate(ROTATION_STATIC_UNITS) if name==unit)
                need(facts['UnitFileState']==prior[index]['unit_file_state'],
                     'cold_archive_static_enablement_changed')
        else:
            need(facts['LoadState']=='not-found' and
                 facts['FragmentPath']=='' and facts['InvocationID']=='',
                 'cold_archive_unit_unknown')
            if not actor:
                need(facts['UnitFileState'] in ('','not-found') and
                     facts['Triggers']==facts['TriggeredBy']=='',
                     'cold_archive_static_unknown')
            missing.append(unit)
        if timer:
            need(facts['NextElapseUSecRealtime'] in ('','n/a') and
                 facts['NextElapseUSecMonotonic'] in ('','n/a','infinity'),
                 'cold_archive_timer_pending')
        else:
            need(all(facts[key]=='0' for key in
                     ('MainPID','ControlPID','NFileDescriptorStore')) and
                 facts['ControlGroup'] in ('','/system.slice/'+unit),
                 'cold_archive_unit_actor_present')
            if facts['ControlGroup']:
                group=Path('/sys/fs/cgroup')/facts['ControlGroup'].lstrip('/')
                need(not group.exists() or
                     group.joinpath('cgroup.procs').read_text(encoding='ascii')=='',
                     'cold_archive_unit_cgroup_present')
        _cold_archive_fixed_cgroup_empty(unit)
    _rotation_actor_jobs(deadline)
    for unit in units:
        _cold_archive_fixed_cgroup_empty(unit)
    return sorted(missing)


def cold_archive_retired_readback(guard_fd: int, pending_sha: str,
                                  old_root: Path) -> dict[str, object]:
    """Recheck retired B with retained B code after A2 partially replaces files."""
    need(os.geteuid()==0 and HEX64.fullmatch(pending_sha) is not None,
         'cold_archive_args_invalid')
    _held_lock(guard_fd,GUARD_LOCK)
    client=Path('/var/lib/aegis-install/client')
    pending_raw=regular(client/'terminal-migrations/pending.json',4096,0o600)
    need(digest(pending_raw)==pending_sha,'cold_archive_pending_changed')
    pending=json.loads(pending_raw,object_pairs_hook=unique)
    need(type(pending) is dict and
         pending.get('schema')=='aegis_auto_terminal_migration_pending_v1' and
         type(pending.get('context_sha256')) is str and
         HEX64.fullmatch(pending['context_sha256']) is not None,
         'cold_archive_pending_changed')
    context_raw=regular(client/'terminal-migrations'/
        ('context-'+pending['context_sha256']+'.json'),256 << 10,0o600)
    need(digest(context_raw)==pending['context_sha256'],
         'cold_archive_context_changed')
    context=json.loads(context_raw,object_pairs_hook=unique)
    old_install_sha=context.get('old_install_sha256')
    need(type(old_install_sha) is str and
         HEX64.fullmatch(old_install_sha) is not None,
         'cold_archive_context_changed')
    archived_raw=regular(client/('auto-guardian-install-guarded-'+
        old_install_sha+'.json'),MAX_RECEIPT,0o600)
    need(digest(archived_raw)==old_install_sha,
         'cold_archive_old_install_changed')
    archived=json.loads(archived_raw,object_pairs_hook=unique)
    need(type(archived) is dict and
         archived.get('schema')=='aegis_auto_guardian_install_v1' and
         type(archived.get('guardian_sha256')) is str and
         HEX64.fullmatch(archived['guardian_sha256']) is not None and
         digest(_retained_rotation_source(old_root,
             'scripts/lib/aegis_auto_guardian.py',0o444))==
             archived['guardian_sha256'] and
         Path(__file__).resolve()==old_root/'scripts/lib/aegis_auto_guardian.py',
         'cold_archive_guardian_source_changed')
    intent=_rotation_intent(guard_fd)
    need(intent['old_public_payload_root']==str(old_root) and
         intent['old_install_sha256']==old_install_sha and
         intent['successor']['next_public_payload_root']==
             pending['release_root'],
         'cold_archive_rotation_changed')
    denied=_rotation_denied(intent)
    retired=_rotation_retired_shape(intent,denied)
    deadline=time.monotonic()+20.0
    missing_units=_cold_archive_rotation_units_absent(deadline)
    modules={}
    def load(field,filename,name):
        raw=_retained_rotation_source(old_root,'scripts/lib/'+filename,0o444)
        need(type(archived.get(field)) is str and
             HEX64.fullmatch(archived[field]) is not None and
             digest(raw)==archived[field] and name not in sys.modules,
             'cold_archive_module_source_changed')
        module=types.ModuleType(name)
        module.__file__=str(old_root/'scripts/lib'/filename)
        sys.modules[name]=module
        modules[name]=module
        exec(compile(raw,module.__file__,'exec',dont_inherit=True),
             module.__dict__)
        need(sys.modules.get(name) is module,
             'cold_archive_module_identity_changed')
        return module
    try:
        load('foreign_policy_source_sha256',
             'aegis_auto_foreign_policy.py','aegis_auto_foreign_policy')
        witness=load('witness_sha256',
                     'aegis_auto_native_witness.py','aegis_auto_native_witness')
        policy=load('guard_policy_source_sha256',
                    'aegis_auto_guard_policy.py','aegis_auto_guard_policy')
        state=regular(client/'device-guard.conf',1 << 15)
        for name in ('device-guard.conf.client-binding',
                     'device-guard.conf.manager-binding'):
            leaf=client/name
            need(not leaf.exists() and not leaf.is_symlink(),
                 'cold_archive_binding_present')
        first=witness.read_policy_raw(Path('/usr/sbin/nft'),deadline=deadline)
        text=witness.read_policy_raw(Path('/usr/sbin/nft'),text=True,
                                     deadline=deadline)
        second=witness.read_policy_raw(Path('/usr/sbin/nft'),deadline=deadline)
        projection,_handles,_counters=witness.policy_projection(first)
        confirmed,_handles2,_counters2=witness.policy_projection(second)
        need(projection==confirmed and _no_client_grant(projection) and
             policy.verify_expected_policy(state,first,text,None,None,
                boot_id=host_anchor()['boot_id'])==digest(projection) and
             digest(projection)==denied['deny_policy_sha256'] and
             digest(state)==intent['old_state_sha256'],
             'cold_archive_kernel_deny_changed')
    finally:
        for name,module in modules.items():
            if sys.modules.get(name) is module:
                sys.modules.pop(name,None)
    need(regular(client/'terminal-migrations/pending.json',4096,0o600)==
         pending_raw and
         regular(client/('auto-guardian-install-guarded-'+
             old_install_sha+'.json'),MAX_RECEIPT,0o600)==archived_raw,
         'cold_archive_retired_source_changed')
    _held_lock(guard_fd,GUARD_LOCK)
    return {'schema':'aegis_auto_guard_cold_archive_retired_readback_v1',
            'boot_id':intent['boot_id'],
            'intent_sha256':retired['intent_sha256'],
            'denied_sha256':retired['denied_sha256'],
            'stopped_successor_sha256':retired['stopped_successor_sha256'],
            'retired_sha256':digest(regular(ROTATION_RETIRED,MAX_RECEIPT)),
            'deny_policy_sha256':denied['deny_policy_sha256'],
            'no_live_actors':True,'missing_units':missing_units}


def rotation_admitted_readback(install_fd: int,
                              guard_fd: int) -> dict[str, object]:
    """Read-only new-source admission before first-arm host reassessment."""
    own_source()
    _held_lock(install_fd, INSTALL_LOCK)
    intent = _rotation_intent(guard_fd)
    denied = _rotation_denied(intent)
    retired = _rotation_retired_shape(intent, denied)
    _rotation_actors_stopped(time.monotonic() + 20.0)
    _rotation_static_stopped(time.monotonic() + 20.0,
                             record(ROTATION_ACTOR_INTENT)["static_units"])
    _rotation_current_deny(intent, denied)
    root = Path(intent["successor"]["next_public_payload_root"])
    candidate = root / "bin/aegis-client"
    installed = record(INSTALL)
    expected = provision_receipt(candidate)
    need(installed == expected and
         _retained_rotation_executable_digest(root) ==
         intent["successor"]["next_candidate_sha256"] and
         _rotation_sources(root) == intent["next_sources"] and
         _rotation_static_sources(root) == intent["next_static_units"] and
         all(digest(regular(Path("/etc/systemd/system") / unit,
                            1 << 16, 0o644)) == sha
             for unit, sha in intent["next_static_units"].items()) and
         read_guard_policy() ==
         {"state_sha256": intent["old_state_sha256"],
          "policy_sha256": denied["deny_policy_sha256"],
          "manager_binding_sha256": None},
         "rotation_admitted_generation_changed")
    _held_lock(install_fd, INSTALL_LOCK)
    _held_lock(guard_fd, GUARD_LOCK)
    return {"schema": "aegis_auto_guard_rotation_admitted_readback_v1",
            "boot_id": intent["boot_id"],
            "kind": intent["successor"]["kind"],
            "intent_sha256": digest(regular(ROTATION_INTENT, MAX_ROTATION_INTENT)),
            "denied_sha256": digest(regular(ROTATION_DENIED, MAX_RECEIPT)),
            "retired_sha256": digest(regular(ROTATION_RETIRED, MAX_RECEIPT)),
            "new_install_sha256": digest(regular(INSTALL, MAX_RECEIPT)),
            "candidate_sha256": intent["successor"]["next_candidate_sha256"],
            "deny_policy_sha256": denied["deny_policy_sha256"],
            "no_live_actors": True}


def _passive_successor_admission(install_fd: int, *,
                                 require_stopped: bool = True,
                                 outer_deadline: float | None = None) -> tuple[dict[str, object], bytes]:
    """Read the old-client preinst handoff before admitting new passive source."""
    _held_lock(install_fd, INSTALL_LOCK)
    preinst_raw = regular(PASSIVE_PREINST, MAX_RECEIPT)
    preinst = json.loads(preinst_raw, object_pairs_hook=unique)
    successor_raw = regular(SUCCESSOR, MAX_RECEIPT)
    successor = json.loads(successor_raw, object_pairs_hook=unique)
    intent_raw = regular(PASSIVE_RETIRE_INTENT, 16384)
    intent = json.loads(intent_raw, object_pairs_hook=unique)
    retired = record(PASSIVE_RETIRED, 16384)
    stopped = json.loads(regular(PASSIVE_OLD_STOPPED, 128 << 10),
                         object_pairs_hook=unique)
    need(type(preinst) is dict and set(preinst) ==
         {"schema", "successor_intent_sha256", "retired_intent_sha256",
          "candidate_sha256", "old_install_sha256"} and
         preinst["schema"] == "aegis_auto_v2_passive_package_preinst_v1" and
         type(successor) is dict and successor.get("schema") ==
         "aegis_auto_v2_stopped_successor_v1" and successor.get("kind") == "upgrade" and
         type(intent) is dict and intent.get("schema") ==
         "aegis_auto_v2_passive_successor_retirement_intent_v1" and
         type(retired) is dict and retired.get("schema") ==
         "aegis_auto_v2_passive_successor_retired_v1" and
         stopped.get("stage", {}).get("mode") == "socks-only" and
         preinst["successor_intent_sha256"] == digest(successor_raw) and
         preinst["retired_intent_sha256"] == digest(intent_raw) ==
         retired.get("intent_sha256") and
         retired.get("stopped_successor_sha256") ==
         intent.get("successor_sha256") and
         retired.get("source_sha256") == intent.get("source_sha256") and
         retired.get("no_live_actors") is True and
         retired.get("non_actor_units_stopped") is True and
         retired.get("boot_id") == intent.get("boot_id") ==
         successor.get("old_boot_id") == host_anchor()["boot_id"] and
         preinst["candidate_sha256"] == successor.get("next_candidate_sha256") and
         intent.get("stopped_sha256") == digest(json.dumps(
             stopped, sort_keys=True, separators=(",", ":")).encode()) and
         stopped.get("input", {}).get("candidate_sha256") is not None,
         "passive_successor_handoff_changed")
    root = Path(successor["next_public_payload_root"])
    candidate = root / "bin/aegis-client"
    need(successor["next_candidate_binary"] == str(candidate) and
         _retained_rotation_executable_digest(root) ==
         preinst["candidate_sha256"] and
         digest(_retained_rotation_source(root, "install.sh", 0o555, 4 << 20)) ==
         successor["next_installer_sha256"],
         "passive_successor_candidate_changed")
    old_root = Path(stopped["input"]["public_payload_root"])
    old_sources = _rotation_predecessor_sources(old_root)
    old_install_raw = regular(INSTALL.parent /
                              ("auto-guardian-install-passive-successor-" +
                               preinst["old_install_sha256"] + ".json"),
                              MAX_RECEIPT) if digest(regular(INSTALL, MAX_RECEIPT)) != \
                              preinst["old_install_sha256"] else regular(INSTALL, MAX_RECEIPT)
    old_install = json.loads(old_install_raw, object_pairs_hook=unique)
    need(digest(old_install_raw) == preinst["old_install_sha256"] and
         old_install.get("guard_unit_sha256") is None and
         old_install.get("worker_sha256") ==
         stopped["input"]["candidate_sha256"] and
         old_install.get("installation_anchor") == installation_anchor() and
         all(old_install.get(field) == sha for field, sha in old_sources.items()),
         "passive_successor_old_source_changed")
    deadline = time.monotonic() + 20.0
    if outer_deadline is not None:
        deadline = min(deadline, outer_deadline)
    need(time.monotonic() < deadline, "passive_successor_deadline_elapsed")
    if require_stopped:
        _rotation_actors_stopped(deadline)
    _rotation_static_stopped(deadline)
    if require_stopped:
        for socket_path in ("/run/aegis-auto-guard/authority.sock",
                            "/run/aegis-auto-guardian-watchdog/authority.sock",
                            "/run/aegis-auto-topology/authority.sock",
                            "/run/aegis-auto-rollback/authority.sock"):
            need(not Path(socket_path).exists() and not Path(socket_path).is_symlink(),
                 "passive_successor_actor_socket_present")
    new_install = provision_receipt(candidate)
    need(new_install["guard_unit_sha256"] is None and
         new_install["worker_sha256"] == preinst["candidate_sha256"] and
         all(new_install[field] == sha for field, sha in
             _rotation_sources(root).items()) and
         all(new_install[field] == sha for field, sha in
             _terminal_successor_sources(root).items()) and
         all(digest(regular(Path("/etc/systemd/system") / unit,
                            1 << 16, 0o644)) == sha for unit, sha in
             _rotation_static_sources(root).items()),
         "passive_successor_new_source_changed")
    return preinst, (json.dumps(new_install, sort_keys=True,
                               separators=(",", ":")) + "\n").encode()


def admit_passive_successor(install_fd: int) -> str:
    preinst, raw = _passive_successor_admission(install_fd)
    current = regular(INSTALL, MAX_RECEIPT)
    if current != raw:
        need(digest(current) == preinst["old_install_sha256"],
             "passive_successor_install_changed")
        _rotation_archive(INSTALL, current, "auto-guardian-install-passive-successor")
        orphans = [name for name in os.listdir(INSTALL.parent)
                   if re.fullmatch(r"\.auto-passive-successor-[0-9a-f]{24}", name)]
        need(len(orphans) <= 32, "passive_successor_temporary_overflow")
        for name in orphans:
            regular(INSTALL.parent / name, MAX_RECEIPT)
        temporary = INSTALL.parent / (".auto-passive-successor-" + secrets.token_hex(12))
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                written = 0
                while written < len(raw):
                    count = os.write(fd, raw[written:])
                    need(count > 0, "passive_successor_short_write")
                    written += count
                os.fsync(fd)
            finally:
                os.close(fd)
            _held_lock(install_fd, INSTALL_LOCK)
            need(regular(INSTALL, MAX_RECEIPT) == current,
                 "passive_successor_install_changed")
            os.replace(temporary, INSTALL)
            parent = os.open(INSTALL.parent, os.O_RDONLY | os.O_DIRECTORY |
                             os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            if temporary.exists():
                temporary.unlink()
    own_source()
    return digest(raw)


def passive_successor_staged_readback(install_fd: int) -> dict[str, object]:
    """Read-only package/configure authority while old actors remain retired."""
    # INSTALL still names A. The held predecessor handoff and exact retained
    # B helper/unit roster below are the source authority until INSTALL rotates.
    preinst, new_install = _passive_successor_admission(install_fd)
    current = regular(INSTALL, MAX_RECEIPT)
    need(digest(current) == preinst["old_install_sha256"] and
         current != new_install,
         "passive_successor_old_install_changed")
    _held_lock(install_fd, INSTALL_LOCK)
    return {"schema": "aegis_auto_guard_passive_successor_staged_v1",
            "boot_id": host_anchor()["boot_id"],
            "preinst_sha256": digest(regular(PASSIVE_PREINST, MAX_RECEIPT)),
            "old_install_sha256": digest(current),
            "candidate_sha256": preinst["candidate_sha256"],
            "no_live_actors": True}


def passive_successor_admitted_readback(install_fd: int) -> dict[str, object]:
    preinst, raw = _passive_successor_admission(install_fd)
    own_source()
    need(regular(INSTALL, MAX_RECEIPT) == raw,
         "passive_successor_install_changed")
    _held_lock(install_fd, INSTALL_LOCK)
    return {"schema": "aegis_auto_guard_passive_successor_admitted_v1",
            "boot_id": host_anchor()["boot_id"],
            "preinst_sha256": digest(regular(PASSIVE_PREINST, MAX_RECEIPT)),
            "new_install_sha256": digest(raw),
            "candidate_sha256": preinst["candidate_sha256"],
            "no_live_actors": True}


def _passive_actor_tick(pid: int) -> int:
    need(pid > 1, "passive_successor_actor_identity_changed")
    with open(f"/proc/{pid}/stat", "rb", buffering=0) as source:
        raw = source.read(4097)
    need(0 < len(raw) <= 4096 and b") " in raw,
         "passive_successor_actor_identity_changed")
    tail = raw.rsplit(b") ", 1)[1].split()
    need(len(tail) > 19 and tail[19].isdigit() and int(tail[19]) > 0,
         "passive_successor_actor_identity_changed")
    return int(tail[19])


def _passive_actor_unix_table() -> bytes:
    table = bytearray()
    maximum = 1 << 20
    with open("/proc/net/unix", "rb", buffering=0) as source:
        while True:
            block = source.read(min(65536, maximum + 1 - len(table)))
            if not block:
                break
            table.extend(block)
            need(len(table) <= maximum, "passive_successor_actor_unix_table_oversized")
    return bytes(table)


def _passive_actor_socket(path: str, pid: int) -> None:
    item = Path(path)
    parent = item.parent.stat(follow_symlinks=False)
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == parent.st_gid == 0 and
         stat.S_IMODE(parent.st_mode) == 0o700,
         "passive_successor_actor_socket_changed")
    info = item.stat(follow_symlinks=False)
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and
         stat.S_IMODE(info.st_mode) & 0o077 == 0,
         "passive_successor_actor_socket_changed")
    table = _passive_actor_unix_table()
    matches = []
    for row in table.decode("ascii").splitlines()[1:]:
        fields = row.split()
        if len(fields) == 8 and fields[7] == path:
            need(fields[6].isdecimal(), "passive_successor_actor_socket_changed")
            matches.append(fields[6])
    need(len(matches) == 1, "passive_successor_actor_socket_changed")
    names = list(Path(f"/proc/{pid}/fd").iterdir())
    need(len(names) <= 1024, "passive_successor_actor_socket_changed")
    target = f"socket:[{matches[0]}]"
    owned = False
    for name in names:
        if name.name.isdecimal():
            try:
                owned |= os.readlink(name) == target
            except FileNotFoundError:
                continue
    need(owned, "passive_successor_actor_socket_changed")


def passive_successor_progress_readback(install_fd: int, *,
                                        deadline: float | None = None) -> dict[str, object]:
    """Classify only exact new passive actors after a sealed package handoff."""
    if deadline is None:
        deadline = time.monotonic() + 40.0
    own_source()
    preinst, new_install = _passive_successor_admission(
        install_fd, require_stopped=False, outer_deadline=deadline)
    need(regular(INSTALL, MAX_RECEIPT) == new_install,
         "passive_successor_install_changed")
    intent = record(PASSIVE_RETIRE_INTENT, 16384)
    need(type(intent.get("actors")) is dict and
         set(intent["actors"]) == {row[0] for row in PASSIVE_SUCCESSOR_ACTORS} and
         type(intent.get("actor_start_ticks")) is dict and
         set(intent["actor_start_ticks"]) == set(intent["actors"]),
         "passive_successor_old_actor_identity_changed")
    need(time.monotonic() < deadline, "passive_successor_deadline_elapsed")
    _boot_fixed_client_stopped(deadline)
    _boot_private_owners_absent(deadline)
    _rotation_static_stopped(deadline)
    active, missing = [], []
    for unit, socket_path, source in PASSIVE_SUCCESSOR_ACTORS:
        facts = _rotation_actor_facts(unit, deadline=deadline)
        old = intent["actors"][unit]
        old_tick = intent["actor_start_ticks"][unit]
        need(type(old) is dict and type(old.get("InvocationID")) is str and
             HEX32.fullmatch(old["InvocationID"]) is not None and
             type(old_tick) is int and old_tick > 0 and
             facts["ControlPID"] == "0" and
             facts["NFileDescriptorStore"] == "0",
             "passive_successor_old_actor_identity_changed")
        old_pid = int(old["MainPID"])
        need(old_pid > 1, "passive_successor_old_actor_identity_changed")
        try:
            current_old_tick = _passive_actor_tick(old_pid)
        except (FileNotFoundError, ProcessLookupError):
            current_old_tick = None
        need(current_old_tick != old_tick,
             "passive_successor_old_actor_still_live")
        if facts["ActiveState"] == "inactive":
            need(facts["SubState"] == "dead" and facts["MainPID"] == "0" and
                 facts["ControlGroup"] == "" and
                 facts["InvocationID"] in ("", "0" * 32, old["InvocationID"]) and
                 not os.path.lexists(socket_path),
                 "passive_successor_missing_actor_changed")
            missing.append(unit)
            continue
        need(facts["ActiveState"] == "active" and
             facts["SubState"] == "running" and
             facts["ControlGroup"] == "/system.slice/" + unit and
             HEX32.fullmatch(facts["InvocationID"]) is not None and
             facts["InvocationID"] != old["InvocationID"],
             "passive_successor_active_actor_changed")
        pid = int(facts["MainPID"])
        handle = os.pidfd_open(pid, 0)
        try:
            with open(f"/proc/{pid}/cgroup", "rb", buffering=0) as source_file:
                cgroup = source_file.read(1025)
            with open(f"/proc/{pid}/cmdline", "rb", buffering=0) as source_file:
                command_line = source_file.read(1025)
            need(_pid_alive(handle) and _passive_actor_tick(pid) != old_tick and
                 cgroup == ("0::/system.slice/" + unit + "\n").encode() and
                 command_line ==
                 b"/usr/bin/python3\0-I\0-B\0" + os.fsencode(source) + b"\0serve\0",
                 "passive_successor_active_actor_changed")
            _passive_actor_socket(socket_path, pid)
            need(_pid_alive(handle), "passive_successor_active_actor_changed")
        finally:
            os.close(handle)
        active.append(unit)
    _rotation_actor_jobs(deadline)
    _held_lock(install_fd, INSTALL_LOCK)
    need(regular(INSTALL, MAX_RECEIPT) == new_install and
         time.monotonic() < deadline,
         "passive_successor_progress_changed")
    return {"schema": "aegis_auto_guard_passive_successor_progress_v1",
            "boot_id": host_anchor()["boot_id"],
            "preinst_sha256": digest(regular(PASSIVE_PREINST, MAX_RECEIPT)),
            "new_install_sha256": digest(new_install),
            "candidate_sha256": preinst["candidate_sha256"],
            "active": active, "missing": missing}


def passive_successor_progress_wait(install_fd: int) -> dict[str, object]:
    """Wait for newly started actor sockets within one readback budget."""
    deadline = time.monotonic() + 40.0
    while True:
        need(time.monotonic() < deadline,
             "passive_successor_deadline_elapsed")
        try:
            proof = passive_successor_progress_readback(
                install_fd, deadline=deadline)
            need(proof["missing"] == [], "passive_successor_actor_not_ready")
            return proof
        except Refused as error:
            if str(error) not in (
                    "passive_successor_active_actor_changed",
                    "passive_successor_actor_socket_changed",
                    "passive_successor_actor_not_ready"):
                raise
        except FileNotFoundError:
            # Socket publication can trail a successful systemctl start.
            pass
        remaining = deadline - time.monotonic()
        need(remaining > 0, "passive_successor_deadline_elapsed")
        time.sleep(min(0.1, remaining))


def rotation_state_handoff(install_fd: int,
                           guard_fd: int) -> dict[str, object]:
    """Seal a newly assessed no-grant state before releasing the guard OFD."""
    own_source()
    _held_lock(install_fd, INSTALL_LOCK)
    intent = _rotation_intent(guard_fd)
    denied = _rotation_denied(intent)
    _rotation_retired_shape(intent, denied)
    _rotation_actors_stopped(time.monotonic() + 20.0)
    _rotation_static_stopped(time.monotonic() + 20.0,
                             record(ROTATION_ACTOR_INTENT)["static_units"])
    root = Path(intent["successor"]["next_public_payload_root"])
    candidate = root / "bin/aegis-client"
    installed = record(INSTALL)
    need(installed == provision_receipt(candidate) and
         _retained_rotation_executable_digest(root) ==
         intent["successor"]["next_candidate_sha256"] and
         _rotation_sources(root) == intent["next_sources"] and
         _rotation_static_sources(root) == intent["next_static_units"] and
         all(digest(regular(Path("/etc/systemd/system") / unit,
                            1 << 16, 0o644)) == sha
             for unit, sha in intent["next_static_units"].items()),
         "rotation_handoff_installed_source_changed")
    assessment = regular(ROTATION_ASSESSMENT, 1 << 15)
    state = regular(GUARD_STATE, 1 << 15)
    need(state == assessment, "rotation_handoff_assessment_changed")
    policy_source = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    policy_source.parse_state(state)
    current = read_guard_policy()
    need(current["state_sha256"] == digest(assessment) and
         current["manager_binding_sha256"] is None and
         not Path(str(GUARD_STATE) + ".client-binding").exists() and
         not Path(str(GUARD_STATE) + ".client-binding").is_symlink(),
         "rotation_handoff_not_denied")
    receipt = {
        "schema": "aegis_auto_guard_rotation_state_handoff_v1",
        "boot_id": intent["boot_id"],
        "kind": intent["successor"]["kind"],
        "intent_sha256": digest(regular(ROTATION_INTENT, MAX_ROTATION_INTENT)),
        "denied_sha256": digest(regular(ROTATION_DENIED, MAX_RECEIPT)),
        "retired_sha256": digest(regular(ROTATION_RETIRED, MAX_RECEIPT)),
        "assessment_sha256": digest(assessment),
        "state_sha256": current["state_sha256"],
        "policy_sha256": current["policy_sha256"],
        "new_install_sha256": digest(regular(INSTALL, MAX_RECEIPT)),
        "candidate_sha256": intent["successor"]["next_candidate_sha256"],
        "guard_device": intent["guard_device"],
        "guard_inode": intent["guard_inode"],
        "no_client_grant": True,
        "no_manager_binding": True,
    }
    _held_lock(install_fd, INSTALL_LOCK)
    _held_lock(guard_fd, GUARD_LOCK)
    _rotation_write_once(ROTATION_HANDOFF, receipt)
    need(regular(GUARD_STATE, 1 << 15) == assessment and
         read_guard_policy() == current,
         "rotation_handoff_changed_after_seal")
    return receipt


def _boot_fixed_client_stopped(deadline: float) -> None:
    remaining = deadline - time.monotonic()
    need(remaining > 0, "boot_readback_deadline_elapsed")
    names = ("Id", "LoadState", "FragmentPath", "ActiveState", "SubState",
             "MainPID", "ControlPID", "ControlGroup",
             "NFileDescriptorStore")
    command = ["/usr/bin/systemctl", "show", "aegis-client.service",
               "--no-pager"]
    for name in names:
        command.extend(("-p", name))
    result = subprocess.run(command, stdin=subprocess.DEVNULL,
                            capture_output=True, check=False,
                            timeout=min(3.0, remaining),
                            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C",
                                 "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 8192 and
         len(result.stderr) <= 4096, "boot_fixed_client_pid1_unavailable")
    facts: dict[str, str] = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        need(sep == "=" and key not in facts, "boot_fixed_client_pid1_invalid")
        facts[key] = value
    need(set(facts) == set(names) and facts["Id"] == "aegis-client.service" and
         facts["LoadState"] == "loaded" and
         facts["FragmentPath"] ==
         "/etc/systemd/system/aegis-client.service" and
         facts["ActiveState"] == "inactive" and facts["SubState"] == "dead" and
         facts["MainPID"] == "0" and facts["ControlPID"] == "0" and
         facts["NFileDescriptorStore"] == "0" and
         facts["ControlGroup"] in ("", "/system.slice/aegis-client.service"),
         "boot_fixed_client_not_stopped")
    if facts["ControlGroup"]:
        group = Path("/sys/fs/cgroup") / facts["ControlGroup"].lstrip("/")
        need(not group.exists() or
             group.joinpath("cgroup.procs").read_text(encoding="ascii") == "",
             "boot_fixed_client_cgroup_not_empty")


def _boot_private_owners_absent(deadline: float) -> None:
    remaining = deadline - time.monotonic()
    need(remaining > 0, "boot_readback_deadline_elapsed")
    result = subprocess.run(
        ["/usr/bin/systemctl", "list-units", "--all",
         "aegis-auto@*.service", "--no-legend", "--no-pager", "--plain"],
        stdin=subprocess.DEVNULL, capture_output=True, check=False,
        timeout=min(3.0, remaining),
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 1 << 16 and
         len(result.stderr) <= 4096, "boot_private_units_unavailable")
    for line in result.stdout.decode("ascii").splitlines():
        fields = line.split()
        need(len(fields) >= 4 and
             PRIVATE_UNIT.fullmatch(fields[0]) is not None and
             fields[2] == "inactive" and fields[3] == "dead",
             "boot_private_owner_present")


def _boot_actor_observation_once(deadline: float) -> list[dict[str, object]]:
    observations: list[dict[str, object]] = []
    for unit, source, _path in ROTATION_ACTORS:
        facts = _rotation_actor_facts(unit, deadline=deadline)
        pid = int(facts["MainPID"])
        need(facts["ControlPID"] == "0" and
             facts["NFileDescriptorStore"] == "0" and
             (pid == 0 and facts["ActiveState"] == "inactive" and
              facts["SubState"] == "dead" or
              pid > 1 and facts["ActiveState"] == "active" and
              facts["SubState"] == "running" and
              HEX32.fullmatch(facts["InvocationID"]) is not None),
             "boot_actor_state_invalid")
        if pid > 1:
            need(facts["ControlGroup"] == "/system.slice/" + unit and
                 Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
                 "0::" + facts["ControlGroup"] + "\n" and
                 Path(f"/proc/{pid}/cmdline").read_bytes() ==
                 _rotation_actor_command(unit, source),
                 "boot_actor_identity_changed")
            handle = os.pidfd_open(pid, 0)
            try:
                need(_pid_alive(handle), "boot_actor_identity_changed")
            finally:
                os.close(handle)
        observations.append({"unit": unit, "active": pid > 1,
                             "main_pid": pid,
                             "invocation_id": facts["InvocationID"] if pid else None})
    _rotation_static_stopped(deadline)
    _rotation_actor_jobs(deadline)
    return observations


def _boot_actor_observation(deadline: float) -> list[dict[str, object]]:
    while True:
        try:
            return _boot_actor_observation_once(deadline)
        except RotationActorJobPending:
            # A valid PID1 pending-job row is boot readiness, not authority.
            # Restart the complete actor/static/job observation after it clears.
            remaining = deadline - time.monotonic()
            need(remaining > 0, "rotation_actor_deadline_elapsed")
            time.sleep(min(0.05, remaining))


def boot_denied_readback(install_fd: int,
                         guard_fd: int) -> dict[str, object]:
    """Fresh-boot readback of installed deny and absence of runtime owner."""
    own_source()
    _held_lock(install_fd, INSTALL_LOCK)
    guard_device, guard_inode = _held_lock(guard_fd, GUARD_LOCK)
    deadline = time.monotonic() + 30.0
    installed = record(INSTALL)
    first = read_guard_policy()
    need(first["state_sha256"] == digest(regular(GUARD_STATE, 1 << 15)),
         "boot_guard_state_changed")
    _boot_pending_absent()
    _boot_fixed_client_stopped(deadline)
    _boot_private_owners_absent(deadline)
    actors = _boot_actor_observation(deadline)
    second = read_guard_policy()
    _boot_pending_absent()
    _boot_fixed_client_stopped(deadline)
    _boot_private_owners_absent(deadline)
    need(second == first and
         _boot_actor_observation(deadline) == actors and
         time.monotonic() < deadline,
         "boot_deny_changed")
    _held_lock(install_fd, INSTALL_LOCK)
    need(_held_lock(guard_fd, GUARD_LOCK) == (guard_device, guard_inode),
         "boot_guard_lock_changed")
    return {"schema": "aegis_auto_guard_boot_denied_readback_v1",
            "boot_id": host_anchor()["boot_id"],
            "candidate_sha256": installed["worker_sha256"],
            "install_sha256": digest(regular(INSTALL, MAX_RECEIPT)),
            "state_sha256": first["state_sha256"],
            "policy_sha256": first["policy_sha256"],
            "manager_binding_sha256": first["manager_binding_sha256"],
            "guard_device": guard_device, "guard_inode": guard_inode,
            "no_client_grant": True, "no_private_owner": True,
            "fixed_client_stopped": True, "actors": actors}


def _boot_pending_absent() -> None:
    for path in (STOP_INTENT, WATCHDOG_PENDING):
        need(not path.exists() and not path.is_symlink(),
             "boot_pending_recovery_present")


def _boot_passive_absent() -> None:
    """Passive Socks has no guarded policy or pending inverse authority."""
    _boot_pending_absent()
    for path in (GUARD_UNIT_FILE, GUARD_STATE, POLICY,
                 Path(str(GUARD_STATE) + ".manager-binding"),
                 Path(str(GUARD_STATE) + ".client-binding")):
        need(not path.exists() and not path.is_symlink(),
             "boot_passive_guard_or_pending_present")


def boot_passive_readback(install_fd: int) -> dict[str, object]:
    """Fresh-boot passive Socks observation; never claim a kernel guard."""
    own_source()
    _held_lock(install_fd, INSTALL_LOCK)
    deadline = time.monotonic() + 30.0
    installed_raw = regular(INSTALL, MAX_RECEIPT)
    installed = record(INSTALL)
    need(installed["guard_unit_sha256"] is None,
         "boot_passive_guard_installed")
    boot = host_anchor()["boot_id"]
    _boot_passive_absent()
    _boot_fixed_client_stopped(deadline)
    _boot_private_owners_absent(deadline)
    actors = _boot_actor_observation(deadline)
    _boot_passive_absent()
    _boot_fixed_client_stopped(deadline)
    _boot_private_owners_absent(deadline)
    need(_boot_actor_observation(deadline) == actors and
         regular(INSTALL, MAX_RECEIPT) == installed_raw and
         host_anchor()["boot_id"] == boot and
         time.monotonic() < deadline,
         "boot_passive_changed")
    _held_lock(install_fd, INSTALL_LOCK)
    return {"schema": "aegis_auto_guard_boot_passive_readback_v1",
            "passive": True, "boot_id": boot,
            "candidate_sha256": installed["worker_sha256"],
            "install_sha256": digest(installed_raw),
            "no_private_owner": True, "fixed_client_stopped": True,
            "actors": actors}


def _publish_policy_receipt(value: dict[str, object]) -> None:
    """Publish a host-verified seal while retaining the original guard OFD."""
    parent = POLICY.parent
    parent_info = parent.stat(follow_symlinks=False)
    need(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == 0 and
         parent_info.st_mode & 0o022 == 0, "policy_parent_untrusted")
    if POLICY.exists() or POLICY.is_symlink():
        regular(POLICY, MAX_RECEIPT)
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    need(len(raw) <= MAX_RECEIPT, "policy_receipt_too_large")
    temporary = parent / (".auto-policy-seal-" + secrets.token_hex(12))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), "policy_receipt_short_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temporary, POLICY)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise
    need(regular(POLICY, MAX_RECEIPT) == raw and record(POLICY) == value,
         "policy_receipt_changed_after_publish")


def _semantic_policy_readback(*, deadline: float | None = None) -> tuple[bytes, bytes]:
    """Prove every accepting predicate, including text-only cgroup level."""
    witness = verified_module(WITNESS, "aegis_auto_native_witness")
    guard_policy = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    state_path = Path("/var/lib/aegis-install/client/device-guard.conf")
    state = regular(state_path, 1 << 15)
    bindings: dict[str, bytes | None] = {}
    for role in ("client", "manager"):
        path = Path(str(state_path) + f".{role}-binding")
        bindings[role] = regular(path, 4096) if path.exists() else None
        need(not path.is_symlink(), "untrusted_guard_binding")
    capture_binding = (regular(CAPTURE_BINDING, 4096)
                       if CAPTURE_BINDING.exists() else None)
    need(not CAPTURE_BINDING.is_symlink(), "untrusted_capture_binding")
    if capture_binding is not None:
        bound_capture = json.loads(capture_binding, object_pairs_hook=unique)
        need(type(bound_capture) is dict and
             type(bound_capture.get("ifindex")) is int and
             bound_capture["ifindex"] > 0 and
             socket.if_nametoindex("aegis-tun0") == bound_capture["ifindex"],
             "capture_numeric_binding_link_changed")

    if bindings["manager"] is not None:
        parsed = guard_policy.parse_state(state)
        manager = json.loads(bindings["manager"], object_pairs_hook=unique)
        need(manager.get("schema") == "aegis_device_guard_binding_v2" and
             manager.get("ifindex") == socket.if_nametoindex(parsed["uplink"]),
             "guard_manager_ifindex_changed")
    first = witness.read_policy_raw(Path("/usr/sbin/nft"), deadline=deadline)
    nft_text = witness.read_policy_raw(Path("/usr/sbin/nft"), text=True,
                                       deadline=deadline)
    second = witness.read_policy_raw(Path("/usr/sbin/nft"), deadline=deadline)
    projection, _handles, _counters = witness.policy_projection(first)
    confirmed, _handles2, _counters2 = witness.policy_projection(second)
    need(guard_policy.verify_expected_policy(
             state, first, nft_text, bindings["client"],
             bindings["manager"], boot_id=host_anchor()["boot_id"],
             capture_binding=capture_binding) ==
         digest(projection), "guard_semantic_seal_changed")
    canonical = guard_policy.canonical_manager_projection(
        projection, bindings["manager"])
    canonical_second = guard_policy.canonical_manager_projection(
        confirmed, bindings["manager"])
    need(canonical == canonical_second, "guard_semantic_seal_changed")
    return state, canonical


def _semantic_policy_snapshot() -> tuple[bytes, dict[str, int], dict[str, int]]:
    """Bind snapshot handles to a fresh full JSON/text semantic readback.

    The manager cgroup may be printed as its protected inode after PID1
    removes its name. Both views must still describe the exact same policy.
    """
    _state, semantic = _semantic_policy_readback()
    witness = verified_module(WITNESS, "aegis_auto_native_witness")
    policy = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    projection, handles, counters = witness.snapshot_policy(Path("/usr/sbin/nft"))
    manager_path = GUARD_STATE.with_name(GUARD_STATE.name + ".manager-binding")
    need(not manager_path.is_symlink(), "guard_semantic_snapshot_binding_changed")
    manager = regular(manager_path, 4096) if manager_path.exists() else None
    need(policy.canonical_manager_projection(projection, manager) == semantic,
         "guard_semantic_snapshot_changed")
    return semantic, handles, counters


def _semantic_capture_snapshot(nft_path: Path) -> tuple[
        bytes, dict[str, int], dict[str, int]]:
    need(nft_path == Path("/usr/sbin/nft"), "foreign_capture_nft_source")
    return _semantic_policy_snapshot()


def _unit_identity(unit: str, pid: int) -> dict[str, str]:
    command = ["/usr/bin/systemctl", "show", unit,
               "-p", "MainPID", "-p", "ControlGroup",
               "-p", "InvocationID", "--no-pager"]
    result = subprocess.run(command, capture_output=True, timeout=2,
                            check=False, env={"PATH": "/usr/sbin:/usr/bin",
                                              "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 4096 and
         len(result.stderr) <= 4096, "unit_identity_unavailable")
    facts = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        need(separator == "=" and key not in facts, "unit_facts_invalid")
        facts[key] = value
    need(set(facts) == {"MainPID", "ControlGroup", "InvocationID"} and
         facts["MainPID"] == str(pid) and
         HEX32.fullmatch(facts["InvocationID"]) is not None and
         facts["ControlGroup"].startswith("/system.slice/") and
         facts["ControlGroup"].endswith("/" + unit),
         "foreign_or_ambiguous_unit")
    cgroup = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii")
    need(cgroup == "0::" + facts["ControlGroup"] + "\n",
         "unit_cgroup_changed")
    return facts


def _peer_identity(peer: socket.socket) -> tuple[int, int]:
    raw = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    pid, uid, _gid = struct.unpack("3i", raw)
    need(pid > 1 and uid == 0, "foreign_peer")
    # SO_PEERPIDFD is tied to this connected AF_UNIX socket.  Opening a
    # pidfd later from the numeric SO_PEERCRED PID would allow a reuse race.
    pidfd_raw = peer.getsockopt(socket.SOL_SOCKET,
                                getattr(socket, "SO_PEERPIDFD", 77), 4)
    need(len(pidfd_raw) == 4, "peer_pidfd_unavailable")
    pidfd = struct.unpack("i", pidfd_raw)[0]
    try:
        pidinfo = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="ascii")
        need(any(line == f"Pid:\t{pid}" for line in pidinfo.splitlines()),
             "peer_pidfd_identity_changed")
        # A live PIDFD pins the process identity across the request.  Polling
        # it before and after effects detects exit without PID reuse.
        watcher = select.poll()
        watcher.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        need(not watcher.poll(0), "peer_exited_before_admission")
        return pid, pidfd
    except BaseException:
        os.close(pidfd)
        raise


def _peer_executable(pid: int, expected_sha256: str) -> None:
    need(type(expected_sha256) is str and HEX64.fullmatch(expected_sha256) is not None and
         executable_digest(Path(f"/proc/{pid}/exe")) == expected_sha256,
         "peer_role_executable_changed")


def _held_guard(fd: int) -> tuple[int, int]:
    identity = _held_lock(fd, GUARD_LOCK)
    need(not TERMINAL_MIGRATION_PENDING.exists() and
         not TERMINAL_MIGRATION_PENDING.is_symlink(),
         'terminal_migration_pending')
    cold_intent = TERMINAL_MIGRATION_PENDING.parent/'cold-recovery'/'intent.json'
    need(not cold_intent.exists() and not cold_intent.is_symlink(),
         'cold_recovery_pending')
    need(not SPLIT.exists() and not SPLIT.is_symlink(),
         "guard_recovery_split")
    need(not STOP_INTENT.exists() and not STOP_INTENT.is_symlink(),
         "stopping_client_cannot_acquire_new_lease")
    return identity


def _held_install(fd: int) -> bool:
    _held_lock(fd, INSTALL_LOCK)
    return True


def _currentboot_consumption_before_first_grant(install_fd: int,
                                                guard_fd: int) -> dict | None:
    """Reauthenticate a prior normal-stop transition before the first lease."""
    _held_install(install_fd)
    _held_lock(guard_fd, GUARD_LOCK)
    need(not TERMINAL_MIGRATION_PENDING.exists() and
         not TERMINAL_MIGRATION_PENDING.is_symlink(),
         'terminal_migration_pending')
    transition = verified_module(ROOT/'aegis_auto_boot_transition.py',
                                 'aegis_auto_boot_transition')
    current_boot = host_anchor()['boot_id']
    source, store = transition._source_facts()
    transition._cold_consumed_under_guard(
        current_boot, source, transition.read(transition.SOURCE_CONFIG,4096))
    receipt = transition.read_consumed_record(current_boot, allow_missing=True)
    if receipt is None:
        # On an initial installation there is no old shutdown carrier. A
        # carrier without its current-boot consumed proof is never a grant.
        transition.historical_carriers_closed(store, source)
        return
    old_raw = transition.read(transition.ROOT/('auto-stop-intent-'+receipt['old_boot_id']+
                                               '-'+receipt['old_intent_sha256']+'.json'))
    old = transition.decode(old_raw)
    marker_path = transition._marker_path(old['boot_id'], store)
    recovered = transition.recovered_for_old(old, current_boot)
    if recovered is None:
        recovered = transition.ROOT/('auto-watchdog-no-journal-'+old['boot_id']+'-'+
                                     receipt['old_intent_sha256']+'.json')
    def locks(a: int, b: int) -> None:
        _held_install(a)
        _held_lock(b, GUARD_LOCK)
    authenticated_lineage: dict | None = None
    def blocked(intent: dict, marker: dict, recovered_row: dict) -> None:
        nonlocal authenticated_lineage
        locks(install_fd, guard_fd)
        candidate = transition.verify_old_lineage(marker, intent, current_boot)
        authenticated_lineage = {
            'current_boot_id': current_boot,
            'predecessor_boot_id': intent['boot_id'],
            'candidate_sha256': candidate,
            'private_unit': intent['service']}
        snapshot_sha, active_sha = _boot_guard_binding({
            'boot_id': current_boot,
            'boot_snapshot_sha256': marker['boot_snapshot_sha256'],
            'active_report_sha256': marker['active_report_sha256'],
            'predecessor_boot_id': intent['boot_id'],
            'candidate_sha256': candidate,
            'private_unit': intent['service'],
            'prior_invocation_id': intent['invocation_id']},
            marker['active_generation_sha256'])
        need(snapshot_sha == marker['boot_snapshot_sha256'] and
             active_sha == marker['active_generation_sha256'],
             'terminal_old_generation_changed')
        authenticated_lineage['source_config_sha256'] = (
            _boot_snapshot_config_sha256(
                snapshot_sha, marker['active_report_sha256'], intent['boot_id'],
                candidate))
        deadline = time.monotonic() + 12
        _state, projection = _semantic_policy_readback(deadline=deadline)
        need(_no_client_grant(projection), 'terminal_consumed_deny_changed')
        _crossboot_policy_seals(intent['boot_id'], marker['policy_sha256'],
                                receipt['policy_sha256'], projection)
        # The cross-boot verifier just matched the current protected policy
        # receipt to the full live kernel table, including any new manager
        # DHCP binding. This is a current-boot deny seal, not an old grant.
        authenticated_lineage['current_policy_sha256'] = digest(projection)
        _boot_fixed_client_stopped(deadline)
        _boot_private_owners_absent(deadline)
        locks(install_fd, guard_fd)
    marker_raw = transition.read(marker_path)
    marker = transition.decode(marker_raw)
    historical_source, historical_store = transition.historical_source_context(
        marker.get('source_sha256'), source, store,
        transition.sha(marker_raw))
    need(historical_source.get('schema') == 'aegis_auto_terminal_source_v1' and
         historical_store.get('schema') == 'aegis_auto_terminal_boot_store_v1' and
         historical_store['root_uuid'] == store['root_uuid'] and
         historical_store['root_dev'] == store['root_dev'] and
         historical_store['boot_uuid'] == store['boot_uuid'] and
         historical_store['boot_dev'] == store['boot_dev'],
         'terminal_historical_source_changed')
    authenticated = transition.authenticated_consumed(
        current_boot=current_boot, marker_path=marker_path,
        recovered_path=recovered,
        source_sha=marker['source_sha256'],
        boot_uuid=historical_store['boot_uuid'], validate_locks=locks,
        install_fd=install_fd, guard_fd=guard_fd,
        verify_block_and_owner=blocked)
    need(authenticated == receipt and authenticated_lineage is not None and
         'current_policy_sha256' in authenticated_lineage and
         authenticated_lineage['predecessor_boot_id'] == receipt['old_boot_id'],
         'terminal_first_arm_lineage_missing')
    return authenticated_lineage


def _exclusive_flock_fdinfo(fdinfo: str, identity: os.stat_result) -> bool:
    """Match Linux fdinfo's full-file flock for this exact inode.

    fs/locks.c prints FLOCK with two spaces between fields.  The owner PID
    can become zero after its original process exits while PID 1 still holds
    the same OFD, so it is parsed but never used as the lease identity.
    """
    if len(fdinfo) > 4096:
        return False
    locks = [line.split() for line in fdinfo.splitlines()
             if line.startswith("lock:")]
    if len(locks) != 1:
        return False
    fields = locks[0]
    if (len(fields) != 9 or fields[0] != "lock:" or
            re.fullmatch(r"[1-9][0-9]*:", fields[1]) is None or
            fields[2:5] != ["FLOCK", "ADVISORY", "WRITE"] or
            re.fullmatch(r"[0-9]+", fields[5]) is None or
            fields[7:] != ["0", "EOF"]):
        return False
    device = re.fullmatch(r"([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)",
                          fields[6])
    return (device is not None and
            int(device[1], 16) == os.major(identity.st_dev) and
            int(device[2], 16) == os.minor(identity.st_dev) and
            int(device[3]) == identity.st_ino)


def _held_lock(fd: int, path: Path) -> tuple[int, int]:
    current = os.fstat(fd)
    named = path.stat(follow_symlinks=False)
    need(stat.S_ISREG(current.st_mode) and current.st_uid == 0 and
         current.st_nlink == 1 and stat.S_IMODE(current.st_mode) == 0o600 and
         (current.st_dev, current.st_ino) == (named.st_dev, named.st_ino),
         "held_lock_changed")
    # The caller passes a duplicate of its flocked open file description.
    # An independent acquisition here would deadlock the owner's worker.
    fdinfo = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii")
    need(_exclusive_flock_fdinfo(fdinfo, current),
         "exclusive_flock_not_held")
    return current.st_dev, current.st_ino


def _claim_guard_handoff(fd: int) -> tuple[int, int]:
    """The source-authenticated PID1 actor is the first writer on this OFD.

    The existing two-second acquisition budget moves from the private worker
    here. No policy is read or changed while another OFD owns the lock.
    """
    held = os.fstat(fd)
    named = GUARD_LOCK.stat(follow_symlinks=False)
    need(stat.S_ISREG(held.st_mode) and held.st_uid == 0 and
         held.st_nlink == 1 and stat.S_IMODE(held.st_mode) == 0o600 and
         (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
         "guard_handoff_inode_changed")
    info = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii")
    need(not any("FLOCK" in line for line in info.splitlines()),
         "guard_handoff_already_locked")
    deadline = time.monotonic() + 2.0
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            need(time.monotonic() < deadline, "guard_handoff_busy")
            # Non-blocking only: request threads cannot bound a blocking
            # flock with SIGALRM. A shorter retry keeps the same deadline.
            time.sleep(min(FLOCK_RETRY_SECONDS, max(0, deadline - time.monotonic())))
    identity = _held_guard(fd)
    need(identity == (held.st_dev, held.st_ino), "guard_handoff_inode_changed")
    return identity


def _pid_alive(fd: int) -> bool:
    watcher = select.poll()
    watcher.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not watcher.poll(0)


def _stage(fd: int, requested: dict[str, object], *, initial: bool) -> tuple[int, int]:
    value = os.fstat(fd)
    need(stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and
         value.st_mode & 0o022 == 0, "untrusted_stage_fd")
    header_fd = os.open("header.json", os.O_RDONLY | os.O_CLOEXEC |
                        os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        h = os.fstat(header_fd)
        need(stat.S_ISREG(h.st_mode) and h.st_uid == 0 and h.st_nlink == 1 and
             stat.S_IMODE(h.st_mode) == 0o600 and 0 < h.st_size <= 65536,
             "untrusted_stage_header")
        raw = os.read(header_fd, 65537)
        need(len(raw) == h.st_size and
             (not initial or digest(raw) == requested["header_sha256"]),
             "stage_header_changed")
        header = json.loads(raw, object_pairs_hook=unique)
        need(type(header) is dict and
             header.get("transaction_nonce") == requested["transaction_nonce"] and
             header.get("planned_generation") == requested["planned_generation"],
             "stage_binding_changed")
    finally:
        os.close(header_fd)
    return value.st_dev, value.st_ino


def _scoped_config_binding(stage_fd: int, request: dict[str, object],
                           guard_policy_sha256: str) -> dict | None:
    """Derive an explicit ingress scope from the protected render recipe."""
    if request["mode"] != "wide-redirect-safe":
        return None
    endpoint = verified_module(ENDPOINT_SOURCE, "aegis_auto_endpoint")
    lease = endpoint.admit_scoped_redirect_config(
        stage_fd=stage_fd,
        transaction_nonce=request["transaction_nonce"],
        planned_generation=request["planned_generation"],
        private_unit=request["private_unit"])
    if lease is None:
        return None
    try:
        lease.revalidate()
        stage = os.fstat(stage_fd)
        return {"stage_dev": stage.st_dev, "stage_ino": stage.st_ino,
                "private_unit": request["private_unit"],
                "transaction_nonce": request["transaction_nonce"],
                "planned_generation": request["planned_generation"],
                "boot_id": request["boot_id"],
                "netns_ino": request["netns_ino"],
                "config_sha256_initial": lease.config_sha256,
                "config_semantic_sha256": lease.config_semantic_sha256,
                "interface": lease.interface, "ifindex": lease.ifindex,
                "listen_ipv4": lease.listen_ipv4,
                "listen_port": lease.listen_port,
                "guard_policy_sha256": guard_policy_sha256}
    finally:
        lease.close()


def _scoped_route_refusal(interface: str, guard_state_sha256: str,
                          relay_pool: tuple[tuple[str, str, str], ...]) -> None:
    """Refuse scoped ingress on the guard uplink or a live egress route."""
    state, _projection = _semantic_policy_readback()
    need(digest(state) == guard_state_sha256,
         "scoped_route_guard_state_changed")
    fields = dict(line.split("=", 1) for line in state.decode("ascii").splitlines())
    need(interface != fields["uplink"], "scoped_ingress_is_guard_uplink")

    def route(family: str, *args: str) -> None:
        result = subprocess.run(["/usr/sbin/ip", "-j", family, "route", *args],
                                stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=2, env={"PATH": "/usr/sbin:/usr/bin",
                                                "LANG": "C", "LC_ALL": "C"})
        need(result.returncode == 0 and len(result.stdout) <= 16384
             and result.stderr == b"",
             "scoped_ingress_route_readback_unavailable")
        rows = json.loads(result.stdout, object_pairs_hook=unique)
        need(type(rows) is list and all(type(row) is dict and
             type(row.get("dev")) is str and
             not any(key in row for key in ("multipath", "nexthops", "nhid"))
             for row in rows),
             "scoped_ingress_route_readback_invalid")
        need(args[0] != "get" or len(rows) == 1,
             "scoped_ingress_relay_route_missing")
        need(all(row["dev"] != interface for row in rows),
             "scoped_ingress_is_egress_route")

    for family in ("-4", "-6"):
        route(family, "show", "default")
    need(type(relay_pool) is tuple and bool(relay_pool),
         "scoped_ingress_relay_pool_missing")
    for _kind, address, _name in relay_pool:
        host = address[1:].split("]:", 1)[0] if address.startswith("[") else \
               address.rsplit(":", 1)[0]
        try:
            family = "-6" if ipaddress.ip_address(host).version == 6 else "-4"
        except ValueError as error:
            raise ValueError("scoped_ingress_relay_not_numeric") from error
        route(family, "get", host)


_FIRST_ARM_COORDINATES = frozenset({
    'receipt_shape', 'receipt_schema', 'request_current_boot',
    'boot_shape', 'lineage_absent', 'lineage_shape', 'lineage_current_boot',
    'lineage_predecessor_boot', 'lineage_candidate', 'old_unit_shape',
    'new_unit_shape', 'unit_reused', 'receipt_hex_fields',
    'relay_list_shape', 'relay_list_count', 'relay_item_shape',
    'manager', 'source_config_leaf', 'installed_main', 'guard_unit',
    'manager_dropin', 'guardian_install', 'assessment_state',
    'install_guard_unit', 'current_policy_seal',
})


def _first_arm_gate(value: bool, coordinate: str, phase: str) -> bool:
    """Keep the original Boolean gate and emit only a static private coordinate."""
    if not value:
        if coordinate in _FIRST_ARM_COORDINATES:
            location = phase if phase in ('grant', 'bind', 'capture') else 'other'
            try:
                os.write(2, ('aegis_auto_firstarm_refused phase=' + location +
                             ' gate=' + coordinate + '\n').encode('ascii'))
            except OSError:
                pass
    return value


def _first_arm_boot_owned(receipt: dict, request: dict,
                          authenticated_lineage: dict | None,
                          phase: str = 'other'
                          ) -> bool:
    """A later boot inherits only an exact, authenticated installed producer."""
    boot = receipt['boot_id']
    current = request['boot_id']
    if not _first_arm_gate(type(boot) is str and
                           re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
                                        boot) is not None, 'boot_shape', phase):
        return False
    if boot == current:
        return True
    if not _first_arm_gate(authenticated_lineage is not None,
                           'lineage_absent', phase):
        return False
    if not _first_arm_gate(type(authenticated_lineage) is dict and
                           set(authenticated_lineage) == {
                               'current_boot_id', 'predecessor_boot_id',
                               'candidate_sha256', 'private_unit',
                               'current_policy_sha256',
                               'source_config_sha256'}, 'lineage_shape', phase):
        return False
    if not _first_arm_gate(authenticated_lineage['current_boot_id'] == current,
                           'lineage_current_boot', phase):
        return False
    if not _first_arm_gate(authenticated_lineage['predecessor_boot_id'] != current,
                           'lineage_predecessor_boot', phase):
        return False
    if not _first_arm_gate(authenticated_lineage['candidate_sha256'] ==
                           receipt['candidate_sha256'], 'lineage_candidate', phase):
        return False
    if not _first_arm_gate(
            type(authenticated_lineage['source_config_sha256']) is str and
            HEX64.fullmatch(authenticated_lineage['source_config_sha256']) is not None,
            'lineage_shape', phase):
        return False
    old_unit = authenticated_lineage['private_unit']
    new_unit = request['private_unit']
    if not _first_arm_gate(type(old_unit) is str and
                           PRIVATE_UNIT.fullmatch(old_unit) is not None,
                           'old_unit_shape', phase):
        return False
    if not _first_arm_gate(type(new_unit) is str and
                           PRIVATE_UNIT.fullmatch(new_unit) is not None,
                           'new_unit_shape', phase):
        return False
    # The authenticated old service was retired before this grant. PID 1
    # mints a fresh private unit for every new boot transaction.
    return _first_arm_gate(old_unit != new_unit, 'unit_reused', phase)


def _first_arm_guard_owned(receipt: dict, request: dict,
                           current_policy_sha256: str,
                           authenticated_lineage: dict | None,
                           phase: str = 'other') -> bool:
    if receipt['boot_id'] == request['boot_id']:
        return _first_arm_gate(current_policy_sha256 == receipt['policy_sha256'],
                               'current_policy_seal', phase)
    return _first_arm_gate(authenticated_lineage is not None and
                           authenticated_lineage.get('current_policy_sha256') ==
                           current_policy_sha256, 'current_policy_seal', phase)


def _fulltun_first_arm(stage_fd: int, request: dict[str, object], *,
                       authenticated_lineage: dict | None = None,
                       phase: str = 'other'
                       ) -> tuple[str, list[str]] | None:
    """Admit a fresh production FullTun only from its protected first arm."""
    leaf = "input/payload/metadata/auto-guard-first-arm.json"
    header = json.loads(_protected_stage_receipt_for_header(stage_fd),
                        object_pairs_hook=unique)
    need(header.get("transaction_nonce") == request["transaction_nonce"] and
         header.get("planned_generation") == request["planned_generation"] and
         header.get("mode") == "full-wide-tun" and
         type(header.get("leaves")) is dict,
         "fulltun_first_arm_header_changed")
    if leaf not in header["leaves"]:
        return None
    raw = _protected_stage_receipt(stage_fd, leaf)
    need(header["leaves"][leaf] == digest(raw) and
         regular(Path("/var/lib/aegis-install/client/auto-guard-first-arm.json"),
                 4096) == raw,
         "fulltun_first_arm_leaf_changed")
    receipt = json.loads(raw, object_pairs_hook=unique)
    fields = {"schema", "boot_id", "candidate_sha256",
              "source_config_sha256", "relay_servers", "assessment_sha256",
              "guard_unit_sha256", "manager", "manager_dropin_sha256",
              "guardian_install_sha256", "policy_sha256",
              "installer_source_sha256"}
    source = ("input/payload/bundle-main/aegis-client.toml" if
              "input/payload/bundle-main/aegis-client.toml" in header["leaves"]
              else "input/payload/config/aegis.toml")
    manager = receipt.get("manager") if type(receipt) is dict else None
    need(_first_arm_gate(type(receipt) is dict and set(receipt) == fields,
                         'receipt_shape', phase) and
         _first_arm_gate(receipt["schema"] == "aegis_auto_guard_first_arm_v1",
                         'receipt_schema', phase) and
         _first_arm_gate(request["boot_id"] ==
                         Path("/proc/sys/kernel/random/boot_id").read_text(
                             encoding="ascii").strip(),
                         'request_current_boot', phase) and
         _first_arm_boot_owned(receipt, request, authenticated_lineage,
                               phase) and
         _first_arm_gate(all(type(receipt[key]) is str and
                             HEX64.fullmatch(receipt[key]) is not None
                             for key in fields -
                             {"schema", "boot_id", "relay_servers", "manager"}),
                         'receipt_hex_fields', phase) and
         _first_arm_gate(type(receipt["relay_servers"]) is list,
                         'relay_list_shape', phase) and
         _first_arm_gate(0 < len(receipt["relay_servers"]) <= 17,
                         'relay_list_count', phase) and
         _first_arm_gate(all(type(server) is str and 0 < len(server) <= 253
                             for server in receipt["relay_servers"]),
                         'relay_item_shape', phase) and
         _first_arm_gate(manager in ("NetworkManager.service",
                                     "systemd-networkd.service"),
                         'manager', phase) and
         _first_arm_gate(
             (header["leaves"].get(source) == receipt["source_config_sha256"]
              if receipt['boot_id'] == request['boot_id'] else
              source == "input/payload/config/aegis.toml" and
              header["leaves"].get(source) ==
              authenticated_lineage['source_config_sha256']),
                         'source_config_leaf', phase) and
         _first_arm_gate(_installed_main_digest(stage_fd, request) ==
                         receipt["candidate_sha256"],
                         'installed_main', phase) and
         _first_arm_gate(digest(regular(GUARD_UNIT_FILE, 1 << 16, 0o644)) ==
                         receipt["guard_unit_sha256"],
                         'guard_unit', phase) and
         _first_arm_gate(digest(regular(Path("/etc/systemd/system") /
                                        (manager + ".d") /
                                        "30-aegis-device-guard.conf",
                                        1 << 16, 0o644)) ==
                         receipt["manager_dropin_sha256"],
                         'manager_dropin', phase) and
         _first_arm_gate(digest(regular(INSTALL, 4096)) ==
                         receipt["guardian_install_sha256"],
                         'guardian_install', phase) and
         _first_arm_gate(record(POLICY)["state_sha256"] ==
                         receipt["assessment_sha256"],
                         'assessment_state', phase) and
         _first_arm_gate(record(INSTALL)["guard_unit_sha256"] ==
                         receipt["guard_unit_sha256"],
                         'install_guard_unit', phase),
         "fulltun_first_arm_owner_changed")
    if not verified_module(POLICY_SOURCE,
                           "aegis_auto_guard_policy").LOCAL_INTENT.exists():
        current_policy = record(POLICY)["policy_sha256"]
        need(_first_arm_guard_owned(receipt, request, current_policy,
                                    authenticated_lineage, phase),
             "fulltun_first_arm_guard_changed")
    return digest(raw), receipt["relay_servers"]


def _local_config_binding(stage_fd: int, request: dict[str, object],
                          guard_policy_sha256: str, *,
                          current_policy_sha256: str | None = None,
                          authenticated_lineage: dict | None = None,
                          phase: str = 'other'
                          ) -> dict | None:
    """Derive local OUTPUT authority solely from the sealed render recipe."""
    if request["mode"] not in ("wide-redirect-safe", "full-wide-tun"):
        return None
    endpoint = verified_module(ENDPOINT_SOURCE, "aegis_auto_endpoint")
    first_arm = None
    first_arm_servers = None
    if request["mode"] == "full-wide-tun":
        admitted_first_arm = _fulltun_first_arm(
            stage_fd, request,
            authenticated_lineage=authenticated_lineage, phase=phase)
        if admitted_first_arm is None:
            return None
        first_arm, first_arm_servers = admitted_first_arm
        lease = endpoint.admit_local_fulltun_config(
            stage_fd=stage_fd,
            transaction_nonce=request["transaction_nonce"],
            planned_generation=request["planned_generation"])
    else:
        lease = endpoint.admit_local_redirect_config(
            stage_fd=stage_fd,
            transaction_nonce=request["transaction_nonce"],
            planned_generation=request["planned_generation"],
            private_unit=request["private_unit"])
    if lease is None:
        return None
    try:
        lease.revalidate()
        if first_arm_servers is not None:
            rendered = tomllib.loads(os.pread(
                lease.config.fd, lease.config.identity[3], 0).decode("utf-8"))
            relay = rendered.get("relay")
            need(type(relay) is dict, "fulltun_relay_source_changed")
            ordinary = [row[1] for row in endpoint._configured_relay_pool(relay)
                        if row[0] == "ordinary"]
            distinct = list(dict.fromkeys(ordinary))
            need(distinct == first_arm_servers,
                 "fulltun_first_arm_relay_changed")
        guard_policy = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
        state_path = Path("/var/lib/aegis-install/client/device-guard.conf")
        state_raw = regular(state_path, 1 << 15)
        state = guard_policy.parse_state(state_raw)
        guard_policy.require_capture_profile(state, request["mode"])
        state_sha = digest(state_raw.rstrip(b"\n"))
        # The immutable producer binding retains its original deny grant.
        # BIND legitimately publishes a new host-verified policy generation.
        # Its caller supplies that current proof separately; neither receipt
        # comparison replaces the held guard/stage/owner authority outside.
        current_sha = (guard_policy_sha256 if current_policy_sha256 is None
                       else current_policy_sha256)
        need(type(current_sha) is str and HEX64.fullmatch(current_sha) is not None,
             "local_current_policy_missing")
        current = record(POLICY)
        need(current["state_sha256"] == digest(state_raw),
             "local_guard_state_changed")
        need(current["policy_sha256"] == current_sha,
             "local_guard_policy_changed")
        manager_path = Path(str(state_path) + ".manager-binding")
        need(not manager_path.is_symlink(), "local_manager_binding_changed")
        manager = (json.loads(regular(manager_path, 4096), object_pairs_hook=unique)
                   if manager_path.exists() else None)
        guard_policy._binding(manager, "manager", state_sha, state["manager"])
        if manager is not None:
            need(manager["boot_id"] == request["boot_id"],
                 "local_manager_boot_changed")
            info = (Path("/sys/fs/cgroup") / manager["path"]).stat(
                follow_symlinks=False)
            need(stat.S_ISDIR(info.st_mode) and info.st_ino ==
                 int(manager["inode"]), "local_manager_cgroup_changed")
        stage = os.fstat(stage_fd)
        return {"stage_dev": stage.st_dev, "stage_ino": stage.st_ino,
                "private_unit": request["private_unit"],
                "transaction_nonce": request["transaction_nonce"],
                "planned_generation": request["planned_generation"],
                "boot_id": request["boot_id"],
                "netns_ino": request["netns_ino"],
                "config_sha256_initial": lease.config_sha256,
                "config_semantic_sha256": lease.config_semantic_sha256,
                "listen_ipv4": lease.listen_ipv4,
                "listen_port": lease.listen_port,
                "dns_port": lease.dns_port,
                "udp_port": lease.udp_port if first_arm is not None else None,
                "profile": "full_wide_tun" if first_arm is not None else
                           "output_only_safe",
                "first_arm_sha256": first_arm,
                "guard_policy_sha256": guard_policy_sha256,
                # Binding markers use the shell helper's newline-stripped
                # state digest. POLICY above separately pins every file byte.
                "guard_state_sha256": state_sha,
                "uplink": state["uplink"],
                "management_ports": [int(port) for port in
                    state["management_ports"].split(",") if port],
                "dhcp4": state["dhcp4"] == "1",
                "manager_binding": manager}
    finally:
        lease.close()


def _local_owner_binding(stage_fd: int, request: dict[str, object],
                         guard_policy_sha256: str, *,
                         current_policy_sha256: str,
                         authenticated_lineage: dict | None = None,
                         phase: str = 'other'
                         ) -> dict | None:
    need(type(current_policy_sha256) is str and
         HEX64.fullmatch(current_policy_sha256) is not None,
         "local_current_policy_missing")
    redirect = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    if not redirect.LOCAL_INTENT.exists():
        need(_local_config_binding(stage_fd, request,
                                   guard_policy_sha256,
                                   current_policy_sha256=current_policy_sha256,
                                   authenticated_lineage=
                                   authenticated_lineage,
                                   phase=phase) is None,
             "local producer intent missing")
        return None
    intent = redirect._scoped_read(redirect.LOCAL_INTENT)
    original = intent.get("binding")
    need(type(original) is dict and
         original.get("private_unit") == request["private_unit"] and
         original.get("guard_policy_sha256") == guard_policy_sha256 and
         (original.get("stage_dev"), original.get("stage_ino")) ==
         (os.fstat(stage_fd).st_dev, os.fstat(stage_fd).st_ino),
         "local_producer_owner_changed")
    fresh = _local_config_binding(stage_fd, request, guard_policy_sha256,
                                  current_policy_sha256=current_policy_sha256,
                                  authenticated_lineage=authenticated_lineage,
                                  phase=phase)
    need(type(fresh) is dict and all(
        fresh[key] == original[key] for key in fresh
        if key != "config_sha256_initial"),
        "local producer configuration changed")
    return original


def _local_retire_after_stop(stage_fd: int, unit: str,
                             original_guard_policy_sha256: str,
                             guard_fd: int) -> dict | None:
    redirect = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    if not redirect.LOCAL_INTENT.exists():
        return None
    intent = redirect._scoped_read(redirect.LOCAL_INTENT)
    binding = intent.get("binding")
    need(type(binding) is dict and binding.get("private_unit") == unit and
         binding.get("guard_policy_sha256") == original_guard_policy_sha256,
         "foreign local stop owner")
    need(binding.get("profile") in ("output_only_safe", "full_wide_tun"),
         "foreign local stop profile")
    request = {"mode": ("full-wide-tun" if binding["profile"] ==
                        "full_wide_tun" else "wide-redirect-safe"),
               "private_unit": unit,
               "transaction_nonce": binding["transaction_nonce"],
               "planned_generation": binding["planned_generation"],
               "boot_id": binding["boot_id"],
               "netns_ino": binding["netns_ino"]}
    need(_stage(stage_fd, request, initial=False) ==
         (binding["stage_dev"], binding["stage_ino"]),
         "local stop stage changed")
    def denied() -> bool:
        state = _policy(request, _held_lock(guard_fd, GUARD_LOCK))
        witness = verified_module(WITNESS, "aegis_auto_native_witness")
        projection, _handles, _counters = _semantic_policy_snapshot()
        return digest(projection) == state["policy_sha256"] and \
            _no_client_grant(projection)
    return redirect.local_retire(
        unit=unit, deny_check=denied,
        stopped_check=lambda: _private_unit_inactive(unit))


def _scoped_owner_binding(stage_fd: int, request: dict[str, object],
                          guard_policy_sha256: str) -> dict | None:
    """Compare fresh sealed config semantics to the original producer owner.

    Accepted format projection may change raw config bytes.  The source
    semantic hash and exact listener/interface remain invariant.
    """
    redirect = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    if not redirect.SCOPED_INTENT.exists():
        fresh = _scoped_config_binding(stage_fd, request, guard_policy_sha256)
        need(fresh is None, "scoped producer intent missing")
        return None
    intent = redirect._scoped_read(redirect.SCOPED_INTENT)
    original = intent.get("binding")
    need(type(original) is dict and
         original.get("private_unit") == request["private_unit"] and
         original.get("guard_policy_sha256") == guard_policy_sha256 and
         original.get("stage_dev") == os.fstat(stage_fd).st_dev and
         original.get("stage_ino") == os.fstat(stage_fd).st_ino,
         "scoped producer owner changed")
    fresh = _scoped_config_binding(stage_fd, request, guard_policy_sha256)
    need(type(fresh) is dict and all(
        fresh[key] == original[key] for key in fresh
        if key != "config_sha256_initial"),
        "scoped producer configuration changed")
    return original


def _scoped_retire_after_stop(stage_fd: int, unit: str,
                              original_guard_policy_sha256: str,
                              guard_fd: int) -> dict | None:
    """Remove only the original scoped table after exact deny and PID1 stop."""
    redirect = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    if not redirect.SCOPED_INTENT.exists():
        return None
    intent = redirect._scoped_read(redirect.SCOPED_INTENT)
    binding = intent.get("binding")
    need(type(binding) is dict and binding.get("private_unit") == unit and
         binding.get("guard_policy_sha256") ==
         original_guard_policy_sha256,
         "foreign scoped stop owner")
    request = {"mode": "wide-redirect-safe", "private_unit": unit,
               "transaction_nonce": binding["transaction_nonce"],
               "planned_generation": binding["planned_generation"],
               "boot_id": binding["boot_id"],
               "netns_ino": binding["netns_ino"]}
    # An inverse must remain possible after a failed config projection.  The
    # original protected intent, held stage and completed StopUnit are its
    # authority; positive endpoint admission may rightly reject that stage.
    need(_stage(stage_fd, request, initial=False) ==
         (binding["stage_dev"], binding["stage_ino"]),
         "scoped stop stage changed")

    def denied() -> bool:
        guard_id = _held_lock(guard_fd, GUARD_LOCK)
        state = _policy(request, guard_id)
        witness = verified_module(WITNESS, "aegis_auto_native_witness")
        projection, _handles, _counters = _semantic_policy_snapshot()
        return (digest(projection) == state["policy_sha256"] and
                _no_client_grant(projection))

    return redirect.scoped_retire(
        unit=unit, deny_check=denied,
        stopped_check=lambda: _private_unit_inactive(unit))


def _launch_runtime_identity(header: dict[str, object], mode: str) -> tuple[int, int, str]:
    """Use the sealed new runtime identity, never the old config owner's UID."""
    binding = header.get("runtime_binding")
    need(type(binding) is dict and type(binding.get("identity")) is dict and
         header.get("mode") == mode, "launch_runtime_binding_missing")
    identity = binding["identity"]
    need(set(identity) == {"user", "uid", "gid"} and
         type(identity["uid"]) is int and type(identity["gid"]) is int and
         identity["uid"] >= 0 and identity["gid"] >= 0,
         "launch_runtime_identity_invalid")
    if mode == "full-wide-tun":
        need(identity == {"user": "root", "uid": 0, "gid": 0} and
             binding.get("policy") == "root",
             "launch_fulltun_runtime_identity_changed")
    elif mode == "wide-redirect-safe":
        need(identity["user"] in ("aegis", "aegis-svc") and
             1 <= identity["uid"] < 1000 and
             1 <= identity["gid"] < 1000 and
             binding.get("policy") == "dedicated_bind",
             "launch_redirect_runtime_identity_changed")
    else:
        need(mode == "socks-only" and
             ((identity == {"user": "root", "uid": 0, "gid": 0} and
               binding.get("policy") == "root") or
              (identity["user"] in ("aegis", "aegis-svc") and
               1 <= identity["uid"] < 1000 and
               1 <= identity["gid"] < 1000 and
               binding.get("policy") in ("dedicated_none", "dedicated_bind"))),
             "launch_socks_runtime_identity_changed")
    return identity["uid"], identity["gid"], binding["policy"]


def _launch_runtime_uid(header: dict[str, object], mode: str) -> int:
    return _launch_runtime_identity(header, mode)[0]


def _stage_leaf(fd: int, name: str) -> bytes:
    need(name in ("activation-owner-may-send-v3.json",
                  "activation-owner-claim-v3.json",
                  "activation-owner-terminal-handoff.json",
                  "activation-owner-postterminal-stop.json"),
         "unadmitted_stage_leaf")
    child = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                    os.O_NONBLOCK, dir_fd=fd)
    try:
        value = os.fstat(child)
        need(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and
             value.st_nlink == 1 and stat.S_IMODE(value.st_mode) == 0o600 and
             0 < value.st_size <= 65536, "untrusted_stage_leaf")
        raw = os.read(child, 65537)
        need(len(raw) == value.st_size, "stage_leaf_changed")
        return raw
    finally:
        os.close(child)


def _protected_stage_receipt(fd: int, name: str) -> bytes:
    """Read one fixed receipt beneath the held stage root without following links."""
    need(name in ("receipts/activation-owner/terminal.json",
                  "receipts/activation-owner/marker-archive.json",
                  "receipts/activation-owner/postterminal-compensated.json",
                  "accepted/install-receipt/installed-generation.json",
                  "receipts/activation-owner/stop-submitted.json",
                  "receipts/activation-owner/stop-completed.json",
                  "receipts/activation-owner/finalized-stop-terminal.json",
                  "receipts/activation-owner/submitted.json",
                  "receipts/activation-owner/completed.json",
                  "receipts/activation-owner/launch-consumed.json",
                  "receipts/config-projection/projection-receipt.json",
                  "receipts/config-config/publication-receipt.json",
                  "input/payload/metadata/auto-guard-first-arm.json",
                  "activation-owner-deactivation-intent-v1.json") or
         re.fullmatch(r"records/active-service/[0-9a-f]{32}\.json", name) is not None,
         "unadmitted_stop_receipt")
    current = os.dup(fd)
    parents: list[tuple[str, tuple[int, int, int, int]]] = []
    try:
        parts = name.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
            directory = os.fstat(current)
            need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and
                 directory.st_mode & 0o022 == 0, "untrusted_stop_receipt_parent")
            parents.append((part, (directory.st_dev, directory.st_ino,
                                   directory.st_uid, directory.st_mode)))
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC |
                       os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        try:
            info = os.fstat(leaf)
            limit = (4 << 20 if name in (
                "receipts/config-projection/projection-receipt.json",
                "receipts/config-config/publication-receipt.json") else 65536)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                 info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and
                 0 < info.st_size <= limit, "untrusted_stop_receipt")
            chunks: list[bytes] = []
            total = 0
            while total < info.st_size:
                part = os.read(leaf, min(1 << 20, info.st_size - total))
                need(part, "stop_receipt_changed")
                chunks.append(part)
                total += len(part)
            raw = b"".join(chunks)
            after = os.fstat(leaf)
            named = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
            stable = lambda item: (item.st_dev, item.st_ino, item.st_uid,
                                   item.st_mode, item.st_nlink, item.st_size,
                                   item.st_mtime_ns, item.st_ctime_ns)
            need(len(raw) == info.st_size and
                 stable(info) == stable(after) == stable(named),
                 "stop_receipt_changed")
            again = os.dup(fd)
            try:
                for part, expected in parents:
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                      os.O_CLOEXEC | os.O_NOFOLLOW,
                                      dir_fd=again)
                    os.close(again)
                    again = next_fd
                    observed = os.fstat(again)
                    need((observed.st_dev, observed.st_ino,
                          observed.st_uid, observed.st_mode) == expected,
                         "stop_receipt_parent_changed")
            finally:
                os.close(again)
            return raw
        finally:
            os.close(leaf)
    finally:
        os.close(current)


def _final_render_recipe_digest(stage_fd: int) -> str:
    parent = os.open("accepted", os.O_RDONLY | os.O_DIRECTORY |
                     os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=stage_fd)
    try:
        parent_info = os.fstat(parent)
        parent_named = os.stat("accepted", dir_fd=stage_fd,
                               follow_symlinks=False)
        need(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == 0 and
             parent_info.st_mode & 0o022 == 0 and
             (parent_info.st_dev, parent_info.st_ino) ==
             (parent_named.st_dev, parent_named.st_ino),
             "launch_recipe_parent_changed")
        child = os.open("final-render-recipe.json", os.O_RDONLY |
                        os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=parent)
        try:
            before = os.fstat(child)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
                 before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
                 0 < before.st_size <= 96 * 1024 * 1024,
                 "launch_recipe_identity_changed")
            h = hashlib.sha256()
            total = 0
            while part := os.read(child, 1 << 20):
                total += len(part)
                need(total <= before.st_size, "launch_recipe_size_changed")
                h.update(part)
            named = os.stat("final-render-recipe.json", dir_fd=parent,
                            follow_symlinks=False)
            after = os.fstat(child)
            parent_after = os.stat("accepted", dir_fd=stage_fd,
                                   follow_symlinks=False)
            need(total == before.st_size and
                 (before.st_dev, before.st_ino, before.st_uid,
                  before.st_mode, before.st_size, before.st_mtime_ns,
                  before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_uid,
                  after.st_mode, after.st_size, after.st_mtime_ns,
                  after.st_ctime_ns) and
                 (after.st_dev, after.st_ino) == (named.st_dev, named.st_ino) and
                 (parent_info.st_dev, parent_info.st_ino) ==
                 (parent_after.st_dev, parent_after.st_ino),
                 "launch_recipe_identity_changed")
            return h.hexdigest()
        finally:
            os.close(child)
    finally:
        os.close(parent)


def _claimed_private_unit(stage_fd: int, original: dict[str, object],
                          grant: dict[str, object], unit: str,
                          *, initial: bool = True,
                          marker_bytes: tuple[bytes, bytes] | None = None) -> None:
    need(PRIVATE_UNIT.fullmatch(unit) is not None, "invalid_private_unit")
    stage_id = _stage(stage_fd, original, initial=initial)
    may_raw = (marker_bytes[0] if marker_bytes is not None else
               _stage_leaf(stage_fd, "activation-owner-may-send-v3.json"))
    may = json.loads(may_raw, object_pairs_hook=unique)
    need(type(may) is dict and set(may) == {"schema", "commitments"} and
         may["schema"] == 3 and type(may["commitments"]) is dict,
         "private_unit_owner_marker_invalid")
    values = may["commitments"]
    binding = values.get("binding")
    native = values.get("native_guard")
    need(type(binding) is dict and type(native) is dict and
         values.get("private_unit") == unit and
         values.get("boot_id") == original["boot_id"] and
         values.get("mode") == original["mode"] and
         binding.get("transaction_nonce") == original["transaction_nonce"] and
         binding.get("planned_generation") == original["planned_generation"] and
         binding.get("header_sha256") == original["header_sha256"] and
         binding.get("stage") == list(stage_id) and
         native.get("guardian_pid") == grant["pid"] and
         native.get("guardian_nonce") == grant["nonce"] and
         native.get("guardian_receipt_sha256") ==
         grant["native_receipt_sha256"] and
         native.get("policy_sha256") == grant["policy_sha256"],
         "private_unit_not_bound_to_held_owner")
    claim = json.loads((marker_bytes[1] if marker_bytes is not None else
                        _stage_leaf(stage_fd,
                                    "activation-owner-claim-v3.json")),
                       object_pairs_hook=unique)
    need(type(claim) is dict and
         claim == {"schema": 3, "may_send_sha256": digest(may_raw),
                   "nonce": original["transaction_nonce"],
                   "stage": list(stage_id)},
         "private_unit_one_use_claim_missing")


def _claimed_launch_unit(stage_fd: int, request: dict[str, object],
                         ticket_sha256: str,
                         native_guard: dict[str, object] | None,
                         *, initial: bool = True,
                         marker_bytes: tuple[bytes, bytes] | None = None) -> None:
    stage_id = _stage(stage_fd, request, initial=initial)
    may_raw = (marker_bytes[0] if marker_bytes is not None else
               _stage_leaf(stage_fd, "activation-owner-may-send-v3.json"))
    may = json.loads(may_raw, object_pairs_hook=unique)
    need(type(may) is dict and set(may) == {"schema", "commitments"} and
         may["schema"] == 3 and type(may["commitments"]) is dict,
         "launch_owner_marker_invalid")
    commitments = may["commitments"]
    binding = commitments.get("binding")
    need(type(binding) is dict and
         commitments.get("private_unit") == request["private_unit"] and
         commitments.get("fixed_unit") == "aegis-client.service" and
         commitments.get("mode") == request["mode"] and
         commitments.get("boot_id") == request["boot_id"] and
         commitments.get("launch_ticket_sha256") == ticket_sha256 and
         commitments.get("native_guard") == native_guard and
         binding.get("transaction_nonce") == request["transaction_nonce"] and
         binding.get("planned_generation") == request["planned_generation"] and
         binding.get("header_sha256") == request["header_sha256"] and
         binding.get("stage") == list(stage_id),
         "launch_ticket_not_bound_to_owner")
    claim = json.loads((marker_bytes[1] if marker_bytes is not None else
                        _stage_leaf(stage_fd,
                                    "activation-owner-claim-v3.json")),
                       object_pairs_hook=unique)
    need(claim == {"schema": 3, "may_send_sha256": digest(may_raw),
                   "nonce": request["transaction_nonce"],
                   "stage": list(stage_id)},
         "launch_one_use_claim_missing")


def _launch_projection_successor(stage_fd: int, initial: dict[str, object],
                                 request: dict[str, object],
                                 ticket_sha256: str,
                                 native_guard: dict[str, object] | None,
                                 identity: object,
                                 guardian_invocation_id: str,
                                 capture_state: dict[str, object] | None,
                                 *, marker_bytes: tuple[bytes, bytes] | None = None,
                                 final_header: dict[str, object] | None = None) -> None:
    """Admit only the retained owner's sealed Metadata→Finalized projection."""
    stage_id = _stage(stage_fd, request, initial=False)
    _claimed_launch_unit(stage_fd, request, ticket_sha256, native_guard,
                         initial=False, marker_bytes=marker_bytes)
    final = (final_header if final_header is not None else
             json.loads(_protected_stage_receipt_for_header(stage_fd),
                        object_pairs_hook=unique))
    need(type(initial) is dict and type(final) is dict and
         initial.get("phase") == "metadata" and final.get("phase") == "finalized" and
         initial.get("mode") == request["mode"] and
         final.get("mode") == request["mode"] and
         initial.get("pending") is None and final.get("pending") is None and
         initial.get("unit_pending") is None and final.get("unit_pending") is None and
         initial.get("render_recipe") == "accepted/render-recipe.json" and
         final.get("render_recipe") == "accepted/final-render-recipe.json" and
         type(initial.get("leaves")) is dict and
         type(final.get("leaves")) is dict and
         type(initial.get("current_records")) is dict and
         type(final.get("current_records")) is dict and
         type(initial.get("active_records")) is dict and
         type(final.get("active_records")) is dict,
         "launch_projection_header_not_owned")
    allowed = {"phase", "render_recipe", "leaves"}
    wide = request["mode"] != "socks-only"
    if wide:
        allowed |= {"current_records", "active_records"}
    expected_base = dict(initial)
    if wide:
        _launch_capture_state(initial, request, identity, capture_state)
        expected_base["capture_started"] = True
    need({key: value for key, value in expected_base.items() if key not in allowed} ==
         {key: value for key, value in final.items() if key not in allowed} and
         set(initial) == set(final) and
         (not wide or (initial.get("capture_started") is False and
                       final.get("capture_started") is True)),
         "launch_projection_header_delta_invalid")
    leaves = final["leaves"]
    added = set(leaves) - set(initial["leaves"])
    active = [name for name in added if
              re.fullmatch(r"records/active-service/[0-9a-f]{32}\.json", name)]
    need(len(active) == 1 and
         added == {active[0], "accepted/final-render-recipe.json"} and
         all(leaves.get(name) == expected for name, expected in
             initial["leaves"].items()),
         "launch_projection_leaves_invalid")
    for name in added:
        actual = (_final_render_recipe_digest(stage_fd) if
                  name == "accepted/final-render-recipe.json" else
                  digest(_protected_stage_receipt(stage_fd, name)))
        need(leaves[name] == actual,
             "launch_projection_leaf_changed")
    evidence = json.loads(_protected_stage_receipt(stage_fd, active[0]),
                          object_pairs_hook=unique)
    may = json.loads((marker_bytes[0] if marker_bytes is not None else
                      _stage_leaf(stage_fd, "activation-owner-may-send-v3.json")),
                     object_pairs_hook=unique)
    unit = evidence.get("unit") if type(evidence) is dict else None
    need(type(may) is dict and type(may.get("commitments")) is dict and
         type(unit) is dict and evidence.get("schema") == 2 and
         evidence.get("unit_name") == request["private_unit"] and
         evidence.get("nonce") == request["transaction_nonce"] and
         evidence.get("input_generation") == initial.get("input_generation") and
         evidence.get("planned_generation") == request["planned_generation"] and
         evidence.get("policy_generation") ==
         may["commitments"].get("policy_generation") and
         evidence.get("installed_generation") ==
         initial["leaves"].get("accepted/install-receipt/installed-generation.json") and
         unit.get("pid") == identity.pid and
         unit.get("uid") == identity.uid and
         unit.get("gid") == initial["runtime_binding"]["identity"]["gid"] and
         unit.get("invocation") == identity.invocation and
         unit.get("cgroup") == identity.cgroup and
         evidence.get("ticks") == identity.start_tick,
         "launch_projection_active_identity_changed")
    submitted_raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/submitted.json")
    completed_raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/completed.json")
    consumed_raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/launch-consumed.json")
    submitted = json.loads(submitted_raw, object_pairs_hook=unique)
    completed = json.loads(completed_raw, object_pairs_hook=unique)
    consumed = json.loads(consumed_raw, object_pairs_hook=unique)
    may_raw = (marker_bytes[0] if marker_bytes is not None else
               _stage_leaf(stage_fd, "activation-owner-may-send-v3.json"))
    claim_raw = (marker_bytes[1] if marker_bytes is not None else
                 _stage_leaf(stage_fd, "activation-owner-claim-v3.json"))
    need(type(submitted) is dict and type(completed) is dict and
         type(consumed) is dict and
         submitted.get("schema") == completed.get("schema") ==
         consumed.get("schema") == 1 and
         submitted.get("kind") == "owned-start-submitted" and
         completed.get("kind") == "owned-start-completed" and
         consumed.get("kind") == "owned-launch-consumed" and
         submitted.get("may_send_sha256") == digest(may_raw) and
         submitted.get("claim_sha256") == digest(claim_raw) and
         submitted.get("pid1_socket") ==
         may["commitments"].get("pid1_socket") and
         submitted.get("pid1_netns") ==
         may["commitments"].get("pid1_netns") and
         submitted.get("unit") == completed.get("unit") ==
         consumed.get("private_unit") == request["private_unit"] and
         completed.get("submitted_sha256") == digest(submitted_raw) and
         completed.get("job_id") == submitted.get("job_id") and
         completed.get("job_path") == submitted.get("job_path") and
         consumed.get("completed_sha256") == digest(completed_raw) and
         consumed.get("ticket_sha256") == ticket_sha256 and
         consumed.get("invocation_id") == completed.get("invocation_id") ==
         identity.invocation and
         consumed.get("main_pid") == identity.pid and
         consumed.get("main_start_tick") == identity.start_tick and
         consumed.get("guardian_pid") == os.getpid() and
         consumed.get("guardian_invocation_id") == guardian_invocation_id and
         submitted.get("boot_id") == request["boot_id"],
         "launch_projection_one_use_chain_changed")
    if wide:
        projected_leaf = "receipts/config-projection/projection-receipt.json"
        old_path = initial["active_records"].get("config")
        prior = initial["current_records"].get(old_path)
        current = final["current_records"]
        active_records = dict(initial["active_records"])
        active_records["config"] = projected_leaf
        need(type(prior) is dict and type(old_path) is str and
             type(current.get(projected_leaf)) is dict and
             current == {**initial["current_records"],
                         projected_leaf: current[projected_leaf]} and
             final["active_records"] == active_records and
             prior.get("role") == "config" and prior.get("phase") == "config",
             "launch_projection_record_delta_invalid")
        seal = current[projected_leaf]
        receipts_fd = os.open("receipts", os.O_RDONLY | os.O_DIRECTORY |
                              os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=stage_fd)
        try:
            projection_fd = os.open("config-projection",
                                    os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_CLOEXEC | os.O_NOFOLLOW,
                                    dir_fd=receipts_fd)
            try:
                projection_dir = os.fstat(projection_fd)
                need(stat.S_ISDIR(projection_dir.st_mode) and
                     projection_dir.st_uid == 0 and
                     projection_dir.st_mode & 0o022 == 0,
                     "launch_projection_directory_changed")
                projection_id = (projection_dir.st_dev, projection_dir.st_ino)
            finally:
                os.close(projection_fd)
        finally:
            os.close(receipts_fd)
        raw = _protected_stage_receipt(stage_fd, projected_leaf)
        original_raw = _protected_stage_receipt(stage_fd, old_path)
        projected = json.loads(raw, object_pairs_hook=unique)
        original = json.loads(original_raw, object_pairs_hook=unique)
        binding = projected.get("binding") if type(projected) is dict else None
        chain = hashlib.sha256(b"aegis-auto-publication-chain-v1\0")
        for field in (request["transaction_nonce"],
                      initial.get("input_generation"),
                      request["planned_generation"], "config", "projection",
                      prior.get("sha256")):
            need(type(field) is str, "launch_projection_chain_invalid")
            encoded = field.encode("utf-8")
            chain.update(len(encoded).to_bytes(8, "big"))
            chain.update(encoded)
        need(seal.get("role") == "config" and seal.get("phase") == "projection" and
             seal.get("predecessor_sha256") == prior.get("sha256") ==
             digest(original_raw) and seal.get("sha256") == digest(raw) and
             seal.get("chain_sha256") == chain.hexdigest() and
             seal.get("stage_dev") == projection_id[0] and
             seal.get("stage_ino") == projection_id[1] and
             type(binding) is dict and
             binding.get("transaction_stage") ==
             {"dev": projection_id[0], "ino": projection_id[1]} and
             binding.get("transaction_nonce") == request["transaction_nonce"] and
             binding.get("phase") == "projection" and
             binding.get("chain_sha256") == seal.get("chain_sha256") and
             projected.get("kind") == "projection" and
             original.get("kind") == "publication" and
             projected.get("base_record_sha256") == prior["sha256"] and
             projected.get("intent") == original.get("intent") and
             projected.get("base_current") == original.get("current"),
             "launch_projection_lineage_changed")
    else:
        need(final["current_records"] == initial["current_records"] and
             final["active_records"] == initial["active_records"],
             "launch_projection_record_delta_invalid")


def _launch_capture_state(initial: dict[str, object], request: dict[str, object],
                          identity: object,
                          capture_state: dict[str, object] | None) -> None:
    need(request["mode"] != "socks-only" and
         type(capture_state) is dict and
         capture_state.get("unit") == request["private_unit"] and
         capture_state.get("nonce") == request["transaction_nonce"] and
         capture_state.get("invocation") == identity.invocation and
         type(capture_state.get("sha256")) is str and
         HEX64.fullmatch(capture_state["sha256"]) is not None and
         initial.get("capture_started") is False,
         "launch_capture_successor_unproved")


def _launch_captured_metadata_successor(stage_fd: int,
                                        initial: dict[str, object],
                                        request: dict[str, object],
                                        ticket_sha256: str,
                                        native_guard: dict[str, object] | None,
                                        identity: object,
                                        capture_state: dict[str, object] | None) -> None:
    _claimed_launch_unit(stage_fd, request, ticket_sha256, native_guard,
                         initial=False)
    _launch_capture_state(initial, request, identity, capture_state)
    current = json.loads(_protected_stage_receipt_for_header(stage_fd),
                         object_pairs_hook=unique)
    expected = dict(initial, capture_started=True)
    need(current == expected and current.get("phase") == "metadata",
         "launch_capture_header_delta_invalid")


def _capture_stage_successor(stage_fd: int, initial: dict[str, object],
                             original: dict[str, object],
                             grant: dict[str, object],
                             previous: dict[str, object]) -> None:
    """Revalidate capture after only the source-owned Header transitions."""
    raw_header = _protected_stage_receipt_for_header(stage_fd)
    if digest(raw_header) == original["header_sha256"]:
        _claimed_private_unit(stage_fd, original, grant,
                              original["private_unit"])
        need(json.loads(raw_header, object_pairs_hook=unique) == initial,
             "capture_initial_header_changed")
        return
    _claimed_private_unit(stage_fd, original, grant,
                          original["private_unit"], initial=False)
    current = json.loads(raw_header,
                         object_pairs_hook=unique)
    consumed = json.loads(_protected_stage_receipt(
        stage_fd, "receipts/activation-owner/launch-consumed.json"),
        object_pairs_hook=unique)
    need(type(consumed) is dict and
         consumed.get("kind") == "owned-launch-consumed" and
         consumed.get("private_unit") == original["private_unit"] and
         consumed.get("invocation_id") == previous["proof"]["invocation_id"] and
         consumed.get("guardian_invocation_id") ==
         grant["guardian_invocation_id"] and
         type(consumed.get("main_pid")) is int and consumed["main_pid"] > 1 and
         consumed.get("ticket_sha256") == json.loads(_stage_leaf(
             stage_fd, "activation-owner-may-send-v3.json"),
             object_pairs_hook=unique)["commitments"]["launch_ticket_sha256"],
         "capture_owner_consumption_changed")
    unit = original["private_unit"]
    pid = _private_unit_main_pid(unit)
    need(pid == consumed["main_pid"], "capture_main_pid_changed")
    pidfd = os.pidfd_open(pid, 0)
    try:
        need(_pid_alive(pidfd), "capture_main_pid_changed")
        facts = _launch_unit_identity(unit, pid)
        launch = verified_module(LAUNCH_SOURCE, "aegis_auto_launch")
        identity = SimpleNamespace(
            pid=pid, uid=_launch_runtime_uid(initial, original["mode"]),
            start_tick=launch._start_tick(pid),
            invocation=facts["InvocationID"], cgroup=facts["ControlGroup"])
        need(identity.invocation == consumed["invocation_id"] and
             identity.start_tick == consumed.get("main_start_tick") and
             _pid_alive(pidfd), "capture_main_identity_changed")
        capture_state = {"unit": unit,
                         "nonce": original["transaction_nonce"],
                         "invocation": identity.invocation,
                         "sha256": previous["sha256"]}
        guard = {"guardian_pid": grant["pid"],
                 "guardian_nonce": grant["nonce"],
                 "guardian_receipt_sha256": grant["native_receipt_sha256"],
                 "policy_sha256": grant["policy_sha256"]}
        if current.get("phase") == "metadata":
            _launch_captured_metadata_successor(
                stage_fd, initial, original,
                consumed["ticket_sha256"], guard, identity, capture_state)
        else:
            _launch_projection_successor(
                stage_fd, initial, original,
                consumed["ticket_sha256"], guard, identity,
                consumed["guardian_invocation_id"], capture_state)
        need(_pid_alive(pidfd) and _launch_unit_identity(unit, pid) == facts,
             "capture_main_identity_changed")
    finally:
        os.close(pidfd)


def _inverse_owner_markers(stage_fd: int, header: dict[str, object],
                           original: dict[str, object],
                           grant: dict[str, object]
                           ) -> tuple[tuple[bytes, bytes], dict[str, object] | None]:
    """Recover exact retired marker bytes only from a sealed terminal archive."""
    stage = os.fstat(stage_fd)
    names = ("activation-owner-may-send-v3.json",
             "activation-owner-claim-v3.json")
    live: list[bytes | None] = []
    for name in names:
        try:
            live.append(_stage_leaf(stage_fd, name))
        except FileNotFoundError:
            live.append(None)
    leaves = header.get("leaves")
    if (all(value is not None for value in live) and
            (type(leaves) is not dict or
             "receipts/activation-owner/terminal.json" not in leaves)):
        return (live[0], live[1]), None
    terminal_raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/terminal.json")
    archive_raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/marker-archive.json")
    terminal = json.loads(terminal_raw, object_pairs_hook=unique)
    archive = json.loads(archive_raw, object_pairs_hook=unique)
    intent_raw = _stage_leaf(stage_fd, "activation-owner-postterminal-stop.json")
    intent = json.loads(intent_raw, object_pairs_hook=unique)
    need(type(leaves) is dict and type(terminal) is dict and
         type(archive) is dict and type(intent) is dict and
         header.get("phase") == "finalized" and
         leaves.get("receipts/activation-owner/terminal.json") ==
         digest(terminal_raw) and
         leaves.get("receipts/activation-owner/marker-archive.json") ==
         digest(archive_raw) and
         terminal.get("schema") == archive.get("schema") == 1 and
         terminal.get("outcome") == "finalized" and
         terminal.get("stage") == [stage.st_dev, stage.st_ino] and
         terminal.get("private_unit") == original["private_unit"] and
         terminal.get("native_guard") ==
         {"guardian_pid": grant["pid"],
          "guardian_nonce": grant["nonce"],
          "guardian_receipt_sha256": grant["native_receipt_sha256"],
          "policy_sha256": grant["policy_sha256"]} and
         terminal.get("marker_archive_sha256") == digest(archive_raw) and
         set(archive) == {"schema", "may_send_hex", "claim_hex",
                          "may_send_sha256", "claim_sha256"},
         "inverse_marker_archive_not_sealed")
    try:
        may_raw = bytes.fromhex(archive["may_send_hex"])
        claim_raw = bytes.fromhex(archive["claim_hex"])
    except (TypeError, ValueError, KeyError) as error:
        raise Refused("inverse_marker_archive_invalid") from error
    need(archive["may_send_hex"] == may_raw.hex() and
         archive["claim_hex"] == claim_raw.hex() and
         digest(may_raw) == archive["may_send_sha256"] ==
         terminal.get("may_send_sha256") and
         digest(claim_raw) == archive["claim_sha256"] ==
         terminal.get("claim_sha256") and
         all(value is None or value == expected for value, expected in
             zip(live, (may_raw, claim_raw), strict=True)) and
         intent == {"schema": 1, "kind": "postterminal-stop-intent",
                    "stage": [stage.st_dev, stage.st_ino],
                    "terminal_sha256": digest(terminal_raw),
                    "marker_archive_sha256": digest(archive_raw),
                    "may_send_sha256": digest(may_raw),
                    "claim_sha256": digest(claim_raw),
                    "private_unit": original["private_unit"]},
         "inverse_marker_archive_changed")
    return (may_raw, claim_raw), terminal


def _inverse_stop_chain(stage_fd: int, original: dict[str, object],
                        effect: dict[str, object],
                        markers: tuple[bytes, bytes]) -> dict[str, object]:
    submitted_raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/submitted.json")
    start_raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/completed.json")
    stop_raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/stop-submitted.json")
    done_raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/stop-completed.json")
    submitted = json.loads(submitted_raw, object_pairs_hook=unique)
    start = json.loads(start_raw, object_pairs_hook=unique)
    stop = json.loads(stop_raw, object_pairs_hook=unique)
    done = json.loads(done_raw, object_pairs_hook=unique)
    may = json.loads(markers[0], object_pairs_hook=unique)
    need(type(submitted) is dict and type(start) is dict and
         type(stop) is dict and type(done) is dict and
         type(may) is dict and type(may.get("commitments")) is dict and
         submitted.get("schema") == start.get("schema") ==
         stop.get("schema") == done.get("schema") == 1 and
         submitted.get("kind") == "owned-start-submitted" and
         start.get("kind") == "owned-start-completed" and
         stop.get("kind") == "owned-stop-submitted" and
         done.get("kind") == "owned-stop-completed" and
         submitted.get("unit") == start.get("unit") ==
         stop.get("unit") == done.get("unit") ==
         original["private_unit"] and
         submitted.get("may_send_sha256") == digest(markers[0]) and
         submitted.get("claim_sha256") == digest(markers[1]) and
         submitted.get("boot_id") == original["boot_id"] and
         submitted.get("pid1_socket") ==
         may["commitments"].get("pid1_socket") and
         submitted.get("pid1_netns") ==
         may["commitments"].get("pid1_netns") and
         start.get("submitted_sha256") == digest(submitted_raw) and
         start.get("job_id") == submitted.get("job_id") and
         start.get("job_path") == submitted.get("job_path") and
         start.get("invocation_id") == done.get("prior_invocation_id") ==
         effect["prior_invocation_id"] and
         stop.get("completed_start_sha256") == digest(start_raw) and
         done.get("stop_submitted_sha256") == digest(stop_raw) and
         stop.get("job_id") == done.get("job_id") == effect["stop_job_id"] and
         stop.get("job_path") == done.get("job_path") == effect["stop_job_path"] and
         stop.get("boot_id") == original["boot_id"] and
         stop.get("pid1_socket") == may["commitments"].get("pid1_socket") and
         stop.get("pid1_netns") == may["commitments"].get("pid1_netns"),
         "inverse_owned_stop_chain_changed")
    return start


def _inverse_stage_successor(stage_fd: int, original: dict[str, object],
                             grant: dict[str, object],
                             effect: dict[str, object]) -> None:
    """Authenticate the original owner and completed stop before inverse.

    A failed projection may leave Metadata, a pending projection, or Finalized
    Header.  Those are never positive activation evidence.  The inverse is
    authorized by the original held owner and the exact completed StopUnit,
    then independently proves kernel deny and capture teardown.
    """
    _stage(stage_fd, original, initial=False)
    header = json.loads(_protected_stage_receipt_for_header(stage_fd),
                        object_pairs_hook=unique)
    need(type(header) is dict and
         header.get("transaction_nonce") == original["transaction_nonce"] and
         header.get("planned_generation") == original["planned_generation"] and
         header.get("mode") == original["mode"],
         "inverse_stage_header_invalid")
    markers, _terminal = _inverse_owner_markers(stage_fd, header,
                                                 original, grant)
    _claimed_private_unit(stage_fd, original, grant,
                          original["private_unit"], initial=False,
                          marker_bytes=markers)
    _inverse_stop_chain(stage_fd, original, effect, markers)


def _pid1_query_kind(raw: bytes) -> str:
    value = raw.lower()
    for kind, terms in (
            ('unit_missing', (b'could not be found', b'not loaded', b'no such unit', b'not found')),
            ('permission', (b'permission denied', b'access denied')),
            ('resource', (b'too many', b'no buffer space', b'cannot allocate memory', b'resource temporarily')),
            ('bus', (b'connection reset', b'connection refused', b'failed to connect', b'broken pipe', b'transport endpoint'))):
        if any(term in value for term in terms):return kind
    return 'other'


def _launch_unit_identity(unit: str, pid: int, *, pending_stop: bool = False
                          ) -> dict[str, str]:
    need(PRIVATE_UNIT.fullmatch(unit) is not None and pid > 1,
         "invalid_launch_unit")
    keys = ("MainPID", "ControlPID", "ControlGroup", "InvocationID",
            "ActiveState", "SubState")
    command = ["/usr/bin/systemctl", "show", unit]
    for key in keys:
        command.extend(("-p", key))
    command.append("--no-pager")
    # A failed read is not evidence that the original process-held lease
    # disappeared. Retry only this fixed read, within its original total2s
    # budget. Identity/parser failures below are never retried or admitted.
    deadline = time.monotonic() + 2.0
    result = None
    for attempt in range(3):
        remaining = deadline - time.monotonic()
        if remaining <= 0:break
        result = subprocess.run(command, capture_output=True, check=False,
            timeout=remaining, env={"PATH": "/usr/sbin:/usr/bin",
                                    "LANG": "C", "LC_ALL": "C"})
        need(len(result.stdout) <= 4096 and len(result.stderr) <= 4096,
             "launch_pid1_unavailable")
        if result.returncode == 0:break
        kind = _pid1_query_kind(result.stderr)
        print(json.dumps({"event":"pid1_query_unavailable","source":"guardian",
            "attempt":attempt+1,"exit":result.returncode,
            "stdout_bytes":len(result.stdout),"stderr_bytes":len(result.stderr),
            "kind":kind,
            "monotonic_ns":time.monotonic_ns()},sort_keys=True),file=sys.stderr,flush=True)
        # Only transient local PID1 bus/resource errors may be retried. A
        # missing unit, permission failure or unknown stderr refuses now.
        if kind not in ("bus", "resource") or attempt == 2:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.025, remaining))
    need(result is not None and result.returncode == 0,
         "launch_pid1_unavailable")
    facts: dict[str, str] = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        need(separator == "=" and key not in facts,
             "launch_pid1_facts_invalid")
        facts[key] = value
    expected_cgroup = "/system.slice/" + unit
    need(set(facts) == set(keys) and facts["MainPID"] == str(pid) and
         ((not pending_stop and facts["ControlPID"] == "0" and
           facts["ActiveState"] in ("activating", "active")) or
          (pending_stop and facts["ControlPID"].isascii() and
           facts["ControlPID"].isdecimal() and
           str(int(facts["ControlPID"])) == facts["ControlPID"] and
           facts["ActiveState"] == "deactivating" and
           facts["SubState"] == "stop")) and
         facts["ControlGroup"] == expected_cgroup and
         HEX32.fullmatch(facts["InvocationID"]) is not None and
         Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
         "0::" + expected_cgroup + "\n", "launch_pid1_identity_changed")
    return facts


def _pending_owned_stop(unit: str, held: object, main_sha: str) -> bool:
    """A live Main may await its exact PID1 ExecStop before deny is proven.

    This admits no traffic or Stop authority. The caller keeps one absolute
    bounded wait; channel/identity loss and every unknown transition refuse.
    True means the pinned typed ControlPID has exec'd the installed helper;
    False also covers its bounded, PID1-owned systemd-executor pre-exec window.
    """
    need(not (INSTALL.parent / "foreign-policy-drift.json").exists(),
         "foreign_policy_drift")
    held.revalidate_process()
    identity = held.identity
    need(identity.unit == unit, "pending_stop_unit_changed")
    before = _launch_unit_identity(unit, identity.pid, pending_stop=True)
    need(before["InvocationID"] == identity.invocation and
         before["ControlGroup"] == identity.cgroup,
         "pending_stop_invocation_changed")
    # ControlPID can be published at any read boundary. Only the one-way
    # 0 -> authenticated helper transition may replace our first snapshot.
    # No retry accepts a different Main, invocation, cgroup or helper PID.
    for _ in range(2):
        control = int(before["ControlPID"])
        descriptor = None
        pre_exec = False
        try:
            if control:
                need(control > 1, "pending_stop_control_invalid")
                descriptor = os.pidfd_open(control, 0)
                need(_pid_alive(descriptor), "pending_stop_control_exited")
                executor = Path("/usr/lib/systemd/systemd-executor")
                running = Path(f"/proc/{control}/exe").stat()
                try:
                    trusted = executor.stat(follow_symlinks=False)
                except FileNotFoundError:
                    # Older systemd may exec the hook directly. It can still
                    # pass the unchanged exact installed-binary check below.
                    trusted = None
                pre_exec = trusted is not None and (
                    running.st_dev, running.st_ino) == (
                    trusted.st_dev, trusted.st_ino)
                if pre_exec:
                    need(stat.S_ISREG(trusted.st_mode) and trusted.st_uid == 0 and
                         trusted.st_mode & 0o022 == 0,
                         "pending_stop_executor_untrusted")
                need(Path(f"/proc/{control}/cgroup").read_text(
                    encoding="ascii") == "0::" + identity.cgroup + "\n",
                    "pending_stop_control_cgroup_changed")
                if not pre_exec:
                    _peer_executable(control, main_sha)
                    with Path(f"/proc/{control}/cmdline").open("rb") as stream:
                        command = stream.read(16385)
                    need(len(command) <= 16384 and command.endswith(b"\0") and
                         command.split(b"\0")[1:] ==
                         [b"auto-stop-service", unit.encode("ascii"), b""],
                         "pending_stop_control_command_changed")
                    _stop_peer(control, {"unit": unit,
                                         "invocation_id": identity.invocation})
            after = _launch_unit_identity(unit, identity.pid, pending_stop=True)
            held.revalidate_process()
            need(descriptor is None or _pid_alive(descriptor),
                 "pending_stop_control_exited")
            if after == before:
                return bool(control) and not pre_exec
            need(control == 0 and int(after["ControlPID"]) > 1 and
                 all(after[key] == before[key] for key in before
                     if key != "ControlPID"), "pending_stop_pid1_changed")
            before = after
        finally:
            if descriptor is not None:
                os.close(descriptor)
    raise Refused("pending_stop_pid1_changed")


def _stop_lost_launch(unit: str) -> None:
    """Stop an exact private unit when its process-held launch channel dies."""
    need(PRIVATE_UNIT.fullmatch(unit) is not None,
         "lost_launch_unit_invalid")
    command = ["/usr/bin/systemctl", "stop", unit]
    result = subprocess.run(command, capture_output=True, check=False,
                            timeout=8, env={"PATH": "/usr/sbin:/usr/bin",
                                            "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 4096 and
         len(result.stderr) <= 4096, "lost_launch_stop_uncertain")
    need(_private_unit_inactive(unit), "lost_launch_still_active")


def _private_unit_inactive(unit: str) -> bool:
    need(PRIVATE_UNIT.fullmatch(unit) is not None,
         "private_unit_readback_invalid")
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", unit, "-p", "ActiveState",
         "-p", "MainPID", "-p", "ControlGroup", "--no-pager"],
        capture_output=True, check=False, timeout=2,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 256 and
         len(result.stderr) <= 256, "lost_launch_stop_readback_unavailable")
    facts = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        need(separator == "=" and key not in facts,
             "lost_launch_stop_readback_invalid")
        facts[key] = value
    need(set(facts) == {"ActiveState", "MainPID", "ControlGroup"},
         "lost_launch_stop_readback_incomplete")
    return (facts["ActiveState"] in ("inactive", "failed") and
            facts["MainPID"] == "0" and not facts["ControlGroup"])


def _receive(peer: socket.socket) -> tuple[dict[str, object], tuple[int, ...]]:
    payload, anc, flags, _address = peer.recvmsg(
        MAX_REQUEST, socket.CMSG_SPACE(12),
        getattr(socket, "MSG_CMSG_CLOEXEC", 0))
    descriptors = array.array("i")
    try:
        for level, kind, data in anc:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors.frombytes(
                    data[:len(data) - len(data) % descriptors.itemsize])
            else:
                raise Refused("unexpected_ancillary_data")
        need(payload and len(payload) <= MAX_REQUEST and
             flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0,
             "request_truncated")
        request = json.loads(payload, object_pairs_hook=unique)
        need(type(request) is dict, "invalid_guardian_request")
        return request, tuple(descriptors)
    except BaseException:
        for fd in descriptors:
            os.close(fd)
        raise


def _receive_no_fds(peer: socket.socket) -> bytes:
    """Read a lease control packet without retaining unexpected rights."""
    payload, ancillary, flags, _address = peer.recvmsg(
        MAX_REQUEST, socket.CMSG_SPACE(4),
        getattr(socket, "MSG_CMSG_CLOEXEC", 0))
    descriptors = array.array("i")
    try:
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors.frombytes(
                    data[:len(data) - len(data) % descriptors.itemsize])
        need(not ancillary and
             flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0,
             "unexpected_lease_ancillary_or_truncation")
        return payload
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _prove_request(request: dict[str, object], fds: tuple[int, ...]) -> None:
    need(len(fds) == 3 and
         set(request) == {"schema", "command", "header_sha256",
                          "transaction_nonce", "planned_generation",
                          "boot_id", "netns_ino", "actor_challenge", "mode",
                          "private_unit"} and
         request["schema"] == "aegis_auto_guardian_request_v1" and
         request["command"] == "prove_deny" and
         request["mode"] in ("full-wide-tun", "wide-redirect-safe") and
         type(request["private_unit"]) is str and
         PRIVATE_UNIT.fullmatch(request["private_unit"]) is not None and
         all(type(request[k]) is str and HEX64.fullmatch(request[k])
             for k in ("header_sha256", "planned_generation")) and
         type(request["transaction_nonce"]) is str and
         HEX32.fullmatch(request["transaction_nonce"]) is not None and
         type(request["actor_challenge"]) is str and
         HEX64.fullmatch(request["actor_challenge"]) is not None and
         type(request["boot_id"]) is str and
         type(request["netns_ino"]) is int and request["netns_ino"] > 0,
         "invalid_guardian_request")


def _stop_request(request: dict[str, object], fds: tuple[int, ...]) -> None:
    need(not fds and set(request) == {"schema", "command", "boot_id",
                                      "invocation_id", "unit"} and
         request["schema"] == "aegis_auto_guardian_stop_v1" and
         request["command"] in ("STOP_BEGIN", "STOP_CLEAN") and
         type(request["unit"]) is str and
         PRIVATE_UNIT.fullmatch(request["unit"]) is not None and
         type(request["boot_id"]) is str and
         request["boot_id"] == Path("/proc/sys/kernel/random/boot_id")
         .read_text(encoding="ascii").strip() and
         type(request["invocation_id"]) is str and
         HEX32.fullmatch(request["invocation_id"]) is not None,
         "invalid_stop_request")


def _bind_request(request: dict[str, object], fds: tuple[int, ...]) -> None:
    need(not fds and set(request) == {"schema", "command", "boot_id",
                                      "invocation_id", "unit"} and
         request["schema"] == "aegis_auto_guardian_bind_v1" and
         request["command"] == "BIND_BEGIN" and
         request["boot_id"] == host_anchor()["boot_id"] and
         type(request["unit"]) is str and
         PRIVATE_UNIT.fullmatch(request["unit"]) is not None and
         type(request["invocation_id"]) is str and
         HEX32.fullmatch(request["invocation_id"]) is not None,
         "invalid_bind_request")


def _bind_peer(pid: int, request: dict[str, object]) -> None:
    command = ["/usr/bin/systemctl", "show", request["unit"],
               "-p", "ControlPID", "-p", "ControlGroup",
               "-p", "InvocationID", "-p", "ActiveState", "--no-pager"]
    result = subprocess.run(command, capture_output=True, timeout=2,
                            check=False, env={"PATH": "/usr/sbin:/usr/bin",
                                              "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 4096,
         "bind_unit_identity_unavailable")
    facts = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        need(separator == "=" and key not in facts, "bind_unit_facts_invalid")
        facts[key] = value
    need(set(facts) == {"ControlPID", "ControlGroup", "InvocationID",
                        "ActiveState"} and
         facts["ControlPID"] == str(pid) and
         facts["InvocationID"] == request["invocation_id"] and
         facts["ActiveState"] == "activating" and
         facts["ControlGroup"] == "/system.slice/" + request["unit"] and
         Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
         "0::/system.slice/" + request["unit"] + "\n", "foreign_bind_peer")


BIND_STEPS = frozenset(("handoff_sent", "foreign_begin", "foreign_end", "foreign_ack",
                        "seal_received", "fresh_foreign_begin", "fresh_foreign_end",
                        "semantic_begin", "semantic_end", "policy_published",
                        "scope_bound", "peer_rechecked", "ack_sent"))


def _bind_step(step: str) -> None:
    """Closed timing coordinates only; no unit, request or configuration bytes."""
    need(step in BIND_STEPS, "invalid_bind_step")
    print("aegis_auto_bind_step " + json.dumps({"step": step,
          "monotonic_ns": time.monotonic_ns()}, sort_keys=True),
          file=sys.stderr, flush=True)


def _host_currentboot_source_proof(fd: int) -> None:
    """The installed guardian owns the host namespace and original Guard OFD.

    The private ExecStartPre cannot execute the strict guardian source verifier:
    systemd's PrivateTmp/ProtectSystem creates a different mount namespace.
    Nothing is handed to that unit before this source-bound host check succeeds.
    """
    _held_lock(fd, GUARD_LOCK)
    # The bounded child performs the full strict host-namespace own_source.
    install_before = regular(INSTALL, MAX_RECEIPT, 0o600)
    installed = json.loads(install_before, object_pairs_hook=unique)
    need(type(installed) is dict, 'bind_install_record_invalid')
    transition = ROOT/'aegis_auto_boot_transition.py'
    expected = installed['terminal_transition_sha256']
    need(type(expected) is str and HEX64.fullmatch(expected),
         'bind_transition_digest_invalid')
    source_config = Path('/etc/aegis-auto-terminal-source.json')
    store_config = Path('/etc/aegis-auto-terminal-store.json')
    # Generic actions allow an absent terminal installation; BIND does not.
    source_before = regular(source_config, 4096, 0o600)
    store_before = regular(store_config, 4096, 0o600)
    for ancestor in (transition.parent, *transition.parent.parents):
        parent = ancestor.stat(follow_symlinks=False)
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
             parent.st_gid == 0 and parent.st_mode & 0o022 == 0,
             'bind_transition_parent_untrusted')
    source_fd = os.open(transition, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        source_stat = os.fstat(source_fd)
        named_stat = transition.stat(follow_symlinks=False)
        def source_identity(actual, named):
            return (stat.S_ISREG(actual.st_mode) and actual.st_uid == 0 and
                    actual.st_gid == 0 and actual.st_nlink == 1 and
                    stat.S_IMODE(actual.st_mode) == 0o500 and
                    0 < actual.st_size <= (1 << 20) and
                    (actual.st_dev, actual.st_ino, actual.st_size,
                     actual.st_mode, actual.st_uid, actual.st_gid, actual.st_nlink,
                     actual.st_mtime_ns, actual.st_ctime_ns) ==
                    (named.st_dev, named.st_ino, named.st_size,
                     named.st_mode, named.st_uid, named.st_gid, named.st_nlink,
                     named.st_mtime_ns, named.st_ctime_ns))
        need(source_identity(source_stat, named_stat),
             'bind_transition_source_untrusted')
        source_raw = os.pread(source_fd, (1 << 20) + 1, 0)
        need(len(source_raw) == source_stat.st_size and
             digest(source_raw) == expected,
             'bind_transition_source_changed')
        need(source_identity(os.fstat(source_fd),
             transition.stat(follow_symlinks=False)),
             'bind_transition_source_changed')
        # Python opens the already-authenticated inode, never the mutable name.
        args = ('/usr/bin/python3', '-I', '-B',
                '/proc/self/fd/'+str(source_fd),
                'verify-consumed-under-guard-held', str(fd), str(source_fd))
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'},
            pass_fds=(fd, source_fd), close_fds=True, start_new_session=True)
        # Observe the leader without reaping: its PID/PGID cannot be reused
        # before the owned group is stopped. No child may outlive this proof.
        deadline = time.monotonic() + 8.0
        observed = None
        try:
            while time.monotonic() < deadline:
                observed = os.waitid(os.P_PID, child.pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None:
                    break
                time.sleep(0.01)
        finally:
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            child.wait(timeout=2)
        need(observed is not None, 'bind_host_source_proof_timeout')
        need(observed.si_code == os.CLD_EXITED and observed.si_status == 0,
             'bind_host_source_proof_refused')
        need(source_identity(os.fstat(source_fd),
             transition.stat(follow_symlinks=False)) and
             digest(os.pread(source_fd, (1 << 20) + 1, 0)) == expected and
             regular(INSTALL, MAX_RECEIPT, 0o600) == install_before and
             regular(source_config, 4096, 0o600) == source_before and
             regular(store_config, 4096, 0o600) == store_before,
             'bind_host_source_generation_changed')
    finally:
        os.close(source_fd)
    _held_lock(fd, GUARD_LOCK)


def _send_bind_handoff(peer: socket.socket, pid: int, pidfd: int,
                       request: dict[str, object], fd: int,
                       stage_fd: int, original: dict[str, object],
                       grant: dict[str, object]) -> None:
    _bind_request(request, ())
    _bind_peer(pid, request)
    _held_lock(fd, GUARD_LOCK)
    need(original["private_unit"] == request["unit"],
         "bind_unit_changed_from_prepared_owner")
    _claimed_private_unit(stage_fd, original, grant, request["unit"])
    need(not STOP_INTENT.exists() and not STOP_INTENT.is_symlink(),
         "bind_during_stop_intent")
    _host_currentboot_source_proof(fd)
    need(_pid_alive(pidfd), "bind_control_peer_exited_after_source_proof")
    _bind_peer(pid, request)
    _held_lock(fd, GUARD_LOCK)
    _claimed_private_unit(stage_fd, original, grant, request["unit"])
    need(not STOP_INTENT.exists() and not STOP_INTENT.is_symlink(),
         "bind_during_stop_intent_after_source_proof")
    payload = json.dumps({"schema": "aegis_auto_guardian_bind_handoff_v2",
                          "boot_id": request["boot_id"],
                          "invocation_id": request["invocation_id"],
                          "unit": request["unit"],
                          "current_boot_source_verified": True},
                         sort_keys=True, separators=(",", ":")).encode()
    sent = peer.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                     array.array("i", [fd]))])
    need(sent == len(payload), "bind_fd_handoff_failed")
    _bind_step("handoff_sent")


def _seal_held_private_bind(peer: socket.socket, pid: int, pidfd: int,
                            request: dict[str, object], guard_fd: int,
                            stage_fd: int, original: dict[str, object],
                            grant: dict[str, object], deadline: float,
                            authenticated_lineage: dict | None = None
                            ) -> None:
    """Seal the exact ControlPID grant in the installed host guardian."""
    # The owner job has a twenty-second bound, including unit construction.
    # This transaction has its own earlier absolute bound. Each child still
    # waits at most seven seconds and re-blocks without a valid host ACK.
    need(time.monotonic() < deadline, "bind_seal_deadline_elapsed")
    peer.settimeout(max(0.001, deadline - time.monotonic()))
    packet = _receive_no_fds(peer)
    need(time.monotonic() < deadline, "bind_seal_deadline_elapsed")
    need(0 < len(packet) <= MAX_REQUEST, "bind_seal_request_missing")
    message = json.loads(packet, object_pairs_hook=unique)
    need(type(message) is dict and message == {
        "schema": "aegis_auto_guardian_bind_foreign_v1",
        "command": "BIND_FOREIGN_ASSESS", "unit": request["unit"],
        "boot_id": request["boot_id"],
        "invocation_id": request["invocation_id"]},
        "invalid_bind_seal_request")
    need(_pid_alive(pidfd), "bind_control_peer_exited")
    _bind_peer(pid, request)
    _held_lock(guard_fd, GUARD_LOCK)
    _claimed_private_unit(stage_fd, original, grant, request["unit"])
    state_path=Path("/var/lib/aegis-install/client/device-guard.conf")
    state=regular(state_path,1<<15)
    group=Path("/sys/fs/cgroup/system.slice")/request["unit"]
    candidate={"schema":"aegis_device_guard_binding_v1",
        "boot_id":request["boot_id"],"state_sha256":digest(state.rstrip(b"\n")),
        "path":"system.slice/"+request["unit"],
        "inode":str(group.stat(follow_symlinks=False).st_ino),
        "invocation":request["invocation_id"]}
    manager_path=Path(str(state_path)+".manager-binding")
    manager=record(manager_path) if manager_path.exists() else None
    fields=dict(line.split("=",1) for line in state.decode("ascii").splitlines())
    foreign=verified_module(FOREIGN_SOURCE,"aegis_auto_foreign_policy")
    _bind_step("foreign_begin")
    assessed=foreign.assess_foreign_policy(fields["uplink"],
        mode=fields.get("capture_profile","full-wide-tun"),
        binding_overrides={"client":candidate,"manager":manager},require_guard=True,
        expected_state_sha256=digest(state.rstrip(b"\n")))
    _bind_step("foreign_end")
    need(_pid_alive(pidfd) and time.monotonic()<deadline,"bind_seal_deadline_elapsed")
    reply=json.dumps({"schema":"aegis_auto_guardian_foreign_assessed_v1",
        "unit":request["unit"],"boot_id":request["boot_id"],
        "invocation_id":request["invocation_id"],
        "foreign_projection_sha256":assessed["foreign_projection_sha256"]},
        sort_keys=True,separators=(",",":")).encode()
    peer.settimeout(max(0.001,deadline-time.monotonic()))
    need(peer.send(reply)==len(reply),"bind_seal_ack_failed")
    _bind_step("foreign_ack")
    packet=_receive_no_fds(peer)
    message=json.loads(packet,object_pairs_hook=unique)
    need(message=={"schema":"aegis_auto_guardian_bind_seal_v1",
        "command":"BIND_SEAL","unit":request["unit"],
        "boot_id":request["boot_id"],"invocation_id":request["invocation_id"]},
        "invalid_bind_seal_request")
    need(_pid_alive(pidfd) and time.monotonic()<deadline,"bind_seal_deadline_elapsed")
    _bind_peer(pid,request)
    _held_lock(guard_fd,GUARD_LOCK)
    _bind_step("seal_received")
    binding=record(Path(str(state_path)+".client-binding"))
    # The v2 helper and semantic verifier bind shell state_text, whose command
    # substitution strips terminal LF bytes. The protected policy seal below
    # separately retains the hash of the exact administrative file bytes.
    need(binding == {
        "schema": "aegis_device_guard_binding_v1",
        "boot_id": request["boot_id"], "state_sha256": digest(state.rstrip(b"\n")),
        "path": "system.slice/" + request["unit"],
        "inode": str(group.stat(follow_symlinks=False).st_ino),
        "invocation": request["invocation_id"]},
        "private_bind_receipt_not_current")
    _bind_step("fresh_foreign_begin")
    fresh=foreign.assess_foreign_policy(fields["uplink"],
        mode=fields.get("capture_profile","full-wide-tun"),require_guard=True,
        expected_state_sha256=digest(state.rstrip(b"\n")))
    _bind_step("fresh_foreign_end")
    need(fresh==assessed,"foreign_policy_drift")
    _bind_step("semantic_begin")
    sealed = seal_policy_receipt(guard_fd, deadline=deadline)
    _bind_step("semantic_end")
    need(time.monotonic() < deadline, "bind_seal_deadline_elapsed")
    need(sealed["boot_id"] == request["boot_id"] and
         sealed["netns_ino"] == original["netns_ino"] and
         (sealed["guard_dev"], sealed["guard_ino"]) ==
         _held_lock(guard_fd, GUARD_LOCK) and
         sealed["state_sha256"] == digest(state),
         "private_bind_seal_identity_changed")
    _publish_policy_receipt(sealed)
    _bind_step("policy_published")
    if original["mode"] == "wide-redirect-safe" or (
            original["mode"] == "full-wide-tun" and
            verified_module(POLICY_SOURCE,
                            "aegis_auto_guard_policy").LOCAL_INTENT.exists()):
        scoped = _scoped_owner_binding(stage_fd, original,
                                       grant["policy_sha256"])
        if scoped is not None:
            redirect = verified_module(POLICY_SOURCE,
                                       "aegis_auto_guard_policy")
            redirect.scoped_bind_invocation(scoped, request["invocation_id"],
                                            deadline=deadline)
        else:
            local = _local_owner_binding(stage_fd, original,
                                         grant["policy_sha256"],
                                         current_policy_sha256=sealed["policy_sha256"],
                                         authenticated_lineage=
                                         authenticated_lineage,
                                         phase='bind')
            need(local is not None, "local redirect owner missing")
            redirect = verified_module(POLICY_SOURCE,
                                       "aegis_auto_guard_policy")
            redirect.local_bind_invocation(
                local, request["invocation_id"], binding["path"],
                int(binding["inode"]), deadline=deadline)
    _bind_step("scope_bound")
    need(_pid_alive(pidfd), "bind_control_peer_exited")
    _bind_peer(pid, request)
    _bind_step("peer_rechecked")
    # The full JSON/text/JSON semantic readback above is immediately before
    # publication under the original guard OFD. Re-read the protected seal
    # here; a second three-command nft pass could outlive PID 1's owner job.
    need(record(POLICY) == sealed and
         _held_lock(guard_fd, GUARD_LOCK) ==
         (sealed["guard_dev"], sealed["guard_ino"]),
         "private_bind_seal_changed")
    need(time.monotonic() < deadline, "bind_seal_deadline_elapsed")
    reply = json.dumps({
        "schema": "aegis_auto_guardian_bind_sealed_v1",
        "unit": request["unit"], "boot_id": request["boot_id"],
        "invocation_id": request["invocation_id"],
        "policy_sha256": sealed["policy_sha256"]},
        sort_keys=True, separators=(",", ":")).encode()
    # This small SOCK_SEQPACKET reply must enqueue immediately. Never wait
    # while the helper's owner deadline can expire and start emergency block.
    peer.setblocking(False)
    need(time.monotonic() < deadline, "bind_seal_deadline_elapsed")
    need(peer.send(reply) == len(reply), "bind_seal_ack_failed")
    _bind_step("ack_sent")


def bind_seal_client(fd: int, *, foreign_only: bool = False) -> None:
    """The installed helper's bounded child uses its original BIND channel."""
    need(fd == 8, "bind_seal_fd_invalid")
    unit = os.environ.get("AEGIS_AUTO_PRIVATE_UNIT")
    invocation = os.environ.get("INVOCATION_ID")
    need(type(unit) is str and PRIVATE_UNIT.fullmatch(unit) is not None and
         type(invocation) is str and HEX32.fullmatch(invocation) is not None,
         "bind_seal_identity_invalid")
    with socket.socket(fileno=os.dup(fd)) as peer:
        need(peer.family == socket.AF_UNIX and
             peer.type & socket.SOCK_SEQPACKET == socket.SOCK_SEQPACKET,
             "bind_seal_channel_invalid")
        deadline = time.monotonic() + 7
        peer.settimeout(max(0.001, deadline - time.monotonic()))
        request = {
            "schema": "aegis_auto_guardian_bind_foreign_v1" if foreign_only else "aegis_auto_guardian_bind_seal_v1",
            "command": "BIND_FOREIGN_ASSESS" if foreign_only else "BIND_SEAL", "unit": unit,
            "boot_id": Path("/proc/sys/kernel/random/boot_id")
                       .read_text(encoding="ascii").strip(),
            "invocation_id": invocation}
        raw = json.dumps(request, sort_keys=True,
                         separators=(",", ":")).encode()
        need(peer.send(raw) == len(raw), "bind_seal_send_failed")
        need(time.monotonic() < deadline, "bind_seal_deadline_elapsed")
        peer.settimeout(max(0.001, deadline - time.monotonic()))
        reply = _receive_no_fds(peer)
        need(time.monotonic() < deadline, "bind_seal_deadline_elapsed")
        value = json.loads(reply, object_pairs_hook=unique)
        field="foreign_projection_sha256" if foreign_only else "policy_sha256"
        schema="aegis_auto_guardian_foreign_assessed_v1" if foreign_only else "aegis_auto_guardian_bind_sealed_v1"
        need(type(value) is dict and
             set(value) == {"schema", "unit", "boot_id", "invocation_id",
                            field} and
             value["schema"] == schema and
             value["unit"] == unit and
             value["boot_id"] == request["boot_id"] and
             value["invocation_id"] == invocation and
             type(value[field]) is str and
             HEX64.fullmatch(value[field]) is not None,
             "bind_seal_ack_invalid")


def _stop_peer(pid: int, request: dict[str, object]) -> None:
    command = ["/usr/bin/systemctl", "show", request["unit"],
               "-p", "ControlPID", "-p", "ControlGroup",
               "-p", "InvocationID", "-p", "ActiveState", "--no-pager"]
    result = subprocess.run(command, capture_output=True, timeout=2,
                            check=False, env={"PATH": "/usr/sbin:/usr/bin",
                                              "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 4096 and
         len(result.stderr) <= 4096, "stop_unit_identity_unavailable")
    facts = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        need(separator == "=" and key not in facts, "stop_unit_facts_invalid")
        facts[key] = value
    with Path(f"/proc/{pid}/cmdline").open("rb") as stream:
        argv = stream.read(4097)
    expected_command = (b"auto-stop-service-clean" if
                        request["command"] == "STOP_CLEAN" else
                        b"auto-stop-service")
    need(len(argv) <= 4096 and argv.endswith(b"\0") and
         argv.split(b"\0")[1:] ==
         [expected_command, request["unit"].encode("ascii"), b""],
         "stop_control_command_changed")
    need(set(facts) == {"ControlPID", "ControlGroup", "InvocationID",
                        "ActiveState"} and facts["ControlPID"] == str(pid) and
         facts["InvocationID"] == request["invocation_id"] and
         facts["ActiveState"] in ("deactivating", "failed", "auto-restart") and
         facts["ControlGroup"] == "/system.slice/" + request["unit"] and
         Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
         "0::/system.slice/" + request["unit"] + "\n", "foreign_stop_peer")


def _private_stop_intent(request: dict[str, object]) -> None:
    parent = STOP_INTENT.parent
    p = parent.stat(follow_symlinks=False)
    need(stat.S_ISDIR(p.st_mode) and p.st_uid == 0 and p.st_mode & 0o022 == 0,
         "untrusted_stop_parent")
    proposed = {"schema": "aegis_auto_stop_intent_v1",
                "boot_id": request["boot_id"],
                "invocation_id": request["invocation_id"],
                "service": request["unit"], "phase": "pending_deny"}
    if STOP_INTENT.exists() or STOP_INTENT.is_symlink():
        existing = record(STOP_INTENT)
        need(existing == proposed or existing == {**proposed, "phase": "deny_proven"},
             "foreign_or_stale_stop_intent")
        return
    raw = (json.dumps(proposed, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(STOP_INTENT, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), "stop_intent_short_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC |
                        os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    need(record(STOP_INTENT) == proposed, "stop_intent_changed")


def _replace_stop_phase(phase: str) -> None:
    """Durably advance the exact sticky intent while guard flock is held."""
    old = record(STOP_INTENT)
    need(old.get("schema") == "aegis_auto_stop_intent_v1" and
         old.get("phase") in ("pending_deny", "deny_proven") and
         phase == "deny_proven", "invalid_stop_phase")
    updated = {**old, "phase": phase}
    temporary = STOP_INTENT.with_name(STOP_INTENT.name + "." +
                                      secrets.token_hex(12) + ".tmp")
    raw = (json.dumps(updated, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), "stop_phase_short_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, STOP_INTENT)
    parent = os.open(STOP_INTENT.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    need(record(STOP_INTENT) == updated, "stop_phase_changed")


def _clear_terminal_stop_intent() -> None:
    """Permit a new lease only after PID1 and kernel prove the old stop ended.

    Caller owns the guard flock.  Ambiguous PID1 state leaves the sticky
    intent intact, including across guardian restarts and host reboot.
    """
    if not STOP_INTENT.exists() and not STOP_INTENT.is_symlink():
        return
    intent = record(STOP_INTENT)
    need(set(intent) == {"schema", "boot_id", "invocation_id", "service",
                         "phase"} and
         intent["schema"] == "aegis_auto_stop_intent_v1" and
         type(intent["service"]) is str and
         PRIVATE_UNIT.fullmatch(intent["service"]) is not None and
         intent["phase"] == "deny_proven" and
         intent["boot_id"] == host_anchor()["boot_id"],
         "stop_intent_not_terminal")
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", intent["service"], "-p", "MainPID",
         "-p", "ControlPID", "-p", "ControlGroup", "-p", "InvocationID",
         "-p", "ActiveState", "--no-pager"], capture_output=True, timeout=2,
        check=False, env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C",
                          "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 4096,
         "stop_terminal_pid1_unavailable")
    facts = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        need(separator == "=" and key not in facts, "stop_terminal_facts_invalid")
        facts[key] = value
    need(set(facts) == {"MainPID", "ControlPID", "ControlGroup",
                        "InvocationID", "ActiveState"} and
         facts["MainPID"] == facts["ControlPID"] == "0" and
         facts["ActiveState"] in ("inactive", "failed") and
         facts["InvocationID"] == intent["invocation_id"] and
         facts["ControlGroup"] in ("", "/system.slice/" + intent["service"]),
         "stop_terminal_pid1_incomplete")
    cgroup = Path("/sys/fs/cgroup/system.slice") / intent["service"]
    if cgroup.exists():
        events = (cgroup / "cgroup.events").read_text(encoding="ascii")
        need("populated 0\n" in events and "populated 1\n" not in events,
             "stop_terminal_cgroup_populated")
    policy = record(POLICY)
    witness = verified_module(WITNESS, "aegis_auto_native_witness")
    projection, _handles, _counters = _semantic_policy_snapshot()
    need(policy.get("schema") == "aegis_auto_guardian_policy_v1" and
         policy.get("policy_sha256") == digest(projection) and
         _no_client_grant(projection), "stop_terminal_deny_changed")
    need(record(STOP_INTENT) == intent, "stop_terminal_intent_changed")
    STOP_INTENT.unlink()
    parent = os.open(STOP_INTENT.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)



TERMINAL_RUN = Path("/run/aegis-auto-terminal")


def _publish_clean_stop(request: dict[str, object], policy_sha: str) -> None:
    """Record an ExecStop-only step; the later PID 1 B proof remains required."""
    parent = TERMINAL_RUN
    info = parent.stat(follow_symlinks=False)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
         stat.S_IMODE(info.st_mode) == 0o700 and info.st_nlink >= 2,
         "terminal_runtime_untrusted")
    a_raw = regular(parent / "a.json", 4096)
    a = json.loads(a_raw, object_pairs_hook=unique)
    need(type(a) is dict and set(a) ==
         {"schema", "boot_id", "unit", "invocation_id", "nonce",
          "final_job", "action", "pid1_tick", "source_sha256",
          "activation_sha256", "stage_dev", "stage_ino",
          "terminal_sha256", "installed_generation_sha256",
          "installed_manifest_sha256", "active_generation_sha256",
          "active_report_sha256", "boot_snapshot_sha256"} and
         a["schema"] == "aegis_auto_terminal_a_v1" and
         a["boot_id"] == request["boot_id"] and
         a["unit"] == request["unit"] and
         a["invocation_id"] == request["invocation_id"] and
         type(a["final_job"]) is int and a["final_job"] > 0 and
         a["action"] in ("reboot", "poweroff") and
         type(a["nonce"]) is str and HEX32.fullmatch(a["nonce"]) and
         type(a["source_sha256"]) is str and HEX64.fullmatch(a["source_sha256"]) and
         type(a["activation_sha256"]) is str and HEX64.fullmatch(a["activation_sha256"]) and
         type(a["terminal_sha256"]) is str and HEX64.fullmatch(a["terminal_sha256"]) and
         all(type(a[k]) is str and HEX64.fullmatch(a[k]) for k in
             ("installed_generation_sha256", "installed_manifest_sha256",
              "active_generation_sha256", "active_report_sha256",
              "boot_snapshot_sha256")) and
         all(type(a[k]) is int and a[k] > 0 for k in ("stage_dev", "stage_ino")),
         "terminal_a_untrusted")
    intent_raw = regular(STOP_INTENT, 4096)
    intent = json.loads(intent_raw, object_pairs_hook=unique)
    need(intent == {"schema": "aegis_auto_stop_intent_v1",
                    "boot_id": request["boot_id"],
                    "invocation_id": request["invocation_id"],
                    "service": request["unit"], "phase": "deny_proven"},
         "clean_stop_intent_changed")
    job_result = subprocess.run(
        ["/usr/bin/systemctl", "show", request["unit"], "-p", "Job", "--no-pager"],
        capture_output=True, timeout=2, check=False,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
    need(job_result.returncode == 0 and not job_result.stderr and
         len(job_result.stdout) <= 256, "private_stop_job_unavailable")
    job_text = job_result.stdout.decode("ascii", "strict")
    match = re.fullmatch(r"Job=([1-9][0-9]*)(?: (/org/freedesktop/systemd1/job/([1-9][0-9]*)))?\n",
                         job_text)
    need(match is not None and (match[3] is None or match[1] == match[3]) and
         0 < int(match[1]) < 1 << 32, "private_stop_job_invalid")
    stop_job = int(match[1])
    stop_path = "/org/freedesktop/systemd1/job/" + match[1]
    payload = {"op": "bind-private", "boot": request["boot_id"],
               "unit": request["unit"], "nonce": a["nonce"],
               "invocation_id": request["invocation_id"],
               "job": stop_job, "path": stop_path}
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC) as sock:
        sock.settimeout(2)
        sock.connect(str(parent / "observer.sock"))
        raw_request = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        need(sock.send(raw_request) == len(raw_request), "private_job_bind_short_send")
        response = sock.recv(257)
    need(response == b'{"bound_private": true}' or response == b'{"bound_private":true}',
         "private_stop_job_not_bound")
    value = {"schema": "aegis_auto_terminal_clean_stop_v1",
             "boot_id": request["boot_id"], "unit": request["unit"],
             "invocation_id": request["invocation_id"],
             "nonce": a["nonce"], "final_job": a["final_job"],
             "action": a["action"],
             "a_sha256": digest(a_raw), "intent_sha256": digest(intent_raw),
             "policy_sha256": policy_sha,
             "activation_sha256": a["activation_sha256"],
             "terminal_sha256": a["terminal_sha256"],
             "stage_dev": a["stage_dev"], "stage_ino": a["stage_ino"],
             "installed_generation_sha256": a["installed_generation_sha256"],
             "installed_manifest_sha256": a["installed_manifest_sha256"],
             "private_stop_job": stop_job, "private_stop_path": stop_path}
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    leaf = parent / "clean-stop.json"
    fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), "clean_stop_short_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(pfd)
    finally:
        os.close(pfd)
    need(regular(leaf, 4096) == raw and regular(STOP_INTENT, 4096) == intent_raw,
         "clean_stop_readback_changed")


def _stop_effect(peer: socket.socket, pid: int, pidfd: int,
                 request: dict[str, object], fds: tuple[int, ...],
                 inherited_guard_fd: int | None,
                 watchdog: object | None) -> None:
    _stop_request(request, fds)
    _stop_peer(pid, request)
    fd = (inherited_guard_fd if inherited_guard_fd is not None else
          os.open(GUARD_LOCK, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW |
                  os.O_NONBLOCK))
    try:
        if inherited_guard_fd is None:
            deadline = time.monotonic() + 0.25
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    need(time.monotonic() < deadline, "stop_guard_lock_busy")
                    time.sleep(min(FLOCK_RETRY_SECONDS, max(0, deadline - time.monotonic())))
        _held_lock(fd, GUARD_LOCK)
        _private_stop_intent(request)
        need(GUARD_HELPER.is_file() and not GUARD_HELPER.is_symlink(),
             "guard_helper_unavailable")
        _run_helper_in_cgroup(GUARD_HELPER, "block", fd)
        # The same held OFD spans sticky intent, helper block and readback.
        # A detached or setsid child cannot outlive cgroup custody.
        _held_lock(fd, GUARD_LOCK)
        # STOP_BEGIN carries only the authenticated unit/boot invocation. Its
        # policy namespace comes from this installed host guardian, rather
        # than an absent (or caller-selected) request field.
        policy = _policy({**request, "netns_ino": host_anchor()["netns_ino"]},
                         _held_lock(fd, GUARD_LOCK))
        witness = verified_module(WITNESS, "aegis_auto_native_witness")
        projection, _handles, _counters = _semantic_policy_snapshot()
        need(digest(projection) == policy["policy_sha256"] and
             _no_client_grant(projection), "stop_kernel_deny_not_proven")
        need(STOP_INTENT.exists() and not STOP_INTENT.is_symlink(),
             "stop_intent_lost")
        _replace_stop_phase("deny_proven")
        if watchdog is not None:
            acknowledgement = watchdog.begin_stop()
            need(acknowledgement["invocation_id"] ==
                 request["invocation_id"] and
                 acknowledgement["policy_sha256"] ==
                 policy["policy_sha256"],
                 "watchdog_stop_barrier_changed")
        if request["command"] == "STOP_CLEAN":
            # ExecStopPost can retain the deny but never produce this receipt.
            # A separate PID 1 terminal witness must have run before ExecStop.
            terminal = verified_module(ROOT/'aegis_auto_terminal_witness.py',
                                       'aegis_auto_terminal_witness')
            pending = terminal.pending_final(terminal.source_config(), optional=True)
            if pending is None:
                need(not any((TERMINAL_RUN/name).exists() or
                             (TERMINAL_RUN/name).is_symlink()
                             for name in ('a.json','clean-stop.json','b.json')),
                     'administrative_stop_terminal_residue')
                # Exact administrative StopUnit retains the kernel deny and
                # current STOP intent; it creates no clean/final/BOOT proof.
            else:
                _publish_clean_stop(request, policy["policy_sha256"])
    finally:
        if inherited_guard_fd is None:
            os.close(fd)
    result = {"schema": "aegis_auto_guardian_stop_result_v1",
              "deny_retained": True, "intent_retained": True,
              "policy_sha256": policy["policy_sha256"]}
    need(_pid_alive(pidfd), "stop_control_peer_exited_before_ack")
    peer.sendall(json.dumps(result, sort_keys=True,
                            separators=(",", ":")).encode())


def _no_client_grant(projection: bytes) -> bool:
    """The stopped client must have no unrestricted socket or DNAT grant.

    Numeric interface and socket predicates can also belong to the manager's
    pinned DHCP exception. Admit those only when the entire table equals the
    trusted renderer with no client or capture binding. Callers still prove
    the full JSON/text seal (including elided cgroup levels) independently.
    """
    payload = json.loads(projection, object_pairs_hook=unique)
    need(type(payload) is list, "invalid_policy_projection")
    state_path = Path("/var/lib/aegis-install/client/device-guard.conf")
    client_path = Path(str(state_path) + ".client-binding")
    def absent() -> None:
        need(not client_path.exists() and not client_path.is_symlink(),
             "client_binding_retained")
        need(not CAPTURE_BINDING.exists() and not CAPTURE_BINDING.is_symlink(),
             "capture_binding_retained")
    absent()
    manager_grant = False
    for item in payload:
        if "rule" not in item or item["rule"].get("chain") not in ("output", "postroute"):
            continue
        expressions = item["rule"].get("expr")
        if type(expressions) is list and any(
                type(expr) is dict and "accept" in expr for expr in expressions):
            canonical = json.dumps(expressions, sort_keys=True)
            if "dnat" in canonical:
                return False
            if "socket" in canonical or '"key": "oif"' in canonical:
                manager_grant = True
    if not manager_grant:
        return True
    manager_path = Path(str(state_path) + ".manager-binding")
    need(not manager_path.is_symlink(), "untrusted_guard_binding")
    if not manager_path.exists():
        return False
    state = regular(state_path, 1 << 15)
    manager_raw = regular(manager_path, 4096, 0o600)
    policy = verified_module(POLICY_SOURCE, "aegis_auto_guard_policy")
    parsed = policy.parse_state(state)
    manager = json.loads(manager_raw, object_pairs_hook=unique)
    need(type(manager) is dict, "untrusted_guard_binding")
    policy._binding(manager, "manager", digest(state.rstrip(b"\n")), parsed["manager"])
    need(manager.get("schema") == "aegis_device_guard_binding_v2" and
         manager["boot_id"] == host_anchor()["boot_id"] and
         manager["ifindex"] == socket.if_nametoindex(parsed["uplink"]),
         "guard_readback_manager_changed")
    expected = policy._expected(parsed, None, manager)
    try:
        actual, _chains = policy._canonical_rules(projection)
        normalized = policy._normalized_numeric_oif(
            actual, None, parsed["capture_interface"], manager, parsed["uplink"])
    except policy.PolicyRefused:
        return False
    denied = normalized == policy._expected_with_elided_levels(expected, normalized)
    absent()
    need(regular(state_path, 1 << 15) == state and
         regular(manager_path, 4096, 0o600) == manager_raw and
         manager["ifindex"] == socket.if_nametoindex(parsed["uplink"]),
         "guard_readback_manager_changed")
    return denied


FLOCK_RETRY_SECONDS = 0.002


def _wait_exit(proc: subprocess.Popen, timeout: float) -> int:
    """Event-driven child exit wait under the same bound (pidfd + poll).

    Python's Popen.wait(timeout) sleeps in a 1-50 ms backoff loop; a pidfd
    becomes readable exactly at exit. Kernels without pidfd keep the
    original bounded Popen.wait.
    """
    deadline = time.monotonic() + timeout
    try:
        pidfd = os.pidfd_open(proc.pid)
    except (AttributeError, OSError):
        return proc.wait(timeout=timeout)
    try:
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(proc.args, timeout)
            if poller.poll(max(1, int(remaining * 1000) + 1)):
                return proc.wait()
    finally:
        os.close(pidfd)



def capture_bind_bpf_client(guard_fd: int, channel_fd: int, nonce: str,
                            interfaces: list[str]) -> None:
    """One inherited read-only channel to the live PID1 guardian Main."""
    own_source()
    guard = _held_lock(guard_fd, GUARD_LOCK)
    need(type(channel_fd) is int and channel_fd > 2 and channel_fd != guard_fd and
         type(nonce) is str and HEX32.fullmatch(nonce) is not None,
         "capture_bpf_channel_invalid")
    state = regular(GUARD_STATE, 1 << 15)
    fields = dict(line.split("=", 1) for line in state.decode("ascii").splitlines())
    need(type(interfaces) is list and len(interfaces) == 3 and
         all(type(item) is str for item in interfaces) and set(interfaces) == {"lo", fields["uplink"], "aegis-tun0"},
         "capture_bpf_interfaces_changed")
    with socket.socket(fileno=os.dup(channel_fd)) as peer:
        peer.settimeout(3.0)
        pid, pidfd = _peer_identity(peer)
        try:
            need(Path(f"/proc/{pid}/cgroup").read_text() ==
                 "0::/system.slice/aegis-auto-guardian.service\n" and
                 os.stat(f"/proc/{pid}/ns/net").st_ino == os.stat("/proc/self/ns/net").st_ino,
                 "capture_bpf_parent_changed")
            facts = _unit_identity(GUARDIAN_UNIT, pid)
            need(_pid_alive(pidfd), "capture_bpf_parent_exited")
            request = {"schema":"aegis_capture_bind_bpf_v1", "nonce":nonce,
                       "guard_dev":guard[0], "guard_ino":guard[1], "interfaces":interfaces}
            raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
            need(peer.send(raw) == len(raw), "capture_bpf_send_failed")
            reply = json.loads(_receive_no_fds(peer), object_pairs_hook=unique)
            need(reply == dict(request, state="BPF_EMPTY") and _pid_alive(pidfd) and
                 _unit_identity(GUARDIAN_UNIT, pid) == facts and
                 _held_lock(guard_fd, GUARD_LOCK) == guard and
                 regular(GUARD_STATE, 1 << 15) == state,
                 "capture_bpf_ack_invalid")
        finally:
            os.close(pidfd)


def _wait_capture_bind_helper(proc: subprocess.Popen, peer: socket.socket,
                              guard_fd: int, nonce: str) -> int:
    """Service only a fixed BPF read inside the unchanged twelve-second wait."""
    deadline = time.monotonic() + 12
    pidfd = os.pidfd_open(proc.pid, 0)
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    poller.register(peer, select.POLLIN | select.POLLHUP | select.POLLERR)
    served = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(proc.args, 12)
            events = poller.poll(max(1, int(remaining * 1000) + 1))
            if any(fd == pidfd for fd, _ in events):
                return proc.wait()
            for fd, event in events:
                if fd != peer.fileno():
                    continue
                need(not served and event & select.POLLIN and
                     not event & (select.POLLERR | select.POLLNVAL),
                     "capture_bpf_request_missing_or_repeated")
                peer.settimeout(max(.001, deadline-time.monotonic()))
                request = json.loads(_receive_no_fds(peer), object_pairs_hook=unique)
                guard = _held_lock(guard_fd, GUARD_LOCK)
                state = regular(GUARD_STATE, 1 << 15)
                fields = dict(line.split("=", 1) for line in state.decode("ascii").splitlines())
                need(type(request) is dict, "capture_bpf_request_invalid")
                interfaces = request.get("interfaces")
                need(type(request) is dict and type(interfaces) is list and len(interfaces) == 3 and
                     all(type(item) is str for item in interfaces) and set(interfaces) == {"lo", fields["uplink"], "aegis-tun0"} and
                     request == {"schema":"aegis_capture_bind_bpf_v1", "nonce":nonce,
                                 "guard_dev":guard[0], "guard_ino":guard[1], "interfaces":interfaces} and
                     fields.get("armed") == "1" and
                     fields.get("capture_profile", "full-wide-tun") == "full-wide-tun",
                     "capture_bpf_request_invalid")
                # The existing watchdog client bounds two PID1 reads at 2s
                # each and its socket at 3s. Reserve those bounds, never extend
                # this helper's original 12s deadline to serve a late query.
                need(deadline-time.monotonic() > 7.5, "capture_bpf_budget_exhausted")
                capture_before = regular(CAPTURE_BINDING, 4096)
                client_path = Path(str(GUARD_STATE) + ".client-binding")
                client_before = regular(client_path, 4096)
                index = capture_binding_index(guard_fd)
                watchdog = verified_module(WATCHDOG_SOURCE, "aegis_auto_guardian_watchdog")
                watchdog.privileged_bpf_query(interfaces)
                need(time.monotonic() < deadline and
                     regular(GUARD_STATE, 1 << 15) == state and
                     regular(CAPTURE_BINDING, 4096) == capture_before and
                     regular(client_path, 4096) == client_before and
                     _held_lock(guard_fd, GUARD_LOCK) == guard and
                     capture_binding_index(guard_fd) == index,
                     "capture_bpf_owner_changed")
                raw = json.dumps(dict(request, state="BPF_EMPTY"),
                                 sort_keys=True, separators=(",", ":")).encode()
                peer.settimeout(max(.001, deadline-time.monotonic()))
                need(peer.send(raw) == len(raw), "capture_bpf_reply_failed")
                served = True
                # The endpoint must close or exit after its one reply. Ignore
                # HUP while still polling the original helper pidfd.
                poller.unregister(peer)
    finally:
        os.close(pidfd)


def _run_helper_in_cgroup(helper: Path, action: str, guard_fd: int) -> None:
    """All helper descendants remain in one delegated cgroup until drained."""
    relative = Path("/proc/self/cgroup").read_text(encoding="ascii")
    need(relative == "0::/system.slice/aegis-auto-guardian.service\n",
         "guardian_cgroup_not_delegated")
    parent = Path("/sys/fs/cgroup/system.slice/aegis-auto-guardian.service")
    need(parent.is_dir() and (parent / "cgroup.controllers").exists(),
         "guardian_cgroup_missing")
    leaf = parent / ("aegis-stop-" + secrets.token_hex(8))
    leaf.mkdir(mode=0o700)
    need((leaf / "cgroup.kill").exists() and (leaf / "cgroup.events").exists(),
         "cgroup_kill_unavailable")
    proc = None
    assist = child_assist = None
    try:
        need(action in ("block", "bind", "capture-bind"), "invalid_guard_helper_action")
        # Bash has no startup files or environment hooks here.  It moves its
        # own PID into the leaf before it execs any guard helper source.  A
        # Python preexec_fn would be unsafe in the threaded guardian server.
        wrapper = 'printf "0\\n" > "$1/cgroup.procs" || exit 111; exec /bin/bash "$2" "$3"'
        passed = (guard_fd,)
        environment = {"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                       "AEGIS_AUTO_HELD_GUARD_FD": str(guard_fd)}
        nonce = secrets.token_hex(16)
        if action == "capture-bind":
            assist, endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                # Bash reserves FD9 for the original guard and FD8 for private
                # BIND. Never let a low descriptor alias either slot.
                duplicate = fcntl.fcntl(endpoint.fileno(), fcntl.F_DUPFD_CLOEXEC, 10)
                child_assist = socket.socket(fileno=duplicate)
            finally:
                endpoint.close()
            passed += (child_assist.fileno(),)
            environment["AEGIS_AUTO_CAPTURE_BPF_FD"] = str(child_assist.fileno())
            environment["AEGIS_AUTO_CAPTURE_BPF_NONCE"] = nonce
        proc = subprocess.Popen(["/bin/bash", "--noprofile", "--norc", "-c",
                                 wrapper, "aegis-guard-helper", str(leaf),
                                 str(helper), action],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                start_new_session=True,
                                pass_fds=passed, env=environment)
        if child_assist is not None:
            child_assist.close(); child_assist = None
        # The one-vCPU installed stand reaches the old 3 s kill boundary before
        # completing block. Keep the whole helper bounded inside the existing
        # 12 s Stop client / 15 s PID1 budgets, including two-second kill/drain
        # and leaf cleanup bounds. The installed cohort measures completion;
        # no timeout is evidence of a successful deny.
        code = (_wait_capture_bind_helper(proc, assist, guard_fd, nonce)
                if action == "capture-bind" else _wait_exit(proc, 6))
        need(code == 0, "guard_reblock_failed")
        events = (leaf / "cgroup.events").read_text(encoding="ascii")
        need("populated 0\n" in events and not any(
            line == "populated 1" for line in events.splitlines()),
            "guard_helper_descendants_remain")
    except BaseException:
        try:
            (leaf / "cgroup.kill").write_text("1\n", encoding="ascii")
        except OSError:
            pass
        if proc is not None:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        raise
    finally:
        for channel in (assist, child_assist):
            if channel is not None: channel.close()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                leaf.rmdir()
                break
            except OSError:
                time.sleep(0.02)


def _policy(request: dict[str, object], guard_id: tuple[int, int]) -> dict[str, object]:
    need(record(INSTALL)["guard_unit_sha256"] is not None,
         "wide_guard_unit_not_installed")
    policy = record(POLICY)
    need(set(policy) == {"schema", "boot_id", "netns_ino", "guard_dev",
                         "guard_ino", "state_sha256", "policy_sha256"} and
         policy["schema"] == "aegis_auto_guardian_policy_v1" and
         policy["boot_id"] == request["boot_id"] and
         policy["netns_ino"] == request["netns_ino"] ==
         os.stat("/proc/self/ns/net").st_ino and
         (policy["guard_dev"], policy["guard_ino"]) == guard_id and
         type(policy["policy_sha256"]) is str and
         HEX64.fullmatch(policy["policy_sha256"]) is not None and
         digest(regular(Path("/var/lib/aegis-install/client/device-guard.conf"),
                        1 << 15)) == policy["state_sha256"],
         "protected_policy_not_admitted")
    need(record(INSTALL).get("installation_anchor") == installation_anchor(),
         "installed_host_identity_changed")
    state, projection = _semantic_policy_readback()
    need(not (INSTALL.parent / "foreign-policy-drift.json").exists(),"foreign_policy_drift")
    foreign=verified_module(FOREIGN_SOURCE,"aegis_auto_foreign_policy")
    fields=dict(line.split("=",1) for line in state.decode("ascii").splitlines())
    foreign.assess_foreign_policy(fields["uplink"],mode=fields.get("capture_profile","full-wide-tun"),require_guard=True)
    need(digest(state) == policy["state_sha256"] and
         digest(projection) == policy["policy_sha256"],
         "current_guard_semantics_changed")
    return policy


def _native_family_complete(native: dict[str, object], policy: dict[str, object],
                            family: int, nonce: bytes, mid_sha256: str) -> bool:
    return (native.get("ack") is True and native.get("address_family") == family and
            native.get("guard_policy_sha256") == policy["policy_sha256"] and
            native.get("challenge_sha256") == digest(nonce) and
            native.get("sink_received") == 0 and
            native.get("baseline_received") == 1 and
            native.get("trace_table_removed") is True and
            type(native.get("guard_output_drop_delta")) is int and
            native["guard_output_drop_delta"] > 0 and
            native.get("foreign_mid_sha256") == mid_sha256)


def _prove_installed_deny(request: dict[str, object], policy: dict[str, object],
                          guard_fd: int) -> dict[str, object]:
    """IPv4 and IPv6 native DROP in one topology lease and one trace window.

    Each family keeps its own sink session, positive control, nonce, DROP
    trace, counter delta and >=1.1 s dwell; three equal full foreign-policy
    samples bracket and split the window (see prove_deny_dual).
    """
    witness = verified_module(WITNESS, "aegis_auto_native_witness")
    rollback = verified_module(ROLLBACK_SOURCE,
                               "aegis_auto_trace_rollback")
    topology = verified_module(TOPOLOGY_SOURCE,
                               "aegis_auto_witness_topology")
    need(_no_client_grant(witness.snapshot_policy(Path("/usr/sbin/nft"))[0]),
         "client_grant_precedes_deny_witness")
    actor_challenge = bytes.fromhex(request["actor_challenge"])
    ipv6_nonce = witness.ipv6_challenge_nonce(actor_challenge)
    need(ipv6_nonce != actor_challenge, "dual_stack_native_witness_incomplete")
    lease = topology.provision_dual(actor_challenge)
    completed_cleanup = False
    try:
        facts = lease.facts
        need(facts["actor_challenge_hex"] == request["actor_challenge"] and
             facts["challenge_nonce_hex"] == request["actor_challenge"] and
             facts["boot_id"] == request["boot_id"] and
             facts["root_netns_ino"] == request["netns_ino"],
             "topology_actor_challenge_changed")
        challenges, positives = [], []
        for family, nonce in ((4, actor_challenge), (6, ipv6_nonce)):
            row = lease.family(family)
            baseline = witness.Challenge(
                facts["root_if"], row["peer_ip"], row["source_port"],
                row["sink_port"], bytes.fromhex(row["baseline_nonce_hex"]))
            challenges.append(witness.Challenge(
                facts["root_if"], row["peer_ip"], row["source_port"],
                row["sink_port"], nonce))
            positives.append(witness.prepare_positive_control(
                lease.sinks[family], baseline, lease.peer_mac))
        lease.verify()

        def grant_check(projection: bytes) -> None:
            need(_no_client_grant(projection), "client_grant_during_deny_witness")

        observed = witness.prove_deny_dual(
            Path("/usr/sbin/nft"), guard_fd, policy["policy_sha256"],
            tuple(challenges), tuple(positives), (lease.sinks[4], lease.sinks[6]),
            rollback.RollbackClient(), lease_verify=lease.verify,
            grant_check=grant_check)
        lease.verify()
        cleaned = lease.cleanup()
        completed_cleanup = True
        need(cleaned == {"state": "CLEAN", "routes_restored": True,
                         "nft_unchanged": True},
             "topology_inverse_not_proven")
        lease.receipts_retained()
        dual = dataclasses.asdict(observed)
        ipv4, ipv6 = dual.pop("ipv4"), dual.pop("ipv6")
        need(_native_family_complete(ipv4, policy, 4, actor_challenge,
                                     dual["foreign_mid_sha256"]),
             "native_witness_incomplete")
        need(_native_family_complete(ipv6, policy, 6, ipv6_nonce,
                                     dual["foreign_mid_sha256"]) and
             ipv4["foreign_projection_sha256"] == ipv6["foreign_projection_sha256"] and
             dual["foreign_before_sha256"] == dual["foreign_mid_sha256"] ==
             dual["foreign_after_sha256"] and
             ipv4["sink_session"] != ipv6["sink_session"] and
             ipv4["trace_sha256"] != ipv6["trace_sha256"],
             "dual_stack_native_witness_incomplete")
        for native in (ipv4, ipv6):
            native["actor_challenge"] = request["actor_challenge"]
            native["topology"] = facts
            native["topology_cleanup"] = cleaned
        ipv4["ipv6_witness"] = ipv6
        ipv4["dual_witness"] = dual
        return ipv4
    finally:
        if not completed_cleanup and not lease.closed:
            # The independent actor also monitors guardian PIDFD and owns a
            # watchdog.  Cleanup refusal keeps the activation unacknowledged.
            lease.cleanup()


def _effect_common(effect: dict[str, object], original: dict[str, object],
                   grant: dict[str, object], stage_id: tuple[int, int]) -> None:
    need(effect.get("schema") == "aegis_auto_guardian_effect_request_v1" and
         effect.get("guardian_nonce") == grant["nonce"] and
         effect.get("mode") == original["mode"] and
         effect.get("private_unit") == original["private_unit"] and
         effect.get("boot_id") == original["boot_id"] and
         effect.get("netns_ino") == original["netns_ino"] and
         (effect.get("stage_dev"), effect.get("stage_ino")) == stage_id and
         effect.get("policy_sha256") == grant["policy_sha256"] and
         effect.get("native_receipt_sha256") ==
         grant["native_receipt_sha256"], "effect_owner_binding_changed")


def _effect_reply_base(effect: dict[str, object]) -> dict[str, object]:
    return {key: effect[key] for key in (
        "guardian_nonce", "mode", "boot_id", "netns_ino",
        "stage_dev", "stage_ino", "policy_sha256", "native_receipt_sha256")}


def _capture_refusal_reply(effect: dict[str, object], error: Exception) -> dict[str, object]:
    """Retain the authenticated owner channel; never serialize exception data."""
    if isinstance(error, Refused):
        reason = "refused"
    elif isinstance(error, TimeoutError):
        reason = "timeout"
    elif isinstance(error, OSError):
        reason = "os_error"
    elif isinstance(error, ValueError):
        reason = "value_error"
    elif isinstance(error, subprocess.SubprocessError):
        reason = "subprocess_error"
    elif isinstance(error, RuntimeError):
        reason = "runtime_error"
    else:
        reason = "unexpected_exception"
    source, line = _pinned_error_location(error, skip_assertion_helper=True)
    return {"schema": "aegis_auto_capture_refused_v1",
            **_effect_reply_base(effect),
            "command": effect["command"],
            "pid1_job_id": effect["pid1_job_id"],
            "pid1_job_path": effect["pid1_job_path"],
            "pid1_unit": effect["pid1_unit"],
            "pid1_invocation_id": effect["pid1_invocation_id"],
            "reason": reason, "source": source, "line": line}


def _capture_request_shape(effect: dict[str, object], original: dict[str, object]) -> None:
    command = effect.get("command")
    needed = {"schema", "command", "guardian_nonce", "mode", "private_unit",
              "boot_id", "netns_ino", "stage_dev", "stage_ino",
              "policy_sha256", "native_receipt_sha256", "pid1_job_id",
              "pid1_job_path", "pid1_invocation_id", "pid1_unit"}
    if command == "CAPTURE_REVALIDATE":
        needed.add("native_capture_sha256")
    need(set(effect) == needed and command in
         ("CAPTURE_READY", "CAPTURE_REVALIDATE") and
         effect.get("pid1_unit") == original["private_unit"] and
         type(effect.get("pid1_job_id")) is int and effect["pid1_job_id"] > 0 and
         type(effect.get("pid1_job_path")) is str and
         re.fullmatch(r"/org/freedesktop/systemd1/job/[1-9][0-9]*",
                      effect["pid1_job_path"]) is not None and
         type(effect.get("pid1_invocation_id")) is str and
         HEX32.fullmatch(effect["pid1_invocation_id"]) is not None,
         "invalid_capture_effect_request")


def _capture_refusal_owner_held(
    request: dict[str, object], guard_fd: int, guard_id: tuple[int, int],
    install_fd: int, stage_fd: int, stage_id: tuple[int, int],
    pidfd: int, watchdog: object, *, allow_registered: bool,
) -> None:
    # A typed refusal is available only while the original owner and the
    # independent recovery actor are still verifiably present. A failed latch
    # may remain REGISTERED; it never counts as a captured effect.
    phase = watchdog.revalidate()["phase"]
    need(_held_guard(guard_fd) == guard_id and
         _held_install(install_fd) and _pid_alive(pidfd) and
         _stage(stage_fd, request, initial=False) == stage_id and
         (phase == "LATCHED" or
          (allow_registered and phase == "REGISTERED")),
         "capture_refusal_owner_lost")


def _private_unit_main_pid(unit: str) -> int:
    need(PRIVATE_UNIT.fullmatch(unit) is not None, "invalid_effect_unit")
    result = subprocess.run(["/usr/bin/systemctl", "show", unit,
                             "-p", "MainPID", "--no-pager"],
                            capture_output=True, timeout=2, check=False,
                            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C",
                                 "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 128,
         "effect_main_pid_unavailable")
    raw = result.stdout.decode("ascii").strip()
    need(re.fullmatch(r"MainPID=[1-9][0-9]*", raw) is not None,
         "effect_main_pid_invalid")
    return int(raw.partition("=")[2])


_CAPTURE_STEPS = frozenset({
    "runtime_admit_begin", "runtime_admit_end", "runtime_proof_begin",
    "runtime_proof_end", "redirect_effect_open", "redirect_proof_begin",
    "redirect_proof_end", "redirect_effect_closed", "qa_effect_open",
    "qa_proof_begin", "qa_proof_end", "qa_effect_closed",
    "native_binding_end", "failure", "cleanup_fault",
    "redirect_await_ready", "redirect_received_ready",
    "redirect_await_observed", "redirect_received_observed",
    "redirect_await_complete", "redirect_received_complete",
    "redirect_await_sink_ready", "redirect_received_sink_ready",
    "redirect_await_sink_complete", "redirect_received_sink_complete",
})


def _capture_nft_diagnostic(step: str) -> None:
    """Retain counters before compensation, without tuples or policy text."""
    if step not in ("redirect_proof_begin", "redirect_proof_failure"):
        return
    # Both inert listings run together; each keeps its 0.5 s bound and both
    # are reaped before this returns, i.e. before the proof's first packet.
    listings = []
    for family, table, chains in (
            ("ip", "aegis_auto_redirect", ("input_gate", "prerouting")),
            ("inet", "aegis_device_guard", ("incoming", "output", "forward", "postroute"))):
        try:
            listings.append((family, table, chains, subprocess.Popen(
                ["/usr/sbin/nft", "--json", "--handle", "list", "table",
                 family, table], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})))
        except BaseException:
            pass
    try:
        for family, table, chains, proc in listings:
            _capture_nft_counters(step, family, table, chains, proc)
    finally:
        for _family, _table, _chains, proc in listings:
            try:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=0.5)
            except BaseException:
                pass


def _capture_nft_counters(step: str, family: str, table: str,
                          chains: tuple[str, ...], proc: subprocess.Popen) -> None:
    try:
        try:
            stdout, _stderr = proc.communicate(timeout=0.5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=0.5)
            return
        if proc.returncode != 0 or not 0 < len(stdout) <= 262144:
            return
        parsed = json.loads(stdout, object_pairs_hook=unique)
        if type(parsed) is not dict or type(parsed.get("nftables")) is not list:
            return
        rows = []
        for item in parsed["nftables"]:
            rule = item.get("rule") if type(item) is dict else None
            if (type(rule) is not dict or rule.get("family") != family or
                    rule.get("table") != table or rule.get("chain") not in chains):
                continue
            handle = rule.get("handle")
            expr = rule.get("expr")
            if type(handle) is not int or not 0 < handle < 2**64 or type(expr) is not list:
                continue
            counts = [e["counter"] for e in expr
                      if type(e) is dict and "counter" in e]
            if len(counts) != 1 or type(counts[0]) is not dict:
                continue
            counter = counts[0]
            if (set(counter) != {"packets", "bytes"} or
                    any(type(v) is not int or not 0 <= v < 2**64
                        for v in counter.values())):
                continue
            rows.append({"chain": rule["chain"], "handle": handle, **counter})
            if len(rows) == 24:
                break
        payload = {"step": step, "table": table, "counters": rows}
        line = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if len(line) <= 3072:
            print("aegis_auto_capture_nft " + line, file=sys.stderr, flush=True)
    except BaseException:
        # These observations never change admission or replace a refusal.
        pass


def _capture_process_diagnostic(pid: int, unit: str | None = None) -> dict[str, object]:
    """Bounded status only; no proc text, cgroup path or executable is logged."""
    result: dict[str, object] = {"pidfd_live": False, "host_netns": False,
                                 "unit_cgroup": False}
    if type(pid) is not int or pid <= 1:
        return result
    descriptor = None
    try:
        descriptor = os.pidfd_open(pid, 0)
        watcher = select.poll()
        watcher.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
        result["pidfd_live"] = not bool(watcher.poll(0))
        result["host_netns"] = (os.stat(f"/proc/{pid}/ns/net").st_ino ==
                                  os.stat("/proc/self/ns/net").st_ino)
        if unit is not None and PRIVATE_UNIT.fullmatch(unit) is not None:
            with open(f"/proc/{pid}/cgroup", "rb", buffering=0) as source:
                result["unit_cgroup"] = (source.read(512) ==
                                         ("0::/system.slice/" + unit + "\n").encode())
        with open(f"/proc/{pid}/status", "rb", buffering=0) as source:
            raw = source.read(16385)
        if len(raw) <= 16384:
            for line in raw.splitlines():
                for field in (b"CapEff", b"CapPrm", b"CapBnd"):
                    prefix = field + b":"
                    if line.startswith(prefix):
                        value = line[len(prefix):].strip()
                        if re.fullmatch(rb"[0-9a-fA-F]{1,16}", value) is not None:
                            result[field.decode("ascii").lower()] = value.decode("ascii").lower()
                if line.startswith(b"NoNewPrivs:"):
                    value = line[len(b"NoNewPrivs:"):].strip()
                    if value in (b"0", b"1"):
                        result["no_new_privs"] = int(value)
    except (OSError, ValueError):
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return result


def _capture_step(step: str, *, mode: str, main_pid: int | None = None,
                  unit: str | None = None, children: object = None,
                  policy_sha256: str | None = None,
                  output_drop_handle: int | None = None,
                  error: BaseException | None = None) -> None:
    """Operational coordinates are fixed or bounded; diagnostic failure is inert."""
    if step not in _CAPTURE_STEPS:
        return
    try:
        payload: dict[str, object] = {"step": step,
                                      "monotonic_ns": time.monotonic_ns(),
                                      "mode": mode if mode in
                                      ("wide-redirect-safe", "full-wide-tun") else "unknown",
                                      "self": _capture_process_diagnostic(os.getpid())}
        if main_pid is not None:
            payload["main"] = _capture_process_diagnostic(main_pid, unit)
        if type(children) is list:
            child_rows = []
            for item in children[:2]:
                if (type(item) is not dict or type(item.get("pid")) is not int or
                        type(item.get("receipt")) is not str):
                    continue
                facts = _capture_process_diagnostic(item["pid"])
                child_rows.append({"live": facts["pidfd_live"],
                                   "host_netns": facts["host_netns"],
                                   "receipt_present": Path(item["receipt"]).is_file(),
                                   **{key: value for key, value in facts.items()
                                      if key in ("capeff", "capprm", "capbnd",
                                                 "no_new_privs")}})
            payload["children"] = child_rows
        if type(policy_sha256) is str and HEX64.fullmatch(policy_sha256):
            payload["policy_sha256"] = policy_sha256
        if type(output_drop_handle) is int and output_drop_handle > 0:
            payload["output_drop_handle"] = output_drop_handle
        if error is not None:
            source, line = _pinned_error_location(error,
                                                  skip_assertion_helper=True)
            payload["error_source"] = source
            payload["error_line"] = line
            payload["error_class"] = _request_refusal_tag(error)
        line = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if len(line) <= 2048:
            print("aegis_auto_capture_step " + line, file=sys.stderr, flush=True)
    except BaseException:
        pass


def _capture_finish_effect(lease: object, *, completed: bool,
                           primary: BaseException | None, mode: str,
                           success_step: str) -> None:
    """Only a proved effect can request CLOSE; failed effects revoke by HUP."""
    try:
        if completed:
            lease.close()
            _capture_step(success_step, mode=mode)
        else:
            lease.abort()
    except BaseException as cleanup_error:
        _capture_step("cleanup_fault", mode=mode, error=cleanup_error)
        if primary is None:
            raise


class _CaptureHeldLease:
    """Keep the original admission/readback order without masking proof failure."""

    def __init__(self, lease: object, mode: str):
        self.lease = lease
        self.mode = mode

    def __enter__(self) -> object:
        try:
            self.lease.revalidate()
            return self.lease
        except BaseException as primary:
            _capture_step("failure", mode=self.mode, error=primary)
            try:
                self.lease.close()
            except BaseException as cleanup_error:
                _capture_step("cleanup_fault", mode=self.mode,
                              error=cleanup_error)
            raise

    def __exit__(self, kind: object, _value: object,
                 _traceback: object) -> None:
        if kind is not None and isinstance(_value, BaseException):
            _capture_step("failure", mode=self.mode, error=_value)
        try:
            self.lease.close()
        except BaseException as cleanup_error:
            _capture_step("cleanup_fault", mode=self.mode,
                          error=cleanup_error)
            if kind is None:
                raise


def _qa_capture_once(*, capture: types.ModuleType,
                     endpoint: types.ModuleType,
                     topology: types.ModuleType,
                     witness: types.ModuleType,
                     original: dict[str, object],
                     effect: dict[str, object],
                     owner: dict[str, object],
                     current: dict[str, object],
                     output_drop_handle: int,
                     installed_main_sha256: str,
                     main_pid: int,
                     runtime_lease: object | None = None,
                     scoped_policy: dict[str, object] | None = None,
                     scoped_verify: object | None = None) -> object:
    """One actual source-owned QA effect, with its own one-shot probe actor."""
    topology_mode = ("FULL_TUN_UDP" if original["mode"] == "full-wide-tun"
                     else "REDIRECT_TCP")
    effect_lease = topology.open_effect(topology_mode, secrets.token_bytes(32))
    minted = False
    completed = False
    primary: BaseException | None = None
    try:
        effect_lease.verify()
        _capture_step("qa_effect_open", mode=original["mode"],
                      main_pid=main_pid, unit=original["private_unit"],
                      children=effect_lease.facts.get("children"))
        # mint returns its own admitted lease still held; _CaptureHeldLease
        # revalidates it (held identity, predicates, content, pidfds, routes)
        # instead of a second by-path admission of the same receipt.
        admitted = endpoint.mint_endpoint_receipt(
            effect_lease=effect_lease,
            unit=original["private_unit"], mode=original["mode"],
            boot_id=original["boot_id"], netns_ino=original["netns_ino"],
            installed_generation=owner["installed_generation_sha256"],
            manifest=owner["installed_manifest_sha256"])
        minted = True
        with _CaptureHeldLease(admitted, original["mode"]):
            common = dict(mode=original["mode"],
                          unit_name=original["private_unit"],
                          boot_id=original["boot_id"],
                          netns_ino=original["netns_ino"],
                          invocation_id=effect["pid1_invocation_id"],
                          main_pid=main_pid,
                          worker_sha256=installed_main_sha256,
                          policy_sha256=current["policy_sha256"],
                          output_drop_handle=output_drop_handle,
                          snapshot_policy=witness.snapshot_policy)
            if original["mode"] == "full-wide-tun":
                need(runtime_lease is None and
                     type(admitted.endpoint) is capture.CaptureEchoEndpoint,
                     "foreign_full_tun_endpoint")
                _capture_step("qa_proof_begin", mode=original["mode"],
                              main_pid=main_pid, unit=original["private_unit"],
                              children=effect_lease.facts.get("children"),
                              policy_sha256=current["policy_sha256"],
                              output_drop_handle=output_drop_handle)
                proof = capture.capture_ready(
                    **common, echo_endpoint=admitted.endpoint,
                    endpoint_lease=admitted)
            else:
                need(type(admitted.endpoint) is capture.RedirectEndpoint,
                     "foreign_redirect_endpoint")
                need(scoped_policy is not None and callable(scoped_verify),
                     "runtime_redirect_scoped_required")
                redirect_policy = scoped_policy["policy_sha256"]
                scoped_args = ({"scoped_policy": scoped_policy,
                                "scoped_verify": scoped_verify}
                               if scoped_policy is not None else {})
                _capture_step("qa_proof_begin", mode=original["mode"],
                              main_pid=main_pid, unit=original["private_unit"],
                              children=effect_lease.facts.get("children"),
                              policy_sha256=current["policy_sha256"],
                              output_drop_handle=output_drop_handle)
                # This is the independent QA sink/probe pair, not the
                # configured runtime endpoint.  Keep its own packet proof and
                # revalidate the runtime lease separately when one is held.
                if runtime_lease is not None:
                    runtime_lease.revalidate()
                proof = capture.capture_redirect_ready(
                    **common,
                    expected_redirect_policy_sha256=redirect_policy,
                    endpoint=admitted.endpoint, endpoint_lease=admitted,
                    phase_callback=lambda phase: _capture_step(
                        phase, mode=original["mode"], main_pid=main_pid,
                        unit=original["private_unit"]),
                    **scoped_args)
        _capture_step("qa_proof_end", mode=original["mode"],
                      main_pid=main_pid, unit=original["private_unit"],
                      children=effect_lease.facts.get("children"))
        completed = True
        return proof
    except BaseException as error:
        primary = error
        _capture_step("failure", mode=original["mode"], main_pid=main_pid,
                      unit=original["private_unit"],
                      children=effect_lease.facts.get("children"), error=error)
        raise
    finally:
        cleanup_failure: BaseException | None = None
        try:
            _capture_finish_effect(effect_lease, completed=completed,
                                   primary=primary, mode=original["mode"],
                                   success_step="qa_effect_closed")
        except BaseException as cleanup_error:
            cleanup_failure = cleanup_error
        if minted:
            try:
                endpoint.retire_endpoint_receipt()
            except BaseException as cleanup_error:
                _capture_step("cleanup_fault", mode=original["mode"],
                              error=cleanup_error)
                if cleanup_failure is None:
                    cleanup_failure = cleanup_error
        if primary is None and cleanup_failure is not None:
            raise cleanup_failure


def _capture_effect(effect: dict[str, object], original: dict[str, object],
                    grant: dict[str, object], guard_fd: int, stage_fd: int,
                    initial_header: dict[str, object],
                    previous: dict[str, object] | None,
                    authenticated_lineage: dict | None = None
                    ) -> tuple[dict[str, object], dict[str, object]]:
    _capture_request_shape(effect, original)
    command = effect["command"]
    if command == "CAPTURE_READY":
        need(previous is None, "capture_already_granted")
    else:
        need(previous is not None and
             effect["native_capture_sha256"] == previous["sha256"] and
             effect["pid1_invocation_id"] ==
             previous["proof"]["invocation_id"],
             "capture_revalidation_identity_changed")
    _held_lock(guard_fd, GUARD_LOCK)
    if previous is None:
        _claimed_private_unit(stage_fd, original, grant,
                              original["private_unit"])
    else:
        _capture_stage_successor(stage_fd, initial_header, original,
                                 grant, previous)
    need(not STOP_INTENT.exists() and not STOP_INTENT.is_symlink(),
         "capture_during_stop")
    current = _policy(original, _held_lock(guard_fd, GUARD_LOCK))
    witness = verified_module(WITNESS, "aegis_auto_native_witness")
    capture = verified_module(CAPTURE_SOURCE, "aegis_auto_capture")
    endpoint = verified_module(ENDPOINT_SOURCE, "aegis_auto_endpoint")
    projection, handles, _counters = witness.snapshot_policy(
        Path("/usr/sbin/nft"))
    need(digest(projection) == current["policy_sha256"],
         "capture_policy_changed_before_effect")
    owner = json.loads(_stage_leaf(stage_fd,
                                   "activation-owner-may-send-v3.json"),
                       object_pairs_hook=unique)["commitments"]
    installed_main_sha256 = _installed_main_digest(stage_fd, original)
    main_pid = _private_unit_main_pid(original["private_unit"])
    if original["mode"] == "full-wide-tun" and previous is None:
        capture_module = verified_module(CAPTURE_SOURCE, "aegis_auto_capture")
        need(not CAPTURE_BINDING.exists() and not CAPTURE_BINDING.is_symlink(),
             "capture_binding_preexists")
        pidfd = os.pidfd_open(main_pid, 0)
        assessment_fd = None
        try:
            capture_module._pidfd_identity(pidfd, main_pid)
            facts = capture_module._service(original["private_unit"])
            need(facts["ActiveState"] == "active" and
                 facts["SubState"] == "running" and
                 facts["MainPID"] == str(main_pid) and
                 facts["InvocationID"] == effect["pid1_invocation_id"] and
                 facts["ControlPID"] == "0", "capture_grant_pid1_changed")
            capture_module._pid_live(
                main_pid, installed_main_sha256,
                capture_module._cgroup(original["private_unit"]))
            capture_module._tun_owned_by_pid(main_pid)
            ifindex, _state = capture_module._link()
            need(Path(f"/proc/{main_pid}/ns/net").stat().st_ino ==
                 original["netns_ino"] and
                 socket.if_nametoindex("aegis-tun0") == ifindex and
                 not select.select([pidfd], [], [], 0)[0],
                 "capture_grant_link_or_worker_changed")
            client = record(Path(str(GUARD_STATE) + ".client-binding"), 4096)
            need(client["path"] == "system.slice/" + original["private_unit"] and
                 client["invocation"] == effect["pid1_invocation_id"],
                 "capture_grant_client_binding_changed")
            assessment_fd = _stop_assessment_reservation(guard_fd)
            _publish_guard_binding(CAPTURE_BINDING, {
                "schema": "aegis_device_guard_capture_binding_v1",
                "boot_id": original["boot_id"],
                "netns_ino": original["netns_ino"],
                "private_unit": original["private_unit"],
                "invocation_id": effect["pid1_invocation_id"],
                "main_pid": main_pid, "ifindex": ifindex,
                "worker_sha256": installed_main_sha256,
                "client_path": client["path"],
                "client_inode": client["inode"],
                "client_invocation": client["invocation"],
            })
            need(capture_binding_index(guard_fd) == ifindex and
                 not select.select([pidfd], [], [], 0)[0],
                 "capture_grant_owner_changed_before_batch")
            _run_helper_in_cgroup(GUARD_HELPER, "capture-bind", guard_fd)
            current = _policy(original, _held_lock(guard_fd, GUARD_LOCK))
            projection, handles, _counters = witness.snapshot_policy(
                Path("/usr/sbin/nft"))
            need(digest(projection) == current["policy_sha256"] and
                 capture_binding_index(guard_fd) == ifindex,
                 "capture_grant_semantic_readback_changed")
        except BaseException:
            _run_helper_in_cgroup(GUARD_HELPER, "block", guard_fd)
            raise
        finally:
            if assessment_fd is not None:
                os.close(assessment_fd)
            os.close(pidfd)
    elif original["mode"] == "full-wide-tun":
        need(capture_binding_index(guard_fd) ==
             previous["proof"]["tun_ifindex"],
             "capture_revalidation_ifindex_changed")
    qa_present = endpoint.qa_relay_receipt_present()
    _capture_step("runtime_admit_begin", mode=original["mode"],
                  main_pid=main_pid, unit=original["private_unit"],
                  policy_sha256=current["policy_sha256"],
                  output_drop_handle=handles["output"])
    runtime = endpoint.admit_runtime_endpoint(
        stage_fd=stage_fd, unit=original["private_unit"],
        mode=original["mode"],
        transaction_nonce=original["transaction_nonce"],
        planned_generation=original["planned_generation"])
    _capture_step("runtime_admit_end", mode=original["mode"],
                  main_pid=main_pid, unit=original["private_unit"])
    with _CaptureHeldLease(runtime, original["mode"]):
        local_ipv4_proof = None
        if original["mode"] == "full-wide-tun":
            _capture_step("runtime_proof_begin", mode=original["mode"],
                          main_pid=main_pid, unit=original["private_unit"])
            proof = capture.capture_runtime_ready(
                mode=original["mode"], unit_name=original["private_unit"],
                boot_id=original["boot_id"], netns_ino=original["netns_ino"],
                invocation_id=effect["pid1_invocation_id"], main_pid=main_pid,
                worker_sha256=installed_main_sha256,
                policy_sha256=current["policy_sha256"],
                output_drop_handle=handles["output"],
                snapshot_policy=witness.snapshot_policy,
                endpoint_lease=runtime)
            _capture_step("runtime_proof_end", mode=original["mode"],
                          main_pid=main_pid, unit=original["private_unit"])
            local_binding = _local_owner_binding(
                stage_fd, original, grant["policy_sha256"],
                current_policy_sha256=current["policy_sha256"],
                authenticated_lineage=
                authenticated_lineage, phase='capture')
            if local_binding is not None:
                need(local_binding["profile"] == "full_wide_tun",
                     "fulltun_local_profile_changed")
                redirect = verified_module(POLICY_SOURCE,
                                           "aegis_auto_guard_policy")
                if previous is None:
                    local_policy = redirect.local_activate(
                        local_binding, effect["pid1_invocation_id"])
                else:
                    local_policy = redirect.local_verify(
                        local_binding, effect["pid1_invocation_id"],
                        config_semantic_sha256=local_binding[
                            "config_semantic_sha256"])

                def verify_fulltun_local() -> dict[str, object]:
                    need(_local_owner_binding(stage_fd, original,
                                              grant["policy_sha256"],
                                              current_policy_sha256=current["policy_sha256"],
                                              authenticated_lineage=
                                              authenticated_lineage,
                                              phase='capture') ==
                         local_binding, "fulltun_local_owner_changed")
                    return redirect.local_verify(
                        local_binding, effect["pid1_invocation_id"],
                        config_semantic_sha256=local_binding[
                            "config_semantic_sha256"])

                def fulltun_local_counters() -> dict[str, int]:
                    verify_fulltun_local()
                    return redirect.local_counters(
                        local_binding, effect["pid1_invocation_id"])

                local_ipv4_proof = capture.capture_runtime_local_redirect_ready(
                    mode=original["mode"], unit_name=original["private_unit"],
                    boot_id=original["boot_id"], netns_ino=original["netns_ino"],
                    invocation_id=effect["pid1_invocation_id"],
                    main_pid=main_pid, worker_sha256=installed_main_sha256,
                    policy_sha256=current["policy_sha256"],
                    output_drop_handle=handles["output"],
                    snapshot_policy=witness.snapshot_policy,
                    runtime_lease=runtime, local_policy=local_policy,
                    local_verify=verify_fulltun_local,
                    local_counters=fulltun_local_counters)
        else:
            scoped_policy = None
            verify_scoped = None
            if runtime.redirect_rollout_profile == "output_only_safe":
                need(not qa_present, "local_redirect_qa_receipt_unexpected")
                local_binding = _local_owner_binding(
                    stage_fd, original, grant["policy_sha256"],
                    current_policy_sha256=current["policy_sha256"],
                    authenticated_lineage=
                    authenticated_lineage, phase='capture')
                need(local_binding is not None and
                     _scoped_owner_binding(stage_fd, original,
                                           grant["policy_sha256"]) is None,
                     "runtime_redirect_local_owner_required")
                redirect = verified_module(POLICY_SOURCE,
                                           "aegis_auto_guard_policy")
                if previous is None:
                    local_policy = redirect.local_activate(
                        local_binding, effect["pid1_invocation_id"])
                else:
                    local_policy = redirect.local_verify(
                        local_binding, effect["pid1_invocation_id"],
                        config_semantic_sha256=local_binding[
                            "config_semantic_sha256"])

                def verify_local() -> dict[str, object]:
                    need(_local_owner_binding(stage_fd, original,
                                              grant["policy_sha256"],
                                              current_policy_sha256=current["policy_sha256"],
                                              authenticated_lineage=
                                              authenticated_lineage,
                                              phase='capture') ==
                         local_binding,
                         "local capture owner changed")
                    return redirect.local_verify(
                        local_binding, effect["pid1_invocation_id"],
                        config_semantic_sha256=local_binding[
                            "config_semantic_sha256"])

                def local_counters() -> dict[str, int]:
                    verify_local()
                    return redirect.local_counters(
                        local_binding, effect["pid1_invocation_id"])

                _capture_step("redirect_proof_begin", mode=original["mode"],
                              main_pid=main_pid, unit=original["private_unit"],
                              policy_sha256=current["policy_sha256"],
                              output_drop_handle=handles["output"])
                proof = capture.capture_runtime_local_redirect_ready(
                    mode=original["mode"], unit_name=original["private_unit"],
                    boot_id=original["boot_id"], netns_ino=original["netns_ino"],
                    invocation_id=effect["pid1_invocation_id"],
                    main_pid=main_pid, worker_sha256=installed_main_sha256,
                    policy_sha256=current["policy_sha256"],
                    output_drop_handle=handles["output"],
                    snapshot_policy=witness.snapshot_policy,
                    runtime_lease=runtime, local_policy=local_policy,
                    local_verify=verify_local, local_counters=local_counters)
                _capture_step("redirect_proof_end", mode=original["mode"],
                              main_pid=main_pid, unit=original["private_unit"])
            elif runtime.redirect_rollout_profile == "prerouting_scoped":
                scoped_binding = _scoped_owner_binding(
                    stage_fd, original, grant["policy_sha256"])
                need(scoped_binding is not None,
                     "runtime_redirect_scoped_required")
                need(scoped_binding["interface"] == runtime.redirect_ingress_ifname,
                     "scoped_ingress_runtime_interface_changed")
                _scoped_route_refusal(scoped_binding["interface"],
                                      current["state_sha256"],
                                      runtime.configured_relay_pool)
                scoped_policy = None
                if scoped_binding is not None:
                    redirect = verified_module(POLICY_SOURCE,
                                               "aegis_auto_guard_policy")
                    if previous is None:
                        scoped_policy = redirect.scoped_activate(
                            scoped_binding, effect["pid1_invocation_id"])
                    else:
                        scoped_policy = redirect.scoped_verify(
                            scoped_binding, effect["pid1_invocation_id"],
                            config_semantic_sha256=scoped_binding[
                                "config_semantic_sha256"], active=True)

                def verify_scoped() -> dict[str, object]:
                    need(scoped_binding is not None and
                         _scoped_owner_binding(stage_fd, original,
                                               grant["policy_sha256"]) ==
                         scoped_binding,
                         "scoped capture owner changed")
                    return redirect.scoped_verify(
                        scoped_binding, effect["pid1_invocation_id"],
                        config_semantic_sha256=scoped_binding[
                            "config_semantic_sha256"], active=True)

                scoped_args = ({"scoped_policy": scoped_policy,
                                "scoped_verify": verify_scoped}
                               if scoped_policy is not None else {})
                topology = verified_module(CAPTURE_TOPOLOGY_SOURCE,
                                           "aegis_auto_capture_topology")
                ingress = topology.open_effect("REDIRECT_PROBE_TCP",
                                               secrets.token_bytes(32))
                _capture_step("redirect_effect_open", mode=original["mode"],
                              main_pid=main_pid, unit=original["private_unit"],
                              children=ingress.facts.get("children"))
                complete = False
                primary: BaseException | None = None
                try:
                    probe = endpoint.admit_runtime_redirect_probe(
                        ingress, runtime, topology)
                    need(scoped_policy is not None,
                         "runtime_redirect_scoped_required")
                    redirect_policy = scoped_policy["policy_sha256"]
                    _capture_step("redirect_proof_begin", mode=original["mode"],
                                  main_pid=main_pid, unit=original["private_unit"],
                                  children=ingress.facts.get("children"),
                                  policy_sha256=current["policy_sha256"],
                                  output_drop_handle=handles["output"])
                    _capture_nft_diagnostic("redirect_proof_begin")
                    proof = capture.capture_runtime_redirect_ready(
                        mode=original["mode"], unit_name=original["private_unit"],
                        boot_id=original["boot_id"],
                        netns_ino=original["netns_ino"],
                        invocation_id=effect["pid1_invocation_id"],
                        main_pid=main_pid,
                        worker_sha256=installed_main_sha256,
                        policy_sha256=current["policy_sha256"],
                        expected_redirect_policy_sha256=redirect_policy,
                        output_drop_handle=handles["output"],
                        snapshot_policy=witness.snapshot_policy,
                        endpoint=probe, effect_lease=ingress,
                        runtime_lease=runtime,
                        phase_callback=lambda phase: _capture_step(
                            phase, mode=original["mode"], main_pid=main_pid,
                            unit=original["private_unit"]), **scoped_args)
                    _capture_step("redirect_proof_end", mode=original["mode"],
                                  main_pid=main_pid, unit=original["private_unit"],
                                  children=ingress.facts.get("children"))
                    complete = True
                except BaseException as error:
                    primary = error
                    _capture_nft_diagnostic("redirect_proof_failure")
                    _capture_step("failure", mode=original["mode"],
                                  main_pid=main_pid, unit=original["private_unit"],
                                  children=ingress.facts.get("children"), error=error)
                    raise
                finally:
                    _capture_finish_effect(ingress, completed=complete,
                                           primary=primary, mode=original["mode"],
                                           success_step="redirect_effect_closed")
            else:
                need(False, "runtime_redirect_profile_invalid")
        native = dataclasses.asdict(proof)
        if local_ipv4_proof is not None:
            native["schema"] = "aegis_auto_runtime_fulltun_local_ready_v1"
            native["local_ipv4"] = dataclasses.asdict(local_ipv4_proof)
        if qa_present:
            topology = verified_module(CAPTURE_TOPOLOGY_SOURCE,
                                       "aegis_auto_capture_topology")
            qa_proof = _qa_capture_once(
                capture=capture, endpoint=endpoint, topology=topology,
                witness=witness, original=original, effect=effect,
                owner=owner, current=current,
                output_drop_handle=handles["output"],
                installed_main_sha256=installed_main_sha256,
                main_pid=main_pid,
                scoped_policy=(scoped_policy if original["mode"] ==
                               "wide-redirect-safe" else None),
                scoped_verify=(verify_scoped if original["mode"] ==
                               "wide-redirect-safe" and scoped_policy is not None
                               else None))
            need(qa_proof.unit_name == proof.unit_name and
                 qa_proof.invocation_id == proof.invocation_id and
                 qa_proof.main_pid == proof.main_pid and
                 qa_proof.guard_policy_sha256 == proof.guard_policy_sha256,
                 "qa_capture_not_bound_to_runtime")
            native["qa_external_capture"] = dataclasses.asdict(qa_proof)
    need(_policy(original, _held_lock(guard_fd, GUARD_LOCK))[
        "policy_sha256"] == current["policy_sha256"],
        "capture_policy_semantics_changed_after_traffic")
    need(native["unit_name"] == original["private_unit"] and
         native["invocation_id"] == effect["pid1_invocation_id"] and
         native["guard_policy_sha256"] == current["policy_sha256"],
         "capture_native_binding_changed")
    _capture_step("native_binding_end", mode=original["mode"],
                  main_pid=main_pid, unit=original["private_unit"],
                  policy_sha256=current["policy_sha256"],
                  output_drop_handle=handles["output"])
    native_sha = digest(json.dumps(native, sort_keys=True,
                                   separators=(",", ":")).encode())
    if previous is not None:
        # A new independent packet proves continued effect.  The original
        # capture identity remains stable for the owner's terminal receipt.
        need(native["main_pid"] == previous["proof"]["main_pid"] and
             native["guard_policy_sha256"] ==
             previous["post_policy_sha256"],
             "capture_revalidation_changed")
        if original["mode"] == "full-wide-tun":
            now_relay = native["runtime_echo"]
            prior_relay = previous["proof"]["runtime_echo"]
            need(("local_ipv4" in native) ==
                 ("local_ipv4" in previous["proof"]),
                 "fulltun_local_revalidation_scope_changed")
            if "local_ipv4" in native:
                need(all(native["local_ipv4"][key] ==
                         previous["proof"]["local_ipv4"][key]
                         for key in ("redirect_policy_sha256",
                                     "configured_relay_pool_sha256",
                                     "auth_profile", "credential_lineage_sha256")),
                     "fulltun_local_revalidation_changed")
        else:
            now_relay = native
            prior_relay = previous["proof"]
        need(all(now_relay[key] == prior_relay[key]
                 for key in ("configured_relay_pool_sha256", "auth_profile",
                             "credential_lineage_sha256")),
             "capture_revalidation_relay_changed")
        retained = previous
        native_sha = previous["sha256"]
    else:
        retained = {"proof": native, "sha256": native_sha,
                    "post_policy_sha256": current["policy_sha256"]}
    reply = {"schema": "aegis_auto_capture_ready_v1" if previous is None else
             "aegis_auto_capture_revalidated_v1",
             **_effect_reply_base(effect),
             "pid1_job_id": effect["pid1_job_id"],
             "pid1_job_path": effect["pid1_job_path"],
             "pid1_invocation_id": effect["pid1_invocation_id"],
             "pid1_unit": effect["pid1_unit"],
             "native_capture_sha256": native_sha}
    return retained, reply


def _post_stop_inverse(effect: dict[str, object], original: dict[str, object],
                       grant: dict[str, object], guard_fd: int, stage_fd: int,
                       captured: dict[str, object] | None) -> dict[str, object]:
    needed = {"schema", "command", "guardian_nonce", "mode", "private_unit",
              "boot_id", "netns_ino", "stage_dev", "stage_ino",
              "policy_sha256", "native_receipt_sha256",
              "prior_invocation_id", "stop_job_id", "stop_job_path",
              "stop_unit", "native_capture_sha256"}
    need(set(effect) == needed and
         effect["command"] == "COMPENSATED_STOP" and
         effect["stop_unit"] == original["private_unit"] and
         type(effect["prior_invocation_id"]) is str and
         HEX32.fullmatch(effect["prior_invocation_id"]) is not None and
         type(effect["stop_job_id"]) is int and effect["stop_job_id"] > 0 and
         type(effect["stop_job_path"]) is str and
         re.fullmatch(r"/org/freedesktop/systemd1/job/[1-9][0-9]*",
                      effect["stop_job_path"]) is not None,
         "invalid_compensated_stop_request")
    _held_lock(guard_fd, GUARD_LOCK)
    _inverse_stage_successor(stage_fd, original, grant, effect)
    intent = record(STOP_INTENT)
    need(intent == {"schema": "aegis_auto_stop_intent_v1",
                    "boot_id": original["boot_id"],
                    "invocation_id": effect["prior_invocation_id"],
                    "service": original["private_unit"],
                    "phase": "deny_proven"}, "stop_intent_not_proven")
    witness = verified_module(WITNESS, "aegis_auto_native_witness")
    capture = verified_module(CAPTURE_SOURCE, "aegis_auto_capture")
    current = _policy(original, _held_lock(guard_fd, GUARD_LOCK))
    projection, handles, _counters = _semantic_policy_snapshot()
    need(digest(projection) == current["policy_sha256"] and
         _no_client_grant(projection), "post_stop_guard_not_denied")
    if original["mode"] in ("wide-redirect-safe", "full-wide-tun"):
        # Post-deny table retirement is an nft writer even when this caller
        # retains the original GuardLock OFD. Serialize it with the monitor's
        # complete foreign-policy snapshots through the existing sidecar.
        assessment_fd = _stop_assessment_reservation(guard_fd)
        try:
            _scoped_retire_after_stop(stage_fd, original["private_unit"],
                                      grant["policy_sha256"], guard_fd)
            _local_retire_after_stop(stage_fd, original["private_unit"],
                                     grant["policy_sha256"], guard_fd)
            _held_lock(assessment_fd, ASSESSMENT_LOCK)
        finally:
            os.close(assessment_fd)
    prior = effect["native_capture_sha256"]
    if captured is None:
        need(prior is None, "foreign_prior_capture_receipt")
        proof = capture.capture_absent_after_stop(
            mode=original["mode"], unit_name=original["private_unit"],
            boot_id=original["boot_id"], netns_ino=original["netns_ino"],
            prior_invocation_id=effect["prior_invocation_id"],
            policy_sha256=current["policy_sha256"],
            output_drop_handle=handles["output"],
            snapshot_policy=_semantic_capture_snapshot)
    else:
        need(type(prior) is str and HEX64.fullmatch(prior) is not None and
             prior == captured["sha256"] and
             captured["proof"]["invocation_id"] ==
             effect["prior_invocation_id"], "prior_capture_changed")
        facts = captured["proof"]
        if original["mode"] == "full-wide-tun":
            proof = capture.capture_inverse(
                mode=original["mode"], unit_name=original["private_unit"],
                boot_id=original["boot_id"], netns_ino=original["netns_ino"],
                prior_invocation_id=effect["prior_invocation_id"],
                prior_tun_ifindex=facts["tun_ifindex"],
                prior_capture_routes=tuple(facts["routes"]),
                policy_sha256=current["policy_sha256"],
                output_drop_handle=handles["output"],
                snapshot_policy=_semantic_capture_snapshot)
        elif facts["schema"] == "aegis_auto_runtime_local_redirect_ready_v1":
            proof = capture.capture_local_redirect_inverse(
                mode=original["mode"], unit_name=original["private_unit"],
                boot_id=original["boot_id"], netns_ino=original["netns_ino"],
                prior_invocation_id=effect["prior_invocation_id"],
                prior_redirect_policy_sha256=facts["redirect_policy_sha256"],
                prior_output_chain_handle=facts["output_chain_handle"],
                prior_tcp_redirect_handle=facts["tcp_redirect_handle"],
                prior_dns_redirect_handle=facts["dns_redirect_handle"],
                policy_sha256=current["policy_sha256"],
                output_drop_handle=handles["output"],
                snapshot_policy=_semantic_capture_snapshot)
        else:
            proof = capture.capture_redirect_inverse(
                mode=original["mode"], unit_name=original["private_unit"],
                boot_id=original["boot_id"], netns_ino=original["netns_ino"],
                prior_invocation_id=effect["prior_invocation_id"],
                prior_redirect_policy_sha256=facts["redirect_policy_sha256"],
                prior_prerouting_chain_handle=facts[
                    "prerouting_chain_handle"],
                prior_redirect_handle=facts["redirect_handle"],
                policy_sha256=current["policy_sha256"],
                output_drop_handle=handles["output"],
                snapshot_policy=_semantic_capture_snapshot)
    raw = json.dumps(dataclasses.asdict(proof), sort_keys=True,
                     separators=(",", ":")).encode()
    need(_policy(original, _held_lock(guard_fd, GUARD_LOCK))[
        "policy_sha256"] == current["policy_sha256"],
        "inverse_policy_semantics_changed")
    if original["mode"] == "full-wide-tun" and MAIN_BINDING.exists():
        need(record(MAIN_BINDING, 4096)["private_unit"] == original["private_unit"],
             "inverse_main_binding_owner_changed")
        _remove_guard_binding(MAIN_BINDING)
    return {"schema": "aegis_auto_capture_inverse_v1",
            "guardian_nonce": effect["guardian_nonce"],
            "mode": effect["mode"], "boot_id": effect["boot_id"],
            "netns_ino": effect["netns_ino"],
            "stage_dev": effect["stage_dev"],
            "stage_ino": effect["stage_ino"],
            "prior_invocation_id": effect["prior_invocation_id"],
            "stop_job_id": effect["stop_job_id"],
            "stop_job_path": effect["stop_job_path"],
            "stop_unit": effect["stop_unit"],
            "post_deny_policy_sha256": current["policy_sha256"],
            "native_inverse_sha256": digest(raw)}


def _complete_compensated_inverse(effect: dict[str, object],
                                  original: dict[str, object],
                                  grant: dict[str, object],
                                  inverse: dict[str, object], guard_fd: int,
                                  stage_fd: int) -> None:
    guard_id = _held_lock(guard_fd, GUARD_LOCK)
    stage = os.fstat(stage_fd)
    need((stage.st_dev, stage.st_ino) ==
         (effect["stage_dev"], effect["stage_ino"]),
         "compensated_stage_changed")
    raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/terminal.json")
    terminal = json.loads(raw, object_pairs_hook=unique)
    header = json.loads(_protected_stage_receipt_for_header(stage_fd),
                        object_pairs_hook=unique)
    leaves = header.get("leaves")
    need(type(leaves) is dict and
         leaves.get("receipts/activation-owner/terminal.json") == digest(raw),
         "compensated_original_terminal_not_sealed")
    if terminal.get("outcome") == "finalized":
        archive_raw = _protected_stage_receipt(
            stage_fd, "receipts/activation-owner/marker-archive.json")
        intent_raw = _stage_leaf(
            stage_fd, "activation-owner-postterminal-stop.json")
        recovery_raw = _protected_stage_receipt(
            stage_fd, "receipts/activation-owner/postterminal-compensated.json")
        intent = json.loads(intent_raw, object_pairs_hook=unique)
        recovery = json.loads(recovery_raw, object_pairs_hook=unique)
        submitted_raw = _protected_stage_receipt(
            stage_fd, "receipts/activation-owner/stop-submitted.json")
        completed_raw = _protected_stage_receipt(
            stage_fd, "receipts/activation-owner/stop-completed.json")
        need(terminal.get("schema") == 1 and
             terminal.get("stage") == [stage.st_dev, stage.st_ino] and
             terminal.get("private_unit") == original["private_unit"] and
             terminal.get("native_guard") ==
             {"guardian_pid": grant["pid"],
              "guardian_nonce": grant["nonce"],
              "guardian_receipt_sha256": grant["native_receipt_sha256"],
              "policy_sha256": grant["policy_sha256"]} and
             leaves.get("receipts/activation-owner/marker-archive.json") ==
             digest(archive_raw) and
             intent == {"schema": 1, "kind": "postterminal-stop-intent",
                        "stage": [stage.st_dev, stage.st_ino],
                        "terminal_sha256": digest(raw),
                        "marker_archive_sha256": digest(archive_raw),
                        "may_send_sha256": terminal.get("may_send_sha256"),
                        "claim_sha256": terminal.get("claim_sha256"),
                        "private_unit": original["private_unit"]} and
             recovery == {
                 "schema": 1, "outcome": "postterminal-compensated",
                 "transaction_nonce": original["transaction_nonce"],
                 "stage": [stage.st_dev, stage.st_ino],
                 "private_unit": original["private_unit"],
                 "terminal_sha256": digest(raw),
                 "marker_archive_sha256": digest(archive_raw),
                 "stop_intent_sha256": digest(intent_raw),
                 "stop_submitted_sha256": digest(submitted_raw),
                 "stop_completed_sha256": digest(completed_raw),
                 "native_inverse_sha256": inverse["native_inverse_sha256"],
                 "post_deny_policy_sha256": inverse["post_deny_policy_sha256"]} and
             header.get("phase") == "native_recovery_required" and
             leaves.get("receipts/activation-owner/stop-submitted.json") ==
             digest(submitted_raw) and
             leaves.get("receipts/activation-owner/stop-completed.json") ==
             digest(completed_raw) and
             leaves.get(
                 "receipts/activation-owner/postterminal-compensated.json") ==
             digest(recovery_raw), "postterminal_inverse_not_committed")
    else:
        need(terminal.get("schema") == 1 and
             terminal.get("outcome") == "compensated-failure" and
             terminal.get("stage") == [stage.st_dev, stage.st_ino] and
             terminal.get("private_unit") == original["private_unit"] and
             terminal.get("native_capture_sha256") is None and
             terminal.get("native_inverse_sha256") ==
             inverse["native_inverse_sha256"] and
             terminal.get("post_deny_policy_sha256") ==
             inverse["post_deny_policy_sha256"] and
             header.get("phase") == "metadata", 
             "compensated_terminal_not_persisted")
    policy = _policy(original, guard_id)
    witness = verified_module(WITNESS, "aegis_auto_native_witness")
    projection, handles, _counters = _semantic_policy_snapshot()
    need(policy["policy_sha256"] == inverse["post_deny_policy_sha256"] ==
         digest(projection) and _no_client_grant(projection),
         "compensated_deny_not_retained")
    capture = verified_module(CAPTURE_SOURCE, "aegis_auto_capture")
    capture.capture_absent_after_stop(
        mode=original["mode"], unit_name=original["private_unit"],
        boot_id=original["boot_id"], netns_ino=original["netns_ino"],
        prior_invocation_id=effect["prior_invocation_id"],
        policy_sha256=policy["policy_sha256"],
        output_drop_handle=handles["output"],
        snapshot_policy=_semantic_capture_snapshot)
    need(_policy(original, guard_id)["policy_sha256"] ==
         policy["policy_sha256"], "compensated_semantics_changed")
    need(record(STOP_INTENT) ==
         {"schema": "aegis_auto_stop_intent_v1",
          "boot_id": original["boot_id"],
          "invocation_id": effect["prior_invocation_id"],
          "service": original["private_unit"], "phase": "deny_proven"},
         "compensated_stop_intent_changed")
    STOP_INTENT.unlink()
    parent = os.open(STOP_INTENT.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _finalized_commit(request: dict[str, object], grant: dict[str, object],
                      captured: dict[str, object], stage_fd: int,
                      guard_fd: int, *, handoff_present: bool) -> None:
    stage = os.fstat(stage_fd)
    for marker in ("activation-owner-may-send-v3.json",
                   "activation-owner-claim-v3.json"):
        try:
            os.stat(marker, dir_fd=stage_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("owner_marker_not_retired")
    raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/terminal.json")
    terminal = json.loads(raw, object_pairs_hook=unique)
    need(terminal.get("schema") == 1 and
         terminal.get("outcome") == "finalized" and
         terminal.get("private_unit") == request["private_unit"] and
         terminal.get("stage") == [stage.st_dev, stage.st_ino] and
         terminal.get("native_capture_sha256") == captured["sha256"] and
         terminal.get("native_guard") ==
         {"guardian_pid": grant["pid"],
          "guardian_nonce": grant["nonce"],
          "guardian_receipt_sha256": grant["native_receipt_sha256"],
          "policy_sha256": grant["policy_sha256"]},
         "finalized_terminal_not_committed")
    header = json.loads(_protected_stage_receipt_for_header(stage_fd),
                        object_pairs_hook=unique)
    need(header.get("phase") == "finalized" and
         type(header.get("leaves")) is dict and
         header["leaves"].get(
             "receipts/activation-owner/terminal.json") == digest(raw),
         "finalized_header_not_committed")
    archive_raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/marker-archive.json")
    archive = json.loads(archive_raw, object_pairs_hook=unique)
    need(type(archive) is dict and
         set(archive) == {"schema", "may_send_hex", "claim_hex",
                          "may_send_sha256", "claim_sha256"} and
         archive["schema"] == 1 and
         type(archive["may_send_hex"]) is str and
         type(archive["claim_hex"]) is str and
         type(archive["may_send_sha256"]) is str and
         type(archive["claim_sha256"]) is str and
         HEX64.fullmatch(archive["may_send_sha256"]) is not None and
         HEX64.fullmatch(archive["claim_sha256"]) is not None and
         digest(bytes.fromhex(archive["may_send_hex"])) ==
         archive["may_send_sha256"] == terminal.get("may_send_sha256") and
         digest(bytes.fromhex(archive["claim_hex"])) ==
         archive["claim_sha256"] == terminal.get("claim_sha256") and
         digest(archive_raw) == terminal.get("marker_archive_sha256") ==
         header["leaves"].get(
             "receipts/activation-owner/marker-archive.json"),
         "finalized_marker_archive_not_committed")
    if handoff_present:
        handoff = json.loads(_stage_leaf(
            stage_fd, "activation-owner-terminal-handoff.json"),
            object_pairs_hook=unique)
        need(handoff == {
            "schema": 1, "kind": "terminal-guardian-handoff",
            "stage": [stage.st_dev, stage.st_ino],
            "private_unit": request["private_unit"],
            "terminal_sha256": digest(raw),
            "marker_archive_sha256": digest(archive_raw),
            "may_send_sha256": archive["may_send_sha256"],
            "claim_sha256": archive["claim_sha256"]},
            "finalized_guardian_handoff_not_committed")
    else:
        try:
            os.stat("activation-owner-terminal-handoff.json",
                    dir_fd=stage_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("finalized_handoff_not_cleared")
    policy = _policy(request, _held_lock(guard_fd, GUARD_LOCK))
    need(policy["policy_sha256"] == captured["post_policy_sha256"],
         "finalized_policy_changed")


def _fresh_stop_inverse(request: dict[str, object], stage_fd: int,
                        install_fd: int, guard_fd: int) -> dict[str, object]:
    """Prove a finalized stop from protected receipts and a live kernel state."""
    keys = {"schema", "command", "actor_challenge", "mode", "boot_id",
            "netns_ino", "stage_dev", "stage_ino", "unit",
            "original_guardian_pid", "original_guardian_nonce",
            "original_guardian_receipt_sha256", "original_guardian_policy_sha256",
            "original_terminal_sha256", "native_capture_sha256",
            "stop_intent_sha256", "stop_submitted_sha256",
            "stop_completed_sha256", "prior_invocation_id", "stop_job_id",
            "stop_job_path", "installed_generation_sha256",
            "installed_manifest_sha256", "policy_generation"}
    need(set(request) == keys and
         request["schema"] == "aegis_auto_guardian_stop_inverse_request_v1" and
         request["command"] == "STOP_INVERSE" and
         request["mode"] in ("full-wide-tun", "wide-redirect-safe") and
         type(request["unit"]) is str and PRIVATE_UNIT.fullmatch(request["unit"]) and
         type(request["actor_challenge"]) is str and
         HEX64.fullmatch(request["actor_challenge"]) and
         type(request["prior_invocation_id"]) is str and
         HEX32.fullmatch(request["prior_invocation_id"]) and
         type(request["native_capture_sha256"]) is str and
         HEX64.fullmatch(request["native_capture_sha256"]) and
         type(request["stop_job_id"]) is int and request["stop_job_id"] > 0 and
         request["stop_job_path"] ==
         f'/org/freedesktop/systemd1/job/{request["stop_job_id"]}' and
         all(type(request[name]) is str and HEX64.fullmatch(request[name])
             for name in ("original_guardian_nonce",
                          "original_guardian_receipt_sha256",
                          "original_guardian_policy_sha256",
                          "original_terminal_sha256", "stop_intent_sha256",
                          "stop_submitted_sha256", "stop_completed_sha256",
                          "installed_generation_sha256",
                          "installed_manifest_sha256", "policy_generation")),
         "invalid_fresh_inverse_request")
    stage = os.fstat(stage_fd)
    need((stage.st_dev, stage.st_ino) ==
         (request["stage_dev"], request["stage_ino"]) and
         stat.S_ISDIR(stage.st_mode) and stage.st_uid == 0,
         "fresh_inverse_stage_changed")
    _held_install(install_fd)
    guard_id = _held_lock(guard_fd, GUARD_LOCK)
    anchor = host_anchor()
    need(request["boot_id"] == anchor["boot_id"] and
         request["netns_ino"] == anchor["netns_ino"] and
         record(INSTALL)["installation_anchor"] == installation_anchor(),
         "fresh_inverse_host_changed")
    path_map = {
        "original_terminal_sha256": "receipts/activation-owner/terminal.json",
        "stop_intent_sha256": "activation-owner-deactivation-intent-v1.json",
        "stop_submitted_sha256": "receipts/activation-owner/stop-submitted.json",
        "stop_completed_sha256": "receipts/activation-owner/stop-completed.json",
    }
    verified = {}
    for field, path in path_map.items():
        raw = _protected_stage_receipt(stage_fd, path)
        need(digest(raw) == request[field], "fresh_inverse_receipt_changed")
        verified[field] = json.loads(raw, object_pairs_hook=unique)
    terminal = verified["original_terminal_sha256"]
    native = terminal.get("native_guard")
    header = json.loads(_protected_stage_receipt_for_header(stage_fd),
                        object_pairs_hook=unique)
    leaves = header.get("leaves")
    need(type(leaves) is dict and
         header.get("phase") == "finalized" and
         header.get("mode") == request["mode"] and
         leaves.get("receipts/activation-owner/terminal.json") ==
         request["original_terminal_sha256"] and
         leaves.get("accepted/install-receipt/installed-generation.json") ==
         request["installed_generation_sha256"] and
         leaves.get("accepted/install-receipt/manifest.json") ==
         request["installed_manifest_sha256"],
         "fresh_inverse_header_binding_invalid")
    need(type(native) is dict and
         terminal.get("schema") == 1 and terminal.get("outcome") == "finalized" and
         terminal.get("private_unit") == request["unit"] and
         terminal.get("stage") == [stage.st_dev, stage.st_ino] and
         terminal.get("native_capture_sha256") == request["native_capture_sha256"] and
         terminal.get("stop_submitted_sha256") is None and
         terminal.get("stop_completed_sha256") is None and
         native == {"guardian_pid": request["original_guardian_pid"],
                    "guardian_nonce": request["original_guardian_nonce"],
                    "guardian_receipt_sha256":
                    request["original_guardian_receipt_sha256"],
                    "policy_sha256": request["original_guardian_policy_sha256"]},
         "fresh_inverse_original_terminal_invalid")
    owner_intent = verified["stop_intent_sha256"]
    submitted = verified["stop_submitted_sha256"]
    completed = verified["stop_completed_sha256"]
    need(owner_intent.get("schema") == 1 and
         owner_intent.get("kind") == "owned-finalized-stop-intent" and
         owner_intent.get("terminal_sha256") == request["original_terminal_sha256"] and
         owner_intent.get("private_unit") == request["unit"] and
         owner_intent.get("invocation_id") == request["prior_invocation_id"] and
         owner_intent.get("policy_generation") == request["policy_generation"] and
         owner_intent.get("boot_id") == request["boot_id"] and
         owner_intent.get("stage") == [stage.st_dev, stage.st_ino] and
         submitted.get("schema") == completed.get("schema") == 1 and
         submitted.get("kind") == "owned-finalized-stop-submitted" and
         completed.get("kind") == "owned-finalized-stop-completed" and
         submitted.get("intent_sha256") ==
         completed.get("intent_sha256") == request["stop_intent_sha256"] and
         completed.get("stop_submitted_sha256") == request["stop_submitted_sha256"] and
         submitted.get("job_id") == completed.get("job_id") ==
         request["stop_job_id"] and
         submitted.get("job_path") == completed.get("job_path") ==
         request["stop_job_path"] and
         submitted.get("unit") == completed.get("unit") == request["unit"] and
         completed.get("prior_invocation_id") == request["prior_invocation_id"],
         "fresh_inverse_stop_chain_invalid")
    sticky = record(STOP_INTENT)
    need(sticky == {"schema": "aegis_auto_stop_intent_v1",
                    "boot_id": request["boot_id"],
                    "invocation_id": request["prior_invocation_id"],
                    "service": request["unit"], "phase": "deny_proven"},
         "fresh_inverse_sticky_intent_missing")
    policy = _policy(request, guard_id)
    witness = verified_module(WITNESS, "aegis_auto_native_witness")
    capture = verified_module(CAPTURE_SOURCE, "aegis_auto_capture")
    projection, handles, _counters = _semantic_policy_snapshot()
    need(digest(projection) == policy["policy_sha256"] and
         _no_client_grant(projection), "fresh_inverse_deny_changed")
    if request["mode"] in ("wide-redirect-safe", "full-wide-tun"):
        _scoped_retire_after_stop(stage_fd, request["unit"],
                                  request["original_guardian_policy_sha256"],
                                  guard_fd)
        _local_retire_after_stop(stage_fd, request["unit"],
                                 request["original_guardian_policy_sha256"],
                                 guard_fd)
    absence = capture.capture_absent_after_stop(
        mode=request["mode"], unit_name=request["unit"],
        boot_id=request["boot_id"], netns_ino=request["netns_ino"],
        prior_invocation_id=request["prior_invocation_id"],
        policy_sha256=policy["policy_sha256"],
        output_drop_handle=handles["output"],
        snapshot_policy=_semantic_capture_snapshot)
    raw = json.dumps(dataclasses.asdict(absence), sort_keys=True,
                     separators=(",", ":")).encode()
    need(_policy(request, _held_lock(guard_fd, GUARD_LOCK))[
        "policy_sha256"] == policy["policy_sha256"],
        "fresh_inverse_policy_semantics_changed")
    return {"schema": "aegis_auto_fresh_stop_inverse_v1",
            "actor_challenge": request["actor_challenge"],
            "guardian_nonce": request["original_guardian_nonce"],
            "mode": request["mode"], "boot_id": request["boot_id"],
            "netns_ino": request["netns_ino"],
            "stage_dev": stage.st_dev, "stage_ino": stage.st_ino,
            "unit": request["unit"],
            "prior_invocation_id": request["prior_invocation_id"],
            "stop_job_id": request["stop_job_id"],
            "stop_job_path": request["stop_job_path"],
            "post_deny_policy_sha256": policy["policy_sha256"],
            "native_inverse_sha256": digest(raw)}


def _complete_fresh_stop_inverse(request: dict[str, object],
                                 proof: dict[str, object], stage_fd: int,
                                 install_fd: int, guard_fd: int) -> None:
    """Clear sticky deny intent only after the owner durably records inverse."""
    _held_install(install_fd)
    guard_id = _held_lock(guard_fd, GUARD_LOCK)
    stage = os.fstat(stage_fd)
    need((stage.st_dev, stage.st_ino) ==
         (request["stage_dev"], request["stage_ino"]),
         "fresh_inverse_stage_replaced")
    raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/finalized-stop-terminal.json")
    terminal = json.loads(raw, object_pairs_hook=unique)
    need(terminal.get("schema") == 1 and
         terminal.get("outcome") == "finalized-stopped" and
         terminal.get("stage") == [stage.st_dev, stage.st_ino] and
         terminal.get("private_unit") == request["unit"] and
         terminal.get("start_terminal_sha256") ==
         request["original_terminal_sha256"] and
         terminal.get("stop_intent_sha256") == request["stop_intent_sha256"] and
         terminal.get("stop_submitted_sha256") ==
         request["stop_submitted_sha256"] and
         terminal.get("stop_completed_sha256") ==
         request["stop_completed_sha256"] and
         terminal.get("prior_invocation_id") ==
         request["prior_invocation_id"] and
         terminal.get("boot_id") == request["boot_id"] and
         terminal.get("native_inverse_sha256") ==
         proof["native_inverse_sha256"] and
         terminal.get("post_deny_policy_sha256") ==
         proof["post_deny_policy_sha256"],
         "fresh_inverse_terminal_not_persisted")
    header = json.loads(_protected_stage_receipt_for_header(stage_fd),
                        object_pairs_hook=unique)
    leaves = header.get("leaves")
    need(type(leaves) is dict and
         leaves.get("receipts/activation-owner/finalized-stop-terminal.json") ==
         digest(raw), "fresh_inverse_header_not_persisted")
    policy = _policy(request, guard_id)
    witness = verified_module(WITNESS, "aegis_auto_native_witness")
    projection, handles, _counters = _semantic_policy_snapshot()
    need(policy["policy_sha256"] == proof["post_deny_policy_sha256"] ==
         digest(projection) and _no_client_grant(projection) and
         handles["output"] > 0, "fresh_inverse_deny_not_retained")
    capture = verified_module(CAPTURE_SOURCE, "aegis_auto_capture")
    capture.capture_absent_after_stop(
        mode=request["mode"], unit_name=request["unit"],
        boot_id=request["boot_id"], netns_ino=request["netns_ino"],
        prior_invocation_id=request["prior_invocation_id"],
        policy_sha256=policy["policy_sha256"],
        output_drop_handle=handles["output"],
        snapshot_policy=_semantic_capture_snapshot)
    need(_policy(request, guard_id)["policy_sha256"] ==
         policy["policy_sha256"], "fresh_inverse_semantics_changed")
    need(record(STOP_INTENT) ==
         {"schema": "aegis_auto_stop_intent_v1",
          "boot_id": request["boot_id"],
          "invocation_id": request["prior_invocation_id"],
          "service": request["unit"], "phase": "deny_proven"},
         "fresh_inverse_stop_intent_changed")
    STOP_INTENT.unlink()
    parent = os.open(STOP_INTENT.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _protected_stage_receipt_for_header(stage_fd: int) -> bytes:
    child = os.open("header.json", os.O_RDONLY | os.O_CLOEXEC |
                    os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=stage_fd)
    try:
        value = os.fstat(child)
        need(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and
             value.st_nlink == 1 and stat.S_IMODE(value.st_mode) == 0o600 and
             0 < value.st_size <= 65536, "untrusted_inverse_header")
        raw = os.read(child, 65537)
        need(len(raw) == value.st_size, "inverse_header_changed")
        return raw
    finally:
        os.close(child)


def _installed_main_digest(stage_fd: int,
                           request: dict[str, object]) -> str:
    """Read the exact accepted installed ELF generation under the held stage.

    The coordinator worker ELF is separately pinned by INSTALL and must never
    be substituted for the PID1 private main executable.
    """
    header = json.loads(_protected_stage_receipt_for_header(stage_fd),
                        object_pairs_hook=unique)
    leaf = "accepted/install-receipt/installed-generation.json"
    raw = _protected_stage_receipt(stage_fd, leaf)
    need(header.get("transaction_nonce") == request["transaction_nonce"] and
         header.get("planned_generation") == request["planned_generation"] and
         type(header.get("leaves")) is dict and
         header["leaves"].get(leaf) == digest(raw),
         "installed_main_stage_generation_changed")
    generation = json.loads(raw, object_pairs_hook=unique)
    need(type(generation) is dict and
         set(generation) == {"source", "operator_uid", "installed",
                             "parents", "identity", "fingerprint"} and
         generation["operator_uid"] == 0 and
         generation["installed"] is True and
         type(generation["source"]) is str and
         type(generation["parents"]) is list and
         type(generation["fingerprint"]) is dict and
         set(generation["fingerprint"]) == {"size", "sha256"} and
         type(generation["fingerprint"]["sha256"]) is str and
         HEX64.fullmatch(generation["fingerprint"]["sha256"]) and
         type(generation["fingerprint"]["size"]) is int and
         0 < generation["fingerprint"]["size"] <= 512 << 20,
         "installed_main_generation_invalid")
    source = Path(generation["source"])
    parts = source.parts
    need(source.is_absolute() and source.name == "aegis-client" and
         len(parts) >= 3 and len(parts) <= 65 and
         all(part not in ("", ".", "..") for part in parts[1:]) and
         len(generation["parents"]) == len(parts) - 1,
         "installed_main_path_invalid")

    def identity(info: os.stat_result) -> dict[str, int]:
        mtime, mtime_ns = divmod(info.st_mtime_ns, 1_000_000_000)
        ctime, ctime_ns = divmod(info.st_ctime_ns, 1_000_000_000)
        return {"dev": info.st_dev, "ino": info.st_ino,
                "uid": info.st_uid, "gid": info.st_gid,
                "mode": info.st_mode, "size": info.st_size,
                "mtime": mtime, "mtime_ns": mtime_ns,
                "ctime": ctime, "ctime_ns": ctime_ns}

    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY |
                      os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for index, part in enumerate(parts[1:]):
            info = os.fstat(current)
            admitted = generation["parents"][index]
            need(type(admitted) is dict and
                 all(identity(info)[key] == admitted.get(key)
                     for key in ("dev", "ino", "uid", "gid", "mode")) and
                 info.st_uid == 0 and info.st_mode & 0o022 == 0,
                 "installed_main_parent_changed")
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if index < len(parts) - 2:
                flags |= os.O_DIRECTORY
            next_fd = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        info = os.fstat(current)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             info.st_nlink == 1 and info.st_mode & 0o022 == 0 and
             info.st_mode & 0o111 != 0 and
             identity(info) == generation["identity"] and
             info.st_size == generation["fingerprint"]["size"],
             "installed_main_inode_changed")
        expected = generation["fingerprint"]["sha256"]
        h = hashlib.sha256()
        total = 0
        while chunk := os.read(current, 1 << 20):
            total += len(chunk)
            need(total <= 512 << 20, "installed_main_too_large")
            h.update(chunk)
        need(total == info.st_size and h.hexdigest() == expected and
             identity(os.fstat(current)) == generation["identity"],
             "installed_main_bytes_changed")
        return expected
    finally:
        os.close(current)


def _launch_terminal(stage_fd: int, request: dict[str, object],
                     ticket_sha256: str,
                     native_guard: dict[str, object] | None,
                     terminal_sha256: str) -> None:
    """Verify the one committed owner terminal before releasing its lock FDs."""
    stage = os.fstat(stage_fd)
    raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/terminal.json")
    archive_raw = _protected_stage_receipt(
        stage_fd, "receipts/activation-owner/marker-archive.json")
    terminal = json.loads(raw, object_pairs_hook=unique)
    archive = json.loads(archive_raw, object_pairs_hook=unique)
    header = json.loads(_protected_stage_receipt_for_header(stage_fd),
                        object_pairs_hook=unique)
    leaves = header.get("leaves")
    need(type(terminal) is dict and type(archive) is dict and
         type(leaves) is dict and header.get("phase") == "finalized" and
         digest(raw) == terminal_sha256 ==
         leaves.get("receipts/activation-owner/terminal.json") and
         digest(archive_raw) == terminal.get("marker_archive_sha256") ==
         leaves.get("receipts/activation-owner/marker-archive.json") and
         terminal.get("schema") == 1 and
         terminal.get("outcome") == "finalized" and
         terminal.get("transaction_nonce") == request["transaction_nonce"] and
         terminal.get("stage") == [stage.st_dev, stage.st_ino] and
         terminal.get("private_unit") == request["private_unit"] and
         terminal.get("launch_ticket_sha256") == ticket_sha256 and
         terminal.get("native_guard") == native_guard and
         (terminal.get("native_capture_sha256") is None if
          request["mode"] == "socks-only" else
          type(terminal.get("native_capture_sha256")) is str and
          HEX64.fullmatch(terminal["native_capture_sha256"]) is not None),
         "launch_terminal_not_sealed_for_owner")
    need(set(archive) == {"schema", "may_send_hex", "claim_hex",
                          "may_send_sha256", "claim_sha256"} and
         archive["schema"] == 1 and
         type(archive["may_send_hex"]) is str and
         type(archive["claim_hex"]) is str and
         type(archive["may_send_sha256"]) is str and
         type(archive["claim_sha256"]) is str and
         HEX64.fullmatch(archive["may_send_sha256"]) is not None and
         HEX64.fullmatch(archive["claim_sha256"]) is not None and
         digest(bytes.fromhex(archive["may_send_hex"])) ==
         archive["may_send_sha256"] == terminal.get("may_send_sha256") and
         digest(bytes.fromhex(archive["claim_hex"])) ==
         archive["claim_sha256"] == terminal.get("claim_sha256"),
         "launch_marker_archive_not_sealed")
    handoff = json.loads(_stage_leaf(
        stage_fd, "activation-owner-terminal-handoff.json"),
        object_pairs_hook=unique)
    need(handoff == {
        "schema": 1, "kind": "terminal-guardian-handoff",
        "stage": [stage.st_dev, stage.st_ino],
        "private_unit": request["private_unit"],
        "terminal_sha256": terminal_sha256,
        "marker_archive_sha256": digest(archive_raw),
        "may_send_sha256": archive["may_send_sha256"],
        "claim_sha256": archive["claim_sha256"]},
        "launch_terminal_handoff_not_owned")
    for marker in ("activation-owner-may-send-v3.json",
                   "activation-owner-claim-v3.json",
                   "activation-owner-native-recovery.json",
                   "activation-owner-postterminal-stop.json"):
        try:
            os.stat(marker, dir_fd=stage_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("launch_owner_handoff_incomplete")


class Guardian:
    def __init__(self) -> None:
        self.server: socket.socket | None = None
        self.singleton: int | None = None
        self.socket_id: tuple[int, int] | None = None
        self.active_guard_fd: int | None = None
        self.active_stage_fd: int | None = None
        self.active_request: dict[str, object] | None = None
        self.active_grant: dict[str, object] | None = None
        # Minted only after the cross-boot carrier is authenticated under the
        # held Install and Guard OFDs; never supplied by a peer or persisted.
        self.active_lineage: dict | None = None
        self.active_capture: dict[str, object] | None = None
        self.active_unit: str | None = None
        self.active_guard_mutex = threading.Lock()
        self.active_guard_idle = threading.Condition(self.active_guard_mutex)
        self.stopped_guard_session: str | None = None
        self.mutation_admissions = 0
        self.workers: set[threading.Thread] = set()
        self.launches: dict[str, object] = {}
        # Values are minted only by _installed_main_digest from the original
        # held stage. STOP hooks can arrive after the transaction RPC closes.
        self.main_digests: dict[str, str] = {}
        self.launch_mutex = threading.Lock()
        self.watchdogs: dict[str, object] = {}
        self.watchdog_mutex = threading.Lock()

    def _release_active_guard_copies(self, guard_fd: int,
                                     request: dict[str, object]) -> None:
        """Drop only this daemon's copies after a durable terminal barrier."""
        with self.active_guard_mutex:
            need(self.active_guard_fd is not None and
                 self.active_stage_fd is not None and
                 self.active_request == request and
                 (os.fstat(self.active_guard_fd).st_dev,
                  os.fstat(self.active_guard_fd).st_ino) ==
                 (os.fstat(guard_fd).st_dev, os.fstat(guard_fd).st_ino),
                 "active_guard_release_owner_changed")
            os.close(self.active_guard_fd)
            os.close(self.active_stage_fd)
            self.active_guard_fd = None
            self.active_stage_fd = None
            self.active_request = None
            self.active_grant = None
            self.active_lineage = None
            self.active_capture = None
            self.active_unit = None

    def _inspect_live(self, peer: socket.socket, peer_pid: int,
                      peer_pidfd: int, request: dict[str, object],
                      fds: tuple[int, ...], installation: dict) -> None:
        """Read the live sealed guardian and exact Main owner without a lease."""
        deadline = time.monotonic() + 11.0
        need(not fds and set(request) == {
            "schema", "command", "guardian_invocation_id", "private_unit",
            "main_pid", "invocation_id", "boot_id", "native_guard"} and
            request["schema"] == "aegis_auto_guardian_live_inspection_v1" and
            request["command"] == "INSPECT_LIVE" and
            type(request["guardian_invocation_id"]) is str and
            HEX32.fullmatch(request["guardian_invocation_id"]) is not None and
            type(request["private_unit"]) is str and
            PRIVATE_UNIT.fullmatch(request["private_unit"]) is not None and
            type(request["main_pid"]) is int and request["main_pid"] > 1 and
            type(request["invocation_id"]) is str and
            HEX32.fullmatch(request["invocation_id"]) is not None and
            request["boot_id"] == host_anchor()["boot_id"],
            "live_inspection_request_invalid")
        own_source()
        _peer_executable(peer_pid, installation["worker_sha256"])
        need(_pid_alive(peer_pidfd) and
             _unit_identity(GUARDIAN_UNIT, os.getpid())["InvocationID"] ==
             request["guardian_invocation_id"],
             "live_inspection_guardian_changed")
        native = request["native_guard"]
        need(native is None or (type(native) is dict and set(native) == {
            "guardian_nonce", "guardian_receipt_sha256", "policy_sha256"} and
            all(type(native[key]) is str and
                HEX64.fullmatch(native[key]) is not None for key in native)),
            "live_inspection_native_guard_invalid")
        with self.active_guard_mutex:
            grant = dict(self.active_grant) if self.active_grant is not None else None
            original = dict(self.active_request) if self.active_request is not None else None
            active_unit = self.active_unit
            guard_present = self.active_guard_fd is not None
            stage_present = self.active_stage_fd is not None
        need(grant is None and original is None and active_unit is None and
             not guard_present and not stage_present,
             "live_inspection_inflight_owner_changed")
        with self.launch_mutex:
            main_sha = self.main_digests.get(request["private_unit"])
        need(type(main_sha) is str and HEX64.fullmatch(main_sha) is not None,
             "live_inspection_main_source_missing")
        facts = _launch_unit_identity(request["private_unit"],
                                      request["main_pid"])
        need(facts["InvocationID"] == request["invocation_id"] and
             facts["ActiveState"] == "active" and
             facts["SubState"] == "running" and
             executable_digest(Path(f'/proc/{request["main_pid"]}/exe')) ==
             main_sha, "live_inspection_main_changed")
        manager_sha = None
        current_policy_sha = None
        if native is None:
            with self.watchdog_mutex:
                need(request["private_unit"] not in self.watchdogs,
                     "live_inspection_passive_has_guard")
        else:
            with self.watchdog_mutex:
                watchdog = self.watchdogs.get(request["private_unit"])
            need(watchdog is not None, "live_inspection_watchdog_missing")
            committed = watchdog.inspect_active(
                deadline=min(deadline - 5.5, time.monotonic() + 4.0))
            need(committed["guardian_pid"] == os.getpid() and
                 committed["private_unit"] == request["private_unit"] and
                 committed["invocation_id"] == request["invocation_id"] and
                 committed["private_main_pid"] == request["main_pid"] and
                 committed["native_guard"] == {
                     "guardian_pid": os.getpid(), **native},
                 "live_inspection_finalized_owner_changed")
            state_path = Path("/var/lib/aegis-install/client/device-guard.conf")
            manager_path = Path(str(state_path) + ".manager-binding")
            need(not manager_path.is_symlink(), "live_inspection_manager_changed")
            manager_raw = regular(manager_path, 4096, 0o600)
            state_raw, projection = _semantic_policy_readback(
                deadline=deadline - 2.5)
            saved = record(POLICY)
            need(digest(state_raw) == saved["state_sha256"] and
                 digest(projection) == saved["policy_sha256"] ==
                 committed["policy_sha256"] and
                 regular(manager_path, 4096, 0o600) == manager_raw,
                 "live_inspection_finalized_policy_changed")
            guard_policy = verified_module(POLICY_SOURCE,
                                           "aegis_auto_guard_policy")
            state = guard_policy.parse_state(state_raw)
            manager = json.loads(manager_raw, object_pairs_hook=unique)
            guard_policy._binding(manager, "manager", digest(state_raw.rstrip(b"\n")),
                                  state["manager"])
            manager_info = (Path("/sys/fs/cgroup") / manager["path"]).stat(
                follow_symlinks=False)
            need(manager["boot_id"] == request["boot_id"] and
                 stat.S_ISDIR(manager_info.st_mode) and
                 manager_info.st_ino == int(manager["inode"]),
                 "live_inspection_manager_changed")
            manager_sha = digest(manager_raw)
            current_policy_sha = committed["policy_sha256"]
            with self.watchdog_mutex:
                need(self.watchdogs.get(request["private_unit"]) is watchdog,
                     "live_inspection_watchdog_changed")
        need(_pid_alive(peer_pidfd) and
             _launch_unit_identity(request["private_unit"],
                                   request["main_pid"]) == facts and
             time.monotonic() < deadline,
             "live_inspection_main_raced")
        response = {"schema": "aegis_auto_guardian_live_inspection_reply_v1",
                    "guardian_pid": os.getpid(),
                    "guardian_invocation_id": request["guardian_invocation_id"],
                    "private_unit": request["private_unit"],
                    "main_pid": request["main_pid"],
                    "invocation_id": request["invocation_id"],
                    "boot_id": request["boot_id"],
                    "policy_sha256": current_policy_sha,
                    "manager_binding_sha256": manager_sha}
        peer.sendall(json.dumps(response, sort_keys=True,
                                separators=(",", ":")).encode())

    def _launch_session(self, peer: socket.socket, peer_pidfd: int,
                        request: dict[str, object], fds: tuple[int, ...],
                        guardian_identity: dict[str, str]) -> None:
        if len(fds) != 3:
            for descriptor in fds:
                os.close(descriptor)
            raise Refused("launch_three_fds_required")
        stage_fd, install_fd, actor_fd = fds
        actor = None
        held = None
        handed_off = False
        try:
            need(set(request) == {"schema", "command", "private_unit",
                                  "mode", "header_sha256",
                                  "transaction_nonce", "planned_generation",
                                  "boot_id", "netns_ino", "actor_challenge"} and
                 request["schema"] == "aegis_auto_guardian_launch_register_v1" and
                 request["command"] == "REGISTER_LAUNCH" and
                 request["mode"] in ("socks-only", "wide-redirect-safe",
                                     "full-wide-tun") and
                 type(request["private_unit"]) is str and
                 PRIVATE_UNIT.fullmatch(request["private_unit"]) is not None and
                 type(request["actor_challenge"]) is str and
                 HEX64.fullmatch(request["actor_challenge"]) is not None and
                 request["boot_id"] == host_anchor()["boot_id"] and
                 request["netns_ino"] == host_anchor()["netns_ino"],
                 "invalid_launch_registration")
            _held_install(install_fd)
            stage_id = _stage(stage_fd, request, initial=True)
            initial_header_raw = _protected_stage_receipt_for_header(stage_fd)
            need(digest(initial_header_raw) == request["header_sha256"],
                 "stage_header_changed")
            header = json.loads(initial_header_raw, object_pairs_hook=unique)
            need(type(header) is dict and header.get("phase") == "metadata" and
                 header.get("pending") is None and
                 header.get("unit_pending") is None,
                 "launch_registration_stage_not_metadata")
            uid, gid, runtime_policy = _launch_runtime_identity(
                header, request["mode"])
            with self.active_guard_mutex:
                grant = (dict(self.active_grant)
                         if self.active_grant is not None else None)
                original = (dict(self.active_request)
                            if self.active_request is not None else None)
            if request["mode"] == "socks-only":
                need(grant is None, "socks_launch_has_wide_deny_lease")
                native_guard = None
            else:
                need(grant is not None and original is not None and
                     original["private_unit"] == request["private_unit"] and
                     original["mode"] == request["mode"] and
                     original["transaction_nonce"] ==
                     request["transaction_nonce"] and
                     (grant["stage_dev"], grant["stage_ino"]) == stage_id,
                     "wide_launch_missing_held_guard")
                native_guard = {
                    "guardian_pid": grant["pid"],
                    "guardian_nonce": grant["nonce"],
                    "guardian_receipt_sha256": grant["native_receipt_sha256"],
                    "policy_sha256": grant["policy_sha256"]}
            launch = verified_module(LAUNCH_SOURCE, "aegis_auto_launch")
            installed_main_sha256 = _installed_main_digest(stage_fd, request)
            if request["mode"] == "full-wide-tun":
                _publish_guard_binding(MAIN_BINDING, {
                    "schema": "aegis_device_guard_main_binding_v1",
                    "boot_id": request["boot_id"],
                    "netns_ino": request["netns_ino"],
                    "private_unit": request["private_unit"],
                    "worker_sha256": installed_main_sha256,
                    "stage_dev": stage_id[0], "stage_ino": stage_id[1],
                })
            with self.launch_mutex:
                need(request["private_unit"] not in self.main_digests,
                     "private_main_generation_already_registered")
                self.main_digests[request["private_unit"]] = installed_main_sha256
            actor_owned_fd = actor_fd
            actor_fd = None
            actor = launch.LaunchActor(
                actor_owned_fd, request["private_unit"],
                installed_main_sha256, uid, gid, runtime_policy,
                _launch_unit_identity,
                lambda identity: _claimed_launch_unit(
                    stage_fd, request, identity.ticket_sha256,
                    native_guard))
            registered = {
                "schema": "aegis_auto_guardian_launch_registered_v1",
                "actor_challenge": request["actor_challenge"],
                "ticket_sha256": actor.ticket_sha256,
                "guardian_pid": os.getpid(),
                "guardian_invocation_id": guardian_identity["InvocationID"],
                "private_unit": request["private_unit"],
                "stage_dev": stage_id[0], "stage_ino": stage_id[1]}
            peer.sendall(json.dumps(registered, sort_keys=True,
                                    separators=(",", ":")).encode())
            held = actor.accept(timeout=30)
            while _pid_alive(peer_pidfd):
                payload = _receive_no_fds(peer)
                if not payload:
                    break
                probe = json.loads(payload, object_pairs_hook=unique)
                terminal_probe = (type(probe) is dict and
                                  probe.get("command") == "LAUNCH_TERMINAL")
                expected = {"schema", "command", "actor_challenge",
                            "ticket_sha256", "private_unit"}
                if terminal_probe:
                    expected.add("terminal_sha256")
                need(type(probe) is dict and
                     set(probe) == expected and
                     probe["schema"] == "aegis_auto_guardian_launch_probe_v1" and
                     probe["command"] in ("LAUNCH_PROOF", "LAUNCH_REVALIDATE",
                                          "LAUNCH_TERMINAL") and
                     probe["actor_challenge"] == request["actor_challenge"] and
                     probe["ticket_sha256"] == actor.ticket_sha256 and
                     probe["private_unit"] == request["private_unit"],
                     "invalid_launch_probe")
                held.revalidate()
                _held_install(install_fd)
                need(_installed_main_digest(stage_fd, request) ==
                     installed_main_sha256,
                     "launch_installed_main_generation_changed")
                identity = held.identity
                if terminal_probe:
                    need(type(probe["terminal_sha256"]) is str and
                         HEX64.fullmatch(probe["terminal_sha256"]) is not None and
                         _pid_alive(peer_pidfd),
                         "launch_terminal_request_invalid")
                    _launch_terminal(stage_fd, request, actor.ticket_sha256,
                                     native_guard, probe["terminal_sha256"])
                    with self.launch_mutex:
                        need(request["private_unit"] not in self.launches,
                             "launch_already_retained")
                        self.launches[request["private_unit"]] = held
                    try:
                        threading.Thread(target=self._watch_launch,
                                         args=(request["private_unit"], held),
                                         daemon=True).start()
                    except BaseException:
                        with self.launch_mutex:
                            if self.launches.get(request["private_unit"]) is held:
                                self.launches.pop(request["private_unit"])
                        raise
                    # The worker still holds its original StageGuard and
                    # InstallLock through this reply. Release only our copies.
                    os.close(stage_fd)
                    stage_fd = None
                    os.close(install_fd)
                    install_fd = None
                    handed_off = True
                    reply = {
                        "schema": "aegis_auto_guardian_launch_terminal_held_v1",
                        "actor_challenge": request["actor_challenge"],
                        "ticket_sha256": identity.ticket_sha256,
                        "guardian_pid": os.getpid(),
                        "guardian_invocation_id": guardian_identity["InvocationID"],
                        "private_unit": identity.unit,
                        "stage_dev": stage_id[0], "stage_ino": stage_id[1],
                        "terminal_sha256": probe["terminal_sha256"],
                        "pid": identity.pid,
                        "start_tick": identity.start_tick,
                        "invocation": identity.invocation,
                        "cgroup": identity.cgroup,
                        "lease_alive": True}
                    peer.sendall(json.dumps(reply, sort_keys=True,
                                            separators=(",", ":")).encode())
                    return
                if probe["command"] == "LAUNCH_REVALIDATE" and digest(
                        _protected_stage_receipt_for_header(stage_fd)) != request["header_sha256"]:
                    with self.active_guard_mutex:
                        capture_state = (dict(self.active_capture)
                                         if self.active_capture is not None else None)
                    current_header = json.loads(
                        _protected_stage_receipt_for_header(stage_fd),
                        object_pairs_hook=unique)
                    if current_header.get("phase") == "metadata":
                        _launch_captured_metadata_successor(
                            stage_fd, header, request, actor.ticket_sha256,
                            native_guard, identity, capture_state)
                    else:
                        _launch_projection_successor(
                            stage_fd, header, request, actor.ticket_sha256,
                            native_guard, identity,
                            guardian_identity["InvocationID"], capture_state)
                else:
                    _claimed_launch_unit(stage_fd, request,
                                         actor.ticket_sha256, native_guard)
                reply = {
                    "schema": "aegis_auto_guardian_launch_held_v1",
                    "actor_challenge": request["actor_challenge"],
                    "ticket_sha256": identity.ticket_sha256,
                    "guardian_pid": os.getpid(),
                    "guardian_invocation_id": guardian_identity["InvocationID"],
                    "private_unit": identity.unit,
                    "pid": identity.pid,
                    "start_tick": identity.start_tick,
                    "invocation": identity.invocation,
                    "cgroup": identity.cgroup,
                    "lease_alive": True}
                peer.sendall(json.dumps(reply, sort_keys=True,
                                        separators=(",", ":")).encode())
            raise Refused("launch_terminal_handoff_missing")
        finally:
            if not handed_off and held is not None:
                held.close()
            if not handed_off and held is None and actor is not None:
                actor.channel.close()
            if actor_fd is not None:
                os.close(actor_fd)
            if stage_fd is not None:
                os.close(stage_fd)
            if install_fd is not None:
                os.close(install_fd)

    def _watch_launch(self, unit: str, held: object) -> None:
        stop_pending_since = None
        while True:
            try:
                if (INSTALL.parent / "foreign-policy-drift.json").exists():
                    with self.watchdog_mutex:
                        watchdog=self.watchdogs.get(unit)
                        if watchdog is not None:
                            watchdog.fail_closed("foreign_policy_drift")
                    raise Refused("foreign_policy_drift")
                held.revalidate()
                stop_pending_since = None
            except (OSError, ValueError, RuntimeError, TimeoutError,
                    subprocess.SubprocessError) as launch_error:
                try:
                    with self.launch_mutex:
                        main_sha = self.main_digests.get(unit)
                    need(main_sha is not None, "pending_stop_main_missing")
                    control_started = _pending_owned_stop(unit, held, main_sha)
                    now = time.monotonic()
                    if stop_pending_since is None:
                        stop_pending_since = now
                    need(now - stop_pending_since < (12.0 if control_started else 1.0),
                         "pending_stop_deadline_expired")
                    with self.watchdog_mutex:
                        watcher = self.watchdogs.get(unit)
                        need(watcher is not None, "pending_stop_watchdog_missing")
                        watcher.revalidate()
                    # PID1 publishes deactivating before ExecStop writes deny.
                    # BEGIN_STOP here would reject/close the independent lease.
                    # Only the typed Stop helper may establish that barrier.
                    time.sleep(0.05)
                    continue
                except (OSError, ValueError, RuntimeError, TimeoutError,
                        subprocess.SubprocessError) as pending_error:
                    # Buffered, not printed: an ordinary Stop (inactive or
                    # proven normal_stopping) is not a refusal. The outcome
                    # is evaluated below in the unchanged order.
                    refusals = []
                    for phase, error in (("launch", launch_error),
                                         ("pending_stop", pending_error)):
                        source, line = _pinned_error_location(
                            error, skip_assertion_helper=True)
                        refusals.append({"event": "launch_transition_refused",
                            "phase": phase, "reason": _request_refusal_tag(error),
                            "source": source, "line": line,
                            "monotonic_ns": time.monotonic_ns()})
                try:
                    stopped = _private_unit_inactive(unit)
                except (OSError, ValueError, RuntimeError, TimeoutError,
                        subprocess.SubprocessError):
                    stopped = False
                normal_stopping = False
                with self.watchdog_mutex:
                    watchdog = self.watchdogs.get(unit)
                    if not stopped and watchdog is not None:
                        try:
                            # Only the independent actor may classify a Main
                            # exit as an ordinary stop: it requires the exact
                            # durable deny-proven intent and current kernel
                            # policy, then owns the bounded inverse deadline.
                            normal_stopping = watchdog.begin_stop(probe=True) is not None
                        except (OSError, ValueError, RuntimeError, TimeoutError,
                                subprocess.SubprocessError):
                            pass
                if not stopped and not normal_stopping:
                    # DISARM can finish between the first PID1 readback and
                    # BEGIN_STOP. It requires inactive plus empty cgroup.
                    try:
                        stopped = _private_unit_inactive(unit)
                    except (OSError, ValueError, RuntimeError, TimeoutError,
                            subprocess.SubprocessError):
                        pass
                if not stopped and not normal_stopping:
                    for refusal in refusals:
                        print(json.dumps(refusal, sort_keys=True),
                              file=sys.stderr, flush=True)
                else:
                    print(json.dumps({"event": "launch_watch_ended",
                        "phase": "inactive" if stopped else "normal_stopping",
                        "monotonic_ns": time.monotonic_ns()},
                        sort_keys=True), file=sys.stderr, flush=True)
                if not stopped and not normal_stopping and watchdog is not None:
                    # The independent actor retains the original guard OFD
                    # and proves the inverse even if this process dies here.
                    try:
                        watchdog.fail_closed("launch_channel_lost")
                    except (OSError, ValueError, RuntimeError, TimeoutError,
                            subprocess.SubprocessError):
                        # Actor uncertainty must end this daemon so its held
                        # guardian PIDFD triggers independent recovery.
                        os._exit(1)
                elif not stopped and not normal_stopping:
                    try:
                        _stop_lost_launch(unit)
                    except (OSError, ValueError, RuntimeError, TimeoutError,
                            subprocess.SubprocessError):
                        os._exit(1)
                with self.launch_mutex:
                    if self.launches.get(unit) is held:
                        self.launches.pop(unit)
                held.close()
                return
            time.sleep(0.25)

    def open(self) -> None:
        own_source()
        runtime = RUNTIME.stat(follow_symlinks=False)
        need(stat.S_ISDIR(runtime.st_mode) and runtime.st_uid == 0 and
             stat.S_IMODE(runtime.st_mode) == 0o700, "untrusted_runtime_directory")
        fd = os.open(SINGLETON, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC |
                     os.O_NOFOLLOW, 0o600)
        try:
            s = os.fstat(fd)
            need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and
                 s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600,
                 "untrusted_singleton")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if SOCKET.exists() or SOCKET.is_symlink():
                old = SOCKET.stat(follow_symlinks=False)
                need(stat.S_ISSOCK(old.st_mode) and old.st_uid == 0 and
                     stat.S_IMODE(old.st_mode) == 0o600,
                     "foreign_socket_path")
                SOCKET.unlink()
            server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET |
                                   socket.SOCK_CLOEXEC)
            try:
                server.bind(str(SOCKET))
                os.chmod(SOCKET, 0o600)
                named = SOCKET.stat(follow_symlinks=False)
                need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
                     stat.S_IMODE(named.st_mode) == 0o600,
                     "socket_bind_changed")
                server.listen(2)
                self.server = server
                self.singleton = fd
                self.socket_id = named.st_dev, named.st_ino
            except BaseException:
                server.close()
                raise
        except BaseException:
            os.close(fd)
            raise

    def close(self) -> None:
        if self.server is not None:
            self.server.close()
            self.server = None
        try:
            named = SOCKET.stat(follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if (named.st_dev, named.st_ino) == self.socket_id:
                SOCKET.unlink()
        if self.singleton is not None:
            os.close(self.singleton)
            self.singleton = None

    def _stopped_guard_session(self, peer, pid, pidfd, request, fds,
                               installation, guardian_identity):
        own_source()
        keys = {'schema','command','actor_challenge','boot_id','netns_ino',
                'unit','prior_invocation_id','stage_dev','stage_ino',
                'stop_terminal_sha256','post_deny_policy_sha256'}
        need(set(request) == keys and len(fds) == 2 and
             request['schema'] == 'aegis_auto_guardian_stopped_guard_v1' and
             request['command'] == 'SEAL_STOPPED_GUARD' and
             all(type(request[k]) is str and HEX64.fullmatch(request[k]) for k in
                 ('actor_challenge','stop_terminal_sha256',
                  'post_deny_policy_sha256')) and
             type(request['unit']) is str and PRIVATE_UNIT.fullmatch(request['unit']) and
             type(request['prior_invocation_id']) is str and
             HEX32.fullmatch(request['prior_invocation_id']) and
             request['boot_id'] == host_anchor()['boot_id'] and
             request['netns_ino'] == host_anchor()['netns_ino'] and
             all(type(request[k]) is int and request[k] > 0 for k in
                 ('stage_dev','stage_ino')), 'stopped_guard_request_invalid')
        _peer_executable(pid, installation['worker_sha256'])
        need(_pid_alive(pidfd), 'stopped_guard_worker_exited')
        stage_fd, install_fd = fds
        _held_install(install_fd)  # original caller OFD, no competing acquisition
        stage = os.fstat(stage_fd)
        need(stat.S_ISDIR(stage.st_mode) and stage.st_uid == 0 and
             stage.st_mode & 0o022 == 0 and
             (stage.st_dev,stage.st_ino) ==
             (request['stage_dev'],request['stage_ino']),
             'stopped_guard_stage_changed')
        raw = _protected_stage_receipt(
            stage_fd,'receipts/activation-owner/finalized-stop-terminal.json')
        terminal = json.loads(raw, object_pairs_hook=unique)
        header = json.loads(_protected_stage_receipt_for_header(stage_fd),
                            object_pairs_hook=unique)
        need(digest(raw) == request['stop_terminal_sha256'] and
             type(header) is dict and type(header.get('leaves')) is dict and
             header['leaves'].get(
                 'receipts/activation-owner/finalized-stop-terminal.json') ==
             digest(raw) and
             terminal.get('schema') == 1 and
             terminal.get('outcome') == 'finalized-stopped' and
             terminal.get('stage') == [stage.st_dev,stage.st_ino] and
             terminal.get('private_unit') == request['unit'] and
             terminal.get('prior_invocation_id') ==
             request['prior_invocation_id'] and
             terminal.get('boot_id') == request['boot_id'] and
             terminal.get('post_deny_policy_sha256') ==
             request['post_deny_policy_sha256'],
             'stopped_guard_terminal_changed')
        _stopped_guard_pid1(request['unit'],request['prior_invocation_id'])
        need(
             not STOP_INTENT.exists() and not STOP_INTENT.is_symlink() and
             not (INSTALL.parent/'foreign-policy-drift.json').exists() and
             not (INSTALL.parent/'foreign-policy-drift.json').is_symlink(),
             'stopped_guard_not_cleanly_stopped')
        # Reserve before waiting for a previously admitted Stop to finish. The
        # condition releases active_guard_mutex while waiting, and blocks any new
        # mutation from entering. This is an independent two-second read wait.
        reserve_deadline = time.monotonic() + STOPPED_GUARD_MONITOR_WAIT
        with self.active_guard_idle:
            need(self.stopped_guard_session is None,
                 'stopped_guard_read_already_present')
            self.stopped_guard_session = request['actor_challenge']
            try:
                while self.mutation_admissions != 0:
                    remaining = reserve_deadline - time.monotonic()
                    need(remaining > 0, 'stopped_guard_mutation_drain_deadline')
                    self.active_guard_idle.wait(remaining)
                need(self.active_guard_fd is None and
                     self.active_stage_fd is None and
                     self.active_grant is None and self.active_request is None and
                     self.active_capture is None and self.active_unit is None,
                     'stopped_guard_active_lease_present')
                with self.launch_mutex:
                    need(not self.launches, 'stopped_guard_launch_present')
                with self.watchdog_mutex:
                    need(not self.watchdogs, 'stopped_guard_watchdog_present')
            except BaseException:
                self.stopped_guard_session = None
                self.active_guard_idle.notify_all()
                raise
        guard_fd = None
        try:
            guard_fd = _stopped_guard_claim()
            deadline = time.monotonic() + LEASE_SECONDS
            own_source()
            _held_install(install_fd)
            policy = read_guard_policy()
            need(policy['policy_sha256'] == request['post_deny_policy_sha256'] and
                 _stopped_guard_pid1(request['unit'],
                     request['prior_invocation_id']) and
                 _pid_alive(pidfd),
                 'stopped_guard_deny_changed')
            nonce = secrets.token_hex(32)
            reply = {'schema':'aegis_auto_guardian_stopped_guard_held_v1',
                     'actor_challenge':request['actor_challenge'],
                     'guardian_nonce':nonce,
                     'guardian_invocation_id':guardian_identity['InvocationID'],
                     'boot_id':request['boot_id'], 'unit':request['unit'],
                     'prior_invocation_id':request['prior_invocation_id'],
                     'stage_dev':stage.st_dev, 'stage_ino':stage.st_ino,
                     'stop_terminal_sha256':request['stop_terminal_sha256'],
                     'post_deny_policy_sha256':request['post_deny_policy_sha256'],
                     'guard_dev':os.fstat(guard_fd).st_dev,
                     'guard_ino':os.fstat(guard_fd).st_ino}
            payload = json.dumps(reply,sort_keys=True,separators=(',',':')).encode()
            need(peer.sendmsg([payload],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                                         array.array('i',[guard_fd]))]) == len(payload),
                 'stopped_guard_handoff_failed')
            peer.settimeout(max(0.001,deadline-time.monotonic()))
            completion = json.loads(_receive_no_fds(peer),object_pairs_hook=unique)
            need(completion == {'schema':'aegis_auto_guardian_stopped_guard_complete_v1',
                                'command':'SEAL_DONE',
                                'actor_challenge':request['actor_challenge'],
                                'guardian_nonce':nonce} and
                 _pid_alive(pidfd) and time.monotonic() < deadline and
                 _held_install(install_fd) and
                 _held_lock(guard_fd,GUARD_LOCK) ==
                 (reply['guard_dev'],reply['guard_ino']) and
                 _stopped_guard_pid1(request['unit'],
                     request['prior_invocation_id']) and
                 read_guard_policy()['policy_sha256'] ==
                 request['post_deny_policy_sha256'] and
                 not (INSTALL.parent/'foreign-policy-drift.json').exists() and
                 not STOP_INTENT.exists(),
                 'stopped_guard_completion_changed')
            final = {'schema':'aegis_auto_guardian_stopped_guard_complete_reply_v1',
                     'actor_challenge':request['actor_challenge'],
                     'guardian_nonce':nonce}
            peer.sendall(json.dumps(final,sort_keys=True,separators=(',',':')).encode())
            # The client keeps its duplicate through the outer read-only command.
            # Closing ours after ACK would expose its still-held duplicate as an
            # unknown root OFD to the monitor. Retain ours until client closes the
            # duplicate first and then the socket, or until the existing lease
            # deadline fails closed.
            peer.settimeout(max(0.001,deadline-time.monotonic()))
            need(peer.recv(1) == b'',
                 'stopped_guard_completion_channel_changed')
            while not _stopped_peer_guard_closed(pid,pidfd,
                                                  (reply['guard_dev'],reply['guard_ino'])):
                need(time.monotonic() < deadline,
                     'stopped_guard_peer_fd_retained_after_eof')
                time.sleep(min(0.01,max(0,deadline-time.monotonic())))
        finally:
            if guard_fd is not None:os.close(guard_fd)
            with self.active_guard_mutex:
                need(self.stopped_guard_session == request['actor_challenge'],
                     'stopped_guard_session_replaced')
                self.stopped_guard_session = None

    def _boot_guard_session(self, peer, pid, pidfd, request, fds,
                            installation, guardian_identity):
        """Read-only fresh-boot guard lease; never inherits an old stage/grant."""
        own_source()
        keys = {'schema','command','actor_challenge','boot_id','netns_ino',
                'boot_snapshot_sha256','active_report_sha256',
                'predecessor_boot_id','candidate_sha256',
                'private_unit','prior_invocation_id'}
        need(set(request) == keys and len(fds) == 1 and
             request['schema'] == 'aegis_auto_guardian_boot_guard_v1' and
             request['command'] == 'SEAL_BOOT_GUARD' and
             all(type(request[k]) is str and HEX64.fullmatch(request[k]) for k in
                 ('actor_challenge','boot_snapshot_sha256',
                  'active_report_sha256','candidate_sha256')) and
             type(request['predecessor_boot_id']) is str and
             type(request['private_unit']) is str and
             PRIVATE_UNIT.fullmatch(request['private_unit']) and
             type(request['prior_invocation_id']) is str and
             HEX32.fullmatch(request['prior_invocation_id']) and
             request['boot_id'] == host_anchor()['boot_id'] and
             request['netns_ino'] == host_anchor()['netns_ino'] and
             request['predecessor_boot_id'] != request['boot_id'],
             'boot_guard_request_invalid')
        _peer_executable(pid, installation['worker_sha256'])
        need(_pid_alive(pidfd), 'boot_guard_worker_exited')
        install_fd = fds[0]
        _held_install(install_fd)
        need(request['candidate_sha256'] == installation['worker_sha256'],
             'boot_guard_candidate_changed')
        snapshot_identity, active_identity = _boot_guard_binding(request)
        # A cross-boot watchdog recovery journal may still hold its own OFD.
        # Wait for its archived, deny-proven terminal rather than claiming a
        # new guard while the monitor interprets that old-boot journal.
        _boot_pending_absent()
        reserve_deadline = time.monotonic() + STOPPED_GUARD_MONITOR_WAIT
        with self.active_guard_idle:
            need(self.stopped_guard_session is None,
                 'boot_guard_read_already_present')
            self.stopped_guard_session = request['actor_challenge']
            try:
                while self.mutation_admissions != 0:
                    remaining = reserve_deadline - time.monotonic()
                    need(remaining > 0, 'boot_guard_mutation_drain_deadline')
                    self.active_guard_idle.wait(remaining)
                need(self.active_guard_fd is None and
                     self.active_stage_fd is None and
                     self.active_grant is None and self.active_request is None and
                     self.active_capture is None and self.active_unit is None,
                     'boot_guard_active_lease_present')
                with self.launch_mutex:
                    need(not self.launches, 'boot_guard_launch_present')
            except BaseException:
                self.stopped_guard_session = None
                self.active_guard_idle.notify_all()
                raise
        guard_fd = None
        try:
            _boot_pending_absent()
            guard_fd = _stopped_guard_claim()
            deadline = time.monotonic() + BOOT_GUARD_LEASE_SECONDS
            _boot_pending_absent()
            own_source()
            _held_install(install_fd)
            need(_boot_guard_binding(request) ==
                 (snapshot_identity,active_identity),
                 'boot_guard_lineage_changed')
            policy = read_guard_policy()
            need(_pid_alive(pidfd), 'boot_guard_worker_exited')
            nonce = secrets.token_hex(32)
            reply = {'schema':'aegis_auto_guardian_boot_guard_held_v1',
                     'actor_challenge':request['actor_challenge'],
                     'guardian_nonce':nonce,
                     'guardian_invocation_id':guardian_identity['InvocationID'],
                     'boot_id':request['boot_id'],
                     'netns_ino':request['netns_ino'],
                     'boot_snapshot_sha256':snapshot_identity,
                     'active_report_sha256':request['active_report_sha256'],
                     'predecessor_boot_id':request['predecessor_boot_id'],
                     'candidate_sha256':request['candidate_sha256'],
                     'private_unit':request['private_unit'],
                     'prior_invocation_id':request['prior_invocation_id'],
                     'guard_dev':os.fstat(guard_fd).st_dev,
                     'guard_ino':os.fstat(guard_fd).st_ino}
            payload = json.dumps(reply,sort_keys=True,separators=(',',':')).encode()
            need(peer.sendmsg([payload],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                                         array.array('i',[guard_fd]))]) == len(payload),
                 'boot_guard_handoff_failed')
            peer.settimeout(max(0.001,deadline-time.monotonic()))
            completion = json.loads(_receive_no_fds(peer),object_pairs_hook=unique)
            need(completion == {'schema':'aegis_auto_guardian_boot_guard_complete_v1',
                                'command':'SEAL_DONE',
                                'actor_challenge':request['actor_challenge'],
                                'guardian_nonce':nonce} and
                 _pid_alive(pidfd) and time.monotonic() < deadline and
                 _held_install(install_fd) and
                 _held_lock(guard_fd,GUARD_LOCK) ==
                 (reply['guard_dev'],reply['guard_ino']) and
                 _boot_guard_binding(request) ==
                 (snapshot_identity,active_identity) and
                 read_guard_policy() == policy and
                 not STOP_INTENT.exists() and
                 not (INSTALL.parent/'foreign-policy-drift.json').exists(),
                 'boot_guard_completion_changed')
            _boot_pending_absent()
            final = {'schema':'aegis_auto_guardian_boot_guard_complete_reply_v1',
                     'actor_challenge':request['actor_challenge'],
                     'guardian_nonce':nonce}
            peer.sendall(json.dumps(final,sort_keys=True,separators=(',',':')).encode())
            peer.settimeout(max(0.001,deadline-time.monotonic()))
            need(peer.recv(1) == b'', 'boot_guard_completion_channel_changed')
            while not _stopped_peer_guard_closed(pid,pidfd,
                                                 (reply['guard_dev'],reply['guard_ino'])):
                need(time.monotonic() < deadline,
                     'boot_guard_peer_fd_retained_after_eof')
                time.sleep(min(0.01,max(0,deadline-time.monotonic())))
        finally:
            if guard_fd is not None: os.close(guard_fd)
            with self.active_guard_mutex:
                need(self.stopped_guard_session == request['actor_challenge'],
                     'boot_guard_session_replaced')
                self.stopped_guard_session = None
                self.active_guard_idle.notify_all()

    def serve_one(self, peer: socket.socket) -> None:
        stage_fd = install_fd = guard_fd = pidfd = None
        watchdog = None
        watchdog_committed = False
        watchdog_disarmed = False
        mutation_reserved = False
        try:
            peer.settimeout(LEASE_SECONDS)
            installation = record(INSTALL)
            guardian_identity = _unit_identity(GUARDIAN_UNIT, os.getpid())
            pid, pidfd = _peer_identity(peer)
            request, fds = _receive(peer)
            if request.get("command") == "SEAL_BOOT_GUARD":
                try:
                    self._boot_guard_session(peer, pid, pidfd, request, fds,
                                             installation, guardian_identity)
                finally:
                    for descriptor in fds:
                        os.close(descriptor)
                return
            if request.get("command") == "SEAL_STOPPED_GUARD":
                try:
                    self._stopped_guard_session(peer, pid, pidfd, request, fds,
                                                installation, guardian_identity)
                finally:
                    for descriptor in fds:
                        os.close(descriptor)
                return
            if request.get("command") != "INSPECT_LIVE":
                # Reserve before any guardian mutation. A stopped observer and
                # a new capture/launch/stop command cannot cross this gate.
                try:
                    with self.active_guard_mutex:
                        need(self.stopped_guard_session is None,
                             "stopped_guard_read_in_progress")
                        self.mutation_admissions += 1
                        mutation_reserved = True
                except BaseException:
                    for descriptor in fds:
                        os.close(descriptor)
                    raise
            if request.get("command") == "INSPECT_LIVE":
                try:
                    self._inspect_live(peer, pid, pidfd, request, fds,
                                       installation)
                finally:
                    for descriptor in fds:
                        os.close(descriptor)
                return
            if request.get("command") == "REGISTER_LAUNCH":
                try:
                    _peer_executable(pid, installation["worker_sha256"])
                except BaseException:
                    for descriptor in fds:
                        os.close(descriptor)
                    raise
                self._launch_session(peer, pidfd, request, fds,
                                     guardian_identity)
                return
            if request.get("command") == "BIND_BEGIN":
                try:
                    need(not fds, "bind_fd_unexpected")
                    _bind_request(request, fds)
                    with self.active_guard_mutex:
                        need(self.active_guard_fd is not None and
                             self.active_stage_fd is not None and
                             self.active_request is not None and
                             self.active_grant is not None,
                             "no_active_owner_guard_lease")
                        inherited = os.dup(self.active_guard_fd)
                        stage_copy = os.dup(self.active_stage_fd)
                        original = dict(self.active_request)
                        active_grant = dict(self.active_grant)
                        authenticated_lineage = (
                            self.active_lineage)
                    try:
                        need(_pid_alive(pidfd), "bind_control_peer_exited")
                        _peer_executable(pid, _installed_main_digest(
                            stage_copy, original))
                        need(_pid_alive(pidfd), "bind_control_peer_exited")
                        bind_deadline = time.monotonic() + BIND_TRANSACTION_SECONDS
                        _send_bind_handoff(peer, pid, pidfd, request, inherited,
                                           stage_copy, original, active_grant)
                        _seal_held_private_bind(peer, pid, pidfd, request,
                                                inherited, stage_copy,
                                                original, active_grant,
                                                bind_deadline,
                                                authenticated_lineage)
                        with self.active_guard_mutex:
                            self.active_unit = request["unit"]
                    finally:
                        os.close(inherited)
                        os.close(stage_copy)
                finally:
                    for descriptor in fds:
                        os.close(descriptor)
                return
            if request.get("command") in ("STOP_BEGIN", "STOP_CLEAN"):
                try:
                    _stop_request(request, fds)
                    with self.watchdog_mutex:
                        stop_watchdog = self.watchdogs.get(request.get("unit"))
                    with self.active_guard_mutex:
                        need(self.active_unit is None or
                             self.active_unit == request.get("unit"),
                             "stop_unit_mismatch_with_held_lease")
                        inherited = (os.dup(self.active_guard_fd)
                                     if self.active_guard_fd is not None else None)
                        stop_stage = (os.dup(self.active_stage_fd)
                                      if self.active_stage_fd is not None else None)
                        stop_original = (dict(self.active_request)
                                         if self.active_request is not None else None)
                    try:
                        if inherited is None:
                            with self.watchdog_mutex:
                                need(stop_watchdog is not None and
                                     self.watchdogs.get(request["unit"]) is
                                     stop_watchdog,
                                     "stop_missing_original_guard_lease")
                                inherited = stop_watchdog.borrow_guard_fd()
                        if (stop_stage is not None and stop_original is not None and
                                stop_original["private_unit"] == request["unit"]):
                            main_sha = _installed_main_digest(stop_stage,
                                                              stop_original)
                        else:
                            with self.launch_mutex:
                                main_sha = self.main_digests.get(request["unit"])
                            need(stop_watchdog is not None and main_sha is not None,
                                 "stop_missing_installed_main_generation")
                        need(_pid_alive(pidfd), "stop_control_peer_exited")
                        _peer_executable(pid, main_sha)
                        need(_pid_alive(pidfd), "stop_control_peer_exited")
                        with self.watchdog_mutex:
                            need(self.watchdogs.get(request["unit"]) is
                                 stop_watchdog,
                                 "stop_watchdog_replaced")
                            _stop_effect(peer, pid, pidfd, request, fds,
                                         inherited, stop_watchdog)
                    finally:
                        if inherited is not None:
                            os.close(inherited)
                        if stop_stage is not None:
                            os.close(stop_stage)
                finally:
                    for descriptor in fds:
                        os.close(descriptor)
                return
            if request.get("command") == "STOP_INVERSE":
                try:
                    _peer_executable(pid, installation["worker_sha256"])
                except BaseException:
                    for descriptor in fds:
                        os.close(descriptor)
                    raise
                if len(fds) != 2:
                    for descriptor in fds:
                        os.close(descriptor)
                    raise Refused("fresh_inverse_two_owner_fds_required")
                inverse_stage_fd, inverse_install_fd = fds
                inverse_guard_fd = None
                try:
                    with self.watchdog_mutex:
                        stopped_watchdog = self.watchdogs.get(request.get("unit"))
                        need(stopped_watchdog is not None,
                             "fresh_inverse_watchdog_missing")
                        inverse_guard_fd = stopped_watchdog.borrow_guard_fd()
                    assessment_fd = _stop_assessment_reservation(inverse_guard_fd)
                    try:
                        proof = _fresh_stop_inverse(request, inverse_stage_fd, inverse_install_fd,
                                                    inverse_guard_fd)
                        _held_lock(assessment_fd, ASSESSMENT_LOCK)
                    finally:
                        os.close(assessment_fd)
                    proof_bytes = json.dumps(proof, sort_keys=True,
                                             separators=(",", ":")).encode()
                    need(len(proof_bytes) <= MAX_REQUEST and
                         peer.sendmsg([proof_bytes],
                                      [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                        array.array("i", [inverse_guard_fd]))]) ==
                         len(proof_bytes), "fresh_inverse_guard_handoff_failed")
                    peer.settimeout(LEASE_SECONDS)
                    packet = _receive_no_fds(peer)
                    need(packet == b"INVERSE_COMPLETE\n" and
                         _pid_alive(pidfd), "fresh_inverse_completion_missing")
                    _complete_fresh_stop_inverse(request, proof, inverse_stage_fd,
                                                 inverse_install_fd, inverse_guard_fd)
                    stopped_watchdog.disarm()
                    with self.watchdog_mutex:
                        need(self.watchdogs.get(request["unit"]) is stopped_watchdog,
                             "fresh_stop_watchdog_replaced")
                        self.watchdogs.pop(request["unit"])
                    # The owner retains its own stage/install locks and the
                    # handed-off original guard OFD through this reply.
                    os.close(inverse_stage_fd)
                    inverse_stage_fd = None
                    os.close(inverse_install_fd)
                    inverse_install_fd = None
                    os.close(inverse_guard_fd)
                    inverse_guard_fd = None
                    peer.sendall(b"COMPLETE\n")
                    return
                finally:
                    if inverse_stage_fd is not None:
                        os.close(inverse_stage_fd)
                    if inverse_install_fd is not None:
                        os.close(inverse_install_fd)
                    if inverse_guard_fd is not None:
                        os.close(inverse_guard_fd)
            if len(fds) != 3:
                for descriptor in fds:
                    os.close(descriptor)
                raise Refused("three_held_descriptors_required")
            stage_fd, install_fd, guard_fd = fds
            _peer_executable(pid, installation["worker_sha256"])
            _prove_request(request, fds)
            deadline = time.monotonic() + LEASE_SECONDS
            _held_install(install_fd)
            stage_id = _stage(stage_fd, request, initial=True)
            initial_header_raw = _protected_stage_receipt_for_header(stage_fd)
            need(digest(initial_header_raw) == request["header_sha256"],
                 "stage_header_changed")
            initial_header = json.loads(initial_header_raw,
                                        object_pairs_hook=unique)
            need(type(initial_header) is dict and
                 initial_header.get("phase") == "metadata" and
                 initial_header.get("capture_started") is False,
                 "capture_registration_stage_not_metadata")
            guard_id = _claim_guard_handoff(guard_fd)
            # The worker transfers an unlocked guard OFD.  Reauthenticate the
            # current-boot carrier only after the source-bound guardian has
            # claimed that same OFD, and before policy or native grant proof.
            authenticated_lineage = (
                _currentboot_consumption_before_first_grant(
                    install_fd, guard_fd))
            policy = _policy(request, guard_id)
            need(request["boot_id"] == Path("/proc/sys/kernel/random/boot_id")
                 .read_text(encoding="ascii").strip(), "boot_changed")
            watchdog_module = verified_module(
                WATCHDOG_SOURCE, "aegis_auto_guardian_watchdog")
            watchdog = watchdog_module.WatchdogClient()
            watchdog.arm(guard_fd=guard_fd, worker_pidfd=pidfd,
                         stage_fd=stage_fd,
                         private_unit=request["private_unit"])
            # A native witness must bind this exact policy to a fresh packet
            # and an independent sink.  Until it succeeds, send no positive
            # grant.  Import is local to the installed, digest-bound source.
            native = _prove_installed_deny(request, policy, guard_fd)
            need(native.get("ack") is True and
                 native.get("guard_policy_sha256") == policy["policy_sha256"],
                 "native_deny_not_proven")
            need(_policy(request, guard_id)["policy_sha256"] ==
                 policy["policy_sha256"],
                 "deny_policy_semantics_changed_after_witness")
            if request["mode"] in ("wide-redirect-safe", "full-wide-tun"):
                scoped = _scoped_config_binding(
                    stage_fd, request, policy["policy_sha256"])
                local = _local_config_binding(
                    stage_fd, request, policy["policy_sha256"],
                    authenticated_lineage=
                    authenticated_lineage, phase='grant')
                need((scoped is None) != (local is None) if
                     request["mode"] == "wide-redirect-safe" else
                     scoped is None,
                     "redirect_profile_ambiguous")
                redirect = verified_module(POLICY_SOURCE,
                                           "aegis_auto_guard_policy")
                if scoped is not None:
                    # The watchdog is already armed. This INPUT gate denies
                    # direct access before the private listener can start;
                    # PREROUTING is activated only after Main/READY.
                    redirect.scoped_prepare(scoped)
                elif local is not None:
                    redirect.local_prepare(local)
            need(time.monotonic() < deadline and _held_guard(guard_fd) == guard_id and
                 _held_install(install_fd) and
                 _pid_alive(pidfd) and
                 _stage(stage_fd, request, initial=True) == stage_id,
                 "lease_changed_before_grant")
            need(watchdog.revalidate()["phase"] == "REGISTERED",
                 "watchdog_pregrant_lease_lost")
            grant = {"schema": "aegis_auto_guardian_grant_v1",
                     "nonce": os.urandom(32).hex(), "native_receipt_sha256":
                     digest(json.dumps(native, sort_keys=True,
                                       separators=(",", ":")).encode()),
                     "actor_challenge": request["actor_challenge"],
                     "private_unit": request["private_unit"],
                     "pid": os.getpid(), "boot_id": request["boot_id"],
                     "netns_ino": request["netns_ino"],
                     "stage_dev": stage_id[0], "stage_ino": stage_id[1],
                     "policy_sha256": policy["policy_sha256"],
                     "guardian_invocation_id": guardian_identity["InvocationID"],
                     "guardian_cgroup": guardian_identity["ControlGroup"],
                     "guardian_source_sha256": record(INSTALL)["guardian_sha256"],
                     "guard_drop_handle": native["guard_drop_handle"],
                     "guard_output_drop_delta": native["guard_output_drop_delta"],
                     "trace_id": native["trace_id"],
                     "trace_sha256": native["trace_sha256"],
                     "sink_pid": native["sink_pid"],
                     "sink_netns_ino": native["sink_netns_ino"],
                     "sink_session": native["sink_session"],
                     "sink_received": native["sink_received"],
                     "baseline_sha256": native["baseline_sha256"],
                     "baseline_method": "af_packet_l2",
                     "topology_inverse_proven": True,
                     "ipv6_trace_sha256": native["ipv6_witness"]["trace_sha256"],
                     "ipv6_sink_received": native["ipv6_witness"]["sink_received"],
                     "ipv6_guard_drop_delta": native["ipv6_witness"]["guard_output_drop_delta"],
                     "foreign_policy_class": native["foreign_policy_class"],
                     "foreign_policy_backend": native["foreign_policy_backend"],
                     "foreign_projection_sha256": native["foreign_projection_sha256"]}
            with self.active_guard_mutex:
                need(self.active_guard_fd is None, "another_guard_lease_active")
                self.active_guard_fd = os.dup(guard_fd)
                self.active_stage_fd = os.dup(stage_fd)
                self.active_request = dict(request)
                self.active_grant = dict(grant)
                self.active_lineage = (
                    authenticated_lineage)
            peer.sendall(json.dumps(grant, sort_keys=True,
                                    separators=(",", ":")).encode())
            captured: dict[str, object] | None = None
            prepared = False
            capture_failed = False
            while time.monotonic() < deadline:
                peer.settimeout(max(0.001, deadline - time.monotonic()))
                payload = _receive_no_fds(peer)
                need(payload, "effect_packet_invalid")
                if payload == b"PREPARE_COMPLETE\n":
                    need(not capture_failed and captured is not None and not prepared,
                         "capture_readiness_missing")
                    need(_held_guard(guard_fd) == guard_id and
                         _held_install(install_fd) and _pid_alive(pidfd) and
                         _stage(stage_fd, request, initial=False) == stage_id and
                         _policy(request, guard_id)["policy_sha256"] ==
                         captured["post_policy_sha256"],
                         "lease_changed_after_effect")
                    prepared = True
                    peer.sendall(b"PREPARED\n")
                    continue
                if payload == b"COMMIT_DONE\n":
                    need(not capture_failed and prepared and captured is not None and
                         _held_install(install_fd) and _pid_alive(pidfd),
                         "effect_not_prepared")
                    _finalized_commit(request, grant, captured,
                                      stage_fd, guard_fd,
                                      handoff_present=True)
                    need(watchdog.revalidate()["phase"] == "LATCHED",
                         "watchdog_pre_handoff_lease_lost")
                    peer.sendall(b"PREPARED_HANDOFF\n")
                    packet = _receive_no_fds(peer)
                    need(packet == b"HANDOFF_CLEARED\n" and
                         _pid_alive(pidfd) and _held_install(install_fd),
                         "owner_handoff_clear_not_acknowledged")
                    _finalized_commit(request, grant, captured,
                                      stage_fd, guard_fd,
                                      handoff_present=False)
                    watchdog.commit_active(
                        digest(_protected_stage_receipt(
                            stage_fd, "receipts/activation-owner/terminal.json")),
                        capture_sha256=captured["sha256"],
                        original_policy_sha256=grant["policy_sha256"],
                        post_policy_sha256=captured["post_policy_sha256"])
                    with self.watchdog_mutex:
                        need(request["private_unit"] not in self.watchdogs,
                             "watchdog_active_lease_replaced")
                        self.watchdogs[request["private_unit"]] = watchdog
                    watchdog_committed = True
                    self._release_active_guard_copies(guard_fd, request)
                    os.close(stage_fd)
                    stage_fd = None
                    os.close(install_fd)
                    install_fd = None
                    os.close(guard_fd)
                    guard_fd = None
                    peer.sendall(b"COMPLETE\n")
                    return
                effect = json.loads(payload, object_pairs_hook=unique)
                need(type(effect) is dict, "invalid_effect_packet")
                _effect_common(effect, request, grant, stage_id)
                need(_held_install(install_fd) and _pid_alive(pidfd) and
                     _stage(stage_fd, request, initial=False) == stage_id,
                     "effect_owner_changed")
                if effect.get("command") == "COMPENSATED_STOP":
                    inverse = _post_stop_inverse(effect, request, grant,
                                                 guard_fd, stage_fd, captured)
                    peer.sendall(json.dumps(inverse, sort_keys=True,
                                            separators=(",", ":")).encode())
                    payload = _receive_no_fds(peer)
                    need(payload == b"INVERSE_COMPLETE\n" and
                         _pid_alive(pidfd) and _held_install(install_fd),
                         "compensated_inverse_completion_missing")
                    _complete_compensated_inverse(effect, request, grant, inverse,
                                                  guard_fd, stage_fd)
                    watchdog.disarm()
                    watchdog_disarmed = True
                    self._release_active_guard_copies(guard_fd, request)
                    os.close(stage_fd)
                    stage_fd = None
                    os.close(install_fd)
                    install_fd = None
                    os.close(guard_fd)
                    guard_fd = None
                    peer.sendall(b"COMPLETE\n")
                    return
                if effect.get("command") in ("CAPTURE_READY",
                                             "CAPTURE_REVALIDATE"):
                    need(not capture_failed, "capture_already_refused")
                    _capture_request_shape(effect, request)
                    captured, reply, capture_failed, latch_proven = self._capture_authorized_effect(
                        effect, request, grant, guard_fd, stage_fd,
                        initial_header, captured, watchdog)
                    if capture_failed:
                        _capture_refusal_owner_held(
                            request, guard_fd, guard_id, install_fd,
                            stage_fd, stage_id, pidfd, watchdog,
                            allow_registered=(effect["command"] == "CAPTURE_READY"
                                              and captured is None and
                                              not latch_proven))
                        with self.active_guard_mutex:
                            need(self.active_request == request and
                                 self.active_grant == grant,
                                 "capture_refusal_launch_owner_changed")
                    peer.sendall(json.dumps(reply, sort_keys=True,
                                            separators=(",", ":")).encode())
                    continue
                raise Refused("unknown_effect_command")
            raise Refused("guardian_effect_deadline_elapsed")
        finally:
            if watchdog is not None and not (watchdog_committed or
                                             watchdog_disarmed):
                try:
                    watchdog.fail_closed("guardian_abort")
                except (OSError, ValueError, RuntimeError, TimeoutError,
                        subprocess.SubprocessError):
                    # The independent actor still watches this PID and its
                    # durable journal.  Failure cannot become a positive ACK.
                    pass
            with self.active_guard_mutex:
                if self.active_guard_fd is not None and guard_fd is not None:
                    active = os.fstat(self.active_guard_fd)
                    own = os.fstat(guard_fd)
                    if (active.st_dev, active.st_ino) == (own.st_dev, own.st_ino):
                        os.close(self.active_guard_fd)
                        self.active_guard_fd = None
                        if self.active_stage_fd is not None:
                            os.close(self.active_stage_fd)
                        self.active_stage_fd = None
                        self.active_request = None
                        self.active_grant = None
                        self.active_lineage = None
                        self.active_capture = None
                        self.active_unit = None
            if mutation_reserved:
                with self.active_guard_mutex:
                    self.mutation_admissions -= 1
                    need(self.mutation_admissions >= 0,
                         "guardian_mutation_admission_underflow")
                    self.active_guard_idle.notify_all()
            if pidfd is not None:
                os.close(pidfd)
            if stage_fd is not None:
                os.close(stage_fd)
            if install_fd is not None:
                os.close(install_fd)
            if guard_fd is not None:
                os.close(guard_fd)
            peer.close()

    def _capture_authorized_effect(
        self, effect: dict[str, object], request: dict[str, object],
        grant: dict[str, object], guard_fd: int, stage_fd: int,
        initial_header: dict[str, object],
        captured: dict[str, object] | None, watchdog: object,
    ) -> tuple[dict[str, object] | None, dict[str, object], bool, bool]:
        # The caller has checked the original owner, job shape and live held
        # descriptors. An effect failure leaves the channel for exact inverse.
        latch_proven = captured is not None
        try:
            if captured is None:
                watchdog.latch(effect["pid1_invocation_id"])
                latch_proven = True
            need(watchdog.revalidate()["phase"] == "LATCHED",
                 "watchdog_effect_lease_lost")
            with self.active_guard_mutex:
                need(self.active_request == request and
                     self.active_grant == grant,
                     "capture_launch_owner_changed")
                authenticated_lineage = self.active_lineage
            next_capture, reply = _capture_effect(
                effect, request, grant, guard_fd, stage_fd,
                initial_header, captured, authenticated_lineage)
            with self.active_guard_mutex:
                need(self.active_request == request and
                     self.active_grant == grant,
                     "capture_launch_owner_changed")
                self.active_capture = {
                    "unit": request["private_unit"],
                    "nonce": request["transaction_nonce"],
                    "invocation": effect["pid1_invocation_id"],
                    "sha256": next_capture["sha256"]}
            return next_capture, reply, False, latch_proven
        except Exception as error:
            # Include refusals after the last packet callback (for example,
            # final lease/policy readback) in the existing closed diagnostic
            # stream. _capture_step emits only fixed source coordinates and an
            # allowlisted error class; the authenticated reply is unchanged.
            _capture_step("failure", mode=request["mode"], error=error)
            if request["mode"] == "full-wide-tun" and (
                    CAPTURE_BINDING.exists() or CAPTURE_BINDING.is_symlink()):
                # A late numeric permission must never survive a refused
                # capture while the original guard OFD remains available.
                # The receipt removal, kernel block and semantic seal must
                # share the monitor's full-assessment reservation too.
                assessment_fd = _stop_assessment_reservation(guard_fd)
                try:
                    _run_helper_in_cgroup(GUARD_HELPER, "block", guard_fd)
                    _held_lock(assessment_fd, ASSESSMENT_LOCK)
                finally:
                    os.close(assessment_fd)
            return captured, _capture_refusal_reply(effect, error), True, latch_proven

    def serve(self) -> None:
        self.open()
        try:
            while True:
                try:
                    need(self.server is not None, "guardian_not_open")
                    peer, _ = self.server.accept()
                    self.workers = {worker for worker in self.workers
                                    if worker.is_alive()}
                    if len(self.workers) >= 4:
                        peer.close()
                        raise Refused("too_many_guardian_requests")
                    worker = threading.Thread(target=self._serve_worker,
                                              args=(peer,), daemon=True)
                    self.workers.add(worker)
                    worker.start()
                except (Refused, OSError, ValueError, RuntimeError, TimeoutError,
                        subprocess.SubprocessError):
                    # The independent deny unit stays armed.  A failed
                    # request never emits a serialized grant.
                    continue
        finally:
            self.close()

    def _serve_worker(self, peer: socket.socket) -> None:
        try:
            self.serve_one(peer)
        except Exception as error:
            # A request may contain private paths or credentials. Journal
            # only an allowlisted reason and bounded pinned-source coordinates.
            reason = _request_refusal_tag(error)
            detail = ""
            if reason == "os_error" and isinstance(error, OSError):
                detail = _os_error_location(error)
            elif reason in ("runtime_error", "value_error", "timeout_error",
                            "subprocess_error"):
                detail = _runtime_error_location(error)
            elif reason in ("unexpected_exception", "refused_unclassified"):
                source_id, line = _pinned_error_location(
                    error, skip_assertion_helper=True)
                if source_id != "unknown":
                    detail = f" source={source_id} line={line}"
            print("aegis_auto_guardian_request_refused:" +
                  reason + detail, file=sys.stderr, flush=True)
            peer.close()


def _cold_guard_phase_hint(cold_root: Path, boot: str) -> Path:
    """Pick a current-boot head path; native binds the head and intent SHA."""
    if not cold_root.exists() and not cold_root.is_symlink():
        return cold_root
    top=cold_root.lstat()
    need(stat.S_ISDIR(top.st_mode) and top.st_uid==top.st_gid==0 and
         stat.S_IMODE(top.st_mode)==0o700,
         'cold_guard_root_untrusted')
    names=os.listdir(cold_root)
    prefix='attempt-head-'+boot+'-'
    heads=[name for name in names if name.startswith(prefix)]
    need(len(names)<=512 and len(heads)<=1 and
         all(re.fullmatch(r'attempt-head-'+boot+r'-[0-9a-f]{64}\.json',
                          name) for name in heads),
         'cold_guard_current_head_ambiguous')
    if not heads:return cold_root
    raw=regular(cold_root/heads[0],8192,0o600)
    head=json.loads(raw,object_pairs_hook=unique)
    need(raw==(json.dumps(head,sort_keys=True,
              separators=(',',':'))+'\n').encode('ascii') and
         type(head) is dict and
         set(head)=={'schema','current_boot_id','prior_boot_id',
                     'prior_intent_sha256','original_intent_sha256',
                     'barrier_sha256','attempt_intent_sha256','attempt_dir'} and
         head['schema']=='aegis_auto_terminal_cold_attempt_head_v1' and
         head['current_boot_id']==boot and
         type(head['prior_intent_sha256']) is str and
         HEX64.fullmatch(head['prior_intent_sha256']) and
         type(head['attempt_intent_sha256']) is str and
         HEX64.fullmatch(head['attempt_intent_sha256']) and
         heads[0]=='attempt-head-'+boot+'-'+
             head['attempt_intent_sha256']+'.json',
         'cold_guard_current_head_invalid')
    phase=cold_root/'attempts'/(
        boot+'-'+head['prior_intent_sha256'])
    info=phase.lstat()
    need(head['attempt_dir']==str(phase) and stat.S_ISDIR(info.st_mode) and
         info.st_uid==info.st_gid==0 and
         stat.S_IMODE(info.st_mode)==0o700 and
         info.st_dev==top.st_dev,
         'cold_guard_phase_untrusted')
    return phase


def cold_denied_readback(install_fd: int, guard_fd: int,
                         retained_root: Path, *, stale_prior_sha: str | None = None,
                         old_rotation_sha: str | None = None) -> dict[str, object]:
    """Read-only current-boot deny proof for an interrupted A-to-B package.

    The native caller authenticates the retained release and this exact script
    before exec. This function rechecks the release sources on both sides of
    the kernel/PID1 observation; it never admits the installed INSTALL receipt
    as its source authority while dpkg may be half configured.
    """
    need(os.geteuid() == 0 and sys.platform.startswith("linux") and
         type(install_fd) is int and type(guard_fd) is int and
         3 <= install_fd <= 1024 and 3 <= guard_fd <= 1024 and
         install_fd != guard_fd and
         retained_root.is_absolute() and
         re.fullmatch(r"/var/lib/aegis-auto/releases/[A-Za-z0-9-]{16,128}",
                      str(retained_root)), "cold_readback_args")
    need((stale_prior_sha is None and old_rotation_sha is None) or
         (type(stale_prior_sha) is str and HEX64.fullmatch(stale_prior_sha) and
          type(old_rotation_sha) is str and HEX64.fullmatch(old_rotation_sha)),
         'cold_stale_source_args')
    _held_lock(install_fd, INSTALL_LOCK)
    guard_identity = _held_lock(guard_fd, GUARD_LOCK)
    own = retained_root / "scripts/lib/aegis_auto_guardian.py"
    need(Path(__file__).resolve() == own and own != SOURCE,
         "cold_source_location")
    sums_raw = regular(retained_root / "SHA256SUMS", 4 << 20, 0o444)
    sums = {}
    for line in sums_raw.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./@-]+)", line)
        need(match is not None and match[2] not in sums,
             "cold_source_manifest_invalid")
        sums[match[2]] = match[1]
    names = ("aegis_auto_guardian.py", "aegis_auto_foreign_policy.py",
             "aegis_auto_native_witness.py", "aegis_auto_guard_policy.py")
    sources = {}
    for name in names:
        relative = "scripts/lib/" + name
        raw = regular(retained_root / relative, 1 << 20, 0o444)
        need(digest(raw) == sums.get(relative), "cold_source_manifest_changed")
        sources[name] = raw
    need(digest(sources["aegis_auto_guardian.py"]) ==
         digest(regular(own, 1 << 20, 0o444)), "cold_executable_changed")
    modules = {}
    for name in names[1:]:
        stem = name[:-3]
        need(stem not in sys.modules, "cold_module_identity_changed")
        module = types.ModuleType(stem)
        module.__file__ = str(retained_root / "scripts/lib" / name)
        sys.modules[stem] = module
        try:
            exec(compile(sources[name], module.__file__, "exec", dont_inherit=True),
                 module.__dict__)
        except BaseException:
            sys.modules.pop(stem, None)
            raise
        modules[stem] = module
    def optional(path,maximum,mode):
        try:
            return regular(path,maximum,mode)
        except FileNotFoundError:
            need(not path.is_symlink(),'cold_foreign_symlink')
            return None
    terminal_source_path=Path('/etc/aegis-auto-terminal-source.json')
    terminal_source_raw=optional(terminal_source_path,4096,0o600)
    terminal_source=(json.loads(terminal_source_raw,object_pairs_hook=unique)
                     if terminal_source_raw is not None else None)
    if terminal_source is not None:
        need(type(terminal_source) is dict and
             terminal_source.get('schema')=='aegis_auto_terminal_source_v1',
             'cold_terminal_source_invalid')
    selected=[]
    for name in ('NetworkManager.service','systemd-networkd.service'):
        leaf=Path('/etc/systemd/system')/(name+'.d')/'30-aegis-device-guard.conf'
        if leaf.exists() or leaf.is_symlink():
            raw=regular(leaf,1 << 16,0o644)
            need(b'Requires=aegis-device-egress-guard.service\n' in raw and
                 b'After=aegis-device-egress-guard.service' in raw,
                 'cold_guard30_source_changed')
            selected.append((name,raw))
    need(len(selected)==1,'cold_selected_manager_ambiguous')
    selected_manager,guard30_raw=selected[0]
    need(terminal_source is None or
         terminal_source.get('selected_manager')==selected_manager,
         'cold_terminal_manager_changed')
    guard30_path = (Path('/etc/systemd/system') /
                    (selected_manager + '.d') / '30-aegis-device-guard.conf')
    manager31_path = (Path('/etc/systemd/system') /
                      (selected_manager + '.d') /
                      '31-aegis-auto-terminal-transition.conf')
    guardian31_path = Path('/etc/systemd/system/aegis-auto-guardian.service.d/'
                           '31-aegis-auto-terminal-transition.conf')
    need(regular(guard30_path,1 << 16,0o644)==guard30_raw,
         'cold_guard30_generation_changed')
    manager31_raw = optional(manager31_path, 1 << 16, 0o644)
    guardian31_raw = optional(guardian31_path, 1 << 16, 0o644)
    transition_dropin = (b'[Unit]\nRequires=aegis-auto-terminal-transition.service\n'
                         b'After=aegis-auto-terminal-transition.service\n')
    for raw in (manager31_raw,guardian31_raw):
        need(raw is None or raw==transition_dropin,
             'cold_manager_transition_source_changed')
    if terminal_source is not None:
        need(terminal_source.get('manager_transition_dropin_sha256')==
             digest(transition_dropin) and
             terminal_source.get('guardian_transition_dropin_sha256')==
             digest(transition_dropin),
             'cold_manager_transition_pin_changed')
    deadline = time.monotonic() + 30.0
    cold_dir=Path('/var/lib/aegis-install/client/terminal-migrations/cold-recovery')
    if stale_prior_sha is not None:
        cold_dir=(cold_dir/'attempts'/
                  (host_anchor()['boot_id']+'-'+stale_prior_sha))
    else:
        cold_dir=_cold_guard_phase_hint(cold_dir,host_anchor()['boot_id'])
    phase01_path=cold_dir/'phase-01.json'
    phase01_raw=optional(phase01_path,8192,0o600)
    phase01=None
    if phase01_raw is not None:
        phase01=json.loads(phase01_raw,object_pairs_hook=unique)
        need(type(phase01) is dict and set(phase01)=={
             'schema','intent_sha256','deny_policy_sha256',
             'pre_quiesce_infrastructure_sha256',
             'post_quiesce_infrastructure_sha256',
             'quiesce_monotonic_tick'} and
             phase01.get('schema')=='aegis_auto_terminal_cold_deny_v2' and
             type(phase01.get('quiesce_monotonic_tick')) is int and
             phase01['quiesce_monotonic_tick']>0 and
             all(type(phase01[key]) is str and HEX64.fullmatch(phase01[key])
                 for key in ('intent_sha256','deny_policy_sha256',
                             'pre_quiesce_infrastructure_sha256',
                             'post_quiesce_infrastructure_sha256')) and
             phase01_raw==(json.dumps(phase01,sort_keys=True,
                             separators=(',',':'))+'\n').encode('ascii'),
             'cold_quiesce_receipt_changed')
    phase02_raw=optional(cold_dir/'phase-02.json',8192,0o600)
    phase02=None
    if phase02_raw is not None:
        phase02=json.loads(phase02_raw,object_pairs_hook=unique)
        need(phase01 is not None and type(phase02) is dict and
             set(phase02)=={'schema','intent_sha256','proof_sha256',
                            'package_repaired_tick'} and
             phase02.get('schema')=='aegis_auto_terminal_cold_package_repaired_v2' and
             phase02.get('intent_sha256')==phase01['intent_sha256'] and
             type(phase02.get('package_repaired_tick')) is int and
             phase02['package_repaired_tick']>phase01['quiesce_monotonic_tick'] and
             type(phase02.get('proof_sha256')) is str and
             HEX64.fullmatch(phase02['proof_sha256']) and
             phase02_raw==(json.dumps(phase02,sort_keys=True,
                 separators=(',',':'))+'\n').encode('ascii'),
             'cold_package_repaired_receipt_changed')
    b_candidate=sums.get('bin/aegis-client')
    need(type(b_candidate) is str and HEX64.fullmatch(b_candidate),
         'cold_candidate_manifest_changed')
    installed_raw=optional(INSTALL,MAX_RECEIPT,0o600)
    installed=(json.loads(installed_raw,object_pairs_hook=unique)
               if installed_raw is not None else None)
    pre_a=phase01 is None and (
        stale_prior_sha is not None or
        installed_raw is not None and installed.get('worker_sha256')!=b_candidate)
    rotation=None
    def old_rotation():
        nonlocal rotation
        need(pre_a,'cold_old_actor_source_unavailable')
        if rotation is not None:return rotation
        if stale_prior_sha is None:
            rotation_raw=regular(ROTATION_INTENT,MAX_ROTATION_INTENT,0o600)
        else:
            try:
                rotation_raw=regular(ROTATION_INTENT,MAX_ROTATION_INTENT,0o600)
            except FileNotFoundError:
                archive=INSTALL.parent/('auto-guard-prior-intent-'+
                                        old_rotation_sha+'.json')
                rotation_raw=regular(archive,MAX_ROTATION_INTENT,0o600)
            need(digest(rotation_raw)==old_rotation_sha,
                 'cold_stale_rotation_source_changed')
        rotation=json.loads(rotation_raw,object_pairs_hook=unique)
        if stale_prior_sha is not None:
            archived_install=INSTALL.parent/(
                'auto-guardian-install-guarded-'+
                str(rotation.get('old_install_sha256'))+'.json')
            old_install_raw=regular(archived_install,MAX_RECEIPT,0o600)
        else:
            old_install_raw=installed_raw
        need(type(rotation) is dict and
             rotation.get('schema')=='aegis_auto_guard_rotation_intent_v1' and
             rotation.get('boot_id')!=host_anchor()['boot_id'] and
             digest(old_install_raw)==rotation.get('old_install_sha256'),
             'cold_prequiesce_source_changed')
        return rotation
    # Exact missing/partial terminal 31 leaves are classified by the native
    # site readback. Each live actor is separately bound to A or B bytes.
    def infrastructure():
        actors=_boot_actor_observation(deadline)
        enriched=[]
        for row in actors:
            unit=row['unit']
            path=next(path for name,_source,path in ROTATION_ACTORS
                      if name==unit)
            source=next(src for name,src,_path in ROTATION_ACTORS
                        if name==unit)
            facts=_rotation_actor_facts(unit,deadline=deadline)
            if row['active']:
                unit_sha=digest(regular(path,1 << 16,0o644))
                source_sha=digest(regular(source,1 << 20,0o500))
            else:
                unit_raw=optional(path,1 << 16,0o644)
                source_raw=optional(source,1 << 20,0o500)
                unit_sha=digest(unit_raw) if unit_raw is not None else None
                source_sha=digest(source_raw) if source_raw is not None else None
            start_tick=None
            if row['active']:
                pid=row['main_pid']
                loaded=subprocess.run(
                    ['/usr/bin/systemctl','show',unit,'--no-pager',
                     '-p','NeedDaemonReload','-p','DropInPaths'],
                    stdin=subprocess.DEVNULL,capture_output=True,check=False,
                    timeout=min(3,max(0.1,deadline-time.monotonic())),
                    env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
                need(loaded.returncode==0 and not loaded.stderr and
                     len(loaded.stdout)<=1024 and
                     loaded.stdout==b'NeedDaemonReload=no\nDropInPaths=\n',
                     'cold_actor_loaded_source_changed')
                stat_raw=Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
                pieces=stat_raw[stat_raw.rfind(')')+2:].split()
                need(len(pieces)>19,'cold_actor_stat_invalid')
                start_tick=int(pieces[19])
                if phase01 is not None and phase02 is not None:
                    need(installed is not None and
                         installed.get('worker_sha256')==b_candidate and
                         terminal_source is not None and
                         terminal_source.get('witness_sha256')==
                             sums.get('scripts/lib/aegis_auto_terminal_witness.py') and
                         start_tick>phase02['package_repaired_tick'] and
                         source_sha==sums.get('scripts/lib/'+source.name) and
                         unit_sha==sums.get('packaging/systemd/'+unit),
                         'cold_new_actor_source_changed')
                elif phase01 is None:
                    if (source_sha==sums.get('scripts/lib/'+source.name) and
                        unit_sha==sums.get('packaging/systemd/'+unit)):
                        pass
                    elif pre_a:
                        _rotation_actor_source(unit,old_rotation())
                    else:
                        need(False,'cold_prequiesce_actor_source_changed')
                else:
                    need(False,'cold_unqualified_infrastructure_active')
            enriched.append({**row,'start_tick':start_tick,
                             'source_sha256':source_sha,
                             'unit_sha256':unit_sha,
                             'control_group':facts['ControlGroup']})
        if phase01 is not None and phase02 is None:
            need(all(not row['active'] for row in actors),
                 'cold_infrastructure_before_package_cut')
        if phase01 is not None and installed is None:
            need(all(not row['active'] for row in actors),
                 'cold_actor_without_installed_source')
        raw=(json.dumps(enriched,sort_keys=True,separators=(',',':'))+'\n').encode()
        need(len(raw)<=16384,'cold_infrastructure_rows_oversize')
        return digest(raw),enriched,all(not row['active'] for row in actors)
    def observer():
        unit='aegis-auto-terminal-observer.service'
        names=('Id','LoadState','FragmentPath','DropInPaths',
               'NeedDaemonReload','UnitFileState','ActiveState','SubState',
               'MainPID','ControlPID','ControlGroup')
        argv=['/usr/bin/systemctl','show',unit,'--no-pager']
        for name in names:
            argv.extend(('-p',name))
        answer=subprocess.run(argv,capture_output=True,check=False,
                              timeout=min(3,max(0.1,deadline-time.monotonic())),
                              env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
        need(answer.returncode==0 and len(answer.stdout)<=8192 and
             not answer.stderr,'cold_observer_pid1_unavailable')
        facts={}
        for line in answer.stdout.decode('ascii').splitlines():
            key,sep,value=line.partition('=')
            need(sep=='=' and key not in facts,'cold_observer_pid1_invalid')
            facts[key]=value
        need(set(facts)==set(names) and facts['Id']==unit and
             facts['DropInPaths']=='' and
             facts['MainPID'].isdigit() and facts['ControlPID'].isdigit() and
             facts['ControlPID']=='0' and
             facts['UnitFileState'] in ('disabled','static','not-found'),
             'cold_observer_pid1_changed')
        if facts['ActiveState']=='inactive':
            need(facts['SubState']=='dead' and facts['MainPID']=='0' and
                 facts['ControlGroup'] in ('','/system.slice/'+unit) and
                 not Path('/run/aegis-auto-terminal').exists() and
                 not Path('/run/aegis-auto-terminal').is_symlink(),
                 'cold_observer_not_absent')
            if facts['ControlGroup']:
                group=Path('/sys/fs/cgroup')/facts['ControlGroup'].lstrip('/')
                need(not group.exists() or
                     group.joinpath('cgroup.procs').read_text(encoding='ascii')=='' and
                     group.joinpath('cgroup.events').read_text(
                         encoding='ascii').find('populated 0')>=0,
                     'cold_observer_cgroup_present')
            return ('absent',None,None)
        need(facts['ActiveState']=='active' and facts['SubState']=='running' and
             int(facts['MainPID'])>1 and facts['NeedDaemonReload']=='no' and
             facts['LoadState']=='loaded' and
             facts['FragmentPath']==
                 '/etc/systemd/system/aegis-auto-terminal-observer.service' and
             terminal_source is not None and
             terminal_source.get('witness_sha256')==
                 sums.get('scripts/lib/aegis_auto_terminal_witness.py') and
             installed is not None and
             installed.get('worker_sha256')==b_candidate,
             'cold_observer_active_source_changed')
        registrar_path=retained_root/'scripts/lib/aegis_auto_terminal_register.py'
        registrar_raw=regular(registrar_path,1 << 20,0o444)
        need(digest(registrar_raw)==
             sums.get('scripts/lib/aegis_auto_terminal_register.py'),
             'cold_observer_registrar_source_changed')
        module=types.ModuleType('aegis_cold_observer_readback')
        module.__file__=str(registrar_path)
        exec(compile(registrar_raw,str(registrar_path),'exec',dont_inherit=True),
             module.__dict__)
        ready=module.observer_ready()
        need(ready.get('observer_pid')==int(facts['MainPID']),
             'cold_observer_pid_changed')
        ready_raw=regular(Path('/run/aegis-auto-terminal/ready.json'),4096,0o600)
        return ('b_ready',terminal_source['witness_sha256'],digest(ready_raw))
    def client_instances_absent():
        for pattern,expression in (
            ('aegis-auto@*.service',r'aegis-auto@[0-9a-f]{64}\.service'),
            ('aegis-auto-terminal-a@*.service',
             r'aegis-auto-terminal-a@[0-9a-f]{64}\.service'),
            ('aegis-auto-terminal-b@*.service',
             r'aegis-auto-terminal-b@[0-9a-f]{64}\.service')):
            result=subprocess.run(
                ['/usr/bin/systemctl','list-units','--all',pattern,
                 '--no-legend','--no-pager','--plain'],
                capture_output=True,check=False,
                timeout=min(3,max(0.1,deadline-time.monotonic())),
                env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
            need(result.returncode==0 and len(result.stdout)<=1 << 16 and
                 not result.stderr,'cold_client_units_unavailable')
            for line in result.stdout.decode('ascii').splitlines():
                fields=line.split()
                need(len(fields)>=4 and
                     re.fullmatch(expression,fields[0]) and
                     fields[2:4]==['inactive','dead'],
                     'cold_client_unit_present')
                group=Path('/sys/fs/cgroup/system.slice')/fields[0]
                need(not group.exists() or
                     group.joinpath('cgroup.procs').read_text(encoding='ascii')=='' and
                     'populated 0' in group.joinpath('cgroup.events').read_text(
                         encoding='ascii'),
                     'cold_client_cgroup_present')
        # A failed boot-config unit may have Result=exit-code but cannot
        # retain a process, job or cgroup while cold deny is observed.
        names=('MainPID','ControlPID','ControlGroup','ActiveState','SubState')
        argv=['/usr/bin/systemctl','show','aegis-auto-config.service','--no-pager']
        for name in names:argv.extend(('-p',name))
        result=subprocess.run(argv,capture_output=True,check=False,
                              timeout=min(3,max(0.1,deadline-time.monotonic())),
                              env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
        need(result.returncode==0 and len(result.stdout)<=4096 and
             not result.stderr,'cold_boot_config_unavailable')
        fields=dict(line.split('=',1) for line in
                    result.stdout.decode('ascii').splitlines())
        need(set(fields)==set(names) and
             fields['MainPID']==fields['ControlPID']=='0' and
             fields['ActiveState'] in ('inactive','failed') and
             fields['ControlGroup'] in
                ('','/system.slice/aegis-auto-config.service'),
             'cold_boot_config_actor_present')
        if fields['ControlGroup']:
            group=Path('/sys/fs/cgroup')/fields['ControlGroup'].lstrip('/')
            need(not group.exists() or
                 group.joinpath('cgroup.procs').read_text(encoding='ascii')=='',
                 'cold_boot_config_cgroup_present')
    state_path = Path("/var/lib/aegis-install/client/device-guard.conf")
    saved = record(POLICY)
    need(saved.get("schema") == "aegis_auto_guardian_policy_v1" and
         saved.get("boot_id") == host_anchor()["boot_id"] and
         saved.get("netns_ino") == host_anchor()["netns_ino"] and
         saved.get("guard_dev") == guard_identity[0] and
         saved.get("guard_ino") == guard_identity[1],
         "cold_policy_receipt_changed")
    def guard_service_active():
        need(regular(GUARD_UNIT_FILE,1 << 16,0o644)==EXPECTED_GUARD_UNIT,
             'cold_guard_unit_source_changed')
        names=('Id','LoadState','FragmentPath','DropInPaths',
               'NeedDaemonReload','ActiveState','SubState',
               'MainPID','ControlPID','Result')
        argv=['/usr/bin/systemctl','show','aegis-device-egress-guard.service',
              '--no-pager']
        for name in names:argv.extend(('-p',name))
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,
                              check=False,
                              timeout=min(3,max(0.1,deadline-time.monotonic())),
                              env={'PATH':'/usr/sbin:/usr/bin',
                                   'LANG':'C','LC_ALL':'C'})
        need(result.returncode==0 and not result.stderr and
             len(result.stdout)<=8192,'cold_guard_pid1_unavailable')
        facts={}
        for line in result.stdout.decode('ascii').splitlines():
            key,sep,value=line.partition('=')
            need(sep=='=' and key not in facts,'cold_guard_pid1_invalid')
            facts[key]=value
        need(set(facts)==set(names) and
             facts['Id']=='aegis-device-egress-guard.service' and
             facts['LoadState']=='loaded' and
             facts['FragmentPath']==str(GUARD_UNIT_FILE) and
             facts['DropInPaths']=='' and facts['NeedDaemonReload']=='no' and
             facts['ActiveState']=='active' and facts['SubState']=='exited' and
             facts['MainPID']==facts['ControlPID']=='0' and
             facts['Result']=='success','cold_guard_pid1_changed')
    def observe():
        guard_service_active()
        state = regular(state_path, 1 << 15, 0o600)
        client_path = Path(str(state_path) + ".client-binding")
        manager_path = Path(str(state_path) + ".manager-binding")
        capture_path = CAPTURE_BINDING
        need(not client_path.exists() and not client_path.is_symlink() and
             not capture_path.exists() and not capture_path.is_symlink() and
             not manager_path.is_symlink(), "cold_client_binding_present")
        manager = regular(manager_path, 4096, 0o600) if manager_path.exists() else None
        witness = modules["aegis_auto_native_witness"]
        policy = modules["aegis_auto_guard_policy"]
        first = witness.read_policy_raw(Path("/usr/sbin/nft"), deadline=deadline)
        text = witness.read_policy_raw(Path("/usr/sbin/nft"), text=True,
                                       deadline=deadline)
        second = witness.read_policy_raw(Path("/usr/sbin/nft"), deadline=deadline)
        projection, _handles, _counters = witness.policy_projection(first)
        confirmed, _h2, _c2 = witness.policy_projection(second)
        need(policy.verify_expected_policy(state, first, text, None, manager,
                boot_id=host_anchor()["boot_id"], capture_binding=None) ==
             digest(projection), "cold_kernel_deny_changed")
        projection = policy.canonical_manager_projection(projection, manager)
        confirmed = policy.canonical_manager_projection(confirmed, manager)
        need(projection == confirmed and _no_client_grant(projection) and
             digest(state) == saved["state_sha256"] and
             digest(projection) == saved["policy_sha256"],
             "cold_kernel_deny_changed")
        _boot_fixed_client_stopped(deadline)
        _boot_private_owners_absent(deadline)
        client_instances_absent()
        infra_sha,actors,quiescent=infrastructure()
        observer_state,observer_source_sha,observer_ready_sha=observer()
        need(not STOP_INTENT.exists() and not STOP_INTENT.is_symlink() and
             not WATCHDOG_PENDING.exists() and not WATCHDOG_PENDING.is_symlink(),
             "cold_stop_or_rescue_pending")
        return (digest(state), digest(projection),
                digest(manager) if manager is not None else None,
                infra_sha,actors,quiescent,
                observer_state,observer_source_sha,observer_ready_sha)
    try:
        first = observe()
        second = observe()
        need(first == second and time.monotonic() < deadline,
             "cold_observation_changed")
        for name, raw in sources.items():
            need(regular(retained_root / "scripts/lib" / name, 1 << 20, 0o444) == raw,
                 "cold_source_generation_changed")
        need(optional(terminal_source_path,4096,0o600) ==
             terminal_source_raw and
             optional(phase01_path,8192,0o600) == phase01_raw and
             optional(cold_dir/'phase-02.json',8192,0o600) == phase02_raw and
             regular(guard30_path,1 << 16,0o644) == guard30_raw and
             optional(manager31_path,1 << 16,0o644) == manager31_raw and
             optional(guardian31_path,1 << 16,0o644) == guardian31_raw,
             'cold_manager_generation_changed')
        _held_lock(install_fd, INSTALL_LOCK)
        need(_held_lock(guard_fd, GUARD_LOCK) == guard_identity and
             record(POLICY) == saved, "cold_owner_changed")
        return {"schema":("aegis_auto_guard_cold_stale_denied_readback_v1"
                          if stale_prior_sha is not None else
                          "aegis_auto_guard_cold_denied_readback_v2"),
                **({'prior_intent_sha256':stale_prior_sha,
                    'rotation_intent_sha256':old_rotation_sha}
                   if stale_prior_sha is not None else {}),
                "boot_id":host_anchor()["boot_id"],
                "selected_manager":selected_manager,
                "guard30_sha256":digest(guard30_raw),
                "manager31_sha256":(None if manager31_raw is None else
                                     digest(manager31_raw)),
                "guardian31_sha256":(None if guardian31_raw is None else
                                      digest(guardian31_raw)),
                "state_sha256":first[0], "policy_sha256":first[1],
                "manager_binding_sha256":first[2],
                "observer_state":first[6],
                "observer_source_sha256":first[7],
                "observer_ready_sha256":first[8],
                "infrastructure_rows_sha256":first[3],
                "infrastructure_rows":first[4],
                "infrastructure_quiescent":first[5],
                "infrastructure_qualified":True,
                "quiesce_state":'post' if phase01 is not None else 'pre',
                "quiesce_receipt_sha256":(digest(phase01_raw)
                    if phase01_raw is not None else None),
                "quiesce_monotonic_tick":(phase01['quiesce_monotonic_tick']
                    if phase01 is not None else None),
                "package_repair_receipt_sha256":(digest(phase02_raw)
                    if phase02_raw is not None else None),
                "package_repaired_tick":(phase02['package_repaired_tick']
                    if phase02 is not None else None),
                "client_actors_absent":True,"jobs_absent":True,
                "cgroups_empty":True,"stop_intent_absent":True}
    finally:
        for name, module in modules.items():
            if sys.modules.get(name) is module:
                sys.modules.pop(name, None)


if __name__ == "__main__":
    if (len(sys.argv)==6 and sys.argv[1]=='cold-archive-retired-readback' and
        sys.argv[5]=='--retained-source' and
        re.fullmatch(r'[0-9]{1,4}',sys.argv[2]) and
        3<=int(sys.argv[2])<=1024 and
        HEX64.fullmatch(sys.argv[3]) is not None):
        print(json.dumps(cold_archive_retired_readback(
            int(sys.argv[2]),sys.argv[3],Path(sys.argv[4])),
            sort_keys=True,separators=(',',':')))
    elif (len(sys.argv) == 8 and
        sys.argv[1] == 'cold-stale-denied-readback' and
        all(re.fullmatch(r'[0-9]{1,4}',value) and 3 <= int(value) <= 1024
            for value in sys.argv[2:4]) and sys.argv[2] != sys.argv[3] and
        re.fullmatch(r'/var/lib/aegis-auto/releases/[A-Za-z0-9-]{16,128}',
                     sys.argv[4]) and
        all(HEX64.fullmatch(value) for value in sys.argv[5:7]) and
        sys.argv[7]=='--retained-source'):
        print(json.dumps(cold_denied_readback(int(sys.argv[2]),int(sys.argv[3]),
            Path(sys.argv[4]),stale_prior_sha=sys.argv[5],
            old_rotation_sha=sys.argv[6]),sort_keys=True,separators=(',',':')))
    elif (len(sys.argv) == 6 and
        sys.argv[1] == 'cold-denied-readback' and
        all(re.fullmatch(r'[0-9]{1,4}',value) and 3 <= int(value) <= 1024
            for value in sys.argv[2:4]) and sys.argv[2] != sys.argv[3] and
        re.fullmatch(r'/var/lib/aegis-auto/releases/[A-Za-z0-9-]{16,128}',
                     sys.argv[4]) and
        sys.argv[5] == '--retained-source'):
        print(json.dumps(cold_denied_readback(int(sys.argv[2]), int(sys.argv[3]),
                        Path(sys.argv[4])),
                         sort_keys=True,separators=(',',':')))
    elif sys.argv == [str(SOURCE), "serve"]:
        Guardian().serve()
    elif len(sys.argv) == 3 and sys.argv[0:2] == [str(SOURCE), "provision"]:
        print(json.dumps(provision_receipt(Path(sys.argv[2])), sort_keys=True,
                         separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "seal-policy", "9"]:
        print(json.dumps(seal_policy_receipt(9), sort_keys=True,
                         separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "capture-binding-index", "9"]:
        print(capture_binding_index(9))
    elif sys.argv == [str(SOURCE), "stopping-deny-readback", "9"]:
        print(json.dumps(stopping_deny_readback(9), sort_keys=True,
                         separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "read-guard-policy"]:
        print(json.dumps(read_guard_policy(), sort_keys=True,
                         separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "archive-stale-manager", "9"]:
        print(archive_stale_manager_binding(9))
    elif (len(sys.argv) == 5 and
          sys.argv[:2] == [str(SOURCE), "prepare-guard-rotation"] and
          sys.argv[2].isascii() and sys.argv[2].isdecimal() and
          str(int(sys.argv[2])) == sys.argv[2] and int(sys.argv[2]) > 2):
        prepared = prepare_guard_rotation(int(sys.argv[2]), Path(sys.argv[3]),
                                          Path(sys.argv[4]))
        print(json.dumps(prepared, sort_keys=True, separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "rotation-preflight", "9"]:
        print(rotation_preflight(9))
    elif (len(sys.argv) == 3 and sys.argv[:2] ==
          [str(SOURCE), "verify-rotation-monitor-stop"] and
          sys.argv[2].isascii() and sys.argv[2].isdecimal() and
          str(int(sys.argv[2])) == sys.argv[2] and int(sys.argv[2]) > 2):
        print(json.dumps(verify_rotation_monitor_stop(int(sys.argv[2])),
                         sort_keys=True, separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "rotation-commit-deny", "9"]:
        print(json.dumps(commit_rotation_deny(9), sort_keys=True,
                         separators=(",", ":")))
    elif (len(sys.argv) == 4 and
          sys.argv[:2] == [str(SOURCE), "retire-rotation-actors"] and
          sys.argv[2].isascii() and sys.argv[2].isdecimal() and
          str(int(sys.argv[2])) == sys.argv[2] and int(sys.argv[2]) > 2 and
          sys.argv[3].isascii() and sys.argv[3].isdecimal() and
          str(int(sys.argv[3])) == sys.argv[3] and int(sys.argv[3]) > 2 and
          sys.argv[2] != sys.argv[3]):
        print(json.dumps(retire_rotation_actors(int(sys.argv[2]),
                                                int(sys.argv[3])),
                         sort_keys=True, separators=(",", ":")))
    elif (len(sys.argv) == 3 and
          sys.argv[:2] == [str(SOURCE), "rotation-retired-readback"] and
          sys.argv[2].isascii() and sys.argv[2].isdecimal() and
          str(int(sys.argv[2])) == sys.argv[2] and int(sys.argv[2]) > 2):
        print(json.dumps(rotation_retired_readback(int(sys.argv[2])),
                         sort_keys=True, separators=(",", ":")))
    elif (len(sys.argv) == 4 and
          sys.argv[:2] == [str(SOURCE), "admit-guarded-rotation"] and
          all(value.isascii() and value.isdecimal() and
              str(int(value)) == value and int(value) > 2
              for value in sys.argv[2:]) and
          sys.argv[2] != sys.argv[3]):
        print(admit_guarded_rotation(int(sys.argv[2]), int(sys.argv[3])))
    elif (len(sys.argv) == 4 and
          sys.argv[:2] == [str(SOURCE), "rotation-admitted-readback"] and
          all(value.isascii() and value.isdecimal() and
              str(int(value)) == value and int(value) > 2
              for value in sys.argv[2:]) and
          sys.argv[2] != sys.argv[3]):
        print(json.dumps(rotation_admitted_readback(int(sys.argv[2]),
                                                   int(sys.argv[3])),
                         sort_keys=True, separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "admit-passive-successor", "9"]:
        print(admit_passive_successor(9))
    elif sys.argv == [str(SOURCE), "passive-successor-admitted-readback", "9"]:
        print(json.dumps(passive_successor_admitted_readback(9),
                         sort_keys=True, separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "passive-successor-staged-readback", "9"]:
        print(json.dumps(passive_successor_staged_readback(9),
                         sort_keys=True, separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "passive-successor-progress-readback", "9"]:
        print(json.dumps(passive_successor_progress_readback(9),
                         sort_keys=True, separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "passive-successor-progress-wait", "9"]:
        print(json.dumps(passive_successor_progress_wait(9),
                         sort_keys=True, separators=(",", ":")))
    elif (len(sys.argv) == 4 and
          sys.argv[:2] == [str(SOURCE), "rotation-state-handoff"] and
          all(value.isascii() and value.isdecimal() and
              str(int(value)) == value and int(value) > 2
              for value in sys.argv[2:]) and
          sys.argv[2] != sys.argv[3]):
        print(json.dumps(rotation_state_handoff(int(sys.argv[2]),
                                                int(sys.argv[3])),
                         sort_keys=True, separators=(",", ":")))
    elif (len(sys.argv) == 4 and
          sys.argv[:2] == [str(SOURCE), "boot-denied-readback"] and
          all(value.isascii() and value.isdecimal() and
              str(int(value)) == value and int(value) > 2
              for value in sys.argv[2:]) and
          sys.argv[2] != sys.argv[3]):
        print(json.dumps(boot_denied_readback(int(sys.argv[2]),
                                              int(sys.argv[3])),
                         sort_keys=True, separators=(",", ":")))
    elif (len(sys.argv) == 3 and
          sys.argv[:2] == [str(SOURCE), "boot-passive-readback"] and
          sys.argv[2].isascii() and sys.argv[2].isdecimal() and
          str(int(sys.argv[2])) == sys.argv[2] and int(sys.argv[2]) > 2):
        print(json.dumps(boot_passive_readback(int(sys.argv[2])),
                         sort_keys=True, separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "upgrade-guard"]:
        print("upgraded" if upgrade_guard_receipt() else "already-admitted")
    elif sys.argv == [str(SOURCE), "upgrade-and-seal-policy", "9"]:
        _held_lock(9, GUARD_LOCK)
        upgrade_guard_receipt()
        print(json.dumps(seal_policy_receipt(9), sort_keys=True,
                         separators=(",", ":")))
    elif sys.argv == [str(SOURCE), "bind-seal", "8"]:
        bind_seal_client(8)
    elif sys.argv == [str(SOURCE), "bind-foreign-assess", "8"]:
        bind_seal_client(8,foreign_only=True)
    else:
        raise Refused("fixed_guardian_command_required")
