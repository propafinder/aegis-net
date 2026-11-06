#!/usr/bin/env python3
"""Source-bound AUTO cross-boot stop transaction. No network effect by itself.

The entrypoint receives already held InstallLock and GuardLock descriptors from
an installed caller. It never invents a terminal witness or kernel-deny proof.
"""
from __future__ import annotations
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time
import types

ROOT = Path('/var/lib/aegis-install/client')
STOP = ROOT / 'auto-stop-intent.json'
CONSUMED_PREFIX = 'auto-terminal-consumed-'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
PRIVATE = re.compile(r'aegis-auto@[0-9a-f]{64}\.service\Z')
SOURCE = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_boot_transition.py')
SOURCE_CONFIG = Path('/etc/aegis-auto-terminal-source.json')
STORE_CONFIG = Path('/etc/aegis-auto-terminal-store.json')
MIGRATION_PENDING = Path('/var/lib/aegis-install/client/terminal-migrations/pending.json')
COLD_ROOT = MIGRATION_PENDING.parent/'cold-recovery'
COLD_PHASE3 = COLD_ROOT/'phase-03.json'
COLD_READY = COLD_ROOT/'transition-ready.json'
INSTALL_LOCK = Path('/run/aegis-auto-install.lock')
GUARD_LOCK = ROOT/'device-guard.conf.lock'
GUARDIAN_SOURCE = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py')

_ROLLOVER_HEAD_KEYS=frozenset({
    'schema','current_boot_id','prior_boot_id','prior_intent_sha256',
    'original_intent_sha256','barrier_sha256','attempt_intent_sha256',
    'attempt_dir'})

class Refused(RuntimeError):
    pass

def need(ok: bool, reason: str) -> None:
    if not ok:
        raise Refused(reason)

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate_key')
        result[key] = value
    return result

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def read(path: Path, limit=8192) -> bytes:
    # All parents are root-owned, non-writable, non-symlink directories.
    for parent in reversed(path.parents):
        if parent == Path('/'):
            continue
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0 and
             not s.st_mode & 0o022, 'parent_untrusted')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
             stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
             0 < before.st_size <= limit, 'leaf_untrusted')
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        named = path.lstat()
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(raw) == before.st_size and
             all(getattr(before, k) == getattr(after, k) == getattr(named, k) for k in keys),
             'leaf_changed')
        return raw
    finally:
        os.close(fd)

def decode(raw):
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict, 'record_not_object')
    return value

def _cold_rollover_hint(current_boot):
    """Select a path hint only; native re-proves the head before effects."""
    if not COLD_ROOT.exists() and not COLD_ROOT.is_symlink():
        return None
    top=COLD_ROOT.lstat()
    need(stat.S_ISDIR(top.st_mode) and top.st_uid==top.st_gid==0 and
         stat.S_IMODE(top.st_mode)==0o700,'rollover_root_untrusted')
    names=os.listdir(COLD_ROOT)
    need(len(names)<=512,'rollover_root_roster_bound')
    prefix='attempt-head-'+current_boot+'-'
    current=[name for name in names if name.startswith(prefix)]
    need(len(current)<=1,'rollover_current_head_ambiguous')
    if not current:return None
    name=current[0]
    need(re.fullmatch(r'attempt-head-'+re.escape(current_boot)+
                      r'-[0-9a-f]{64}\.json',name),
         'rollover_current_head_name')
    raw=read(COLD_ROOT/name,8192)
    head=decode(raw)
    need(canonical(head)==raw and set(head)==_ROLLOVER_HEAD_KEYS and
         head['schema']=='aegis_auto_terminal_cold_attempt_head_v1' and
         head['current_boot_id']==current_boot and
         type(head['prior_intent_sha256']) is str and
         HEX64.fullmatch(head['prior_intent_sha256']) and
         type(head['attempt_intent_sha256']) is str and
         HEX64.fullmatch(head['attempt_intent_sha256']) and
         head['attempt_intent_sha256']==name[-69:-5] and
         (head['barrier_sha256'] is None or
          type(head['barrier_sha256']) is str and
          HEX64.fullmatch(head['barrier_sha256'])),
         'rollover_current_head_invalid')
    phase=COLD_ROOT/'attempts'/(
        current_boot+'-'+head['prior_intent_sha256'])
    need(head['attempt_dir']==str(phase),'rollover_attempt_path_changed')
    info=phase.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and
         stat.S_IMODE(info.st_mode)==0o700 and info.st_dev==top.st_dev,
         'rollover_attempt_dir_untrusted')
    return phase,head

def write_new(path: Path, raw: bytes) -> None:
    need(0 < len(raw) <= 8192 and not path.exists() and not path.is_symlink(),
         'publication_collision')
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            need(os.write(fd, raw) == len(raw), 'publication_short_write')
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(dfd)
        need(read(path) == raw, 'publication_changed')
    finally:
        os.close(dfd)

def write_new_atomic(path: Path, raw: bytes) -> None:
    """Publish a complete cold barrier with no visible partial final name."""
    need(sys.platform.startswith('linux') and 0 < len(raw) <= 8192 and
         not path.exists() and not path.is_symlink(),
         'atomic_publication_collision')
    dfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        fd=os.open(path.parent,os.O_TMPFILE|os.O_WRONLY|os.O_CLOEXEC,0o600)
        try:
            offset=0
            while offset<len(raw):
                written=os.write(fd,raw[offset:])
                need(written>0,'atomic_publication_short_write')
                offset+=written
            os.fsync(fd)
            import ctypes
            libc=ctypes.CDLL(None,use_errno=True)
            linkat=libc.linkat
            linkat.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,
                             ctypes.c_char_p,ctypes.c_int)
            linkat.restype=ctypes.c_int
            need(linkat(fd,b'',dfd,os.fsencode(path.name),0x1000)==0,
                 'atomic_publication_link_refused')  # AT_EMPTY_PATH
            os.fsync(dfd)
            need(read(path,8192)==raw,'atomic_publication_changed')
        finally:
            os.close(fd)
    finally:
        os.close(dfd)

def validate_old(intent, current_boot):
    need(set(intent) == {'schema', 'boot_id', 'invocation_id', 'service', 'phase'} and
         intent['schema'] == 'aegis_auto_stop_intent_v1' and
         intent['phase'] == 'deny_proven' and
         type(intent['boot_id']) is str and UUID.fullmatch(intent['boot_id']) and
         intent['boot_id'] != current_boot and
         type(intent['invocation_id']) is str and
         re.fullmatch(r'[0-9a-f]{32}', intent['invocation_id']) and
         type(intent['service']) is str and PRIVATE.fullmatch(intent['service']),
         'old_stop_invalid')

def validate_marker(marker, intent_raw, current_boot, source_sha, boot_uuid):
    need(type(marker) is dict and set(marker) ==
         {'schema', 'old_boot_id', 'boot_uuid', 'source_sha256', 'intent_sha256',
          'nonce', 'a_sha256', 'clean_stop_sha256', 'b_sha256', 'policy_sha256',
          'active_generation_sha256', 'active_report_sha256', 'boot_snapshot_sha256',
          'final_job', 'final_job_type', 'action', 'pid1_tick',
          'root_uuid', 'root_dev', 'boot_dev', 'hook_sha256', 'helper_sha256'} and
         marker['schema'] == 'aegis_auto_terminal_boot_v1' and
         marker['old_boot_id'] == decode(intent_raw)['boot_id'] and
         marker['old_boot_id'] != current_boot and
         marker['boot_uuid'] == boot_uuid and
         type(marker['root_uuid']) is str and UUID.fullmatch(marker['root_uuid']) and
         type(marker['root_dev']) is str and re.fullmatch(r'[0-9]+:[0-9]+', marker['root_dev']) and
         type(marker['boot_dev']) is str and re.fullmatch(r'[0-9]+:[0-9]+', marker['boot_dev']) and
         all(type(marker[k]) is str and HEX64.fullmatch(marker[k])
             for k in ('hook_sha256', 'helper_sha256')) and
         marker['source_sha256'] == source_sha and
         marker['intent_sha256'] == sha(intent_raw) and
         marker['final_job_type'] == 'start' and
         marker['action'] in ('reboot', 'poweroff') and
         type(marker['final_job']) is int and 0 < marker['final_job'] < 1 << 32 and
         type(marker['pid1_tick']) is int and 0 <= marker['pid1_tick'] < 1 << 64 and
         type(marker['nonce']) is str and re.fullmatch(r'[0-9a-f]{32}', marker['nonce']) and
         all(type(marker[k]) is str and HEX64.fullmatch(marker[k])
             for k in ('a_sha256', 'clean_stop_sha256', 'b_sha256', 'policy_sha256',
                       'active_generation_sha256','active_report_sha256',
                       'boot_snapshot_sha256')),
         'marker_invalid')

def consumed_path(current_boot: str) -> Path:
    need(type(current_boot) is str and UUID.fullmatch(current_boot), 'boot_id_invalid')
    return ROOT / (CONSUMED_PREFIX + current_boot + '.json')

def read_consumed_record(current_boot: str, *, allow_missing: bool = False):
    """Read-only storage parser, never an authorization predicate."""
    if STOP.exists() or STOP.is_symlink():
        if allow_missing:
            return None
        raise Refused('current_or_old_stop_intent_present')
    try:
        raw = read(consumed_path(current_boot))
    except FileNotFoundError:
        if allow_missing:
            return None
        raise
    value = decode(raw)
    common = {'schema', 'old_boot_id', 'new_boot_id', 'old_intent_sha256',
              'marker_sha256', 'recovered_sha256', 'policy_sha256',
              'source_sha256', 'nonce'}
    v1 = value.get('schema') == 'aegis_auto_terminal_consumed_v1'
    v2 = value.get('schema') == 'aegis_auto_terminal_consumed_v2'
    need(((v1 and set(value) == common) or
          (v2 and set(value) == common | {'old_policy_sha256'} and
           type(value['old_policy_sha256']) is str and
           HEX64.fullmatch(value['old_policy_sha256']) and
           value['old_policy_sha256'] != value['policy_sha256'])) and
         value['new_boot_id'] == current_boot and
         value['old_boot_id'] != current_boot and
         all(type(value[k]) is str and HEX64.fullmatch(value[k])
             for k in ('old_intent_sha256', 'marker_sha256', 'recovered_sha256',
                       'policy_sha256', 'source_sha256')),
         'consumed_invalid')
    archive = ROOT / ('auto-stop-intent-' + value['old_boot_id'] + '-' +
                      value['old_intent_sha256'] + '.json')
    need(sha(read(archive)) == value['old_intent_sha256'], 'archived_stop_changed')
    return value


def old_consumed_policy(receipt: dict) -> str:
    """Historical v1 has one seal; v2 keeps the old marker seal distinct."""
    return receipt['old_policy_sha256'] if receipt['schema'] == \
        'aegis_auto_terminal_consumed_v2' else receipt['policy_sha256']


def recovered_policy_origin(recovered: dict, current_boot: str,
                            old_policy_sha: str, current_policy_sha: str) -> None:
    """Bind a selected watchdog archive to its producer's boot domain.

    A same-boot RECOVERED archive has no recovery_boot_id and seals the old
    BOOT marker. A watchdog replay after reboot writes recovery_boot_id and
    seals the new deny policy. The no-journal cut has a separate exact schema.
    """
    if 'recovery_boot_id' in recovered:
        need(recovered['recovery_boot_id'] == current_boot and
             recovered.get('policy_sha256') == current_policy_sha,
             'recovered_current_policy_changed')
    else:
        need(recovered.get('policy_sha256') == old_policy_sha,
             'recovered_old_policy_changed')


def transition_dropin_path(unit: str) -> Path:
    need(unit in ('NetworkManager.service', 'systemd-networkd.service',
                  'aegis-auto-guardian.service'), 'transition_dropin_unit_invalid')
    return (Path('/etc/systemd/system') / (unit + '.d') /
            '31-aegis-auto-terminal-transition.conf')

def historical_carriers_closed(store: dict, source: dict) -> None:
    """An old BOOT carrier cannot silently become an unconsumed new boot."""
    directory = Path('/boot')/store['boot_store_dir']
    entries = tuple(directory.iterdir())
    consumed_names = tuple(p for p in ROOT.iterdir() if
                           p.name.startswith(CONSUMED_PREFIX))
    need(len(entries) <= 128 and len(consumed_names) <= 128,
         'terminal_history_oversize')
    for carrier in entries:
        if not carrier.name.startswith('terminal-'):
            continue
        raw = read(carrier)
        row = decode(raw)
        need(row.get('schema') == 'aegis_auto_terminal_boot_v1' and
             carrier.name == ('terminal-'+row['old_boot_id']+'-'+
                              row['nonce']+'.json'),
             'terminal_history_carrier_invalid')
        _historical_source, old_store = historical_source_context(
            row.get('source_sha256'), source, store, sha(raw))
        need(row.get('hook_sha256') == old_store['hook_sha256'] and
             row.get('helper_sha256') == old_store['helper_sha256'] and
             row.get('root_uuid') == old_store['root_uuid'] and
             row.get('boot_uuid') == old_store['boot_uuid'] and
             row.get('root_dev') == old_store['root_dev'] and
             row.get('boot_dev') == old_store['boot_dev'],
             'terminal_history_carrier_source')
        matches = []
        for candidate in consumed_names:
            prior = decode(read(candidate))
            if (prior.get('old_boot_id') == row['old_boot_id'] and
                prior.get('marker_sha256') == sha(raw)):
                matches.append(candidate)
        need(len(matches) == 1, 'terminal_unconsumed_carrier')

def recovered_for_old(intent: dict, current_boot: str) -> Path | None:
    """Select exactly one archived watchdog recovery, or a closed no-journal cut."""
    prefix = 'auto-watchdog-' + intent['service'][11:75] + '-recovered-'
    names = sorted(ROOT.iterdir(), key=lambda p: p.name)
    need(len(names) <= 512, 'recovery_roster_oversize')
    matching = []
    for path in names:
        if not path.name.startswith(prefix):
            continue
        need(re.fullmatch(re.escape(prefix) + r'[0-9a-f]{16}\.json', path.name),
             'recovery_archive_name_invalid')
        raw = read(path, 1 << 20)
        value = decode(raw)
        if value.get('boot_id') == intent['boot_id'] and value.get('private_unit') == intent['service']:
            need(value.get('phase') == 'RECOVERED', 'recovery_archive_phase_invalid')
            matching.append(path)
    need(len(matching) <= 1, 'recovery_archive_ambiguous')
    if matching:
        return matching[0]
    pending = ROOT / 'auto-watchdog-pending.json'
    need(not pending.exists() and not pending.is_symlink(),
         'pending_watchdog_without_recovery')
    return None


def authenticated_consumed(*, current_boot: str, marker_path: Path,
                           recovered_path: Path, source_sha: str, boot_uuid: str,
                           validate_locks, install_fd: int, guard_fd: int,
                           verify_block_and_owner) -> dict:
    """Grant-side predicate; the storage parser alone is insufficient."""
    validate_locks(install_fd, guard_fd)
    receipt = read_consumed_record(current_boot)
    intent_path = ROOT / ('auto-stop-intent-' + receipt['old_boot_id'] + '-' +
                          receipt['old_intent_sha256'] + '.json')
    old_raw = read(intent_path)
    validate_old(decode(old_raw), current_boot)
    marker_raw = read(marker_path)
    marker = decode(marker_raw)
    validate_marker(marker, old_raw, current_boot, source_sha, boot_uuid)
    recovered_raw = read(recovered_path, 1 << 20)
    recovered = decode(recovered_raw)
    selected = recovered_for_old(decode(old_raw), current_boot)
    if selected is None:
        expected_path = ROOT / ('auto-watchdog-no-journal-' +
                                receipt['old_boot_id'] + '-' +
                                receipt['old_intent_sha256'] + '.json')
        expected_recovered = {
            'schema': 'aegis_auto_terminal_no_journal_recovered_v1',
            'boot_id': receipt['old_boot_id'], 'recovery_boot_id': current_boot,
            'private_unit': decode(old_raw)['service'],
            'intent_sha256': receipt['old_intent_sha256'],
            'policy_sha256': receipt['policy_sha256']}
        need(recovered_path == expected_path and recovered == expected_recovered,
             'consumed_no_journal_changed')
    else:
        need(recovered_path == selected and
             recovered.get('schema') == 'aegis_auto_watchdog_pending_v1' and
             recovered.get('phase') == 'RECOVERED' and
             recovered.get('boot_id') == receipt['old_boot_id'] and
             recovered.get('private_unit') == decode(old_raw)['service'],
             'consumed_recovery_not_selected')
        recovered_policy_origin(recovered, current_boot,
                                old_consumed_policy(receipt),
                                receipt['policy_sha256'])
    need(sha(marker_raw) == receipt['marker_sha256'] and
         sha(recovered_raw) == receipt['recovered_sha256'] and
         receipt['source_sha256'] == source_sha and
             marker['policy_sha256'] == old_consumed_policy(receipt),
         'consumed_proof_mismatch')
    verify_block_and_owner(decode(old_raw), marker, recovered)
    validate_locks(install_fd, guard_fd)
    need(read_consumed_record(current_boot) == receipt and
         read(marker_path) == marker_raw and read(recovered_path, 1 << 20) == recovered_raw and
         read(intent_path) == old_raw,
         'consumed_proof_changed')
    return receipt


def consume_locked(*, install_fd: int, guard_fd: int, validate_locks,
                   current_boot: str, marker_path: Path, recovered_path: Path,
                   source_sha: str, boot_uuid: str, policy_sha: str,
                   verify_block_and_owner) -> dict:
    """One-shot durable transition after caller's complete source/PID1 proof.

    `validate_locks` and `verify_block_and_owner` are installed source-bound
    callables. The latter must recheck current kernel deny and old actor absence.
    This function grants no lease, network or policy mutation.
    """
    validate_locks(install_fd, guard_fd)
    need(UUID.fullmatch(current_boot) and UUID.fullmatch(boot_uuid) and
         HEX64.fullmatch(source_sha) and HEX64.fullmatch(policy_sha), 'input_invalid')
    intent_raw = read(STOP)
    intent = decode(intent_raw)
    validate_old(intent, current_boot)
    marker_raw = read(marker_path)
    marker = decode(marker_raw)
    validate_marker(marker, intent_raw, current_boot, source_sha, boot_uuid)
    # The old marker seals the old kernel. A new boot may have removed exactly
    # the authenticated old manager DHCP exception before network-pre. The
    # installed callback proves both sealed policies under the held locks.
    selected = recovered_for_old(intent, current_boot)
    need(recovered_path is None or recovered_path == selected,
         'recovery_selection_changed')
    recovered_path = selected
    if recovered_path is None:
        # R9 proves the watchdog may have no pending journal. Do not invent
        # a recovered watchdog transaction in that branch. Verify the closed
        # no-journal state and publish a distinct, deny-only receipt.
        pending = ROOT / 'auto-watchdog-pending.json'
        need(not pending.exists() and not pending.is_symlink(),
             'pending_watchdog_without_recovery')
        recovered = {'schema': 'aegis_auto_terminal_no_journal_recovered_v1',
                     'boot_id': intent['boot_id'],
                     'recovery_boot_id': current_boot,
                     'private_unit': intent['service'],
                     'intent_sha256': sha(intent_raw),
                     'policy_sha256': policy_sha}
        recovered_raw = canonical(recovered)
        recovered_path = ROOT / ('auto-watchdog-no-journal-' +
                                 intent['boot_id'] + '-' + sha(intent_raw) + '.json')
        verify_block_and_owner(intent, marker, recovered)
        if recovered_path.exists() or recovered_path.is_symlink():
            need(read(recovered_path, 1 << 20) == recovered_raw, 'no_journal_changed')
        else:
            write_new(recovered_path, recovered_raw)
    else:
        recovered_raw = read(recovered_path, 1 << 20)
        recovered = decode(recovered_raw)
        need(recovered.get('schema') == 'aegis_auto_watchdog_pending_v1' and
             recovered.get('phase') == 'RECOVERED' and
             recovered.get('boot_id') == intent['boot_id'] and
             recovered.get('private_unit') == intent['service'],
             'recovered_invalid')
        recovered_policy_origin(recovered, current_boot,
                                marker['policy_sha256'], policy_sha)
    verify_block_and_owner(intent, marker, recovered)
    validate_locks(install_fd, guard_fd)
    need(read(STOP) == intent_raw and read(marker_path) == marker_raw and
         read(recovered_path, 1 << 20) == recovered_raw, 'proof_changed')
    archive = ROOT / ('auto-stop-intent-' + intent['boot_id'] + '-' + sha(intent_raw) + '.json')
    if archive.exists() or archive.is_symlink():
        need(read(archive) == intent_raw, 'archive_changed')
    else:
        write_new(archive, intent_raw)
    result = {'schema': ('aegis_auto_terminal_consumed_v1'
                         if marker['policy_sha256'] == policy_sha else
                         'aegis_auto_terminal_consumed_v2'),
              'old_boot_id': intent['boot_id'], 'new_boot_id': current_boot,
              'old_intent_sha256': sha(intent_raw), 'marker_sha256': sha(marker_raw),
              'recovered_sha256': sha(recovered_raw), 'policy_sha256': policy_sha,
              'source_sha256': source_sha, 'nonce': marker['nonce']}
    if marker['policy_sha256'] != policy_sha:
        result['old_policy_sha256'] = marker['policy_sha256']
    body = canonical(result)
    destination = consumed_path(current_boot)
    if destination.exists() or destination.is_symlink():
        need(read(destination) == body, 'consumed_collision')
    else:
        write_new(destination, body)
    validate_locks(install_fd, guard_fd)
    verify_block_and_owner(intent, marker, recovered)
    need(read(STOP) == intent_raw and read(archive) == intent_raw and
         read(destination) == body, 'preunlink_changed')
    STOP.unlink()
    dfd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    need(read_consumed_record(current_boot) == result, 'postunlink_changed')
    return result

def _source_bytes(path: Path, mode: int, limit: int) -> bytes:
    for parent in reversed(path.parents):
        if parent == Path('/'): continue
        value = parent.lstat()
        need(stat.S_ISDIR(value.st_mode) and value.st_uid == value.st_gid == 0 and
             not value.st_mode & 0o022, 'source_parent_untrusted')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
             stat.S_IMODE(before.st_mode) == mode and before.st_nlink == 1 and
             0 < before.st_size <= limit, 'source_leaf_untrusted')
        raw = os.read(fd, limit+1)
        after, named = os.fstat(fd), path.lstat()
        keys = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                'st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw) == before.st_size and
             all(getattr(before,k) == getattr(after,k) == getattr(named,k) for k in keys),
             'source_generation_changed')
        return raw
    finally: os.close(fd)

def _source_facts(*, postconsumed_site: bool = False):
    """Authenticate installed source and the mounted ROOT/BOOT site.

    The normal transition and guardian first grant read both block-device
    UUIDs.  Networkd's held, read-only post-consume verifier runs in a
    char-device-only cgroup: it may use the already authenticated same-boot
    consumed proof, while still matching both live mount source/dev pairs.
    No caller may return success in that mode without completing the exact
    same-boot normal consumed, cold-ready or rollover proof under Guard OFD.
    """
    need(type(postconsumed_site) is bool, 'site_mode_invalid')
    source = decode(read(SOURCE_CONFIG, 4096))
    store = decode(read(STORE_CONFIG, 4096))
    need(source.get('schema') == 'aegis_auto_terminal_source_v1' and
         source.get('transition_sha256') == sha(_source_bytes(SOURCE, 0o500, 1 << 20)) and
         store.get('schema') == 'aegis_auto_terminal_boot_store_v1' and
         source.get('hook_sha256') == store.get('hook_sha256') and
         source.get('boot_helper_sha256') == store.get('helper_sha256'),
         'transition_source_changed')
    helper_path = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_boot_store.py')
    raw = _source_bytes(helper_path, 0o500, 1 << 20)
    need(sha(raw) == source['boot_helper_sha256'], 'boot_helper_changed')
    namespace = {'__file__':str(helper_path),'__name__':'aegis_terminal_boot_store'}
    exec(compile(raw, str(helper_path), 'exec'), namespace)
    helper = types.SimpleNamespace(**namespace)
    helper.check_config(store)
    rows = helper.mounts()
    for target, prefix in (('/', 'root'), ('/boot', 'boot')):
        mounted = helper.one_mount(rows,target)
        need(mounted['fstype'] == 'ext4' and
             mounted['source'] == store[prefix+'_source'] and
             mounted['dev'] == store[prefix+'_dev'] and
             helper.dev_number(store[prefix+'_source']) == store[prefix+'_dev'] and
             (postconsumed_site or
              helper.blkid_uuid(store[prefix+'_source']) == store[prefix+'_uuid']),
             'terminal_boot_layout_changed')
    return source, store


MIGRATION_ROOT = Path('/var/lib/aegis-install/client/terminal-migrations')
MIGRATION_HEAD = MIGRATION_ROOT/'head.json'


def _migration_history_record(path: Path, limit=8192):
    raw = read(path, limit)
    row = decode(raw)
    need(canonical(row) == raw, 'migration_history_noncanonical')
    return row, raw


def historical_source_context(marker_source_sha: str, current_source: dict,
                              current_store: dict, marker_sha: str | None,
                              force_history: bool = False):
    """Authenticate one old marker through the finite completed rotation chain.

    A previous source authorizes only historical marker/consumed lineage; new
    runtime and guardian source predicates still use the installed generation.
    """
    need(type(marker_source_sha) is str and HEX64.fullmatch(marker_source_sha),
         'historical_marker_source')
    need(marker_sha is None or
         (type(marker_sha) is str and HEX64.fullmatch(marker_sha)),
         'historical_marker_digest')
    current_source_sha = sha(read(SOURCE_CONFIG,4096))
    if marker_source_sha == current_source_sha and not force_history:
        return current_source, current_store
    head, _ = _migration_history_record(MIGRATION_HEAD,4096)
    need(set(head) == {'schema','edge_sha256'} and
         head['schema'] == 'aegis_auto_terminal_migration_head_v1' and
         type(head['edge_sha256']) is str and HEX64.fullmatch(head['edge_sha256']),
         'migration_head_invalid')
    current_install_sha = sha(read(ROOT/'auto-guardian-install.json',1 << 20))
    cursor = head['edge_sha256']
    visited = set()
    for _ in range(32):
        need(cursor not in visited and HEX64.fullmatch(cursor),
             'migration_history_cycle')
        visited.add(cursor)
        edge, raw = _migration_history_record(MIGRATION_ROOT/('edge-'+cursor+'.json'),8192)
        need(sha(raw) == cursor and set(edge) == {
             'schema','old_source_sha256','new_source_sha256',
             'old_context_sha256','prior_head_sha256','candidate_sha256',
             'package_sha256','intent_sha256','new_install_sha256',
             'next_bundle_manifest_sha256','next_sums_sha256',
             'observer_runtime_sha256','new_observer_orphan_sha256s'} and
             edge['schema'] == 'aegis_auto_terminal_migration_edge_v1' and
             edge['new_source_sha256'] == current_source_sha and
             edge['new_install_sha256'] == current_install_sha and
             all(type(edge[k]) is str and HEX64.fullmatch(edge[k]) for k in
                 ('old_source_sha256','old_context_sha256','candidate_sha256',
                  'package_sha256','intent_sha256','new_install_sha256',
                  'next_bundle_manifest_sha256','next_sums_sha256',
                  'observer_runtime_sha256')) and
             (edge['prior_head_sha256'] is None or
              type(edge['prior_head_sha256']) is str and
              HEX64.fullmatch(edge['prior_head_sha256'])),
             'migration_edge_invalid')
        orphans=edge['new_observer_orphan_sha256s']
        need(type(orphans) is list and len(orphans)<=8 and
             orphans==sorted(set(orphans)) and
             all(type(item) is str and HEX64.fullmatch(item) for item in orphans),
             'migration_new_orphan_roster_invalid')
        for orphan_sha in orphans:
            orphan,orphan_raw=_migration_history_record(
                MIGRATION_ROOT/('observer-new-orphan-'+
                    edge['intent_sha256']+'-'+orphan_sha+'.json'),16384)
            need(sha(orphan_raw)==orphan_sha and
                 type(orphan) is dict and
                 orphan.get('schema')=='aegis_auto_terminal_new_observer_orphan_v1' and
                 orphan.get('pending_sha256')==edge['intent_sha256'] and
                 orphan.get('new_source_sha256')==edge['new_source_sha256'] and
                 type(orphan.get('new_witness_sha256')) is str and
                 HEX64.fullmatch(orphan['new_witness_sha256']),
                 'migration_new_orphan_history_invalid')
        completed, _ = _migration_history_record(
            MIGRATION_ROOT/('complete-'+cursor+'.json'),8192)
        need(completed == {
             'schema':'aegis_auto_terminal_migration_complete_v1',
             'intent_sha256':edge['intent_sha256'],
             'edge_sha256':cursor,
             'new_source_sha256':edge['new_source_sha256'],
             'candidate_sha256':edge['candidate_sha256']},
             'migration_complete_invalid')
        context, context_raw = _migration_history_record(
            MIGRATION_ROOT/('context-'+edge['old_context_sha256']+'.json'),256 << 10)
        need(sha(context_raw) == edge['old_context_sha256'] and
             set(context) == {'schema','old_source_sha256','old_install_sha256',
                              'leaves','markers','next_bundle_manifest_sha256',
                              'next_sums_sha256'} and
             context['schema'] == 'aegis_auto_terminal_migration_context_v1' and
             context['old_source_sha256'] == edge['old_source_sha256'] and
             type(context['old_install_sha256']) is str and
             HEX64.fullmatch(context['old_install_sha256']),
             'migration_context_invalid')
        leaves = context['leaves']
        need(type(leaves) is dict and
             '/etc/aegis-auto-terminal-source.json' in leaves and
             '/etc/aegis-auto-terminal-store.json' in leaves,
             'migration_context_leaves')
        source_raw = bytes.fromhex(leaves['/etc/aegis-auto-terminal-source.json']['hex'])
        store_raw = bytes.fromhex(leaves['/etc/aegis-auto-terminal-store.json']['hex'])
        need(sha(source_raw) == edge['old_source_sha256'] and
             source_raw == canonical(decode(source_raw)) and
             store_raw == canonical(decode(store_raw)),
             'migration_context_source_changed')
        source, store = decode(source_raw), decode(store_raw)
        observer, observer_raw = _migration_history_record(
            MIGRATION_ROOT/('observer-runtime-'+edge['intent_sha256']+'.json'),16384)
        need(sha(observer_raw) == edge['observer_runtime_sha256'] and
             set(observer) == {'schema','pending_sha256','old_source_sha256',
                'boot_id','ready_hex','ready_sha256','observer_pid',
                'observer_start_tick','observer_invocation_id',
                'observer_source_sha256','source_config_sha256',
                'run_dev','run_ino','members'} and
             observer['schema'] == 'aegis_auto_terminal_observer_runtime_v1' and
             observer['pending_sha256'] == edge['intent_sha256'] and
             observer['old_source_sha256'] == edge['old_source_sha256'] and
             observer['source_config_sha256'] == edge['old_source_sha256'] and
             observer['observer_source_sha256'] == source['witness_sha256'] and
             sha(bytes.fromhex(observer['ready_hex'])) == observer['ready_sha256'],
             'migration_observer_history_invalid')
        need(source.get('schema') == 'aegis_auto_terminal_source_v1' and
             store.get('schema') == 'aegis_auto_terminal_boot_store_v1' and
             store['root_uuid'] == current_store['root_uuid'] and
             store['root_dev'] == current_store['root_dev'] and
             store['boot_uuid'] == current_store['boot_uuid'] and
             store['boot_dev'] == current_store['boot_dev'] and
             source['hook_sha256'] == store['hook_sha256'] and
             source['boot_helper_sha256'] == store['helper_sha256'],
             'migration_context_site_changed')
        markers = context['markers']
        need(type(markers) is list and len(markers) <= 128 and
             all(type(item) is dict and set(item) == {'name','sha256'} and
                 type(item['name']) is str and
                 re.fullmatch(r'terminal-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-[0-9a-f]{32}\.json', item['name']) and
                 type(item['sha256']) is str and HEX64.fullmatch(item['sha256'])
                 for item in markers), 'migration_context_marker_roster')
        if (edge['old_source_sha256'] == marker_source_sha and
            (marker_sha is None or marker_sha in
             {item['sha256'] for item in markers})):
            return source, store
        cursor = edge['prior_head_sha256']
        need(cursor is not None, 'historical_source_unreachable')
        current_source_sha = edge['old_source_sha256']
        current_install_sha = context['old_install_sha256']
    raise Refused('migration_history_bound')

def _marker_path(old_boot: str, store: dict) -> Path:
    directory = Path('/boot')/store['boot_store_dir']
    need(store['boot_store_dir'] == 'aegis-auto-terminal' and
         stat.S_ISDIR(directory.lstat().st_mode) and
         directory.lstat().st_uid == directory.lstat().st_gid == 0 and
         stat.S_IMODE(directory.lstat().st_mode) == 0o700,
         'terminal_boot_store_untrusted')
    names = list(directory.iterdir())
    need(len(names) <= 128, 'terminal_boot_roster_oversize')
    matches = [p for p in names if re.fullmatch(
        r'terminal-'+re.escape(old_boot)+r'-[0-9a-f]{32}\.json',p.name)]
    need(len(matches) == 1, 'terminal_boot_marker_not_unique')
    return matches[0]

def verify_old_lineage(marker: dict, intent: dict, current_boot: str) -> str:
    """Bind the shutdown carrier to the durable finalized active generation."""
    control = Path('/var/lib/aegis-auto/control')
    active_path = control/'generation.json'
    try:
        active_raw = read(active_path, 139264)
    except FileNotFoundError:
        active_raw = b''
    if sha(active_raw) != marker['active_generation_sha256']:
        active_raw = read(control/'generation-history'/
                          ('active-'+marker['active_generation_sha256']+'.json'),
                          139264)
    need(sha(active_raw) == marker['active_generation_sha256'],
         'terminal_active_generation_changed')
    active = decode(active_raw)
    need(active.get('schema') == 'aegis_auto_v2_generation_v1' and
         active.get('report_sha256') == marker['active_report_sha256'] and
         active.get('boot_snapshot_sha256') == marker['boot_snapshot_sha256'] and
         type(active.get('report')) is dict,
         'terminal_active_generation_invalid')
    report = active['report']
    report_raw = json.dumps(report, sort_keys=True, separators=(',', ':'),
                            ensure_ascii=False).encode()
    need(sha(report_raw) == marker['active_report_sha256'] and
         report.get('schema') == 'aegis_auto_active_stage_inspection_v1' and
         type(report.get('stage')) is dict and
         report['stage'].get('phase') == 'finalized' and
         report['stage'].get('mode') == 'full-wide-tun' and
         type(report.get('terminal')) is dict and
         report['terminal'].get('outcome') == 'finalized' and
         report['terminal'].get('boot_id') == intent['boot_id'] and
         report['terminal'].get('private_unit') == intent['service'] and
         report['terminal'].get('invocation_id') == intent['invocation_id'] and
         type(report.get('input')) is dict and
         type(report['input'].get('candidate_sha256')) is str and
         HEX64.fullmatch(report['input']['candidate_sha256']),
         'terminal_active_report_invalid')
    snapshot_raw = read(control/'boot-snapshots'/
                        ('snapshot-'+marker['boot_snapshot_sha256']+'.json'), 1 << 20)
    need(sha(snapshot_raw) == marker['boot_snapshot_sha256'],
         'terminal_boot_snapshot_changed')
    snapshot = decode(snapshot_raw)
    need(snapshot.get('schema') == 'aegis_auto_v2_boot_snapshot_v1' and
         snapshot.get('active_report_sha256') == marker['active_report_sha256'] and
         snapshot.get('predecessor_boot_id') == intent['boot_id'] and
         snapshot.get('source') == report['input'] and
         snapshot.get('current_fixed') == report.get('current_fixed') and
         snapshot['source'].get('candidate_sha256') ==
             report['input']['candidate_sha256'] and
         current_boot != intent['boot_id'],
         'terminal_boot_snapshot_invalid')
    old_stage = report['stage'].get('path')
    need(type(old_stage) is str and
         Path(old_stage).parent == Path('/run/aegis-installer-config-snapshots') and
         not Path(old_stage).exists() and not Path(old_stage).is_symlink(),
         'terminal_old_stage_present')
    return report['input']['candidate_sha256']

def qualify_old_marker(current_boot: str):
    """Read-only pre-watchdog cut; this is never a grant or STOP unlink."""
    source, store = _source_facts()
    intent_raw = read(STOP)
    intent = decode(intent_raw)
    validate_old(intent, current_boot)
    marker_path = _marker_path(intent['boot_id'], store)
    marker_raw = read(marker_path)
    marker = decode(marker_raw)
    source, store = historical_source_context(marker.get('source_sha256'),
                                              source, store, sha(marker_raw))
    validate_marker(marker, intent_raw, current_boot,
                    marker['source_sha256'], store['boot_uuid'])
    need(marker['root_uuid'] == store['root_uuid'] and
         marker['root_dev'] == store['root_dev'] and
         marker['boot_dev'] == store['boot_dev'] and
         marker['hook_sha256'] == store['hook_sha256'] and
         marker['helper_sha256'] == store['helper_sha256'],
         'marker_site_changed')
    verify_old_lineage(marker, intent, current_boot)
    return marker_path, marker, source, store

def _claim(path: Path, *, create=False) -> int:
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    if create: flags |= os.O_CREAT
    fd = os.open(path, flags, 0o600)
    try:
        value, named = os.fstat(fd), path.lstat()
        need(stat.S_ISREG(value.st_mode) and value.st_uid == value.st_gid == 0 and
             stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1 and
             (value.st_dev,value.st_ino) == (named.st_dev,named.st_ino),
             'transition_lock_untrusted')
        deadline = time.monotonic()+3
        while True:
            try: fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB); break
            except BlockingIOError:
                need(time.monotonic()<deadline,'transition_lock_busy')
                time.sleep(0.01)
        return fd
    except BaseException:
        os.close(fd)
        raise

def _bounded_native(argv, inherited):
    child = subprocess.Popen(argv,stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        pass_fds=inherited,close_fds=True,
        env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
    output = bytearray()
    deadline = time.monotonic()+90
    try:
        while True:
            remaining = deadline-time.monotonic()
            need(remaining > 0,'cold_native_timeout')
            ready,_,_ = select.select([child.stdout.fileno()],[],[],remaining)
            need(ready,'cold_native_timeout')
            part = os.read(child.stdout.fileno(),min(4096,(128 << 10)+1-len(output)))
            if not part: break
            output.extend(part)
            need(len(output) <= 128 << 10,'cold_native_reply_bound')
        need(child.wait(timeout=max(.01,deadline-time.monotonic())) == 0,
             'cold_native_refused')
        return bytes(output)
    finally:
        if child.poll() is None:
            child.kill(); child.wait(timeout=5)
        child.stdout.close()

def _cold_rename_consumed(source: Path, target: Path, raw: bytes) -> None:
    """One no-overwrite, fsynced transition of an exact protected leaf."""
    if not source.exists() and not source.is_symlink():
        need(read(target,8192)==raw,'cold_consumed_missing_or_changed')
        return
    need(read(source,8192)==raw and
         not target.exists() and not target.is_symlink(),
         'cold_consumed_collision')
    parent=os.open(source.parent,os.O_RDONLY|os.O_DIRECTORY|
                   os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        target_parent=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|
                              os.O_NOFOLLOW|os.O_CLOEXEC)
    except BaseException:
        os.close(parent)
        raise
    try:
        import ctypes
        libc=ctypes.CDLL(None,use_errno=True)
        renameat2=libc.renameat2
        renameat2.argtypes=(ctypes.c_int,ctypes.c_char_p,
                            ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
        renameat2.restype=ctypes.c_int
        rc=renameat2(parent,os.fsencode(source.name),target_parent,
                     os.fsencode(target.name),1)  # RENAME_NOREPLACE
        need(rc==0,'cold_consumed_rename_refused')
        os.fsync(parent)
        if target.parent!=source.parent:
            os.fsync(target_parent)
        need(read(target,8192)==raw and
             not source.exists() and not source.is_symlink(),
             'cold_consumed_generation_changed')
    finally:
        os.close(target_parent)
        os.close(parent)

def _cold_rollover_barrier_sha(head, intent_sha, current_boot):
    """Bind an immutable head or its exact later barrier-bound receipt."""
    head_sha=sha(canonical(head))
    barrier_sha=head['barrier_sha256']
    if barrier_sha is None:
        bound_path=COLD_ROOT/('barrier-bound-'+intent_sha+'.json')
        raw=read(bound_path,4096)
        bound=decode(raw)
        need(canonical(bound)==raw and set(bound)=={
             'schema','current_boot_id','attempt_head_sha256',
             'attempt_intent_sha256','barrier_sha256',
             'original_intent_sha256'} and
             bound['schema']=='aegis_auto_terminal_cold_barrier_bound_v1' and
             bound['current_boot_id']==current_boot and
             bound['attempt_head_sha256']==head_sha and
             bound['attempt_intent_sha256']==intent_sha and
             bound['original_intent_sha256']==head['original_intent_sha256'],
             'cold_rollover_bound_invalid')
        barrier_sha=bound['barrier_sha256']
    need(type(barrier_sha) is str and HEX64.fullmatch(barrier_sha),
         'cold_rollover_barrier_invalid')
    active=COLD_ROOT/'rollover-barrier.json'
    consumed=COLD_ROOT/('rollover-barrier-consumed-'+barrier_sha+'.json')
    bodies=[]
    for path in (active,consumed):
        if path.exists() or path.is_symlink():bodies.append(read(path,4096))
    need(bodies and len(set(bodies))==1 and sha(bodies[0])==barrier_sha,
         'cold_rollover_barrier_changed')
    return barrier_sha,bodies[0]

def _cold_consume_republished_barrier(barrier_sha,raw):
    """Preserve the first consumed copy when another boot reused its bytes."""
    active=COLD_ROOT/'rollover-barrier.json'
    consumed=COLD_ROOT/('rollover-barrier-consumed-'+barrier_sha+'.json')
    if not consumed.exists() and not consumed.is_symlink():
        _cold_rename_consumed(active,consumed,raw)
        return
    need(read(consumed,4096)==raw,'cold_rollover_consumed_changed')
    if active.exists() or active.is_symlink():
        need(read(active,4096)==raw,'cold_rollover_active_changed')
        parent=os.open(COLD_ROOT,os.O_RDONLY|os.O_DIRECTORY|
                       os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            os.unlink('rollover-barrier.json',dir_fd=parent)
            os.fsync(parent)
        finally:os.close(parent)
    need(not active.exists() and not active.is_symlink() and
         read(consumed,4096)==raw,'cold_rollover_consumption_changed')

def _cold_original_intent_bytes(original_sha):
    need(type(original_sha) is str and HEX64.fullmatch(original_sha),
         'cold_original_sha_invalid')
    active=COLD_ROOT/'intent.json'
    consumed=COLD_ROOT/('intent-consumed-'+original_sha+'.json')
    paths=[path for path in (active,consumed)
           if path.exists() or path.is_symlink()]
    need(len(paths)==1,'cold_original_active_consumed_ambiguous')
    raw=read(paths[0],8192)
    need(sha(raw)==original_sha and canonical(decode(raw))==raw,
         'cold_original_intent_changed')
    return raw


def _cold_transition(install_fd, guard_fd, source, store, current_boot,
                     validate_locks, *, phase_root=COLD_ROOT,
                     rollover_head=None):
    """Authenticate B site and consume the cold barrier only after PID1 proof."""
    need(not STOP.exists() and not STOP.is_symlink(),
         'cold_stop_or_rescue_pending')
    ready_path=phase_root/'transition-ready.json'
    phase3_path=phase_root/'phase-03.json'
    native_prebind_path=phase_root/'cold-denied-prebind.json'
    ready_raw = (read(ready_path,4096) if
                 ready_path.exists() or ready_path.is_symlink() else None)
    if ready_raw is not None:
        prior=decode(ready_raw)
        if rollover_head is None:
            need(canonical(prior)==ready_raw and
                 prior.get('schema')==
                     'aegis_auto_terminal_cold_transition_ready_v1' and
                 type(prior.get('consumed_intent_leaf')) is str and
                 re.fullmatch(r'intent-consumed-[0-9a-f]{64}\.json',
                              prior['consumed_intent_leaf']),
                 'cold_transition_ready_changed')
            consumed_name=prior['consumed_intent_leaf']
        else:
            need(canonical(prior)==ready_raw and
                 set(prior)=={'schema','current_boot_id',
                   'original_intent_sha256','prior_intent_sha256',
                   'attempt_head_sha256','attempt_intent_sha256',
                   'barrier_sha256','cold_prebind_sha256',
                   'source_config_sha256','observer_ready_sha256',
                   'site_readback_sha256','deny_policy_sha256',
                   'phase02_sha256','phase03_sha256','phase04_sha256',
                   'native_transition_sha256',
                   'consumed_original_intent_leaf',
                   'consumed_attempt_intent_leaf',
                   'consumed_pending_leaf',
                   'consumed_rollover_barrier_leaf'} and
                 prior['schema']==
                     'aegis_auto_terminal_cold_rollover_transition_ready_v1' and
                 prior['current_boot_id']==current_boot and
                 prior['attempt_head_sha256']==sha(canonical(rollover_head)) and
                 prior['attempt_intent_sha256']==
                     rollover_head['attempt_intent_sha256'] and
                 prior['original_intent_sha256']==
                     rollover_head['original_intent_sha256'] and
                 prior['prior_intent_sha256']==
                     rollover_head['prior_intent_sha256'] and
                 prior['consumed_attempt_intent_leaf']==
                     'intent-consumed-'+prior['attempt_intent_sha256']+'.json',
                 'cold_rollover_ready_changed')
            consumed_name=prior['consumed_attempt_intent_leaf']
        consumed=phase_root/consumed_name
        active=phase_root/'intent.json'
        intent_raw=read(active,8192) if active.exists() else read(consumed,8192)
    else:
        prior=None
        intent_raw=read(phase_root/'intent.json',8192)
    need(read(phase_root/'phase-00.json',8192)==intent_raw,
         'cold_intent_phase_changed')
    intent=decode(intent_raw)
    intent_sha=sha(intent_raw)
    need(canonical(intent)==intent_raw and
         intent.get('schema')=='aegis_auto_terminal_cold_intent_v1' and
         intent.get('current_boot_id')==current_boot and
         intent.get('selected_manager')==source['selected_manager'] and
         type(intent.get('retained_root')) is str and
         re.fullmatch(r'/var/lib/aegis-auto/releases/[A-Za-z0-9-]{16,128}',
                      intent['retained_root']) and
         all(type(intent.get(k)) is str and HEX64.fullmatch(intent[k])
             for k in ('new_candidate_sha256','new_package_sha256',
                       'deny_policy_sha256','guard30_sha256',
                       'initial_denied_proof_sha256',
                       'initial_infrastructure_rows_sha256',
                       'next_bundle_manifest_sha256','next_sums_sha256')),
         'cold_intent_invalid')
    phase1_raw=read(phase_root/'phase-01.json',8192)
    phase1=decode(phase1_raw)
    need(canonical(phase1)==phase1_raw and
         set(phase1)=={'schema','intent_sha256','deny_policy_sha256',
                       'pre_quiesce_infrastructure_sha256',
                       'post_quiesce_infrastructure_sha256',
                       'quiesce_monotonic_tick'} and
         phase1['schema']=='aegis_auto_terminal_cold_deny_v2' and
         phase1['intent_sha256']==intent_sha and
         phase1['deny_policy_sha256']==intent['deny_policy_sha256'] and
         phase1['pre_quiesce_infrastructure_sha256']==
             intent['initial_infrastructure_rows_sha256'] and
         type(phase1['quiesce_monotonic_tick']) is int and
         phase1['quiesce_monotonic_tick']>0,
         'cold_quiesce_phase_changed')
    phase2_raw=read(phase_root/'phase-02.json',8192)
    phase2=decode(phase2_raw)
    need(canonical(phase2)==phase2_raw and
         set(phase2)=={'schema','intent_sha256','proof_sha256',
                       'package_repaired_tick'} and
         phase2['schema']=='aegis_auto_terminal_cold_package_repaired_v2' and
         phase2['intent_sha256']==intent_sha and
         type(phase2['package_repaired_tick']) is int and
         phase2['package_repaired_tick']>phase1['quiesce_monotonic_tick'] and
         type(phase2['proof_sha256']) is str and
         HEX64.fullmatch(phase2['proof_sha256']),
         'cold_package_phase_changed')
    phase3_raw=read(phase3_path,8192)
    phase3=decode(phase3_raw)
    need(canonical(phase3)==phase3_raw and
         set(phase3)=={'schema','package_repaired_sha256',
                       'cold_prebind_sha256','intent_sha256'} and
         phase3['schema']=='aegis_auto_terminal_cold_denied_prebind_v2' and
         phase3['package_repaired_sha256']==sha(phase2_raw) and
         phase3['intent_sha256']==intent_sha and
         type(phase3['cold_prebind_sha256']) is str and
         HEX64.fullmatch(phase3['cold_prebind_sha256']),
         'cold_prebind_phase_changed')
    native_raw=read(native_prebind_path,8192)
    need(sha(native_raw)==phase3['cold_prebind_sha256'],
         'cold_native_prebind_changed')
    phase4_raw=read(phase_root/'phase-04.json',8192)
    phase4=decode(phase4_raw)
    need(canonical(phase4)==phase4_raw and
         set(phase4)=={'schema','intent_sha256','cold_prebind_sha256',
                       'source_config_sha256','observer_ready_sha256'} and
         phase4['schema']=='aegis_auto_terminal_cold_site_ready_v1' and
         phase4['intent_sha256']==intent_sha and
         phase4['cold_prebind_sha256']==sha(native_raw) and
         phase4['source_config_sha256']==sha(read(SOURCE_CONFIG,4096)) and
         type(phase4['observer_ready_sha256']) is str and
         HEX64.fullmatch(phase4['observer_ready_sha256']),
         'cold_site_ready_phase_changed')
    installed=Path('/usr/local/bin/aegis-client')
    installed_mode=stat.S_IMODE(installed.lstat().st_mode)
    need(installed_mode in (0o555,0o755) and
         sha(_source_bytes(installed,installed_mode,512 << 20))==
             intent['new_candidate_sha256'],
         'cold_candidate_changed')
    command=[str(installed),'auto-verify-cold-transition-inherited',
             '--lock-fd',str(install_fd),'--guard-fd',str(guard_fd),
             '--retained-root',intent['retained_root'],
             '--intent-sha256',intent_sha]
    proof_raw=_bounded_native(command,(install_fd,guard_fd))
    proof=decode(proof_raw)
    need(canonical(proof)==proof_raw and
         set(proof)=={'schema','boot_id','intent_sha256',
                     'cold_prebind_sha256','deny_policy_sha256','site_state',
                     'site_readback_sha256','observer_state',
                     'observer_ready_sha256','source_config_sha256',
                     'package_repair_receipt_sha256','no_client_grant'} and
         proof['schema']=='aegis_auto_v2_cold_prebind_verification_v1' and
         proof['boot_id']==current_boot and
         proof['intent_sha256']==intent_sha and
         proof['cold_prebind_sha256']==sha(native_raw) and
         proof['deny_policy_sha256']==intent['deny_policy_sha256'] and
         proof['site_state']=='b_complete' and
         proof['observer_state']=='b_ready' and
         proof['observer_ready_sha256']==phase4['observer_ready_sha256'] and
         proof['source_config_sha256']==phase4['source_config_sha256'] and
         proof['package_repair_receipt_sha256']==sha(phase2_raw) and
         proof['no_client_grant'] is True and
         type(proof['site_readback_sha256']) is str and
         HEX64.fullmatch(proof['site_readback_sha256']),
         'cold_transition_native_refused')
    consumed_intent='intent-consumed-'+intent_sha+'.json'
    need(not MIGRATION_PENDING.is_symlink(),'cold_pending_symlink')
    if MIGRATION_PENDING.exists():
        pending_raw=read(MIGRATION_PENDING,8192)
        consumed_pending='pending-consumed-'+sha(pending_raw)+'.json'
    elif prior is not None and prior.get('consumed_pending_leaf') is not None:
        consumed_pending=prior['consumed_pending_leaf']
        need(type(consumed_pending) is str and
             re.fullmatch(r'pending-consumed-[0-9a-f]{64}\.json',
                          consumed_pending),'cold_consumed_pending_name')
        pending_raw=read(phase_root/consumed_pending,8192)
        need(consumed_pending=='pending-consumed-'+sha(pending_raw)+'.json',
             'cold_consumed_pending_changed')
    else:
        pending_raw=None
        consumed_pending=None
    if rollover_head is None:
        expected={'schema':'aegis_auto_terminal_cold_transition_ready_v1',
                  'current_boot_id':current_boot,
                  'intent_sha256':intent_sha,
                  'cold_prebind_sha256':sha(native_raw),
                  'source_config_sha256':phase4['source_config_sha256'],
                  'observer_ready_sha256':phase4['observer_ready_sha256'],
                  'site_readback_sha256':proof['site_readback_sha256'],
                  'deny_policy_sha256':intent['deny_policy_sha256'],
                  'consumed_intent_leaf':consumed_intent,
                  'consumed_pending_leaf':consumed_pending}
    else:
        need(rollover_head['attempt_intent_sha256']==intent_sha and
             rollover_head['current_boot_id']==current_boot,
             'cold_rollover_head_intent_changed')
        barrier_sha,barrier_raw=_cold_rollover_barrier_sha(
            rollover_head,intent_sha,current_boot)
        if ready_raw is None:
            need((COLD_ROOT/'rollover-barrier.json').exists() or
                 (COLD_ROOT/'rollover-barrier.json').is_symlink(),
                 'cold_rollover_active_barrier_missing')
            need(read(COLD_ROOT/'rollover-barrier.json',4096)==barrier_raw,
                 'cold_rollover_active_barrier_changed')
        original_sha=rollover_head['original_intent_sha256']
        original_raw=_cold_original_intent_bytes(original_sha)
        expected={
            'schema':'aegis_auto_terminal_cold_rollover_transition_ready_v1',
            'current_boot_id':current_boot,
            'original_intent_sha256':original_sha,
            'prior_intent_sha256':rollover_head['prior_intent_sha256'],
            'attempt_head_sha256':sha(canonical(rollover_head)),
            'attempt_intent_sha256':intent_sha,
            'barrier_sha256':barrier_sha,
            'cold_prebind_sha256':sha(native_raw),
            'source_config_sha256':phase4['source_config_sha256'],
            'observer_ready_sha256':phase4['observer_ready_sha256'],
            'site_readback_sha256':proof['site_readback_sha256'],
            'deny_policy_sha256':intent['deny_policy_sha256'],
            'phase02_sha256':sha(phase2_raw),
            'phase03_sha256':sha(phase3_raw),
            'phase04_sha256':sha(phase4_raw),
            'native_transition_sha256':sha(proof_raw),
            'consumed_original_intent_leaf':
                'intent-consumed-'+original_sha+'.json',
            'consumed_attempt_intent_leaf':consumed_intent,
            'consumed_pending_leaf':consumed_pending,
            'consumed_rollover_barrier_leaf':
                'rollover-barrier-consumed-'+barrier_sha+'.json'}
    validate_locks(install_fd,guard_fd)
    need(_source_facts()==(source,store) and
         read(phase_root/'phase-04.json',8192)==phase4_raw,
         'cold_transition_generation_changed')
    if rollover_head is not None:
        need(_cold_rollover_hint(current_boot)==(phase_root,rollover_head),
             'cold_rollover_head_generation_changed')
    if ready_raw is None:
        write_new_atomic(ready_path,canonical(expected))
    else:
        need(ready_raw==canonical(expected),'cold_transition_ready_changed')
    _cold_rename_consumed(phase_root/'intent.json',
                          phase_root/consumed_intent,intent_raw)
    if rollover_head is not None:
        _cold_rename_consumed(
            COLD_ROOT/'intent.json',
            COLD_ROOT/expected['consumed_original_intent_leaf'],
            original_raw)
    if consumed_pending is not None:
        _cold_rename_consumed(MIGRATION_PENDING,
                              phase_root/consumed_pending,pending_raw)
    if rollover_head is not None:
        _cold_consume_republished_barrier(barrier_sha,barrier_raw)
    validate_locks(install_fd,guard_fd)
    need(read(ready_path,4096)==canonical(expected),
         'cold_transition_ready_generation_changed')
    if rollover_head is not None:
        need(_cold_rollover_hint(current_boot)==(phase_root,rollover_head),
             'cold_rollover_head_after_consumption_changed')

def boot_transition():
    need(os.geteuid() == 0 and sys.platform.startswith('linux'),
         'transition_root_linux_required')
    current_boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(UUID.fullmatch(current_boot),'transition_boot_id_invalid')
    rollover_hint=_cold_rollover_hint(current_boot)
    cold_present = (COLD_PHASE3.exists() or COLD_PHASE3.is_symlink() or
                    rollover_hint is not None)
    need(cold_present or
         not MIGRATION_PENDING.exists() and not MIGRATION_PENDING.is_symlink(),
         'terminal_migration_pending')
    source, store = _source_facts()
    install_fd = _claim(INSTALL_LOCK, create=True)
    try:
        guard_fd = _claim(GUARD_LOCK)
        try:
            need(cold_present or
                 not MIGRATION_PENDING.exists() and not MIGRATION_PENDING.is_symlink(),
                 'terminal_migration_pending')
            guardian_raw = _source_bytes(GUARDIAN_SOURCE, 0o500, 1 << 20)
            installed = decode(read(Path('/var/lib/aegis-install/client/auto-guardian-install.json'),1<<20))
            need(installed.get('guardian_sha256') == sha(guardian_raw),
                 'guardian_source_changed')
            namespace = {'__file__':str(GUARDIAN_SOURCE),
                         '__name__':'aegis_terminal_guardian'}
            exec(compile(guardian_raw, str(GUARDIAN_SOURCE), 'exec'), namespace)
            guardian = types.SimpleNamespace(**namespace)
            guardian.own_source()
            def locks(a,b):
                guardian._held_lock(a, INSTALL_LOCK)
                guardian._held_lock(b, GUARD_LOCK)
            def blocked(intent, marker, recovered):
                locks(install_fd,guard_fd)
                candidate_sha = verify_old_lineage(marker, intent, current_boot)
                snapshot_sha, active_sha = guardian._boot_guard_binding({
                    'boot_id': current_boot,
                    'boot_snapshot_sha256': marker['boot_snapshot_sha256'],
                    'active_report_sha256': marker['active_report_sha256'],
                    'predecessor_boot_id': intent['boot_id'],
                    'candidate_sha256': candidate_sha,
                    'private_unit': intent['service'],
                'prior_invocation_id': intent['invocation_id']},
                marker['active_generation_sha256'])
                need(snapshot_sha == marker['boot_snapshot_sha256'] and
                     active_sha == marker['active_generation_sha256'],
                     'terminal_boot_guard_mismatch')
                deadline = time.monotonic()+12
                state, projection = guardian._semantic_policy_readback(deadline=deadline)
                policy = guardian.record(guardian.POLICY)
                need(policy['policy_sha256'] == sha(projection) and
                     guardian._no_client_grant(projection),
                     'transition_kernel_deny_changed')
                guardian._crossboot_policy_seals(
                    intent['boot_id'], marker['policy_sha256'],
                    policy['policy_sha256'], projection)
                guardian._boot_fixed_client_stopped(deadline)
                guardian._boot_private_owners_absent(deadline)
                need(guardian.regular(guardian.GUARD_STATE,1<<15) == state and
                     read(STOP) == intent_raw,
                     'transition_owner_changed')
                locks(install_fd,guard_fd)
            if cold_present:
                locks(install_fd,guard_fd)
                if rollover_hint is None:
                    _cold_transition(install_fd,guard_fd,source,store,
                                     current_boot,locks)
                else:
                    _cold_transition(install_fd,guard_fd,source,store,
                                     current_boot,locks,
                                     phase_root=rollover_hint[0],
                                     rollover_head=rollover_hint[1])
                locks(install_fd,guard_fd)
                return
            if not STOP.exists() and not STOP.is_symlink():
                # First boot or completed prior transition. No new grant.
                locks(install_fd,guard_fd)
                return
            intent_raw = read(STOP)
            marker_path, marker, source, store = qualify_old_marker(current_boot)
            recovered = recovered_for_old(decode(intent_raw), current_boot)
            locks(install_fd,guard_fd)
            consume_locked(install_fd=install_fd,guard_fd=guard_fd,
                validate_locks=locks,current_boot=current_boot,
                marker_path=marker_path,recovered_path=recovered,
                source_sha=marker['source_sha256'],
                boot_uuid=store['boot_uuid'],
                policy_sha=guardian.record(guardian.POLICY)['policy_sha256'],
                verify_block_and_owner=blocked)
        finally: os.close(guard_fd)
    finally: os.close(install_fd)

def _cold_rollover_consumed_under_guard(current_boot, source, source_raw,
                                        phase_root, head):
    """Bind current-boot B transition history without acquiring InstallLock."""
    ready_raw=read(phase_root/'transition-ready.json',4096)
    ready=decode(ready_raw)
    need(canonical(ready)==ready_raw and set(ready)=={
         'schema','current_boot_id','original_intent_sha256',
         'prior_intent_sha256','attempt_head_sha256',
         'attempt_intent_sha256','barrier_sha256',
         'cold_prebind_sha256','source_config_sha256',
         'observer_ready_sha256','site_readback_sha256',
         'deny_policy_sha256','phase02_sha256','phase03_sha256',
         'phase04_sha256','native_transition_sha256',
         'consumed_original_intent_leaf','consumed_attempt_intent_leaf',
         'consumed_pending_leaf','consumed_rollover_barrier_leaf'} and
         ready['schema']==
             'aegis_auto_terminal_cold_rollover_transition_ready_v1' and
         ready['current_boot_id']==current_boot and
         ready['attempt_head_sha256']==sha(canonical(head)) and
         ready['attempt_intent_sha256']==head['attempt_intent_sha256'] and
         ready['original_intent_sha256']==head['original_intent_sha256'] and
         ready['prior_intent_sha256']==head['prior_intent_sha256'] and
         ready['source_config_sha256']==sha(source_raw) and
         all(type(ready[key]) is str and HEX64.fullmatch(ready[key]) for key in
             ('barrier_sha256','cold_prebind_sha256',
              'observer_ready_sha256','site_readback_sha256',
              'deny_policy_sha256','phase02_sha256','phase03_sha256',
              'phase04_sha256','native_transition_sha256')),
         'cold_rollover_consumed_ready_invalid')
    need(ready['consumed_original_intent_leaf']==
             'intent-consumed-'+ready['original_intent_sha256']+'.json' and
         ready['consumed_attempt_intent_leaf']==
             'intent-consumed-'+ready['attempt_intent_sha256']+'.json' and
         ready['consumed_rollover_barrier_leaf']==
             'rollover-barrier-consumed-'+ready['barrier_sha256']+'.json' and
         (ready['consumed_pending_leaf'] is None or
          type(ready['consumed_pending_leaf']) is str and
          re.fullmatch(r'pending-consumed-[0-9a-f]{64}\.json',
                       ready['consumed_pending_leaf'])),
         'cold_rollover_consumed_names_invalid')
    original_raw=read(COLD_ROOT/ready['consumed_original_intent_leaf'],8192)
    intent_raw=read(phase_root/ready['consumed_attempt_intent_leaf'],8192)
    original=decode(original_raw);intent=decode(intent_raw)
    need(canonical(original)==original_raw and
         canonical(intent)==intent_raw and
         sha(original_raw)==ready['original_intent_sha256'] and
         sha(intent_raw)==ready['attempt_intent_sha256'] and
         intent.get('schema')=='aegis_auto_terminal_cold_intent_v1' and
         intent.get('current_boot_id')==current_boot and
         intent.get('selected_manager')==source.get('selected_manager') and
         intent.get('deny_policy_sha256')==ready['deny_policy_sha256'] and
         intent.get('new_candidate_sha256')==
             original.get('new_candidate_sha256'),
         'cold_rollover_consumed_intent_invalid')
    barrier_sha,barrier_raw=_cold_rollover_barrier_sha(
        head,ready['attempt_intent_sha256'],current_boot)
    barrier=decode(barrier_raw)
    need(barrier_sha==ready['barrier_sha256'] and
         canonical(barrier)==barrier_raw and
         set(barrier)=={'schema','original_intent_sha256',
                        'original_boot_id','retained_root',
                        'new_candidate_sha256',
                        'next_bundle_manifest_sha256','next_sums_sha256'} and
         barrier['schema']==
             'aegis_auto_terminal_cold_rollover_barrier_v1' and
         barrier['original_intent_sha256']==
             ready['original_intent_sha256'] and
         barrier['original_boot_id']==original.get('current_boot_id') and
         barrier['retained_root']==intent.get('retained_root') and
         barrier['new_candidate_sha256']==
             intent.get('new_candidate_sha256') and
         barrier['next_bundle_manifest_sha256']==
             intent.get('next_bundle_manifest_sha256') and
         barrier['next_sums_sha256']==intent.get('next_sums_sha256') and
         read(COLD_ROOT/ready['consumed_rollover_barrier_leaf'],4096)==
             barrier_raw and
         not (COLD_ROOT/'rollover-barrier.json').exists() and
         not (COLD_ROOT/'rollover-barrier.json').is_symlink(),
         'cold_rollover_barrier_not_consumed')
    for ordinal in (2,3,4):
        raw=read(phase_root/f'phase-{ordinal:02d}.json',8192)
        need(sha(raw)==ready[f'phase{ordinal:02d}_sha256'] and
             canonical(decode(raw))==raw,
             'cold_rollover_phase_changed')
    phase4=decode(read(phase_root/'phase-04.json',8192))
    need(phase4.get('source_config_sha256')==sha(source_raw) and
         phase4.get('observer_ready_sha256')==
             ready['observer_ready_sha256'] and
         phase4.get('cold_prebind_sha256')==
             ready['cold_prebind_sha256'] and
         sha(read(phase_root/'cold-denied-prebind.json',8192))==
             ready['cold_prebind_sha256'],
         'cold_rollover_site_phase_changed')
    config_raw=read(phase_root/'cold-config-intent.json',4096)
    config=decode(config_raw)
    need(canonical(config)==config_raw and
         set(config)=={'schema','current_boot_id','intent_sha256',
                       'cold_prebind_sha256','old_context_sha256',
                       'new_install_sha256','source_config_sha256',
                       'store_config_sha256','active_hook_sha256',
                       'manager31_sha256','guardian31_sha256',
                       'selected_manager'} and
         config.get('schema')=='aegis_auto_terminal_cold_config_intent_v1' and
         config.get('current_boot_id')==current_boot and
         config.get('intent_sha256')==ready['attempt_intent_sha256'] and
         config.get('cold_prebind_sha256')==ready['cold_prebind_sha256'] and
         config.get('source_config_sha256')==sha(source_raw) and
         config.get('store_config_sha256')==sha(read(STORE_CONFIG,4096)) and
         config.get('new_install_sha256')==
             sha(read(ROOT/'auto-guardian-install.json',1 << 20)) and
         config.get('manager31_sha256')==
             source.get('manager_transition_dropin_sha256') and
         config.get('guardian31_sha256')==
             source.get('guardian_transition_dropin_sha256') and
         config.get('selected_manager')==source.get('selected_manager'),
         'cold_rollover_config_intent_changed')
    need(not MIGRATION_PENDING.exists() and not MIGRATION_PENDING.is_symlink(),
         'cold_rollover_pending_still_active')
    if ready['consumed_pending_leaf'] is not None:
        pending_raw=read(phase_root/ready['consumed_pending_leaf'],8192)
        need(ready['consumed_pending_leaf']==
             'pending-consumed-'+sha(pending_raw)+'.json' and
             not MIGRATION_PENDING.exists() and
             not MIGRATION_PENDING.is_symlink(),
             'cold_rollover_pending_not_consumed')
    manager=source.get('selected_manager')
    need(manager in ('NetworkManager.service','systemd-networkd.service'),
         'cold_rollover_manager_invalid')
    for unit,key in ((manager,'manager_transition_dropin_sha256'),
                     ('aegis-auto-guardian.service',
                      'guardian_transition_dropin_sha256')):
        path=transition_dropin_path(unit)
        need(sha(_source_bytes(path,0o644,4096))==source.get(key),
             'cold_rollover_transition_dropin_changed')
    need(read(phase_root/'transition-ready.json',4096)==ready_raw and
         read(phase_root/'cold-config-intent.json',4096)==config_raw and
         read(phase_root/ready['consumed_attempt_intent_leaf'],8192)==
             intent_raw and
         read(COLD_ROOT/ready['consumed_original_intent_leaf'],8192)==
             original_raw and
         read(SOURCE_CONFIG,4096)==source_raw,
         'cold_rollover_consumed_generation_changed')


def _cold_consumed_under_guard(current_boot: str, source: dict,
                               source_raw: bytes) -> bool:
    """Bind a completed cold transition; report current-boot proof only."""
    intent_path=COLD_ROOT/'intent.json'
    config_intent=COLD_ROOT/'cold-config-intent.json'
    need(not intent_path.exists() and not intent_path.is_symlink(),
         'cold_intent_still_active')
    rollover_hint=_cold_rollover_hint(current_boot)
    if rollover_hint is not None:
        _cold_rollover_consumed_under_guard(
            current_boot,source,source_raw,*rollover_hint)
        return True
    ready_raw=read(COLD_READY,4096) if COLD_READY.exists() or COLD_READY.is_symlink() else None
    if ready_raw is None:
        need(not config_intent.exists() and not config_intent.is_symlink(),
             'cold_configuration_without_transition')
        return False
    ready=decode(ready_raw)
    need(canonical(ready)==ready_raw and
         set(ready)=={'schema','current_boot_id','intent_sha256',
                      'cold_prebind_sha256','source_config_sha256',
                      'observer_ready_sha256','site_readback_sha256',
                      'deny_policy_sha256','consumed_intent_leaf',
                      'consumed_pending_leaf'} and
         ready['schema']=='aegis_auto_terminal_cold_transition_ready_v1',
         'cold_transition_ready_invalid')
    if ready['current_boot_id'] != current_boot:
        # An old cold transition does not authorize this boot. The caller
        # authenticates this exact current-boot consumed carrier below.
        need(read_consumed_record(current_boot,allow_missing=True) is not None,
             'cold_previous_boot_unqualified')
        return False
    need(ready['source_config_sha256']==sha(source_raw) and
         all(type(ready[key]) is str and HEX64.fullmatch(ready[key]) for key in
             ('intent_sha256','cold_prebind_sha256','observer_ready_sha256',
              'site_readback_sha256','deny_policy_sha256')) and
         ready['consumed_intent_leaf']==
             'intent-consumed-'+ready['intent_sha256']+'.json' and
         (ready['consumed_pending_leaf'] is None or
          type(ready['consumed_pending_leaf']) is str and
          re.fullmatch(r'pending-consumed-[0-9a-f]{64}\.json',
                       ready['consumed_pending_leaf'])),
         'cold_transition_source_invalid')
    consumed_raw=read(COLD_ROOT/ready['consumed_intent_leaf'],8192)
    intent=decode(consumed_raw)
    need(canonical(intent)==consumed_raw and
         sha(consumed_raw)==ready['intent_sha256'] and
         intent.get('schema')=='aegis_auto_terminal_cold_intent_v1' and
         intent.get('current_boot_id')==current_boot and
         intent.get('deny_policy_sha256')==ready['deny_policy_sha256'] and
         intent.get('selected_manager')==source.get('selected_manager'),
         'cold_consumed_intent_invalid')
    phase4_raw=read(COLD_ROOT/'phase-04.json',8192)
    phase4=decode(phase4_raw)
    need(canonical(phase4)==phase4_raw and
         set(phase4)=={'schema','intent_sha256','cold_prebind_sha256',
                       'source_config_sha256','observer_ready_sha256'} and
         phase4['schema']=='aegis_auto_terminal_cold_site_ready_v1' and
         phase4['intent_sha256']==ready['intent_sha256'] and
         phase4['cold_prebind_sha256']==ready['cold_prebind_sha256'] and
         phase4['source_config_sha256']==sha(source_raw) and
         phase4['observer_ready_sha256']==ready['observer_ready_sha256'],
         'cold_site_ready_invalid')
    config_raw=read(config_intent,4096)
    config=decode(config_raw)
    need(canonical(config)==config_raw and
         set(config)=={'schema','current_boot_id','intent_sha256',
                       'cold_prebind_sha256','old_context_sha256',
                       'new_install_sha256','source_config_sha256',
                       'store_config_sha256','active_hook_sha256',
                       'manager31_sha256','guardian31_sha256',
                       'selected_manager'} and
         config['schema']=='aegis_auto_terminal_cold_config_intent_v1' and
         config['current_boot_id']==current_boot and
         config['intent_sha256']==ready['intent_sha256'] and
         config['cold_prebind_sha256']==ready['cold_prebind_sha256'] and
         config['source_config_sha256']==sha(source_raw) and
         config['store_config_sha256']==sha(read(STORE_CONFIG,4096)) and
         config['new_install_sha256']==
             sha(read(ROOT/'auto-guardian-install.json',1 << 20)) and
         config['selected_manager']==source.get('selected_manager') and
         config['manager31_sha256']==source.get('manager_transition_dropin_sha256') and
         config['guardian31_sha256']==source.get('guardian_transition_dropin_sha256'),
         'cold_config_intent_invalid')
    if ready['consumed_pending_leaf'] is not None:
        pending_raw=read(COLD_ROOT/ready['consumed_pending_leaf'],8192)
        need(ready['consumed_pending_leaf']==
             'pending-consumed-'+sha(pending_raw)+'.json' and
             not MIGRATION_PENDING.exists() and not MIGRATION_PENDING.is_symlink(),
             'cold_pending_not_consumed')
    manager=source.get('selected_manager')
    need(manager in ('NetworkManager.service','systemd-networkd.service'),
         'cold_manager_invalid')
    for unit,key in ((manager,'manager_transition_dropin_sha256'),
                     ('aegis-auto-guardian.service',
                      'guardian_transition_dropin_sha256')):
        path=transition_dropin_path(unit)
        need(sha(_source_bytes(path,0o644,4096))==source.get(key),
             'cold_transition_dropin_changed')
    need(read(COLD_READY,4096)==ready_raw and
         read(COLD_ROOT/ready['consumed_intent_leaf'],8192)==consumed_raw and
         read(COLD_ROOT/'phase-04.json',8192)==phase4_raw and
         read(config_intent,4096)==config_raw and
         read(SOURCE_CONFIG,4096)==source_raw,
         'cold_transition_generation_changed')
    return True

def verify_consumed_under_guard(fd: int) -> None:
    """Read-only historical proof under the caller's existing exclusive Guard OFD.

    This path takes no InstallLock while Guard is held. The first guardian
    lease has a separate dual-lock/current-deny check; existing guard actions
    still own their current kernel and actor predicates.
    """
    need(os.geteuid() == 0 and sys.platform.startswith('linux') and
         type(fd) is int and 0 <= fd <= 1024, 'guard_verifier_argv')
    need(not MIGRATION_PENDING.exists() and not MIGRATION_PENDING.is_symlink(),
         'terminal_migration_pending')
    if not SOURCE_CONFIG.exists() and not SOURCE_CONFIG.is_symlink():
        need(not STORE_CONFIG.exists() and not STORE_CONFIG.is_symlink(),
             'partial_terminal_configuration')
        boot_dir = Path('/boot/aegis-auto-terminal')
        need(not boot_dir.exists() and not boot_dir.is_symlink() and
             not any(p.name.startswith(CONSUMED_PREFIX) for p in ROOT.iterdir()),
             'unqualified_terminal_history')
        return
    source_raw = read(SOURCE_CONFIG, 4096)
    store_raw = read(STORE_CONFIG, 4096)
    current_boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(type(current_boot) is str and UUID.fullmatch(current_boot),
         'current_boot_invalid')
    # This read is only a selector.  The char-only networkd cgroup cannot
    # open ROOT/BOOT block devices for blkid, although the earlier privileged
    # transition already did so before publishing this same-boot receipt.
    # Absence of all current-boot proof retains the full device check.
    candidate = read_consumed_record(current_boot, allow_missing=True)
    cold_hint = (_cold_rollover_hint(current_boot) is not None or
                 COLD_READY.exists() or COLD_READY.is_symlink())
    site_mode = candidate is not None or cold_hint
    _source, store = _source_facts(postconsumed_site=site_mode)
    guardian_raw = _source_bytes(GUARDIAN_SOURCE, 0o500, 1 << 20)
    installed_raw = read(ROOT/'auto-guardian-install.json', 1 << 20)
    installed = decode(installed_raw)
    need(installed.get('guardian_sha256') == sha(guardian_raw),
         'guardian_source_changed')
    namespace = {'__file__':str(GUARDIAN_SOURCE),
                 '__name__':'aegis_terminal_guardian_readonly'}
    exec(compile(guardian_raw, str(GUARDIAN_SOURCE), 'exec'), namespace)
    guardian = types.SimpleNamespace(**namespace)
    guardian.own_source()
    def guard_lock(_ignored: int, guard_fd: int) -> None:
        guardian._held_lock(guard_fd, GUARD_LOCK)
    guard_lock(fd, fd)
    need(not MIGRATION_PENDING.exists() and not MIGRATION_PENDING.is_symlink(),
         'terminal_migration_pending')
    cold_verified = _cold_consumed_under_guard(current_boot, _source, source_raw)
    receipt = read_consumed_record(current_boot, allow_missing=True)
    need(receipt == candidate, 'terminal_consumed_selector_changed')
    need(not site_mode or receipt is not None or cold_verified,
         'terminal_mount_only_without_current_proof')
    if receipt is None:
        historical_carriers_closed(store, _source)
    else:
        old_raw = read(ROOT/('auto-stop-intent-'+receipt['old_boot_id']+'-'+
                             receipt['old_intent_sha256']+'.json'))
        old = decode(old_raw)
        marker_path = _marker_path(old['boot_id'], store)
        marker_raw = read(marker_path)
        marker_value = decode(marker_raw)
        _historical_source, historical_store = historical_source_context(
            marker_value.get('source_sha256'), _source, store, sha(marker_raw))
        recovered_path = recovered_for_old(old, current_boot)
        if recovered_path is None:
            recovered_path = ROOT/('auto-watchdog-no-journal-'+old['boot_id']+
                                   '-'+receipt['old_intent_sha256']+'.json')
        def lineage(intent: dict, marker: dict, _recovered: dict) -> None:
            guard_lock(fd, fd)
            candidate = verify_old_lineage(marker, intent, current_boot)
            snapshot_sha, active_sha = guardian._boot_guard_binding({
                'boot_id':current_boot,
                'boot_snapshot_sha256':marker['boot_snapshot_sha256'],
                'active_report_sha256':marker['active_report_sha256'],
                'predecessor_boot_id':intent['boot_id'],
                'candidate_sha256':candidate,
                'private_unit':intent['service'],
                'prior_invocation_id':intent['invocation_id']},
                marker['active_generation_sha256'])
            need(snapshot_sha == marker['boot_snapshot_sha256'] and
                 active_sha == marker['active_generation_sha256'],
                 'terminal_old_generation_changed')
            guard_lock(fd, fd)
        authenticated_consumed(current_boot=current_boot,
            marker_path=marker_path, recovered_path=recovered_path,
            source_sha=marker_value['source_sha256'],
            boot_uuid=historical_store['boot_uuid'],
            validate_locks=guard_lock, install_fd=fd, guard_fd=fd,
            verify_block_and_owner=lineage)
        lineage(old, decode(read(marker_path)), decode(read(recovered_path,1 << 20)))
    need(_source_facts(postconsumed_site=site_mode) == (_source, store),
         'terminal_postconsumed_site_changed')
    guard_lock(fd, fd)
    need(read(SOURCE_CONFIG, 4096) == source_raw and
         read(STORE_CONFIG, 4096) == store_raw and
         read(ROOT/'auto-guardian-install.json', 1 << 20) == installed_raw and
         _source_bytes(GUARDIAN_SOURCE, 0o500, 1 << 20) == guardian_raw,
         'terminal_source_generation_changed')

def _refusal_diagnostic(error: BaseException) -> str:
    """Fixed, redacted failure reason without a traceback or private values."""
    known = {'transition_kernel_deny_changed',
             'crossboot_policy_input_invalid',
             'crossboot_current_policy_changed',
             'crossboot_owner_binding_retained',
             'crossboot_current_manager_changed',
             'crossboot_deny_base_changed',
             'crossboot_old_boot_invalid',
             'crossboot_manager_retirement_not_unique',
             'crossboot_manager_retirement_name_changed',
             'crossboot_manager_archive_changed',
             'crossboot_manager_retirement_changed',
             'cold_transition_dropin_changed'}
    reason = str(error) if str(error) in known else 'unclassified'
    frame = error.__traceback__
    origin = 'unknown'
    while frame is not None:
        name = Path(frame.tb_frame.f_code.co_filename).name
        if (name in ('aegis_auto_boot_transition.py',
                     'aegis_auto_guardian.py',
                     'aegis_auto_guard_policy.py') and
                frame.tb_frame.f_code.co_name not in ('need', '_need')):
            origin = name + ':' + str(frame.tb_lineno)
        frame = frame.tb_next
    kind = type(error).__name__
    if kind not in ('Refused', 'PolicyRefused', 'ValueError', 'OSError', 'TimeoutExpired',
                    'FileNotFoundError', 'KeyError', 'TypeError'):
        kind = 'other'
    return ('aegis_auto_boot_transition_refused reason=' + reason +
            ' type=' + kind + ' origin=' + origin)


if __name__ == '__main__':
    try:
        if sys.argv == [str(SOURCE), 'boot-transition']:
            boot_transition()
        elif (len(sys.argv) == 3 and sys.argv[:2] ==
              [str(SOURCE), 'verify-consumed-under-guard'] and
              re.fullmatch(r'[0-9]{1,4}', sys.argv[2])):
            verify_consumed_under_guard(int(sys.argv[2]))
        elif (len(sys.argv) == 4 and
              re.fullmatch(r'/proc/self/fd/[0-9]{1,4}', sys.argv[0]) and
              sys.argv[1] == 'verify-consumed-under-guard-held' and
              re.fullmatch(r'[0-9]{1,4}', sys.argv[2]) and
              re.fullmatch(r'[0-9]{1,4}', sys.argv[3]) and
              sys.argv[0] == '/proc/self/fd/'+sys.argv[3]):
            # Guardian passed this source inode only after validating its SHA,
            # owner, mode and named generation. Reconfirm before running proof.
            source_fd = int(sys.argv[3])
            held = os.fstat(source_fd)
            named = SOURCE.stat(follow_symlinks=False)
            need(stat.S_ISREG(held.st_mode) and held.st_uid == 0 and
                 held.st_gid == 0 and held.st_nlink == 1 and
                 stat.S_IMODE(held.st_mode) == 0o500 and
                 0 < held.st_size <= (1 << 20) and
                 (held.st_dev, held.st_ino, held.st_size, held.st_mode,
                  held.st_uid, held.st_gid, held.st_nlink,
                  held.st_mtime_ns, held.st_ctime_ns) ==
                 (named.st_dev, named.st_ino, named.st_size, named.st_mode,
                  named.st_uid, named.st_gid, named.st_nlink,
                  named.st_mtime_ns, named.st_ctime_ns),
                 'held_transition_source_changed')
            installed = read(ROOT/'auto-guardian-install.json', 4096)
            installed_record = json.loads(installed, object_pairs_hook=unique)
            need(hashlib.sha256(os.pread(source_fd, (1 << 20)+1, 0)).hexdigest() ==
                 installed_record['terminal_transition_sha256'],
                 'held_transition_hash_changed')
            verify_consumed_under_guard(int(sys.argv[2]))
        else:
            raise Refused('transition_command')
    except BaseException as error:
        print(_refusal_diagnostic(error), file=sys.stderr)
        raise SystemExit(2)
