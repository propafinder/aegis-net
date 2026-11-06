#!/usr/bin/env python3
"""One exact AUTO private generation's A/B registration and source custody.

Called only from the held activation session. No client policy or network grant.
Each phase is fail closed; compensation invokes cleanup for the same unit.
"""
from __future__ import annotations
import hashlib
import ctypes as C
import fcntl
import types
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import subprocess
import sys
import time
import types

SOURCE = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_register.py')
CONFIG = Path('/etc/aegis-auto-terminal-source.json')
STORE_CONFIG = Path('/etc/aegis-auto-terminal-store.json')
INSTALL = Path('/var/lib/aegis-install/client/auto-guardian-install.json')
BOOT_HELPER = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_boot_store.py')
STAGED_HOOK = Path('/usr/local/lib/aegis/helpers/lib/aegis-auto-terminal-hook')
ACTIVE_HOOK = Path('/usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook')
RUN = Path('/run/aegis-auto-terminal')
STAGE_PARENT = Path('/run/aegis-installer-config-snapshots')
PRIVATE = re.compile(r'aegis-auto@([0-9a-f]{64})\.service\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')

class Refused(RuntimeError):
    pass

def need(value, reason):
    if not value:
        raise Refused(reason)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def unique(pairs):
    result = {}
    for k, v in pairs:
        need(k not in result, 'duplicate_json_key')
        result[k] = v
    return result

def held(path, maximum, mode):
    for parent in reversed(path.parents):
        if parent == Path('/'):
            continue
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0 and
             not s.st_mode & 0o022, 'untrusted_parent')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        named = path.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
             stat.S_IMODE(before.st_mode) == mode and before.st_nlink == 1 and
             0 < before.st_size <= maximum, 'untrusted_leaf')
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(raw) == before.st_size and
             all(getattr(before, k) == getattr(after, k) == getattr(named, k) for k in keys),
             'leaf_changed')
        return raw
    finally:
        os.close(fd)

def config():
    raw = held(CONFIG, 4096, 0o600)
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict and
         value.get('schema') == 'aegis_auto_terminal_source_v1' and
         type(value.get('register_sha256')) is str and
         HEX64.fullmatch(value['register_sha256']) and
         digest(held(SOURCE, 1 << 20, 0o500)) == value['register_sha256'],
         'registration_source_changed')
    for key, path, mode in (
      ('witness_sha256','/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_witness.py',0o500),
      ('a_unit_sha256','/etc/systemd/system/aegis-auto-terminal-a@.service',0o644),
      ('b_unit_sha256','/etc/systemd/system/aegis-auto-terminal-b@.service',0o644),
      ('observer_unit_sha256','/etc/systemd/system/aegis-auto-terminal-observer.service',0o644),
      ('transition_unit_sha256','/etc/systemd/system/aegis-auto-terminal-transition.service',0o644),
      ('boot_helper_sha256','/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_boot_store.py',0o500),
      ('hook_sha256','/usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook',0o755)):
        need(type(value.get(key)) is str and HEX64.fullmatch(value[key]) and
             digest(held(Path(path), 1 << 20, mode)) == value[key],
             'registration_payload_changed')
    need(value.get('selected_manager') in ('NetworkManager.service','systemd-networkd.service'),
         'registration_manager_invalid')
    dropin = b'[Unit]\nRequires=aegis-auto-terminal-transition.service\nAfter=aegis-auto-terminal-transition.service\n'
    for key, unit_name in (
      ('manager_transition_dropin_sha256', value['selected_manager']),
      ('guardian_transition_dropin_sha256','aegis-auto-guardian.service')):
        path = Path('/etc/systemd/system')/(unit_name+'.d')/'31-aegis-auto-terminal-transition.conf'
        need(value.get(key) == digest(dropin) and held(path,4096,0o644) == dropin,
             'registration_transition_dropin_changed')
    return value

def command(args, *, timeout=5):
    result = subprocess.run(args, capture_output=True, timeout=timeout, check=False,
                            env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
    need(result.returncode == 0 and len(result.stdout) <= 4096 and
         len(result.stderr) <= 4096 and not result.stderr,
         'pid1_registration_refused')
    return result.stdout.decode('ascii', 'strict')

def unit_id(unit):
    match = PRIVATE.fullmatch(unit)
    need(match is not None, 'private_unit_name_invalid')
    return match[1]

def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)

def _observer_ready_match(row, live, current_source, config_sha, boot, pid1_tick):
    need(type(row) is dict and set(row) ==
         {'schema','boot','pid1_tick','pid1_private_bus_peer','pid1_private_bus_ready',
          'job_removed_match_registered','kernel_connector_ack',
          'observer_pid','observer_start_tick','observer_invocation_id',
          'observer_source_sha256','source_config_sha256'} and
         row['schema'] == 'aegis_auto_terminal_witness_ready_v2' and
         row['boot'] == boot and
         type(row['pid1_tick']) is int and 0 <= row['pid1_tick'] < (1 << 64) and
         type(row['pid1_private_bus_peer']) is int and
         row['pid1_private_bus_peer'] == 1 and
         all(row[k] is True for k in ('pid1_private_bus_ready',
              'job_removed_match_registered','kernel_connector_ack')) and
         row['pid1_tick'] == pid1_tick and
         all(row[key] == value for key,value in live.items()) and
         live['observer_source_sha256'] == current_source['witness_sha256'] and
         live['source_config_sha256'] == config_sha,
         'terminal_observer_not_ready')


def observer_ready():
    raw = held(RUN/'ready.json', 4096, 0o600)
    row = json.loads(raw, object_pairs_hook=unique)
    current_source = config()
    witness_path = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_witness.py')
    witness_raw = held(witness_path,1 << 20,0o500)
    need(digest(witness_raw) == current_source['witness_sha256'],
         'terminal_observer_source_changed')
    module = types.ModuleType('aegis_terminal_ready_readback')
    module.__file__ = str(witness_path)
    exec(compile(witness_raw,str(witness_path),'exec',dont_inherit=True),
         module.__dict__)
    live = module.live_observer_facts()
    _observer_ready_match(row,live,current_source,
                          digest(held(CONFIG,4096,0o600)),
                          Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                          module.pid1_facts()['start_tick'])
    return row

def qualified_stock_system_bus():
    """The held RefUnit sender must outlive B on the pinned Noble PID1 layout."""
    expected = {
        'dbus.service': 'bf7ec47644997441174ef6aac992d34cc46b9d2d7b8dc2feba7074d719fdbef1',
        'dbus.socket': '12b7aaec8d1e007047ec12fc85b1cc6db78565dfb896850cd9148dee0455fe7e',
    }
    for unit, expected_sha in expected.items():
        facts = command(['/usr/bin/systemctl', 'show', unit, '-p', 'FragmentPath',
                         '-p', 'DropInPaths', '-p', 'UnitFileState', '--no-pager'])
        rows = dict(line.split('=', 1) for line in facts.splitlines())
        need(set(rows) == {'FragmentPath', 'DropInPaths', 'UnitFileState'} and
             rows['DropInPaths'] == '' and
             rows['UnitFileState'] in ('enabled', 'static') and
             rows['FragmentPath'] in ('/usr/lib/systemd/system/'+unit,
                                      '/lib/systemd/system/'+unit) and
             digest(held(Path(rows['FragmentPath']), 4096, 0o644)) == expected_sha,
             'terminal_system_bus_layout_unqualified')

def wait_observer_ready():
    """Type=simple reports spawn before the authenticated READY publication."""
    deadline = time.monotonic() + 10
    while True:
        facts = command(['/usr/bin/systemctl', 'show',
                         'aegis-auto-terminal-observer.service',
                         '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID',
                         '-p', 'FragmentPath', '-p', 'DropInPaths', '--no-pager'],
                        timeout=2)
        rows = dict(line.split('=', 1) for line in facts.splitlines())
        need(set(rows) == {'ActiveState', 'SubState', 'MainPID',
                           'FragmentPath', 'DropInPaths'} and
             rows['ActiveState'] == 'active' and rows['SubState'] == 'running' and
             rows['MainPID'].isdigit() and int(rows['MainPID']) > 1 and
             rows['FragmentPath'] ==
             '/etc/systemd/system/aegis-auto-terminal-observer.service' and
             rows['DropInPaths'] == '', 'terminal_observer_not_running')
        config()
        try:
            observer_ready()
            return
        except FileNotFoundError:
            need(time.monotonic() < deadline, 'terminal_observer_ready_timeout')
            time.sleep(0.05)

def publish(path, raw, mode):
    need(0 < len(raw) <= (1 << 20), 'publication_size')
    try:
        existing = held(path, 1 << 20, mode)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        need(existing == raw, 'publication_changed')
        return
    parent = path.parent
    parent_stat = parent.lstat()
    need(stat.S_ISDIR(parent_stat.st_mode) and parent_stat.st_uid == parent_stat.st_gid == 0 and
         not parent_stat.st_mode & 0o022, 'publication_parent_untrusted')
    dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                  os.O_CLOEXEC)
    try:
        before = os.fstat(dfd)
        need((before.st_dev, before.st_ino) ==
             (parent_stat.st_dev, parent_stat.st_ino),
             'publication_parent_changed')
        # An unnamed inode has no partial visible final path and leaves no
        # unowned temp leaf after crash. Unsupported filesystems refuse.
        fd = os.open(parent, os.O_WRONLY | os.O_TMPFILE | os.O_CLOEXEC, mode)
        try:
            need(os.write(fd, raw) == len(raw), 'publication_short_write')
            os.fchmod(fd, mode)
            os.fsync(fd)
            link = C.CDLL(None, use_errno=True).linkat
            link.argtypes = [C.c_int, C.c_char_p, C.c_int, C.c_char_p,
                             C.c_int]
            link.restype = C.c_int
            need(link(fd, b'', dfd, path.name.encode(), 0x1000) == 0,
                 'publication_collision')
            os.fsync(dfd)
        finally:
            os.close(fd)
        after = os.fstat(dfd)
        need((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
             'publication_parent_changed')
    finally:
        os.close(dfd)
    need(held(path, 1 << 20, mode) == raw, 'publication_readback_changed')

def _site_plan():
    """Read-only exact expected bytes for the current installed package."""
    qualified_stock_system_bus()
    installed = json.loads(held(INSTALL, 1 << 20, 0o600), object_pairs_hook=unique)
    fields = {
      'terminal_register_sha256': (SOURCE, 0o500),
      'terminal_witness_sha256': (Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_witness.py'), 0o500),
      'terminal_boot_store_sha256': (BOOT_HELPER, 0o500),
      'terminal_transition_sha256': (Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_boot_transition.py'), 0o500),
      'terminal_a_unit_sha256': (Path('/etc/systemd/system/aegis-auto-terminal-a@.service'), 0o644),
      'terminal_b_unit_sha256': (Path('/etc/systemd/system/aegis-auto-terminal-b@.service'), 0o644),
      'terminal_observer_unit_sha256': (Path('/etc/systemd/system/aegis-auto-terminal-observer.service'), 0o644),
      'terminal_transition_unit_sha256': (Path('/etc/systemd/system/aegis-auto-terminal-transition.service'), 0o644),
      'terminal_hook_staged_sha256': (STAGED_HOOK, 0o500),
    }
    need(type(installed) is dict and installed.get('schema') == 'aegis_auto_guardian_install_v1',
         'installed_receipt_invalid')
    for field, (path, mode) in fields.items():
        need(type(installed.get(field)) is str and HEX64.fullmatch(installed[field]) and
             digest(held(path, 1 << 20, mode)) == installed[field],
             'installed_terminal_source_changed')
    namespace = {'__file__':str(BOOT_HELPER),'__name__':'aegis_terminal_boot_store'}
    exec(compile(held(BOOT_HELPER, 1 << 20, 0o500), str(BOOT_HELPER), 'exec'),
         namespace)
    helper = types.SimpleNamespace(**namespace)
    rows = helper.mounts()
    root, boot = helper.one_mount(rows, '/'), helper.one_mount(rows, '/boot')
    need(root['fstype'] == boot['fstype'] == 'ext4' and
         root['dev'] != boot['dev'] and
         all(type(row['source']) is str and row['source'].startswith('/dev/')
             for row in (root, boot)), 'unsupported_boot_layout')
    need(helper.dev_number(root['source']) == root['dev'] and
         helper.dev_number(boot['source']) == boot['dev'], 'boot_device_changed')
    staged = held(STAGED_HOOK, 1 << 20, 0o500)
    need(digest(staged) == installed['terminal_hook_staged_sha256'],
         'hook_source_changed')
    store = {
      'schema':'aegis_auto_terminal_boot_store_v1',
      'root_uuid':helper.blkid_uuid(root['source']), 'root_dev':root['dev'],
      'root_source':root['source'],
      'boot_uuid':helper.blkid_uuid(boot['source']), 'boot_dev':boot['dev'],
      'boot_source':boot['source'],
      'run_mount_dir':'/run/aegis-auto-terminal-boot-store',
      'boot_store_dir':'aegis-auto-terminal',
      'hook_path':str(ACTIVE_HOOK),
      'hook_sha256':digest(staged),
      'helper_sha256':installed['terminal_boot_store_sha256'],
    }
    helper.check_config(store)
    helper.preflight_sources(store)
    transition = b'[Unit]\nRequires=aegis-auto-terminal-transition.service\nAfter=aegis-auto-terminal-transition.service\n'
    options = []
    for manager in ('NetworkManager.service', 'systemd-networkd.service'):
        old = Path('/etc/systemd/system')/(manager+'.d')/'30-aegis-device-guard.conf'
        if old.exists() or old.is_symlink():
            raw = held(old, 4096, 0o644)
            need(b'Requires=aegis-device-egress-guard.service\n' in raw and
                 b'After=aegis-device-egress-guard.service' in raw,
                 'manager_guard_dependency_changed')
            options.append(manager)
    need(len(options) == 1, 'manager_not_unique')
    need(not (Path('/etc/systemd/system/networking.service.d')/
              '31-aegis-auto-terminal-transition.conf').exists(),
         'foreign_legacy_transition')
    source = {
      'schema':'aegis_auto_terminal_source_v1',
      'selected_manager':options[0],
      'manager_transition_dropin_sha256':digest(transition),
      'guardian_transition_dropin_sha256':digest(transition),
      'register_sha256':installed['terminal_register_sha256'],
      'witness_sha256':installed['terminal_witness_sha256'],
      'a_unit_sha256':installed['terminal_a_unit_sha256'],
      'b_unit_sha256':installed['terminal_b_unit_sha256'],
      'observer_unit_sha256':installed['terminal_observer_unit_sha256'],
      'transition_unit_sha256':installed['terminal_transition_unit_sha256'],
      'transition_sha256':installed['terminal_transition_sha256'],
      'hook_sha256':digest(staged),
      'boot_helper_sha256':installed['terminal_boot_store_sha256'],
      'shutdown_sha256':helper.file_sha('/usr/lib/systemd/systemd-shutdown'),
      'reboot_unit_sha256':helper.file_sha('/usr/lib/systemd/system/systemd-reboot.service'),
      'poweroff_unit_sha256':helper.file_sha('/usr/lib/systemd/system/systemd-poweroff.service'),
    }
    def encoded(value):
        return (json.dumps(value, sort_keys=True, separators=(',',':'))+'\n').encode('ascii')
    intent_fields = {
      'install_sha256':digest(held(INSTALL, 1 << 20, 0o600)),
      'source_sha256':digest(encoded(source)),
      'store_sha256':digest(encoded(store)),
      'hook_sha256':digest(staged),
      'selected_manager':options[0],
      'dropin_sha256':digest(transition),
    }
    return (installed,helper,staged,store,source,transition,options[0],
            intent_fields)


def configure(unit):
    """Publish a qualified Full activation site before private start."""
    unit_id(unit)
    configure_site()


def configure_site():
    _installed,helper,staged,store,source,transition,selected,intent_fields = \
        _site_plan()
    def encoded(value):
        return (json.dumps(value, sort_keys=True, separators=(',',':'))+'\n').encode('ascii')
    intent = Path('/var/lib/aegis-install/client/auto-terminal-configure-intent.json')
    publish(intent, encoded({'schema':'aegis_auto_terminal_configure_intent_v1',
                            **intent_fields}), 0o600)
    # All later publications are an idempotent prefix of this exact intent.
    boot_store_dir = Path('/boot')/'aegis-auto-terminal'
    boot_store_dir.mkdir(mode=0o700, exist_ok=True)
    sync_dir(Path('/boot'))
    helper.secure_dir(boot_store_dir, os.stat('/boot').st_dev)
    publish(ACTIVE_HOOK, staged, 0o755)
    helper.check_sources(store)
    publish(STORE_CONFIG, encoded(store), 0o600)
    publish(CONFIG, encoded(source), 0o600)
    # Manager 30 remains valid during passive staging. This 31 layer is
    # published only after all inputs and the active shutdown hook are exact.
    for unit_name in (selected, 'aegis-auto-guardian.service'):
        directory = Path('/etc/systemd/system')/(unit_name+'.d')
        directory.mkdir(mode=0o755, exist_ok=True)
        publish(directory/'31-aegis-auto-terminal-transition.conf', transition, 0o644)
    config()
    command(['/usr/bin/systemctl','daemon-reload'], timeout=15)
    command(['/usr/bin/systemctl','start','aegis-auto-terminal-observer.service'], timeout=15)
    wait_observer_ready()
    need(digest(held(CONFIG,4096,0o600)) == digest(encoded(source)) and
         digest(held(STORE_CONFIG,4096,0o600)) == digest(encoded(store)),
         'terminal_config_changed')
    publish(Path('/var/lib/aegis-install/client/auto-terminal-configured.json'),
            encoded({'schema':'aegis_auto_terminal_configured_v1',
                     **intent_fields}), 0o600)

def prepare(unit):
    # The private StartTransientUnit carries Requires/After=B@token. B is a
    # resident oneshot and stops after the private unit, before the guardian.
    config(); observer_ready()
    control = Path('/var/lib/aegis-install/client')
    roster = tuple(control.iterdir())
    need(len(roster) <= 512, 'terminal_registration_roster_oversize')
    for candidate in roster:
        if not candidate.name.startswith('auto-terminal-registration-pending-'):
            continue
        match = re.fullmatch(r'auto-terminal-registration-pending-([0-9a-f]{64})\.json',
                             candidate.name)
        need(match is not None, 'terminal_registration_name_invalid')
        completed = control/('auto-terminal-registration-complete-'+match[1]+'.json')
        if not completed.exists() and not completed.is_symlink():
            raise Refused('terminal_previous_registration_requires_recovery')
        pending_raw = held(candidate, 4096, 0o600)
        pending_row = json.loads(pending_raw, object_pairs_hook=unique)
        complete_row = json.loads(held(completed, 4096, 0o600),
                                  object_pairs_hook=unique)
        need(pending_row.get('schema') ==
             'aegis_auto_terminal_registration_pending_v1' and
             pending_row.get('unit') == 'aegis-auto@'+match[1]+'.service' and
             complete_row.get('schema') ==
             'aegis_auto_terminal_registration_complete_v1' and
             complete_row.get('pending_sha256') == digest(pending_raw) and
             type(complete_row.get('activation_sha256')) is str and
             HEX64.fullmatch(complete_row['activation_sha256']) and
             type(complete_row.get('active_generation_sha256')) is str and
             HEX64.fullmatch(complete_row['active_generation_sha256']),
             'terminal_prior_registration_changed')
    token = unit_id(unit)
    pending = Path('/var/lib/aegis-install/client')/(
        'auto-terminal-registration-pending-'+token+'.json')
    complete = Path('/var/lib/aegis-install/client')/(
        'auto-terminal-registration-complete-'+token+'.json')
    need(not pending.exists() and not pending.is_symlink() and
         not complete.exists() and not complete.is_symlink(),
         'terminal_previous_registration_requires_recovery')
    b = 'aegis-auto-terminal-b@' + unit_id(unit) + '.service'
    facts = command(['/usr/bin/systemctl','show',b,'-p','FragmentPath',
                     '-p','DropInPaths','--no-pager'])
    need(set(facts.splitlines()) == {
        'FragmentPath=/etc/systemd/system/aegis-auto-terminal-b@.service',
        'DropInPaths='}, 'terminal_b_source_unavailable')

def orphan_cgroup_empty(unit, base=Path('/sys/fs/cgroup/system.slice')):
    """Prove the fixed old unit cgroup empty even if PID 1 cleared its property."""
    group = base/unit
    need(not group.is_symlink(), 'terminal_orphan_private_cgroup_changed')
    if group.exists():
        need(group.is_dir() and not group.is_symlink(),
             'terminal_orphan_private_cgroup_changed')
        procs = group.joinpath('cgroup.procs').read_bytes()
        events = group.joinpath('cgroup.events').read_bytes()
        need(len(procs) <= 4096 and procs == b'' and len(events) <= 4096 and
             events.splitlines().count(b'populated 0') == 1 and
             all(line in (b'populated 0', b'frozen 0', b'frozen 1')
                 for line in events.splitlines()),
             'terminal_orphan_private_cgroup_not_empty')


def recover_incomplete(_new_unit):
    """Compensate only an orphan prepublication A/B registration under deny.

    A durable active report for the old private unit is never retired here;
    that case requires the existing typed inverse before retry.
    """
    config(); observer_ready(); unit_id(_new_unit)
    control = Path('/var/lib/aegis-install/client')
    entries = tuple(control.iterdir())
    need(len(entries) <= 512, 'terminal_registration_roster_oversize')
    incomplete = []
    for pending in entries:
        if not pending.name.startswith('auto-terminal-registration-pending-'):
            continue
        match = re.fullmatch(r'auto-terminal-registration-pending-([0-9a-f]{64})\.json',
                             pending.name)
        need(match is not None, 'terminal_registration_name_invalid')
        completed = control/('auto-terminal-registration-complete-'+match[1]+'.json')
        if completed.exists() or completed.is_symlink():
            continue
        raw = held(pending,4096,0o600)
        row = json.loads(raw,object_pairs_hook=unique)
        unit = 'aegis-auto@'+match[1]+'.service'
        need(set(row) == {'schema','boot_id','unit','source_sha256'} and
             row['schema'] == 'aegis_auto_terminal_registration_pending_v1' and
             row['unit'] == unit and
             row['source_sha256'] == digest(held(CONFIG,4096,0o600)) and
             type(row['boot_id']) is str and
             re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
                          r'[0-9a-f]{4}-[0-9a-f]{12}',row['boot_id']),
             'terminal_orphan_pending_changed')
        incomplete.append((unit,pending,raw,row))
    need(len(incomplete) <= 1, 'terminal_multiple_orphans')
    if not incomplete: return
    unit,pending,pending_raw,row = incomplete[0]
    active_path = Path('/var/lib/aegis-auto/control/generation.json')
    try:
        active = json.loads(held(active_path,139264,0o600),object_pairs_hook=unique)
    except FileNotFoundError:
        active = None
    if active is not None:
        report = active.get('report') if type(active) is dict else None
        need(type(report) is dict and
             (type(report.get('terminal')) is not dict or
              report['terminal'].get('private_unit') != unit),
             'terminal_orphan_has_durable_active_owner')
    for suffix in ('a','b'):
        actor = 'aegis-auto-terminal-'+suffix+'@'+unit_id(unit)+'.service'
        facts = command(['/usr/bin/systemctl','show',actor,
                         '-p','Job','--no-pager'])
        need(set(facts.splitlines()) in ({'Job='},{'Job=0'}),
             'terminal_orphan_actor_job')
    private_facts = command(['/usr/bin/systemctl','show',unit,'-p','ActiveState',
                             '-p','SubState','-p','Job','-p','MainPID',
                             '-p','ControlPID','-p','NFileDescriptorStore',
                             '-p','ControlGroup','-p','LoadState',
                             '--no-pager'])
    private_rows = dict(line.split('=',1) for line in private_facts.splitlines())
    need(set(private_rows) == {'ActiveState','SubState','Job','MainPID',
                               'ControlPID','NFileDescriptorStore',
                               'ControlGroup','LoadState'} and
         private_rows['ActiveState'] == 'inactive' and
         private_rows['SubState'] == 'dead' and
         private_rows['LoadState'] in ('loaded','not-found') and
         private_rows['Job'] in ('','0') and
         private_rows['MainPID'] == private_rows['ControlPID'] ==
             private_rows['NFileDescriptorStore'] == '0' and
         private_rows['ControlGroup'] in ('','/system.slice/'+unit),
         'terminal_orphan_private_not_stopped')
    # PID 1 may clear ControlGroup before the named cgroup is removed.  The
    # exact unit-derived path remains authoritative even when that property is
    # empty; a surviving descendant may have no MainPID or ControlPID.
    orphan_cgroup_empty(unit)
    # Enforce the old policy block before any source-qualified actor cleanup.
    command(['/bin/bash','/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh',
             'block'],timeout=15)
    guardian_path = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py')
    guardian_raw = held(guardian_path,1 << 20,0o500)
    installed = json.loads(held(INSTALL,1 << 20,0o600),object_pairs_hook=unique)
    need(installed.get('guardian_sha256') == digest(guardian_raw),
         'terminal_orphan_guardian_changed')
    namespace = {'__file__':str(guardian_path),
                 '__name__':'aegis_terminal_guardian_recovery'}
    exec(compile(guardian_raw,str(guardian_path),'exec'),namespace)
    guardian = types.SimpleNamespace(**namespace)
    guardian.own_source()
    guard_path = Path('/var/lib/aegis-install/client/device-guard.conf.lock')
    fd = os.open(guard_path,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        lock_deadline = time.monotonic()+3
        while True:
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except BlockingIOError:
                need(time.monotonic()<lock_deadline,
                     'terminal_orphan_guard_lock_busy')
                time.sleep(0.01)
        guardian._held_lock(fd,guard_path)
        deadline = time.monotonic()+12
        _state,projection = guardian._semantic_policy_readback(deadline=deadline)
        need(guardian._no_client_grant(projection) and
             not guardian.STOP_INTENT.exists() and
             not guardian.STOP_INTENT.is_symlink(),
             'terminal_orphan_not_denied')
        guardian._boot_private_owners_absent(deadline)
        cleanup(unit)
        guardian._held_lock(fd,guard_path)
        compensated = pending.with_name(pending.name.replace('-pending-','-compensated-'))
        expected = (json.dumps({
            'schema':'aegis_auto_terminal_registration_compensated_v1',
            'pending_sha256':digest(pending_raw),
            'unit':unit,'source_sha256':row['source_sha256']},
            sort_keys=True,separators=(',',':'))+'\n').encode()
        need(not pending.exists() and not pending.is_symlink() and
             held(compensated,4096,0o600) == expected and
             guardian._no_client_grant(
                 guardian._semantic_policy_readback(deadline=time.monotonic()+12)[1]),
             'terminal_orphan_cleanup_changed')
        guardian._boot_private_owners_absent(time.monotonic()+12)
    finally:
        os.close(fd)


def activate(unit):
    config(); observer_ready()
    prepare(unit)
    a = 'aegis-auto-terminal-a@'+unit_id(unit)+'.service'
    command(['/usr/bin/systemctl','start',a],timeout=15)
    facts = command(['/usr/bin/systemctl','show',a,'-p','ActiveState',
                     '-p','SubState','-p','FragmentPath','-p','DropInPaths',
                     '--no-pager'])
    need('ActiveState=active\n' in facts and 'SubState=exited\n' in facts and
         'FragmentPath=/etc/systemd/system/aegis-auto-terminal-a@.service\n' in facts and
         'DropInPaths=\n' in facts, 'terminal_a_not_active')
    pending = Path('/var/lib/aegis-install/client')/(
        'auto-terminal-registration-pending-'+unit_id(unit)+'.json')
    body = (json.dumps({'schema':'aegis_auto_terminal_registration_pending_v1',
                        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                        'unit':unit,
                        'source_sha256':digest(held(CONFIG,4096,0o600))},
                       sort_keys=True,separators=(',',':'))+'\n').encode()
    publish(pending, body, 0o600)

def _activation_preseal(unit, stage: Path, generation: str, manifest: str):
    """Derive a no-grant crash witness before native generation publication."""
    config();observer_ready();activate_readback(unit)
    need(type(generation) is str and HEX64.fullmatch(generation) and
         type(manifest) is str and HEX64.fullmatch(manifest) and
         stage.is_absolute() and '..' not in stage.parts and
         stage.parent==STAGE_PARENT,'terminal_preseal_stage_invalid')
    stage_stat=stage.lstat()
    need(stat.S_ISDIR(stage_stat.st_mode) and stage_stat.st_uid==0 and
         not stage_stat.st_mode & 0o022,'terminal_preseal_stage_changed')
    terminal_raw=held(stage/'receipts/activation-owner/terminal.json',
                      1 << 20,0o600)
    terminal=json.loads(terminal_raw,object_pairs_hook=unique)
    source_sha=digest(held(CONFIG,4096,0o600))
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    pending=Path('/var/lib/aegis-install/client')/(
        'auto-terminal-registration-pending-'+unit_id(unit)+'.json')
    pending_raw=held(pending,4096,0o600)
    need(type(terminal) is dict and terminal.get('schema')==1 and
         terminal.get('outcome')=='finalized' and
         terminal.get('private_unit')==unit and
         terminal.get('stage')==[stage_stat.st_dev,stage_stat.st_ino] and
         type(terminal.get('transaction_nonce')) is str and
         re.fullmatch(r'[0-9a-f]{32}',terminal['transaction_nonce']) and
         json.loads(pending_raw,object_pairs_hook=unique)=={
             'schema':'aegis_auto_terminal_registration_pending_v1',
             'boot_id':boot,'unit':unit,'source_sha256':source_sha},
         'terminal_preseal_source_changed')
    record={'schema':'aegis_auto_terminal_activation_preseal_v1',
            'boot_id':boot,'unit':unit,
            'nonce':terminal['transaction_nonce'],
            'stage_path':str(stage),'stage_dev':stage_stat.st_dev,
            'stage_ino':stage_stat.st_ino,
            'terminal_sha256':digest(terminal_raw),
            'installed_generation_sha256':generation,
            'installed_manifest_sha256':manifest,
            'source_sha256':source_sha}
    return record,stage_stat,terminal_raw


def preseal(unit, stage: Path, generation: str, manifest: str):
    """Durably pin finalized identity before auto-seal-generation can commit."""
    record,before,_=_activation_preseal(unit,stage,generation,manifest)
    raw=(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode()
    path=Path('/var/lib/aegis-install/client')/(
        'auto-terminal-activation-preseal-'+unit_id(unit)+'.json')
    publish(path,raw,0o600)
    after=stage.lstat()
    need(held(path,4096,0o600)==raw and
         all(getattr(before,k)==getattr(after,k) for k in
             ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
              'st_size','st_mtime_ns','st_ctime_ns')),
         'terminal_preseal_readback_changed')


def commit(unit, stage: Path, generation: str, manifest: str):
    preseal_record,_,_= _activation_preseal(unit,stage,generation,manifest)
    preseal_raw=(json.dumps(preseal_record,sort_keys=True,
                 separators=(',',':'))+'\n').encode()
    preseal_path=Path('/var/lib/aegis-install/client')/(
        'auto-terminal-activation-preseal-'+unit_id(unit)+'.json')
    need(held(preseal_path,4096,0o600)==preseal_raw,
         'terminal_preseal_missing_or_changed')
    c=config(); observer_ready(); activate_readback(unit)
    need(HEX64.fullmatch(generation) and HEX64.fullmatch(manifest) and
         stage.is_absolute() and '..' not in stage.parts and
         stage.parent == STAGE_PARENT, 'terminal_stage_invalid')
    stage_stat = stage.lstat()
    need(stat.S_ISDIR(stage_stat.st_mode) and stage_stat.st_uid == 0 and
         not stage_stat.st_mode & 0o022, 'terminal_stage_changed')
    terminal_path = stage/'receipts/activation-owner/terminal.json'
    terminal_raw = held(terminal_path, 1 << 20, 0o600)
    terminal = json.loads(terminal_raw, object_pairs_hook=unique)
    need(type(terminal) is dict and terminal.get('schema') == 1 and
         terminal.get('outcome') == 'finalized' and
         terminal.get('private_unit') == unit and
         terminal.get('stage') == [stage_stat.st_dev, stage_stat.st_ino] and
         type(terminal.get('transaction_nonce')) is str and
         re.fullmatch(r'[0-9a-f]{32}', terminal['transaction_nonce']),
         'terminal_activation_mismatch')
    active_path = Path('/var/lib/aegis-auto/control/generation.json')
    active_raw = held(active_path, 139264, 0o600)
    active = json.loads(active_raw, object_pairs_hook=unique)
    report = active.get('report') if type(active) is dict else None
    need(type(report) is dict and active.get('schema') == 'aegis_auto_v2_generation_v1' and
         type(report.get('stage')) is dict and
         report['stage'].get('path') == str(stage) and
         report['stage'].get('device') == stage_stat.st_dev and
         report['stage'].get('inode') == stage_stat.st_ino and
         report['stage'].get('phase') == 'finalized' and
         type(report.get('terminal')) is dict and
         report['terminal'].get('start_terminal_sha256') == digest(terminal_raw) and
         report['terminal'].get('private_unit') == unit and
         report['terminal'].get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
         type(report.get('input')) is dict and
         report['input'].get('installed_manifest_sha256') == manifest and
         type(active.get('boot_snapshot_sha256')) is str and
         HEX64.fullmatch(active['boot_snapshot_sha256']) and
         type(active.get('report_sha256')) is str and
         HEX64.fullmatch(active['report_sha256']),
         'terminal_durable_generation_mismatch')
    snapshot_path = Path('/var/lib/aegis-auto/control/boot-snapshots')/(
        'snapshot-'+active['boot_snapshot_sha256']+'.json')
    snapshot_raw = held(snapshot_path, 1 << 20, 0o600)
    need(digest(snapshot_raw) == active['boot_snapshot_sha256'],
         'terminal_boot_snapshot_changed')
    record = {'schema':'aegis_auto_terminal_activation_v1',
              'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'unit':unit, 'nonce':terminal['transaction_nonce'],
              'stage_path':str(stage),
              'stage_dev':stage_stat.st_dev,'stage_ino':stage_stat.st_ino,
              'terminal_sha256':digest(terminal_raw),
              'installed_generation_sha256':generation,
              'installed_manifest_sha256':manifest,
              'active_generation_sha256':digest(active_raw),
              'active_report_sha256':active['report_sha256'],
              'boot_snapshot_sha256':active['boot_snapshot_sha256'],
              'source_sha256':digest(held(CONFIG,4096,0o600))}
    raw = (json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode()
    path = RUN/('activation-'+unit_id(unit)+'.json')
    publish(path, raw, 0o600)
    durable = Path('/var/lib/aegis-install/client')/(
        'auto-terminal-activation-'+unit_id(unit)+'.json')
    # The complete receipt must never outlive the only readable activation
    # body. Reboot may erase /run immediately after generation sealing.
    publish(durable,raw,0o600)
    after = stage.lstat()
    keys = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
            'st_size','st_mtime_ns','st_ctime_ns')
    need(held(path,4096,0o600)==raw and
         held(durable,4096,0o600)==raw and
         all(getattr(stage_stat,k)==getattr(after,k) for k in keys),
         'activation_readback_changed')
    pending = Path('/var/lib/aegis-install/client')/(
        'auto-terminal-registration-pending-'+unit_id(unit)+'.json')
    pending_row = json.loads(held(pending,4096,0o600), object_pairs_hook=unique)
    need(pending_row == {
        'schema':'aegis_auto_terminal_registration_pending_v1',
        'boot_id':record['boot_id'],'unit':unit,
        'source_sha256':record['source_sha256']},
        'terminal_pending_changed')
    complete = pending.with_name(pending.name.replace('-pending-','-complete-'))
    publish(complete, (json.dumps({
        'schema':'aegis_auto_terminal_registration_complete_v1',
        'pending_sha256':digest(held(pending,4096,0o600)),
        'activation_sha256':digest(raw),
        'active_generation_sha256':record['active_generation_sha256']},
        sort_keys=True,separators=(',',':'))+'\n').encode(), 0o600)

def activate_readback(unit):
    a = 'aegis-auto-terminal-a@'+unit_id(unit)+'.service'
    facts = command(['/usr/bin/systemctl','show',a,'-p','ActiveState',
                     '-p','SubState','--no-pager'])
    need(set(facts.splitlines())=={'ActiveState=active','SubState=exited'},
         'terminal_a_not_active')

def cleanup(unit):
    # Compensation only. An inactive B or A may have no active job. A source
    # mismatch or ambiguous PID 1 state preserves the independent deny.
    c=config();need(c['schema']=='aegis_auto_terminal_source_v1','source_changed')
    a='aegis-auto-terminal-a@'+unit_id(unit)+'.service'
    b='aegis-auto-terminal-b@'+unit_id(unit)+'.service'
    command(['/usr/bin/systemctl','stop',a],timeout=15)
    command(['/usr/bin/systemctl','stop',b],timeout=15)
    pending = Path('/var/lib/aegis-install/client')/(
        'auto-terminal-registration-pending-'+unit_id(unit)+'.json')
    if pending.exists() or pending.is_symlink():
        pending_raw = held(pending,4096,0o600)
        row = json.loads(pending_raw,object_pairs_hook=unique)
        need(row.get('unit') == unit and
             row.get('schema') == 'aegis_auto_terminal_registration_pending_v1',
             'terminal_pending_changed')
        compensated = pending.with_name(pending.name.replace('-pending-','-compensated-'))
        publish(compensated,(json.dumps({
            'schema':'aegis_auto_terminal_registration_compensated_v1',
            'pending_sha256':digest(pending_raw),
            'unit':unit,
            'source_sha256':row['source_sha256']},
            sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
        pending.unlink();sync_dir(pending.parent)


# A stopped, guarded package rotation is the only caller of this history.
MIGRATION = Path('/var/lib/aegis-install/client/terminal-migrations')
MIGRATION_PENDING = MIGRATION/'pending.json'
MIGRATION_HEAD = MIGRATION/'head.json'
COLD_RECOVERY = MIGRATION/'cold-recovery'


_COLD_ARCHIVE_PHASE_LEAVES = frozenset({
    'intent.json', 'phase-00.json', 'phase-01.json', 'phase-02.json',
    'phase-03.json', 'phase-04.json', 'phase-05.json',
    'cold-denied-prebind.json', 'cold-config-intent.json',
    'transition-ready.json',
})


def _cold_archive_boot_hex(name, prefix):
    tail=name.removeprefix(prefix).removesuffix('.json')
    return (name.startswith(prefix) and name.endswith('.json') and
            re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-[0-9a-f]{64}',
                         tail) is not None)


def _cold_archive_leaf_allowed(name, role):
    if role==2:
        return name=='intent.json'
    if name in _COLD_ARCHIVE_PHASE_LEAVES or any(
        re.fullmatch(prefix+r'[0-9a-f]{64}\.json',name) for prefix in
        ('intent-consumed-','pending-consumed-')):
        return True
    if role==1:
        return False
    return (name=='rollover-barrier.json' or any(
        re.fullmatch(prefix+r'[0-9a-f]{64}\.json',name) for prefix in
        ('cold-old-context-','rollover-barrier-consumed-','barrier-bound-',
         'prior-pointer-retire-intent-','prior-pointer-retired-')) or
        any(_cold_archive_boot_hex(name,prefix) for prefix in
            ('prior-pointer-retired-','attempt-head-','stage-retirement-')))


def _cold_archive_row(path, logical, directory=False):
    before=path.lstat()
    need(before.st_uid==before.st_gid==0 and
         stat.S_IMODE(before.st_mode)==(0o700 if directory else 0o600) and
         (stat.S_ISDIR(before.st_mode) if directory else
          stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
          0<before.st_size<=1 << 20), 'cold_archive_member_untrusted')
    raw=None if directory else held(path,1 << 20,0o600)
    if raw is not None:
        row=json.loads(raw,object_pairs_hook=unique)
        need(type(row) is dict and type(row.get('schema')) is str and
             row['schema'].startswith('aegis_') and
             raw==_migration_json(row),'cold_archive_member_noncanonical')
    after=path.lstat()
    keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
          'st_size','st_mtime_ns','st_ctime_ns')
    need(all(getattr(before,k)==getattr(after,k) for k in keys),
         'cold_archive_member_changed')
    return {'path':logical,'kind':'dir' if directory else 'file',
            'mode':stat.S_IMODE(before.st_mode),'uid':before.st_uid,
            'gid':before.st_gid,'nlink':before.st_nlink,
            'size':None if directory else before.st_size,
            'sha256':None if directory else digest(raw)}


def _cold_archive_walk(path, logical, role, rows):
    names=sorted(path.iterdir(),key=lambda entry:entry.name)
    need(len(names)<=512,'cold_archive_directory_bound')
    for child in names:
        name=child.name
        need(re.fullmatch(r'[A-Za-z0-9_.-]{1,200}',name) is not None,
             'cold_archive_name_invalid')
        next_role=None
        if role==0 and name=='attempts':
            next_role=3
        elif role==0 and name.startswith('stage-retired-') and \
             _cold_archive_boot_hex('stage-retirement-'+name[len('stage-retired-'):]+'.json',
                                    'stage-retirement-'):
            next_role=2
        elif role==3 and _cold_archive_boot_hex('attempt-head-'+name+'.json',
                                               'attempt-head-'):
            next_role=1
        if next_role is not None:
            rows.append(_cold_archive_row(child,logical+'/'+name,True))
            _cold_archive_walk(child,logical+'/'+name,next_role,rows)
        else:
            need(role!=3 and _cold_archive_leaf_allowed(name,role),
                 'cold_archive_foreign_member')
            rows.append(_cold_archive_row(child,logical+'/'+name))
        need(len(rows)<=512,'cold_archive_roster_bound')


def _cold_archive_preseal(path, current_source_sha, source, store, history):
    """A B-only preseal is historical evidence, never a grant by itself."""
    name=path.name
    need(re.fullmatch(r'auto-terminal-activation-preseal-[0-9a-f]{64}\.json',
                      name),'cold_archive_preseal_name')
    token=name[len('auto-terminal-activation-preseal-'):-len('.json')]
    row,raw=_migration_record(path,4096)
    need(set(row)=={'schema','boot_id','unit','nonce','stage_path','stage_dev',
                    'stage_ino','terminal_sha256','installed_generation_sha256',
                    'installed_manifest_sha256','source_sha256'} and
         row['schema']=='aegis_auto_terminal_activation_preseal_v1' and
         row['unit']=='aegis-auto@'+token+'.service' and
         type(row['boot_id']) is str and
         re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
                      row['boot_id']) and
         type(row['nonce']) is str and
         re.fullmatch(r'[0-9a-f]{32}',row['nonce']) and
         type(row['stage_path']) is str and
         row['stage_path'].startswith('/run/aegis-') and
         type(row['stage_dev']) is int and row['stage_dev']>=0 and
         type(row['stage_ino']) is int and row['stage_ino']>0 and
         all(type(row[key]) is str and HEX64.fullmatch(row[key]) for key in
             ('terminal_sha256','installed_generation_sha256',
              'installed_manifest_sha256','source_sha256')),
         'cold_archive_preseal_invalid')
    if row['source_sha256']!=current_source_sha:
        historical_source,historical_store=history.historical_source_context(
            row['source_sha256'],source,store,None)
        need(historical_source.get('schema')=='aegis_auto_terminal_source_v1' and
             historical_store.get('root_uuid')==store.get('root_uuid') and
             historical_store.get('boot_uuid')==store.get('boot_uuid'),
             'cold_archive_preseal_source')
    client=MIGRATION.parent
    pending=client/('auto-terminal-registration-pending-'+token+'.json')
    compensated=client/('auto-terminal-registration-compensated-'+token+'.json')
    pending_raw=None
    pending_sha=None
    if pending.exists() or pending.is_symlink():
        pending_row,pending_raw=_migration_record(pending,4096)
        need(pending_row=={'schema':'aegis_auto_terminal_registration_pending_v1',
             'boot_id':row['boot_id'],'unit':row['unit'],
             'source_sha256':row['source_sha256']},
             'cold_archive_preseal_pending')
        pending_sha=digest(pending_raw)
    if compensated.exists() or compensated.is_symlink():
        tomb,_=_migration_record(compensated,4096)
        need(set(tomb)=={'schema','pending_sha256','unit','source_sha256'} and
             tomb['schema']=='aegis_auto_terminal_registration_compensated_v1' and
             tomb['unit']==row['unit'] and
             tomb['source_sha256']==row['source_sha256'] and
             type(tomb['pending_sha256']) is str and
             HEX64.fullmatch(tomb['pending_sha256']) and
             (pending_sha is None or tomb['pending_sha256']==pending_sha),
             'cold_archive_preseal_compensated')
        pending_sha=tomb['pending_sha256']
    else:
        need(pending_raw is not None,'cold_archive_preseal_orphan')
    activation=client/('auto-terminal-activation-'+token+'.json')
    complete=client/('auto-terminal-registration-complete-'+token+'.json')
    if activation.exists() or activation.is_symlink():
        active,active_raw=_migration_record(activation,4096)
        need(active.get('schema')=='aegis_auto_terminal_activation_v1' and
             all(active.get(key)==value for key,value in row.items() if
                 key!='schema'),'cold_archive_preseal_activation')
    else:
        active_raw=None
    if complete.exists() or complete.is_symlink():
        completed,_=_migration_record(complete,4096)
        need(active_raw is not None and pending_sha is not None and
             set(completed)=={'schema','pending_sha256','activation_sha256',
                              'active_generation_sha256'} and
             completed['schema']=='aegis_auto_terminal_registration_complete_v1' and
             completed['pending_sha256']==pending_sha and
             completed['activation_sha256']==digest(active_raw) and
             completed['active_generation_sha256']==active.get('active_generation_sha256'),
             'cold_archive_preseal_complete')
    need(held(path,4096,0o600)==raw,'cold_archive_preseal_changed')


def cold_history_archive_readback(install_fd,guard_fd,pending_sha):
    """Give native a closed, no-grant logical roster before A2 package effect."""
    need(type(pending_sha) is str and HEX64.fullmatch(pending_sha),
         'cold_archive_pending_arg')
    source=config()
    source_raw=held(CONFIG,4096,0o600)
    old_source_sha=digest(source_raw)
    guardian,_=_migration_guard(install_fd,guard_fd)
    pending,pending_raw=_migration_record(MIGRATION_PENDING,4096)
    need(digest(pending_raw)==pending_sha and
         type(pending) is dict and
         pending.get('schema')=='aegis_auto_terminal_migration_pending_v1' and
         pending.get('old_source_sha256')==old_source_sha and
         pending.get('boot_id')==Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
         type(pending.get('context_sha256')) is str and
         HEX64.fullmatch(pending['context_sha256']),
         'cold_archive_pending_changed')
    context,context_raw=_migration_record(
        MIGRATION/('context-'+pending['context_sha256']+'.json'),256 << 10)
    need(digest(context_raw)==pending['context_sha256'] and
         context.get('old_source_sha256')==old_source_sha,
         'cold_archive_context_changed')
    deadline=time.monotonic()+12
    guardian._rotation_actors_stopped(deadline)
    guardian._boot_private_owners_absent(deadline)
    _migration_observer_group_empty()
    install=json.loads(held(INSTALL,1 << 20,0o600),object_pairs_hook=unique)
    transition=Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_boot_transition.py')
    transition_raw=held(transition,1 << 20,0o500)
    need(install.get('terminal_transition_sha256')==digest(transition_raw),
         'cold_archive_transition_source')
    namespace={'__file__':str(transition),'__name__':'aegis_cold_archive_transition'}
    exec(compile(transition_raw,str(transition),'exec'),namespace)
    history=types.SimpleNamespace(**namespace)
    store=json.loads(held(STORE_CONFIG,4096,0o600),object_pairs_hook=unique)
    history.historical_carriers_closed(store,source)
    archive=MIGRATION.parent/('terminal-cold-history-'+pending_sha)
    need(not archive.is_symlink(),'cold_archive_root_symlink')
    if archive.exists():
        _cold_archive_row(archive,'archive',True)
        archive_names={entry.name for entry in archive.iterdir()}
        need(archive_names<={'archive-intent.json','archive-complete.json',
                             'cold-recovery','preseal'},'cold_archive_foreign_root')
    else:
        archive_names=set()
    live=COLD_RECOVERY.exists() or COLD_RECOVERY.is_symlink()
    saved='cold-recovery' in archive_names
    need(not (live and saved),'cold_archive_double_tree')
    cold_root=COLD_RECOVERY if live else archive/'cold-recovery' if saved else None
    rows=[]
    if cold_root is not None:
        rows.append(_cold_archive_row(cold_root,
                                     'terminal-migrations/cold-recovery',True))
        _cold_archive_walk(cold_root,'terminal-migrations/cold-recovery',0,rows)
        # The installed transition parser reads a fixed cold root. Rebind
        # only its source-authenticated, in-memory namespace to the exact
        # held archive location during a rename-prefix replay.
        namespace['COLD_ROOT']=cold_root
        namespace['COLD_PHASE3']=cold_root/'phase-03.json'
        namespace['COLD_READY']=cold_root/'transition-ready.json'
        history._cold_consumed_under_guard(
            Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            source,source_raw)
    preseal_live=[]
    preseal_saved=[]
    for name in sorted(os.listdir(MIGRATION.parent)):
        if name.startswith('auto-terminal-activation-preseal-'):
            need(re.fullmatch(r'auto-terminal-activation-preseal-[0-9a-f]{64}\.json',
                              name),'cold_archive_preseal_name')
            preseal_live.append(name)
    if 'preseal' in archive_names:
        preseal=archive/'preseal'
        _cold_archive_row(preseal,'archive/preseal',True)
        for name in sorted(os.listdir(preseal)):
            need(re.fullmatch(r'auto-terminal-activation-preseal-[0-9a-f]{64}\.json',
                              name),'cold_archive_preseal_name')
            preseal_saved.append(name)
    need(not set(preseal_live)&set(preseal_saved),'cold_archive_preseal_double')
    for name in preseal_live:
        _cold_archive_preseal(MIGRATION.parent/name,old_source_sha,
                              source,store,history)
        rows.append(_cold_archive_row(MIGRATION.parent/name,name))
    for name in preseal_saved:
        _cold_archive_preseal(archive/'preseal'/name,old_source_sha,
                              source,store,history)
        rows.append(_cold_archive_row(archive/'preseal'/name,name))
    need(len(rows)<=512 and sum(row['size'] or 0 for row in rows)<=16 << 20,
         'cold_archive_roster_oversize')
    rows.sort(key=lambda row:row['path'])
    need(len({row['path'] for row in rows})==len(rows),
         'cold_archive_logical_duplicate')
    raw=_migration_json(rows)
    need(len(raw)<=4 << 20,'cold_archive_manifest_oversize')
    state=('complete' if 'archive-complete.json' in archive_names else
           'archived_prefix' if saved or preseal_saved else 'source')
    need(held(CONFIG,4096,0o600)==source_raw and
         held(MIGRATION_PENDING,4096,0o600)==pending_raw,
         'cold_archive_source_generation_changed')
    guardian._held_lock(install_fd,guardian.INSTALL_LOCK)
    guardian._held_lock(guard_fd,guardian.GUARD_LOCK)
    return {'schema':'aegis_auto_terminal_cold_archive_roster_v1',
            'ordinary_pending_sha256':pending_sha,
            'old_source_sha256':old_source_sha,
            'cold_root':'terminal-migrations/cold-recovery',
            'cold_root_present':cold_root is not None,
            'members':rows,
            'member_manifest_sha256':digest(raw),'no_client_grant':True}


def _migration_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode('ascii')


def _migration_record(path, maximum=131072):
    raw = held(path, maximum, 0o600)
    row = json.loads(raw, object_pairs_hook=unique)
    need(raw == _migration_json(row), 'migration_record_noncanonical')
    return row, raw


def _migration_dir():
    parent = MIGRATION.parent
    before = parent.lstat()
    need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0 and
         stat.S_IMODE(before.st_mode) == 0o700, 'migration_parent_untrusted')
    MIGRATION.mkdir(mode=0o700, exist_ok=True)
    actual = MIGRATION.lstat()
    need(stat.S_ISDIR(actual.st_mode) and actual.st_uid == actual.st_gid == 0 and
         stat.S_IMODE(actual.st_mode) == 0o700 and actual.st_dev == before.st_dev,
         'migration_dir_untrusted')
    sync_dir(parent)
    return MIGRATION


def _migration_guard(install_fd, guard_fd):
    need(type(install_fd) is int and type(guard_fd) is int and
         3 <= install_fd <= 1024 and 3 <= guard_fd <= 1024 and
         install_fd != guard_fd, 'migration_lock_args')
    path = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py')
    raw = held(path, 1 << 20, 0o500)
    receipt = json.loads(held(INSTALL, 1 << 20, 0o600), object_pairs_hook=unique)
    need(receipt.get('guardian_sha256') == digest(raw), 'migration_guardian_source')
    namespace = {'__file__':str(path), '__name__':'aegis_terminal_migration_guardian'}
    exec(compile(raw, str(path), 'exec'), namespace)
    guardian = types.SimpleNamespace(**namespace)
    guardian.own_source()
    guardian._held_lock(install_fd, guardian.INSTALL_LOCK)
    guardian._held_lock(guard_fd, guardian.GUARD_LOCK)
    deadline = time.monotonic()+12
    state, projection = guardian._semantic_policy_readback(deadline=deadline)
    need(guardian._no_client_grant(projection) and
         not guardian.STOP_INTENT.exists() and
         not guardian.STOP_INTENT.is_symlink(), 'migration_not_denied')
    guardian._boot_private_owners_absent(deadline)
    rows = command(['/usr/bin/systemctl', 'list-jobs', '--no-legend',
                    '--no-pager', '--plain'], timeout=5)
    need(not any(('aegis-auto' in line or 'systemd-reboot.service' in line or
                  'systemd-poweroff.service' in line) for line in rows.splitlines()),
         'migration_jobs_pending')
    for pattern in ('aegis-auto-terminal-a@*.service',
                    'aegis-auto-terminal-b@*.service',
                    'aegis-auto@*.service'):
        units = command(['/usr/bin/systemctl','list-units','--all','--plain',
                         '--no-legend','--no-pager',pattern],timeout=5)
        for line in units.splitlines():
            fields = line.split()
            need(fields and re.fullmatch(
                 r'aegis-auto(?:-terminal-[ab])?@[0-9a-f]{64}\.service',fields[0]) and
                 len(fields) >= 4 and fields[2] == 'inactive' and
                 fields[3] == 'dead', 'migration_actor_not_stopped')
    guardian._held_lock(install_fd, guardian.INSTALL_LOCK)
    guardian._held_lock(guard_fd, guardian.GUARD_LOCK)
    return guardian, state


def _migration_site_leaves(source):
    selected = source['selected_manager']
    need(selected in ('NetworkManager.service','systemd-networkd.service'),
         'migration_manager_invalid')
    leaf = '31-aegis-auto-terminal-transition.conf'
    return {
      str(CONFIG):0o600, str(STORE_CONFIG):0o600, str(ACTIVE_HOOK):0o755,
      '/var/lib/aegis-install/client/auto-terminal-configure-intent.json':0o600,
      '/var/lib/aegis-install/client/auto-terminal-configured.json':0o600,
      '/etc/systemd/system/'+selected+'.d/'+leaf:0o644,
      '/etc/systemd/system/aegis-auto-guardian.service.d/'+leaf:0o644,
    }


def _migration_boot_roster(store):
    directory = Path('/boot')/store['boot_store_dir']
    boot = Path('/boot').lstat();site = directory.lstat()
    need(stat.S_ISDIR(boot.st_mode) and stat.S_ISDIR(site.st_mode) and
         boot.st_uid == boot.st_gid == site.st_uid == site.st_gid == 0 and
         stat.S_IMODE(site.st_mode) == 0o700 and
         boot.st_dev == site.st_dev != Path('/').stat().st_dev and
         store['boot_dev'] == f'{os.major(site.st_dev)}:{os.minor(site.st_dev)}',
         'migration_boot_site_changed')
    names = sorted(directory.iterdir(), key=lambda p:p.name)
    need(len(names) <= 128, 'migration_boot_roster_bound')
    result = []
    for path in names:
        need(re.fullmatch(r'terminal-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-[0-9a-f]{32}\.json',
                          path.name), 'migration_boot_member_name')
        raw = held(path, 4096, 0o600)
        row = json.loads(raw, object_pairs_hook=unique)
        need(type(row) is dict and row.get('schema') ==
             'aegis_auto_terminal_boot_v1' and
             path.name == 'terminal-'+row.get('old_boot_id','')+'-'+row.get('nonce','')+'.json' and
             row.get('boot_uuid') == store['boot_uuid'] and
             row.get('boot_dev') == store['boot_dev'] and
             row.get('root_uuid') == store['root_uuid'] and
             row.get('root_dev') == store['root_dev'], 'migration_boot_member_site')
        result.append({'name':path.name,'sha256':digest(raw)})
    return result


def _migration_marker_lineage(source, store):
    transition = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_boot_transition.py')
    raw = held(transition, 1 << 20, 0o500)
    need(digest(raw) == source['transition_sha256'],
         'migration_transition_source_changed')
    namespace = {'__file__':str(transition),
                 '__name__':'aegis_terminal_migration_transition'}
    exec(compile(raw, str(transition), 'exec'), namespace)
    module = types.SimpleNamespace(**namespace)
    module.historical_carriers_closed(store,source)


def _migration_release(root, candidate_sha, package_sha):
    need(type(root) is str and re.fullmatch(
         r'/var/lib/aegis-auto/releases/[A-Za-z0-9-]{16,128}',root) and
         type(candidate_sha) is str and HEX64.fullmatch(candidate_sha) and
         type(package_sha) is str and HEX64.fullmatch(package_sha),
         'migration_release_args')
    release = Path(root)
    need(digest(held(release/'bin/aegis-client', 512 << 20, 0o555)) == candidate_sha,
         'migration_candidate_changed')
    packages = sorted((release/'packages').glob('aegis-client_*.deb'))
    need(len(packages) == 1 and
         digest(held(packages[0], 512 << 20, 0o444)) == package_sha,
         'migration_package_changed')
    return release


_COLD_NATIVE_FIELDS = frozenset({
    'schema','old_boot_id','current_boot_id','old_active_sha256',
    'old_stopped_sha256','successor_intent_sha256','old_install_sha256',
    'old_source_sha256','old_context_sha256','context_state',
    'cold_old_context_sha256','cold_context_state',
    'old_observer_archive_sha256','guardian_rotation_intent_sha256',
    'guardian_rotation_denied_sha256','guardian_rotation_retired_sha256',
    'retained_root','new_candidate_sha256','new_package_sha256',
    'package_state','installed_source_sha256','roster_sha256',
    'deny_policy_sha256','guard30_sha256','selected_manager',
    'manager31_sha256','guardian31_sha256','migration_state',
    'site_state','site_readback_sha256','observer_state',
    'observer_source_sha256','observer_ready_sha256',
    'infrastructure_rows_sha256','infrastructure_qualified',
    'client_actors_absent','jobs_absent','cgroups_empty',
    'stop_intent_absent','cold_intent_sha256',
})


def _cold_retained_self(release):
    """Recheck B's already native-anchored registrar bytes before effects."""
    own = release/'scripts/lib/aegis_auto_terminal_register.py'
    need(Path(__file__).resolve() == own and not own.is_symlink(),
         'cold_registrar_location')
    raw = held(release/'SHA256SUMS',4 << 20,0o444)
    rows={}
    for line in raw.decode('ascii').splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./@-]+)',line)
        need(match is not None and match[2] not in rows,
             'cold_registrar_sums_invalid')
        rows[match[2]]=match[1]
    need(digest(held(own,1 << 20,0o444)) ==
         rows.get('scripts/lib/aegis_auto_terminal_register.py'),
         'cold_registrar_source_changed')
    return digest(raw)


def _cold_native_readback(release, install_fd, guard_fd):
    candidate = release/'bin/aegis-client'
    args=[str(candidate),'auto-verify-cold-retired-successor',
          '--lock-fd',str(install_fd),'--guard-fd',str(guard_fd),
          '--retained-root',str(release)]
    result=subprocess.run(args,capture_output=True,check=False,timeout=90,
                          pass_fds=(install_fd,guard_fd),
                          env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
    need(result.returncode==0 and not result.stderr and
         0<len(result.stdout)<=64 << 10,'cold_native_readback_refused')
    row=json.loads(result.stdout,object_pairs_hook=unique)
    need(type(row) is dict and set(row)==_COLD_NATIVE_FIELDS and
         row['schema']=='aegis_auto_v2_cold_retired_successor_v2' and
         row['retained_root']==str(release) and
         row['current_boot_id']==
             Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
         row['infrastructure_qualified'] is True and
         all(row[key] is True for key in
             ('client_actors_absent','jobs_absent','cgroups_empty',
              'stop_intent_absent')),
         'cold_native_readback_shape')
    return row

_ROLLOVER_ATTEMPT_FIELDS = frozenset({
    'schema','current_boot_id','original_intent_sha256',
    'prior_intent_sha256','barrier_sha256','attempt_intent_sha256',
    'attempt_head_sha256','attempt_dir',
    'prior_pointer_retirement_sha256','no_client_grant'})

def _rollover_barrier_exact(expected_sha):
    """Bind the active or consumed barrier, including their overlap cut."""
    need(type(expected_sha) is str and HEX64.fullmatch(expected_sha),
         'rollover_barrier_sha_shape')
    roster=os.listdir(COLD_RECOVERY)
    need(len(roster)<=512 and
         all(not name.startswith('rollover-barrier-consumed-') or
             name=='rollover-barrier-consumed-'+expected_sha+'.json'
             for name in roster),'rollover_barrier_foreign_consumed')
    names=(COLD_RECOVERY/'rollover-barrier.json',
           COLD_RECOVERY/('rollover-barrier-consumed-'+expected_sha+'.json'))
    bodies=[]
    for path in names:
        if path.exists() or path.is_symlink():
            raw=held(path,8192,0o600)
            need(digest(raw)==expected_sha,'rollover_barrier_sha_mismatch')
            row=json.loads(raw,object_pairs_hook=unique)
            need(raw==_migration_json(row) and type(row) is dict and
                 set(row)=={'schema','original_intent_sha256',
                            'original_boot_id','retained_root',
                            'new_candidate_sha256',
                            'next_bundle_manifest_sha256','next_sums_sha256'} and
                 row['schema']=='aegis_auto_terminal_cold_rollover_barrier_v1',
                 'rollover_barrier_record_invalid')
            bodies.append(raw)
    need(bodies and len(set(bodies))==1,'rollover_barrier_missing_or_conflict')
    return True

def cold_attempt_readback(release_raw, install_fd, guard_fd):
    """Resolve only the native-authenticated current-boot rollover attempt."""
    release=Path(release_raw)
    need(release.is_absolute() and
         str(release)==release_raw and
         re.fullmatch(r'/var/lib/aegis-auto/releases/[A-Za-z0-9-]{16,128}',
                      release_raw) is not None,
         'rollover_release_path')
    candidate=release/'bin/aegis-client'
    command=[str(candidate),'auto-verify-cold-attempt-inherited',
             '--lock-fd',str(install_fd),'--guard-fd',str(guard_fd),
             '--retained-root',release_raw]
    result=subprocess.run(command,capture_output=True,check=False,timeout=90,
                          pass_fds=(install_fd,guard_fd),
                          env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
    need(result.returncode==0 and not result.stderr and
         0<len(result.stdout)<=8192,'rollover_native_readback_refused')
    row=json.loads(result.stdout,object_pairs_hook=unique)
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(type(row) is dict and set(row)==_ROLLOVER_ATTEMPT_FIELDS and
         row['schema']=='aegis_auto_v2_cold_attempt_resolution_v1' and
         row['current_boot_id']==boot and
         row['no_client_grant'] is True and
         all(type(row[key]) is str and HEX64.fullmatch(row[key]) for key in
             ('original_intent_sha256','prior_intent_sha256')) and
         (type(row['barrier_sha256']) is str and
          _rollover_barrier_exact(row['barrier_sha256']) or
          row['barrier_sha256'] is None and
          not (COLD_RECOVERY/'rollover-barrier.json').exists() and
          not (COLD_RECOVERY/'rollover-barrier.json').is_symlink() and
          not any(name.startswith('rollover-barrier-consumed-') for name in
                  os.listdir(COLD_RECOVERY)) and
          digest(held(COLD_RECOVERY/'intent.json',8192,0o600))==
              row['original_intent_sha256']) and
         all(row[key] is None or
             type(row[key]) is str and HEX64.fullmatch(row[key]) for key in
             ('attempt_intent_sha256','attempt_head_sha256',
              'prior_pointer_retirement_sha256')) and
         row['attempt_dir']==str(COLD_RECOVERY/'attempts'/
                 (boot+'-'+row['prior_intent_sha256'])),
         'rollover_native_readback_shape')
    # Native proves the chain and current deny. These same held locks remain
    # open for the caller's subsequent exact publication/readback.
    return row


def _migration_rotation_bound(guardian, guard_fd, release, candidate_sha,
                              old_install_sha):
    intent = guardian._rotation_intent(guard_fd)
    successor = intent['successor']
    need(intent['old_install_sha256'] == old_install_sha and
         successor['kind'] == 'upgrade' and
         successor['next_public_payload_root'] == str(release) and
         successor['next_candidate_binary'] == str(release/'bin/aegis-client') and
         successor['next_candidate_sha256'] == candidate_sha and
         type(successor.get('next_bundle_manifest_sha256')) is str and
         type(successor.get('next_sums_sha256')) is str and
         HEX64.fullmatch(successor['next_bundle_manifest_sha256']) and
         HEX64.fullmatch(successor['next_sums_sha256']),
         'migration_rotation_mismatch')
    manifest_raw = held(release/'bundle.manifest.json',4 << 20,0o444)
    sums_raw = held(release/'SHA256SUMS',4 << 20,0o444)
    need(digest(manifest_raw) == successor['next_bundle_manifest_sha256'] and
         digest(sums_raw) == successor['next_sums_sha256'],
         'migration_next_bundle_anchor_changed')
    manifest = json.loads(manifest_raw, object_pairs_hook=unique)
    need(type(manifest) is dict and
         manifest.get('schema') == 'aegis_release_bundle_manifest_v2' and
         type(manifest.get('files')) is list and
         len(manifest['files']) <= 4096 and
         len(manifest['files']) == len(set(manifest['files'])) and
         'SHA256SUMS' in manifest['files'],
         'migration_next_bundle_manifest')
    sums = {}
    for line in sums_raw.decode('ascii','strict').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./@-]+)',line)
        need(match is not None and match[2] not in sums,
             'migration_next_sums_shape')
        sums[match[2]] = match[1]
    need(set(sums) == set(manifest['files']) - {'SHA256SUMS'},
         'migration_next_sums_roster')
    required = {
      'scripts/lib/aegis_auto_terminal_register.py':0o444,
      'scripts/lib/aegis_auto_terminal_witness.py':0o444,
      'scripts/lib/aegis_auto_terminal_boot_store.py':0o444,
      'scripts/lib/aegis_auto_boot_transition.py':0o444,
      'scripts/lib/aegis_auto_guardian.py':0o444,
      'scripts/lib/aegis_installer_auto_v2.py':0o444,
      'packaging/systemd/aegis-auto-terminal-a@.service':0o444,
      'packaging/systemd/aegis-auto-terminal-b@.service':0o444,
      'packaging/systemd/aegis-auto-terminal-observer.service':0o444,
      'packaging/systemd/aegis-auto-terminal-transition.service':0o444,
      'packaging/systemd/system-shutdown/aegis-auto-terminal-hook':0o444,
    }
    for name,mode in required.items():
        need(name in sums and
             digest(held(release/name,1 << 20,mode)) == sums[name],
             'migration_next_helper_changed')
    return (successor['next_bundle_manifest_sha256'],
            successor['next_sums_sha256'])


def _migration_runtime_archive(pending_raw, old_source_sha):
    pending_sha = digest(pending_raw)
    path = MIGRATION/('observer-runtime-'+pending_sha+'.json')
    record, raw = _migration_record(path,16384)
    need(set(record) == {'schema','pending_sha256','old_source_sha256',
                         'boot_id','ready_hex','ready_sha256','observer_pid',
                         'observer_start_tick','observer_invocation_id',
                         'observer_source_sha256','source_config_sha256',
                         'run_dev','run_ino','members'} and
         record['schema'] == 'aegis_auto_terminal_observer_runtime_v1' and
         record['pending_sha256'] == pending_sha and
         record['old_source_sha256'] == old_source_sha and
         record['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
         type(record['ready_hex']) is str and
         digest(bytes.fromhex(record['ready_hex'])) == record['ready_sha256'] and
         type(record['members']) is dict and
         type(record['observer_pid']) is int and record['observer_pid'] > 1 and
         type(record['observer_start_tick']) is int and
         record['observer_start_tick'] > 0 and
         type(record['observer_invocation_id']) is str and
         re.fullmatch(r'[0-9a-f]{32}',record['observer_invocation_id']) and
         type(record['run_dev']) is int and record['run_dev'] > 0 and
         type(record['run_ino']) is int and record['run_ino'] > 0 and
         set(record['members']) in ({'ready.json','observer.sock'},
                                    {'ready.json','observer.sock',
                                     'activation-'+unit_id(json.loads(pending_raw,object_pairs_hook=unique)['unit'])+'.json'}),
         'migration_observer_archive_changed')
    for name, member in record['members'].items():
        need(type(member) is dict and set(member) == {'stat','hex'} and
             type(member['stat']) is list and len(member['stat']) == 9 and
             all(type(value) is int and value >= 0 for value in member['stat']) and
             (member['hex'] is None if name == 'observer.sock' else
              type(member['hex']) is str and len(member['hex']) <= 8192),
             'migration_observer_archive_member')
    need(record['members']['ready.json']['hex'] == record['ready_hex'],
         'migration_observer_archive_ready')
    ready = json.loads(bytes.fromhex(record['ready_hex']),object_pairs_hook=unique)
    need(type(ready) is dict and
         set(ready) == {'schema','boot','pid1_tick','pid1_private_bus_peer',
                        'pid1_private_bus_ready','job_removed_match_registered',
                        'kernel_connector_ack','observer_pid',
                        'observer_start_tick','observer_invocation_id',
                        'observer_source_sha256','source_config_sha256'} and
         ready['schema'] == 'aegis_auto_terminal_witness_ready_v2' and
         ready['boot'] == record['boot_id'] and
         ready['pid1_private_bus_peer'] == 1 and
         all(ready[key] is True for key in
             ('pid1_private_bus_ready','job_removed_match_registered',
              'kernel_connector_ack')) and
         ready['observer_pid'] == record['observer_pid'] and
         ready['observer_start_tick'] == record['observer_start_tick'] and
         ready['observer_invocation_id'] == record['observer_invocation_id'] and
         ready['observer_source_sha256'] == record['observer_source_sha256'] and
         ready['source_config_sha256'] == record['source_config_sha256'],
         'migration_observer_archive_ready')
    return record,raw


def _migration_observer_group_empty():
    unit = 'aegis-auto-terminal-observer.service'
    facts = command(['/usr/bin/systemctl','show',unit,'-p','ActiveState',
                     '-p','SubState','-p','MainPID','-p','ControlPID',
                     '-p','ControlGroup','--no-pager'],timeout=3)
    rows = dict(line.split('=',1) for line in facts.splitlines())
    need(set(rows) == {'ActiveState','SubState','MainPID','ControlPID','ControlGroup'} and
         rows['ActiveState'] == 'inactive' and rows['SubState'] == 'dead' and
         rows['MainPID'] == rows['ControlPID'] == '0' and
         rows['ControlGroup'] in ('','/system.slice/'+unit),
         'migration_observer_not_stopped')
    group = Path('/sys/fs/cgroup/system.slice')/unit
    need(not group.is_symlink(),'migration_observer_cgroup_changed')
    if group.exists():
        need(group.is_dir() and (group/'cgroup.procs').read_bytes() == b'' and
             b'populated 0\n' in (group/'cgroup.events').read_bytes(),
             'migration_observer_cgroup_live')


def _migration_socket_owned(pid):
    path = os.fsencode(RUN/'observer.sock')
    raw = Path('/proc/net/unix').read_bytes()
    need(len(raw) <= 256 << 10,'migration_unix_roster_bound')
    inodes = set()
    for line in raw.splitlines()[1:]:
        fields = line.split()
        if len(fields) == 8 and fields[7] == path:
            need(fields[6].isascii() and fields[6].isdigit(),
                 'migration_socket_inode')
            inodes.add(fields[6].decode('ascii'))
    need(len(inodes) == 1,'migration_socket_not_unique')
    fds = Path('/proc')/str(pid)/'fd'
    need(any(os.readlink(child) == 'socket:['+next(iter(inodes))+']'
             for child in fds.iterdir()),'migration_socket_not_observer_owned')


def _migration_retire_observer_runtime(pending_raw, old_source_sha):
    pending_sha = digest(pending_raw)
    archive = MIGRATION/('observer-runtime-'+pending_sha+'.json')
    if not archive.exists() and not archive.is_symlink():
        ready = observer_ready()  # Current installed A source and live PID 1.
        need(ready['source_config_sha256'] == old_source_sha,
             'migration_observer_old_source_changed')
        _migration_socket_owned(ready['observer_pid'])
        run = RUN.lstat()
        need(stat.S_ISDIR(run.st_mode) and run.st_uid == run.st_gid == 0 and
             stat.S_IMODE(run.st_mode) == 0o700 and
             run.st_dev == Path('/run').stat().st_dev,
             'migration_observer_run_untrusted')
        names = {p.name for p in RUN.iterdir()}
        unit = json.loads(pending_raw,object_pairs_hook=unique)['unit']
        activation = 'activation-'+unit_id(unit)+'.json'
        need(names in ({'ready.json','observer.sock'},
                       {'ready.json','observer.sock',activation}),
             'migration_observer_run_roster')
        members = {}
        for name in sorted(names):
            path = RUN/name
            before = path.lstat()
            if name == 'observer.sock':
                need(stat.S_ISSOCK(before.st_mode) and before.st_uid == before.st_gid == 0 and
                     stat.S_IMODE(before.st_mode) == 0o600,
                     'migration_observer_socket_changed')
                raw = None
            else:
                raw = held(path,4096,0o600)
                if name == 'ready.json':
                    need(json.loads(raw,object_pairs_hook=unique) == ready,
                         'migration_observer_ready_changed')
                else:
                    row = json.loads(raw,object_pairs_hook=unique)
                    need(type(row) is dict and set(row) == {
                         'schema','boot_id','unit','nonce','stage_path',
                         'stage_dev','stage_ino','terminal_sha256',
                         'installed_generation_sha256','installed_manifest_sha256',
                         'active_generation_sha256','active_report_sha256',
                         'boot_snapshot_sha256','source_sha256'} and
                         row['schema'] == 'aegis_auto_terminal_activation_v1' and
                         row['unit'] == unit and row['boot_id'] == ready['boot'] and
                         row['source_sha256'] == old_source_sha and
                         type(row['stage_path']) is str and
                         Path(row['stage_path']).parent == STAGE_PARENT and
                         '..' not in Path(row['stage_path']).parts and
                         type(row['nonce']) is str and
                         re.fullmatch(r'[0-9a-f]{32}',row['nonce']) and
                         type(row['stage_dev']) is int and row['stage_dev'] > 0 and
                         type(row['stage_ino']) is int and row['stage_ino'] > 0 and
                         all(type(row[key]) is str and HEX64.fullmatch(row[key])
                             for key in ('terminal_sha256',
                              'installed_generation_sha256',
                              'installed_manifest_sha256',
                              'active_generation_sha256','active_report_sha256',
                              'boot_snapshot_sha256')),
                         'migration_observer_activation_changed')
            after = path.lstat()
            keys = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                    'st_size','st_mtime_ns','st_ctime_ns')
            need(all(getattr(before,k)==getattr(after,k) for k in keys),
                 'migration_observer_member_raced')
            members[name] = {'stat':[getattr(before,k) for k in keys],
                             'hex':None if raw is None else raw.hex()}
        ready_raw = held(RUN/'ready.json',4096,0o600)
        record = {'schema':'aegis_auto_terminal_observer_runtime_v1',
                  'pending_sha256':pending_sha,'old_source_sha256':old_source_sha,
                  'boot_id':ready['boot'],'ready_hex':ready_raw.hex(),
                  'ready_sha256':digest(ready_raw),
                  'observer_pid':ready['observer_pid'],
                  'observer_start_tick':ready['observer_start_tick'],
                  'observer_invocation_id':ready['observer_invocation_id'],
                  'observer_source_sha256':ready['observer_source_sha256'],
                  'source_config_sha256':ready['source_config_sha256'],
                  'run_dev':run.st_dev,'run_ino':run.st_ino,'members':members}
        publish(archive,_migration_json(record),0o600)
    record,raw = _migration_runtime_archive(pending_raw,old_source_sha)
    old_source = config()
    need(record['observer_source_sha256'] == old_source['witness_sha256'] and
         record['source_config_sha256'] == old_source_sha,
         'migration_observer_archive_source')
    if RUN.exists() or RUN.is_symlink():
        run = RUN.lstat()
        need(stat.S_ISDIR(run.st_mode) and run.st_uid == run.st_gid == 0 and
             stat.S_IMODE(run.st_mode) == 0o700 and
             (run.st_dev,run.st_ino) == (record['run_dev'],record['run_ino']),
             'migration_observer_run_changed')
        present = {p.name for p in RUN.iterdir()}
        need(present <= set(record['members']),'migration_observer_run_foreign')
        for name in present:
            row = record['members'][name]
            path = RUN/name
            before = path.lstat()
            keys = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                    'st_size','st_mtime_ns','st_ctime_ns')
            need([getattr(before,k) for k in keys] == row['stat'],
                 'migration_observer_member_changed')
            if row['hex'] is not None:
                need(held(path,4096,0o600) == bytes.fromhex(row['hex']),
                     'migration_observer_member_bytes')
    # A retry after archived-but-not-stopped is legal only for the exact A PID.
    facts = command(['/usr/bin/systemctl','show',
                     'aegis-auto-terminal-observer.service','-p','ActiveState',
                     '-p','MainPID','--no-pager'],timeout=3)
    states = dict(line.split('=',1) for line in facts.splitlines())
    need(set(states) == {'ActiveState','MainPID'},
         'migration_observer_state_invalid')
    if states['ActiveState'] == 'active':
        need(states['MainPID'] == str(record['observer_pid']) and
             observer_ready() == json.loads(
                 bytes.fromhex(record['ready_hex']),object_pairs_hook=unique),
             'migration_observer_replaced')
        pidfd = os.pidfd_open(record['observer_pid'],0)
        try:
            client=socket.socket(socket.AF_UNIX,
                                 socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
            client.settimeout(12)
            try:
                client.connect(str(RUN/'observer.sock'))
                request={'op':'retire','boot':record['boot_id'],
                         'unit':json.loads(pending_raw,object_pairs_hook=unique)['unit'],
                         'pending_sha256':pending_sha,
                         'old_source_sha256':old_source_sha}
                client.sendall(json.dumps(request,sort_keys=True,
                                          separators=(',',':')).encode())
                answer=client.recv(4097)
                need(answer == json.dumps({'retiring':True,
                     'pending_sha256':pending_sha},sort_keys=True).encode(),
                     'migration_observer_retire_refused')
            finally:
                client.close()
            poll=select.poll();poll.register(pidfd,select.POLLIN)
            events=poll.poll(5000)
            need(len(events)==1 and events[0][0]==pidfd and
                 events[0][1]&select.POLLIN,
                 'migration_observer_retire_timeout')
        finally:
            os.close(pidfd)
        command(['/usr/bin/systemctl','stop',
                 'aegis-auto-terminal-observer.service'],timeout=5)
    _migration_observer_group_empty()
    old_proc = Path('/proc')/str(record['observer_pid'])
    if old_proc.exists():
        need(old_proc.is_dir() and
             (lambda raw:int(raw[raw.rfind(')')+2:].split()[19]))(
                 (old_proc/'stat').read_text()) != record['observer_start_tick'],
             'migration_observer_old_pid_live')
    if RUN.exists() or RUN.is_symlink():
        dfd = os.open(RUN,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            need((os.fstat(dfd).st_dev,os.fstat(dfd).st_ino) ==
                 (record['run_dev'],record['run_ino']),
                 'migration_observer_run_changed')
            for name in sorted(record['members']):
                if name not in {p.name for p in RUN.iterdir()}:
                    continue
                before = os.stat(name,dir_fd=dfd,follow_symlinks=False)
                keys = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                        'st_size','st_mtime_ns','st_ctime_ns')
                need([getattr(before,k) for k in keys] ==
                     record['members'][name]['stat'],
                     'migration_observer_unlink_raced')
                if record['members'][name]['hex'] is not None:
                    need(held(RUN/name,4096,0o600) ==
                         bytes.fromhex(record['members'][name]['hex']),
                         'migration_observer_unlink_bytes')
                os.unlink(name,dir_fd=dfd)
                os.fsync(dfd)
            need(not tuple(RUN.iterdir()),'migration_observer_run_not_empty')
        finally:
            os.close(dfd)
        RUN.rmdir()
        sync_dir(Path('/run'))
    need(not RUN.exists() and not RUN.is_symlink(),
         'migration_observer_run_retire_failed')
    return digest(raw),record

def _migration_orphan_ready(raw, source_sha, witness_sha, boot):
    ready=json.loads(raw,object_pairs_hook=unique)
    need(type(ready) is dict,'migration_new_orphan_ready_shape')
    live_keys=('observer_pid','observer_start_tick',
               'observer_invocation_id','observer_source_sha256',
               'source_config_sha256')
    need(all(key in ready for key in live_keys),
         'migration_new_orphan_ready_shape')
    live={key:ready[key] for key in live_keys}
    pid1_raw=Path('/proc/1/stat').read_text()
    fields=pid1_raw[pid1_raw.rfind(')')+2:].split()
    need(len(fields)>20,'migration_new_orphan_pid1_stat')
    pid1_tick=int(fields[19])
    _observer_ready_match(ready,live,{'witness_sha256':witness_sha},
                          source_sha,boot,pid1_tick)
    need(type(ready['observer_pid']) is int and ready['observer_pid']>1 and
         type(ready['observer_start_tick']) is int and
         ready['observer_start_tick']>0 and
         type(ready['observer_invocation_id']) is str and
         re.fullmatch(r'[0-9a-f]{32}',ready['observer_invocation_id']),
         'migration_new_orphan_ready_shape')
    prior=Path('/proc')/str(ready['observer_pid'])
    if prior.exists():
        stat_raw=(prior/'stat').read_text()
        need(int(stat_raw[stat_raw.rfind(')')+2:].split()[19]) !=
             ready['observer_start_tick'],
             'migration_new_orphan_old_pid_live')
    return ready


def _migration_new_orphan_record(path, pending_sha, source_sha, witness_sha):
    row,raw = _migration_record(path,16384)
    need(path.name == 'observer-new-orphan-'+pending_sha+'-'+digest(raw)+'.json' and
         set(row) == {'schema','pending_sha256','new_source_sha256',
                      'new_witness_sha256','boot_id','run_dev','run_ino',
                      'unit_state','members'} and
         row['schema'] == 'aegis_auto_terminal_new_observer_orphan_v1' and
         row['pending_sha256'] == pending_sha and
         row['new_source_sha256'] == source_sha and
         row['new_witness_sha256'] == witness_sha and
         row['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
         row['unit_state'] in ('inactive','failed') and
         type(row['run_dev']) is int and row['run_dev'] > 0 and
         type(row['run_ino']) is int and row['run_ino'] > 0 and
         type(row['members']) is dict and
         set(row['members']) <= {'observer.sock','ready.json','ready.json.tmp'},
         'migration_new_orphan_archive_changed')
    for name,member in row['members'].items():
        need(type(member) is dict and set(member) == {'stat','hex'} and
             type(member['stat']) is list and len(member['stat']) == 9 and
             all(type(value) is int and value >= 0 for value in member['stat']) and
             (member['hex'] is None if name == 'observer.sock' else
              type(member['hex']) is str and len(member['hex']) <= 8192),
             'migration_new_orphan_member_invalid')
    if 'ready.json' in row['members']:
        _migration_orphan_ready(
            bytes.fromhex(row['members']['ready.json']['hex']),
            source_sha,witness_sha,row['boot_id'])
    return row,raw


def _migration_new_orphan_roster(pending_sha,source_sha,witness_sha):
    need(type(pending_sha) is str and HEX64.fullmatch(pending_sha),
         'migration_new_orphan_pending')
    names = tuple(MIGRATION.iterdir())
    need(len(names) <= 512,'migration_new_orphan_roster_bound')
    prefix = 'observer-new-orphan-'+pending_sha+'-'
    entries = []
    for path in names:
        if not path.name.startswith(prefix):
            continue
        need(re.fullmatch(r'observer-new-orphan-[0-9a-f]{64}-[0-9a-f]{64}\.json',
                          path.name), 'migration_new_orphan_name')
        row,raw = _migration_new_orphan_record(
            path,pending_sha,source_sha,witness_sha)
        entries.append((digest(raw),row))
    need(len(entries) <= 8,'migration_new_orphan_count')
    return sorted(entries,key=lambda item:item[0])


def _migration_orphan_socket_unbound():
    raw=Path('/proc/net/unix').read_bytes()
    need(len(raw)<=256 << 10,'migration_new_orphan_unix_bound')
    target=os.fsencode(RUN/'observer.sock')
    need(not any(len(fields)==8 and fields[7]==target
                 for fields in (line.split() for line in raw.splitlines()[1:])),
         'migration_new_orphan_socket_live')


def _migration_orphan_bytes(path, name):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);named=path.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
             stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
             0 <= before.st_size <= 4096,'migration_new_orphan_file_metadata')
        raw=os.read(fd,4097);after=os.fstat(fd)
        keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
              'st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw)==before.st_size and
             all(getattr(before,k)==getattr(after,k)==getattr(named,k)
                 for k in keys),'migration_new_orphan_file_changed')
        return raw,before
    finally:os.close(fd)


def _migration_retire_new_orphan(pending_sha,source_sha,witness_sha):
    unit='aegis-auto-terminal-observer.service'
    facts=command(['/usr/bin/systemctl','show',unit,'-p','Id',
                   '-p','LoadState','-p','UnitFileState',
                   '-p','FragmentPath','-p','DropInPaths',
                   '-p','NeedDaemonReload','-p','ActiveState','-p','SubState',
                   '-p','MainPID','-p','ControlPID','-p','ControlGroup',
                   '--no-pager'],timeout=3)
    rows=dict(line.split('=',1) for line in facts.splitlines())
    fragment=Path('/etc/systemd/system')/unit
    need(set(rows)=={'Id','LoadState','UnitFileState',
                     'FragmentPath','DropInPaths','NeedDaemonReload','ActiveState','SubState',
                     'MainPID','ControlPID','ControlGroup'} and
         rows['Id']==unit and rows['LoadState']=='loaded' and
         rows['UnitFileState']=='disabled' and
         rows['FragmentPath']==str(fragment) and
         rows['DropInPaths']=='' and rows['NeedDaemonReload']=='no' and
         digest(held(fragment,4096,0o644))==config()['observer_unit_sha256'] and
         (rows['ActiveState'],rows['SubState']) in
         (('inactive','dead'),('failed','failed')) and
         rows['MainPID']==rows['ControlPID']=='0' and
         rows['ControlGroup'] in ('','/system.slice/'+unit),
         'migration_new_orphan_pid1_not_dead')
    group=Path('/sys/fs/cgroup/system.slice')/unit
    need(not group.is_symlink(),'migration_new_orphan_cgroup_changed')
    if group.exists():
        need(group.is_dir() and (group/'cgroup.procs').read_bytes()==b'' and
             b'populated 0\n' in (group/'cgroup.events').read_bytes(),
             'migration_new_orphan_cgroup_live')
    if not RUN.exists() and not RUN.is_symlink():
        if rows['ActiveState']=='failed':
            command(['/usr/bin/systemctl','reset-failed',unit],timeout=3)
            _migration_observer_group_empty()
        return [entry[0] for entry in _migration_new_orphan_roster(
            pending_sha,source_sha,witness_sha)]
    run=RUN.lstat()
    need(stat.S_ISDIR(run.st_mode) and run.st_uid==run.st_gid==0 and
         stat.S_IMODE(run.st_mode)==0o700 and
         run.st_dev==Path('/run').stat().st_dev,
         'migration_new_orphan_run_untrusted')
    names={path.name for path in RUN.iterdir()}
    need(names <= {'observer.sock','ready.json','ready.json.tmp'},
         'migration_new_orphan_run_roster')
    archive=None
    for digest_value,row in _migration_new_orphan_roster(
            pending_sha,source_sha,witness_sha):
        if (row['run_dev'],row['run_ino'])==(run.st_dev,run.st_ino):
            need(archive is None,'migration_new_orphan_ambiguous')
            archive=(digest_value,row)
    if archive is None:
        members={}
        keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
              'st_size','st_mtime_ns','st_ctime_ns')
        for name in sorted(names):
            path=RUN/name
            if name=='observer.sock':
                _migration_orphan_socket_unbound()
                st=path.lstat()
                need(stat.S_ISSOCK(st.st_mode) and st.st_uid==st.st_gid==0 and
                     stat.S_IMODE(st.st_mode)==0o600,
                     'migration_new_orphan_socket_changed')
                raw=None
            else:
                raw,st=_migration_orphan_bytes(path,name)
                if name=='ready.json':
                    _migration_orphan_ready(raw,source_sha,witness_sha,
                        Path('/proc/sys/kernel/random/boot_id').read_text().strip())
            members[name]={'stat':[getattr(st,k) for k in keys],
                           'hex':None if raw is None else raw.hex()}
        record={'schema':'aegis_auto_terminal_new_observer_orphan_v1',
                'pending_sha256':pending_sha,'new_source_sha256':source_sha,
                'new_witness_sha256':witness_sha,
                'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'run_dev':run.st_dev,'run_ino':run.st_ino,
                'unit_state':rows['ActiveState'],'members':members}
        raw=_migration_json(record);archive_sha=digest(raw)
        publish(MIGRATION/('observer-new-orphan-'+pending_sha+'-'+
                           archive_sha+'.json'),raw,0o600)
        archive=(archive_sha,record)
    archive_sha,record=archive
    present={path.name for path in RUN.iterdir()}
    need(present <= set(record['members']),
         'migration_new_orphan_runtime_changed')
    dfd=os.open(RUN,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        current=os.fstat(dfd)
        need((current.st_dev,current.st_ino)==(record['run_dev'],record['run_ino']),
             'migration_new_orphan_run_changed')
        keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
              'st_size','st_mtime_ns','st_ctime_ns')
        for name in sorted(present):
            if name=='observer.sock':
                _migration_orphan_socket_unbound()
            member=record['members'][name]
            st=os.stat(name,dir_fd=dfd,follow_symlinks=False)
            need([getattr(st,k) for k in keys]==member['stat'],
                 'migration_new_orphan_member_raced')
            if member['hex'] is not None:
                actual,_=_migration_orphan_bytes(RUN/name,name)
                need(actual==bytes.fromhex(member['hex']),
                     'migration_new_orphan_member_bytes')
            os.unlink(name,dir_fd=dfd)
            os.fsync(dfd)
        need(not tuple(RUN.iterdir()),'migration_new_orphan_run_not_empty')
    finally:os.close(dfd)
    RUN.rmdir();sync_dir(Path('/run'))
    need(not RUN.exists() and not RUN.is_symlink(),
         'migration_new_orphan_retirement_failed')
    command(['/usr/bin/systemctl','reset-failed',unit],timeout=3)
    _migration_observer_group_empty()
    return [entry[0] for entry in _migration_new_orphan_roster(
        pending_sha,source_sha,witness_sha)]

def migration_prepare(unit, root, candidate_sha, package_sha, install_fd, guard_fd):
    unit_id(unit)
    old_source = config()
    guardian, _state = _migration_guard(install_fd, guard_fd)
    release = _migration_release(root, candidate_sha, package_sha)
    bundle_sha,sums_sha = _migration_rotation_bound(
        guardian,guard_fd,release,candidate_sha,
        digest(held(INSTALL,1 << 20,0o600)))
    store = json.loads(held(STORE_CONFIG,4096,0o600), object_pairs_hook=unique)
    leaves = {path:{'mode':mode,'hex':held(Path(path),1 << 20,mode).hex()}
              for path,mode in _migration_site_leaves(old_source).items()}
    old_source_sha = digest(bytes.fromhex(leaves[str(CONFIG)]['hex']))
    _migration_marker_lineage(old_source,store)
    markers = _migration_boot_roster(store)
    context = {'schema':'aegis_auto_terminal_migration_context_v1',
               'old_source_sha256':old_source_sha,
               'old_install_sha256':digest(held(INSTALL,1 << 20,0o600)),
               'next_bundle_manifest_sha256':bundle_sha,
               'next_sums_sha256':sums_sha,
               'leaves':leaves, 'markers':markers}
    context_raw = _migration_json(context)
    need(len(context_raw) <= 256 << 10, 'migration_context_oversize')
    directory = _migration_dir()
    context_sha = digest(context_raw)
    prior_head = None
    if MIGRATION_HEAD.exists() or MIGRATION_HEAD.is_symlink():
        head,_ = _migration_record(MIGRATION_HEAD,4096)
        need(set(head) == {'schema','edge_sha256'} and
             head['schema'] == 'aegis_auto_terminal_migration_head_v1' and
             type(head['edge_sha256']) is str and HEX64.fullmatch(head['edge_sha256']),
             'migration_head_invalid')
        prior_head = head['edge_sha256']
    pending = {'schema':'aegis_auto_terminal_migration_pending_v1',
               'old_source_sha256':old_source_sha, 'context_sha256':context_sha,
               'candidate_sha256':candidate_sha,'package_sha256':package_sha,
               'next_bundle_manifest_sha256':bundle_sha,
               'next_sums_sha256':sums_sha,
               'release_root':str(release),'unit':unit,
               'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
               'marker_roster_sha256':digest(_migration_json(markers)),
               'prior_head_sha256':prior_head}
    pending_raw = _migration_json(pending)
    publish(MIGRATION_PENDING,pending_raw,0o600)
    # A crash before context publication retains a typed, source-bound intent.
    # The old installed registrar can replay this exact pending under 9/10
    # before dpkg begins; there is no ownerless archived context leaf.
    publish(directory/('context-'+context_sha+'.json'),context_raw,0o600)
    observer_runtime_sha,_ = _migration_retire_observer_runtime(
        pending_raw,old_source_sha)
    need(type(observer_runtime_sha) is str and HEX64.fullmatch(observer_runtime_sha),
         'migration_observer_archive_invalid')
    need(held(MIGRATION_PENDING,4096,0o600) == pending_raw and
         _migration_boot_roster(store) == markers, 'migration_prepare_readback')
    return {'schema':'aegis_auto_terminal_migration_prepare_v1',
            'status':'prepared','candidate_sha256':candidate_sha,
            'intent_sha256':digest(pending_raw)}


def cold_complete_context(unit, root, candidate_sha, package_sha,
                          install_fd, guard_fd):
    """Complete only the old-boot pending-before-context crash cut.

    This creates no old observer runtime archive and grants no route. Native
    proves the sealed old chain and fresh current-boot deny before and after.
    """
    unit_id(unit)
    release=_migration_release(root,candidate_sha,package_sha)
    sums_sha=_cold_retained_self(release)
    first=_cold_native_readback(release,install_fd,guard_fd)
    pending,pending_raw=_migration_record(MIGRATION_PENDING,4096)
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(set(pending)=={'schema','old_source_sha256','context_sha256',
                       'candidate_sha256','package_sha256','release_root',
                       'unit','boot_id','marker_roster_sha256','prior_head_sha256',
                       'next_bundle_manifest_sha256','next_sums_sha256'} and
         pending['schema']=='aegis_auto_terminal_migration_pending_v1' and
         pending['boot_id']!=boot and pending['unit']==unit and
         pending['release_root']==str(release) and
         pending['candidate_sha256']==candidate_sha and
         pending['package_sha256']==package_sha and
         type(pending['context_sha256']) is str and
         HEX64.fullmatch(pending['context_sha256']) and
         pending['next_sums_sha256']==sums_sha and
         first['migration_state']=='pending_prefix' and
         first['context_state'] in ('missing_reconstructible','present_exact') and
         first['site_state']=='a_exact' and
         first['observer_state']=='absent' and
         first['old_observer_archive_sha256'] is None and
         first['package_state']=='old_exact' and
         first['old_context_sha256']==pending['context_sha256'] and
         first['old_boot_id']==pending['boot_id'] and
         first['old_install_sha256']==
             digest(held(INSTALL,1 << 20,0o600)),
         'cold_context_cut_changed')
    context_path=MIGRATION/('context-'+pending['context_sha256']+'.json')
    if first['context_state']=='present_exact':
        raw=held(context_path,256 << 10,0o600)
        need(digest(raw)==pending['context_sha256'] and
             held(MIGRATION_PENDING,4096,0o600)==pending_raw,
             'cold_context_existing_changed')
        _migration_guard(install_fd,guard_fd)
        second=_cold_native_readback(release,install_fd,guard_fd)
        need(second['context_state']=='present_exact' and
             all(second[key]==first[key] for key in
                 ('old_boot_id','old_active_sha256','old_stopped_sha256',
                  'successor_intent_sha256','old_install_sha256',
                  'old_source_sha256','old_context_sha256',
                  'new_candidate_sha256','new_package_sha256',
                  'deny_policy_sha256','guard30_sha256','selected_manager')),
             'cold_context_existing_postproof_changed')
        return {'schema':'aegis_auto_terminal_cold_context_complete_v1',
                'context_sha256':pending['context_sha256'],
                'pending_sha256':digest(pending_raw),'current_boot_id':boot,
                'status':'already_present','no_client_grant':True}
    old_source=config()
    guardian,_state=_migration_guard(install_fd,guard_fd)
    bundle_sha,verified_sums=_migration_rotation_bound(
        guardian,guard_fd,release,candidate_sha,first['old_install_sha256'])
    need((bundle_sha,verified_sums)==
         (pending['next_bundle_manifest_sha256'],pending['next_sums_sha256']) and
         digest(held(CONFIG,4096,0o600))==
         pending['old_source_sha256']==first['old_source_sha256'],
         'cold_context_source_changed')
    old_store=json.loads(held(STORE_CONFIG,4096,0o600),
                         object_pairs_hook=unique)
    leaves={path:{'mode':mode,'hex':held(Path(path),1 << 20,mode).hex()}
            for path,mode in _migration_site_leaves(old_source).items()}
    _migration_marker_lineage(old_source,old_store)
    markers=_migration_boot_roster(old_store)
    context={'schema':'aegis_auto_terminal_migration_context_v1',
             'old_source_sha256':pending['old_source_sha256'],
             'old_install_sha256':first['old_install_sha256'],
             'next_bundle_manifest_sha256':bundle_sha,
             'next_sums_sha256':verified_sums,
             'leaves':leaves,'markers':markers}
    context_raw=_migration_json(context)
    need(len(context_raw)<=256 << 10 and
         digest(context_raw)==pending['context_sha256'] and
         digest(_migration_json(markers))==pending['marker_roster_sha256'],
         'cold_context_not_reconstructible')
    if MIGRATION_HEAD.exists() or MIGRATION_HEAD.is_symlink():
        head,_=_migration_record(MIGRATION_HEAD,4096)
        need(set(head)=={'schema','edge_sha256'} and
             head['schema']=='aegis_auto_terminal_migration_head_v1' and
             head['edge_sha256']==pending['prior_head_sha256'],
             'cold_context_prior_head_changed')
    else:
        need(pending['prior_head_sha256'] is None,
             'cold_context_prior_head_missing')
    publish(context_path,context_raw,0o600)
    need(held(MIGRATION_PENDING,4096,0o600)==pending_raw and
         held(context_path,256 << 10,0o600)==context_raw,
         'cold_context_publication_changed')
    _migration_guard(install_fd,guard_fd)
    second=_cold_native_readback(release,install_fd,guard_fd)
    need(second['context_state']=='present_exact' and
         second['old_context_sha256']==pending['context_sha256'] and
         second['site_state']=='a_exact' and
         second['observer_state']=='absent' and
         second['package_state']=='old_exact' and
         all(second[key]==first[key] for key in
             ('old_boot_id','old_active_sha256','old_stopped_sha256',
              'successor_intent_sha256','old_install_sha256',
              'old_source_sha256','new_candidate_sha256','new_package_sha256',
              'deny_policy_sha256','guard30_sha256','selected_manager')),
         'cold_context_postproof_changed')
    return {'schema':'aegis_auto_terminal_cold_context_complete_v1',
            'context_sha256':pending['context_sha256'],
            'pending_sha256':digest(pending_raw),'current_boot_id':boot,
            'status':'published','no_client_grant':True}


def _cold_old_context_bytes(root, install_fd, guard_fd):
    """Compute exact A site context while A is still installed and intact."""
    release=Path(root)
    _cold_retained_self(release)
    first=_cold_native_readback(release,install_fd,guard_fd)
    need(first['migration_state']=='preparation_absent' and
         first['context_state']=='absent_not_prepared' and
         first['cold_context_state'] in
             ('absent_not_prepared','missing_reconstructible') and
         first['site_state']=='a_exact' and
         first['observer_state']=='absent' and
         first['package_state']=='old_exact' and
         first['old_context_sha256'] is None and
         first['old_observer_archive_sha256'] is None,
         'cold_old_context_not_reconstructible')
    old_source=config()
    guardian,_state=_migration_guard(install_fd,guard_fd)
    old_install=held(INSTALL,1 << 20,0o600)
    need(digest(old_install)==first['old_install_sha256'] and
         digest(held(CONFIG,4096,0o600))==first['old_source_sha256'],
         'cold_old_site_changed')
    # Normal _migration_rotation_bound calls guardian._rotation_intent(),
    # which requires the OLD boot to be current. The native cold verifier
    # authenticates this archived rotation; bind its held bytes here without
    # importing the same-boot predicate.
    rotation_raw=held(guardian.ROTATION_INTENT,1 << 20,0o600)
    rotation=json.loads(rotation_raw,object_pairs_hook=unique)
    successor=rotation.get('successor')
    need(digest(rotation_raw)==first['guardian_rotation_intent_sha256'] and
         rotation.get('schema')=='aegis_auto_guard_rotation_intent_v1' and
         rotation.get('boot_id')==first['old_boot_id'] and
         rotation.get('old_install_sha256')==first['old_install_sha256'] and
         type(successor) is dict and successor.get('kind')=='upgrade' and
         successor.get('intent_sha256')==first['successor_intent_sha256'] and
         successor.get('next_public_payload_root')==str(release) and
         successor.get('next_candidate_sha256')==first['new_candidate_sha256'],
         'cold_old_rotation_changed')
    bundle_sha=successor.get('next_bundle_manifest_sha256')
    sums_sha=successor.get('next_sums_sha256')
    need(type(bundle_sha) is str and HEX64.fullmatch(bundle_sha) and
         type(sums_sha) is str and HEX64.fullmatch(sums_sha),
         'cold_old_rotation_anchors_missing')
    store=json.loads(held(STORE_CONFIG,4096,0o600),
                     object_pairs_hook=unique)
    leaves={path:{'mode':mode,'hex':held(Path(path),1 << 20,mode).hex()}
            for path,mode in _migration_site_leaves(old_source).items()}
    _migration_marker_lineage(old_source,store)
    markers=_migration_boot_roster(store)
    context={
       'schema':'aegis_auto_terminal_cold_old_context_v1',
       'old_boot_id':first['old_boot_id'],
       'current_boot_id':first['current_boot_id'],
       'old_active_sha256':first['old_active_sha256'],
       'old_stopped_sha256':first['old_stopped_sha256'],
       'successor_intent_sha256':first['successor_intent_sha256'],
       'guardian_rotation_intent_sha256':first['guardian_rotation_intent_sha256'],
       'guardian_rotation_denied_sha256':first['guardian_rotation_denied_sha256'],
       'guardian_rotation_retired_sha256':first['guardian_rotation_retired_sha256'],
       'old_install_sha256':first['old_install_sha256'],
       'old_source_sha256':first['old_source_sha256'],
       'next_bundle_manifest_sha256':bundle_sha,
       'next_sums_sha256':sums_sha,
       'selected_manager':first['selected_manager'],
       'leaves':leaves,'markers':markers,
    }
    raw=_migration_json(context)
    need(len(raw)<=256 << 10 and
         bundle_sha==digest(held(release/'bundle.manifest.json',4 << 20,0o444)) and
         sums_sha==digest(held(release/'SHA256SUMS',4 << 20,0o444)),
         'cold_old_context_anchor_changed')
    _migration_guard(install_fd,guard_fd)
    second=_cold_native_readback(release,install_fd,guard_fd)
    need(all(second[key]==first[key] for key in
             ('old_boot_id','current_boot_id','old_active_sha256',
              'old_stopped_sha256','successor_intent_sha256',
              'old_install_sha256','old_source_sha256','new_candidate_sha256',
              'new_package_sha256','deny_policy_sha256','guard30_sha256',
              'selected_manager','site_state','package_state')) and
         held(CONFIG,4096,0o600)==bytes.fromhex(leaves[str(CONFIG)]['hex']),
         'cold_old_context_recheck_changed')
    return raw,first


def cold_old_context_candidate(root, install_fd, guard_fd):
    raw,first=_cold_old_context_bytes(root,install_fd,guard_fd)
    return {'schema':'aegis_auto_terminal_cold_old_context_candidate_v1',
            'context_sha256':digest(raw),
            'successor_intent_sha256':first['successor_intent_sha256'],
            'current_boot_id':first['current_boot_id'],
            'no_client_grant':True}


def cold_old_context_publish(root, expected_sha, install_fd, guard_fd):
    need(type(expected_sha) is str and HEX64.fullmatch(expected_sha),
         'cold_old_context_sha_invalid')
    raw,first=_cold_old_context_bytes(root,install_fd,guard_fd)
    need(digest(raw)==expected_sha and
         first['cold_context_state']=='missing_reconstructible' and
         first['cold_old_context_sha256']==expected_sha,
         'cold_old_context_intent_mismatch')
    phase_root,_head=_cold_site_current_phase_root()
    intent_raw=held(phase_root/'intent.json',8192,0o600)
    intent=json.loads(intent_raw,object_pairs_hook=unique)
    need(intent.get('schema')=='aegis_auto_terminal_cold_intent_v1' and
         intent.get('old_context_sha256')==expected_sha and
         intent.get('successor_intent_sha256')==
             first['successor_intent_sha256'] and
         intent.get('current_boot_id')==first['current_boot_id'] and
         intent_raw==_migration_json(intent),
         'cold_old_context_barrier_changed')
    path=COLD_RECOVERY/('cold-old-context-'+expected_sha+'.json')
    publish(path,raw,0o600)
    need(held(path,256 << 10,0o600)==raw and
         held(phase_root/'intent.json',8192,0o600)==intent_raw,
         'cold_old_context_publication_changed')
    second=_cold_native_readback(Path(root),install_fd,guard_fd)
    need(second['cold_context_state']=='present_exact' and
         second['cold_old_context_sha256']==expected_sha and
         second['old_context_sha256'] is None and
         second['site_state']=='a_exact' and
         second['observer_state']=='absent',
         'cold_old_context_postproof_changed')
    return {'schema':'aegis_auto_terminal_cold_old_context_published_v1',
            'context_sha256':expected_sha,
            'current_boot_id':second['current_boot_id'],
            'no_client_grant':True}


def _cold_optional_leaf(path, mode):
    try:
        return held(Path(path),1 << 20,mode)
    except FileNotFoundError:
        need(not Path(path).is_symlink(),'cold_site_foreign_symlink')
        return None


def _cold_site_expected_old(old_context, release):
    if old_context is None:
        old_source=config()  # Only the intact, still installed A site.
        old_store=json.loads(held(STORE_CONFIG,4096,0o600),
                             object_pairs_hook=unique)
        _migration_marker_lineage(old_source,old_store)
        _migration_boot_roster(old_store)
        return {path:held(Path(path),1 << 20,mode)
                for path,mode in _migration_site_leaves(old_source).items()},old_source
    need(type(old_context) is dict and
         old_context.get('schema') in (
             'aegis_auto_terminal_migration_context_v1',
             'aegis_auto_terminal_cold_old_context_v1') and
         type(old_context.get('leaves')) is dict and
         type(old_context.get('markers')) is list,
         'cold_old_context_invalid')
    leaves=old_context['leaves']
    source_leaf=leaves.get(str(CONFIG))
    need(type(source_leaf) is dict and set(source_leaf)=={'mode','hex'} and
         source_leaf['mode']==0o600 and type(source_leaf['hex']) is str,
         'cold_old_source_leaf_invalid')
    old_source=json.loads(bytes.fromhex(source_leaf['hex']),
                          object_pairs_hook=unique)
    expected_modes=_migration_site_leaves(old_source)
    need(set(leaves)==set(expected_modes) and
         all(type(row) is dict and set(row)=={'mode','hex'} and
             row['mode']==expected_modes[path] and
             type(row['hex']) is str and len(row['hex'])<=2 << 20
             for path,row in leaves.items()),
         'cold_old_leaf_roster_invalid')
    old_store=json.loads(bytes.fromhex(leaves[str(STORE_CONFIG)]['hex']),
                         object_pairs_hook=unique)
    need(_migration_boot_roster(old_store)==old_context['markers'],
         'cold_old_boot_roster_changed')
    return {path:bytes.fromhex(row['hex']) for path,row in leaves.items()},old_source


def _cold_site_current_phase_root():
    """Choose a path hint; the native caller binds the exact current head."""
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot),
         'cold_site_boot_invalid')
    try:top=COLD_RECOVERY.lstat()
    except FileNotFoundError:return COLD_RECOVERY,None
    need(stat.S_ISDIR(top.st_mode) and top.st_uid==top.st_gid==0 and
         stat.S_IMODE(top.st_mode)==0o700,
         'cold_site_root_untrusted')
    names=os.listdir(COLD_RECOVERY)
    prefix='attempt-head-'+boot+'-'
    heads=[name for name in names if name.startswith(prefix)]
    need(len(names)<=512 and len(heads)<=1 and
         all(re.fullmatch(r'attempt-head-'+boot+r'-[0-9a-f]{64}\.json',name)
             for name in heads),'cold_site_current_head_ambiguous')
    if not heads:return COLD_RECOVERY,None
    raw=held(COLD_RECOVERY/heads[0],8192,0o600)
    head=json.loads(raw,object_pairs_hook=unique)
    need(raw==_migration_json(head) and type(head) is dict and
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
         'cold_site_current_head_invalid')
    phase=COLD_RECOVERY/'attempts'/(
        boot+'-'+head['prior_intent_sha256'])
    need(head['attempt_dir']==str(phase),'cold_site_attempt_path_changed')
    info=phase.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and
         stat.S_IMODE(info.st_mode)==0o700 and
         info.st_dev==COLD_RECOVERY.lstat().st_dev,
         'cold_site_attempt_dir_untrusted')
    return phase,head


def _cold_site_intent_raw():
    phase,head=_cold_site_current_phase_root()
    active=_cold_optional_leaf(phase/'intent.json',0o600)
    ready_raw=_cold_optional_leaf(phase/'transition-ready.json',0o600)
    if ready_raw is None:
        if head is not None:
            need(active is not None and
                 digest(active)==head['attempt_intent_sha256'],
                 'cold_site_attempt_intent_changed')
        return active
    ready=json.loads(ready_raw,object_pairs_hook=unique)
    if head is not None:
        need(ready_raw==_migration_json(ready) and type(ready) is dict and
             set(ready)=={'schema','current_boot_id',
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
             ready['schema']==
                 'aegis_auto_terminal_cold_rollover_transition_ready_v1' and
             ready['current_boot_id']==head['current_boot_id'] and
             ready['attempt_head_sha256']==digest(_migration_json(head)) and
             ready['attempt_intent_sha256']==
                 head['attempt_intent_sha256'] and
             ready['consumed_attempt_intent_leaf']==
                 'intent-consumed-'+head['attempt_intent_sha256']+'.json',
             'cold_site_rollover_ready_changed')
        consumed=_cold_optional_leaf(
            phase/ready['consumed_attempt_intent_leaf'],0o600)
        need((active is None)!=(consumed is None),
             'cold_site_rollover_active_consumed_ambiguous')
        chosen=active if active is not None else consumed
        need(digest(chosen)==head['attempt_intent_sha256'],
             'cold_site_rollover_intent_digest_changed')
        return chosen
    need(ready_raw==_migration_json(ready) and type(ready) is dict and
         set(ready)=={'schema','current_boot_id','intent_sha256',
                      'cold_prebind_sha256','source_config_sha256',
                      'observer_ready_sha256','site_readback_sha256',
                      'deny_policy_sha256','consumed_intent_leaf',
                      'consumed_pending_leaf'} and
         ready['schema']=='aegis_auto_terminal_cold_transition_ready_v1' and
         ready['current_boot_id']==
             Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
         all(type(ready[key]) is str and HEX64.fullmatch(ready[key])
             for key in ('intent_sha256','cold_prebind_sha256',
                         'source_config_sha256','observer_ready_sha256',
                         'site_readback_sha256','deny_policy_sha256')) and
         ready['consumed_intent_leaf']==
             'intent-consumed-'+ready['intent_sha256']+'.json' and
         (ready['consumed_pending_leaf'] is None or
          type(ready['consumed_pending_leaf']) is str and
          re.fullmatch(r'pending-consumed-[0-9a-f]{64}\.json',
                       ready['consumed_pending_leaf'])),
         'cold_transition_ready_changed')
    consumed=_cold_optional_leaf(phase/ready['consumed_intent_leaf'],
                                 0o600)
    need((active is None) != (consumed is None),
         'cold_intent_active_consumed_ambiguous')
    chosen=active if active is not None else consumed
    need(digest(chosen)==ready['intent_sha256'],
         'cold_intent_ready_digest_changed')
    return chosen


def _cold_site_classify(actual,old_values,b_values,old_order,new_order):
    need(set(actual)==set(old_values)==set(old_order)==set(new_order),
         'cold_site_roster_changed')
    if all(actual[path]==old_values[path] for path in actual):
        return 'a_exact'
    if any(all(actual[path] is None for path in old_order[:cut]) and
           all(actual[path]==old_values[path] for path in old_order[cut:])
           for cut in range(1,len(old_order))):
        return 'a_retiring_prefix'
    if all(value is None for value in actual.values()):
        return 'absent'
    if b_values is not None and all(actual[path]==b_values[path]
                                    for path in actual):
        return 'b_complete'
    if b_values is not None and any(
            all(actual[path]==b_values[path] for path in new_order[:cut]) and
            all(actual[path] is None for path in new_order[cut:])
            for cut in range(1,len(new_order))):
        return 'b_prefix'
    raise Refused('cold_site_foreign_or_mixed_prefix')


def _cold_site_lock(fd,path):
    need(type(fd) is int and 3<=fd<=1024,'cold_site_lock_fd')
    named=path.lstat(); held_fd=os.fstat(fd)
    need(stat.S_ISREG(held_fd.st_mode) and held_fd.st_uid==held_fd.st_gid==0 and
         stat.S_IMODE(held_fd.st_mode)==0o600 and held_fd.st_nlink==1 and
         (held_fd.st_dev,held_fd.st_ino)==(named.st_dev,named.st_ino),
         'cold_site_lock_identity')
    info=Path(f'/proc/self/fdinfo/{fd}').read_text(encoding='ascii')
    rows=[line.split() for line in info.splitlines() if line.startswith('lock:')]
    need(len(info)<=4096 and len(rows)==1 and len(rows[0])==9 and
         rows[0][0]=='lock:' and
         re.fullmatch(r'[1-9][0-9]*:',rows[0][1]) and
         rows[0][2:5]==['FLOCK','ADVISORY','WRITE'] and
         re.fullmatch(r'[0-9]+',rows[0][5]) and
         rows[0][7:]==['0','EOF'],'cold_site_lock_not_exclusive')
    dev=re.fullmatch(r'([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)',rows[0][6])
    need(dev is not None and
         int(dev[1],16)==os.major(held_fd.st_dev) and
         int(dev[2],16)==os.minor(held_fd.st_dev) and
         int(dev[3])==held_fd.st_ino,'cold_site_lock_inode_changed')


_COLD_STALE_INTENT_FIELDS=frozenset({
    'schema','old_boot_id','current_boot_id','old_active_sha256',
    'old_stopped_sha256','successor_intent_sha256','old_install_sha256',
    'old_source_sha256','guardian_rotation_intent_sha256',
    'guardian_rotation_denied_sha256','guardian_rotation_retired_sha256',
    'retained_root','new_candidate_sha256','new_package_sha256',
    'selected_manager','manager31_sha256','guard30_sha256',
    'old_context_sha256','deny_policy_sha256',
    'initial_denied_proof_sha256','initial_infrastructure_rows_sha256',
    'next_bundle_manifest_sha256','next_sums_sha256'})

def _cold_site_stale_intent_raw(prior_sha,release):
    """Resolve one prior-boot intent by content, never by a caller path."""
    need(type(prior_sha) is str and HEX64.fullmatch(prior_sha),
         'cold_stale_intent_sha_invalid')
    candidates=(COLD_RECOVERY/'intent.json',
                COLD_RECOVERY/('intent-consumed-'+prior_sha+'.json'))
    matches=[]
    def consider(path):
        raw=_cold_optional_leaf(path,0o600)
        if raw is None or digest(raw)!=prior_sha:return
        row=json.loads(raw,object_pairs_hook=unique)
        need(raw==_migration_json(row) and type(row) is dict and
             set(row)==_COLD_STALE_INTENT_FIELDS and
             row['schema']=='aegis_auto_terminal_cold_intent_v1' and
             row['retained_root']==str(release) and
             row['current_boot_id']!=
                 Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'cold_stale_intent_changed')
        matches.append((row,raw,path.parent))
    for path in candidates:consider(path)
    attempts=COLD_RECOVERY/'attempts'
    if attempts.exists() or attempts.is_symlink():
        info=attempts.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and
             stat.S_IMODE(info.st_mode)==0o700,
             'cold_stale_attempts_untrusted')
        names=os.listdir(attempts)
        need(len(names)<=32 and all(re.fullmatch(
             r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-[0-9a-f]{64}',
             name) for name in names),'cold_stale_attempt_names')
        for name in names:
            child=attempts/name
            info=child.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and
                 stat.S_IMODE(info.st_mode)==0o700 and
                 info.st_dev==attempts.lstat().st_dev,
                 'cold_stale_attempt_untrusted')
            consider(child/'intent.json')
            consider(child/('intent-consumed-'+prior_sha+'.json'))
    need(len(matches)==1,'cold_stale_intent_ambiguous')
    return matches[0]

def _cold_stale_migration_state(release,old_context_sha,intent,cold_root):
    """Classify only the exact B-bound ordinary migration prefix."""
    pending_raw=_cold_optional_leaf(MIGRATION_PENDING,0o600)
    if pending_raw is None:
        ready_raw=_cold_optional_leaf(cold_root/'transition-ready.json',0o600)
        if ready_raw is not None:
            ready=json.loads(ready_raw,object_pairs_hook=unique)
            need(ready_raw==_migration_json(ready) and type(ready) is dict and
                 ready.get('current_boot_id')==intent['current_boot_id'],
                 'cold_stale_ready_noncanonical')
            if cold_root==COLD_RECOVERY:
                need(set(ready)=={
                     'schema','current_boot_id','intent_sha256',
                     'cold_prebind_sha256','source_config_sha256',
                     'observer_ready_sha256','site_readback_sha256',
                     'deny_policy_sha256','consumed_intent_leaf',
                     'consumed_pending_leaf'} and
                     ready['schema']==
                         'aegis_auto_terminal_cold_transition_ready_v1' and
                     ready['intent_sha256']==digest(_migration_json(intent)),
                     'cold_stale_ready_invalid')
            else:
                ready_keys={
                    'schema','current_boot_id','original_intent_sha256',
                    'prior_intent_sha256','attempt_head_sha256',
                    'attempt_intent_sha256','barrier_sha256',
                    'cold_prebind_sha256','source_config_sha256',
                    'observer_ready_sha256','site_readback_sha256',
                    'deny_policy_sha256','phase02_sha256','phase03_sha256',
                    'phase04_sha256','native_transition_sha256',
                    'consumed_original_intent_leaf',
                    'consumed_attempt_intent_leaf',
                    'consumed_pending_leaf',
                    'consumed_rollover_barrier_leaf'}
                need(set(ready)==ready_keys and
                     ready['schema']==
                         'aegis_auto_terminal_cold_rollover_transition_ready_v1' and
                     ready['attempt_intent_sha256']==
                         digest(_migration_json(intent)) and
                     ready['consumed_attempt_intent_leaf']==
                         'intent-consumed-'+ready['attempt_intent_sha256']+'.json' and
                     ready['consumed_original_intent_leaf']==
                         'intent-consumed-'+ready['original_intent_sha256']+'.json' and
                     ready['consumed_rollover_barrier_leaf']==
                         'rollover-barrier-consumed-'+ready['barrier_sha256']+'.json' and
                     all(type(ready[key]) is str and HEX64.fullmatch(ready[key])
                         for key in (
                         'original_intent_sha256','prior_intent_sha256',
                         'attempt_head_sha256','attempt_intent_sha256',
                         'barrier_sha256','cold_prebind_sha256',
                         'source_config_sha256','observer_ready_sha256',
                         'site_readback_sha256','deny_policy_sha256',
                         'phase02_sha256','phase03_sha256','phase04_sha256',
                         'native_transition_sha256')),
                     'cold_stale_rollover_ready_invalid')
            consumed=ready['consumed_pending_leaf']
            if consumed is not None:
                need(type(consumed) is str and re.fullmatch(
                     r'pending-consumed-[0-9a-f]{64}\.json',consumed),
                     'cold_stale_pending_leaf_invalid')
                pending_raw=held(cold_root/consumed,4096,0o600)
                need(digest(pending_raw)==consumed[17:-5],
                     'cold_stale_consumed_pending_changed')
    candidate_sha=digest(held(release/'bin/aegis-client',512 << 20,0o555))
    if pending_raw is not None:
        pending=json.loads(pending_raw,object_pairs_hook=unique)
        need(pending_raw==_migration_json(pending) and
             set(pending)=={'schema','old_source_sha256','context_sha256',
               'candidate_sha256','package_sha256',
               'next_bundle_manifest_sha256','next_sums_sha256',
               'release_root','unit','boot_id','marker_roster_sha256',
               'prior_head_sha256'} and
             pending['schema']=='aegis_auto_terminal_migration_pending_v1' and
             old_context_sha is not None and
             pending['context_sha256']==old_context_sha and
             pending['old_source_sha256']==intent['old_source_sha256'] and
             pending['candidate_sha256']==candidate_sha and
             pending['package_sha256']==intent['new_package_sha256'] and
             pending['release_root']==str(release) and
             pending['next_bundle_manifest_sha256']==
                 intent['next_bundle_manifest_sha256'] and
             pending['next_sums_sha256']==intent['next_sums_sha256'],
             'cold_stale_pending_changed')
        return 'pending_prefix'
    head_raw=_cold_optional_leaf(MIGRATION_HEAD,0o600)
    if head_raw is not None:
        head=json.loads(head_raw,object_pairs_hook=unique)
        need(head_raw==_migration_json(head) and
             set(head)=={'schema','edge_sha256'} and
             head['schema']=='aegis_auto_terminal_migration_head_v1' and
             type(head['edge_sha256']) is str and
             HEX64.fullmatch(head['edge_sha256']),
             'cold_stale_head_changed')
        edge_raw=held(MIGRATION/('edge-'+head['edge_sha256']+'.json'),8192,0o600)
        edge=json.loads(edge_raw,object_pairs_hook=unique)
        need(edge_raw==_migration_json(edge) and
             digest(edge_raw)==head['edge_sha256'] and
             edge.get('schema')=='aegis_auto_terminal_migration_edge_v1',
             'cold_stale_edge_changed')
        if (edge.get('candidate_sha256')==candidate_sha and
            edge.get('old_source_sha256')==intent['old_source_sha256'] and
            edge.get('package_sha256')==intent['new_package_sha256'] and
            edge.get('next_bundle_manifest_sha256')==
                intent['next_bundle_manifest_sha256'] and
            edge.get('next_sums_sha256')==intent['next_sums_sha256']):
            need(old_context_sha is not None and
                 edge.get('old_context_sha256')==old_context_sha,
                 'cold_stale_edge_mismatch')
            return 'completed_edge'
    need(old_context_sha is None,'cold_stale_context_without_migration')
    return 'preparation_absent'

def cold_site_readback(install_fd,guard_fd,root,old_context_arg,
                       stale_prior_sha=None):
    """Read-only A/B site prefix classifier under native-held lock OFDs."""
    need(type(install_fd) is int and type(guard_fd) is int and
         3<=install_fd<=1024 and 3<=guard_fd<=1024 and
         install_fd!=guard_fd and
         re.fullmatch(r'/var/lib/aegis-auto/releases/[A-Za-z0-9-]{16,128}',root),
         'cold_site_args')
    release=Path(root)
    sums_sha=_cold_retained_self(release)
    bundle_sha=digest(held(release/'bundle.manifest.json',4 << 20,0o444))
    _cold_site_lock(install_fd,Path('/run/aegis-auto-install.lock'))
    _cold_site_lock(guard_fd,Path('/var/lib/aegis-install/client/device-guard.conf.lock'))
    need(old_context_arg=='none' or HEX64.fullmatch(old_context_arg),
         'cold_site_context_arg')
    old_context_sha=None if old_context_arg=='none' else old_context_arg
    context_state='absent_not_prepared'
    old_context=None
    if old_context_sha is not None:
        context_path=MIGRATION/('context-'+old_context_sha+'.json')
        raw=_cold_optional_leaf(context_path,0o600)
        if raw is None:
            context_state='missing_reconstructible'
        else:
            need(digest(raw)==old_context_sha and
                 raw==_migration_json(json.loads(raw,object_pairs_hook=unique)),
                 'cold_site_context_changed')
            old_context=json.loads(raw,object_pairs_hook=unique)
            context_state='present_exact'
    cold_context_sha=None
    cold_context_state='absent_not_prepared'
    stale_intent=None
    cold_root=COLD_RECOVERY
    if stale_prior_sha is None:
        cold_root,_head=_cold_site_current_phase_root()
        intent_raw=_cold_site_intent_raw()
    else:
        stale_intent,intent_raw,cold_root=_cold_site_stale_intent_raw(
            stale_prior_sha,release)
    if intent_raw is not None:
        intent=json.loads(intent_raw,object_pairs_hook=unique)
        need(intent_raw==_migration_json(intent) and
             intent.get('schema')=='aegis_auto_terminal_cold_intent_v1' and
             (intent.get('current_boot_id')==
                 Path('/proc/sys/kernel/random/boot_id').read_text().strip()
              if stale_prior_sha is None else
               digest(intent_raw)==stale_prior_sha and
               intent.get('current_boot_id')==
                   stale_intent['current_boot_id']) and
             intent.get('retained_root')==str(release),
             'cold_site_intent_changed')
        cold_context_sha=intent.get('old_context_sha256')
        need(cold_context_sha is None or
             type(cold_context_sha) is str and HEX64.fullmatch(cold_context_sha),
             'cold_site_old_context_invalid')
        if cold_context_sha is not None:
            cold_context_path=COLD_RECOVERY/(
                'cold-old-context-'+cold_context_sha+'.json')
            raw=_cold_optional_leaf(cold_context_path,0o600)
            if raw is None:
                cold_context_state='missing_reconstructible'
            else:
                need(digest(raw)==cold_context_sha and
                     raw==_migration_json(json.loads(raw,object_pairs_hook=unique)),
                     'cold_site_cold_context_changed')
                need(old_context is None and old_context_sha is None,
                     'cold_site_dual_context')
                old_context=json.loads(raw,object_pairs_hook=unique)
                cold_context_state='present_exact'
    old_values,old_source=_cold_site_expected_old(old_context,release)
    selected=old_source['selected_manager']
    leaf_modes=_migration_site_leaves(old_source)
    actual={path:_cold_optional_leaf(path,mode)
            for path,mode in leaf_modes.items()}
    need(set(actual)==set(old_values),'cold_site_leaf_roster_changed')
    b_values=None
    install_raw=_cold_optional_leaf(INSTALL,0o600)
    installed=(json.loads(install_raw,object_pairs_hook=unique)
               if install_raw is not None else None)
    b_candidate=digest(held(release/'bin/aegis-client',512 << 20,0o555))
    if type(installed) is dict and installed.get('worker_sha256')==b_candidate:
        try:
            _installed,helper,staged,store,source,transition,b_manager,fields = \
                _site_plan()
        except (Refused,FileNotFoundError):
            # An interrupted dpkg may have B INSTALL but only an A/absent
            # site. The exact A/absent classifier below still refuses every
            # foreign or mixed dynamic leaf; native checks package progress.
            b_manager=None
        if b_manager is not None:
            need(b_manager==selected,'cold_site_manager_changed')
            enc=lambda value:_migration_json(value)
            b_values={
          str(CONFIG):enc(source),str(STORE_CONFIG):enc(store),
          str(ACTIVE_HOOK):staged,
          '/var/lib/aegis-install/client/auto-terminal-configure-intent.json':
              enc({'schema':'aegis_auto_terminal_configure_intent_v1',**fields}),
          '/var/lib/aegis-install/client/auto-terminal-configured.json':
              enc({'schema':'aegis_auto_terminal_configured_v1',**fields}),
          '/etc/systemd/system/'+selected+'.d/31-aegis-auto-terminal-transition.conf':
              transition,
          '/etc/systemd/system/aegis-auto-guardian.service.d/31-aegis-auto-terminal-transition.conf':
              transition,
            }
            need(set(b_values)==set(actual),'cold_site_new_roster_changed')
    old_order=sorted(old_values)
    new_order=[
      '/var/lib/aegis-install/client/auto-terminal-configure-intent.json',
      str(ACTIVE_HOOK),str(STORE_CONFIG),str(CONFIG),
      '/etc/systemd/system/'+selected+'.d/31-aegis-auto-terminal-transition.conf',
      '/etc/systemd/system/aegis-auto-guardian.service.d/31-aegis-auto-terminal-transition.conf',
      '/var/lib/aegis-install/client/auto-terminal-configured.json',
    ]
    need(set(new_order)==set(actual),'cold_site_order_invalid')
    state=_cold_site_classify(actual,old_values,b_values,old_order,new_order)
    config_intent_path=cold_root/'cold-config-intent.json'
    config_intent_raw=_cold_optional_leaf(config_intent_path,0o600)
    if (config_intent_raw is not None or
        cold_context_sha is not None and state in
            ('a_retiring_prefix','absent','b_prefix','b_complete')):
        need(config_intent_raw is not None,'cold_config_intent_missing')
        raw=config_intent_raw
        row=json.loads(raw,object_pairs_hook=unique)
        need(raw==_migration_json(row) and set(row)=={
             'schema','current_boot_id','intent_sha256','cold_prebind_sha256',
             'old_context_sha256','new_install_sha256','source_config_sha256',
             'store_config_sha256','active_hook_sha256','manager31_sha256',
             'guardian31_sha256','selected_manager'} and
             row['schema']=='aegis_auto_terminal_cold_config_intent_v1' and
             row['current_boot_id']==
                 (Path('/proc/sys/kernel/random/boot_id').read_text().strip()
                  if stale_prior_sha is None else intent['current_boot_id']) and
             row['intent_sha256']==digest(intent_raw) and
             row['old_context_sha256']==
                 (old_context_sha if old_context_sha is not None else
                  cold_context_sha) and
             row['selected_manager']==selected and
             b_values is not None and
             row['new_install_sha256']==digest(held(INSTALL,1 << 20,0o600)) and
             row['source_config_sha256']==digest(b_values[str(CONFIG)]) and
             row['store_config_sha256']==digest(b_values[str(STORE_CONFIG)]) and
             row['active_hook_sha256']==digest(b_values[str(ACTIVE_HOOK)]) and
             row['manager31_sha256']==row['guardian31_sha256']==
                 digest(b_values['/etc/systemd/system/'+selected+'.d/'
                                 '31-aegis-auto-terminal-transition.conf']) and
             type(row['cold_prebind_sha256']) is str and
             HEX64.fullmatch(row['cold_prebind_sha256']),
             'cold_config_prefix_unbound')
    names=(str(CONFIG),str(STORE_CONFIG),str(ACTIVE_HOOK),
           '/var/lib/aegis-install/client/auto-terminal-configure-intent.json',
           '/var/lib/aegis-install/client/auto-terminal-configured.json',
           '/etc/systemd/system/'+selected+'.d/31-aegis-auto-terminal-transition.conf',
           '/etc/systemd/system/aegis-auto-guardian.service.d/31-aegis-auto-terminal-transition.conf')
    observer_archive_sha=None
    if old_context_sha is not None:
        pending_raw=_cold_optional_leaf(MIGRATION_PENDING,0o600)
        if pending_raw is None:
            ready_raw=_cold_optional_leaf(cold_root/'transition-ready.json',
                                          0o600)
            if ready_raw is not None:
                ready=json.loads(ready_raw,object_pairs_hook=unique)
                consumed_leaf=ready.get('consumed_pending_leaf')
                need(type(consumed_leaf) is str and
                     re.fullmatch(r'pending-consumed-[0-9a-f]{64}\.json',
                                  consumed_leaf),
                     'cold_pending_consumed_missing')
                pending_raw=held(cold_root/consumed_leaf,4096,0o600)
                need(digest(pending_raw)==consumed_leaf[17:-5],
                     'cold_pending_consumed_changed')
        if pending_raw is not None:
            runtime=MIGRATION/('observer-runtime-'+digest(pending_raw)+'.json')
            archive=_cold_optional_leaf(runtime,0o600)
            observer_archive_sha=None if archive is None else digest(archive)
        else:
            edges=tuple(MIGRATION.glob('edge-*.json'))
            need(len(edges)<=32,'cold_site_edge_roster_bound')
            matches=[]
            for edge_path in edges:
                need(re.fullmatch(r'edge-[0-9a-f]{64}\.json',edge_path.name),
                     'cold_site_edge_name_invalid')
                edge,edge_raw=_migration_record(edge_path,8192)
                need(digest(edge_raw)==edge_path.name[5:-5],
                     'cold_site_edge_changed')
                if (edge.get('old_context_sha256')==old_context_sha and
                    edge.get('candidate_sha256')==b_candidate):
                    matches.append(edge)
            need(len(matches)<=1,'cold_site_edge_ambiguous')
            if matches:
                old_runtime_sha=matches[0].get('observer_runtime_sha256')
                old_intent_sha=matches[0].get('intent_sha256')
                need(type(old_runtime_sha) is str and
                     HEX64.fullmatch(old_runtime_sha) and
                     type(old_intent_sha) is str and
                     HEX64.fullmatch(old_intent_sha),
                     'cold_site_edge_runtime_invalid')
                runtime=MIGRATION/('observer-runtime-'+old_intent_sha+'.json')
                archive=held(runtime,16384,0o600)
                need(digest(archive)==old_runtime_sha,
                     'cold_site_edge_runtime_changed')
                observer_archive_sha=old_runtime_sha
    _cold_site_lock(install_fd,Path('/run/aegis-auto-install.lock'))
    _cold_site_lock(guard_fd,Path('/var/lib/aegis-install/client/device-guard.conf.lock'))
    need(all(_cold_optional_leaf(path,leaf_modes[path])==actual[path]
             for path in actual),'cold_site_generation_changed')
    result={'schema':'aegis_auto_terminal_cold_site_readback_v1',
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'site_state':state,'context_state':context_state,
            'old_context_sha256':old_context_sha,
            'cold_context_state':cold_context_state,
            'cold_old_context_sha256':cold_context_sha,
            'old_observer_archive_sha256':observer_archive_sha,
            'next_bundle_manifest_sha256':bundle_sha,
            'next_sums_sha256':sums_sha}
    for key,path in zip(('source_config_sha256','store_config_sha256',
                         'active_hook_sha256','configure_intent_sha256',
                         'configured_sha256','manager31_sha256',
                         'guardian31_sha256'),names):
        result[key]=None if actual[path] is None else digest(actual[path])
    if stale_prior_sha is not None:
        current,intent_again,source_dir_again=_cold_site_stale_intent_raw(
            stale_prior_sha,release)
        need(intent_again==intent_raw and current==stale_intent and
             source_dir_again==cold_root,
             'cold_stale_intent_generation_changed')
        result.update({
            'schema':'aegis_auto_terminal_cold_stale_site_readback_v1',
            'prior_boot_id':intent['current_boot_id'],
            'prior_intent_sha256':stale_prior_sha,
            'selected_manager':selected,
            'migration_state':_cold_stale_migration_state(
                release,old_context_sha,intent,cold_root),
            'manager31_state':(
                'absent' if actual['/etc/systemd/system/'+selected+'.d/'
                                   '31-aegis-auto-terminal-transition.conf']
                         is None else
                'a_exact' if state in ('a_exact','a_retiring_prefix') else
                'b_exact' if state in ('b_prefix','b_complete') else
                None),
            'no_client_grant':True})
        need(result['manager31_state'] is not None,
             'cold_stale_manager31_phase_unknown')
    return result


def _cold_prebind_readback(root,intent_sha,install_fd,guard_fd):
    release=Path(root)
    result=subprocess.run([
        str(release/'bin/aegis-client'),'auto-verify-cold-prebind-inherited',
        '--lock-fd',str(install_fd),'--guard-fd',str(guard_fd),
        '--retained-root',str(release),'--intent-sha256',intent_sha],
        capture_output=True,check=False,timeout=210,
        pass_fds=(install_fd,guard_fd),
        env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
    need(result.returncode==0 and not result.stderr and
         0<len(result.stdout)<=8192,'cold_prebind_native_refused')
    row=json.loads(result.stdout,object_pairs_hook=unique)
    expanded={
         'schema','boot_id','intent_sha256','cold_prebind_sha256',
         'deny_policy_sha256','site_state','no_client_grant',
         'site_readback_sha256','observer_state',
                   'observer_ready_sha256','source_config_sha256',
                   'package_repair_receipt_sha256'}
    need(type(row) is dict and set(row)==expanded and
         row['schema']=='aegis_auto_v2_cold_prebind_verification_v1' and
         row['boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
         row['intent_sha256']==intent_sha and
         type(row['cold_prebind_sha256']) is str and
         HEX64.fullmatch(row['cold_prebind_sha256']) and
         type(row['deny_policy_sha256']) is str and
         HEX64.fullmatch(row['deny_policy_sha256']) and
         row['site_state'] in ('a_exact','a_retiring_prefix','absent',
                               'b_prefix','b_complete') and
         row['no_client_grant'] is True,
         'cold_prebind_native_invalid')
    need(all(type(row[key]) is str and HEX64.fullmatch(row[key])
             for key in ('site_readback_sha256',
                         'package_repair_receipt_sha256')) and
         (row['source_config_sha256'] is None and
          row['site_state']=='absent' or
          type(row['source_config_sha256']) is str and
          HEX64.fullmatch(row['source_config_sha256'])) and
         row['observer_state'] in ('absent','b_ready') and
         (row['observer_ready_sha256'] is None or
          type(row['observer_ready_sha256']) is str and
          HEX64.fullmatch(row['observer_ready_sha256'])) and
         (row['observer_state']=='absent') ==
             (row['observer_ready_sha256'] is None),
         'cold_prebind_native_projection_invalid')
    return row


def cold_configure(root,intent_sha,install_fd,guard_fd):
    """Replayable B site publication after the native retired prebind seal."""
    need(type(intent_sha) is str and HEX64.fullmatch(intent_sha),
         'cold_configure_intent_arg')
    release=Path(root)
    _cold_retained_self(release)
    _cold_site_lock(install_fd,Path('/run/aegis-auto-install.lock'))
    _cold_site_lock(guard_fd,Path('/var/lib/aegis-install/client/device-guard.conf.lock'))
    phase_root,head=_cold_site_current_phase_root()
    if head is not None:
        need(head['attempt_intent_sha256']==intent_sha and
             head['attempt_dir']==str(phase_root),
             'cold_configure_rollover_head_changed')
    proof=_cold_prebind_readback(root,intent_sha,install_fd,guard_fd)
    first=_cold_native_readback(release,install_fd,guard_fd)
    need(first['cold_intent_sha256']==intent_sha and
         first['package_state']=='new_exact' and
         first['stop_intent_absent'] is True and
         first['observer_state'] in ('absent','b_ready') and
         (first['context_state']=='present_exact' or
          first['cold_context_state']=='present_exact') and
         first['site_state']==proof['site_state'] and
         first['deny_policy_sha256']==proof['deny_policy_sha256'],
         'cold_configure_source_changed')
    ordinary=first['old_context_sha256']
    cold=first['cold_old_context_sha256']
    need((ordinary is None)!=(cold is None),'cold_configure_context_ambiguous')
    if ordinary is not None:
        context_path=MIGRATION/('context-'+ordinary+'.json')
        context_sha=ordinary
    else:
        context_path=COLD_RECOVERY/('cold-old-context-'+cold+'.json')
        context_sha=cold
    context_raw=held(context_path,256 << 10,0o600)
    need(digest(context_raw)==context_sha and
         context_raw==_migration_json(json.loads(context_raw,
                                                  object_pairs_hook=unique)),
         'cold_configure_old_context_changed')
    context=json.loads(context_raw,object_pairs_hook=unique)
    old_values,_old_source=_cold_site_expected_old(context,release)
    _installed,_helper,staged,store,source,transition,selected,fields= \
        _site_plan()
    source_raw=_migration_json(source)
    store_raw=_migration_json(store)
    configure_intent=_migration_json({
        'schema':'aegis_auto_terminal_cold_config_intent_v1',
        'current_boot_id':first['current_boot_id'],
        'intent_sha256':intent_sha,
        'cold_prebind_sha256':proof['cold_prebind_sha256'],
        'old_context_sha256':context_sha,
        'new_install_sha256':digest(held(INSTALL,1 << 20,0o600)),
        'source_config_sha256':digest(source_raw),
        'store_config_sha256':digest(store_raw),
        'active_hook_sha256':digest(staged),
        'manager31_sha256':digest(transition),
        'guardian31_sha256':digest(transition),
        'selected_manager':selected})
    config_intent_path=phase_root/'cold-config-intent.json'
    publish(config_intent_path,configure_intent,0o600)
    old_order=sorted(old_values)
    site=cold_site_readback(install_fd,guard_fd,root,
                            ordinary if ordinary is not None else 'none')
    need(site['site_state']==first['site_state'] and
         site['site_state'] in ('a_exact','a_retiring_prefix','absent',
                               'b_prefix','b_complete'),
         'cold_configure_prefix_changed')
    for path in old_order:
        _migration_unlink_if_old(path,_migration_site_leaves(_old_source)[path],
                                 old_values[path])
    need(cold_site_readback(install_fd,guard_fd,root,
           ordinary if ordinary is not None else 'none')['site_state'] in
         ('absent','b_prefix','b_complete'),
         'cold_configure_old_site_not_retired')
    configure_site()
    ready=observer_ready()
    after=_cold_prebind_readback(root,intent_sha,install_fd,guard_fd)
    final=_cold_native_readback(release,install_fd,guard_fd)
    need(after['cold_prebind_sha256']==proof['cold_prebind_sha256'] and
         after['deny_policy_sha256']==proof['deny_policy_sha256'] and
         after['site_state']=='b_complete' and
         final['site_state']=='b_complete' and
         final['observer_state']=='b_ready' and
         final['observer_ready_sha256']==digest(held(RUN/'ready.json',4096,0o600)) and
         final['cold_intent_sha256']==intent_sha and
         final['package_state']=='new_exact' and
         held(config_intent_path,8192,0o600)==configure_intent,
         'cold_configure_postproof_changed')
    need(_cold_site_current_phase_root()==(phase_root,head),
         'cold_configure_rollover_head_generation_changed')
    _cold_site_lock(install_fd,Path('/run/aegis-auto-install.lock'))
    _cold_site_lock(guard_fd,Path('/var/lib/aegis-install/client/device-guard.conf.lock'))
    return {'schema':'aegis_auto_terminal_cold_configure_v1',
            'current_boot_id':final['current_boot_id'],
            'intent_sha256':intent_sha,
            'cold_prebind_sha256':proof['cold_prebind_sha256'],
            'source_config_sha256':digest(source_raw),
            'observer_ready_sha256':final['observer_ready_sha256'],
            'no_client_grant':True}


def _migration_unlink_if_old(path, mode, old_raw):
    name = Path(path)
    try:
        actual = held(name, 1 << 20, mode)
    except FileNotFoundError:
        return
    if actual != old_raw:
        # A previous same-successor replay may already have published new
        # bytes. configure() below authenticates that exact new value.
        return
    parent = os.open(name.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(parent)
        need(before.st_uid == before.st_gid == 0 and
             not before.st_mode & 0o022, 'migration_leaf_parent')
        need(held(name, 1 << 20, mode) == old_raw, 'migration_old_leaf_changed')
        os.unlink(name.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _migration_head_update(prior_head, edge_sha):
    desired = _migration_json({'schema':'aegis_auto_terminal_migration_head_v1',
                               'edge_sha256':edge_sha})
    previous = None
    if MIGRATION_HEAD.exists() or MIGRATION_HEAD.is_symlink():
        previous, _ = _migration_record(MIGRATION_HEAD,4096)
        need(set(previous) == {'schema','edge_sha256'} and
             previous['schema'] == 'aegis_auto_terminal_migration_head_v1',
             'migration_head_changed')
        if previous['edge_sha256'] == edge_sha:
            need(held(MIGRATION_HEAD,4096,0o600) == desired,
                 'migration_head_changed')
            return
        need(previous['edge_sha256'] == prior_head, 'migration_head_branch')
    else:
        need(prior_head is None, 'migration_head_missing')
    temporary = MIGRATION/('head-next-'+edge_sha+'.json')
    publish(temporary,desired,0o600)
    parent = os.open(MIGRATION, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need(held(temporary,4096,0o600) == desired, 'migration_head_staged')
        os.replace(temporary,MIGRATION_HEAD)
        os.fsync(parent)
    finally:
        os.close(parent)
    need(held(MIGRATION_HEAD,4096,0o600) == desired,
         'migration_head_readback')


def _migration_existing_edge_for_pending(intent_sha):
    entries=tuple(MIGRATION.iterdir())
    need(len(entries)<=512,'migration_edge_roster_bound')
    found=[]
    for path in entries:
        if not path.name.startswith('edge-'):
            continue
        need(re.fullmatch(r'edge-[0-9a-f]{64}\.json',path.name),
             'migration_edge_name_invalid')
        row,raw=_migration_record(path,8192)
        need(digest(raw)==path.name[5:-5] and
             type(row) is dict and set(row)=={
               'schema','old_source_sha256','new_source_sha256',
               'old_context_sha256','prior_head_sha256','candidate_sha256',
               'package_sha256','next_bundle_manifest_sha256',
               'next_sums_sha256','intent_sha256','observer_runtime_sha256',
               'new_observer_orphan_sha256s','new_install_sha256'} and
             row['schema']=='aegis_auto_terminal_migration_edge_v1' and
             all(type(row[key]) is str and HEX64.fullmatch(row[key])
                 for key in ('old_source_sha256','new_source_sha256',
                   'old_context_sha256','candidate_sha256','package_sha256',
                   'next_bundle_manifest_sha256','next_sums_sha256',
                   'intent_sha256','observer_runtime_sha256',
                   'new_install_sha256')) and
             type(row['new_observer_orphan_sha256s']) is list and
             row['new_observer_orphan_sha256s']==
             sorted(set(row['new_observer_orphan_sha256s'])) and
             len(row['new_observer_orphan_sha256s'])<=8 and
             all(type(item) is str and HEX64.fullmatch(item)
                 for item in row['new_observer_orphan_sha256s']),
             'migration_edge_record_changed')
        if row.get('intent_sha256')==intent_sha:
            found.append(row)
    need(len(found)<=1,'migration_edge_fork')
    return found[0] if found else None


def migration_commit(unit, root, candidate_sha, package_sha,
                     install_fd, guard_fd, expected_intent_sha):
    unit_id(unit)
    need(type(expected_intent_sha) is str and HEX64.fullmatch(expected_intent_sha),
         'migration_expected_intent')
    guardian, _state = _migration_guard(install_fd,guard_fd)
    release = _migration_release(root,candidate_sha,package_sha)
    pending,pending_raw = _migration_record(MIGRATION_PENDING,4096)
    need(digest(pending_raw) == expected_intent_sha and
         set(pending) == {'schema','old_source_sha256','context_sha256',
                          'candidate_sha256','package_sha256','release_root',
                          'unit','boot_id','marker_roster_sha256','prior_head_sha256',
                          'next_bundle_manifest_sha256','next_sums_sha256'} and
         pending['schema'] == 'aegis_auto_terminal_migration_pending_v1' and
         pending['unit'] == unit and pending['release_root'] == str(release) and
         pending['candidate_sha256'] == candidate_sha and
         pending['package_sha256'] == package_sha and
         pending['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
         'migration_pending_changed')
    context_raw = held(MIGRATION/('context-'+pending['context_sha256']+'.json'),
                       256 << 10,0o600)
    need(digest(context_raw) == pending['context_sha256'],
         'migration_context_changed')
    context = json.loads(context_raw, object_pairs_hook=unique)
    need(set(context) == {'schema','old_source_sha256','old_install_sha256',
                          'leaves','markers','next_bundle_manifest_sha256',
                          'next_sums_sha256'} and
         context['schema'] == 'aegis_auto_terminal_migration_context_v1' and
         context['old_source_sha256'] == pending['old_source_sha256'] and
         digest(_migration_json(context['markers'])) ==
         pending['marker_roster_sha256'], 'migration_context_invalid')
    bundle_sha,sums_sha = _migration_rotation_bound(
        guardian,guard_fd,release,candidate_sha,context['old_install_sha256'])
    need(pending['next_bundle_manifest_sha256'] ==
         context['next_bundle_manifest_sha256'] == bundle_sha and
         pending['next_sums_sha256'] == context['next_sums_sha256'] == sums_sha,
         'migration_next_bundle_anchor_changed')
    old_leaves = context['leaves']
    need(type(old_leaves) is dict and
         set(old_leaves) == set(_migration_site_leaves(
              json.loads(bytes.fromhex(old_leaves[str(CONFIG)]['hex']),
                         object_pairs_hook=unique))), 'migration_leaf_roster')
    old_store = json.loads(bytes.fromhex(old_leaves[str(STORE_CONFIG)]['hex']),
                           object_pairs_hook=unique)
    need(_migration_boot_roster(old_store) == context['markers'],
         'migration_boot_roster_changed')
    current_install = json.loads(held(INSTALL,1 << 20,0o600),object_pairs_hook=unique)
    need(current_install.get('worker_sha256') == candidate_sha and
         current_install.get('terminal_register_sha256') == digest(held(SOURCE,1 << 20,0o500)),
         'migration_new_install_changed')
    # The old observer and its volatile socket/READY were source-bound and
    # retired before dpkg installed this new source. No late old process survives.
    locked_edge=_migration_existing_edge_for_pending(expected_intent_sha)
    if locked_edge is not None:
        need(locked_edge.get('candidate_sha256')==candidate_sha and
             locked_edge.get('package_sha256')==package_sha and
             locked_edge.get('old_source_sha256')==pending['old_source_sha256'] and
             locked_edge.get('old_context_sha256')==pending['context_sha256'] and
             locked_edge.get('next_bundle_manifest_sha256')==bundle_sha and
             locked_edge.get('next_sums_sha256')==sums_sha,
             'migration_existing_edge_changed')
    observer_runtime_sha,old_observer = _migration_runtime_archive(
        pending_raw,pending['old_source_sha256'])
    old_source = json.loads(bytes.fromhex(
        old_leaves[str(CONFIG)]['hex']),object_pairs_hook=unique)
    need(old_observer['observer_source_sha256'] == old_source['witness_sha256'] and
         old_observer['source_config_sha256'] == pending['old_source_sha256'],
         'migration_observer_archive_source')
    # Two source-qualified crash prefixes are possible. Before B configure,
    # the old runtime is fully absent. After B configure started, its new
    # source and PID 1 unit may already be live while pending still exists.
    old_config_raw = bytes.fromhex(old_leaves[str(CONFIG)]['hex'])
    present_config = None
    if CONFIG.exists() or CONFIG.is_symlink():
        present_config = held(CONFIG,4096,0o600)
    if locked_edge is not None:
        need(present_config is not None and
             digest(present_config)==locked_edge.get('new_source_sha256') and
             locked_edge.get('observer_runtime_sha256')==observer_runtime_sha,
             'migration_existing_edge_source_changed')
    if present_config is None or present_config == old_config_raw:
        _migration_observer_group_empty()
        need(not RUN.exists() and not RUN.is_symlink(),
             'migration_observer_run_not_retired')
    else:
        new_prefix = config()
        need(new_prefix['register_sha256'] ==
             current_install['terminal_register_sha256'] and
             new_prefix['witness_sha256'] ==
             current_install['terminal_witness_sha256'],
             'migration_new_observer_source')
        new_source_sha = digest(held(CONFIG,4096,0o600))
        unit_facts=command(['/usr/bin/systemctl','show',
            'aegis-auto-terminal-observer.service','-p','ActiveState',
            '-p','MainPID','--no-pager'],timeout=3)
        state=dict(line.split('=',1) for line in unit_facts.splitlines())
        need(set(state)=={'ActiveState','MainPID'},
             'migration_new_observer_state')
        if state['ActiveState'] in ('inactive','failed'):
            need(locked_edge is None,'migration_new_orphan_after_edge')
            _migration_retire_new_orphan(expected_intent_sha,new_source_sha,
                                         new_prefix['witness_sha256'])
        elif state['ActiveState']=='active':
            need(state['MainPID'].isascii() and state['MainPID'].isdecimal() and
                 int(state['MainPID'])>1,'migration_new_observer_pid')
            if RUN.exists() or RUN.is_symlink():
                run = RUN.lstat()
                need(stat.S_ISDIR(run.st_mode) and run.st_uid == run.st_gid == 0 and
                     stat.S_IMODE(run.st_mode) == 0o700 and
                     run.st_dev == Path('/run').stat().st_dev,
                     'migration_new_observer_run_untrusted')
                names = {path.name for path in RUN.iterdir()}
                need(names <= {'observer.sock','ready.json','ready.json.tmp'},
                     'migration_new_observer_run_roster')
                if 'ready.json' in names:
                    new_live = observer_ready()
                    need((new_live['observer_pid'],new_live['observer_start_tick'],
                          new_live['observer_invocation_id']) !=
                         (old_observer['observer_pid'],
                          old_observer['observer_start_tick'],
                          old_observer['observer_invocation_id']),
                         'migration_observer_not_new')
        else:
            raise Refused('migration_new_observer_state')
    old_proc = Path('/proc')/str(old_observer['observer_pid'])
    if old_proc.exists():
        raw = (old_proc/'stat').read_text()
        need(int(raw[raw.rfind(')')+2:].split()[19]) !=
             old_observer['observer_start_tick'],
             'migration_observer_old_pid_live')
    _migration_guard(install_fd,guard_fd)
    for path,row in old_leaves.items():
        need(type(row) is dict and set(row) == {'mode','hex'} and
             row['mode'] in (0o600,0o644,0o755) and
             type(row['hex']) is str and len(row['hex']) <= 2 << 20,
             'migration_old_leaf_shape')
        _migration_unlink_if_old(path,row['mode'],bytes.fromhex(row['hex']))
    # configure() computes all new bytes from the newly installed receipt and
    # stock layout. Its O_EXCL publication is replayable for the same bytes.
    configure(unit)
    new_ready = observer_ready()
    need((new_ready['observer_pid'],new_ready['observer_start_tick'],
          new_ready['observer_invocation_id']) !=
         (old_observer['observer_pid'],old_observer['observer_start_tick'],
          old_observer['observer_invocation_id']) and
         new_ready['observer_source_sha256'] ==
         json.loads(held(CONFIG,4096,0o600),object_pairs_hook=unique)['witness_sha256'],
         'migration_observer_not_new')
    new_source_raw = held(CONFIG,4096,0o600)
    new_source_sha = digest(new_source_raw)
    new_orphans = [entry[0] for entry in _migration_new_orphan_roster(
        expected_intent_sha,new_source_sha,
        config()['witness_sha256'])]
    need(locked_edge is None or
         locked_edge.get('new_observer_orphan_sha256s') == new_orphans,
         'migration_orphan_roster_after_edge')
    need(_migration_boot_roster(old_store) == context['markers'] and
         held(MIGRATION_PENDING,4096,0o600) == pending_raw,
         'migration_post_publish_changed')
    edge = {'schema':'aegis_auto_terminal_migration_edge_v1',
            'old_source_sha256':pending['old_source_sha256'],
            'new_source_sha256':new_source_sha,
            'old_context_sha256':pending['context_sha256'],
            'prior_head_sha256':pending['prior_head_sha256'],
            'candidate_sha256':candidate_sha,'package_sha256':package_sha,
            'next_bundle_manifest_sha256':bundle_sha,
            'next_sums_sha256':sums_sha,
            'intent_sha256':expected_intent_sha,
            'observer_runtime_sha256':observer_runtime_sha,
            'new_observer_orphan_sha256s':new_orphans,
            'new_install_sha256':digest(held(INSTALL,1 << 20,0o600))}
    edge_raw = _migration_json(edge);edge_sha = digest(edge_raw)
    publish(MIGRATION/('edge-'+edge_sha+'.json'),edge_raw,0o600)
    _migration_head_update(pending['prior_head_sha256'],edge_sha)
    complete = {'schema':'aegis_auto_terminal_migration_complete_v1',
                'intent_sha256':expected_intent_sha,'edge_sha256':edge_sha,
                'new_source_sha256':new_source_sha,
                'candidate_sha256':candidate_sha}
    publish(MIGRATION/('complete-'+edge_sha+'.json'),
            _migration_json(complete),0o600)
    _migration_guard(install_fd,guard_fd)
    need(config()['schema'] == 'aegis_auto_terminal_source_v1' and
         _migration_release(root,candidate_sha,package_sha) == release and
         held(MIGRATION_PENDING,4096,0o600) == pending_raw,
         'migration_completion_changed')
    parent = os.open(MIGRATION,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        os.unlink('pending.json',dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    return {'schema':'aegis_auto_terminal_migration_commit_v1',
            'status':'committed','candidate_sha256':candidate_sha,
            'intent_sha256':expected_intent_sha,
            'new_source_sha256':new_source_sha}


if __name__=='__main__':
    try:
        need(os.geteuid()==0 and sys.platform.startswith('linux') and
             3<=len(sys.argv)<=9,'registration_argv')
        operation,unit=sys.argv[1:3]
        if operation=='cold-history-archive-readback' and len(sys.argv)==5:
            result=cold_history_archive_readback(int(unit),int(sys.argv[3]),
                                                 sys.argv[4])
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        elif operation=='cold-attempt-readback' and len(sys.argv)==5:
            result=cold_attempt_readback(unit,int(sys.argv[3]),
                                         int(sys.argv[4]))
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        elif operation=='cold-old-context-candidate' and len(sys.argv)==5:
            result=cold_old_context_candidate(unit,int(sys.argv[3]),
                                              int(sys.argv[4]))
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        elif operation=='cold-old-context-publish' and len(sys.argv)==6:
            result=cold_old_context_publish(unit,sys.argv[3],
                                            int(sys.argv[4]),int(sys.argv[5]))
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        elif operation=='cold-site-readback' and len(sys.argv)==6:
            result=cold_site_readback(int(unit),int(sys.argv[3]),
                                      sys.argv[4],sys.argv[5])
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        elif (operation=='cold-stale-site-readback' and len(sys.argv)==8 and
              sys.argv[7]=='--retained-source'):
            result=cold_site_readback(int(unit),int(sys.argv[3]),
                                      sys.argv[4],sys.argv[6],
                                      stale_prior_sha=sys.argv[5])
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        elif operation=='cold-configure' and len(sys.argv)==6:
            result=cold_configure(unit,sys.argv[3],int(sys.argv[4]),
                                  int(sys.argv[5]))
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        elif operation=='migration-prepare' and len(sys.argv)==8:
            result=migration_prepare(unit,sys.argv[3],sys.argv[4],sys.argv[5],
                                     int(sys.argv[6]),int(sys.argv[7]))
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        elif operation=='cold-complete-context' and len(sys.argv)==8:
            result=cold_complete_context(unit,sys.argv[3],sys.argv[4],sys.argv[5],
                                         int(sys.argv[6]),int(sys.argv[7]))
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        elif operation=='migration-commit' and len(sys.argv)==9:
            result=migration_commit(unit,sys.argv[3],sys.argv[4],sys.argv[5],
                                    int(sys.argv[6]),int(sys.argv[7]),sys.argv[8])
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        elif operation=='configure' and len(sys.argv)==3:configure(unit)
        elif operation=='recover-incomplete' and len(sys.argv)==3:
            recover_incomplete(unit)
        elif operation=='prepare' and len(sys.argv)==3:prepare(unit)
        elif operation=='activate' and len(sys.argv)==3:activate(unit)
        elif operation=='preseal' and len(sys.argv)==6:
            preseal(unit,Path(sys.argv[3]),sys.argv[4],sys.argv[5])
        elif operation=='commit' and len(sys.argv)==6:
            commit(unit,Path(sys.argv[3]),sys.argv[4],sys.argv[5])
        elif operation=='cleanup' and len(sys.argv)==3:cleanup(unit)
        else:raise Refused('registration_operation')
    except BaseException:
        raise SystemExit(2)
