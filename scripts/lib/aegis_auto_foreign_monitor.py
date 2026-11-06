#!/usr/bin/env python3
"""Root foreign-policy monitor, independent of the client and guardian.

Subscribe before the first snapshot. Event checks use a leading edge deadline;
continuous traffic cannot postpone the full poll. Revoke never disarms a guard.
"""
from __future__ import annotations
import argparse
import ctypes
import types
import contextlib
import errno
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aegis_auto_foreign_policy as _foreign_policy
from aegis_auto_foreign_policy import (assess_foreign_policy, check_links, trusted_read,
    ForeignPolicyRefused, PolicyInputUnavailable, PolicySnapshotChanged, need, decode, run)

STATE = Path('/var/lib/aegis-install/client/device-guard.conf')
LOCK = STATE.with_suffix(STATE.suffix + '.lock')
ASSESSMENT_LOCK = STATE.with_suffix(STATE.suffix + '.assessment.lock')
ASSESSMENT_STOP_WAIT = 60.0  # bounded by installed actor lease
INSTALL_LOCK = Path('/run/aegis-auto-install.lock')
DRIFT = STATE.parent / 'foreign-policy-drift.json'
# Design B+ (r20): PID1 shutdown facts used only to classify a refusal.
TERMINAL_TARGETS = frozenset(('reboot.target', 'poweroff.target', 'halt.target', 'kexec.target'))
NONTERMINAL_SHUTDOWN_TARGETS = frozenset(('soft-reboot.target', 'exit.target'))
SHUTDOWN_TARGETS = tuple(sorted(TERMINAL_TARGETS | NONTERMINAL_SHUTDOWN_TARGETS))
SHUTDOWN_EXES = frozenset(('/usr/lib/systemd/systemd-shutdown', '/lib/systemd/systemd-shutdown'))
SYSTEM_STATES = frozenset(('initializing', 'starting', 'running', 'degraded',
                           'maintenance', 'stopping', 'offline', 'unknown'))
READ_ENV = (('PATH', '/usr/sbin:/usr/bin:/sbin:/bin'), ('LANG', 'C'), ('LC_ALL', 'C'))
PID1_READ_SECONDS = 2.0
PID1_OUTPUT_BOUND = 1 << 16
NFT_READ_SECONDS = 3.0
FREEZE_POLL_SECONDS = 0.5
FIRST_UNKNOWN_SECONDS = 1.0   # first classification: only PID1's exec race
FREEZE_UNKNOWN_SECONDS = 5.0  # inside an already confirmed window
# B+ tripwire: the fixed product shape of the owned guard table.
GUARD_TABLE = 'aegis_device_guard'
GUARD_CHAINS = {'incoming': ('filter', 'prerouting', -190, 'accept'),
                'output': ('filter', 'output', 2147483647, 'drop'),
                'forward': ('filter', 'forward', 10, 'drop'),
                'postroute': ('filter', 'postrouting', 2147483647, 'drop')}
GUARD_TABLE_KEYS = frozenset(('family', 'name', 'handle'))
GUARD_CHAIN_KEYS = frozenset(('family', 'table', 'name', 'handle', 'type', 'hook', 'prio', 'policy'))
GUARD_TERMINAL_DROPS = ('output', 'forward', 'postroute')
MANAGER_CGROUPS = frozenset(('system.slice/NetworkManager.service',
                             'system.slice/systemd-networkd.service'))
OWNED_TABLES = frozenset((('ip', 'aegis_auto_redirect'), ('ip', 'aegis_auto_local_redirect'),
                          ('inet', 'aegis_auto_witness')))
RULESET_ARGV = ('nft', '--json', 'list', 'ruleset')
GUARD_ARGV = ('nft', '--json', 'list', 'table', 'inet', GUARD_TABLE)
TABLES_ARGV = ('nft', '--json', 'list', 'tables')
SYS_CLASS_NET = Path('/sys/class/net')
# Closed check_links/bpf_bindings reasons that name a netfilter bypass. Every
# other reason (missing link, failed read, bound) is not positive evidence.
LINK_BYPASS_REASONS = frozenset(('netkit device', 'XDP attachment', 'tc ingress/clsact qdisc',
                                 'capture interface type', 'capture interface owner',
                                 'tc filter', 'forwarding host',
                                 'XDP/netfilter/TCX/netkit BPF link',
                                 'BPF program attached to protected interface'))
HELPER = '/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh'
TRANSITION_UNIT = 'aegis-auto-terminal-transition.service'
TRANSITION_SOURCE = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_boot_transition.py')
TRANSITION_UNIT_FILE = Path('/etc/systemd/system/aegis-auto-terminal-transition.service')
TRANSITION_WAIT_SECONDS = 125.0  # installed oneshot TimeoutStartSec=120s, plus PID1 completion
POLL_SECONDS = 1.0
MAX_DEBOUNCE = 0.100
_BORROW_CONTEXT = None
_ACTOR_MODULE = None


def state():
    raw = trusted_read(STATE, 16384)
    fields = {}
    for line in raw.decode('ascii').splitlines():
        k, sep, v = line.partition('=')
        need(sep and k not in fields, 'invalid guard state')
        fields[k] = v
    need(fields.get('armed') in ('0', '1'), 'guard arming unknown')
    return raw, fields


def actor_module():
    global _ACTOR_MODULE
    path=Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian_watchdog.py')
    installation=decode(trusted_read(STATE.parent/'auto-guardian-install.json',1<<20))
    raw=trusted_read(path,1<<20);sha=hashlib.sha256(raw).hexdigest()
    need(sha==installation.get('watchdog_sha256'),'monitor watchdog source differs')
    if _ACTOR_MODULE is not None:
        need(_ACTOR_MODULE[0]==sha,'monitor watchdog generation changed')
        need(sys.modules.get(_ACTOR_MODULE[1].__name__) is _ACTOR_MODULE[1],
             'monitor actor module identity changed')
        _ACTOR_MODULE[1]._own_source()
        return _ACTOR_MODULE[1]
    module=types.ModuleType('aegis_foreign_monitor_watchdog');module.__file__=str(path)
    need(module.__name__ not in sys.modules,'monitor actor module identity already occupied')
    sys.modules[module.__name__]=module
    try:
        exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__)
        module._own_source()
    except BaseException:
        if sys.modules.get(module.__name__) is module:sys.modules.pop(module.__name__,None)
        raise
    _ACTOR_MODULE=(sha,module)
    return module


def _actor_facts(unit):
    managers=('NetworkManager.service','systemd-networkd.service')
    need(unit in ('aegis-auto-guardian-watchdog.service','aegis-auto-guardian.service',*managers),
         'unknown monitor OFD actor')
    facts=dict(line.split('=',1) for line in run('systemctl','show',unit,
        '-p','MainPID','-p','ControlPID','-p','ActiveState','-p','InvocationID','-p','ControlGroup').decode().splitlines())
    need(set(facts)=={'MainPID','ControlPID','ActiveState','InvocationID','ControlGroup'} and
         facts['ActiveState'] in (('active','activating') if unit in managers or
             unit == 'aegis-auto-guardian-watchdog.service' else ('active',)) and
         facts['ControlGroup']=='/system.slice/'+unit and
         len(facts['InvocationID'])==32,'monitor OFD actor is not active')
    need(any(int(facts[k])>1 for k in ('MainPID','ControlPID')) if unit in managers else
         int(facts['MainPID'])>1,'monitor OFD actor PID unavailable')
    return facts


def _journal_private(actor):
    journal=decode(trusted_read(actor.JOURNAL,1<<20))
    need(journal.get('boot_id')==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
         'monitor actor journal boot changed')
    private=journal.get('private_unit')
    need(type(private) is str and actor.PRIVATE.fullmatch(private),
         'monitor actor journal private identity changed')
    return private


def _witness_denied():
    binding=Path(str(STATE)+'.client-binding')
    need(not binding.exists() and not binding.is_symlink(),
         'monitor preclaim witness has client binding')


def _borrow_context(actor, unit, facts, pidfd, transient):
    """Called only after original-OFD/PID1/source/netns authentication above.

    The guardian's DROP witness precedes the watchdog journal. That bounded
    phase may have only the trace-only witness table (one tuple of six rules,
    or the merged witness's two tuples of six rules each), never a client
    grant or an inferred private-unit candidate. Unknown OFD holders are
    still refused.
    """
    context=None
    if transient:
        context={'private_unit':None,'transient':True}
    elif os.path.lexists(actor.JOURNAL):
        journal = decode(trusted_read(actor.JOURNAL, 1 << 20))
        if (unit == 'aegis-auto-guardian-watchdog.service' and
                journal.get('phase') in ('RECOVERING_AFTER_REBOOT', 'RECOVERED') and
                journal.get('recovery_boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
                journal.get('boot_id') != journal.get('recovery_boot_id')):
            _witness_denied()
            context = {'private_unit':None, 'transient':True, 'reboot_deny':True}
        else:
            context={'private_unit':_journal_private(actor),
                     'private_invocation':journal.get('invocation_id'),
                     'private_main_pid':journal.get('private_main_pid')}
    elif unit in ('aegis-auto-guardian.service',
                  'aegis-auto-guardian-watchdog.service'):
        _witness_denied()
        context={'private_unit':None,'witness_only':True}
    if context is not None:
        context.update(actor_pidfd=os.dup(pidfd),actor_unit=unit,actor_facts=facts)
    return context


def _same_actor_or_watchdog_ready(unit, before, after):
    return after == before or (
        unit == 'aegis-auto-guardian-watchdog.service' and
        before.get('ActiveState') == 'activating' and
        after.get('ActiveState') == 'active' and
        set(after) == set(before) and
        all(after[key] == before[key] for key in before if key != 'ActiveState') and
        int(before['MainPID']) > 1 and before['ControlPID'] == '0')


def _borrowed_actor_stable(actor, context, after, fd):
    before=context['actor_facts']
    need(actor._alive(context['actor_pidfd']),
         'monitor leased actor disappeared during snapshot')
    if after == before:return
    # READY=1 advances this exact borrowed watchdog from activating to active.
    # Its process, PID1 invocation, cgroup and original guard OFD must remain
    # unchanged; no other PID1 movement is an admitted policy snapshot.
    need(_same_actor_or_watchdog_ready(context['actor_unit'],before,after),
         'monitor leased actor disappeared during snapshot')
    actor._guard_identity(fd)
    published=decode(trusted_read(actor.JOURNAL,1<<20))
    need(published.get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
         published.get('private_unit') == context.get('private_unit') and
         published.get('invocation_id') == context.get('private_invocation') and
         published.get('private_main_pid') == context.get('private_main_pid'),
         'monitor watchdog journal changed during snapshot')
    need(actor._alive(context['actor_pidfd']),
         'monitor leased actor disappeared during snapshot')


class ActorIdentityRefused(ValueError):
    def __init__(self, unit, kind):
        self.actor_kind={'aegis-auto-guardian-watchdog.service':'watchdog',
            'aegis-auto-guardian.service':'guardian','NetworkManager.service':'manager',
            'systemd-networkd.service':'manager'}[unit]
        need(kind in ('pidfd','cgroup','netns'),'unknown actor identity predicate')
        self.identity_failure=kind
        super().__init__('monitor OFD actor identity changed')


class TransitionRevoked(RuntimeError):
    """The transition wait already made the sticky restrictive response."""


def _completed_actor_after_proc_error(actor, pidfd):
    """Only a kernel-confirmed exit can excuse a disappearing /proc leaf.

    No actor FD has been borrowed at this point. A still-live actor remains
    a refusal; the caller's original flock is required before any snapshot.
    """
    if not actor._alive(pidfd):return True
    watcher=select.poll()
    watcher.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
    watcher.poll(200)
    return not actor._alive(pidfd)


class LeaseUnavailable(RuntimeError):
    """No live authenticated OFD was found during the bounded PID1 walk."""


def _rotation_process_identity(coordinator, pidfd):
    actor = actor_module()
    pid = coordinator['pid']
    need(actor._pidfd_pid(pidfd) == pid and actor._alive(pidfd), 'rotation coordinator not live')
    proc = Path('/proc') / str(pid)
    need(int(proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]) == coordinator['birth'] and
         hashlib.sha256(proc.joinpath('cmdline').read_bytes()).hexdigest() == coordinator['argv_sha256'] and
         proc.joinpath('cgroup').read_text() == coordinator['cgroup'] and
         os.stat(proc/'ns/net').st_ino == os.stat('/proc/self/ns/net').st_ino and
         any(row.split() == ['Uid:', '0', '0', '0', '0'] for row in
             proc.joinpath('status').read_text().splitlines()), 'rotation coordinator identity changed')
    source = Path(coordinator['source'])
    need(hashlib.sha256(trusted_read(source, 4 << 20)).hexdigest() == coordinator['source_sha256'],
         'rotation coordinator retained source changed')
    with (proc/'exe').open('rb') as stream:
        digest = hashlib.sha256(); size = 0
        for block in iter(lambda: stream.read(1 << 20), b''):
            size += len(block); need(size <= 64 << 20, 'rotation interpreter size')
            digest.update(block)
    need(digest.hexdigest() == coordinator['exe_sha256'] and actor._alive(pidfd),
         'rotation coordinator interpreter changed')


def _borrow_rotation_guard():
    """Only the stopped-successor verifier's exact retained coordinator/OFD.

    The intent is produced before FD10 acquisition. It does not admit an
    arbitrary root writer, a new flock, or a private runtime process.
    """
    intent_path = STATE.parent/'auto-guard-rotation-intent.json'
    if not os.path.lexists(intent_path):
        return None
    raw = trusted_read(intent_path, 1 << 20)
    intent = decode(raw)
    need(type(intent) is dict, 'rotation intent invalid')
    coordinator = intent.get('coordinator')
    if coordinator is None:
        return None  # Historical unregistered writers remain refused.
    need(intent.get('schema') == 'aegis_auto_guard_rotation_intent_v1' and
         intent.get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
         type(intent.get('successor')) is dict and
         type(intent['successor'].get('next_public_payload_root')) is str and
         Path(intent['successor']['next_public_payload_root']).is_absolute() and
         '..' not in Path(intent['successor']['next_public_payload_root']).parts and
         all(type(intent.get(k)) is int and intent[k] > 0 for k in ('guard_device','guard_inode')) and
         type(coordinator) is dict and set(coordinator) == {
             'pid','birth','argv_sha256','exe_sha256','source','source_sha256','cgroup',
             'install_device','install_inode'} and
         all(type(coordinator[k]) is int and coordinator[k] > 0 for k in
             ('pid','birth','install_device','install_inode')) and
         all(type(coordinator[k]) is str and len(coordinator[k]) == 64 and
             all(c in '0123456789abcdef' for c in coordinator[k]) for k in
             ('argv_sha256','exe_sha256','source_sha256')),
         'rotation coordinator registration invalid')
    # Once a new generation is admitted, this old registration grants nothing.
    if hashlib.sha256(trusted_read(STATE.parent/'auto-guardian-install.json', 1 << 20)).hexdigest() != intent.get('old_install_sha256'):
        return None
    expected_source = str(Path(intent['successor']['next_public_payload_root'])/
                          'scripts/lib/aegis_installer_auto_v2.py')
    need(coordinator['source'] == expected_source, 'rotation coordinator source path changed')
    actor = actor_module()
    try:
        pidfd = os.pidfd_open(coordinator['pid'], 0)
    except ProcessLookupError:
        return None
    borrowed = install = None
    try:
        if not actor._alive(pidfd):
            return None
        _rotation_process_identity(coordinator, pidfd)
        lib = ctypes.CDLL(None, use_errno=True)
        need(hasattr(lib, 'pidfd_getfd'), 'rotation pidfd_getfd unavailable')
        install = lib.pidfd_getfd(pidfd, 9, 0)
        if install < 0:
            install = None
            return None
        info = os.fstat(install)
        named = INSTALL_LOCK.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600 and
             (info.st_dev,info.st_ino) == (named.st_dev,named.st_ino) ==
             (coordinator['install_device'],coordinator['install_inode']) and
             actor._exclusive_flock_fdinfo(Path(f'/proc/self/fdinfo/{install}').read_text(), info),
             'rotation install OFD changed')
        borrowed = lib.pidfd_getfd(pidfd, 10, 0)
        if borrowed < 0:
            borrowed = None
            return None
        try:
            actor._guard_identity(borrowed)
        except (OSError, actor.Refused):
            return None  # The registered coordinator has not acquired FD10.
        need((os.fstat(borrowed).st_dev,os.fstat(borrowed).st_ino) ==
             (intent['guard_device'],intent['guard_inode']), 'rotation guard inode changed')
        _rotation_process_identity(coordinator, pidfd)
        context = {'private_unit':None, 'transient':True, 'rotation':True,
                   'actor_pidfd':os.dup(pidfd), 'coordinator':coordinator,
                   'rotation_intent_sha256':hashlib.sha256(raw).hexdigest()}
        result = borrowed; borrowed = None
        return result, context
    finally:
        for fd in (borrowed, install, pidfd):
            if fd is not None: os.close(fd)


def borrow_actor_guard():
    """Duplicate the original locked OFD; never unlock/reacquire a live lease.

    pidfd_getfd is authenticated against PID1 MainPID, PIDFD, root cgroup/netns,
    source-pinned actor and the exact kernel FLOCK inode. A retained duplicate
    stays usable for emergency block if the original actor dies.
    """
    rotation = _borrow_rotation_guard()
    if rotation is not None:
        return rotation
    actor=actor_module();lib=ctypes.CDLL(None,use_errno=True)
    need(hasattr(lib,'pidfd_getfd'),'monitor pidfd_getfd unavailable')
    manager=state()[1]['manager']
    need(manager in ('NetworkManager.service','systemd-networkd.service'),'monitor manager identity')
    for unit in ('aegis-auto-guardian-watchdog.service','aegis-auto-guardian.service',manager):
        try:before=_actor_facts(unit)
        except (OSError,ValueError,subprocess.SubprocessError):continue
        transient=unit==manager
        pid=int(before['ControlPID'] if transient else before['MainPID'])
        if pid<=1:continue
        try:
            pidfd=os.pidfd_open(pid,0)
        except ProcessLookupError:
            # A completed ControlPID/MainPID can disappear after PID1's facts
            # were read. No descriptor or authority has been borrowed yet.
            # Continue the same bounded actor walk; if none remains, the
            # caller must acquire the original flock exclusively or refuse.
            # Permission/resource errors still propagate, and a live unknown
            # writer can never become an unlocked policy assessment.
            continue
        if transient:
            try:
                argv=Path(f'/proc/{pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
                status=Path(f'/proc/{pid}/status').read_text()
                root_uid=any(line.split()==['Uid:','0','0','0','0'] for line in status.splitlines())
            except OSError:
                os.close(pidfd);continue
            # Both installed manager units use these exact source-pinned
            # ControlPID hooks. Networkd's ready hook holds FD9 while waiting
            # for its genuine lease and publishing the pinned DHCP policy.
            actions = (b'bind-manager', b'manager-ready')
            commands = [[shell, HELPER.encode(), action] for shell in
                        (b'/bin/bash', b'/usr/bin/bash') for action in actions]
            if not root_uid or argv not in commands:
                os.close(pidfd);continue
        try:
            # PID1 may publish a helper which finishes after pidfd_open but
            # before proc/cgroup/netns reads. No descriptor or authority has
            # been borrowed yet. Only a kernel-proven exit skips this actor;
            # a live identity/namespace mismatch remains an immediate refusal.
            try:
                if not actor._alive(pidfd):continue
                if actor._pidfd_pid(pidfd)!=pid or not actor._alive(pidfd):
                    raise ActorIdentityRefused(unit,'pidfd')
                if Path(f'/proc/{pid}/cgroup').read_text()!='0::/system.slice/'+unit+'\n':
                    raise ActorIdentityRefused(unit,'cgroup')
                if os.stat(f'/proc/{pid}/ns/net').st_ino!=os.stat('/proc/self/ns/net').st_ino:
                    raise ActorIdentityRefused(unit,'netns')
                descriptors=list(Path(f'/proc/{pid}/fd').iterdir())
                need(len(descriptors)<=4096,'monitor actor FD bound')
            except OSError:
                if _completed_actor_after_proc_error(actor,pidfd):continue
                raise
            except (ValueError,actor.Refused):
                if not actor._alive(pidfd):continue
                raise
            for path in descriptors:
                if not path.name.isdecimal():continue
                try:
                    if path.stat().st_ino!=LOCK.stat().st_ino or path.stat().st_dev!=LOCK.stat().st_dev:continue
                except FileNotFoundError:continue
                fd=lib.pidfd_getfd(ctypes.c_int(pidfd),ctypes.c_int(int(path.name)),ctypes.c_uint(0))
                if fd<0:continue
                try:
                    actor._guard_identity(fd)
                    need(actor._alive(pidfd) and _same_actor_or_watchdog_ready(
                         unit,before,_actor_facts(unit)),'monitor OFD actor changed')
                    context=_borrow_context(actor,unit,before,pidfd,transient)
                    if context is None:
                        # A watchdog without an authenticated current journal
                        # has no stable private or reboot-deny witness. Never
                        # lend its OFD as an untracked monitor-owned lock.
                        os.close(fd)
                        continue
                    return fd,context
                except (OSError,ValueError,actor.Refused):os.close(fd)
        finally:os.close(pidfd)
    raise LeaseUnavailable('monitor original guard OFD unavailable')


def _assessment_identity(fd):
    held=os.fstat(fd);named=ASSESSMENT_LOCK.stat(follow_symlinks=False)
    need(stat.S_ISREG(held.st_mode) and held.st_uid==held.st_gid==0 and
         held.st_nlink==1 and stat.S_IMODE(held.st_mode)==0o600 and
         held.st_size==0 and (held.st_dev,held.st_ino)==(named.st_dev,named.st_ino),
         'assessment lock changed')
    return held


def _assessment_holder_rows(identity):
    raw=Path('/proc/locks').read_bytes()
    need(len(raw)<=1<<20,'assessment lock owner list bound')
    held=[]
    for line in raw.decode('ascii').splitlines():
        row=line.split()
        if len(row)!=8 or row[1:4]!=['FLOCK','ADVISORY','WRITE']:
            continue
        parts=row[5].split(':')
        if len(parts)!=3:continue
        try:key=(os.makedev(int(parts[0],16),int(parts[1],16)),int(parts[2]))
        except ValueError:continue
        if key==(identity.st_dev,identity.st_ino):held.append(row)
    return held


def _isolated_deny_policy_sha(deadline):
    # The monitor imports foreign_policy before its guardian actor is loaded.
    # Run the installed guardian's existing read-only verifier in a fresh
    # interpreter so its verified_module cache owns every dependency identity.
    remaining=deadline-time.monotonic()
    need(remaining>0,'assessment wait elapsed')
    command=('/usr/bin/python3','-I','-B',
             '/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py',
             'read-guard-policy')
    result=subprocess.run(command,capture_output=True,check=False,
                          timeout=min(10.0,remaining),
                          env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
    need(result.returncode==0 and 0<len(result.stdout)<=4096 and
         len(result.stderr)<=4096 and time.monotonic()<deadline,
         'assessment isolated deny readback refused')
    reply=decode(result.stdout)
    need(type(reply) is dict and set(reply)==
         {'state_sha256','policy_sha256','manager_binding_sha256'} and
         all(type(reply[key]) is str and
             re.fullmatch('[0-9a-f]{64}',reply[key]) for key in
             ('state_sha256','policy_sha256')) and
         (reply['manager_binding_sha256'] is None or
          (type(reply['manager_binding_sha256']) is str and
           re.fullmatch('[0-9a-f]{64}',reply['manager_binding_sha256']))),
         'assessment isolated deny reply invalid')
    return reply['state_sha256'],reply['policy_sha256']


def _authenticated_stopped_retirement_holder(identity, deadline):
    """An exact PID1 actor may serialize a protected receipt/nft transition.

    An active guardian with a staged FullTun main binding may hold the sidecar
    while publishing the late numeric grant. This authenticates waiting only;
    the caller still acquires its own lock and performs a full fresh assessment.
    """
    need(time.monotonic()<deadline,'assessment wait elapsed')
    actor=actor_module()
    installation=decode(trusted_read(STATE.parent/'auto-guardian-install.json',1<<20))
    rows=_assessment_holder_rows(identity)
    if not rows:return False  # holder released during the identity walk
    need(len(rows)==1 and rows[0][6:]==['0','EOF'],
         'unknown assessment lock holder')
    for unit,path,key,unit_path,unit_key in (
        ('aegis-auto-guardian.service',
         Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py'),'guardian_sha256',
         Path('/etc/systemd/system/aegis-auto-guardian.service'),'guardian_unit_sha256'),
        ('aegis-auto-guardian-watchdog.service',
         Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian_watchdog.py'),'watchdog_sha256',
         Path('/etc/systemd/system/aegis-auto-guardian-watchdog.service'),'watchdog_unit_sha256')):
        try:facts=_actor_facts(unit)
        except (OSError,ValueError,subprocess.SubprocessError):
            if not _assessment_holder_rows(identity):return False
            continue
        try:pid=int(facts['MainPID'])
        except (KeyError,TypeError,ValueError):
            if not _assessment_holder_rows(identity):return False
            raise
        if rows[0][4]!=str(pid):continue
        try:pidfd=os.pidfd_open(pid,0)
        except ProcessLookupError:
            if not _assessment_holder_rows(identity):return False
            raise
        try:
            need(hashlib.sha256(trusted_read(path,1<<20)).hexdigest()==installation[key] and
                 hashlib.sha256(trusted_read(unit_path,1<<16)).hexdigest()==installation[unit_key],
                 'assessment holder actor changed')
            try:
                alive_before=actor._alive(pidfd)
                cmdline=Path(f'/proc/{pid}/cmdline').read_bytes()
                cgroup=Path(f'/proc/{pid}/cgroup').read_text()
                netns=os.stat(f'/proc/{pid}/ns/net').st_ino
                local_netns=os.stat('/proc/self/ns/net').st_ino
                same_exe=os.path.samefile(f'/proc/{pid}/exe','/usr/bin/python3')
                status=Path(f'/proc/{pid}/status').read_text()
                fresh_facts=_actor_facts(unit)
                alive_after=actor._alive(pidfd)
            except (OSError,ValueError,subprocess.SubprocessError):
                if not _assessment_holder_rows(identity):return False
                raise
            if not (alive_before and alive_after) and not _assessment_holder_rows(identity):
                return False  # dead pidfd, independently reacquire the unheld lock
            need(alive_before and
                 cmdline==(b'/usr/bin/python3\0-I\0-B\0'+str(path).encode()+b'\0serve\0') and
                 cgroup=='0::/system.slice/'+unit+'\n' and
                 netns==local_netns and same_exe and
                 any(line.split()==['Uid:','0','0','0','0'] for line in status.splitlines()) and
                 fresh_facts==facts and alive_after,
                 'assessment holder actor changed')
            current_rows=_assessment_holder_rows(identity)
            if not current_rows:return False  # release is not borrowed authority
            need(current_rows==rows,'assessment holder actor changed')
            boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            intent_path=actor.STOP_INTENT
            intent=None
            if intent_path.exists():intent=decode(trusted_read(intent_path,4096))
            if unit=='aegis-auto-guardian.service' and intent is None:
                # CAPTURE_READY writes its protected receipt before replacing
                # the kernel table and sealing the result. Never inspect that
                # half-state. Only the installed guardian, with the original
                # sidecar flock and an active staged FullTun main generation,
                # can make a monitor wait for the complete transaction.
                main=decode(trusted_read(STATE.parent/'device-guard.conf.main-binding',4096))
                journal=decode(trusted_read(actor.JOURNAL,1<<20))
                need(type(main) is dict and set(main)==
                     {'schema','boot_id','netns_ino','private_unit',
                      'worker_sha256','stage_dev','stage_ino'} and
                     main['schema']=='aegis_device_guard_main_binding_v1' and
                     main['boot_id']==boot and
                     type(main['netns_ino']) is int and
                     main['netns_ino']==os.stat('/proc/self/ns/net').st_ino and
                     type(main['private_unit']) is str and
                     actor.PRIVATE.fullmatch(main['private_unit']) and
                     type(main['worker_sha256']) is str and
                     re.fullmatch('[0-9a-f]{64}',main['worker_sha256']) and
                     type(main['stage_dev']) is int and main['stage_dev']>0 and
                     type(main['stage_ino']) is int and main['stage_ino']>0 and
                     journal.get('schema')=='aegis_auto_watchdog_pending_v1' and
                     journal.get('boot_id')==boot and
                     journal.get('phase')=='LATCHED' and
                     (journal.get('stage_dev'),journal.get('stage_ino'))==
                     (main['stage_dev'],main['stage_ino']) and
                     journal.get('private_unit')==main['private_unit'] and
                     state()[1]['armed']=='1',
                     'assessment active guardian generation changed')
                props=dict(line.split('=',1) for line in run(
                    'systemctl','show',main['private_unit'],
                    '-p','ActiveState','-p','SubState','-p','MainPID',
                    '-p','ControlPID','-p','InvocationID').decode().splitlines())
                need(set(props)=={'ActiveState','SubState','MainPID',
                                  'ControlPID','InvocationID'} and
                     props['ActiveState']=='active' and
                     props['SubState']=='running' and
                     props['MainPID'].isdecimal() and
                     int(props['MainPID'])>1 and
                     props['ControlPID']=='0' and
                     re.fullmatch('[0-9a-f]{32}',props['InvocationID']) and
                     props['InvocationID']==journal.get('invocation_id'),
                     'assessment active guardian private unit changed')
                final_rows=_assessment_holder_rows(identity)
                if not final_rows:
                    # The authenticated capture transaction may finish while
                    # PID1 is read. Release grants no borrowed authority: the
                    # caller must obtain its own lock and assess afresh.
                    return False
                need(final_rows==rows and _actor_facts(unit)==facts and
                     actor._alive(pidfd) and time.monotonic()<deadline,
                     'assessment active guardian holder changed')
                return True
            if unit=='aegis-auto-guardian.service':
                need(type(intent) is dict and
                     set(intent)=={'schema','boot_id','service','invocation_id','phase'} and
                     intent['schema']=='aegis_auto_stop_intent_v1' and
                     intent['boot_id']==boot and intent['phase']=='deny_proven' and
                     type(intent['invocation_id']) is str and
                     re.fullmatch('[0-9a-f]{32}',intent['invocation_id']),
                     'assessment guardian has no stopped deny')
                private=intent['service']
                expected_invocation=intent['invocation_id']
            else:
                journal=decode(trusted_read(actor.JOURNAL,1<<20))
                need(type(journal) is dict and
                     journal.get('schema')=='aegis_auto_watchdog_pending_v1' and
                     type(journal.get('private_unit')) is str and
                     actor.PRIVATE.fullmatch(journal['private_unit']) and
                     journal.get('phase') in
                     ('RECOVERING','RECOVERING_NO_OFD','RECOVERING_AFTER_REBOOT') and
                     type(journal.get('stage_dev')) is int and
                     type(journal.get('stage_ino')) is int,
                     'assessment watchdog recovery journal changed')
                if journal['phase']=='RECOVERING_AFTER_REBOOT':
                    need(journal.get('recovery_boot_id')==boot and
                         journal.get('boot_id')!=boot,
                         'assessment watchdog recovery boot changed')
                else:
                    need(journal.get('boot_id')==boot,
                         'assessment watchdog recovery boot changed')
                private=journal['private_unit']
                expected_invocation=journal.get('invocation_id')
                if intent is not None:
                    need(type(intent) is dict and
                         intent.get('schema')=='aegis_auto_stop_intent_v1' and
                         intent.get('service')==private and
                         ((intent.get('phase')=='deny_proven' and
                           intent.get('boot_id')==boot and
                           type(intent.get('invocation_id')) is str and
                           re.fullmatch('[0-9a-f]{32}',intent['invocation_id'])) or
                          (journal['phase']=='RECOVERING_AFTER_REBOOT' and
                           intent.get('phase') in ('pending_deny','deny_proven') and
                           intent.get('boot_id')==journal['boot_id'] and
                           intent.get('invocation_id')==journal.get('invocation_id'))),
                         'assessment watchdog Stop intent changed')
                    if intent.get('boot_id')==boot:
                        expected_invocation=intent['invocation_id']
            need(type(private) is str and actor.PRIVATE.fullmatch(private),
                 'assessment holder private unit changed')
            props=dict(line.split('=',1) for line in run('systemctl','show',private,
                 '-p','ActiveState','-p','MainPID','-p','ControlPID','-p','InvocationID').decode().splitlines())
            need(set(props)=={'ActiveState','MainPID','ControlPID','InvocationID'} and
                 props['ActiveState'] in ('inactive','failed') and
                 props['MainPID']==props['ControlPID']=='0' and
                 props['InvocationID'] in ('',expected_invocation),
                 'assessment holder private unit still live')
            _witness_denied()
            protected_policy=decode(trusted_read(
                STATE.parent/'auto-guardian-policy.json',4096))
            need(type(protected_policy) is dict and
                 protected_policy.get('schema')=='aegis_auto_guardian_policy_v1' and
                 _isolated_deny_policy_sha(deadline)==(
                     protected_policy.get('state_sha256'),
                     protected_policy.get('policy_sha256')),
                 'assessment holder deny policy changed')
            try:
                post_facts=_actor_facts(unit)
                post_alive=actor._alive(pidfd)
            except (OSError,ValueError,subprocess.SubprocessError):
                if not _assessment_holder_rows(identity):return False
                raise
            if not post_alive and not _assessment_holder_rows(identity):
                return False  # dead pidfd, independently reacquire the unheld lock
            need(post_facts==facts and post_alive,
                 'assessment holder changed during deny')
            need(time.monotonic()<deadline,'assessment wait elapsed')
            current_rows=_assessment_holder_rows(identity)
            if not current_rows:return False  # caller must take its own flock
            need(current_rows==rows,'assessment holder changed during deny')
            return True
        finally:os.close(pidfd)
    if not _assessment_holder_rows(identity):return False
    need(False,'unknown assessment lock holder')


def _acquire_assessment_reservation():
    fd=os.open(ASSESSMENT_LOCK,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        identity=_assessment_identity(fd)
        deadline=time.monotonic()+ASSESSMENT_STOP_WAIT
        while True:
            need(time.monotonic()<deadline,'assessment wait elapsed')
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                _assessment_identity(fd)
                need(actor_module()._exclusive_flock_fdinfo(
                     Path(f'/proc/self/fdinfo/{fd}').read_text(),identity),
                     'assessment lock not held')
                return fd
            except BlockingIOError:
                if not _authenticated_stopped_retirement_holder(identity,deadline):
                    continue  # owner released during exact identity proof
                need(time.monotonic()<deadline,'assessment wait elapsed')
                time.sleep(min(0.01,max(0,deadline-time.monotonic())))
    except BaseException:
        os.close(fd)
        raise


def _ordinary_v1_without_auto_lease():
    raw=trusted_read(STATE,16384)
    lines=[line.partition(b'=') for line in raw.splitlines()]
    schemas=[value for key,sep,value in lines if sep and key==b'schema']
    need(len(schemas)==1,'monitor guard schema changed')
    if schemas[0]!=b'aegis_device_guard_v1':return False
    import aegis_auto_guard_policy as policy
    policy._legacy_state(raw)
    need(not any(os.path.lexists(path) for path in (
        STATE.parent/'auto-guardian-install.json',
        STATE.parent/'auto-guardian-policy.json',
        STATE.parent/'device-guard.conf.auto-lease-split',
        STATE.parent/'auto-stop-intent.json')),
        'v1 state overlaps an AUTO lease')
    return True


def _ordinary_v1_writer_alive():
    for unit,actions in (
        ('aegis-client.service',('bind','capture-bind-legacy','block')),
        ('aegis-device-egress-guard.service',('block',))):
        try:
            raw=run('systemctl','show',unit,'-p','ControlPID','-p','ControlGroup',
                    '-p','ActiveState')
            facts=dict(line.split('=',1) for line in raw.decode('ascii').splitlines())
            pid=int(facts['ControlPID'])
            if (pid<=1 or facts['ControlGroup']!='/system.slice/'+unit or
                    facts['ActiveState'] not in ('activating','deactivating')):
                continue
            proc=Path('/proc')/str(pid)
            argv=proc.joinpath('cmdline').read_bytes().rstrip(b'\0').split(b'\0')
            expected=[[shell,HELPER.encode(),action.encode()]
                      for shell in (b'/bin/bash',b'/usr/bin/bash')
                      for action in actions]
            if (argv in expected and
                    proc.joinpath('cgroup').read_text()=='0::/system.slice/'+unit+'\n' and
                    proc.joinpath('ns/net').stat().st_ino==Path('/proc/1/ns/net').stat().st_ino and
                    any(line.split()==['Uid:','0','0','0','0'] for line in
                        proc.joinpath('status').read_text().splitlines())):
                return True
        except (OSError,ValueError,KeyError,UnicodeError,subprocess.SubprocessError):
            continue
    return False


def _wait_ordinary_v1_writer(fd, original):
    deadline=time.monotonic()+40
    while True:
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            named=LOCK.lstat();held=os.fstat(fd)
            need((held.st_dev,held.st_ino)==(named.st_dev,named.st_ino)==
                 (original.st_dev,original.st_ino) and
                 stat.S_ISREG(named.st_mode) and named.st_uid==0 and
                 named.st_nlink==1 and stat.S_IMODE(named.st_mode)==0o600,
                 'v1 guard lock changed after writer exit')
            return
        except BlockingIOError:
            need(time.monotonic()<deadline and _ordinary_v1_writer_alive(),
                 'unrecognized or timed-out v1 guard writer')
            time.sleep(0.02)


def _transition_facts():
    """Read only the installed oneshot's exact PID1 identity and completion."""
    wanted={'LoadState','ActiveState','SubState','Type','Result','MainPID',
            'ControlPID','InvocationID','ControlGroup','FragmentPath','DropInPaths'}
    rows=run('systemctl','show',TRANSITION_UNIT,*(item for key in sorted(wanted)
        for item in ('-p',key))).decode('ascii').splitlines()
    facts=dict(line.split('=',1) for line in rows)
    completed=(facts.get('ActiveState')=='active' and
               facts.get('SubState')=='exited' and
               facts.get('MainPID')=='0' and facts.get('ControlPID')=='0' and
               facts.get('Result')=='success')
    need(len(rows)==len(wanted) and set(facts)==wanted and
         facts['LoadState']=='loaded' and facts['Type']=='oneshot' and
         (facts['ControlGroup']=='/system.slice/'+TRANSITION_UNIT or
          completed and facts['ControlGroup']=='') and
         facts['FragmentPath']==str(TRANSITION_UNIT_FILE) and
         facts['DropInPaths']=='' and
         re.fullmatch('[0-9a-f]{32}',facts['InvocationID']) is not None,
         'transition PID1 identity changed')
    return facts


def _transition_source():
    installed=decode(trusted_read(STATE.parent/'auto-guardian-install.json',1<<20))
    need(installed.get('schema')=='aegis_auto_guardian_install_v1',
         'transition installed identity invalid')
    for path,key in ((TRANSITION_SOURCE,'terminal_transition_sha256'),
                     (TRANSITION_UNIT_FILE,'terminal_transition_unit_sha256')):
        expected=installed.get(key)
        need(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected) and
             hashlib.sha256(trusted_read(path,1<<20)).hexdigest()==expected,
             'transition installed source changed')
    # Pin the effective command as well as the file: a unit drop-in or a
    # different running executable must never authorize a foreign lock holder.
    raw=trusted_read(TRANSITION_UNIT_FILE,1<<20)
    expected=('ExecStart=/usr/bin/python3 -I -B '+str(TRANSITION_SOURCE)+
              ' boot-transition\n').encode('ascii')
    need(expected in raw,
         'transition unit command changed')


def _transition_publication(before,after):
    need(all(after[key]==before[key] for key in
         ('InvocationID','FragmentPath','DropInPaths','LoadState','Type')) and
         after['ControlPID']=='0' and after['ActiveState'] in ('activating','active') and
         after['MainPID'] in (before['MainPID'],'0'),
         'transition PID1 completion identity changed')
    if after['ActiveState']=='active':
        need(after['ControlGroup'] in (before['ControlGroup'],'') and
             after['MainPID']=='0' and after['SubState']=='exited' and
             after['Result']=='success',
             'transition PID1 completion refused')
        return True
    need(after['ControlGroup']==before['ControlGroup'] and
         after['SubState']=='start', 'transition PID1 start changed')
    return False


def _transition_sample_after_read(before, current, still_alive):
    """A PIDFD may report exit while PID1 publishes the same oneshot."""
    if current == before:
        return False
    need(not still_alive, 'transition live holder changed')
    _transition_publication(before,current)
    return True


def _revoke_borrowed_transition(fd,pidfd):
    """Block on the proven original OFD before an unknown writer can delay us."""
    durable=blocked=stopped=False
    try:publish_drift(True);durable=True
    except (OSError,ValueError):pass
    env={**os.environ,'AEGIS_AUTO_FORCE_BLOCK':'1',
         'AEGIS_AUTO_HELD_GUARD_FD':str(fd),
         'AEGIS_DEVICE_GUARD_STATE':str(STATE)}
    try:
        result=subprocess.run(['/bin/bash',HELPER,'block'],pass_fds=(fd,),
            env=env,timeout=40,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        blocked=result.returncode==0
    except (OSError,subprocess.SubprocessError):pass
    units={'aegis-client.service','aegis-auto@*.service','aegis-auto-config.service'}
    first_stop=stop_owned_units(units)
    # A transition still running after the first block cannot be allowed to
    # rewrite its receipts or rule state. Stop only this exact authenticated
    # PID1 unit, then retain the borrowed OFD for a final restrictive block.
    unit_stopped=False
    try:
        result=subprocess.run(['systemctl','stop',TRANSITION_UNIT],
            timeout=5,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        unit_stopped=result.returncode==0 and not actor_module()._alive(pidfd)
    except (OSError,subprocess.SubprocessError):pass
    try:
        result=subprocess.run(['/bin/bash',HELPER,'block'],pass_fds=(fd,),
            env=env,timeout=40,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        blocked=blocked and result.returncode==0
    except (OSError,subprocess.SubprocessError):blocked=False
    stopped=stop_owned_units(units)
    owned_deny=False
    if durable and blocked and unit_stopped:
        try:
            _witness_denied()
            _isolated_deny_policy_sha(time.monotonic()+10)
            # A foreign ACCEPT outside our owned table can remain. It is
            # precisely why this sticky incident cannot become an admitted
            # clean policy; only the restrictive owned guard is proved here.
            owned_deny=True
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):pass
    need(durable and blocked and first_stop and stopped and unit_stopped and owned_deny,
         'transition emergency revoke incomplete')


def _wait_authenticated_transition(fd, original):
    """Serialize only the pinned transition's original OFD, then reassess.

    This returns no policy proof. The caller must obtain the named lock or a
    separately authenticated actor lease and run the ordinary full assessment.
    """
    actor=actor_module()
    before=_transition_facts()
    if before['ActiveState']!='activating' or before['SubState']!='start' or \
            before['ControlPID']!='0' or not before['MainPID'].isdecimal() or \
            int(before['MainPID'])<=1:
        raise LeaseUnavailable('transition oneshot MainPID unavailable')
    _transition_source()
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    pid=int(before['MainPID'])
    try:pidfd=os.pidfd_open(pid,0)
    except ProcessLookupError:
        # The caller may only reacquire the original named inode; no proof is
        # returned from a PID that exited between PID1 facts and pidfd_open.
        return
    borrowed=None
    generation=None
    try:
        generation=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW|socket.SOCK_NONBLOCK,12)
        generation.bind((0,0))
        start_generation=get_generation(generation)
        need(actor._alive(pidfd) and actor._pidfd_pid(pidfd)==pid,
             'transition PIDFD changed')
        status=Path(f'/proc/{pid}/status').read_text()
        need(any(line.split()==['Uid:','0','0','0','0'] for line in status.splitlines()) and
             Path(f'/proc/{pid}/cgroup').read_text()=='0::/system.slice/'+TRANSITION_UNIT+'\n' and
             os.stat(f'/proc/{pid}/ns/net').st_ino==os.stat('/proc/self/ns/net').st_ino and
             os.path.samefile(f'/proc/{pid}/exe','/usr/bin/python3') and
             Path(f'/proc/{pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')==
             [b'/usr/bin/python3',b'-I',b'-B',str(TRANSITION_SOURCE).encode(),b'boot-transition'],
             'transition process identity changed')
        descriptors=list(Path(f'/proc/{pid}/fd').iterdir())
        need(len(descriptors)<=4096,'transition FD bound')
        lib=ctypes.CDLL(None,use_errno=True)
        need(hasattr(lib,'pidfd_getfd'),'transition pidfd_getfd unavailable')
        for path in descriptors:
            if not path.name.isdecimal():continue
            try:entry=path.stat()
            except FileNotFoundError:continue
            if (entry.st_dev,entry.st_ino)!=(original.st_dev,original.st_ino):continue
            candidate=lib.pidfd_getfd(ctypes.c_int(pidfd),ctypes.c_int(int(path.name)),ctypes.c_uint(0))
            if candidate<0:continue
            try:
                actor._guard_identity(candidate)
                borrowed=candidate;break
            except (OSError,ValueError,actor.Refused):os.close(candidate)
        need(borrowed is not None and actor._alive(pidfd) and
             _transition_facts()==before and
             Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot,
             'transition original guard OFD unavailable')
        try:
            _witness_denied()
            # The transition only changes authenticated receipt files. Its
            # wait starts from a full current deny readback. A concurrent
            # receipt rewrite may refuse; it cannot authorize a grant.
            _isolated_deny_policy_sha(time.monotonic()+10)
            need(get_generation(generation)==start_generation,
                 'transition initial deny generation changed')
            deadline=time.monotonic()+TRANSITION_WAIT_SECONDS
            while actor._alive(pidfd):
                need(time.monotonic()<deadline,'transition wait elapsed')
                facts=_transition_facts()
                need(actor._guard_identity(borrowed)==
                     (original.st_dev,original.st_ino) and
                     get_generation(generation)==start_generation and
                     Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot,
                     'transition holder changed')
                _witness_denied()
                if _transition_sample_after_read(before,facts,actor._alive(pidfd)):
                    break
                select.select([pidfd],[],[],min(0.25,max(0,deadline-time.monotonic())))
            # The kernel can report PIDFD exit before PID1 has published the
            # oneshot's active/exited state. Wait only for that exact same
            # invocation to finish, within the original 125-second deadline.
            while True:
                after=_transition_facts()
                complete=_transition_publication(before,after)
                need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot and
                     get_generation(generation)==start_generation,
                     'transition completion boot or nft generation changed')
                _witness_denied()
                if complete:
                    break
                need(time.monotonic()<deadline,
                     'transition PID1 completion unavailable')
                time.sleep(0.05)
            _transition_source()
            _witness_denied()
        except Exception:
            _revoke_borrowed_transition(borrowed,pidfd)
            raise TransitionRevoked('transition wait already revoked') from None
    finally:
        if borrowed is not None:os.close(borrowed)
        if generation is not None:generation.close()
        os.close(pidfd)


def _unverified_holder_sticky():
    # No borrowed authority is available to block under the held OFD. Still
    # make the refusal durable and request owned product Stop immediately;
    # generic revoke will attempt its restrictive block after this refusal.
    try:publish_drift(True)
    except (OSError,ValueError):pass
    stop_owned_units({'aegis-client.service','aegis-auto@*.service',
                      'aegis-auto-config.service'})


@contextlib.contextmanager
def guard_lock(*, reserve_assessment=False):
    global _BORROW_CONTEXT
    fd=os.open(LOCK,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);context=None
    assessment_fd=None
    try:
        st=os.fstat(fd);named=LOCK.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
             stat.S_IMODE(st.st_mode)==0o600 and
             (st.st_dev,st.st_ino)==(named.st_dev,named.st_ino),'guard lock changed')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            if _ordinary_v1_without_auto_lease():
                _wait_ordinary_v1_writer(fd,st)
            else:
                try:
                    borrowed,context=borrow_actor_guard()
                except LeaseUnavailable:
                    # A live terminal transition is a separate, source-pinned
                    # oneshot. Its original OFD may serialize us, but it never
                    # lends a policy snapshot while it is writing receipts.
                    # A completed writer can also race the actor walk; then
                    # only immediate ownership of this original inode admits.
                    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError:
                        try:_wait_authenticated_transition(fd,st)
                        except TransitionRevoked:raise
                        except Exception:
                            _unverified_holder_sticky()
                            raise
                        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        except BlockingIOError:
                            try:borrowed,context=borrow_actor_guard()
                            except Exception:
                                _unverified_holder_sticky()
                                raise
                            os.close(fd);fd=borrowed
                    current=LOCK.lstat();held=os.fstat(fd)
                    need((held.st_dev,held.st_ino)==(current.st_dev,current.st_ino)==
                         (st.st_dev,st.st_ino) and stat.S_ISREG(current.st_mode) and
                         current.st_uid==0 and current.st_nlink==1 and
                         stat.S_IMODE(current.st_mode)==0o600,
                         'guard lock changed after writer exit')
                else:
                    os.close(fd);fd=borrowed
        previous=_BORROW_CONTEXT;_BORROW_CONTEXT=context
        try:
            if reserve_assessment:
                if not _ordinary_v1_without_auto_lease():
                    assessment_fd=_acquire_assessment_reservation()
            yield fd
            if context is not None:
                if context.get('rotation'):
                    _rotation_process_identity(context['coordinator'], context['actor_pidfd'])
                    need(hashlib.sha256(trusted_read(STATE.parent/'auto-guard-rotation-intent.json',
                         1 << 20)).hexdigest() == context['rotation_intent_sha256'],
                         'rotation intent changed during assessment')
                    actor_module()._guard_identity(fd)
                    return
                actor=actor_module()
                after=_actor_facts(context['actor_unit'])
                if context.get('transient'):
                    need(all(after[k]==context['actor_facts'][k] for k in
                         ('InvocationID','ControlGroup')),'monitor manager invocation changed')
                    if context.get('reboot_deny'):
                        _witness_denied()
                else:
                    _borrowed_actor_stable(actor,context,after,fd)
                    if context.get('witness_only'):
                        if os.path.lexists(actor.JOURNAL):
                            _journal_private(actor)
                        else:
                            _witness_denied()
        finally:
            try:
                if assessment_fd is not None:
                    identity=_assessment_identity(assessment_fd)
                    need(actor_module()._exclusive_flock_fdinfo(
                         Path(f'/proc/self/fdinfo/{assessment_fd}').read_text(),identity),
                         'assessment lock lost before guard owner revalidation')
            finally:
                try:
                    if assessment_fd is not None:os.close(assessment_fd)
                finally:_BORROW_CONTEXT=previous
    finally:
        if context is not None:os.close(context['actor_pidfd'])
        if fd>=0:os.close(fd)


def stopping_transition_token():
    """Read a typed Stop epoch; this never proves or installs a permission."""
    context = _BORROW_CONTEXT
    if not context or not context.get('private_unit') or context.get('transient'):
        return None
    intent_path = STATE.parent / 'auto-stop-intent.json'
    if not intent_path.exists():
        return None
    actor = actor_module()
    need(actor.STOP_INTENT == intent_path, 'monitor Stop source path changed')
    try:intent = decode(trusted_read(intent_path, 4096))
    except FileNotFoundError:return None  # no candidate; full policy read still mandatory
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(set(intent) == {'schema','boot_id','service','invocation_id','phase'} and
         intent['schema'] == 'aegis_auto_stop_intent_v1' and
         intent['boot_id'] == boot and
         intent['service'] == context['private_unit'] and
         intent['invocation_id'] == context.get('private_invocation') and
         type(intent['invocation_id']) is str and
         re.fullmatch('[0-9a-f]{32}', intent['invocation_id']) and
         intent['phase'] in ('pending_deny','deny_proven'),
         'monitor Stop identity changed')
    # The committed barrier already removed the old grant. No candidate is
    # needed, and DISARM may now retire the journal under this borrowed OFD.
    if intent['phase'] == 'deny_proven':return None
    journal = decode(trusted_read(actor.JOURNAL, 1 << 20))
    need(journal.get('boot_id') == boot and
         journal.get('private_unit') == intent['service'] and
         journal.get('invocation_id') == intent['invocation_id'] and
         journal.get('phase') in ('LATCHED','COMMITTED_ACTIVE') and
         journal.get('private_cgroup') == '/system.slice/' + intent['service'] and
         type(journal.get('private_main_pid')) is int and journal['private_main_pid'] > 1,
         'monitor Stop identity changed')
    return (intent['service'], intent['invocation_id'], intent['phase'],
            journal['private_main_pid'])


def assessment_options(fields):
    context=_BORROW_CONTEXT
    if context is None:return {}
    context.pop('stopping_client_binding', None)
    context.pop('stopping_main_pid', None)
    context.pop('verified_client_binding', None)
    if context.get('reboot_deny'):
        _witness_denied()
    if context.get('witness_only'):
        actor=actor_module()
        if not os.path.lexists(actor.JOURNAL):
            _witness_denied()
            return {'allow_active_trace':True}
        # The ordinary typed lease may have completed its journal while this
        # read was being prepared. Promote only through the same live receipt
        # validation used for every other authenticated lease.
        context['private_unit']=_journal_private(actor)
        published=decode(trusted_read(actor.JOURNAL,1<<20))
        context['private_invocation']=published.get('invocation_id')
        context['private_main_pid']=published.get('private_main_pid')
        context.pop('witness_only')
    raw,_=state();state_sha=hashlib.sha256(raw.rstrip(b'\n')).hexdigest()
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    def candidate(unit):
        need(unit in ('NetworkManager.service','systemd-networkd.service') or
             unit==context['private_unit'],'unknown monitor cgroup candidate')
        facts=dict(line.split('=',1) for line in run('systemctl','show',unit,
            '-p','MainPID','-p','ControlPID','-p','ActiveState','-p','InvocationID','-p','ControlGroup',
            '-p','SubState').decode().splitlines())
        stopping = facts['ActiveState'] == 'deactivating' and unit == context['private_unit']
        if stopping:
            token = stopping_transition_token()
            if token is None:return None
            need(facts.get('SubState') == 'stop' and
                 facts['InvocationID'] == token[1], 'monitor stopping invocation changed')
            if facts['MainPID'] == '0':return None
            need(facts['MainPID'] == str(token[3]), 'monitor stopping Main changed')
        elif facts['ActiveState'] not in ('active','activating'):
            return None
        if not facts['ControlGroup']:return None
        if not any(int(facts[k])>1 for k in ('MainPID','ControlPID')):return None
        path=facts['ControlGroup'].lstrip('/')
        need(path.startswith('system.slice/') and path.rsplit('/',1)[-1]==unit and
             '..' not in path.split('/'),'monitor cgroup candidate differs from PID1')
        binding = {'schema':'aegis_device_guard_binding_v1','boot_id':boot,
                'state_sha256':state_sha,'path':path,
                'inode':str((Path('/sys/fs/cgroup')/path).stat().st_ino),
                'invocation':facts['InvocationID']}
        if unit == fields['manager']:
            manager_path = Path(str(STATE) + '.manager-binding')
            if manager_path.exists() or manager_path.is_symlink():
                actual = decode(trusted_read(manager_path, 4096))
                need(type(actual) is dict and all(actual.get(key) == value
                     for key, value in binding.items() if key != 'schema'),
                     'monitor manager binding changed')
                need(actual.get('schema') == 'aegis_device_guard_binding_v2' and
                     actual.get('ifindex') == int((Path('/sys/class/net') /
                     fields['uplink'] / 'ifindex').read_text().strip()),
                     'monitor manager ifindex changed')
                binding = actual
            else:
                # A manager startup is initially acquisition-only. The
                # first held-lock grant gets its numeric uplink identity.
                binding.update(schema='aegis_device_guard_binding_v2',
                    ifindex=(Path('/sys/class/net') / fields['uplink'] /
                             'ifindex').read_text().strip(),
                    dhcp4_server=None, dhcp6_server=None)
                binding['ifindex'] = int(binding['ifindex'])
        if stopping:
            # Reconstruct only the original, still-live cgroup's old grant
            # while its durable receipt has been revoked ahead of nft block.
            # The complete kernel verifier must still match this candidate.
            context['stopping_client_binding'] = binding
            context['stopping_main_pid'] = token[3]
        return binding
    def current_candidates():
        context.pop('stopping_client_binding', None)
        context.pop('stopping_main_pid', None)
        client=candidate(context['private_unit']) if context['private_unit'] is not None else None
        manager=candidate(fields['manager'])
        return [{'client':a,'manager':b} for a in (None,client) for b in (None,manager)]
    def observed_binding(pair):
        client=decode(pair['client'])if type(pair['client'])is bytes else pair['client']
        need(client is None or context['private_unit'] is None or
             client['path']=='system.slice/'+context['private_unit'],
             'verified client binding differs from original owner')
        # The membership read must use the receipt/candidate which actually
        # verified this kernel snapshot, not a second pathname read after
        # typed Stop has unlinked or replaced that receipt.
        context['verified_client_binding']=dict(client)if client is not None else None
        need(client is None or context.get('private_invocation') in (None,client['invocation']),
             'verified client invocation differs from original owner')
        # REGISTERED precedes BIND_SEAL and the later watchdog LATCH. A
        # durable grant already verified against the complete kernel policy
        # is valid during that interval and while a manager owns the OFD.
        # No journal phase is promoted here; membership brackets PID1 below.
    # Resolve once, after the full verifier has read the durable receipts.
    # Eager resolution would duplicate PID1 queries on every monitor poll.
    return {'binding_candidates':[],
            'binding_candidate_provider':current_candidates,
            'binding_observer':observed_binding,
            'allow_active_trace':not context.get('transient',False)}


def publish_drift(leak_possible):
    # No raw parser input or exception strings enter a journal or receipt.
    value = {'schema': 'aegis_foreign_policy_drift_v1',
             'reason': 'foreign_policy_drift', 'leak_possible': bool(leak_possible),
             'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'monotonic_ns': time.monotonic_ns()}
    # Keep the first incident identity across systemd restart/ExecStopPost.
    # A retry may only strengthen leak_possible, never reset its timestamp.
    if DRIFT.exists():
        previous=decode(trusted_read(DRIFT,4096))
        need(previous.get('schema')==value['schema'] and
             previous.get('reason')=='foreign_policy_drift' and
             type(previous.get('leak_possible')) is bool, 'invalid sticky drift')
        if previous['leak_possible'] or not leak_possible:return
        value=previous
        value['leak_possible']=True
    raw = (json.dumps(value, sort_keys=True) + '\n').encode()
    tmp = DRIFT.with_name('.foreign-policy-drift-' + os.urandom(16).hex())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, DRIFT)
        d = os.open(DRIFT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        tmp.unlink(missing_ok=True)


def ufw_table_status():
    # Diagnostic follows the restrictive action. It must never prevent block
    # or client stop, and does not turn a lost table into a safe drift.
    try:
        tables=decode(run('nft','--json','list','tables'))['nftables']
        present={(t['table']['family'],t['table']['name']) for t in tables if 'table' in t}
        return 'present' if {('ip','filter'),('ip6','filter')} <= present else 'missing'
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        return 'unknown'


def stop_owned_units(units):
    need(units=={'aegis-client.service','aegis-auto@*.service',
                 'aegis-auto-config.service'},'unexpected stop unit set')
    # PID1's glob stop returns failure when the AUTO units are not loaded.
    # Enumerate the exact loaded product set first; never count an absent
    # wildcard as a failed client stop or skip a loaded private instance.
    okay=True
    discovered=set()
    try:
        listing=subprocess.run(['systemctl','list-units','--all','--type=service',
            '--plain','--no-legend','--no-pager','aegis-auto@*.service',
            'aegis-auto-config.service'],capture_output=True,timeout=3)
        need(listing.returncode==0 and len(listing.stdout)<=16384,
             'PID1 product unit inventory unavailable')
        for line in listing.stdout.decode('utf-8').splitlines():
            words=line.split()
            unit=words[1] if words and words[0]=='●' else words[0]
            need(unit=='aegis-auto-config.service' or
                 re.fullmatch(r'aegis-auto@[0-9a-f]{64}\.service',unit),
                 'unexpected product unit inventory')
            discovered.add(unit)
    except (OSError,ValueError,IndexError,UnicodeError,subprocess.SubprocessError):
        okay=False
        # If PID1 listing fails, still request the prior fixed glob/exact
        # stops; preserve the failed verification result after those attempts.
        discovered={'aegis-auto@*.service','aegis-auto-config.service'}
    targets={'aegis-client.service'} | discovered
    for unit in sorted(targets):
        try:
            result=subprocess.run(['systemctl','--no-block','stop',unit],
                timeout=3,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            okay=okay and result.returncode==0
        except (OSError,subprocess.SubprocessError):
            okay=False
    return okay


def revoke(*, leak_possible=True):
    # This read is outside flock: purge commits armed=0 while holding that
    # lock, then stops this unit. The stop handler must not wait on purge.
    try:
        if state()[1]['armed']=='0':return
    except (OSError,ValueError):
        stop_owned_units({'aegis-client.service','aegis-auto@*.service','aegis-auto-config.service'})
        raise
    units={'aegis-client.service','aegis-auto@*.service','aegis-auto-config.service'}
    block_ok=False;durable=False;stopped=False
    try:
        with guard_lock() as fd:
            _,fields=state()
            if fields['armed']=='0':return
            # A full disk, damaged receipt or failed journal cannot precede
            # and thereby prevent the restrictive kernel operation.
            try:
                publish_drift(leak_possible);durable=True
            except (OSError,ValueError):
                pass
            env={**os.environ,'AEGIS_AUTO_HELD_GUARD_FD':str(fd),
                 'AEGIS_DEVICE_GUARD_STATE':str(STATE)}
            try:
                result=subprocess.run(['/bin/bash',HELPER,'block'],pass_fds=(fd,),
                    env=env,timeout=40,stdout=subprocess.DEVNULL)
                block_ok=result.returncode==0
            except (OSError,subprocess.SubprocessError):
                pass
    finally:
        # ExecStopPost takes guard flock; release it before asking PID1 to
        # stop every loaded private instance of this single-client product.
        stopped=stop_owned_units(units)
    print(json.dumps({'reason':'foreign_policy_drift','leak_possible':bool(leak_possible),
                      'guard_block_verified':block_ok,'sticky_record_durable':durable,
                      'client_stop_requested':stopped,'ufw_tables':ufw_table_status()}),flush=True)
    need(block_ok and durable and stopped,
         'foreign policy revoke incomplete; client stop requested; leak_possible')
    print(json.dumps({'reason':'foreign_policy_drift','leak_possible':bool(leak_possible),
                      'guard_retained':True}),flush=True)


class CgroupTransition(RuntimeError):
    """PID1 changed an invocation inside a read; never an admitted proof."""


def cgroup_members():
    binding = Path(str(STATE) + '.client-binding')
    stopping = _BORROW_CONTEXT.get('stopping_client_binding') if _BORROW_CONTEXT else None
    frozen = _BORROW_CONTEXT is not None and 'verified_client_binding' in _BORROW_CONTEXT
    if frozen:
        value=_BORROW_CONTEXT['verified_client_binding']
        if value is None:return
    elif binding.exists():
        value = decode(trusted_read(binding, 4096))
    elif stopping is not None:
        value = stopping
    else:return
    path = value.get('path')
    need(type(path) is str and path.startswith('system.slice/') and
         '..' not in path.split('/'), 'client cgroup path')
    unit = path.rsplit('/', 1)[-1]
    def facts():
        return dict(l.split('=', 1) for l in run('systemctl', 'show', unit,
            '-p', 'MainPID', '-p', 'ControlPID', '-p', 'ControlGroup',
            '-p', 'InvocationID', '-p', 'ActiveState', '-p', 'SubState').decode().splitlines())
    props = facts()
    original_main = _BORROW_CONTEXT.get('private_main_pid') if frozen else None
    frozen_main = str(original_main) if original_main is not None else props['MainPID']
    prestart_control = props['ControlPID'] if frozen and original_main is None and frozen_main == '0' else None
    if frozen and (props['InvocationID'] != value['invocation'] or props['ControlGroup'] != '/' + path or
            props['MainPID'] != frozen_main or
            not (frozen_main.isdecimal() and int(frozen_main) > 1 or
                 prestart_control is not None and prestart_control.isdecimal() and
                 int(prestart_control) > 1 and props.get('ActiveState') == 'activating' and
                 props.get('SubState') == 'start-pre')):
        raise CgroupTransition('verified cgroup identity changed before membership read')
    # The protected client grant also covers the exact PID1 ExecStartPre.
    # Its Main is not published until BIND returns. Pin this ControlPID and
    # phase for this read; publication of Main needs a complete fresh proof.
    if stopping is not None and (props['InvocationID'] != stopping['invocation'] or
            props['MainPID'] != str(_BORROW_CONTEXT['stopping_main_pid']) or
            props['ControlGroup'] != '/' + path):
        raise CgroupTransition('typed Stop Main changed during membership read')
    need(props['ControlGroup'] == '/' + path, 'client cgroup identity')
    try:
        members = {int(x) for x in (Path('/sys/fs/cgroup') / path / 'cgroup.procs').read_text().split()}
    except FileNotFoundError:
        if stopping is not None or frozen:raise CgroupTransition('verified cgroup removed during read')
        raise
    after = facts()
    if frozen and (after['InvocationID'] != value['invocation'] or after['ControlGroup'] != '/' + path or
            after['MainPID'] != frozen_main or prestart_control is not None and
            (after['ControlPID'] != prestart_control or after.get('ActiveState') != 'activating' or
             after.get('SubState') != 'start-pre')):
        raise CgroupTransition('verified cgroup identity changed after membership read')
    if stopping is not None and (after['InvocationID'] != stopping['invocation'] or
            after['MainPID'] != str(_BORROW_CONTEXT['stopping_main_pid']) or
            after['ControlGroup'] != '/' + path):
        raise CgroupTransition('typed Stop Main changed after membership read')
    need(len(props['InvocationID']) == 32 and len(after['InvocationID']) == 32 and
         after['ControlGroup'] == '/' + path, 'client cgroup identity changed')
    if props['InvocationID'] != after['InvocationID']:
        raise CgroupTransition('client cgroup generation changed')
    allowed = {int(row[k]) for row in (props, after) for k in ('MainPID', 'ControlPID') if int(row[k]) > 0}
    need(len(members) <= 1024, 'client cgroup process bound')
    # Admit only descendants of the exact PID1 Main/Control owners. A root
    # process moved into the cgroup has an unrelated parent and is refused.
    pending = members - allowed
    for _ in range(128):
        advanced = set()
        for pid in pending:
            try:
                fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
            except FileNotFoundError:
                advanced.add(pid)
                continue
            if int(fields[1]) in allowed:
                advanced.add(pid)
                allowed.add(pid)
        if not advanced:
            break
        pending -= advanced
    need(not pending, 'unexpected client cgroup process')


def get_generation(sock):
    # NFT_MSG_GETGEN (subsystem NFTABLES=10, message=16), NLM_F_REQUEST.
    seq = int(time.monotonic_ns() & 0xffffffff)
    sock.send(struct.pack('=IHHII', 20, (10 << 8) | 16, 1, seq, 0) +
              struct.pack('!BBH', socket.AF_UNSPEC, 0, 0))
    deadline = time.monotonic() + 0.1
    while True:
        # A scheduler delay must not discard a matching kernel reply already
        # queued before the deadline. Read readiness before testing elapsed time.
        ready, _, _ = select.select([sock], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        data = sock.recv(65536)
        offset = 0
        while offset + 16 <= len(data):
            length, typ, flags, reply_seq, _ = struct.unpack_from('=IHHII', data, offset)
            need(16 <= length <= len(data) - offset, 'netfilter response size')
            if reply_seq == seq:
                need(typ != 2, 'netfilter GETGEN refused')
                need(typ == (10 << 8) | 15 and length >= 24,
                     'netfilter GETGEN response type')
                attrs = data[offset+20:offset+length]
                cursor = 0
                generation = None
                while cursor + 4 <= len(attrs):
                    size, kind = struct.unpack_from('=HH', attrs, cursor)
                    need(4 <= size <= len(attrs)-cursor, 'netfilter generation attribute size')
                    if kind & 0x3fff == 1:  # NFTA_GEN_ID, network byte order
                        need(size == 8 and generation is None, 'netfilter generation attribute')
                        generation = struct.unpack_from('!I', attrs, cursor+4)[0]
                    cursor += (size+3) & ~3
                need(cursor == len(attrs) and generation is not None, 'netfilter generation missing')
                return generation
            offset += (length + 3) & ~3
        if time.monotonic() >= deadline:
            break
    need(False, 'netfilter GETGEN timeout')


def link_identities():
    rows = socket.if_nameindex()
    need(type(rows) is list and len(rows) <= 4096 and
         all(type(index) is int and index > 0 and type(name) is str and
             0 < len(name) <= 15 for index, name in rows) and
         len({index for index, _ in rows}) == len(rows) and
         len({name for _, name in rows}) == len(rows), 'link identity inventory invalid')
    return frozenset(rows)


def owned_tun_stop_proven():
    """Authorize a retry, never a policy admission, after exact owned teardown."""
    private = _BORROW_CONTEXT.get('private_unit') if _BORROW_CONTEXT else None
    actor = actor_module()
    installation = actor._own_source()
    import aegis_auto_guard_policy as policy
    path = Path(__file__).with_name('aegis_auto_guard_policy.py')
    need(Path(policy.__file__).resolve() == path.resolve() and
         hashlib.sha256(trusted_read(path, 1 << 20)).hexdigest() ==
         installation['guard_policy_source_sha256'], 'Stop policy source changed')
    intent = policy._scoped_read(policy.SCOPED_PARENT / 'auto-stop-intent.json')
    need(type(intent) is dict and type(intent.get('service')) is str and
         re.fullmatch(r'aegis-auto@[0-9a-f]{64}\.service', intent['service']) and
         (private is None or private == intent['service']),
         'TUN removal has no authenticated Stop owner')
    # PID1 may close TUN after the helper has returned its deny ACK. When
    # this monitor owns flock directly, the protected durable Stop intent
    # supplies the owner; an extant borrowed owner must still match exactly.
    return policy.verify_stopping_guard(intent['service'], intent.get('invocation_id'))


def stable_assessment(gen, baseline=None):
    """Retry only an observed nft transaction, within the existing poll budget.

    Stable unsafe input, unknown lock holders and exhausted budgets still
    revoke. No failed proof is returned or cached as an admission. A B+
    tripwire baseline is refreshed only from an admitted proof's own ruleset
    snapshot, after both locks are released; it never admits anything.
    """
    retry_deadline = None
    removed_owned_tun = False
    for attempt in range(3):
        accepted = False
        with guard_lock(reserve_assessment=True):
            snapshot_started = time.monotonic_ns()
            links_before = link_identities()
            need(not removed_owned_tun or not any(name == 'aegis-tun0' for _, name in links_before),
                 'stopped TUN reappeared during policy read')
            before = get_generation(gen)
            _, fields = state()
            if fields['armed'] == '0':
                return None
            failure = None
            try:
                with _ruleset_capture() as rulesets:
                    proof = assess_foreign_policy(fields['uplink'],
                        mode=fields.get('capture_profile', 'full-wide-tun'), require_guard=True,
                        allow_stopped_local_display_transition=True,
                        **assessment_options(fields))
                cgroup_members()
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                failure = error
            after = get_generation(gen)
            if isinstance(failure, PolicySnapshotChanged):
                # This remains a failed proof.  Fingerprints distinguish a
                # concurrent owned transition from a parser/readback defect
                # without publishing addresses, comments or rule contents.
                failure.generation_before = before
                failure.generation_after = after
            links_after = link_identities()
            gone_tun = {row for row in links_before - links_after if row[1] == 'aegis-tun0'}
            link_transition = bool(gone_tun)
            if link_transition:
                need(len(gone_tun) == 1 and links_before - links_after == gone_tun and
                     not links_after - links_before, 'unowned concurrent link mutation')
                owned_tun_stop_proven()
                removed_owned_tun = True
            pid1_transition = (isinstance(failure, CgroupTransition) and
                               _BORROW_CONTEXT is not None and
                               _BORROW_CONTEXT.get('private_unit') is not None)
            if before == after and not pid1_transition and not link_transition:
                if failure is not None:
                    raise failure
                if removed_owned_tun:
                    need(not any(name == 'aegis-tun0' for _, name in links_after),
                         'stopped TUN reappeared during policy read')
                    owned_tun_stop_proven()
                # POLL_SECONDS schedules starts; it was never a deadline for
                # the existing bounded policy commands. A retry begun before
                # that boundary may finish later. Its complete fresh proof is
                # valid only under this unchanged kernel generation and the
                # same revalidated guard owner, exactly like the first pass.
                accepted = True
        if accepted:
            # The guard owner was revalidated on exit above. No extra nft read
            # and no work under either lock: only these already-read bytes.
            _refresh_baseline(baseline, rulesets, links_after)
            return proof
        # The scheduling interval does not expire the initial full snapshot.
        # Start the same bounded retry window at the first observed mutation,
        # after releasing/revalidating that read's original guard owner. This
        # permits one fresh proof even when the initial complete read took >1s.
        # Further mutations share this deadline and the existing three-pass cap.
        # Stable unsafe input still raises above immediately, without a retry.
        now = time.monotonic()
        print(json.dumps({'event':'foreign_policy_retry','attempt':attempt + 1,
            'nft_changed':before != after,'owned_tun_removed':link_transition,
            'pid1_transition':pid1_transition,'snapshot_ns':time.monotonic_ns() - snapshot_started,
            'monotonic_ns':time.monotonic_ns()},sort_keys=True),file=sys.stderr,flush=True)
        if retry_deadline is None:
            retry_deadline = now + POLL_SECONDS
        need(attempt < 2 and now < retry_deadline,
             'netfilter generation did not stabilize within poll budget')
    raise AssertionError('unreachable assessment retry')


# Design B+ (r20): shutdown-aware refusal classification.
#
# A refusal is recorded and revoked exactly as before unless PID1 itself proves
# a real terminal shutdown (reboot, poweroff, halt or kexec) and no client
# grant is live. While that proof holds the monitor is silent: no file,
# kernel, stdout or journal write and no lock, so a manager stopping inside
# the shutdown leaves no false sticky drift. The guard has no stop job and its
# kernel deny stays until systemd-shutdown; the next boot reassesses before
# any bind. Positive evidence that the deny was loosened inside the window
# (the tripwire) is still recorded, and revoke re-applies the deny.


def _trace(event, **fields):
    """No-op seam. Never on a decision path; the product writes nothing here."""
    return None


@contextlib.contextmanager
def _ruleset_capture():
    """Keep the bytes of the assessment's own ruleset reads; no extra read."""
    captured = []
    original = _foreign_policy.run

    def capture(*argv):
        raw = original(*argv)
        if tuple(argv) == RULESET_ARGV:
            captured.append(raw)
        return raw
    _foreign_policy.run = capture
    try:
        yield captured
    finally:
        _foreign_policy.run = original


def _pid1_exe_is_shutdown():
    """PID1 has exec'd systemd-shutdown: no manager, job or cancel remains."""
    try:
        return os.readlink('/proc/1/exe') in SHUTDOWN_EXES
    except OSError:
        return False


def _pid1_read(*argv):
    result = subprocess.run(('/usr/bin/systemctl', *argv), capture_output=True,
                            stdin=subprocess.DEVNULL, timeout=PID1_READ_SECONDS,
                            check=False, env=dict(READ_ENV))
    need(result.returncode == 0 and len(result.stdout) <= PID1_OUTPUT_BOUND,
         'PID1 shutdown readback unavailable')
    return result.stdout.decode('ascii')


def _system_state():
    text = _pid1_read('show', '-p', 'SystemState')
    need(text.startswith('SystemState=') and text.endswith('\n') and
         text.count('\n') == 1 and text[len('SystemState='):-1] in SYSTEM_STATES,
         'PID1 SystemState readback')
    return text


def shutdown_verdict():
    """Return 'confirmed', 'denied' or 'unknown'. Read-only; grants nothing.

    confirmed: PID1 is systemd-shutdown, or SystemState is exactly 'stopping',
    exactly one of reboot/poweroff/halt/kexec.target is pending (start job)
    or reached, no soft-reboot or exit target is pending or reached, and
    SystemState is unchanged after the reads. denied: any other complete
    readback (running, degraded, maintenance, starting, a cancelled, failed
    or conflicting terminal job, soft-reboot, two terminal targets). unknown:
    a failed, slow or malformed readback, or SystemState offline/unknown.
    """
    if _pid1_exe_is_shutdown():
        return 'confirmed'
    try:
        first = _system_state()
        value = first[len('SystemState='):-1]
        if value in ('offline', 'unknown'):
            return 'unknown'
        if value != 'stopping':
            return 'denied'
        # Only the six shutdown targets are listed, so many stop jobs with
        # long unit names cannot push this readback past its bound.
        jobs = _pid1_read('list-jobs', '--no-legend', '--plain', '--full',
                          '--no-pager', '--', *SHUTDOWN_TARGETS)
        ids, units, pending = set(), set(), set()
        for line in jobs.splitlines():
            row = line.split()
            need(len(row) == 4 and re.fullmatch('[1-9][0-9]*', row[0]) is not None and
                 row[0] not in ids and row[1] in SHUTDOWN_TARGETS and
                 row[1] not in units and row[3] in ('waiting', 'running'),
                 'PID1 shutdown job row')
            ids.add(row[0])
            units.add(row[1])
            if row[2] == 'start':
                pending.add(row[1])
        reached, seen = set(pending), []
        text = _pid1_read('show', *SHUTDOWN_TARGETS, '-p', 'Id', '-p', 'ActiveState')
        for block in text.strip('\n').split('\n\n'):
            facts = dict(line.split('=', 1) for line in block.split('\n'))
            need(set(facts) == {'Id', 'ActiveState'}, 'PID1 target readback')
            seen.append(facts['Id'])
            if facts['ActiveState'] in ('active', 'activating'):
                reached.add(facts['Id'])
        need(sorted(seen) == list(SHUTDOWN_TARGETS), 'PID1 target readback')
        if (reached & NONTERMINAL_SHUTDOWN_TARGETS or
                len(reached & TERMINAL_TARGETS) != 1):
            return 'denied'
        # PID1 may have moved on during the reads: the answer must still hold.
        return 'confirmed' if _system_state() == first else 'unknown'
    except Exception:
        return 'unknown'


def _items(value):
    """nft JSON as (kind, object) pairs; metainfo is dropped."""
    need(type(value) is dict and set(value) == {'nftables'} and
         type(value['nftables']) is list, 'nft JSON shape')
    items = []
    for item in value['nftables']:
        need(type(item) is dict and len(item) == 1, 'nft JSON item')
        kind, obj = next(iter(item.items()))
        need(type(kind) is str and type(obj) is dict, 'nft JSON item')
        if kind != 'metainfo':
            items.append((kind, obj))
    return items


def _nft_items(argv):
    result = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL,
                            timeout=NFT_READ_SECONDS, check=False, env=dict(READ_ENV))
    need(result.returncode == 0, 'nft readback unavailable')
    return _items(decode(result.stdout))


def _owner(kind, obj):
    return (obj.get('family'), obj.get('name') if kind == 'table' else obj.get('table'))


def _is_cgroupv2(left):
    return (type(left) is dict and type(left.get('socket')) is dict and
            left['socket'].get('key') == 'cgroupv2')


def _cgroup_id(value):
    """nft prints a cgroupv2 operand as its path, or as its id once pruned."""
    if type(value) is int and value > 0:
        return value
    need(type(value) is str and 0 < len(value) <= 4096, 'guard cgroup operand')
    if re.fullmatch('[1-9][0-9]*', value):
        return int(value)
    parts = value.split('/')
    need('\0' not in value and '' not in parts and '.' not in parts and '..' not in parts,
         'guard cgroup operand')
    return os.stat('/sys/fs/cgroup/' + value, follow_symlinks=False).st_ino


def _canonical(value):
    """Comparison form: no handle, index or counter values; cgroup ids."""
    if type(value) is list:
        return [_canonical(item) for item in value]
    if type(value) is dict:
        match = value.get('match') if set(value) == {'match'} else None
        if type(match) is dict and _is_cgroupv2(match.get('left')):
            body = {key: _canonical(item) for key, item in match.items() if key != 'right'}
            body['right'] = ['cgroupv2-id', _cgroup_id(match.get('right'))]
            return {'match': body}
        return {key: (None if key == 'counter' else _canonical(item))
                for key, item in value.items() if key not in ('handle', 'index')}
    return value


def _rule_row(obj):
    """(canonical text, ends in accept) of one rule; its chain is the key."""
    row = _canonical({key: item for key, item in obj.items() if key != 'chain'})
    expr = row.get('expr')
    accept = type(expr) is list and bool(expr) and expr[-1] == {'accept': None}
    return (json.dumps(row, sort_keys=True, separators=(',', ':')), accept)


class _Loosened(Exception):
    """Positive evidence that the owned deny lost a restriction."""


def _guard_rules(items):
    """Rule objects per guard chain; _Loosened on any non-product shape.

    Baseline-free: the table is missing or carries flags (dormant) or other
    fields, holds an object kind the product never renders (named set, map,
    counter, flowtable...), its chains differ from the four fixed base chains
    (type, hook, priority, policy), or a terminal output/forward/postroute
    drop is gone.
    """
    rows = [(kind, obj) for kind, obj in items if _owner(kind, obj) == ('inet', GUARD_TABLE)]
    tables = [obj for kind, obj in rows if kind == 'table']
    if len(tables) != 1 or not set(tables[0]) <= GUARD_TABLE_KEYS:
        raise _Loosened('guard table')
    chains, rules = {}, {name: [] for name in GUARD_CHAINS}
    for kind, obj in rows:
        if kind == 'table':
            continue
        if kind == 'chain' and obj.get('name') not in chains and set(obj) <= GUARD_CHAIN_KEYS:
            chains[obj.get('name')] = tuple(obj.get(key) for key in ('type', 'hook', 'prio', 'policy'))
        elif kind == 'rule' and obj.get('chain') in rules:
            rules[obj['chain']].append(obj)
        else:
            raise _Loosened('guard object')
    if chains != GUARD_CHAINS:
        raise _Loosened('guard chains')
    for name in GUARD_TERMINAL_DROPS:
        tail = rules[name][-1:]
        if not tail or _canonical(tail[0].get('expr')) not in (
                [{'counter': None}, {'drop': None}], [{'drop': None}]):
            raise _Loosened('guard terminal drop')
    return rules


def _guard_view(items):
    return {name: [_rule_row(obj) for obj in objs]
            for name, objs in _guard_rules(items).items()}


def _only_accepts_removed(current, assessed):
    """current keeps the assessed order and every dropped row ended in accept."""
    position = 0
    for row in current:
        while position < len(assessed) and assessed[position][0] != row[0]:
            if not assessed[position][1]:
                return False
            position += 1
        if position == len(assessed):
            return False
        position += 1
    return all(row[1] for row in assessed[position:])


def guard_loosened(items, assessed):
    """True only on positive evidence that the guard lost a restriction.

    Removing accept rules (the client grant, a stopped manager's DHCP
    exception) is restrictive. Any non-product shape, an added or reordered
    rule, or a removed rule that does not end in accept is loosening. Without
    a usable comparison (no baseline, a cgroup pruned between nft's read and
    this stat) only the baseline-free checks decide.
    """
    try:
        rules = _guard_rules(items)
    except _Loosened:
        return True
    if assessed is None:
        return None
    try:
        current = {name: [_rule_row(obj) for obj in objs] for name, objs in rules.items()}
    except Exception:
        return None
    return not all(_only_accepts_removed(current[name], assessed.get(name, []))
                   for name in GUARD_CHAINS)


def _reroute_view(items):
    """Base chains outside the guard that can move a packet after the guard
    accepted it (route or nat at output; any ingress/egress or netdev hook),
    each with its exact chain object and canonical rule rows."""
    chains = {}
    for kind, obj in items:
        if kind != 'chain' or 'hook' not in obj or _owner(kind, obj) == ('inet', GUARD_TABLE):
            continue
        if (obj.get('family') == 'netdev' or obj.get('hook') in ('ingress', 'egress') or
                (obj.get('hook') == 'output' and
                 (obj.get('type') in ('route', 'nat') or
                  type(obj.get('prio')) is int and obj['prio'] >= 2147483647))):
            key = (obj.get('family'), obj.get('table'), obj.get('name'))
            need(key not in chains, 'duplicate rerouting chain')
            chains[key] = (json.dumps(obj, sort_keys=True, separators=(',', ':')), [])
    for kind, obj in items:
        key = (obj.get('family'), obj.get('table'), obj.get('chain'))
        if kind == 'rule' and key in chains:
            chains[key][1].append(_rule_row(obj)[0])
    return chains


def _subsequence(current, assessed):
    remaining = iter(assessed)
    return all(any(row == old for old in remaining) for row in current)


def reroute_loosened(items, assessed):
    """True on a rerouting chain or rule absent from the last assessed ruleset.

    The r18 assessment refuses every foreign non-filter chain, so a new one
    inside the window is never admitted state. Without a baseline only the
    product-owned redirect/witness tables are admitted by name.
    """
    try:
        current = _reroute_view(items)
    except Exception:
        return None
    for key, (chain, rows) in current.items():
        if assessed is None:
            if key[:2] in OWNED_TABLES:
                continue
            return True
        if key not in assessed or assessed[key][0] != chain or \
                not _subsequence(rows, assessed[key][1]):
            return True
    return False


def links_loosened(uplink):
    """True only when the product's own link reader names a netfilter bypass."""
    if type(uplink) is not str:
        return None
    try:
        check_links(uplink)
    except ForeignPolicyRefused as error:
        # Subclasses (unavailable input, changed snapshot) are never evidence.
        if type(error) is ForeignPolicyRefused and len(error.args) == 1 and \
                error.args[0] in LINK_BYPASS_REASONS:
            return True
        return None
    except Exception:
        return None
    return False


def link_names_loosened(fields, assessed):
    """True when a protected link name now names another link.

    The deny accepts by interface name (lo, the capture TUN, the uplink's
    DHCP/ND/management replies). A recreated or renamed link carrying one of
    those names after the last assessment is positive evidence. Without a
    baseline, a capture-interface name that is not a TUN device is.
    """
    names = {'lo', 'aegis-tun0'}
    for key in ('uplink', 'capture_interface'):
        if type(fields.get(key)) is str:
            names.add(fields[key])
    try:
        current = link_identities()
    except Exception:
        return None
    if assessed is not None:
        return any(name in names and (index, name) not in assessed for index, name in current)
    captures = {'aegis-tun0', fields.get('capture_interface')}
    for index, name in current:
        if name not in captures:
            continue
        base = SYS_CLASS_NET / name
        try:
            flags = int((base / 'tun_flags').read_text().strip(), 16)
        except FileNotFoundError:
            try:
                same = int((base / 'ifindex').read_text().strip()) == index
            except (OSError, ValueError):
                same = False
            if same:
                return True
            continue
        except (OSError, ValueError):
            return None
        if flags & 0x3 != 0x1:
            return True
    return False


def live_client_grant(items):
    """False only when no guard rule names a live non-manager cgroup.

    A cgroup removed after its grant is printed by nft as its id; nothing
    can match it any more. None (unreadable) is never proof of no grant.
    """
    if items is None:
        return None
    for kind, obj in items:
        if kind != 'rule' or _owner(kind, obj) != ('inet', GUARD_TABLE):
            continue
        if type(obj.get('expr')) is not list:
            return None
        for statement in obj['expr']:
            match = statement.get('match') if type(statement) is dict else None
            if type(match) is not dict or not _is_cgroupv2(match.get('left')):
                continue
            right = match.get('right')
            if (type(right) is int and right > 0) or (
                    type(right) is str and re.fullmatch('[1-9][0-9]*', right)):
                continue
            if type(right) is not str or right.startswith('/') or '..' in right.split('/'):
                return None
            if right in MANAGER_CGROUPS:
                continue
            if os.path.isdir('/sys/fs/cgroup/' + right):
                return True
    return False


def _window_view():
    """(items, complete): the ruleset, else the guard table, else a proven absence."""
    try:
        return _nft_items(RULESET_ARGV), True
    except Exception:
        pass
    try:
        return _nft_items(GUARD_ARGV), False
    except Exception:
        pass
    try:
        tables = _nft_items(TABLES_ARGV)
    except Exception:
        return None, False
    if any(kind == 'table' and _owner(kind, obj) == ('inet', GUARD_TABLE) for kind, obj in tables):
        return None, False
    return tables, False


def _freeze_fields():
    try:
        fields = state()[1]
    except Exception:
        return {}
    return {key: fields.get(key) for key in ('uplink', 'capture_interface')}


def tripwire(items, complete, baseline, fields):
    """Name of the first check with positive evidence, else None.

    Every failed or partial read is no evidence; nothing here raises.
    """
    checks = []
    if items is not None:
        checks.append(('guard', lambda: guard_loosened(items, baseline.get('guard'))))
        if complete:
            checks.append(('reroute', lambda: reroute_loosened(items, baseline.get('reroute'))))
    checks.append(('links', lambda: links_loosened(fields.get('uplink'))))
    checks.append(('link_names', lambda: link_names_loosened(fields, baseline.get('links'))))
    for name, check in checks:
        try:
            if check() is True:
                return name
        except Exception:
            pass
    return None


def _refresh_baseline(baseline, rulesets, links):
    """Last good tripwire baseline from an admitted proof's own snapshot."""
    if baseline is None or not rulesets:
        return
    raw = rulesets[-1]
    if raw == baseline.get('raw') and links == baseline.get('links'):
        return
    try:
        items = _items(decode(raw))
        guard = _guard_view(items)
        reroute = _reroute_view(items)
    except Exception:
        return  # a failed capture never clears or weakens the last good one
    baseline.update(raw=raw, guard=guard, reroute=reroute, links=links)


def shutdown_freeze(baseline):
    """Classify one refusal. Return (reason, frozen): why it must be recorded now.

    A live or unprovable client grant returns first, from one nft read and
    before any PID1 read, so a slow or hung PID1 cannot delay that revoke.
    Only without a grant is PID1 asked. While PID1 keeps confirming a real
    terminal shutdown and the tripwire stays silent this never returns: no
    assessment, revoke, kernel or file write, no stdout/journal output and
    no lock. systemd-shutdown's SIGTERM then ends the process; PID1 is no
    longer a manager, so no ExecStopPost runs. A grant seen again at freeze
    entry, a cancelled, failed or conflicting shutdown, isolate/rescue or
    soft-reboot, an unreadable PID1 or tripwire evidence returns, and the
    caller records the suppressed refusal; nothing is re-assessed or cleared.
    Unreadable PID1 is counted from the first unknown verdict: 1 s first and
    5 s inside a window, plus the 2 s bound of each systemctl read, so about
    4.5 s at most before a no-grant refusal is recorded.
    """
    fields = _freeze_fields()
    items, _complete = _window_view()
    if live_client_grant(items) is not False:
        _trace('not_shutdown', reason='grant')
        return 'grant', False
    unknown_since = None
    limit = FIRST_UNKNOWN_SECONDS
    frozen = False
    while True:
        verdict = shutdown_verdict()
        if verdict == 'confirmed':
            unknown_since = None
            items, complete = _window_view()
            if not frozen:
                # Suppress only when no client grant can still pass the guard;
                # a grant may have appeared while PID1 was being read.
                if live_client_grant(items) is not False:
                    _trace('not_shutdown', reason='grant')
                    return 'grant', False
                frozen = True
                limit = FREEZE_UNKNOWN_SECONDS
                _trace('freeze_enter')
            hit = tripwire(items, complete, baseline, fields)
            if hit is not None:
                _trace('freeze_exit', reason='tripwire', check=hit)
                return 'tripwire', True
        elif verdict == 'denied':
            _trace('freeze_exit' if frozen else 'not_shutdown', reason='denied')
            return 'denied', frozen
        else:
            now = time.monotonic()
            if unknown_since is None:
                unknown_since = now
            elif now - unknown_since >= limit:
                _trace('freeze_exit' if frozen else 'not_shutdown', reason='unknown')
                return 'unknown', frozen
        time.sleep(FREEZE_POLL_SECONDS)


def rotation_stop_authorized():
    """A typed stopped successor may retire this generation's monitor only.

    The original registered coordinator OFD stays exclusive. The guardian
    independently checks complete deny and a bounded PID1 resume timer.
    """
    try:
        with guard_lock() as fd:
            if not _BORROW_CONTEXT or not _BORROW_CONTEXT.get('rotation'):
                return False
            actor_module()._own_source()
            helper = '/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py'
            result = subprocess.run(['/usr/bin/python3','-I','-B',helper,
                'verify-rotation-monitor-stop',str(fd)], pass_fds=(fd,),
                capture_output=True, timeout=20)
            need(result.returncode == 0 and len(result.stdout) <= 4096,
                 'rotation monitor stop not proved')
            proof = decode(result.stdout)
            need(proof == {'schema':'aegis_rotation_monitor_quiesced_v1',
                 'intent_sha256':_BORROW_CONTEXT['rotation_intent_sha256'],
                 'deny_proven':True,'independent_resume_seconds':600},
                 'rotation monitor stop reply changed')
            print(json.dumps({'event':'quiesced_for_rotation',
                  'intent_sha256':proof['intent_sha256']}), flush=True)
            return True
    except Exception:
        # A malformed or unavailable quiescence proof always takes ordinary
        # revoke, including failures not expected by the normal parser.
        return False


def refusal_coordinates(error):
    """Closed source coordinates only; never exception text or parser input."""
    root=Path(__file__).resolve().parent
    sources={str(root/name):label for name,label in (
        ('aegis_auto_foreign_monitor.py','monitor'),
        ('aegis_auto_foreign_policy.py','foreign_policy'),
        ('aegis_auto_guard_policy.py','guard_policy'))}
    source='unknown';line=0;trace=error.__traceback__
    while trace is not None:
        label=sources.get(trace.tb_frame.f_code.co_filename)
        if label is not None and trace.tb_frame.f_code.co_name not in('need','_need') and 1<=trace.tb_lineno<=10000:
            source=label;line=trace.tb_lineno
        trace=trace.tb_next
    result = {'event':'foreign_policy_refused','source':source,'line':line}
    if isinstance(error,ActorIdentityRefused):
        result.update(actor_kind=error.actor_kind,identity_failure=error.identity_failure)
    if isinstance(error,PolicyInputUnavailable):
        result.update(policy_input=error.command_tag, input_failure=error.failure_tag,
                      input_exit=error.exit_status)
    if isinstance(error,PolicySnapshotChanged):
        result.update(snapshot_first_sha256=error.first_sha256,
                      snapshot_second_sha256=error.second_sha256,
                      snapshot_changed_index=error.changed_index,
                      snapshot_first_kind=error.first_kind,
                      snapshot_second_kind=error.second_kind,
                      snapshot_foreign_changed=error.foreign_changed,
                      snapshot_owned_changes=error.owned_changes)
        for name in ('generation_before', 'generation_after'):
            value = getattr(error, name, None)
            if type(value) is int and 0 <= value <= 0xffffffff:
                result[name] = value
    return result


def monitor():
    need(os.geteuid() == 0, 'root required')
    nft = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_NONBLOCK, 12)
    rtn = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_NONBLOCK, 0)
    gen = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_NONBLOCK, 12)
    # NFNLGRP_NFTABLES=7; RTMGRP_LINK=1, RTMGRP_TC=8. Subscription is live
    # before the first snapshot, including events queued during that snapshot.
    nft.bind((0, 1 << 6))
    rtn.bind((0, 1 | 8))
    gen.bind((0, 0))
    previous = None
    baseline = {'raw': None, 'guard': None, 'reroute': None, 'links': None}
    next_poll = time.monotonic()
    event_deadline = None
    while True:
        now = time.monotonic()
        due = min(next_poll, event_deadline if event_deadline is not None else next_poll)
        ready, _, _ = select.select([nft, rtn], [], [], max(0, due - now))
        for sock in ready:
            try:
                data, _, flags, _ = sock.recvmsg(MAX_INPUT)
                if not data or flags & socket.MSG_TRUNC:
                    next_poll = 0
            except OSError:
                # ENOBUFS and all other socket errors force an immediate full
                # assessment; none can be treated as 'no events'.
                next_poll = 0
            if event_deadline is None:
                event_deadline = time.monotonic() + MAX_DEBOUNCE
        now = time.monotonic()
        if now < next_poll and (event_deadline is None or now < event_deadline):
            continue
        check_started=time.monotonic()
        try:
            proof = stable_assessment(gen, baseline)
            if proof is None:
                return
            if previous is not None and proof != previous:
                print(json.dumps({'event': 'safe_foreign_policy_drift',
                    'foreign_projection_sha256': proof['foreign_projection_sha256']}), flush=True)
            previous = proof
            _trace('assessment_ok')
        except Exception as error:
            if isinstance(error,TransitionRevoked):
                # The exact borrowed original OFD already performed the
                # durable restrictive block and product stop. Re-entering
                # guard_lock here could wait on that actor a second time.
                print(json.dumps(refusal_coordinates(error)),flush=True)
                return
            # Every exception class is a refusal. B+: classify it against PID1
            # before any durable or kernel action; only a confirmed terminal
            # shutdown without a live grant suppresses the record, and that
            # never returns while it holds. Every other outcome revokes.
            _trace('refusal', error=error)
            try:
                reason, frozen = shutdown_freeze(baseline)
            except Exception:
                reason, frozen = 'classification_failed', False
            _trace('revoke', reason=reason, frozen=frozen)
            if frozen:
                # A window that did not end in systemd-shutdown, or a loosened
                # deny: the record must not depend on the guard lock that
                # revoke() takes next (an unknown holder would block it).
                try:
                    if state()[1]['armed'] == '1':
                        publish_drift(True)
                except Exception:
                    pass
            try:
                revoke(leak_possible=True)
            finally:
                # Diagnostics follow the restrictive action and cannot mask
                # its result. The output contains no arbitrary error strings.
                try:print(json.dumps(refusal_coordinates(error)),flush=True)
                except (OSError,ValueError):pass
            # Sticky refusal: only explicit administrative recovery clears it.
            return
        next_poll = check_started + POLL_SECONDS
        event_deadline = None


def monitor_stop():
    # A stop PID1 runs this for is never a clean shutdown: the monitor has no
    # stop job in a reboot/poweroff/halt/kexec transaction. Only the typed
    # rotation quiescence is exempt, and any exception class revokes.
    try:
        authorized = rotation_stop_authorized() is True
    except BaseException:
        authorized = False
    if not authorized:
        revoke(leak_possible=True)


MAX_INPUT = 4 << 20
if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    commands=p.add_mutually_exclusive_group()
    commands.add_argument('--stopped', action='store_true')
    # Retired r19 handoff: the installed aegis-auto-clean-shutdown.service
    # still names this flag in ExecStop. It is accepted and inert (no lock,
    # read, write or PID1 call); the guard keeps its deny through shutdown.
    commands.add_argument('--shutdown-handoff', action='store_true')
    args = p.parse_args()
    try:
        if args.stopped:
            monitor_stop()
        elif not args.shutdown_handoff:
            monitor()
    except Exception:
        # A failing monitor is an alarm, never an implicit grant. systemd runs
        # the same bounded revoke path after abnormal exit and restarts it.
        raise SystemExit('foreign_policy_drift: monitor unavailable; leak_possible')
