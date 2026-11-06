"""Bounded installed original-profile full-wide activation/recovery test operator.

Product networking remains in the exact signed Rust client and release helpers.
This operator never installs, enrolls, renews, deploys, downloads or builds. Its
scoped result is not independent capture, reboot, target-network or beta acceptance.
"""
import argparse
import ipaddress
from types import SimpleNamespace
import datetime
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import shutil
import signal
import shlex
import tempfile
import tomllib
import stat
import struct
import subprocess
import sys
import time

from device_candidate_verify import read, file_hash, require, trusted, verify
from device_candidate_acceptance import guest_guard

BASE = Path('/var/lib/aegis-fullwide-acceptance')
CLIENT = Path('/usr/local/bin/aegis-client')
CONFIG = Path('/etc/aegis/client/aegis.toml')
GUARD = Path('/usr/local/lib/aegis/aegis-device-egress-guard.sh')
GUARD_STATE = Path('/var/lib/aegis-install/client/device-guard.conf')
UNITS = Path('/etc/systemd/system')
SELECTED = (Path('/run/aegis-relay-geneva'), Path('/var/lib/aegis-install/client/relay-geneva-guard-state.json'),
            Path('/etc/systemd/system/aegis-client.service.d/25-relay-geneva-profile.conf'))
HEX = re.compile('[0-9a-f]{64}\\Z')
COLLECTOR_KEYS = ('pid', 'start_ticks', 'invocation', 'output_device', 'output_inode')
CLIENT_EXEC = ('ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate structured field')
        result[key] = value
    return result


def load(path):
    return json.loads(read(path, 65536), object_pairs_hook=unique)


def private(path):
    data = read(path, 65536)
    info = Path(path).lstat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'private root-owned input required')
    return data


def new(path, data, mode=0o600):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        raw = data if isinstance(data, bytes) else (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, mode)
    except BaseException:
        raise
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class Commands:
    """Every held child has a deadline; failures are private exclusive records."""
    def __init__(self, work, deadline):
        self.work, self.deadline, self.sequence = Path(work), deadline, 0
        self.prefix = '%d-%s' % (time.time_ns(), os.urandom(4).hex())

    def call(self, argv, budget=10):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'whole operation deadline expired')
        self.sequence += 1
        cutoff = time.monotonic() + min(remaining, budget)
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            child = subprocess.Popen([str(x) for x in argv], stdout=out, stderr=err,
                start_new_session=True, close_fds=True,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'HOME': '/root', 'TZ': 'UTC'})
            failure = None
            try:
                while child.poll() is None:
                    if time.monotonic() >= cutoff:
                        failure = 'COMMAND_DEADLINE'
                        raise TimeoutError(failure)
                    if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > 1024 * 1024:
                        failure = 'COMMAND_OUTPUT_BOUND'
                        raise ValueError(failure)
                    time.sleep(min(0.01, max(0, cutoff - time.monotonic())))
                require(time.monotonic() < cutoff, 'command terminal observation was late')
                if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > 1024 * 1024:
                    failure = 'COMMAND_OUTPUT_BOUND'
                    raise ValueError(failure)
            except BaseException as original:
                cleanup = []
                if child.poll() is None:
                    try:
                        require(os.getpgid(child.pid) == child.pid, 'held command process group changed')
                        os.killpg(child.pid, signal.SIGKILL)
                    except BaseException as group_error:
                        cleanup.append(type(group_error).__name__)
                        try:
                            child.kill()  # Direct unreaped Popen Child only.
                        except BaseException as direct_error:
                            cleanup.append(type(direct_error).__name__)
                try:
                    child.wait(timeout=2)
                except BaseException as wait_error:
                    cleanup.append(type(wait_error).__name__)
                new(self.work / ('command-%s-%04d.json' % (self.prefix, self.sequence)),
                    {'exit': child.returncode, 'failure': failure or type(original).__name__, 'cleanup_errors': cleanup})
                raise
            out.seek(0); err.seek(0)
            stdout, stderr = out.read(1024 * 1024 + 1), err.read(1024 * 1024 + 1)
            require(len(stdout) + len(stderr) <= 1024 * 1024, 'command output exceeds bound')
            new(self.work / ('command-%s-%04d.json' % (self.prefix, self.sequence)), {'exit': child.returncode,
                'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)})
            require(child.returncode == 0, 'owned operation command failed')
            return stdout.decode()

    def props(self, unit):
        raw = self.call(['systemctl', 'show', unit, '--no-pager', '--property=LoadState,ActiveState,MainPID,InvocationID,FragmentPath,ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,DropInPaths,Type,User,NoNewPrivileges,Unit,NextElapseUSecRealtime,TimersCalendar'])
        return unique(line.split('=', 1) for line in raw.splitlines() if '=' in line)


def check_pin(path, expected):
    require(isinstance(expected, str) and HEX.fullmatch(expected), 'canonical file digest required')
    require(file_hash(path) == expected, 'owned file changed')


def validate_owner(state):
    require(set(state) == {'schema', 'source', 'run_id', 'boot_id', 'controller', 'controller_sha256',
        'python', 'python_sha256', 'controller_dependencies', 'unit_pins', 'guard_sha256', 'client_sha256', 'config_sha256', 'state_sha256',
        'client_unit_pins', 'managed_unit_pins', 'helper_pins', 'quiet_seconds', 'capture', 'collector_identity', 'uplink', 'native_network_sha256', 'baseline', 'deadline_unix'}, 'invalid recovery owner schema')
    require(state['schema'] == 'aegis_fullwide_recovery_owner_v2', 'unsupported recovery owner')
    require(re.fullmatch('[0-9a-f]{40}', state['source']) and re.fullmatch('[a-z0-9]{1,12}', state['run_id']), 'invalid owner identity')
    require(type(state['deadline_unix']) is int and state['deadline_unix'] > 0, 'invalid absolute recovery deadline')
    require(isinstance(state['client_unit_pins'], dict) and str(UNITS / 'aegis-client.service') in state['client_unit_pins'], 'owned client main unit pin missing')
    for path in state['client_unit_pins']:
        require(path in ('/etc/systemd/system/aegis-client.service',
            '/etc/systemd/system/aegis-client.service.d/20-ipv6-tun.conf',
            '/etc/systemd/system/aegis-client.service.d/30-device-egress-guard.conf',
            '/etc/systemd/system/aegis-client.service.d/10-wide.conf'), 'unsupported client unit ownership path')
    require(set(state['unit_pins']) == {'aegis-fw-accept-' + state['run_id'] + suffix for suffix in ('.service', '.timer')}, 'recovery unit ownership mismatch')
    require(isinstance(state['helper_pins'], dict) and set(state['helper_pins']) == {
        '/usr/local/lib/aegis/lib/root-state.sh', '/usr/local/lib/aegis/aegis-wide-disable.sh',
        '/usr/local/lib/aegis/setup-wide-linux-redirect.sh', '/usr/local/lib/aegis/setup-wide-linux-tproxy.sh',
        '/usr/local/lib/aegis/janitor-wide-linux-tproxy.sh'}, 'complete helper inventory required')
    require(type(state['quiet_seconds']) is int and 5 <= state['quiet_seconds'] <= 30, 'finite quiet interval required')
    require(re.fullmatch('[A-Za-z0-9_.-]+', state['uplink']), 'literal uplink required')
    require(HEX.fullmatch(state['native_network_sha256']), 'independent native network pin required')
    require(set(state['collector_identity']) == set(COLLECTOR_KEYS) and re.fullmatch('[1-9][0-9]*', state['collector_identity']['pid']) and re.fullmatch('[0-9]+', state['collector_identity']['start_ticks']) and re.fullmatch('[a-f0-9]{32}', state['collector_identity']['invocation']) and all(type(state['collector_identity'][key]) is int and state['collector_identity'][key] > 0 for key in ('output_device', 'output_inode')), 'typed collector identity required')
    require(state['python'].startswith('/usr/bin/python3') and HEX.fullmatch(state['python_sha256']), 'root interpreter pin required')
    require(set(state['baseline']) == {'guard_state', 'manager', 'client_loaded', 'client_initial_invocation'} and isinstance(state['baseline']['client_loaded'], dict) and (state['baseline']['client_initial_invocation'] == '' or re.fullmatch('[a-f0-9]{32}', state['baseline']['client_initial_invocation'])), 'complete loaded client baseline required')
    return state


def owner_identity(state, same_boot=True):
    validate_owner(state)
    if same_boot:
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == state['boot_id'],
                'reboot not supported by this activation slice; recovery retained')
    require(not any(p.exists() or p.is_symlink() for p in SELECTED), 'selected relay ownership requires explicit selected teardown')
    for path, pin in [(CLIENT, state['client_sha256']), (GUARD, state['guard_sha256']),
                      (CONFIG, state['config_sha256']), (GUARD_STATE, state['state_sha256'])]:
        check_pin(path, pin)
    require(set(state['managed_unit_pins']) == {'/etc/systemd/system/aegis-device-egress-guard.service', '/etc/systemd/system/aegis-wide.service', '/etc/systemd/system/aegis-wide-tun-firewall.service', '/etc/systemd/system/' + state['baseline']['manager'] + '.d/30-aegis-device-guard.conf'}, 'complete touched unit inventory required')
    for path, pin in state['managed_unit_pins'].items():
        if pin is None:
            require(not Path(path).exists() and not Path(path).is_symlink(), 'previously absent touched unit appeared')
        else:
            check_pin(path, pin)
    for path, pin in state['helper_pins'].items():
        require(path in ('/usr/local/lib/aegis/lib/root-state.sh', '/usr/local/lib/aegis/aegis-wide-disable.sh', '/usr/local/lib/aegis/setup-wide-linux-redirect.sh', '/usr/local/lib/aegis/setup-wide-linux-tproxy.sh', '/usr/local/lib/aegis/janitor-wide-linux-tproxy.sh'), 'foreign recovery dependency')
        check_pin(path, pin)
    for path, pin in state['client_unit_pins'].items():
        check_pin(path, pin)
    actual = {str(p) for p in (UNITS / 'aegis-client.service.d').glob('*.conf')}
    require(actual == set(state['client_unit_pins']) - {str(UNITS / 'aegis-client.service')}, 'client drop-in inventory changed')


def units(state, state_path):
    # Fixed public owned paths; systemd substitutions are never admitted.
    for value in (state['python'], state['controller'], str(state_path)):
        require(re.fullmatch('/[A-Za-z0-9_./-]+', value) and '..' not in Path(value).parts, 'unsafe systemd executable path')
    name = 'aegis-fw-accept-' + state['run_id']
    when = datetime.datetime.fromtimestamp(state['deadline_unix'], datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    service = ('[Unit]\nDescription=Owned finite full-wide acceptance recovery\n[Service]\nType=oneshot\nUMask=0077\n'
        'TimeoutStartSec=90\nKillMode=control-group\nRestart=no\nExecStart=' + state['python'] + ' ' + state['controller'] +
        ' recover-owned --state ' + str(state_path) + '\n')
    timer = ('[Unit]\nDescription=Persistent owned full-wide recovery deadline\n[Timer]\nOnCalendar=' + when +
        '\nPersistent=true\nAccuracySec=1s\nUnit=' + name + '.service\n[Install]\nWantedBy=timers.target\n')
    return {name + '.service': service.encode(), name + '.timer': timer.encode()}


def check_units(state, runner):
    for name, pin in state['unit_pins'].items():
        path = UNITS / name
        check_pin(path, pin)
        value = runner.props(name)
        require(value.get('LoadState') == 'loaded' and value.get('FragmentPath') == str(path), 'recovery unit loaded identity differs')
        require(not value.get('DropInPaths'), 'recovery unit gained foreign drop-ins')
        if name.endswith('.service'):
            expected = [state['python'], state['controller'], 'recover-owned', '--state', str(BASE / state['run_id'] / 'state.json')]
            require(value.get('ExecStart', '').count('argv[]=') == 1, 'recovery service has extra loaded commands')
            actual = value.get('ExecStart', '').partition('argv[]=')[2].partition(' ; ')[0]
            require(actual and shlex.split(actual) == expected, 'loaded recovery executable differs')
        if name.endswith('.timer'):
            require(value.get('Unit') == name[:-6] + '.service', 'timer targets foreign recovery')
            ready_path = BASE / state['run_id'] / 'owner-ready.json'
            if ready_path.exists():
                ready = json.loads(private(ready_path), object_pairs_hook=unique)
                require(ready == {'schema': 'aegis_fullwide_timer_ready_v1', 'source': state['source'], 'run_id': state['run_id'], 'boot_id': state['boot_id'], 'timer': name, 'invocation': value.get('InvocationID'), 'deadline_unix': state['deadline_unix']}, 'recovery timer invocation was replaced')
    check_pin(state['controller'], state['controller_sha256'])
    check_pin(state['python'], state['python_sha256'])
    for path, pin in state['controller_dependencies'].items():
        require(Path(path).parent == Path(state['controller']).parent and Path(path).name in ('device_candidate_verify.py', 'device_candidate_acceptance.py'), 'foreign controller dependency')
        check_pin(path, pin)


def timer_ready(state, runner, remaining_operation):
    """Typed D-Bus epoch proves the actual loaded timer's finite future due time."""
    name = 'aegis-fw-accept-' + state['run_id'] + '.timer'
    check_units(state, runner)
    timer = runner.props(name)
    require(timer.get('ActiveState') == 'active' and re.fullmatch('[a-f0-9]{32}', timer.get('InvocationID', '')), 'actual timer is not active with typed invocation')
    encoded = ''.join(character if character.isalnum() else '_%02x' % ord(character) for character in name)
    raw = runner.call(['busctl', '--json=short', 'get-property', 'org.freedesktop.systemd1',
        '/org/freedesktop/systemd1/unit/' + encoded, 'org.freedesktop.systemd1.Timer', 'NextElapseUSecRealtime'])
    value = json.loads(raw, object_pairs_hook=unique)
    # busctl get-property unwraps the variant: the UINT64 data is a scalar.
    require(set(value) == {'type', 'data'} and value['type'] == 't' and type(value['data']) is int, 'typed actual timer epoch unavailable')
    require(value['data'] == state['deadline_unix'] * 1000000, 'actual loaded deadline differs from owned timer')
    require(state['deadline_unix'] > time.time() + remaining_operation + 60, 'actual recovery interval does not reserve operation and cleanup')
    require(runner.props(name) == timer, 'timer identity changed while observing deadline')
    return {'schema': 'aegis_fullwide_timer_ready_v1', 'source': state['source'], 'run_id': state['run_id'],
        'boot_id': state['boot_id'], 'timer': name, 'invocation': timer['InvocationID'], 'deadline_unix': state['deadline_unix']}


def client_semantics(properties, unit_pins):
    """Stable loaded command semantics, excluding per-execution timestamps/status."""
    require(properties.get('LoadState') == 'loaded' and properties.get('FragmentPath') == str(UNITS / 'aegis-client.service'), 'loaded client fragment differs')
    require(properties.get('Type') == 'notify' and properties.get('User') in ('', 'root') and properties.get('NoNewPrivileges') == 'yes', 'loaded client privilege/type differs')
    dropins = shlex.split(properties.get('DropInPaths', ''))
    require(len(dropins) == len(set(dropins)) and set(dropins) == set(unit_pins) - {str(UNITS / 'aegis-client.service')}, 'loaded client drop-in inventory differs')
    result = {key: properties.get(key, '') for key in ('LoadState', 'FragmentPath', 'Type', 'User', 'NoNewPrivileges')}
    result['DropInPaths'] = dropins
    for key in CLIENT_EXEC:
        raw = properties.get(key, '')
        commands = list(re.finditer(r'\{ path=(.*?) ; argv\[\]=(.*?) ; ignore_errors=(yes|no) ; .*? \}', raw))
        require((not raw and not commands) or (commands and raw == ' '.join(item.group(0) for item in commands) and raw.count('argv[]=') == len(commands)), 'unsupported loaded lifecycle command format')
        result[key] = [{'path': item.group(1), 'argv': item.group(2), 'ignore_errors': item.group(3)} for item in commands]
    require(len(result['ExecStart']) == 1, 'loaded client has extra start commands')
    expected = [str(CLIENT), '--config', str(CONFIG), '--runtime-events-jsonl', '/var/log/aegis-client/runtime-events.jsonl']
    require(result['ExecStart'][0]['path'] == str(CLIENT) and shlex.split(result['ExecStart'][0]['argv']) == expected, 'actual loaded signed client command differs')
    return result


def client_receipt(state, properties, identity):
    require(re.fullmatch('[a-f0-9]{32}', properties.get('InvocationID', '')) and identity['sha256'] == state['client_sha256'], 'actual client invocation/executable differs')
    return {'schema': 'aegis_fullwide_client_ready_v1', 'source': state['source'], 'run_id': state['run_id'],
        'boot_id': state['boot_id'], 'unit': 'aegis-client.service', 'invocation': properties['InvocationID'],
        'pid': identity['pid'], 'start_ticks': identity['start_ticks'], 'sha256': identity['sha256']}


def validate_client_ready(state, ready):
    require(set(ready) == {'schema', 'source', 'run_id', 'boot_id', 'unit', 'invocation', 'pid', 'start_ticks', 'sha256'} and ready['schema'] == 'aegis_fullwide_client_ready_v1' and all(ready[key] == state[key] for key in ('source', 'run_id', 'boot_id')) and ready['unit'] == 'aegis-client.service' and ready['sha256'] == state['client_sha256'] and re.fullmatch('[a-f0-9]{32}', ready['invocation']) and re.fullmatch('[1-9][0-9]*', ready['pid']) and re.fullmatch('[0-9]+', ready['start_ticks']), 'client ready custody differs')
    return ready


def bind_started_client(state, runner):
    properties = runner.props('aegis-client.service')
    require(client_semantics(properties, state['client_unit_pins']) == state['baseline']['client_loaded'], 'loaded client changed during activation')
    require(properties.get('ActiveState') == 'active' and re.fullmatch('[1-9][0-9]*', properties.get('MainPID', '')), 'actual activated client is not running')
    identity = process_identity(properties['MainPID'])
    receipt = client_receipt(state, properties, identity)
    require(runner.props('aegis-client.service') == properties and process_identity(identity['pid']) == identity, 'actual client changed during binding')
    new(BASE / state['run_id'] / 'client-ready.json', receipt)
    return receipt


def check_client(state, runner, terminal=False):
    properties = runner.props('aegis-client.service')
    require(client_semantics(properties, state['client_unit_pins']) == state['baseline']['client_loaded'], 'loaded client execution changed')
    ready_path = BASE / state['run_id'] / 'client-ready.json'
    if properties.get('MainPID') == '0' and properties.get('ActiveState') in ('inactive', 'failed'):
        expected_invocation = state['baseline']['client_initial_invocation']
        if ready_path.exists():
            ready = validate_client_ready(state, json.loads(private(ready_path), object_pairs_hook=unique))
            expected_invocation = ready['invocation']
            stopped_path = BASE / state['run_id'] / 'client-stopped.json'
            if stopped_path.exists():
                stopped = json.loads(private(stopped_path), object_pairs_hook=unique)
                require(set(stopped) == {'schema', 'ready', 'terminal_invocation'} and stopped['schema'] == 'aegis_fullwide_client_stopped_v1' and stopped['ready'] == ready and stopped['terminal_invocation'] in ('', ready['invocation']), 'client terminal custody differs')
                expected_invocation = stopped['terminal_invocation']
        require(properties.get('InvocationID', '') == expected_invocation, 'terminal client invocation was replaced or lost')
    else:
        require(not terminal and properties.get('ActiveState') == 'active' and ready_path.exists(), 'running unbound client refuses recovery')
        ready = validate_client_ready(state, json.loads(private(ready_path), object_pairs_hook=unique))
        identity = process_identity(properties.get('MainPID', ''))
        require(ready == client_receipt(state, properties, identity), 'activated client process/invocation was replaced')
        require(process_identity(identity['pid']) == identity, 'client birth changed during owner check')
    require(runner.props('aegis-client.service') == properties, 'loaded client changed during owner check')
    return properties


def bind_stopped_client(state, runner):
    """Called only after exact owned stop and its terminal readback barrier."""
    ready_path = BASE / state['run_id'] / 'client-ready.json'
    if not ready_path.exists():
        check_client(state, runner, terminal=True)
        return
    ready = validate_client_ready(state, json.loads(private(ready_path), object_pairs_hook=unique))
    properties = runner.props('aegis-client.service')
    require(client_semantics(properties, state['client_unit_pins']) == state['baseline']['client_loaded'] and properties.get('MainPID') == '0' and properties.get('ActiveState') in ('inactive', 'failed') and properties.get('InvocationID', '') in ('', ready['invocation']), 'owned stop terminal readback differs')
    require(runner.props('aegis-client.service') == properties, 'client changed across terminal readback')
    record = {'schema': 'aegis_fullwide_client_stopped_v1', 'ready': ready, 'terminal_invocation': properties.get('InvocationID', '')}
    stopped_path = BASE / state['run_id'] / 'client-stopped.json'
    if stopped_path.exists():
        require(json.loads(private(stopped_path), object_pairs_hook=unique) == record, 'existing terminal client receipt differs')
    else:
        new(stopped_path, record)


def observe_quiet(state, runner):
    """Hold full declared interval even when the separately owned collector dies."""
    record = {'quiet_start_unix': time.time(), 'capture': 'COLLECTOR_CONTINUITY_OBSERVED_SCOPED_ONLY'}
    end = time.monotonic() + state['quiet_seconds']
    while True:
        try:
            observed = capture_identity(state['capture'], runner, state['uplink'])
            require({key: observed[key] for key in COLLECTOR_KEYS} == state['collector_identity'], 'collector identity changed')
        except Exception as error:
            if record['capture'] != 'INCOMPLETE':
                record['collector_first_loss_unix'] = time.time()
                record['collector_first_loss_type'] = type(error).__name__
            record['capture'] = 'INCOMPLETE'
        if time.monotonic() >= end:
            break
        time.sleep(max(0, min(0.1, end - time.monotonic())))
    record['quiet_end_unix'] = time.time()
    return record


def bounded_native_model(runner):
    """Same canonical model as device_candidate_acceptance, with held deadlines."""
    state = {}
    for family in ('-4', '-6'):
        for object_name in ('route', 'rule'):
            command = ['ip', '-j', family, object_name, 'show']
            if object_name == 'route':
                command += ['table', 'all']
            rows = json.loads(runner.call(command))
            rows = [{key: value for key, value in row.items() if key != 'expires'} for row in rows]
            state[family + object_name] = sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))
    for utility in ('iptables-save', 'ip6tables-save'):
        state[utility] = '\n'.join(re.sub(r'\[\d+:\d+\]', '[0:0]', line)
            for line in runner.call([utility]).strip().splitlines() if not line.startswith('#'))
    state['forwarding'] = runner.call(['sysctl', '-n', 'net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding', 'net.ipv4.conf.all.route_localnet']).strip()
    resolver = Path('/etc/resolv.conf')
    state['resolver'] = digest(resolver.read_bytes())
    state['resolver_link'] = os.readlink(resolver) if resolver.is_symlink() else None
    require(time.monotonic() < runner.deadline, 'native model observation exceeded recovery deadline')
    return state


def recover(state_path):
    state_path = Path(state_path)
    state = validate_owner(json.loads(private(state_path), object_pairs_hook=unique))
    work = state_path.parent
    require(state_path == BASE / state['run_id'] / 'state.json' and state['controller'] == str(work / 'device_fullwide_acceptance.py'), 'recovery state is not the exact owned run')
    require(set(state['controller_dependencies']) == {str(work / name) for name in ('device_candidate_verify.py', 'device_candidate_acceptance.py')}, 'exact controller dependency inventory required')
    runner = Commands(work, time.monotonic() + 85)
    lock_fd = None
    receipt = {'schema': 'aegis_fullwide_recovery_result_v1', 'source': state['source'], 'run_id': state['run_id'],
               'cleanup': 'INCOMPLETE', 'capture': 'INCOMPLETE', 'native_acceptance': False}
    try:
        lock_fd = os.open(work / 'recovery.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(lock_fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, 'untrusted recovery serialization file')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_units(state, runner)
        owner_identity(state)
        check_client(state, runner)
        # The exact original helper atomically blocks before the client stops.
        runner.call(['/bin/bash', GUARD, 'block'], 15)
        owner_identity(state)
        check_units(state, runner)
        check_client(state, runner)
        runner.call(['systemctl', 'stop', 'aegis-client.service'], 15)
        barrier = runner.props('aegis-client.service')
        require(barrier.get('MainPID') == '0' and barrier.get('ActiveState') in ('inactive', 'failed'), 'quiet interval requires stopped owned client')
        bind_stopped_client(state, runner)
        receipt.update(observe_quiet(state, runner))
        owner_identity(state)
        check_units(state, runner)
        check_client(state, runner, terminal=True)
        runner.call(['/bin/bash', GUARD, 'recover'], 20)
        final = runner.props('aegis-client.service')
        require(final.get('MainPID') == '0' and final.get('ActiveState') in ('inactive', 'failed'), 'owned client has not terminated')
        after = runner.call(['ip', '-j', 'link', 'show'])
        require(not any(row.get('ifname', '').startswith('aegis-tun') for row in json.loads(after)), 'capture interface remains')
        disarmed = private(GUARD_STATE).decode()
        original = state['baseline']['guard_state']
        require(disarmed == original.replace('armed=1\n', 'armed=0\n'), 'original state was not exactly disarmed')
        require(digest(json.dumps(bounded_native_model(runner), sort_keys=True, separators=(',', ':')).encode()) == state['native_network_sha256'], 'independently pinned native route/rule/firewall/resolver/sysctl model differs')
        receipt['cleanup'] = 'ORIGINAL_PROFILE_RECOVERED_SCOPED'
    except BaseException as error:
        receipt['error_type'] = type(error).__name__
        # No fallback teardown, generic purge, name kill or unverified disarm.
    finally:
        try:
            new(work / ('recovery-result-%d.json' % time.time_ns()), receipt)
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
    return receipt


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('phase', choices=('verify-only', 'activate', 'recover-owned'))
    p.add_argument('--state')
    p.add_argument('--spec')
    return p


def main():
    args = parser().parse_args()
    os.umask(0o077)
    if args.phase == 'recover-owned':
        require(sys.platform == 'linux' and os.geteuid() == 0 and args.state, 'owned recovery requires root Linux state')
        result = recover(args.state)
        print(json.dumps({'cleanup': result['cleanup'], 'native_acceptance': False}))
        return 0 if result['cleanup'] == 'ORIGINAL_PROFILE_RECOVERED_SCOPED' else 2
    require(args.spec and not args.state, 'exact independent private spec required')
    spec = json.loads(private(args.spec), object_pairs_hook=unique)
    return activate(spec, verify_only=args.phase == 'verify-only')


def process_identity(pid):
    require(re.fullmatch('[1-9][0-9]*', str(pid)), 'invalid held unit PID')
    def ticks():
        raw = Path('/proc/' + str(pid) + '/stat').read_text()
        return raw.rsplit(')', 1)[1].split()[19]
    before = ticks()
    # Kernel /proc/PID/exe is intentionally a link, unlike administrator inputs.
    with open('/proc/' + str(pid) + '/exe', 'rb') as stream:
        checksum = hashlib.sha256()
        while block := stream.read(65536):
            checksum.update(block)
    require(before == ticks(), 'kernel process identity changed')
    return {'pid': str(pid), 'start_ticks': before, 'sha256': checksum.hexdigest()}


def capture_identity(capture, runner, uplink):
    require(set(capture) == {'unit', 'executable', 'sha256', 'output', 'invocation'}, 'invalid collector contract')
    require(re.fullmatch('[A-Za-z0-9_.-]+\\.service', capture['unit']), 'invalid collector unit')
    require(capture['unit'] not in ('aegis-client.service', 'aegis-device-egress-guard.service'), 'collector is not an independent unit')
    require(capture['executable'] in ('/usr/sbin/tcpdump', '/usr/bin/tcpdump'), 'fixed full-snapshot collector required')
    require(re.fullmatch('/[A-Za-z0-9_./-]+\\.pcap', capture['output']), 'unsafe collector output')
    check_pin(capture['executable'], capture['sha256'])
    properties = runner.props(capture['unit'])
    require(properties.get('ExecStart', '').count('argv[]=') == 1 and not properties.get('DropInPaths'), 'collector gained foreign commands/drop-ins')
    expected = [capture['executable'], '-i', uplink, '-s', '0', '-U', '-Z', 'root', '-w', capture['output']]
    actual = properties.get('ExecStart', '').partition('argv[]=')[2].partition(' ; ')[0]
    require(properties.get('LoadState') == 'loaded' and properties.get('ActiveState') == 'active' and
            properties.get('InvocationID') == capture['invocation'] and capture['invocation'] and
            actual and shlex.split(actual) == expected, 'collector readiness/identity/whole-snapshot args differ')
    pid = properties.get('MainPID', '')
    require(re.fullmatch('[1-9][0-9]*', pid), 'actual collector PID unavailable')
    identity = process_identity(pid)
    require(identity['sha256'] == capture['sha256'], 'actual collector executable differs')
    output_identity = collector_output(capture['output'], pid)
    require(process_identity(pid) == identity, 'collector birth changed during output readiness')
    require(runner.props(capture['unit']) == properties, 'collector properties changed during readiness')
    return {'pid': pid, 'start_ticks': identity['start_ticks'], 'invocation': capture['invocation'], 'observed_unix': time.time(), **output_identity}


def pcap_header(raw):
    """Only fixed public global-header bytes; no packet/payload contents exposed."""
    require(len(raw) == 24, 'collector has not written a complete global header')
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>', b'\xa1\xb2\x3c\x4d': '>'}.get(raw[:4])
    require(endian is not None, 'fixed tcpdump pcap output required')
    major, minor, _, _, snap, _ = struct.unpack(endian + 'HHiiii', raw[4:])
    require((major, minor) == (2, 4) and snap >= 65535, 'collector global header is truncated/unsupported')


def collector_output(path, pid):
    with trusted(path, 64 * 1024 * 1024 * 1024) as output:
        info = os.fstat(output.fileno())
        require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'root-private collector output required')
        pcap_header(output.read(24))
        descriptors = list(Path('/proc/' + pid + '/fd').iterdir())
        require(len(descriptors) <= 64, 'collector descriptor inventory exceeds bound')
        opened = False
        for descriptor in descriptors:
            try:
                held = descriptor.stat()
                if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
                    continue
                rows = Path('/proc/' + pid + '/fdinfo/' + descriptor.name).read_text().splitlines()
                flags = [row.partition(':')[2].strip() for row in rows if row.startswith('flags:')]
                require(len(flags) == 1 and int(flags[0], 8) & 3 in (os.O_WRONLY, os.O_RDWR), 'collector output descriptor is not writable')
                require((descriptor.stat().st_dev, descriptor.stat().st_ino) == (info.st_dev, info.st_ino), 'collector output descriptor changed')
                opened = True
            except FileNotFoundError:
                continue
        require(opened, 'pinned collector has not opened its exact recording output')
        return {'output_device': info.st_dev, 'output_inode': info.st_ino}


def probe(endpoint, kind, family, deadline):
    require(set(endpoint) == {'address', 'port'} and type(endpoint['port']) is int and 0 < endpoint['port'] < 65536, 'invalid controlled endpoint')
    address = ipaddress.ip_address(endpoint['address'])
    require(address.version == (4 if family == socket.AF_INET else 6) and not address.is_unspecified and not address.is_multicast, 'controlled endpoint family differs')
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'probe whole deadline expired')
    request = os.urandom(32)
    if kind == 'dns':
        require(endpoint['port'] == 53, 'DNS probe requires port53')
        request = request[:2] + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
    with socket.socket(family, socket.SOCK_STREAM if kind == 'tcp' else socket.SOCK_DGRAM) as channel:
        def io_deadline():
            left = deadline - time.monotonic()
            require(left > 0, 'probe whole deadline expired before I/O')
            channel.settimeout(min(8, left))
        io_deadline()
        channel.connect((str(address), endpoint['port']))
        if kind == 'tcp':
            io_deadline()
            channel.sendall(request)
            response = b''
            while len(response) < len(request):
                io_deadline()
                block = channel.recv(len(request) - len(response))
                require(block, 'controlled TCP response closed early')
                response += block
        else:
            io_deadline()
            channel.send(request)
            io_deadline()
            response = channel.recv(4096)
    require(time.monotonic() < deadline, 'probe completed after whole deadline')
    if kind == 'dns':
        require(len(response) >= 12 and response[:2] == request[:2] and response[2] & 128 and
                response[3] & 15 == 0 and int.from_bytes(response[6:8], 'big') > 0, 'DNS response invalid')
    else:
        require(response == request, 'controlled exact echo differs')
    return {'kind': kind, 'family': address.version, 'response_bytes': len(response)}


def activate(spec, verify_only=False):
    require(set(spec) == {'schema', 'release', 'run_id', 'vm_marker', 'os_id', 'bundle_dir',
        'profile_sha256', 'config_sha256', 'guard_state_sha256', 'native_network_sha256', 'client_loaded_sha256', 'client_unit_pins', 'managed_unit_pins', 'capture',
        'probes', 'operation_seconds', 'quiet_seconds'}, 'invalid activation spec')
    require(spec['schema'] == 'aegis_installed_fullwide_activation_spec_v1', 'unsupported activation spec')
    require(re.fullmatch('[a-z0-9]{1,12}', spec['run_id']), 'fresh short run ID required')
    require(type(spec['operation_seconds']) is int and 60 <= spec['operation_seconds'] <= 180 and
            type(spec['quiet_seconds']) is int and 5 <= spec['quiet_seconds'] <= 30, 'bounded public operation/quiet intervals required')
    release = spec['release']
    keys = {'client_manifest', 'client_manifest_sha256', 'operator_manifest', 'operator_manifest_sha256',
        'bootstrap', 'public_key', 'public_key_sha256', 'source', 'tag', 'authority', 'minimum_sequence', 'arch', 'client_bundle_schema'}
    require(set(release) == keys and release['client_bundle_schema'] in ('aegis_client_release_bundle_manifest_v2', 'aegis_client_release_bundle_manifest_v3'), 'exact signed v2/v3 release inputs required')
    verified = verify(SimpleNamespace(**release))
    if verify_only:
        print(json.dumps({'signed_source': verified['source_sha'], 'verdict': 'SIGNED_INPUTS_VERIFIED_ONLY', 'native_acceptance': False}))
        return 0
    host = guest_guard(SimpleNamespace(**release, vm_marker=spec['vm_marker'], run_id=spec['run_id'], os_id=spec['os_id']), clean=False)
    require(shutil.which('busctl'), 'actual typed systemd timer observation requires installed busctl')
    require(sys.executable.startswith('/usr/bin/python3'), 'system Python required for persistent recovery')
    require(not any(x.exists() or x.is_symlink() for x in SELECTED), 'selected relay profile is outside this original-profile slice')
    profile_path = Path(spec['bundle_dir']) / 'profile.json'
    check_pin(profile_path, spec['profile_sha256'])
    profile = load(profile_path)
    require(profile.get('schema') in ('aegis_device_bundle_v2', 'aegis_device_bundle_v3', 'aegis_device_bundle_v4') and
            profile.get('product_mode') == 'full-wide-tun' and profile.get('udp') is True, 'typed full-wide UDP public profile required')
    pins = verified['client']['file_hashes']
    check_pin(CLIENT, verified['client']['binary_sha256'])
    check_pin(GUARD, pins['scripts/aegis-device-egress-guard.sh'])
    check_pin(CONFIG, spec['config_sha256'])
    check_pin(GUARD_STATE, spec['guard_state_sha256'])
    guard_raw = private(GUARD_STATE).decode()
    fields = unique(line.split('=', 1) for line in guard_raw.splitlines() if '=' in line)
    require(fields.get('schema') == 'aegis_device_guard_v2' and fields.get('armed') == '1' and fields.get('service') == 'aegis-client.service', 'exact armed original v2 guard required')
    require(fields.get('manager') in ('systemd-networkd.service', 'NetworkManager.service') and re.fullmatch('[A-Za-z0-9_.-]+', fields.get('uplink', '')), 'supported literal managed host required')
    require(not Path(str(GUARD_STATE) + '.client-binding').exists() and not Path(str(GUARD_STATE) + '.client-binding').is_symlink(), 'client must already be BLOCKED without a grant')
    config = tomllib.loads(private(CONFIG).decode())
    ingress = config.get('ingress', {}); wide = ingress.get('wide', {}); relay = config.get('relay', {})
    require(config.get('mode') == 'relay' and ingress.get('primary') == 'wide' and ingress.get('allow_fallback') is False and wide.get('enabled') is True and wide.get('ipv6_tun_carried') is True and wide.get('udp_redirect_port') == 15081 and wide.get('capture_dns') is True and relay.get('inner_tls') and relay.get('outer_geneva') is None, 'installed original full-wide inner TLS capture differs')
    require(set(spec['probes']) == {'tcp4', 'tcp6', 'udp4', 'udp6', 'dns4', 'dns6'}, 'complete controlled dual-stack probe matrix required')
    if not BASE.exists():
        BASE.mkdir(mode=0o700)
    require(BASE.lstat().st_uid == 0 and stat.S_IMODE(BASE.lstat().st_mode) == 0o700 and not BASE.is_symlink(), 'untrusted owned controller base')
    work = BASE / spec['run_id']
    work.mkdir(mode=0o700)  # Existing failed attempts cannot be reused.
    deadline = time.monotonic() + spec['operation_seconds']
    runner = Commands(work, deadline)
    result = {'schema': 'aegis_installed_fullwide_activation_result_v1', 'source': release['source'], 'run_id': spec['run_id'],
        'operation': 'FAILED', 'capture': 'INCOMPLETE', 'cleanup': 'INCOMPLETE', 'native_acceptance': False,
        'scope': 'already-installed original-profile activation/recovery; install/reboot/pool revocation/independent acceptance not covered'}
    state = None
    try:
        unit = runner.props('aegis-client.service')
        require(unit.get('LoadState') == 'loaded' and unit.get('Type') == 'notify' and unit.get('User') in ('', 'root') and unit.get('NoNewPrivileges') == 'yes' and unit.get('MainPID') == '0' and unit.get('ActiveState') in ('inactive', 'failed'), 'exact installed client must be stopped before activation')
        require(unit.get('ExecStart', '').count('argv[]=') == 1, 'loaded client has extra commands')
        actual_argv = unit.get('ExecStart', '').partition('argv[]=')[2].partition(' ; ')[0]
        expected_argv = [str(CLIENT), '--config', str(CONFIG), '--runtime-events-jsonl', '/var/log/aegis-client/runtime-events.jsonl']
        require(actual_argv and shlex.split(actual_argv) == expected_argv, 'actual loaded signed client command differs')
        loaded = client_semantics(unit, spec['client_unit_pins'])
        require(HEX.fullmatch(spec['client_loaded_sha256']) and digest(json.dumps(loaded, sort_keys=True, separators=(',', ':')).encode()) == spec['client_loaded_sha256'], 'independently pinned full loaded client semantics differ')
        helpers = {}
        for name in ('lib/root-state.sh', 'aegis-wide-disable.sh', 'setup-wide-linux-redirect.sh', 'setup-wide-linux-tproxy.sh', 'janitor-wide-linux-tproxy.sh'):
            path = '/usr/local/lib/aegis/' + name
            helpers[path] = pins['scripts/' + name]
            check_pin(path, helpers[path])
        controller = Path(__file__).resolve()
        dependencies = {}
        for filename in ('device_fullwide_acceptance.py', 'device_candidate_verify.py', 'device_candidate_acceptance.py'):
            raw = read(controller.parent / filename, 256 * 1024)
            new(work / filename, raw)
            if filename != 'device_fullwide_acceptance.py':
                dependencies[str(work / filename)] = digest(raw)
        collector_initial = capture_identity(spec['capture'], runner, fields['uplink'])
        state = {'schema': 'aegis_fullwide_recovery_owner_v2', 'source': release['source'], 'run_id': spec['run_id'],
            'boot_id': host['boot_id'], 'controller': str(work / 'device_fullwide_acceptance.py'),
            'controller_sha256': file_hash(work / 'device_fullwide_acceptance.py'), 'controller_dependencies': dependencies,
            'python': str(Path(sys.executable).resolve()), 'python_sha256': file_hash(Path(sys.executable).resolve()),
            'unit_pins': {}, 'guard_sha256': pins['scripts/aegis-device-egress-guard.sh'],
            'client_sha256': verified['client']['binary_sha256'], 'config_sha256': spec['config_sha256'],
            'state_sha256': spec['guard_state_sha256'], 'client_unit_pins': spec['client_unit_pins'], 'managed_unit_pins': spec['managed_unit_pins'], 'helper_pins': helpers,
            'capture': spec['capture'], 'collector_identity': {key: collector_initial[key] for key in COLLECTOR_KEYS}, 'quiet_seconds': spec['quiet_seconds'], 'uplink': fields['uplink'],
            'native_network_sha256': spec['native_network_sha256'],
            'baseline': {'guard_state': guard_raw, 'manager': fields['manager'], 'client_loaded': loaded, 'client_initial_invocation': unit.get('InvocationID', '')},
            'deadline_unix': int(time.time()) + spec['operation_seconds'] + 90}
        name = 'aegis-fw-accept-' + spec['run_id']
        generated = units(state, work / 'state.json')
        state['unit_pins'] = {key: digest(value) for key, value in generated.items()}
        validate_owner(state)
        owner_identity(state)
        for key in generated:
            require(runner.props(key).get('LoadState') == 'not-found', 'fresh recovery unit name is occupied')
        new(work / 'recovery.lock', b'')
        new(work / 'state.json', state)
        for key, value in generated.items():
            new(UNITS / key, value, 0o644)
        runner.call(['systemctl', 'daemon-reload'])
        runner.call(['systemctl', 'enable', '--now', name + '.timer'])
        check_units(state, runner)
        timer_observed = timer_ready(state, runner, max(0, deadline - time.monotonic()))
        new(work / 'owner-ready.json', timer_observed)
        check_client(state, runner, terminal=True)
        ready = capture_identity(spec['capture'], runner, fields['uplink'])
        require({key: ready[key] for key in COLLECTOR_KEYS} == state['collector_identity'], 'collector changed while recovery owner was armed')
        result['collector_ready'] = ready
        result['record_interval_start_unix'] = time.time()
        runner.call([CLIENT, '--config', CONFIG, '--validate-config'])
        owner_identity(state)
        check_units(state, runner)
        check_client(state, runner, terminal=True)
        runner.call(['/bin/bash', GUARD, 'block'], 15)
        owner_identity(state)
        check_units(state, runner)
        check_client(state, runner, terminal=True)
        runner.call(['systemctl', 'start', 'aegis-client.service'], 45)
        result['client_ready'] = bind_started_client(state, runner)
        running = runner.props('aegis-client.service')
        require(running.get('ActiveState') == 'active' and re.fullmatch('[1-9][0-9]*', running.get('MainPID', '')), 'client did not become active')
        require(process_identity(running['MainPID'])['sha256'] == state['client_sha256'], 'actual running client bytes differ')
        result['probes'] = []
        for key, endpoint in spec['probes'].items():
            require(capture_identity(spec['capture'], runner, fields['uplink'])['pid'] == ready['pid'], 'collector changed during recording')
            result['probes'].append(probe(endpoint, key[:-1], socket.AF_INET if key[-1] == '4' else socket.AF_INET6, deadline))
        result['operation'] = 'CONTROLLED_FULLWIDE_PROBES_SCOPED_PASS'
    except BaseException as error:
        result['error_type'] = type(error).__name__
    finally:
        if state is not None and (work / 'state.json').exists():
            try:
                cleanup = recover(work / 'state.json')
                result['cleanup'] = cleanup['cleanup']
                result['capture'] = cleanup['capture']
                result['quiet_start_unix'] = cleanup.get('quiet_start_unix')
                result['quiet_end_unix'] = cleanup.get('quiet_end_unix')
                result['record_interval_end_unix'] = time.time()
                if cleanup['capture'] != 'COLLECTOR_CONTINUITY_OBSERVED_SCOPED_ONLY':
                    result['operation'] = 'FAILED'
                if cleanup['cleanup'] == 'ORIGINAL_PROFILE_RECOVERED_SCOPED':
                    finish = Commands(work, time.monotonic() + 20)
                    finish.sequence = 10000
                    check_units(state, finish)
                    for key in state['unit_pins']:
                        finish.call(['systemctl', 'disable', '--now', key], 8)
                        value = finish.props(key)
                        require(value.get('MainPID') == '0' and value.get('ActiveState') == 'inactive', 'owned recovery unit not terminal')
                    result['guard_disarm'] = 'OWNED_TIMER_AND_SERVICE_TERMINAL'
            except BaseException as error:
                result['cleanup_error_type'] = type(error).__name__
                result['guard_disarm'] = 'INCOMPLETE'
        new(work / 'result.json', result)
    print(json.dumps({key: result[key] for key in ('operation', 'capture', 'cleanup', 'native_acceptance')}))
    return 0 if result['operation'] == 'CONTROLLED_FULLWIDE_PROBES_SCOPED_PASS' and result['capture'] == 'COLLECTOR_CONTINUITY_OBSERVED_SCOPED_ONLY' and result['cleanup'] == 'ORIGINAL_PROFILE_RECOVERED_SCOPED' and result.get('guard_disarm') == 'OWNED_TIMER_AND_SERVICE_TERMINAL' else 2


if __name__ == '__main__':
    raise SystemExit(main())
