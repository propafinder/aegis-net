"""Bounded diagnostic retention only; no acceptance or network mutation.

One fixed read-only nft query is permitted only inside a freshly verified owned
inner net/mount namespace after the attempt has already failed.
"""
import hashlib
import ctypes
import base64
import json
import os
from pathlib import Path
import re
import select
import stat
import signal
import subprocess
import functools
import sys
import time

STDERR_LIMIT = 65536
METADATA_LIMIT = 1048576
PHASES = {'setup_intent', 'installed_guard_authorized', 'setup_failed',
          'ready', 'readiness_failed', 'worker_terminal', 'runtime_fault',
          'fail_closed', 'rules_arm_intent', 'route_epoch_refreshed',
          'flow_arm_intent', 'flow_arm_confirmed', 'flow_retire_intent',
          'linger_failed', 'flow_delete_intent', 'flow_retired', 'quiesced',
          'worker_failed', 'native_command_failed', 'owned_nft_epoch',
          'owned_nft_delete_epoch', 'route_notification_refused',
          'owned_existing_local32_proven', 'packet_worker_stopped',
          'native_teardown_checked', 'native_release_authorized',
          'native_release_deadline_failed'}

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def sha(body):
    return hashlib.sha256(body).hexdigest()

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate diagnostic JSON field')
        result[key] = value
    return result

def parse(body):
    require(len(body) <= METADATA_LIMIT, 'diagnostic JSON bound')
    return json.loads(body, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(RuntimeError('nonfinite JSON')))

def own_directory(path):
    value = Path(path).lstat()
    require(stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid()
            and value.st_mode & 0o777 == 0o700, 'owned diagnostic directory refused')
    return value

def write_exclusive(root, name, body):
    require(type(body) is bytes and len(body) <= METADATA_LIMIT, 'retained diagnostic bound')
    require(type(name) is str and re.fullmatch('[a-z0-9.-]+', name), 'flat diagnostic name refused')
    before = own_directory(root)
    fd = os.open(Path(root)/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(body)
        while view:
            count = os.write(fd, view)
            require(count > 0, 'diagnostic write stalled')
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    after = own_directory(root)
    require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), 'diagnostic directory changed')
    return {'name': name, 'bytes': len(body), 'sha256': sha(body)}

def write_json(root, name, value):
    return write_exclusive(root, name, json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())

def read_owned(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and before.st_size <= limit
                and before.st_mode & 0o022 == 0, 'owned bounded diagnostic file refused')
        body = bytearray()
        while len(body) <= limit:
            part = os.read(fd, min(65536, limit+1-len(body)))
            if not part:
                break
            body.extend(part)
        after = os.fstat(fd)
        require(len(body) == before.st_size <= limit
                and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'diagnostic file changed or exceeds bound')
        current = Path(path).lstat()
        require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino), 'diagnostic path substitution')
        return bytes(body)
    finally:
        os.close(fd)

def retain_process_stderr(root, process, label):
    """Called only after this owned child's checked wait, never an unbounded read.

    An oversized/incomplete stream is retained as a truncated diagnostic and
    explicitly fails completeness. It cannot become runtime acceptance.
    """
    require(re.fullmatch('probe-[0-2]|peer', label), 'owned consumer label')
    require(process.poll() is not None and process.stderr is not None, 'consumer must be terminal before diagnostic drain')
    fd = process.stderr.fileno()
    os.set_blocking(fd, False)
    body = bytearray()
    eof = False
    until = time.monotonic()+1
    try:
        while len(body) <= STDERR_LIMIT and time.monotonic() < until:
            if not select.select([fd], [], [], max(0, until-time.monotonic()))[0]:
                break
            part = os.read(fd, min(8192, STDERR_LIMIT+1-len(body)))
            if not part:
                eof = True
                break
            body.extend(part)
    finally:
        process.stderr.close()
    oversized = len(body) > STDERR_LIMIT
    record = write_exclusive(root, label+'.stderr', bytes(body[:STDERR_LIMIT]))
    record.update(exit_code=process.returncode, eof_observed=eof,
                  truncated_oversize=oversized, incomplete_deadline=not eof and not oversized,
                  complete=eof and not oversized, scope='controlled child stderr only; no runtime acceptance')
    write_json(root, label+'-diagnostic.json', record)
    return record

def retain_completed_stderr(root, label, body, exit_code):
    """Retain an already returned terminal stderr value with a strict disk cap.

    This does not claim to bound the caller's existing communicate() allocation.
    It avoids losing stderr when that existing acceptance check rejects output.
    """
    require(re.fullmatch('probe-[0-2]|peer', label) and type(body) is bytes
            and type(exit_code) is int, 'completed controlled child frame')
    record = write_exclusive(root, label+'.stderr', body[:STDERR_LIMIT])
    record.update(exit_code=exit_code, eof_observed=True, truncated_oversize=len(body)>STDERR_LIMIT,
                  incomplete_deadline=False, complete=len(body)<=STDERR_LIMIT,
                  scope='existing communicate result; bounded retention only; no runtime acceptance')
    write_json(root, label+'-diagnostic.json', record)
    return record

def journal_snapshot(directory):
    directory = Path(directory)
    if not directory.exists():
        require(not directory.is_symlink(), 'native evidence dangling symlink')
        return {'entries': [], 'directory_observed': False, 'complete': True}
    parent = own_directory(directory)
    instances = []
    for instance in directory.iterdir():
        instances.append(instance)
        require(len(instances) <= 3, 'native instance inventory bound')
    entries, total = [], 0
    for instance in sorted(instances):
        require(re.fullmatch('[0-9a-f]{8}', instance.name), 'native instance name refused')
        own_directory(instance)
        records = []
        for path in instance.iterdir():
            records.append(path)
            require(len(records) <= 2048-len(entries), 'native record inventory bound')
        for path in sorted(records):
            match = re.fullmatch(r'([0-9]{8})_([a-z0-9_]+)\.json', path.name)
            require(match is not None and match[2] in PHASES, 'unknown native diagnostic member')
            body = read_owned(path, 65536)
            total += len(body)
            require(total <= METADATA_LIMIT, 'total native journal byte bound')
            value = parse(body)
            require(type(value) is dict, 'native journal object required')
            entries.append({'instance': instance.name, 'name': path.name, 'value': value, 'sha256': sha(body)})
    after = own_directory(directory)
    require((parent.st_dev, parent.st_ino) == (after.st_dev, after.st_ino), 'native evidence parent changed')
    result = {'entries': entries, 'directory_observed': True, 'complete': True, 'total_member_bytes': total}
    require(len(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()) <= METADATA_LIMIT,
            'native journal retained encoding bound')
    return result

def public_host_snapshot(root, label, ip, nft):
    require(label in ('before', 'after'), 'host observation phase refused')
    require(type(parse(ip)) is list and type(parse(nft)) is dict, 'public host JSON shape')
    return {'ip': write_exclusive(root, 'host-ip-'+label+'.json', ip),
            'nft': write_exclusive(root, 'host-nft-'+label+'.json', nft)}

def host_difference(before_ip, before_nft, after_ip, after_nft):
    paths = []
    def differences(left, right, path):
        if len(paths) >= 64:
            return
        if type(left) != type(right):
            paths.append(path)
        elif type(left) is dict:
            for key in sorted(set(left)|set(right)):
                if key not in left or key not in right:
                    paths.append(path+'/'+key)
                else:
                    differences(left[key], right[key], path+'/'+key)
        elif type(left) is list:
            if len(left) != len(right):
                paths.append(path+'/length')
            for index, (a, b) in enumerate(zip(left, right)):
                differences(a, b, path+'/'+str(index))
        elif left != right:
            paths.append(path)
    for name, left, right in [('ip', before_ip, after_ip), ('nft', before_nft, after_nft)]:
        differences(parse(left), parse(right), '/'+name)
    return {'exact_raw_ip_equal': before_ip == after_ip, 'exact_raw_nft_equal': before_nft == after_nft,
            'changed_JSON_paths': paths[:64], 'path_inventory_may_be_truncated': len(paths) >= 64,
            'acceptance_normalization_performed': False,
            'scope': 'bounded public host readback only; inspect values offline; exact acceptance unchanged'}


NFT_FAILURE_ARGV = ('/usr/sbin/nft', '-j', '-n', '-y', '-p', 'list', 'ruleset')
NFT_FAILURE_STDOUT_LIMIT = 262144
NFT_FAILURE_TIMEOUT = 3

_FAILURE_LIBC = ctypes.CDLL(None, use_errno=True)

def _failure_query_parent_death(parent, expected_namespace):
    require(_FAILURE_LIBC.prctl(1, signal.SIGKILL) == 0 and os.getppid() == parent,
            'NFT diagnostic parent-death binding failed')
    require(os.readlink('/proc/self/ns/net') == expected_namespace['net']
            and os.readlink('/proc/self/ns/mnt') == expected_namespace['mount'],
            'NFT diagnostic executing-child namespace changed')

def _nft_failure_tool_pin(deadline):
    path = Path('/usr/sbin/nft')
    require(path.resolve(strict=True) == path, 'fixed NFT diagnostic helper must be canonical')
    for parent in path.parents:
        meta = parent.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and meta.st_mode & 0o022 == 0,
                'NFT diagnostic helper ancestor not root protected')
    meta = path.lstat()
    require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_mode & 0o022 == 0
            and meta.st_nlink == 1 and meta.st_size <= 8*1048576,
            'fixed NFT diagnostic helper not protected regular root file')
    require(time.monotonic() < deadline, 'NFT diagnostic helper pin deadline')
    raw = read_owned(path,8*1048576)
    after = path.lstat()
    require((meta.st_dev,meta.st_ino,meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns)
            == (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            and time.monotonic() < deadline, 'NFT diagnostic helper changed or pin deadline')
    return {'path':str(path),'sha256':sha(raw),'device':meta.st_dev,'inode':meta.st_ino}

def _bounded_failure_query(argv, expected_namespace, namespace_readlink=None):
    """Fixed read-only command, no shell/input, bounded nonblocking owned pipes.

    This is diagnostics only. Query failure or interrupted/oversized output is
    retained explicitly, never converted into a ruleset/operation acceptance.
    Failure cleanup signals only our still-unreaped exact child process group.
    """
    require(sys.platform == 'linux' and tuple(argv) == NFT_FAILURE_ARGV, 'only fixed read-only Linux NFT diagnostic query')
    readlink = os.readlink if namespace_readlink is None else namespace_readlink
    child = None
    pipes = []
    stdout, stderr = bytearray(), bytearray()
    ended = [False, False]
    code = None
    failure = None
    failure_reason = None
    phase = 'pre_spawn'
    started = time.monotonic()
    tool_pin = None
    tool_after_verified = False
    cleanup_errors = []
    pipes_closed = True
    try:
        tool_pin = _nft_failure_tool_pin(started+NFT_FAILURE_TIMEOUT)
        require(readlink('/proc/self/ns/net') == expected_namespace['net']
                and readlink('/proc/self/ns/mnt') == expected_namespace['mount'],
                'NFT diagnostic pre-spawn namespace changed')
        phase = 'spawn'
        child = subprocess.Popen(list(NFT_FAILURE_ARGV), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True,
                                 preexec_fn=functools.partial(_failure_query_parent_death,os.getpid(),expected_namespace))
        pipes = [child.stdout, child.stderr]
        require(all(p is not None for p in pipes), 'NFT diagnostic pipe absent')
        for pipe in pipes:
            os.set_blocking(pipe.fileno(), False)
        until = started+NFT_FAILURE_TIMEOUT
        phase = 'read_output'
        while not all(ended):
            remaining = until-time.monotonic()
            if remaining <= 0:
                failure_reason = 'deadline'
                raise TimeoutError('NFT diagnostic total deadline')
            active = [p for i,p in enumerate(pipes) if not ended[i]]
            readable, _, _ = select.select(active, [], [], min(remaining, 0.05))
            for pipe in readable:
                index = pipes.index(pipe)
                body = stdout if index == 0 else stderr
                limit = NFT_FAILURE_STDOUT_LIMIT if index == 0 else STDERR_LIMIT
                piece = os.read(pipe.fileno(), min(8192, limit+1-len(body)))
                if not piece:
                    ended[index] = True
                else:
                    body.extend(piece)
                    if len(body) > limit:
                        failure_reason = 'stdout_oversize' if index == 0 else 'stderr_oversize'
                        raise OverflowError('NFT diagnostic output exceeded bound')
        remaining = until-time.monotonic()
        phase = 'terminal_wait'
        if remaining <= 0:
            failure_reason = 'deadline'
            raise TimeoutError('NFT diagnostic terminal deadline')
        code = child.wait(timeout=remaining)
        phase = 'tool_pin_after'
        require(_nft_failure_tool_pin(until) == tool_pin, 'NFT diagnostic helper changed after query')
        tool_after_verified = True
    except BaseException as error:
        failure = type(error).__name__
        failure_reason = failure_reason or ('interrupted' if isinstance(error,(KeyboardInterrupt,SystemExit)) else 'transport_'+phase)
    finally:
        def cleanup_error(phase, error):
            cleanup_errors.append({'phase':phase,'type':type(error).__name__})
        if child is not None and child.returncode is None:
            # This exact child remains unreaped, so its PID cannot be reused.
            group_owned = False
            try:
                group_owned = os.getpgid(child.pid) == child.pid
            except ProcessLookupError:
                pass
            except BaseException as error:
                cleanup_error('group_identity',error)
            if group_owned:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    cleanup_error('group_signal',error)
            # Always attempt the exact owned child as well: group inspection or
            # signaling may have failed; no unrelated PID/group is adopted.
            try:
                child.kill()
            except ProcessLookupError:
                pass
            except BaseException as error:
                cleanup_error('child_signal',error)
            try:
                code = child.wait(timeout=0.25)
            except BaseException as error:
                cleanup_error('child_wait',error)
        for index, pipe in enumerate(pipes):
            if pipe is not None:
                try:
                    pipe.close()
                except BaseException as error:
                    cleanup_error('pipe_close_'+str(index),error)
                    pipes_closed = False
        cleanup_unconfirmed = (child is not None and child.returncode is None) or not pipes_closed
        if cleanup_unconfirmed:
            failure = failure or 'CleanupUnconfirmed'
            failure_reason = failure_reason or 'cleanup_unconfirmed'
    return {'stdout':bytes(stdout[:NFT_FAILURE_STDOUT_LIMIT]),
            'stderr':bytes(stderr[:STDERR_LIMIT]), 'returncode':code,
            'stdout_eof':ended[0], 'stderr_eof':ended[1],
            'stdout_oversize':len(stdout)>NFT_FAILURE_STDOUT_LIMIT,
            'stderr_oversize':len(stderr)>STDERR_LIMIT,
            'failure_type':failure,'failure_reason':failure_reason,
            'tool_pin':tool_pin,'tool_pin_verified_after':tool_after_verified,
            'owned_child_terminal':child is not None and child.returncode is not None,
            'cleanup_errors':cleanup_errors,'cleanup_unconfirmed':cleanup_unconfirmed}

class InnerNftNamespaceRefusal(RuntimeError):
    """Diagnostic-only current namespace mismatched the verified inner pair."""

def retain_failed_inner_ruleset(root, host_netns, host_mntns, expected_netns, expected_mntns, *, runner=None, namespace_readlink=None):
    """Failure-only public NFT readback before namespace cleanup, never a gate.

    Does not read request/PKI/input files or any existing host namespace. Namespace
    drift refuses the operation; command argv is exactly the fixed query above.
    Output remains private until the explicit metadata-only export allowlist.
    """
    own_directory(root)
    destination = Path(root)/'inner-nft-failure.json'
    require(not destination.exists() and not destination.is_symlink(), 'new failure-only NFT diagnostic output required')
    readlink = os.readlink if namespace_readlink is None else namespace_readlink
    def namespace_pair():
        net = readlink('/proc/self/ns/net')
        mount = readlink('/proc/self/ns/mnt')
        if not (type(host_netns) is str and type(host_mntns) is str
                and re.fullmatch(r'net:\[[0-9]+\]',host_netns)
                and re.fullmatch(r'mnt:\[[0-9]+\]',host_mntns)
                and re.fullmatch(r'net:\[[0-9]+\]',net)
                and re.fullmatch(r'mnt:\[[0-9]+\]',mount)
                and net != host_netns and mount != host_mntns
                and net == expected_netns and mount == expected_mntns):
            raise InnerNftNamespaceRefusal('NFT failure diagnostic requires original fresh inner namespaces')
        return {'net':net,'mount':mount}
    before = namespace_pair()
    observed = _bounded_failure_query(NFT_FAILURE_ARGV,before,readlink) if runner is None else runner(NFT_FAILURE_ARGV)
    require(type(observed) is dict and set(observed) == {'stdout','stderr','returncode','stdout_eof','stderr_eof','stdout_oversize','stderr_oversize','failure_type','failure_reason','tool_pin','tool_pin_verified_after','owned_child_terminal','cleanup_errors','cleanup_unconfirmed'}, 'NFT diagnostic transport schema')
    stdout, stderr = observed['stdout'], observed['stderr']
    require(type(stdout) is bytes and len(stdout)<=NFT_FAILURE_STDOUT_LIMIT
            and type(stderr) is bytes and len(stderr)<=STDERR_LIMIT
            and (observed['returncode'] is None or type(observed['returncode']) is int)
            and (observed['failure_type'] is None or type(observed['failure_type']) is str)
            and (observed['failure_reason'] is None or type(observed['failure_reason']) is str)
            and (observed['tool_pin'] is None or type(observed['tool_pin']) is dict)
            and all(type(observed[k]) is bool for k in ('stdout_eof','stderr_eof','stdout_oversize','stderr_oversize','tool_pin_verified_after','owned_child_terminal','cleanup_unconfirmed'))
            and type(observed['cleanup_errors']) is list and len(observed['cleanup_errors'])<=5
            and all(type(row) is dict and set(row)=={'phase','type'}
                    and type(row['phase']) is str and len(row['phase'])<=32
                    and type(row['type']) is str and len(row['type'])<=64
                    for row in observed['cleanup_errors']),
            'NFT diagnostic typed bounds')
    after = namespace_pair()
    if before != after:
        raise InnerNftNamespaceRefusal('NFT failure diagnostic namespace changed')
    parse_error = None
    try:
        value = parse(stdout)
        schema = type(value) is dict and set(value)=={'nftables'} and type(value['nftables']) is list
    except (RuntimeError, UnicodeError, ValueError) as error:
        schema = False
        parse_error = type(error).__name__
    result = {'scope':'failed attempt owned-inner NFT readback only; no normalization or acceptance',
              'namespace':before,'argv':list(NFT_FAILURE_ARGV),
              'stdout_sha256':sha(stdout),'stdout_bytes':len(stdout),'stdout_base64':base64.b64encode(stdout).decode('ascii'),
              'stderr_sha256':sha(stderr),'stderr_bytes':len(stderr),'stderr_prefix_hex':stderr.hex(),
              'ruleset_schema_observed':schema,'json_parse_error_type':parse_error,
              **{k:v for k,v in observed.items() if k not in ('stdout','stderr')},
              'native_accepted':False,'host_query_performed':False,'rule_mutation_performed':False,
              'raw_frames_or_private_files_read':False}
    write_json(root,'inner-nft-failure.json',result)
    return result

# Future configuration gate, distinct from host_difference() raw diagnostics.
# No raw file, diagnostic equality or historical acceptance is rewritten.
HOST_CONFIGURATION_SCHEMA = 'aegis.native.host-configuration.v1'
HOST_CONFIGURATION_NODE_LIMIT = 65536
HOST_CONFIGURATION_DEPTH_LIMIT = 64
HOST_CONFIGURATION_COUNTER_LIMIT = 2048


def _host_configuration_json(body, kind):
    require(type(body) is bytes, 'host configuration requires exact raw bytes')
    value = parse(body)
    require((kind == 'ip' and type(value) is list)
            or (kind == 'nft' and type(value) is dict and set(value) == {'nftables'}
                and type(value['nftables']) is list), 'host configuration JSON shape')
    count = 0
    def bounded(item, depth):
        nonlocal count
        count += 1
        require(count <= HOST_CONFIGURATION_NODE_LIMIT and depth <= HOST_CONFIGURATION_DEPTH_LIMIT,
                'host configuration structural bound')
        require(type(item) in (dict, list, str, int, bool, type(None)),
                'host configuration scalar type refused')
        if type(item) is int:
            require(-(1 << 63) <= item <= (1 << 64)-1, 'host configuration integer bound')
        elif type(item) is dict:
            require(all(type(key) is str for key in item), 'host configuration object key')
            for child in item.values(): bounded(child, depth+1)
        elif type(item) is list:
            for child in item: bounded(child, depth+1)
    bounded(value, 0)
    return value


def host_configuration_comparison(before_ip, before_nft, after_ip, after_nft, namespaces):
    """Full JSON comparison; only existing anonymous counter state may grow.

    Every list position, object key and other typed value remains exact. We do
    not strip counters, metadata, handles, sets, quotas, comments or predicates.
    A boolean result never proves a live run: raw files and caller namespace
    observations are separate provenance, independently recomputed by a future
    source-bound artifact verifier. No host command is executed here.
    """
    require(type(namespaces) is dict and set(namespaces) == {'before', 'after'},
            'host namespace observations required')
    for phase in ('before', 'after'):
        row = namespaces[phase]
        require(type(row) is dict and set(row) == {'net', 'mount'}
                and type(row['net']) is str and type(row['mount']) is str
                and re.fullmatch(r'net:\[[1-9][0-9]{0,19}\]',row['net']) is not None
                and re.fullmatch(r'mnt:\[[1-9][0-9]{0,19}\]',row['mount']) is not None,
                'host namespace observation shape')
    values = {name: _host_configuration_json(body, kind) for name, body, kind in (
        ('ip_before', before_ip, 'ip'), ('ip_after', after_ip, 'ip'),
        ('nft_before', before_nft, 'nft'), ('nft_after', after_nft, 'nft'))}
    left, right = values['nft_before'], values['nft_after']
    allowed = {}
    identities = [set(), set()]
    # Validate even the raw-equal path. Counter shape is never silently adopted.
    for side, nft in enumerate((left, right)):
        for index, row in enumerate(nft['nftables']):
            require(type(row) is dict and len(row) == 1, 'host NFT row shape')
            if 'rule' not in row: continue
            rule = row['rule']
            require(type(rule) is dict and type(rule.get('expr')) is list,
                    'host NFT rule expression shape')
            require(all(type(rule.get(key)) is str and rule[key]
                        for key in ('family', 'table', 'chain'))
                    and type(rule.get('handle')) is int and 0 < rule['handle'] <= (1 << 64)-1,
                    'host NFT exact rule identity required')
            identity = tuple(rule[key] for key in ('family', 'table', 'chain', 'handle'))
            require(identity not in identities[side], 'duplicate host rule identity refused')
            identities[side].add(identity)
            for position, expression in enumerate(rule['expr']):
                if type(expression) is not dict or 'counter' not in expression: continue
                require(set(expression) == {'counter'} and type(expression['counter']) is dict
                        and set(expression['counter']) == {'packets', 'bytes'},
                        'unknown or named host counter refused')
                counter = expression['counter']
                require(all(type(counter[key]) is int and 0 <= counter[key] <= (1 << 64)-1
                            for key in ('packets', 'bytes')), 'host counter requires unsigned u64')
                path = ('nftables', index, 'rule', 'expr', position, 'counter')
                allowed.setdefault(path, {})[side] = {'identity': identity, 'counter': counter}
                require(len(allowed) <= HOST_CONFIGURATION_COUNTER_LIMIT, 'host counter inventory bound')
    differences, deltas = [], []
    def refuse(path, reason):
        require(len(differences) < 64, 'host configuration difference inventory bound')
        differences.append({'path': '/'+'/'.join(str(x) for x in path), 'reason': reason})
    def compare(a, b, path):
        if path in allowed:
            pins = allowed[path]
            if set(pins) != {0, 1} or pins[0]['identity'] != pins[1]['identity']:
                refuse(path, 'counter_identity_or_membership_changed'); return
            old, new = pins[0]['counter'], pins[1]['counter']
            if any(new[key] < old[key] for key in ('packets', 'bytes')):
                refuse(path, 'counter_decrease_or_reset'); return
            if old != new:
                deltas.append({'path': '/'+'/'.join(str(x) for x in path),
                               'nftables_index': path[1], 'expression_index': path[4],
                               'rule_identity': dict(zip(('family','table','chain','handle'), pins[0]['identity'])),
                               'before': old, 'after': new,
                               'delta': {key: new[key]-old[key] for key in ('packets','bytes')}})
            return
        if type(a) != type(b): refuse(path, 'typed_value_changed')
        elif type(a) is dict:
            if set(a) != set(b): refuse(path, 'object_membership_changed'); return
            for key in a: compare(a[key], b[key], path+(key,))
        elif type(a) is list:
            if len(a) != len(b): refuse(path, 'list_membership_changed'); return
            for index, (old, new) in enumerate(zip(a,b)): compare(old,new,path+(index,))
        elif a != b: refuse(path, 'value_changed')
    compare(left, right, ())
    ip_equal = before_ip == after_ip
    namespace_equal = namespaces['before'] == namespaces['after']
    return {'schema': HOST_CONFIGURATION_SCHEMA,
            'raw': {name: {'bytes':len(body), 'sha256':sha(body)} for name, body in (
                ('ip_before', before_ip), ('nft_before', before_nft),
                ('ip_after', after_ip), ('nft_after', after_nft))},
            'exact_raw_ip_equal':ip_equal, 'exact_raw_nft_equal':before_nft == after_nft,
            'namespaces':namespaces, 'namespace_equal':namespace_equal,
            'nft_configuration_equal':not differences,
            'configuration_unchanged':ip_equal and namespace_equal and not differences,
            'anonymous_counter_deltas':deltas, 'refused_differences':differences,
            'comparison_complete':True, 'raw_evidence_rewritten':False,
            'scope':'host configuration comparison only; no retrospective or native runtime acceptance'}


def verify_host_configuration_record(record, before_ip, before_nft, after_ip, after_nft, namespaces):
    """Future artifact seam: recompute from pinned RAW inputs, never trust labels.

    The caller must separately verify source/artifact provenance and that these
    are the original before/after namespace observations from a NEW exact run.
    """
    expected = host_configuration_comparison(before_ip,before_nft,after_ip,after_nft,namespaces)
    require(type(record) is dict and json.dumps(record,sort_keys=True,separators=(',',':'),allow_nan=False)
            == json.dumps(expected,sort_keys=True,separators=(',',':'),allow_nan=False),
            'host configuration record disagrees with complete raw recomputation')
    require(expected['configuration_unchanged'], 'host configuration preservation refused')
    return expected
