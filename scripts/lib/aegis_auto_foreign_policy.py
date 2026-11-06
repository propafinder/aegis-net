#!/usr/bin/env python3
"""Read-only admission of foreign filtering policy; caller holds guard flock.

This module grants no packet permission. Unknown syntax and unavailable inputs
refuse admission. The four-chain guard remains independently installed on refusal.
"""
from __future__ import annotations

import collections
import contextlib
import copy
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import socket
import stat
import struct
import select
import subprocess
import sys
import threading
import time

MAX_INPUT = 4 << 20
IFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
# Stock UFW's IPv6 hl/rt matches read headers (Linux xt_hl.c/ip6t_rt.c).
# Upper-case HL/ROUTE mutation targets remain outside XT_TARGET.
XT_MATCH = frozenset(('conntrack', 'state', 'limit', 'recent', 'hashlimit',
                      'addrtype', 'multiport', 'comment', 'pkttype', 'iprange',
                      'mac', 'tcp', 'udp', 'icmp', 'icmp6', 'icmpv6', 'hl', 'rt'))
XT_TARGET = frozenset(('REJECT', 'LOG'))
VERDICTS = frozenset(('accept', 'drop', 'return', 'continue'))
BUILTINS = frozenset(('INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING'))
OWNED = frozenset(('aegis_device_guard', 'aegis_auto_redirect',
                   'aegis_auto_local_redirect', 'aegis_auto_witness'))
STATE = Path('/var/lib/aegis-install/client/device-guard.conf')


class ForeignPolicyRefused(ValueError):
    """Input cannot prove a non-mutating, filter-only foreign policy."""


class PolicySnapshotChanged(ForeignPolicyRefused):
    """A failed proof with bounded fingerprints, never retained rule contents."""
    def __init__(self, first, second):
        super().__init__('ruleset changed during assessment')
        self.first_sha256 = digest(first)
        self.second_sha256 = digest(second)
        left = first.get('nftables') if type(first) is dict else None
        right = second.get('nftables') if type(second) is dict else None
        left = left if type(left) is list else [{'unknown': None}]
        right = right if type(right) is list else [{'unknown': None}]
        index = next((i for i, (a, b) in enumerate(zip(left, right)) if a != b),
                     min(len(left), len(right)))
        self.changed_index = index
        kinds = {'metainfo', 'table', 'chain', 'rule', 'set', 'element', 'map'}
        self.first_kind = self._kind(left, index, kinds)
        self.second_kind = self._kind(right, index, kinds)
        def partition(rows):
            owned = {(family, name): [] for family, name in
                     (('inet', 'aegis_device_guard'), ('inet', 'aegis_auto_witness'),
                      ('ip', 'aegis_auto_redirect'), ('ip', 'aegis_auto_local_redirect'))}
            foreign = []
            for item in rows:
                kind, body = next(iter(item.items())) if type(item) is dict and len(item) == 1 else ('', None)
                key = (body.get('family'), body.get('name') if kind == 'table' else body.get('table')) if type(body) is dict else None
                if key is not None and not all(type(part) is str for part in key):key = None
                if key in owned:owned[key].append(item)
                else:foreign.append(item)
            return owned, foreign
        owned_first, foreign_first = partition(left)
        owned_second, foreign_second = partition(right)
        self.foreign_changed = foreign_first != foreign_second
        self.owned_changes = [
            {'family': family, 'table': name,
             'first_sha256': digest(owned_first[(family, name)]),
             'second_sha256': digest(owned_second[(family, name)]),
             'first_rows': len(owned_first[(family, name)]),
             'second_rows': len(owned_second[(family, name)])}
            for family, name in owned_first
            if owned_first[(family, name)] != owned_second[(family, name)]]

    @staticmethod
    def _kind(rows, index, kinds):
        if index >= len(rows):return 'absent'
        row = rows[index]
        if type(row) is not dict or len(row) != 1:return 'unknown'
        kind = next(iter(row))
        return kind if kind in kinds else 'unknown'


POLICY_INPUT_TAGS = frozenset(('nft_ruleset', 'nft_guard_json', 'nft_guard_text',
    'ip_links', 'tc_qdisc', 'tc_ingress', 'tc_egress', 'ufw_unit',
    'iptables_version', 'iptables_save', 'ip6tables_save',
    'iptables_legacy_save', 'ip6tables_legacy_save', 'unknown'))
POLICY_INPUT_FAILURES = frozenset(('missing_device', 'missing_file', 'dump_interrupted',
    'no_buffer', 'busy', 'permission', 'temporary', 'other'))


class PolicyInputUnavailable(ForeignPolicyRefused):
    def __init__(self, argv, status, errors):
        tag = {
            ('nft','--json','list','ruleset'):'nft_ruleset',
            ('nft','--json','list','table','inet','aegis_device_guard'):'nft_guard_json',
            ('nft','-a','list','table','inet','aegis_device_guard'):'nft_guard_text',
            ('ip','-j','-d','link','show'):'ip_links',
            ('iptables','-V'):'iptables_version',
            ('iptables-save',):'iptables_save', ('ip6tables-save',):'ip6tables_save',
            ('iptables-legacy-save',):'iptables_legacy_save',
            ('ip6tables-legacy-save',):'ip6tables_legacy_save',
        }.get(tuple(argv), 'unknown')
        if argv[:4] == ('tc','-j','qdisc','show'):tag='tc_qdisc'
        if argv[:4] == ('tc','-j','filter','show') and argv[-1] in ('ingress','egress'):
            tag='tc_'+argv[-1]
        if argv[:3] == ('systemctl','show','ufw.service'):tag='ufw_unit'
        failure='other'
        for literal,kind in ((b'No such device','missing_device'),(b'Cannot find device','missing_device'),
            (b'No such file or directory','missing_file'),(b'Dump was interrupted','dump_interrupted'),
            (b'No buffer space available','no_buffer'),(b'Device or resource busy','busy'),
            (b'Permission denied','permission'),(b'Operation not permitted','permission'),
            (b'Resource temporarily unavailable','temporary')):
            if literal in errors:failure=kind;break
        self.command_tag=tag;self.failure_tag=failure
        self.exit_status=status if type(status)is int and -255<=status<=255 else 0
        super().__init__('policy_input_unavailable')


def need(ok, reason):
    if not ok:
        raise ForeignPolicyRefused(reason)


def restore_route_expiry(before, after, old_start, old_end, new_start, new_end):
    """Restore only lifetime presentation of unchanged kernel route identities.

    IPv6 RA may renew an existing route. RFC4861 sections4.2/6.2.1 limit
    advertised default-router lifetime to9000s; a previously observed larger
    baseline is its own ceiling. Prefix Valid Lifetime is a separate uint32
    field (RFC4861 sections4.6.2/6.3.4): a baseline's remaining seconds are not
    its advertised ceiling. Every other route attribute and row remains exact.
    https://www.rfc-editor.org/rfc/rfc4861.html#section-6.2.1
    """
    need(all(type(v) is int and v > 0 for v in
             (old_start, old_end, new_start, new_end)) and
         old_start <= old_end <= new_start <= new_end and
         new_end-old_start <= 900*10**9, 'route_snapshot_clock_invalid')
    need(type(before) is list and type(after) is list and
         len(before) == len(after) <= 4096, 'route_snapshot_shape_changed')
    low = max(0, (new_start-old_end)//10**9-1)
    high = (new_end-old_start+10**9-1)//10**9+1
    restored = []
    for old, current in zip(before, after):
        need(type(old) is dict and type(current) is dict and set(old) == set(current),
             'route_snapshot_fields_changed')
        row = dict(current)
        if 'expires' in old:
            initial, remaining = old['expires'], current['expires']
            need(type(initial) is int and type(remaining) is int and
                 0 < initial <= 2**32-1 and 0 < remaining <= 2**32-1,
                 'route_snapshot_expiry_changed')
            countdown = remaining <= initial and low <= initial-remaining <= high
            renewed = False
            if old.get('protocol') == 'ra':
                import ipaddress
                try:
                    ipv6 = (ipaddress.ip_address(old['gateway']).version == 6
                            if old.get('dst') == 'default' else
                            ipaddress.ip_network(old['dst']).version == 6)
                except (KeyError, TypeError, ValueError):
                    ipv6 = False
                ceiling = max(initial, 9000) if old.get('dst') == 'default' else 2**32-1
                renewed = ipv6 and remaining <= ceiling
            need(countdown or renewed, 'route_snapshot_expiry_changed')
            row['expires'] = initial
        need(row == old, 'route_snapshot_changed')
        restored.append(row)
    return restored


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT, 'JSON size bound')
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def _pid1_query_kind(raw):
    value=raw.lower()
    for kind,terms in (
        ('unit_missing',(b'could not be found',b'not loaded',b'no such unit',b'not found')),
        ('permission',(b'permission denied',b'access denied')),
        ('resource',(b'too many',b'no buffer space',b'cannot allocate memory',b'resource temporarily')),
        ('bus',(b'connection reset',b'connection refused',b'failed to connect',b'broken pipe',b'transport endpoint'))):
        if any(term in value for term in terms):return kind
    return 'other'


# Fixed policy-reader argv shared by the prefetching caller and the run() call
# that evaluates each result at its original position.
IPTABLES_VERSION = ('iptables', '-V')
LINK_INVENTORY = ('ip', '-j', '-d', 'link', 'show')
UFW_UNIT = ('systemctl', 'show', 'ufw.service', '-p', 'FragmentPath', '-p',
            'DropInPaths', '-p', 'NeedDaemonReload')
GUARD_JSON = ('nft', '--json', 'list', 'table', 'inet', 'aegis_device_guard')
GUARD_TEXT = ('nft', '-a', 'list', 'table', 'inet', 'aegis_device_guard')
RULESET = ('nft', '--json', 'list', 'ruleset')
READ_SECONDS = 3.0


class _Child:
    """One bounded policy reader: file-backed output, own 3 s deadline."""
    __slots__ = ('argv', 'deadline', 'output', 'errors', 'proc', 'pidfd', 'error')

    def __init__(self, argv, deadline):
        self.argv, self.deadline = argv, deadline
        self.output = self.errors = self.proc = self.pidfd = self.error = None


def _spawn(argv, output, errors):
    """Seam: start one reader; return (Popen, pidfd or None).

    The pidfd is opened by the parent immediately after fork/exec. The child
    cannot be reaped by anyone else, so the descriptor names exactly it.
    """
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                            stderr=errors, close_fds=True,
                            env={**os.environ, 'LC_ALL': 'C'})
    opener = getattr(os, 'pidfd_open', None)
    if opener is None:
        return proc, None
    try:
        return proc, opener(proc.pid)
    except OSError:
        # Kernels without pidfd keep the bounded Popen.wait fallback.
        return proc, None


def _start(argv, deadline):
    import tempfile
    child = _Child(argv, deadline)
    # A temporary file avoids an unbounded PIPE allocation before size checking.
    child.output = tempfile.TemporaryFile()
    child.errors = tempfile.TemporaryFile()
    try:
        child.proc, child.pidfd = _spawn(argv, child.output, child.errors)
    except (OSError, subprocess.SubprocessError) as error:
        # Raised by the consuming run() at the read's original position, so
        # refusal order and labels do not depend on prefetching.
        child.error = error
    return child


def _close(child):
    """Idempotent: kill and reap a live reader, then release its descriptors."""
    proc, child.proc = child.proc, None
    if proc is not None:
        try:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=2)
        except (OSError, subprocess.SubprocessError):
            pass
    pidfd, child.pidfd = child.pidfd, None
    if pidfd is not None:
        os.close(pidfd)
    for name in ('output', 'errors'):
        stream = getattr(child, name)
        setattr(child, name, None)
        if stream is not None:
            stream.close()


def _wait(child):
    """Event-driven exit wait under the reader's own deadline (no sleep poll)."""
    if child.error is not None:
        raise child.error
    while True:
        remaining = child.deadline - time.monotonic()
        if remaining <= 0:
            _close(child)
            raise subprocess.TimeoutExpired(child.argv, READ_SECONDS)
        if child.pidfd is None:
            try:
                return child.proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                continue
        poller = select.poll()
        poller.register(child.pidfd, select.POLLIN)
        if poller.poll(max(1, int(remaining * 1000) + 1)):
            # The pidfd is readable only after exit; this waitpid reaps it.
            return child.proc.wait()


_PREFETCH = threading.local()


def _registry():
    registry = getattr(_PREFETCH, 'children', None)
    if registry is None:
        registry = _PREFETCH.children = {}
    return registry


@contextlib.contextmanager
def prefetch(*argvs):
    """Start independent bounded reads now, in the calling thread only.

    Every result is still consumed and evaluated by the unchanged run() call
    at its original position, so the checks, their order and their refusal
    labels stay the same. Leaving the block, normally or by a refusal, kills
    and reaps every reader that was not consumed; none outlives the block.
    """
    registry = _registry()
    started = []
    try:
        for argv in argvs:
            argv = tuple(argv)
            need(argv not in registry, 'duplicate prefetched policy read')
            child = _start(argv, time.monotonic() + READ_SECONDS)
            started.append(child)
            registry[argv] = child
        yield
    finally:
        for child in started:
            if registry.get(child.argv) is child:
                del registry[child.argv]
            _close(child)


def run(*argv):
    pid1_read = len(argv) >= 3 and argv[0] in ('systemctl','/usr/bin/systemctl') and argv[1] == 'show'
    child = _registry().pop(tuple(argv), None)
    deadline = child.deadline if child is not None else time.monotonic() + READ_SECONDS
    for attempt in range(3 if pid1_read else 1):
        try:
            if child is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:raise subprocess.TimeoutExpired(argv,READ_SECONDS)
                child = _start(tuple(argv), deadline)
            code = _wait(child)
            output, errors = child.output, child.errors
            need(output.tell() <= MAX_INPUT and errors.tell() <= MAX_INPUT,
                 'policy command output exceeds bound')
            if code:
                errors.seek(0);error=errors.read(MAX_INPUT+1)
                if pid1_read:
                    kind = _pid1_query_kind(error)
                    print(json.dumps({'event':'pid1_query_unavailable','source':'foreign_policy',
                        'attempt':attempt+1,'exit':code,'stdout_bytes':output.tell(),
                        'stderr_bytes':len(error),'kind':kind,
                        'monotonic_ns':time.monotonic_ns()},sort_keys=True),file=sys.stderr,flush=True)
                    # Retry only a transient PID1 bus/resource failure and
                    # spend the pause from this call's original 3 s budget.
                    if kind in ('bus','resource') and attempt < 2:
                        remaining = deadline-time.monotonic()
                        if remaining > 0:
                            time.sleep(min(0.025,remaining))
                            continue
                raise PolicyInputUnavailable(argv,code,error)
            output.seek(0)
            return output.read(MAX_INPUT + 1)
        finally:
            if child is not None:
                _close(child)
                child = None


def trusted_read(path, limit=MAX_INPUT):
    path = Path(path)
    # Resolve distro /lib and /sbin aliases, then authenticate the resolved ancestry.
    resolved = path.resolve(strict=True)
    for item in (resolved, *resolved.parents):
        st = item.lstat()
        need(st.st_uid == 0 and not st.st_mode & 0o022 and
             not stat.S_ISLNK(st.st_mode), 'untrusted policy ancestry')
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_size <= limit, 'untrusted policy file')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        need(len(raw) <= limit and (before.st_dev, before.st_ino, before.st_size,
             before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino,
             after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'policy file raced')
        return raw


def keys(value, required, optional=()):
    need(type(value) is dict and set(required) <= value.keys() and
         value.keys() <= set(required) | set(optional), 'unknown expression fields')


def readonly(value):
    """Expressions usable only as match operands, never statements."""
    if type(value) in (str, int, bool) or value is None:
        need(not isinstance(value, str) or len(value) <= 4096, 'operand bound')
        return
    if type(value) is list:
        need(len(value) <= 4096, 'operand list bound')
        for child in value:
            readonly(child)
        return
    need(type(value) is dict and len(value) == 1, 'unknown match operand')
    name, v = next(iter(value.items()))
    if name == 'meta':
        keys(v, ('key',))
        need(v['key'] in ('iifname', 'oifname', 'l4proto', 'nfproto', 'pkttype'),
             'mutable or unsupported metadata')
    elif name == 'payload':
        keys(v, ('protocol', 'field'))
        fields = {'ip': ('saddr', 'daddr', 'protocol', 'ttl', 'length', 'frag-off'),
                  'ip6': ('saddr', 'daddr', 'nexthdr', 'hoplimit'),
                  'tcp': ('sport', 'dport', 'flags'), 'udp': ('sport', 'dport'),
                  'icmp': ('type', 'code'), 'icmpv6': ('type', 'code'),
                  'ether': ('saddr', 'daddr', 'type')}
        need(v['protocol'] in fields and v['field'] in fields[v['protocol']],
             'unsupported payload read')
    elif name == 'ct':
        keys(v, ('key',), ('dir',))
        need(v['key'] in ('state', 'status') and
             v.get('dir') in (None, 'original', 'reply'), 'unsupported conntrack read')
    elif name == 'fib':
        keys(v, ('result', 'flags'))
        need(v['result'] in ('type', 'oif', 'oifname') and type(v['flags']) is list and
             set(v['flags']) <= {'saddr', 'daddr', 'mark', 'iif', 'oif'}, 'unsupported fib')
    elif name in ('set', 'concat'):
        need(type(v) is list and len(v) <= 4096, 'invalid set operand')
        for child in v:
            readonly(child)
    elif name in ('prefix', 'range', '&', '|', '^', '<<', '>>'):
        if name == 'prefix':
            keys(v, ('addr', 'len'))
            need(type(v['len']) is int and 0 <= v['len'] <= 128, 'invalid prefix')
            readonly(v['addr'])
        else:
            need(type(v) is list and len(v) == 2, 'invalid binary operand')
            for child in v:
                readonly(child)
    else:
        need(False, 'unknown read-only expression: ' + str(name))


def statement(expr, chains):
    need(type(expr) is dict and len(expr) == 1, 'invalid statement')
    name, v = next(iter(expr.items()))
    if name in VERDICTS:
        need(v is None, 'invalid verdict')
    elif name in ('jump', 'goto'):
        keys(v, ('target',))
        need(v['target'] in chains, 'cross-table or missing jump')
    elif name == 'match':
        keys(v, ('op', 'left', 'right'))
        need(v['op'] in ('==', '!=', '<', '>', '<=', '>=', 'in'), 'unknown comparator')
        readonly(v['left'])
        readonly(v['right'])
    elif name == 'counter':
        keys(v, ('packets', 'bytes'))
        need(all(type(n) is int and n >= 0 for n in v.values()), 'invalid counter')
    elif name == 'limit':
        keys(v, ('rate', 'per'), ('burst', 'unit', 'inv'))
        need(type(v['rate']) is int and v['rate'] > 0 and
             v['per'] in ('second', 'minute', 'hour', 'day', 'week') and
             v.get('unit') in (None, 'packets', 'bytes', 'kbytes', 'mbytes') and
             type(v.get('inv', False)) is bool and
             type(v.get('burst', 0)) is int and v.get('burst', 0) >= 0, 'invalid limit')
    elif name == 'log':
        keys(v, (), ('prefix', 'level', 'flags'))
        need(type(v.get('prefix', '')) is str and len(v.get('prefix', '')) <= 256 and
             v.get('level', 'warn') in ('emerg', 'alert', 'crit', 'err', 'warn',
                                       'notice', 'info', 'debug') and
             (type(v.get('flags', [])) is list and set(v.get('flags', [])) <=
              {'tcp sequence', 'tcp options', 'ip options', 'skuid', 'ether', 'all'}),
             'unsupported log statement')
    elif name == 'reject':
        if v is not None:
            keys(v, ('type',), ('expr',))
            need(v['type'] in ('tcp reset', 'icmp', 'icmpv6', 'icmpx'), 'invalid reject')
            if 'expr' in v:
                readonly(v['expr'])
    elif name == 'xt':
        keys(v, ('type', 'name'))
        need((v['type'] == 'match' and v['name'] in XT_MATCH) or
             (v['type'] == 'target' and v['name'] in XT_TARGET), 'unsafe xt extension')
    else:
        need(False, 'unsafe or unknown statement: ' + str(name))


def normalize(value):
    if type(value) is list:
        return [normalize(v) for v in value]
    if type(value) is dict:
        return {k: (None if k == 'counter' else normalize(v))
                for k, v in value.items() if k not in ('handle', 'index')}
    return value


def parse_save(raw, *, legacy=False):
    need(type(raw) is bytes and len(raw) <= MAX_INPUT, 'xtables size bound')
    text = raw.decode('ascii')
    table = None
    chains = set()
    extensions = collections.Counter()
    rules = 0
    targets = []
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        if line.startswith('*'):
            need(table is None, 'nested xtables table')
            table = line[1:]
            need(table in (('filter', 'nat', 'mangle', 'raw', 'security') if legacy else
                           ('filter',)), 'non-filter xtables table')
        elif line == 'COMMIT':
            need(table is not None, 'unpaired xtables commit')
            table = None
        elif line.startswith(':'):
            parts = line[1:].split()
            need(table is not None and len(parts) == 3 and
                 re.fullmatch(r'\[\d+:\d+\]', parts[2]) and
                 parts[1] in ('-', 'ACCEPT', 'DROP'), 'invalid xtables chain')
            if legacy:
                need(parts[0] in BUILTINS and parts[1] != '-', 'legacy custom chain')
            need((table, parts[0]) not in chains, 'duplicate xtables chain')
            chains.add((table, parts[0]))
        else:
            need(not legacy, 'legacy rules are unsupported')
            parts = shlex.split(line)
            need(table == 'filter' and len(parts) >= 2 and parts[0] == '-A' and
                 (table, parts[1]) in chains, 'invalid xtables rule')
            rules += 1
            for i, token in enumerate(parts[2:], 2):
                if token in ('-m', '--match'):
                    need(i + 1 < len(parts) and parts[i + 1] in XT_MATCH,
                         'unsafe xtables match')
                    extensions[('match', parts[i + 1])] += 1
                if token in ('-j', '--jump', '-g', '--goto'):
                    need(i + 1 < len(parts), 'missing xtables target')
                    target = parts[i + 1]
                    targets.append((table, target))
                    if target in XT_TARGET:
                        extensions[('target', target)] += 1
    need(table is None, 'incomplete xtables save')
    for table, target in targets:
        need(target in ('ACCEPT', 'DROP', 'RETURN') or target in XT_TARGET or
             (table, target) in chains, 'unsafe xtables target')
    return chains, extensions, rules


def assess_rules(nft, saves, legacy_saves, *, verified_owned=()):
    """Pure policy parser. verified_owned is supplied only by live strict verifiers."""
    keys(nft, ('nftables',))
    need(type(nft['nftables']) is list and len(nft['nftables']) <= 32768,
         'nft inventory bound')
    tables, chains, foreign = set(), {}, []
    xt = {'ip': collections.Counter(), 'ip6': collections.Counter()}
    xtchains = {'ip': set(), 'ip6': set()}
    # Table and chain discovery precedes validating jump targets.
    for item in nft['nftables']:
        need(type(item) is dict and len(item) == 1, 'unknown nft inventory item')
        kind, obj = next(iter(item.items()))
        if kind == 'metainfo':
            keys(obj, ('version', 'release_name', 'json_schema_version'))
            need(obj['json_schema_version'] == 1, 'unsupported nft JSON schema')
            continue
        need(type(obj) is dict, 'invalid nft object')
        family = obj.get('family')
        name = obj.get('name') if kind == 'table' else obj.get('table')
        key = (family, name)
        if name in OWNED:
            need(key in verified_owned, 'unverified AEGIS table')
            continue
        need(type(name) is str and not name.startswith('aegis'), 'foreign AEGIS name')
        need(family in ('ip', 'ip6', 'inet'), 'unsupported foreign family')
        if kind == 'table':
            keys(obj, ('family', 'name'), ('handle',))
            need(key not in tables, 'duplicate nft table')
            tables.add(key)
        elif kind == 'chain':
            keys(obj, ('family', 'table', 'name'),
                 ('handle', 'type', 'hook', 'prio', 'policy'))
            ck = (*key, obj['name'])
            need(ck not in chains and type(obj['name']) is str, 'duplicate chain')
            if 'hook' in obj:
                need(set(obj) >= {'type', 'prio', 'policy'} and
                     obj['type'] == 'filter' and obj['hook'] in
                     ('input', 'output', 'forward', 'prerouting', 'postrouting') and
                     type(obj['prio']) is int and obj['policy'] in ('accept', 'drop'),
                     'non-filter foreign chain')
                need(obj['hook'] != 'output' or obj['prio'] < 2147483647,
                     'foreign output overlaps final guard priority')
            else:
                need(not set(obj) & {'type', 'prio', 'policy'}, 'partial base chain')
            chains[ck] = obj
            if family in xtchains and name == 'filter':
                xtchains[family].add((name, obj['name']))
        elif kind not in ('rule', 'set', 'element'):
            need(False, 'stateful or unknown foreign object')
        foreign.append(item)
    for item in foreign:
        kind, obj = next(iter(item.items()))
        key = (obj['family'], obj.get('table', obj.get('name')))
        need(key in tables, 'object in missing table')
        names = {c[2] for c in chains if c[:2] == key}
        if kind == 'rule':
            keys(obj, ('family', 'table', 'chain', 'expr'), ('handle', 'comment', 'index'))
            need(obj['chain'] in names and type(obj['expr']) is list and
                 len(obj['expr']) <= 128, 'rule chain or expression bound')
            for expr in obj['expr']:
                statement(expr, names)
                if 'xt' in expr:
                    need(key[0] in xt and key[1] == 'filter', 'opaque xt outside cross-checked filter table')
                if 'xt' in expr and key[0] in xt and key[1] == 'filter':
                    e = expr['xt']
                    xt[key[0]][(e['type'], e['name'])] += 1
        elif kind == 'set':
            keys(obj, ('family', 'table', 'name', 'type'), ('handle', 'flags', 'elem', 'size'))
            need(type(obj.get('flags', [])) is list and set(obj.get('flags', [])) <=
                 {'constant', 'interval'} and type(obj['type']) in (str, list),
                 'mutable, timed or verdict set')
            readonly(obj.get('elem', []))
        elif kind == 'element':
            keys(obj, ('family', 'table', 'name', 'elem'))
            readonly(obj['elem'])
    # xt opaque JSON semantics are independently constrained by extension names
    # in -save. Native payload translations need not preserve a match module name.
    for family, raw in saves.items():
        need(family in xtchains, 'unexpected save family')
        actual, extensions, _ = parse_save(raw)
        need(actual == xtchains[family], 'nft/save chain inventory differs')
        need(xt[family] == collections.Counter({k: n for k, n in extensions.items()
             if k in xt[family]}) and set(xt[family]) <= set(extensions),
             'nft/save opaque extension inventory differs')
    need(set(saves) == {'ip', 'ip6'}, 'both xtables families required')
    for raw in legacy_saves:
        parse_save(raw, legacy=True)
    need(len(legacy_saves) == 2, 'both legacy families required')
    projection = [normalize(i) for i in foreign]
    return projection


def _local_bpf_bindings(interfaces):
    """Enumerate pinned link types and query attachment points without bpftool."""
    syscall = {'x86_64': 321, 'aarch64': 280}.get(platform.machine())
    need(syscall is not None, 'unsupported bpf syscall architecture')
    libc = ctypes.CDLL(None, use_errno=True)
    def call(command, raw):
        # BPF_PROG_QUERY writes modern revision/link fields beyond the legacy
        # 32-byte prefix. Always provide a full, zero-extended union allocation;
        # a small ctypes object must never be used as an output union buffer.
        attribute=raw.ljust(256,b"\0")
        need(len(attribute)==256,'BPF attribute bound')
        buf = ctypes.create_string_buffer(attribute)
        result = libc.syscall(ctypes.c_long(syscall), ctypes.c_int(command),
                              ctypes.byref(buf), ctypes.c_uint(256))
        if result < 0:
            raise OSError(ctypes.get_errno(), 'bpf input unavailable')
        return result, buf.raw[:len(raw)]
    next_id = 0
    for _ in range(16384):
        try:
            _, raw = call(31, struct.pack('III', next_id, 0, 0))
        except OSError as error:
            if error.errno == errno.ENOENT:
                break
            raise
        next_id = struct.unpack('III', raw)[1]
        fd, _ = call(30, struct.pack('III', next_id, 0, 0))
        try:
            info = ctypes.create_string_buffer(256)
            _, raw = call(15, struct.pack('IIQ', fd, 256, ctypes.addressof(info)))
            link_type = struct.unpack_from('I', info.raw)[0]
            need(link_type not in (6, 10, 11, 13), 'XDP/netfilter/TCX/netkit BPF link')
        finally:
            os.close(fd)
    else:
        need(False, 'BPF link inventory bound')
    for interface in interfaces:
        index = socket.if_nametoindex(interface)
        # Query the attachment points supported by reviewed Linux 7.0. EINVAL
        # reports unsupported attachment types. Linux netkit_dev_fetch returns
        # ENXIO specifically for a present interface with non-netkit operations;
        # ENODEV (interface race), EACCES and EPERM always remain refusals.
        for attach in (37, 46, 47, 54, 55):
            try:
                _, raw = call(16, struct.pack('IIIIQII', index, attach, 0, 0, 0, 0, 0))
                need(struct.unpack_from('I', raw, 24)[0] == 0,
                     'BPF program attached to protected interface')
            except OSError as error:
                need(error.errno in (errno.EINVAL, errno.EOPNOTSUPP) or
                     attach in (54,55) and error.errno==errno.ENXIO,
                     'BPF attachment query unavailable')



# Set only by the installed guardian's source-pinned module loader. A private
# worker importing this module cannot mint or inherit this root actor client.
_privileged_bpf_query = None


def bpf_bindings(interfaces):
    need(type(interfaces) is list and 1<=len(interfaces)<=3 and
         all(type(x) is str and IFACE.fullmatch(x) for x in interfaces) and
         len(set(interfaces))==len(interfaces), 'BPF interface query bound')
    try:
        return _local_bpf_bindings(interfaces)
    except OSError as error:
        # Linux LINK_GET_NEXT_ID requires SYS_ADMIN, not merely CAP_BPF.
        # Keep the guardian's existing capability set: delegate this fixed
        # read-only operation to its already privileged, authenticated actor.
        if error.errno!=errno.EPERM or not callable(_privileged_bpf_query):raise
        need(_privileged_bpf_query(interfaces) is None,'invalid root BPF query result')


def _capture_executable_sha(path, metadata):
    # Filesystems can expose the same timestamp tuple for two quick writes.
    # Rehash the held executable; metadata equality alone is not its digest.
    key = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
           metadata.st_ctime_ns, metadata.st_mode, metadata.st_uid, metadata.st_nlink)
    need(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and
         not metadata.st_mode & 0o022 and metadata.st_nlink == 1 and
         0 < metadata.st_size <= 512 << 20, 'capture owner executable untrusted')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        actual = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                  before.st_ctime_ns, before.st_mode, before.st_uid, before.st_nlink)
        need(actual == key, 'capture owner executable changed')
        digest_value = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            need(total <= metadata.st_size, 'capture owner executable grew')
            digest_value.update(chunk)
        after = os.fstat(fd)
        need(total == metadata.st_size and
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
              after.st_ctime_ns, after.st_mode, after.st_uid, after.st_nlink) == key,
             'capture owner executable changed')
        result = digest_value.hexdigest()
    finally:
        os.close(fd)
    return result


def capture_tun_owner(link):
    """Prove a nonpersistent TUN fd belongs to the installed service worker.

    A TUN UID or a link name cannot identify its process. Match the executable
    inode, protected system-unit cgroup, network namespace and actual TUN fd;
    recheck process/link identities after reading them. An ordinary foreign
    process holding a TUN fd never qualifies.
    """
    client = Path('/usr/local/bin/aegis-client')
    install = Path('/var/lib/aegis-install/client/auto-guardian-install.json')
    main_path = Path('/var/lib/aegis-install/client/device-guard.conf.main-binding')
    try:
        main = decode(trusted_read(main_path, 4096))
    except FileNotFoundError:
        main = None
    if main is not None:
        need(type(main) is dict and set(main) == {
             'schema', 'boot_id', 'netns_ino', 'private_unit',
             'worker_sha256', 'stage_dev', 'stage_ino'} and
             main['schema'] == 'aegis_device_guard_main_binding_v1' and
             re.fullmatch(r'aegis-auto@[0-9a-f]{64}\.service', main['private_unit']) and
             re.fullmatch('[0-9a-f]{64}', main['worker_sha256']) and
             type(main['netns_ino']) is int and main['netns_ino'] > 0 and
             type(main['stage_dev']) is int and main['stage_dev'] > 0 and
             type(main['stage_ino']) is int and main['stage_ino'] > 0 and
             main['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'capture main binding invalid')
    expected_sha = None
    try:
        record = decode(trusted_read(install, 1 << 20))
    except FileNotFoundError:
        record = None
    if record is not None:
        need(type(record) is dict and record.get('schema') == 'aegis_auto_guardian_install_v1' and
             type(record.get('worker_sha256')) is str and
             re.fullmatch('[0-9a-f]{64}', record['worker_sha256']),
             'capture owner installation invalid')
        expected_sha = record['worker_sha256']
        identity = None
    else:
        try:
            binary = client.stat(follow_symlinks=False)
        except FileNotFoundError:
            return False
        need(stat.S_ISREG(binary.st_mode) and binary.st_uid == 0 and
             not binary.st_mode & 0o022 and binary.st_nlink == 1,
             'capture owner executable untrusted')
        identity = (binary.st_dev, binary.st_ino)
    netns = Path('/proc/self/ns/net').stat().st_ino
    need(main is None or main['netns_ino'] == netns,
         'capture main network namespace changed')
    processes = list(Path('/proc').iterdir())
    need(len(processes) <= 65536, 'capture owner process inventory bound')
    for process in processes:
        if not process.name.isascii() or not process.name.isdecimal():
            continue
        try:
            cgroup = (process / 'cgroup').read_text(encoding='ascii')
            if len(cgroup) > 4096 or not re.fullmatch(
                    r'0::/system\.slice/(?:[A-Za-z0-9_.@:-]+/)*'
                    r'(?:aegis-client\.service|aegis-auto@[0-9a-f]{64}\.service)\n', cgroup):
                continue
            unit = cgroup.rstrip('\n').rsplit('/', 1)[-1]
            private = unit.startswith('aegis-auto@')
            if private:
                if main is None or unit != main['private_unit']:
                    continue
                shown = subprocess.run(
                    ['/usr/bin/systemctl', 'show', unit, '-p', 'MainPID',
                     '--no-pager'], capture_output=True, timeout=2, check=False,
                    env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C'})
                need(shown.returncode == 0 and
                     shown.stdout == f'MainPID={process.name}\n'.encode() and
                     len(shown.stderr) <= 4096,
                     'capture private MainPID changed')
            executable = (process / 'exe').stat()
            target_sha = main['worker_sha256'] if private else expected_sha
            if target_sha is not None:
                if _capture_executable_sha(process / 'exe', executable) != target_sha:
                    continue
            elif (executable.st_dev, executable.st_ino) != identity:
                continue
            before = (process / 'stat').read_text(encoding='ascii')
            need(len(before) <= 8192, 'capture owner stat bound')
            if (process / 'ns/net').stat().st_ino != netns:
                continue
            descriptors = list((process / 'fd').iterdir())
            need(len(descriptors) <= 4096, 'capture owner fd inventory bound')
            owned = False
            for descriptor in descriptors:
                if not descriptor.name.isdecimal() or os.readlink(descriptor) != '/dev/net/tun':
                    continue
                info = (process / 'fdinfo' / descriptor.name).read_text(encoding='ascii')
                need(len(info) <= 4096, 'capture owner fdinfo bound')
                names = [line.partition(':')[2].strip() for line in info.splitlines()
                         if line.partition(':')[0] == 'iff']
                if names == ['aegis-tun0']:
                    owned = True
                    break
            if not owned:
                continue
            after = (process / 'stat').read_text(encoding='ascii')
            # starttime remains stable even if the PID is rapidly reused.
            first = before.rsplit(')', 1)[1].split()
            last = after.rsplit(')', 1)[1].split()
            need(len(first) >= 20 and len(last) >= 20, 'capture owner stat invalid')
            if first[19] != last[19]:
                continue
            named = (process / 'exe').stat()
            need((named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns,
                  named.st_ctime_ns) ==
                 (executable.st_dev, executable.st_ino, executable.st_size,
                  executable.st_mtime_ns, executable.st_ctime_ns) and
                 socket.if_nametoindex('aegis-tun0') == link['ifindex'],
                 'capture owner identity changed')
            return True
        except (FileNotFoundError, ProcessLookupError):
            continue
    return False


def check_links(uplink):
    need(IFACE.fullmatch(uplink) and uplink not in ('lo', 'aegis-tun0'), 'bad uplink')
    links = decode(run(*LINK_INVENTORY))
    need(type(links) is list and len(links) <= 4096, 'link inventory bound')
    # Every tc read of a protected link starts together; each result is still
    # evaluated below in the original link and command order.
    names = dict.fromkeys(link.get('ifname') for link in links if type(link) is dict and
                          link.get('ifname') in ('lo', uplink, 'aegis-tun0'))
    reads = [argv for name in names for argv in
             (('tc', '-j', 'qdisc', 'show', 'dev', name),
              ('tc', '-j', 'filter', 'show', 'dev', name, 'ingress'),
              ('tc', '-j', 'filter', 'show', 'dev', name, 'egress'))]
    interfaces = []
    with prefetch(*reads):
        for link in links:
            need(link.get('linkinfo', {}).get('info_kind') != 'netkit', 'netkit device')
            if link.get('ifname') not in ('lo', uplink, 'aegis-tun0'):
                continue
            if link['ifname'] == 'aegis-tun0':
                info = link.get('linkinfo', {})
                data = info.get('info_data', {})
                need(info.get('info_kind') == 'tun' and data.get('type') == 'tun' and
                     data.get('persist') is False and type(link.get('ifindex')) is int and
                     link['ifindex'] > 0, 'capture interface type')
                need(capture_tun_owner(link), 'capture interface owner')
            interfaces.append(link['ifname'])
            xdp = link.get('xdp')
            need(not xdp or xdp == {'attached': 'off'}, 'XDP attachment')
            qdisc = decode(run('tc', '-j', 'qdisc', 'show', 'dev', link['ifname']))
            need(type(qdisc) is list and all(q.get('kind') not in ('clsact', 'ingress')
                                           for q in qdisc), 'tc ingress/clsact qdisc')
            for direction in ('ingress', 'egress'):
                need(decode(run('tc', '-j', 'filter', 'show', 'dev', link['ifname'],
                                direction)) == [], 'tc filter')
    need({'lo', uplink} <= set(interfaces), 'protected interface missing')
    bpf_bindings(interfaces)
    for path in ('/proc/sys/net/ipv4/ip_forward', '/proc/sys/net/ipv6/conf/all/forwarding'):
        need(Path(path).read_text().strip() == '0', 'forwarding host')
    return interfaces


# Per-process memo of pure code signatures. A key covers every input of the
# signature (content digest, filename, optimization, interpreter cache tag and
# bytecode magic), so a hit equals recomputation. Never persisted; the caller
# still reads and checks every file on every assessment.
_SIGNATURES = collections.OrderedDict()
_SIGNATURES_LOCK = threading.Lock()
SIGNATURE_MEMO_ENTRIES = 16


def _memo_signature(key, compute):
    with _SIGNATURES_LOCK:
        if key in _SIGNATURES:
            _SIGNATURES.move_to_end(key)
            return _SIGNATURES[key]
    value = compute()
    with _SIGNATURES_LOCK:
        _SIGNATURES[key] = value
        _SIGNATURES.move_to_end(key)
        while len(_SIGNATURES) > SIGNATURE_MEMO_ENTRIES:
            _SIGNATURES.popitem(last=False)
    return value


def verify_bytecode(raw, source, filename, optimization=0):
    # Marshal reference/interning encodings need not be byte-identical for the
    # same code object. Compare every executable/code metadata field instead,
    # including nested constants and filenames, without executing cached code.
    import importlib.util
    import io
    import marshal
    import types
    need(type(raw) is bytes and type(source) is bytes and type(filename) is str and
         optimization in (0, 1, 2), 'invalid UFW bytecode input')
    need(16<=len(raw)<=MAX_INPUT and raw[:4]==importlib.util.MAGIC_NUMBER and
         int.from_bytes(raw[4:8],'little') in (0,1,3),'unreviewed UFW cache header')
    fields=('co_argcount','co_posonlyargcount','co_kwonlyargcount','co_nlocals',
        'co_stacksize','co_flags','co_code','co_consts','co_names','co_varnames',
        'co_filename','co_name','co_qualname','co_firstlineno','co_linetable',
        'co_exceptiontable','co_freevars','co_cellvars')
    def signature(value,depth=0):
        need(depth<=64,'UFW code constant depth')
        if type(value) is types.CodeType:
            return tuple((k,signature(getattr(value,k),depth+1)) for k in fields)
        if type(value) is tuple:
            return tuple(signature(v,depth+1) for v in value)
        if type(value) is slice:
            return ('slice',signature(value.start,depth+1),signature(value.stop,depth+1),signature(value.step,depth+1))
        need(type(value) in (str,bytes,int,float,complex,bool,frozenset,type(None),type(Ellipsis)),
             'unknown UFW code constant type')
        return value
    def cached_signature():
        stream=io.BytesIO(raw[16:])
        cached=marshal.load(stream)
        need(stream.tell()==len(raw)-16 and type(cached) is types.CodeType,
             'invalid UFW cached code or suffix')
        return signature(cached)
    def expected_signature():
        return signature(compile(source,filename,'exec',dont_inherit=True,optimize=optimization))
    tag=(sys.implementation.cache_tag,bytes(importlib.util.MAGIC_NUMBER))
    observed=_memo_signature(('pyc',hashlib.sha256(raw).hexdigest(),*tag),cached_signature)
    expected=_memo_signature(('source',hashlib.sha256(source).hexdigest(),filename,
                              optimization,*tag),expected_signature)
    need(observed==expected,'UFW bytecode differs from source')


def ufw_integrity(mode):
    """Stock 0.36.2-9build1 code plus literal administrator filtering choices."""
    if not Path('/etc/ufw/ufw.conf').exists():
        need(not shutil.which('ufw'), 'UFW configuration missing')
        return {'enabled': False, 'class': 'absent', 'sha256': digest({})}
    pins = json.loads(trusted_read(Path(__file__).with_name('aegis_auto_ufw_pins.json')),
                      object_pairs_hook=unique)
    seen = {}
    for path, sha in pins.items():
        if path in ('/etc/default/ufw', '/etc/ufw/sysctl.conf'):
            continue
        if path in ('/etc/ufw/before.init', '/etc/ufw/after.init') and not Path(path).exists():
            continue
        raw = trusted_read(path)
        if path.endswith(('/before.init', '/after.init')) and not os.stat(path).st_mode & 0o111:
            seen[path] = hashlib.sha256(raw).hexdigest()
            continue
        need(hashlib.sha256(raw).hexdigest() == sha, 'unreviewed UFW code: ' + path)
        seen[path] = sha
    package = Path('/usr/lib/python3/dist-packages/ufw')
    need({str(p) for p in package.rglob('*.py')} ==
         {p for p in pins if p.startswith(str(package) + '/')}, 'unknown UFW Python module')
    # Source-loader precedence must not be replaced by an extension module or
    # a new package directory next to the eight pinned source leaves.
    need(all(p.name=='__pycache__' and p.is_dir() or str(p) in pins
             for p in package.iterdir()),'unknown UFW package leaf')
    import sys
    for p in package.rglob('*.pyc'):
        tag=sys.implementation.cache_tag
        match=re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)\.'+re.escape(tag)+r'(?:\.opt-([12]))?\.pyc',p.name)
        if match is None:
            # Older interpreter tags are not import candidates for this boot.
            need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.cpython-[0-9]+(?:\.opt-[12])?\.pyc',p.name),
                 'unknown UFW bytecode name')
            continue
        source=package/(match[1]+'.py')
        need(str(source) in pins,'unknown UFW bytecode source')
        verify_bytecode(trusted_read(p),trusted_read(source),str(source),int(match[2] or 0))
    md5 = trusted_read('/var/lib/dpkg/info/ufw.md5sums').decode('ascii')
    packaged = {}
    for line in md5.splitlines():
        h, path = line.split(None, 1)
        packaged['/' + path] = h
    for path in seen:
        if path in packaged:
            need(hashlib.md5(trusted_read(path)).hexdigest() == packaged[path],
                 'UFW dpkg secondary digest mismatch')
    raw = trusted_read('/etc/default/ufw', 65536)
    values = literals(raw, {'IPV6', 'DEFAULT_INPUT_POLICY', 'DEFAULT_OUTPUT_POLICY',
        'DEFAULT_FORWARD_POLICY', 'DEFAULT_APPLICATION_POLICY', 'MANAGE_BUILTINS',
        'IPT_SYSCTL', 'IPT_MODULES'})
    need(set(values) == {'IPV6', 'DEFAULT_INPUT_POLICY', 'DEFAULT_OUTPUT_POLICY',
        'DEFAULT_FORWARD_POLICY', 'DEFAULT_APPLICATION_POLICY', 'MANAGE_BUILTINS',
        'IPT_SYSCTL', 'IPT_MODULES'} and values['IPV6'] in ('yes', 'no') and
        values['MANAGE_BUILTINS'] == 'no' and values['IPT_MODULES'] == '' and
        values['IPT_SYSCTL'] == '/etc/ufw/sysctl.conf' and all(values[k] in
        ('ACCEPT', 'DROP', 'REJECT') for k in ('DEFAULT_INPUT_POLICY',
        'DEFAULT_OUTPUT_POLICY', 'DEFAULT_FORWARD_POLICY')) and
        values['DEFAULT_APPLICATION_POLICY'] in ('ACCEPT', 'DROP', 'REJECT', 'SKIP'),
        'unsupported literal UFW defaults')
    seen['/etc/default/ufw'] = hashlib.sha256(raw).hexdigest()
    raw = trusted_read('/etc/ufw/sysctl.conf', 65536)
    need(hashlib.sha256(raw).hexdigest() == pins['/etc/ufw/sysctl.conf'],
         'unreviewed UFW sysctl policy')
    seen['/etc/ufw/sysctl.conf'] = hashlib.sha256(raw).hexdigest()
    conf = trusted_read('/etc/ufw/ufw.conf', 65536)
    values = literals(conf, {'ENABLED', 'LOGLEVEL'})
    need(values.get('ENABLED') in ('yes', 'no') and values.get('LOGLEVEL', 'off') in
         ('off', 'low', 'medium', 'high', 'full'), 'unsupported UFW configuration')
    enabled = values['ENABLED'] == 'yes'
    need(not enabled or mode != 'prerouting_scoped', 'active UFW with LAN Redirect')
    props = dict(line.split('=', 1) for line in run(*UFW_UNIT).decode().splitlines())
    need(props == {'FragmentPath': '/usr/lib/systemd/system/ufw.service',
                   'DropInPaths': '', 'NeedDaemonReload': 'no'}, 'custom or stale UFW unit')
    # Stable code/default hashes only; ENABLED and runtime filter rules can change
    # safely without changing the boot assessment's administrative policy bytes.
    return {'enabled': enabled, 'class': 'reviewed_nf_tables', 'sha256': digest(seen)}


def literals(raw, allowed):
    need(all(c in (9, 10) or 32 <= c <= 126 for c in raw), 'nonliteral configuration')
    result = {}
    for rawline in raw.decode('ascii').splitlines():
        line = rawline.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        need(sep and key in allowed and key not in result, 'unknown literal key')
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        need(re.fullmatch(r'[A-Za-z0-9_./ -]*', value) is not None, 'shell syntax refused')
        result[key] = value
    return result


TRACE_BATCH_SCHEMA = 'aegis_auto_witness_trace_batch_v1'


def _active_trace_rule(obj):
    """One read-only trace rule as (family, oifname, daddr, sport, dport, prefix)."""
    keys(obj,('family','table','chain','expr'),('handle',))
    expr=obj['expr'];need(obj['chain']=='trace_out' and type(expr) is list and
                        len(expr)==6,'unsafe active trace rule')
    matches=[]
    for expression in expr[:5]:
        keys(expression,('match',));m=expression['match'];keys(m,('op','left','right'))
        need(m['op']=='==','unsafe active trace comparison');matches.append(m)
    lefts=[m['left'] for m in matches]
    family=lefts[1].get('payload',{}).get('protocol') if type(lefts[1]) is dict else None
    need(family in ('ip','ip6') and lefts==[
        {'meta':{'key':'oifname'}},{'payload':{'protocol':family,'field':'daddr'}},
        {'payload':{'protocol':'udp','field':'sport'}},
        {'payload':{'protocol':'udp','field':'dport'}},
        {'payload':{'base':'th','offset':64,'len':96}}],
        'unsafe active trace operands')
    interface,address,sport,dport,nonce=[m['right'] for m in matches]
    import ipaddress
    need(type(interface) is str and IFACE.fullmatch(interface) and
         type(address) is str and ipaddress.ip_address(address) in
         ipaddress.ip_network('198.18.0.0/15' if family=='ip' else '2001:db8::/32') and
         all(type(x) is int and 1024<=x<=65535 for x in (sport,dport)) and sport!=dport,
         'unsafe active trace tuple')
    # nft JSON represents raw 96-bit payload values as an integer or 0x string.
    if type(nonce) is str:
        need(re.fullmatch(r'0x[0-9a-f]{1,24}',nonce),'invalid trace payload prefix')
        nonce=int(nonce,16)
    need(type(nonce) is int and 0<=nonce<1<<96,'duplicate or invalid trace payload prefix')
    need(expr[5]=={'mangle':{'key':{'meta':{'key':'nftrace'}},'value':1}},
         'active trace mutates packet authority')
    return family,interface,address,sport,dport,nonce


def verify_active_trace_table(nft, expected=None):
    """Allow only the source witness's benign tracing projections.

    Exactly one of two shapes is admitted. The single-family witness has 8
    rows: one table, one chain and six rules of one tuple. The merged
    dual-family witness has 14 rows: one table, one chain and twelve rules,
    exactly two tuples on one oifname (one ip in 198.18.0.0/15, one ip6 in
    2001:db8::/32) with distinct source ports and six rules each. Every
    payload prefix is distinct across the whole table. Every rule is
    match-only plus `meta nftrace set 1`.

    The independent monitor uses this while borrowing the authenticated
    active actor's original OFD. With `expected` (the exact batch the
    guardian installed), every rule must also equal it field for field and
    in order. It never admits packet verdicts, mark writes, queues or an
    arbitrary AEGIS-named object.
    """
    rows=[(kind,obj) for row in nft['nftables'] for kind,obj in row.items()
          if obj.get('family')=='inet' and
             obj.get('table',obj.get('name'))=='aegis_auto_witness']
    need(len(rows) in (8,14),'active trace inventory differs')
    tables=chains=0;parsed=[]
    for kind,obj in rows:
        if kind=='table':
            keys(obj,('family','name'),('handle',));tables+=1;continue
        if kind=='chain':
            keys(obj,('family','table','name','type','hook','prio','policy'),('handle',))
            need(obj['name']=='trace_out' and obj['type']=='filter' and obj['hook']=='output'
                 and obj['prio']==-200 and obj['policy']=='accept','unsafe active trace chain')
            chains+=1;continue
        need(kind=='rule','unknown active trace object')
        parsed.append(_active_trace_rule(obj))
    need(tables==chains==1 and len(parsed)==len(rows)-2,'active trace shape differs')
    prefixes=[rule[5] for rule in parsed]
    need(len(set(prefixes))==len(prefixes),'duplicate or invalid trace payload prefix')
    tuples=list(dict.fromkeys(rule[:5] for rule in parsed))
    if len(parsed)==6:
        need(len(tuples)==1,'mixed active trace tuples')
    else:
        need(len(tuples)==2 and sorted(item[0] for item in tuples)==['ip','ip6'] and
             tuples[0][1]==tuples[1][1] and tuples[0][3]!=tuples[1][3] and
             all(sum(1 for rule in parsed if rule[:5]==item)==6 for item in tuples),
             'mixed active trace tuples')
    if expected is None:
        return
    import ipaddress
    need(type(expected) is dict and set(expected)=={'schema','rules'} and
         expected['schema']==TRACE_BATCH_SCHEMA and type(expected['rules']) is list and
         len(expected['rules'])==len(parsed),'active trace differs from installed batch')
    for observed,wanted in zip(parsed,expected['rules']):
        need(type(wanted) is dict and
             set(wanted)=={'family','oifname','daddr','sport','dport','prefix'} and
             type(wanted['daddr']) is str and
             (observed[0],observed[1],ipaddress.ip_address(observed[2]),
              observed[3],observed[4],observed[5])==
             (wanted['family'],wanted['oifname'],ipaddress.ip_address(wanted['daddr']),
              wanted['sport'],wanted['dport'],wanted['prefix']),
             'active trace differs from installed batch')


def scoped_prepared_phase(policy):
    """Admit only the exact deny-only scoped INPUT gate before BIND.

    The guardian installs it during capture registration (scoped_prepare);
    the ExecStartPre BIND writes BOUND later. The gate drops direct listener
    access and accepts only DNAT'd owner-marked flows, so it grants no egress.
    The host identity, the receipt chain and the live projection are checked;
    every other receipt combination or kernel shape refuses.
    """
    need(not policy.SCOPED_ACTIVE.exists() and not policy.SCOPED_ACTIVE.is_symlink(),
         'scoped active receipt without bound owner')
    intent = policy._scoped_read(policy.SCOPED_INTENT)
    need(type(intent) is dict and type(intent.get('binding')) is dict,
         'scoped prepared intent invalid')
    binding = policy._scoped_binding(intent['binding'], check_host=True)
    need(intent == policy._scoped_intent(binding), 'scoped prepared intent changed')
    prepared = policy._scoped_prepared(binding, live=True)
    retire = policy.SCOPED_RETIRE_INTENT
    if retire.exists() or retire.is_symlink():
        # A prepared-only retire publishes its exact intent before deleting
        # this same table; any bound/active or changed record still refuses.
        need(policy._scoped_read(retire) == {
            'schema': 'aegis_auto_scoped_redirect_retire_intent_v1',
            'intent_sha256': policy._scoped_hash(intent),
            'prepared_sha256': policy._scoped_hash(prepared),
            'bound_sha256': None, 'active_sha256': None,
            'prior_policy': prepared['policy'], 'reboot': False},
            'scoped prepared retire intent changed')
    need(not policy.SCOPED_ACTIVE.exists() and not policy.SCOPED_ACTIVE.is_symlink(),
         'scoped prepared phase changed')
    return binding


def verified_owned_tables(nft, state_path, binding_overrides=None, *, binding_candidates=None,
                          binding_candidate_provider=None, binding_observer=None, allow_active_trace=False,
                          expected_active_trace=None, expected_state_sha256=None):
    import aegis_auto_guard_policy as policy
    present = {(o.get('family'), o.get('name')) for x in nft['nftables']
               for kind, o in x.items() if kind == 'table' and o.get('name') in OWNED}
    verified = set()
    if ('inet', 'aegis_device_guard') in present:
        raw = trusted_read(state_path, 16384)
        if expected_state_sha256 is not None:
            need(type(expected_state_sha256) is str and
                 re.fullmatch(r'[0-9a-f]{64}', expected_state_sha256) is not None and
                 hashlib.sha256(raw.rstrip(b'\n')).hexdigest() == expected_state_sha256,
                 'preapply guard state changed')
        def binding(role):
            if binding_overrides is not None:return binding_overrides.get(role)
            try:return trusted_read(str(state_path) + '.' + role + '-binding', 4096)
            except FileNotFoundError:return None
        try:
            capture_binding = trusted_read(str(state_path) + '.capture-binding', 4096)
        except FileNotFoundError:
            capture_binding = None
        if capture_binding is not None:
            bound_capture = decode(capture_binding)
            need(type(bound_capture) is dict and
                 type(bound_capture.get('ifindex')) is int and
                 bound_capture['ifindex'] > 0 and
                 socket.if_nametoindex('aegis-tun0') == bound_capture['ifindex'],
                 'capture numeric binding lost its live interface')
        with prefetch(GUARD_JSON,GUARD_TEXT):
            json_raw=run(*GUARD_JSON)
            text_raw=run(*GUARD_TEXT)
        pairs=[{'client':binding('client'),'manager':binding('manager')}]
        # Resolve the original typed Stop candidate after receipt reads. A
        # revocation can precede nft replacement; every candidate must still
        # verify the exact complete JSON/text snapshot below, including all
        # chains/rules/handles. No failed snapshot becomes a permission.
        need(binding_candidate_provider is None or callable(binding_candidate_provider),
             'invalid monitor binding provider')
        need(binding_observer is None or callable(binding_observer),'invalid monitor binding observer')
        if binding_candidates is not None:
            need(type(binding_candidates) is list and len(binding_candidates)<=4,
                 'monitor binding candidate bound')
            need(all(type(pair)is dict and set(pair)=={'client','manager'}for pair in binding_candidates),
                 'bad monitor binding pair')
            pairs+=binding_candidates
        def candidates():
            yield from pairs
            if binding_candidate_provider is not None:
                fresh=binding_candidate_provider()
                need(type(fresh)is list and len(fresh)<=4,'monitor binding candidate bound')
                yield from fresh
        schema=[line.partition(b'=')[2] for line in raw.splitlines()
                if line.partition(b'=')[0]==b'schema']
        need(len(schema)==1,'guard schema missing or duplicate')
        if schema[0]==b'aegis_device_guard_v1':
            try:
                policy.verify_expected_legacy_policy(raw,json_raw,text_raw,
                    boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    capture_binding=capture_binding)
            except policy.PolicyRefused as error:
                raise ForeignPolicyRefused('persistent v1 guard differs from authenticated policy') from error
        else:
            for pair in candidates():
                need(type(pair) is dict and set(pair)=={'client','manager'},'bad monitor binding pair')
                try:
                    policy.verify_expected_policy(raw,json_raw,text_raw,pair['client'],pair['manager'],
                        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                        capture_binding=capture_binding)
                except policy.PolicyRefused:continue
                if binding_observer is not None:binding_observer(pair)
                break
            else:need(False,'persistent guard differs from every authenticated binding')
        verified.add(('inet', 'aegis_device_guard'))
    for table, path, verifier in (
        ('aegis_auto_redirect', policy.SCOPED_ACTIVE, policy.scoped_verify),
        ('aegis_auto_local_redirect', policy.LOCAL_ACTIVE, policy.local_verify)):
        if ('ip', table) not in present:
            continue
        if (table == 'aegis_auto_redirect' and not policy.SCOPED_BOUND.exists() and
                not policy.SCOPED_BOUND.is_symlink()):
            # Prepared before BIND (r9/r14 #36): exact gate only, never BOUND-less
            # PREROUTING. A symlinked BOUND takes the strict O_NOFOLLOW read below.
            scoped_prepared_phase(policy)
            verified.add(('ip', table))
            continue
        bound_path = policy.SCOPED_BOUND if table == 'aegis_auto_redirect' else policy.LOCAL_BOUND
        bound = policy._scoped_read(bound_path)
        intent_path = policy.SCOPED_INTENT if table == 'aegis_auto_redirect' else policy.LOCAL_INTENT
        binding = policy._scoped_read(intent_path)['binding']
        try:
            verifier(binding, bound['invocation_id'],
                     config_semantic_sha256=binding['config_semantic_sha256'],
                     **({'active': path.exists()} if table == 'aegis_auto_redirect' else {}))
        except (OSError, policy.PolicyRefused) as original_error:
            if table != 'aegis_auto_local_redirect':
                raise
            # Stop may retire Main's cgroup before its exact local NAT table.
            # Independent complete deny, revoked client binding and the exact
            # durable Stop owner are mandatory; runtime verification stays live.
            try:
                policy.local_verify_stopping(binding, bound['invocation_id'],
                    config_semantic_sha256=binding['config_semantic_sha256'])
            except (OSError, policy.PolicyRefused):
                raise original_error
        verified.add(('ip', table))
    # Witness calls assessment immediately before creation and after removal.
    # A trace table outside that serialized operation is never name-admitted.
    # The merged witness's own mid-window sample names the exact batch.
    need(expected_active_trace is None or
         (allow_active_trace and ('inet','aegis_auto_witness') in present),
         'installed trace batch missing')
    if ('inet','aegis_auto_witness') in present:
        need(allow_active_trace,'witness table outside held lease')
        verify_active_trace_table(nft,expected_active_trace)
        verified.add(('inet','aegis_auto_witness'))
    return verified


def exact_stopped_local_cgroup_spelling(first, second, verified):
    """Accept one source-bound nft display change after an exact owned Stop.

    The caller must restrict this to the monitor's held GuardLock and
    AssessmentLock path. This function grants no packet permission.
    """
    if ('ip', 'aegis_auto_local_redirect') not in verified:
        return False
    left = first.get('nftables') if type(first) is dict else None
    right = second.get('nftables') if type(second) is dict else None
    if type(left) is not list or type(right) is not list or len(left) != len(right):
        return False
    differences = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
    if len(differences) != 1:
        return False
    index = differences[0]
    before, after = left[index], right[index]
    if (type(before) is not dict or type(after) is not dict or
            set(before) != {'rule'} or set(after) != {'rule'} or
            type(before['rule']) is not dict or type(after['rule']) is not dict):
        return False
    b, a = before['rule'], after['rule']
    if not (b.get('family') == a.get('family') == 'ip' and
            b.get('table') == a.get('table') == 'aegis_auto_local_redirect' and
            b.get('chain') == a.get('chain') == 'output'):
        return False
    be, ae = b.get('expr'), a.get('expr')
    if type(be) is not list or type(ae) is not list or len(be) != 3 or len(ae) != 3:
        return False
    left_match, right_match = be[0], ae[0]
    if (type(left_match) is not dict or type(right_match) is not dict or
            type(left_match.get('match')) is not dict or
            type(right_match.get('match')) is not dict):
        return False
    expected = {'op': '==', 'left': {'socket': {'key': 'cgroupv2'}}}
    if not (all(left_match['match'].get(k) == v for k, v in expected.items()) and
            all(right_match['match'].get(k) == v for k, v in expected.items())):
        return False
    import aegis_auto_guard_policy as policy
    intent = policy._scoped_read(policy.LOCAL_INTENT)
    if type(intent) is not dict or type(intent.get('binding')) is not dict:
        return False
    binding = policy._local_binding(intent['binding'], check_host=False)
    bound = policy._local_bound(binding,
                                policy._scoped_read(policy.LOCAL_BOUND)['invocation_id'],
                                check_host=False)
    path, inode = bound['cgroup_path'], str(bound['cgroup_inode'])
    if not (left_match['match'].get('right') == path and
            right_match['match'].get('right') == inode and
            b.get('comment') == a.get('comment') ==
            policy._local_intent(binding)['owner_marker']):
        return False
    # Compare every complete normalized atom. Only the original owner rule's
    # displayed cgroup operand may differ; a changed foreign or other owned
    # row remains a PolicySnapshotChanged refusal.
    canonical = copy.deepcopy(second)
    canonical['nftables'][index]['rule']['expr'][0]['match']['right'] = path
    if canonical != first:
        return False
    # A named first snapshot was already admitted by verified_owned_tables.
    # The stopped verifier now proves the protected bound inode, exact local
    # JSON/text policy, durable deny and Stop owner again against the kernel.
    policy.local_verify_stopping(binding, bound['invocation_id'],
                                 config_semantic_sha256=binding['config_semantic_sha256'])
    confirmed = normalize(decode(run('nft', '--json', 'list', 'ruleset')))
    return confirmed == second


def assess_foreign_policy(uplink, *, mode='full-wide-tun', state_path=STATE, binding_overrides=None, require_guard=False, binding_candidates=None, binding_candidate_provider=None, binding_observer=None, allow_active_trace=False, allow_stopped_local_display_transition=False, expected_active_trace=None, expected_state_sha256=None):
    need(os.geteuid() == 0, 'root required')
    need(mode in ('full-wide-tun', 'wide-redirect-safe', 'prerouting_scoped'), 'unknown mode')
    # The pre-snapshot reads are independent; they start together and every
    # result is evaluated in the original order. All finish before snapshot 1.
    early = [IPTABLES_VERSION, LINK_INVENTORY]
    if Path('/etc/ufw/ufw.conf').exists():
        early.append(UFW_UNIT)
    with prefetch(*early):
        backend = run(*IPTABLES_VERSION).decode('ascii').strip()
        need('(nf_tables)' in backend, 'legacy xtables backend')
        ufw = ufw_integrity(mode)
        if Path(state_path).exists():
            fields={}
            for line in trusted_read(state_path,16384).decode('ascii').splitlines():
                k,sep,v=line.partition('=')
                need(sep and k not in fields,'invalid foreign policy administrative state')
                fields[k]=v
            if 'foreign_policy' in fields or 'ufw_integrity_sha256' in fields:
                need(fields.get('foreign_policy')=='filter_only' and
                     fields.get('ufw_integrity_sha256')==ufw['sha256'],
                     'UFW integrity differs from assessed administrative state')
        check_links(uplink)
    # Two complete snapshots detect policy transactions during cross-parsing.
    first = decode(run(*RULESET))
    need(not require_guard or any(x.get('table',{}).get('family')=='inet' and
        x.get('table',{}).get('name')=='aegis_device_guard' for x in first['nftables']),
        'persistent guard table missing')
    owned = verified_owned_tables(first, state_path, binding_overrides,
        binding_candidates=binding_candidates,binding_candidate_provider=binding_candidate_provider,
        binding_observer=binding_observer,allow_active_trace=allow_active_trace,
        expected_active_trace=expected_active_trace,
        expected_state_sha256=expected_state_sha256)
    # All four saves run together between the snapshots. Each is consumed in
    # order, and the block reaps every one before snapshot 2 can start.
    present = [c for c in ('iptables-legacy-save', 'ip6tables-legacy-save') if shutil.which(c)]
    with prefetch(('iptables-save',), ('ip6tables-save',), *((c,) for c in present)):
        saves = {f: run(c) for f, c in (('ip', 'iptables-save'), ('ip6', 'ip6tables-save'))}
        legacy = [run(c) if c in present else b'' for c in
                  ('iptables-legacy-save', 'ip6tables-legacy-save')]
    for name in ('ip', 'ip6', 'arp'):
        path = Path('/proc/net/' + name + '_tables_names')
        if path.exists():
            need(set(path.read_text().split()) <= {'filter', 'nat', 'raw', 'mangle', 'security'},
                 'unknown legacy table')
    projection = assess_rules(first, saves, legacy, verified_owned=owned)
    second = decode(run(*RULESET))
    normalized_first, normalized_second = normalize(first), normalize(second)
    if normalized_first != normalized_second and not (
            allow_stopped_local_display_transition and require_guard and
            mode == 'wide-redirect-safe' and
            exact_stopped_local_cgroup_spelling(normalized_first, normalized_second, owned)):
        raise PolicySnapshotChanged(normalized_first, normalized_second)
    return {'schema': 'aegis_foreign_policy_v1', 'class': 'filter_only',
            'backend': 'nf_tables', 'foreign_projection_sha256': digest(projection),
            'ufw_class': ufw['class'], 'ufw_integrity_sha256': ufw['sha256'],
            'ufw_enabled': ufw['enabled']}


def ufw_snapshot():
    rules=decode(run('nft','--json','list','ruleset'))
    rows=[]
    for item in rules['nftables']:
        kind,obj=next(iter(item.items()))
        if kind=='metainfo':continue
        if obj.get('family') in ('ip','ip6') and obj.get('table',obj.get('name'))=='filter':
            rows.append(normalize(item))
    conf=Path('/etc/ufw/ufw.conf')
    return {'schema':'aegis_ufw_reverse_snapshot_v1',
        'ufw_conf_sha256':hashlib.sha256(trusted_read(conf)).hexdigest() if conf.exists() else None,
        'filter_projection_sha256':digest(rows),
        'unit_state':run('systemctl','show','ufw.service','-p','ActiveState','-p','UnitFileState').decode('ascii')}


def retain_ufw_snapshot(path):
    value=ufw_snapshot()
    if path.exists():
        decode(trusted_read(path,16384))
        return
    raw=(json.dumps(value,sort_keys=True)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(d)
    finally:os.close(d)


def main():
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--uplink')
    p.add_argument('--snapshot',type=Path)
    p.add_argument('--verify-snapshot',type=Path)
    p.add_argument('--mode', default='full-wide-tun')
    p.add_argument('--state', type=Path, default=STATE)
    a = p.parse_args()
    if a.snapshot is not None:
        need(os.geteuid()==0,'root required')
        retain_ufw_snapshot(a.snapshot)
        return
    if a.verify_snapshot is not None:
        need(ufw_snapshot()==decode(trusted_read(a.verify_snapshot,16384)),
             'UFW reverse check differs from pre-install snapshot')
        print(json.dumps({'ufw_unchanged':True}))
        return
    need(a.uplink is not None,'uplink required')
    print(json.dumps(assess_foreign_policy(a.uplink, mode=a.mode, state_path=a.state),
                     sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('Foreign policy refused: ' + str(error))
