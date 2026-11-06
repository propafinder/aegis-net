#!/usr/bin/env bash
# Exercise the real wrapper/deadman and root-state library with inert commands.
# Every administrative path is relocated; no host firewall/resolver is changed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROLLBACK_TEST_BASH="${AEGIS_TEST_BASH_BINARY:-$(command -v bash)}"
TASK_TMP="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wide-rollback.XXXXXX")"
TASK_TMP="$(cd "$TASK_TMP" && pwd -P)"
trap 'rm -rf "$TASK_TMP"' EXIT
"$ROLLBACK_TEST_BASH" -n "$ROOT/scripts/aegis-wide-enable.sh"
"$ROLLBACK_TEST_BASH" -n "$ROOT/scripts/aegis-origin-guard.sh"

python3 - "$ROOT" "$TASK_TMP" "$ROLLBACK_TEST_BASH" <<'PY'
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

root, work, bash_binary = map(Path, sys.argv[1:])
assert bash_binary.is_absolute() and os.access(bash_binary, os.X_OK)
host = work / 'host'
bin_dir = work / 'bin'
# Quotes, shell metacharacters and expansion syntax are literal path bytes.
scripts = work / 'scripts\'";touch "$AEGIS_ROLLBACK_TEST_INJECTED";#'
for path in (host / 'etc/aegis/client', host / 'etc/sysctl.d', host / 'run',
             host / 'var/lib/aegis-install/client', scripts / 'lib', bin_dir):
    path.mkdir(parents=True, mode=0o700)
config = host / 'etc/aegis/client/aegis.toml'
resolver = host / 'etc/resolv.conf'
snapshot = host / 'var/lib/aegis-install/client/resolver-original.json'
sentinel = host / 'run/aegis-wide-confirmed";touch "$AEGIS_ROLLBACK_TEST_SENTINEL_INJECTED";#'
client = bin_dir / 'state-client\'";touch "$AEGIS_ROLLBACK_TEST_CLIENT_INJECTED";#'
injected = [work / name for name in ('path-injected', 'sentinel-injected', 'client-injected')]

def relocate(text):
    for prefix in ('/etc/', '/var/lib/', '/run/'):
        text = text.replace(prefix, str(host) + prefix)
    return text

text = relocate((root / 'scripts/aegis-wide-enable.sh').read_text())
old = 'SENTINEL_FILE="' + str(host / 'run/aegis-wide-confirmed') + '"'
assert text.count(old) == 1
text = text.replace(old, 'SENTINEL_FILE=' + shlex.quote(str(sentinel)))
(scripts / 'aegis-wide-enable.sh').write_text(text)
(scripts / 'lib/root-state.sh').write_text(relocate((root / 'scripts/lib/root-state.sh').read_text()))

# Fake typed metadata is deliberately restricted to this fixture. The actual
# shell library still authenticates the administrator-owned executable and
# initializes/rechecks resolver state in each process. No real client is needed.
stub = r'''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
case = pathlib.Path(os.environ['AEGIS_ROLLBACK_TEST_CASE'])
host = pathlib.Path(os.environ['AEGIS_ROLLBACK_TEST_HOST'])
with (case / 'commands.jsonl').open('a') as out:
    out.write(json.dumps([name, args]) + '\n')
fail = os.environ.get('AEGIS_ROLLBACK_TEST_FAIL', '')
def counter(label):
    path = case / label
    value = int(path.read_text()) + 1 if path.exists() else 1
    path.write_text(str(value))
    return value
def guarded(path):
    path = pathlib.Path(path)
    if os.path.commonpath([str(host), str(path)]) != str(host) or '..' in path.parts:
        raise ValueError('fixture administrative path escaped')
    current = path
    while current != host:
        if current.is_symlink():
            raise ValueError('fixture symlink rejected')
        current = current.parent
    if path.exists() and path.stat().st_mode & 0o022:
        raise ValueError('fixture writable state rejected')
    return path
if name.startswith('state-client'):
    assert args[:2] == ['profile', 'metadata']
    command = args[2]
    if command == '--help':
        if counter('help-count') == 2 and fail == 'late-init':
            sys.exit(31)
        sys.exit(0)
    for i, value in enumerate(args[:-1]):
        if value in ('--path', '--snapshot'):
            guarded(args[i + 1])
    if command == 'validate':
        sys.exit(32 if fail == 'parent-preflight' else 0)
    if command == 'resolver-check':
        count = counter('resolver-check-count')
        sys.exit(33 if count == 2 and fail == 'late-resolver' else 0)
    if command == 'resolver-restore':
        source = guarded(args[args.index('--snapshot') + 1])
        target = guarded(args[args.index('--path') + 1])
        record = json.loads(source.read_text())
        assert set(record) == {'fixture_original'}
        target.write_text(record['fixture_original'])
        source.unlink()
        sys.exit(0)
    raise ValueError('unexpected metadata operation')
if name == 'iptables':
    # A failed -N may mean an existing chain; -F must then succeed.
    if '-N' in args and fail in ('chain', 'existing-chain'):
        sys.exit(41)
    if '-F' in args and fail == 'chain':
        sys.exit(42)
    if '-C' in args:
        sys.exit(1)
    if '-I' in args and fail == 'hook':
        sys.exit(43)
    if '-A' in args:
        if '--sport' in args and args[args.index('--sport') + 1] == '22' and '--ctdir' in args and fail == 'ssh-port':
            sys.exit(44)
        if '-d' in args:
            dest = args[args.index('-d') + 1]
            if dest == '192.0.2.19' and fail == 'ssh-peer':
                sys.exit(45)
            if dest == '198.51.100.27' and '-p' in args:
                proto = args[args.index('-p') + 1]
                if fail == 'relay-' + proto:
                    sys.exit(46)
    sys.exit(0)
if name == 'setsid':
    (case / 'timer-argv.json').write_text(json.dumps(args))
    if fail == 'confirmed':
        pathlib.Path(args[5]).touch()
    # Exercise the real shell executable-custody check, not just a fake
    # metadata failure. This mode change is confined to our own fixture client.
    if fail == 'late-untrusted-client':
        pathlib.Path(args[9]).chmod(0o777)
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=5)
    finally:
        if fail == 'late-untrusted-client':
            pathlib.Path(args[9]).chmod(0o700)
    (case / 'timer.out').write_text(result.stdout + result.stderr)
    (case / 'timer-status').write_text(str(result.returncode))
    sys.exit(result.returncode)
if name == 'ip':
    if args[:4] == ['-4', 'route', 'show', 'default']:
        print('default via 192.0.2.1 dev eth0')
    sys.exit(0)
if name in ('setup-wide-linux-redirect.sh', 'setup-wide-linux-tproxy.sh'):
    assert args in (['cgroup-path'], ['preflight'], ['apply'], ['teardown'])
    if args in (['cgroup-path'], ['preflight'], ['apply']):
        assert os.environ.get('AEGIS_WIDE_REQUIRE_CGROUP') == '1'
        assert os.environ.get('AEGIS_WIDE_EXEMPT_SERVICE') == 'aegis-client.service'
        if args == ['cgroup-path']:
            assert 'AEGIS_WIDE_EXEMPT_CGROUP' not in os.environ
            if fail == 'service-identity': sys.exit(47)
            print('system.slice/aegis-client.service')
        else:
            assert os.environ.get('AEGIS_WIDE_EXEMPT_CGROUP') == 'system.slice/aegis-client.service'
            if args == ['preflight'] and fail == 'service-preflight': sys.exit(48)
    sys.exit(0)
if name in ('sleep', 'logger', 'systemctl'):
    sys.exit(0)
# Deny any unexpected privileged operation rather than falling through to host.
sys.exit(97)
'''
for name in ('iptables', 'ip6tables', 'nft', 'ip', 'sysctl', 'systemctl', 'logger',
             'sleep', 'setsid', 'sudo', 'resolvectl', 'networkctl', 'firewall-cmd'):
    path = bin_dir / name
    path.write_text(stub)
    path.chmod(0o700)
client.write_text(stub)
client.chmod(0o700)
for name in ('setup-wide-linux-redirect.sh', 'setup-wide-linux-tproxy.sh'):
    path = scripts / name
    path.write_text(stub)
    path.chmod(0o700)
# Both the wrapper and its literal `setsid bash -c` use the selected shell.
(bin_dir / 'bash').write_text('#!/bin/sh\nexec ' + shlex.quote(str(bash_binary)) + ' "$@"\n')
(bin_dir / 'bash').chmod(0o700)

base = {k: v for k, v in os.environ.items()
        if not k.startswith('AEGIS_') and k not in ('SSH_CONNECTION', 'BASH_ENV', 'ENV')}
base.update(PATH=str(bin_dir) + os.pathsep + os.environ['PATH'],
            AEGIS_WIDE_SKIP_ROOT_CHECK='1', AEGIS_EXEMPT_UID='424',
            AEGIS_ROOT_STATE_CLIENT=str(client), AEGIS_WIDE_ROLLBACK_SECS='7',
            AEGIS_ROLLBACK_TEST_HOST=str(host),
            AEGIS_ROLLBACK_TEST_INJECTED=str(injected[0]),
            AEGIS_ROLLBACK_TEST_SENTINEL_INJECTED=str(injected[1]),
            AEGIS_ROLLBACK_TEST_CLIENT_INJECTED=str(injected[2]),
            SSH_CONNECTION='192.0.2.19 54321 192.0.2.10 22')

def require(value, message):
    if not value:
        raise AssertionError(message)

def run_case(name, failure='', interval='7'):
    case = work / name
    case.mkdir(mode=0o700)
    # The Linux detector uses GNU sed's \s extension; the no-space spelling
    # also permits this stub-only contract to execute under macOS BSD sed.
    config.write_text('[relay]\nserver="198.51.100.27:443"\n')
    config.chmod(0o600)
    resolver.write_text('# Managed by aegis fixture\nnameserver 127.0.0.1\n')
    resolver.chmod(0o600)
    snapshot.write_text(json.dumps({'fixture_original': 'nameserver 192.0.2.53\n'}))
    snapshot.chmod(0o600)
    if sentinel.exists():
        sentinel.unlink()
    env = dict(base, AEGIS_ROLLBACK_TEST_CASE=str(case),
               AEGIS_ROLLBACK_TEST_FAIL=failure, AEGIS_WIDE_ROLLBACK_SECS=interval)
    result = subprocess.run(['bash', str(scripts / 'aegis-wide-enable.sh'), '--yes',
                             '--mode=redirect', '--interface=eth0', '--dns=off',
                             '--ipv6=block', '--ssh-safe-ports=22'],
                            env=env, capture_output=True, text=True, timeout=8)
    (case / 'parent.out').write_text(result.stdout + result.stderr)
    # The production timer is detached; wait only for this fake setsid's finite
    # receipt. Confirmation and full recording are not conflated with this wait.
    if result.returncode == 0:
        deadline = time.monotonic() + 6
        while not (case / 'timer-status').exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        require((case / 'timer-status').exists(), name + ': timer never completed')
    records = [json.loads(line) for line in (case / 'commands.jsonl').read_text().splitlines()] \
        if (case / 'commands.jsonl').exists() else []
    require(not any(path.exists() for path in injected), name + ': path was executed as shell source')
    return case, result, records

def called(records, name, args=None):
    return any(row[0] == name and (args is None or row[1] == args) for row in records)

try:
    case, result, records = run_case('literal-path-and-resolver')
    require(result.returncode == 0, 'literal-path activation failed')
    argv = json.loads((case / 'timer-argv.json').read_text())
    require(argv[:2] == ['bash', '-c'], 'timer did not invoke fixed bash program')
    require(argv[3:] == ['aegis-wide-enable', '7', str(sentinel), 'AEGIS_WIDE_SSH_EXEMPT',
                         str(scripts / 'setup-wide-linux-redirect.sh'),
                         str(scripts / 'lib/root-state.sh'), str(client), str(snapshot)],
            'timer lost a positional value or parent-default state path')
    require(all(value not in argv[2] for value in (str(sentinel), str(scripts), str(client))),
            'timer embedded a pathname in shell source')
    require(called(records, 'sleep', ['7']), 'sleep interval not transferred exactly')
    require(called(records, 'setup-wide-linux-redirect.sh', ['apply']) and
            called(records, 'setup-wide-linux-redirect.sh', ['teardown']), 'helper path/action not transferred')
    require((case / 'help-count').read_text() == '2' and
            (case / 'resolver-check-count').read_text() == '2', 'child did not initialize/recheck trusted state')
    require(resolver.read_text() == 'nameserver 192.0.2.53\n' and not snapshot.exists(),
            'deadman did not restore retained resolver state')
    require(called(records, 'systemctl', ['start', '--no-block', 'systemd-resolved']),
            'resolver service was not restored')
    require((case / 'timer-status').read_text() == '0', 'deadman cleanup failed')
    print('ok: literal quoted paths, exact deadman argv/defaults, child trusted state and resolver restore')

    # Destination-only relay exceptions no longer exist. Their old mutation
    # failures are replaced by actual identity/preflight refusal controls.
    for failure in ('chain', 'ssh-port', 'ssh-peer', 'service-identity', 'service-preflight', 'hook'):
        case, result, records = run_case('reject-' + failure, failure)
        require(result.returncode == 4, failure + ': exemption failure did not abort')
        require('refusing capture apply' in (case / 'parent.out').read_text(), failure + ': missing refusal')
        require(not called(records, 'setup-wide-linux-redirect.sh', ['apply']) and not called(records, 'setsid'),
                failure + ': capture helper or timer reached after failed exemption')
        require(snapshot.exists(), failure + ': rollback state was consumed')
    print('ok: chain creation/flush, exact SSH reply, verified service identity/preflight and OUTPUT-hook errors abort before capture')

    case, result, records = run_case('existing-chain', 'existing-chain')
    require(result.returncode == 0 and called(records, 'setup-wide-linux-redirect.sh', ['apply']),
            'existing chain could not be flushed before capture')
    print('ok: existing-chain flush success remains supported')

    case, result, records = run_case('parent-preflight', 'parent-preflight')
    require(result.returncode != 0 and not any(row[0] in ('iptables', 'systemctl', 'setsid',
            'setup-wide-linux-redirect.sh') for row in records), 'parent preflight did not precede mutations')
    print('ok: denied parent trusted-state preflight performs no firewall/service/capture mutation')

    case, result, records = run_case('invalid-interval', interval='7; touch "$AEGIS_ROLLBACK_TEST_INJECTED"; #')
    require(result.returncode == 2 and not records, 'invalid deadman interval reached state/mutation')
    print('ok: invalid interval rejected before initialization or mutation')

    for failure in ('late-init', 'late-resolver', 'late-untrusted-client'):
        case, result, records = run_case(failure, failure)
        require(result.returncode == 0 and (case / 'timer-status').read_text() != '0',
                failure + ': late trust failure did not refuse deadman cleanup')
        require(not called(records, 'setup-wide-linux-redirect.sh', ['teardown']) and
                not called(records, 'systemctl') and not any('-D' in row[1] for row in records),
                failure + ': cleanup mutation preceded child trust validation')
        require(snapshot.exists(), failure + ': rejected recovery state was consumed')
    print('ok: late child init/resolver/executable-custody refusal preserves state before teardown')

    case, result, records = run_case('confirmed', 'confirmed')
    require(result.returncode == 0 and (case / 'timer-status').read_text() == '0', 'confirmed timer failed')
    require(not called(records, 'setup-wide-linux-redirect.sh', ['teardown']) and
            (case / 'help-count').read_text() == '1' and snapshot.exists(),
            'confirmed timer still attempted cleanup')
    print('ok: confirmed timer skips cleanup')
except BaseException:
    for case in sorted(work.iterdir()):
        if case.is_dir() and (case / 'parent.out').exists():
            print('FAILED-RUN-RECEIPT ' + case.name, file=sys.stderr)
            for name in ('parent.out', 'timer.out', 'commands.jsonl'):
                path = case / name
                if path.exists():
                    print(path.read_text(), file=sys.stderr)
    raise
print('PASS: bounded wide rollback safety; all firewall/service/resolver operations are fixture stubs')
PY

# Existing finite rollback lane owns these eight inert actual-block controls.
AEGIS_TEST_BASH_BINARY="$ROLLBACK_TEST_BASH" python3 "$ROOT/scripts/test-wide-wrapper-owned-exemption-contract.py"

# Whole wrapper/independent rollback with actual private metadata and inert OS commands.
AEGIS_TEST_CLIENT_BINARY="${AEGIS_TEST_CLIENT_BINARY:-$ROOT/target/debug/aegis-client}" python3 "$ROOT/scripts/test-wide-wrapper-preview-transaction-contract.py"
