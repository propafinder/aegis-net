#!/usr/bin/env python3
"""Run one source-bound CI command from a private interactive launchd job.

A QoS clamp belongs to the process and survives fork/exec. An after-exec
pthread/task request alone cannot remove it. Only the private job gets a
fresh launch context; its command and cancellation checks remain unchanged.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import resource
import secrets
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve()
ENV_KEYS = frozenset(('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'RUSTUP_HOME',
    'CARGO_HOME', 'CARGO_TARGET_DIR', 'MACOSX_DEPLOYMENT_TARGET', 'PKG_CONFIG_PATH',
    'PKG_CONFIG_LIBDIR', 'VPX_VERSION', 'LIBRARY_PATH', 'CPATH', 'SDKROOT',
    'CARGO_NET_OFFLINE', 'CARGO_INCREMENTAL', 'CARGO_PROFILE_DEV_DEBUG',
    'CARGO_PROFILE_TEST_DEBUG', 'CARGO_PROFILE_TEST_OPT_LEVEL',
    'CARGO_PROFILE_TEST_DEBUG_ASSERTIONS', 'CARGO_PROFILE_TEST_OVERFLOW_CHECKS',
    'AEGIS_B06_TIMING_TRACE', 'AEGIS_BUILD_GIT_SHA',
    'AEGIS_BUILD_TIMESTAMP', 'AEGIS_BUILD_TARGET', 'AEGIS_BUILD_FEATURES',
    'AEGIS_CARGO_LOCK_SHA256'))


def need(ok, label):
    if not ok:
        raise RuntimeError(label)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def helpers():
    base = HERE.with_name('run-b08-clippy-host-r1.py')
    c15 = HERE.with_name('run-final-source-contracts-r1.py')
    need(sha(base) == '7559f2b493699ce6579afa73244f0ee8a455da6957dffb88fa8321661c844cc8'
         and sha(c15) == '0d1b216465385a0cc1f3c5ccd8ab32566c441a8f8e9563164d08eb1a5dbfa752',
         'closure_helper_changed')
    return load('launchd_base', base), load('launchd_c15', c15)


def run(argv, valid=(0,), timeout=20):
    row = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    need(row.returncode in valid and len(row.stdout) + len(row.stderr) <= 65536, 'launchctl_refusal')
    return row


def domain_exists(domain):
    # A domain's complete service inventory can exceed the job output cap.
    # Only its existence is needed; no inventory is retained or parsed.
    row = subprocess.run(['/bin/launchctl', 'print', domain], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
    need(row.returncode in (0, 113) and len(row.stderr) <= 4096, 'launchd_domain_refusal')
    return row.returncode == 0


def write(path, row):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(row, out, sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())


def job_plist(row):
    job = {'Label': row['label'], 'ProgramArguments': [row['python'], '-I', '-B', str(HERE),
            '--worker', row['bundle'], row['bundle_sha']], 'RunAtLoad': True,
            'ProcessType': 'Interactive', 'KeepAlive': False, 'AbandonProcessGroup': False,
            'ExitTimeOut': 20, 'Umask': 0o077, 'WorkingDirectory': row['repo'],
            'EnvironmentVariables': row['env'],
            'StandardOutPath': str(Path(row['execution']) / 'worker.stdout'),
            'StandardErrorPath': str(Path(row['execution']) / 'worker.stderr')}
    # These remain job-scoped in the only admitted gui/user domains.
    job['Nice'] = row['nice']
    job['SoftResourceLimits'] = {'NumberOfFiles': row['nofile'][0]}
    if row['nofile'][1] != resource.RLIM_INFINITY:
        job['HardResourceLimits'] = {'NumberOfFiles': row['nofile'][1]}
    return job


def bundle(path, pin):
    need(path.is_absolute() and not path.is_symlink() and path.stat().st_uid == os.getuid()
         and stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_nlink == 1
         and path.stat().st_size < 65536 and sha(path) == pin, 'bundle_identity')
    row = json.loads(path.read_bytes())
    need(row['bundle'] == str(path) and row['execution'] == str(path.parent)
         and row['operator_sha'] == sha(HERE) and row['domain'] in
         ('gui/' + str(os.getuid()), 'user/' + str(os.getuid()))
         and re.fullmatch(r'org\.aegis\.ci\.ne\.[0-9a-f]{32}', row['label'])
         and 1 <= row['timeout'] <= 2700 and row['argv']
         and Path(row['argv'][0]).is_absolute() and set(row['env']) <= ENV_KEYS
         and type(row['nice']) is int and -20 <= row['nice'] <= 19
         and type(row['nofile']) is list and len(row['nofile']) == 2
         and all(type(v) is int for v in row['nofile'])
         and 256 <= row['nofile'][0] <= row['nofile'][1] <= resource.RLIM_INFINITY,
         'bundle_shape')
    return row


def source(row, base):
    base.verify_source(Path(row['repo']), Path(row['manifest']), row['commit'], row['manifest_sha'])


def worker(row):
    base, c15 = helpers()
    execution = Path(row['execution'])
    before = list(resource.getrlimit(resource.RLIMIT_NOFILE))
    try:
        # Preserve the invoking job's actual descriptor budget. A fresh launchd
        # job otherwise silently uses its small default (EMFILE in NE bursts).
        resource.setrlimit(resource.RLIMIT_NOFILE, tuple(row['nofile']))
        observed = list(resource.getrlimit(resource.RLIMIT_NOFILE))
        nice = os.getpriority(os.PRIO_PROCESS, 0)
        write(execution / 'process-context.json', {'caller_nofile': row['nofile'],
              'worker_before_nofile': before, 'worker_nofile': observed,
              'caller_nice': row['nice'], 'worker_nice': nice})
        need(observed == row['nofile'] and nice == row['nice'], 'caller_resource_context_not_preserved')
        source(row, base)
    except Exception as error:
        write(execution / 'worker-result.json', {'command_closed': True, 'command': {
            'name': 'command', 'argv': row['argv'], 'executed': False,
            'exit_code': 73, 'reason': 'worker_admission_refused', 'passed': False},
            'admission_failure': type(error).__name__})
        return 73
    stop = [False]
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.__setitem__(0, True))
    c15.PER_COMMAND_SECONDS = row['timeout']
    result = c15.one(Path(row['repo']), Path(row['execution']), 'command', row['argv'], stop)
    source(row, base)
    write(Path(row['execution']) / 'worker-result.json', {'command_closed': True, 'command': result})
    return result['exit_code'] if result['reason'] == 'exit' else 124


def stop_job(row):
    service = row['domain'] + '/' + row['label']
    # An exited one-shot remains registered but kill returns ESRCH (3).
    # Bootout and the independent absence check run even if signaling fails.
    try:
        run(['/bin/launchctl', 'kill', 'SIGTERM', service], valid=(0, 3, 113))
        deadline = time.monotonic() + 20
        result = Path(row['execution']) / 'worker-result.json'
        while not result.exists() and time.monotonic() < deadline:
            probe = run(['/bin/launchctl', 'print', service], valid=(0, 113))
            if probe.returncode == 113:
                break
            time.sleep(.1)
    finally:
        run(['/bin/launchctl', 'bootout', service], valid=(0, 113))
        need(run(['/bin/launchctl', 'print', service], valid=(0, 113)).returncode == 113,
             'job_absence_unproved')


def guard(row):
    base, _ = helpers();out = Path(row['execution'])
    write(out / 'guard-ready.json', {'label': row['label'], 'owner_start': row['owner_start']})
    while time.time() < row['deadline'] and base.marker(row['owner_pid']) == row['owner_start']:
        time.sleep(.25)
    stop_job(row)
    write(out / 'rollback.json', {'label': row['label'], 'job_absent': True})
    return 0


def main():
    os.umask(0o077)
    if len(sys.argv) == 4 and sys.argv[1] in ('--worker', '--guard'):
        row = bundle(Path(sys.argv[2]), sys.argv[3]);return worker(row) if sys.argv[1] == '--worker' else guard(row)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--execution', type=Path, required=True)
    parser.add_argument('--timeout-seconds', type=int, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args();base, c15 = helpers()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    need(sys.platform == 'darwin' and command and Path(command[0]).is_absolute()
         and 1 <= args.timeout_seconds <= 2700 and args.repo.resolve(strict=True) == args.repo
         and not args.execution.exists() and args.execution.is_absolute()
         and args.execution.parent.resolve(strict=True) == args.execution.parent
         and args.execution.parent.stat().st_uid == os.getuid()
         and args.execution.parent.stat().st_mode & 0o077 == 0, 'host_admission')
    args.execution.mkdir(mode=0o700)
    manifest = args.execution / 'source-manifest.json'
    run([sys.executable, '-I', '-B', str(HERE.with_name('build-source-manifest-r1.py')),
         str(args.repo), str(manifest)], timeout=120)
    commit = json.loads(manifest.read_bytes())['source_commit']
    domains = ('gui/' + str(os.getuid()), 'user/' + str(os.getuid()))
    domain = next((d for d in domains if domain_exists(d)), None)
    need(domain is not None, 'user_launchd_domain_unavailable')
    row = {'repo': str(args.repo), 'execution': str(args.execution), 'commit': commit,
           'manifest': str(manifest), 'manifest_sha': sha(manifest), 'operator_sha': sha(HERE),
           'label': 'org.aegis.ci.ne.' + secrets.token_hex(16), 'domain': domain,
           'env': {k: v for k, v in os.environ.items() if k in ENV_KEYS}, 'python': sys.executable,
           'argv': command, 'timeout': args.timeout_seconds, 'owner_pid': os.getpid(),
           'nofile': list(resource.getrlimit(resource.RLIMIT_NOFILE)),
           'nice': os.getpriority(os.PRIO_PROCESS, 0),
           'owner_start': base.marker(os.getpid()), 'deadline': time.time() + args.timeout_seconds + 45,
           'bundle': str(args.execution / 'bundle.json')}
    need(row['owner_start'] is not None, 'owner_identity')
    source(row, base);write(Path(row['bundle']), row)
    row['bundle_sha'] = sha(Path(row['bundle']))
    plist = args.execution / 'job.plist';plist.write_bytes(plistlib.dumps(job_plist(row)));plist.chmod(0o600)
    stopped = [False]
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.__setitem__(0, True))
    watcher = None;closed = False;launched = False
    try:
        with (args.execution / 'guard.stdout').open('xb') as out, (args.execution / 'guard.stderr').open('xb') as err:
            watcher = subprocess.Popen([sys.executable, '-I', '-B', str(HERE), '--guard', row['bundle'], row['bundle_sha']],
                stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
        until = time.monotonic() + 10
        while not (args.execution / 'guard-ready.json').exists() and time.monotonic() < until:
            time.sleep(.1)
        need((args.execution / 'guard-ready.json').exists() and watcher.poll() is None, 'guard_not_ready')
        launched = True
        run(['/bin/launchctl', 'bootstrap', domain, str(plist)])
        result = args.execution / 'worker-result.json'
        while not result.exists() and time.time() < row['deadline'] and not stopped[0]:
            need(watcher.poll() is None, 'guard_exited')
            time.sleep(.1)
        stop_job(row);closed = True
        need(result.is_file(), 'worker_closure_missing')
        outcome = json.loads(result.read_bytes())
        need(outcome['command_closed'] is True and not (args.execution / 'rollback.json').exists(), 'command_closure_or_rollback')
        source(row, base)
        write(args.execution / 'result.json', {'source_commit': commit, 'job_absent': True,
              'command_closed': True, 'command': outcome['command'], 'accepted': outcome['command']['passed']})
        context = args.execution / 'process-context.json'
        if context.exists():
            print(json.dumps({'schema': 'aegis_darwin_launch_context_v2', **json.loads(context.read_bytes())}), file=sys.stderr, flush=True)
        if (args.execution / 'command.log').exists():
            sys.stdout.buffer.write((args.execution / 'command.log').read_bytes());sys.stdout.flush()
        return outcome['command']['exit_code'] if outcome['command']['reason'] == 'exit' else 124
    finally:
        if not closed and launched:
            stop_job(row);closed = True
        if watcher is not None and (closed or not launched):
            c15.close_child(watcher)


if __name__ == '__main__':
    raise SystemExit(main())
