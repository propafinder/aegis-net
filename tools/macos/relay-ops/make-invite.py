#!/usr/bin/python3 -I
"""B-06 v45 operator: mint one AEGIS invitation and write `<name>.aegis-invite`.

The friend's Mac joins with that one file (`aegis-ne-host --enroll`, menu
"Join with Invitation..."). This script, run by the operator on their Mac:

1. checks the public bundle directory (exactly bundle.json, outer-ca.pem,
   inner-ca.pem, device-ca.pem: regular files, at most 64 KiB, UTF-8, no
   private key, an online full-wide v4 profile);
2. refuses an output that exists, then takes an exclusive lock file;
3. runs, over SSH (`ssh -F CONFIG ALIAS`, BatchMode, bounded) and as root
   (`sudo -n python3 -I -B -`), `aegis-server device --registry REGISTRY
   invite --device-id ID --token-out T --ttl-secs N` into a fresh private
   directory under /run, reads the token back and removes that directory;
4. never prints, logs or passes the token on a command line: it travels only
   in the SSH session's stdout into this process's memory;
5. writes the package (`aegis_device_invite_v1`, the canonical form
   `invite_package.rs` admits) with O_CREAT|O_EXCL|O_NOFOLLOW at 0600.

The package is a secret until it is redeemed: deliver it privately, never
commit, paste or log it. The invitation expires after --ttl-secs (at most
24 hours, the server's limit) and works once.

Exit codes: 0 written; 2 usage; 3 input refused (output exists, bundle,
device id, SSH config); 4 lock busy; 5 the relay step failed (nothing
written); 6 the output could not be written.
"""
import argparse
import datetime
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

SCHEMA = 'aegis_device_invite_v1'
EXTENSION = '.aegis-invite'
MEMBERS = ('bundle.json', 'outer-ca.pem', 'inner-ca.pem', 'device-ca.pem')
MAX_PUBLIC_BYTES = 64 * 1024
DEFAULT_SSH_CONFIG = '/Users/developer/.ssh/aegis/config'
DEFAULT_ALIAS = 'relay-a'
DEFAULT_RELAY_ROOT = '/opt/aegis-macos-test-20261021'
DEVICE_ID = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$')
TOKEN = re.compile(r'^[0-9a-f]{64}$')
HEX64 = re.compile(r'[0-9a-fA-F]{64}')
ALIAS = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$')
REMOTE_PATH = re.compile(r'^/[A-Za-z0-9._/-]{1,255}$')
SSH_TIMEOUT = 120
ORPHAN = ('the relay may have minted an invitation that no file holds; it stays '
          'valid until it expires (--ttl-secs): mint a new one only after '
          'checking the registry, or rotate it there')

# Runs on the relay as root. Its parameters are validated literals; the token
# exists only in the private directory under /run (removed here) and on stdout.
REMOTE = r'''
import json,os,shutil,subprocess,sys,tempfile
P=json.loads(%s)
def out(value):
    sys.stdout.write(json.dumps(value)+'\n');sys.stdout.flush()
for key in ('server','registry'):
    if not os.path.isfile(P[key]) or os.path.islink(P[key]):
        out({'ok':False,'error':key+'_missing'});sys.exit(0)
d=tempfile.mkdtemp(prefix='aegis-invite-',dir='/run')
try:
    t=os.path.join(d,'invitation')
    r=subprocess.run([P['server'],'device','--registry',P['registry'],'invite',
        '--device-id',P['device_id'],'--token-out',t,'--ttl-secs',str(P['ttl_secs'])],
        stdin=subprocess.DEVNULL,capture_output=True,timeout=90)
    if r.returncode!=0:
        lines=r.stderr.decode(errors='replace').strip().splitlines()
        out({'ok':False,'error':'invite_failed','rc':r.returncode,'detail':(lines[-1] if lines else '')[:300]})
    else:
        with open(t) as f:token=f.read().strip()
        out({'ok':True,'token':token})
finally:
    shutil.rmtree(d,ignore_errors=True)
'''


class Refused(Exception):
    def __init__(self, code, message, ambiguous=False):
        super().__init__(message)
        self.code = code
        # The relay may have minted before the failure.
        self.ambiguous = ambiguous


def scrub(text):
    """Never let anything shaped like a token reach the terminal."""
    return HEX64.sub('<redacted>', text)


def check_bundle(directory):
    directory = Path(directory)
    if not directory.is_dir() or directory.is_symlink():
        raise Refused(3, 'bundle dir must be a real directory')
    names = sorted(entry.name for entry in directory.iterdir())
    if names != sorted(MEMBERS):
        raise Refused(3, 'bundle dir must hold exactly: ' + ', '.join(MEMBERS))
    public = {}
    for name in MEMBERS:
        path = directory / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or info.st_size > MAX_PUBLIC_BYTES:
            raise Refused(3, f'{name}: must be a non-empty regular file of at most 64 KiB')
        raw = path.read_bytes()
        if b'PRIVATE KEY' in raw:
            raise Refused(3, f'{name}: private key material is forbidden')
        try:
            public[name] = raw.decode('utf-8')
        except UnicodeDecodeError:
            raise Refused(3, f'{name}: not UTF-8') from None
    try:
        profile = json.loads(public['bundle.json'])
    except json.JSONDecodeError:
        raise Refused(3, 'bundle.json is not JSON') from None
    if (not isinstance(profile, dict)
            or profile.get('schema') != 'aegis_device_bundle_v4'
            or profile.get('product_mode') != 'full-wide-tun'
            or profile.get('udp') is not True
            or not isinstance(profile.get('enrollment'), dict)):
        raise Refused(3, 'bundle.json must be an online full-wide v4 profile with UDP')
    for name in MEMBERS[1:]:
        if '-----BEGIN CERTIFICATE-----' not in public[name]:
            raise Refused(3, f'{name}: no PEM certificate')
    return public


def check_ssh_config(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise Refused(3, 'SSH config missing') from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise Refused(3, 'SSH config must be a private regular file of this user')


def output_path(text):
    path = Path(os.path.abspath(text))
    if not path.name.endswith(EXTENSION) or path.name == EXTENSION:
        raise Refused(3, f'output name must end in {EXTENSION}')
    if os.path.lexists(path):
        raise Refused(3, 'output exists; choose a new name (never overwritten)')
    if not path.parent.is_dir():
        raise Refused(3, 'output directory missing')
    return path


def ssh_argv(config, alias):
    return ['ssh', '-T', '-F', str(config), '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=12', '-o', 'ControlMaster=no',
            '-o', 'ControlPath=none', '-o', 'ServerAliveInterval=5',
            '-o', 'ServerAliveCountMax=3', alias,
            '/usr/bin/sudo -n /usr/bin/python3 -I -B -']


def remote_program(device_id, registry, server, ttl_secs):
    params = json.dumps({'device_id': device_id, 'registry': registry,
                         'server': server, 'ttl_secs': ttl_secs})
    return REMOTE % repr(params)


class Lock:
    def __init__(self, path):
        self.path = Path(path)
        self.fd = None

    def __enter__(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise Refused(4, f'lock busy: {self.path}') from None
        # The holder unlinks the file when it is done: a lock taken on a file
        # that is no longer at the path is not the lock.
        try:
            current = os.lstat(self.path).st_ino
        except FileNotFoundError:
            current = None
        if current != os.fstat(fd).st_ino:
            os.close(fd)
            raise Refused(4, f'lock busy (just released): {self.path}; run again')
        os.ftruncate(fd, 0)
        now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        os.write(fd, f'{now} make-invite pid={os.getpid()}\n'.encode())
        self.fd = fd
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            os.close(self.fd)
            self.fd = None


def mint(argv_ssh, program):
    try:
        done = subprocess.run(argv_ssh, input=program.encode(), capture_output=True,
                              timeout=SSH_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        raise Refused(5, 'relay step timed out', ambiguous=True) from None
    except OSError as error:
        raise Refused(5, f'ssh could not run: {type(error).__name__}') from None
    lines = done.stdout.decode(errors='replace').strip().splitlines()
    reply = None
    if lines:
        try:
            reply = json.loads(lines[-1])
        except json.JSONDecodeError:
            reply = None
    if done.returncode != 0 or not isinstance(reply, dict):
        err = done.stderr.decode(errors='replace').strip().splitlines()
        raise Refused(5, scrub(f'relay step failed (ssh exit {done.returncode}): '
                               + (err[-1] if err else 'no reply')), ambiguous=True)
    if reply.get('ok') is not True:
        detail = str(reply.get('detail', ''))
        raise Refused(5, scrub(f"relay refused: {reply.get('error', 'unknown')} {detail}".strip()))
    token = reply.get('token')
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise Refused(5, 'relay returned a malformed invitation (not written)', ambiguous=True)
    return token


def package_bytes(device_id, public, token):
    value = {'bundle': public, 'device_id': device_id, 'invitation': token, 'schema': SCHEMA}
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')


def reserve(path):
    """Create the empty output (0600, exclusive) before anything is minted, so
    a minted invitation always has its file."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as error:
        raise Refused(6, f'output not created: {type(error).__name__}') from None
    os.fchmod(fd, 0o600)
    return fd


def write_reserved(fd, path, data):
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except OSError as error:
        os.close(fd)
        os.unlink(path)
        raise Refused(6, f'output not written: {type(error).__name__}; ' + ORPHAN) from None
    os.close(fd)
    dirfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--device-id', required=True)
    parser.add_argument('--bundle-dir', required=True)
    parser.add_argument('--out', required=True, help='new FILE.aegis-invite (never overwritten)')
    parser.add_argument('--ssh-config', default=DEFAULT_SSH_CONFIG)
    parser.add_argument('--ssh-alias', default=DEFAULT_ALIAS)
    parser.add_argument('--relay-root', default=DEFAULT_RELAY_ROOT)
    parser.add_argument('--registry', help='default: RELAY_ROOT/registry.json')
    parser.add_argument('--server', help='default: RELAY_ROOT/aegis-server')
    parser.add_argument('--ttl-secs', type=int, default=86400)
    parser.add_argument('--lock-file', help='default: ~/.aegis-local/locks/relay-invite-ALIAS.lock')
    parser.add_argument('--dry-run', action='store_true',
                        help='check everything, print the SSH command, contact nothing')
    args = parser.parse_args(argv)
    try:
        if not DEVICE_ID.fullmatch(args.device_id):
            raise Refused(3, "device id: 1..64 ASCII letters, digits, '-' or '_'")
        if not 1 <= args.ttl_secs <= 86400:
            raise Refused(3, 'ttl must be 1..86400 seconds (the server limit)')
        if not ALIAS.fullmatch(args.ssh_alias):
            raise Refused(3, 'ssh alias refused')
        root = args.relay_root.rstrip('/')
        registry = args.registry or f'{root}/registry.json'
        server = args.server or f'{root}/aegis-server'
        for path in (root, registry, server):
            if not REMOTE_PATH.fullmatch(path) or '/../' in path + '/':
                raise Refused(3, f'remote path refused: {path}')
        public = check_bundle(args.bundle_dir)
        out = output_path(args.out)
        check_ssh_config(args.ssh_config)
        command = ssh_argv(args.ssh_config, args.ssh_alias)
        program = remote_program(args.device_id, registry, server, args.ttl_secs)
        if args.dry_run:
            print('dry run; would run: ' + ' '.join(command))
            print(f'remote: {server} device --registry {registry} invite '
                  f'--device-id {args.device_id} --token-out /run/aegis-invite-*/invitation '
                  f'--ttl-secs {args.ttl_secs}')
            print(f'would write {out} (0600)')
            return 0
        lock = args.lock_file or str(Path.home() / '.aegis-local' / 'locks'
                                     / f'relay-invite-{args.ssh_alias}.lock')
        with Lock(lock):
            # Checked again under the lock, then reserved: never overwritten,
            # and a minted invitation always has its file.
            out = output_path(str(out))
            fd = reserve(out)
            started = datetime.datetime.now(datetime.timezone.utc)
            try:
                token = mint(command, program)
            except Refused as refusal:
                os.close(fd)
                os.unlink(out)
                if refusal.ambiguous:
                    refusal.args = (f'{refusal}; {ORPHAN}',)
                raise
            write_reserved(fd, out, package_bytes(args.device_id, public, token))
            del token
        mode = stat.S_IMODE(os.lstat(out).st_mode)
        expires = (started + datetime.timedelta(seconds=args.ttl_secs)).strftime('%Y-%m-%dT%H:%M:%SZ')
        print(f'wrote {out} (mode {mode:04o}) for device {args.device_id}')
        print(f'the invitation works once and expires about {expires} (UTC)')
        print('deliver it privately; never commit, paste or log it')
        return 0
    except Refused as refusal:
        print(f'make-invite: {refusal}', file=sys.stderr)
        return refusal.code


if __name__ == '__main__':
    sys.exit(main())
