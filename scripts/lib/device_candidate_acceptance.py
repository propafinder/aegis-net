"""Real lifecycle acceptance, exclusively in an explicitly marked disposable VM.

No compilation, download, production credential import, or release-policy bypass.
Python is the lab controller; device identity and installation use signed Rust and
shell release artifacts. A successful local contract test is NOT native acceptance.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import time

from device_candidate_verify import MAX_ARCHIVE, extract_verified, file_hash, read, require, sha, trusted, verify

IDENTITY = Path('/var/lib/aegis-identity/client')
CONFIG = Path('/etc/aegis/client/aegis.toml')
CLIENT = Path('/usr/local/bin/aegis-client')
EMPTY_PATHS = (CLIENT, Path('/usr/local/bin/aegis-server'), Path('/etc/aegis'),
               Path('/usr/bin/aegis-client'), Path('/usr/bin/aegis-server'),
               Path('/usr/local/lib/aegis'), Path('/usr/lib/aegis'),
               Path('/var/lib/aegis'), Path('/var/lib/aegis-client'),
               Path('/var/lib/aegis-install'), Path('/var/lib/aegis-identity'),
               Path('/etc/systemd/system/aegis-client.service'),
               Path('/etc/systemd/system/aegis-server.service'))
PURGED_PATHS = (CLIENT, CONFIG.parent, Path('/usr/local/lib/aegis'), Path('/usr/lib/aegis'),
                Path('/var/lib/aegis-client'), Path('/var/lib/aegis-install/client'),
                Path('/var/log/aegis-client'), Path('/etc/default/aegis-client'),
                Path('/etc/systemd/system/aegis-client.service'),
                Path('/etc/systemd/system/aegis-client.service.d'),
                Path('/etc/systemd/system/aegis-wide.service'),
                Path('/etc/systemd/system/aegis-wide-tun-firewall.service'))
CGROUP_ROOT = Path('/sys/fs/cgroup')


def run(args, timeout=30, *, ok=True, env=None):
    result = subprocess.run([str(value) for value in args], capture_output=True,
                            timeout=timeout, env=env)
    if ok:
        require(result.returncode == 0, 'command failed: ' + str(args[0]))
    return result


def text(args, timeout=30):
    return run(args, timeout).stdout.decode().strip()


def write_new(path, contents, mode=0o600):
    path = Path(path)
    with path.open('xb') as stream:
        stream.write(contents.encode() if isinstance(contents, str) else contents)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(mode)


def json_new(path, data):
    write_new(path, json.dumps(data, indent=2, sort_keys=True) + '\n')


def copy_pinned(source, destination, digest, limit):
    with trusted(source, limit) as incoming, destination.open('xb') as output:
        checksum = hashlib.sha256()
        while block := incoming.read(65536):
            checksum.update(block)
            output.write(block)
        output.flush()
        os.fsync(output.fileno())
    require(checksum.hexdigest() == digest, 'staged input changed after verification')


def properties(unit):
    output = text(['systemctl', 'show', unit, '--no-pager',
                   '--property=MainPID,ActiveState,LoadState,User,NoNewPrivileges,UMask'])
    return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)


def guest_guard(args, clean):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'real root Linux VM required')
    require(Path('/proc/1/comm').read_text().strip() == 'systemd', 'real systemd PID 1 required')
    virt = text(['systemd-detect-virt', '--vm'])
    require(virt not in ('', 'none'), 'a VM boundary is mandatory')
    machine = read('/etc/machine-id').decode().strip()
    marker = json.loads(read(args.vm_marker))
    require(set(marker) == {'schema', 'purpose', 'machine_id', 'run_id', 'source_sha'}, 'invalid VM marker')
    require(marker == {'schema': 'aegis_disposable_vm_v1', 'purpose': 'device_candidate_acceptance',
                       'machine_id': machine, 'run_id': args.run_id, 'source_sha': args.source},
            'external VM marker does not authorize this machine/run/source')
    require(Path(args.vm_marker).stat().st_mode & 0o777 == 0o600, 'VM marker must be mode 0600')
    os_release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            os_release[key] = value.strip('"')
    require(os_release.get('ID') == args.os_id, 'native OS differs from requested gate')
    require({'x86_64': 'x86_64', 'aarch64': 'aarch64'}.get(os.uname().machine) == args.arch,
            'guest architecture differs from signed candidate')
    if args.os_id == 'almalinux':
        require(os_release.get('VERSION_ID', '').startswith('9.'), 'AlmaLinux 9 required')
        require(text(['getenforce']) == 'Enforcing', 'AlmaLinux gate requires SELinux Enforcing')
        require(text(['getconf', 'GNU_LIBC_VERSION']) == 'glibc 2.34', 'AlmaLinux gate requires glibc 2.34')
        require(properties('firewalld.service').get('ActiveState') == 'active', 'AlmaLinux gate requires firewalld active')
    for dependency in ('openssl', 'ip', 'systemctl', 'systemd-run', 'bash', 'ss', 'iptables', 'ip6tables',
                       'iptables-save', 'ip6tables-save', 'pgrep', 'sysctl', 'curl', 'tar'):
        require(shutil.which(dependency) is not None, 'required VM dependency is missing: ' + dependency)
    if clean:
        require(all(not path.exists() and not path.is_symlink() for path in EMPTY_PATHS),
                'VM contains an existing Aegis installation; no installed files have been read')
        for service in ('aegis-client.service', 'aegis-server.service'):
            state = properties(service)
            require(state.get('LoadState') == 'not-found' and state.get('MainPID') == '0', 'existing Aegis unit detected')
        require(not run(['pgrep', '-x', 'aegis-client'], ok=False).stdout and
                not run(['pgrep', '-x', 'aegis-server'], ok=False).stdout, 'existing Aegis process detected')
    return {'os': os_release, 'virtualization': virt, 'kernel': os.uname().release, 'arch': os.uname().machine,
            'machine_id_sha256': sha(machine.encode()), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def network_state():
    state = {}
    for family in ('-4', '-6'):
        for object_name in ('route', 'rule'):
            command = ['ip', '-j', family, object_name, 'show']
            if object_name == 'route':
                command += ['table', 'all']
            rows = json.loads(text(command))
            # Router-advertisement lifetimes count down independently of this
            # test. Keep route identity/policy, ignore only the expiry countdown.
            rows = [{key: value for key, value in row.items() if key != 'expires'} for row in rows]
            state[family + object_name] = sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))
    for utility in ('iptables-save', 'ip6tables-save'):
        state[utility] = '\n'.join(re.sub(r'\[\d+:\d+\]', '[0:0]', line)
                                  for line in text([utility]).splitlines() if not line.startswith('#'))
    state['forwarding'] = text(['sysctl', '-n', 'net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding', 'net.ipv4.conf.all.route_localnet'])
    # Resolver symlink belongs to this disposable OS; preserve its link and
    # resolved bytes in-memory without treating either as admin instructions.
    resolver = Path('/etc/resolv.conf')
    state['resolver'] = sha(resolver.read_bytes())
    state['resolver_link'] = os.readlink(resolver) if resolver.is_symlink() else None
    return state


def snapshot():
    """Hashes are kept in private lab state and never published as secret hashes."""
    files = {}
    for base in (Path('/etc/aegis'), Path('/var/lib/aegis-install/client'),
                 Path('/etc/systemd/system/aegis-client.service.d')):
        if base.exists():
            for path in base.rglob('*'):
                if path.is_file() and not path.is_symlink():
                    files[str(path)] = file_hash(path)
    for path in (CLIENT, Path('/etc/systemd/system/aegis-client.service')):
        if path.exists():
            files[str(path)] = file_hash(path)
    return {'files': files, 'pid': properties('aegis-client.service').get('MainPID')}


def exact_running(unit, expected):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        state = properties(unit)
        pid = state.get('MainPID', '0')
        try:
            # /proc/PID/exe is a kernel link by design; no arbitrary path input.
            with open('/proc/' + str(int(pid)) + '/exe', 'rb') as binary:
                digest = hashlib.sha256()
                while block := binary.read(65536):
                    digest.update(block)
            if state.get('ActiveState') == 'active' and digest.hexdigest() == expected:
                return state
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
        time.sleep(0.25)
    raise ValueError('actual running executable did not reach signed identity: ' + unit)


def tight(path, mode):
    info = path.lstat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == mode and not path.is_symlink(),
            'incorrect protected ownership/mode: ' + str(path))


def key_identity():
    key = IDENTITY / 'device.key'
    tight(IDENTITY, 0o700)
    tight(key, 0o600)
    info = key.stat()
    require(info.st_nlink == 1, 'device key hardlink detected')
    return {'inode': info.st_ino, 'device': info.st_dev, 'sha256': file_hash(key)}


def release_floor(arch):
    directory = Path('/var/lib/aegis-install/releases')
    floor = directory / ('client-linux-' + arch + '.json')
    pending = directory / ('client-linux-' + arch + '.pending.json')
    tight(directory, 0o700)
    tight(floor, 0o600)
    return {'floor': json.loads(read(floor)), 'pending': json.loads(read(pending)) if pending.exists() else None}


def socks_credentials():
    """Read only the config created after the empty-VM guard; never log secrets."""
    data = read(CONFIG, 1024 * 1024).decode()
    match = re.search(r'(?ms)^\[socks\]\s*\n(.*?)(?=^\[|\Z)', data)
    require(match is not None, 'SOCKS config missing')
    fields = {}
    for name in ('auth_token', 'auth_user', 'listen'):
        value = re.search(r'^' + name + r'\s*=\s*("(?:[^"\\]|\\.)*")\s*$', match[1], re.M)
        if value:
            fields[name] = json.loads(value[1])
    require(fields.get('listen') == '127.0.0.1:1080' and fields.get('auth_token'), 'protected authenticated SOCKS listener required')
    return fields.get('auth_user', 'aegis').encode(), fields['auth_token'].encode()


def recv_exact(stream, count):
    data = b''
    while len(data) < count:
        part = stream.recv(count - len(data))
        require(bool(part), 'truncated SOCKS response')
        data += part
    return data


def traffic(work):
    user, password = socks_credentials()
    require(len(user) <= 255 and len(password) <= 255, 'invalid local credential length')
    expected = read(work / 'payload.bin', 2 * 1024 * 1024)
    with socket.create_connection(('127.0.0.1', 1080), 15) as stream:
        stream.settimeout(15)
        stream.sendall(b'\x05\x01\x02')
        require(recv_exact(stream, 2) == b'\x05\x02', 'SOCKS did not enforce credential authentication')
        stream.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
        require(recv_exact(stream, 2) == b'\x01\x00', 'SOCKS authentication failed')
        stream.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + (18080).to_bytes(2, 'big'))
        response = recv_exact(stream, 4)
        require(response[:3] == b'\x05\x00\x00', 'SOCKS relay connection failed')
        sizes = {1: 4, 4: 16}
        length = recv_exact(stream, 1)[0] if response[3] == 3 else sizes.get(response[3])
        require(length is not None, 'invalid SOCKS bound address')
        recv_exact(stream, length + 2)
        stream.sendall(b'GET /payload HTTP/1.1\r\nHost: synthetic.test\r\nConnection: close\r\n\r\n')
        received = bytearray()
        while part := stream.recv(65536):
            received.extend(part)
            require(len(received) <= len(expected) + 8192, 'traffic response exceeds expected bound')
        header, separator, body = bytes(received).partition(b'\r\n\r\n')
        require(separator and header.split(b'\r\n')[0].endswith(b'200 OK') and body == expected,
                'end-to-end synthetic response bytes differ')
    return {'bytes': len(expected), 'sha256': sha(expected), 'target': 'relay-network-namespace-loopback-only'}


class Lab:
    def __init__(self, args, verified, work):
        self.args, self.verified, self.work = args, verified, work
        self.client = work / 'client/bin/aegis-client'
        self.server = work / 'operator/bin/aegis-server'
        self.ns = 'agd-' + args.run_id
        self.link = 'ag' + sha(args.run_id.encode())[:9]
        self.relay_unit = self.ns + '-relay.service'
        self.http_unit = self.ns + '-http.service'
        self.device_id = 'acceptance-' + args.run_id
        self.phase_count = 0

    def bootstrap(self, phase, extra=(), ok=True):
        self.phase_count += 1
        download = self.work / ('download-' + str(self.phase_count) + '-' + phase)
        env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'HOME': '/root', 'LANG': 'C.UTF-8', 'TMPDIR': '/tmp',
               'AEGIS_INSTALL_MANIFEST_PUBKEY': str(self.work / 'release-public-key.pem')}
        args = ['bash', self.work / 'bootstrap-install.sh', 'client', '--offline',
                '--source', (self.work / 'delivery' / Path(self.args.client_manifest).name).as_uri(),
                '--release-authority', self.args.authority, '--minimum-release-sequence', self.args.minimum_sequence,
                '--download-dir', download]
        if phase.startswith('recover-'):
            args += ['--recover-interrupted-release', phase.removeprefix('recover-')]
        else:
            args += ['--bundle', self.work / 'public-bundle', '--device-id', self.device_id,
                     '--identity-dir', IDENTITY, '--profile', 'socks-only', '--force'] + list(extra)
        result = run(args, timeout=330, ok=False, env=env)
        write_new(self.work / ('private-' + phase + '.log'), result.stdout + result.stderr)
        require((result.returncode == 0) == ok, 'unexpected bootstrap result: ' + phase)
        return result

    def pki(self):
        for role in ('outer', 'inner', 'device'):
            run(['openssl', 'req', '-new', '-x509', '-newkey', 'ed25519', '-nodes',
                 '-keyout', self.work / (role + '-ca.key'), '-out', self.work / (role + '-ca.pem'),
                 '-days', '3', '-subj', '/CN=Synthetic ' + role + ' issuer',
                 '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
        for role, name in (('outer', 'relay.test'), ('inner', 'origin.test')):
            run(['openssl', 'req', '-new', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=' + name,
                 '-keyout', self.work / (role + '.key'), '-out', self.work / (role + '.csr')])
            extensions = self.work / (role + '.ext')
            write_new(extensions, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:' + name + '\n')
            run(['openssl', 'x509', '-req', '-in', self.work / (role + '.csr'), '-CA', self.work / (role + '-ca.pem'),
                 '-CAkey', self.work / (role + '-ca.key'), '-set_serial', '1', '-days', '2',
                 '-extfile', extensions, '-out', self.work / (role + '.pem')])
        json_new(self.work / 'profile.json', {'schema': 'aegis_device_bundle_v1', 'relay_server': '192.0.2.2:18443',
                 'outer_server_name': 'relay.test', 'inner_server_name': 'origin.test', 'udp': False})
        run([self.client, 'device', 'bundle-create', '--bundle-dir', self.work / 'public-bundle',
             '--profile', self.work / 'profile.json', '--outer-ca', self.work / 'outer-ca.pem',
             '--inner-ca', self.work / 'inner-ca.pem', '--device-ca', self.work / 'device-ca.pem'])
        write_new(self.work / 'payload.bin', os.urandom(1024 * 1024))

    def issue(self):
        operator = [self.server, 'device', '--registry', self.work / 'registry.json']
        run(operator + ['init'])
        run(operator + ['invite', '--device-id', self.device_id, '--token-out', self.work / 'invitation'])
        run(operator + ['issue', '--csr', IDENTITY / 'device.csr', '--ca-cert', self.work / 'device-ca.pem',
                        '--ca-key', self.work / 'device-ca.key', '--invitation-file', self.work / 'invitation',
                        '--certificate-out', self.work / 'response.pem'])
        self.registry_policy('after-issue', force=True)
        lines = ['listen = "192.0.2.2:18443"', 'cert = ' + json.dumps(str(self.work / 'outer.pem')),
                 'key = ' + json.dumps(str(self.work / 'outer.key')), 'fallback = "close"',
                 '[target_policy]', 'profile = "full_vpn_egress"', 'allowed_ports = [18080]', '[transport.inner_tls]']
        for key, leaf in (('cert', 'inner.pem'), ('key', 'inner.key'), ('client_ca', 'device-ca.pem'), ('device_registry', 'registry.json')):
            lines.append(key + ' = ' + json.dumps(str(self.work / leaf)))
        write_new(self.work / 'server.toml', '\n'.join(lines) + '\n')
        run([self.server, '--config', self.work / 'server.toml', 'config-check'])

    def registry_policy(self, reason, force=False):
        registry = self.work / 'registry.json'
        operator = [self.server, 'device', '--registry', registry]
        before_hash = file_hash(registry)
        before = json.loads(text(operator + ['status']))
        require(file_hash(registry) == before_hash, 'registry status unexpectedly mutated stored policy')
        require(before['version'] == 2 and type(before['observed_at_unix_secs']) is int, 'registry v2 status required')
        validity = before['validity']
        require(all(type(validity[key]) is int for key in ('issued_at_unix_secs', 'expires_at_unix_secs')) and
                0 < validity['issued_at_unix_secs'] < validity['expires_at_unix_secs'] and
                validity['expires_at_unix_secs'] - validity['issued_at_unix_secs'] <= 3600,
                'registry validity exceeds accepted policy')
        refreshed = force or validity['expires_at_unix_secs'] <= before['observed_at_unix_secs'] + 600
        after = before
        if refreshed:
            # Explicit lab administrator operation, separate from read/status.
            refreshed_value = json.loads(text(operator + ['refresh-registry', '--ttl-secs', '3600']))
            refreshed_hash = file_hash(registry)
            after = json.loads(text(operator + ['status']))
            require(file_hash(registry) == refreshed_hash, 'post-refresh status mutated policy')
            require(after['generation'] > before['generation'] and after['version'] == refreshed_value['version'] == 2 and
                    after['generation'] == refreshed_value['generation'] and after['validity'] == refreshed_value['validity'] and
                    after['devices'] == before['devices'], 'administrative refresh changed device authorizations or returned inconsistent state')
        require(after['validity']['expires_at_unix_secs'] > after['observed_at_unix_secs'] + 600 and
                after['validity']['expires_at_unix_secs'] - after['validity']['issued_at_unix_secs'] <= 3600,
                'registry policy lacks sufficient remaining lifetime')
        receipt = {'schema': 'aegis_lab_registry_policy_action_v1', 'run_id': self.args.run_id,
                   'source_sha': self.args.source, 'reason': reason,
                   'action': 'ADMIN_REFRESH_3600S' if refreshed else 'READ_ONLY_CURRENT_POLICY',
                   'generation_before': before['generation'], 'generation_after': after['generation'],
                   'validity_before': before['validity'], 'validity_after': after['validity'],
                   'observed_at_unix_secs': after['observed_at_unix_secs'], 'status_read_did_not_extend_policy': True}
        json_new(self.work / ('registry-policy-' + str(time.time_ns()) + '.json'), receipt)
        return receipt

    def start_network(self):
        self.registry_policy('before-relay-start-or-after-reboot')
        routes = text(['ip', '-j', '-4', 'route', 'show', 'table', 'all'])
        require(not any(str(row.get('dst', '')).startswith('192.0.2.') for row in json.loads(routes)), 'synthetic subnet already routed')
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 18080))
        run(['ip', 'netns', 'add', self.ns])
        run(['ip', 'link', 'add', self.link, 'type', 'veth', 'peer', 'name', self.link + 'p'])
        run(['ip', 'link', 'set', self.link + 'p', 'netns', self.ns])
        run(['ip', 'addr', 'add', '192.0.2.1/30', 'dev', self.link])
        run(['ip', 'link', 'set', self.link, 'up'])
        for command in (['ip', 'addr', 'add', '192.0.2.2/30', 'dev', self.link + 'p'],
                        ['ip', 'link', 'set', self.link + 'p', 'up'], ['ip', 'link', 'set', 'lo', 'up']):
            run(['ip', 'netns', 'exec', self.ns] + command)
        require(not text(['ip', 'netns', 'exec', self.ns, 'ip', '-4', 'route', 'show', 'default']), 'relay namespace unexpectedly has external egress')
        for unit, command in self.network_commands():
            run(['systemd-run', '--quiet', '--unit', unit, '--property=RuntimeMaxSec=5400',
                 '--property=UMask=0077', '--property=TimeoutStopSec=10', '--property=NoNewPrivileges=yes',
                 '--property=Type=exec'] + command)
        exact_running(self.relay_unit, self.verified['operator']['binary_sha256'])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            listening = text(['ip', 'netns', 'exec', self.ns, 'ss', '-H', '-ltn'])
            if '127.0.0.1:18080' in listening:
                return
            time.sleep(0.25)
        raise ValueError('isolated synthetic HTTP fixture did not bind')

    def network_commands(self):
        prefix = [shutil.which('ip'), 'netns', 'exec', self.ns]
        return [(self.http_unit, prefix + [sys.executable, str(Path(__file__).absolute()), 'serve-payload', '--work-dir', str(self.work)]),
                (self.relay_unit, prefix + [str(self.server), '--config', str(self.work / 'server.toml')])]

    def check(self, key):
        state = exact_running('aegis-client.service', self.verified['client']['binary_sha256'])
        require(file_hash(CLIENT) == self.verified['client']['binary_sha256'], 'installed binary differs from signed candidate')
        require(state.get('User') in ('', 'root'), 'unexpected privilege relaxation for root-private inner identity')
        require(state.get('NoNewPrivileges') == 'yes' and state.get('UMask') == '0077', 'unit process hardening mismatch')
        tight(CONFIG.parent, 0o700)
        tight(CONFIG, 0o600)
        require(key_identity() == key, 'device private key was replaced')
        contents = read(CONFIG, 1024 * 1024).decode()
        require(str(IDENTITY / 'device.key') in contents and str(CONFIG.parent / 'inner-ca.pem') in contents,
                'final config does not reference protected persistent identity and CA')
        # Only this freshly generated synthetic key is read; no private bytes leave
        # the VM. Scan bounded installer/config trees, not arbitrary host files.
        for root in (CONFIG.parent, self.work):
            for path in root.rglob('*'):
                if path.is_file() and not path.is_symlink() and path.stat().st_size == (IDENTITY / 'device.key').stat().st_size:
                    require(file_hash(path) != key['sha256'], 'device key copied into bundle/installer/config tree')
        return traffic(self.work)

    def purge(self, phase):
        before = exact_running(self.relay_unit, self.verified['operator']['binary_sha256'])['MainPID']
        before_network = network_state()
        before_floor = release_floor(self.args.arch)
        script = self.work / 'operator/scripts/purge-installed-aegis.sh'
        require(file_hash(script) == self.verified['operator']['file_hashes']['scripts/purge-installed-aegis.sh'], 'purge helper differs from signed inventory')
        result = run(['bash', script, 'client', '--force'], timeout=180)
        write_new(self.work / ('private-' + phase + '.log'), result.stdout + result.stderr)
        require(all(not path.exists() and not path.is_symlink() for path in PURGED_PATHS), 'managed client files remain after purge')
        state = properties('aegis-client.service')
        require(state.get('MainPID') == '0' and state.get('LoadState') == 'not-found', 'client unit/process remains after purge')
        require(properties(self.relay_unit).get('MainPID') == before, 'client purge disturbed isolated relay')
        require(IDENTITY.exists(), 'purge unexpectedly removed retained device identity')
        require(release_floor(self.args.arch) == before_floor, 'purge changed antirollback floor')
        require(network_state() == before_network, 'SOCKS-only purge changed resolver/routes/firewall/forwarding')

    def stop_network(self):
        groups = []
        # Verify both owned command vectors before stopping either unit. A
        # reused name is never authority to kill its unrelated processes.
        for unit, expected in self.network_commands():
            command = text(['systemctl', 'show', unit, '--property=ExecStart', '--value'])
            arguments = command.partition('argv[]=')[2].partition(' ; ')[0]
            require(arguments and shlex.split(arguments) == expected, 'lab unit was replaced; cleanup stopped')
            group = text(['systemctl', 'show', unit, '--property=ControlGroup', '--value'])
            if group:
                require(group.startswith('/') and '..' not in Path(group).parts, 'invalid lab cgroup')
                groups.append(CGROUP_ROOT / group.lstrip('/'))
        for unit, _ in self.network_commands():
            run(['systemctl', 'stop', unit], timeout=30)
            off = properties(unit)
            require(off.get('MainPID') == '0' and off.get('ActiveState') in ('inactive', 'failed'), 'lab service did not stop')
        for group in groups:
            if group.exists():
                for index, processes in enumerate(group.rglob('cgroup.procs')):
                    require(index < 4096 and not processes.read_text().strip(), 'lab cgroup still owns processes')
        # Do this BEFORE unlinking the named namespace: a detached namespace
        # containing surviving processes must never count as successful cleanup.
        require(not text(['ip', 'netns', 'pids', self.ns]), 'lab network namespace still owns processes')
        run(['ip', 'link', 'delete', self.link])
        run(['ip', 'netns', 'delete', self.ns])


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('phase', choices=('verify-only', 'pre-reboot', 'post-reboot', 'serve-payload'))
    result.add_argument('--work-dir')
    for name in ('client-manifest', 'client-manifest-sha256', 'operator-manifest', 'operator-manifest-sha256',
                 'bootstrap', 'public-key', 'public-key-sha256', 'source', 'tag', 'authority', 'vm-marker', 'run-id'):
        result.add_argument('--' + name)
    result.add_argument('--client-bundle-schema', choices=('aegis_client_release_bundle_manifest_v1', 'aegis_client_release_bundle_manifest_v2', 'aegis_client_release_bundle_manifest_v3'), default='aegis_client_release_bundle_manifest_v1')
    result.add_argument('--minimum-sequence', type=int)
    result.add_argument('--arch', choices=('x86_64', 'aarch64'))
    result.add_argument('--os-id', choices=('ubuntu', 'debian', 'almalinux'))
    return result


def main():
    args = parser().parse_args()
    os.umask(0o077)
    if args.phase == 'serve-payload':
        payload = read(Path(args.work_dir) / 'payload.bin', 2 * 1024 * 1024)
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != '/payload':
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *_args):
                pass
        http.server.HTTPServer(('127.0.0.1', 18080), Handler).serve_forever()
        return
    for name in ('client_manifest', 'client_manifest_sha256', 'operator_manifest', 'operator_manifest_sha256',
                 'bootstrap', 'public_key', 'public_key_sha256', 'source', 'tag', 'authority', 'minimum_sequence', 'arch'):
        require(getattr(args, name) is not None, 'missing independently supplied trust input: ' + name)
    verified = verify(args)
    if args.phase == 'verify-only':
        print(json.dumps(verified, indent=2, sort_keys=True))
        return
    require(args.run_id and re.fullmatch(r'[a-z0-9]{1,12}', args.run_id), 'short unique run ID required')
    require(args.os_id and args.vm_marker and not args.work_dir, 'native mode requires OS/VM marker; managed workspace cannot be overridden')
    host = guest_guard(args, clean=args.phase == 'pre-reboot')
    base = Path('/var/lib/aegis-acceptance')
    if not base.exists():
        base.mkdir(mode=0o700)
    tight(base, 0o700)
    work = base / args.run_id
    lab = Lab(args, verified, work)
    result = {'schema': 'aegis_device_candidate_systemd_vm_v1', 'client_bundle_schema': verified['client_bundle_schema'], 'source_sha': args.source, 'tag': args.tag, 'run_id': args.run_id,
              'client_manifest_sha256': args.client_manifest_sha256, 'operator_manifest_sha256': args.operator_manifest_sha256,
              'phase': args.phase, 'host': host, 'checks': {}, 'verdict': 'FAIL',
              'not_run': ['cross-version migration', 'full-wide TUN/UDP/IPv6', 'restricted-network field test',
                          'pool certificate rotation', 'physical ARM', 'release downgrade'],
              'private_material': 'synthetic VM-local keys only; retained private lab logs are not public receipts'}
    result['acceleration_evidence'] = 'guest cannot distinguish hardware virtualization from emulation; correlate independent host/controller receipt by run_id and source_sha'
    try:
        if args.phase == 'pre-reboot':
            work.mkdir(mode=0o700)
            extract_verified(verified['client'], work / 'client')
            extract_verified(verified['operator'], work / 'operator')
            write_new(work / 'bootstrap-install.sh', read(args.bootstrap, 256 * 1024))
            write_new(work / 'release-public-key.pem', read(args.public_key, 16384))
            require(file_hash(work / 'bootstrap-install.sh') == verified['bootstrap_sha256'] and
                    file_hash(work / 'release-public-key.pem') == verified['release_key_sha256'], 'staging trust input changed')
            delivery = work / 'delivery'
            delivery.mkdir(mode=0o700)
            manifest = Path(args.client_manifest)
            copy_pinned(manifest, delivery / manifest.name, args.client_manifest_sha256, 65536)
            # Detached signature is public and was verified over these exact bytes.
            write_new(delivery / (manifest.name + '.sig'), read(str(manifest) + '.sig', 64))
            copy_pinned(verified['client']['archive'], delivery / Path(verified['client']['archive']).name,
                        verified['client']['archive_sha256'], MAX_ARCHIVE)
            json_new(work / 'verified.json', verified)
            lab.pki()
            lab.bootstrap('prepare')
            require(not CLIENT.exists() and not CONFIG.exists(), 'pending enrollment changed installed client')
            key = key_identity()
            lab.bootstrap('resume')
            require(key_identity() == key and not CLIENT.exists(), 'resume changed key or installed client')
            result['checks']['prepare_resume_without_service_or_key_copy'] = 'PASS'
            lab.issue()
            lab.start_network()
            certificate = ['--device-certificate', work / 'response.pem']
            lab.bootstrap('install', certificate)
            result['checks']['install_and_exact_signed_traffic'] = lab.check(key)
            before = snapshot()
            floor_before = release_floor(args.arch)
            require(floor_before['pending'] is None and
                    floor_before['floor']['manifest_sha256'] == args.client_manifest_sha256 and
                    floor_before['floor']['sequence'] == verified['release_policy']['sequence'], 'installed release floor differs from candidate')
            lab.bootstrap('reject-response', ['--upgrade', '--device-certificate', work / 'outer-ca.pem'], ok=False)
            require(snapshot() == before and key_identity() == key, 'rejected response changed installed state')
            floor_failed = release_floor(args.arch)
            require(floor_failed['floor'] == floor_before['floor'] and floor_failed['pending'] is not None,
                    'failed installer did not preserve prior floor and pending journal')
            lab.bootstrap('recover-inspect')
            lab.bootstrap('recover-discard-failed')
            require(snapshot() == before, 'pending recovery changed installed client')
            require(release_floor(args.arch) == floor_before, 'explicit recovery changed durable release floor')
            result['checks']['invalid_response_preserves_state_and_explicit_pending_recovery'] = 'PASS'
            result['checks']['release_floor_unchanged_pending_cleared_only_after_state_check'] = 'PASS'
            lab.bootstrap('upgrade', certificate + ['--upgrade'])
            result['checks']['same_candidate_upgrade'] = lab.check(key)
            lab.bootstrap('reinstall', certificate + ['--reinstall'])
            result['checks']['same_candidate_reinstall'] = lab.check(key)
            lab.purge('uninstall')
            require(key_identity() == key, 'uninstall changed retained device key')
            result['checks']['uninstall_retains_identity_and_relay'] = 'PASS'
            lab.bootstrap('fresh', certificate)
            result['checks']['fresh_from_retained_identity'] = lab.check(key)
            require(text(['systemctl', 'is-enabled', 'aegis-client.service']) == 'enabled', 'installed client will not start at boot')
            result['checks']['registry_policy_before_reboot'] = lab.registry_policy('before-external-reboot')
            json_new(work / 'private-state.json', {'key': key, 'boot_id': host['boot_id'], 'verified': verified})
            result['verdict'] = 'PRE_REBOOT_SCOPED_PASS'
        else:
            tight(work, 0o700)
            previous = json.loads(read(work / 'pre-reboot-receipt.json', 1024 * 1024))
            require(previous['verdict'] == 'PRE_REBOOT_SCOPED_PASS', 'pre-reboot gate was not accepted')
            state = json.loads(read(work / 'private-state.json', 4 * 1024 * 1024))
            require(state['verified'] == verified and state['boot_id'] != host['boot_id'], 'candidate changed or actual reboot was not observed')
            for name, item, binary in (('client', verified['client'], 'aegis-client'), ('operator', verified['operator'], 'aegis-server')):
                require(file_hash(work / name / 'bin' / binary) == item['binary_sha256'], 'staged executable changed across reboot')
            before_network = network_state()
            lab.start_network()
            result['checks']['actual_reboot_and_signed_traffic'] = lab.check(state['key'])
            lab.purge('final-uninstall')
            require(key_identity() == state['key'], 'final uninstall changed retained key')
            lab.stop_network()
            require(lab.ns not in text(['ip', 'netns', 'list']), 'lab network namespace remains')
            require(network_state() == before_network, 'lab cleanup changed guest network baseline')
            result['checks']['final_uninstall_and_namespace_cleanup'] = 'PASS'
            result['verdict'] = 'SYSTEMD_VM_SOCKS_INNER_TLS_LIFECYCLE_SCOPED_PASS'
    except BaseException as error:
        result['error'] = str(error)
        # Preserve the failed VM for independent inspection/snapshot reset.
        # Do not claim product rollback from a best-effort cleanup.
        raise
    finally:
        if work.exists():
            receipt = work / (args.phase + '-receipt.json')
            if not receipt.exists():
                json_new(receipt, result)
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        sys.exit(1)
