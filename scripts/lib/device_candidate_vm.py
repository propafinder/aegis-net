"""Bounded clone controller for a powered-off disposable Linux acceptance VM.

Run on the Linux KVM host, after candidate pins are independently approved.
This never selects, stops, modifies, or deletes an existing VM. The original
cloud image and optional retained RC18 guest are read-only inputs. Reset means
replace this lab's overlay, not downgrade an installed release or clear F11.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import socket
import stat
import subprocess
import sys
from types import SimpleNamespace

from device_candidate_acceptance import exact_running, json_new, properties, run, text, tight, write_new
from device_candidate_verify import file_hash, read, require, trusted, verify

ROOT = Path('/var/lib/aegis-candidate-vms')
SPEC_FIELDS = {'client_manifest', 'client_manifest_sha256', 'operator_manifest', 'operator_manifest_sha256',
               'bootstrap', 'public_key', 'public_key_sha256', 'source', 'tag', 'authority',
               'minimum_sequence', 'arch'}
DEPENDENCIES = {'prepare': ('qemu-img', 'cloud-localds', 'systemctl', 'ssh-keygen', 'openssl', 'qemu-system-x86_64'),
                'start': ('qemu-img', 'systemd-run', 'systemctl', 'openssl'),
                'stop': ('systemctl',), 'reset': ('systemctl', 'qemu-img'), 'inspect': ('systemctl',)}


def candidate_for_action(action, spec_path):
    if action not in ('prepare', 'start'):
        return None, None
    require(spec_path, 'prepare/start requires independent candidate spec')
    spec = json.loads(read(spec_path))
    require(set(spec) in (SPEC_FIELDS, SPEC_FIELDS | {'client_bundle_schema'}), 'candidate spec must contain exactly independent verifier inputs')
    return spec, verify(SimpleNamespace(**spec))


def image_hash(path, algorithm='sha512'):
    with trusted(path, 32 * 1024**3) as stream:
        digest = hashlib.new(algorithm)
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def image_info(path):
    result = json.loads(text(['qemu-img', 'info', '--output=json', path]))
    require(result.get('format') == 'qcow2', 'only qcow2 images are accepted')
    return result


def off(unit):
    state = properties(unit)
    require(state.get('ActiveState') in ('inactive', 'failed') and state.get('MainPID') == '0', 'lab VM must be fully off')


def own_unit(state):
    if properties(state['unit']).get('LoadState') == 'not-found':
        return
    command = text(['systemctl', 'show', state['unit'], '--property=ExecStart', '--value'])
    arguments = command.partition('argv[]=')[2].partition(' ; ')[0]
    require(arguments and shlex.split(arguments) == qemu_command(state, Path(state['guest']).parent),
            'unit name is occupied by a different command; nothing stopped')
    pid = properties(state['unit']).get('MainPID', '0')
    if pid != '0':
        try:
            require(pid_executable_hash(pid) == state['qemu_sha256'], 'owned unit currently runs a different executable')
        except FileNotFoundError:
            require(properties(state['unit']).get('MainPID') == '0', 'unit PID changed while verifying ownership')


def pid_executable_hash(pid):
    require(str(int(pid)) == pid and int(pid) > 0, 'invalid unit PID')
    with open('/proc/' + pid + '/exe', 'rb') as stream:
        digest = hashlib.sha256()
        while block := stream.read(65536):
            digest.update(block)
        return digest.hexdigest()


def stop(state):
    own_unit(state)
    if properties(state['unit']).get('LoadState') != 'not-found':
        run(['systemctl', 'stop', state['unit']], timeout=45)
    off(state['unit'])


def sync_directory(work):
    fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def validate_overlay(path, state, digest=None):
    actual = image_hash(path)
    if digest is not None:
        require(actual == digest, 'reset overlay changed; retained data was not removed')
    info = image_info(path)
    require(info.get('full-backing-filename') == state['base'] and
            info.get('backing-filename-format') == 'qcow2' and info.get('virtual-size') == 16 * 1024**3,
            'reset overlay backing/size mismatch')
    return actual


def recover_reset(state, work):
    """Finish a durable reset intent; each reachable cut retains old bytes."""
    journal_path = work / 'reset.pending.json'
    if not journal_path.exists():
        require(not journal_path.is_symlink(), 'reset journal is a link')
        return False
    own_unit(state)
    off(state['unit'])
    journal = json.loads(read(journal_path))
    require(set(journal) == {'schema', 'run_id', 'stage', 'retained', 'old_sha512', 'new_sha512'} and
            journal['schema'] == 'aegis_vm_reset_intent_v1' and journal['run_id'] == state['run_id'], 'invalid reset journal')
    require(re.fullmatch(r'reset-stage-[0-9]+\.qcow2', journal['stage']) and
            re.fullmatch(r'retained-overlay-[0-9]+\.qcow2', journal['retained']) and
            all(re.fullmatch(r'[0-9a-f]{128}', journal[key]) for key in ('old_sha512', 'new_sha512')), 'invalid reset journal paths/digests')
    active, stage, retained = Path(state['guest']), work / journal['stage'], work / journal['retained']
    if not retained.exists():
        require(not retained.is_symlink(), 'retained overlay is a link')
        validate_overlay(active, state, journal['old_sha512'])
        validate_overlay(stage, state, journal['new_sha512'])
        active.rename(retained)
        sync_directory(work)
    else:
        validate_overlay(retained, state, journal['old_sha512'])
    if not active.exists():
        require(not active.is_symlink(), 'active overlay is a link')
        validate_overlay(stage, state, journal['new_sha512'])
        stage.rename(active)
        sync_directory(work)
    else:
        require(not stage.exists() and not stage.is_symlink(), 'ambiguous reset files; nothing discarded')
        validate_overlay(active, state, journal['new_sha512'])
    journal_path.unlink()
    sync_directory(work)
    return True


def reset(state, work):
    own_unit(state)
    off(state['unit'])
    assert_preserved(state)
    if recover_reset(state, work):
        assert_preserved(state)
        return 'RECOVERED_PREVIOUS_RESET'
    old_hash = validate_overlay(Path(state['guest']), state)
    suffix = str(time_ns())
    stage = work / ('reset-stage-' + suffix + '.qcow2')
    retained = work / ('retained-overlay-' + suffix + '.qcow2')
    require(not stage.exists() and not stage.is_symlink() and not retained.exists() and not retained.is_symlink(), 'reset output already exists')
    # No active rename happens until bounded creation, backing validation and
    # both file/directory durability complete. Failed creation leaves old active.
    run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', state['base'], stage, '16G'], timeout=60)
    new_hash = validate_overlay(stage, state)
    with trusted(stage, 32 * 1024**3) as stream:
        os.fsync(stream.fileno())
    sync_directory(work)
    journal = {'schema': 'aegis_vm_reset_intent_v1', 'run_id': state['run_id'],
               'stage': stage.name, 'retained': retained.name, 'old_sha512': old_hash, 'new_sha512': new_hash}
    journal_stage = work / ('reset-journal-' + suffix + '.tmp')
    json_new(journal_stage, journal)
    journal_stage.rename(work / 'reset.pending.json')
    sync_directory(work)
    recover_reset(state, work)
    assert_preserved(state)
    return 'RESET_COMPLETED'


def assert_preserved(state):
    for image in state['preserved_images']:
        require(image_hash(image['path']) == image['sha512'], 'original image changed; stop and inspect')
    require(image_hash(state['base']) == state['base_sha512'], 'immutable lab baseline changed')


def clone(args, verified, spec=None):
    require(verified['arch'] == 'x86_64' and os.uname().machine == 'x86_64', 'this KVM provisioning controller requires native x86_64; prepare ARM firmware separately')
    require(re.fullmatch(r'[0-9a-f]{128}', args.image_sha512 or ''), 'independent pristine image SHA-512 pin required')
    require(args.image and Path(args.image).is_absolute(), 'absolute pristine image path required')
    require(args.ssh_public_key and args.ssh_public_key_sha256, 'independently pinned SSH public key required')
    key = read(args.ssh_public_key, 16384).decode().strip()
    require(hashlib.sha256(read(args.ssh_public_key, 16384)).hexdigest() == args.ssh_public_key_sha256,
            'SSH public key pin mismatch')
    require(re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]*)?', key), 'one plain Ed25519 public key required')
    run(['ssh-keygen', '-lf', args.ssh_public_key])
    require(image_hash(args.image) == args.image_sha512, 'pristine cloud image pin mismatch')
    info = image_info(args.image)
    require(not info.get('backing-filename') and not info.get('snapshots'), 'pristine standalone source without snapshots required')
    require(0 < info['virtual-size'] <= 16 * 1024**3, 'unexpected cloud image virtual size')
    require(1024 <= args.ssh_port <= 65535, 'explicit unprivileged loopback forwarding port required')
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', args.ssh_port))
    work = ROOT / args.run_id
    require(not work.exists(), 'run ID already exists; use its bounded start/stop/reset actions')
    preserved = [{'path': str(Path(args.image).absolute()), 'sha512': args.image_sha512}]
    if args.preserve_disk:
        require(args.preserve_disk_sha512 and re.fullmatch(r'[0-9a-f]{128}', args.preserve_disk_sha512), 'retained guest disk requires independent SHA-512 pin')
        require(image_hash(args.preserve_disk) == args.preserve_disk_sha512, 'retained guest disk pin mismatch')
        # qemu-img's normal file locking rejects images held writable by QEMU.
        image_info(args.preserve_disk)
        preserved.append({'path': str(Path(args.preserve_disk).absolute()), 'sha512': args.preserve_disk_sha512})
    require(shutil.disk_usage(ROOT).free >= max(8 * 1024**3, info['virtual-size']), 'insufficient space for standalone lab clone')
    work.mkdir(mode=0o700)
    base = work / 'baseline.qcow2'
    run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'qcow2', args.image, base], timeout=300)
    require(not image_info(base).get('backing-filename'), 'new baseline unexpectedly references old VM storage')
    base.chmod(0o400)
    guest = work / 'guest.qcow2'
    run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', base, guest, '16G'])
    marker = {'schema': 'aegis_disposable_vm_v1', 'purpose': 'device_candidate_acceptance',
              'machine_id': '', 'run_id': args.run_id, 'source_sha': verified['source_sha']}
    # All values are validated JSON values; no shell interpolation or host mount.
    marker_program = ('import json,os; from pathlib import Path; os.umask(0o077); '
                      'm=' + repr(marker) + '; m["machine_id"]=Path("/etc/machine-id").read_text().strip(); '
                      'p=Path("/etc/aegis-disposable-vm.json"); '
                      'p.write_text(json.dumps(m)+"\\n"); p.chmod(0o600)')
    cloud = {'hostname': 'aegis-acceptance-' + args.run_id, 'manage_etc_hosts': True,
             'disable_root': False, 'ssh_pwauth': False,
             'users': [{'name': 'root', 'lock_passwd': True, 'ssh_authorized_keys': [key]}],
             'runcmd': [['python3', '-c', marker_program]],
             'package_update': False, 'package_upgrade': False}
    write_new(work / 'user-data', '#cloud-config\n' + json.dumps(cloud, indent=2) + '\n')
    json_new(work / 'meta-data', {'instance-id': 'aegis-acceptance-' + args.run_id,
                                'local-hostname': cloud['hostname']})
    run(['cloud-localds', work / 'seed.img', work / 'user-data', work / 'meta-data'])
    state = {'schema': 'aegis_candidate_vm_controller_v1', 'run_id': args.run_id,
             'unit': 'aegis-candidate-' + args.run_id + '.service', 'source_sha': verified['source_sha'],
             'candidate': verified, 'candidate_spec': spec, 'preserved_images': preserved, 'base': str(base),
             'base_sha512': image_hash(base), 'guest': str(guest), 'ssh_port': args.ssh_port,
             'seed_sha512': image_hash(work / 'seed.img'), 'arch': verified['arch']}
    state['qemu_binary'] = str(Path(shutil.which('qemu-system-x86_64')).resolve())
    state['qemu_sha256'] = file_hash(state['qemu_binary'])
    state['resources'] = {'memory_mib': 1536, 'memory_limit_mib': 2048,
                          'host_reserve_mib': 512, 'cpus': 1, 'cpu_quota_percent': 75}
    state['qemu_argv'] = initial_qemu_command(state, work)
    assert_preserved(state)
    json_new(work / 'state.json', state)
    return state


def initial_qemu_command(state, work):
    resources = state['resources']
    return [state['qemu_binary'],
         '-name', 'aegis-acceptance-' + state['run_id'], '-machine', 'q35,accel=kvm', '-cpu', 'host',
         '-smp', str(resources['cpus']), '-m', str(resources['memory_mib']), '-display', 'none', '-monitor', 'none',
         '-serial', 'file:' + str(work / 'private-console.log'),
         '-drive', 'file=' + state['guest'] + ',if=virtio,format=qcow2',
         '-drive', 'file=' + str(work / 'seed.img') + ',if=virtio,format=raw,readonly=on',
         '-netdev', 'user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:' + str(state['ssh_port']) + '-:22',
         '-device', 'virtio-net-pci,netdev=n0']


def qemu_command(state, work):
    # The recorded command, not current defaults, establishes unit ownership.
    # Updating controller CPU/RAM defaults cannot prevent an older owned stop.
    arguments = state['qemu_argv']
    require(isinstance(arguments, list) and 1 <= len(arguments) <= 128 and
            all(isinstance(value, str) and len(value) <= 4096 for value in arguments) and
            arguments[0] == state['qemu_binary'] and
            ['-name', 'aegis-acceptance-' + state['run_id']] == arguments[1:3] and
            'file=' + state['guest'] + ',if=virtio,format=qcow2' in arguments, 'invalid recorded QEMU command')
    return arguments


def memory_preflight(state, meminfo=Path('/proc/meminfo')):
    match = re.search(r'^MemAvailable:\s+([0-9]+)\s+kB$', meminfo.read_text(), re.M)
    require(match is not None, 'host MemAvailable is unavailable')
    available = int(match[1]) * 1024
    # Allow the complete unit limit plus its retained host-service reserve.
    # No reclaim, swapping policy changes or stopping other processes.
    policy = state['resources']
    require(all(type(policy[key]) is int and policy[key] > 0 for key in ('memory_mib', 'memory_limit_mib', 'host_reserve_mib', 'cpus', 'cpu_quota_percent')) and
            policy['memory_mib'] <= policy['memory_limit_mib'] and policy['host_reserve_mib'] >= 512,
            'invalid saved VM resource policy')
    required = (policy['memory_limit_mib'] + policy['host_reserve_mib']) * 1024**2
    require(available >= required, 'insufficient MemAvailable for VM limit and retained host reserve')
    return available


def start(state, work):
    own_unit(state)
    off(state['unit'])
    assert_preserved(state)
    recover_reset(state, work)
    require(image_hash(work / 'seed.img') == state['seed_sha512'], 'cloud seed changed')
    validate_overlay(Path(state['guest']), state)
    require(file_hash(state['qemu_binary']) == state['qemu_sha256'], 'pinned OS QEMU executable changed')
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', state['ssh_port']))
    require(os.uname().machine == state['arch'] == 'x86_64', 'native x86_64 KVM required; ARM firmware provisioning is separate')
    memory_preflight(state)
    run(['systemd-run', '--quiet', '--unit', state['unit'], '--property=Type=exec', '--property=RuntimeMaxSec=7200',
         '--property=TimeoutStopSec=30', '--property=KillMode=mixed', '--property=UMask=0077',
         '--property=MemoryMax=' + str(state['resources']['memory_limit_mib']) + 'M',
         '--property=CPUQuota=' + str(state['resources']['cpu_quota_percent']) + '%'] + qemu_command(state, work))
    exact_running(state['unit'], state['qemu_sha256'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'start', 'stop', 'reset', 'inspect'))
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--candidate-spec', help='required only for prepare/start; stop/reset/inspect use protected owned state')
    for name in ('image', 'image-sha512', 'preserve-disk', 'preserve-disk-sha512', 'ssh-public-key', 'ssh-public-key-sha256'):
        parser.add_argument('--' + name)
    parser.add_argument('--ssh-port', type=int, default=22219)
    args = parser.parse_args()
    os.umask(0o077)
    require(sys.platform == 'linux' and os.geteuid() == 0, 'root Linux host required')
    require(re.fullmatch(r'[a-z0-9]{1,12}', args.run_id), 'short unique run ID required')
    require(Path('/proc/1/comm').read_text().strip() == 'systemd', 'systemd host required')
    for command in DEPENDENCIES[args.action]:
        require(shutil.which(command), 'missing host dependency: ' + command)
    # No mutation, including clone creation, precedes authenticating the candidate.
    if args.action in ('prepare', 'start'):
        require(Path('/dev/kvm').exists(), 'KVM device required for prepare/start')
    spec, verified = candidate_for_action(args.action, args.candidate_spec)
    if not ROOT.exists():
        require(args.action == 'prepare', 'controller workspace does not exist')
        ROOT.mkdir(mode=0o700)
    tight(ROOT, 0o700)
    work = ROOT / args.run_id
    if args.action == 'prepare':
        state = clone(args, verified, spec)
        verdict = 'CLONE_PREPARED_NOT_STARTED'
    else:
        tight(work, 0o700)
        # Serialize same-run controllers; stopping an owned VM must still work
        # after candidate metadata expires. Only prepare/start execute a new
        # image and therefore require current signature/freshness verification.
        lock = os.open(work / '.controller.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        lock_info = os.fstat(lock)
        require(stat.S_ISREG(lock_info.st_mode) and lock_info.st_nlink == 1 and lock_info.st_uid == 0 and
                stat.S_IMODE(lock_info.st_mode) == 0o600, 'untrusted controller lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        tight(work / 'state.json', 0o600)
        state = json.loads(read(work / 'state.json', 4 * 1024 * 1024))
        require(state['schema'] == 'aegis_candidate_vm_controller_v1' and state['run_id'] == args.run_id and
                state['unit'] == 'aegis-candidate-' + args.run_id + '.service' and
                (spec is None or state['candidate_spec'] == spec) and
                (verified is None or state['candidate'] == verified),
                'controller state or exact candidate differs')
        require(state['guest'] == str(work / 'guest.qcow2') and state['base'] == str(work / 'baseline.qcow2'), 'controller disk path differs')
        require(re.fullmatch(r'[0-9a-f]{40}', state['source_sha']) and state['arch'] == 'x86_64' and
                re.fullmatch(r'[0-9a-f]{64}', state['qemu_sha256']), 'invalid owned state identity')
        if args.action == 'start':
            start(state, work)
            verdict = 'LAB_VM_STARTED_ACCEPTANCE_NOT_RUN'
        elif args.action == 'stop':
            # This exact unit was created and recorded by this controller. Never
            # stop a name supplied in arbitrary operator JSON or an older VM.
            stop(state)
            verdict = 'OWNED_LAB_VM_STOPPED'
        elif args.action == 'reset':
            reset(state, work)
            verdict = 'LAB_SNAPSHOT_RESET_ORIGINAL_IMAGES_UNCHANGED'
        else:
            own_unit(state)
            off(state['unit'])
            assert_preserved(state)
            verdict = 'OFF_AND_ORIGINAL_IMAGES_UNCHANGED'
    receipt = {'schema': 'aegis_candidate_vm_receipt_v1', 'verdict': verdict,
               'source_sha': state['source_sha'], 'unit': state['unit'], 'run_id': state['run_id'],
               'work_dir': str(work), 'guest_ssh': '127.0.0.1:' + str(state['ssh_port']),
               'host_mounts': [], 'network': 'QEMU restricted user network; loopback SSH forwarding only',
               'host_arch': os.uname().machine, 'guest_arch': state['arch'], 'requested_acceleration': 'kvm',
               'acceleration_evidence': 'matching host/guest architecture and actual QEMU started with explicit accel=kvm' if args.action == 'start' else 'NOT_RECHECKED_THIS_ACTION',
               'original_image_verification': 'NOT_RECHECKED_BY_STOP' if args.action == 'stop' else 'PASS',
               'native_acceptance': 'NOT_RUN unless separate guest receipts pass',
               'rollback_boundary': 'entire disposable overlay reset, not release antirollback bypass'}
    json_new(work / ('receipt-' + args.action + '-' + str(time_ns()) + '.json'), receipt)
    print(json.dumps(receipt, indent=2))


def time_ns():
    import time
    return time.time_ns()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        sys.exit(1)
