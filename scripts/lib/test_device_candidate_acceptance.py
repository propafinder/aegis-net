"""Isolated acceptance-controller contracts; no native service claim."""
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import device_candidate_acceptance as guest
import device_candidate_verify as verifier
import device_candidate_vm as vm

ROOT = Path(__file__).resolve().parents[2]


def command(args, **kwargs):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, **kwargs)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors='replace'))
    return result.stdout


class CandidateContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='aegis-candidate-contract-')
        self.work = Path(self.temporary.name).resolve()
        self.work.chmod(0o700)
        self.key = self.work / 'synthetic-signing.key'
        self.public = self.work / 'synthetic-public.pem'
        command(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', self.key])
        command(['openssl', 'pkey', '-in', self.key, '-pubout', '-out', self.public])
        self.key.chmod(0o600)
        self.public.chmod(0o600)
        self.bootstrap = self.work / 'bootstrap-install.sh'
        # The only fixture bootstrap change relocates its root floor to the
        # private test tree. HOME is also private for non-root contract runs.
        source = (ROOT / 'bootstrap-install.sh').read_text()
        self.bootstrap.write_text(source.replace('/var/lib/aegis-install/releases', str(self.work / 'root-floor')))
        self.bootstrap.chmod(0o600)
        self.spec = SimpleNamespace(source='a' * 40, tag='v0.3.50-rc.19', arch='x86_64',
            authority='github:fixture/aegis:.github/workflows/release.yml', minimum_sequence=19,
            public_key=str(self.public), public_key_sha256=verifier.file_hash(self.public), bootstrap=str(self.bootstrap),
            client_manifest=str(self.work / 'client-release.manifest.json'),
            operator_manifest=str(self.work / 'release.manifest.json'), run_id='fixture')
        now = int(time.time())
        self.policy = {'schema': 'aegis_release_policy_v1', 'authority': self.spec.authority, 'sequence': 19,
                       'tag': self.spec.tag, 'issued_at_unix': now - 10, 'expires_at_unix': now + 3600}
        self.capture = self.work / 'installer-arguments.json'
        script = self.work / 'fixture-installer.py'
        script.write_text('import json,sys\nfrom pathlib import Path\nPath(' + repr(str(self.capture)) + ').write_text(json.dumps(sys.argv[1:]))\n')
        self.installer = ('#!/bin/sh\nexec python3 ' + str(script) + ' "$@"\n').encode()
        self.client_bytes = b'NEVER EXECUTE THIS SYNTHETIC BINARY\n'
        self.archives = {}
        self.build('client')
        self.build('server')

    def tearDown(self):
        self.temporary.cleanup()

    def build(self, role, *, extra=None, missing_sum=None, missing_member=None, bad_binary=None, special=None, client_schema=None):
        public = role == 'client'
        name = ('aegis-client' if public else 'aegis') + '-0.3.50-linux-x86_64'
        schema = client_schema or getattr(self.spec, 'client_bundle_schema', verifier.CLIENT_BUNDLE_SCHEMA_V1)
        allowed = verifier.PUBLIC_PAYLOAD_V2 if schema == verifier.CLIENT_BUNDLE_SCHEMA_V2 else verifier.PUBLIC_PAYLOAD
        payload = {name: b'public fixture\n' for name in allowed}
        payload['bin/aegis-client'] = self.client_bytes
        payload['install.sh'] = self.installer
        if not public:
            payload['bin/aegis-server'] = b'NEVER EXECUTE SYNTHETIC SERVER\n'
        if extra:
            payload.update(extra)
        if missing_member:
            payload.pop(missing_member)
        binary = {name: {'path': 'bin/' + name, 'sha256': verifier.sha(payload['bin/' + name]), 'features': []}
                  for name in ('aegis-client',) if public}
        if not public:
            binary = {name: {'path': 'bin/' + name, 'sha256': verifier.sha(payload['bin/' + name]), 'features': []}
                      for name in ('aegis-client', 'aegis-server')}
        if bad_binary:
            binary[bad_binary]['sha256'] = '0' * 64
        payload['SHA256SUMS'] = ''.join(verifier.sha(value) + '  ' + key + '\n'
            for key, value in sorted(payload.items()) if key != missing_sum).encode()
        inner = {'schema': schema if public else 'aegis_release_bundle_manifest_v2',
                 'bundle_name': name, 'version': '0.3.50', 'git_sha': self.spec.source, 'arch': 'x86_64',
                 'platform': 'linux', 'target_triple': 'x86_64-unknown-linux-gnu', 'binaries': binary, 'files': sorted(payload)}
        if public:
            inner['distribution'] = 'public_client'
        payload['bundle.manifest.json'] = json.dumps(inner).encode()
        archive = self.work / (name + '.tar.gz')
        with tarfile.open(archive, 'w:gz') as output:
            for relative, value in payload.items():
                info = tarfile.TarInfo(name + '/' + relative)
                info.size = len(value)
                info.mode = 0o755 if relative == 'install.sh' else 0o600
                output.addfile(info, io.BytesIO(value))
            if special:
                info = tarfile.TarInfo(special[0])
                info.type = special[1]
                info.linkname = '/etc/passwd'
                output.addfile(info, io.BytesIO(b''))
        archive.chmod(0o600)
        manifest = {'schema': 'aegis_linux_release_manifest_v1', 'version': '0.3.50', 'git_sha': self.spec.source,
                    'arch': 'x86_64', 'platform': 'linux', 'target_triple': 'x86_64-unknown-linux-gnu',
                    'channel': 'rc', 'prerelease': True, 'release_policy': copy.deepcopy(self.policy),
                    'bootstrap': {'path': 'bootstrap-install.sh', 'sha256': verifier.file_hash(self.bootstrap)},
                    'artifacts': {'bundle': {'status': 'ready', 'directory': name,
                       'archive': {'path': archive.name, 'sha256': verifier.file_hash(archive), 'sha256_path': archive.name + '.sha256'}}}}
        if public:
            manifest['distribution'] = 'public_client'
        self.archives[role] = archive
        self.sign(role, manifest)

    def sign(self, role, manifest):
        field = 'client_manifest' if role == 'client' else 'operator_manifest'
        path = Path(getattr(self.spec, field))
        path.write_text(json.dumps(manifest))
        path.chmod(0o600)
        command(['openssl', 'pkeyutl', '-sign', '-inkey', self.key, '-rawin', '-in', path, '-out', str(path) + '.sig'])
        setattr(self.spec, field + '_sha256', verifier.file_hash(path))

    def reject(self, message):
        with self.assertRaisesRegex(ValueError, message):
            verifier.verify(self.spec)
        self.assertFalse(self.capture.exists(), 'candidate code ran during verification')

    def mutate_policy(self, field, value):
        for role, path in (('client', self.spec.client_manifest), ('server', self.spec.operator_manifest)):
            data = json.loads(Path(path).read_text())
            data['release_policy'][field] = value
            self.sign(role, data)

    def test_positive_signed_inventory_and_exact_extraction(self):
        accepted = verifier.verify(self.spec)
        extracted = verifier.extract_verified(accepted['client'], self.work / 'extracted')
        actual = {str(path.relative_to(extracted)): verifier.file_hash(path) for path in extracted.rglob('*') if path.is_file()}
        self.assertEqual(actual, accepted['client']['file_hashes'])
        self.assertFalse(self.capture.exists())

    def test_public_allowlist_agrees_with_publisher(self):
        source = (ROOT / 'tools/measure/src/public_client_delivery.rs').read_text()
        block = re.search(r'const PAYLOAD:.*?= &\[(.*?)\];', source, re.S)
        self.assertEqual(set(re.findall(r'"([^"]+)"', block[1])), verifier.PUBLIC_PAYLOAD)

    def test_public_v2_allowlist_adds_exactly_the_reviewed_guard(self):
        self.assertEqual(verifier.PUBLIC_PAYLOAD_V2 - verifier.PUBLIC_PAYLOAD, {verifier.DEVICE_GUARD_PAYLOAD})
        source = (ROOT / 'tools/measure/src/public_client_delivery.rs').read_text()
        guard = re.search(r'const DEVICE_GUARD_PAYLOAD: &str = "([^"]+)";', source)[1]
        self.assertEqual(guard, verifier.DEVICE_GUARD_PAYLOAD)
        self.spec.client_bundle_schema = verifier.CLIENT_BUNDLE_SCHEMA_V2
        self.build('client')
        self.build('server')
        accepted = verifier.verify(self.spec)
        self.assertEqual(accepted['client_bundle_schema'], verifier.CLIENT_BUNDLE_SCHEMA_V2)
        extracted = verifier.extract_verified(accepted['client'], self.work / 'v2-extracted')
        self.assertEqual((extracted / guard).read_bytes(), b'public fixture\n')
        self.assertFalse(self.capture.exists())

    def test_independent_payload_schema_prevents_silent_upgrade_or_downgrade(self):
        self.spec.client_bundle_schema = verifier.CLIENT_BUNDLE_SCHEMA_V2
        self.reject('independent client bundle schema mismatch')
        self.build('client')
        del self.spec.client_bundle_schema
        self.reject('independent client bundle schema mismatch')
        self.spec.client_bundle_schema = verifier.CLIENT_BUNDLE_SCHEMA_V2
        self.build('client', client_schema=verifier.CLIENT_BUNDLE_SCHEMA_V1)
        self.reject('independent client bundle schema mismatch')
        self.build('client', client_schema='aegis_client_release_bundle_manifest_v3')
        self.reject('independent client bundle schema mismatch')
        for schema in ['future', None, 2, []]:
            self.spec.client_bundle_schema = schema
            self.reject('unsupported independent client bundle schema')

    def test_guard_under_legacy_schema_and_missing_v2_guard_are_rejected(self):
        self.build('client', extra={verifier.DEVICE_GUARD_PAYLOAD: b'guard under wrong schema'})
        self.reject('public file allowlist mismatch')
        self.spec.client_bundle_schema = verifier.CLIENT_BUNDLE_SCHEMA_V2
        self.build('client', missing_member=verifier.DEVICE_GUARD_PAYLOAD)
        self.reject('public file allowlist mismatch')
        self.build('client', missing_sum=verifier.DEVICE_GUARD_PAYLOAD)
        self.reject('incomplete nested checksum')
        for forbidden in ['device.key', 'server.key', 'aegis-server.toml', 'bin/aegis-server', 'src/main.rs']:
            self.build('client', extra={forbidden: b'inert but forbidden'})
            self.reject('public file allowlist mismatch')

    def test_v2_operator_guard_dependency_must_match_public_copy(self):
        self.spec.client_bundle_schema = verifier.CLIENT_BUNDLE_SCHEMA_V2
        self.build('client')
        self.reject('public/operator device guard differs')
        self.build('server', extra={verifier.DEVICE_GUARD_PAYLOAD: b'different signed operator guard'})
        self.reject('public/operator device guard differs')
        self.build('server')
        verifier.verify(self.spec)

    def test_schema_cli_and_controller_spec_are_strict_and_historical_compatible(self):
        parsed = guest.parser().parse_args(['verify-only'])
        self.assertEqual(parsed.client_bundle_schema, verifier.CLIENT_BUNDLE_SCHEMA_V1)
        parsed = guest.parser().parse_args(['verify-only', '--client-bundle-schema', verifier.CLIENT_BUNDLE_SCHEMA_V2])
        self.assertEqual(parsed.client_bundle_schema, verifier.CLIENT_BUNDLE_SCHEMA_V2)
        legacy_spec = {key: getattr(self.spec, key) for key in vm.SPEC_FIELDS}
        path = self.work / 'spec.json'
        path.write_text(json.dumps(legacy_spec)); path.chmod(0o600)
        original = path.read_bytes()
        _, old = vm.candidate_for_action('prepare', str(path))
        self.assertEqual(old['client_bundle_schema'], verifier.CLIENT_BUNDLE_SCHEMA_V1)
        self.assertEqual(path.read_bytes(), original)
        self.spec.client_bundle_schema = verifier.CLIENT_BUNDLE_SCHEMA_V2
        self.build('client')
        self.build('server')
        fresh_spec = {key: getattr(self.spec, key) for key in vm.SPEC_FIELDS}
        fresh_spec['client_bundle_schema'] = verifier.CLIENT_BUNDLE_SCHEMA_V2
        path.write_text(json.dumps(fresh_spec))
        original = path.read_bytes()
        _, current = vm.candidate_for_action('prepare', str(path))
        self.assertEqual(current['client_bundle_schema'], verifier.CLIENT_BUNDLE_SCHEMA_V2)
        self.assertEqual(path.read_bytes(), original)
        for key, value in [('unknown_field', 'bad'), ('client_bundle_schema', 'unknown')]:
            path.write_text(json.dumps({**fresh_spec, key: value}))
            with self.assertRaises(ValueError):
                vm.candidate_for_action('prepare', str(path))
        self.assertFalse(self.capture.exists())

    def test_exact_manifest_pin_before_parse(self):
        self.spec.client_manifest_sha256 = '0' * 64
        self.reject('manifest pin mismatch')

    def test_wrong_signature(self):
        Path(self.spec.client_manifest + '.sig').write_bytes(b'0' * 64)
        self.reject('verification utility failed')

    def test_wrong_public_key_pin(self):
        self.spec.public_key_sha256 = '0' * 64
        self.reject('release key pin mismatch')

    def test_source_mismatch(self):
        self.spec.source = 'b' * 40
        self.reject('source mismatch')

    def test_architecture_mismatch(self):
        self.spec.arch = 'aarch64'
        self.reject('architecture mismatch')

    def test_expired(self):
        self.mutate_policy('issued_at_unix', int(time.time()) - 1000)
        self.mutate_policy('expires_at_unix', int(time.time()) - 1)
        self.reject('expired/future')

    def test_future(self):
        self.mutate_policy('issued_at_unix', int(time.time()) + 600)
        self.reject('expired/future')

    def test_independent_sequence_floor(self):
        self.spec.minimum_sequence = 20
        self.reject('independent floor')

    def test_unlisted_public_operator_file(self):
        self.build('client', extra={'operator-secrets.json': b'public fixture, still forbidden'})
        self.reject('public file allowlist')

    def test_nested_binary_digest_mismatch(self):
        self.build('server', bad_binary='aegis-client')
        self.reject('public/operator client differs')

    def test_missing_nested_checksum(self):
        self.build('client', missing_sum='install.sh')
        self.reject('incomplete nested checksum')

    def test_archive_link_rejected_before_extract(self):
        self.build('client', special=('aegis-client-0.3.50-linux-x86_64/alias', tarfile.SYMTYPE))
        self.reject('links and special')

    def test_archive_traversal_rejected(self):
        self.build('client', special=('../outside', tarfile.REGTYPE))
        self.reject('traversal')

    def test_changed_archive_unsigned_sibling_cannot_help(self):
        archive = self.archives['client']
        archive.write_bytes(archive.read_bytes() + b'changed')
        Path(str(archive) + '.sha256').write_text(verifier.file_hash(archive))
        self.reject('signed archive hash mismatch')

    def test_changed_archive_after_verification(self):
        accepted = verifier.verify(self.spec)
        self.archives['client'].write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'archive changed after preflight'):
            verifier.extract_verified(accepted['client'], self.work / 'must-stay-empty')
        self.assertEqual(list((self.work / 'must-stay-empty').iterdir()), [])

    def test_manifest_symlink_and_writable_input(self):
        path = Path(self.spec.client_manifest)
        original = path.read_bytes()
        path.unlink()
        path.symlink_to(self.spec.operator_manifest)
        with self.assertRaises(OSError):
            verifier.verify(self.spec)
        path.unlink()
        path.write_bytes(original)
        path.chmod(0o666)
        self.reject('untrusted input file')

    def test_cloud_image_pin_is_checked_before_mutation(self):
        args = SimpleNamespace(image_sha512='0' * 128, image=str(self.work / 'image.qcow2'),
                               ssh_public_key=None, ssh_public_key_sha256=None)
        verified = verifier.verify(self.spec)
        with patch.object(vm.os, 'uname', return_value=SimpleNamespace(machine='x86_64')):
            with self.assertRaisesRegex(ValueError, 'SSH public key required'):
                vm.clone(args, verified)
        self.assertFalse((self.work / 'baseline.qcow2').exists())

    def test_vm_stop_rejects_reused_unit_name(self):
        state = self.vm_state()
        with patch.object(vm, 'properties', return_value={'LoadState': 'loaded'}), \
             patch.object(vm, 'text', return_value='{ path=/usr/bin/sleep ; argv[]=sleep 500 ; }'), \
             patch.object(vm, 'run') as mutation:
            with self.assertRaisesRegex(ValueError, 'different command'):
                vm.stop(state)
            mutation.assert_not_called()

    def test_vm_owned_stop_does_not_need_unexpired_candidate(self):
        state = self.vm_state()
        import shlex
        command_line = '{ argv[]=' + shlex.join(state['qemu_argv']) + ' ; }'
        with patch.object(vm, 'properties', return_value={'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0'}), \
             patch.object(vm, 'text', return_value=command_line), patch.object(vm, 'assert_preserved') as preserved, \
             patch.object(vm, 'run') as mutation, patch.object(vm, 'verify', side_effect=AssertionError('stop must not require freshness')):
            vm.stop(state)
            mutation.assert_called_once_with(['systemctl', 'stop', state['unit']], timeout=45)
            preserved.assert_not_called()

    def vm_state(self):
        directory = self.work / 'vm'
        directory.mkdir(mode=0o700, exist_ok=True)
        for name, data in (('baseline.qcow2', b'BASE'), ('guest.qcow2', b'OLD'), ('seed.img', b'SEED')):
            path = directory / name
            path.write_bytes(data)
            path.chmod(0o600)
        state = {'unit': 'aegis-candidate-fixture.service', 'run_id': 'fixture', 'guest': str(directory / 'guest.qcow2'),
                 'base': str(directory / 'baseline.qcow2'), 'base_sha512': vm.image_hash(directory / 'baseline.qcow2'),
                 'preserved_images': [], 'arch': 'x86_64', 'ssh_port': 22219,
                 'seed_sha512': vm.image_hash(directory / 'seed.img'),
                 'qemu_binary': '/usr/bin/qemu-system-x86_64', 'qemu_sha256': 'a' * 64,
                 'resources': {'memory_mib': 1536, 'memory_limit_mib': 2048, 'host_reserve_mib': 512, 'cpus': 1, 'cpu_quota_percent': 75}}
        state['qemu_argv'] = vm.initial_qemu_command(state, directory)
        return state

    def test_vm_stop_inputs_and_tools_are_independent_of_candidate(self):
        self.assertEqual(vm.DEPENDENCIES['stop'], ('systemctl',))
        with patch.object(vm, 'read', side_effect=AssertionError('stop must not read build inputs')), \
             patch.object(vm, 'verify', side_effect=AssertionError('stop must not verify artifacts')):
            self.assertEqual(vm.candidate_for_action('stop', '/missing/spec.json'), (None, None))

    def test_vm_deactivating_owned_process_can_stop(self):
        state = self.vm_state()
        import shlex
        before = {'LoadState': 'loaded', 'ActiveState': 'deactivating', 'MainPID': '123'}
        after = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0'}
        values = [before, before, before, after]
        with patch.object(vm, 'properties', side_effect=values), patch.object(vm, 'text', return_value='{ argv[]=' + shlex.join(state['qemu_argv']) + ' ; }'), \
             patch.object(vm, 'pid_executable_hash', return_value=state['qemu_sha256']), patch.object(vm, 'run') as mutation, \
             patch.object(vm, 'exact_running', side_effect=AssertionError('stop must not require active')):
            vm.stop(state)
            mutation.assert_called_once_with(['systemctl', 'stop', state['unit']], timeout=45)

    def test_vm_resource_defaults_do_not_change_stored_command(self):
        state = self.vm_state()
        saved = list(state['qemu_argv'])
        state['resources']['memory_mib'] = 777
        self.assertEqual(vm.qemu_command(state, Path(state['guest']).parent), saved)

    def test_vm_memory_guard_uses_available_not_free(self):
        state = self.vm_state()
        path = self.work / 'meminfo'
        path.write_text('MemFree: 9000000 kB\nMemAvailable: 2000000 kB\n')
        with self.assertRaisesRegex(ValueError, 'insufficient MemAvailable'):
            vm.memory_preflight(state, path)
        path.write_text('MemFree: 1000 kB\nMemAvailable: 2912580 kB\n')
        self.assertEqual(vm.memory_preflight(state, path), 2912580 * 1024)

    def test_reset_create_failure_retains_active_inode_and_bytes(self):
        state = self.vm_state()
        active = Path(state['guest'])
        inode = active.stat().st_ino
        def failed_create(args, **_kwargs):
            Path(args[-2]).write_bytes(b'PARTIAL')
            raise ValueError('injected create failure')
        info = {'format': 'qcow2', 'full-backing-filename': state['base'], 'backing-filename-format': 'qcow2', 'virtual-size': 16 * 1024**3}
        with patch.object(vm, 'own_unit'), patch.object(vm, 'off'), patch.object(vm, 'image_info', return_value=info), patch.object(vm, 'run', side_effect=failed_create):
            with self.assertRaisesRegex(ValueError, 'injected create failure'):
                vm.reset(state, active.parent)
            self.assertEqual(active.read_bytes(), b'OLD')
            self.assertEqual(active.stat().st_ino, inode)
            self.assertFalse((active.parent / 'reset.pending.json').exists())

    def test_reset_sigkill_after_retain_recovers_without_new_create(self):
        state = self.vm_state()
        active = Path(state['guest'])
        work = active.parent
        info = {'format': 'qcow2', 'full-backing-filename': state['base'], 'backing-filename-format': 'qcow2', 'virtual-size': 16 * 1024**3}
        def create(args, **_kwargs):
            Path(args[-2]).write_bytes(b'NEW')
        sync = vm.sync_directory
        def kill_after_retain(path):
            sync(path)
            if list(work.glob('retained-overlay-*')) and not active.exists():
                os.kill(os.getpid(), signal.SIGKILL)
        pid = os.fork()
        if pid == 0:
            try:
                with patch.object(vm, 'own_unit'), patch.object(vm, 'off'), patch.object(vm, 'image_info', return_value=info), \
                     patch.object(vm, 'run', side_effect=create), patch.object(vm, 'sync_directory', side_effect=kill_after_retain):
                    vm.reset(state, work)
            except BaseException:
                os._exit(8)
            os._exit(9)
        _, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL, status)
        self.assertTrue((work / 'reset.pending.json').exists())
        self.assertFalse(active.exists())
        with patch.object(vm, 'own_unit'), patch.object(vm, 'off'), patch.object(vm, 'image_info', return_value=info), \
             patch.object(vm, 'run', side_effect=AssertionError('recovery must use prevalidated staged overlay')):
            self.assertEqual(vm.reset(state, work), 'RECOVERED_PREVIOUS_RESET')
        self.assertEqual(active.read_bytes(), b'NEW')
        self.assertEqual([path.read_bytes() for path in work.glob('retained-overlay-*')], [b'OLD'])
        self.assertFalse((work / 'reset.pending.json').exists())

    def test_signature_ignores_unsafe_tmpdir(self):
        unsafe = self.work / 'unsafe'
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o777)
        temporary = verifier.tempfile.TemporaryDirectory
        used = []
        def capture(*args, **kwargs):
            used.append(Path(kwargs['dir']))
            return temporary(*args, **kwargs)
        with patch.dict(os.environ, {'TMPDIR': str(unsafe)}), patch.object(verifier.tempfile, 'TemporaryDirectory', side_effect=capture):
            verifier.verify(self.spec)
        self.assertEqual(used, [verifier.trusted_scratch_parent()] * 2)
        self.assertEqual(list(unsafe.iterdir()), [])
        with self.assertRaisesRegex(ValueError, 'no protected signature scratch'):
            verifier.trusted_scratch_parent([unsafe])

    def test_signature_default_sticky_parent_is_os_owned(self):
        parent = verifier.trusted_scratch_parent()
        info = parent.stat()
        self.assertEqual(info.st_uid, 0)
        self.assertTrue(info.st_mode & 0o1000)

    def test_vm_start_requires_exec_and_actual_qemu_readiness(self):
        state = self.vm_state()
        info = {'format': 'qcow2', 'full-backing-filename': state['base'], 'backing-filename-format': 'qcow2', 'virtual-size': 16 * 1024**3}
        platform = SimpleNamespace(machine='x86_64', sysname=os.uname().sysname)
        with patch.object(vm, 'own_unit'), patch.object(vm, 'off'), patch.object(vm, 'image_info', return_value=info), \
             patch.object(vm, 'file_hash', return_value=state['qemu_sha256']), patch.object(vm.os, 'uname', return_value=platform), \
             patch.object(vm.socket, 'socket'), patch.object(vm, 'memory_preflight'), patch.object(vm, 'run') as mutation, \
             patch.object(vm, 'exact_running', side_effect=ValueError('injected failed QEMU exec')) as ready:
            with self.assertRaisesRegex(ValueError, 'failed QEMU exec'):
                vm.start(state, Path(state['guest']).parent)
            self.assertIn('--property=Type=exec', mutation.call_args.args[0])
            ready.assert_called_once_with(state['unit'], state['qemu_sha256'])

    def cleanup_fixture(self, *, failure=None):
        import shlex
        lab = guest.Lab(self.spec, {}, self.work)
        groups = self.work / 'cgroups'
        groups.mkdir()
        calls = []
        with patch.object(guest.shutil, 'which', return_value='/usr/sbin/ip'):
            commands = dict(lab.network_commands())
            for unit in commands:
                directory = groups / 'system.slice' / unit
                directory.mkdir(parents=True)
                (directory / 'cgroup.procs').write_text('456\n' if failure == 'cgroup' else '')
            def query(args, **_kwargs):
                calls.append(args)
                if '--property=ExecStart' in args:
                    return '{ argv[]=' + shlex.join(commands[args[2]]) + ' ; }'
                if '--property=ControlGroup' in args:
                    return '/system.slice/' + args[2]
                if args[:3] == ['ip', 'netns', 'pids']:
                    return '789' if failure == 'namespace' else ''
                raise AssertionError(args)
            def mutate(args, **_kwargs):
                calls.append(args)
                if failure == 'stop' and args[:2] == ['systemctl', 'stop']:
                    raise ValueError('injected systemctl stop failure')
            with patch.object(guest, 'text', side_effect=query), patch.object(guest, 'run', side_effect=mutate), \
                 patch.object(guest, 'CGROUP_ROOT', groups), patch.object(guest, 'properties', return_value={'MainPID': '0', 'ActiveState': 'inactive'}):
                error = None
                try:
                    lab.stop_network()
                except ValueError as value:
                    error = value
        return error, calls

    def test_failed_lab_stop_cannot_delete_namespace_or_pass(self):
        error, calls = self.cleanup_fixture(failure='stop')
        self.assertRegex(str(error), 'stop failure')
        self.assertFalse(any(args[:3] == ['ip', 'netns', 'delete'] for args in calls))

    def test_lingering_cgroup_cannot_delete_namespace_or_pass(self):
        error, calls = self.cleanup_fixture(failure='cgroup')
        self.assertRegex(str(error), 'cgroup still owns processes')
        self.assertFalse(any(args[:3] == ['ip', 'netns', 'delete'] for args in calls))

    def test_lingering_namespace_process_cannot_be_detached(self):
        error, calls = self.cleanup_fixture(failure='namespace')
        self.assertRegex(str(error), 'namespace still owns processes')
        self.assertFalse(any(args[:3] == ['ip', 'netns', 'delete'] for args in calls))

    def test_successful_lab_cleanup_checks_processes_before_delete(self):
        error, calls = self.cleanup_fixture()
        self.assertIsNone(error)
        check = next(i for i, args in enumerate(calls) if args[:3] == ['ip', 'netns', 'pids'])
        delete = next(i for i, args in enumerate(calls) if args[:3] == ['ip', 'netns', 'delete'])
        self.assertLess(check, delete)

    def test_actual_registry_v2_explicit_refresh_and_readonly_status(self):
        server = Path(os.environ.get('AEGIS_DEVICE_SERVER', ROOT / 'target/debug/aegis-server')).resolve()
        self.assertTrue(server.is_file(), 'build aegis-server before this contract or set AEGIS_DEVICE_SERVER')
        lab_dir = self.work / 'registry-lab'
        lab_dir.mkdir(mode=0o700)
        operator = [server, 'device', '--registry', lab_dir / 'registry.json']
        command(operator + ['init'])
        lab = guest.Lab(self.spec, {}, lab_dir)
        lab.server = server
        refreshed = lab.registry_policy('fixture-after-issue', force=True)
        self.assertEqual(refreshed['action'], 'ADMIN_REFRESH_3600S')
        current = lab.registry_policy('fixture-current-read')
        self.assertEqual(current['action'], 'READ_ONLY_CURRENT_POLICY')
        self.assertEqual(current['generation_before'], current['generation_after'])
        command(operator + ['refresh-registry', '--ttl-secs', '1'])
        near_expiry = lab.registry_policy('fixture-near-expiry')
        self.assertEqual(near_expiry['action'], 'ADMIN_REFRESH_3600S')
        self.assertEqual(len(list(lab_dir.glob('registry-policy-*.json'))), 3)

    def test_vm_running_snapshot_refused(self):
        with patch.object(vm, 'properties', return_value={'ActiveState': 'active', 'MainPID': '345'}):
            with self.assertRaisesRegex(ValueError, 'fully off'):
                vm.off('aegis-candidate-fixture.service')

    def test_preserved_image_change_refused(self):
        state = {'preserved_images': [{'path': '/retained.qcow2', 'sha512': 'a' * 128}],
                 'base': '/baseline.qcow2', 'base_sha512': 'a' * 128}
        with patch.object(vm, 'image_hash', return_value='b' * 128):
            with self.assertRaisesRegex(ValueError, 'original image changed'):
                vm.assert_preserved(state)

    def test_native_mode_refuses_current_unmarked_host(self):
        with self.assertRaises((ValueError, FileNotFoundError)):
            guest.guest_guard(SimpleNamespace(vm_marker=str(self.work / 'missing-marker')), clean=True)
        self.assertFalse(self.capture.exists())

    def test_actual_bootstrap_forwarding_and_floor_contract(self):
        accepted = verifier.verify(self.spec)
        lab_dir = self.work / 'lab'
        lab_dir.mkdir(mode=0o700)
        shutil.copyfile(self.bootstrap, lab_dir / 'bootstrap-install.sh')
        shutil.copyfile(self.public, lab_dir / 'release-public-key.pem')
        delivery = lab_dir / 'delivery'
        delivery.mkdir(mode=0o700)
        for source in (Path(self.spec.client_manifest), Path(self.spec.client_manifest + '.sig'), self.archives['client']):
            shutil.copyfile(source, delivery / source.name)
        home = self.work / 'home'
        home.mkdir(mode=0o700)
        lab = guest.Lab(self.spec, accepted, lab_dir)
        actual_run = guest.run
        def isolated_run(args, timeout=30, *, ok=True, env=None):
            # Only the fixture invocation receives OS/path overrides; no product
            # file or system/network command is executed by this fake installer.
            env = dict(env or os.environ)
            env.update(PATH=os.environ['PATH'], HOME=str(home),
                       AEGIS_BOOTSTRAP_OS_KIND_OVERRIDE='linux', AEGIS_BOOTSTRAP_HOST_FAMILY_OVERRIDE='other',
                       AEGIS_BOOTSTRAP_ARCH_OVERRIDE='x86_64')
            return actual_run(args, timeout, ok=ok, env=env)
        with patch.object(guest, 'run', isolated_run):
            lab.bootstrap('fixture-install', ['--device-certificate', self.work / 'response.pem', '--upgrade'])
        received = json.loads(self.capture.read_text())
        self.assertEqual(received, ['client', '--bundle', str(lab_dir / 'public-bundle'), '--device-id', 'acceptance-fixture',
                                   '--identity-dir', str(guest.IDENTITY), '--profile', 'socks-only', '--force',
                                   '--device-certificate', str(self.work / 'response.pem'), '--upgrade', '--bundle-local-only'])
        floors = list(self.work.rglob('client-linux-x86_64.json'))
        self.assertEqual(len(floors), 1)
        self.assertEqual(json.loads(floors[0].read_text())['manifest_sha256'], self.spec.client_manifest_sha256)
        self.assertEqual(floors[0].stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.work.rglob('*.pending.json')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
