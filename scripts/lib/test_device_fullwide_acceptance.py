"""Harmless source contracts and real owned child failures; never native acceptance."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import select
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import device_fullwide_acceptance as m


class FullwideContracts(unittest.TestCase):
    def state(self):
        return {'schema': 'aegis_fullwide_recovery_owner_v2', 'source': '1' * 40, 'run_id': 'trial1',
            'boot_id': 'fixture-boot', 'controller': '/var/lib/aegis-fullwide-acceptance/trial1/device_fullwide_acceptance.py',
            'controller_sha256': '2' * 64, 'python': '/usr/bin/python3.13', 'python_sha256': '3' * 64,
            'controller_dependencies': {}, 'unit_pins': {'aegis-fw-accept-trial1.service': '4' * 64, 'aegis-fw-accept-trial1.timer': '5' * 64},
            'guard_sha256': '6' * 64, 'client_sha256': '7' * 64, 'config_sha256': '8' * 64, 'state_sha256': '9' * 64,
            'client_unit_pins': {'/etc/systemd/system/aegis-client.service': 'a' * 64},
            'helper_pins': {p: 'c' * 64 for p in ('/usr/local/lib/aegis/lib/root-state.sh', '/usr/local/lib/aegis/aegis-wide-disable.sh', '/usr/local/lib/aegis/setup-wide-linux-redirect.sh', '/usr/local/lib/aegis/setup-wide-linux-tproxy.sh', '/usr/local/lib/aegis/janitor-wide-linux-tproxy.sh')}, 'managed_unit_pins': {},
            'quiet_seconds': 5, 'capture': {}, 'collector_identity': {'pid': '1', 'start_ticks': '1', 'invocation': 'a' * 32, 'output_device': 1, 'output_inode': 1}, 'uplink': 'eth0', 'native_network_sha256': 'b' * 64,
            'baseline': {'guard_state': 'armed=1\n', 'manager': 'systemd-networkd.service', 'client_loaded': {}, 'client_initial_invocation': ''}, 'deadline_unix': 1900000000}

    def test_unknown_owner_field_refuses(self):
        state = self.state(); state['force'] = True
        with self.assertRaises(ValueError): m.validate_owner(state)

    def test_old_or_other_recovery_schema_refuses(self):
        state = self.state(); state['schema'] = 'generic_recovery'
        with self.assertRaises(ValueError): m.validate_owner(state)

    def test_foreign_timer_owner_refuses(self):
        state = self.state(); state['unit_pins']['foreign.timer'] = 'a' * 64
        with self.assertRaises(ValueError): m.validate_owner(state)

    def test_quiet_interval_bounds_are_real(self):
        for quiet in (True, 0, 4, 31, 100000):
            state = self.state(); state['quiet_seconds'] = quiet
            with self.assertRaises(ValueError): m.validate_owner(state)

    def test_invalid_source_refuses(self):
        state = self.state(); state['source'] = 'short'
        with self.assertRaises(ValueError): m.validate_owner(state)

    def test_foreign_client_dropin_refuses(self):
        state = self.state(); state['client_unit_pins']['/etc/systemd/system/ssh.service'] = 'a' * 64
        with self.assertRaises(ValueError): m.validate_owner(state)

    def test_no_independent_native_network_pin_refuses(self):
        state = self.state(); state['native_network_sha256'] = 'unknown'
        with self.assertRaises(ValueError): m.validate_owner(state)

    def test_systemd_substitution_and_injection_refuse(self):
        for controller in ('/root/%n.py', '/root/part\nExecStart=/bin/true', '/root/../other.py', '/root/a b.py'):
            state = self.state(); state['controller'] = controller
            with self.assertRaises(ValueError): m.units(state, Path('/root/state.json'))

    def test_persistent_finite_owned_timer_recipe(self):
        state = self.state(); generated = m.units(state, Path('/var/lib/aegis-fullwide-acceptance/trial1/state.json'))
        self.assertEqual(set(generated), set(state['unit_pins']))
        timer = generated['aegis-fw-accept-trial1.timer'].decode()
        service = generated['aegis-fw-accept-trial1.service'].decode()
        self.assertIn('Persistent=true', timer); self.assertIn('UTC', timer)
        self.assertIn('Unit=aegis-fw-accept-trial1.service', timer)
        self.assertIn('TimeoutStartSec=90', service); self.assertIn('KillMode=control-group', service)
        self.assertIn('Restart=no', service); self.assertNotIn('pkill', service)

    def test_exclusive_retained_record_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'failed.json'
            m.new(path, {'failure': 'first'})
            before = path.read_bytes()
            with self.assertRaises(FileExistsError): m.new(path, {'failure': 'second'})
            self.assertEqual(before, path.read_bytes()); self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_duplicate_input_refuses(self):
        with self.assertRaises(ValueError): json.loads('{"a":1,"a":2}', object_pairs_hook=m.unique)

    def test_unknown_activation_spec_refuses_before_verifier(self):
        with patch.object(m, 'verify', side_effect=AssertionError('verifier touched')):
            with self.assertRaises(ValueError): m.activate({'schema': 'fake', 'force': True})

    def test_actual_owned_command_success_bounded_metadata_only(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = m.Commands(folder, time.monotonic() + 3)
            self.assertEqual(runner.call([sys.executable, '-c', 'print("private fixture payload")']), 'private fixture payload\n')
            receipts = list(Path(folder).glob('command-*.json')); self.assertEqual(len(receipts), 1)
            self.assertNotIn('private fixture payload', receipts[0].read_text())
            self.assertEqual(json.loads(receipts[0].read_text())['exit'], 0)

    def test_actual_owned_deadline_kills_only_owned_group_and_keeps_spectator(self):
        with tempfile.TemporaryDirectory() as folder:
            spectator = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'])
            try:
                runner = m.Commands(folder, time.monotonic() + 0.08)
                with self.assertRaises(TimeoutError): runner.call([sys.executable, '-c', 'import time; time.sleep(10)'])
                self.assertIsNone(spectator.poll())
                receipt = json.loads(next(Path(folder).glob('command-*.json')).read_text())
                self.assertEqual(receipt['failure'], 'COMMAND_DEADLINE'); self.assertLess(receipt['exit'], 0)
            finally:
                spectator.terminate(); spectator.wait(timeout=2)

    def test_actual_output_flood_is_bounded_and_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = m.Commands(folder, time.monotonic() + 3)
            with self.assertRaises(ValueError):
                runner.call([sys.executable, '-c', 'import os,time;\nwhile True: os.write(1,b"x"*65536); time.sleep(.001)'])
            receipt = json.loads(next(Path(folder).glob('command-*.json')).read_text())
            self.assertEqual(receipt['failure'], 'COMMAND_OUTPUT_BOUND'); self.assertLess(receipt['exit'], 0)

    def test_actual_group_query_failure_still_reaps_direct_child(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = m.Commands(folder, time.monotonic() + 0.06)
            with patch.object(m.os, 'getpgid', side_effect=PermissionError('fixture')):
                with self.assertRaises(TimeoutError): runner.call([sys.executable, '-c', 'import time; time.sleep(10)'])
            receipt = json.loads(next(Path(folder).glob('command-*.json')).read_text())
            self.assertEqual(receipt['failure'], 'COMMAND_DEADLINE')
            self.assertLess(receipt['exit'], 0); self.assertEqual(receipt['cleanup_errors'], ['PermissionError'])

    def test_actual_collector_exit_holds_full_scaled_interval_and_retains_first_loss(self):
        collector = subprocess.Popen([sys.executable, '-u', '-c', 'import sys; print("READY",flush=True); assert sys.stdin.buffer.read(1)==b"X"'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        spectator = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'])
        state = self.state(); state['quiet_seconds'] = .09
        requested_exit = False
        def observe(*_):
            nonlocal requested_exit
            if collector.poll() is not None: raise RuntimeError('actual fixture collector terminated')
            if not requested_exit:
                collector.stdin.write(b'X'); collector.stdin.flush()
                requested_exit = True
            return state['collector_identity']
        try:
            # Readiness confirmation precedes the entire declared record interval.
            self.assertTrue(select.select([collector.stdout], [], [], 2)[0])
            self.assertEqual(collector.stdout.readline(), b'READY\n')
            self.assertIsNone(collector.poll())
            confirmed = time.monotonic()
            started = time.monotonic()
            with patch.object(m, 'capture_identity', side_effect=observe): result = m.observe_quiet(state, object())
            self.assertGreaterEqual(time.monotonic() - started, .09)
            self.assertEqual(result['capture'], 'INCOMPLETE')
            self.assertIn('collector_first_loss_unix', result)
            self.assertLessEqual(confirmed, started)
            self.assertEqual(collector.wait(timeout=2), 0)
            self.assertEqual(collector.stdout.read(), b'')  # Actual EOF, no fixed exit delay.
            self.assertTrue(requested_exit)
            self.assertIsNone(spectator.poll())
        finally:
            if collector.poll() is None: collector.kill()
            collector.wait(timeout=2); collector.stdin.close(); collector.stdout.close()
            spectator.terminate(); spectator.wait(timeout=2)

    def test_changed_same_name_collector_keeps_full_interval_failure(self):
        state = self.state(); state['quiet_seconds'] = .02
        foreign = dict(state['collector_identity'], start_ticks='99')
        started = time.monotonic()
        with patch.object(m, 'capture_identity', return_value=foreign): result = m.observe_quiet(state, object())
        self.assertGreaterEqual(time.monotonic() - started, .02)
        self.assertEqual(result['capture'], 'INCOMPLETE')

    def test_clean_scaled_observation_is_not_native_capture_acceptance(self):
        state = self.state(); state['quiet_seconds'] = .02
        with patch.object(m, 'capture_identity', return_value=state['collector_identity']): result = m.observe_quiet(state, object())
        self.assertEqual(result['capture'], 'COLLECTOR_CONTINUITY_OBSERVED_SCOPED_ONLY')
        self.assertNotIn('native_acceptance', result)

    def test_actual_nonzero_command_does_not_become_success(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = m.Commands(folder, time.monotonic() + 3)
            with self.assertRaises(ValueError): runner.call([sys.executable, '-c', 'raise SystemExit(7)'])
            receipt = json.loads(next(Path(folder).glob('command-*.json')).read_text())
            self.assertEqual(receipt['exit'], 7)

    def test_whole_deadline_refuses_before_child_spawn(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(m.subprocess, 'Popen', side_effect=AssertionError('spawned')):
            with self.assertRaises(ValueError): m.Commands(folder, time.monotonic() - 1).call(['/bin/true'])
            self.assertFalse(list(Path(folder).iterdir()))

    def test_independent_runners_keep_both_receipts(self):
        with tempfile.TemporaryDirectory() as folder:
            for _ in range(2): m.Commands(folder, time.monotonic() + 3).call([sys.executable, '-c', 'pass'])
            self.assertEqual(len(list(Path(folder).glob('command-*.json'))), 2)

    def test_actual_terminal_output_flood_is_failed_and_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = m.Commands(folder, time.monotonic() + 3)
            with self.assertRaises(ValueError):
                runner.call([sys.executable, '-c', 'import os; os.write(1,b"x"*2097152)'])
            receipt = json.loads(next(Path(folder).glob('command-*.json')).read_text())
            self.assertEqual(receipt['failure'], 'COMMAND_OUTPUT_BOUND')

    def test_missing_signed_helper_is_not_an_owner(self):
        state = self.state(); state['helper_pins'].pop('/usr/local/lib/aegis/aegis-wide-disable.sh')
        with self.assertRaises(ValueError): m.validate_owner(state)

    def timer_runner(self, state, value=None):
        class Observed:
            def props(inner, name):
                return {'ActiveState': 'active', 'InvocationID': 'd' * 32}
            def call(inner, argv):
                self.assertEqual(argv[:3], ['busctl', '--json=short', 'get-property'])
                self.assertEqual(argv[4], '/org/freedesktop/systemd1/unit/aegis_2dfw_2daccept_2dtrial1_2etimer')
                return json.dumps(value if value is not None else {'type': 't', 'data': state['deadline_unix'] * 1000000})
        return Observed()

    def test_typed_scalar_actual_timer_deadline_positive_model(self):
        state = self.state()
        with patch.object(m, 'check_units'), patch.object(m.time, 'time', return_value=state['deadline_unix'] - 200):
            result = m.timer_ready(state, self.timer_runner(state), 60)
        self.assertEqual(result['deadline_unix'], state['deadline_unix'])
        self.assertEqual(result['invocation'], 'd' * 32)

    def test_wrong_typed_timer_deadline_refuses_before_activation(self):
        state = self.state()
        for value in ({'type': 't', 'data': [state['deadline_unix'] * 1000000]},
                      {'type': 't', 'data': True}, {'type': 's', 'data': 'future'},
                      {'type': 't', 'data': state['deadline_unix'] * 1000000 + 1}):
            with self.subTest(value=value), patch.object(m, 'check_units'):
                with self.assertRaises(ValueError): m.timer_ready(state, self.timer_runner(state, value), 60)

    def test_correct_timer_epoch_without_remaining_cleanup_reserve_refuses(self):
        state = self.state()
        with patch.object(m, 'check_units'), patch.object(m.time, 'time', return_value=state['deadline_unix'] - 120):
            with self.assertRaises(ValueError): m.timer_ready(state, self.timer_runner(state), 60)

    def test_timer_invocation_changed_during_readback_refuses(self):
        state = self.state(); runner = self.timer_runner(state)
        runner.props = lambda name: {'ActiveState': 'active', 'InvocationID': 'd' * 32} if not getattr(runner, 'seen', False) else {'ActiveState': 'active', 'InvocationID': 'e' * 32}
        original_call = runner.call
        def call(argv):
            runner.seen = True
            return original_call(argv)
        runner.call = call
        with patch.object(m, 'check_units'), patch.object(m.time, 'time', return_value=state['deadline_unix'] - 200):
            with self.assertRaises(ValueError): m.timer_ready(state, runner, 60)

    def loaded_units_runner(self, state, foreign=None):
        class Loaded:
            def props(inner, name):
                value = {'LoadState': 'loaded', 'FragmentPath': str(m.UNITS / name), 'DropInPaths': ''}
                if name.endswith('.service'):
                    value['ExecStart'] = '{ path=' + state['python'] + ' ; argv[]=' + ' '.join([state['python'], state['controller'], 'recover-owned', '--state', str(m.BASE / state['run_id'] / 'state.json')]) + ' ; ignore_errors=no ; }'
                else:
                    value.update(Unit=name[:-6] + '.service', InvocationID='d' * 32)
                if foreign: foreign(name, value)
                return value
        return Loaded()

    def test_loaded_owned_commands_and_no_dropins_positive_model(self):
        with patch.object(m, 'check_pin'), patch.object(m.Path, 'exists', return_value=False):
            m.check_units(self.state(), self.loaded_units_runner(self.state()))

    def test_foreign_loaded_command_dropin_and_target_refuse(self):
        state = self.state()
        def extra(name, value):
            if name.endswith('.service'): value['ExecStart'] += ' { argv[]=/bin/true ; }'
        def dropin(name, value): value['DropInPaths'] = '/foreign.conf'
        def target(name, value):
            if name.endswith('.timer'): value['Unit'] = 'foreign.service'
        for foreign in (extra, dropin, target):
            with self.subTest(foreign=foreign.__name__), patch.object(m, 'check_pin'), patch.object(m.Path, 'exists', return_value=False):
                with self.assertRaises(ValueError): m.check_units(state, self.loaded_units_runner(state, foreign))

    def test_replaced_timer_invocation_refuses_owned_ready_receipt(self):
        state = self.state()
        ready = {'schema': 'aegis_fullwide_timer_ready_v1', 'source': state['source'], 'run_id': state['run_id'], 'boot_id': state['boot_id'], 'timer': 'aegis-fw-accept-trial1.timer', 'invocation': 'e' * 32, 'deadline_unix': state['deadline_unix']}
        with patch.object(m, 'check_pin'), patch.object(m.Path, 'exists', return_value=True), patch.object(m, 'private', return_value=json.dumps(ready).encode()):
            with self.assertRaises(ValueError): m.check_units(state, self.loaded_units_runner(state))

    def test_changed_boot_refuses_before_helper_or_unit_checks(self):
        state = self.state()
        with patch.object(m.Path, 'read_text', return_value='different-boot'), patch.object(m, 'check_pin', side_effect=AssertionError('touched helper')):
            with self.assertRaisesRegex(ValueError, 'reboot not supported'): m.owner_identity(state)

    def test_capture_loss_cannot_recover_to_success_after_observer_returns(self):
        state = self.state(); state['quiet_seconds'] = .02
        observations = [RuntimeError('first loss'), state['collector_identity']]
        with patch.object(m, 'capture_identity', side_effect=observations):
            result = m.observe_quiet(state, object())
        self.assertEqual(result['capture'], 'INCOMPLETE')
        self.assertEqual(result['collector_first_loss_type'], 'RuntimeError')

    def test_full_snapshot_header_known_public_endianness(self):
        import struct
        for magic, endian in ((b'\xd4\xc3\xb2\xa1', '<'), (b'\xa1\xb2\xc3\xd4', '>'), (b'\x4d\x3c\xb2\xa1', '<'), (b'\xa1\xb2\x3c\x4d', '>')):
            m.pcap_header(magic + struct.pack(endian + 'HHiiii', 2, 4, 0, 0, 262144, 1))

    def test_missing_or_truncated_collector_header_refuses(self):
        import struct
        for raw in (b'', b'\xd4\xc3\xb2\xa1', b'X' * 24, b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiiii', 2, 4, 0, 0, 1500, 1)):
            with self.subTest(raw_length=len(raw)), self.assertRaises(ValueError): m.pcap_header(raw)

    def test_collector_pins_distribution_path_and_loaded_argv(self):
        digest = 'a' * 64
        identity = {'pid': '123', 'start_ticks': '456', 'sha256': digest}
        class Collector:
            def __init__(self, path, drop=False): self.path, self.drop = path, drop
            def props(self, unit):
                return {'LoadState': 'loaded', 'ActiveState': 'active', 'InvocationID': 'b' * 32,
                        'DropInPaths': '', 'MainPID': '123',
                        'ExecStart': '{ path=' + self.path + ' ; argv[]=' + self.path +
                                     ' -i eth0 -s 0 -U ' + ('' if self.drop else '-Z root ') + '-w /root/capture.pcap ; ignore_errors=no ; }'}
        for path in ('/usr/sbin/tcpdump', '/usr/bin/tcpdump'):
            capture = {'unit': 'independent-capture.service', 'executable': path,
                       'sha256': digest, 'output': '/root/capture.pcap', 'invocation': 'b' * 32}
            with self.subTest(path=path), patch.object(m, 'check_pin'), patch.object(m, 'process_identity', return_value=identity), patch.object(m, 'collector_output', return_value={'output_device': 1, 'output_inode': 2}):
                self.assertEqual(m.capture_identity(capture, Collector(path), 'eth0')['pid'], '123')
                with self.assertRaises(ValueError):
                    m.capture_identity(dict(capture, executable='/bin/sh'), Collector('/bin/sh'), 'eth0')
                with self.assertRaises(ValueError):
                    m.capture_identity(capture, Collector('/bin/sh'), 'eth0')
                with self.assertRaises(ValueError):
                    m.capture_identity(capture, Collector(path, drop=True), 'eth0')

    def test_replaced_output_inode_stays_incomplete_full_interval(self):
        state = self.state(); state['quiet_seconds'] = .02
        foreign = dict(state['collector_identity'], output_inode=99)
        started = time.monotonic()
        with patch.object(m, 'capture_identity', return_value=foreign): result = m.observe_quiet(state, object())
        self.assertGreaterEqual(time.monotonic() - started, .02)
        self.assertEqual(result['capture'], 'INCOMPLETE')

    def recovery_flow_model(self, helper_fail=False, foreign_fragment=False, afterquiet_change=False):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); work = base / 'trial1'; work.mkdir()
            lock = work / 'recovery.lock'; lock.write_bytes(b''); lock.chmod(0o600)
            state = self.state(); state['controller'] = str(work / 'device_fullwide_acceptance.py')
            state['controller_dependencies'] = {str(work / n): 'c' * 64 for n in ('device_candidate_verify.py', 'device_candidate_acceptance.py')}
            state['native_network_sha256'] = m.digest(b'{}')
            modeled_properties = self.client_properties()
            state['baseline']['client_loaded'] = m.client_semantics(modeled_properties, state['client_unit_pins'])
            if foreign_fragment: modeled_properties['FragmentPath'] = '/run/systemd/system/aegis-client.service'
            calls = []
            class ModeledCommands:
                def __init__(inner, work, deadline): inner.deadline = deadline
                def props(inner, name): return dict(modeled_properties)
                def call(inner, argv, budget=10):
                    calls.append(list(map(str, argv)))
                    if argv[-1] == 'recover' and helper_fail: raise RuntimeError('modeled helper failure')
                    return '[]' if argv[0] == 'ip' else ''
            def inputs(path):
                return b'armed=0\n' if path == m.GUARD_STATE else json.dumps(state).encode()
            original_quiet = m.observe_quiet
            def shortened_clock(s, r):
                return original_quiet(dict(s, quiet_seconds=.02), r)
            observations = 0
            def owner_check(s):
                nonlocal observations
                observations += 1
                if afterquiet_change and observations == 3: raise ValueError('modeled changed ownership after quiet')
            # Native ownership/readback/helper adapters are modeled, never executed.
            with patch.object(m, 'BASE', base), patch.object(m, 'private', side_effect=inputs), patch.object(m, 'Commands', ModeledCommands), patch.object(m, 'check_units'), patch.object(m, 'owner_identity', side_effect=owner_check), patch.object(m.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100600, st_uid=0, st_nlink=1)), patch.object(m, 'capture_identity', side_effect=RuntimeError('modeled collector loss')), patch.object(m, 'observe_quiet', side_effect=shortened_clock), patch.object(m, 'bounded_native_model', return_value={}):
                result = m.recover(work / 'state.json')
            receipt = json.loads(next(work.glob('recovery-result-*.json')).read_text())
            self.assertEqual(receipt, result)
            self.assertEqual(result['capture'], 'INCOMPLETE')
            if foreign_fragment:
                self.assertEqual(calls, [])
                self.assertEqual(result['cleanup'], 'INCOMPLETE')
                return result
            self.assertGreaterEqual(result['quiet_end_unix'] - result['quiet_start_unix'], .02)
            self.assertEqual(calls[:2], [['/bin/bash', str(m.GUARD), 'block'], ['systemctl', 'stop', 'aegis-client.service']])
            if afterquiet_change:
                self.assertNotIn(['/bin/bash', str(m.GUARD), 'recover'], calls)
            else:
                self.assertIn(['/bin/bash', str(m.GUARD), 'recover'], calls)
            self.assertFalse(result['native_acceptance'])
            return result

    def test_recovery_model_keeps_capture_failure_alongside_successful_cleanup(self):
        result = self.recovery_flow_model()
        self.assertEqual(result['cleanup'], 'ORIGINAL_PROFILE_RECOVERED_SCOPED')

    def test_recovery_model_retains_helper_failure_and_failed_capture_separately(self):
        result = self.recovery_flow_model(helper_fail=True)
        self.assertEqual(result['cleanup'], 'INCOMPLETE')
        self.assertEqual(result['error_type'], 'RuntimeError')

    def client_properties(self, running=False):
        argv = ' '.join([str(m.CLIENT), '--config', str(m.CONFIG), '--runtime-events-jsonl', '/var/log/aegis-client/runtime-events.jsonl'])
        def command(path, arguments):
            return '{ path=' + path + ' ; argv[]=' + arguments + ' ; ignore_errors=no ; pid=0 ; start_time=0 ; status=0 ; }'
        return {'LoadState': 'loaded', 'FragmentPath': str(m.UNITS / 'aegis-client.service'),
            'Type': 'notify', 'User': 'root', 'NoNewPrivileges': 'yes', 'DropInPaths': '',
            'ExecStart': command(str(m.CLIENT), argv),
            'ExecStartPre': command('/bin/bash', '/bin/bash /usr/local/lib/aegis/aegis-device-egress-guard.sh bind'),
            'ExecStartPost': '', 'ExecStop': '',
            'ExecStopPost': command('/bin/bash', '/bin/bash /usr/local/lib/aegis/aegis-device-egress-guard.sh block'),
            'ActiveState': 'active' if running else 'inactive', 'MainPID': '42' if running else '0',
            'InvocationID': 'd' * 32 if running else ''}

    def client_model(self, state, properties):
        class Readback:
            def props(inner, name):
                self.assertEqual(name, 'aegis-client.service')
                return dict(properties)
        state['baseline']['client_loaded'] = m.client_semantics(self.client_properties(), state['client_unit_pins'])
        return Readback()

    def test_expected_loaded_lifecycle_is_kept_and_runtime_fields_not_semantics(self):
        properties = self.client_properties()
        before = m.client_semantics(properties, self.state()['client_unit_pins'])
        for key in m.CLIENT_EXEC: properties[key] = properties[key].replace('pid=0', 'pid=77').replace('status=0', 'status=9')
        self.assertEqual(before, m.client_semantics(properties, self.state()['client_unit_pins']))
        self.assertEqual(before['ExecStartPre'][0]['argv'], '/bin/bash /usr/local/lib/aegis/aegis-device-egress-guard.sh bind')
        self.assertEqual(before['ExecStopPost'][0]['argv'], '/bin/bash /usr/local/lib/aegis/aegis-device-egress-guard.sh block')

    def test_foreign_loaded_client_fragment_argv_run_dropin_and_lifecycle_refuse(self):
        cases = [('FragmentPath', '/run/systemd/system/aegis-client.service'),
                 ('DropInPaths', '/run/systemd/system/aegis-client.service.d/99-foreign.conf'),
                 ('ExecStart', self.client_properties()['ExecStart'].replace('--config', '--foreign')),
                 ('ExecStop', '{ path=/bin/true ; argv[]=/bin/true ; ignore_errors=no ; pid=0 ; }'),
                 ('ExecStopPost', self.client_properties()['ExecStopPost'] + ' { path=/bin/true ; argv[]=/bin/true ; ignore_errors=no ; pid=0 ; }')]
        for key, value in cases:
            state = self.state(); properties = self.client_properties(); runner = self.client_model(state, properties); properties[key] = value
            with self.subTest(key=key), patch.object(m.Path, 'exists', return_value=False), self.assertRaises(ValueError): m.check_client(state, runner)

    def test_initial_stopped_unit_needs_no_ready_process_binding(self):
        state = self.state(); properties = self.client_properties(); runner = self.client_model(state, properties)
        with patch.object(m.Path, 'exists', return_value=False), patch.object(m, 'process_identity', side_effect=AssertionError('process touched')):
            self.assertEqual(m.check_client(state, runner, terminal=True)['MainPID'], '0')

    def test_active_unbound_client_refuses_before_process_or_mutation(self):
        state = self.state(); properties = self.client_properties(True); runner = self.client_model(state, properties)
        with patch.object(m.Path, 'exists', return_value=False), patch.object(m, 'process_identity', side_effect=AssertionError('process touched')):
            with self.assertRaisesRegex(ValueError, 'unbound'): m.check_client(state, runner)

    def test_started_binding_is_exclusive_without_state_rewrite(self):
        state = self.state(); properties = self.client_properties(True); runner = self.client_model(state, properties)
        identity = {'pid': '42', 'start_ticks': '500', 'sha256': state['client_sha256']}
        before = json.dumps(state, sort_keys=True)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); (base / state['run_id']).mkdir()
            with patch.object(m, 'BASE', base), patch.object(m, 'process_identity', return_value=identity):
                ready = m.bind_started_client(state, runner)
                self.assertEqual(json.loads((base/state['run_id']/'client-ready.json').read_text()), ready)
                with self.assertRaises(FileExistsError): m.bind_started_client(state, runner)
            self.assertEqual(json.dumps(state, sort_keys=True), before)

    def test_replaced_active_client_process_birth_invocation_or_executable_refuses(self):
        for field, replacement in (('pid', '43'), ('start_ticks', '501'), ('sha256', 'e'*64), ('invocation', 'e'*32)):
            state = self.state(); properties = self.client_properties(True); runner = self.client_model(state, properties)
            identity = {'pid': '42', 'start_ticks': '500', 'sha256': state['client_sha256']}
            ready = m.client_receipt(state, properties, identity)
            ready[field] = replacement
            with self.subTest(field=field), patch.object(m.Path, 'exists', return_value=True), patch.object(m, 'private', return_value=json.dumps(ready).encode()), patch.object(m, 'process_identity', return_value=identity):
                with self.assertRaises(ValueError): m.check_client(state, runner)

    def test_started_owner_positive_binding_refuses_terminal_flag(self):
        state = self.state(); properties = self.client_properties(True); runner = self.client_model(state, properties)
        identity = {'pid': '42', 'start_ticks': '500', 'sha256': state['client_sha256']}; ready = m.client_receipt(state, properties, identity)
        with patch.object(m.Path, 'exists', return_value=True), patch.object(m, 'private', return_value=json.dumps(ready).encode()), patch.object(m, 'process_identity', return_value=identity):
            self.assertEqual(m.check_client(state, runner)['MainPID'], '42')
            with self.assertRaises(ValueError): m.check_client(state, runner, terminal=True)

    def test_loaded_client_readback_changes_refuse(self):
        state = self.state(); properties = self.client_properties(); runner = self.client_model(state, properties)
        foreign = dict(properties, InvocationID='e'*32)
        with patch.object(m.Path, 'exists', return_value=False), patch.object(runner, 'props', side_effect=[properties, foreign]):
            with self.assertRaises(ValueError): m.check_client(state, runner)

    def test_known_started_then_stopped_owner_preserves_empty_terminal_invocation(self):
        state = self.state(); running = self.client_properties(True); identity = {'pid': '42', 'start_ticks': '500', 'sha256': state['client_sha256']}
        ready = m.client_receipt(state, running, identity); terminal = self.client_properties(); runner = self.client_model(state, terminal)
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder); work=base/state['run_id']; work.mkdir(); (work/'client-ready.json').write_text(json.dumps(ready))
            def private_input(path): return Path(path).read_bytes()
            with patch.object(m, 'BASE', base), patch.object(m, 'private', side_effect=private_input):
                m.bind_stopped_client(state, runner)
                self.assertEqual(m.check_client(state, runner, terminal=True)['MainPID'], '0')
                terminal['InvocationID'] = 'e'*32
                with self.assertRaises(ValueError): m.check_client(state, runner, terminal=True)

    def test_recovery_model_foreign_loaded_client_refuses_before_any_mutation(self):
        result = self.recovery_flow_model(foreign_fragment=True)
        self.assertEqual(result['error_type'], 'ValueError')

    def test_recovery_model_changed_ownership_after_quiet_keeps_capture_and_refuses_release(self):
        result = self.recovery_flow_model(afterquiet_change=True)
        self.assertEqual(result['cleanup'], 'INCOMPLETE')
        self.assertEqual(result['error_type'], 'ValueError')

    def test_malformed_ready_owner_refuses_before_terminal_or_active_use(self):
        state = self.state(); properties = self.client_properties(True)
        ready = m.client_receipt(state, properties, {'pid': '42', 'start_ticks': '500', 'sha256': state['client_sha256']})
        for field, value in (('pid', '0'), ('start_ticks', 'unknown'), ('invocation', ''), ('source', 'e'*40), ('unit', 'ssh.service')):
            invalid = dict(ready, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError): m.validate_client_ready(state, invalid)

    def test_dropin_only_owner_without_main_client_file_pin_refuses(self):
        state = self.state(); state['client_unit_pins'] = {'/etc/systemd/system/aegis-client.service.d/30-device-egress-guard.conf': 'a'*64}
        with self.assertRaisesRegex(ValueError, 'main unit pin'): m.validate_owner(state)


if __name__ == '__main__':
    unittest.main(verbosity=2)
