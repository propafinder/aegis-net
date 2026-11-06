"""Real Linux flock tests for the monitor/Stop retirement reservation."""
import importlib.util
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import fcntl
from contextlib import ExitStack
from types import SimpleNamespace
from dataclasses import dataclass


ROOT = Path(__file__).resolve().parents[2]
MONITOR = ROOT / 'scripts/lib/aegis_auto_foreign_monitor.py'


def load_monitor():
    spec = importlib.util.spec_from_file_location('aegis_stop_reservation_monitor', MONITOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GUARDIAN_SPEC = importlib.util.spec_from_file_location(
    'aegis_stop_reservation_guardian', ROOT / 'scripts/lib/aegis_auto_guardian.py')
GUARDIAN = importlib.util.module_from_spec(GUARDIAN_SPEC)
GUARDIAN_SPEC.loader.exec_module(GUARDIAN)


def held_flock(fdinfo, identity):
    # Exercise the production inode-aware parser against actual kernel fdinfo.
    return GUARDIAN._exclusive_flock_fdinfo(fdinfo, identity)


def hold_in_child(path, pipe):
    descriptor = os.open(path, os.O_RDONLY)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    pipe.send(os.getpid())
    pipe.recv()
    os.close(descriptor)
    pipe.close()


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'root Linux /proc/locks fixture required')
class StopAssessmentReservation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.monitor = load_monitor()
        self.monitor.ASSESSMENT_LOCK = self.root / 'assessment.lock'
        self.monitor.ASSESSMENT_LOCK.touch(mode=0o600)
        self.monitor.LOCK = self.root / 'guard.lock'
        self.monitor.LOCK.touch(mode=0o600)
        # This cohort models an installed AUTO v2 lease. The state must live
        # under a trusted root-owned ancestry for production trusted_read().
        self.v2_state_root = tempfile.TemporaryDirectory(
            prefix='aegis-stop-v2-', dir='/run')
        self.addCleanup(self.v2_state_root.cleanup)
        self.monitor.STATE = Path(self.v2_state_root.name) / 'device-guard.conf'
        self.monitor.STATE.write_bytes(b'schema=aegis_device_guard_v2\n')
        self.monitor.STATE.chmod(0o600)
        self.actor = type('Actor', (), {'_exclusive_flock_fdinfo': staticmethod(held_flock)})()
        patcher = mock.patch.object(self.monitor, 'actor_module', return_value=self.actor)
        patcher.start()
        self.addCleanup(patcher.stop)

    def start_child_holder(self):
        parent, child = multiprocessing.get_context('fork').Pipe()
        process = multiprocessing.get_context('fork').Process(
            target=hold_in_child, args=(str(self.monitor.ASSESSMENT_LOCK), child))
        process.start()
        self.assertEqual(parent.recv(), process.pid)
        child.close()
        return parent, process

    def test_authenticated_holder_waits_then_fresh_independent_lock(self):
        pipe, process = self.start_child_holder()
        checked = []
        authenticated_seen = threading.Event()
        def authenticated(identity, deadline):
            rows = self.monitor._assessment_holder_rows(identity)
            if not rows:
                # The authenticated owner may finish after an earlier EBUSY.
                # Production retries a fresh independent flock in this case.
                self.assertTrue(checked)
                return False
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][4], str(process.pid))
            checked.append(True)
            authenticated_seen.set()
            return True
        def release():
            authenticated_seen.wait(timeout=1.0)
            time.sleep(0.20)
            pipe.send('release')
        thread = threading.Thread(target=release)
        thread.start()
        try:
            with mock.patch.object(self.monitor, '_authenticated_stopped_retirement_holder',
                                   side_effect=authenticated):
                started = time.monotonic()
                held = self.monitor._acquire_assessment_reservation()
                self.assertGreaterEqual(time.monotonic() - started, 0.15)
                self.assertTrue(checked)
                independent = os.open(self.monitor.ASSESSMENT_LOCK, os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(independent)
                os.close(held)
        finally:
            thread.join(timeout=2)
            process.join(timeout=2)
            pipe.close()
            self.assertFalse(process.is_alive())

    def test_unknown_holder_refuses_without_wait(self):
        pipe, process = self.start_child_holder()
        try:
            with mock.patch.object(self.monitor, '_authenticated_stopped_retirement_holder',
                                   side_effect=ValueError('unknown holder')):
                started = time.monotonic()
                with self.assertRaisesRegex(ValueError, 'unknown holder'):
                    self.monitor._acquire_assessment_reservation()
                self.assertLess(time.monotonic() - started, 1.0)
        finally:
            pipe.send('release')
            process.join(timeout=2)
            pipe.close()
            self.assertFalse(process.is_alive())

    def test_released_holder_is_not_promoted_to_authority(self):
        pipe, process = self.start_child_holder()
        checked = []
        def released_during_proof(identity, _deadline):
            self.assertEqual(self.monitor._assessment_holder_rows(identity)[0][4],
                             str(process.pid))
            pipe.send('release')
            process.join(timeout=2)
            self.assertFalse(process.is_alive())
            checked.append(True)
            return False
        try:
            with mock.patch.object(self.monitor, '_authenticated_stopped_retirement_holder',
                                   side_effect=released_during_proof):
                held = self.monitor._acquire_assessment_reservation()
            self.assertEqual(checked, [True])
            os.close(held)
        finally:
            if process.is_alive():
                pipe.send('release')
                process.join(timeout=2)
            pipe.close()

    def test_full_holder_proof_release_or_replacement_is_closed(self):
        """Real FLOCK rows disappear or change during exact PID1 holder proof."""
        for seam in ('identity_walk', 'post_deny', 'identity_walk_exit',
                     'post_deny_exit', 'identity_walk_dead', 'post_deny_dead',
                     'replacement', 'source_mismatch_empty'):
            with self.subTest(seam=seam):
                self._full_holder_release_case(seam)

    def _full_holder_release_case(self, seam):
        def release_but_live(path, pipe):
            fd = os.open(path, os.O_RDONLY)
            fcntl.flock(fd, fcntl.LOCK_EX)
            pipe.send(os.getpid())
            if not pipe.poll(2) or pipe.recv() != 'release':
                raise AssertionError('release command absent')
            os.close(fd)
            pipe.send('released')
            if seam in ('identity_walk_exit', 'post_deny_exit',
                        'identity_walk_dead', 'post_deny_dead'):
                pipe.close()
                return
            if not pipe.poll(2) or pipe.recv() != 'finish':
                raise AssertionError('finish command absent')
            pipe.close()
        def replacement_holder(path, pipe):
            fd = os.open(path, os.O_RDONLY)
            fcntl.flock(fd, fcntl.LOCK_EX)
            pipe.send(os.getpid())
            if not pipe.poll(2) or pipe.recv() != 'finish':
                raise AssertionError('replacement finish absent')
            os.close(fd)
            pipe.close()
        def receive(pipe):
            self.assertTrue(pipe.poll(2), 'bounded child reply absent')
            return pipe.recv()
        parent, child = multiprocessing.get_context('fork').Pipe()
        process = multiprocessing.get_context('fork').Process(
            target=release_but_live,
            args=(str(self.monitor.ASSESSMENT_LOCK), child))
        process.start()
        pid = receive(parent)
        self.assertEqual(pid, process.pid)
        child.close()
        replacement_pipe = None
        replacement_process = None
        descriptor = os.open(self.monitor.ASSESSMENT_LOCK, os.O_RDONLY)
        identity = self.monitor._assessment_identity(descriptor)
        os.close(descriptor)
        self.assertEqual(self.monitor._assessment_holder_rows(identity)[0][4], str(pid))
        boot = '22222222-2222-4222-8222-222222222222'
        invocation = 'a' * 32
        private = 'aegis-private-test.service'
        source = b'guardian source'
        unit_source = b'guardian unit'
        state_sha, policy_sha = 'b' * 64, 'c' * 64
        intent_path = self.root / 'stop-intent.json'
        intent_path.write_text(json.dumps({
            'schema':'aegis_auto_stop_intent_v1', 'boot_id':boot,
            'service':private, 'invocation_id':invocation,
            'phase':'deny_proven'}))
        actor = SimpleNamespace(
            STOP_INTENT=intent_path,
            PRIVATE=re.compile(r'aegis-private-[a-z]+\.service\Z'),
            _alive=lambda _fd: process.is_alive(),
            _exclusive_flock_fdinfo=held_flock)
        install = {'guardian_sha256':hashlib.sha256(source).hexdigest(),
                   'guardian_unit_sha256':hashlib.sha256(unit_source).hexdigest()}
        facts = {'MainPID':str(pid), 'ControlPID':'0', 'ActiveState':'active',
                 'InvocationID':'d'*32,
                 'ControlGroup':'/system.slice/aegis-auto-guardian.service'}
        original_read_text = Path.read_text
        original_read_bytes = Path.read_bytes
        original_stat = os.stat
        def read_text(path, *args, **kwargs):
            name = str(path)
            if name == '/proc/sys/kernel/random/boot_id': return boot
            if name == f'/proc/{pid}/cgroup':
                return '0::/system.slice/aegis-auto-guardian.service\n'
            if name == f'/proc/{pid}/status': return 'Uid:\t0\t0\t0\t0\n'
            return original_read_text(path, *args, **kwargs)
        def read_bytes(path, *args, **kwargs):
            if str(path) == f'/proc/{pid}/cmdline':
                return (b'/usr/bin/python3\0-I\0-B\0'
                        b'/usr/local/lib/aegis/helpers/lib/'
                        b'aegis_auto_guardian.py\0serve\0')
            return original_read_bytes(path, *args, **kwargs)
        def trusted(path, _bound):
            name = str(path)
            if name.endswith('auto-guardian-install.json'):
                return json.dumps(install).encode()
            if name.endswith('aegis_auto_guardian.py'):
                if seam == 'source_mismatch_empty':
                    release_first()
                    return b'changed guardian source'
                return source
            if name.endswith('aegis-auto-guardian.service'): return unit_source
            if path == intent_path: return original_read_bytes(intent_path)
            if name.endswith('auto-guardian-policy.json'):
                return json.dumps({'schema':'aegis_auto_guardian_policy_v1',
                                   'state_sha256':state_sha,
                                   'policy_sha256':policy_sha}).encode()
            raise AssertionError(name)
        def stat(path, *args, **kwargs):
            if str(path) in (f'/proc/{pid}/ns/net', '/proc/self/ns/net'):
                return SimpleNamespace(st_ino=123)
            return original_stat(path, *args, **kwargs)
        released = False
        facts_calls = 0
        def release_first():
            nonlocal released, replacement_pipe, replacement_process
            if seam == 'replacement':
                replacement_pipe, child_pipe = multiprocessing.get_context('fork').Pipe()
                replacement_process = multiprocessing.get_context('fork').Process(
                    target=replacement_holder,
                    args=(str(self.monitor.ASSESSMENT_LOCK), child_pipe))
                replacement_process.start()
                child_pipe.close()
            parent.send('release')
            self.assertEqual(receive(parent), 'released')
            released = True  # Set before any subsequent assertion or callback.
            if seam in ('identity_walk_exit', 'post_deny_exit',
                        'identity_walk_dead', 'post_deny_dead'):
                process.join(timeout=2)
                self.assertFalse(process.is_alive())
            else:
                self.assertTrue(process.is_alive())
            rows = self.monitor._assessment_holder_rows(identity)
            if seam == 'replacement':
                replacement_pid = receive(replacement_pipe)
                rows = self.monitor._assessment_holder_rows(identity)
                self.assertEqual(rows[0][4], str(replacement_pid))
            else:
                self.assertEqual(rows, [])
        def actor_facts(unit):
            nonlocal facts_calls
            if unit != 'aegis-auto-guardian.service':
                raise ValueError('not the PID1 holder')
            facts_calls += 1
            if seam in ('identity_walk', 'identity_walk_exit',
                        'identity_walk_dead') and facts_calls == 2:
                release_first()
                if seam == 'identity_walk_exit':
                    raise OSError('PID1 holder exited during identity walk')
            if seam == 'post_deny_exit' and released:
                raise OSError('PID1 holder exited after deny')
            return facts
        def semantic(_deadline):
            if seam in ('post_deny', 'post_deny_exit', 'post_deny_dead',
                        'replacement'):
                release_first()
            return state_sha, policy_sha
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(self.monitor, 'actor_module',
                                                      return_value=actor))
                stack.enter_context(mock.patch.object(self.monitor, 'trusted_read',
                                                      side_effect=trusted))
                stack.enter_context(mock.patch.object(self.monitor, '_actor_facts',
                                                      side_effect=actor_facts))
                stack.enter_context(mock.patch.object(self.monitor, '_witness_denied'))
                stack.enter_context(mock.patch.object(self.monitor,
                                   '_isolated_deny_policy_sha', side_effect=semantic))
                stack.enter_context(mock.patch.object(self.monitor, 'run',
                    return_value=(f'ActiveState=inactive\nMainPID=0\nControlPID=0\n'
                                  f'InvocationID={invocation}\n').encode()))
                stack.enter_context(mock.patch.object(Path, 'read_text', read_text))
                stack.enter_context(mock.patch.object(Path, 'read_bytes', read_bytes))
                stack.enter_context(mock.patch.object(self.monitor.os, 'stat',
                                                      side_effect=stat))
                stack.enter_context(mock.patch.object(self.monitor.os.path, 'samefile',
                                                      return_value=True))
                if seam == 'source_mismatch_empty':
                    with self.assertRaisesRegex(ValueError,
                            'assessment holder actor changed'):
                        self.monitor._authenticated_stopped_retirement_holder(
                            identity, time.monotonic()+5)
                elif seam == 'replacement':
                    with self.assertRaisesRegex(ValueError,
                            'assessment holder changed during deny'):
                        self.monitor._authenticated_stopped_retirement_holder(
                            identity, time.monotonic()+5)
                else:
                    self.assertFalse(self.monitor._authenticated_stopped_retirement_holder(
                        identity, time.monotonic()+5))
                    self.assertTrue(released)
                    held = self.monitor._acquire_assessment_reservation()
                    try:
                        self.assertTrue(held_flock(
                            Path(f'/proc/self/fdinfo/{held}').read_text(), identity))
                    finally:
                        os.close(held)
        finally:
            if replacement_process is not None:
                if replacement_process.is_alive():
                    replacement_pipe.send('finish')
                replacement_process.join(timeout=2)
                if replacement_process.is_alive():
                    replacement_process.terminate()
                    replacement_process.join(timeout=2)
                replacement_pipe.close()
            if process.is_alive():
                if not released:
                    parent.send('release')
                    self.assertEqual(receive(parent), 'released')
                if seam not in ('identity_walk_exit', 'post_deny_exit',
                                 'identity_walk_dead', 'post_deny_dead'):
                    parent.send('finish')
            process.join(timeout=2)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
            parent.close()
            self.assertFalse(process.is_alive())
            if replacement_process is not None:
                self.assertFalse(replacement_process.is_alive())

    def test_exact_holder_cannot_extend_absolute_wait(self):
        pipe, process = self.start_child_holder()
        try:
            with mock.patch.object(self.monitor, '_authenticated_stopped_retirement_holder',
                                   return_value=True), \
                 mock.patch.object(self.monitor, 'ASSESSMENT_STOP_WAIT', 0.05):
                started = time.monotonic()
                with self.assertRaisesRegex(ValueError, 'assessment wait elapsed'):
                    self.monitor._acquire_assessment_reservation()
                self.assertLess(time.monotonic() - started, 0.5)
        finally:
            pipe.send('release')
            process.join(timeout=2)
            pipe.close()
            self.assertFalse(process.is_alive())

    def test_real_foreign_lock_pid_cannot_claim_guardian_or_watchdog(self):
        pipe, process = self.start_child_holder()
        descriptor = os.open(self.monitor.ASSESSMENT_LOCK, os.O_RDONLY)
        try:
            identity = self.monitor._assessment_identity(descriptor)
            # The child truly owns the kernel lock, but is no PID1 source-pinned
            # guardian or watchdog. Never convert its busy inode into a wait.
            with mock.patch.object(self.monitor, 'trusted_read', return_value=b'{}'), \
                 mock.patch.object(self.monitor, '_actor_facts',
                                   side_effect=ValueError('no matching PID1 actor')):
                with self.assertRaisesRegex(ValueError, 'unknown assessment lock holder'):
                    self.monitor._authenticated_stopped_retirement_holder(
                        identity, time.monotonic() + 2)
        finally:
            os.close(descriptor)
            pipe.send('release')
            process.join(timeout=2)
            pipe.close()
            self.assertFalse(process.is_alive())

    def _active_guardian_capture_case(self, seam='wait'):
        """A receipt published under the sidecar never becomes a monitor snapshot."""
        pipe, process = self.start_child_holder()
        guardian_unit = 'aegis-auto-guardian.service'
        private = 'aegis-auto@' + 'a' * 64 + '.service'
        boot = '22222222-2222-4222-8222-222222222222'
        source, unit_source = b'guardian source', b'guardian unit'
        main_path = self.monitor.STATE.parent / 'device-guard.conf.main-binding'
        journal_path = self.root / 'journal'
        intent_path = self.root / 'absent-stop-intent'
        actor = SimpleNamespace(JOURNAL=journal_path,
            STOP_INTENT=intent_path,
            PRIVATE=re.compile(r'aegis-auto@[a-f0-9]{64}\.service\Z'),
            _alive=lambda _fd: True, _exclusive_flock_fdinfo=held_flock)
        installation = {
            'guardian_sha256': hashlib.sha256(source).hexdigest(),
            'guardian_unit_sha256': hashlib.sha256(unit_source).hexdigest(),
        }
        facts = {'MainPID': str(process.pid), 'ControlPID': '0',
                 'ActiveState': 'active', 'InvocationID': 'd' * 32,
                 'ControlGroup': '/system.slice/' + guardian_unit}
        main = {'schema': 'aegis_device_guard_main_binding_v1',
                'boot_id': boot, 'netns_ino': 123, 'private_unit': private,
                'worker_sha256': 'f' * 64, 'stage_dev': 1, 'stage_ino': 2}
        original_text, original_bytes, original_stat = (
            Path.read_text, Path.read_bytes, os.stat)
        def read_text(path, *args, **kwargs):
            name = str(path)
            if name == '/proc/sys/kernel/random/boot_id': return boot
            if name == f'/proc/{process.pid}/cgroup':
                return '0::/system.slice/' + guardian_unit + '\n'
            if name == f'/proc/{process.pid}/status': return 'Uid:\t0\t0\t0\t0\n'
            return original_text(path, *args, **kwargs)
        def read_bytes(path, *args, **kwargs):
            if str(path) == f'/proc/{process.pid}/cmdline':
                return (b'/usr/bin/python3\0-I\0-B\0'
                        b'/usr/local/lib/aegis/helpers/lib/'
                        b'aegis_auto_guardian.py\0serve\0')
            return original_bytes(path, *args, **kwargs)
        def trusted(path, _bound):
            name = str(path)
            if name.endswith('auto-guardian-install.json'):
                return json.dumps(installation).encode()
            if name.endswith('aegis_auto_guardian.py'): return source
            if name.endswith('aegis-auto-guardian.service'): return unit_source
            if path == main_path: return json.dumps(main).encode()
            if path == journal_path:
                return json.dumps({'schema':'aegis_auto_watchdog_pending_v1',
                    'boot_id':boot,'phase':'LATCHED',
                    'private_unit':private,'stage_dev':1,'stage_ino':2,
                    'invocation_id':'e' * 32}).encode()
            raise AssertionError(name)
        def stat(path, *args, **kwargs):
            if str(path) in (f'/proc/{process.pid}/ns/net', '/proc/self/ns/net'):
                return SimpleNamespace(st_ino=123)
            return original_stat(path, *args, **kwargs)
        private_facts = (f'ActiveState=active\nSubState=running\nMainPID=42\n'
                         'ControlPID=0\nInvocationID=' + 'e' * 32 + '\n').encode()
        acquired = threading.Event()
        observations = []
        replacements = []
        actor_reads = [0]
        def actor_facts(unit):
            if unit != guardian_unit:raise ValueError('not holder')
            actor_reads[0] += 1
            if seam == 'actor_changed' and actor_reads[0] == 3:
                return dict(facts, InvocationID='f' * 32)
            return facts
        def private_query(*args):
            if seam in ('release_final', 'replace_final'):
                # Real kernel release happens AFTER the entry/intermediate
                # holder walks, precisely at the last PID1 read before595.
                pipe.send('release')
                process.join(timeout=2)
                self.assertFalse(process.is_alive())
                if seam == 'replace_final':
                    replacement_pipe,replacement_process=self.start_child_holder()
                    replacements.append((replacement_pipe,replacement_process))
            return private_facts
        def assess_after_lock():
            try:
                fd = self.monitor._acquire_assessment_reservation()
                try:
                    observations.append('receipt-and-kernel-sealed')
                    acquired.set()
                finally: os.close(fd)
            except BaseException as error: observations.append(error)
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(self.monitor, 'actor_module', return_value=actor))
                stack.enter_context(mock.patch.object(self.monitor, 'trusted_read', side_effect=trusted))
                stack.enter_context(mock.patch.object(self.monitor, '_actor_facts',
                    side_effect=actor_facts))
                stack.enter_context(mock.patch.object(self.monitor, 'state',
                                                      return_value=(b'', {'armed':'1'})))
                stack.enter_context(mock.patch.object(self.monitor, 'run',
                                                      side_effect=private_query))
                stack.enter_context(mock.patch.object(self.monitor.os, 'pidfd_open',
                    side_effect=lambda *_: os.open('/dev/null', os.O_RDONLY)))
                stack.enter_context(mock.patch.object(Path, 'read_text', read_text))
                stack.enter_context(mock.patch.object(Path, 'read_bytes', read_bytes))
                stack.enter_context(mock.patch.object(self.monitor.os, 'stat', side_effect=stat))
                stack.enter_context(mock.patch.object(self.monitor.os.path, 'samefile', return_value=True))
                if seam == 'wait':
                    thread = threading.Thread(target=assess_after_lock, daemon=True)
                    thread.start()
                    self.assertFalse(acquired.wait(timeout=0.10),
                                     'monitor observed receipt before kernel/seal transition')
                    pipe.send('release')
                    process.join(timeout=2)
                    thread.join(timeout=2)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(observations, ['receipt-and-kernel-sealed'])
                else:
                    identity_fd=os.open(self.monitor.ASSESSMENT_LOCK,os.O_RDONLY)
                    try:identity=self.monitor._assessment_identity(identity_fd)
                    finally:os.close(identity_fd)
                    # Use a separate fresh descriptor below, so this fixture
                    # never borrows the child's original open-file description.
                    if seam == 'release_final':
                        self.assertFalse(self.monitor._authenticated_stopped_retirement_holder(
                            identity,time.monotonic()+2))
                        self.assertFalse(self.monitor._assessment_holder_rows(identity))
                        descriptor=self.monitor._acquire_assessment_reservation()
                        try:
                            self.assertTrue(held_flock(Path('/proc/self/fdinfo/'+str(descriptor)).read_text(),identity))
                            self.assertEqual(self.monitor._assessment_holder_rows(identity)[0][4],str(os.getpid()))
                            observations.append('fresh-owned-lock-before-full-assessment')
                        finally:os.close(descriptor)
                        self.assertEqual(observations,['fresh-owned-lock-before-full-assessment'])
                    else:
                        with self.assertRaisesRegex(ValueError,'assessment active guardian holder changed'):
                            self.monitor._authenticated_stopped_retirement_holder(
                                identity,time.monotonic()+2)
                        self.assertTrue(self.monitor._assessment_holder_rows(identity))
        finally:
            if process.is_alive():
                pipe.send('release')
                process.join(timeout=2)
            pipe.close()
            for replacement_pipe,replacement_process in replacements:
                if replacement_process.is_alive():
                    replacement_pipe.send('release')
                    replacement_process.join(timeout=2)
                replacement_pipe.close()
                self.assertFalse(replacement_process.is_alive())

    def test_active_guardian_capture_transition_waits_for_complete_snapshot(self):
        self._active_guardian_capture_case()

    def test_active_guardian_release_at_final_read_requires_fresh_owned_lock(self):
        self._active_guardian_capture_case('release_final')

    def test_active_guardian_replacement_at_final_read_remains_refused(self):
        self._active_guardian_capture_case('replace_final')

    def test_active_guardian_actor_change_with_lock_still_held_remains_refused(self):
        self._active_guardian_capture_case('actor_changed')

    def test_watchdog_holder_boot_binding_and_source_are_required(self):
        """Exercise the full holder predicate after PID1/process evidence is supplied."""
        boot = '22222222-2222-4222-8222-222222222222'
        old_boot = '11111111-1111-4111-8111-111111111111'
        old_invocation = 'a' * 32
        new_invocation = 'b' * 32
        unit = 'aegis-private-test.service'
        pid = os.getpid()
        source = b'watchdog source'
        unit_source = b'watchdog unit'
        policy_sha = 'c' * 64
        state_sha = 'e' * 64
        journal_path = self.root / 'journal.json'
        intent_path = self.root / 'intent.json'
        actor = SimpleNamespace(
            STOP_INTENT=intent_path, JOURNAL=journal_path,
            PRIVATE=re.compile(r'aegis-private-[a-z]+\.service\Z'),
            _alive=lambda _fd: True,
        )
        installation = {
            'watchdog_sha256': hashlib.sha256(source).hexdigest(),
            'watchdog_unit_sha256': hashlib.sha256(unit_source).hexdigest(),
        }
        identity = os.stat(self.monitor.ASSESSMENT_LOCK)
        rows = [['1:', 'FLOCK', 'ADVISORY', 'WRITE', str(pid),
                 '00:00:1', '0', 'EOF']]
        facts = {'MainPID': str(pid), 'ControlPID': '0', 'ActiveState': 'active',
                 'InvocationID': 'd' * 32,
                 'ControlGroup': '/system.slice/aegis-auto-guardian-watchdog.service'}
        original_read_text = Path.read_text
        original_read_bytes = Path.read_bytes
        original_stat = os.stat
        def read_text(path, *args, **kwargs):
            text = str(path)
            if text == '/proc/sys/kernel/random/boot_id': return boot
            if text == f'/proc/{pid}/cgroup':
                return '0::/system.slice/aegis-auto-guardian-watchdog.service\n'
            if text == f'/proc/{pid}/status': return 'Uid:\t0\t0\t0\t0\n'
            return original_read_text(path, *args, **kwargs)
        def read_bytes(path, *args, **kwargs):
            if str(path) == f'/proc/{pid}/cmdline':
                return (b'/usr/bin/python3\0-I\0-B\0'
                        b'/usr/local/lib/aegis/helpers/lib/'
                        b'aegis_auto_guardian_watchdog.py\0serve\0')
            return original_read_bytes(path, *args, **kwargs)
        def trusted(path, _bound):
            name = str(path)
            if name.endswith('auto-guardian-install.json'):
                return json.dumps(installation).encode()
            if name.endswith('aegis_auto_guardian_watchdog.py'):
                return source
            if name.endswith('aegis-auto-guardian-watchdog.service'):
                return unit_source
            if path == journal_path: return original_read_bytes(journal_path)
            if path == intent_path: return original_read_bytes(intent_path)
            if name.endswith('auto-guardian-policy.json'):
                return json.dumps({'schema':'aegis_auto_guardian_policy_v1',
                                   'state_sha256':state_sha,
                                   'policy_sha256':policy_sha}).encode()
            raise AssertionError(name)
        def stat(path, *args, **kwargs):
            if str(path) in (f'/proc/{pid}/ns/net', '/proc/self/ns/net'):
                return SimpleNamespace(st_ino=123)
            return original_stat(path, *args, **kwargs)
        def verify(journal, intent, invocation='', source_bytes=source):
            journal_path.write_text(json.dumps(journal))
            if intent is None: intent_path.unlink(missing_ok=True)
            else: intent_path.write_text(json.dumps(intent))
            def trust(path, bound):
                if str(path).endswith('aegis_auto_guardian_watchdog.py'):
                    return source_bytes
                return trusted(path, bound)
            payload = (f'ActiveState=inactive\nMainPID=0\nControlPID=0\n'
                       f'InvocationID={invocation}\n').encode()
            def actor_facts(name):
                if name == 'aegis-auto-guardian-watchdog.service': return facts
                raise ValueError('not the PID1 holder')
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(self.monitor, 'actor_module', return_value=actor))
                stack.enter_context(mock.patch.object(self.monitor, 'trusted_read', side_effect=trust))
                stack.enter_context(mock.patch.object(self.monitor, '_actor_facts',
                            side_effect=actor_facts))
                stack.enter_context(mock.patch.object(self.monitor, '_assessment_holder_rows', return_value=rows))
                stack.enter_context(mock.patch.object(self.monitor, '_witness_denied'))
                stack.enter_context(mock.patch.object(self.monitor, '_isolated_deny_policy_sha',
                            return_value=(state_sha, policy_sha)))
                stack.enter_context(mock.patch.object(self.monitor, 'run', return_value=payload))
                stack.enter_context(mock.patch.object(self.monitor.os, 'pidfd_open',
                            side_effect=lambda *_: os.open('/dev/null', os.O_RDONLY)))
                stack.enter_context(mock.patch.object(Path, 'read_text', read_text))
                stack.enter_context(mock.patch.object(Path, 'read_bytes', read_bytes))
                stack.enter_context(mock.patch.object(self.monitor.os, 'stat', side_effect=stat))
                stack.enter_context(mock.patch.object(self.monitor.os.path, 'samefile', return_value=True))
                return self.monitor._authenticated_stopped_retirement_holder(
                    identity, time.monotonic() + 5)
        old_journal = {'schema':'aegis_auto_watchdog_pending_v1',
                       'private_unit':unit, 'phase':'RECOVERING_AFTER_REBOOT',
                       'boot_id':old_boot, 'recovery_boot_id':boot,
                       'invocation_id':old_invocation, 'stage_dev':12, 'stage_ino':34}
        old_intent = {'schema':'aegis_auto_stop_intent_v1',
                      'boot_id':old_boot, 'service':unit,
                      'invocation_id':old_invocation, 'phase':'pending_deny'}
        self.assertTrue(verify(old_journal, old_intent))
        current_intent = {**old_intent, 'boot_id':boot,
                          'invocation_id':new_invocation, 'phase':'deny_proven'}
        self.assertTrue(verify(old_journal, current_intent, new_invocation))
        with self.assertRaises(ValueError):
            verify(old_journal, {**current_intent, 'phase':'pending_deny'}, new_invocation)
        with self.assertRaises(ValueError):
            verify({**old_journal, 'recovery_boot_id':old_boot}, old_intent)
        with self.assertRaises(ValueError):
            verify(old_journal, old_intent, source_bytes=b'changed source')

    def test_reservation_survives_original_guard_owner_exit_revalidation(self):
        original = os.open(self.monitor.LOCK, os.O_RDONLY)
        fcntl.flock(original, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pidfd = os.open('/dev/null', os.O_RDONLY)
        context = {'actor_pidfd': pidfd, 'actor_unit': 'aegis-auto-guardian.service',
                   'actor_facts': {'MainPID': '123'}, 'transient': False}
        def borrow():
            return os.dup(original), context
        def on_exit(_actor, _context, _after, _guard_fd):
            independent = os.open(self.monitor.ASSESSMENT_LOCK, os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(independent)
        try:
            with mock.patch.object(self.monitor, 'borrow_actor_guard', side_effect=borrow), \
                 mock.patch.object(self.monitor, '_actor_facts', return_value={'MainPID': '123'}), \
                 mock.patch.object(self.monitor, '_borrowed_actor_stable', side_effect=on_exit):
                with self.monitor.guard_lock(reserve_assessment=True):
                    pass
            independent = os.open(self.monitor.ASSESSMENT_LOCK, os.O_RDONLY)
            try:
                fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(independent)
        finally:
            os.close(original)


    def test_compensated_post_deny_retirement_serializes_both_writes(self):
        """Use real kernel FLOCKs; exercise the production inverse body."""
        @dataclass
        class Absent:
            admitted: bool = True

        projection = b'[]'
        policy_sha = hashlib.sha256(projection).hexdigest()
        private = 'aegis-auto@' + 'a' * 64 + '.service'
        original = {'mode':'wide-redirect-safe','private_unit':private,
                    'boot_id':'22222222-2222-4222-8222-222222222222',
                    'netns_ino':123}
        grant = {'policy_sha256':policy_sha}
        stage = self.root/'stage'
        stage.mkdir()
        stage_fd = os.open(stage, os.O_RDONLY|os.O_DIRECTORY)
        self.addCleanup(os.close,stage_fd)
        guard_fd = os.open(self.monitor.LOCK, os.O_RDONLY)
        self.addCleanup(os.close,guard_fd)
        fcntl.flock(guard_fd, fcntl.LOCK_EX)
        witnessed = []

        def assert_exclusive_owners(label):
            for path in (self.monitor.LOCK,self.monitor.ASSESSMENT_LOCK):
                contender = os.open(path, os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:
                    os.close(contender)
            witnessed.append(label)
            if label == 'local' and error_on_local:
                raise GUARDIAN.Refused('local_retirement_test_refusal')

        def effect_packet():
            return {'schema':'aegis_auto_effect_v1','command':'COMPENSATED_STOP',
                    'guardian_nonce':'b'*64,'mode':'wide-redirect-safe',
                    'private_unit':private,'boot_id':original['boot_id'],
                    'netns_ino':123,'stage_dev':os.fstat(stage_fd).st_dev,
                    'stage_ino':os.fstat(stage_fd).st_ino,
                    'policy_sha256':policy_sha,'native_receipt_sha256':'c'*64,
                    'prior_invocation_id':'d'*32,'stop_job_id':1,
                    'stop_job_path':'/org/freedesktop/systemd1/job/1',
                    'stop_unit':private,'native_capture_sha256':None}

        witness = SimpleNamespace(snapshot_policy=lambda _path:
                                  (projection,{'output':1},{}))
        capture = SimpleNamespace(capture_absent_after_stop=lambda **_kw:Absent())
        def module(path, _name):
            if path == GUARDIAN.WITNESS:return witness
            if path == GUARDIAN.CAPTURE_SOURCE:return capture
            raise AssertionError('unexpected module')
        stop_intent = {'schema':'aegis_auto_stop_intent_v1',
                       'boot_id':original['boot_id'],
                       'invocation_id':'d'*32,'service':private,
                       'phase':'deny_proven'}
        original_reserve = GUARDIAN._stop_assessment_reservation
        for error_on_local in (False,True):
            reserve_entered = threading.Event()
            def reserve(fd):
                reserve_entered.set()
                return original_reserve(fd)
            pipe, holder = self.start_child_holder()
            workers=[]
            def cleanup_child(pipe=pipe,holder=holder,workers=workers):
                try:pipe.send('release')
                except (OSError,ValueError):pass
                holder.join(timeout=2)
                if holder.is_alive():
                    holder.terminate();holder.join(timeout=2)
                pipe.close()
                for thread in workers:thread.join(timeout=35)
            self.addCleanup(cleanup_child)
            witnessed.clear()
            outcome=[]
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(GUARDIAN,'GUARD_LOCK',self.monitor.LOCK))
                stack.enter_context(mock.patch.object(GUARDIAN,'ASSESSMENT_LOCK',
                                                      self.monitor.ASSESSMENT_LOCK))
                stack.enter_context(mock.patch.object(GUARDIAN,'_stopped_monitor_owner',
                                                      return_value=True))
                stack.enter_context(mock.patch.object(GUARDIAN,
                                                      '_stop_assessment_reservation',
                                                      side_effect=reserve))
                stack.enter_context(mock.patch.object(GUARDIAN,'_inverse_stage_successor'))
                stack.enter_context(mock.patch.object(GUARDIAN,'record',return_value=stop_intent))
                stack.enter_context(mock.patch.object(GUARDIAN,'_policy',
                                                      return_value={'policy_sha256':policy_sha}))
                stack.enter_context(mock.patch.object(GUARDIAN,'_semantic_policy_snapshot',
                                                      return_value=(projection,{'output':1},{})))
                stack.enter_context(mock.patch.object(GUARDIAN,'verified_module',side_effect=module))
                stack.enter_context(mock.patch.object(GUARDIAN,'_no_client_grant',return_value=True))
                stack.enter_context(mock.patch.object(GUARDIAN,'_scoped_retire_after_stop',
                          side_effect=lambda *_:assert_exclusive_owners('scoped')))
                stack.enter_context(mock.patch.object(GUARDIAN,'_local_retire_after_stop',
                          side_effect=lambda *_:assert_exclusive_owners('local')))
                def invoke():
                    try:outcome.append(GUARDIAN._post_stop_inverse(
                        effect_packet(),original,grant,guard_fd,stage_fd,None))
                    except BaseException as exc:outcome.append(exc)
                worker=threading.Thread(target=invoke,daemon=True)
                workers.append(worker)
                worker.start()
                self.assertTrue(reserve_entered.wait(timeout=2),
                                'inverse did not enter assessment reservation')
                time.sleep(0.05)
                self.assertEqual(witnessed,[], 'writer crossed held monitor snapshot')
                pipe.send('release')
                holder.join(timeout=2)
                self.assertFalse(holder.is_alive())
                pipe.close()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(witnessed,['scoped','local'])
                if error_on_local:
                    self.assertIsInstance(outcome[0],GUARDIAN.Refused)
                else:
                    self.assertEqual(outcome[0]['schema'],'aegis_auto_capture_inverse_v1')
                independent = os.open(self.monitor.ASSESSMENT_LOCK,os.O_RDONLY)
                try:fcntl.flock(independent,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(independent)
                guard_probe = os.open(self.monitor.LOCK,os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(guard_probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(guard_probe)


if __name__ == '__main__':
    unittest.main()
