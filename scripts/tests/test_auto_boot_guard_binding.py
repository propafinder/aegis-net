"""Boot guard lineage, FD admission and original guardian OFD lifetime regressions."""
import copy
import array
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import signal
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]  # correct after copy into scripts/tests
SOURCE = ROOT / 'scripts/lib/aegis_auto_guardian.py'
spec = importlib.util.spec_from_file_location('boot_guardian', SOURCE)
guardian = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guardian)


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class BootGuardBinding(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(guardian, '_boot_guard_binding'),
                        'integrated boot guard binding API absent')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.control = Path(self.temp.name)
        self.report = {
            'schema': 'aegis_auto_active_stage_inspection_v1',
            'stage': {'mode': 'full-wide-tun', 'phase': 'finalized',
                      'path': '/run/aegis-installer-config-snapshots/old-absent-stage'},
            'terminal': {'boot_id': 'old-boot', 'outcome': 'finalized',
                         'private_unit': 'aegis-auto@' + 'e' * 64 + '.service',
                         'invocation_id': 'f' * 32},
            'input': {'candidate_sha256': 'c' * 64},
            'current_fixed': {'roles': []},
        }
        self.report_sha = sha(packed(self.report))
        self.snapshot = {
            'schema': 'aegis_auto_v2_boot_snapshot_v1',
            'active_report_sha256': self.report_sha,
            'predecessor_boot_id': 'old-boot',
            'source': self.report['input'],
            'current_fixed': self.report['current_fixed'],
        }
        self.snapshot_raw = packed(self.snapshot)
        self.snapshot_sha = sha(self.snapshot_raw)
        self.active = {
            'schema': 'aegis_auto_v2_generation_v1',
            'boot_snapshot_sha256': self.snapshot_sha,
            'report_sha256': self.report_sha,
            'report': self.report,
        }
        self.request = {
            'boot_snapshot_sha256': self.snapshot_sha,
            'active_report_sha256': self.report_sha,
            'predecessor_boot_id': 'old-boot',
            'boot_id': 'new-boot',
            'candidate_sha256': 'c' * 64,
            'private_unit': 'aegis-auto@' + 'e' * 64 + '.service',
            'prior_invocation_id': 'f' * 32,
        }

    def bind(self, *, snapshot=None, active=None, request=None):
        snapshot = self.snapshot if snapshot is None else snapshot
        active = self.active if active is None else active
        request = self.request if request is None else request
        source = {
            'snapshot-' + request['boot_snapshot_sha256'] + '.json': packed(snapshot),
            'generation.json': packed(active),
        }
        def protected(path, _maximum):
            return source[path.name]
        with mock.patch.object(guardian, 'BOOT_CONTROL', self.control), \
             mock.patch.object(guardian, '_boot_protected_file', side_effect=protected):
            return guardian._boot_guard_binding(request)

    def test_valid_durable_lineage(self):
        self.assertEqual(self.bind(), (self.snapshot_sha, sha(packed(self.active))))

    def test_snapshot_modified_after_hash_refused(self):
        changed = copy.deepcopy(self.snapshot)
        changed['source']['candidate_sha256'] = 'd' * 64
        with self.assertRaisesRegex(guardian.Refused, 'boot_guard_snapshot_changed'):
            self.bind(snapshot=changed)

    def test_active_report_digest_refused(self):
        changed = copy.deepcopy(self.active)
        changed['report']['stage']['phase'] = 'pending'
        with self.assertRaisesRegex(guardian.Refused, 'boot_guard_report_changed'):
            self.bind(active=changed)

    def test_active_report_source_refused(self):
        changed = copy.deepcopy(self.active)
        changed['report']['input']['candidate_sha256'] = 'd' * 64
        with self.assertRaisesRegex(guardian.Refused, 'boot_guard_report_changed'):
            self.bind(active=changed)

    def test_predecessor_equal_current_refused(self):
        changed = dict(self.request, boot_id='old-boot')
        with self.assertRaisesRegex(guardian.Refused, 'boot_guard_report_changed'):
            self.bind(request=changed)

    def test_private_unit_mismatch_refused(self):
        changed = dict(self.request, private_unit='aegis-auto@'+'0'*64+'.service')
        with self.assertRaisesRegex(guardian.Refused, 'boot_guard_report_changed'):
            self.bind(request=changed)

    def test_prior_invocation_mismatch_refused(self):
        changed = dict(self.request, prior_invocation_id='0'*32)
        with self.assertRaisesRegex(guardian.Refused, 'boot_guard_report_changed'):
            self.bind(request=changed)

    def test_old_stage_still_present_refused(self):
        original = guardian.Path.exists
        def exists(path):
            if str(path) == '/run/aegis-installer-config-snapshots/old-absent-stage':
                return True
            return original(path)
        with mock.patch.object(guardian.Path, 'exists', exists):
            with self.assertRaisesRegex(guardian.Refused, 'boot_guard_old_stage_present'):
                self.bind()


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'requires Linux root for real flock FD identity')
class BootGuardFdAdmission(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(guardian.Guardian, '_boot_guard_session'),
                        'integrated boot guard session API absent')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.install = Path(self.temp.name) / 'install.lock'
        self.install.write_bytes(b'')
        self.install.chmod(0o600)
        self.valid_fd = os.open(self.install, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(self.valid_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(os.close, self.valid_fd)
        self.guard = Path(self.temp.name) / 'device-guard.conf.lock'
        self.guard.write_bytes(b'')
        self.guard.chmod(0o600)
        self.request = {
            'schema': 'aegis_auto_guardian_boot_guard_v1',
            'command': 'SEAL_BOOT_GUARD',
            'actor_challenge': 'a' * 64,
            'boot_id': 'new-boot', 'netns_ino': 42,
            'boot_snapshot_sha256': 'b' * 64,
            'active_report_sha256': 'c' * 64,
            'predecessor_boot_id': 'old-boot',
            'candidate_sha256': 'd' * 64,
            'private_unit': 'aegis-auto@' + 'e' * 64 + '.service',
            'prior_invocation_id': 'f' * 32,
        }

    def session(self, fds, error):
        actor = guardian.Guardian()
        peer = mock.Mock()
        with mock.patch.object(guardian, 'own_source'), \
             mock.patch.object(guardian, 'host_anchor',
                               return_value={'boot_id':'new-boot','netns_ino':42}), \
             mock.patch.object(guardian, '_peer_executable'), \
             mock.patch.object(guardian, '_pid_alive', return_value=True), \
             mock.patch.object(guardian, 'INSTALL_LOCK', self.install), \
             mock.patch.object(guardian, '_boot_guard_binding',
                               return_value=('b'*64,'e'*64)) as lineage, \
             mock.patch.object(guardian, '_stopped_guard_claim') as claim:
            with self.assertRaisesRegex(guardian.Refused, error):
                actor._boot_guard_session(peer, os.getpid(), -1, self.request,
                                          fds, {'worker_sha256':'d'*64},
                                          {'InvocationID':'f'*32})
            claim.assert_not_called()
            lineage.assert_not_called()
            peer.sendmsg.assert_not_called()

    def test_forged_install_inode_refuses_before_lineage_and_claim(self):
        forged = Path(self.temp.name) / 'forged.lock'
        forged.write_bytes(b''); forged.chmod(0o600)
        fd = os.open(forged, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            self.session((fd,), 'held_lock_changed')
        finally:
            os.close(fd)

    def test_unlocked_install_fd_refuses_before_lineage_and_claim(self):
        fd = os.open(self.install, os.O_RDWR | os.O_NOFOLLOW)
        try:
            self.session((fd,), 'exclusive_flock_not_held')
        finally:
            os.close(fd)

    def test_extra_fd_refuses_before_lineage_and_claim(self):
        self.session((self.valid_fd, self.valid_fd), 'boot_guard_request_invalid')

    def test_pending_recovery_journal_refuses_until_archived(self):
        stop = Path(self.temp.name) / 'stop-intent.json'
        watchdog = Path(self.temp.name) / 'watchdog-pending.json'
        with mock.patch.object(guardian, 'STOP_INTENT', stop), \
             mock.patch.object(guardian, 'WATCHDOG_PENDING', watchdog):
            guardian._boot_pending_absent()
            for pending in (stop, watchdog):
                pending.write_text('{}')
                with self.assertRaisesRegex(guardian.Refused,
                                            'boot_pending_recovery_present'):
                    guardian._boot_pending_absent()
                pending.unlink()
            guardian._boot_pending_absent()

    def test_full_boot_session_keeps_original_ofd_until_eof(self):
        """Real SCM_RIGHTS, child peer, independent contender and boot ACK."""
        rpc_server, rpc_client = socket.socketpair(socket.AF_UNIX,
                                                     socket.SOCK_SEQPACKET)
        ctl_parent, ctl_child = socket.socketpair(socket.AF_UNIX,
                                                   socket.SOCK_SEQPACKET)
        child_pid = os.fork()
        if child_pid == 0:
            signal.alarm(12)
            rpc_server.close(); ctl_parent.close()
            os.close(self.valid_fd)
            try:
                raw, ancillary, _, _ = rpc_client.recvmsg(4096,
                                                          socket.CMSG_SPACE(4))
                fds = array.array('i')
                for level, kind, payload in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        fds.frombytes(payload[:len(payload) - len(payload) % fds.itemsize])
                if len(fds) != 1: os._exit(11)
                guard_fd = fds[0]
                held = json.loads(raw)
                if held['schema'] != 'aegis_auto_guardian_boot_guard_held_v1':
                    os._exit(12)
                ctl_child.sendall(b'HELD')
                if ctl_child.recv(32) != b'COMPLETE': os._exit(13)
                rpc_client.sendall(packed({
                    'schema':'aegis_auto_guardian_boot_guard_complete_v1',
                    'command':'SEAL_DONE',
                    'actor_challenge':held['actor_challenge'],
                    'guardian_nonce':held['guardian_nonce']}))
                final = json.loads(rpc_client.recv(4096))
                if final != {
                    'schema':'aegis_auto_guardian_boot_guard_complete_reply_v1',
                    'actor_challenge':held['actor_challenge'],
                    'guardian_nonce':held['guardian_nonce']}:
                    os._exit(14)
                ctl_child.sendall(b'ACK')
                if ctl_child.recv(32) != b'CLOSE_DUP': os._exit(15)
                os.close(guard_fd)
                ctl_child.sendall(b'DUP_CLOSED')
                if ctl_child.recv(32) != b'CLOSE_RPC': os._exit(16)
                rpc_client.close()
                ctl_child.sendall(b'RPC_CLOSED')
                os._exit(0)
            except BaseException:
                os._exit(17)
        rpc_client.close(); ctl_child.close()
        self.addCleanup(ctl_parent.close)
        self.addCleanup(rpc_server.close)
        def reap():
            try: os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError: pass
            try: os.waitpid(child_pid, 0)
            except ChildProcessError: pass
        self.addCleanup(reap)
        pidfd = os.pidfd_open(child_pid)
        self.addCleanup(os.close, pidfd)
        actor = guardian.Guardian()
        faults = []
        ctl_parent.settimeout(8)
        with mock.patch.object(guardian, 'own_source'), \
             mock.patch.object(guardian, 'host_anchor',
                               return_value={'boot_id':'new-boot','netns_ino':42}), \
             mock.patch.object(guardian, '_peer_executable'), \
             mock.patch.object(guardian, '_boot_guard_binding',
                               return_value=('b'*64,'e'*64)), \
             mock.patch.object(guardian, '_boot_pending_absent'), \
             mock.patch.object(guardian, 'read_guard_policy',
                               return_value={'policy_sha256':'0'*64}), \
             mock.patch.object(guardian, 'INSTALL_LOCK', self.install), \
             mock.patch.object(guardian, 'GUARD_LOCK', self.guard), \
             mock.patch.object(guardian, 'STOP_INTENT', self.guard.with_name('no-stop-intent')), \
             mock.patch.object(guardian, 'INSTALL', self.install.with_suffix('.json')), \
             mock.patch.object(guardian, 'BOOT_GUARD_LEASE_SECONDS', 8):
            def serve():
                try:
                    actor._boot_guard_session(rpc_server, child_pid, pidfd,
                                              self.request, (self.valid_fd,),
                                              {'worker_sha256':'d'*64},
                                              {'InvocationID':'1'*32})
                except BaseException as error:
                    faults.append(error)
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            contender = os.open(self.guard, os.O_RDONLY | os.O_NOFOLLOW)
            self.addCleanup(os.close, contender)
            def blocked():
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(ctl_parent.recv(32), b'HELD')
            blocked()
            ctl_parent.sendall(b'COMPLETE')
            self.assertEqual(ctl_parent.recv(32), b'ACK')
            blocked()
            ctl_parent.sendall(b'CLOSE_DUP')
            self.assertEqual(ctl_parent.recv(32), b'DUP_CLOSED')
            blocked()
            ctl_parent.sendall(b'CLOSE_RPC')
            self.assertEqual(ctl_parent.recv(32), b'RPC_CLOSED')
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(faults, [])
            self.assertIsNone(actor.stopped_guard_session)
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)


if __name__ == '__main__':
    unittest.main()
