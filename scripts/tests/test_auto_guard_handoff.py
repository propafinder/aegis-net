"""Actual Linux OFD/SCM_RIGHTS controls for guardian-first lock acquisition."""
import array
import fcntl
import importlib.util
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('handoff_guardian', Path(__file__).resolve().parents[1]/'lib/aegis_auto_guardian.py')
guardian = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guardian)


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root OFD fixture')
class GuardHandoff(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.path = Path(folder.name)/'guard.lock'
        self.fd = os.open(self.path, os.O_RDWR|os.O_CREAT|os.O_EXCL, 0o600)
        self.addCleanup(os.close, self.fd)
        for key, value in [('GUARD_LOCK',self.path), ('SPLIT',self.path.with_name('no-split')),
                           ('STOP_INTENT',self.path.with_name('no-stop'))]:
            context = patch.object(guardian,key,value); context.start(); self.addCleanup(context.stop)

    def test_scm_delay_has_no_worker_lock_and_receiver_claim_is_shared(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        pid = os.fork()
        if pid == 0:
            signal.alarm(5)
            left.close(); os.close(self.fd)
            try:
                _, ancillary, flags, _ = right.recvmsg(16, socket.CMSG_SPACE(4))
                assert flags == 0 and len(ancillary) == 1
                received = array.array('i'); received.frombytes(ancillary[0][2])
                assert len(received) == 1
                guardian._claim_guard_handoff(received[0])
                right.send(b'R'); assert right.recv(1) == b'Q'
                os.close(received[0]); os._exit(0)
            except BaseException:
                right.send(b'E'); os._exit(1)
        right.close(); left.settimeout(5)
        try:
            time.sleep(.3)  # Delayed SCM_RIGHTS transfer, not a lock retry.
            other = os.open(self.path, os.O_RDWR)
            try:
                fcntl.flock(other, fcntl.LOCK_EX|fcntl.LOCK_NB)
                fcntl.flock(other, fcntl.LOCK_UN)
                self.assertNotIn('FLOCK', Path(f'/proc/self/fdinfo/{self.fd}').read_text())
                left.sendmsg([b'G'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[self.fd]))])
                self.assertEqual(left.recv(1), b'R')
                self.assertEqual(guardian._held_guard(self.fd), (os.fstat(self.fd).st_dev,os.fstat(self.fd).st_ino))
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX|fcntl.LOCK_NB)
                left.send(b'Q')
            finally:
                os.close(other)
        finally:
            left.close()
            _, status = os.waitpid(pid, 0)
        self.assertEqual(status, 0)

    def test_anonymous_prelocked_handoff_is_refused_without_unlocking_it(self):
        fcntl.flock(self.fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        with self.assertRaisesRegex(guardian.Refused, 'already_locked'):
            guardian._claim_guard_handoff(self.fd)
        other = os.open(self.path, os.O_RDONLY)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:
            os.close(other)

    def test_unknown_live_holder_and_replaced_inode_are_not_admitted(self):
        other = os.open(self.path, os.O_RDONLY)
        try:
            fcntl.flock(other, fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(guardian.time,'monotonic',side_effect=[0,3]), \
                 self.assertRaisesRegex(guardian.Refused, 'handoff_busy'):
                guardian._claim_guard_handoff(self.fd)
            fcntl.flock(other, fcntl.LOCK_UN)
        finally:
            os.close(other)
        self.path.rename(self.path.with_name('retained-original'))
        replacement = os.open(self.path, os.O_RDWR|os.O_CREAT|os.O_EXCL, 0o600); os.close(replacement)
        with self.assertRaisesRegex(guardian.Refused, 'inode_changed'):
            guardian._claim_guard_handoff(self.fd)


if __name__ == '__main__':
    unittest.main()
