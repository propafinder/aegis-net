"""Real Linux OFD, SCM_RIGHTS and refusal controls for stopped guard reads.

No nft/systemd or product state changes. PID1/source/policy admission fixtures
are separate from the real kernel lock and connection lifetime controls.
"""
import ctypes
import array
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'scripts/lib/aegis_auto_guardian.py'
spec = importlib.util.spec_from_file_location('stopped_guardian', SOURCE)
guardian = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guardian)


class Actor:
    def __init__(self, path):
        self.path = path
        self.parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        pid = os.fork()
        if pid == 0:
            signal.alarm(8)
            self.parent.close()
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            child.sendall(str(fd).encode())
            while True:
                action = child.recv(32)
                if action == b'RELEASE':
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    child.sendall(b'RELEASED')
                elif action == b'BORROW':
                    child.sendmsg([b'FD'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                              array.array('i',[fd]))])
                elif action == b'EXIT':
                    os.close(fd)
                    os._exit(0)
                else:
                    os._exit(2)
        child.close()
        self.parent.settimeout(3)
        self.pid = pid
        self.fd_number = int(self.parent.recv(32))

    def borrow_real_pidfd(self):
        pidfd = os.pidfd_open(self.pid)
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            function = libc.pidfd_getfd
            function.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_uint)
            function.restype = ctypes.c_int
            fd = function(pidfd, self.fd_number, 0)
            if fd < 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
            return fd
        finally:
            os.close(pidfd)

    def send_original_ofd(self):
        self.parent.sendall(b'BORROW')
        payload, controls, _, _ = self.parent.recvmsg(32, socket.CMSG_SPACE(4))
        assert payload == b'FD'
        values = array.array('i')
        for level, kind, data in controls:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values.frombytes(data[:4])
        assert len(values) == 1
        return values[0]

    def release(self):
        self.parent.sendall(b'RELEASE')
        assert self.parent.recv(32) == b'RELEASED'

    def close(self):
        if self.pid:
            try: self.parent.sendall(b'EXIT')
            except OSError: pass
            _, status = os.waitpid(self.pid, 0)
            self.pid = None
            assert os.waitstatus_to_exitcode(status) == 0
        self.parent.close()


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'requires Linux root real OFD fixture')
class StoppedGuardRealLinux(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(guardian, '_stopped_guard_claim'),
                        'stopped guard API absent from integrated Linux source')
        self.assertTrue(hasattr(guardian.Guardian, '_stopped_guard_session'),
                        'stopped guard session absent from integrated Linux source')
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'device-guard.conf.lock'
        self.path.write_bytes(b'')
        self.path.chmod(0o600)
        patch = mock.patch.object(guardian, 'GUARD_LOCK', self.path)
        patch.start(); self.addCleanup(patch.stop)

    def actor(self):
        actor = Actor(self.path)
        self.addCleanup(actor.close)
        return actor

    def contender_refused(self):
        contender = os.open(self.path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(contender)

    def test_guardian_first_claim_holds_original_inode_and_releases_on_close(self):
        fd = guardian._stopped_guard_claim()
        try:
            self.assertEqual((os.fstat(fd).st_dev, os.fstat(fd).st_ino),
                             (self.path.stat().st_dev, self.path.stat().st_ino))
            self.contender_refused()
        finally:
            os.close(fd)
        contender = os.open(self.path, os.O_RDWR)
        try: fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally: os.close(contender)

    def test_monitor_first_authenticated_handoff_waits_only_for_exact_owner(self):
        actor = self.actor()
        try: borrowed = actor.borrow_real_pidfd()
        except (OSError, AttributeError) as error:
            self.skipTest('kernel pidfd_getfd unavailable: ' + type(error).__name__)
        self.addCleanup(os.close, borrowed)
        self.assertEqual((os.fstat(borrowed).st_dev, os.fstat(borrowed).st_ino),
                         (self.path.stat().st_dev, self.path.stat().st_ino))
        self.contender_refused()
        proofs = []
        def exact_owner(identity, deadline):
            proofs.append(identity)
            self.assertEqual(identity, (self.path.stat().st_dev, self.path.stat().st_ino))
            self.assertGreater(deadline, time.monotonic())
            if len(proofs) == 1: actor.release()
        with mock.patch.object(guardian, '_stopped_monitor_owner', side_effect=exact_owner):
            fd = guardian._stopped_guard_claim()
        try:
            self.assertEqual(len(proofs), 1)
            self.assertEqual((os.fstat(fd).st_dev,os.fstat(fd).st_ino),proofs[0])
            self.contender_refused()
        finally: os.close(fd)

    def test_unknown_live_holder_refuses_immediately_without_waiting(self):
        self.actor()
        began = time.monotonic()
        with mock.patch.object(guardian, '_stopped_monitor_owner',
                               side_effect=guardian.Refused('stopped_guard_unknown_writer')) as owner:
            with self.assertRaisesRegex(guardian.Refused,'unknown_writer'):
                guardian._stopped_guard_claim()
        self.assertEqual(owner.call_count, 1)
        self.assertLess(time.monotonic()-began, 0.25)
        self.contender_refused()

    def test_stale_monitor_identity_does_not_wait_on_still_busy_lock(self):
        self.actor()
        began = time.monotonic()
        with mock.patch.object(guardian, '_stopped_monitor_owner', return_value=False) as owner:
            with self.assertRaisesRegex(guardian.Refused,
                                        'stopped_guard_busy_after_monitor_transition'):
                guardian._stopped_guard_claim()
        self.assertEqual(owner.call_count, 1)
        self.assertLess(time.monotonic()-began, 0.25)
        self.contender_refused()

    def test_exact_monitor_releases_during_second_pid1_read(self):
        """A real child flock can disappear after its exact kernel owner row."""
        self._monitor_second_read_transition(replacement=False)

    def test_new_foreign_holder_during_second_pid1_read_refuses(self):
        """A second real child winning the handoff is never grandfathered in."""
        self._monitor_second_read_transition(replacement=True)

    def test_initial_foreign_holder_never_uses_release_path(self):
        self._monitor_second_read_transition(replacement=True, initial_foreign=True)

    def test_borrowed_old_ofd_is_proved_by_monitor_fdinfo_same_lock_fields(self):
        self._borrowed_old_ofd_case(release_during_second_locks_read=False)

    def test_borrowed_old_ofd_release_after_fdinfo_claims_immediately(self):
        self._borrowed_old_ofd_case(release_during_second_locks_read=True)

    def test_borrowed_old_ofd_replaced_by_foreign_holder_refuses(self):
        self._borrowed_old_ofd_case(release_during_second_locks_read=True,
                                    replace_after_release=True)

    def _borrowed_old_ofd_case(self, release_during_second_locks_read,
                               replace_after_release=False):
        """Two real children retain the original guard lock across actor exit."""
        actor = self.actor()
        borrowed = actor.send_original_ofd()
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        pid = os.fork()
        if pid == 0:
            signal.alarm(5)
            parent.close()
            os.close(borrowed)  # receive a distinct SCM_RIGHTS duplicate below
            payload, controls, _, _ = child.recvmsg(32, socket.CMSG_SPACE(4))
            if payload != b'GUARD': os._exit(2)
            values = array.array('i')
            for level, kind, data in controls:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    values.frombytes(data[:4])
            if len(values) != 1: os._exit(3)
            held = values[0]
            child.sendall(b'HELD')
            if child.recv(32) != b'RELEASE': os._exit(4)
            os.close(held)
            child.sendall(b'RELEASED')
            os._exit(0)
        child.close()
        parent.settimeout(3)
        try:
            parent.sendmsg([b'GUARD'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                                        array.array('i',[borrowed]))])
            self.assertEqual(parent.recv(32),b'HELD')
            os.close(borrowed)
            borrowed = None
            actor.close()
            identity=(self.path.stat().st_dev,self.path.stat().st_ino)
            rows=[]
            for line in Path('/proc/locks').read_text().splitlines():
                row=line.split()
                if len(row)!=8 or row[1:4]!=['FLOCK','ADVISORY','WRITE']:
                    continue
                parts=row[5].split(':')
                if len(parts)==3 and (
                    os.makedev(int(parts[0],16),int(parts[1],16)),int(parts[2]))==identity:
                    rows.append(row)
            self.assertEqual(len(rows),1)
            self.assertNotEqual(rows[0][4],str(pid))
            source=b'fixture-monitor-source'; digest=hashlib.sha256(source).hexdigest()
            unit=guardian.STOPPED_GUARD_UNIT
            facts={'MainPID':str(pid),'ControlPID':'0','ActiveState':'active',
                   'SubState':'running','InvocationID':'a'*32,
                   'ControlGroup':'/system.slice/'+unit,
                   'FragmentPath':str(guardian.FOREIGN_UNIT_FILE),
                   'DropInPaths':'','NeedDaemonReload':'no',
                   'ExecStart':('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 '
                                '-I -B '+str(guardian.FOREIGN_MONITOR_SOURCE)+
                                ' ; ignore_errors=no ; }')}
            actual_read=guardian._stopped_bounded_read
            actual_fdinfo_proof=guardian._exclusive_flock_fdinfo
            verified_fdinfo=[]
            lock_reads=[]
            released=[]
            replacements=[]
            def fdinfo_proof(info,named):
                valid=actual_fdinfo_proof(info,named)
                if valid:verified_fdinfo.append(True)
                return valid
            def read(path,maximum):
                path=str(path)
                if path=='/proc/'+str(pid)+'/cmdline':
                    return (b'/usr/bin/python3\0-I\0-B\0'+
                            str(guardian.FOREIGN_MONITOR_SOURCE).encode()+b'\0')
                if path=='/proc/'+str(pid)+'/cgroup':
                    return ('0::'+facts['ControlGroup']+'\n').encode()
                if path=='/proc/locks':
                    lock_reads.append(True)
                    if release_during_second_locks_read and len(lock_reads)==2:
                        self.assertEqual(verified_fdinfo,[True])
                        parent.sendall(b'RELEASE')
                        self.assertEqual(parent.recv(32),b'RELEASED')
                        released.append(True)
                        if replace_after_release:
                            replacements.append(self.actor())  # distinct real OFD and process
                return actual_read(path,maximum)
            def pid1(*_args,**_kwargs):
                return type('Result',(),{'returncode':0,'stdout':
                    ''.join(f'{k}={v}\n' for k,v in facts.items()).encode(),
                    'stderr':b''})()
            actual_proof=guardian._stopped_monitor_has_same_lock
            checked=[]
            def release_after_proof(proc,guard_identity,first_row,deadline):
                valid=actual_proof(proc,guard_identity,first_row,deadline)
                checked.append(valid)
                self.assertTrue(valid)
                parent.sendall(b'RELEASE')
                self.assertEqual(parent.recv(32),b'RELEASED')
                released.append(True)
                return valid
            install={'foreign_monitor_source_sha256':digest,
                     'foreign_monitor_unit_sha256':digest}
            with mock.patch.object(guardian,'record',return_value=install), \
                 mock.patch.object(guardian,'regular',return_value=source), \
                 mock.patch.object(guardian,'_stopped_bounded_read',side_effect=read), \
                 mock.patch.object(guardian.subprocess,'run',side_effect=pid1), \
                 mock.patch.object(guardian.os.path,'samefile',return_value=True), \
                 mock.patch.object(guardian,'_exclusive_flock_fdinfo',
                                   side_effect=fdinfo_proof):
                if replace_after_release:
                    with self.assertRaisesRegex(guardian.Refused,
                                                'stopped_guard_unknown_writer'):
                        guardian._stopped_guard_claim()
                elif release_during_second_locks_read:
                    fd=guardian._stopped_guard_claim()
                else:
                    with mock.patch.object(guardian,'_stopped_monitor_has_same_lock',
                                           side_effect=release_after_proof):
                        fd=guardian._stopped_guard_claim()
            if replace_after_release:
                self.assertEqual(released,[True])
                self.assertEqual(len(replacements),1)
                self.assertEqual(verified_fdinfo,[True])
                self.assertEqual(lock_reads,[True,True])
                self.contender_refused()
                return
            try:
                self.assertEqual(released,[True])
                # The first proof belongs to the monitor; the second is the
                # guardian's fresh claimed FD checked by _held_lock.
                self.assertEqual(verified_fdinfo,[True,True])
                if release_during_second_locks_read:
                    self.assertEqual(checked,[])
                    self.assertEqual(lock_reads,[True,True])
                else:
                    self.assertEqual(checked,[True])
                self.assertEqual((os.fstat(fd).st_dev,os.fstat(fd).st_ino),identity)
                self.contender_refused()
            finally:os.close(fd)
        finally:
            if borrowed is not None:os.close(borrowed)
            try:parent.sendall(b'RELEASE')
            except OSError:pass
            os.waitpid(pid,0)
            parent.close()

    def test_open_unlocked_monitor_fd_cannot_borrow_foreign_kernel_lock(self):
        foreign=self.actor()
        unlocked=os.open(self.path,os.O_RDONLY | os.O_CLOEXEC)
        try:
            identity=(self.path.stat().st_dev,self.path.stat().st_ino)
            rows=[]
            for line in Path('/proc/locks').read_text().splitlines():
                row=line.split()
                if len(row)!=8 or row[1:4]!=['FLOCK','ADVISORY','WRITE']:
                    continue
                parts=row[5].split(':')
                if len(parts)==3 and (
                    os.makedev(int(parts[0],16),int(parts[1],16)),int(parts[2]))==identity:
                    rows.append(row)
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0][4],str(foreign.pid))
            self.assertFalse(guardian._stopped_monitor_has_same_lock(
                Path('/proc')/str(os.getpid()),identity,rows[0],time.monotonic()+2))
            self.contender_refused()
        finally:os.close(unlocked)

    def _monitor_second_read_transition(self, replacement, initial_foreign=False):
        actor = self.actor()
        source = b'fixture-monitor-source'
        digest = hashlib.sha256(source).hexdigest()
        unit = guardian.STOPPED_GUARD_UNIT
        rows = {'MainPID':str(actor.pid), 'ControlPID':'0',
                'ActiveState':'active', 'SubState':'running',
                'InvocationID':'a'*32,
                'ControlGroup':'/system.slice/'+unit,
                'FragmentPath':str(guardian.FOREIGN_UNIT_FILE),
                'DropInPaths':'', 'NeedDaemonReload':'no',
                'ExecStart':('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 '
                             '-I -B '+str(guardian.FOREIGN_MONITOR_SOURCE)+
                             ' ; ignore_errors=no ; }')}
        original_read = guardian._stopped_bounded_read
        second = []
        if initial_foreign:
            actor.release()
            second.append(self.actor())
        calls = []
        def read(path, maximum):
            path = str(path)
            if path == '/proc/'+str(actor.pid)+'/cmdline':
                return (b'/usr/bin/python3\0-I\0-B\0'+
                        str(guardian.FOREIGN_MONITOR_SOURCE).encode()+b'\0')
            if path == '/proc/'+str(actor.pid)+'/cgroup':
                return ('0::'+rows['ControlGroup']+'\n').encode()
            return original_read(path, maximum)
        def pid1(*_args, **_kwargs):
            calls.append(1)
            if len(calls) == 2 and not initial_foreign:
                actor.release()
                if replacement:
                    second.append(self.actor())  # separate real process/OFD
                changed = dict(rows, MainPID='0', ActiveState='inactive',
                               SubState='dead')
                values = changed
            else:
                values = rows
            return type('Result',(),{'returncode':0,'stdout':
                ''.join(f'{key}={value}\n' for key,value in values.items()).encode(),
                'stderr':b''})()
        install = {'foreign_monitor_source_sha256':digest,
                   'foreign_monitor_unit_sha256':digest}
        with mock.patch.object(guardian,'record',return_value=install), \
             mock.patch.object(guardian,'regular',return_value=source), \
             mock.patch.object(guardian,'_stopped_bounded_read',side_effect=read), \
             mock.patch.object(guardian.subprocess,'run',side_effect=pid1), \
             mock.patch.object(guardian.os.path,'samefile',return_value=True):
            if replacement:
                with self.assertRaisesRegex(guardian.Refused,
                        'stopped_guard_unknown_writer' if initial_foreign else
                        'stopped_guard_busy_after_monitor_transition'):
                    guardian._stopped_guard_claim()
                self.assertEqual(len(second),1)
                self.contender_refused()
            else:
                fd = guardian._stopped_guard_claim()
                try:
                    self.assertEqual((os.fstat(fd).st_dev,os.fstat(fd).st_ino),
                                     (self.path.stat().st_dev,self.path.stat().st_ino))
                    self.contender_refused()
                finally:os.close(fd)
            self.assertEqual(len(calls),1 if initial_foreign else 2)

    def test_monitor_owner_rejects_source_pid1_and_real_proc_mismatch(self):
        actor = self.actor()
        guard_id = (self.path.stat().st_dev,self.path.stat().st_ino)
        source = b'fixture-monitor-source'
        good_sha = hashlib.sha256(source).hexdigest()
        with mock.patch.object(guardian,'record',return_value={
                'foreign_monitor_source_sha256':'0'*64,
                'foreign_monitor_unit_sha256':good_sha}), \
             mock.patch.object(guardian,'regular',return_value=source), \
             mock.patch.object(guardian.subprocess,'run') as run:
            with self.assertRaisesRegex(guardian.Refused,
                                        'stopped_guard_monitor_source_changed'):
                guardian._stopped_monitor_owner(guard_id,time.monotonic()+2)
            run.assert_not_called()
        trusted = {'foreign_monitor_source_sha256':good_sha,
                   'foreign_monitor_unit_sha256':good_sha}
        fields = {'MainPID':'0','ControlPID':'0','ActiveState':'inactive',
                  'SubState':'dead','InvocationID':'1'*32,
                  'ControlGroup':'/system.slice/aegis-foreign-policy-monitor.service',
                  'FragmentPath':str(guardian.FOREIGN_UNIT_FILE),
                  'DropInPaths':'','NeedDaemonReload':'no','ExecStart':''}
        def result(rows):
            return type('Result',(),{'returncode':0,'stdout':
                ''.join(f'{key}={value}\n' for key,value in rows.items()).encode(),
                'stderr':b''})()
        with mock.patch.object(guardian,'record',return_value=trusted), \
             mock.patch.object(guardian,'regular',return_value=source), \
             mock.patch.object(guardian.subprocess,'run',return_value=result(fields)):
            with self.assertRaisesRegex(guardian.Refused,
                                        'stopped_guard_monitor_pid1_changed'):
                guardian._stopped_monitor_owner(guard_id,time.monotonic()+2)
        fields.update(MainPID=str(actor.pid),ControlPID='0',ActiveState='active',
                      SubState='running',ExecStart=(
                          '{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 '
                          '-I -B '+str(guardian.FOREIGN_MONITOR_SOURCE)+
                          ' ; ignore_errors=no ; }'))
        with mock.patch.object(guardian,'record',return_value=trusted), \
             mock.patch.object(guardian,'regular',return_value=source), \
             mock.patch.object(guardian.subprocess,'run',return_value=result(fields)):
            with self.assertRaisesRegex(guardian.Refused,
                                        'stopped_guard_monitor_process_changed'):
                guardian._stopped_monitor_owner(guard_id,time.monotonic()+2)
        self.contender_refused()  # fake PID1 evidence never took or released OFD

    def test_replaced_named_guard_inode_is_never_accepted(self):
        original = guardian.fcntl.flock
        changed = []
        def switch(fd, operation):
            if not changed:
                retained = self.path.with_name('retained-original')
                self.path.rename(retained)
                self.path.write_bytes(b'')
                self.path.chmod(0o600)
                changed.append(retained)
            return original(fd, operation)
        with mock.patch.object(guardian.fcntl, 'flock', side_effect=switch):
            with self.assertRaises(guardian.Refused):
                guardian._stopped_guard_claim()
        self.assertEqual(len(changed), 1)
        self.assertNotEqual(changed[0].stat().st_ino, self.path.stat().st_ino)

    def _session_prefix(self, stage_fd, install_fd, stage_identity, reason):
        request = {'schema':'aegis_auto_guardian_stopped_guard_v1',
                   'command':'SEAL_STOPPED_GUARD','actor_challenge':'a'*64,
                   'boot_id':'test-boot','netns_ino':42,
                   'unit':'aegis-auto@'+'b'*64+'.service',
                   'prior_invocation_id':'c'*32,
                   'stage_dev':stage_identity.st_dev,'stage_ino':stage_identity.st_ino,
                   'stop_terminal_sha256':'d'*64,'post_deny_policy_sha256':'e'*64}
        dummy = guardian.Guardian()
        peer = mock.Mock()
        with mock.patch.object(guardian, 'own_source'), \
             mock.patch.object(guardian, 'host_anchor', return_value={'boot_id':'test-boot','netns_ino':42}), \
             mock.patch.object(guardian, '_peer_executable'), \
             mock.patch.object(guardian, '_pid_alive', return_value=True), \
             mock.patch.object(guardian, '_stopped_guard_claim') as claim:
            with self.assertRaisesRegex(guardian.Refused, reason):
                guardian.Guardian._stopped_guard_session(dummy, peer, 2, 3, request,
                                               (stage_fd,install_fd),
                                               {'worker_sha256':'f'*64},
                                               {'InvocationID':'1'*32})
            claim.assert_not_called()  # invalid FDs never acquire guard authority
            peer.sendmsg.assert_not_called()

    def test_forged_install_fd_refuses_before_guard_claim(self):
        stage = Path(self.folder.name) / 'stage'
        stage.mkdir(mode=0o700)
        sfd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        forged = Path(self.folder.name) / 'forged-install.lock'
        forged.write_bytes(b''); forged.chmod(0o600)
        ffd = os.open(forged, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(ffd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        named = Path(self.folder.name) / 'original-install.lock'
        named.write_bytes(b''); named.chmod(0o600)
        try:
            with mock.patch.object(guardian, 'INSTALL_LOCK', named):
                self._session_prefix(sfd, ffd, os.fstat(sfd), 'held_lock_changed')
        finally:
            os.close(ffd); os.close(sfd)

    def test_forged_stage_fd_refuses_before_guard_claim(self):
        valid = Path(self.folder.name) / 'stage-valid'; valid.mkdir(mode=0o700)
        forged = Path(self.folder.name) / 'stage-forged'; forged.mkdir(mode=0o700)
        ffd = os.open(forged, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        install = Path(self.folder.name) / 'original-install.lock'
        install.write_bytes(b''); install.chmod(0o600)
        ifd = os.open(install, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(ifd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with mock.patch.object(guardian, 'INSTALL_LOCK', install):
                self._session_prefix(ffd, ifd, valid.stat(), 'stopped_guard_stage_changed')
        finally:
            os.close(ifd); os.close(ffd)

    def test_monitor_can_borrow_live_guardian_original_ofd_without_unlock(self):
        actor = self.actor()
        try: borrowed = actor.borrow_real_pidfd()
        except (OSError, AttributeError) as error:
            self.skipTest('kernel pidfd_getfd unavailable: ' + type(error).__name__)
        spec = importlib.util.spec_from_file_location(
            'foreign_monitor', ROOT / 'scripts/lib/aegis_auto_foreign_monitor.py')
        monitor = importlib.util.module_from_spec(spec); spec.loader.exec_module(monitor)
        with mock.patch.object(monitor, 'LOCK', self.path), \
             mock.patch.object(monitor, '_ordinary_v1_without_auto_lease', return_value=False), \
             mock.patch.object(monitor, 'borrow_actor_guard', return_value=(borrowed, None)):
            with monitor.guard_lock() as received:
                self.assertEqual((os.fstat(received).st_dev,os.fstat(received).st_ino),
                                 (self.path.stat().st_dev,self.path.stat().st_ino))
                self.contender_refused()
        self.contender_refused()  # guardian process still holds the OFD
        actor.release()

    def test_full_session_retains_guard_through_ack_and_until_peer_eof(self):
        """Run the real socket/SCM_RIGHTS/OFD lifetime around mocked policy reads.

        PID1 and source provenance are separate tests: this fixture isolates the
        guard ownership collision and the terminal wire lifetime. The peer is
        an actual child process so /proc/<pid>/fd closure is observed by Linux.
        """
        stage = Path(self.folder.name) / 'stage'
        stage.mkdir(mode=0o700)
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        install_path = Path(self.folder.name) / 'original-install.lock'
        install_path.write_bytes(b'')
        install_path.chmod(0o600)
        install_fd = os.open(install_path, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(install_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rpc_server, rpc_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        control_parent, control_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        child_pid = os.fork()
        if child_pid == 0:
            signal.alarm(12)
            rpc_server.close(); control_parent.close()
            os.close(stage_fd); os.close(install_fd)
            try:
                payload, ancillary, _, _ = rpc_client.recvmsg(4096, socket.CMSG_SPACE(4))
                fds = array.array('i')
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
                if len(fds) != 1:
                    os._exit(11)
                guard_fd = fds[0]
                held = json.loads(payload)
                control_child.sendall(b'HELD')
                if control_child.recv(32) != b'COMPLETE': os._exit(12)
                completion = {'schema':'aegis_auto_guardian_stopped_guard_complete_v1',
                              'command':'SEAL_DONE',
                              'actor_challenge':held['actor_challenge'],
                              'guardian_nonce':held['guardian_nonce']}
                rpc_client.sendall(json.dumps(completion,separators=(',',':')).encode())
                ack = json.loads(rpc_client.recv(4096))
                if ack != {'schema':'aegis_auto_guardian_stopped_guard_complete_reply_v1',
                           'actor_challenge':held['actor_challenge'],
                           'guardian_nonce':held['guardian_nonce']}:
                    os._exit(13)
                control_child.sendall(b'ACK')
                if control_child.recv(32) != b'CLOSE_DUP': os._exit(14)
                os.close(guard_fd)
                control_child.sendall(b'DUP_CLOSED')
                if control_child.recv(32) != b'CLOSE_RPC': os._exit(15)
                rpc_client.close()
                control_child.sendall(b'RPC_CLOSED')
                os._exit(0)
            except BaseException:
                os._exit(16)
        rpc_client.close(); control_child.close()
        self.addCleanup(control_parent.close)
        self.addCleanup(rpc_server.close)
        self.addCleanup(os.close, stage_fd)
        self.addCleanup(os.close, install_fd)
        def reap_child():
            try: os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError: pass
            try: os.waitpid(child_pid, 0)
            except ChildProcessError: pass
        self.addCleanup(reap_child)
        pidfd = os.pidfd_open(child_pid)
        self.addCleanup(os.close, pidfd)
        raw = json.dumps({'schema':1,'outcome':'finalized-stopped',
                          'stage':[stage.stat().st_dev,stage.stat().st_ino],
                          'private_unit':'aegis-auto@'+'b'*64+'.service',
                          'prior_invocation_id':'c'*32,'boot_id':'test-boot',
                          'post_deny_policy_sha256':'e'*64},
                         sort_keys=True,separators=(',',':')).encode()
        terminal_hash = hashlib.sha256(raw).hexdigest()
        header = json.dumps({'leaves':{
            'receipts/activation-owner/finalized-stop-terminal.json':terminal_hash}},
            separators=(',',':')).encode()
        request = {'schema':'aegis_auto_guardian_stopped_guard_v1',
                   'command':'SEAL_STOPPED_GUARD','actor_challenge':'a'*64,
                   'boot_id':'test-boot','netns_ino':42,
                   'unit':'aegis-auto@'+'b'*64+'.service',
                   'prior_invocation_id':'c'*32,
                   'stage_dev':stage.stat().st_dev,'stage_ino':stage.stat().st_ino,
                   'stop_terminal_sha256':terminal_hash,
                   'post_deny_policy_sha256':'e'*64}
        dummy = guardian.Guardian()
        faults = []
        control_parent.settimeout(8)
        with mock.patch.object(guardian, 'own_source'), \
             mock.patch.object(guardian, 'host_anchor',
                               return_value={'boot_id':'test-boot','netns_ino':42}), \
             mock.patch.object(guardian, '_peer_executable'), \
             mock.patch.object(guardian, '_protected_stage_receipt',return_value=raw), \
             mock.patch.object(guardian, '_protected_stage_receipt_for_header',return_value=header), \
             mock.patch.object(guardian, '_stopped_guard_pid1',return_value={'ActiveState':'inactive'}), \
             mock.patch.object(guardian, 'read_guard_policy',
                               return_value={'policy_sha256':'e'*64}), \
             mock.patch.object(guardian, 'INSTALL_LOCK',install_path), \
             mock.patch.object(guardian, 'INSTALL',install_path.with_suffix('.json')), \
             mock.patch.object(guardian, 'STOP_INTENT',stage/'no-stop-intent'), \
             mock.patch.object(guardian, 'LEASE_SECONDS',8):
            def serve():
                try:
                    guardian.Guardian._stopped_guard_session(
                        dummy,rpc_server,child_pid,pidfd,request,(stage_fd,install_fd),
                        {'worker_sha256':'f'*64},{'InvocationID':'1'*32})
                except BaseException as error:
                    faults.append(error)
            worker = threading.Thread(target=serve,daemon=True)
            worker.start()
            self.assertEqual(control_parent.recv(32),b'HELD')
            self.contender_refused()
            control_parent.sendall(b'COMPLETE')
            self.assertEqual(control_parent.recv(32),b'ACK')
            self.contender_refused()
            control_parent.sendall(b'CLOSE_DUP')
            self.assertEqual(control_parent.recv(32),b'DUP_CLOSED')
            self.contender_refused()  # actor retained original until channel EOF
            control_parent.sendall(b'CLOSE_RPC')
            self.assertEqual(control_parent.recv(32),b'RPC_CLOSED')
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive(), 'guardian did not release at EOF')
            self.assertEqual(faults,[])
            self.assertIsNone(dummy.stopped_guard_session)
            contender = os.open(self.path,os.O_RDONLY | os.O_NOFOLLOW)
            try: fcntl.flock(contender,fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally: os.close(contender)

    def test_prior_mutation_drains_while_new_mutation_refuses_and_fds_close(self):
        """Exercise the real Condition reservation and serve_one admission gate."""
        stage = Path(self.folder.name) / 'stage'
        stage.mkdir(mode=0o700)
        stage_fd = os.open(stage,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        install = Path(self.folder.name) / 'install.lock'
        install.write_bytes(b''); install.chmod(0o600)
        install_fd = os.open(install,os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(install_fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(os.close,stage_fd)
        self.addCleanup(os.close,install_fd)
        raw = json.dumps({'schema':1,'outcome':'finalized-stopped',
                          'stage':[stage.stat().st_dev,stage.stat().st_ino],
                          'private_unit':'aegis-auto@'+'b'*64+'.service',
                          'prior_invocation_id':'c'*32,'boot_id':'test-boot',
                          'post_deny_policy_sha256':'e'*64},
                         sort_keys=True,separators=(',',':')).encode()
        raw_sha = hashlib.sha256(raw).hexdigest()
        header = json.dumps({'leaves':{
            'receipts/activation-owner/finalized-stop-terminal.json':raw_sha}}).encode()
        challenge = 'a'*64
        request = {'schema':'aegis_auto_guardian_stopped_guard_v1',
                   'command':'SEAL_STOPPED_GUARD','actor_challenge':challenge,
                   'boot_id':'test-boot','netns_ino':42,
                   'unit':'aegis-auto@'+'b'*64+'.service',
                   'prior_invocation_id':'c'*32,
                   'stage_dev':stage.stat().st_dev,'stage_ino':stage.stat().st_ino,
                   'stop_terminal_sha256':raw_sha,
                   'post_deny_policy_sha256':'e'*64}
        actor = guardian.Guardian()
        with actor.active_guard_idle:
            actor.mutation_admissions = 1  # already admitted Stop inverse
        faults = []
        peer = mock.Mock()
        with mock.patch.object(guardian,'own_source'), \
             mock.patch.object(guardian,'host_anchor',
                               return_value={'boot_id':'test-boot','netns_ino':42}), \
             mock.patch.object(guardian,'_peer_executable'), \
             mock.patch.object(guardian,'_pid_alive',return_value=True), \
             mock.patch.object(guardian,'_protected_stage_receipt',return_value=raw), \
             mock.patch.object(guardian,'_protected_stage_receipt_for_header',return_value=header), \
             mock.patch.object(guardian,'_stopped_guard_pid1',return_value={'ActiveState':'inactive'}), \
             mock.patch.object(guardian,'INSTALL_LOCK',install), \
             mock.patch.object(guardian,'INSTALL',install.with_suffix('.json')), \
             mock.patch.object(guardian,'STOP_INTENT',stage/'no-stop-intent'), \
             mock.patch.object(guardian,'_stopped_guard_claim',
                               side_effect=guardian.Refused('fixture_after_drain')) as claim:
            def observe():
                try:
                    actor._stopped_guard_session(peer,os.getpid(),-1,request,
                                                  (stage_fd,install_fd),
                                                  {'worker_sha256':'f'*64},
                                                  {'InvocationID':'1'*32})
                except BaseException as error:
                    faults.append(error)
            thread = threading.Thread(target=observe,daemon=True)
            thread.start()
            deadline = time.monotonic()+1
            while actor.stopped_guard_session is None and time.monotonic()<deadline:
                time.sleep(.002)
            self.assertEqual(actor.stopped_guard_session,challenge)
            self.assertEqual(actor.mutation_admissions,1)
            claim.assert_not_called()  # read waits until admitted mutation drains
            server,client = socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            self.addCleanup(client.close)
            new_fd = os.dup(stage_fd)
            new_pidfd = os.pidfd_open(os.getpid())
            with mock.patch.object(guardian,'record',return_value={}), \
                 mock.patch.object(guardian,'_unit_identity',return_value={}), \
                 mock.patch.object(guardian,'_peer_identity',
                                   return_value=(os.getpid(),new_pidfd)), \
                 mock.patch.object(guardian,'_receive',
                                   return_value=({'command':'REGISTER_LAUNCH'},(new_fd,))):
                with self.assertRaisesRegex(guardian.Refused,
                                            'stopped_guard_read_in_progress'):
                    actor.serve_one(server)
            with self.assertRaises(OSError): os.fstat(new_fd)
            with self.assertRaises(OSError): os.fstat(new_pidfd)
            self.assertEqual(actor.mutation_admissions,1)
            with actor.active_guard_idle:
                actor.mutation_admissions -= 1
                actor.active_guard_idle.notify_all()
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(faults),1)
            self.assertIsInstance(faults[0],guardian.Refused)
            self.assertIn('fixture_after_drain',str(faults[0]))
            self.assertEqual(claim.call_count,1)
            self.assertIsNone(actor.stopped_guard_session)
            with actor.active_guard_idle:
                actor.mutation_admissions = 1
            with mock.patch.object(guardian,'STOPPED_GUARD_MONITOR_WAIT',.03):
                with self.assertRaisesRegex(guardian.Refused,
                                            'stopped_guard_mutation_drain_deadline'):
                    actor._stopped_guard_session(peer,os.getpid(),-1,request,
                                                  (stage_fd,install_fd),
                                                  {'worker_sha256':'f'*64},
                                                  {'InvocationID':'1'*32})
            self.assertIsNone(actor.stopped_guard_session)
            self.assertEqual(actor.mutation_admissions,1)
            self.assertEqual(claim.call_count,1)  # timeout never takes guard


if __name__ == '__main__': unittest.main()
