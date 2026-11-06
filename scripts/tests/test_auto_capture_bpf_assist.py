"""Real inherited SEQPACKET/pidfd/OFD protocol controls; no PID1 authority claim.

Source/PID1/watchdog identity is exercised separately by guard_capture_bind_pid1.
This fixture scripts only the live capture owner and privileged query outcome.
"""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

LIB=Path(__file__).resolve().parents[1]/'lib'
spec=importlib.util.spec_from_file_location('_capture_bpf_guardian',LIB/'aegis_auto_guardian.py')
g=importlib.util.module_from_spec(spec);sys.modules[spec.name]=g;spec.loader.exec_module(g)


@unittest.skipUnless(sys.platform=='linux' and hasattr(os,'pidfd_open'),'Linux original OFD/pidfd required')
class InheritedBpfRead(unittest.TestCase):
    def exchange(self, mutate=None, *, query_error=False, owner_changed=False, unlocked=False, late=False):
        with tempfile.TemporaryDirectory() as folder:
            lock=Path(folder)/'guard';lock.touch(mode=0o600)
            fd=os.open(lock,os.O_RDONLY);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if unlocked:fcntl.flock(fd,fcntl.LOCK_UN)
            identity=os.fstat(fd);nonce='a'*32
            request={'schema':'aegis_capture_bind_bpf_v1','nonce':nonce,'guard_dev':identity.st_dev,
                'guard_ino':identity.st_ino,'interfaces':['lo','up0','aegis-tun0']}
            if mutate:mutate(request)
            peer,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            code='''import socket,sys,json
s=socket.socket(fileno=int(sys.argv[1]));s.settimeout(3)
s.send(sys.argv[2].encode());r=json.loads(s.recv(4096))
assert r==dict(json.loads(sys.argv[2]),state='BPF_EMPTY')
'''
            proc=subprocess.Popen([sys.executable,'-I','-B','-c',code,str(child.fileno()),json.dumps(request)],
                pass_fds=(child.fileno(),),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            child.close();query=mock.Mock(side_effect=g.Refused('fixture_bpf_present') if query_error else None)
            clock=[0.0];receive=g._receive_no_fds
            def packet(channel):
                raw=receive(channel)
                if late:clock[0]=5.0
                return raw
            try:
                with mock.patch.object(g,'GUARD_LOCK',lock),mock.patch.object(g,'regular',return_value=
                        b'armed=1\ncapture_profile=full-wide-tun\nuplink=up0\n'), \
                     mock.patch.object(g,'capture_binding_index',side_effect=[3,4] if owner_changed else [3,3]), \
                     mock.patch.object(g,'verified_module',return_value=types.SimpleNamespace(privileged_bpf_query=query)), \
                     mock.patch.object(g,'_receive_no_fds',side_effect=packet), \
                     mock.patch.object(g.time,'monotonic',side_effect=lambda:clock[0]):
                    result=g._wait_capture_bind_helper(proc,peer,fd,nonce)
                return result,query.call_args_list
            finally:
                peer.close();os.close(fd)
                if proc.poll() is None:proc.kill()
                proc.wait(timeout=5)

    def test_one_exact_query_replies_and_reaps_the_original_child(self):
        code,calls=self.exchange();self.assertEqual(code,0)
        self.assertEqual(calls,[mock.call(['lo','up0','aegis-tun0'])])

    def test_wrong_nonce_never_reaches_privileged_query(self):
        with self.assertRaisesRegex(g.Refused,'capture_bpf_request_invalid'):
            self.exchange(lambda r:r.update(nonce='b'*32))

    def test_other_interface_never_reaches_privileged_query(self):
        with self.assertRaisesRegex(g.Refused,'capture_bpf_request_invalid'):
            self.exchange(lambda r:r.update(interfaces=['lo','up0','foreign0']))

    def test_extra_command_cannot_become_read_only_authority(self):
        with self.assertRaisesRegex(g.Refused,'capture_bpf_request_invalid'):
            self.exchange(lambda r:r.update(command='REGISTER'))

    def test_named_fd_without_original_flock_is_refused(self):
        with self.assertRaisesRegex(g.Refused,'exclusive_flock_not_held'):
            self.exchange(unlocked=True)

    def test_watchdog_refusal_cannot_emit_positive_ack(self):
        with self.assertRaisesRegex(g.Refused,'fixture_bpf_present'):
            self.exchange(query_error=True)

    def test_changed_capture_owner_cannot_emit_positive_ack(self):
        with self.assertRaisesRegex(g.Refused,'capture_bpf_owner_changed'):
            self.exchange(owner_changed=True)

    def test_late_query_does_not_extend_original_helper_budget(self):
        with self.assertRaisesRegex(g.Refused,'capture_bpf_budget_exhausted'):
            self.exchange(late=True)


if __name__=='__main__':unittest.main()
