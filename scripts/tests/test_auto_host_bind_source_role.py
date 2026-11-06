"""Source-only controls for the host guardian's terminal BIND proof role.

The real PID1 namespace/FD control is separate and mandatory before A4.
"""
import hashlib
import os
import runpy
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'lib/aegis_auto_guardian.py'
G = runpy.run_path(str(SOURCE))

class HostBindSourceProofTests(unittest.TestCase):
    def setUp(self):
        self.proof = G['_host_currentboot_source_proof']
        self.globals = self.proof.__globals__
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.transition = self.root/'aegis_auto_boot_transition.py'
        self.transition.write_bytes(b'exact-transition')
        self.transition.chmod(0o500)
        self.done = mock.Mock()
        self.done.wait.return_value = 0
        self.done.poll.return_value = 0
        self.done.pid = 12034
        self.digest = hashlib.sha256(b'exact-transition').hexdigest()
        def regular(path, limit, mode):
            if path.name == 'auto-guardian-install.json':
                self.assertEqual((limit,mode),(4096,0o600))
                return ('{"terminal_transition_sha256":"'+self.digest+'"}').encode()
            self.assertEqual((limit,mode),(4096,0o600))
            self.assertIn(path.name, ('aegis-auto-terminal-source.json',
                                       'aegis-auto-terminal-store.json'))
            return path.name.encode()
        self.values = dict(ROOT=self.root, _held_lock=mock.Mock(),
            own_source=mock.Mock(), regular=regular)
        self.patch = mock.patch.dict(self.globals,self.values)
        self.patch.start()
        self.popen = mock.patch.object(self.globals['subprocess'],'Popen',
            return_value=self.done)
        self.popen.start()
        self.killpg = mock.patch.object(self.globals['os'],'killpg')
        self.killpg.start()
        self.waitid = mock.patch.object(self.globals['os'],'waitid',
            return_value=types.SimpleNamespace(si_code=os.CLD_EXITED,si_status=0))
        self.waitid.start()
        real_stat = Path.stat
        real_fstat = os.fstat
        def root_stat(path, *args, **kwargs):
            value=real_stat(path,*args,**kwargs)
            if path == self.transition or path == self.root or path in self.root.parents:
                mode=value.st_mode
                if stat.S_ISDIR(mode): mode &= ~0o022
                return types.SimpleNamespace(st_mode=mode,
                    st_uid=0,st_gid=0,st_nlink=value.st_nlink,st_dev=value.st_dev,
                    st_ino=value.st_ino,st_size=value.st_size,
                    st_mtime_ns=value.st_mtime_ns,st_ctime_ns=value.st_ctime_ns)
            return value
        def root_fstat(fd):
            value=real_fstat(fd)
            return types.SimpleNamespace(st_mode=value.st_mode,st_uid=0,st_gid=0,
                st_nlink=value.st_nlink,st_dev=value.st_dev,st_ino=value.st_ino,
                st_size=value.st_size,st_mtime_ns=value.st_mtime_ns,
                st_ctime_ns=value.st_ctime_ns)
        self.statpatch = mock.patch.object(Path,'stat',root_stat)
        self.fstatpatch = mock.patch.object(self.globals['os'],'fstat',root_fstat)
        self.statpatch.start();self.fstatpatch.start()
    def tearDown(self):
        self.fstatpatch.stop();self.statpatch.stop();self.waitid.stop();self.killpg.stop()
        self.popen.stop();self.patch.stop();self.tmp.cleanup()

    def test_exact_host_process_precedes_handoff(self):
        self.proof(9)
        self.assertEqual(self.globals['_held_lock'].call_count,2)
        self.globals['own_source'].assert_not_called()
        self.globals['subprocess'].Popen.assert_called_once()
        args,kwargs=self.globals['subprocess'].Popen.call_args
        self.assertEqual(args[0][0:3],('/usr/bin/python3','-I','-B'))
        self.assertEqual(args[0][-3], 'verify-consumed-under-guard-held')
        self.assertEqual(args[0][-2], '9')
        self.assertEqual(kwargs['pass_fds'][0],9)
        self.assertEqual(len(kwargs['pass_fds']),2)
        self.assertTrue(kwargs['start_new_session'])
        self.assertFalse(any(k.startswith('AEGIS_') for k in kwargs['env']))

    def test_absent_source_or_store_refuses_before_process(self):
        def missing(path,limit,mode):
            if path.name in ('aegis-auto-terminal-source.json',
                             'aegis-auto-terminal-store.json'):
                raise FileNotFoundError(path)
            return ('{"terminal_transition_sha256":"'+self.digest+'"}').encode()
        self.globals['regular']=missing
        with self.assertRaises(FileNotFoundError): self.proof(9)
        self.globals['subprocess'].Popen.assert_not_called()

    def test_failed_host_child_refuses_without_handoff(self):
        self.globals['os'].waitid.return_value = types.SimpleNamespace(
            si_code=os.CLD_EXITED,si_status=2)
        with self.assertRaises(G['Refused']): self.proof(9)
        self.globals['subprocess'].Popen.assert_called_once()

    def test_handoff_cannot_send_before_host_proof(self):
        handoff=G['_send_bind_handoff'];globals_=handoff.__globals__
        peer=mock.Mock(); original={'private_unit':'aegis-auto@'+'a'*64+'.service'}
        request={'unit':original['private_unit'],'boot_id':'b','invocation_id':'i'}
        with mock.patch.dict(globals_,dict(_bind_request=mock.Mock(),
            _bind_peer=mock.Mock(),_held_lock=mock.Mock(),
            _claimed_private_unit=mock.Mock(),
            STOP_INTENT=mock.Mock(**{'exists.return_value':False,
                                    'is_symlink.return_value':False}),
            _host_currentboot_source_proof=mock.Mock(side_effect=G['Refused']('no_proof')))):
            with self.assertRaises(G['Refused']):
                handoff(peer,123,11,request,9,10,original,{})
            peer.sendmsg.assert_not_called()

if __name__ == '__main__': unittest.main()
