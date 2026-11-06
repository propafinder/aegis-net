"""The actual CLI rc78 handler retains a closed code with stderr discarded."""
import ast
import contextlib
import errno
import json
import os
from pathlib import Path
import runpy
import socket
import sys
import tempfile
import unittest

SOURCE=Path(__file__).resolve().parents[1]/'lib/aegis_initrd_policy.py'


class BootCloudJournal(unittest.TestCase):
    def check_code(self, code):
        with tempfile.TemporaryDirectory(prefix='ag-lf7-',dir='/tmp') as folder:
            destination=Path(folder)/'journal';peer=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
            self.addCleanup(peer.close);peer.bind(str(destination));peer.settimeout(.1)
            namespace=runpy.run_path(str(SOURCE))
            error=namespace['CloudInitRefusal'](code,'private fixture detail must never reach the journal')
            def fail():raise error
            namespace['main']=fail
            emit=namespace.get('journal_cloud_init_refusal')
            if emit is not None:
                namespace['journal_cloud_init_refusal']=lambda value:emit(value,socket_path=destination)
            tree=ast.parse(SOURCE.read_text())
            entry=next(n for n in tree.body if isinstance(n,ast.If) and
                ast.unparse(n.test)=="__name__ == '__main__'")
            with open(os.devnull,'w') as sink,contextlib.redirect_stderr(sink):
                with self.assertRaises(SystemExit) as caught:
                    exec(compile(ast.Module(body=entry.body,type_ignores=[]),str(SOURCE),'exec'),namespace)
            self.assertEqual(caught.exception.code,78)
            payload=peer.recv(4097)
            self.assertLessEqual(len(payload),4096)
            self.assertNotIn(b'private fixture',payload)
            fields=dict(row.split(b'=',1) for row in payload.splitlines())
            record=json.loads(fields[b'MESSAGE'])
            self.assertEqual(record,{'schema':'aegis_boot_host_refusal_v1','code':code,
                'action':namespace['CLOUD_INIT_REFUSALS'][code][0]})
            self.assertEqual(fields[b'AEGIS_REFUSAL_CODE'].decode(),code)

    def test_active_cloud_reason_survives_discarded_stderr(self):
        self.check_code('cloud_init_early_network_unverified')

    def test_changed_cloud_pins_reason_survives_discarded_stderr(self):
        self.check_code('cloud_init_disabled_profile_unproved')


    def test_missing_journal_is_nonblocking_best_effort(self):
        namespace=runpy.run_path(str(SOURCE))
        with tempfile.TemporaryDirectory(prefix='ag-lf7-',dir='/tmp') as folder:
            error=namespace['CloudInitRefusal']('cloud_init_disabled_profile_unproved','private')
            self.assertFalse(namespace['journal_cloud_init_refusal'](error,socket_path=Path(folder)/'missing'))

    @unittest.skipUnless(sys.platform=='linux','Linux receiver queue limit required')
    def test_full_journal_queue_never_waits_or_changes_refusal(self):
        namespace=runpy.run_path(str(SOURCE))
        with tempfile.TemporaryDirectory(prefix='ag-lf7-',dir='/tmp') as folder:
            destination=Path(folder)/'journal'
            with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as peer, \
                 socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as filler:
                peer.bind(str(destination));filler.setblocking(False);filler.connect(str(destination))
                for _ in range(1024):
                    try:filler.send(b'x'*1024)
                    except OSError as error:
                        if error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK,errno.ENOBUFS):raise
                        break
                else:self.fail('could not bound the journal fixture queue')
                error=namespace['CloudInitRefusal']('cloud_init_disabled_profile_unproved','private')
                self.assertFalse(namespace['journal_cloud_init_refusal'](error,socket_path=destination))

    def test_unknown_or_untyped_reason_never_enters_journal(self):
        namespace=runpy.run_path(str(SOURCE))
        with tempfile.TemporaryDirectory(prefix='ag-lf7-',dir='/tmp') as folder:
            destination=Path(folder)/'journal'
            with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as peer:
                peer.bind(str(destination));peer.setblocking(False)
                error=namespace['CloudInitRefusal']('cloud_init_disabled_profile_unproved','private')
                error.code='private-injected-code'
                for candidate in (error,ValueError('private')):
                    self.assertFalse(namespace['journal_cloud_init_refusal'](candidate,socket_path=destination))
                with self.assertRaises(BlockingIOError):peer.recv(4096)


if __name__=='__main__':unittest.main()
