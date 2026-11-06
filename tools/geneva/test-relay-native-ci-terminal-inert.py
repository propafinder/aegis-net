#!/usr/bin/env python3
"""Execute actual native outer/inner failure branches with inert OS adapters.

Every command, process launch, signal, socket and namespace operation is replaced.
Only temporary test files are written; no synthetic receipt enters live evidence.
"""
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('relay_terminal_inert', HERE/'relay-native-ci.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def ident(pid):
    return {'pid':pid,'start':'INERT_START','group':pid,'argv':'INERT_ARGS','exe':'INERT_EXE'}


class OuterAdapter:
    def __init__(self, root, failure, error):
        self.root, self.failure, self.error = root, failure, error
        self.calls=[];self.processes=[];self.signals=[]

    def command(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[0] == self.failure:
            self.failure=None
            raise self.error('INERT_FAILURE')
        if argv[0]=='git':return b'INERT_SOURCE\n'
        if argv[0]=='ip':return b'[]'
        if argv[0]=='nft':return b'{"nftables":[]}'
        raise AssertionError('Unexpected external command '+argv[0])

    def pki(self, root):
        folder=root/'private-test-pki';folder.mkdir(mode=0o700)
        (folder/'ca.key').write_bytes(b'INERT_ONLY_NOT_A_KEY')
        if self.failure=='pki':raise self.error('INERT_FAILURE')
        return folder

    def popen(self, argv, **kwargs):
        adapter=self
        guard='watchdog' in argv
        class Process:
            pid=102 if guard else 101
            returncode=None
            def poll(self):return self.returncode
            def wait(self, timeout=None):
                if not guard and timeout==110:
                    if adapter.failure=='child_wait':
                        adapter.failure=None
                        raise adapter.error('INERT_FAILURE')
                    (adapter.root/'inner-result.json').write_text(json.dumps({'status':'INERT_SYNTHETIC_CHILD_NOT_RUNTIME_PROOF'}))
                self.returncode=0
                return 0
            def communicate(self, timeout=None):
                if guard and adapter.failure=='guard_terminal':
                    adapter.failure=None
                    raise adapter.error('INERT_FAILURE')
                self.returncode=0
                return b'',b''
        process=Process();self.processes.append(process)
        if not guard:
            m.c.exclusive(self.root/'inner-start.json',{'child':ident(process.pid),'tool_sha256':m.c.digest(m.SELF)})
        else:
            state=json.loads((self.root/'watchdog-input.json').read_text())
            m.c.exclusive(self.root/'watchdog-ready.json',{**state,'watchdog':ident(process.pid)})
        return process

    def killpg(self,pid,sig):
        self.signals.append((pid,sig))
        assert pid==101
        self.processes[0].returncode=-9

    def session_absent(self,pid):
        return all(p.pid!=pid or p.returncode is not None for p in self.processes)

    def patches(self):
        stack=ExitStack()
        original_stat=Path.stat
        original_lstat=Path.lstat
        def root_owned_stat(path,*args,**kwargs):
            values=list(original_stat(path,*args,**kwargs));values[4]=0
            return os.stat_result(values)
        stack.enter_context(patch.object(Path,'stat',root_owned_stat))
        def root_owned_lstat(path,*args,**kwargs):
            values=list(original_lstat(path,*args,**kwargs));values[4]=0
            return os.stat_result(values)
        stack.enter_context(patch.object(Path,'lstat',root_owned_lstat))
        for owner,name,value in ((m.sys,'platform','linux'),(m.os,'geteuid',lambda:0),
            (m.os,'readlink',lambda path:{'/proc/self/ns/net':'net:[100]','/proc/self/ns/mnt':'mnt:[101]'}[path]),
            (m.os,'killpg',self.killpg),(m.c,'command',self.command),(m,'pki',self.pki),
            (m.subprocess,'Popen',self.popen),(m.c,'identity',ident),
            (m.c,'same_process',lambda row:True),(m.c,'session_absent',self.session_absent)):
            stack.enter_context(patch.object(owner,name,value))
        # Any accidental observation socket is a test failure, never a real socket.
        stack.enter_context(patch.object(m.socket,'socket',side_effect=AssertionError('Unexpected socket')))
        return stack


class ActualOuterTerminal(unittest.TestCase):
    def run_failure(self, failure, error=RuntimeError):
        with tempfile.TemporaryDirectory(prefix='aegis-native-terminal-INERT-') as td:
            root=Path(td)/'stage';binary=Path(td)/'probe';binary.write_bytes(b'INERT_NOT_EXECUTABLE')
            adapter=OuterAdapter(root,failure,error)
            if failure=='invalidbinary':binary.unlink()
            with adapter.patches():
                with self.assertRaises(RuntimeError):m.outer(str(binary),str(root))
            row=json.loads((root/'receipt.json').read_text())
            self.assertTrue(row['status'].startswith('FAIL'))
            self.assertFalse(row['production_or_target_network_or_independent_capture_or_signed_release_acceptance'])
            self.assertFalse((root/'private-test-pki').exists())
            return row,adapter

    def test_ip_baseline_failure_and_interrupt_have_terminal_no_false_proof(self):
        for error in (RuntimeError,KeyboardInterrupt):
            row,adapter=self.run_failure('ip',error)
            self.assertFalse(row['host_baselines_observed'])
            self.assertFalse(row['cleanup']['host_network_rules_unchanged'])
            self.assertFalse(row['owned_child_started']);self.assertEqual(adapter.processes,[])
            self.assertIn(error.__name__,[x['type'] for x in row['errors']])

    def test_invalid_binary_has_terminal_null_pin_before_any_baseline_or_child(self):
        row,adapter=self.run_failure('invalidbinary')
        self.assertIsNone(row['binary_sha256'])
        self.assertFalse(row['host_baselines_observed'])
        self.assertFalse(row['owned_child_started'])
        self.assertFalse(row['cleanup']['host_network_rules_unchanged'])
        self.assertEqual(adapter.calls,[]);self.assertEqual(adapter.processes,[])

    def test_nft_baseline_failure_never_claims_full_host_baseline(self):
        row,adapter=self.run_failure('nft')
        self.assertFalse(row['host_baselines_observed'])
        self.assertFalse(row['cleanup']['host_network_rules_unchanged'])
        self.assertEqual(adapter.processes,[])

    def test_partial_pki_failure_removes_owned_files_before_any_child(self):
        for error in (RuntimeError,KeyboardInterrupt):
            row,adapter=self.run_failure('pki',error)
            self.assertTrue(row['cleanup']['test_PKI_removed'])
            self.assertTrue(row['cleanup']['owned_session_absent'])
            self.assertEqual(adapter.processes,[])

    def test_child_wait_interrupt_still_checks_exact_session_and_guard(self):
        row,adapter=self.run_failure('child_wait',KeyboardInterrupt)
        self.assertTrue(row['owned_child_started']);self.assertTrue(row['independent_guard_started'])
        self.assertTrue(row['cleanup']['owned_session_absent'])
        self.assertTrue(row['cleanup']['watchdog_terminal'])
        self.assertEqual(adapter.signals,[(101,m.signal.SIGKILL)])

    def test_guard_terminal_interrupt_retained_and_not_accepted(self):
        row,adapter=self.run_failure('guard_terminal',KeyboardInterrupt)
        self.assertTrue(row['cleanup']['owned_session_absent'])
        self.assertFalse(row['cleanup']['watchdog_terminal'])
        self.assertIsNone(adapter.processes[1].returncode)
        self.assertIn('KeyboardInterrupt',[x['type'] for x in row['errors']])


class ActualEvidenceExport(unittest.TestCase):
    def root_owned(self):
        original_stat=Path.stat
        def owned(path,*args,**kwargs):
            values=list(original_stat(path,*args,**kwargs));values[4]=0
            return os.stat_result(values)
        return patch.object(Path,'stat',owned)

    def test_restrictive_umask_still_exports_readable_metadata_only(self):
        with tempfile.TemporaryDirectory(prefix='aegis-export-INERT-') as td:
            stage=Path(td)/'stage';stage.mkdir(mode=0o700)
            (stage/'receipt.json').write_bytes(b'{"status":"INERT_FAILURE"}\n')
            (stage/'inner.stderr').write_bytes(b'INERT_DIAGNOSTIC')
            (stage/'private-test-pki').mkdir(mode=0o700)
            private=stage/'private-test-pki'/'ca.key';private.write_bytes(b'INERT_NOT_A_KEY');private.chmod(0o600)
            (stage/'input.json').write_bytes(b'INERT_PRIVATE_INPUT_NOT_EXPORTED')
            out=Path(td)/'export'
            previous=os.umask(0o077)
            try:
                with self.root_owned():m.export(str(stage),str(out))
            finally:os.umask(previous)
            self.assertEqual(out.stat().st_mode&0o777,0o755)
            self.assertEqual({p.name for p in out.iterdir()},{'receipt.json','inner.stderr'})
            for path in out.iterdir():
                self.assertEqual(path.stat().st_mode&0o777,0o644)
                self.assertEqual(path.read_bytes(),(stage/path.name).read_bytes())
            self.assertEqual(stage.stat().st_mode&0o777,0o700)
            self.assertEqual(private.stat().st_mode&0o777,0o600)

    def test_existing_output_refused_before_permissions_or_contents_change(self):
        with tempfile.TemporaryDirectory(prefix='aegis-export-INERT-') as td:
            out=Path(td)/'existing';out.mkdir(mode=0o700);marker=out/'marker';marker.write_bytes(b'INERT_OLD_ATTEMPT')
            with self.assertRaises(RuntimeError):m.export(td,str(out))
            self.assertEqual(out.stat().st_mode&0o777,0o700)
            self.assertEqual(marker.read_bytes(),b'INERT_OLD_ATTEMPT')

    def test_allowlisted_symlink_refused_without_copying_target(self):
        with tempfile.TemporaryDirectory(prefix='aegis-export-INERT-') as td:
            stage=Path(td)/'stage';stage.mkdir(mode=0o700);target=Path(td)/'target';target.write_bytes(b'INERT_NOT_METADATA')
            (stage/'receipt.json').symlink_to(target);out=Path(td)/'export'
            with self.root_owned(),self.assertRaises(RuntimeError):m.export(str(stage),str(out))
            self.assertEqual(list(out.iterdir()),[])

    def test_oversized_metadata_refused_without_partial_copy(self):
        with tempfile.TemporaryDirectory(prefix='aegis-export-INERT-') as td:
            stage=Path(td)/'stage';stage.mkdir(mode=0o700);(stage/'receipt.json').write_bytes(b'x'*1048577);out=Path(td)/'export'
            with self.root_owned(),self.assertRaises(RuntimeError):m.export(str(stage),str(out))
            self.assertEqual(list(out.iterdir()),[])


class ActualInnerTerminal(unittest.TestCase):
    def run_failure(self,phase,error=RuntimeError):
        with tempfile.TemporaryDirectory(prefix='aegis-native-inner-INERT-') as td:
            root=Path(td);cfg={'tool_sha256':m.c.digest(m.SELF),'common_sha256':m.c.digest(m.COMMON),
                'observer_sha256':m.c.digest(m.OBSERVER),
                'diagnostics_sha256':m.c.digest(m.DIAGNOSTICS),
                'host_netns':'HOST_NET','host_mntns':'HOST_MNT','pki':str(root/'INERT_PKI')}
            m.c.exclusive(root/'input.json',cfg)
            m.c.exclusive(root/'watchdog-ready.json',{'child':ident(os.getpid()),'tool_sha256':cfg['tool_sha256'],
                'watchdog':ident(202),'deadline':time.monotonic()+120})
            calls=[];spawned=[]
            def command(argv,**kwargs):
                calls.append(list(argv))
                if argv[0]==phase:raise error('INERT_FAILURE')
                if argv==['ip','-j','-d','link','show']:
                    return json.dumps([{'ifindex':1,'ifname':'lo','address':'00:00:00:00:00:00','link_type':'loopback'}]).encode()
                return b''
            def popen(argv,**kwargs):spawned.append(argv);raise error('INERT_FAILURE')
            with ExitStack() as stack:
                stack.enter_context(patch.object(m.os,'readlink',lambda path:'INERT_FRESH_'+path.rsplit('/',1)[-1]))
                stack.enter_context(patch.object(m.c,'identity',ident))
                stack.enter_context(patch.object(m.c,'same_process',lambda row:phase!='readiness'))
                stack.enter_context(patch.object(m.c,'command',command))
                stack.enter_context(patch.object(m.subprocess,'Popen',popen))
                stack.enter_context(patch.object(m.socket,'socket',side_effect=AssertionError('Unexpected socket')))
                with self.assertRaises(error):m.inner(str(root))
            row=json.loads((root/'inner-failure.json').read_text())
            self.assertTrue(row['status'].startswith('FAIL'))
            self.assertEqual(row['error_type'],error.__name__)
            self.assertFalse((root/'inner-result.json').exists())
            self.assertFalse(any(argv[0] in ('ip','nft') and argv!=['ip','-j','-d','link','show'] for argv in calls))
            return calls,spawned

    def test_unready_guard_refuses_before_mount_links_or_endpoint(self):
        calls,spawned=self.run_failure('readiness')
        self.assertEqual(calls,[]);self.assertEqual(spawned,[])

    def test_mount_early_error_or_interrupt_retains_failure(self):
        for error in (RuntimeError,KeyboardInterrupt):
            calls,spawned=self.run_failure('mount',error)
            self.assertEqual(calls[0][0],'mount');self.assertEqual(spawned,[])

    def test_sysctl_interrupt_retains_failure_before_endpoint(self):
        calls,spawned=self.run_failure('sysctl',KeyboardInterrupt)
        self.assertTrue(any(x[0]=='sysctl' for x in calls));self.assertEqual(spawned,[])

    def test_endpoint_spawn_interrupt_retains_failure_no_links_or_socket(self):
        calls,spawned=self.run_failure('endpoint',KeyboardInterrupt)
        self.assertEqual(len(spawned),1)

if __name__=='__main__':unittest.main()
