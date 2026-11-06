#!/usr/bin/env python3
"""Failure-only retention tests; no nft/kernel/socket/VM/container commands.

Actual bounded pipe pump uses small harmless Python children through an explicit
inert executable adapter; Linux pre-exec/PDEATHSIG is NOT exercised here.
"""
import ast
import base64
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
CONTROLLER=HERE/'relay-native-ci.py'
HELPER=HERE/'relay_native_diagnostics.py'
spec=importlib.util.spec_from_file_location('nft_failure_retention',HELPER)
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
NETS={'/proc/self/ns/net':'net:[101]','/proc/self/ns/mnt':'mnt:[202]'}
PAIR={'net':'net:[101]','mount':'mnt:[202]'}
TOOL={'path':'/usr/sbin/nft','sha256':'a'*64,'device':1,'inode':2}
def output(raw=b'{"nftables":[]}',stderr=b''):
    return {'stdout':raw,'stderr':stderr,'returncode':0,'stdout_eof':True,'stderr_eof':True,
            'stdout_oversize':False,'stderr_oversize':False,'failure_type':None,'failure_reason':None,
            'tool_pin':TOOL,'tool_pin_verified_after':True,'owned_child_terminal':True,
            'cleanup_errors':[],'cleanup_unconfirmed':False}
def save(root,runner=None,readlink=None):
    return d.retain_failed_inner_ruleset(root,'net:[1]','mnt:[2]','net:[101]','mnt:[202]',
        runner=runner or (lambda args:output()),namespace_readlink=readlink or dict(NETS,**{'/proc/700/ns/net':'net:[303]'}).__getitem__)

class Retention(unittest.TestCase):
    def test_exact_query_raw_bytes_and_stderr_retained_private_without_private_file_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'private-test-pki').mkdir();(root/'private-test-pki/ca.key').write_text('INERT_PRIVATE_SENTINEL')
            raw=b'{ "nftables": [ {"table":{"family":"ip","name":"aegis_rg_INERT"}} ] }\n'
            calls=[]
            def run(argv):calls.append(argv);return output(raw,b'INERT stderr')
            value=save(root,run)
            self.assertEqual(calls,[d.NFT_FAILURE_ARGV]);self.assertEqual(calls[0],('/usr/sbin/nft','-j','-n','-y','-p','list','ruleset'))
            self.assertEqual(base64.b64decode(value['stdout_base64']),raw);self.assertEqual(value['stdout_sha256'],d.sha(raw))
            self.assertEqual(bytes.fromhex(value['stderr_prefix_hex']),b'INERT stderr');self.assertTrue(value['ruleset_schema_observed'])
            self.assertFalse(value['native_accepted']);self.assertFalse(value['rule_mutation_performed']);self.assertFalse(value['host_query_performed'])
            body=(root/'inner-nft-failure.json').read_bytes();self.assertNotIn(b'INERT_PRIVATE_SENTINEL',body)
            self.assertEqual((root/'inner-nft-failure.json').stat().st_mode&0o777,0o600)
    def test_invalid_json_and_utf8_still_preserve_exact_bounded_raw_stdout(self):
        for raw in [b'not-json',b'\xff\x00not-json',b'{"nftables":[],"nftables":[]}']:
            with tempfile.TemporaryDirectory() as tmp:
                value=save(Path(tmp),lambda argv:output(raw,b'INERT stderr'))
                self.assertEqual(base64.b64decode(value['stdout_base64']),raw);self.assertFalse(value['ruleset_schema_observed'])
                self.assertIsNotNone(value['json_parse_error_type'])
    def test_host_or_foreign_namespace_refused_before_query_and_post_query_drift_not_saved(self):
        for namespaces in [{'net':'net:[1]','mount':'mnt:[202]'},{'net':'net:[101]','mount':'mnt:[2]'},{'net':'net:[303]','mount':'mnt:[202]'}]:
            with tempfile.TemporaryDirectory() as tmp:
                calls=[]
                with self.assertRaises(d.InnerNftNamespaceRefusal):save(Path(tmp),lambda args:calls.append(args),lambda path:namespaces['net' if path.endswith('/net') else 'mount'])
                self.assertEqual(calls,[])
        with tempfile.TemporaryDirectory() as tmp:
            calls=[]
            def read(path):
                calls.append(path)
                return NETS[path] if len(calls)<=2 else ('net:[303]' if path.endswith('/net') else 'mnt:[202]')
            with self.assertRaises(d.InnerNftNamespaceRefusal):save(Path(tmp),readlink=read)
            self.assertFalse((Path(tmp)/'inner-nft-failure.json').exists())
    def test_exclusive_output_and_symlink_refuse_without_query(self):
        for link in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);destination=root/'inner-nft-failure.json'
                if link:destination.symlink_to(root/'absent-INERT')
                else:destination.write_bytes(b'INERT previous failure')
                calls=[]
                with self.assertRaises(RuntimeError):save(root,lambda args:calls.append(args))
                self.assertEqual(calls,[])
                if not link:self.assertEqual(destination.read_bytes(),b'INERT previous failure')
    def test_oversized_or_untyped_adapter_metadata_refused(self):
        for key,value in [('stdout',b'x'*(d.NFT_FAILURE_STDOUT_LIMIT+1)),('stderr',b'x'*(d.STDERR_LIMIT+1)),('stdout_eof',1),('returncode',True)]:
            with tempfile.TemporaryDirectory() as tmp:
                observed=output();observed[key]=value
                with self.assertRaises(RuntimeError):save(Path(tmp),lambda args:observed)
    def pump(self,code,timeout=1,limit=4096):
        popen=subprocess.Popen
        def actual_python_only(argv,**kwargs):
            self.assertEqual(tuple(argv),d.NFT_FAILURE_ARGV)
            kwargs.pop('preexec_fn',None) # Linux-only parent-death proof explicitly unmeasured.
            return popen([sys.executable,'-c',code],**kwargs)
        with patch.object(d.sys,'platform','linux'),patch.object(d,'_nft_failure_tool_pin',lambda deadline:TOOL),patch.object(d.subprocess,'Popen',actual_python_only),patch.object(d,'NFT_FAILURE_TIMEOUT',timeout),patch.object(d,'NFT_FAILURE_STDOUT_LIMIT',limit):
            return d._bounded_failure_query(d.NFT_FAILURE_ARGV,PAIR,dict(NETS,**{'/proc/700/ns/net':'net:[303]'}).__getitem__)
    def test_actual_harmless_python_stdout_and_stderr_bounded_pump(self):
        value=self.pump("import sys;sys.stdout.buffer.write(b'{\"nftables\":[]}');sys.stderr.buffer.write(b'INERT_ERROR')")
        self.assertEqual(value['stdout'],b'{"nftables":[]}');self.assertEqual(value['stderr'],b'INERT_ERROR')
        self.assertTrue(value['stdout_eof']);self.assertTrue(value['stderr_eof']);self.assertTrue(value['owned_child_terminal'])
        self.assertIsNone(value['failure_type']);self.assertEqual(value['returncode'],0)
    def test_actual_harmless_python_oversize_and_deadline_retained_not_accepted(self):
        value=self.pump("import sys;sys.stdout.buffer.write(b'x'*10000)")
        self.assertEqual(len(value['stdout']),4096);self.assertTrue(value['stdout_oversize']);self.assertEqual(value['failure_reason'],'stdout_oversize');self.assertTrue(value['owned_child_terminal'])
        value=self.pump('import time;time.sleep(1)',timeout=0.05)
        self.assertEqual(value['failure_reason'],'deadline');self.assertTrue(value['owned_child_terminal']);self.assertIsNotNone(value['failure_type'])

    def test_group_inspection_error_or_group_signal_interrupt_still_reaps_and_closes_real_child(self):
        original_popen=subprocess.Popen
        for phase,error in [('group_identity',PermissionError('INERT')),('group_signal',KeyboardInterrupt('INERT'))]:
            children=[]
            def harmless_only(argv,**kwargs):
                self.assertEqual(tuple(argv),d.NFT_FAILURE_ARGV)
                self.assertEqual(kwargs.pop('preexec_fn').args[1],PAIR)
                child=original_popen([sys.executable,'-c','import time;time.sleep(1)'],**kwargs)
                children.append(child);return child
            with ExitStack() as patches:
                patches.enter_context(patch.object(d.sys,'platform','linux'))
                patches.enter_context(patch.object(d,'_nft_failure_tool_pin',lambda deadline:TOOL))
                patches.enter_context(patch.object(d.subprocess,'Popen',harmless_only))
                patches.enter_context(patch.object(d,'NFT_FAILURE_TIMEOUT',0.05))
                patches.enter_context(patch.object(d.os,'getpgid',side_effect=error) if phase=='group_identity' else patch.object(d.os,'getpgid',lambda pid:pid))
                if phase=='group_signal':patches.enter_context(patch.object(d.os,'killpg',side_effect=error))
                value=d._bounded_failure_query(d.NFT_FAILURE_ARGV,PAIR,dict(NETS,**{'/proc/700/ns/net':'net:[303]'}).__getitem__)
            self.assertEqual(value['failure_reason'],'deadline')
            self.assertEqual(value['failure_type'],'TimeoutError')
            self.assertIn({'phase':phase,'type':type(error).__name__},value['cleanup_errors'])
            self.assertTrue(value['owned_child_terminal']);self.assertFalse(value['cleanup_unconfirmed'])
            self.assertIsNotNone(children[0].returncode)
            self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
    def test_each_cleanup_phase_failure_keeps_original_error_and_attempts_all_other_phases(self):
        events=[]
        class Pipe:
            def __init__(self,index):self.index=index
            def fileno(self):return self.index
            def close(self):
                events.append(('close',self.index))
                if self.index==10:raise KeyboardInterrupt('INERT')
        class Child:
            pid=30001;returncode=None
            stdout=Pipe(10);stderr=Pipe(11)
            def kill(self):events.append(('kill',));raise PermissionError('INERT')
            def wait(self,timeout):events.append(('wait',timeout));raise TimeoutError('INERT')
        with patch.object(d.sys,'platform','linux'),patch.object(d,'_nft_failure_tool_pin',lambda deadline:TOOL),patch.object(d.subprocess,'Popen',lambda *args,**kwargs:Child()),patch.object(d.os,'set_blocking',lambda *args:None),patch.object(d.select,'select',side_effect=KeyboardInterrupt('INERT body')),patch.object(d.os,'getpgid',side_effect=OSError('INERT')):
            value=d._bounded_failure_query(d.NFT_FAILURE_ARGV,PAIR,dict(NETS,**{'/proc/700/ns/net':'net:[303]'}).__getitem__)
        self.assertEqual(value['failure_reason'],'interrupted');self.assertEqual(value['failure_type'],'KeyboardInterrupt')
        self.assertEqual(events,[('kill',),('wait',0.25),('close',10),('close',11)])
        self.assertTrue(value['cleanup_unconfirmed']);self.assertFalse(value['owned_child_terminal'])
        self.assertEqual([row['phase'] for row in value['cleanup_errors']],['group_identity','child_signal','child_wait','pipe_close_0'])
    def test_executing_child_checks_exact_namespace_after_parent_death_binding(self):
        class Libc:
            def prctl(self,*args):return 0
        with patch.object(d,'_FAILURE_LIBC',Libc()),patch.object(d.os,'getppid',lambda:321),patch.object(d.os,'readlink',dict(NETS,**{'/proc/700/ns/net':'net:[303]'}).__getitem__):
            d._failure_query_parent_death(321,PAIR)
            for wrong in [{'net':'net:[1]','mount':'mnt:[202]'},{'net':'net:[101]','mount':'mnt:[2]'}]:
                with self.assertRaises(RuntimeError):d._failure_query_parent_death(321,wrong)
            with self.assertRaises(RuntimeError):d._failure_query_parent_death(999,PAIR)

# Exercise actual staged inner_body()/export(), using the existing inert adapters.
LEGACY=HERE/'test-relay-native-capture-protocol-r2-inert.py'
if not LEGACY.exists():LEGACY=Path('/Users/developer/Documents/Projects/Aegis/target/worktrees/source-closeout-integration-oct03/tools/geneva/test-relay-native-capture-protocol-r2-inert.py')
spec=importlib.util.spec_from_file_location('existing_actual_inner_inert_adapter',LEGACY)
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
m=h.m;m.SELF=CONTROLLER;m.DIAGNOSTICS=HELPER;m.d=d
for node in ast.parse(CONTROLLER.read_text()).body:
    if isinstance(node,ast.FunctionDef) and node.name in ('inner_body','export'):
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(CONTROLLER),'exec'),m.__dict__)

class ActualController(unittest.TestCase):
    def actual_inner(self,failure,diagnostic_failure=False):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'fake-binary').write_bytes(b'INERT_NO_BINARY')
            a=h.Adapter(root,failure);a.setup()
            cfg=json.loads((root/'input.json').read_text());cfg.update(host_netns='net:[1]',host_mntns='mnt:[2]');(root/'input.json').write_text(json.dumps(cfg))
            def query(argv,pair,readlink):
                self.assertEqual(pair,PAIR);a.events.append(('NFT_failure_readback',))
                if diagnostic_failure:raise d.InnerNftNamespaceRefusal('INERT diagnostic namespace refusal')
                return output()
            with a.patches(),patch.object(m.os,'readlink',dict(NETS,**{'/proc/700/ns/net':'net:[303]'}).__getitem__),patch.object(d,'_bounded_failure_query',query):
                if failure:
                    with self.assertRaises(RuntimeError):m.inner(str(root))
                else:m.inner(str(root))
            files={p.name for p in root.iterdir()}
            if (root/'inner-failure.json').exists():a.retained_inner_failure=json.loads((root/'inner-failure.json').read_text())
            return a,files
    def test_actual_failed_inner_retains_before_consumer_cleanup_and_never_claims_success(self):
        a,files=self.actual_inner('capture_fail')
        self.assertIn('inner-nft-failure.json',files);self.assertNotIn('inner-result.json',files)
        query=a.events.index(('NFT_failure_readback',));kills=[i for i,e in enumerate(a.events) if e[0]=='kill']
        self.assertTrue(kills);self.assertLess(query,min(kills))
    def test_diagnostic_namespace_refusal_does_not_obscure_original_body_failure_or_cleanup(self):
        a,files=self.actual_inner('capture_fail',diagnostic_failure=True)
        self.assertEqual(a.retained_inner_failure['error_type'],'RuntimeError')
        self.assertIn({'phase':'inner_nft_failure_retention','type':'InnerNftNamespaceRefusal'},a.retained_inner_failure['diagnostic_errors'])
        self.assertNotIn('inner-result.json',files);self.assertNotIn('inner-nft-failure.json',files)
        self.assertEqual({e[1] for e in a.events if e[0]=='kill'},{'tls','peer'})
    def test_actual_successful_inner_does_not_query_or_create_failure_only_member(self):
        a,files=self.actual_inner(None)
        self.assertNotIn('inner-nft-failure.json',files);self.assertIn('inner-result.json',files)
        self.assertNotIn(('NFT_failure_readback',),a.events)
    def test_actual_export_adds_only_fixed_failure_member_and_excludes_private_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'stage';root.mkdir(mode=0o700);out=Path(tmp)/'export'
            d.write_json(root,'inner-nft-failure.json',{'INERT':True,'native_accepted':False})
            (root/'input.json').write_text('INERT private input');(root/'request-0.json').write_text('INERT private request')
            (root/'private-test-pki').mkdir();(root/'private-test-pki/ca.key').write_text('INERT private key')
            oldstat=Path.stat
            def fake_root_stat(path,*args,**kwargs):
                value=oldstat(path,*args,**kwargs)
                if path==root/'inner-nft-failure.json':
                    values=list(value);values[4]=0;return os.stat_result(values)
                return value
            with patch.object(Path,'stat',fake_root_stat):m.export(str(root),str(out))
            self.assertEqual({p.name for p in out.iterdir()},{'inner-nft-failure.json'})
            self.assertEqual((out/'inner-nft-failure.json').stat().st_mode&0o777,0o644)

if __name__=='__main__':unittest.main()
