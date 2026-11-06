#!/usr/bin/env python3
"""Repository-shape diagnostic source regressions; no kernel or network.

Small local children only emit fixed INERT bytes. Full sibling controller and
helper modules are imported from the repository, never author artifact paths.
"""
from contextlib import ExitStack
import hashlib
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bounded_native_diagnostics_test',HERE/'relay_native_diagnostics.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
source=HERE/'relay-native-ci.py'

def controller(names,common):
    spec=importlib.util.spec_from_file_location('actual_repository_native_controller_inert',source)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    value.c=common;value.require=d.require;value.d=d
    require_names=set(names)
    assert require_names <= set(value.__dict__)
    return value.__dict__

def ownfile(path,body):
    path.write_bytes(body);path.chmod(0o600)

class DiagnosticsInert(unittest.TestCase):
    def test_route_origin_failure_header_metadata_is_retained_as_failure_only(self):
        with tempfile.TemporaryDirectory(prefix='AEGIS_INERT_ROUTE_ORIGIN_') as directory:
            root=Path(directory);instance=root/'12345678';instance.mkdir(mode=0o700)
            value={'group_mask':1,'required_group_mask':4,'headers':[{'type':16,'candidate_ifindex':7}],
                   'headers_complete':True,'origin_accepted':False,'raw_body_retained':False}
            body=json.dumps(value,separators=(',',':')).encode()
            ownfile(instance/'00000000_route_notification_refused.json',body)
            retained=d.journal_snapshot(root)
            self.assertEqual(retained['entries'][0]['value'],value)
            self.assertEqual(retained['entries'][0]['sha256'],hashlib.sha256(body).hexdigest())
            self.assertFalse(retained['entries'][0]['value']['origin_accepted'])

    def test_route_origin_failure_allowlist_does_not_accept_unknown_or_private_member(self):
        with tempfile.TemporaryDirectory(prefix='AEGIS_INERT_ROUTE_UNKNOWN_') as directory:
            root=Path(directory);instance=root/'12345678';instance.mkdir(mode=0o700)
            ownfile(instance/'00000000_route_notification_refused.json',b'{"headers_complete":false,"origin_accepted":false}')
            ownfile(instance/'00000001_route_body_private.json',b'{"raw":"INERT_DO_NOT_EXPORT"}')
            with self.assertRaises(RuntimeError):d.journal_snapshot(root)


    def test_real_child_early_failure_retains_actual_stderr_and_exit(self):
        with tempfile.TemporaryDirectory(prefix='AEGIS_INERT_STDERR_') as directory:
            proc=subprocess.Popen([sys.executable,'-c',"import os,sys;os.write(2,b'INERT_PROBE_NATIVE_ERROR\\n');sys.exit(7)"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            proc.wait(timeout=3)
            result=d.retain_process_stderr(Path(directory),proc,'probe-0')
            proc.stdout.close()
            self.assertEqual(result['exit_code'],7);self.assertTrue(result['complete'])
            self.assertEqual((Path(directory)/'probe-0.stderr').read_bytes(),b'INERT_PROBE_NATIVE_ERROR\n')
            self.assertEqual((Path(directory)/'probe-0.stderr').stat().st_mode & 0o777,0o600)

    def test_real_small_oversize_child_retention_bounded_and_explicitly_incomplete(self):
        with tempfile.TemporaryDirectory(prefix='AEGIS_INERT_OVERSIZE_') as directory, tempfile.TemporaryFile() as stderr:
            proc=subprocess.Popen([sys.executable,'-c',"import os;os.write(2,b'I'*70000)"],stderr=stderr)
            proc.wait(timeout=3);stderr.seek(0);proc.stderr=stderr
            requests=[];actual=os.read
            def bounded(fd,count):requests.append(count);return actual(fd,count)
            with patch.object(d.os,'read',side_effect=bounded):result=d.retain_process_stderr(Path(directory),proc,'peer')
            self.assertTrue(result['truncated_oversize']);self.assertFalse(result['complete'])
            self.assertEqual(result['bytes'],65536);self.assertLessEqual(sum(requests),65537)

    def test_live_consumer_refused_without_signaling_or_overwriting(self):
        with tempfile.TemporaryDirectory(prefix='AEGIS_INERT_REFUSAL_') as directory:
            fake=SimpleNamespace(poll=lambda:None,stderr=io.BytesIO(b'INERT'))
            with self.assertRaises(RuntimeError):d.retain_process_stderr(Path(directory),fake,'probe-0')
            self.assertEqual(list(Path(directory).iterdir()),[])
            ownfile(Path(directory)/'peer.stderr',b'RETAINED INERT FIRST ATTEMPT')
            with self.assertRaises(FileExistsError):d.write_exclusive(Path(directory),'peer.stderr',b'NEW')
            self.assertEqual((Path(directory)/'peer.stderr').read_bytes(),b'RETAINED INERT FIRST ATTEMPT')

    def test_real_existing_communicate_failure_retains_stderr_before_closed_pipe(self):
        with tempfile.TemporaryDirectory(prefix='AEGIS_INERT_COMPLETE_CHILD_') as directory:
            proc=subprocess.Popen([sys.executable,'-c',"import os,sys;os.write(2,b'INERT_LATE_ERROR');sys.exit(8)"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            _,stderr=proc.communicate(timeout=3)
            self.assertTrue(proc.stderr.closed)
            result=d.retain_completed_stderr(Path(directory),'probe-1',stderr,proc.returncode)
            self.assertTrue(result['complete']);self.assertEqual(result['exit_code'],8)
            self.assertEqual((Path(directory)/'probe-1.stderr').read_bytes(),b'INERT_LATE_ERROR')

    def test_owned_journals_retain_failure_before_namespace_teardown(self):
        with tempfile.TemporaryDirectory(prefix='AEGIS_INERT_JOURNAL_') as directory:
            root=Path(directory);instance=root/'12345678';instance.mkdir(mode=0o700)
            body=b'{"reason":"INERT_NFT_FAILURE","kind":"Other"}'
            ownfile(instance/'00000000_setup_failed.json',body)
            result=d.journal_snapshot(root)
            self.assertEqual(result['entries'][0]['value']['reason'],'INERT_NFT_FAILURE')
            self.assertEqual(result['entries'][0]['sha256'],hashlib.sha256(body).hexdigest())

    def test_journal_symlink_foreign_inventory_and_oversize_refused(self):
        for failure in ('symlink','unknown','oversize','duplicate','instance_limit'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory(prefix='AEGIS_INERT_BAD_JOURNAL_') as directory:
                root=Path(directory);instance=root/'12345678';instance.mkdir(mode=0o700)
                path=instance/'00000000_setup_failed.json'
                if failure=='symlink':path.symlink_to(root/'ABSENT_INERT')
                elif failure=='unknown':ownfile(instance/'private-test-key.pem',b'INERT_DO_NOT_EXPORT')
                elif failure=='oversize':ownfile(path,b'I'*65537)
                elif failure=='duplicate':ownfile(path,b'{"kind":1,"kind":2}')
                else:
                    for name in ('12345679','1234567a','1234567b'):(root/name).mkdir(mode=0o700)
                with self.assertRaises((RuntimeError,OSError)):d.journal_snapshot(root)

    def test_host_diagnostics_preserve_counter_vs_rule_diff_without_acceptance_normalization(self):
        with tempfile.TemporaryDirectory(prefix='AEGIS_INERT_HOST_') as directory:
            root=Path(directory);before_ip=b'[{"ifname":"lo"}]'
            before_nft=b'{"nftables":[{"rule":{"expr":[{"counter":{"packets":0,"bytes":0}},{"drop":null}]}}]}'
            after_nft=before_nft.replace(b'"packets":0',b'"packets":1')
            d.public_host_snapshot(root,'before',before_ip,before_nft)
            d.public_host_snapshot(root,'after',before_ip,after_nft)
            difference=d.host_difference(before_ip,before_nft,before_ip,after_nft)
            self.assertFalse(difference['exact_raw_nft_equal']);self.assertFalse(difference['acceptance_normalization_performed'])
            self.assertEqual(difference['changed_JSON_paths'],['/nft/nftables/0/rule/expr/0/counter/packets'])
            changed=after_nft.replace(b'"drop":null',b'"accept":null')
            self.assertTrue(any('/accept' in p or '/drop' in p for p in d.host_difference(before_ip,before_nft,before_ip,changed)['changed_JSON_paths']))

    def test_actual_export_exact_flat_allowlist_omits_PKI_requests_and_secret_files(self):
        for route in ('native-lstat','stat-forwarding-lstat'):
            with self.subTest(route=route),tempfile.TemporaryDirectory(prefix='AEGIS_INERT_EXPORT_') as directory:
                root=Path(directory)/'stage';root.mkdir(mode=0o700);out=Path(directory)/'new-export'
                for name in ('receipt.json','probe-0.stderr','probe-0-diagnostic.json','native-journals-failure.json','host-difference.json'):
                    ownfile(root/name,b'{}')
                for name in ('request-0.json','input.json','secret.pem'):ownfile(root/name,b'INERT_NOT_EXPORTED')
                (root/'private-test-pki').mkdir(mode=0o700);ownfile(root/'private-test-pki'/'leaf.key',b'INERT_NOT_EXPORTED')
                values=controller({'export'},SimpleNamespace())
                # Current platform UID is adapted only for this pure exporter test.
                realstat=Path.stat
                def owned_stat(path,*args,**kwargs):
                    value=realstat(path,*args,**kwargs)
                    if path.parent==root:
                        fields={name:getattr(value,name) for name in dir(value) if name.startswith('st_')}
                        fields['st_uid']=0
                        return SimpleNamespace(**fields)
                    return value
                with ExitStack() as patches:
                    patches.enter_context(patch.object(Path,'stat',owned_stat))
                    if route=='stat-forwarding-lstat':
                        patches.enter_context(patch.object(Path,'lstat',lambda path:path.stat(follow_symlinks=False)))
                    values['export'](str(root),str(out))
                self.assertEqual({p.name for p in out.iterdir()},{'receipt.json','probe-0.stderr','probe-0-diagnostic.json','native-journals-failure.json','host-difference.json'})
                self.assertEqual(out.stat().st_mode & 0o777,0o755)

    def test_actual_export_refuses_dangling_symlink_and_bad_command_inventory(self):
        for failure in ('symlink','inventory'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory(prefix='AEGIS_INERT_REFUSE_EXPORT_') as directory:
                root=Path(directory)/'stage';root.mkdir(mode=0o700);out=Path(directory)/'export'
                if failure=='symlink':(root/'probe-0.stderr').symlink_to(root/'ABSENT_INERT')
                else:ownfile(root/'command-failure-secret.json',b'{}')
                values=controller({'export'},SimpleNamespace())
                with self.assertRaises(RuntimeError):values['export'](str(root),str(out))
                self.assertEqual(list(out.iterdir()),[])

    def test_actual_inner_early_probe_failure_retains_real_stderr_and_journal_and_cleans_peer(self):
        with tempfile.TemporaryDirectory(prefix='AEGIS_INERT_ACTUAL_INNER_') as directory:
            root=Path(directory);journal=root/'native';journal.mkdir(mode=0o700)
            instance=journal/'12345678';instance.mkdir(mode=0o700)
            ownfile(instance/'00000000_setup_failed.json',b'{"reason":"INERT_CAUSE"}')
            ownfile(root/'input.json',json.dumps({'tool_sha256':'INERT','common_sha256':'INERT','observer_sha256':'INERT','diagnostics_sha256':'INERT','host_netns':'net:[1]','host_mntns':'mnt:[2]','binary':'INERT_PROBE','binary_sha256':'INERT','source':'INERT_SOURCE','pki':str(root/'INERT_NOT_REAL_PKI')}).encode())
            identity=lambda pid:{'pid':pid}
            ownfile(root/'watchdog-ready.json',json.dumps({'child':identity(os.getpid()),'tool_sha256':'INERT','watchdog':identity(799),'deadline':time.monotonic()+120}).encode())
            def exclusive(path,value):ownfile(path,json.dumps(value).encode())
            lo={'ifindex':1,'ifname':'lo','address':'00:00:00:00:00:00','link_type':'loopback'}
            client={'ifindex':2,'ifname':'client0','address':'02:00:00:00:00:02','link_type':'ether','link_index':3,'linkinfo':{'info_kind':'veth'}}
            relay={'ifindex':3,'ifname':'relay0','address':'02:00:00:00:00:03','link_type':'ether','link_index':2,'linkinfo':{'info_kind':'veth'}}
            link_reads=iter([[lo],[lo,client]])
            def command(args,**kwargs):
                return json.dumps(next(link_reads)).encode() if args==['ip','-j','-d','link','show'] else b''
            common=SimpleNamespace(FAILURE_ROOT=None,digest=lambda _: 'INERT',identity=identity,same_process=lambda _:True,exclusive=exclusive,die_with_parent=lambda _:None,command=command,rpc=lambda *_args:{'ok':True,'links':[lo,relay]})
            processes=[]
            class Peer:
                pid=799;returncode=None
                def __init__(self):self.stderr=tempfile.TemporaryFile()
                def poll(self):return self.returncode
                def kill(self):self.returncode=-9
                def wait(self,timeout=None):return self.returncode
            def popen(args,**kwargs):
                if 'peer' in args:proc=Peer()
                else:proc=subprocess.Popen([sys.executable,'-c',"import os,sys;os.write(2,b'INERT_EARLY_REAL_PROCESS_ERROR\\n');sys.exit(9)"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                processes.append(proc)
                self.addCleanup(proc.stderr.close)
                if hasattr(proc,'stdout'):self.addCleanup(proc.stdout.close)
                return proc
            def read_line(proc,_until):
                if isinstance(proc,Peer):return json.dumps({'ok':True,'pid':proc.pid,'namespace':'net:[303]','links':[lo]})
                proc.wait(timeout=3)
                self.assertEqual(proc.stdout.readline(),b'')
                raise RuntimeError('child exited before response')
            common.read_line=read_line
            values=controller({'inner','inner_body'},common)
            values['subprocess']=SimpleNamespace(Popen=popen,PIPE=subprocess.PIPE)
            values['functools']=__import__('functools')
            realread=Path.read_bytes;realjournal=d.journal_snapshot
            def read(path):return b'1\n' if str(path).startswith('/proc/sys/net/ipv4/conf/') else realread(path)
            namespaces={'/proc/self/ns/net':'net:[101]','/proc/self/ns/mnt':'mnt:[202]','/proc/799/ns/net':'net:[303]'}
            queries=[]
            nft_raw=b'{ "nftables": [] }\n'
            def inert_fixed_readonly_query(argv,pair,readlink):
                self.assertEqual(argv,('/usr/sbin/nft','-j','-n','-y','-p','list','ruleset'))
                self.assertEqual(pair,{'net':'net:[101]','mount':'mnt:[202]'})
                self.assertEqual({key:readlink(path) for key,path in [('net','/proc/self/ns/net'),('mount','/proc/self/ns/mnt')]},pair)
                queries.append((argv,pair))
                return {'stdout':nft_raw,'stderr':b'INERT_READONLY_DIAGNOSTIC','returncode':0,
                        'stdout_eof':True,'stderr_eof':True,'stdout_oversize':False,'stderr_oversize':False,
                        'failure_type':None,'failure_reason':None,'tool_pin':{'path':'/usr/sbin/nft','sha256':'a'*64,'device':1,'inode':2},
                        'tool_pin_verified_after':True,'owned_child_terminal':True,'cleanup_errors':[],'cleanup_unconfirmed':False}
            with patch.object(os,'readlink',side_effect=namespaces.__getitem__),patch.object(d,'_bounded_failure_query',side_effect=inert_fixed_readonly_query),patch.object(os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)),patch.object(Path,'read_bytes',side_effect=None,autospec=True) as reader,patch.object(d,'journal_snapshot',side_effect=lambda _:realjournal(journal)):
                reader.side_effect=read
                with self.assertRaisesRegex(RuntimeError,'child exited'):values['inner'](str(root))
            self.assertEqual((root/'probe-0.stderr').read_bytes(),b'INERT_EARLY_REAL_PROCESS_ERROR\n')
            self.assertEqual(json.loads((root/'probe-0-diagnostic.json').read_bytes())['exit_code'],9)
            self.assertEqual(json.loads((root/'native-journals-failure.json').read_bytes())['entries'][0]['value']['reason'],'INERT_CAUSE')
            failed=json.loads((root/'inner-failure.json').read_bytes())
            self.assertEqual(failed['diagnostic_errors'],[])
            self.assertEqual(failed['error_type'],'RuntimeError')
            self.assertEqual(len(queries),1)
            nft=json.loads((root/'inner-nft-failure.json').read_bytes())
            self.assertEqual(base64.b64decode(nft['stdout_base64']),nft_raw)
            self.assertEqual(nft['stdout_sha256'],hashlib.sha256(nft_raw).hexdigest())
            self.assertEqual(bytes.fromhex(nft['stderr_prefix_hex']),b'INERT_READONLY_DIAGNOSTIC')
            self.assertFalse(nft['native_accepted']);self.assertFalse(nft['rule_mutation_performed']);self.assertFalse(nft['host_query_performed'])
            self.assertEqual(nft['namespace'],{'net':'net:[101]','mount':'mnt:[202]'})
            self.assertEqual((root/'inner-nft-failure.json').stat().st_mode&0o777,0o600)
            self.assertTrue(processes[0].stderr.closed)
            self.assertFalse((root/'inner-result.json').exists());self.assertEqual(processes[0].poll(),-9)
            processes[-1].stdout.close()

if __name__=='__main__':unittest.main()
