#!/usr/bin/env python3
"""Actual inner() protocol tests using only inert OS/socket/process adapters.
Temporary synthetic receipts are never exported as runtime evidence.
"""
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('relay_capture_protocol_inert',HERE/'relay-native-ci.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

LO={'ifindex':1,'ifname':'lo','address':'00:00:00:00:00:00','link_type':'loopback'}
CLIENT={'ifindex':2,'ifname':'client0','address':'02:00:00:00:00:02','link_type':'ether','link_index':3,'linkinfo':{'info_kind':'veth'}}
RELAY={'ifindex':3,'ifname':'relay0','address':'02:00:00:00:00:03','link_type':'ether','link_index':2,'linkinfo':{'info_kind':'veth'}}

class Adapter:
    def __init__(self,root,failure=None):
        self.root=root;self.failure=failure;self.events=[];self.processes=[];self.current=None;self.completed=0;self.links_ready=False;self.peer_reaped=False;self.client_deleted=False
    def identity(self,pid):return {'pid':pid,'start':'INERT_START','group':pid,'argv':'INERT_ARGS','exe':'INERT_EXE'}
    def command(self,args,**kwargs):
        self.events.append(('command',args[0]))
        if args==['ip','link','add','client0','address','02:00:00:00:00:02','type','veth','peer','name','relay0','address','02:00:00:00:00:03']:self.links_ready=True
        if args==['ip','-j','-d','link','show']:
            self.events.append(('topology_read',self.peer_reaped))
            if not self.links_ready or self.client_deleted or(self.peer_reaped and self.failure not in ('cleanup_present','cleanup_delete_failed','cleanup_foreign')):return json.dumps([LO]).encode()
            client=dict(CLIENT)
            if self.peer_reaped and self.failure=='cleanup_foreign':client['ifindex']=9
            return json.dumps([LO,client]).encode()
        if args==['ip','link','delete','client0']:
            self.events.append(('delete_client',))
            if self.failure=='cleanup_delete_failed' or(self.peer_reaped and self.failure!='cleanup_present'):raise RuntimeError('INERT exact delete failed or missing client0')
            self.client_deleted=True
        if args[:4]==['ip','-j','link','show']:
            live=self.current is not None and not self.current.terminal
            return json.dumps([{'ifname':'agv12345678'}] if live else []).encode()
        if args[0]=='nft':return b'{"nftables":[]}'
        return b''
    def popen(self,args,**kwargs):
        a=self;peer='peer' in args
        class Input:
            def write(self,data):a.events.append(('write',a.current.mode if a.current else 'peer',data))
            def flush(self):pass
        class Process:
            pid=700 if peer else 701+len(a.processes)
            returncode=None;terminal=False;reads=0
            stdin=Input()
            mode='peer' if peer else args[-1]
            def poll(self):return self.returncode
            def kill(self):a.events.append(('kill',self.mode));self.returncode=-9
            def wait(self,timeout=None):a.events.append(('wait',self.mode));return self.returncode
            def communicate(self,timeout=None):
                self.returncode=0
                if self.mode=='peer':a.peer_reaped=True;a.events.append(('peer_reaped',))
                return b'',b''
        obj=Process();self.processes.append(obj)
        if not peer:self.current=obj
        return obj
    def read_line(self,proc,deadline):
        if proc.mode=='peer':return json.dumps({'ok':True,'pid':proc.pid,'namespace':'net:[303]','links':[LO]})
        proc.reads+=1;self.events.append(('read',proc.mode,proc.reads))
        if proc.reads==1:return json.dumps({'phase':'ready','source':'INERT_SOURCE','fallback_dials':0})
        if proc.reads==2:return json.dumps({'phase':'transfer_complete','tun_still_owned':True})
        if proc.reads!=3:raise AssertionError('unexpected read count')
        self.events.append(('terminal',proc.mode));proc.terminal=True
        op={'fallback_dials':0,'worker_healthy_before_quiesce':True,'native_packet_counters':{'outbound_batches':3,'outbound_empty_batches':0,'outbound_emitted_frames':3,'inbound_emitted_frames':3}}
        if proc.mode=='drop':
            op.update(selected_connection_refused=True,actual_program_drop_acknowledged=True)
            op['native_packet_counters']={'outbound_batches':3,'outbound_empty_batches':3,'outbound_emitted_frames':0,'inbound_emitted_frames':0}
            if self.failure=='drop_without_ack':op['actual_program_drop_acknowledged']=False
            if self.failure=='drop_no_empty_batch':op['native_packet_counters']['outbound_empty_batches']=0
            if self.failure=='drop_nonempty_batch':op['native_packet_counters']['outbound_batches']=4
            if self.failure=='drop_emitted_frame':op['native_packet_counters']['outbound_emitted_frames']=1
        else:
            op.update(strict_local_CA_name_TLS13_echo=True,encrypted_echo_bytes=len(m.MARKER) if proc.mode=='tls' else 65536)
        if self.failure=='unhealthy_worker':op['worker_healthy_before_quiesce']=False
        return json.dumps({'phase':'terminal','owned_runtime_quiesced':True,'operation':op})
    def packet(self,inbound=False,ttl=64):
        return {'src':'192.0.2.3' if inbound else '192.0.2.2','dst':'192.0.2.2' if inbound else '192.0.2.3',
                'sport':24443 if inbound else 12345,'dport':12345 if inbound else 24443,'flags':0x12 if inbound else 2,'ttl':ttl,'seq':100,'clear_marker_present':False}
    def capture(self,interface,ethernet=True,**kwargs):
        a=self
        class Capture:
            stops=0
            def stop(self):
                self.stops+=1;a.events.append(('stop_TUN',a.current.mode,self.stops))
                if a.failure=='capture_interrupt' and self.stops==1:raise KeyboardInterrupt('INERT_CAPTURE_INTERRUPT')
                clean=not(a.failure=='capture_fail' and self.stops==1)
                rows=[] if a.current.mode=='drop' else [a.packet(True,63),a.packet(True,64)]
                return {'clean':clean,'kernel_counter_matches_received':clean,'thread_terminal_confirmed':True,'owned_fd_closed':True,'records':rows}
        return Capture()
    def rpc(self,proc,value):
        self.events.append(('rpc',value['op']))
        if value['op']=='observe':
            if self.failure=='physical_fail':raise RuntimeError('INERT_PHYSICAL_CAPTURE_FAILURE')
            if self.current.mode!='drop':self.completed+=1
            size=len(m.MARKER) if self.completed==1 else 65536
            answers=[{'bytes':len(m.MARKER)}] if self.completed==1 else [{'bytes':len(m.MARKER)},{'bytes':65536}]
            return {'errors':[],'packets':[] if self.current.mode=='drop' else [self.packet(False,64),self.packet(False,63)],'TLS_echoes':answers,'capture':{'clean':True}}
        if value['op']=='open':return {'ok':True,'links':[LO,RELAY]}
        if value['op']=='exit':return {'ok':True,'pid':proc.pid,'namespace':'net:[303]','links':[LO,RELAY],
                                     'tls_worker_joined':True,'physical_capture_closed':True,'errors':[]}
        raise AssertionError('unexpected RPC')
    def setup(self):
        cfg={'tool_sha256':m.c.digest(m.SELF),'common_sha256':m.c.digest(m.COMMON),'observer_sha256':m.c.digest(m.OBSERVER),
             'diagnostics_sha256':m.c.digest(m.DIAGNOSTICS),
             'host_netns':'INERT_HOST_NET','host_mntns':'INERT_HOST_MNT','binary':str(self.root/'fake-binary'),
             'binary_sha256':m.c.digest(self.root/'fake-binary'),'source':'INERT_SOURCE','pki':str(self.root/'pki')}
        journal=self.root/'journal-INERT';journal.mkdir()
        instance=journal/'instance-INERT';instance.mkdir()
        name='000001_worker_terminal.json';value={'runtime_fault':False,'requested_stop':True}
        if self.failure=='journal_runtime_fault_filename':name='000001_runtime_fault.json';value={'cause':'INERT_METADATA_ONLY'}
        if self.failure=='journal_worker_failed_filename':name='000001_worker_failed.json';value={'cause':'INERT_METADATA_ONLY'}
        if self.failure=='journal_terminal_fault':value={'runtime_fault':True,'requested_stop':False}
        (instance/name).write_text(json.dumps(value))
        (self.root/'input.json').write_text(json.dumps(cfg))
        ready={'child':self.identity(os.getpid()),'tool_sha256':m.c.digest(m.SELF),'watchdog':self.identity(799),'deadline':time.monotonic()+120}
        (self.root/'watchdog-ready.json').write_text(json.dumps(ready))
    def patches(self):
        s=ExitStack();oldread=Path.read_bytes;olditer=Path.iterdir
        def read(path):
            if str(path).startswith('/proc/sys/net/ipv4/conf/'):return b'1\n'
            return oldread(path)
        def iterate(path):
            if str(path)=='/run/aegis-relay-geneva':return olditer(self.root/'journal-INERT')
            return olditer(path)
        for owner,name,value in [(m.c,'identity',self.identity),(m.c,'same_process',lambda x:True),
            (m.c,'command',self.command),(m.c,'read_line',self.read_line),(m.c,'rpc',self.rpc),
            (m.os,'readlink',lambda x:{'/proc/self/ns/net':'net:[101]','/proc/self/ns/mnt':'mnt:[202]','/proc/700/ns/net':'net:[303]'}[x]),
            (m.os,'statvfs',lambda x:SimpleNamespace(f_flag=os.ST_RDONLY)),
            (m.subprocess,'Popen',self.popen),(m,'start_capture',self.capture),
            (m.d,'retain_process_stderr',lambda *args:{'scope':'INERT_TERMINAL_FAKE_CONSUMER_NO_FD'}),
            (m.d,'journal_snapshot',lambda path:{'entries':[],'directory_observed':False,'complete':True,'scope':'INERT_NO_HOST_JOURNAL_READ'}),
            (Path,'read_bytes',read),(Path,'iterdir',iterate)]:s.enter_context(patch.object(owner,name,value))
        s.enter_context(patch.object(m.socket,'socket',side_effect=AssertionError('Unexpected real socket')))
        s.enter_context(patch.object(m.os,'killpg',side_effect=AssertionError('Unexpected actual signal')))
        return s

class ActualInnerProtocol(unittest.TestCase):
    def execute(self,failure=None):
        with tempfile.TemporaryDirectory(prefix='aegis-capture-INERT-') as td:
            root=Path(td);(root/'fake-binary').write_bytes(b'INERT_NOT_EXECUTABLE');a=Adapter(root,failure);a.setup()
            with a.patches():
                if failure and failure!='cleanup_present':
                    with self.assertRaises(KeyboardInterrupt if failure=='capture_interrupt' else RuntimeError):m.inner(str(root))
                else:m.inner(str(root))
            result=json.loads((root/('inner-failure.json' if failure and failure!='cleanup_present' else 'inner-result.json')).read_text())
            capture=json.loads((root/'capture-failure.json').read_text()) if (root/'capture-failure.json').exists() else None
            self.assertFalse((root/'inner-result.json').exists()) if failure and failure!='cleanup_present' else self.assertEqual(len(result['rows']),3)
            return a,result,capture
    def test_three_modes_close_capture_before_permit_before_terminal(self):
        a,row,_=self.execute()
        for mode in ('tls','tls-transfer','drop'):
            stop=a.events.index(('stop_TUN',mode,1));permit=a.events.index(('write',mode,b'capture_closed\n'));terminal=a.events.index(('terminal',mode))
            self.assertLess(stop,permit);self.assertLess(permit,terminal)
            self.assertTrue(row['rows'][('tls','tls-transfer','drop').index(mode)]['capture_closed_before_TUN_teardown'])
        self.assertFalse(row['target_network']);self.assertFalse(row['independent_capture']);self.assertFalse(row['final_signed_client'])
    def test_capture_failure_prevents_permit_and_cleans_both_consumers(self):
        a,_,capture=self.execute('capture_fail')
        self.assertFalse(any(e[0]=='terminal' or(e[0]=='write' and e[2]==b'capture_closed\n') for e in a.events))
        self.assertEqual({e[1] for e in a.events if e[0]=='kill'},{'tls','peer'})
        self.assertIsNotNone(capture)
    def test_physical_failure_after_TUN_stop_prevents_permit_and_cleans(self):
        a,_,_=self.execute('physical_fail')
        self.assertIn(('stop_TUN','tls',1),a.events)
        self.assertFalse(any(e[0]=='terminal' or(e[0]=='write' and e[2]==b'capture_closed\n') for e in a.events))
        self.assertEqual({e[1] for e in a.events if e[0]=='kill'},{'tls','peer'})
    def test_connection_refusal_without_actual_drop_ack_or_empty_batch_is_refused(self):
        for failure in ('drop_without_ack','drop_no_empty_batch','drop_nonempty_batch','drop_emitted_frame'):
            with self.subTest(failure=failure):
                a,row,_=self.execute(failure)
                self.assertEqual(row['status'],'FAIL_NATIVE_RELAY_ATTEMPT_RETAINED')
                self.assertIn(('terminal','drop'),a.events)
    def test_unhealthy_worker_does_not_pass_even_if_tls_echo_and_capture_succeed(self):
        a,row,_=self.execute('unhealthy_worker')
        self.assertEqual(row['status'],'FAIL_NATIVE_RELAY_ATTEMPT_RETAINED')
        self.assertIn(('terminal','tls'),a.events)
    def test_runtime_fault_and_worker_failed_journal_filename_refused_without_phase_field(self):
        for failure in ('journal_runtime_fault_filename','journal_worker_failed_filename'):
            with self.subTest(failure=failure):
                a,row,_=self.execute(failure)
                self.assertEqual(row['status'],'FAIL_NATIVE_RELAY_ATTEMPT_RETAINED')
                self.assertEqual(sum(e[0]=='terminal' for e in a.events),3)
    def test_worker_terminal_runtime_fault_true_refused(self):
        _,row,_=self.execute('journal_terminal_fault')
        self.assertEqual(row['status'],'FAIL_NATIVE_RELAY_ATTEMPT_RETAINED')
    def test_normal_requested_stop_journal_stays_accepted(self):
        _,row,_=self.execute()
        self.assertEqual(row['status'],'PASS_CONTROLLED_RELAY_GENEVA_TLS_DUPLICATION_DROP_AND_CLEANUP')
    def test_capture_interrupt_retained_and_consumer_cleanup_runs(self):
        a,row,_=self.execute('capture_interrupt')
        self.assertEqual(row['error_type'],'KeyboardInterrupt')
        self.assertFalse(any(e[0]=='terminal' or(e[0]=='write' and e[2]==b'capture_closed\n') for e in a.events))
        self.assertEqual({e[1] for e in a.events if e[0]=='kill'},{'tls','peer'})

    def test_exact_peer_reap_removes_veth_without_blind_missing_delete(self):
        a,row,_=self.execute()
        self.assertEqual(sum(e[0]=='terminal' for e in a.events),3)
        self.assertIn(('peer_reaped',),a.events)
        self.assertNotIn(('delete_client',),a.events)
        reads=[i for i,e in enumerate(a.events) if e==('topology_read',True)]
        self.assertEqual(len(reads),2);self.assertLess(a.events.index(('peer_reaped',)),min(reads))
        self.assertTrue(row['owned_namespace_topology_removed'])
    def test_exact_present_link_deleted_but_foreign_or_failed_delete_refused_after_all_loops(self):
        a,row,_=self.execute('cleanup_present')
        self.assertTrue(row['owned_namespace_topology_removed']);self.assertIn(('delete_client',),a.events)
        for failure in ('cleanup_foreign','cleanup_delete_failed'):
            with self.subTest(failure=failure):
                a,row,_=self.execute(failure)
                self.assertEqual(sum(e[0]=='terminal' for e in a.events),3)
                self.assertEqual(row['status'],'FAIL_NATIVE_RELAY_ATTEMPT_RETAINED')
                retained=row['completed_loop_diagnostics']
                self.assertEqual([v['mode'] for v in retained['completed_scenarios']],['tls','tls-transfer','drop'])
                self.assertIs(retained['runtime_acceptance'],False)
                self.assertEqual(('delete_client',) in a.events,failure=='cleanup_delete_failed')

if __name__=='__main__':unittest.main()
