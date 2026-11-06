"""Actual prepared native controller pure/temporary-file contracts. No sockets."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('relay_native_controller',HERE/'relay-native-ci.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class MetadataContracts(unittest.TestCase):
    def test_actual_frame_and_raw_TUN_metadata_match(self):
        frame=m.c.frame();physical=m.packet_metadata(frame);tun=m.packet_metadata(frame[14:],False)
        for key in ('src','dst','sport','dport','seq','flags','ttl','clear_marker_present'):
            self.assertEqual(physical[key],tun[key])
        self.assertFalse(physical['clear_marker_present'])

    def test_clear_marker_detection_and_corrupt_IHL_refusal(self):
        frame=bytearray(m.c.frame());frame[-16:]=m.MARKER
        self.assertTrue(m.packet_metadata(frame)['clear_marker_present'])
        frame[14]=0x4f
        with self.assertRaises(RuntimeError):m.packet_metadata(frame[:54])

    def test_non_TCP_or_non_IP_not_claimed_as_native_evidence(self):
        frame=bytearray(m.c.frame());frame[23]=17
        self.assertIsNone(m.packet_metadata(frame))
        self.assertIsNone(m.packet_metadata(b'not a frame'))

    def test_real_drain_bounds_packet_metadata(self):
        class Socket:
            def recv(self,size):return m.c.frame()
        with patch.object(m.select,'select',return_value=([object()],[],[])):
            with self.assertRaises(RuntimeError):m.drain(Socket())

class CleanupContracts(unittest.TestCase):
    def test_partial_test_PKI_removed_after_creation_failure(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/'private-test-pki';folder.mkdir(mode=0o700)
            (folder/'ca.key').write_bytes(b'synthetic fixture, never a real credential')
            m.remove_test_pki(folder);self.assertFalse(folder.exists())

    def test_unexpected_or_symlink_member_never_deleted(self):
        for variant in ('foreign','symlink'):
            with tempfile.TemporaryDirectory() as td:
                folder=Path(td)/'private-test-pki';folder.mkdir(mode=0o700)
                key=folder/'ca.key';key.write_bytes(b'synthetic fixture')
                if variant=='foreign':(folder/'unowned.data').write_bytes(b'foreign')
                else:(folder/'leaf.key').symlink_to(key)
                with self.assertRaises(RuntimeError):m.remove_test_pki(folder)
                self.assertTrue(key.exists())

    def test_export_actual_allowlist_excludes_keys_frames_binaries_source(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'stage';root.mkdir(mode=0o700);out=Path(td)/'export'
            (root/'receipt.json').write_bytes(b'{"status":"synthetic"}')
            for name in ('ca.key','probe','input.json','captured-frames.json','controller.py'):
                (root/name).write_bytes(b'must never be exported')
            original=Path.stat
            def root_stat(path,*args,**kwargs):
                value=list(original(path,*args,**kwargs));value[4]=0
                return os.stat_result(value)
            with patch.object(Path,'stat',root_stat):m.export(str(root),str(out))
            self.assertEqual([p.name for p in out.iterdir()],['receipt.json'])



# Inert exact source helpers; no kernel, namespace, ip or socket execution.
import ast, copy, json, re
from types import SimpleNamespace
d=m.d
ROOT=HERE
NAMES={'link_snapshot','link_identity','topology_identity','owned_pair_identity','cleanup_peer_topology','completed_scenario_diagnostics'}
source=(HERE/'relay-native-ci.py').read_text();tree=ast.parse(source)
helpers=ast.Module(body=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in NAMES],type_ignores=[])
assert len(helpers.body)==len(NAMES)
LO={'ifindex':1,'ifname':'lo','address':'00:00:00:00:00:00','link_type':'loopback'}
CLIENT={'ifindex':2,'ifname':'client0','address':'02:00:00:00:00:02','link_type':'ether','link_index':3,'linkinfo':{'info_kind':'veth'}}
RELAY={'ifindex':3,'ifname':'relay0','address':'02:00:00:00:00:03','link_type':'ether','link_index':2,'linkinfo':{'info_kind':'veth'}}
class Harness:
    def __init__(self,states,delete_error=None):
        self.states=copy.deepcopy(states);self.calls=[];self.delete_error=delete_error
        self.endpoint=SimpleNamespace(pid=123,returncode=0,poll=lambda:0)
        self.namespace='net:[71]';self.peer_namespace='net:[72]'
        self.env={'require':d.require,'d':d,'c':SimpleNamespace(command=self.command),
                  'os':SimpleNamespace(readlink=lambda _:self.namespace),'re':re}
        exec(compile(helpers,str(ROOT/'relay-native-ci.py'),'exec'),self.env)
        local_lo=self.env['topology_identity']([LO],('lo',))['lo']
        peer_lo=self.env['topology_identity']([LO],('lo',))['lo']
        self.local,self.peer=self.env['owned_pair_identity']([LO,CLIENT],[LO,RELAY],local_lo,peer_lo)
        self.birth={'pid':123,'start':'345','group':99,'argv':'00','exe':'/python'}
        self.terminal={'ok':True,'pid':123,'namespace':self.peer_namespace,'links':[LO,RELAY],
                       'errors':[],'tls_worker_joined':True,'physical_capture_closed':True}
    def command(self,argv):
        self.calls.append(tuple(argv))
        if argv==['ip','-j','-d','link','show']:
            if not self.states:raise AssertionError('unexpected topology observation')
            return json.dumps(self.states.pop(0)).encode()
        if argv==['ip','link','delete','client0']:
            if self.delete_error is not None:raise self.delete_error
            return b''
        raise AssertionError('unexpected operational command')
    def cleanup(self,stdout=b'',stderr=b''):
        return self.env['cleanup_peer_topology']('net:[71]',self.local,self.peer,self.birth,
                                                self.peer_namespace,self.terminal,self.endpoint,stdout,stderr)
    def deletes(self):return [x for x in self.calls if x==('ip','link','delete','client0')]

class PeerTopologyCleanupContracts(unittest.TestCase):
    def test_present_owned_veth_deleted_then_exact_absence(self):
        h=Harness([[LO,CLIENT],[LO]]);h.cleanup();self.assertEqual(len(h.deletes()),1)
    def test_delete_failure_is_primary_unchanged(self):
        primary=RuntimeError('delete transport failure');h=Harness([[LO,CLIENT]],primary)
        with self.assertRaises(RuntimeError) as caught:h.cleanup()
        self.assertIs(caught.exception,primary);self.assertEqual(len(h.calls),2)
    def test_delete_success_without_absence_refused(self):
        h=Harness([[LO,CLIENT],[LO,CLIENT]])
        with self.assertRaises(RuntimeError):h.cleanup()
        self.assertEqual(len(h.deletes()),1)
    def test_replaced_renamed_extra_wrong_kind_and_wrong_peer_no_deletion(self):
        variants=[]
        for key,value in [('ifindex',8),('ifname','renamed0'),('address','02:00:00:00:00:09'),('link_index',9),('link_type','loopback')]:
            row=copy.deepcopy(CLIENT);row[key]=value;variants.append([LO,row])
        row=copy.deepcopy(CLIENT);row['linkinfo']['info_kind']='dummy';variants.append([LO,row])
        extra=copy.deepcopy(CLIENT);extra['ifname']='extra0';extra['ifindex']=4;variants.append([LO,CLIENT,extra])
        replaced_lo=copy.deepcopy(LO);replaced_lo['ifindex']=5;variants.append([replaced_lo])
        variants.extend([[],[CLIENT],[LO,LO]])
        for states in variants:
            with self.subTest(states=states):
                h=Harness([states])
                with self.assertRaises((RuntimeError,AttributeError)):h.cleanup()
                self.assertEqual(h.deletes(),[])
    def test_absence_requires_namespace_terminal_reap_literal_types(self):
        mutations=[lambda h:setattr(h,'namespace','net:[81]'),lambda h:setattr(h.endpoint,'pid',124),
                   lambda h:setattr(h.endpoint,'returncode',None),lambda h:setattr(h.endpoint,'returncode',False),
                   lambda h:setattr(h.endpoint,'returncode',1),lambda h:setattr(h.endpoint,'poll',lambda:None),
                   lambda h:h.birth.update(pid=True),lambda h:h.terminal.update(pid=True),
                   lambda h:h.terminal.update(pid=124),lambda h:h.terminal.update(namespace='net:[83]'),
                   lambda h:h.terminal.update(ok=1),lambda h:h.terminal.update(tls_worker_joined=1),
                   lambda h:h.terminal.update(physical_capture_closed=1),lambda h:h.terminal.update(errors=['worker']),
                   lambda h:h.terminal.update(links=[LO]),lambda h:h.terminal.update(links=[LO,CLIENT])]
        for index,mutate in enumerate(mutations):
            with self.subTest(index=index):
                h=Harness([[LO],[LO]]);mutate(h)
                with self.assertRaises(RuntimeError):h.cleanup()
                self.assertEqual(h.calls,[])
        for out,err in [(b'late',b''),(b'',b'error')]:
            h=Harness([[LO],[LO]])
            with self.assertRaises(RuntimeError):h.cleanup(out,err)
            self.assertEqual(h.calls,[])
    def test_initial_pair_requires_fresh_membership_reciprocal_indices_and_macs(self):
        h=Harness([]);f=h.env['owned_pair_identity'];lo=h.local['lo']
        for key,value in [('link_index',9),('address','02:00:00:00:00:04'),('ifindex',True)]:
            client=copy.deepcopy(CLIENT);client[key]=value
            with self.assertRaises(RuntimeError):f([LO,client],[LO,RELAY],lo,lo)
        with self.assertRaises(RuntimeError):h.env['topology_identity']([LO,CLIENT],('lo',))
    def test_actual_completed_rows_retained_only_bounded_failure_metadata(self):
        h=Harness([]);rows=[{'mode':m,'terminal':{'phase':'terminal'},'physical_packets':2,'tun_packets':3,
                            'TUN_capture':{'not_retained':'raw_bound'},'physical_capture':{}}
                           for m in ('tls','tls-transfer','drop')]
        result=h.env['completed_scenario_diagnostics'](rows)
        self.assertIs(result['runtime_acceptance'],False);self.assertEqual(len(result['completed_scenarios']),3)
        self.assertNotIn('TUN_capture',result['completed_scenarios'][0])
        with self.assertRaises(RuntimeError):h.env['completed_scenario_diagnostics'](rows*2)
        with self.assertRaises(RuntimeError):h.env['completed_scenario_diagnostics'](rows[::-1])
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700);d.write_json(tmp,'inner-failure.json',{'status':'FAIL','completed_loop_diagnostics':result})
            self.assertEqual(json.loads((Path(tmp)/'inner-failure.json').read_bytes())['status'],'FAIL')
            with self.assertRaises(FileExistsError):d.write_json(tmp,'inner-failure.json',result)
    def test_failure_snapshot_new_phases_and_fault_retained_unknown_refused(self):
        phases=['owned_existing_local32_proven','packet_worker_stopped','native_teardown_checked',
                'native_release_authorized','native_release_deadline_failed']
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700);instance=Path(tmp)/'1234abcd';instance.mkdir(mode=0o700)
            for i,phase in enumerate(phases):
                path=instance/f'{i:08d}_{phase}.json';path.write_text(json.dumps({'phase':phase,'runtime_fault':phase.endswith('failed')}));path.chmod(0o600)
            result=d.journal_snapshot(tmp)
            self.assertEqual(len(result['entries']),5)
            self.assertTrue(result['entries'][-1]['value']['runtime_fault'])
            self.assertNotIn('runtime_acceptance',result)
            unknown=instance/'00000005_unknown.json';unknown.write_text('{}');unknown.chmod(0o600)
            with self.assertRaises(RuntimeError):d.journal_snapshot(tmp)
    def test_snapshot_duplicate_and_oversized_json_refused(self):
        for body in [b'{"phase":"x","phase":"y"}',b'x'*65537]:
            with tempfile.TemporaryDirectory() as tmp:
                os.chmod(tmp,0o700);instance=Path(tmp)/'1234abcd';instance.mkdir(mode=0o700)
                path=instance/'00000000_native_release_authorized.json';path.write_bytes(body);path.chmod(0o600)
                with self.assertRaises(RuntimeError):d.journal_snapshot(tmp)

if __name__=='__main__':unittest.main()
