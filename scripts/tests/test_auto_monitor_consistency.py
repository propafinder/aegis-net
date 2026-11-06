"""Generation brackets may retry a transaction, never a stable unsafe policy."""
import contextlib
import copy
import json
import tempfile
from types import SimpleNamespace
from pathlib import Path
import socket
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
import aegis_auto_foreign_monitor as monitor


class MonitorConsistency(unittest.TestCase):
    def assess(self, generations, results, clock=None, context=None, links=None, stop_proof=None, stop_tokens=None):
        values = iter(results)
        def policy(*_args, **_kwargs):
            value = next(values)
            if isinstance(value, Exception): raise value
            return value
        with patch.object(monitor,'guard_lock',side_effect=lambda **_kwargs:contextlib.nullcontext()), \
             patch.object(monitor,'state',return_value=(b'',{'armed':'1','uplink':'eth0'})), \
             patch.object(monitor,'assessment_options',return_value={}), \
             patch.object(monitor,'get_generation',side_effect=generations), \
             patch.object(monitor,'assess_foreign_policy',side_effect=policy) as called, \
             patch.object(monitor,'cgroup_members'), \
             patch.object(monitor,'stopping_transition_token',side_effect=stop_tokens or (lambda:None)), \
             patch.object(monitor,'link_identities',side_effect=links or (lambda:frozenset({(1,'lo')}))), \
             patch.object(monitor,'owned_tun_stop_proven',side_effect=stop_proof or (lambda:{})), \
             patch.object(monitor,'_BORROW_CONTEXT',context), \
             patch.object(monitor.time,'monotonic',side_effect=clock or (lambda:0)):
            result = monitor.stable_assessment(object())
            return result, called.call_count

    def test_transaction_during_snapshot_is_reassessed_from_scratch(self):
        proof = {'foreign_projection_sha256':'a'*64}
        result,count = self.assess([7,8,8,8], [ValueError('mixed snapshot'),proof])
        self.assertEqual((result,count),(proof,2))

    def test_stable_unknown_rule_is_never_retried(self):
        error = ValueError('stable unauthorized rule')
        with self.assertRaisesRegex(ValueError,'stable unauthorized'):
            self.assess([9,9],[error,{}])

    def test_typed_stop_publication_cannot_retry_stable_foreign_policy(self):
        token=('aegis-auto@'+'a'*64+'.service','b'*32,'pending_deny',123)
        with self.assertRaisesRegex(ValueError,'stable unsafe'):
            self.assess([4,4],[ValueError('stable unsafe')],stop_tokens=[None,token])

    def test_stopping_candidate_is_only_original_live_main_under_protected_intent(self):
        unit='aegis-auto@'+'a'*64+'.service';boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()if sys.platform=='linux'else'12345678-1234-1234-1234-123456789abc'
        context={'private_unit':unit,'private_invocation':'b'*32}
        journal={'boot_id':boot,'private_unit':unit,'invocation_id':'b'*32,
                 'phase':'COMMITTED_ACTIVE','private_main_pid':123,'private_cgroup':'/system.slice/'+unit}
        intent={'schema':'aegis_auto_stop_intent_v1','boot_id':boot,'service':unit,
                'invocation_id':'b'*32,'phase':'pending_deny'}
        facts={'MainPID':'123','ControlPID':'234','ActiveState':'deactivating','SubState':'stop',
               'InvocationID':'b'*32,'ControlGroup':'/system.slice/'+unit}
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);state=root/'state';stop=root/'auto-stop-intent.json';native=root/'journal.json'
            stop.touch();actor=SimpleNamespace(STOP_INTENT=stop,JOURNAL=native)
            def read(path,*args):return json.dumps(intent if path==stop else journal).encode()
            def query(*args):
                row=facts if args[2]==unit else dict(facts,MainPID='321',ActiveState='active',ControlGroup='/system.slice/systemd-networkd.service')
                return ''.join(k+'='+v+'\n'for k,v in row.items()).encode()
            original_read=Path.read_text
            def text(path,*args,**kw):
                if str(path)=='/proc/sys/kernel/random/boot_id':return boot
                if str(path)=='/sys/class/net/eth0/ifindex':return '11\n'
                return original_read(path,*args,**kw)
            with patch.object(monitor,'STATE',state),patch.object(monitor,'_BORROW_CONTEXT',context), \
                 patch.object(monitor,'actor_module',return_value=actor),patch.object(monitor,'trusted_read',side_effect=read), \
                 patch.object(monitor,'state',return_value=(b'fixed-state',{})),patch.object(monitor,'run',side_effect=query), \
                 patch.object(Path,'stat',return_value=SimpleNamespace(st_ino=77,st_mode=0o100600)),patch.object(Path,'read_text',text), \
                 patch.object(Path,'exists',new=lambda path: path==stop):
                def current_options():
                    value=monitor.assessment_options({'manager':'systemd-networkd.service','uplink':'eth0'})
                    self.assertEqual(value['binding_candidates'],[])
                    value['binding_candidates']=value['binding_candidate_provider']()
                    return value
                options=current_options()
                candidate=context['stopping_client_binding'];self.assertEqual(candidate['path'],'system.slice/'+unit)
                self.assertIn({'client':candidate,'manager':None},options['binding_candidates'])
                with patch.object(monitor,'stopping_transition_token',return_value=None):
                    early=current_options()
                self.assertTrue(all(row['client']is None for row in early['binding_candidates']))
                refreshed=early['binding_candidate_provider']()
                self.assertIn({'client':candidate,'manager':None},refreshed)
                for field,bad in (('private_main_pid',999),('invocation_id','c'*32),('private_unit','other'),('phase','REGISTERED')):
                    before=copy.deepcopy(journal);journal[field]=bad
                    with self.assertRaises(ValueError):current_options()
                    journal.clear();journal.update(before)
                facts['MainPID']='999'
                with self.assertRaises(ValueError):current_options()
                facts['MainPID']='0';options=current_options()
                self.assertNotIn('stopping_client_binding',context)
                self.assertTrue(all(row['client']is None for row in options['binding_candidates']))
                intent['phase']='deny_proven';facts['MainPID']='123'
                options=current_options()
                self.assertNotIn('stopping_client_binding',context)
                intent['phase']='pending_deny'
                for field,bad in (('boot_id','old-boot'),('service','foreign.service'),
                                  ('invocation_id','c'*32),('phase','unknown'),('schema','unknown')):
                    before=copy.deepcopy(intent);intent[field]=bad
                    with self.assertRaises(ValueError):current_options()
                    intent.clear();intent.update(before)

    def test_receiptless_stopping_cgroup_still_rejects_foreign_process(self):
        unit='aegis-auto@'+'a'*64+'.service';binding={'path':'system.slice/'+unit,'invocation':'b'*32}
        context={'stopping_client_binding':binding,'stopping_main_pid':123}
        facts={'MainPID':'123','ControlPID':'234','ControlGroup':'/system.slice/'+unit,'InvocationID':'b'*32}
        parent=234
        def text(path,*args,**kwargs):
            if path.name=='cgroup.procs':return '123\n234\n999\n'
            if str(path)=='/proc/999/stat':return '999 (fixture) S '+str(parent)+' '+'0 '*25
            raise AssertionError('unexpected process read')
        with tempfile.TemporaryDirectory()as folder,patch.object(monitor,'STATE',Path(folder)/'state'), \
             patch.object(monitor,'_BORROW_CONTEXT',context),patch.object(Path,'read_text',text), \
             patch.object(monitor,'run',side_effect=lambda *_:''.join(k+'='+v+'\n'for k,v in facts.items()).encode()):
            monitor.cgroup_members()
            parent=777
            with self.assertRaisesRegex(ValueError,'unexpected client cgroup process'):monitor.cgroup_members()
            facts['MainPID']='0'
            with self.assertRaises(monitor.CgroupTransition):monitor.cgroup_members()

    def test_verified_binding_does_not_require_post_bind_latch_or_promote_manager_owner(self):
        unit='aegis-auto@'+'a'*64+'.service';binding={'path':'system.slice/'+unit,'invocation':'b'*32}
        for context in ({'private_unit':unit,'private_invocation':None,'private_main_pid':None},
                        {'private_unit':None,'transient':True},
                        {'private_unit':unit,'private_invocation':'b'*32,'private_main_pid':123}):
            with patch.object(monitor,'_BORROW_CONTEXT',context), \
                 patch.object(monitor,'state',return_value=(b'fixed-state',{})), \
                 patch.object(Path,'read_text',return_value='12345678-1234-1234-1234-123456789abc'), \
                 patch.object(monitor,'trusted_read',side_effect=AssertionError('no journal promotion')), \
                 patch.object(monitor,'run',side_effect=AssertionError('provider must stay lazy')):
                options=monitor.assessment_options({'manager':'systemd-networkd.service'})
                options['binding_observer']({'client':binding,'manager':None})
                self.assertEqual(context['verified_client_binding'],binding)
                self.assertIsNot(context['verified_client_binding'],binding)
                self.assertEqual(context.get('private_main_pid'),123 if context.get('private_invocation') else None)
                context['private_invocation']='c'*32
                with self.assertRaisesRegex(ValueError,'invocation differs'):
                    options['binding_observer']({'client':binding,'manager':None})

    def test_verified_snapshot_membership_survives_receipt_removal_but_not_owner_change(self):
        unit='aegis-auto@'+'a'*64+'.service'
        binding={'path':'system.slice/'+unit,'invocation':'b'*32}
        context={'verified_client_binding':binding,'private_main_pid':123}
        facts={'MainPID':'123','ControlPID':'234','ControlGroup':'/system.slice/'+unit,'InvocationID':'b'*32}
        parent=234
        def text(path,*args,**kwargs):
            if path.name=='cgroup.procs':return '123\n234\n999\n'
            if str(path)=='/proc/999/stat':return '999 (fixture) S '+str(parent)+' '+'0 '*25
            raise AssertionError('receipt must not be reread')
        with tempfile.TemporaryDirectory()as folder,patch.object(monitor,'STATE',Path(folder)/'state'), \
             patch.object(monitor,'_BORROW_CONTEXT',context),patch.object(Path,'read_text',text), \
             patch.object(monitor,'trusted_read',side_effect=AssertionError('receipt was removed')), \
             patch.object(monitor,'run',side_effect=lambda *_:''.join(k+'='+v+'\n'for k,v in facts.items()).encode()):
            monitor.cgroup_members()
            parent=777
            with self.assertRaisesRegex(ValueError,'unexpected client cgroup process'):monitor.cgroup_members()
            parent=234
            for key,value in (('MainPID','0'),('InvocationID','c'*32),('ControlGroup','/other')):
                old=facts[key];facts[key]=value
                with self.assertRaises(monitor.CgroupTransition):monitor.cgroup_members()
                facts[key]=old
            with patch.object(Path,'read_text',side_effect=FileNotFoundError):
                with self.assertRaises(monitor.CgroupTransition):monitor.cgroup_members()
            context.pop('private_main_pid')
            changed=dict(facts,MainPID='999')
            def encode(row):return ''.join(k+'='+v+'\n'for k,v in row.items()).encode()
            with patch.object(monitor,'run',side_effect=[encode(facts),encode(changed)]):
                with self.assertRaises(monitor.CgroupTransition):monitor.cgroup_members()
            facts['MainPID']='0'
            with self.assertRaises(monitor.CgroupTransition):monitor.cgroup_members()
            facts['MainPID']='123'
            context['verified_client_binding']=None
            with patch.object(monitor,'run',side_effect=AssertionError('no verified grant')):
                monitor.cgroup_members()

    def test_verified_prestart_pins_control_and_phase_without_admitting_unrelated_pid(self):
        unit='aegis-auto@'+'a'*64+'.service';binding={'path':'system.slice/'+unit,'invocation':'b'*32}
        context={'private_unit':unit,'private_main_pid':None,'verified_client_binding':binding}
        facts={'MainPID':'0','ControlPID':'234','ControlGroup':'/system.slice/'+unit,
               'InvocationID':'b'*32,'ActiveState':'activating','SubState':'start-pre'}
        parent=234
        def text(path,*args,**kwargs):
            if path.name=='cgroup.procs':return '234\n999\n'
            if str(path)=='/proc/999/stat':return '999 (fixture) S '+str(parent)+' '+'0 '*25
            raise AssertionError('no receipt reread')
        def encode(row):return ''.join(k+'='+v+'\n'for k,v in row.items()).encode()
        with patch.object(monitor,'_BORROW_CONTEXT',context),patch.object(Path,'read_text',text), \
             patch.object(monitor,'run',side_effect=lambda *_:encode(facts)):
            monitor.cgroup_members()
            parent=777
            with self.assertRaisesRegex(ValueError,'unexpected client cgroup process'):monitor.cgroup_members()
            parent=234
            for key,value in (('ControlPID','0'),('ActiveState','active'),('SubState','stop')):
                old=facts[key];facts[key]=value
                with self.assertRaises(monitor.CgroupTransition):monitor.cgroup_members()
                facts[key]=old
            for changed in (dict(facts,MainPID='123'),dict(facts,ControlPID='321'),dict(facts,SubState='start')):
                with patch.object(monitor,'run',side_effect=[encode(facts),encode(changed)]):
                    with self.assertRaises(monitor.CgroupTransition):monitor.cgroup_members()
            context['private_main_pid']=0
            with self.assertRaises(monitor.CgroupTransition):monitor.cgroup_members()

    def test_continuous_transactions_and_exhausted_budget_refuse(self):
        with self.assertRaisesRegex(ValueError,'did not stabilize'):
            self.assess([1,2,2,3,3,4],[{},{},{}])
        with self.assertRaisesRegex(ValueError,'did not stabilize'):
            self.assess([1,2,2,3],[{},{}],clock=iter([2,4]).__next__)
        # The first complete read may itself take longer than the polling
        # interval. Its observed generation change starts the retry window.
        proof,count=self.assess([1,2,2,2],[{'stale':True},{'fresh':True}],
                                clock=iter([4]).__next__)
        self.assertEqual((proof,count),({'fresh':True},2))
        with self.assertRaisesRegex(ValueError,'stable unsafe retry'):
            self.assess([1,2,2,2],[{},ValueError('stable unsafe retry')],
                        clock=iter([4]).__next__)

    def test_pid1_transition_retry_requires_authenticated_private_owner(self):
        error = monitor.CgroupTransition('typed transition')
        with self.assertRaises(monitor.CgroupTransition):
            self.assess([2,2],[error,{}])
        self.assertEqual(self.assess([2,2,2,2],[error,{'safe':True}],
            context={'private_unit':'aegis-auto@'+'a'*64+'.service'}),({'safe':True},2))

    def test_owned_tun_removal_requires_exact_deny_then_complete_fresh_proof(self):
        before=frozenset({(1,'lo'),(2,'eth0'),(3,'aegis-tun0')})
        after=before-{(3,'aegis-tun0')}
        error=monitor.PolicyInputUnavailable(('tc','-j','qdisc','show','dev','aegis-tun0'),1,b'Cannot find device')
        proof={'fresh':True}
        self.assertEqual(self.assess([4,4,4,4],[error,proof],
            links=[before,after,after,after]),(proof,2))
        with self.assertRaisesRegex(ValueError,'deny unavailable'):
            self.assess([4,4],[error],links=[before,after],
                stop_proof=lambda:monitor.need(False,'deny unavailable'))
        # Removing a second interface, or admitting a successor TUN, is unsafe.
        with self.assertRaisesRegex(ValueError,'unowned concurrent'):
            self.assess([4,4],[error],links=[before,after-{(2,'eth0')}])
        with self.assertRaisesRegex(ValueError,'reappeared'):
            self.assess([4,4],[error,proof],links=[before,after,before])
        with self.assertRaisesRegex(ValueError,'fresh unsafe'):
            self.assess([4,4,4,4],[error,ValueError('fresh unsafe')],
                links=[before,after,after,after])
        with self.assertRaises(monitor.PolicyInputUnavailable):
            self.assess([4,4],[error],links=[before,before])

    def test_closed_input_failure_coordinates_do_not_retain_command_or_stderr(self):
        error=monitor.PolicyInputUnavailable(('tc','-j','qdisc','show','dev','PRIVATE_SENTINEL'),
            1,b'Cannot find device PRIVATE_SENTINEL')
        row=monitor.refusal_coordinates(error)
        self.assertEqual((row['policy_input'],row['input_failure'],row['input_exit']),
            ('tc_qdisc','missing_device',1))
        self.assertNotIn('PRIVATE_SENTINEL',repr(row)+str(error))

    def test_queued_getgen_reply_survives_scheduler_delay_and_ignores_sequence_in_identity(self):
        class Kernel:
            def send(self, message): self.seq=struct.unpack_from('=I',message,8)[0]
            def recv(self, _size):
                return (struct.pack('=IHHII',28,(10<<8)|15,0,self.seq,0) +
                        struct.pack('!BBH',socket.AF_UNSPEC,0,0) +
                        struct.pack('=HH',8,1|0x4000) + struct.pack('!I',42))
        peer=Kernel()
        for seq in (1234,5678):
            with patch.object(monitor.time,'monotonic_ns',return_value=seq), \
                 patch.object(monitor.time,'monotonic',side_effect=[0,1]), \
                 patch.object(monitor.select,'select',return_value=([peer],[],[])):
                self.assertEqual(monitor.get_generation(peer),42)

    def test_malformed_generation_is_not_an_admission(self):
        class Kernel:
            def send(self,message): self.seq=struct.unpack_from('=I',message,8)[0]
            def recv(self,_size):
                return struct.pack('=IHHII',24,(10<<8)|15,0,self.seq,0)+b'\0'*4+struct.pack('=HH',4,1)
        peer=Kernel()
        with patch.object(monitor.select,'select',return_value=([peer],[],[])), \
             self.assertRaises(ValueError):
            monitor.get_generation(peer)

    def test_invalid_quiescence_proof_always_selects_ordinary_revoke(self):
        with patch.object(monitor,'guard_lock',side_effect=KeyError('corrupt protected metadata')):
            self.assertFalse(monitor.rotation_stop_authorized())


if __name__ == '__main__':
    unittest.main()
