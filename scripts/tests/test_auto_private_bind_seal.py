"""Private ControlPID's host assessment precedes binding and final seal ACK."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE=Path(__file__).resolve().parents[1]/'lib/aegis_auto_guardian.py'
HELPER=SOURCE.parent.parent/'aegis-device-egress-guard.sh'
SPEC=importlib.util.spec_from_file_location('aegis_auto_guardian_bind_seal',SOURCE)
guardian=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(guardian)


class PrivateBindSealTests(unittest.TestCase):
    @staticmethod
    def helper_binding_digest(state):
        source=HELPER.read_text();read_line='state_text="$(aegis_root_read "$STATE")"'
        digest_line=next(l.split(' || fail',1)[0] for l in source.splitlines()
                         if l.strip().startswith('state_digest="$(printf'))
        assert read_line in source
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'state';path.write_bytes(state)
            command='set -euo pipefail\naegis_root_read() { cat "$1"; }\n'+read_line+'\n'+digest_line+'\nprintf "%s" "$state_digest"\n'
            result=subprocess.run(['bash','-c',command],check=True,capture_output=True,
                env={'STATE':str(path),'PATH':'/usr/bin:/bin'})
        return result.stdout.decode()

    def exercise(self, *, terminal_lf=True, bad_binding=None, foreign_error=False,
                 foreign_drift=False, expire_after_publish=False, bad_seal=False,
                 deadline=5, foreign_elapsed=0, local=False,
                 authenticated_lineage=None):
        unit='aegis-auto@'+'a'*64+'.service'
        request={'unit':unit,'boot_id':'b'*36,'invocation_id':'c'*32}
        state=b'schema=aegis_device_guard_v2\narmed=1\nuplink=eth0'+(b'\n' if terminal_lf else b'')
        binding={'schema':'aegis_device_guard_binding_v1','boot_id':request['boot_id'],
            'state_sha256':self.helper_binding_digest(state),'path':'system.slice/'+unit,
            'inode':'123','invocation':request['invocation_id']}
        if bad_binding:binding.update(bad_binding)
        sealed={'policy_sha256':'d'*64,'boot_id':request['boot_id'],'netns_ino':44,
            'guard_dev':1,'guard_ino':2,'state_sha256':guardian.digest(state)}
        if bad_seal:sealed['state_sha256']=hashlib.sha256(state.rstrip(b'\n')).hexdigest()
        messages=iter([{'schema':'aegis_auto_guardian_bind_foreign_v1',
                       'command':'BIND_FOREIGN_ASSESS',**request},
                      {'schema':'aegis_auto_guardian_bind_seal_v1',
                       'command':'BIND_SEAL',**request}])
        peer=Mock();sent=[];events=[];clock=[0.0];assessments=[]
        def send(raw):sent.append(json.loads(raw));events.append('wire');return len(raw)
        peer.send.side_effect=send
        def assess(*args,**kwargs):
            events.append('assess');assessments.append(kwargs)
            if len(assessments)==1:clock[0]=foreign_elapsed
            if foreign_error:raise ValueError('refused')
            return {'foreign_projection_sha256':('e' if len(assessments)>1 and foreign_drift else 'f')*64}
        foreign=SimpleNamespace(assess_foreign_policy=assess,
            local_bind_invocation=Mock(),scoped_bind_invocation=Mock())
        owner=Mock(return_value={'guard_policy_sha256':'a'*64})
        def record(path):
            if path==guardian.POLICY:return sealed
            events.append('binding_read');return binding
        publish=Mock(side_effect=lambda *_: (events.append('publish'),clock.__setitem__(0,100) if expire_after_publish else None))
        error=None
        with contextlib.ExitStack() as stack:
            patches=[patch.object(guardian,'_receive_no_fds',side_effect=lambda _:json.dumps(next(messages)).encode()),
                patch.object(guardian,'_pid_alive',return_value=True),
                patch.object(guardian,'_bind_peer'),patch.object(guardian,'_held_lock',return_value=(1,2)),
                patch.object(guardian,'_claimed_private_unit'),patch.object(guardian,'record',side_effect=record),
                patch.object(guardian,'regular',return_value=state),
                patch.object(Path,'stat',return_value=SimpleNamespace(st_ino=123)),
                patch.object(Path,'exists',return_value=False),
                patch.object(guardian,'verified_module',return_value=foreign),
                patch.object(guardian,'seal_policy_receipt',return_value=sealed),
                patch.object(guardian,'_publish_policy_receipt',publish),
                patch.object(guardian.time,'monotonic',side_effect=lambda:clock[0])]
            if local:
                patches.extend([patch.object(guardian,'_scoped_owner_binding',return_value=None),
                                patch.object(guardian,'_local_owner_binding',owner)])
            for item in patches:stack.enter_context(item)
            try:
                guardian._seal_held_private_bind(peer,42,5,request,9,10,
                    {'mode':'wide-redirect-safe' if local else 'socks-only','private_unit':unit,'netns_ino':44},{'policy_sha256':'a'*64},deadline,
                    authenticated_lineage=authenticated_lineage)
            except (guardian.Refused,ValueError) as e:error=e
        if local and error is None:
            assert owner.call_args.args[2]=='a'*64
            assert owner.call_args.kwargs=={
                'current_policy_sha256':sealed['policy_sha256'],
                'authenticated_lineage':authenticated_lineage,
                'phase':'bind'}
            foreign.local_bind_invocation.assert_called_once()
        return error,publish,sent,events,assessments,binding

    def test_local_bind_uses_sealed_current_epoch_and_keeps_original_grant(self):
        error,publish,sent,*_=self.exercise(local=True,deadline=10)
        self.assertIsNone(error);publish.assert_called_once()
        self.assertEqual(sent[-1]['schema'],'aegis_auto_guardian_bind_sealed_v1')

    def test_local_bind_forwards_only_authenticated_lineage(self):
        lineage={'current_boot_id':'b'*36,'predecessor_boot_id':'a'*36,
                 'candidate_sha256':'c'*64,'private_unit':'aegis-auto@'+'a'*64+'.service',
                 'current_policy_sha256':'d'*64}
        error,publish,sent,*_=self.exercise(local=True,deadline=10,
                                           authenticated_lineage=lineage)
        self.assertIsNone(error);publish.assert_called_once()
        self.assertEqual(sent[-1]['schema'],'aegis_auto_guardian_bind_sealed_v1')

    def test_slow_complete_foreign_read_needs_remaining_absolute_seal_window(self):
        error,publish,sent,*_=self.exercise(foreign_elapsed=6,deadline=5)
        self.assertIsNotNone(error);publish.assert_not_called();self.assertEqual(sent,[])
        error,publish,sent,*_=self.exercise(foreign_elapsed=6,deadline=10)
        self.assertIsNone(error);publish.assert_called_once()
        self.assertEqual(sent[-1]['schema'],'aegis_auto_guardian_bind_sealed_v1')
        error,publish,sent,*_=self.exercise(foreign_elapsed=6,deadline=10,expire_after_publish=True)
        self.assertIsNotNone(error)
        self.assertFalse(any(x['schema']=='aegis_auto_guardian_bind_sealed_v1'for x in sent))

    def test_binding_must_match_control_invocation_before_host_seal_or_ack(self):
        error,publish,sent,events,assessments,binding=self.exercise()
        self.assertIsNone(error);publish.assert_called_once()
        self.assertEqual([x['schema'] for x in sent],['aegis_auto_guardian_foreign_assessed_v1','aegis_auto_guardian_bind_sealed_v1'])
        self.assertLess(events.index('assess'),events.index('binding_read'))
        self.assertLess(events.index('binding_read'),events.index('publish'))
        self.assertEqual(assessments[0]['binding_overrides']['client'],binding)
        self.assertNotIn('binding_overrides',assessments[1])
        for key,value in (('schema','wrong'),('boot_id','e'*36),('state_sha256','e'*64),
            ('path','system.slice/other.service'),('inode','124'),('invocation','e'*32)):
            with self.subTest(field=key):
                error,publish,sent,*_=self.exercise(bad_binding={key:value})
                self.assertIsInstance(error,guardian.Refused);publish.assert_not_called()
                self.assertTrue(all(x['schema']!='aegis_auto_guardian_bind_sealed_v1' for x in sent))

    def test_raw_state_digest_cannot_be_replaced_by_helper_digest(self):
        error,publish,sent,*_=self.exercise(bad_seal=True)
        self.assertIsInstance(error,guardian.Refused);publish.assert_not_called()
        self.assertTrue(all(x['schema']!='aegis_auto_guardian_bind_sealed_v1' for x in sent))

    def test_foreign_refusal_or_drift_cannot_publish_permission(self):
        for kwargs in ({'foreign_error':True},{'foreign_drift':True}):
            with self.subTest(case=kwargs):
                error,publish,sent,*_=self.exercise(**kwargs)
                self.assertIsNotNone(error);publish.assert_not_called()
                self.assertTrue(all(x['schema']!='aegis_auto_guardian_bind_sealed_v1' for x in sent))

    def test_deadline_after_publication_has_no_positive_seal_ack(self):
        error,publish,sent,*_=self.exercise(expire_after_publish=True)
        self.assertIsInstance(error,guardian.Refused);publish.assert_called_once()
        self.assertTrue(all(x['schema']!='aegis_auto_guardian_bind_sealed_v1' for x in sent))

    def test_helper_digest_and_host_seal_keep_raw_state_identity_distinct(self):
        for state in (b'schema=aegis_device_guard_v2\narmed=1\n',b'schema=aegis_device_guard_v2\narmed=1'):
            actual=self.helper_binding_digest(state)
            self.assertEqual(actual,hashlib.sha256(state.rstrip(b'\n')).hexdigest())
            self.assertEqual(actual==guardian.digest(state),not state.endswith(b'\n'))

    def test_no_terminal_lf_binding_is_accepted(self):
        error,publish,sent,*_=self.exercise(terminal_lf=False)
        self.assertIsNone(error);publish.assert_called_once()
        self.assertEqual(sent[-1]['schema'],'aegis_auto_guardian_bind_sealed_v1')

if __name__=='__main__':unittest.main()
