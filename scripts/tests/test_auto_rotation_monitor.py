"""Rotation quiescence never substitutes a marker for literal kernel deny."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]/'lib'
sys.path.insert(0,str(ROOT))
import aegis_auto_foreign_monitor as monitor
spec=importlib.util.spec_from_file_location('rotation_monitor_guardian',ROOT/'aegis_auto_guardian.py')
guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)


class RotationMonitor(unittest.TestCase):
    def verify(self, *, state=b'state', projection=b'deny', timer=True, installed=b'install'):
        intent={'old_install_sha256':hashlib.sha256(b'install').hexdigest(),
                'old_state_sha256':hashlib.sha256(b'state').hexdigest()}
        with patch.object(guardian,'own_source'), \
             patch.object(guardian,'_rotation_intent',return_value=intent), \
             patch.object(guardian,'regular',side_effect=lambda path,*_:installed if path==guardian.INSTALL else b'intent'), \
             patch.object(guardian,'_rotation_denied',return_value={'deny_policy_sha256':hashlib.sha256(b'deny').hexdigest()}), \
             patch.object(guardian,'_deny_without_bindings',return_value=(state,projection)), \
             patch.object(guardian,'_rotation_monitor_resume_live',return_value=timer):
            return guardian.verify_rotation_monitor_stop(19)

    def test_exact_deny_and_independent_resume_are_both_required(self):
        value=self.verify()
        self.assertEqual(value['schema'],'aegis_rotation_monitor_quiesced_v1')
        self.assertTrue(value['deny_proven'])
        for changed in ({'state':b'new state'}, {'projection':b'accept'},
                        {'timer':False}, {'installed':b'new generation'}):
            with self.subTest(changed=changed),self.assertRaises(guardian.Refused):
                self.verify(**changed)

    def test_unregistered_and_malformed_quiescence_cannot_skip_revoke(self):
        import contextlib
        for context in (None,{}, {'private_unit':None,'transient':True}):
            with patch.object(monitor,'guard_lock',side_effect=lambda:contextlib.nullcontext(9)), \
                 patch.object(monitor,'_BORROW_CONTEXT',context), \
                 patch.object(monitor.subprocess,'run',side_effect=AssertionError('unregistered control')):
                self.assertFalse(monitor.rotation_stop_authorized())
        with patch.object(monitor,'guard_lock',side_effect=TypeError('malformed protected proof')):
            self.assertFalse(monitor.rotation_stop_authorized())

    def test_resume_timer_rejects_extra_commands_dropins_and_longer_deadline(self):
        from types import SimpleNamespace
        name='aegis-rotation-fixture'
        timer='[Timer]\nOnActiveSec=600s\n'
        service='[Service]\nExecStart=/usr/bin/systemctl start aegis-foreign-policy-monitor.service\n'
        timer_props=dict(LoadState='loaded',ActiveState='active',Triggers=name+'.service',
                         FragmentPath='/run/systemd/transient/'+name+'.timer',DropInPaths='',
                         NextElapseUSecMonotonic='600000000')
        service_props=dict(FragmentPath='/run/systemd/transient/'+name+'.service',DropInPaths='',User='',Group='')
        def check(timer_text=timer,service_text=service,timer_values=None,service_values=None):
            def run(argv,**_kwargs):
                if argv[0]=='/usr/bin/busctl':
                    value=(timer_values or timer_props)['NextElapseUSecMonotonic']
                    return SimpleNamespace(returncode=0,stdout=('t '+value+'\n').encode())
                values=(timer_values or timer_props) if argv[2].endswith('.timer') else (service_values or service_props)
                return SimpleNamespace(returncode=0,stdout=('\n'.join(k+'='+v for k,v in values.items())+'\n').encode())
            with patch.object(guardian,'_rotation_monitor_resume_name',return_value=name), \
                 patch.object(guardian.subprocess,'run',side_effect=run), \
                 patch.object(guardian,'regular',side_effect=lambda path,*_:(timer_text if str(path).endswith('.timer') else service_text).encode()), \
                 patch.object(guardian.time,'monotonic_ns',return_value=0):
                return guardian._rotation_monitor_resume_live()
        self.assertTrue(check())
        for change in ({'timer_text':timer.replace('600s','2h')},
                       {'service_text':service+'ExecStartPre=/bin/true\n'},
                       {'service_text':service.replace('/usr/bin/systemctl','/bin/bash')},
                       {'timer_values':dict(timer_props,NextElapseUSecMonotonic='603000000')},
                       {'service_values':dict(service_props,DropInPaths='/untrusted/drop-in.conf')}):
            with self.subTest(change=change),self.assertRaises(guardian.Refused):
                check(**change)


if __name__=='__main__':unittest.main()
