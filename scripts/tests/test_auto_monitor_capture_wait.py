"""Actual watchdog API + full monitor wait predicate; scripted PID1/proc facts.

No kernel/PID1 acceptance claim. The actual loaded watchdog must supply only its
own API; the Main receipt belongs to the guard's fixed protected state directory.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import types
import unittest
from unittest import mock

LIB=Path(__file__).resolve().parents[1]/'lib';sys.path.insert(0,str(LIB))
import aegis_auto_foreign_monitor as p
spec=importlib.util.spec_from_file_location('_capture_wait_watchdog',LIB/'aegis_auto_guardian_watchdog.py')
actor=importlib.util.module_from_spec(spec);sys.modules[spec.name]=actor;spec.loader.exec_module(actor)


class CaptureWait(unittest.TestCase):
    def check(self, *, main_change=None, journal_change=None, unit_change=None):
        boot='00000000-0000-0000-0000-000000000001';unit='aegis-auto@'+'a'*64+'.service'
        source=Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py')
        guardian_unit=Path('/etc/systemd/system/aegis-auto-guardian.service')
        main={'schema':'aegis_device_guard_main_binding_v1','boot_id':boot,'netns_ino':7,
            'private_unit':unit,'worker_sha256':'c'*64,'stage_dev':1,'stage_ino':2}
        journal={'schema':'aegis_auto_watchdog_pending_v1','boot_id':boot,'phase':'LATCHED',
            'private_unit':unit,'stage_dev':1,'stage_ino':2,'invocation_id':'d'*32}
        props={'ActiveState':'active','SubState':'running','MainPID':'5000','ControlPID':'0','InvocationID':'d'*32}
        if main_change:main.update(main_change)
        if journal_change:journal.update(journal_change)
        if unit_change:props.update(unit_change)
        installation={'guardian_sha256':hashlib.sha256(b'source').hexdigest(),
            'guardian_unit_sha256':hashlib.sha256(b'unit').hexdigest()}
        rows=[['1:','FLOCK','ADVISORY','WRITE','4242','00:00:17','0','EOF']]
        facts={'MainPID':'4242','ControlPID':'0','ActiveState':'active','InvocationID':'b'*32,
            'ControlGroup':'/system.slice/aegis-auto-guardian.service'}
        def trusted(path,_limit):
            path=Path(path)
            if path==p.STATE.parent/'auto-guardian-install.json':value=installation
            elif path==p.STATE.parent/'device-guard.conf.main-binding':value=main
            elif path==actor.JOURNAL:value=journal
            elif path==source:return b'source'
            elif path==guardian_unit:return b'unit'
            else:raise AssertionError('unreviewed receipt path:'+str(path))
            return json.dumps(value).encode()
        def text(path,*_args,**_kwargs):
            path=str(path)
            if path=='/proc/4242/cgroup':return '0::/system.slice/aegis-auto-guardian.service\n'
            if path=='/proc/4242/status':return 'Uid:\t0\t0\t0\t0\n'
            if path=='/proc/sys/kernel/random/boot_id':return boot+'\n'
            raise AssertionError(path)
        def raw(path):
            self.assertEqual(str(path),'/proc/4242/cmdline')
            return b'/usr/bin/python3\0-I\0-B\0'+str(source).encode()+b'\0serve\0'
        descriptor=os.open(os.devnull,os.O_RDONLY)
        with mock.patch.object(p,'actor_module',return_value=actor), \
             mock.patch.object(p,'trusted_read',side_effect=trusted), \
             mock.patch.object(p,'_assessment_holder_rows',return_value=rows), \
             mock.patch.object(p,'_actor_facts',return_value=facts), \
             mock.patch.object(p.os,'pidfd_open',return_value=descriptor,create=True), \
             mock.patch.object(actor,'_alive',return_value=True), \
             mock.patch.object(p.os,'stat',return_value=types.SimpleNamespace(st_ino=7)), \
             mock.patch.object(p.os.path,'samefile',return_value=True), \
             mock.patch.object(Path,'read_text',text),mock.patch.object(Path,'read_bytes',raw), \
             mock.patch.object(Path,'exists',return_value=False), \
             mock.patch.object(p,'state',return_value=(b'armed=1',{'armed':'1'})), \
             mock.patch.object(p,'run',return_value=('\n'.join(k+'='+v for k,v in props.items())+'\n').encode()):
            return p._authenticated_stopped_retirement_holder(types.SimpleNamespace(),time.monotonic()+10)

    def test_exact_active_main_uses_the_actual_watchdog_api(self):
        self.assertTrue(self.check())

    def test_wrong_main_or_pending_generation_remains_refused(self):
        for main,journal in (({'boot_id':'f'*36},None),({'worker_sha256':'bad'},None),
                (None,{'phase':'REGISTERED'}),(None,{'stage_ino':3})):
            with self.subTest(main=main,journal=journal),self.assertRaisesRegex(ValueError,'assessment active guardian generation changed'):
                self.check(main_change=main,journal_change=journal)

    def test_pending_control_or_other_invocation_remains_refused(self):
        for props in ({'ControlPID':'99'},{'InvocationID':'e'*32},{'SubState':'dead'}):
            with self.subTest(props=props),self.assertRaisesRegex(ValueError,'assessment active guardian private unit changed'):
                self.check(unit_change=props)


if __name__=='__main__':unittest.main()
