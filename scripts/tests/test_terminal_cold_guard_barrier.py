"""Pure source and filesystem controls for the cold guard admission barrier."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SOURCE=Path(__file__).resolve().parents[1]/'lib/aegis_auto_boot_transition.py'
spec=importlib.util.spec_from_file_location('terminal_cold_transition_test',SOURCE)
transition=importlib.util.module_from_spec(spec);spec.loader.exec_module(transition)
sha=lambda raw:hashlib.sha256(raw).hexdigest()
canonical=lambda row:json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n'

class ColdGuardBarrierTests(unittest.TestCase):
 @unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os,'O_TMPFILE'),
                      'Linux unnamed temporary inode required')
 def test_partial_atomic_ready_never_exposes_final_name(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'transition-ready.json'
   original_write=os.write
   calls=[0]
   def partial(fd,raw):
    calls[0]+=1
    if calls[0]==1:return original_write(fd,raw[:1])
    raise OSError('synthetic interrupted write')
   with mock.patch.object(transition.os,'write',side_effect=partial):
    with self.assertRaises(OSError):
     transition.write_new_atomic(path,b'{"complete":true}\n')
   self.assertFalse(path.exists() or path.is_symlink())

 def test_shell_refuses_active_and_symlink_ready(self):
  shell=(SOURCE.parents[1]/'aegis-device-egress-guard.sh').read_text()
  marker='if [[ "$ACTION" != block &&\n      ( -e /var/lib/aegis-install/client/terminal-migrations/cold-recovery/intent.json'
  begin=shell.index(marker)
  end=shell.index(' ]]; then',begin)
  condition=shell[begin+len('if '):end+3]
  prefix='/var/lib/aegis-install/client/terminal-migrations/cold-recovery'
  with tempfile.TemporaryDirectory() as directory:
   cold=Path(directory);(cold/'cold-config-intent.json').write_bytes(b'intent\n')
   (cold/'target').write_bytes(b'ready\n')
   ready=cold/'transition-ready.json'
   for link,expect in ((True,0),(False,1)):
    if ready.exists() or ready.is_symlink():ready.unlink()
    if link:ready.symlink_to(cold/'target')
    else:ready.write_bytes(b'ready\n')
    command='ACTION=bind-manager; if '+condition.replace(prefix,str(cold))+\
            '; then exit 0; else exit 1; fi'
    result=subprocess.run(['bash','-c',command],check=False)
    self.assertEqual(result.returncode,expect)
   (cold/'intent.json').write_bytes(b'intent\n')
   result=subprocess.run(['bash','-c',command],check=False)
   self.assertEqual(result.returncode,0)

 def check(self,mutation=None):
  with tempfile.TemporaryDirectory() as directory:
   cold=Path(directory);boot='1'*8+'-'+'1'*4+'-'+'1'*4+'-'+'1'*4+'-'+'1'*12
   source_raw=b'current source\n';store_raw=b'current store\n'
   dropin=b'[Unit]\nRequires=transition\n'
   source={'selected_manager':'systemd-networkd.service',
           'manager_transition_dropin_sha256':sha(dropin),
           'guardian_transition_dropin_sha256':sha(dropin)}
   intent={'schema':'aegis_auto_terminal_cold_intent_v1',
           'current_boot_id':boot,'deny_policy_sha256':'d'*64,
           'selected_manager':'systemd-networkd.service'}
   intent_raw=canonical(intent);intent_sha=sha(intent_raw)
   phase4={'schema':'aegis_auto_terminal_cold_site_ready_v1',
           'intent_sha256':intent_sha,'cold_prebind_sha256':'e'*64,
           'source_config_sha256':sha(source_raw),'observer_ready_sha256':'f'*64}
   ready={'schema':'aegis_auto_terminal_cold_transition_ready_v1',
          'current_boot_id':boot,'intent_sha256':intent_sha,
          'cold_prebind_sha256':'e'*64,'source_config_sha256':sha(source_raw),
          'observer_ready_sha256':'f'*64,'site_readback_sha256':'a'*64,
          'deny_policy_sha256':'d'*64,
          'consumed_intent_leaf':'intent-consumed-'+intent_sha+'.json',
          'consumed_pending_leaf':None}
   if mutation in ('oldboot','oldbootqualified'):
    ready['current_boot_id']='0'*8+'-'+'0'*4+'-'+'0'*4+'-'+'0'*4+'-'+'0'*12
   (cold/'transition-ready.json').write_bytes(canonical(ready))
   (cold/ready['consumed_intent_leaf']).write_bytes(intent_raw)
   (cold/'phase-04.json').write_bytes(canonical(phase4))
   installed_raw=b'current install\n'
   config={'schema':'aegis_auto_terminal_cold_config_intent_v1',
           'current_boot_id':boot,'intent_sha256':intent_sha,
           'cold_prebind_sha256':'e'*64,'old_context_sha256':'c'*64,
           'new_install_sha256':sha(installed_raw),
           'source_config_sha256':sha(source_raw),
           'store_config_sha256':sha(store_raw),
           'active_hook_sha256':'a'*64,
           'manager31_sha256':sha(dropin),
           'guardian31_sha256':sha(dropin),
           'selected_manager':'systemd-networkd.service'}
   (cold/'cold-config-intent.json').write_bytes(canonical(config))
   if mutation=='source':source_raw=b'changed source\n'
   if mutation=='active':(cold/'intent.json').write_bytes(intent_raw)
   if mutation=='unready':(cold/'transition-ready.json').unlink()
   pending=cold/'pending.json'
   def read(path,limit=8192):
    if path==transition.SOURCE_CONFIG:return source_raw
    if path==transition.STORE_CONFIG:return store_raw
    if path==transition.ROOT/'auto-guardian-install.json':return installed_raw
    return Path(path).read_bytes()
   with (mock.patch.object(transition,'COLD_ROOT',cold),
         mock.patch.object(transition,'COLD_READY',cold/'transition-ready.json'),
         mock.patch.object(transition,'_cold_rollover_hint',return_value=None),
         mock.patch.object(transition,'MIGRATION_PENDING',pending),
         mock.patch.object(transition,'SOURCE_CONFIG',cold/'source.json'),
         mock.patch.object(transition,'read_consumed_record',return_value=
                           {'qualified':True} if mutation=='oldbootqualified' else None),
         mock.patch.object(transition,'read',side_effect=read),
         mock.patch.object(transition,'_source_bytes',return_value=
                           b'changed dropin\n' if mutation=='dropin' else dropin)):
    return transition._cold_consumed_under_guard(boot,source,source_raw)

 def test_current_boot_exact_consumed_source_admits(self):
  self.assertIs(self.check(),True)
 def test_active_intent_refuses(self):
  with self.assertRaises(transition.Refused):self.check('active')
 def test_config_without_transition_refuses(self):
  with self.assertRaises(transition.Refused):self.check('unready')
 def test_changed_dropin_refuses(self):
  with self.assertRaises(transition.Refused):self.check('dropin')
 def test_changed_source_refuses(self):
  with self.assertRaises(transition.Refused):self.check('source')
 def test_old_cold_ready_without_current_boot_carrier_refuses(self):
  with self.assertRaises(transition.Refused):self.check('oldboot')
 def test_old_cold_ready_requires_later_full_carrier_check(self):
  self.assertIs(self.check('oldbootqualified'),False)
 def test_no_cold_ready_is_not_current_boot_proof(self):
  with tempfile.TemporaryDirectory() as directory:
   cold=Path(directory)
   with (mock.patch.object(transition,'COLD_ROOT',cold),
         mock.patch.object(transition,'COLD_READY',cold/'transition-ready.json'),
         mock.patch.object(transition,'_cold_rollover_hint',return_value=None)):
    self.assertIs(transition._cold_consumed_under_guard(
        '11111111-1111-1111-1111-111111111111',{},b'source'),False)

if __name__=='__main__':unittest.main()
