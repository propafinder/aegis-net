"""Pure filesystem control for the pending-before-context cold crash cut."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE=Path(__file__).resolve().parents[1]/'lib/aegis_auto_terminal_register.py'
spec=importlib.util.spec_from_file_location('registrar_cold_test',SOURCE)
reg=importlib.util.module_from_spec(spec);spec.loader.exec_module(reg)
sha=lambda value:hashlib.sha256(value).hexdigest()

class ColdContextTests(unittest.TestCase):
 def check(self,corrupt,replay=False):
  with tempfile.TemporaryDirectory() as temporary:
   directory=Path(temporary);migration=directory/'migration';migration.mkdir()
   pending_path=migration/'pending.json';release=directory/'B';release.mkdir()
   boot='1'*8+'-'+ '1'*4+'-'+'1'*4+'-'+'1'*4+'-'+'1'*12
   oldboot='0'*8+'-'+ '0'*4+'-'+'0'*4+'-'+'0'*4+'-'+'0'*12
   unit='aegis-auto@'+'a'*64+'.service'
   source=b'old source\n';install=b'old install\n';store=b'{}\n';leaf=b'old leaf\n'
   markers=[];bundle='b'*64;sums='c'*64;candidate='d'*64;package='e'*64
   context={'schema':'aegis_auto_terminal_migration_context_v1',
            'old_source_sha256':sha(source),'old_install_sha256':sha(install),
            'next_bundle_manifest_sha256':bundle,'next_sums_sha256':sums,
            'leaves':{'/synthetic':{'mode':0o600,'hex':leaf.hex()}},'markers':markers}
   raw=reg._migration_json(context);context_sha=sha(raw)
   pending={'schema':'aegis_auto_terminal_migration_pending_v1',
            'old_source_sha256':sha(source),
            'context_sha256':'0'*64 if corrupt else context_sha,
            'candidate_sha256':candidate,'package_sha256':package,
            'next_bundle_manifest_sha256':bundle,'next_sums_sha256':sums,
            'release_root':str(release),'unit':unit,'boot_id':oldboot,
            'marker_roster_sha256':sha(reg._migration_json(markers)),
            'prior_head_sha256':None}
   pending_path.write_bytes(reg._migration_json(pending))
   proof={'migration_state':'pending_prefix','context_state':'missing_reconstructible',
          'site_state':'a_exact','observer_state':'absent',
          'old_observer_archive_sha256':None,'package_state':'old_exact',
          'old_context_sha256':pending['context_sha256'],'old_boot_id':oldboot,
          'old_install_sha256':sha(install),'old_source_sha256':sha(source),
          'old_active_sha256':'1'*64,'old_stopped_sha256':'2'*64,
          'successor_intent_sha256':'3'*64,'new_candidate_sha256':candidate,
          'new_package_sha256':package,'deny_policy_sha256':'4'*64,
          'guard30_sha256':'5'*64,'selected_manager':'systemd-networkd.service'}
   bytes_by_path={str(reg.CONFIG):source,str(reg.INSTALL):install,
                  str(reg.STORE_CONFIG):store,'/synthetic':leaf}
   held=lambda path,maximum,mode:(bytes_by_path[str(path)] if str(path) in bytes_by_path else Path(path).read_bytes())
   record=lambda path,maximum:(json.loads(Path(path).read_bytes()),Path(path).read_bytes())
   original_read=Path.read_text
   read_text=lambda path,*a,**kw:boot if str(path)=='/proc/sys/kernel/random/boot_id' else original_read(path,*a,**kw)
   with (mock.patch.object(reg,'MIGRATION',migration),
         mock.patch.object(reg,'MIGRATION_PENDING',pending_path),
         mock.patch.object(reg,'MIGRATION_HEAD',migration/'head.json'),
         mock.patch.object(reg,'_migration_release',return_value=release),
         mock.patch.object(reg,'_cold_retained_self',return_value=sums),
         mock.patch.object(reg,'_cold_native_readback',side_effect=[proof,{**proof,'context_state':'present_exact'},
                      {**proof,'context_state':'present_exact'},
                      {**proof,'context_state':'present_exact'}]),
         mock.patch.object(reg,'_migration_record',side_effect=record),
         mock.patch.object(reg,'config',return_value={'schema':'old'}),
         mock.patch.object(reg,'_migration_guard',return_value=(object(),None)),
         mock.patch.object(reg,'_migration_rotation_bound',return_value=(bundle,sums)),
         mock.patch.object(reg,'_migration_site_leaves',return_value={'/synthetic':0o600}),
         mock.patch.object(reg,'_migration_marker_lineage'),
         mock.patch.object(reg,'_migration_boot_roster',return_value=markers),
         mock.patch.object(reg,'held',side_effect=held),
         mock.patch.object(reg,'publish',side_effect=lambda path,value,mode:Path(path).write_bytes(value)),
         mock.patch.object(Path,'read_text',autospec=True,side_effect=read_text)):
    if corrupt:
     with self.assertRaisesRegex(reg.Refused,'cold_context_not_reconstructible'):
      reg.cold_complete_context(unit,str(release),candidate,package,9,10)
     self.assertFalse(list(migration.glob('context-*.json')))
    else:
     result=reg.cold_complete_context(unit,str(release),candidate,package,9,10)
     self.assertEqual((migration/('context-'+context_sha+'.json')).read_bytes(),raw)
     self.assertEqual(result['context_sha256'],context_sha)
     self.assertTrue(result['no_client_grant'])
     self.assertEqual(result['status'],'published')
     if replay:
      again=reg.cold_complete_context(unit,str(release),candidate,package,9,10)
      self.assertEqual(again['status'],'already_present')
      self.assertEqual(again['context_sha256'],context_sha)
     self.assertFalse(list(migration.glob('observer-runtime-*.json')))
 def test_exact_context_published(self):self.check(False)
 def test_mismatched_context_refuses_without_publication(self):self.check(True)
 def test_after_publication_retry_is_read_only(self):self.check(False,True)

if __name__=='__main__':unittest.main()
