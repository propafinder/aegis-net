"""Closed native current-attempt handoff parser, without PID1 authority."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE=Path(__file__).resolve().parents[1]/'lib/aegis_auto_terminal_register.py'
spec=importlib.util.spec_from_file_location('cold_rollover_register_test',SOURCE)
reg=importlib.util.module_from_spec(spec);spec.loader.exec_module(reg)
PUBLISHER=Path(__file__).resolve().parents[1]/'lib/aegis_installer_auto_v2.py'
publisher_spec=importlib.util.spec_from_file_location('cold_rollover_publisher_test',PUBLISHER)
publisher=importlib.util.module_from_spec(publisher_spec);publisher_spec.loader.exec_module(publisher)

class RolloverResolutionTests(unittest.TestCase):
 @unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os,'O_TMPFILE'),
                      'Linux unnamed temporary inode required')
 def test_interrupted_barrier_write_has_no_final_name(self):
  with tempfile.TemporaryDirectory(dir='/run') as directory:
   parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
   original=os.write;calls=[0]
   def partial(fd,body):
    calls[0]+=1
    if calls[0]==1:return original(fd,body[:1])
    raise OSError('synthetic interrupted barrier write')
   try:
    with mock.patch.object(publisher.os,'write',side_effect=partial):
     with self.assertRaises(OSError):
      publisher._cold_atomic_leaf(parent,'rollover-barrier.json',b'{"full":true}\n')
    self.assertEqual(calls[0],2)
    self.assertFalse((Path(directory)/'rollover-barrier.json').exists())
   finally:os.close(parent)

 def check(self,mutate=None,barrier_location='active'):
  boot='1'*8+'-'+'1'*4+'-'+'1'*4+'-'+'1'*4+'-'+'1'*12
  prior='a'*64;root='/var/lib/aegis-auto/releases/'+'b'*16
  original_bytes=b'original cold intent\n'
  barrier=(json.dumps({
      'schema':'aegis_auto_terminal_cold_rollover_barrier_v1',
      'original_intent_sha256':hashlib.sha256(original_bytes).hexdigest(),
      'original_boot_id':boot,'retained_root':root,
      'new_candidate_sha256':'c'*64,
      'next_bundle_manifest_sha256':'d'*64,
      'next_sums_sha256':'e'*64},
      sort_keys=True,separators=(',',':'))+'\n').encode()
  row={'schema':'aegis_auto_v2_cold_attempt_resolution_v1',
       'current_boot_id':boot,'original_intent_sha256':hashlib.sha256(original_bytes).hexdigest(),
       'prior_intent_sha256':prior,'barrier_sha256':None,
       'attempt_intent_sha256':None,'attempt_head_sha256':None,
       'attempt_dir':str(reg.COLD_RECOVERY/'attempts'/(boot+'-'+prior)),
       'prior_pointer_retirement_sha256':None,'no_client_grant':True}
  if mutate=='head':row['attempt_head_sha256']='e'*64
  if mutate in ('bound','conflict','foreign_consumed'):
   row['barrier_sha256']=hashlib.sha256(barrier).hexdigest()
  if mutate=='grant':row['no_client_grant']=False
  if mutate=='extra':row['unrecognized']=True
  original_reader=Path.read_text
  def read(path,*args,**kwargs):
   if str(path)=='/proc/sys/kernel/random/boot_id':return boot+'\n'
   return original_reader(path,*args,**kwargs)
  with tempfile.TemporaryDirectory() as directory:
   cold=Path(directory);(cold/'intent.json').write_bytes(original_bytes)
   if mutate=='bound':
    if barrier_location in ('active','both'):
     (cold/'rollover-barrier.json').write_bytes(barrier)
    if barrier_location in ('consumed','both'):
     (cold/('rollover-barrier-consumed-'+row['barrier_sha256']+'.json')).write_bytes(barrier)
   if mutate=='conflict':
    (cold/'rollover-barrier.json').write_bytes(barrier)
    (cold/('rollover-barrier-consumed-'+row['barrier_sha256']+'.json')).write_bytes(b'foreign\n')
   if mutate=='foreign_consumed':
    (cold/'rollover-barrier.json').write_bytes(barrier)
    (cold/('rollover-barrier-consumed-'+'f'*64+'.json')).write_bytes(barrier)
   row['attempt_dir']=str(cold/'attempts'/(boot+'-'+prior))
   if mutate=='path':row['attempt_dir']+='/foreign'
   result=SimpleNamespace(returncode=0,stderr=b'',
       stdout=(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode())
   def held(path,*args):
    if path.is_symlink():raise reg.Refused('synthetic_symlink')
    return path.read_bytes()
   with mock.patch.object(reg,'COLD_RECOVERY',cold),\
        mock.patch.object(reg.subprocess,'run',return_value=result) as child,\
        mock.patch.object(reg,'held',side_effect=held),\
        mock.patch.object(Path,'read_text',autospec=True,side_effect=read):
    parsed=reg.cold_attempt_readback(root,9,10)
  self.assertEqual(parsed,row)
  self.assertEqual(child.call_args.kwargs['pass_fds'],(9,10))
  self.assertEqual(child.call_args.args[0][1],
                   'auto-verify-cold-attempt-inherited')
 def test_prehead_and_published_head(self):
  self.check();self.check('head')
  for location in ('active','consumed','both'):
   self.check('bound',location)
 def test_foreign_path_refuses(self):
  with self.assertRaises(reg.Refused):self.check('path')
 def test_grant_or_extra_field_refuses(self):
  for mutation in ('grant','extra'):
   with self.subTest(mutation=mutation),self.assertRaises(reg.Refused):
    self.check(mutation)
 def test_conflicting_or_foreign_consumed_barrier_refuses(self):
  for mutation in ('conflict','foreign_consumed'):
   with self.subTest(mutation=mutation),self.assertRaises(reg.Refused):
    self.check(mutation)

if __name__=='__main__':unittest.main()
