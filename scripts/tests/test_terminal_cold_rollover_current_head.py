"""Current attempt path hints; native source/deny proof is a separate gate."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

BASE=Path(__file__).resolve().parents[1]/'lib'

def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,BASE/filename)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

register=load('cold_head_register','aegis_auto_terminal_register.py')
guardian=load('cold_head_guardian','aegis_auto_guardian.py')
BOOT='12345678-1234-1234-1234-123456789abc'
PRIOR='a'*64
INTENT='b'*64


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,
                     'root Linux source identity required')
class CurrentHeadTests(unittest.TestCase):
    def fixture(self,root):
        cold=root/'cold-recovery'
        attempts=cold/'attempts'
        cold.mkdir(mode=0o700)
        attempts.mkdir(mode=0o700)
        phase=attempts/(BOOT+'-'+PRIOR)
        phase.mkdir(mode=0o700)
        row={'schema':'aegis_auto_terminal_cold_attempt_head_v1',
             'current_boot_id':BOOT,
             'prior_boot_id':'87654321-4321-4321-4321-cba987654321',
             'prior_intent_sha256':PRIOR,
             'original_intent_sha256':'c'*64,
             'barrier_sha256':None,
             'attempt_intent_sha256':INTENT,
             'attempt_dir':str(phase)}
        raw=(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode()
        head=cold/('attempt-head-'+BOOT+'-'+INTENT+'.json')
        head.write_bytes(raw);head.chmod(0o600)
        return cold,phase,head

    def test_both_children_select_same_exact_current_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            cold,phase,_=self.fixture(Path(directory))
            original=Path.read_text
            def read(path,*args,**kwargs):
                if str(path)=='/proc/sys/kernel/random/boot_id':
                    return BOOT+'\n'
                return original(path,*args,**kwargs)
            with mock.patch.object(register,'COLD_RECOVERY',cold),\
                 mock.patch.object(register,'held',
                                   side_effect=lambda path,*_args:
                                       path.read_bytes()),\
                 mock.patch.object(Path,'read_text',autospec=True,
                                   side_effect=read):
                selected,head=register._cold_site_current_phase_root()
            self.assertEqual(selected,phase)
            self.assertEqual(head['attempt_intent_sha256'],INTENT)
            self.assertEqual(guardian._cold_guard_phase_hint(cold,BOOT),phase)

    def test_symlink_head_and_ambiguous_head_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            cold,_,head=self.fixture(Path(directory))
            copy=cold/('attempt-head-'+BOOT+'-'+'d'*64+'.json')
            copy.write_bytes(head.read_bytes());copy.chmod(0o600)
            with self.assertRaises((guardian.Refused,OSError)):
                guardian._cold_guard_phase_hint(cold,BOOT)
            copy.unlink()
            raw=head.read_bytes();head.unlink();head.symlink_to('/dev/null')
            with self.assertRaises((guardian.Refused,OSError)):
                guardian._cold_guard_phase_hint(cold,BOOT)
            head.unlink();head.write_bytes(raw);head.chmod(0o600)
            self.assertEqual(hashlib.sha256(raw).hexdigest(),
                             hashlib.sha256(head.read_bytes()).hexdigest())


if __name__=='__main__':unittest.main()
