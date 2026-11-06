"""Real private-fs publication cuts; no PID1, network, or route authority."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SOURCE=Path(__file__).resolve().parents[1]/'lib/aegis_installer_auto_v2.py'
spec=importlib.util.spec_from_file_location('cold_rollover_coordinator',SOURCE)
coordinator=importlib.util.module_from_spec(spec)
spec.loader.exec_module(coordinator)

BOOT='12345678-1234-1234-1234-123456789abc'
PRIOR='a'*64


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0 and
                     hasattr(os,'O_TMPFILE'),
                     'root Linux O_TMPFILE is required')
class RolloverPublicationTests(unittest.TestCase):
    def fixture(self,root):
        cold=root/'cold-recovery'
        old=b'{"old":"source-bound"}\n'
        intent={key:'a'*64 for key in coordinator._COLD_INTENT_FIELDS}
        intent.update(schema='aegis_auto_terminal_cold_intent_v1',
                      current_boot_id=BOOT,
                      retained_root='/var/lib/aegis-auto/releases/'+'b'*16,
                      old_context_sha256=None)
        raw=(json.dumps(intent,sort_keys=True,separators=(',',':'))+'\n').encode()
        handoff={'current_boot_id':BOOT,'prior_boot_id':
                 '87654321-4321-4321-4321-cba987654321',
                 'prior_intent_sha256':PRIOR,
                 'original_intent_sha256':hashlib.sha256(old).hexdigest(),
                 'retained_root':intent['retained_root']}
        cold.mkdir(mode=0o700)
        (cold/'intent.json').write_bytes(old)
        (cold/'intent.json').chmod(0o600)
        return cold,handoff,raw

    def test_atomic_final_directory_contains_intent_before_head(self):
        with tempfile.TemporaryDirectory(dir='/run') as directory:
            root=Path(directory)
            cold,handoff,raw=self.fixture(root)
            with mock.patch.object(coordinator,'COLD_RECOVERY',cold),\
                 mock.patch.object(coordinator,'current_boot',return_value=BOOT):
                result=coordinator._cold_publish_attempt(handoff,raw,None)
            name=BOOT+'-'+PRIOR
            final=cold/'attempts'/name
            self.assertEqual(sorted(p.name for p in final.iterdir()),
                             ['intent.json'])
            self.assertEqual((final/'intent.json').read_bytes(),raw)
            self.assertFalse((cold/'attempts'/('stage-'+name)).exists())
            head=cold/('attempt-head-'+BOOT+'-'+result['intent_sha256']+'.json')
            self.assertEqual(hashlib.sha256(head.read_bytes()).hexdigest(),
                             result['head_sha256'])

    def test_interrupted_unnamed_intent_write_never_exposes_final(self):
        with tempfile.TemporaryDirectory(dir='/run') as directory:
            root=Path(directory)
            cold,handoff,raw=self.fixture(root)
            name=BOOT+'-'+PRIOR
            with mock.patch.object(coordinator,'COLD_RECOVERY',cold),\
                 mock.patch.object(coordinator,'current_boot',return_value=BOOT),\
                 mock.patch.object(coordinator.os,'write',
                                   side_effect=OSError('interrupted write')) as write:
                with self.assertRaises(OSError):
                    coordinator._cold_publish_attempt(handoff,raw,None)
                write.assert_called_once()
            self.assertFalse((cold/'attempts'/name).exists())
            self.assertFalse(any(p.name.startswith('attempt-head-')
                                 for p in cold.iterdir()))
            self.assertEqual(list((cold/'attempts'/('stage-'+name)).iterdir()),[])


if __name__=='__main__':
    unittest.main()
