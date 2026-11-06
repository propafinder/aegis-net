"""Cold history custody gates before A2 package mutation."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


SOURCE=Path(__file__).resolve().parents[1]/'lib/aegis_installer_auto_v2.py'
spec=importlib.util.spec_from_file_location('cold_archive_operator_test',SOURCE)
operator=importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)
OLD=Path('/var/lib/aegis-auto/releases/'+'a'*32)
NEW=Path('/var/lib/aegis-auto/releases/'+'b'*32)
PENDING='c'*64
MANIFEST='d'*64


class ColdArchiveOperator(unittest.TestCase):
    def test_exact_a2_a3_pairs_and_crossed_or_unknown_pairs_refuse(self):
        source_a2='05b662114e6e892dca2c065b43bdb0778797f82c'
        source_a3='c3d307626e531b9a75163ab760ed0d5fd55432de'
        registrar='9f62abb8e65340fb5ff3ff85c75def5159b6b4b4c321d4c1ddd543597768e1cb'
        elf_a2='f3fc01961b8cdca54553c0027cc3828a77b3043ee9f84308b89ed58b88bbc674'
        elf_a3='9d65862e9bcc96e0127e349cc54e2e2822425744ee0a6118b22284a2e9161f96'
        self.assertEqual(operator._cold_archive_exact_pair(source_a2,registrar,elf_a2),'a2')
        self.assertEqual(operator._cold_archive_exact_pair(source_a3,registrar,elf_a3),'a3')
        for source,elf,helper in ((source_a2,elf_a3,registrar),
                                  (source_a3,elf_a2,registrar),
                                  (source_a3,elf_a3,'0'*64),
                                  ('0'*40,elf_a3,registrar)):
            with self.subTest(source=source,elf=elf,helper=helper):
                with self.assertRaises(operator.Refused):
                    operator._cold_archive_exact_pair(source,helper,elf)

    def test_unknown_successor_never_calls_archive(self):
        progress={}
        with (mock.patch.object(operator,'_cold_archive_successor_profile',
                                return_value='same_source_or_no_cold_history'),
              mock.patch.object(operator,'_cold_history_archive_before_a2',
                                side_effect=AssertionError('archive called')) as archive):
            self.assertIsNone(operator._cold_archive_for_exact_successor(
                progress,'archive-phase',OLD/'bin/aegis-client',NEW,PENDING,9,10))
        self.assertEqual(progress,{})
        archive.assert_not_called()

    def proof(self, state='complete', sha=MANIFEST):
        return {'schema':'aegis_auto_v2_cold_history_archive_verification_v1',
                'current_boot_id':'00000000-0000-0000-0000-000000000000',
                'ordinary_pending_sha256':PENDING,'old_source_sha256':'e'*64,
                'member_manifest_sha256':sha,'deny_policy_sha256':'f'*64,
                'cold_root_present':True,'state':state,'no_client_grant':True}

    def test_complete_replay_uses_old_retained_native_without_live_child(self):
        with (mock.patch.object(operator,'_cold_archive_old_root_hint',
                                return_value=OLD),
              mock.patch.object(operator,'_cold_archive_native',
                                return_value=self.proof()) as native,
              mock.patch.object(operator,'_cold_archive_child',
                                side_effect=AssertionError('live B child used'))):
            result=operator._cold_history_archive_before_a2(
                Path('/usr/local/bin/aegis-client'),NEW,PENDING,9,10)
        self.assertEqual(result,MANIFEST)
        native.assert_called_once_with(OLD/'bin/aegis-client',OLD,PENDING,9,10)

    def test_mismatched_child_manifest_refuses_before_directory_creation(self):
        first=self.proof(state='source')
        child={'ordinary_pending_sha256':PENDING,
               'old_source_sha256':'e'*64,'member_manifest_sha256':'0'*64,
               'cold_root_present':True}
        with (mock.patch.object(operator,'_cold_archive_old_root_hint',
                                return_value=OLD),
              mock.patch.object(operator,'_cold_archive_native',
                                return_value=first),
              mock.patch.object(operator,'_cold_archive_child',
                                return_value=child),
              self.assertRaises(operator.Refused)):
            operator._cold_history_archive_before_a2(
                OLD/'bin/aegis-client',NEW,PENDING,9,10)

    def test_old_root_hint_requires_rotation_to_this_incoming_root(self):
        row={'schema':'aegis_auto_guard_rotation_intent_v1',
             'old_public_payload_root':str(OLD),
             'successor':{'next_public_payload_root':str(NEW)}}
        with mock.patch.object(operator,'bounded_root_bytes',
                               return_value=json.dumps(row).encode()):
            self.assertEqual(operator._cold_archive_old_root_hint(NEW),OLD)
            with self.assertRaises(operator.Refused):
                operator._cold_archive_old_root_hint(OLD)


if __name__=='__main__':
    unittest.main()
