"""One coordinator identity must own both readiness and final guard readback."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('coordinator_loader_test', ROOT / 'scripts/lib/aegis_installer_auto_v2.py')
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
NAME = 'aegis_auto_guardian_preflight'


class InstalledGuardianLoader(unittest.TestCase):
    def setUp(self):
        self.previous = sys.modules.pop(NAME, None)
        c._GUARDIAN_CACHE = None
        self.raw = b'from dataclasses import dataclass\n@dataclass\nclass Marker: value: int\n'
        self.reader = mock.patch.object(c, 'bounded_root_bytes', side_effect=self.read)
        self.reader.start()

    def read(self, path, maximum, modes):
        self.assertEqual(path, c.INSTALLED_GUARDIAN)
        self.assertEqual((maximum, modes), (1 << 20, (0o500,)))
        return self.raw

    def tearDown(self):
        self.reader.stop()
        c._GUARDIAN_CACHE = None
        sys.modules.pop(NAME, None)
        if self.previous is not None:
            sys.modules[NAME] = self.previous

    def test_readiness_and_receipt_share_real_verified_dependency_cache(self):
        self.raw = (ROOT / 'scripts/lib/aegis_auto_guardian.py').read_bytes()
        first = c.installed_guardian()
        dependency_names = ('aegis_auto_foreign_policy', 'aegis_auto_native_witness')
        prior = {name: sys.modules.pop(name, None) for name in dependency_names}
        foreign = b'VALUE = 1\n'
        witness = b'from dataclasses import dataclass\nfrom aegis_auto_foreign_policy import VALUE\n@dataclass\nclass Marker: value: int\n'
        files = {first.FOREIGN_SOURCE: foreign, first.WITNESS: witness}
        receipt = {'foreign_policy_source_sha256': hashlib.sha256(foreign).hexdigest(),
                   'witness_sha256': hashlib.sha256(witness).hexdigest()}
        try:
            with mock.patch.object(first, 'record', return_value=receipt), \
                 mock.patch.object(first, 'regular', side_effect=lambda path, *_a: files[path]):
                loaded = first.verified_module(first.WITNESS, dependency_names[1])
                self.assertEqual(loaded.Marker(3).value, 3)
                second = c.installed_guardian()
                self.assertIs(second, first)
                self.assertIs(second.verified_module(second.WITNESS, dependency_names[1]), loaded)
                # Generation and module substitution still refuse on reuse.
                self.raw += b'\n'
                with self.assertRaises(c.Refused):
                    c.installed_guardian()
        finally:
            for name, previous in prior.items():
                sys.modules.pop(name, None)
                if previous is not None:
                    sys.modules[name] = previous

    def test_foreign_identity_is_never_replaced_or_accepted(self):
        foreign = types.ModuleType(NAME)
        sys.modules[NAME] = foreign
        with self.assertRaises(c.Refused):
            c.installed_guardian()
        self.assertIs(sys.modules[NAME], foreign)
        del sys.modules[NAME]
        first = c.installed_guardian()
        self.assertEqual(first.Marker(9).value, 9)
        sys.modules[NAME] = foreign
        with self.assertRaises(c.Refused):
            c.installed_guardian()
        self.assertIs(sys.modules[NAME], foreign)

    def test_failed_compile_does_not_publish_or_poison_retry(self):
        self.raw = b'raise RuntimeError("fixture initialization failure")\n'
        with self.assertRaises(RuntimeError):
            c.installed_guardian()
        self.assertNotIn(NAME, sys.modules)
        self.assertIsNone(c._GUARDIAN_CACHE)
        self.raw = b'VALUE = 2\n'
        self.assertEqual(c.installed_guardian().VALUE, 2)


if __name__ == '__main__':
    unittest.main()
