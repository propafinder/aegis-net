#!/usr/bin/env python3
"""Synthetic files and mocked ownership; no sudo, native driver or network."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("handoff", Path(__file__).with_name("handoff-deviceguard-ci-evidence.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class HandoffContract(unittest.TestCase):
    def setUp(self):
        ownership = patch.object(MODULE.os, "fchown")
        ownership.start()
        self.addCleanup(ownership.stop)
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-handoff-inert-")
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.parent = self.workspace / "ci-output/device-guard"
        self.parent.mkdir(parents=True)
        self.target = self.parent / "audit17-native-123-2"

    def create(self):
        self.target.mkdir(mode=0o700)
        for name in ("outer.log", "input-r1.json", "receipt-r1.json"):
            path = self.target / name
            path.write_bytes(b"synthetic fixture only\n")
            path.chmod(0o600)

    def invoke(self):
        return MODULE.handoff(str(self.workspace), "123", "2", 1001, 1001, expected_owner=os.getuid())

    def test_valid_bounded_flat_files_only_transfer_opened_handles(self):
        self.create()
        with patch.object(MODULE.os, "fchown") as transfer:
            self.assertTrue(self.invoke())
            self.assertEqual(transfer.call_count, 4)
            self.assertTrue(all(call.args[1:] == (1001, 1001) for call in transfer.call_args_list))
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in self.target.iterdir()))

    def test_no_current_evidence_does_not_mutate(self):
        with patch.object(MODULE.os, "fchown") as transfer:
            self.assertFalse(self.invoke())
            transfer.assert_not_called()

    def test_export_witnesses_transfer_without_replacing_native_receipt(self):
        self.create()
        original = (self.target / "receipt-r1.json").read_bytes()
        for name in ("export-complete-r1.json", "export-failure-r1.json"):
            with self.subTest(name=name):
                witness = self.target / name
                witness.write_bytes(b'{"native_acceptance":false}\n')
                witness.chmod(0o600)
                with patch.object(MODULE.os, "fchown") as transfer:
                    self.assertTrue(self.invoke())
                    self.assertEqual(transfer.call_count, 5)
                self.assertEqual((self.target / "receipt-r1.json").read_bytes(), original)
                self.assertEqual(witness.read_bytes(), b'{"native_acceptance":false}\n')
                witness.unlink()

    def test_unexpected_file_refuses_entire_inventory_before_mutation(self):
        self.create()
        (self.target / "unexpected.py").write_text("do not execute\n")
        with patch.object(MODULE.os, "fchown") as transfer, patch.object(MODULE.os, "fchmod") as mode:
            with self.assertRaises(ValueError):
                self.invoke()
            transfer.assert_not_called()
            mode.assert_not_called()

    def test_symlink_and_hardlink_refused_before_mutation(self):
        self.create()
        linked = self.target / "inside-receipt-r1.json"
        for hard in (False, True):
            if hard:
                os.link(self.target / "input-r1.json", linked)
            else:
                linked.symlink_to(self.target / "input-r1.json")
            with patch.object(MODULE.os, "fchown") as transfer:
                with self.assertRaises((OSError, ValueError)):
                    self.invoke()
                transfer.assert_not_called()
            linked.unlink()

    def test_broad_permissions_or_large_file_refused(self):
        self.create()
        outer = self.target / "outer.log"
        outer.chmod(0o666)
        with self.assertRaises(ValueError):
            self.invoke()
        outer.chmod(0o600)
        with outer.open("wb") as output:
            output.truncate(1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            self.invoke()

    def test_root_target_and_path_alias_refused(self):
        with self.assertRaises(ValueError):
            MODULE.handoff(str(self.workspace), "123", "2", 0, 1001)
        alias = self.workspace / "alias"
        alias.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            MODULE.handoff(str(alias), "123", "2", 1001, 1001)

    def test_readable_outer_log_normalized_to_private_mode(self):
        self.create()
        outer = self.target / "outer.log"
        outer.chmod(0o644)
        with patch.object(MODULE.os, "fchown"):
            self.assertTrue(self.invoke())
        self.assertEqual(outer.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
