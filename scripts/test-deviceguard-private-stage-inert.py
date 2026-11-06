#!/usr/bin/env python3
"""Synthetic file staging/export only; no root, namespace, driver or network."""
import hashlib
import types
import json
import os
import argparse
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE_PREIMAGE = None
MODULE = types.ModuleType("stage")
exec(compile((ROOT / "scripts/deviceguard-native-private-stage.py").read_bytes(), "<synthetic-stage-contract>", "exec"), MODULE.__dict__)
NAMES = ("test-device-egress-guard-native.py", "aegis-device-egress-guard.sh", "test-device-egress-guard-contract.sh")


class PrivateStageContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-stage-inert-")
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name).resolve()
        self.original = self.parent / "runner-workspace"
        self.original.mkdir(mode=0o700)
        self.assets = {}
        for name in NAMES:
            path = self.original / name
            data = ("synthetic " + name + "\n").encode()
            path.write_bytes(data)
            path.chmod(0o600)
            self.assets[name] = (path, hashlib.sha256(data).hexdigest())
        self.destination = self.original / "audit17-native-123-2"
        self.destination.mkdir(mode=0o700)

    def prepare(self):
        return MODULE.prepare(self.parent, self.destination.name, self.assets, expected_owner=os.getuid())

    def evidence(self, stage):
        evidence = Path(stage["evidence"])
        config = {"driver": str(Path(stage["root"]) / "scripts" / NAMES[0]),
                  "helper": str(Path(stage["root"]) / "scripts" / NAMES[1]),
                  "staging_root": stage["root"], "staging_output_name": stage["output_name"]}
        record = {"success": False, "pid": 1234, "owned_process_group": 1234,
                  "parent_reaped": True, "owned_group_signalled": True}
        for name, data in {"input-r1.json": json.dumps(config).encode(), "outer.log": b"synthetic refusal\n",
                           "receipt-r1.json": json.dumps(record).encode(),
                           "started-r1.json": json.dumps({"pid": 1234, "owned_process_group": 1234}).encode()}.items():
            MODULE.private_write(evidence / name, data)

    def test_staged_assets_and_child_paths_exclude_original_workspace(self):
        stage = self.prepare()
        for name, (original, digest) in self.assets.items():
            staged = Path(stage["root"]) / "scripts" / name
            self.assertNotIn(str(self.original), str(staged))
            self.assertEqual(staged.read_bytes(), original.read_bytes())
            self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
            self.assertEqual(hashlib.sha256(staged.read_bytes()).hexdigest(), digest)
        self.evidence(stage)
        self.assertNotIn(str(self.original), (Path(stage["evidence"]) / "input-r1.json").read_text())

    def test_failed_native_evidence_exports_byte_exact_and_stage_is_retained(self):
        stage = self.prepare()
        self.evidence(stage)
        hashes = MODULE.export(stage, self.destination)
        self.assertEqual(set(hashes), {"input-r1.json", "outer.log", "receipt-r1.json", "started-r1.json"})
        for name, digest in hashes.items():
            self.assertEqual((self.destination / name).read_bytes(), (Path(stage["evidence"]) / name).read_bytes())
            self.assertEqual((self.destination / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual(hashlib.sha256((self.destination / name).read_bytes()).hexdigest(), digest)
        self.assertTrue(Path(stage["root"]).exists())

    def test_partial_export_is_refused_before_destination_mutation(self):
        stage = self.prepare()
        MODULE.private_write(Path(stage["evidence"]) / "outer.log", b"partial\n")
        with self.assertRaises(ValueError):
            MODULE.export(stage, self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertTrue(Path(stage["root"]).exists())

    def test_cross_attempt_or_workspace_config_refused_before_export(self):
        for foreign in ("audit17-native-123-3", "runner-workspace"):
            stage = self.prepare()
            self.evidence(stage)
            input_file = Path(stage["evidence"]) / "input-r1.json"
            config = json.loads(input_file.read_text())
            if foreign == "runner-workspace":
                config["driver"] = str(self.assets[NAMES[0]][0])
            else:
                config["staging_output_name"] = foreign
            input_file.write_text(json.dumps(config))
            with self.assertRaises(ValueError):
                MODULE.export(stage, self.destination)
            self.assertEqual(list(self.destination.iterdir()), [])

    def test_existing_destination_or_changed_asset_refused(self):
        stage = self.prepare()
        self.evidence(stage)
        sentinel = self.destination / "outer.log"
        sentinel.write_bytes(b"original failed attempt\n")
        with self.assertRaises(ValueError):
            MODULE.export(stage, self.destination)
        self.assertEqual(sentinel.read_bytes(), b"original failed attempt\n")
        sentinel.unlink()
        (Path(stage["root"]) / "scripts" / NAMES[0]).write_bytes(b"changed\n")
        with self.assertRaises(ValueError):
            MODULE.export(stage, self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_unclosed_or_unsignalled_child_refuses_export_without_mutation(self):
        for field in ("parent_reaped", "owned_group_signalled", "cleanup_error_type"):
            stage = self.prepare()
            self.evidence(stage)
            receipt = Path(stage["evidence"]) / "receipt-r1.json"
            record = json.loads(receipt.read_text())
            record[field] = "OSError" if field == "cleanup_error_type" else False
            receipt.write_text(json.dumps(record))
            with self.assertRaises(ValueError):
                MODULE.export(stage, self.destination)
            self.assertEqual(list(self.destination.iterdir()), [])
            self.assertTrue(Path(stage["root"]).exists())

    def test_mid_copy_failure_withholds_native_receipt_and_retains_partial_evidence(self):
        stage = self.prepare()
        self.evidence(stage)
        real_open = MODULE.os.open

        def refused_open(path, flags, *args, **kwargs):
            if path == "outer.log" and flags & os.O_CREAT:
                raise OSError("synthetic mid-copy refusal")
            return real_open(path, flags, *args, **kwargs)

        with patch.object(MODULE.os, "open", side_effect=refused_open):
            with self.assertRaises(OSError):
                MODULE.export(stage, self.destination)
        self.assertTrue((self.destination / "input-r1.json").exists())
        self.assertFalse((self.destination / "receipt-r1.json").exists())
        self.assertTrue((Path(stage["evidence"]) / "receipt-r1.json").exists())

    def test_alias_or_oversize_inventory_refused_without_output(self):
        stage = self.prepare()
        self.evidence(stage)
        link = Path(stage["evidence"]) / "inside-receipt-r1.json"
        link.symlink_to(Path(stage["evidence"]) / "receipt-r1.json")
        with self.assertRaises((ValueError, OSError)):
            MODULE.export(stage, self.destination)
        link.unlink()
        with (Path(stage["evidence"]) / "outer.log").open("wb") as output:
            output.truncate(1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            MODULE.export(stage, self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_native_source_uses_staged_argv_config_and_preserved_isolation(self):
        path = NATIVE_SOURCE_PREIMAGE or ROOT / "scripts/test-device-egress-guard-native.py"
        source = path.read_text()
        self.assertIn("staging.prepare('/tmp'", source)
        self.assertIn("exec(compile(staging_bytes,'<reviewed-private-stage>','exec'),staging.__dict__)", source)
        self.assertNotIn("spec.loader.exec_module", source)
        self.assertIn("cwd=stage['root']", source)
        self.assertIn("config={'host_namespaces':host,'helper':str(staged_helper),'driver':str(staged_driver)", source)
        self.assertIn("record.get('owned_group_signalled') is True", source)
        self.assertIn("write(out/'export-complete-r1.json'", source)
        self.assertIn("write(out/'export-failure-r1.json'", source)
        self.assertIn("str(staged_driver),'--inside',str(evidence/'input-r1.json')", source)
        self.assertNotIn("str(script),'--inside',str(out/'input-r1.json')", source)
        self.assertIn("'--user','--map-root-user','--net','--mount','--pid','--fork','--mount-proc','--kill-child=KILL'", source)
        self.assertIn("os.getpid() == 1 and os.geteuid() == 0 and all(own[n] != c['host_namespaces'][n] for n in NS)", source)
        match = re.search(r"STAGE_SHA = '([a-f0-9]{64})'", source)
        self.assertEqual(match[1], hashlib.sha256((ROOT / "scripts/deviceguard-native-private-stage.py").read_bytes()).hexdigest())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--native-source-preimage", type=Path)
    arguments, remaining = parser.parse_known_args()
    NATIVE_SOURCE_PREIMAGE = arguments.native_source_preimage
    unittest.main(argv=[__file__, *remaining])
