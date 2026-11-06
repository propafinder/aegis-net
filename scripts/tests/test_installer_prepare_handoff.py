"""Real Linux filesystem/lock controls for the Prepare-to-pointer handoff.

No PID1, product traffic or installed acceptance is inferred from these tests.
"""

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "lib/aegis_installer_auto_v2.py"
SPEC = importlib.util.spec_from_file_location("prepare_handoff_controls", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Interrupted(Exception):
    pass


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "requires an isolated root Linux filesystem")
class PrepareHandoffControls(unittest.TestCase):
    def setUp(self):
        self.lock = Path("/run/aegis-auto-install.lock")
        if self.lock.exists() or self.lock.is_symlink():
            self.skipTest("original install lock already exists; never replace it")
        lock = os.open(self.lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.lock_identity = os.fstat(lock).st_ino
        os.close(lock)
        self.root = Path(tempfile.mkdtemp(prefix="aegis-handoff-", dir="/root"))
        self.root.chmod(0o700)
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        parent = Path("/run/aegis-installer-config-snapshots")
        parent.mkdir(mode=0o700, exist_ok=True)
        self.stage = Path(tempfile.mkdtemp(prefix="handoff-control-", dir=parent))
        self.stage.chmod(0o700)
        authority = b'{"logical_bundle":null,"references":[]}'
        (self.stage / "input").mkdir(mode=0o700)
        (self.stage / "input/authority.json").write_bytes(authority)
        (self.stage / "input/authority.json").chmod(0o600)
        self.header = json.dumps({"mode": "socks-only", "plan": {"product_mode": "socks-only"},
                                  "leaves": {"input/authority.json": hashlib.sha256(authority).hexdigest()}}).encode()
        (self.stage / "header.json").write_bytes(self.header)
        (self.stage / "header.json").chmod(0o600)
        self.release = self.root / "release"
        (self.release / "bin").mkdir(parents=True, mode=0o700)
        installed = self.root / "installed"
        installed.mkdir(mode=0o700)
        self.candidate = self.release / "bin/aegis-client"
        self.candidate.write_bytes(b"immutable candidate for bookkeeping controls")
        self.candidate.chmod(0o555)
        self.candidate_sha = hashlib.sha256(self.candidate.read_bytes()).hexdigest()
        stage_info = self.stage.stat()
        self.intent = {
            "schema": "aegis_auto_v2_prepare_handoff_v1", "phase": "intent",
            "boot_id": MODULE.current_boot(), "stage": str(self.stage),
            "candidate_binary": str(self.candidate),
            "public_payload_root": str(self.release), "nonce": "1" * 32,
        }
        self.intent_raw = json.dumps(self.intent, separators=(",", ":")).encode()
        self.complete = {
            "schema": self.intent["schema"], "phase": "completed",
            "intent_sha256": hashlib.sha256(self.intent_raw).hexdigest(),
            "stage": str(self.stage), "stage_device": stage_info.st_dev,
            "stage_inode": stage_info.st_ino,
            "header_sha256": hashlib.sha256(self.header).hexdigest(),
            "input_generation": "2" * 64, "candidate_sha256": self.candidate_sha,
            "provenance_sha256": "3" * 64,
        }
        self.complete_raw = json.dumps(self.complete, separators=(",", ":")).encode()
        self.handoff = self.intent_raw, self.complete_raw
        for leaf, raw in zip((MODULE.PREPARE_CURRENT, MODULE.PREPARE_COMPLETED), self.handoff):
            (self.control / leaf).write_bytes(raw)
            (self.control / leaf).chmod(0o600)
        self.paths = {"candidate-binary": self.candidate,
                      "public-payload-root": self.release,
                      "installed-binary": Path("/usr/local/bin/aegis-client")}
        directory = MODULE.directory

        def fixture_directory(path, mode=None):
            # Keep the production pointer's fixed pathname while directing its
            # parent fd to the fixture's real root-owned directory. Never rely
            # on or change the runner's /usr/local/bin ownership or contents.
            return directory(installed if Path(path) == Path("/usr/local/bin")
                             else path, mode)

        directory_patch = mock.patch.object(MODULE, "directory",
                                            side_effect=fixture_directory)
        directory_patch.start()
        self.addCleanup(directory_patch.stop)
        self.patch = mock.patch.object(MODULE, "control_directory", side_effect=lambda:
                                      os.open(self.control, os.O_RDONLY | os.O_DIRECTORY))
        self.patch.start()
        self.control_patch = mock.patch.object(MODULE, "CONTROL", self.control)
        self.control_patch.start()
        self.progress = {"phase": "prepare"}

    def tearDown(self):
        self.control_patch.stop()
        self.patch.stop()
        shutil.rmtree(self.stage)
        shutil.rmtree(self.root)
        self.assertEqual(self.lock.stat().st_ino, self.lock_identity)
        self.lock.unlink()

    def publish(self):
        return MODULE.record_prepared_stage(self.stage, self.paths, SimpleNamespace(),
                                            self.progress)

    def assert_consumed(self):
        with (self.control / MODULE.POINTER).open() as stream:
            pointer = json.load(stream)
        self.assertEqual(pointer["stage"], str(self.stage))
        self.assertEqual(pointer["candidate_sha256"], self.candidate_sha)
        self.assertEqual(pointer["boot_id"], MODULE.current_boot())
        self.assertEqual((self.control / MODULE.POINTER).stat().st_mode & 0o777, 0o600)
        for leaf, raw in zip((MODULE.PREPARE_CURRENT, MODULE.PREPARE_COMPLETED), self.handoff):
            self.assertFalse((self.control / leaf).exists())
            archive = self.control / ("prepare-archive-" + hashlib.sha256(raw).hexdigest() + ".json")
            self.assertEqual(archive.read_bytes(), raw)
            self.assertEqual(archive.stat().st_mode & 0o777, 0o600)

    def test_completed_prepare_publishes_pointer_before_retiring_handoff(self):
        original = MODULE.atomic_exclusive_bytes
        mutations = []

        def publish(parent, leaf, raw, *args):
            competitor = os.open(self.lock, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(competitor)
            if leaf.startswith("prepare-archive-"):
                self.assertTrue((self.control / MODULE.POINTER).exists())
            mutations.append(leaf)
            return original(parent, leaf, raw, *args)

        with mock.patch.object(MODULE, "atomic_exclusive_bytes", side_effect=publish):
            self.publish()
        self.assertEqual(mutations[0], MODULE.POINTER)
        self.assert_consumed()

    def test_crash_before_or_after_each_atomic_publication_replays(self):
        leaves = [MODULE.POINTER] + ["prepare-archive-" + hashlib.sha256(raw).hexdigest() + ".json"
                                     for raw in self.handoff]
        for leaf in leaves:
            for after in (False, True):
                with self.subTest(leaf=leaf, after=after):
                    original = MODULE.atomic_exclusive_bytes

                    def crash(parent, target, raw, *args):
                        if target == leaf and not after:
                            raise Interrupted()
                        result = original(parent, target, raw, *args)
                        if target == leaf:
                            raise Interrupted()
                        return result

                    with mock.patch.object(MODULE, "atomic_exclusive_bytes", side_effect=crash):
                        with self.assertRaises(Interrupted):
                            self.publish()
                    MODULE.recover_prepare_handoff(self.candidate)
                    self.assert_consumed()
                    # Each cut starts from a new exact protected Prepare pair.
                    for name in os.listdir(self.control):
                        (self.control / name).unlink()
                    for target, raw in zip((MODULE.PREPARE_CURRENT, MODULE.PREPARE_COMPLETED), self.handoff):
                        (self.control / target).write_bytes(raw)
                        (self.control / target).chmod(0o600)

    def test_crash_after_each_fixed_leaf_retirement_replays(self):
        for leaf in (MODULE.PREPARE_CURRENT, MODULE.PREPARE_COMPLETED):
            with self.subTest(leaf=leaf):
                unlink = MODULE.os.unlink

                def crash(target, *args, **kwargs):
                    result = unlink(target, *args, **kwargs)
                    if target == leaf:
                        raise Interrupted()
                    return result

                with mock.patch.object(MODULE.os, "unlink", side_effect=crash):
                    with self.assertRaises(Interrupted):
                        self.publish()
                MODULE.recover_prepare_handoff(self.candidate)
                self.assert_consumed()
                for name in os.listdir(self.control):
                    (self.control / name).unlink()
                for target, raw in zip((MODULE.PREPARE_CURRENT, MODULE.PREPARE_COMPLETED), self.handoff):
                    (self.control / target).write_bytes(raw)
                    (self.control / target).chmod(0o600)

    def test_incomplete_prepare_never_mints_pointer(self):
        (self.control / MODULE.PREPARE_COMPLETED).unlink()
        with self.assertRaises(MODULE.Refused):
            MODULE.recover_prepare_handoff(self.candidate)
        self.assertFalse((self.control / MODULE.POINTER).exists())
        self.assertTrue((self.control / MODULE.PREPARE_CURRENT).exists())

    def test_changed_stage_header_refuses_without_pointer_or_retirement(self):
        (self.stage / "header.json").write_bytes(b"different header")
        with self.assertRaises(MODULE.Refused):
            self.publish()
        self.assertFalse((self.control / MODULE.POINTER).exists())
        self.assertTrue((self.control / MODULE.PREPARE_CURRENT).exists())

    def test_foreign_candidate_refuses_recovery_without_pointer(self):
        other = self.release / "bin/other-client"
        other.write_bytes(self.candidate.read_bytes())
        other.chmod(0o555)
        with self.assertRaises(MODULE.Refused):
            MODULE.recover_prepare_handoff(other)
        self.assertFalse((self.control / MODULE.POINTER).exists())

    def test_recovery_rechecks_passive_reference_even_with_valid_handoff_header(self):
        snapshot = self.control / MODULE.PASSIVE_INPUT
        expected = b"original certificate"
        captured = b"foreign certificate"
        leaf = "input/references/0000/bytes"
        (self.stage / "input/references/0000").mkdir(mode=0o700, parents=True)
        (self.stage / leaf).write_bytes(captured)
        (self.stage / leaf).chmod(0o600)
        authority = json.dumps({"logical_bundle": str(snapshot), "references": [{
            "stage_bytes": leaf, "generation_leaf": "input/references/0000/metadata.json",
            "original_path": str(snapshot / "inner/ca.pem"),
            "final_path": "/etc/aegis/client/inner/ca.pem", "expected_uid": 0}]}).encode()
        (self.stage / "input/authority.json").write_bytes(authority)
        header = {"mode": "socks-only", "plan": {"product_mode": "socks-only"}, "leaves": {
            "input/authority.json": hashlib.sha256(authority).hexdigest(),
            leaf: hashlib.sha256(captured).hexdigest()}}
        self.header = json.dumps(header).encode()
        (self.stage / "header.json").write_bytes(self.header)
        self.complete["header_sha256"] = hashlib.sha256(self.header).hexdigest()
        self.complete_raw = json.dumps(self.complete, separators=(",", ":")).encode()
        (self.control / MODULE.PREPARE_COMPLETED).write_bytes(self.complete_raw)
        passive = {"schema": "aegis_auto_v2_fresh_passive_intent_v1",
                   "boot_id": MODULE.current_boot(), "fresh_origin": "packaged",
                   "source": {"public_payload_root": str(self.release), "fresh_origin": "packaged",
                              "package_sha256": "4" * 64, "source_tree_sha256": "5" * 64,
                              "candidate_sha256": self.candidate_sha, "installer_sha256": "6" * 64},
                   "original_bundle": "/root/original-bundle", "bundle_files": {
                       "aegis-client.toml": {"size": 1, "sha256": "7" * 64},
                       "ca.pem": {"size": 1, "sha256": "8" * 64},
                       "aegis-client-privileged-dns.toml": None, "masque-ca.pem": None},
                   "options_sha256": MODULE._passive_optional(dict.fromkeys(MODULE.PASSIVE_OPTIONS)),
                   "external_refs": [{"path": "/root/original-bundle/inner/ca.pem",
                                      "snapshot_relative": "inner/ca.pem", "size": len(expected),
                                      "sha256": hashlib.sha256(expected).hexdigest()}]}
        (self.control / MODULE.PASSIVE_INTENT).write_text(json.dumps(passive))
        (self.control / MODULE.PASSIVE_INTENT).chmod(0o600)
        # Header/complete digests are internally valid, but the original
        # protected passive intent still binds different credential bytes.
        MODULE.admitted_prepare_handoff(self.stage, self.paths)
        with self.assertRaises(MODULE.Refused):
            MODULE.recover_prepare_handoff(self.candidate)
        self.assertFalse((self.control / MODULE.POINTER).exists())
        self.assertTrue((self.control / MODULE.PREPARE_CURRENT).exists())
        self.assertTrue((self.control / MODULE.PREPARE_COMPLETED).exists())

    def test_partial_retirement_with_substituted_archive_refuses(self):
        unlink = MODULE.os.unlink

        def crash(target, *args, **kwargs):
            result = unlink(target, *args, **kwargs)
            if target == MODULE.PREPARE_CURRENT:
                raise Interrupted()
            return result

        with mock.patch.object(MODULE.os, "unlink", side_effect=crash):
            with self.assertRaises(Interrupted):
                self.publish()
        archive = self.control / ("prepare-archive-" + hashlib.sha256(self.intent_raw).hexdigest() + ".json")
        archive.write_bytes(b"substituted")
        before = (self.control / MODULE.POINTER).read_bytes()
        with self.assertRaises(MODULE.Refused):
            MODULE.recover_prepare_handoff(self.candidate)
        self.assertEqual((self.control / MODULE.POINTER).read_bytes(), before)
        self.assertTrue((self.control / MODULE.PREPARE_COMPLETED).exists())

    def test_existing_pointer_is_never_replaced(self):
        self.publish()
        before = (self.control / MODULE.POINTER).read_bytes()
        for leaf, raw in zip((MODULE.PREPARE_CURRENT, MODULE.PREPARE_COMPLETED), self.handoff):
            (self.control / leaf).write_bytes(raw)
            (self.control / leaf).chmod(0o600)
        with self.assertRaises(MODULE.Refused):
            self.publish()
        self.assertEqual((self.control / MODULE.POINTER).read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
