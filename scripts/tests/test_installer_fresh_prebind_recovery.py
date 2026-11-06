"""Coordinator crash/lock controls; simulated actors are not native evidence."""

from contextlib import ExitStack
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "lib/aegis_installer_auto_v2.py"
SPEC = importlib.util.spec_from_file_location("fresh_prebind_coordinator", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FreshPrebindRecovery(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        temporary = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.home = Path(temporary)
        self.old = self.home / "old"
        self.new = self.home / "new"
        self.control = self.home / "control"
        self.control.mkdir()
        self.lock = self.home / "lock"
        self.lock.touch(mode=0o600)
        self.pending = self.home / "abort-pending"
        (self.home / "phase").write_text("Prepared")
        (self.home / "fault").write_text("")
        for root in (self.old, self.new):
            (root / "bin").mkdir(parents=True)
            actor = root / "bin/aegis-client"
            actor.write_text("#!" + sys.executable + "\n" + f"home={str(self.home)!r}\n" + '''
import fcntl,pathlib,sys
h=pathlib.Path(home)
with (h/'lock').open('r+') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    assert sys.argv[1]=='auto-rollback-fresh-prebind'
    for step in ('header','archive'):
        with (h/'trace').open('a') as out:out.write(step+'\\n')
        fault=(h/'fault').read_text()
        if fault==step+'-before':raise SystemExit(1)
        if step=='header':
            assert (h/'phase').read_text() in ('Prepared','RolledBack') and not (h/'archived').exists()
            (h/'phase').write_text('RolledBack')
        else:
            assert (h/'phase').read_text()=='RolledBack'
            (h/'archived').touch()
        if fault==step+'-after':raise SystemExit(1)
        if fault==step+'-stdout':
            print('untrusted')
            raise SystemExit(0)
''')
            actor.chmod(0o555)
        self.pointer = {"boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                        "stage": "/run/aegis-installer-config-snapshots/.auto-" + "a" * 32,
                        "candidate_sha256": "a" * 64,
                        "previous_binary": {"sha256": "a" * 64}}
        self.source = {"public_payload_root": str(self.old), "candidate_sha256": "a" * 64}
        intent = {"fresh_origin": "packaged", "boot_id": self.pointer["boot_id"],
                  "source": self.source}
        for target, name, kwargs in (
            (MODULE.sys, "platform", {"new": "linux"}),
            (MODULE.os, "geteuid", {"return_value": 0}),
            (MODULE, "CONTROL", {"new": self.control}),
            (MODULE, "PASSIVE_ABORT_PENDING", {"new": self.pending}),
            (MODULE, "_incoming_upgrade_coordinator", {}),
            (MODULE, "signed_client_package", {}),
            (MODULE, "_open_original_lock", {"side_effect": self.open_lock}),
            (MODULE, "fresh_package_lock", {"side_effect": lambda fd: os.fstat(fd)}),
            (MODULE, "control_directory", {"side_effect": lambda: os.open(self.control, os.O_RDONLY)}),
            (MODULE, "current_pointer", {"side_effect": lambda _fd: None if
                (self.home / "archived").exists() else (self.pointer, b"pending", None)}),
            (MODULE, "current_boot", {"return_value": self.pointer["boot_id"]}),
            (MODULE, "_passive_record", {"return_value": intent}),
            (MODULE, "_passive_intent_shape", {}),
            (MODULE, "_passive_identity", {"side_effect": lambda *_args: self.source}),
            (MODULE, "_passive_installed_origin", {}),
        ):
            self.stack.enter_context(mock.patch.object(target, name, **kwargs))

    def open_lock(self, *_args):
        fd = os.open(self.lock, os.O_RDWR | os.O_CLOEXEC)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd

    def recover(self):
        return MODULE.recover_fresh_prepared(self.new)

    def test_typed_actor_can_take_exclusive_lock_and_archive(self):
        self.assertEqual(self.recover(), "recovered")
        self.assertEqual((self.home / "trace").read_text(), "header\narchive\n")
        self.assertEqual((self.home / "phase").read_text(), "RolledBack")

    def test_before_header_failure_never_calls_old_archive(self):
        (self.home / "fault").write_text("header-before")
        with self.assertRaises(MODULE.Refused):
            self.recover()
        self.assertEqual((self.home / "trace").read_text(), "header\n")
        self.assertEqual((self.home / "phase").read_text(), "Prepared")

    def test_lost_header_response_stops_then_retries_idempotently(self):
        (self.home / "fault").write_text("header-after")
        with self.assertRaises(MODULE.Refused):
            self.recover()
        self.assertFalse((self.home / "archived").exists())
        (self.home / "fault").write_text("")
        self.assertEqual(self.recover(), "recovered")
        self.assertEqual((self.home / "trace").read_text(), "header\nheader\narchive\n")

    def test_old_archive_failure_preserves_rolled_back_for_retry(self):
        (self.home / "fault").write_text("archive-before")
        with self.assertRaises(MODULE.Refused):
            self.recover()
        self.assertEqual((self.home / "phase").read_text(), "RolledBack")
        self.assertFalse((self.home / "archived").exists())
        (self.home / "fault").write_text("")
        self.assertEqual(self.recover(), "recovered")

    def test_lost_archive_response_requires_independent_abort_readback(self):
        (self.home / "fault").write_text("archive-after")
        with self.assertRaises(MODULE.Refused):
            self.recover()
        self.assertEqual(self.recover(), "abort-readback-required")
        self.assertEqual((self.home / "trace").read_text(), "header\narchive\n")

    def test_unexpected_header_stdout_never_falls_through(self):
        (self.home / "fault").write_text("header-stdout")
        with self.assertRaises(MODULE.Refused):
            self.recover()
        self.assertFalse((self.home / "archived").exists())

    def test_upgrade_candidate_is_rejected_before_any_actor(self):
        self.pointer["previous_binary"]["sha256"] = "b" * 64
        with self.assertRaises(MODULE.Refused):
            self.recover()
        self.assertFalse((self.home / "trace").exists())

    def test_existing_abort_plan_is_authenticated_then_only_resumed(self):
        self.pending.write_text("pending")
        with mock.patch.object(MODULE, "_abort_pending_plan") as plan:
            self.assertEqual(self.recover(), "abort-readback-required")
            plan.assert_called_once_with()
        self.assertFalse((self.home / "trace").exists())
        with mock.patch.object(MODULE, "_abort_pending_plan", side_effect=MODULE.Refused):
            with self.assertRaises(MODULE.Refused):
                self.recover()


if __name__ == "__main__":
    unittest.main()
