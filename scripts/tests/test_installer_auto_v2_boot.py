"""Boot coordinator fault injection only; no PID1 or installed PASS."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import contextlib
import re
import sys
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "lib/aegis_installer_auto_v2.py"
SPEC = importlib.util.spec_from_file_location("boot_coordinator_test", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BootCoordinatorFaults(unittest.TestCase):
    def test_rust_emitted_phase_vocabulary_matches_coordinator_admission(self):
        root = SOURCE.parents[2]
        boot = (root / "aegis-client/src/profile_auto_transaction/installer_v2_boot.rs").read_text()
        guardian = (root / "aegis-client/src/profile_auto_guardian.rs").read_text()
        labels = set(re.findall(r'refuse_boot_phase\("([a-z_]+)"\)', boot))
        labels.update(re.findall(r'AEGIS_AUTO_BOOT_REFUSED phase=([a-z_]+)', guardian))
        self.assertEqual(labels, MODULE._BOOT_FAILURE_PHASES)

    def test_closed_boot_phase_parser_drops_unknown_and_injected_stderr(self):
        def bounded(value):
            return value.ljust(512, b"\0")
        admitted = b"AEGIS_AUTO_BOOT_REFUSED phase=namespace_changed\n"
        self.assertEqual(MODULE._closed_boot_failure_phase(bounded(admitted)),
                         "namespace_changed")
        for raw in (b"private-key-value\n" + admitted,
                    b"AEGIS_AUTO_BOOT_REFUSED phase=private-key-value\n",
                    admitted.rstrip(b"\n") + b" private-key-value\n",
                    admitted + b"x" * 512,
                    b"AEGIS_AUTO_BOOT_REFUSED phase=namespace_changed\xff\n"):
            with self.subTest(raw=raw[:48]):
                self.assertIsNone(MODULE._closed_boot_failure_phase(bounded(raw)[:512]))

    @unittest.skipUnless(sys.platform.startswith("linux") and
                         hasattr(os, "memfd_create"), "Linux memfd fixture")
    def test_boot_child_stderr_is_bounded_and_only_fixed_phase_survives(self):
        for code, expected in (
            ("import sys;sys.stderr.write('AEGIS_AUTO_BOOT_REFUSED "
             "phase=guard_ack_preflight\\nprivate-key-value\\n');sys.exit(1)",
             "guard_ack_preflight"),
            ("import sys;sys.stderr.write('private-key-value\\nAEGIS_AUTO_BOOT_REFUSED "
             "phase=guard_ack_preflight\\n');sys.exit(1)", None),
            ("import sys;sys.stderr.write('private-key-value'*100);sys.exit(1)", None),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(MODULE.Refused) as refused:
                    MODULE.call_output([sys.executable, "-c", code],
                                       maximum=32, timeout=5,
                                       closed_boot_phase=True)
                self.assertEqual(getattr(refused.exception,
                                         "boot_failure_phase", None), expected)
                self.assertNotIn("private-key-value", str(refused.exception))

    def test_boot_coordinator_emits_only_whitelisted_phase(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"controlled executable bytes")
            error = MODULE.Refused("private-key-value")
            error.boot_failure_phase = "source_changed"
            stderr = io.StringIO()
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=None), \
                 mock.patch.object(MODULE, "held_root_file",
                                   side_effect=lambda *_: os.open(candidate, os.O_RDONLY)), \
                 mock.patch.object(MODULE, "call_output", side_effect=error), \
                 mock.patch.object(MODULE, "record_failure") as failure, \
                 contextlib.redirect_stderr(stderr):
                with self.assertRaises(MODULE.Refused):
                    MODULE.boot_current()
            self.assertEqual(stderr.getvalue(), "AUTO_V2_BOOT_REFUSED phase=source_changed\n")
            self.assertNotIn("private-key-value", stderr.getvalue())
            failure.assert_called_once()

    def boot(self, changes):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"controlled executable bytes")
            installer = b"controlled installer bytes"
            boot_raw = b"protected boot intent"
            proof = {
                "schema": "aegis_auto_v2_boot_successor_verification_v1",
                "new_boot_id": "new", "old_boot_id": "old",
                "intent_sha256": hashlib.sha256(boot_raw).hexdigest(),
                "candidate_sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
                "public_payload_root": "/var/lib/aegis-auto/releases/controlled",
                "candidate_binary": "/var/lib/aegis-auto/releases/controlled/bin/aegis-client",
                "installer_sha256": hashlib.sha256(installer).hexdigest(),
            }
            proof.update(changes)
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=None), \
                 mock.patch.object(MODULE, "boot_pending_recovery_intent", return_value=boot_raw), \
                 mock.patch.object(MODULE, "held_root_file", side_effect=lambda *_: os.open(candidate, os.O_RDONLY)), \
                 mock.patch.object(MODULE, "bounded_root_bytes", return_value=installer), \
                 mock.patch.object(MODULE, "current_boot", return_value="new"), \
                 mock.patch.object(MODULE, "call_output", return_value=json.dumps(proof).encode()), \
                 mock.patch.object(MODULE, "record_failure") as failure, \
                 mock.patch.object(MODULE, "run", return_value=True) as install:
                if changes:
                    with self.assertRaises(MODULE.Refused):
                        MODULE.boot_current()
                    install.assert_not_called()
                    failure.assert_called_once()
                    self.assertEqual(failure.call_args.args[0]["phase"], "boot_successor")
                    self.assertEqual(MODULE._PHASE, "boot_successor")
                else:
                    self.assertEqual(MODULE.boot_current(), "boot_active")
                    args = install.call_args.args[0]
                    self.assertEqual(args.existing_choice, "upgrade")
                    self.assertEqual(args.staging_parent, "/run/aegis-installer-config-snapshots")
                    self.assertEqual(args.config_root, "/etc/aegis/client")
                    self.assertIsNone(args.bundle_dir)
                    failure.assert_not_called()

    def test_foreign_or_same_boot_proof_never_reaches_prepare(self):
        for changes in ({"old_boot_id": "new"}, {"new_boot_id": "foreign"},
                        {"schema": "old-stage"}, {"candidate_sha256": "0" * 64},
                        {"public_payload_root": "/tmp/foreign"},
                        {"candidate_binary": "/usr/local/bin/aegis-client"},
                        {"installer_sha256": "0" * 64}):
            with self.subTest(changes=changes):
                self.boot(changes)

    def test_verified_new_boot_uses_fresh_production_prepare(self):
        self.boot({})

    def test_same_boot_pending_recovery_precedes_old_retirement_and_reopens_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"old source after bounded rollback")
            installer = b"controlled installer bytes"
            boot_raw = b"protected boot intent"
            candidate_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
            proof = {
                "schema": "aegis_auto_v2_boot_successor_verification_v1",
                "new_boot_id": "new", "old_boot_id": "old",
                "intent_sha256": hashlib.sha256(boot_raw).hexdigest(),
                "candidate_sha256": candidate_sha,
                "public_payload_root": "/var/lib/aegis-auto/releases/controlled",
                "candidate_binary": "/var/lib/aegis-auto/releases/controlled/bin/aegis-client",
                "installer_sha256": hashlib.sha256(installer).hexdigest(),
            }
            events = []
            pending = ({"boot_id": "new", "schema": "aegis_installer_auto_v2_boot_stage_v3"},
                       b"protected pending", None)
            def recover(_, **kwargs):
                events.append("recover")
                self.assertEqual(kwargs["expected_pointer"], b"protected pending")
                return "recovered"
            def held(*_args, **_kwargs):
                events.append("fresh-elf")
                return os.open(candidate, os.O_RDONLY)
            def begin(*_args, **_kwargs):
                events.append("begin")
                return json.dumps(proof).encode()
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "current_pointer", side_effect=[pending, None]) as pointer, \
                 mock.patch.object(MODULE, "current_boot", return_value="new"), \
                 mock.patch.object(MODULE, "boot_pending_recovery_intent", return_value=boot_raw), \
                 mock.patch.object(MODULE, "recover_current", side_effect=recover), \
                 mock.patch.object(MODULE, "held_root_file", side_effect=held), \
                 mock.patch.object(MODULE, "bounded_root_bytes", return_value=installer), \
                 mock.patch.object(MODULE, "call_output", side_effect=begin), \
                 mock.patch.object(MODULE, "run", return_value=True) as install, \
                 mock.patch.object(MODULE, "record_failure") as failure:
                self.assertEqual(MODULE.boot_current(), "boot_active")
            self.assertEqual(pointer.call_count, 2)
            self.assertEqual(events[:3], ["recover", "fresh-elf", "begin"])
            self.assertEqual(events.count("begin"), 1)
            self.assertEqual(events.count("fresh-elf"), 2)
            install.assert_called_once()
            failure.assert_not_called()

    def test_same_boot_pending_recovery_refuses_ambiguous_or_foreign_state_before_begin(self):
        with tempfile.TemporaryDirectory() as temporary:
            pending = ({"boot_id": "new", "schema": "aegis_installer_auto_v2_boot_stage_v3"},
                       b"protected pending", None)
            for after, outcome in ((pending, "recovered"), (None, "unknown")):
                with self.subTest(after=after, outcome=outcome), \
                     mock.patch.object(MODULE.sys, "platform", "linux"), \
                     mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                     mock.patch.object(MODULE, "control_directory",
                                       side_effect=lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)), \
                     mock.patch.object(MODULE, "current_pointer",
                                       side_effect=[pending, after]), \
                     mock.patch.object(MODULE, "current_boot", return_value="new"), \
                     mock.patch.object(MODULE, "boot_pending_recovery_intent"), \
                     mock.patch.object(MODULE, "recover_current", return_value=outcome) as recover, \
                     mock.patch.object(MODULE, "held_root_file") as held, \
                     mock.patch.object(MODULE, "call_output") as begin, \
                     mock.patch.object(MODULE, "record_failure") as failure:
                    with self.assertRaises(MODULE.Refused):
                        MODULE.boot_current()
                    recover.assert_called_once()
                    held.assert_not_called()
                    begin.assert_not_called()
                    failure.assert_called_once()
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "current_pointer",
                                   side_effect=MODULE.Refused("malformed pointer")), \
                 mock.patch.object(MODULE, "recover_current") as recover, \
                 mock.patch.object(MODULE, "call_output") as begin, \
                 mock.patch.object(MODULE, "record_failure") as failure:
                with self.assertRaises(MODULE.Refused):
                    MODULE.boot_current()
                recover.assert_not_called()
                begin.assert_not_called()
                failure.assert_called_once()

    def test_terminal_same_boot_recovery_returns_without_old_begin(self):
        with tempfile.TemporaryDirectory() as temporary:
            pending = ({"boot_id": "new", "schema": "aegis_installer_auto_v2_boot_stage_v3"},
                       b"protected pending", None)
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=pending), \
                 mock.patch.object(MODULE, "current_boot", return_value="new"), \
                 mock.patch.object(MODULE, "boot_pending_recovery_intent"), \
                 mock.patch.object(MODULE, "recover_current",
                                   return_value="terminal_active") as recover, \
                 mock.patch.object(MODULE, "held_root_file") as held, \
                 mock.patch.object(MODULE, "call_output") as begin:
                self.assertEqual(MODULE.boot_current(), "boot_active")
                recover.assert_called_once()
                held.assert_not_called()
                begin.assert_not_called()

    def test_completed_boot_prepare_cut_recovers_v3_before_old_begin(self):
        pending = ({"boot_id":"new", "schema":"aegis_installer_auto_v2_boot_stage_v3"},
                   b"exact v3 pointer", None)
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(MODULE.sys, "platform", "linux"), \
             mock.patch.object(MODULE.os, "geteuid", return_value=0), \
             mock.patch.object(MODULE, "control_directory",
                               side_effect=lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)), \
             mock.patch.object(MODULE, "current_pointer", side_effect=[None, pending]), \
             mock.patch.object(MODULE, "current_boot", return_value="new"), \
             mock.patch.object(MODULE, "boot_completed_before_pointer",
                               return_value=(Path("/var/lib/aegis-auto/releases/x/bin/aegis-client"),
                                             "a" * 64)), \
             mock.patch.object(MODULE, "recover_prepare_handoff") as handoff, \
             mock.patch.object(MODULE, "boot_pending_recovery_intent") as lineage, \
             mock.patch.object(MODULE, "recover_current",
                               return_value="terminal_active") as recover, \
             mock.patch.object(MODULE, "call_output") as begin:
            self.assertEqual(MODULE.boot_current(), "boot_active")
            handoff.assert_called_once_with(
                Path("/var/lib/aegis-auto/releases/x/bin/aegis-client"),
                boot_intent_sha256="a" * 64)
            lineage.assert_called_once()
            recover.assert_called_once_with(Path("/usr/local/bin/aegis-client"),
                                            expected_pointer=b"exact v3 pointer")
            begin.assert_not_called()

    def test_completed_boot_prepare_selector_refuses_v1_and_wrong_boot_sha(self):
        with tempfile.TemporaryDirectory() as temporary:
            control = Path(temporary)
            boot_sha = "a" * 64
            prepared = {"schema":"aegis_auto_v2_boot_prepare_handoff_v2",
                        "boot_intent_sha256":boot_sha, "stage":"/run/aegis-installer-config-snapshots/x"}
            completed = {"schema":"aegis_auto_v2_boot_prepare_handoff_v2",
                         "boot_intent_sha256":boot_sha,"candidate_sha256":"b" * 64}
            for name, data in ((MODULE.PREPARE_CURRENT, prepared),
                               (MODULE.PREPARE_COMPLETED, completed)):
                leaf = control / name
                leaf.write_text(json.dumps(data))
                os.chmod(leaf, 0o600)
            fd = os.open(control, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(MODULE, "current_boot", return_value="new"), \
                     mock.patch.object(MODULE, "boot_pending_recovery_intent",
                                       return_value=b"other protected intent"), \
                     mock.patch.object(MODULE, "admitted_prepare_handoff") as admitted:
                    with self.assertRaises(MODULE.Refused):
                        MODULE.boot_completed_before_pointer(fd)
                    admitted.assert_not_called()
                    prepared["schema"] = "aegis_auto_v2_prepare_handoff_v1"
                    (control / MODULE.PREPARE_CURRENT).write_text(json.dumps(prepared))
                    with self.assertRaises(MODULE.Refused):
                        MODULE.boot_completed_before_pointer(fd)
            finally:
                os.close(fd)

    def test_intent_only_boot_cut_archives_only_when_stage_absent(self):
        boot = "11234567-89ab-cdef-0123-456789abcdef"
        stage = "/run/aegis-installer-config-snapshots/.auto-" + "a" * 32
        root = "/var/lib/aegis-auto/releases/controlled"
        candidate = root + "/bin/aegis-client"
        boot_intent = {"new_boot_id":boot,"candidate_sha256":"b" * 64,
                       "candidate_binary":candidate,"public_payload_root":root}
        boot_raw = json.dumps(boot_intent).encode()
        prepared = {"schema":"aegis_auto_v2_boot_prepare_handoff_v2",
                    "phase":"intent","boot_id":boot,"stage":stage,
                    "candidate_binary":candidate,"public_payload_root":root,
                    "nonce":"c" * 32,
                    "boot_intent_sha256":hashlib.sha256(boot_raw).hexdigest()}
        prepared_raw = json.dumps(prepared).encode()
        with tempfile.TemporaryDirectory() as temporary:
            control = Path(temporary) / "control"
            staging = Path(temporary) / "staging"
            control.mkdir()
            staging.mkdir()
            (control / "generation-history").mkdir(mode=0o700)
            os.chmod(staging, 0o700)
            (control / MODULE.PREPARE_CURRENT).write_bytes(prepared_raw)
            archives = {}
            def leaf(_fd, name, *_args):
                if name in archives:
                    return archives[name], (control / MODULE.PREPARE_CURRENT).stat()
                path = control / name
                if name == "generation-boot-successor-current.json":
                    return boot_raw, (control / MODULE.PREPARE_CURRENT).stat()
                return path.read_bytes(), path.stat()
            def publish(_fd, name, raw):
                archives[name] = raw
            stage_fds = set()
            real_fstat = os.fstat
            def open_stage(*_args):
                fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
                stage_fds.add(fd)
                return fd
            def fstat(fd):
                fact = real_fstat(fd)
                if MODULE.stat.S_ISDIR(fact.st_mode):
                    stage_fds.discard(fd)
                    return mock.Mock(st_mode=MODULE.stat.S_IFDIR | 0o700,
                                     st_uid=0, st_gid=0, st_dev=fact.st_dev,
                                     st_ino=fact.st_ino, st_nlink=fact.st_nlink)
                return fact
            with mock.patch.object(MODULE, "_open_original_lock",
                                   side_effect=lambda *_: os.open(control, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(control, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "control_leaf", side_effect=leaf), \
                 mock.patch.object(MODULE, "current_pointer", return_value=None), \
                 mock.patch.object(MODULE, "current_boot", return_value=boot), \
                 mock.patch.object(MODULE, "boot_pending_recovery_intent", return_value=boot_raw), \
                 mock.patch.object(MODULE, "directory", side_effect=open_stage), \
                 mock.patch.object(MODULE, "fresh_package_lock"), \
                 mock.patch.object(MODULE, "_abort_unit_barrier", return_value=[]), \
                 mock.patch.object(MODULE, "atomic_exclusive_bytes", side_effect=publish), \
                 mock.patch.object(MODULE.os, "fstat", side_effect=fstat):
                # A present partial stage must remain untouched and refuse.
                (staging / (".auto-" + "a" * 32)).mkdir()
                os.chmod(staging / (".auto-" + "a" * 32), 0o700)
                (staging / (".auto-" + "a" * 32) / "unknown").write_bytes(b"retained")
                with self.assertRaises(MODULE.Refused):
                    MODULE.retire_boot_prepare_without_stage()
                self.assertTrue((control / MODULE.PREPARE_CURRENT).exists())
                (staging / (".auto-" + "a" * 32) / "unknown").unlink()
                if sys.platform.startswith("linux") and os.geteuid() == 0:
                    MODULE.retire_boot_prepare_without_stage()
                    self.assertTrue((staging / (".failed-boot-prepare-" +
                                                hashlib.sha256(prepared_raw).hexdigest())).is_dir())
                    self.assertFalse((staging / (".auto-" + "a" * 32)).exists())
                    self.assertFalse((control / MODULE.PREPARE_CURRENT).exists())
                    return
                (staging / (".auto-" + "a" * 32)).rmdir()
                MODULE.retire_boot_prepare_without_stage()
                self.assertFalse((control / MODULE.PREPARE_CURRENT).exists())
                self.assertEqual(list(archives.values()), [prepared_raw])

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                         "root protected stage quarantine fixture")
    def test_stage_created_receipt_quarantines_exact_preheader_bytes(self):
        boot = "11234567-89ab-cdef-0123-456789abcdef"
        root = "/var/lib/aegis-auto/releases/controlled"
        candidate = root + "/bin/aegis-client"
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            control = base / "control"
            history = control / "generation-history"
            staging = base / "staging"
            control.mkdir(mode=0o700)
            history.mkdir(mode=0o700)
            staging.mkdir(mode=0o700)
            stage = staging / (".auto-" + "a" * 32)
            stage.mkdir(mode=0o700)
            lock_leaf = stage / ".stage-mutation.lock"
            lock_leaf.write_bytes(b"")
            os.chmod(lock_leaf, 0o600)
            stage_path = "/run/aegis-installer-config-snapshots/" + stage.name
            boot_intent = {"new_boot_id":boot,"candidate_sha256":"b" * 64,
                           "candidate_binary":candidate,"public_payload_root":root}
            boot_raw = json.dumps(boot_intent).encode()
            prepared = {"schema":"aegis_auto_v2_boot_prepare_handoff_v2",
                        "phase":"intent","boot_id":boot,"stage":stage_path,
                        "candidate_binary":candidate,"public_payload_root":root,
                        "nonce":"c" * 32,
                        "boot_intent_sha256":hashlib.sha256(boot_raw).hexdigest()}
            prepared_raw = json.dumps(prepared).encode()
            facts = stage.stat()
            created = {"schema":"aegis_auto_v2_boot_stage_created_v1",
                       "prepare_intent_sha256":hashlib.sha256(prepared_raw).hexdigest(),
                       "boot_intent_sha256":prepared["boot_intent_sha256"],
                       "boot_id":boot,"stage":stage_path,
                       "stage_device":facts.st_dev,"stage_inode":facts.st_ino,
                       "candidate_binary":candidate,"public_payload_root":root}
            for name, raw in ((MODULE.PREPARE_CURRENT, prepared_raw),
                              (MODULE.PREPARE_STAGE_CREATED, json.dumps(created).encode()),
                              ("generation-boot-successor-current.json", boot_raw)):
                leaf = control / name
                leaf.write_bytes(raw)
                os.chmod(leaf, 0o600)
            with mock.patch.object(MODULE, "_open_original_lock",
                                   side_effect=lambda *_: os.open(control, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(control, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "directory",
                                   side_effect=lambda *_: os.open(staging, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=None), \
                 mock.patch.object(MODULE, "current_boot", return_value=boot), \
                 mock.patch.object(MODULE, "boot_pending_recovery_intent", return_value=boot_raw), \
                 mock.patch.object(MODULE, "fresh_package_lock"), \
                 mock.patch.object(MODULE, "_abort_unit_barrier", return_value=[]):
                MODULE.retire_boot_prepare_without_stage()
            quarantine = staging / (".failed-boot-prepare-" +
                                    hashlib.sha256(prepared_raw).hexdigest())
            self.assertFalse(stage.exists())
            self.assertEqual((quarantine / ".stage-mutation.lock").read_bytes(), b"")
            self.assertFalse((control / MODULE.PREPARE_CURRENT).exists())
            self.assertFalse((control / MODULE.PREPARE_STAGE_CREATED).exists())
            journal = history / ("prepare-quarantine-" +
                                 hashlib.sha256(prepared_raw).hexdigest() + ".json")
            self.assertEqual(json.loads(journal.read_bytes())["files"][0]["path"],
                             ".stage-mutation.lock")

    def test_boot_current_intent_only_cut_retires_before_source_reopen(self):
        events = []
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(MODULE.sys, "platform", "linux"), \
             mock.patch.object(MODULE.os, "geteuid", return_value=0), \
             mock.patch.object(MODULE, "control_directory",
                               side_effect=lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)), \
             mock.patch.object(MODULE, "current_pointer", return_value=None), \
             mock.patch.object(MODULE, "control_leaf",
                               side_effect=lambda _fd, leaf: (b"typed intent", None)
                               if leaf == MODULE.PREPARE_CURRENT else (_ for _ in ()).throw(
                                   FileNotFoundError(leaf))), \
             mock.patch.object(MODULE, "retire_boot_prepare_without_stage",
                               side_effect=lambda: events.append("retire")), \
             mock.patch.object(MODULE, "held_root_file",
                               side_effect=lambda *_: (events.append("source"),
                                   (_ for _ in ()).throw(MODULE.Refused()))[1]), \
             mock.patch.object(MODULE, "record_failure"), \
             mock.patch.object(MODULE, "call_output",
                               side_effect=lambda *_args, **_kw: (events.append("complete"),
                                   (_ for _ in ()).throw(MODULE.Refused()))[1]) as begin:
            with self.assertRaises(MODULE.Refused):
                MODULE.boot_current()
            self.assertEqual(events, ["complete", "retire", "source"])
            begin.assert_called_once()

    def test_boot_current_completes_source_stage_then_publishes_v3(self):
        pending = ({"boot_id":"new", "schema":"aegis_installer_auto_v2_boot_stage_v3"},
                   b"v3 pending", None)
        events = []
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(MODULE.sys, "platform", "linux"), \
             mock.patch.object(MODULE.os, "geteuid", return_value=0), \
             mock.patch.object(MODULE, "control_directory",
                               side_effect=lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)), \
             mock.patch.object(MODULE, "current_pointer", side_effect=[None, pending]), \
             mock.patch.object(MODULE, "current_boot", return_value="new"), \
             mock.patch.object(MODULE, "control_leaf",
                               side_effect=lambda _fd, leaf: (b"typed", None)
                               if leaf == MODULE.PREPARE_CURRENT else (_ for _ in ()).throw(
                                   FileNotFoundError(leaf))), \
             mock.patch.object(MODULE, "call_output",
                               side_effect=lambda *_args, **_kwargs:
                                   (events.append("complete"), b"stage\n")[1]), \
             mock.patch.object(MODULE, "boot_completed_before_pointer",
                               side_effect=lambda _fd:
                                   (events.append("custody"),
                                    (Path("/var/lib/aegis-auto/releases/x/bin/aegis-client"),
                                     "a" * 64))[1]), \
             mock.patch.object(MODULE, "recover_prepare_handoff",
                               side_effect=lambda *_args, **_kw: events.append("publish")), \
             mock.patch.object(MODULE, "boot_pending_recovery_intent",
                               side_effect=lambda *_args, **_kw: events.append("lineage")), \
             mock.patch.object(MODULE, "recover_current",
                               return_value="terminal_active"):
            self.assertEqual(MODULE.boot_current(), "boot_active")
            self.assertEqual(events, ["complete", "custody", "publish", "lineage"])

    def test_prepare_custody_keeps_inode_but_allows_postworker_header_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            header = stage / "header.json"
            header.write_bytes(b'{"phase":"prepared"}')
            os.chmod(header, 0o600)
            boot = "11234567-89ab-cdef-0123-456789abcdef"
            candidate = root / "candidate"
            prepared = {"schema":"aegis_auto_v2_boot_prepare_handoff_v2",
                        "phase":"intent","boot_id":boot,"stage":str(stage),
                        "candidate_binary":str(candidate),"public_payload_root":str(root),
                        "nonce":"a" * 32,"boot_intent_sha256":"b" * 64}
            intent_raw = json.dumps(prepared).encode()
            stats = stage.stat()
            created = {"schema":"aegis_auto_v2_boot_stage_created_v1",
                       "prepare_intent_sha256":hashlib.sha256(intent_raw).hexdigest(),
                       "boot_intent_sha256":prepared["boot_intent_sha256"],
                       "boot_id":boot,"stage":str(stage),
                       "stage_device":stats.st_dev,"stage_inode":stats.st_ino,
                       "candidate_binary":str(candidate),
                       "public_payload_root":str(root)}
            created_raw = json.dumps(created).encode()
            (root / MODULE.PREPARE_STAGE_CREATED).write_bytes(created_raw)
            completed = {"schema":prepared["schema"],"phase":"completed",
                         "intent_sha256":hashlib.sha256(intent_raw).hexdigest(),
                         "stage":str(stage),"stage_device":stats.st_dev,
                         "stage_inode":stats.st_ino,
                         "header_sha256":hashlib.sha256(header.read_bytes()).hexdigest(),
                         "input_generation":"c" * 64,"candidate_sha256":"d" * 64,
                         "provenance_sha256":"e" * 64,
                         "boot_intent_sha256":prepared["boot_intent_sha256"],
                         "stage_created_sha256":hashlib.sha256(created_raw).hexdigest()}
            raw = json.dumps(completed).encode()
            real_fstat = os.fstat
            def root_fstat(fd):
                fact = real_fstat(fd)
                return mock.Mock(st_mode=fact.st_mode, st_uid=0, st_gid=0,
                                 st_nlink=fact.st_nlink, st_dev=fact.st_dev,
                                 st_ino=fact.st_ino, st_size=fact.st_size)
            paths = {"candidate-binary":candidate,"public-payload-root":root}
            def staged_leaf(_parent, name, *_args):
                if name == MODULE.PREPARE_STAGE_CREATED:
                    return created_raw, None
                raise FileNotFoundError(name)
            with mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(root, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "current_boot", return_value=boot), \
                 mock.patch.object(MODULE, "control_leaf", side_effect=staged_leaf), \
                 mock.patch.object(MODULE.os, "fstat", side_effect=root_fstat):
                expected = (intent_raw, raw)
                self.assertEqual(MODULE.admitted_prepare_handoff(
                    stage, paths, expected), expected)
                header.write_bytes(b'{"phase":"finalized"}')
                with self.assertRaises(MODULE.Refused):
                    MODULE.admitted_prepare_handoff(stage, paths, expected)
                self.assertEqual(MODULE.admitted_prepare_handoff(
                    stage, paths, expected, check_prepared_header=False), expected)
                completed["stage_inode"] += 1
                with self.assertRaises(MODULE.Refused):
                    MODULE.admitted_prepare_handoff(
                        stage, paths, (intent_raw, json.dumps(completed).encode()),
                        check_prepared_header=False)
                completed["stage_inode"] -= 1
                created["stage_inode"] += 1
                created_raw = json.dumps(created).encode()
                with self.assertRaises(MODULE.Refused):
                    MODULE.admitted_prepare_handoff(
                        stage, paths, expected, check_prepared_header=False)

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                         "root-protected Linux fixture")
    def test_v3_recovery_selector_binds_intent_prepare_and_archived_seal(self):
        old_boot = "01234567-89ab-cdef-0123-456789abcdef"
        new_boot = "11234567-89ab-cdef-0123-456789abcdef"
        stage = "/run/aegis-installer-config-snapshots/stage"
        root = "/var/lib/aegis-auto/releases/controlled"
        candidate = root + "/bin/aegis-client"
        candidate_sha = "a" * 64
        intent = {"schema":"aegis_auto_v2_boot_successor_v1",
                  "old_active_sha256":"b" * 64,"old_snapshot_sha256":"c" * 64,
                  "old_pointer_sha256":"d" * 64,"verified_boot_sha256":"e" * 64,
                  "old_boot_id":old_boot,"new_boot_id":new_boot,
                  "public_payload_root":root,"candidate_binary":candidate,
                  "candidate_sha256":candidate_sha,"installer_sha256":"f" * 64}
        intent_raw = json.dumps(intent, sort_keys=True, separators=(",", ":")).encode()
        boot_sha = hashlib.sha256(intent_raw).hexdigest()
        prepare = {"schema":"aegis_auto_v2_boot_prepare_handoff_v2",
                   "phase":"intent","boot_id":new_boot,"stage":stage,
                   "candidate_binary":candidate,"public_payload_root":root,
                   "nonce":"0" * 32,"boot_intent_sha256":boot_sha}
        prepare_raw = json.dumps(prepare, sort_keys=True, separators=(",", ":")).encode()
        created = {"schema":"aegis_auto_v2_boot_stage_created_v1",
                   "prepare_intent_sha256":hashlib.sha256(prepare_raw).hexdigest(),
                   "boot_intent_sha256":boot_sha,"boot_id":new_boot,"stage":stage,
                   "stage_device":12,"stage_inode":34,
                   "candidate_binary":candidate,"public_payload_root":root}
        created_raw = json.dumps(created, sort_keys=True, separators=(",", ":")).encode()
        completed = {"schema":"aegis_auto_v2_boot_prepare_handoff_v2",
                     "phase":"completed","intent_sha256":hashlib.sha256(prepare_raw).hexdigest(),
                     "stage":stage,"stage_device":12,"stage_inode":34,
                     "header_sha256":"1" * 64,"input_generation":"2" * 64,
                     "candidate_sha256":candidate_sha,"provenance_sha256":"3" * 64,
                     "boot_intent_sha256":boot_sha,
                     "stage_created_sha256":hashlib.sha256(created_raw).hexdigest()}
        completed_raw = json.dumps(completed, sort_keys=True, separators=(",", ":")).encode()
        pointer = {"schema":"aegis_installer_auto_v2_boot_stage_v3",
                   "stage":stage,"boot_id":new_boot,"candidate_sha256":candidate_sha,
                   "boot_intent_sha256":hashlib.sha256(intent_raw).hexdigest(),
                   "prepare_intent_sha256":hashlib.sha256(prepare_raw).hexdigest(),
                   "prepare_completed_sha256":hashlib.sha256(completed_raw).hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            control = Path(temporary)
            os.chmod(control, 0o700)
            for name, raw in (
                ("generation-boot-successor-current.json", intent_raw),
                ("prepare-archive-" + pointer["prepare_intent_sha256"] + ".json", prepare_raw),
                ("prepare-archive-" + hashlib.sha256(created_raw).hexdigest() + ".json",
                 created_raw),
                ("prepare-archive-" + pointer["prepare_completed_sha256"] + ".json",
                 completed_raw),
            ):
                leaf = control / name
                leaf.write_bytes(raw)
                os.chmod(leaf, 0o600)
            fd = os.open(control, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(MODULE, "current_boot", return_value=new_boot), \
                     mock.patch.object(MODULE, "admitted_prepare_handoff",
                                       return_value=(prepare_raw, completed_raw)) as stage_admit:
                    self.assertEqual(MODULE.boot_pending_recovery_intent(
                        fd, pointer, require_v3=True), intent_raw)
                    stage_admit.assert_called_with(Path(stage),
                        {"candidate-binary":Path(candidate),
                         "public-payload-root":Path(root)},
                        (prepare_raw, completed_raw), check_prepared_header=False)
                    for key, wrong in (("stage", "/run/aegis-installer-config-snapshots/foreign"),
                                       ("candidate_sha256", "9" * 64),
                                       ("prepare_completed_sha256", "8" * 64),
                                       ("schema", "aegis_installer_auto_v2_stage_v2")):
                        with self.subTest(key=key), self.assertRaises(MODULE.Refused):
                            MODULE.boot_pending_recovery_intent(
                                fd, {**pointer, key:wrong}, require_v3=True)
                    active_report = {"stage":{"path":stage},
                                     "terminal":{"boot_id":new_boot},
                                     "input":{"candidate_sha256":candidate_sha,
                                              "public_payload_root":root,
                                              "candidate_binary":candidate}}
                    active = {"schema":"aegis_auto_v2_generation_v1",
                              "predecessor_boot_intent_sha256":
                                  pointer["boot_intent_sha256"],
                              "report":active_report,
                              "report_sha256":hashlib.sha256(json.dumps(
                                  active_report, sort_keys=True,
                                  separators=(",", ":")).encode()).hexdigest()}
                    history = control / "generation-history"
                    history.mkdir(mode=0o700)
                    archived = history / ("boot-intent-" +
                                          pointer["boot_intent_sha256"] + ".json")
                    archived.write_bytes(intent_raw)
                    os.chmod(archived, 0o600)
                    sealed = control / "generation.json"
                    sealed.write_bytes(json.dumps(active).encode())
                    os.chmod(sealed, 0o600)
                    (control / "generation-boot-successor-current.json").unlink()
                    self.assertEqual(MODULE.boot_pending_recovery_intent(
                        fd, pointer, require_v3=True), intent_raw)
                    active["report"]["stage"]["path"] = "/run/aegis-installer-config-snapshots/foreign"
                    sealed.write_bytes(json.dumps(active).encode())
                    with self.assertRaises(MODULE.Refused):
                        MODULE.boot_pending_recovery_intent(fd, pointer, require_v3=True)
            finally:
                os.close(fd)

    def test_record_stage_boot_capability_publishes_v3_only_with_exact_handoff(self):
        boot = "11234567-89ab-cdef-0123-456789abcdef"
        stage = "/run/aegis-installer-config-snapshots/stage"
        root = "/var/lib/aegis-auto/releases/controlled"
        candidate = root + "/bin/aegis-client"
        candidate_sha = "a" * 64
        intent = {"new_boot_id":boot,"candidate_sha256":candidate_sha,
                  "public_payload_root":root,"candidate_binary":candidate}
        intent_raw = json.dumps(intent, sort_keys=True).encode()
        boot_sha = hashlib.sha256(intent_raw).hexdigest()
        prepare_raw = json.dumps({"schema":"aegis_auto_v2_boot_prepare_handoff_v2",
                                  "stage":stage,"boot_id":boot,
                                  "public_payload_root":root,
                                  "candidate_binary":candidate,
                                  "boot_intent_sha256":boot_sha}).encode()
        completed_raw = json.dumps({"schema":"aegis_auto_v2_boot_prepare_handoff_v2",
                                    "stage":stage,"candidate_sha256":candidate_sha,
                                    "boot_intent_sha256":boot_sha,
                                    "intent_sha256":hashlib.sha256(prepare_raw).hexdigest()}).encode()
        handoff = (prepare_raw, completed_raw)
        published = []
        def control_leaf(_fd, leaf, *_args, **_kwargs):
            if leaf == MODULE.PREPARE_CURRENT:
                return prepare_raw, None
            if leaf == MODULE.PREPARE_COMPLETED:
                return completed_raw, None
            if leaf == MODULE.POINTER and published:
                return published[-1], None
            raise FileNotFoundError(leaf)
        def publish(_fd, leaf, raw, *_args):
            self.assertEqual(leaf, MODULE.POINTER)
            published.append(raw)
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(MODULE, "control_directory",
                               side_effect=lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)), \
             mock.patch.object(MODULE, "current_pointer", return_value=None), \
             mock.patch.object(MODULE, "current_boot", return_value=boot), \
             mock.patch.object(MODULE, "control_leaf", side_effect=control_leaf), \
             mock.patch.object(MODULE, "boot_pending_recovery_intent", return_value=intent_raw), \
             mock.patch.object(MODULE, "snapshot_old_binary", return_value=None), \
             mock.patch.object(MODULE, "atomic_exclusive_bytes", side_effect=publish):
            MODULE.record_stage(Path(stage), candidate_sha,
                                Path("/usr/local/bin/aegis-client"), handoff,
                                hashlib.sha256(intent_raw).hexdigest())
            pointer = json.loads(published[-1])
            self.assertEqual(pointer["schema"], "aegis_installer_auto_v2_boot_stage_v3")
            self.assertEqual(pointer["boot_intent_sha256"],
                             hashlib.sha256(intent_raw).hexdigest())
            self.assertEqual(pointer["prepare_intent_sha256"],
                             hashlib.sha256(prepare_raw).hexdigest())
            self.assertEqual(pointer["prepare_completed_sha256"],
                             hashlib.sha256(completed_raw).hexdigest())
            published.clear()
            with self.assertRaises(MODULE.Refused):
                MODULE.record_stage(Path(stage), candidate_sha,
                                    Path("/usr/local/bin/aegis-client"), handoff)
            published.clear()
            with self.assertRaises(MODULE.Refused):
                MODULE.record_stage(Path(stage), candidate_sha,
                                    Path("/usr/local/bin/aegis-client"), handoff,
                                    "0" * 64)
            self.assertEqual(published, [])

    def test_recovered_elf_cannot_be_claimed_under_foreign_successor_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"restored old executable")
            proof = {
                "schema": "aegis_auto_v2_boot_successor_verification_v1",
                "new_boot_id": "new", "old_boot_id": "old",
                "candidate_sha256": "0" * 64,
            }
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "current_pointer",
                                   side_effect=[({"boot_id": "new"}, b"pending", None), None]), \
                 mock.patch.object(MODULE, "current_boot", return_value="new"), \
                 mock.patch.object(MODULE, "boot_pending_recovery_intent"), \
                 mock.patch.object(MODULE, "recover_current", return_value="recovered"), \
                 mock.patch.object(MODULE, "held_root_file",
                                   side_effect=lambda *_: os.open(candidate, os.O_RDONLY)), \
                 mock.patch.object(MODULE, "call_output",
                                   return_value=json.dumps(proof).encode()) as begin, \
                 mock.patch.object(MODULE, "run") as install, \
                 mock.patch.object(MODULE, "record_failure") as failure:
                with self.assertRaises(MODULE.Refused):
                    MODULE.boot_current()
                begin.assert_called_once()
                install.assert_not_called()
                failure.assert_called_once()

    def test_failed_boot_successor_records_fixed_phase_without_source_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            with mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(parent, os.O_RDONLY |
                                                               os.O_DIRECTORY)):
                MODULE.record_failure({"phase": "boot_successor", "worker": None,
                                       "worker_started": None}, MODULE.Refused("private detail"))
            leaves = list(parent.glob("failure-*.json"))
            self.assertEqual(len(leaves), 1)
            raw = leaves[0].read_bytes()
            self.assertEqual(json.loads(raw), {
                "schema": "aegis_installer_auto_v2_failure_v1", "phase": "boot_successor",
                "reason": "refused", "worker_exit": None, "remaining_ms": None})
            self.assertNotIn(b"private detail", raw)


if __name__ == "__main__":
    unittest.main()
