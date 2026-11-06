"""Inert fault controls for the explicit fresh-passive abort transaction.

The filesystem controls use real root-owned inodes only when run as root on
Linux. They never invoke systemd, nft, the installer, or a live host service.
"""

import importlib.util
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "lib" / "aegis_installer_auto_v2.py"
SPEC = importlib.util.spec_from_file_location("aegis_fresh_passive_abort_test", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AbortContract(unittest.TestCase):
    def test_cross_filesystem_directory_size_is_not_file_byte_identity(self):
        directory = {"path": ".", "mode": stat.S_IFDIR | 0o700,
                     "size": 40}
        regular = {"path": "sealed", "mode": stat.S_IFREG | 0o600,
                   "size": 3, "sha256": "a" * 64}
        self.assertEqual(MODULE._abort_rolled_copy_rows([directory, regular]),
                         MODULE._abort_rolled_copy_rows(
                             [dict(directory, size=4096), regular]))
        self.assertNotEqual(MODULE._abort_rolled_copy_rows([directory, regular]),
                            MODULE._abort_rolled_copy_rows(
                                [directory, dict(regular, size=4)]))

    def test_unreadable_proc_process_is_refusal(self):
        entry = mock.Mock(name="pid", path="/proc/31337")
        entry.name = "31337"
        with mock.patch.object(MODULE.os, "scandir", return_value=[entry]), \
             mock.patch("builtins.open", side_effect=PermissionError(13, "denied")):
            with self.assertRaises(PermissionError):
                MODULE._abort_no_source_processes()

    def test_route_hash_normalizes_only_numeric_expires(self):
        original = [{"dst": "2001:db8::/64", "gateway": "fe80::1",
                     "dev": "eth0", "table": "main", "metric": 1024,
                     "expires": 120, "cacheinfo": {"foo": 7}}]
        current = [json.loads(json.dumps(original[0]))]

        def routes(argv, **_kwargs):
            return json.dumps(current if "-6" in argv else []).encode()

        with mock.patch.object(MODULE, "call_output", side_effect=routes):
            baseline = MODULE._abort_route_hashes()
            current[0]["expires"] = 119
            self.assertEqual(MODULE._abort_route_hashes(), baseline)
            for field, value in (("gateway", "fe80::2"), ("dev", "eth1"),
                                 ("dst", "2001:db8:1::/64"), ("table", 100),
                                 ("metric", 1025), ("cacheinfo", {"foo": 8})):
                with self.subTest(field=field):
                    current[0] = json.loads(json.dumps(original[0]))
                    current[0][field] = value
                    self.assertNotEqual(MODULE._abort_route_hashes(), baseline)
            current[0] = json.loads(json.dumps(original[0]))
            del current[0]["expires"]
            self.assertNotEqual(MODULE._abort_route_hashes(), baseline)
            for value in (True, -1, "119"):
                current[0]["expires"] = value
                with self.subTest(expires=value), self.assertRaises(MODULE.Refused):
                    MODULE._abort_route_hashes()

    def test_abort_parser_has_only_lock_fd_not_incoming_package(self):
        args = MODULE.parser().parse_args(["abort-fresh-passive", "--install-fd", "9"])
        self.assertEqual((args.operation, args.install_fd), ("abort-fresh-passive", 9))
        with self.assertRaises(SystemExit):
            MODULE.parser().parse_args(["abort-fresh-passive", "--install-fd", "9",
                                        "--incoming-deb", "/tmp/foreign.deb"])

    def test_pending_marker_blocks_other_coordinator_entry_before_effects(self):
        with tempfile.TemporaryDirectory() as raw:
            pending = Path(raw) / "pending.json"
            pending.write_text("held")
            with mock.patch.object(MODULE, "PASSIVE_ABORT_PENDING", pending), \
                 mock.patch.object(MODULE, "passive_intent_locate") as locate:
                self.assertNotEqual(MODULE.main(["passive-locate", "--install-fd", "9"]), 0)
                locate.assert_not_called()

    def test_timer_readback_never_requests_service_pid_properties(self):
        requested = []

        def output(argv, **_kwargs):
            requested.extend(argv)
            return (b"Id=aegis-auto-trace-rollback.timer\nLoadState=loaded\n"
                    b"ActiveState=inactive\nSubState=dead\nNeedDaemonReload=no\n"
                    b"UnitFileState=static\n"
                    b"FragmentPath=/etc/systemd/system/aegis-auto-trace-rollback.timer\n"
                    b"DropInPaths=\nTriggers=aegis-auto-trace-rollback.service\nTriggeredBy=\n"
                    b"WantedBy=\nRequiredBy=\nBoundBy=\nUpheldBy=\n")

        with mock.patch.object(MODULE, "call_output", side_effect=output), \
             mock.patch.object(MODULE, "_abort_admin_present", return_value=True):
            self.assertEqual(MODULE._abort_unit_quiescent(
                "aegis-auto-trace-rollback.timer")["ActiveState"], "inactive")
        self.assertNotIn("ControlPID", requested)
        self.assertNotIn("MainPID", requested)
        self.assertNotIn("ControlGroup", requested)

    def test_service_stale_invocation_id_requires_other_stopped_facts(self):
        valid = {"Id": "aegis-auto-guardian.service", "LoadState": "loaded",
                 "ActiveState": "inactive", "SubState": "dead", "NeedDaemonReload": "no",
                 "UnitFileState": "disabled", "MainPID": "0", "ControlPID": "0",
                 "ControlGroup": "", "InvocationID": "a" * 32,
                 "NFileDescriptorStore": "0",
                 "FragmentPath": "/etc/systemd/system/aegis-auto-guardian.service",
                 "DropInPaths": "", "Triggers": "", "TriggeredBy": "",
                 "WantedBy": "", "RequiredBy": "aegis-auto-config.service",
                 "BoundBy": "", "UpheldBy": ""}
        with mock.patch.object(MODULE, "_abort_unit_facts", return_value=valid), \
             mock.patch.object(MODULE, "_abort_admin_present", return_value=True):
            self.assertEqual(MODULE._abort_unit_quiescent(valid["Id"]), valid)
        for key, value in (("MainPID", "31"), ("ControlGroup", "/system.slice/foreign"),
                           ("NFileDescriptorStore", "1"), ("UnitFileState", "enabled")):
            with self.subTest(key=key), mock.patch.object(
                    MODULE, "_abort_unit_facts", return_value=dict(valid, **{key: value})), \
                 mock.patch.object(MODULE, "_abort_admin_present", return_value=True):
                with self.assertRaises(MODULE.Refused):
                    MODULE._abort_unit_quiescent(valid["Id"])

    @staticmethod
    def _inactive_admin_facts(unit, state):
        facts = {"Id": unit, "LoadState": "loaded", "ActiveState": "inactive",
                 "SubState": "dead", "NeedDaemonReload": "no",
                 "UnitFileState": state,
                 "FragmentPath": "/etc/systemd/system/" + unit,
                 "DropInPaths": "", "Triggers": "", "TriggeredBy": "",
                 "WantedBy": "", "RequiredBy": "", "BoundBy": "", "UpheldBy": ""}
        if unit.endswith(".timer"):
            facts["Triggers"] = ("aegis-device-dhcp-refresh.service"
                                  if unit == "aegis-device-dhcp-refresh.timer" else
                                  "aegis-auto-trace-rollback.service")
        else:
            facts.update(MainPID="0", ControlPID="0", ControlGroup="",
                         InvocationID="", NFileDescriptorStore="0")
            if unit == "aegis-auto-trace-rollback.service":
                facts["TriggeredBy"] = "aegis-auto-trace-rollback.timer"
        return facts

    def test_abort_install_states_match_every_shipped_admin_unit(self):
        units = SOURCE.parents[2] / "packaging" / "systemd"
        for unit in MODULE.FRESH_CLIENT_UNITS:
            section = ""
            installable = False
            for line in (units / unit).read_text().splitlines():
                line = line.strip()
                if line.startswith("["):
                    section = line
                if section == "[Install]" and line.startswith("WantedBy="):
                    installable |= bool(line.partition("=")[2].strip())
            expected = "disabled" if installable else "static"
            facts = self._inactive_admin_facts(unit, expected)
            with self.subTest(unit=unit), \
                 mock.patch.object(MODULE, "_abort_unit_facts", return_value=facts), \
                 mock.patch.object(MODULE, "_abort_admin_present", return_value=True):
                self.assertEqual(MODULE._abort_unit_quiescent(unit), facts)
                for wrong in {"disabled", "static", "enabled", "enabled-runtime",
                              "masked", "linked", "indirect"} - {expected}:
                    with self.subTest(wrong=wrong), mock.patch.object(
                            MODULE, "_abort_unit_facts", return_value=dict(
                                facts, UnitFileState=wrong)):
                        with self.assertRaises(MODULE.Refused):
                            MODULE._abort_unit_quiescent(unit)

    def test_abort_disabled_monitor_still_refuses_foreign_or_live_facts(self):
        unit = "aegis-foreign-policy-monitor.service"
        facts = self._inactive_admin_facts(unit, "disabled")
        for key, value in (("WantedBy", "foreign.service"),
                           ("RequiredBy", "foreign.service"),
                           ("BoundBy", "foreign.service"),
                           ("UpheldBy", "foreign.service"),
                           ("DropInPaths", "/etc/systemd/system/foreign.conf"),
                           ("FragmentPath", "/usr/lib/systemd/system/" + unit),
                           ("MainPID", "42"), ("ControlPID", "43"),
                           ("NFileDescriptorStore", "1"),
                           ("ActiveState", "active")):
            with self.subTest(field=key), mock.patch.object(
                    MODULE, "_abort_unit_facts", return_value=dict(
                        facts, **{key: value})), mock.patch.object(
                    MODULE, "_abort_admin_present", return_value=True):
                with self.assertRaises(MODULE.Refused):
                    MODULE._abort_unit_quiescent(unit)

    def test_pending_retry_rechecks_no_prepare_before_any_stop(self):
        plan = {"source": {"public_payload_root": "/protected/source",
                           "fresh_origin": "packaged"}, "items": []}
        with tempfile.TemporaryDirectory() as raw:
            pending = Path(raw) / "pending"
            pending.write_text("pending")
            with mock.patch.object(MODULE, "PASSIVE_ABORT_PENDING", pending), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE, "fresh_package_lock"), \
                 mock.patch.object(MODULE, "_abort_pending_plan",
                                   return_value=(Path(raw), plan)), \
                 mock.patch.object(MODULE, "_passive_identity", return_value=plan["source"]), \
                 mock.patch.object(MODULE, "_passive_installed_origin"), \
                 mock.patch.object(MODULE, "_abort_unit_barrier"), \
                 mock.patch.object(MODULE, "_abort_no_effects",
                                   side_effect=MODULE.Refused()), \
                 mock.patch.object(MODULE, "call_output") as command:
                with self.assertRaises(MODULE.Refused):
                    MODULE.abort_fresh_passive(9)
                command.assert_not_called()
                self.assertTrue(pending.exists())

    def test_pre_intent_refusal_has_no_actor_or_route_effect(self):
        with tempfile.TemporaryDirectory() as raw:
            pending = Path(raw) / "pending"
            with mock.patch.object(MODULE, "PASSIVE_ABORT_PENDING", pending), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE, "fresh_package_lock"), \
                 mock.patch.object(MODULE, "_abort_completed_plan", return_value=None), \
                 mock.patch.object(MODULE, "_abort_publish_intent",
                                   side_effect=MODULE.Refused()), \
                 mock.patch.object(MODULE, "call_output") as command:
                with self.assertRaises(MODULE.Refused):
                    MODULE.abort_fresh_passive(9)
                self.assertFalse(pending.exists())
                command.assert_not_called()

    def test_foreign_capture_marker_refuses_before_route_or_rule_probe(self):
        sentinel = "/run/aegis-auto-capture-topology/owned-state.json"
        real_exists = Path.exists
        with mock.patch.object(Path, "exists", autospec=True,
                               side_effect=lambda path: str(path) == sentinel or
                               real_exists(path)), \
             mock.patch.object(MODULE, "call_output") as command:
            with self.assertRaises(MODULE.Refused):
                MODULE._abort_capture_absent()
            command.assert_not_called()

    def test_abort_diagnostic_never_echoes_exception_or_arguments(self):
        secret = "private-bundle-token-value"
        diagnostic = MODULE._abort_failure_diagnostic(MODULE.Refused(secret))
        rendered = json.dumps(diagnostic)
        self.assertNotIn(secret, rendered)
        self.assertEqual(set(diagnostic), {"schema", "status", "class", "source",
                                           "line", "errno"})
        self.assertEqual((diagnostic["status"], diagnostic["class"]),
                         ("refused", "refused"))


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "real root-owned filesystem controls require isolated Linux root")
class RootFilesystemAbortCuts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-abort-test-", dir="/var/lib")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.archive = self.root / "archive"
        self.archive.mkdir(mode=0o700)
        self.source.write_bytes(b"retained private fixture bytes\n")
        self.source.chmod(0o600)
        self.item = {"path": str(self.source), "archive_leaf": "asset-000",
                     "tree": MODULE._abort_private_tree(self.source)}

    def _unpublished_assessment(self):
        control = self.root / "control"
        control.mkdir(mode=0o700)
        for name in (MODULE.PASSIVE_INTENT, MODULE.PASSIVE_READY, "v2-enabled"):
            leaf = control / name
            leaf.write_bytes(b"{}\n")
            leaf.chmod(0o600)
        (control / MODULE.PASSIVE_INPUT).mkdir(mode=0o700)
        stage = control / "first-arm.1234abcd"
        stage.mkdir(mode=0o700)
        facts = stage / "relay-facts.json"
        # Inert history is not parsed as permission or a first-arm proof.
        facts.write_bytes(b"untrusted diagnostic bytes, never authority\n")
        facts.chmod(0o600)
        return control, stage, facts

    def _admit_abort_names(self, control):
        class ReadyReached(Exception):
            pass

        source = {"public_payload_root": "/protected/source"}
        intent = {"fresh_origin": "packaged", "boot_id": "fixture-boot",
                  "source": source}

        def record(_parent, leaf):
            if leaf == MODULE.PASSIVE_INTENT:
                return intent
            raise ReadyReached()

        with ExitStack() as stack:
            for name, value in (
                ("CONTROL", control),
                ("fresh_package_lock", lambda _fd: None),
                ("_passive_control", lambda: os.open(
                    control, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)),
                ("_passive_record", record),
                ("_passive_intent_shape", lambda _value: None),
                ("_passive_identity", lambda *_args: source),
                ("_passive_installed_origin", lambda *_args: None),
                ("_abort_failure_history", lambda *_args, **_kwargs: []),
                ("current_boot", lambda: "fixture-boot"),
            ):
                stack.enter_context(mock.patch.object(MODULE, name, value))
            with self.assertRaises(ReadyReached):
                MODULE._abort_original_facts(9)

    def test_abort_admits_unpublished_assessment_as_inert_history(self):
        control, _stage, _facts = self._unpublished_assessment()
        self._admit_abort_names(control)
        # Admission reaches ready-record authentication; later checks are intact.

    def test_abort_refuses_changed_assessment_before_plan_or_stop(self):
        control, stage, facts = self._unpublished_assessment()
        original = facts.read_bytes()
        for kind in ("symlink", "hardlink", "fifo", "writable", "oversize",
                     "unknown-leaf", "unknown-control"):
            with self.subTest(kind=kind):
                facts.unlink()
                if kind == "symlink":
                    facts.symlink_to(self.source)
                elif kind == "hardlink":
                    os.link(self.source, facts)
                elif kind == "fifo":
                    os.mkfifo(facts, 0o600)
                else:
                    facts.write_bytes(original)
                    facts.chmod(0o622 if kind == "writable" else 0o600)
                    if kind == "oversize":
                        with facts.open("r+b") as stream:
                            stream.truncate(MODULE.PASSIVE_FILE_MAX + 1)
                extra = None
                if kind in ("unknown-leaf", "unknown-control"):
                    extra = (stage if kind == "unknown-leaf" else control) / "foreign"
                    extra.write_bytes(b"foreign")
                    extra.chmod(0o600)
                with self.assertRaises((MODULE.Refused, OSError)), \
                     mock.patch.object(MODULE, "_abort_plan_items") as plan, \
                     mock.patch.object(MODULE, "call_output") as effects:
                    self._admit_abort_names(control)
                plan.assert_not_called()
                effects.assert_not_called()
                if extra is not None:
                    extra.unlink()

    def test_abort_preserves_assessment_tree_bytes_and_inodes(self):
        control, stage, facts = self._unpublished_assessment()
        self._admit_abort_names(control)
        identities = [(p.stat().st_dev, p.stat().st_ino)
                      for p in (control, stage, facts)]
        item = {"path": str(control), "archive_leaf": "asset-control",
                "tree": MODULE._abort_private_tree(control)}
        MODULE._abort_move(self.archive, item)
        MODULE._abort_move(self.archive, item)
        archived = self.archive / "asset-control"
        self.assertEqual([(p.stat().st_dev, p.stat().st_ino) for p in
                          (archived, archived / stage.name,
                           archived / stage.name / facts.name)], identities)
        self.assertEqual((archived / stage.name / facts.name).read_bytes(),
                         b"untrusted diagnostic bytes, never authority\n")

    def test_exact_file_rename_is_idempotent_and_preserves_bytes(self):
        MODULE._abort_move(self.archive, self.item)
        self.assertFalse(self.source.exists())
        self.assertEqual((self.archive / "asset-000").read_bytes(),
                         b"retained private fixture bytes\n")
        MODULE._abort_move(self.archive, self.item)
        self.assertEqual(MODULE._abort_private_tree(self.archive / "asset-000"),
                         self.item["tree"])

    def test_cut_after_rename_before_fsync_recovers_from_archived_inode(self):
        original = MODULE.os.fsync
        calls = []

        def cut(fd):
            calls.append(fd)
            if len(calls) == 1:
                raise OSError("injected cut after rename")
            return original(fd)

        with mock.patch.object(MODULE.os, "fsync", side_effect=cut):
            with self.assertRaises(OSError):
                MODULE._abort_move(self.archive, self.item)
        self.assertFalse(self.source.exists())
        self.assertTrue((self.archive / "asset-000").exists())
        MODULE._abort_move(self.archive, self.item)
        self.assertFalse(MODULE._abort_item_location(self.archive, self.item))

    def test_foreign_archive_or_changed_bytes_refused(self):
        (self.archive / "asset-000").write_bytes(b"foreign")
        with self.assertRaises(MODULE.Refused):
            MODULE._abort_move(self.archive, self.item)
        (self.archive / "asset-000").unlink()
        self.source.write_bytes(b"changed")
        with self.assertRaises(MODULE.Refused):
            MODULE._abort_move(self.archive, self.item)

    def _stage_fixture(self):
        self.stage_parent = Path(tempfile.mkdtemp(prefix="aegis-stage-cut-", dir="/run"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.stage_parent))
        stage = self.stage_parent / (".auto-" + "a" * 32)
        stage.mkdir(mode=0o700)
        (stage / ".publication-fence.lock").write_bytes(b"")
        (stage / ".stage-mutation.lock").write_bytes(b"")
        (stage / "header.json").write_bytes(b'{"phase":"rolled-back"}\n')
        (stage / "nested").mkdir(mode=0o700)
        (stage / "nested" / "sealed").write_bytes(b"private frozen bytes\n")
        for leaf in stage.rglob("*"):
            if leaf.is_file():
                leaf.chmod(0o600)
        info = stage.lstat()
        value = {"stage": str(stage),
                 "retired_path": str(self.stage_parent / "retired" / ("b" * 32)),
                 "proof": {"stage_device": info.st_dev, "stage_inode": info.st_ino},
                 "tree": MODULE._abort_rolled_stage_tree(stage)}
        return stage, value

    def test_rolled_stage_real_copy_and_partial_resume(self):
        stage, value = self._stage_fixture()
        with mock.patch.object(MODULE, "PASSIVE_ABORT_STAGE_PARENT", self.stage_parent):
            target = self.archive / "stage-copy"
            target.mkdir(mode=0o700)
            (target / ".publication-fence.lock").write_bytes(b"")
            (target / ".publication-fence.lock").chmod(0o600)
            (target / "header.json").write_bytes(b'{"phase":')
            (target / "header.json").chmod(0o600)
            MODULE._abort_rolled_copy_stage(self.archive, value, stage)
            self.assertTrue((self.archive / "stage-copy-complete.json").is_file())
            MODULE._abort_rolled_copy_stage(self.archive, value, stage)
            self.assertEqual((target / "header.json").read_bytes(),
                             (stage / "header.json").read_bytes())

    def test_rolled_stage_rejects_substitution_symlink_hardlink_fifo(self):
        stage, _ = self._stage_fixture()
        sealed = stage / "nested" / "sealed"
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                sealed.unlink()
                if kind == "symlink":
                    sealed.symlink_to(stage / "header.json")
                elif kind == "hardlink":
                    os.link(stage / "header.json", sealed)
                else:
                    os.mkfifo(sealed, 0o600)
                with self.assertRaises(MODULE.Refused):
                    MODULE._abort_rolled_stage_tree(stage)
                sealed.unlink()
                sealed.write_bytes(b"private frozen bytes\n")
                sealed.chmod(0o600)

    def test_rolled_stage_copy_rejects_foreign_prefix_and_budget(self):
        stage, value = self._stage_fixture()
        target = self.archive / "stage-copy"
        target.mkdir(mode=0o700)
        (target / "header.json").write_bytes(b"foreign")
        (target / "header.json").chmod(0o600)
        with self.assertRaises(MODULE.Refused):
            MODULE._abort_rolled_copy_stage(self.archive, value, stage)
        (target / "header.json").unlink()
        os.mkfifo(target / "header.json", 0o600)
        with self.assertRaises(MODULE.Refused):
            MODULE._abort_rolled_copy_stage(self.archive, value, stage)
        (target / "header.json").unlink()
        with mock.patch.object(MODULE.time, "monotonic", return_value=float("inf")):
            with self.assertRaises(MODULE.Refused):
                MODULE._abort_rolled_copy_stage(self.archive, value, stage)

    def test_rolled_stage_whole_directory_retirement_is_retryable(self):
        stage, value = self._stage_fixture()
        retired_parent = Path(tempfile.mkdtemp(prefix="aegis-retired-cut-", dir="/run"))
        self.addCleanup(lambda: __import__("shutil").rmtree(retired_parent))
        value["retired_path"] = str(retired_parent / ("c" * 32))
        plan = {"recovered": value, "items": [{"path": "/unused"}],
                "boot_id": MODULE.current_boot()}
        with mock.patch.object(MODULE, "PASSIVE_ABORT_STAGE_PARENT", self.stage_parent), \
             mock.patch.object(MODULE, "PASSIVE_ABORT_RETIRED_STAGES", retired_parent), \
             mock.patch.object(MODULE, "fresh_package_lock"), \
             mock.patch.object(MODULE, "_abort_item_location"), \
             mock.patch.object(MODULE, "_abort_no_effects"):
            MODULE._abort_rolled_retire_stage(self.archive, plan, 9)
            self.assertFalse(stage.exists())
            self.assertTrue(Path(value["retired_path"]).is_dir())
            MODULE._abort_rolled_retire_stage(self.archive, plan, 9)
            MODULE._abort_rolled_complete_readback(self.archive, value,
                                                    plan_boot=MODULE.current_boot())

    def test_rolled_stage_reboot_requires_complete_copy_receipt(self):
        stage, value = self._stage_fixture()
        retired_parent = Path(tempfile.mkdtemp(prefix="aegis-retired-reboot-", dir="/run"))
        self.addCleanup(lambda: __import__("shutil").rmtree(retired_parent))
        value["retired_path"] = str(retired_parent / ("c" * 32))
        with mock.patch.object(MODULE, "PASSIVE_ABORT_STAGE_PARENT", self.stage_parent):
            MODULE._abort_rolled_copy_stage(self.archive, value, stage)
            __import__("shutil").rmtree(stage)
            with mock.patch.object(MODULE, "current_boot", return_value="new-boot"):
                MODULE._abort_rolled_complete_readback(
                    self.archive, value, plan_boot="old-boot")
                (self.archive / "stage-copy-complete.json").unlink()
                with self.assertRaises(FileNotFoundError):
                    MODULE._abort_rolled_complete_readback(
                        self.archive, value, plan_boot="old-boot")

    def test_rolled_stage_reboot_refuses_missing_copy_byte(self):
        stage, value = self._stage_fixture()
        retired_parent = Path(tempfile.mkdtemp(prefix="aegis-retired-bytes-", dir="/run"))
        self.addCleanup(lambda: __import__("shutil").rmtree(retired_parent))
        value["retired_path"] = str(retired_parent / ("c" * 32))
        with mock.patch.object(MODULE, "PASSIVE_ABORT_STAGE_PARENT", self.stage_parent):
            MODULE._abort_rolled_copy_stage(self.archive, value, stage)
            __import__("shutil").rmtree(stage)
            (self.archive / "stage-copy" / "header.json").unlink()
            with mock.patch.object(MODULE, "current_boot", return_value="new-boot"):
                with self.assertRaises(MODULE.Refused):
                    MODULE._abort_rolled_complete_readback(
                        self.archive, value, plan_boot="old-boot")

    def test_rolled_stage_rejects_changed_inode_before_copy(self):
        stage, value = self._stage_fixture()
        with tempfile.TemporaryDirectory(prefix="aegis-held-stage-inode-", dir="/run") as held_raw:
            old = stage / "header.json"
            prior_file = old.stat()
            prior_stage = stage.stat()
            retained = Path(held_raw) / "old-header.json"
            old.rename(retained)
            old.write_bytes(b'{"phase":"rolled-back"}\n')
            old.chmod(0o600)
            os.utime(old, ns=(prior_file.st_atime_ns, prior_file.st_mtime_ns))
            os.utime(stage, ns=(prior_stage.st_atime_ns, prior_stage.st_mtime_ns))
            self.assertEqual(old.read_bytes(), retained.read_bytes())
            self.assertEqual(old.lstat().st_mtime_ns, retained.lstat().st_mtime_ns)
            self.assertEqual(old.lstat().st_dev, retained.lstat().st_dev)
            self.assertNotEqual(old.lstat().st_ino, retained.lstat().st_ino)
            with mock.patch.object(MODULE, "PASSIVE_ABORT_STAGE_PARENT", self.stage_parent):
                with self.assertRaises(MODULE.Refused):
                    MODULE._abort_rolled_stage_location(value)

    def test_rolled_stage_rejects_named_lock_replacement_after_flock(self):
        stage, _ = self._stage_fixture()
        fences = MODULE._abort_rolled_stage_fences(stage)
        try:
            lock = stage / ".stage-mutation.lock"
            lock.rename(stage / ".old-lock")
            lock.write_bytes(b"")
            lock.chmod(0o600)
            with self.assertRaises(MODULE.Refused):
                MODULE._abort_rolled_fences_revalidate(stage, fences)
        finally:
            for fd in reversed(fences):
                os.close(fd)

    def test_full_recovered_abort_replays_stage_and_common_rename_cuts(self):
        for cut in ("stage-copy", "stage-rename", "helper", "admin",
                    "dropin", "control", "complete"):
            with self.subTest(cut=cut), \
                 tempfile.TemporaryDirectory(prefix="aegis-rolled-run-", dir="/var/lib") as raw, \
                 tempfile.TemporaryDirectory(prefix="aegis-rolled-stage-", dir="/run") as run, \
                 tempfile.TemporaryDirectory(prefix="aegis-rolled-retired-", dir="/run") as retired:
                root = Path(raw)
                stage_parent = Path(run)
                retired_parent = Path(retired)
                stage = stage_parent / (".auto-" + "a" * 32)
                stage.mkdir(mode=0o700)
                for name, raw_bytes in ((".publication-fence.lock", b""),
                                        (".stage-mutation.lock", b""),
                                        ("header.json", b"sealed\n")):
                    leaf = stage / name
                    leaf.write_bytes(raw_bytes)
                    leaf.chmod(0o600)
                info = stage.lstat()
                source = {"public_payload_root": str(root), "fresh_origin": "packaged",
                          "candidate_sha256": "d" * 64}
                value = {"stage": str(stage),
                         "retired_path": str(retired_parent / ("b" * 32)),
                         "proof": {"stage_device": info.st_dev,
                                   "stage_inode": info.st_ino,
                                   "candidate_sha256": source["candidate_sha256"],
                                   "public_payload_root": str(root),
                                   "fresh_intent_sha256": "e" * 64},
                         "tree": MODULE._abort_rolled_stage_tree(stage)}
                archive = root / ("abort-" + "c" * 32)
                archive.mkdir(mode=0o700)
                pending = root / "fresh-passive-abort-current.json"
                pending.write_text('{"status":"pending"}\n')
                pending.chmod(0o600)
                paths = {name: root / name for name in
                         ("helper", "admin", "dropin", "control")}
                for name, path in paths.items():
                    if name == "control":
                        path.mkdir(mode=0o700)
                        (path / "sealed.json").write_bytes(b"original\n")
                        (path / "sealed.json").chmod(0o600)
                    else:
                        path.write_bytes(name.encode())
                        path.chmod(0o600)
                socket_item = {"path": str(root / "absent.sock"),
                               "archive_leaf": "asset-002",
                               "archive_path": str(root / "socket-archive" / "asset-002"),
                               "socket": {"initial_active": False, "metadata": None}}
                items = ([{"path": str(paths[name]), "archive_leaf": f"asset-{index:03d}",
                           "tree": MODULE._abort_private_tree(paths[name])}
                          for index, name in ((0, "helper"), (1, "admin"))] +
                         [socket_item] +
                         [{"path": str(paths[name]), "archive_leaf": f"asset-{index:03d}",
                           "tree": MODULE._abort_private_tree(paths[name])}
                          for index, name in ((3, "dropin"), (4, "control"))])
                plan = {"schema": "aegis_auto_v2_fresh_rolled_back_abort_v1",
                        "run_id": "c" * 32, "boot_id": "fixture-boot", "source": source,
                        "intent_sha256": "e" * 64, "failure_count": 1,
                        "items": items, "recovered": value}
                cut_once = []

                def interrupt(label):
                    if label == cut and not cut_once:
                        cut_once.append(label)
                        raise RuntimeError("injected recovered cut")

                real_copy = MODULE._abort_rolled_copy_stage
                real_retire = MODULE._abort_rolled_retire_stage
                real_move = MODULE._abort_move
                real_complete = MODULE._abort_complete_pointer

                def copy(*args):
                    real_copy(*args)
                    interrupt("stage-copy")

                def retire(*args):
                    real_retire(*args)
                    interrupt("stage-rename")

                def move(destination, item):
                    real_move(destination, item)
                    for name, path in paths.items():
                        if item["path"] == str(path):
                            interrupt(name)

                def complete(destination):
                    real_complete(destination)
                    interrupt("complete")

                def output(argv, **_kwargs):
                    if argv[-1:] == ["cleanup"]:
                        return (b'{"schema":"aegis_auto_witness_topology_cleanup_v1",'
                                b'"routes_restored":true}')
                    if argv[:2] == ["/usr/bin/systemctl", "daemon-reload"]:
                        return b""
                    raise AssertionError("unexpected command")

                with ExitStack() as stack:
                    for name, bound in (
                        ("PASSIVE_ABORT_PENDING", pending),
                        ("PASSIVE_ABORT_STAGE_PARENT", stage_parent),
                        ("PASSIVE_ABORT_RETIRED_STAGES", retired_parent),
                        ("CONTROL", paths["control"]),
                        ("PASSIVE_ABORT_WITNESS_SOCKET", Path(socket_item["path"])),
                        ("PASSIVE_ACTORS", ()),
                        ("FRESH_CLIENT_HELPERS", ("helper",)),
                        ("FRESH_CLIENT_UNITS", ("admin",)),
                        ("fresh_package_lock", lambda _fd: None),
                        ("_abort_pending_plan", lambda: (archive, plan)),
                        ("_abort_completed_plan", lambda _fd: (archive, plan)
                         if (archive / "completed.json").exists() else None),
                        ("_passive_identity", lambda *_args: source),
                        ("_passive_installed_origin", lambda *_args: None),
                        ("_abort_unit_barrier", lambda **_kwargs: []),
                        ("_abort_no_effects", lambda **_kwargs: None),
                        ("_abort_topology_absent", lambda: None),
                        ("_abort_no_source_processes", lambda: None),
                        ("_abort_route_hashes", lambda: ["base4", "base6"]),
                        ("current_boot", lambda: "fixture-boot"),
                        ("call_output", output),
                        ("_abort_rolled_copy_stage", copy),
                        ("_abort_rolled_retire_stage", retire),
                        ("_abort_move", move),
                        ("_abort_complete_pointer", complete),
                    ):
                        stack.enter_context(mock.patch.object(MODULE, name, bound))
                    with self.assertRaisesRegex(RuntimeError, "injected recovered cut"):
                        MODULE.abort_fresh_passive(9)
                    self.assertTrue(cut_once)
                    result = MODULE.abort_fresh_passive(9)
                    self.assertEqual(result["status"], "aborted-fresh-rolled-back")
                    self.assertFalse(pending.exists())
                    self.assertFalse(stage.exists())
                    self.assertTrue(Path(value["retired_path"]).is_dir())
                    self.assertTrue((archive / "stage-copy-complete.json").is_file())
                    self.assertFalse(paths["control"].exists())

    def test_only_preprepare_failures_are_inert_history(self):
        control = self.root / "control"
        control.mkdir(mode=0o700)
        name = "failure-" + "a" * 32 + ".json"
        receipt = control / name
        value = {"schema": "aegis_installer_auto_v2_failure_v1",
                 "phase": "prepare", "reason": "refused", "worker_exit": None,
                 "remaining_ms": None}
        receipt.write_text(json.dumps(value, separators=(",", ":")))
        receipt.chmod(0o600)
        with mock.patch.object(MODULE, "CONTROL", control):
            fd = MODULE.directory(control, 0o700)
            try:
                self.assertEqual(MODULE._abort_failure_history(fd), [name])
                for bad in (dict(value, phase="finalize"),
                            dict(value, worker_exit=0),
                            dict(value, remaining_ms=1)):
                    receipt.write_text(json.dumps(bad, separators=(",", ":")))
                    with self.assertRaises(MODULE.Refused):
                        MODULE._abort_failure_history(fd)
            finally:
                os.close(fd)

    def test_pending_pointer_is_renamed_only_at_final_commit(self):
        pending = self.root / "fresh-passive-abort-current.json"
        pending.write_text('{"status":"pending"}\n')
        pending.chmod(0o600)
        with mock.patch.object(MODULE, "PASSIVE_ABORT_PENDING", pending):
            MODULE._abort_complete_pointer(self.archive)
        self.assertFalse(pending.exists())
        self.assertEqual((self.archive / "completed.json").read_bytes(),
                         b'{"status":"pending"}\n')

    def test_final_pointer_cut_after_rename_has_completed_inode(self):
        pending = self.root / "fresh-passive-abort-current.json"
        pending.write_text('{"status":"pending"}\n')
        pending.chmod(0o600)
        original = MODULE.os.fsync
        calls = []

        def cut(fd):
            calls.append(fd)
            if len(calls) == 1:
                raise OSError("injected final-rename cut")
            return original(fd)

        with mock.patch.object(MODULE, "PASSIVE_ABORT_PENDING", pending), \
             mock.patch.object(MODULE.os, "fsync", side_effect=cut):
            with self.assertRaises(OSError):
                MODULE._abort_complete_pointer(self.archive)
        self.assertFalse(pending.exists())
        self.assertTrue((self.archive / "completed.json").exists())

    def test_stale_unix_socket_is_archived_but_live_bound_socket_refused(self):
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        path = runtime / "authority.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        path.chmod(0o600)
        with mock.patch.object(MODULE, "PASSIVE_ABORT_WITNESS_SOCKET", path):
            with self.assertRaises(MODULE.Refused):
                MODULE._abort_stale_witness_socket()
            listener.close()
            metadata = MODULE._abort_stale_witness_socket()
            item = {"path": str(path), "archive_leaf": "asset-000",
                    "archive_path": str(runtime / "abort-" / "asset-000"),
                    "socket": {"initial_active": False, "metadata": metadata}}
            MODULE._abort_move(self.archive, item)
            self.assertFalse(path.exists())
            self.assertTrue(stat.S_ISSOCK(Path(item["archive_path"]).lstat().st_mode))
            MODULE._abort_move(self.archive, item)

    def test_replaced_socket_inode_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="aegis-abort-replaced-", dir="/run") as raw:
            runtime = Path(raw)
            runtime.chmod(0o700)
            path = runtime / "authority.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            path.chmod(0o600)
            listener.close()
            with mock.patch.object(MODULE, "PASSIVE_ABORT_WITNESS_SOCKET", path):
                metadata = MODULE._abort_stale_witness_socket()
                with tempfile.TemporaryDirectory(prefix="aegis-held-socket-inode-", dir="/run") as held_raw:
                    retained = Path(held_raw) / "old-authority.sock"
                    path.rename(retained)
                    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    replacement.bind(str(path))
                    path.chmod(0o600)
                    replacement.close()
                    os.utime(path, ns=(path.stat().st_atime_ns,
                                       metadata["mtime_ns"]))
                    self.assertEqual(path.lstat().st_mtime_ns,
                                     retained.lstat().st_mtime_ns)
                    self.assertEqual(path.lstat().st_dev, retained.lstat().st_dev)
                    self.assertNotEqual(path.lstat().st_ino, retained.lstat().st_ino)
                    item = {"path": str(path), "archive_leaf": "asset-000",
                            "archive_path": str(runtime / "abort-" / "asset-000"),
                            "socket": {"initial_active": False, "metadata": metadata}}
                    with self.assertRaises(MODULE.Refused):
                        MODULE._abort_move(self.archive, item)

    def test_stale_runtime_socket_uses_run_same_fs_archive(self):
        with tempfile.TemporaryDirectory(prefix="aegis-abort-runtime-", dir="/run") as raw:
            runtime = Path(raw)
            runtime.chmod(0o700)
            path = runtime / "authority.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            path.chmod(0o600)
            listener.close()
            with mock.patch.object(MODULE, "PASSIVE_ABORT_WITNESS_SOCKET", path):
                metadata = MODULE._abort_stale_witness_socket()
                item = {"path": str(path), "archive_leaf": "asset-000",
                        "archive_path": str(runtime / "abort-runtime" / "asset-000"),
                        "socket": {"initial_active": False, "metadata": metadata}}
                self.assertNotEqual(path.lstat().st_dev, self.archive.stat().st_dev)
                MODULE._abort_move(self.archive, item)
                archived = Path(item["archive_path"])
                self.assertFalse(path.exists())
                self.assertEqual(archived.lstat().st_ino, metadata["ino"])
                self.assertEqual(archived.lstat().st_dev, metadata["dev"])
                MODULE._abort_move(self.archive, item)

    def test_full_abort_replays_every_owned_phase_cut(self):
        cuts = ("stop", "cleanup", "inverse", "socket", "helper", "admin",
                "reload-first", "dropin", "reload-second", "control", "complete")
        for cut in cuts:
            with self.subTest(cut=cut), \
                 tempfile.TemporaryDirectory(prefix="aegis-abort-run-", dir="/var/lib") as raw, \
                 tempfile.TemporaryDirectory(prefix="aegis-abort-sock-", dir="/run") as run_raw:
                root = Path(raw)
                runtime = Path(run_raw)
                runtime.chmod(0o700)
                archive = root / ("abort-" + "a" * 32)
                archive.mkdir(mode=0o700)
                pending = root / "fresh-passive-abort-current.json"
                pending.write_text('{"status":"pending"}\n')
                pending.chmod(0o600)
                sources = {name: root / name for name in
                           ("helper", "admin", "dropin", "control")}
                for name, path in sources.items():
                    if name == "control":
                        path.mkdir(mode=0o700)
                        (path / "failure.json").write_text("inert receipt")
                        (path / "failure.json").chmod(0o600)
                    else:
                        path.write_text(name)
                        path.chmod(0o600)
                socket_path = runtime / "authority.sock"
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(str(socket_path))
                socket_path.chmod(0o600)
                listener.close()
                socket_metadata = MODULE._abort_socket_metadata(socket_path)
                socket_item = {"path": str(socket_path), "archive_leaf": "asset-002",
                               "archive_path": str(runtime / "abort-" / "asset-002"),
                               "socket": {"initial_active": False,
                                          "metadata": socket_metadata}}
                items = [{"path": str(sources["helper"]), "archive_leaf": "asset-000",
                          "tree": MODULE._abort_private_tree(sources["helper"])},
                         {"path": str(sources["admin"]), "archive_leaf": "asset-001",
                          "tree": MODULE._abort_private_tree(sources["admin"])},
                         socket_item,
                         {"path": str(sources["dropin"]), "archive_leaf": "asset-003",
                          "tree": MODULE._abort_private_tree(sources["dropin"])},
                         {"path": str(sources["control"]), "archive_leaf": "asset-004",
                          "tree": MODULE._abort_private_tree(sources["control"])}]
                source = {"public_payload_root": str(root), "fresh_origin": "packaged"}
                plan = {"run_id": "a" * 32, "boot_id": "fixture-boot", "source": source,
                        "failure_count": 1, "items": items}
                phase = {"active": True, "dirty": False, "reloads": 0,
                         "cut_done": False, "stops": 0, "cleanups": 0}

                def interrupt(label):
                    if cut == label and not phase["cut_done"]:
                        phase["cut_done"] = True
                        raise RuntimeError("injected phase cut")

                def barrier(*, allow_active):
                    if phase["dirty"] or (phase["active"] and not allow_active):
                        raise MODULE.Refused()
                    return [{"unit": "aegis-auto-guardian.service",
                             "active": phase["active"]},
                            {"unit": "aegis-auto-witness-topology.service",
                             "active": False}]

                def output(argv, **_kwargs):
                    if argv[:2] == ["/usr/bin/systemctl", "stop"]:
                        phase["active"] = False
                        phase["stops"] += 1
                        interrupt("stop")
                        return b""
                    if argv[:2] == ["/usr/bin/systemctl", "daemon-reload"]:
                        phase["dirty"] = False
                        phase["reloads"] += 1
                        interrupt("reload-first" if phase["reloads"] == 1
                                  else "reload-second")
                        return b""
                    if argv[-1:] == ["cleanup"]:
                        phase["cleanups"] += 1
                        interrupt("cleanup")
                        return (b'{"schema":"aegis_auto_witness_topology_cleanup_v1",'
                                b'"routes_restored":true}')
                    raise AssertionError("unexpected mocked command")

                real_move = MODULE._abort_move

                def move(destination, item):
                    was_present = Path(item["path"]).exists()
                    real_move(destination, item)
                    label = ("socket" if "socket" in item else
                             next((name for name, path in sources.items()
                                   if str(path) == item["path"]), ""))
                    if label in ("admin", "dropin") and was_present:
                        phase["dirty"] = True
                    interrupt(label)

                real_write = MODULE._passive_write

                def write(parent, leaf, value):
                    real_write(parent, leaf, value)
                    if leaf == "inverse.json":
                        interrupt("inverse")

                real_complete = MODULE._abort_complete_pointer

                def complete(destination):
                    real_complete(destination)
                    interrupt("complete")

                def completed(_install_fd):
                    return (archive, plan) if (archive / "completed.json").exists() else None

                with ExitStack() as stack:
                    for name, value in (
                        ("PASSIVE_ABORT_PENDING", pending),
                        ("PASSIVE_ABORT_WITNESS_SOCKET", socket_path),
                        ("CONTROL", sources["control"]),
                        ("PASSIVE_ACTORS", (("aegis-auto-guardian.service", "", "helper"),)),
                        ("FRESH_CLIENT_HELPERS", ("helper",)),
                        ("FRESH_CLIENT_UNITS", ("admin",)),
                        ("fresh_package_lock", lambda _fd: None),
                        ("_abort_pending_plan", lambda: (archive, plan)),
                        ("_abort_completed_plan", completed),
                        ("_passive_identity", lambda *_args: source),
                        ("_passive_installed_origin", lambda *_args: None),
                        ("_abort_unit_barrier", barrier),
                        ("_abort_unit_facts", lambda _unit: {
                            "ActiveState": "active" if phase["active"] else "inactive"}),
                        ("_abort_no_effects", lambda **_kwargs: None),
                        ("_abort_no_source_processes", lambda: None),
                        ("_abort_topology_absent", lambda: None),
                        ("_abort_route_hashes", lambda: ["base4", "base6"]),
                        ("_abort_stale_witness_socket", lambda: socket_metadata),
                        ("current_boot", lambda: "fixture-boot"),
                        ("call_output", output),
                        ("_abort_move", move),
                        ("_passive_write", write),
                        ("_abort_complete_pointer", complete),
                    ):
                        stack.enter_context(mock.patch.object(MODULE, name, value))
                    with self.assertRaisesRegex(RuntimeError, "injected phase cut"):
                        MODULE.abort_fresh_passive(9)
                    self.assertEqual(phase["stops"], 1)
                    self.assertTrue(phase["cut_done"])
                    if cut == "complete":
                        self.assertFalse(pending.exists())
                        self.assertTrue((archive / "completed.json").exists())
                    else:
                        self.assertTrue(pending.exists())
                        self.assertFalse((archive / "completed.json").exists())
                    result = MODULE.abort_fresh_passive(9)
                    self.assertEqual(result["status"], "aborted-fresh-passive")
                    self.assertFalse(pending.exists())
                    self.assertTrue((archive / "completed.json").exists())
                    self.assertFalse(sources["control"].exists())
                    for item in items:
                        self.assertFalse(Path(item["path"]).exists())


if __name__ == "__main__":
    unittest.main()
