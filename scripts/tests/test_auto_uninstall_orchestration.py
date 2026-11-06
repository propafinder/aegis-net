"""Actual coordinator reboot and package replay branches with bounded mocks."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "lib/aegis_installer_auto_v2.py"
SPEC = importlib.util.spec_from_file_location("aegis_auto_uninstall_orchestration", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


class RebootCoordinatorTest(unittest.TestCase):
    def setUp(self):
        self.pointer_raw = b"protected historical pointer"
        self.owners = [{"path": "/owner", "kind": "file", "content_sha256": "a" * 64}]
        self.guard = {"content_sha256": "b" * 64}
        self.intent = {"boot_id": "old-boot", "stage": "/run/stage",
                       "pointer_sha256": hashlib.sha256(self.pointer_raw).hexdigest(),
                       "candidate_sha256": "c" * 64,
                       "owner_manifest_sha256": hashlib.sha256(
                           canonical(self.owners)).hexdigest(),
                       "guard_config_sha256": self.guard["content_sha256"],
                       "version": "1.2.3-1"}
        self.phases = []
        self.advanced = []

    def run_reboot(self, pointer_state, *, owners=None, guard=None, version=None):
        result = {"schema": "aegis_auto_v2_uninstall_reboot_observation_v1",
                  "stage": self.intent["stage"], "old_boot_id": "old-boot",
                  "new_boot_id": "new-boot", "candidate_sha256": "c" * 64,
                  "pointer_sha256": self.intent["pointer_sha256"],
                  "pointer_state": pointer_state,
                  "active_report_sha256": "d" * 64,
                  "boot_proof": {"schema": "aegis_auto_v2_verified_boot_v1"}}
        result_raw = canonical(result)
        owners = self.owners if owners is None else owners
        guard = self.guard if guard is None else guard
        version = self.intent["version"] if version is None else version

        def advance(_fd, state, _observation):
            self.advanced.append(state)
            self.phases.append(({"state": state}, "a" * 64))
            return self.intent, self.phases

        journal = SimpleNamespace(directory=lambda: 91,
                                  read=lambda _fd: (self.intent, self.phases),
                                  canonical=canonical, advance=advance)
        def output(args, **_kwargs):
            return result_raw if args[0].endswith("aegis-client") else \
                ("install ok installed\n" + version + "\n").encode()

        patches = (
            mock.patch.object(MODULE, "uninstall_journal", journal),
            mock.patch.object(MODULE.sys, "platform", "linux"),
            mock.patch.object(MODULE.os, "geteuid", return_value=0),
            mock.patch.object(MODULE.os, "close", return_value=None),
            mock.patch.object(MODULE, "held_root_file", return_value=92),
            mock.patch.object(MODULE, "file_sha", return_value=(1, "c" * 64)),
            mock.patch.object(MODULE, "current_boot", return_value="new-boot"),
            mock.patch.object(MODULE, "call_output", side_effect=output),
            mock.patch.object(MODULE, "_uninstall_source_facts", return_value=(
                {"stage": self.intent["stage"], "candidate_sha256": "c" * 64},
                self.pointer_raw, owners, version, guard)),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8]:
            return MODULE.uninstall_stop_and_archive()

    def test_intent_only_pending_reconciles_exact_owners_guard_and_version(self):
        self.assertEqual(self.run_reboot("pending")["state"], "reboot-observed")
        self.assertEqual(self.advanced, ["admitted", "reboot-observed"])
        for kind, changes in (
            ("owners", {"owners": [{"path": "/changed"}]}),
            ("guard", {"guard": {"content_sha256": "e" * 64}}),
            ("version", {"version": "9.9.9-1"}),
        ):
            with self.subTest(kind=kind):
                self.phases.clear()
                self.advanced.clear()
                with self.assertRaises(MODULE.Refused):
                    self.run_reboot("pending", **changes)
                self.assertEqual(self.advanced, [])

    def test_stopped_seal_and_archived_pointer_reconcile_without_old_stage(self):
        for state in ("stopped-sealed", "stopped-archived"):
            with self.subTest(state=state):
                self.phases.clear()
                self.advanced.clear()
                self.assertEqual(self.run_reboot(state)["state"], "reboot-observed")
                self.assertEqual(self.advanced, ["admitted", "reboot-observed"])

    def test_exact_dpkg_partial_states_retry_and_foreign_status_refuses(self):
        for status in (b"deinstall ok config-files", b"purge ok config-files",
                       b"deinstall ok half-installed", b"install ok installed"):
            self.assertTrue(MODULE._uninstall_dpkg_retry_needed(
                SimpleNamespace(returncode=0, stdout=status, stderr=b"")))
        for status in (b"install reinstreq half-installed", b"install ok unpacked"):
            with self.assertRaises(MODULE.Refused):
                MODULE._uninstall_dpkg_retry_needed(
                    SimpleNamespace(returncode=0, stdout=status, stderr=b""))
        self.assertFalse(MODULE._uninstall_dpkg_retry_needed(SimpleNamespace(
            returncode=1, stdout=b"", stderr=
            b"dpkg-query: no packages found matching aegis-client\n")))
        for error in (b"dpkg database locked\n", b"permission denied\n", b""):
            with self.subTest(error=error), self.assertRaises(MODULE.Refused):
                MODULE._uninstall_dpkg_retry_needed(SimpleNamespace(
                    returncode=1, stdout=b"", stderr=error))

    def test_every_backed_generic_root_must_be_absent_for_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            MODULE._uninstall_generic_roots_absent(temporary)
            for source in MODULE.uninstall_journal.GENERIC_PURGE_ROOTS:
                with self.subTest(source=source):
                    path = Path(temporary) / source.lstrip("/")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"retained residue")
                    with self.assertRaises(MODULE.Refused):
                        MODULE._uninstall_generic_roots_absent(temporary)
                    path.unlink()

    def test_terminal_journal_resumes_partial_dpkg_without_installed_helper(self):
        terminal = [({"state": state}, "a" * 64)
                    for state in MODULE.uninstall_journal.STATES]
        journal = SimpleNamespace(directory=lambda: 91,
                                  absent=lambda _fd, _name: False,
                                  read=lambda _fd: (self.intent, terminal))
        with mock.patch.object(MODULE, "uninstall_journal", journal), \
             mock.patch.object(MODULE, "_passive_removal_journal_kind", return_value="active"), \
             mock.patch.object(MODULE.sys, "platform", "linux"), \
             mock.patch.object(MODULE.os, "geteuid", return_value=0), \
             mock.patch.object(MODULE.os, "close", return_value=None), \
             mock.patch.object(MODULE, "uninstall_purge",
                               return_value={"state": "completed"}) as purge, \
             mock.patch.object(MODULE, "_uninstall_source_facts") as source:
            self.assertEqual(MODULE.uninstall_all(), {"state": "completed"})
            purge.assert_called_once_with()
            source.assert_not_called()


class InterruptedOwnerRetirementTest(unittest.TestCase):
    def setUp(self):
        self.units = MODULE.UNINSTALL_OWNERS[5:]
        self.expected = {owner.lstrip("/"): {"path": owner.lstrip("/"),
                         "kind": "absent"} for owner in self.units}
        self.owner = self.units[0]
        self.entry = {"path": self.owner.lstrip("/"), "kind": "file",
                      "mode": 0o644, "device": 7, "inode": 11,
                      "size": 9, "sha256": "a" * 64}
        self.expected[self.owner.lstrip("/")] = self.entry

    def run_reconcile(self, *, retired=False, tampered=False, active=False,
                      split=False, queued_job=None, reappeared_guard=False,
                      active_foreign=False):
        def inventory(paths):
            path = paths[0]
            if path.startswith("/var/lib/aegis-auto-uninstall/backup/retired-"):
                index = int(path.rsplit("-", 1)[1])
                owner = MODULE.UNINSTALL_OWNERS[index]
                found = retired and owner == self.owner
            else:
                owner = path
                found = owner == self.owner and not retired
            if not found:
                entry = {"path": path.lstrip("/"), "kind": "absent"}
            else:
                entry = {**self.entry, "path": path.lstrip("/")}
                if tampered:
                    entry["sha256"] = "b" * 64
            return {"entries": [entry]}

        journal = SimpleNamespace(
            verify_backup=lambda _fd, _owners, _sha: {
                "entries": list(self.expected.values())},
            source_manifest=inventory)
        facts = {"LoadState": "loaded", "FragmentPath":
                 "/etc/systemd/system/aegis-auto-guardian.service"}
        def stopped(unit, *, allow_reload_pending=False):
            self.assertTrue(allow_reload_pending)
            if active or (active_foreign and unit ==
                          "aegis-foreign-policy-monitor.service"):
                raise MODULE.Refused("actor active")
            if unit in ("aegis-device-egress-guard.service",
                        "aegis-foreign-policy-monitor.service",
                        "aegis-auto-clean-shutdown.service",
                        "aegis-device-dhcp-refresh.service",
                        "aegis-device-dhcp-refresh.timer"):
                return {"LoadState": ("loaded" if reappeared_guard and unit ==
                        "aegis-device-egress-guard.service" else "not-found"),
                        "FragmentPath": (
                            "/etc/systemd/system/aegis-device-egress-guard.service"
                            if reappeared_guard and unit ==
                            "aegis-device-egress-guard.service" else "")}
            return {**facts, "FragmentPath": (
                "/usr/lib/systemd/system/aegis-client.service" if
                unit == "aegis-client.service" else
                "/etc/systemd/system/" + unit)}
        def output(args, **_kwargs):
            if args[1] == "list-jobs" and queued_job is not None:
                return ("19 " + queued_job + " start waiting\n").encode()
            return b""
        with mock.patch.object(MODULE, "uninstall_journal", journal), \
             mock.patch.object(MODULE, "_uninstall_guard_split",
                               return_value=split), \
             mock.patch.object(MODULE, "_uninstall_nft_table_absent"), \
             mock.patch.object(MODULE, "_uninstall_unit_stopped",
                               side_effect=stopped) as status, \
             mock.patch.object(MODULE, "no_private_jobs_or_units") as jobs, \
             mock.patch.object(MODULE, "call_output", side_effect=output) as calls:
            if (tampered or active or split or queued_job is not None or
                    reappeared_guard or active_foreign):
                with self.assertRaises(MODULE.Refused):
                    MODULE._uninstall_reconcile_retired_units(91, "c" * 64)
                self.assertFalse(any(call.args[0][1] == "daemon-reload"
                                     for call in calls.call_args_list))
            else:
                self.assertEqual(MODULE._uninstall_reconcile_retired_units(
                    91, "c" * 64), retired)
                if retired:
                    self.assertEqual(status.call_count,
                                     len(MODULE._UNINSTALL_ACTOR_UNITS) + 6)
                    jobs.assert_called_once_with()
                    self.assertEqual([call.args[0][1] for call in calls.call_args_list],
                                     ["list-units", "list-jobs", "list-jobs", "daemon-reload"])
                    calls.assert_any_call(
                        ["/usr/bin/systemctl", "list-jobs", "--no-legend",
                         "--plain"], maximum=65536, timeout=5)
                    calls.assert_any_call(
                        ["/usr/bin/systemctl", "daemon-reload"],
                        maximum=1024, timeout=15)
                else:
                    status.assert_not_called()
                    calls.assert_not_called()

    def test_exact_retired_unit_reloads_before_strict_recheck(self):
        self.run_reconcile(retired=True)

    def test_no_retired_unit_keeps_strict_normal_path(self):
        self.run_reconcile()

    def test_tampered_retired_unit_refuses_before_reload(self):
        self.run_reconcile(retired=True, tampered=True)

    def test_restarted_actor_refuses_before_reload(self):
        self.run_reconcile(retired=True, active=True)

    def test_guard_split_refuses_before_reload(self):
        self.run_reconcile(retired=True, split=True)

    def test_queued_static_actor_refuses_before_reload(self):
        self.run_reconcile(retired=True,
                           queued_job="aegis-auto-witness-topology.service")

    def test_reappeared_device_guard_refuses_before_reload(self):
        self.run_reconcile(retired=True, reappeared_guard=True)

    def test_active_foreign_monitor_refuses_before_reload(self):
        self.run_reconcile(retired=True, active_foreign=True)

    def test_reload_pending_requires_explicit_replay_branch(self):
        raw = (b"Id=aegis-auto-guardian.service\nLoadState=loaded\n"
               b"ActiveState=inactive\nSubState=dead\nMainPID=0\n"
               b"ControlPID=0\nControlGroup=\nNFileDescriptorStore=0\n"
               b"NeedDaemonReload=yes\nFragmentPath="
               b"/etc/systemd/system/aegis-auto-guardian.service\n")
        with mock.patch.object(MODULE, "call_output", return_value=raw):
            with self.assertRaises(MODULE.Refused):
                MODULE._uninstall_unit_stopped("aegis-auto-guardian.service")
            facts = MODULE._uninstall_unit_stopped(
                "aegis-auto-guardian.service", allow_reload_pending=True)
            self.assertEqual(facts["NeedDaemonReload"], "yes")

    def test_real_first_unit_rename_cut_replays_after_pid1_reload(self):
        # Exercise actual journal backup/rename/replay on a private root. The
        # interruption is after its first systemd unit rename and before that
        # unit's receipt, unlike a repeat after completed retirement.
        actor = MODULE.UNINSTALL_OWNERS[5]
        with tempfile.TemporaryDirectory(prefix="aegis-a10-unit-cut-") as temporary:
            root = Path(temporary)
            for relative in ("var", "var/lib", "var/lib/aegis-auto",
                             "var/lib/aegis-auto/control", "etc",
                             "etc/systemd", "etc/systemd/system"):
                directory = root / relative
                directory.mkdir(exist_ok=True)
                directory.chmod(0o700)
            actor_path = root / actor.lstrip("/")
            actor_path.write_bytes(b"[Unit]\nDescription=retained actor\n")
            actor_path.chmod(0o644)
            actor_inode = actor_path.stat().st_ino
            options = {"owner": os.getuid(), "group": os.getgid()}
            j = MODULE.uninstall_journal
            fd = j.directory(temporary, create=True, **options)
            try:
                intent = {"schema": j.SCHEMA, "boot_id":
                          "11111111-2222-3333-4444-555555555555",
                          "stage": "/run/aegis-installer-config-snapshots/unit-cut",
                          "pointer_sha256": "a" * 64,
                          "candidate_sha256": "b" * 64,
                          "owner_manifest_sha256": "c" * 64,
                          "guard_config_sha256": "d" * 64,
                          "package": "aegis-client", "version": "1.2.3-1",
                          "backup_root": "/var/lib/aegis-auto-uninstall/backup",
                          "nonce": "e" * 32}
                j.begin(fd, intent, **options)
                for state in ("admitted", "stopped-archived"):
                    j.advance(fd, state, "f" * 64, **options)
                backup_sha = j.backup_owners(fd, MODULE.UNINSTALL_OWNERS,
                                              root=temporary, **options)
                j.advance(fd, "guard-recovering", "f" * 64,
                          backup_manifest_sha256=backup_sha,
                          guard_split_sha256="a" * 64, **options)
                for state in ("guard-released", "actors-quiescent"):
                    j.advance(fd, state, "f" * 64,
                              **({"guard_split_sha256": "a" * 64}
                                 if state == "guard-released" else {}),
                              **options)
                source = j.module
                original_publish = source.publish
                def cut_after_rename(parent, name, raw, **kwargs):
                    if name == "retired-05.json":
                        raise RuntimeError("interrupted after unit rename")
                    return original_publish(parent, name, raw, **kwargs)
                with mock.patch.object(source, "publish",
                                       side_effect=cut_after_rename):
                    with self.assertRaisesRegex(RuntimeError,
                                                "interrupted after unit rename"):
                        j.retire_owners(fd, MODULE.UNINSTALL_OWNERS, backup_sha,
                                        root=temporary, **options)
                retired = root / "var/lib/aegis-auto-uninstall/backup/retired-05"
                self.assertFalse(actor_path.exists())
                self.assertEqual(retired.stat().st_ino, actor_inode)
                self.assertFalse((retired.parent / "retired-05.json").exists())
                self.assertEqual(len(j.read(fd, **options)[1]), 5)
                self.assertEqual(j.verify_backup(fd, MODULE.UNINSTALL_OWNERS,
                    backup_sha, **options)["owners"], list(MODULE.UNINSTALL_OWNERS))

                verify = source.verify_backup
                inventory = source.source_manifest
                commands = []
                def pid1(command, **_kwargs):
                    commands.append(tuple(command))
                    if command[1] == "show":
                        unit = command[2]
                        loaded = unit == Path(actor).name
                        process = ("" if unit.endswith(".timer") else
                                   "MainPID=0\nControlPID=0\nControlGroup=\n"
                                   "NFileDescriptorStore=0\n")
                        return ("Id=" + unit + "\nLoadState=" +
                                ("loaded" if loaded else "not-found") +
                                "\nActiveState=inactive\nSubState=dead\n" +
                                process + "NeedDaemonReload=" +
                                ("yes" if loaded else "no") +
                                "\nFragmentPath=" + (actor if loaded else "") +
                                "\n").encode()
                    return b""
                with mock.patch.object(j, "verify_backup", side_effect=lambda
                        held, owners, digest: verify(held, owners, digest,
                                                    **options)), \
                     mock.patch.object(j, "source_manifest", side_effect=lambda
                        paths: inventory(paths, root=temporary, **options)), \
                     mock.patch.object(MODULE, "_uninstall_guard_split",
                                       return_value=False), \
                     mock.patch.object(MODULE, "_uninstall_nft_table_absent"), \
                     mock.patch.object(MODULE, "call_output", side_effect=pid1):
                    self.assertTrue(MODULE._uninstall_reconcile_retired_units(
                        fd, backup_sha))
                self.assertIn(("/usr/bin/systemctl", "show", Path(actor).name,
                               "--no-pager", "-p", "Id", "-p", "LoadState",
                               "-p", "ActiveState", "-p", "SubState", "-p",
                               "MainPID", "-p", "ControlPID", "-p", "ControlGroup",
                               "-p", "NFileDescriptorStore", "-p",
                               "NeedDaemonReload", "-p", "FragmentPath"), commands)
                self.assertEqual(commands[-1],
                                 ("/usr/bin/systemctl", "daemon-reload"))
                result = j.retire_owners(fd, MODULE.UNINSTALL_OWNERS, backup_sha,
                                         root=temporary, **options)
                self.assertEqual(len(result), 64)
                self.assertEqual(retired.stat().st_ino, actor_inode)
                self.assertTrue((retired.parent / "retired-05.json").is_file())
                self.assertEqual(len(j.read(fd, **options)[1]), 5)
            finally:
                os.close(fd)


class UninstallTimerStateTest(unittest.TestCase):
    UNIT = "aegis-auto-trace-rollback.timer"
    RAW = (b"Id=aegis-auto-trace-rollback.timer\nLoadState=loaded\n"
           b"ActiveState=inactive\nSubState=dead\n"
           b"FragmentPath=/etc/systemd/system/aegis-auto-trace-rollback.timer\n"
           b"NeedDaemonReload=no\n")

    def test_real_systemd_timer_schema_is_stopped(self):
        with mock.patch.object(MODULE, "call_output", return_value=self.RAW) as output:
            facts = MODULE._uninstall_unit_stopped(self.UNIT)
        self.assertEqual(facts["ActiveState"], "inactive")
        self.assertNotIn("MainPID", facts)
        self.assertNotIn("MainPID", output.call_args.args[0])

    def test_timer_extra_process_field_refuses(self):
        with mock.patch.object(MODULE, "call_output",
                               return_value=self.RAW + b"MainPID=0\n"):
            with self.assertRaises(MODULE.Refused):
                MODULE._uninstall_unit_stopped(self.UNIT)

    def test_active_timer_refuses(self):
        active = self.RAW.replace(b"ActiveState=inactive", b"ActiveState=active")
        with mock.patch.object(MODULE, "call_output", return_value=active):
            with self.assertRaises(MODULE.Refused):
                MODULE._uninstall_unit_stopped(self.UNIT)


if __name__ == "__main__":
    unittest.main()
