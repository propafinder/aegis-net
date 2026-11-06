"""Focused first-arm ordering and real singleton lock regression."""

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import aegis_auto_guard_policy as guard_policy


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/lib/aegis_auto_guardian.py"
SPEC = importlib.util.spec_from_file_location("aegis_auto_guardian_upgrade", SOURCE)
guardian = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guardian)


class FirstArmUpgradeTests(unittest.TestCase):
    def test_boot_actor_commands_match_all_installed_units_and_reject_mutations(self):
        commands = {}
        for unit, source, _installed_unit in guardian.ROTATION_ACTORS:
            line = next(line for line in
                        (ROOT / "packaging/systemd" / unit).read_text().splitlines()
                        if line.startswith("ExecStart="))
            actual = [part.encode() for part in line.removeprefix("ExecStart=").split()]
            expected = guardian._rotation_actor_command(unit, source)
            self.assertEqual(expected.rstrip(b"\0").split(b"\0"), actual)
            commands[unit] = expected
        self.assertEqual(len(commands), 6)
        foreign = "aegis-foreign-policy-monitor.service"
        self.assertFalse(commands[foreign].endswith(b"serve\0"))
        for unit in set(commands) - {foreign}:
            self.assertTrue(commands[unit].endswith(b"serve\0"))

        active = {unit: 1234 + index for index, (unit, _source, _path)
                  in enumerate(guardian.ROTATION_ACTORS)}
        by_pid = {pid: unit for unit, pid in active.items()}
        changed = dict(commands)
        wrong_cgroup = set()
        alive = [True]
        pending_job = [False]
        def facts(unit, **_kwargs):
            return {"MainPID": str(active[unit]), "ControlPID": "0",
                    "NFileDescriptorStore": "0", "ActiveState": "active",
                    "SubState": "running", "InvocationID": "a" * 32,
                    "ControlGroup": "/system.slice/" + unit}
        def read_text(path, **_kwargs):
            unit = by_pid[int(path.parts[2])]
            return "0::/system.slice/" + ("foreign.service" if unit in wrong_cgroup
                                            else unit) + "\n"
        def read_bytes(path):
            return changed[by_pid[int(path.parts[2])]]
        def jobs(_deadline):
            if pending_job[0]:
                raise guardian.Refused("rotation_actor_job_pending")
        def observe():
            with patch.object(guardian, "_rotation_actor_facts", side_effect=facts), \
                 patch.object(guardian.Path, "read_text", read_text), \
                 patch.object(guardian.Path, "read_bytes", read_bytes), \
                 patch.object(guardian.os, "pidfd_open",
                              side_effect=lambda *_: os.open(os.devnull, os.O_RDONLY),
                              create=True), \
                 patch.object(guardian, "_pid_alive", side_effect=lambda *_: alive[0]), \
                 patch.object(guardian, "_rotation_static_stopped"), \
                 patch.object(guardian, "_rotation_actor_jobs", side_effect=jobs):
                return guardian._boot_actor_observation(guardian.time.monotonic() + 3)
        # Each actor is observed with its own actual unit cgroup and argv.
        # This drives the boot readback's identity predicate rather than a
        # replica of its byte comparison.
        self.assertEqual(len(observe()), 6)
        changed[foreign] += b"serve\0"
        with self.assertRaises(guardian.Refused):
            observe()
        changed[foreign] = commands[foreign]
        guardian_unit = "aegis-auto-guardian.service"
        changed[guardian_unit] = changed[guardian_unit].removesuffix(b"serve\0")
        with self.assertRaises(guardian.Refused):
            observe()
        changed[guardian_unit] = commands[guardian_unit]
        wrong_cgroup.add(foreign)
        with self.assertRaises(guardian.Refused):
            observe()
        wrong_cgroup.clear()
        alive[0] = False
        with self.assertRaises(guardian.Refused):
            observe()
        alive[0] = True
        pending_job[0] = True
        with self.assertRaises(guardian.Refused):
            observe()

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                         "root-owned rotation receipt required")
    def test_rotation_intent_full_roster_has_own_strict_size_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            intent_path = parent / "intent.json"
            other_path = parent / "denied.json"
            old_root = "/var/lib/aegis-auto/releases/" + "a" * 64
            next_root = "/var/lib/aegis-auto/releases/" + "b" * 64
            intent = {
                "schema": "aegis_auto_guard_rotation_intent_v1",
                "boot_id": "a" * 36,
                "stopped_successor_sha256": "a" * 64,
                "old_public_payload_root": old_root,
                "old_rollback_unit_sha256": "a" * 64,
                "old_static_units": {unit: "a" * 64 for unit, _ in guardian.ROTATION_STATIC_UNITS},
                "successor": {
                    "intent_sha256": "a" * 64,
                    "old_active_sha256": "a" * 64,
                    "old_stopped_sha256": "a" * 64,
                    "next_public_payload_root": next_root,
                    "next_candidate_binary": next_root + "/bin/aegis-client",
                    "next_candidate_sha256": "b" * 64,
                    "next_installer_sha256": "b" * 64,
                    "next_bundle_manifest_sha256": "b" * 64,
                    "next_sums_sha256": "b" * 64,
                    "kind": "upgrade",
                    "prior_successor_intent_sha256": None,
                },
                "next_sources": {field: "b" * 64 for field, _, _ in guardian.ROTATION_SOURCES},
                "next_static_units": {unit: "b" * 64 for unit, _ in guardian.ROTATION_STATIC_UNITS},
                "next_rollback_unit_sha256": "b" * 64,
                "old_install_sha256": "a" * 64,
                "old_policy_sha256": "a" * 64,
                "old_manager_sha256": "a" * 64,
                "old_state_sha256": "a" * 64,
                "old_guard_unit_sha256": "a" * 64,
                "old_manager_dropin_sha256": "a" * 64,
                "guard_device": 1,
                "guard_inode": 2,
                "coordinator": {
                    "pid": 1111,
                    "birth": 123456,
                    "argv_sha256": "b" * 64,
                    "exe_sha256": "b" * 64,
                    "source": next_root + "/scripts/lib/aegis_installer_auto_v2.py",
                    "source_sha256": "b" * 64,
                    "cgroup": "0::/system.slice/aegis-qa.service\n",
                    "install_device": 1,
                    "install_inode": 2,
                },
            }
            raw = (json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode()
            self.assertGreater(len(raw), guardian.MAX_RECEIPT)
            self.assertLessEqual(len(raw), guardian.MAX_ROTATION_INTENT)
            with patch.object(guardian, "ROTATION_INTENT", intent_path):
                self.assertEqual(guardian._rotation_write_once(intent_path, intent), raw)
                self.assertEqual(guardian._rotation_write_once(intent_path, intent), raw)
                self.assertEqual(guardian.record(intent_path, guardian.MAX_ROTATION_INTENT), intent)
                self.assertEqual(guardian._rotation_prior_entries()[0][-1], guardian.MAX_ROTATION_INTENT)
                with self.assertRaises(guardian.Refused):
                    guardian._rotation_write_once(other_path, intent)
                with self.assertRaises(guardian.Refused):
                    guardian._rotation_write_once(intent_path, {"oversized": "x" * 8192})

    def test_guarded_boot_refuses_pending_stop_or_watchdog_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            state = parent / "device-guard.conf"
            state.write_bytes(b"sealed-state")
            state.chmod(0o600)
            install = parent / "install.json"
            install.write_bytes(b"installed")
            install.chmod(0o600)
            current = {"state_sha256": guardian.digest(state.read_bytes()),
                       "policy_sha256": "a" * 64,
                       "manager_binding_sha256": None}
            for pending in (parent / "stop.json", parent / "watchdog.json"):
                pending.write_bytes(b"pending")
                pending.chmod(0o600)
                with patch.object(guardian, "own_source"), \
                     patch.object(guardian, "_held_lock", return_value=(1, 2)), \
                     patch.object(guardian, "GUARD_STATE", state), \
                     patch.object(guardian, "INSTALL", install), \
                     patch.object(guardian, "STOP_INTENT", parent / "stop.json"), \
                     patch.object(guardian, "WATCHDOG_PENDING",
                                  parent / "watchdog.json"), \
                     patch.object(guardian, "record", return_value={
                         "worker_sha256": "b" * 64}), \
                     patch.object(guardian, "read_guard_policy",
                                  return_value=current), \
                     patch.object(guardian, "_boot_fixed_client_stopped") as fixed:
                    with self.assertRaises(guardian.Refused):
                        guardian.boot_denied_readback(9, 10)
                    fixed.assert_not_called()
                pending.unlink()

    def test_passive_boot_requires_absent_guard_and_pending_journals(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            names = ("guard.service", "device-guard.conf", "policy.json",
                     "device-guard.conf.manager-binding",
                     "device-guard.conf.client-binding", "stop.json",
                     "watchdog.json")
            fields = ("GUARD_UNIT_FILE", "GUARD_STATE", "POLICY",
                      None, None, "STOP_INTENT", "WATCHDOG_PENDING")
            patches = [patch.object(guardian, field, parent / name)
                       for name, field in zip(names, fields) if field]
            for context in patches:
                context.start()
                self.addCleanup(context.stop)
            guardian._boot_passive_absent()
            for name in names:
                leaf = parent / name
                leaf.write_bytes(b"foreign")
                with self.assertRaises(guardian.Refused):
                    guardian._boot_passive_absent()
                leaf.unlink()
            target = parent / "missing"
            (parent / names[0]).symlink_to(target)
            with self.assertRaises(guardian.Refused):
                guardian._boot_passive_absent()

    def test_passive_boot_readback_never_claims_guard_policy(self):
        old = b'{"worker_sha256":"' + b"a" * 64 + b'","guard_unit_sha256":null}'
        actors = [{"unit": "aegis-auto-guardian.service", "active": False,
                   "main_pid": 0, "invocation_id": None}]
        checks = []
        def absent():
            checks.append("absent")
        with patch.object(guardian, "own_source"), \
             patch.object(guardian, "_held_lock", return_value=(1, 2)), \
             patch.object(guardian, "regular", return_value=old), \
             patch.object(guardian, "record", return_value={
                 "worker_sha256": "a" * 64, "guard_unit_sha256": None}), \
             patch.object(guardian, "host_anchor", return_value={
                 "boot_id": "a" * 36}), \
             patch.object(guardian, "_boot_passive_absent", side_effect=absent), \
             patch.object(guardian, "_boot_fixed_client_stopped"), \
             patch.object(guardian, "_boot_private_owners_absent"), \
             patch.object(guardian, "_boot_actor_observation",
                          return_value=actors), \
             patch.object(guardian, "read_guard_policy") as guarded:
            result = guardian.boot_passive_readback(9)
            self.assertEqual(result["schema"],
                             "aegis_auto_guard_boot_passive_readback_v1")
            self.assertTrue(result["passive"])
            self.assertEqual(result["actors"], actors)
            self.assertNotIn("policy_sha256", result)
            self.assertNotIn("manager_binding_sha256", result)
            self.assertEqual(checks, ["absent", "absent"])
            guarded.assert_not_called()

    @unittest.skipUnless(os.geteuid() == 0, "root-owned phase archive required")
    def test_repeat_rotation_archives_exact_prior_phase_and_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            prior_sha, next_sha, old_worker = ("1" * 64, "2" * 64,
                                               "3" * 64)
            root = Path("/var/lib/aegis-auto/releases/" + "4" * 64)
            files = {
                "INSTALL": "install.json", "ROTATION_INTENT": "intent.json",
                "ROTATION_DENIED": "denied.json",
                "ROTATION_ACTOR_INTENT": "actor-intent.json",
                "ROTATION_RETIRED": "retired.json",
                "ROTATION_ASSESSMENT": "assessment.conf",
                "ROTATION_HANDOFF": "handoff.json",
            }
            contexts = [patch.object(guardian, key, parent / value)
                        for key, value in files.items()]
            for context in contexts:
                context.start()
                self.addCleanup(context.stop)

            def write(name, body):
                path = parent / files[name]
                raw = (json.dumps(body, sort_keys=True,
                                  separators=(",", ":")) + "\n").encode()
                path.write_bytes(raw)
                path.chmod(0o600)
                return raw

            old_install = write("INSTALL", {"worker_sha256": old_worker})
            prior_intent = {"schema": "aegis_auto_guard_rotation_intent_v1",
                            "boot_id": "5" * 36,
                            "guard_device": 7, "guard_inode": 9,
                            "successor": {"intent_sha256": prior_sha,
                                          "kind": "upgrade",
                                          "next_public_payload_root": str(root),
                                          "next_candidate_sha256": old_worker},
                            "old_install_sha256": "6" * 64,
                            "old_manager_sha256": "7" * 64,
                            "old_policy_sha256": "8" * 64,
                            "old_state_sha256": "9" * 64}
            intent_raw = write("ROTATION_INTENT", prior_intent)
            denied = {"schema": "aegis_auto_guard_rotation_denied_v1",
                      "boot_id": prior_intent["boot_id"],
                      "intent_sha256": guardian.digest(intent_raw),
                      "old_install_sha256": prior_intent["old_install_sha256"],
                      "old_manager_sha256": prior_intent["old_manager_sha256"],
                      "old_policy_sha256": prior_intent["old_policy_sha256"],
                      "old_state_sha256": prior_intent["old_state_sha256"],
                      "deny_policy_sha256": "a" * 64,
                      "guard_device": 7, "guard_inode": 9}
            denied_raw = write("ROTATION_DENIED", denied)
            write("ROTATION_ACTOR_INTENT", {"schema": "test"})
            retired_raw = write("ROTATION_RETIRED", {"schema": "test"})
            assessment = b"schema=aegis_device_guard_v2\n"
            (parent / files["ROTATION_ASSESSMENT"]).write_bytes(assessment)
            (parent / files["ROTATION_ASSESSMENT"]).chmod(0o600)
            handoff = {
                "schema": "aegis_auto_guard_rotation_state_handoff_v1",
                "boot_id": prior_intent["boot_id"], "kind": "upgrade",
                "intent_sha256": guardian.digest(intent_raw),
                "denied_sha256": guardian.digest(denied_raw),
                "retired_sha256": guardian.digest(retired_raw),
                "assessment_sha256": guardian.digest(assessment),
                "state_sha256": guardian.digest(assessment),
                "policy_sha256": "b" * 64,
                "new_install_sha256": guardian.digest(old_install),
                "candidate_sha256": old_worker, "guard_device": 7,
                "guard_inode": 9, "no_client_grant": True,
                "no_manager_binding": True,
            }
            write("ROTATION_HANDOFF", handoff)
            verified = {"successor": {
                "intent_sha256": next_sha,
                "prior_successor_intent_sha256": prior_sha}}
            with patch.object(guardian, "_rotation_retired_shape") as sealed:
                guardian._rotation_advance_previous(verified, old_install, root)
                sealed.assert_called_once()
                self.assertFalse((parent / files["ROTATION_INTENT"]).exists())
                self.assertFalse((parent / files["ROTATION_HANDOFF"]).exists())
                archives = list(parent.glob("auto-guard-prior-*.json"))
                self.assertEqual(len(archives), 5)
                guardian._rotation_advance_previous(verified, old_install, root)
                write("ROTATION_INTENT", {"successor": {
                    "intent_sha256": next_sha}})
                guardian._rotation_advance_previous(verified, old_install, root)
                self.assertTrue((parent / files["ROTATION_INTENT"]).exists())
                archives[0].write_bytes(b"tampered")
                with self.assertRaises(guardian.Refused):
                    guardian._rotation_advance_previous(verified,
                                                        old_install, root)

    def test_rotation_static_timer_requires_exact_source_trigger_and_no_schedule(self):
        unit = "aegis-auto-trace-rollback.timer"
        names = ("Id", "LoadState", "FragmentPath", "ActiveState", "SubState",
                 "InvocationID", "UnitFileState", "Triggers", "TriggeredBy",
                 "NextElapseUSecRealtime", "NextElapseUSecMonotonic")
        values = {name: "" for name in names}
        values.update(Id=unit, LoadState="loaded",
                      FragmentPath="/etc/systemd/system/" + unit,
                      ActiveState="inactive", SubState="dead",
                      UnitFileState="enabled",
                      Triggers="aegis-auto-trace-rollback.service",
                      NextElapseUSecRealtime="n/a",
                      NextElapseUSecMonotonic="n/a")

        def show(*_args, **_kwargs):
            output = "".join(f"{key}={value}\n" for key, value in values.items())
            return SimpleNamespace(returncode=0, stdout=output.encode(),
                                   stderr=b"")

        with patch.object(guardian.subprocess, "run", side_effect=show):
            facts = guardian._rotation_static_facts(
                unit, deadline=guardian.time.monotonic() + 3.0)
            self.assertEqual(facts["Triggers"],
                             "aegis-auto-trace-rollback.service")
            values["NextElapseUSecMonotonic"] = "Mon 2026-10-19 10:00:00 UTC"
            with self.assertRaises(guardian.Refused):
                guardian._rotation_static_stopped(
                    guardian.time.monotonic() + 3.0)
            values["NextElapseUSecMonotonic"] = "n/a"
            values["Triggers"] = "foreign.service"
            with self.assertRaises(guardian.Refused):
                guardian._rotation_static_facts(
                    unit, deadline=guardian.time.monotonic() + 3.0)

    def test_rotation_static_real_pid1_per_type_schema(self):
        timer, service = [unit for unit, _relative in
                          guardian.ROTATION_STATIC_UNITS]
        common = {"LoadState": "loaded", "ActiveState": "inactive",
                  "SubState": "dead", "InvocationID": ""}
        rows = {
            # Values as real systemd 252/255 print them for a stopped pair
            # (see test_rotation_static_recorded_real_pid1_bytes).
            timer: {**common, "Id": timer,
                    "FragmentPath": "/etc/systemd/system/" + timer,
                    "UnitFileState": "static", "Triggers": service,
                    "TriggeredBy": "", "NextElapseUSecRealtime": "",
                    "NextElapseUSecMonotonic": "infinity"},
            service: {**common, "Id": service,
                      "FragmentPath": "/etc/systemd/system/" + service,
                      "UnitFileState": "static", "Triggers": "",
                      "TriggeredBy": "", "MainPID": "0",
                      "ControlPID": "0", "ControlGroup": "",
                      "NFileDescriptorStore": "0"},
        }

        def show(command, **_kwargs):
            unit = command[2]
            output = "".join(f"{key}={value}\n" for key, value in rows[unit].items())
            return SimpleNamespace(returncode=0, stdout=output.encode(),
                                   stderr=b"")

        with patch.object(guardian.subprocess, "run", side_effect=show), \
             patch.object(guardian, "_rotation_actor_jobs"):
            deadline = guardian.time.monotonic() + 3.0
            self.assertEqual(guardian._rotation_static_facts(timer, deadline=deadline)
                             ["NextElapseUSecMonotonic"], "infinity")
            self.assertEqual(guardian._rotation_static_facts(service, deadline=deadline)
                             ["MainPID"], "0")
            guardian._rotation_static_stopped(deadline)
            rows[timer]["Unexpected"] = "1"
            with self.assertRaises(guardian.Refused):
                guardian._rotation_static_facts(timer, deadline=deadline)
            del rows[timer]["Unexpected"]
            rows[timer]["ActiveState"] = "active"
            with self.assertRaises(guardian.Refused):
                guardian._rotation_static_stopped(deadline)

    def test_rotation_static_recorded_real_pid1_bytes(self):
        """Replay verbatim systemd 252/255 readbacks of every lifecycle state.

        An inactive timer prints NextElapseUSecMonotonic=infinity, and once
        PID1 has garbage-collected the inactive static timer the service
        prints an empty TriggeredBy. The stopped states must pass, and every
        state that has a live timer, a running service or no loaded unit must
        still refuse.
        """
        fixture = json.loads((Path(__file__).resolve().parent / "fixtures" /
                              "rotation_static_pid1_readbacks.json")
                             .read_text(encoding="utf-8"))
        timer, service = [unit for unit, _relative in
                          guardian.ROTATION_STATIC_UNITS]
        expected = {
            "S0-never-started": None,
            "S1-timer-waiting": "rotation_static_not_stopped",
            "S2-service-activating": "rotation_static_not_stopped",
            "S3-after-service-ran": "rotation_static_not_stopped",
            "S4-both-stopped-after-fire": None,
            "S5-timer-stopped-before-elapse": None,
            "S6-timer-start-no-block": "rotation_static_not_stopped",
            "S7-files-removed-before-reload": "rotation_static_pid1_changed",
            "S8-not-found-after-reload": "rotation_static_pid1_changed",
        }
        static = [{"unit_file_state": "static"}, {"unit_file_state": "static"}]
        self.assertEqual(len(fixture["platforms"]), 3)

        def replay(row):
            def run(command, **_kwargs):
                self.assertEqual(command[0], "/usr/bin/systemctl")
                if command[1] == "list-jobs":
                    stdout = row["list_jobs_stdout"]
                else:
                    self.assertEqual(command[1], "show")
                    unit = command[2]
                    names = command[5::2]
                    self.assertEqual(command[3], "--no-pager")
                    self.assertEqual(command[4::2], ["-p"] * len(names))
                    if unit == timer:
                        self.assertEqual(names, fixture["timer_names"])
                        stdout = row["timer_stdout"]
                    else:
                        self.assertEqual(unit, service)
                        self.assertEqual(names, fixture["service_names"])
                        stdout = row["service_stdout"]
                return SimpleNamespace(returncode=0, stdout=stdout.encode(),
                                       stderr=b"")
            return patch.object(guardian.subprocess, "run", side_effect=run)

        def outcome(call):
            try:
                call()
            except guardian.Refused as error:
                return error.args[0]
            return None

        seen = set()
        for platform in fixture["platforms"]:
            for row in platform["states"]:
                label = row["label"]
                seen.add(label)
                with self.subTest(platform=platform["platform"], state=label), \
                        replay(row):
                    deadline = guardian.time.monotonic() + 3.0
                    self.assertEqual(
                        outcome(lambda: guardian._rotation_static_stopped(deadline)),
                        expected[label])
                    self.assertEqual(
                        outcome(lambda: guardian._rotation_static_stopped(
                            deadline, static)),
                        expected[label])
                    if expected[label] is None:
                        self.assertEqual(
                            outcome(lambda: guardian._rotation_static_stopped(
                                deadline, [{"unit_file_state": "enabled"},
                                           static[1]])),
                            "rotation_static_enablement_changed")
        self.assertEqual(seen, set(expected))

        # Mutations of recorded stopped bytes still refuse.
        stopped = fixture["platforms"][0]["states"][0]
        waiting = fixture["platforms"][0]["states"][1]
        pending = next(line for line in waiting["timer_stdout"].splitlines()
                       if line.startswith("NextElapseUSecMonotonic="))
        self.assertNotEqual(pending, "NextElapseUSecMonotonic=infinity")
        mutants = {
            "rotation_static_timer_pending": dict(
                stopped, timer_stdout=stopped["timer_stdout"].replace(
                    "NextElapseUSecMonotonic=infinity", pending)),
            "rotation_static_service_changed": dict(
                stopped, service_stdout=stopped["service_stdout"].replace(
                    "TriggeredBy=\n", "TriggeredBy=foreign.path\n")),
            "rotation_static_timer_changed": dict(
                stopped, timer_stdout=stopped["timer_stdout"].replace(
                    "Triggers=aegis-auto-trace-rollback.service\n",
                    "Triggers=foreign.service\n")),
            "rotation_actor_job_pending": dict(
                stopped, list_jobs_stdout=
                "150 aegis-auto-trace-rollback.service start waiting\n"),
        }
        for reason, row in mutants.items():
            with self.subTest(mutant=reason), replay(row):
                self.assertEqual(
                    outcome(lambda: guardian._rotation_static_stopped(
                        guardian.time.monotonic() + 3.0)), reason)
        # A service that still names its loaded timer is equally stopped.
        named = dict(stopped, service_stdout=stopped["service_stdout"].replace(
            "TriggeredBy=\n", "TriggeredBy=" + timer + "\n"))
        with replay(named):
            guardian._rotation_static_stopped(guardian.time.monotonic() + 3.0)

    def test_passive_predecessor_sources_admit_pre_ee8816f5_retention_modes(self):
        """L-F3: an r19-retained predecessor keeps bundle 0755 policy data at 0555.

        Installers before ee8816f5 kept the release bundle's exec bit, and
        build-release-bundle.sh chmods every HELPER_SCRIPTS entry to 0755.
        Passive successor admission reads the predecessor's sources and must
        admit exactly that historical retention; the new root stays 0444.
        """
        root = Path("/var/lib/aegis-auto/releases/" + "a" * 64)
        content = {relative: ("source " + relative).encode()
                   for _field, relative, _mode in guardian.ROTATION_SOURCES}
        modes = {}

        def lstat(path, *args, **kwargs):
            relative = str(Path(path).relative_to(root))
            return SimpleNamespace(st_mode=stat.S_IFREG | modes[relative])

        def retained(read_root, relative, mode, maximum=1 << 20):
            self.assertEqual(read_root, root)
            guardian.need(mode == modes[relative], "untrusted_file")
            return content[relative]

        def outcome(call):
            try:
                return call()
            except guardian.Refused as error:
                return error.args[0]

        expected = {field: guardian.digest(content[relative])
                    for field, relative, _mode in guardian.ROTATION_SOURCES}
        bundle_exec = {relative for _field, relative, mode in guardian.ROTATION_SOURCES
                       if relative.startswith("scripts/lib/")}
        self.assertGreaterEqual(len(bundle_exec), 15)
        with patch.object(guardian.os, "lstat", side_effect=lstat), \
             patch.object(guardian, "_retained_rotation_source", side_effect=retained):
            modes.update({relative: mode for _field, relative, mode
                          in guardian.ROTATION_SOURCES})
            self.assertEqual(guardian._rotation_predecessor_sources(root), expected)
            self.assertEqual(guardian._rotation_sources(root), expected)
            modes.update({relative: 0o555 for relative in bundle_exec})
            self.assertEqual(guardian._rotation_predecessor_sources(root), expected)
            # The successor root is retained by the new installer: 0444 only.
            self.assertEqual(outcome(lambda: guardian._rotation_sources(root)),
                             "untrusted_file")
            for field, relative, mode in guardian.ROTATION_SOURCES:
                for wrong in (0o644, 0o755, 0o666, 0o777, 0o400, 0o4555):
                    with self.subTest(relative=relative, mode=oct(wrong)):
                        saved = modes[relative]
                        modes[relative] = wrong
                        self.assertEqual(
                            outcome(lambda: guardian._rotation_predecessor_sources(root)),
                            "untrusted_file")
                        modes[relative] = saved
            helper = next(relative for _field, relative, mode in guardian.ROTATION_SOURCES
                          if mode == 0o555)
            modes[helper] = 0o444
            self.assertEqual(outcome(lambda: guardian._rotation_predecessor_sources(root)),
                             "untrusted_file")
        source = SOURCE.read_text(encoding="utf-8")
        body = source[source.index("def _passive_successor_admission("):]
        body = body[:body.index("\ndef ")]
        self.assertIn("old_sources = _rotation_predecessor_sources(old_root)", body)
        self.assertNotIn("_rotation_sources(old_root)", body)

    def test_rotation_static_retirement_keeps_enablement_and_rejects_pending_work(self):
        timer, service = [unit for unit, _relative in
                          guardian.ROTATION_STATIC_UNITS]
        rows = {
            timer: {"ActiveState": "inactive", "SubState": "dead",
                    "NextElapseUSecRealtime": "n/a",
                    "NextElapseUSecMonotonic": "n/a",
                    "UnitFileState": "enabled"},
            service: {"ActiveState": "inactive", "SubState": "dead",
                      "MainPID": "0", "ControlPID": "0",
                      "NFileDescriptorStore": "0", "ControlGroup": "",
                      "UnitFileState": "static"},
        }
        prior = [{"unit_file_state": "enabled"},
                 {"unit_file_state": "static"}]
        with patch.object(guardian, "_rotation_static_facts",
                          side_effect=lambda unit, **_kwargs: rows[unit]), \
             patch.object(guardian, "_rotation_actor_jobs") as jobs:
            guardian._rotation_static_stopped(
                guardian.time.monotonic() + 3.0, prior)
            jobs.assert_called_once()
            rows[timer]["NextElapseUSecRealtime"] = "scheduled"
            with self.assertRaises(guardian.Refused):
                guardian._rotation_static_stopped(
                    guardian.time.monotonic() + 3.0, prior)
            rows[timer]["NextElapseUSecRealtime"] = "n/a"
            rows[service]["UnitFileState"] = "enabled"
            with self.assertRaises(guardian.Refused):
                guardian._rotation_static_stopped(
                    guardian.time.monotonic() + 3.0, prior)

    def test_rotation_retired_receipt_binds_all_seven_units(self):
        h = "a" * 64
        actor_rows = [{"unit": unit, "prior_main_pid": 0,
                       "prior_invocation_id": None, "prior_cgroup": None}
                      for unit, _source, _path in guardian.ROTATION_ACTORS]
        static_rows = [{"unit": unit,
                        "unit_file_state": ("enabled" if unit.endswith(".timer")
                                            else "static"),
                        "prior_active_state": "inactive",
                        "prior_main_pid": 0, "prior_control_pid": 0,
                        "prior_invocation_id": None}
                       for unit, _relative in guardian.ROTATION_STATIC_UNITS]
        actor_intent = {
            "schema": "aegis_auto_guard_rotation_actor_intent_v1",
            "boot_id": "b" * 36, "intent_sha256": h,
            "denied_sha256": h, "actors": actor_rows,
            "static_units": static_rows,
        }
        intent = {"boot_id": "b" * 36,
                  "stopped_successor_sha256": h,
                  "old_install_sha256": h, "old_manager_sha256": h,
                  "guard_device": 7, "guard_inode": 9}
        denied = {"deny_policy_sha256": h}
        retired = {
            "schema": "aegis_auto_guard_rotation_retired_v1",
            "boot_id": "b" * 36, "intent_sha256": h,
            "denied_sha256": h, "stopped_successor_sha256": h,
            "old_install_sha256": h, "old_manager_sha256": h,
            "guard_device": 7, "guard_inode": 9,
            "deny_policy_sha256": h,
            "actors": [dict(entry, stopped_verified=True,
                            fdstore_empty_verified=True)
                       for entry in actor_rows],
            "static_units": [dict(entry, stopped_verified=True,
                                  no_next_elapse_verified=True)
                             for entry in static_rows],
        }

        def loaded(path, *_args):
            if path == guardian.ROTATION_RETIRED:
                return retired
            if path == guardian.ROTATION_ACTOR_INTENT:
                return actor_intent
            raise AssertionError("unexpected receipt")

        with patch.object(guardian, "record", side_effect=loaded), \
             patch.object(guardian, "regular", return_value=b"fixed"), \
             patch.object(guardian, "digest", return_value=h):
            self.assertIs(guardian._rotation_retired_shape(intent, denied),
                          retired)
            retired["static_units"][0]["no_next_elapse_verified"] = False
            with self.assertRaises(guardian.Refused):
                guardian._rotation_retired_shape(intent, denied)
            retired["static_units"][0]["no_next_elapse_verified"] = True
            retired["static_units"].pop()
            with self.assertRaises(guardian.Refused):
                guardian._rotation_retired_shape(intent, denied)

    def test_boot_private_owner_readback_rejects_active_and_foreign_unit(self):
        unit = "aegis-auto@" + "c" * 64 + ".service"
        output = {"raw": b""}

        def listed(*_args, **_kwargs):
            return SimpleNamespace(returncode=0, stdout=output["raw"],
                                   stderr=b"")

        with patch.object(guardian.subprocess, "run", side_effect=listed):
            guardian._boot_private_owners_absent(
                guardian.time.monotonic() + 3.0)
            output["raw"] = (unit + " loaded inactive dead old\n").encode()
            guardian._boot_private_owners_absent(
                guardian.time.monotonic() + 3.0)
            output["raw"] = (unit + " loaded active running owner\n").encode()
            with self.assertRaises(guardian.Refused):
                guardian._boot_private_owners_absent(
                    guardian.time.monotonic() + 3.0)
            output["raw"] = b"foreign.service loaded inactive dead other\n"
            with self.assertRaises(guardian.Refused):
                guardian._boot_private_owners_absent(
                    guardian.time.monotonic() + 3.0)

    def test_boot_fixed_client_readback_requires_inactive_zero_fdstore(self):
        names = ("Id", "LoadState", "FragmentPath", "ActiveState", "SubState",
                 "MainPID", "ControlPID", "ControlGroup",
                 "NFileDescriptorStore")
        values = {name: "" for name in names}
        values.update(Id="aegis-client.service", LoadState="loaded",
                      FragmentPath="/etc/systemd/system/aegis-client.service",
                      ActiveState="inactive", SubState="dead", MainPID="0",
                      ControlPID="0", NFileDescriptorStore="0")

        def show(*_args, **_kwargs):
            text = "".join(f"{key}={value}\n" for key, value in values.items())
            return SimpleNamespace(returncode=0, stdout=text.encode(),
                                   stderr=b"")

        with patch.object(guardian.subprocess, "run", side_effect=show):
            guardian._boot_fixed_client_stopped(
                guardian.time.monotonic() + 3.0)
            values["NFileDescriptorStore"] = "1"
            with self.assertRaises(guardian.Refused):
                guardian._boot_fixed_client_stopped(
                    guardian.time.monotonic() + 3.0)
            values["NFileDescriptorStore"] = "0"
            values["ActiveState"] = "active"
            with self.assertRaises(guardian.Refused):
                guardian._boot_fixed_client_stopped(
                    guardian.time.monotonic() + 3.0)

    def test_rotation_handoff_requires_new_sealed_assessment_and_no_manager(self):
        h = lambda data: hashlib.sha256(data).hexdigest()
        assessment = b"schema=aegis_device_guard_v2\narmed=1\n"
        observed = {guardian.ROTATION_ASSESSMENT: assessment,
                    guardian.GUARD_STATE: assessment,
                    guardian.ROTATION_INTENT: b"intent",
                    guardian.ROTATION_DENIED: b"denied",
                    guardian.ROTATION_RETIRED: b"retired",
                    guardian.INSTALL: b"install"}
        root = Path("/var/lib/aegis-auto/releases/" + "a" * 64)
        candidate = root / "bin/aegis-client"
        intent = {"boot_id": "b" * 36, "guard_device": 7,
                  "guard_inode": 9,
                  "successor": {"next_public_payload_root": str(root),
                                "next_candidate_sha256": "c" * 64,
                                "kind": "upgrade"},
                  "next_sources": {}, "next_static_units": {}}
        current = {"state_sha256": h(assessment),
                   "policy_sha256": "d" * 64,
                   "manager_binding_sha256": None}
        installed = {"schema": "test"}
        written = []

        def read(path, *_args, **_kwargs):
            if path in observed:
                return observed[path]
            raise AssertionError("unexpected held path")

        with patch.object(guardian, "own_source"), \
             patch.object(guardian, "_held_lock", return_value=(7, 9)), \
             patch.object(guardian, "_rotation_intent", return_value=intent), \
             patch.object(guardian, "_rotation_denied", return_value={}), \
             patch.object(guardian, "_rotation_retired_shape"), \
             patch.object(guardian, "_rotation_actors_stopped"), \
             patch.object(guardian, "_rotation_static_stopped"), \
             patch.object(guardian, "record",
                          side_effect=lambda path: ({"static_units": []}
                                                    if path == guardian.ROTATION_ACTOR_INTENT
                                                    else installed)), \
             patch.object(guardian, "regular", side_effect=read), \
             patch.object(guardian, "provision_receipt", return_value=installed), \
             patch.object(guardian, "_retained_rotation_executable_digest",
                          return_value="c" * 64), \
             patch.object(guardian, "_rotation_sources", return_value={}), \
             patch.object(guardian, "_rotation_static_sources", return_value={}), \
             patch.object(guardian, "verified_module",
                          return_value=SimpleNamespace(parse_state=lambda _raw: {})), \
             patch.object(guardian, "read_guard_policy",
                          side_effect=lambda: current), \
             patch.object(guardian, "_rotation_write_once",
                          side_effect=lambda _path, value: written.append(value)):
            proof = guardian.rotation_state_handoff(9, 10)
            self.assertEqual(proof["assessment_sha256"], h(assessment))
            self.assertEqual(len(written), 1)
            observed[guardian.GUARD_STATE] = assessment + b"changed\n"
            with self.assertRaises(guardian.Refused):
                guardian.rotation_state_handoff(9, 10)
            observed[guardian.GUARD_STATE] = assessment
            current["manager_binding_sha256"] = "e" * 64
            with self.assertRaises(guardian.Refused):
                guardian.rotation_state_handoff(9, 10)

    def test_installer_proves_idle_and_stops_guardian_before_candidate_block(self):
        source = (ROOT / "install.sh").read_text()
        arm = source.split("activate_device_full_wide_capture() {", 1)[1]
        arm = arm.split("device_full_wide_probes() {", 1)[0]
        admit = arm.index("stage_auto_device_owner_admit >/dev/null || return 1")
        stop = arm.index("('systemctl', 'stop', 'aegis-auto-guardian.service')")
        block = arm.index('AEGIS_DEVICE_GUARD_STATE="$stage/guard.conf" bash "$guard" block')
        publish = arm.index('install_atomic_write "$state" 0600 strict')
        self.assertLess(admit, stop)
        self.assertLess(stop, block)
        self.assertLess(block, publish)

    def test_staged_auto_does_not_reblock_under_live_foreign_monitor(self):
        source = (ROOT / "install.sh").read_text()
        arm = source.split("activate_device_full_wide_capture() {", 1)[1]
        arm = arm.split("device_full_wide_probes() {", 1)[0]
        first_block = arm.index('AEGIS_DEVICE_GUARD_STATE="$stage/guard.conf" bash "$guard" block')
        monitor_start = arm.index("systemctl start aegis-device-egress-guard.service")
        stage_end = arm.index('TEMP_PATHS+=("$stage")')
        staged = arm[arm.rfind('if [[ "$stage_auto" == 1 ]]; then', 0, stage_end):stage_end]
        self.assertLess(first_block, monitor_start)
        self.assertNotIn('bash "$guard" block', staged)
        for required in (
            "stage_auto_device_owner_admit >/dev/null",
            'bash "$guard" manager-status',
            "systemctl is-active --quiet aegis-device-egress-guard.service",
            "systemctl is-active --quiet \"$manager\"",
            "write_stage_auto_device_guard_receipt",
        ):
            self.assertIn(required, staged)

    @unittest.skipUnless(os.geteuid() == 0, "real root-owned receipt/lock required")
    def test_upgrade_holds_singleton_through_receipt_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            runtime = base / "runtime"
            install = base / "auto-guardian-install.json"
            guard_unit = base / "aegis-device-egress-guard.service"
            old = {"schema": "test", "guard_unit_sha256": None}
            raw = (json.dumps(old) + "\n").encode()
            install.write_bytes(raw)
            install.chmod(0o600)
            unit_raw = b"[Unit]\nDescription=focused lock test\n"
            guard_unit.write_bytes(unit_raw)
            guard_unit.chmod(0o644)
            calls = []

            def source_check(*, pending_guard_unit=False):
                calls.append(pending_guard_unit)
                if len(calls) == 1:
                    raise guardian.Refused("passive_generation")
                if len(calls) == 3:
                    contender = os.open(runtime / "guardian.lock", os.O_RDWR | os.O_NOFOLLOW)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(contender)

            with patch.object(guardian, "RUNTIME", runtime), \
                 patch.object(guardian, "SINGLETON", runtime / "guardian.lock"), \
                 patch.object(guardian, "INSTALL", install), \
                 patch.object(guardian, "GUARD_UNIT_FILE", guard_unit), \
                 patch.object(guardian, "own_source", side_effect=source_check):
                self.assertTrue(guardian.upgrade_guard_receipt())
                self.assertEqual(calls, [False, True, False])
                upgraded = json.loads(install.read_bytes())
                self.assertEqual(upgraded["guard_unit_sha256"],
                                 hashlib.sha256(unit_raw).hexdigest())
                archived = list(base.glob("auto-guardian-install-passive-*.json"))
                self.assertEqual(len(archived), 1)
                self.assertEqual(archived[0].read_bytes(), raw)
                named = runtime / "guardian.lock"
                self.assertTrue(stat.S_ISREG(named.stat().st_mode))
                contender = os.open(named, os.O_RDWR | os.O_NOFOLLOW)
                try:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(contender)

    @unittest.skipUnless(os.geteuid() == 0, "root-owned receipt required")
    def test_old_boot_manager_archived_only_after_exact_deny(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            state = parent / "device-guard.conf"
            manager = parent / "device-guard.conf.manager-binding"
            policy = parent / "auto-guardian-policy.json"
            lock = parent / "device-guard.conf.lock"
            state_raw = (b"schema=aegis_device_guard_v2\narmed=1\n"
                         b"service=aegis-client.service\nuplink=eth0\n"
                         b"manager=systemd-networkd.service\n"
                         b"capture_interface=aegis-tun0\n"
                         b"management_address_policy=current_local\n"
                         b"management_ports=22\ndhcp4=1\ndhcp6=1\n"
                         b"initramfs_network=absent_verified\n")
            state.write_bytes(state_raw)
            state.chmod(0o600)
            old_boot = "11111111-2222-3333-4444-555555555555"
            new_boot = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            old = {"schema": "aegis_device_guard_binding_v1",
                   "boot_id": old_boot,
                   "state_sha256": hashlib.sha256(
                       state_raw.rstrip(b"\n")).hexdigest(),
                   "path": "system.slice/systemd-networkd.service",
                   "inode": "12345", "invocation": "f" * 32}
            raw = (json.dumps(old, sort_keys=True) + "\n").encode()
            manager.write_bytes(raw)
            manager.chmod(0o600)
            lock.write_bytes(b"lock")
            lock.chmod(0o600)
            saved = {"schema": "aegis_auto_guardian_policy_v1",
                     "boot_id": old_boot,
                     "state_sha256": hashlib.sha256(state_raw).hexdigest(),
                     "guard_dev": lock.stat().st_dev,
                     "guard_ino": lock.stat().st_ino}
            policy.write_text(json.dumps(saved) + "\n")
            policy.chmod(0o600)
            observed = []

            def denied(_deadline):
                observed.append("kernel_deny_verified")
                return state_raw, b"denied"

            with patch.object(guardian, "own_source"), \
                 patch.object(guardian, "_held_lock"), \
                 patch.object(guardian, "GUARD_STATE", state), \
                 patch.object(guardian, "POLICY", policy), \
                 patch.object(guardian, "GUARD_LOCK", lock), \
                 patch.object(guardian, "host_anchor",
                              return_value={"boot_id": new_boot}), \
                 patch.object(guardian, "_deny_without_bindings",
                              side_effect=denied), \
                 patch.object(guardian, "verified_module",
                              return_value=guard_policy):
                self.assertEqual(guardian.archive_stale_manager_binding(9),
                                 hashlib.sha256(raw).hexdigest())
                self.assertEqual(observed, ["kernel_deny_verified"])
                self.assertFalse(manager.exists())
                archive = parent / ("device-guard-manager-oldboot-" +
                                    hashlib.sha256(raw).hexdigest() + ".json")
                self.assertEqual(archive.read_bytes(), raw)
                self.assertEqual(guardian.archive_stale_manager_binding(9),
                                 "absent")

    @unittest.skipUnless(os.geteuid() == 0, "root-owned receipt required")
    def test_current_boot_or_unproved_deny_never_retires_manager(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            state = parent / "device-guard.conf"
            manager = parent / "device-guard.conf.manager-binding"
            policy = parent / "auto-guardian-policy.json"
            lock = parent / "device-guard.conf.lock"
            state_raw = (b"schema=aegis_device_guard_v2\narmed=1\n"
                         b"service=aegis-client.service\nuplink=eth0\n"
                         b"manager=systemd-networkd.service\n"
                         b"capture_interface=aegis-tun0\n"
                         b"management_address_policy=current_local\n"
                         b"management_ports=22\ndhcp4=1\ndhcp6=1\n"
                         b"initramfs_network=absent_verified\n")
            state.write_bytes(state_raw)
            state.chmod(0o600)
            boot = "11111111-2222-3333-4444-555555555555"
            old = {"schema": "aegis_device_guard_binding_v1",
                   "boot_id": boot,
                   "state_sha256": hashlib.sha256(
                       state_raw.rstrip(b"\n")).hexdigest(),
                   "path": "system.slice/systemd-networkd.service",
                   "inode": "12345", "invocation": "f" * 32}
            raw = (json.dumps(old) + "\n").encode()
            manager.write_bytes(raw)
            manager.chmod(0o600)
            lock.write_bytes(b"lock")
            lock.chmod(0o600)
            policy.write_text(json.dumps({
                "schema": "aegis_auto_guardian_policy_v1", "boot_id": boot,
                "state_sha256": hashlib.sha256(state_raw).hexdigest(),
                "guard_dev": lock.stat().st_dev,
                "guard_ino": lock.stat().st_ino}) + "\n")
            policy.chmod(0o600)
            with patch.object(guardian, "own_source"), \
                 patch.object(guardian, "_held_lock"), \
                 patch.object(guardian, "GUARD_STATE", state), \
                 patch.object(guardian, "POLICY", policy), \
                 patch.object(guardian, "GUARD_LOCK", lock), \
                 patch.object(guardian, "verified_module",
                              return_value=guard_policy):
                with patch.object(guardian, "host_anchor",
                                  return_value={"boot_id": boot}), \
                     patch.object(guardian, "_deny_without_bindings") as deny:
                    with self.assertRaises(guardian.Refused):
                        guardian.archive_stale_manager_binding(9)
                    deny.assert_not_called()
                with patch.object(guardian, "host_anchor",
                                  return_value={"boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}), \
                     patch.object(guardian, "_deny_without_bindings",
                                  side_effect=guardian.Refused("deny_changed")):
                    with self.assertRaises(guardian.Refused):
                        guardian.archive_stale_manager_binding(9)
                self.assertEqual(manager.read_bytes(), raw)
                self.assertFalse(list(parent.glob("device-guard-manager-oldboot-*")))


if __name__ == "__main__":
    unittest.main()
