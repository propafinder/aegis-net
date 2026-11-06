"""Crash, tamper and actor tests for the isolated uninstall protocol."""
import ast
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import aegis_auto_uninstall_journal as journal

H = "a" * 64
G = "b" * 64
B = "c" * 64


def intent():
    return {"schema": journal.SCHEMA,
            "boot_id": "11111111-2222-3333-4444-555555555555",
            "stage": "/run/aegis-installer-config-snapshots/test-stage",
            "pointer_sha256": H, "candidate_sha256": G,
            "owner_manifest_sha256": B, "guard_config_sha256": H,
            "package": "aegis-client", "version": "1.2.3-1",
            "backup_root": "/var/lib/aegis-auto-uninstall/backup",
            "nonce": "f" * 32}


class JournalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-a10-journal-")
        root = Path(self.temp.name)
        (root / "var/lib").mkdir(parents=True)
        for part in (root, root / "var", root / "var/lib"):
            part.chmod(0o700)
        self.fd = journal.directory(root, create=True, owner=os.getuid(), group=os.getgid())
        self.options = {"owner": os.getuid(), "group": os.getgid()}

    def tearDown(self):
        os.close(self.fd)
        self.temp.cleanup()

    def begin(self):
        return journal.begin(self.fd, intent(), **self.options)

    def advance(self, state, **kwargs):
        return journal.advance(self.fd, state, H, **kwargs, **self.options)

    def test_full_chain_and_idempotent_replay(self):
        self.begin()
        self.begin()
        for index, state in enumerate(journal.STATES):
            options = {}
            if index >= 5:
                options["backup_manifest_sha256"] = B
            if index in (2, 3):
                options["guard_split_sha256"] = G
            self.advance(state, **options)
            self.advance(state, **options)
        handoff = journal.seal_package_handoff(self.fd, **self.options)
        self.assertEqual(handoff["backup_manifest_sha256"], B)
        self.assertEqual(journal.seal_package_handoff(self.fd, **self.options), handoff)
        for effect in journal.EFFECTS:
            journal.record_effect(self.fd, effect, H, **self.options)
            journal.record_effect(self.fd, effect, H, **self.options)
        self.assertEqual(len(journal.read(self.fd, **self.options)[1]), len(journal.STATES))
        archived = journal.archive_completed(self.fd, root=self.temp.name,
                                             **self.options)
        self.assertTrue((Path(self.temp.name) / "var/lib" / archived /
                         "completed.json").is_file())
        self.assertFalse((Path(self.temp.name) /
                          "var/lib/aegis-auto-uninstall").exists())

    def test_interrupted_publish_replay_and_gap_refusal(self):
        self.begin()
        self.advance("admitted")
        self.advance("stopped-archived")
        os.rename("phase-001.json", "phase-003.json", src_dir_fd=self.fd,
                  dst_dir_fd=self.fd)
        with self.assertRaises(journal.Refused):
            journal.read(self.fd, **self.options)
        os.rename("phase-003.json", "phase-001.json", src_dir_fd=self.fd,
                  dst_dir_fd=self.fd)
        self.advance("stopped-archived")
        with self.assertRaises(journal.Refused):
            self.advance("actors-quiescent")

    def test_changed_intent_and_symlink_refuse(self):
        self.begin()
        changed = intent()
        changed["candidate_sha256"] = H
        with self.assertRaises(journal.Refused):
            journal.begin(self.fd, changed, **self.options)
        os.symlink("intent.json", "phase-000.json", dir_fd=self.fd)
        with self.assertRaises((journal.Refused, OSError)):
            journal.read(self.fd, **self.options)

    def test_duplicate_json_and_premature_handoff_refuse(self):
        self.begin()
        with self.assertRaises(journal.Refused):
            journal.seal_package_handoff(self.fd, **self.options)
        raw = journal.leaf(self.fd, "intent.json", **self.options)
        self.assertRaises(journal.Refused, journal.strict_json,
                          raw[:-1] + b',"schema":"duplicate"}')

    def test_guard_and_backup_refs_are_required(self):
        self.begin()
        self.advance("admitted")
        self.advance("stopped-archived")
        with self.assertRaises(journal.Refused):
            self.advance("guard-recovering")
        self.advance("guard-recovering", guard_split_sha256=G)
        self.advance("guard-released", guard_split_sha256=G)
        self.advance("actors-quiescent")
        with self.assertRaises(journal.Refused):
            self.advance("owners-archived")

    def test_reboot_observation_is_distinct_from_stopped_seal(self):
        self.begin()
        self.advance("admitted")
        self.advance("reboot-observed")
        phases = journal.read(self.fd, **self.options)[1]
        self.assertEqual(phases[1][0]["state"], "reboot-observed")
        with self.assertRaises(journal.Refused):
            self.advance("stopped-archived")

    def test_intent_only_reboot_replays_admission_then_observation(self):
        self.begin()
        self.assertEqual(journal.read(self.fd, **self.options)[1], [])
        self.advance("admitted")
        self.advance("reboot-observed")
        phases = journal.read(self.fd, **self.options)[1]
        self.assertEqual([phase[0]["state"] for phase in phases],
                         ["admitted", "reboot-observed"])

    def test_reboot_observation_replays_pending_phase_after_archive_cut(self):
        self.begin()
        self.advance("admitted")
        raw = journal.canonical({"schema": journal.PHASE_SCHEMA,
            "index": 1, "state": "reboot-observed",
            "intent_sha256": journal.sha(journal.canonical(intent())),
            "previous_sha256": journal.read(self.fd, **self.options)[1][0][1],
            "observation_sha256": "a" * 64,
            "backup_manifest_sha256": None, "guard_split_sha256": None})
        child = os.open("pending-phase-001.json", os.O_WRONLY | os.O_CREAT |
                        os.O_EXCL, 0o600, dir_fd=self.fd)
        try:
            os.write(child, raw)
            os.fsync(child)
        finally:
            os.close(child)
        self.advance("reboot-observed")
        self.assertEqual(journal.read(self.fd, **self.options)[1][1][0]["state"],
                         "reboot-observed")

    def test_active_capture_topology_is_stopped_before_actor_seal(self):
        source = (Path(__file__).resolve().parents[1] / "lib" /
                  "aegis_installer_auto_v2.py").read_text()
        function = next(node for node in ast.parse(source).body
                        if isinstance(node, ast.FunctionDef) and
                        node.name == "_uninstall_stop_actors")
        calls = []
        active = {"aegis-auto-capture-topology.service": True}

        def state(unit):
            return {"LoadState": "loaded",
                    "FragmentPath": "/etc/systemd/system/" + unit,
                    "ActiveState": "active" if active.get(unit, False) else "inactive"}

        def call_output(command, **_kwargs):
            calls.append(tuple(command))
            if command[1] == "stop":
                active[command[2]] = False
            return b""

        def need(condition):
            if not condition:
                raise AssertionError("actor readback refused")

        namespace = {"_uninstall_unit_state": state,
                     "_uninstall_terminal_instances_stopped": lambda: calls.append(
                         ("terminal-instances-stopped",)),
                     "_uninstall_unit_stopped": lambda unit: need(
                         state(unit)["ActiveState"] == "inactive"),
                     "call_output": call_output, "need": need,
                     "no_private_jobs_or_units": lambda: need(
                         not active["aegis-auto-capture-topology.service"])}
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     "<installed uninstall actor>", "exec"), namespace)
        namespace["_uninstall_stop_actors"]()
        # Before stopping actors and after their PID 1 readback.
        self.assertEqual(calls.count(("terminal-instances-stopped",)), 2)
        self.assertIn(("/usr/bin/systemctl", "stop",
                       "aegis-auto-capture-topology.service"), calls)
        self.assertNotIn(("/usr/bin/systemctl", "disable",
                          "aegis-auto-capture-topology.service"), calls)

    def test_generic_purge_backup_retains_private_config_and_home(self):
        root = Path(self.temp.name)
        samples = (("/etc/aegis/client", "client.toml", b"private config"),
                   ("/var/lib/aegis-client", "state", b"private home"),
                   ("/var/log/aegis-client", "events", b"private log"))
        for directory, name, raw in samples:
            location = root / directory.lstrip("/")
            location.mkdir(parents=True, mode=0o700, exist_ok=True)
            location.chmod(0o700)
            (location / name).write_bytes(raw)
            (location / name).chmod(0o600)
        self.begin()
        proof = journal.backup_generic_roots(self.fd, root=self.temp.name,
                                             **self.options)
        self.assertEqual(journal.verify_generic_backup(self.fd, root=self.temp.name,
                                                       **self.options), proof)
        for directory, name, raw in samples:
            (root / directory.lstrip("/") / name).unlink()
            (root / directory.lstrip("/")).rmdir()
        self.assertEqual(journal.backup_generic_roots(self.fd, root=self.temp.name,
                                                     **self.options), proof)
        self.assertEqual((root / "var/lib/aegis-auto-uninstall/backup/generic"
                          "/generic-01/state").read_bytes(), b"private home")

    def test_direct_package_purge_before_generic_receipt_refuses(self):
        self.begin()
        for index, state in enumerate(journal.STATES):
            options = {}
            if index >= 5:
                options["backup_manifest_sha256"] = B
            if index in (2, 3):
                options["guard_split_sha256"] = G
            self.advance(state, **options)
        journal.seal_package_handoff(self.fd, **self.options)
        original_read = journal.read
        with mock.patch.object(journal.sys, "platform", "linux"), \
             mock.patch.object(journal.os, "geteuid", return_value=0), \
             mock.patch.object(journal, "directory", return_value=os.dup(self.fd)), \
             mock.patch.object(journal, "read", side_effect=lambda fd:
                               original_read(fd, **self.options)):
            with self.assertRaises(journal.Refused):
                journal.verify_package_handoff(intent()["version"])

    def test_replay_complete_pending_intent(self):
        raw = journal.canonical(intent())
        child = os.open("pending-intent.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600, dir_fd=self.fd)
        try:
            os.write(child, raw)
            os.fsync(child)
        finally:
            os.close(child)
        journal.begin(self.fd, intent(), **self.options)
        self.assertTrue(journal.absent(self.fd, "pending-intent.json"))
        self.assertFalse(journal.absent(self.fd, "intent.json"))

    def test_partial_pending_is_retained_and_replaced(self):
        child = os.open("pending-intent.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600, dir_fd=self.fd)
        os.close(child)
        journal.begin(self.fd, intent(), **self.options)
        retained = [name for name in os.listdir(self.fd) if name.startswith("failed-")]
        self.assertEqual(len(retained), 1)
        self.assertEqual(os.stat(retained[0], dir_fd=self.fd).st_size, 0)
        self.assertEqual(journal.read(self.fd, **self.options)[0], intent())

    def test_pending_phase_does_not_advance_chain(self):
        self.begin()
        self.advance("admitted")
        child = os.open("pending-phase-001.json", os.O_WRONLY | os.O_CREAT |
                        os.O_EXCL, 0o600, dir_fd=self.fd)
        os.close(child)
        self.assertEqual(len(journal.read(self.fd, **self.options)[1]), 1)
        self.advance("stopped-archived")
        self.assertEqual(len(journal.read(self.fd, **self.options)[1]), 2)

    def test_private_owner_backup_and_manifest(self):
        owners = Path(self.temp.name) / "owners"
        owners.mkdir(mode=0o700)
        nested = owners / "o0"
        nested.mkdir(mode=0o700)
        (nested / "secret").write_bytes(b"private rollback material")
        (nested / "secret").chmod(0o600)
        (owners / "o1").write_bytes(b"unit source")
        (owners / "o1").chmod(0o600)
        paths = tuple(f"/owners/o{index}" for index in range(11))
        manifest_sha = journal.backup_owners(self.fd, paths, root=self.temp.name,
                                             **self.options)
        self.assertEqual(len(manifest_sha), 64)
        self.assertEqual(journal.verify_backup(self.fd, paths, manifest_sha,
                                               **self.options)["owners"], list(paths))
        self.assertEqual((Path(self.temp.name) / "var/lib/aegis-auto-uninstall/backup"
                          "/owners/o0/secret").read_bytes(), b"private rollback material")
        self.assertEqual(journal.backup_owners(self.fd, paths, root=self.temp.name,
                                               **self.options), manifest_sha)
        (nested / "secret").write_bytes(b"changed")
        with self.assertRaises((journal.Refused, OSError)):
            journal.backup_owners(self.fd, paths, root=self.temp.name,
                                  **self.options)
        copied = (Path(self.temp.name) / "var/lib/aegis-auto-uninstall/backup"
                  "/owners/o0/secret")
        copied.write_bytes(b"tampered")
        with self.assertRaises((journal.Refused, OSError)):
            journal.verify_backup(self.fd, paths, manifest_sha, **self.options)

    def test_retirement_replays_after_first_rename(self):
        owners = Path(self.temp.name) / "owners"
        owners.mkdir(mode=0o700)
        (owners / "o0").write_bytes(b"control")
        (owners / "o0").chmod(0o600)
        paths = tuple(f"/owners/o{index}" for index in range(11))
        self.begin()
        self.advance("admitted")
        self.advance("stopped-archived")
        backup_sha = journal.backup_owners(self.fd, paths, root=self.temp.name,
                                           **self.options)
        self.advance("guard-recovering", backup_manifest_sha256=backup_sha,
                     guard_split_sha256=G)
        self.advance("guard-released", guard_split_sha256=G)
        self.advance("actors-quiescent")
        result = journal.retire_owners(self.fd, paths, backup_sha,
                                       root=self.temp.name, **self.options)
        self.assertEqual(len(result), 64)
        self.assertFalse((owners / "o0").exists())
        self.assertEqual(journal.retire_owners(self.fd, paths, backup_sha,
                         root=self.temp.name, **self.options), result)
        auto = Path(self.temp.name) / "var/lib/aegis-auto"
        auto.mkdir(mode=0o700)
        (auto / "release").write_bytes(b"retained package source")
        (auto / "release").chmod(0o600)
        self.advance("owners-archived", backup_manifest_sha256=backup_sha)
        auto_sha = journal.retire_auto_root(self.fd, root=self.temp.name,
                                            **self.options)
        self.assertEqual(len(auto_sha), 64)
        self.assertEqual(journal.retire_auto_root(self.fd, root=self.temp.name,
                         **self.options), auto_sha)
        self.assertFalse(auto.exists())


if __name__ == "__main__":
    unittest.main()
