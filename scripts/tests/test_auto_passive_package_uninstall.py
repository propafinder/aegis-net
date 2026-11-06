"""Passive DEBs must be removable without inventing an active V2 generation."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


journal = load("passive_uninstall_journal_test", ROOT / "scripts/lib/aegis_auto_uninstall_journal.py")
coordinator = load("passive_uninstall_coordinator_test", ROOT / "scripts/lib/aegis_installer_auto_v2.py")


class PassivePackageRemoval(unittest.TestCase):
    def intent(self):
        return {"schema": "aegis_auto_v2_passive_package_removal_v1",
                "package": "aegis-client", "version": "0.3.50-100",
                "payload_sha256": "a" * 64,
                "boot_id": "12345678-1234-1234-1234-123456789abc",
                "nonce": "b" * 32}

    def test_passive_intent_is_distinct_from_active_stop_authority(self):
        value = self.intent()
        journal.validate_passive_intent(value)
        with self.assertRaises(journal.Refused):
            journal.validate_intent(value)
        for key in value:
            missing = value.copy(); del missing[key]
            with self.subTest(missing=key), self.assertRaises(journal.Refused):
                journal.validate_passive_intent(missing)
        for key, bad in (("schema", journal.SCHEMA), ("package", "aegis-server"),
                         ("payload_sha256", "A" * 64), ("nonce", "../escape"),
                         ("version", "bad\nversion"), ("boot_id", "unknown")):
            value = self.intent(); value[key] = bad
            with self.subTest(key=key), self.assertRaises(journal.Refused):
                journal.validate_passive_intent(value)

    def test_unarmed_roster_is_closed_and_keeps_all_sixteen_units(self):
        files = {"usr/local/bin/aegis-client": {"sha256": "c" * 64, "mode": 0o755, "retained_mode": 0o555}}
        for name in coordinator.FRESH_CLIENT_HELPERS:
            files["usr/local/lib/aegis/helpers/" + name] = {
                "sha256": "c" * 64, "mode": 0o500 if name.startswith("lib/aegis_auto_") or name in (
                    "lib/aegis_installer_auto_v2.py", "lib/aegis_initrd_policy.py",
                    "lib/aegis_initrd_classic.py", "lib/aegis-auto-terminal-hook") else 0o755,
                "retained_mode": 0o444}
        for name in coordinator.FRESH_CLIENT_UNITS:
            files["etc/systemd/system/" + name] = {
                "sha256": "c" * 64, "mode": 0o644, "retained_mode": 0o444}
        payload = {"files": files, "install_sha256": "d" * 64, "package_version": "0.3.50-100"}
        coordinator._passive_removal_payload(payload)
        self.assertEqual(len(coordinator.FRESH_CLIENT_UNITS), 16)
        for leaf in ("lib/aegis_initrd_classic.py", "lib/aegis-auto-terminal-hook"):
            self.assertEqual(files["usr/local/lib/aegis/helpers/" + leaf]["mode"], 0o500)
        for key in ("etc/systemd/system/aegis-auto-guardian.service",
                    "usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py"):
            bad = copy.deepcopy(payload); del bad["files"][key]
            with self.subTest(missing=key), self.assertRaises(coordinator.Refused):
                coordinator._passive_removal_payload(bad)
        bad = copy.deepcopy(payload)
        bad["files"]["etc/systemd/system/foreign.service"] = next(iter(files.values()))
        with self.assertRaises(coordinator.Refused):
            coordinator._passive_removal_payload(bad)

    def test_partial_passive_journal_blocks_normal_python_mutators(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "intent.json").write_bytes(journal.canonical(self.intent()))
            (root / "intent.json").chmod(0o600)
            with mock.patch.object(coordinator, "uninstall_journal", journal), \
                 mock.patch.object(journal, "directory", side_effect=lambda: os.open(root, os.O_RDONLY)), \
                 mock.patch.object(journal, "leaf", wraps=lambda fd, name, **kw: (
                     root / name).read_bytes()), \
                 mock.patch.object(coordinator.Path, "exists", return_value=True):
                self.assertTrue(coordinator.uninstall_intent_present())

    def test_cut_after_mkdir_also_blocks_python_mutators(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(coordinator, "uninstall_journal", journal), \
                 mock.patch.object(journal, "directory", side_effect=lambda: os.open(root, os.O_RDONLY)), \
                 mock.patch.object(coordinator.Path, "exists", return_value=True):
                self.assertTrue(coordinator.uninstall_intent_present())

    def test_every_durable_owner_refuses_before_live_probes(self):
        owners = (*coordinator.UNINSTALL_OWNERS[:5], "/var/lib/aegis-install/client",
                  "/var/lib/aegis-install/auto-client",
                  "/etc/systemd/system/aegis-device-egress-guard.service",
                  "/etc/systemd/system/aegis-client.service")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for index, owner in enumerate(owners):
                for broken_link in (False, True):
                    root = base / f"owner-{index}-link-{int(broken_link)}"
                    selected = root / owner.lstrip("/")
                    selected.parent.mkdir(parents=True, exist_ok=True)
                    if broken_link:
                        selected.symlink_to(root / "absent-target")
                    else:
                        selected.write_bytes(b"retained ownership")
                    with self.subTest(owner=owner, broken_link=broken_link), \
                         mock.patch.object(coordinator, "uninstall_journal", journal), \
                         mock.patch.object(coordinator, "Path", side_effect=lambda p: root / str(p).lstrip("/")), \
                         mock.patch.object(coordinator, "call_output") as live:
                        with self.assertRaises(coordinator.Refused):
                            coordinator._passive_removal_no_owner()
                        live.assert_not_called()
                    selected.unlink()

    def test_all_packaged_actors_require_dead_zero_pid_and_expected_fragment(self):
        names = (*coordinator.FRESH_CLIENT_UNITS, "aegis-client.service",
                 "aegis-device-egress-guard.service")
        def facts(name):
            absent = name == "aegis-device-egress-guard.service"
            result = {"Id": name, "LoadState": "not-found" if absent else "loaded",
                      "ActiveState": "inactive", "SubState": "dead",
                      "NeedDaemonReload": "no", "FragmentPath": "" if absent else (
                          "/usr/lib/systemd/system/" if name == "aegis-client.service" else
                          "/etc/systemd/system/") + name}
            if not name.endswith(".timer"):
                result.update(MainPID="0", ControlPID="0", ControlGroup="", NFileDescriptorStore="0")
            return result
        with mock.patch.object(coordinator, "_uninstall_unit_state", side_effect=lambda n, **kw: facts(n)):
            coordinator._passive_removal_actors()
        for name in names:
            for change in ({"ActiveState": "active", "SubState": "running"},
                           {"FragmentPath": "/etc/systemd/system/foreign.service"},
                           *([] if name.endswith(".timer") else [
                               {"MainPID": "42"}, {"ControlPID": "42"},
                               {"ControlGroup": "/system.slice/leftover"},
                               {"NFileDescriptorStore": "1"}])):
                def observed(n, **kw):
                    row = facts(n)
                    if n == name:
                        row.update(change)
                    return row
                with self.subTest(unit=name, change=change), \
                     mock.patch.object(coordinator, "_uninstall_unit_state", side_effect=observed), \
                     self.assertRaises(coordinator.Refused):
                    coordinator._passive_removal_actors()

    def test_same_bytes_replaced_inode_refuses_final_payload_recheck(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "unit"; path.write_bytes(b"exact payload")
            fd = os.open(path, os.O_RDONLY)
            payload = {"files": {"fixed/unit": {"mode": 0o600}}}
            held = [(fd, "/fixed/unit", hashlib.sha256(path.read_bytes()).hexdigest())]
            try:
                with mock.patch.object(coordinator, "held_root_file", side_effect=lambda *a: os.open(path, os.O_RDONLY)):
                    coordinator._passive_removal_recheck_held(held, payload)
                    replacement = Path(temporary) / "replacement"
                    replacement.write_bytes(path.read_bytes()); replacement.replace(path)
                    with self.assertRaises(coordinator.Refused):
                        coordinator._passive_removal_recheck_held(held, payload)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
