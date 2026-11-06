"""Exercise the production FullTun first-arm predicate across cold boots."""

import hashlib
import json
import stat
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import aegis_auto_guardian as guardian


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class FullReceiptColdSuccessor(unittest.TestCase):
    def test_production_consumed_grant_binds_snapshot_config(self):
        prior = "00000000-0000-0000-0000-000000000001"
        current = "00000000-0000-0000-0000-000000000002"
        candidate = "a" * 64
        installed = "e" * 64
        old = {"boot_id": prior,
               "service": "aegis-auto@" + "b" * 64 + ".service",
               "invocation_id": "1" * 32}
        receipt = {"old_boot_id": prior, "old_intent_sha256": "2" * 64,
                   "policy_sha256": "3" * 64}
        marker = {"boot_snapshot_sha256": "4" * 64,
                  "active_report_sha256": "5" * 64,
                  "active_generation_sha256": "6" * 64,
                  "policy_sha256": "7" * 64,
                  "source_sha256": "8" * 64}
        source = {"schema": "aegis_auto_terminal_source_v1"}
        store = {"schema": "aegis_auto_terminal_boot_store_v1",
                 "root_uuid": "r", "root_dev": "d", "boot_uuid": "b",
                 "boot_dev": "e"}
        marker_path = Path('/marker')
        read_map = {Path('/source'): b'source', marker_path:
                    json.dumps(marker).encode(),
                    Path('/old'): json.dumps(old).encode()}
        consumed_called = [True]

        def read(path, *_args):
            if path.name.startswith('auto-stop-intent-'):
                return read_map[Path('/old')]
            return read_map[path]

        def authenticated_consumed(**kwargs):
            if consumed_called[0]:
                kwargs['verify_block_and_owner'](old, marker, {})
            return receipt

        transition = SimpleNamespace(
            SOURCE_CONFIG=Path('/source'), ROOT=Path('/root'),
            _source_facts=lambda: (source, store),
            _cold_consumed_under_guard=lambda *_args: None,
            read_consumed_record=lambda *_args, **_kwargs: receipt,
            read=read, decode=json.loads,
            _marker_path=lambda *_args: marker_path,
            recovered_for_old=lambda *_args: Path('/recovered'),
            verify_old_lineage=lambda *_args: candidate,
            historical_source_context=lambda *_args: (source, store),
            sha=sha, authenticated_consumed=authenticated_consumed)
        with ExitStack() as stack:
            def patch(name, value):
                return stack.enter_context(mock.patch.object(guardian, name, value))
            patch('TERMINAL_MIGRATION_PENDING',
                  SimpleNamespace(exists=lambda: False, is_symlink=lambda: False))
            patch('_held_install', lambda *_args: True)
            patch('_held_lock', lambda *_args: (1, 1))
            patch('verified_module', lambda *_args: transition)
            patch('host_anchor', lambda: {'boot_id': current})
            boot_binding = patch('_boot_guard_binding', mock.Mock(
                return_value=(marker['boot_snapshot_sha256'],
                              marker['active_generation_sha256'])))
            config_binding = patch('_boot_snapshot_config_sha256', mock.Mock(
                return_value=installed))
            patch('_semantic_policy_readback', lambda **_kwargs: (None, b'policy'))
            patch('_no_client_grant', lambda *_args: True)
            patch('_crossboot_policy_seals', lambda *_args: None)
            patch('_boot_fixed_client_stopped', lambda *_args: None)
            patch('_boot_private_owners_absent', lambda *_args: None)
            lineage = guardian._currentboot_consumption_before_first_grant(9, 10)
            self.assertEqual(lineage['source_config_sha256'], installed)
            self.assertEqual(lineage['candidate_sha256'], candidate)
            config_binding.assert_called_once_with(
                marker['boot_snapshot_sha256'], marker['active_report_sha256'],
                prior, candidate)
            boot_binding.assert_called_once()
            consumed_called[0] = False
            with self.assertRaises(guardian.Refused):
                guardian._currentboot_consumption_before_first_grant(9, 10)
            consumed_called[0] = True
            marker['boot_snapshot_sha256'] = "f" * 64
            with self.assertRaises(guardian.Refused):
                guardian._currentboot_consumption_before_first_grant(9, 10)

    def test_authenticated_boot_snapshot_config_leaf_shape(self):
        active = "a" * 64
        predecessor = "00000000-0000-0000-0000-000000000001"
        installed = "e" * 64
        node = {"device": 1, "inode": 2, "mode": stat.S_IFREG | 0o600,
                "uid": 0, "gid": 0, "links": 1, "size": 2156,
                "mtime": 1, "mtime_ns": 0, "ctime": 1, "ctime_ns": 0,
                "content_sha256": installed}
        snapshot = {"schema": "aegis_auto_v2_boot_snapshot_v1",
                    "active_report_sha256": active,
                    "predecessor_boot_id": predecessor,
                    "source": {"candidate_sha256": "a" * 64},
                    "config": {"path": "/etc/aegis/client",
                               "entries": {"aegis.toml": node}}}

        def checked(value, expected_active=active, expected_boot=predecessor,
                    expected_sha=None):
            raw = json.dumps(value, sort_keys=True).encode()
            with mock.patch.object(guardian, "_boot_protected_file",
                                   return_value=raw) as protected:
                result = guardian._boot_snapshot_config_sha256(
                    expected_sha or sha(raw), expected_active, expected_boot,
                    "a" * 64)
            protected.assert_called_once_with(
                guardian.BOOT_CONTROL / 'boot-snapshots' /
                f'snapshot-{expected_sha or sha(raw)}.json', 1 << 20)
            return result

        self.assertEqual(checked(snapshot), installed)
        for change in (
                {"schema": "foreign"},
                {"active_report_sha256": "f" * 64},
                {"predecessor_boot_id": "00000000-0000-0000-0000-000000000009"},
                {"source": {"candidate_sha256": "f" * 64}},
                {"config": {"path": "/tmp/untrusted",
                            "entries": {"aegis.toml": node}}},
                {"config": {"path": "/etc/aegis/client",
                            "entries": {"aegis.toml": {**node, "mode": stat.S_IFLNK | 0o777}}}},
                {"config": {"path": "/etc/aegis/client",
                            "entries": {"aegis.toml": {**node, "size": "2156"}}}},
                {"config": {"path": "/etc/aegis/client",
                            "entries": {"aegis.toml": [node]}}},
                {"config": {"path": "/etc/aegis/client", "entries": {}}}):
            with self.subTest(change=change):
                with self.assertRaises(guardian.Refused):
                    checked({**snapshot, **change})
        with self.assertRaises(guardian.Refused):
            checked(snapshot, expected_sha="f" * 64)  # Marker substitution.
        changed = {**snapshot,
                   "config": {"path": "/etc/aegis/client",
                              "entries": {"aegis.toml":
                                          {**node, "content_sha256": "f" * 64}}}}
        with self.assertRaises(guardian.Refused):
            checked(changed, expected_sha=sha(json.dumps(snapshot,
                                                        sort_keys=True).encode()))

    def test_production_first_arm_three_boots_and_refusals(self):
        boots = [f"00000000-0000-0000-0000-{number:012x}"
                 for number in (1, 2, 3)]
        old_unit = "aegis-auto@" + "b" * 64 + ".service"
        successor_units = ["aegis-auto@" + token * 64 + ".service"
                           for token in ("c", "d")]
        candidate = "a" * 64
        source = "c" * 64
        installed_source = "e" * 64
        original_policy = "d" * 64
        current_policy = [original_policy]
        host_boot = [boots[0]]
        installed_candidate = [candidate]
        guard_raw = b"guard unit\n"
        dropin_raw = b"manager dropin\n"
        install_raw = b"guardian install\n"
        receipt = {
            "schema": "aegis_auto_guard_first_arm_v1",
            "boot_id": boots[0], "candidate_sha256": candidate,
            "source_config_sha256": source,
            "relay_servers": ["192.0.2.1:443"],
            "assessment_sha256": "1" * 64,
            "guard_unit_sha256": sha(guard_raw),
            "manager": "systemd-networkd.service",
            "manager_dropin_sha256": sha(dropin_raw),
            "guardian_install_sha256": sha(install_raw),
            "policy_sha256": original_policy,
            "installer_source_sha256": "2" * 64}
        arm_raw = json.dumps(receipt, sort_keys=True).encode()
        leaf = "input/payload/metadata/auto-guard-first-arm.json"
        config_leaf = "input/payload/config/aegis.toml"
        header = {"transaction_nonce": "3" * 64,
                  "planned_generation": "4" * 64,
                  "mode": "full-wide-tun",
                  "leaves": {leaf: sha(arm_raw), config_leaf: source}}
        request = {"transaction_nonce": header["transaction_nonce"],
                   "planned_generation": header["planned_generation"],
                   "mode": "full-wide-tun", "boot_id": boots[0],
                   "private_unit": old_unit}
        first_arm_path = Path(
            "/var/lib/aegis-install/client/auto-guard-first-arm.json")
        dropin_path = (Path("/etc/systemd/system") /
                       "systemd-networkd.service.d" /
                       "30-aegis-device-guard.conf")
        files = {first_arm_path: arm_raw,
                 guardian.GUARD_UNIT_FILE: guard_raw,
                 dropin_path: dropin_raw,
                 guardian.INSTALL: install_raw}
        policy_module = SimpleNamespace(
            LOCAL_INTENT=SimpleNamespace(exists=lambda: False))

        def call(lineage=None, phase="other"):
            return guardian._fulltun_first_arm(
                10, request, authenticated_lineage=lineage, phase=phase)

        with mock.patch.object(guardian, "_protected_stage_receipt_for_header",
                               side_effect=lambda *_args: json.dumps(header).encode()), \
             mock.patch.object(guardian, "_protected_stage_receipt",
                               return_value=arm_raw), \
             mock.patch.object(guardian, "regular",
                               side_effect=lambda path, *_args: files[path]), \
             mock.patch.object(guardian, "_installed_main_digest",
                               side_effect=lambda *_args: installed_candidate[0]), \
             mock.patch.object(guardian, "record",
                               side_effect=lambda path: {
                                   "state_sha256": receipt["assessment_sha256"],
                                   "policy_sha256": current_policy[0]}
                               if path == guardian.POLICY else
                               {"guard_unit_sha256": receipt["guard_unit_sha256"]}), \
             mock.patch.object(guardian, "verified_module",
                               return_value=policy_module), \
             mock.patch.object(Path, "read_text",
                               side_effect=lambda *_args, **_kwargs: host_boot[0]):
            self.assertEqual(call(), (sha(arm_raw), receipt["relay_servers"]))
            current_policy[0] = "e" * 64
            with self.assertRaises(guardian.Refused):
                call()  # Same boot still requires the original policy seal.

            for prior, current, current_unit in zip(
                    boots, boots[1:], successor_units):
                request["private_unit"] = current_unit
                host_boot[0] = request["boot_id"] = current
                lineage = {"current_boot_id": current,
                           "predecessor_boot_id": prior,
                           "candidate_sha256": candidate,
                           "private_unit": old_unit,
                           "source_config_sha256": installed_source,
                           "current_policy_sha256": current_policy[0]}
                # The first arm sealed the original bundle; each predecessor
                # boot snapshot seals the installed, rendered client config.
                header["leaves"][config_leaf] = installed_source
                with self.assertRaises(guardian.Refused):
                    call()  # A stored receipt alone has no successor authority.
                self.assertEqual(call(lineage),
                                 (sha(arm_raw), receipt["relay_servers"]))
                header["leaves"]["input/payload/bundle-main/aegis-client.toml"] = (
                    installed_source)
                with self.assertRaises(guardian.Refused):
                    call(lineage)  # Successor may only use installed config.
                del header["leaves"]["input/payload/bundle-main/aegis-client.toml"]
                coordinates = []
                with mock.patch.object(guardian.os, "write",
                                       side_effect=lambda fd, data:
                                       coordinates.append((fd, data)) or len(data)):
                    with self.assertRaises(guardian.Refused):
                        call(phase="grant")
                self.assertEqual(coordinates, [(2,
                    b"aegis_auto_firstarm_refused phase=grant gate=lineage_absent\n")])
                header["leaves"][config_leaf] = "f" * 64
                coordinates.clear()
                with mock.patch.object(guardian.os, "write",
                                       side_effect=lambda fd, data:
                                       coordinates.append((fd, data)) or len(data)):
                    with self.assertRaises(guardian.Refused):
                        call(lineage, phase="grant")
                self.assertEqual(coordinates, [(2,
                    b"aegis_auto_firstarm_refused phase=grant gate=source_config_leaf\n")])
                header["leaves"][config_leaf] = installed_source
                request["private_unit"] = "malformed-fresh-service"
                with self.assertRaises(guardian.Refused):
                    call(lineage)
                request["private_unit"] = old_unit
                with self.assertRaises(guardian.Refused):
                    call(lineage)  # Reusing the retired service is never fresh.
                request["private_unit"] = current_unit
                for field, bad in (("candidate_sha256", "f" * 64),
                                   ("source_config_sha256", "f" * 64),
                                   ("private_unit", current_unit),
                                   ("current_boot_id", prior),
                                   ("current_policy_sha256", "f" * 64)):
                    with self.assertRaises(guardian.Refused, msg=field):
                        call({**lineage, field: bad})
                with self.assertRaises(guardian.Refused):
                    call({**lineage, "private_unit": "malformed-old-service"})
                installed_candidate[0] = "f" * 64
                with self.assertRaises(guardian.Refused):
                    call(lineage)
                installed_candidate[0] = candidate
                host_boot[0] = prior
                with self.assertRaises(guardian.Refused):
                    call(lineage)
                host_boot[0] = current
                old_unit = current_unit


if __name__ == "__main__":
    unittest.main()
