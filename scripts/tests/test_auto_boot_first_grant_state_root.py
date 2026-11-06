"""The first cold-boot grant reads terminal records from the state root."""

import hashlib
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import aegis_auto_guardian as guardian


class FirstGrantStateRoot(unittest.TestCase):
    def test_consumed_archive_and_no_journal_recovery_use_state_root(self):
        boot = "11111111-2222-3333-4444-555555555555"
        old_boot = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        old_sha = "f" * 64
        state = Path("/var/lib/aegis-install/client")
        archive = state / f"auto-stop-intent-{old_boot}-{old_sha}.json"
        no_journal = state / f"auto-watchdog-no-journal-{old_boot}-{old_sha}.json"
        marker_path = state / "marker.json"
        source_config = Path("/etc/aegis-auto-terminal-source.json")
        old = {"boot_id": old_boot, "service": "aegis-auto@" + "a" * 64 + ".service",
               "invocation_id": "a" * 32}
        marker = {"source_sha256": "b" * 64,
                  "boot_snapshot_sha256": "d" * 64,
                  "active_report_sha256": "e" * 64,
                  "active_generation_sha256": "f" * 64,
                  "policy_sha256": "c" * 64}
        receipt = {"old_boot_id": old_boot, "old_intent_sha256": old_sha,
                   "policy_sha256": "c" * 64}
        source = {"schema": "aegis_auto_terminal_source_v1"}
        store = {"schema": "aegis_auto_terminal_boot_store_v1",
                 "root_uuid": "r", "root_dev": "1:1", "boot_uuid": "b",
                 "boot_dev": "2:2"}
        reads = []
        authenticated = []

        def read(path, limit=8192):
            reads.append(path)
            if path == source_config:
                return b"source"
            if path == archive:
                return b"old"
            if path == marker_path:
                return b"marker"
            raise FileNotFoundError(path)

        def decode(raw):
            return {b"old": old, b"marker": marker}[raw]

        def authenticate(**kwargs):
            authenticated.append(kwargs)
            kwargs["verify_block_and_owner"](old, marker, {})
            return receipt

        transition = SimpleNamespace(
            ROOT=state, SOURCE_CONFIG=source_config, read=read,
            _source_facts=lambda: (source, store),
            _cold_consumed_under_guard=lambda *args: None,
            read_consumed_record=lambda current_boot, allow_missing: receipt,
            decode=decode, _marker_path=lambda *args: marker_path,
            recovered_for_old=lambda *args: None,
            sha=lambda raw: hashlib.sha256(raw).hexdigest(),
            historical_source_context=lambda *args: (source, store),
            verify_old_lineage=lambda *_args: "a" * 64,
            authenticated_consumed=authenticate)
        pending = mock.Mock()
        pending.exists.return_value = False
        pending.is_symlink.return_value = False
        with mock.patch.object(guardian, "_held_install"), \
             mock.patch.object(guardian, "_held_lock"), \
             mock.patch.object(guardian, "TERMINAL_MIGRATION_PENDING", pending), \
             mock.patch.object(guardian, "verified_module", return_value=transition), \
             mock.patch.object(guardian, "_boot_guard_binding",
                               return_value=("d" * 64, "f" * 64)), \
             mock.patch.object(guardian, "_boot_snapshot_config_sha256",
                               return_value="9" * 64), \
             mock.patch.object(guardian, "_semantic_policy_readback",
                               return_value=(b"state", b"projection")), \
             mock.patch.object(guardian, "_no_client_grant", return_value=True), \
             mock.patch.object(guardian, "_crossboot_policy_seals"), \
             mock.patch.object(guardian, "_boot_fixed_client_stopped"), \
             mock.patch.object(guardian, "_boot_private_owners_absent"), \
             mock.patch.object(guardian, "host_anchor", return_value={"boot_id": boot}):
            lineage = guardian._currentboot_consumption_before_first_grant(10, 11)

        self.assertIn(archive, reads)
        self.assertEqual(len(authenticated), 1)
        self.assertEqual(authenticated[0]["recovered_path"], no_journal)
        self.assertEqual(authenticated[0]["current_boot"], boot)
        self.assertEqual(authenticated[0]["marker_path"], marker_path)
        self.assertEqual(lineage, {
            "current_boot_id": boot, "predecessor_boot_id": old_boot,
            "candidate_sha256": "a" * 64, "private_unit": old["service"],
            "source_config_sha256": "9" * 64,
            "current_policy_sha256": hashlib.sha256(b"projection").hexdigest()})


if __name__ == "__main__":
    unittest.main()
