"""Storage and source contracts for a stricter current-boot deny seal.

The kernel JSON/text verifier and terminal PID1 witness have separate tests;
this fixture checks their cross-boot authenticated receipt composition.
"""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import aegis_auto_guardian as guardian
import aegis_auto_guard_policy as policy
import aegis_auto_boot_transition as transition
from aegis_auto_native_witness import policy_projection
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_auto_guard_policy import kernel_rows, encoded as nft_encoded

OLD = "11111111-2222-3333-4444-555555555555"
NEW = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
STATE = (b"schema=aegis_device_guard_v2\narmed=1\n"
         b"service=aegis-client.service\nuplink=eth0\n"
         b"manager=systemd-networkd.service\n"
         b"capture_interface=aegis-tun0\n"
         b"management_address_policy=current_local\n"
         b"management_ports=22\ndhcp4=1\ndhcp6=1\n"
         b"initramfs_network=absent_verified\n")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class CrossbootSeals(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.state = root / "device-guard.conf"
        self.state.write_bytes(STATE)
        self.lock = root / "device-guard.conf.lock"
        self.lock.write_bytes(b"lock")
        self.policy_path = root / "auto-guardian-policy.json"
        self.old_sha = "1" * 64
        self.projection = b"current proved kernel projection"
        self.current_sha = sha(self.projection)
        stat = self.lock.stat()
        self.policy_path.write_bytes(encoded({
            "schema": "aegis_auto_guardian_policy_v1", "boot_id": NEW,
            "netns_ino": 42,
            "state_sha256": sha(STATE), "policy_sha256": self.current_sha,
            "guard_dev": stat.st_dev, "guard_ino": stat.st_ino,
        }))
        self.binding = {
            "schema": "aegis_device_guard_binding_v2", "boot_id": OLD,
            "state_sha256": sha(STATE.rstrip(b"\n")),
            "path": "system.slice/systemd-networkd.service",
            "inode": "5660", "invocation": "f" * 32,
            "ifindex": 2, "dhcp4_server": None, "dhcp6_server": None,
        }
        self.binding_raw = encoded(self.binding)
        self.binding_sha = sha(self.binding_raw)
        self.archive = root / ("device-guard-manager-oldboot-" +
                               self.binding_sha + ".json")
        self.archive.write_bytes(self.binding_raw)
        self.witness_path = root / ("device-guard-manager-retired-" + OLD +
                                    "-" + self.binding_sha + ".json")
        self.witness = {
            "schema": "aegis_manager_oldboot_retirement_v1",
            "old_boot_id": OLD, "new_boot_id": NEW,
            "old_policy_sha256": self.old_sha,
            "current_policy_sha256": self.current_sha,
            "state_sha256": sha(STATE),
            "binding_sha256": self.binding_sha,
            "guard_dev": stat.st_dev, "guard_ino": stat.st_ino,
        }
        self.witness_path.write_bytes(encoded(self.witness))
        patches = (
            mock.patch.object(guardian, "GUARD_STATE", self.state),
            mock.patch.object(guardian, "GUARD_LOCK", self.lock),
            mock.patch.object(guardian, "POLICY", self.policy_path),
            mock.patch.object(guardian, "INSTALL", root / "auto-guardian-install.json"),
            mock.patch.object(guardian, "CAPTURE_BINDING", root / "capture-binding"),
            mock.patch.object(guardian, "host_anchor", return_value={
                "boot_id": NEW, "netns_ino": 42}),
            mock.patch.object(guardian, "regular", side_effect=lambda path, *a: Path(path).read_bytes()),
            mock.patch.object(guardian, "record", side_effect=lambda path, *a: json.loads(Path(path).read_bytes())),
            mock.patch.object(guardian, "verified_module", return_value=policy),
            mock.patch.object(guardian, "_no_client_grant", return_value=True),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def verify(self, old_sha=None):
        guardian._crossboot_policy_seals(
            OLD, old_sha or self.old_sha, self.current_sha, self.projection)

    def test_distinct_seals_require_exact_old_manager_retirement(self):
        self.verify()
        with self.assertRaises(guardian.Refused):
            self.verify("2" * 64)
        self.witness_path.unlink()
        with self.assertRaises(guardian.Refused):
            self.verify()

    def test_current_policy_receipt_schema_and_netns_are_exact(self):
        saved = json.loads(self.policy_path.read_bytes())
        for changes in ({"schema": "aegis_auto_guardian_policy_v2"},
                        {"netns_ino": 43}, {"extra": "untrusted"}):
            self.policy_path.write_bytes(encoded({**saved, **changes}))
            with self.subTest(changes=changes), self.assertRaises(guardian.Refused):
                self.verify()
        self.policy_path.write_bytes(encoded(saved))
        self.verify()

    def test_archive_and_witness_mutations_refuse(self):
        self.witness["current_policy_sha256"] = "2" * 64
        self.witness_path.write_bytes(encoded(self.witness))
        with self.assertRaises(guardian.Refused):
            self.verify()
        self.witness["current_policy_sha256"] = self.current_sha
        self.witness_path.write_bytes(encoded(self.witness))
        self.archive.write_bytes(self.binding_raw.replace(b"5660", b"5661"))
        with self.assertRaises(guardian.Refused):
            self.verify()

    def test_guard_retirement_publishes_both_seals_before_unlink(self):
        manager_path = self.state.with_name(self.state.name + ".manager-binding")
        manager_path.write_bytes(self.binding_raw)
        self.witness_path.unlink()
        saved = json.loads(self.policy_path.read_bytes())
        saved["boot_id"] = OLD
        saved["policy_sha256"] = self.old_sha
        self.policy_path.write_bytes(encoded(saved))
        with mock.patch.object(guardian, "own_source"), \
             mock.patch.object(guardian, "_held_lock"), \
             mock.patch.object(guardian, "_deny_without_bindings",
                               return_value=(STATE, self.projection)), \
             mock.patch.object(guardian, "_rotation_write_once",
                               side_effect=lambda path, row: Path(path).write_bytes(encoded(row))):
            self.assertEqual(guardian.archive_stale_manager_binding(9),
                             self.binding_sha)
        self.assertFalse(manager_path.exists())
        self.assertEqual(json.loads(self.witness_path.read_bytes()), self.witness)
        self.assertEqual(self.archive.read_bytes(), self.binding_raw)

    def test_zero_dhcp_retirement_keeps_equal_historical_seal(self):
        self.witness_path.unlink()
        zero = STATE.replace(b"dhcp4=1\n", b"dhcp4=0\n").replace(
            b"dhcp6=1\n", b"dhcp6=0\n")
        self.state.write_bytes(zero)
        manager = {**self.binding, "state_sha256": sha(zero.rstrip(b"\n"))}
        raw = encoded(manager)
        manager_path = self.state.with_name(self.state.name + ".manager-binding")
        saved = json.loads(self.policy_path.read_bytes())
        saved.update(boot_id=OLD, state_sha256=sha(zero),
                     policy_sha256=self.current_sha)
        self.policy_path.write_bytes(encoded(saved))
        def retire():
            with mock.patch.object(guardian, "own_source"), \
                 mock.patch.object(guardian, "_held_lock"), \
                 mock.patch.object(guardian, "_deny_without_bindings",
                                   return_value=(zero, self.projection)):
                return guardian.archive_stale_manager_binding(9)
        manager_path.write_bytes(raw)
        self.assertEqual(retire(), sha(raw))
        self.assertFalse(manager_path.exists())
        self.assertFalse(any(self.state.parent.glob("device-guard-manager-retired-*")))
        self.assertEqual((self.state.parent /
                          ("device-guard-manager-oldboot-" + sha(raw) + ".json"))
                         .read_bytes(), raw)
        manager_path.write_bytes(raw)
        saved["policy_sha256"] = self.old_sha
        self.policy_path.write_bytes(encoded(saved))
        with self.assertRaises(guardian.Refused):
            retire()
        self.assertEqual(manager_path.read_bytes(), raw)

    def test_dual_stack_manager_numeric_projection_needs_two_distinct_rules(self):
        manager = {**self.binding, "boot_id": NEW}
        table = kernel_rows(STATE, manager=manager)
        named, _, _ = policy_projection(nft_encoded(table))
        rows = json.loads(named)
        marker = policy._marker(manager, "manager")
        changed = 0
        for item in rows:
            rule = item.get("rule", {})
            if rule.get("comment") != marker:
                continue
            socket_matches = [expr["match"] for expr in rule["expr"]
                              if "match" in expr and
                              "socket" in expr["match"].get("left", {})]
            self.assertEqual(len(socket_matches), 1)
            socket_matches[0]["right"] = manager["inode"]
            changed += 1
        self.assertEqual(changed, 2)
        numeric = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(policy.canonical_manager_projection(numeric, manager),
                         named)
        duplicate = rows + [next(item for item in rows
                                 if item.get("rule", {}).get("comment") == marker)]
        with self.assertRaises(policy.PolicyRefused):
            policy.canonical_manager_projection(
                json.dumps(duplicate, sort_keys=True,
                           separators=(",", ":")).encode(), manager)

    def test_client_or_manager_binding_refuses(self):
        path = self.state.with_name(self.state.name + ".client-binding")
        path.write_bytes(b"untrusted")
        with self.assertRaises(guardian.Refused):
            self.verify()
        path.unlink()
        path = self.state.with_name(self.state.name + ".manager-binding")
        path.write_bytes(self.binding_raw)
        with self.assertRaises(guardian.Refused):
            self.verify()

    def test_historical_equal_seal_remains_admitted_without_retirement(self):
        self.witness_path.unlink()
        guardian._crossboot_policy_seals(
            OLD, self.current_sha, self.current_sha, self.projection)

    def test_fresh_live_manager_refines_only_the_consumed_deny_base(self):
        manager = {**self.binding, "boot_id": NEW, "invocation": "e" * 32}
        base = policy_projection(nft_encoded(kernel_rows(STATE)))[0]
        live = policy_projection(nft_encoded(kernel_rows(STATE,
                                                        manager=manager)))[0]
        self.witness["current_policy_sha256"] = sha(base)
        self.witness_path.write_bytes(encoded(self.witness))
        saved = json.loads(self.policy_path.read_bytes())
        saved["policy_sha256"] = sha(live)
        self.policy_path.write_bytes(encoded(saved))
        manager_path = self.state.with_name(self.state.name + ".manager-binding")
        manager_path.write_bytes(encoded(manager))
        with mock.patch.object(guardian, "read_guard_policy",
                               return_value={"policy_sha256": sha(live)}):
            guardian._crossboot_policy_seals(OLD, self.old_sha, sha(base), live)
            wrong = {**manager, "inode": "5661"}
            manager_path.write_bytes(encoded(wrong))
            with self.assertRaises((guardian.Refused, policy.PolicyRefused)):
                guardian._crossboot_policy_seals(OLD, self.old_sha,
                                                 sha(base), live)
            manager_path.write_bytes(encoded({**manager, "boot_id": OLD}))
            with self.assertRaises(guardian.Refused):
                guardian._crossboot_policy_seals(OLD, self.old_sha,
                                                 sha(base), live)
            manager_path.write_bytes(encoded({**manager,
                                               "dhcp4_server": "10.77.0.1"}))
            with mock.patch.object(guardian, "read_guard_policy",
                                   side_effect=guardian.Refused(
                                       "live_manager_lease_changed")):
                with self.assertRaises(guardian.Refused):
                    guardian._crossboot_policy_seals(OLD, self.old_sha,
                                                     sha(base), live)
            manager_path.write_bytes(encoded(manager))
        with mock.patch.object(guardian, "read_guard_policy",
                               side_effect=guardian.Refused("manager_pid_changed")):
            with self.assertRaises(guardian.Refused):
                guardian._crossboot_policy_seals(OLD, self.old_sha,
                                                 sha(base), live)

    def test_full_old_to_managerless_to_new_manager_consumption(self):
        root = self.state.parent
        base = policy_projection(nft_encoded(kernel_rows(STATE)))[0]
        self.projection = base
        self.current_sha = sha(base)
        self.witness["current_policy_sha256"] = self.current_sha
        self.witness_path.write_bytes(encoded(self.witness))
        saved = json.loads(self.policy_path.read_bytes())
        saved["policy_sha256"] = self.current_sha
        self.policy_path.write_bytes(encoded(saved))
        stop = root / "auto-stop-intent.json"
        unit = "aegis-auto@" + "a" * 64 + ".service"
        intent = {"schema": "aegis_auto_stop_intent_v1", "boot_id": OLD,
                  "invocation_id": "b" * 32, "service": unit,
                  "phase": "deny_proven"}
        stop.write_bytes(transition.canonical(intent))
        marker = {"schema": "aegis_auto_terminal_boot_v1",
                  "old_boot_id": OLD, "boot_uuid":
                  "33333333-3333-3333-3333-333333333333",
                  "source_sha256": "c" * 64,
                  "intent_sha256": sha(stop.read_bytes()),
                  "nonce": "d" * 32, "a_sha256": "e" * 64,
                  "clean_stop_sha256": "f" * 64, "b_sha256": "0" * 64,
                  "policy_sha256": self.old_sha,
                  "active_generation_sha256": "2" * 64,
                  "active_report_sha256": "3" * 64,
                  "boot_snapshot_sha256": "4" * 64,
                  "final_job": 12, "final_job_type": "start",
                  "action": "reboot", "pid1_tick": 0,
                  "root_uuid": "44444444-4444-4444-4444-444444444444",
                  "root_dev": "1:2", "boot_dev": "3:4",
                  "hook_sha256": "5" * 64, "helper_sha256": "6" * 64}
        marker_path = root / "terminal-marker.json"
        marker_path.write_bytes(transition.canonical(marker))
        recovery = {"schema": "aegis_auto_watchdog_pending_v1",
                    "phase": "RECOVERED", "boot_id": OLD,
                    "private_unit": unit, "policy_sha256": self.old_sha}
        recovery_path = root / ("auto-watchdog-" + "a" * 64 +
                                "-recovered-" + "7" * 16 + ".json")
        recovery_path.write_bytes(transition.canonical(recovery))
        def block(old, received_marker, recovered):
            self.assertEqual(old, intent)
            self.assertEqual(received_marker, marker)
            self.assertEqual(recovered, recovery)
            guardian._crossboot_policy_seals(OLD, self.old_sha,
                                             self.current_sha, self.projection)
        with mock.patch.object(transition, "ROOT", root), \
             mock.patch.object(transition, "STOP", stop), \
             mock.patch.object(transition, "read",
                               side_effect=lambda path, limit=8192: Path(path).read_bytes()), \
             mock.patch.object(transition, "write_new",
                               side_effect=lambda path, raw: Path(path).write_bytes(raw)):
            # The old-boot archive may not claim the new policy merely by
            # changing its digest. Only a watchdog recovery with the exact
            # new recovery_boot_id may seal that current policy.
            recovery_path.write_bytes(encoded({**recovery,
                                               "policy_sha256": self.current_sha}))
            with self.assertRaises(transition.Refused):
                transition.consume_locked(
                    install_fd=0, guard_fd=0, validate_locks=lambda *_: None,
                    current_boot=NEW, marker_path=marker_path,
                    recovered_path=recovery_path, source_sha="c" * 64,
                    boot_uuid=marker["boot_uuid"], policy_sha=self.current_sha,
                    verify_block_and_owner=block)
            self.assertTrue(stop.exists())
            recovery_path.write_bytes(encoded(recovery))
            consumed = transition.consume_locked(
                install_fd=0, guard_fd=0, validate_locks=lambda *_: None,
                current_boot=NEW, marker_path=marker_path,
                recovered_path=recovery_path, source_sha="c" * 64,
                boot_uuid=marker["boot_uuid"], policy_sha=self.current_sha,
                verify_block_and_owner=block)
            self.assertEqual(consumed["schema"],
                             "aegis_auto_terminal_consumed_v2")
            manager = {**self.binding, "boot_id": NEW,
                       "invocation": "e" * 32}
            live = policy_projection(nft_encoded(kernel_rows(STATE,
                                                            manager=manager)))[0]
            saved = json.loads(self.policy_path.read_bytes())
            saved["policy_sha256"] = sha(live)
            self.policy_path.write_bytes(encoded(saved))
            self.state.with_name(self.state.name + ".manager-binding").write_bytes(
                encoded(manager))
            with mock.patch.object(guardian, "read_guard_policy",
                                   return_value={"policy_sha256": sha(live)}):
                def current_block(old, received_marker, recovered):
                    self.assertEqual(old, intent)
                    self.assertEqual(received_marker, marker)
                    self.assertEqual(recovered, recovery)
                    guardian._crossboot_policy_seals(OLD, self.old_sha,
                                                      consumed["policy_sha256"], live)
                self.assertEqual(transition.authenticated_consumed(
                    current_boot=NEW, marker_path=marker_path,
                    recovered_path=recovery_path, source_sha="c" * 64,
                    boot_uuid=marker["boot_uuid"],
                    validate_locks=lambda *_: None,
                    install_fd=0, guard_fd=0,
                    verify_block_and_owner=current_block), consumed)


class ColdSourcePathAndDiagnostic(unittest.TestCase):
    def test_held_site_checks_both_mounts_without_block_open(self):
        """R12 networkd may stat block nodes but cannot run blkid there."""
        source_bytes = b"installed transition fixture"
        helper_path = Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_boot_store.py')
        helper_bytes = b'''def check_config(value): pass
def mounts():
 return [{'target':'/','fstype':'ext4','source':'/dev/vda1','dev':'254:1'},
         {'target':'/boot','fstype':'ext4','source':'/dev/vda16','dev':'254:16'}]
def one_mount(rows,target):
 found=[r for r in rows if r['target']==target]
 assert len(found)==1
 return found[0]
def dev_number(path): return {'/dev/vda1':'254:1','/dev/vda16':'254:16'}[path]
def blkid_uuid(path): raise PermissionError('cgroup blocks blkid')
'''
        source = {'schema':'aegis_auto_terminal_source_v1',
                  'transition_sha256':sha(source_bytes),
                  'boot_helper_sha256':sha(helper_bytes),'hook_sha256':'a'*64}
        store = {'schema':'aegis_auto_terminal_boot_store_v1',
                 'helper_sha256':sha(helper_bytes),'hook_sha256':'a'*64,
                 'root_source':'/dev/vda1','boot_source':'/dev/vda16',
                 'root_dev':'254:1','boot_dev':'254:16',
                 'root_uuid':'11111111-1111-1111-1111-111111111111',
                 'boot_uuid':'22222222-2222-2222-2222-222222222222'}
        def read_config(path, *_args):
            return encoded(source if path == transition.SOURCE_CONFIG else store)
        def source_blob(path, *_args):
            return helper_bytes if path == helper_path else source_bytes
        with (mock.patch.object(transition,'read',side_effect=read_config),
              mock.patch.object(transition,'_source_bytes',side_effect=source_blob)):
            self.assertEqual(transition._source_facts(postconsumed_site=True),
                             (source,store))
            with self.assertRaises(PermissionError):
                transition._source_facts()
            with self.assertRaises(transition.Refused):
                transition._source_facts(postconsumed_site='true')
            store['boot_dev']='254:17'
            with self.assertRaises(transition.Refused):
                transition._source_facts(postconsumed_site=True)

    def test_held_guard_selects_mount_only_only_for_current_boot_history(self):
        boot='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/'source.json';store=root/'store.json';pending=root/'pending'
            source.write_bytes(b'{}\n');store.write_bytes(b'{}\n')
            seen=[]
            def select_site(**kwargs):
                seen.append(kwargs['postconsumed_site'])
                raise RuntimeError('site selected before any effects')
            def read_config(path,*_args):
                return source.read_bytes() if path==source else store.read_bytes()
            original_read_text=Path.read_text
            def boot_text(path,*args,**kwargs):
                if str(path)=='/proc/sys/kernel/random/boot_id':return boot+'\n'
                return original_read_text(path,*args,**kwargs)
            with (mock.patch.object(transition,'SOURCE_CONFIG',source),
                  mock.patch.object(transition,'STORE_CONFIG',store),
                  mock.patch.object(transition,'MIGRATION_PENDING',pending),
                  mock.patch.object(transition,'COLD_READY',root/'ready.json'),
                  mock.patch.object(transition.os,'geteuid',return_value=0),
                  mock.patch.object(transition.sys,'platform','linux'),
                  mock.patch.object(transition,'read',side_effect=read_config),
                  mock.patch.object(transition,'_source_facts',side_effect=select_site),
                  mock.patch.object(Path,'read_text',autospec=True,side_effect=boot_text)):
                for receipt,rollover,ready,expected in (
                    (None,None,False,False),
                    ({'schema':'aegis_auto_terminal_consumed_v2'},None,False,True),
                    (None,('phase','head'),False,True),
                    (None,None,True,True)):
                    if ready:(root/'ready.json').write_bytes(b'candidate\n')
                    elif (root/'ready.json').exists():(root/'ready.json').unlink()
                    with (mock.patch.object(transition,'read_consumed_record',return_value=receipt),
                          mock.patch.object(transition,'_cold_rollover_hint',return_value=rollover)):
                        with self.assertRaisesRegex(RuntimeError,'site selected'):
                            transition.verify_consumed_under_guard(4)
                    self.assertIs(seen.pop(),expected)

    def test_exact_real_manager_and_guardian_dropin_paths(self):
        for unit in ("NetworkManager.service", "systemd-networkd.service",
                     "aegis-auto-guardian.service"):
            self.assertEqual(transition.transition_dropin_path(unit),
                             Path("/etc/systemd/system") / (unit + ".d") /
                             "31-aegis-auto-terminal-transition.conf")
        with self.assertRaises(transition.Refused):
            transition.transition_dropin_path("foreign.service")

    def test_refusal_diagnostic_does_not_echo_private_values(self):
        for secret in ("private invitation: secret-value", "secretabc"):
            message = transition._refusal_diagnostic(transition.Refused(secret))
            self.assertIn("reason=unclassified", message)
            self.assertNotIn(secret, message)
        try:
            transition.transition_dropin_path("foreign.service")
        except transition.Refused as error:
            message = transition._refusal_diagnostic(error)
        else:
            self.fail("foreign transition unit admitted")
        self.assertIn("origin=aegis_auto_boot_transition.py:", message)
        self.assertNotIn("foreign.service", message)


if __name__ == "__main__":
    unittest.main()
