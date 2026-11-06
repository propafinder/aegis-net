"""Read-only finalized guardian inspection decisions; no native authority claim."""
import hashlib
import json
import os
import stat
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import aegis_auto_guardian as guardian
import aegis_auto_guard_policy as guard_policy
import aegis_auto_guardian_watchdog as watchdog_policy

BOOT = "11111111-2222-3333-4444-555555555555"
UNIT = "aegis-auto@" + "a" * 64 + ".service"
MANAGER = {"schema": "aegis_device_guard_binding_v1",
           "boot_id": BOOT, "state_sha256": "", "path":
           "system.slice/systemd-networkd.service", "inode": "12345",
           "invocation": "b" * 32}
STATE = (b"schema=aegis_device_guard_v2\narmed=1\n"
         b"service=aegis-client.service\nuplink=eth0\n"
         b"manager=systemd-networkd.service\n"
         b"capture_interface=aegis-tun0\n"
         b"management_address_policy=current_local\nmanagement_ports=22\n"
         b"dhcp4=1\ndhcp6=1\ninitramfs_network=absent_verified\n")


class FinalizedInspection(unittest.TestCase):
    def setUp(self):
        self.server = guardian.Guardian()
        self.server.main_digests[UNIT] = "a" * 64
        self.request = {"schema": "aegis_auto_guardian_live_inspection_v1",
                        "command": "INSPECT_LIVE",
                        "guardian_invocation_id": "c" * 32,
                        "private_unit": UNIT, "main_pid": 123,
                        "invocation_id": "d" * 32,
                        "boot_id": BOOT, "native_guard": None}
        self.peer = mock.Mock()
        self.facts = {"InvocationID": "d" * 32,
                      "ActiveState": "active", "SubState": "running"}
        self.patches = [
            mock.patch.object(guardian, "own_source"),
            mock.patch.object(guardian, "_peer_executable"),
            mock.patch.object(guardian, "_pid_alive", return_value=True),
            mock.patch.object(guardian, "_unit_identity",
                              return_value={"InvocationID": "c" * 32}),
            mock.patch.object(guardian, "_launch_unit_identity",
                              return_value=self.facts),
            mock.patch.object(guardian, "executable_digest",
                              return_value="a" * 64),
            mock.patch.object(guardian, "host_anchor",
                              return_value={"boot_id": BOOT}),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def inspect(self):
        self.server._inspect_live(self.peer, 456, 9, self.request, (),
                                  {"worker_sha256": "a" * 64})
        return json.loads(self.peer.sendall.call_args.args[0])

    def test_postfinalized_passive_main_has_no_guard_prerequisite(self):
        result = self.inspect()
        self.assertIsNone(result["manager_binding_sha256"])
        self.assertIsNone(result["policy_sha256"])
        with mock.patch.object(guardian, "_launch_unit_identity",
                               return_value=dict(self.facts, InvocationID="e" * 32)):
            with self.assertRaises(guardian.Refused):
                self.inspect()
        self.server.watchdogs[UNIT] = object()
        with self.assertRaises(guardian.Refused):
            self.inspect()

    def test_watchdog_read_only_active_request_requires_exact_journal(self):
        client = watchdog_policy.WatchdogClient()
        client.authority = mock.Mock()
        client.private_unit = UNIT
        reply = {"state": "INSPECTED_ACTIVE", "private_unit": UNIT,
                 "invocation_id": "d" * 32, "private_main_pid": 123,
                 "guardian_pid": 456, "native_guard": {},
                 "terminal_sha256": "1" * 64,
                 "policy_sha256": "2" * 64,
                 "journal_sha256": "3" * 64}
        with mock.patch.object(client, "_live"), \
             mock.patch.object(watchdog_policy, "_send") as send, \
             mock.patch.object(watchdog_policy, "_recv", return_value=reply), \
             mock.patch.object(watchdog_policy, "_read_root", return_value=b"journal"), \
             mock.patch.object(watchdog_policy, "_sha", return_value="3" * 64):
            deadline = time.monotonic() + 2.0
            self.assertEqual(client.inspect_active(deadline=deadline), reply)
            send.assert_called_once_with(client.authority,
                                         {"op": "INSPECT_ACTIVE",
                                          "deadline_ns":
                                          int(deadline * 1_000_000_000)})
            with mock.patch.object(watchdog_policy, "_sha",
                                   return_value="f" * 64):
                with self.assertRaises(watchdog_policy.Refused):
                    client.inspect_active(deadline=deadline)
            with self.assertRaises(watchdog_policy.Refused):
                client.inspect_active(deadline=time.monotonic() - 1.0)

    def test_postfinalized_guard_uses_watchdog_terminal_and_live_policy(self):
        native = {"guardian_nonce": "1" * 64,
                  "guardian_receipt_sha256": "2" * 64,
                  "policy_sha256": "3" * 64}
        self.request["native_guard"] = native
        current_policy = "4" * 64
        observed = {"guardian_pid": os.getpid(), "private_unit": UNIT,
                    "invocation_id": "d" * 32, "private_main_pid": 123,
                    "native_guard": {"guardian_pid": os.getpid(), **native},
                    "policy_sha256": current_policy}
        watchdog = mock.Mock()
        watchdog.inspect_active.return_value = observed
        self.server.watchdogs[UNIT] = watchdog
        state_sha = hashlib.sha256(STATE).hexdigest()
        manager = dict(MANAGER,
                       state_sha256=hashlib.sha256(STATE.rstrip(b"\n")).hexdigest())
        manager_raw = json.dumps(manager, sort_keys=True).encode()
        projection = b"authenticated-projection"
        saved = {"state_sha256": state_sha,
                 "policy_sha256": hashlib.sha256(projection).hexdigest()}
        observed["policy_sha256"] = saved["policy_sha256"]
        def protected(path, *_args):
            return manager_raw if str(path).endswith("manager-binding") else STATE
        with mock.patch.object(guardian, "_semantic_policy_readback",
                               return_value=(STATE, projection)), \
             mock.patch.object(guardian, "record", return_value=saved), \
             mock.patch.object(guardian, "regular", side_effect=protected), \
             mock.patch.object(guardian, "verified_module",
                               return_value=guard_policy), \
             mock.patch.object(guardian.Path, "stat",
                               return_value=mock.Mock(st_mode=stat.S_IFDIR | 0o755,
                                                      st_ino=12345)), \
             mock.patch.object(guardian.Path, "is_symlink", return_value=False):
            reply = self.inspect()
            self.assertEqual(reply["manager_binding_sha256"],
                             hashlib.sha256(manager_raw).hexdigest())
            self.assertEqual(reply["policy_sha256"], saved["policy_sha256"])
            watchdog.inspect_active.return_value = dict(
                observed, native_guard=dict(observed["native_guard"],
                                            guardian_nonce="f" * 64))
            with self.assertRaises(guardian.Refused):
                self.inspect()
            watchdog.inspect_active.return_value = dict(
                observed, policy_sha256="f" * 64)
            with self.assertRaises(guardian.Refused):
                self.inspect()
            self.server.watchdogs.clear()
            with self.assertRaises(guardian.Refused):
                self.inspect()

    def test_deny_readback_binds_live_manager_before_and_after(self):
        from aegis_auto_native_witness import policy_projection
        from test_auto_guard_policy import encoded, kernel_rows
        state_sha = hashlib.sha256(STATE).hexdigest()
        manager = dict(MANAGER, schema="aegis_device_guard_binding_v2",
                       ifindex=3, dhcp4_server=None, dhcp6_server=None,
                       state_sha256=hashlib.sha256(
                           STATE.rstrip(b"\n")).hexdigest())
        projection = policy_projection(encoded(kernel_rows(state=STATE, manager=manager)))[0]
        raw = json.dumps(manager, sort_keys=True).encode()
        saved = {"schema": "aegis_auto_guardian_policy_v1",
                 "boot_id": BOOT, "netns_ino": 9,
                 "guard_dev": 17, "guard_ino": 23,
                 "state_sha256": state_sha,
                 "policy_sha256": hashlib.sha256(projection).hexdigest()}
        def protected(path, *_args):
            return raw if str(path).endswith("manager-binding") else STATE
        live = (123, {"MainPID": "123", "ControlGroup": "/" + manager["path"],
                      "InvocationID": manager["invocation"],
                      "ActiveState": "active", "SubState": "running"})
        guard_file = mock.Mock(st_mode=stat.S_IFREG | 0o600, st_uid=0,
                               st_nlink=1, st_dev=17, st_ino=23)
        with mock.patch.object(guardian, "record", side_effect=lambda path:
                               {"guard_unit_sha256": "1" * 64,
                                "installation_anchor": "installed"}
                               if path == guardian.INSTALL else saved), \
             mock.patch.object(guardian, "installation_anchor",
                               return_value="installed"), \
             mock.patch.object(guardian, "host_anchor",
                               return_value={"boot_id": BOOT, "netns_ino": 9}), \
             mock.patch.object(guardian, "_semantic_policy_readback",
                               return_value=(STATE, projection)), \
             mock.patch.object(guardian, "regular", side_effect=protected), \
             mock.patch.object(guardian, "verified_module",
                               return_value=guard_policy), \
             mock.patch.object(guardian.Path, "stat", return_value=guard_file), \
             mock.patch.object(guardian.Path, "is_symlink", return_value=False), \
             mock.patch.object(guardian.Path, "exists",
                               new=lambda path: str(path).endswith(".manager-binding")), \
             mock.patch.object(guardian, "_manager_live_facts",
                               return_value=live) as live_facts, \
             mock.patch.object(guardian.socket, "if_nametoindex",
                               return_value=3), \
             mock.patch.object(guardian.os, "pidfd_open", return_value=77,
                               create=True), \
             mock.patch.object(guardian.os, "close"):
            receipt = guardian.read_guard_policy()
            self.assertEqual(receipt["manager_binding_sha256"],
                             hashlib.sha256(raw).hexdigest())
            self.assertEqual(live_facts.call_count, 2)
            with mock.patch.object(guardian.socket, "if_nametoindex",
                                   return_value=4), self.assertRaises(guardian.Refused):
                guardian.read_guard_policy()
            live_facts.side_effect = [live, (124, dict(live[1], MainPID="124"))]
            with self.assertRaises(guardian.Refused):
                guardian.read_guard_policy()

    def test_manager_pid1_and_cgroup_owner_is_exact(self):
        manager = dict(MANAGER)
        output = ("MainPID=123\nControlGroup=/" + manager["path"] +
                  "\nInvocationID=" + manager["invocation"] +
                  "\nActiveState=active\nSubState=running\n").encode()
        result = SimpleNamespace(returncode=0, stdout=output, stderr=b"")
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_ino=12345)
        with mock.patch.object(guardian.subprocess, "run",
                               return_value=result), \
             mock.patch.object(guardian.Path, "read_text",
                               return_value="0::/" + manager["path"] + "\n"), \
             mock.patch.object(guardian.Path, "stat", return_value=info):
            self.assertEqual(guardian._manager_live_facts(
                manager, time.monotonic() + 2.0)[0], 123)
            result.stdout = output.replace(
                manager["invocation"].encode(), b"e" * 32)
            with self.assertRaises(guardian.Refused):
                guardian._manager_live_facts(manager, time.monotonic() + 2.0)


if __name__ == "__main__":
    unittest.main()
