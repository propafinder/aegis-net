"""A capture-interface name is never authority for an unbound guard."""
import contextlib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import aegis_auto_foreign_policy as policy
import aegis_auto_guardian as guardian
import auto_guard_render_harness as harness


class CaptureInterfaceAdmission(unittest.TestCase):
    def render(self, client=None, tun_ifindex=None):
        rc, text, error = harness.render(profile="full-wide-tun", uplink="up0",
            management_ports="", client=client, scoped=None,
            tun_ifindex=tun_ifindex)
        self.assertEqual(rc, 0, error)
        return text

    def test_unbound_guard_has_no_capture_name_permission(self):
        text = self.render()
        self.assertNotIn('oifname "aegis-tun0"', text)

    def test_bound_client_has_no_name_only_capture_permission(self):
        client = {"boot_id": "11111111-2222-3333-4444-555555555555",
                  "state_sha256": "1" * 64, "path": "system.slice/aegis-client.service",
                  "inode": "12", "invocation": "2" * 32}
        self.assertNotIn('output oifname "aegis-tun0" counter accept', self.render(client))
        self.assertNotIn('output meta oif ', self.render(client))
        late = self.render(client, tun_ifindex=9)
        self.assertIn('output meta oif 9 meta oifkind "tun" counter accept', late)
        self.assertIn('postroute meta oif 9 meta oifkind "tun" counter accept', late)
        self.assertNotIn('output oifname "aegis-tun0" counter accept', late)
        stopped = self.render(tun_ifindex=9)
        self.assertNotIn('meta oif 9 counter accept', stopped)

    def check(self, kind, owned=False):
        links = [{"ifname": "lo"}, {"ifname": "up0"},
                 {"ifname": "aegis-tun0", "ifindex": 9,
                  "linkinfo": {"info_kind": kind,
                               "info_data": {"type": "tun", "persist": False}}}]
        def read(*args):
            return json.dumps(links).encode() if args == policy.LINK_INVENTORY else b"[]"
        with mock.patch.object(policy, "run", side_effect=read), \
             mock.patch.object(policy, "prefetch", return_value=contextlib.nullcontext()), \
             mock.patch.object(policy, "bpf_bindings"), \
             mock.patch.object(policy, "capture_tun_owner", return_value=owned, create=True), \
             mock.patch.object(Path, "read_text", return_value="0\n"):
            return policy.check_links("up0")

    def test_foreign_link_types_cannot_borrow_capture_name(self):
        for kind in ("macvlan", "veth", "dummy"):
            with self.subTest(kind=kind), self.assertRaisesRegex(
                    policy.ForeignPolicyRefused, "capture interface type"):
                self.check(kind)

    def test_tun_without_product_owner_is_refused(self):
        with self.assertRaisesRegex(policy.ForeignPolicyRefused, "capture interface owner"):
            self.check("tun")

    def test_product_owned_tun_keeps_other_link_checks(self):
        self.assertEqual(self.check("tun", owned=True), ["lo", "up0", "aegis-tun0"])

    def owner_fixture(self, *, cgroup="0::/system.slice/aegis-client.service\n",
                      iff="aegis-tun0", foreign_executable=False, installed=False,
                      private_main=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "aegis-client"
            binary.write_bytes(b"synthetic executable identity")
            binary.chmod(0o555)
            other = root / "other"
            other.write_bytes(b"foreign")
            proc = root / "proc"
            process = proc / "200"
            (process / "fd").mkdir(parents=True)
            (process / "fdinfo").mkdir()
            (process / "ns").mkdir()
            (proc / "self/ns").mkdir(parents=True)
            namespace = proc / "self/ns/net"
            namespace.write_bytes(b"synthetic netns inode")
            boot_file = root / "boot_id"
            boot_file.write_text("11111111-2222-3333-4444-555555555555\n")
            (process / "exe").symlink_to(other if foreign_executable else binary)
            (process / "ns/net").symlink_to(namespace)
            (process / "cgroup").write_text(cgroup)
            (process / "stat").write_text("200 (aegis-client) " + " ".join(["S"] + ["0"] * 18 + ["42"]))
            (process / "fd/9").symlink_to("/dev/net/tun")
            (process / "fdinfo/9").write_text("iff:\t" + iff + "\n")
            real_stat = os.stat
            def metadata(path, *args, **kwargs):
                value = real_stat(path, *args, **kwargs)
                if str(path) == str(binary):
                    return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_nlink=1,
                                           st_dev=value.st_dev, st_ino=value.st_ino)
                return value
            def paths(value):
                return {"/usr/local/bin/aegis-client": binary,
                        "/proc": proc, "/proc/self/ns/net": namespace,
                        "/proc/sys/kernel/random/boot_id": boot_file}.get(value, Path(value))
            with contextlib.ExitStack() as stack:
                if installed or private_main:
                    def installation_only(path, _limit):
                        if str(path).endswith('main-binding'):
                            if not private_main:
                                raise FileNotFoundError(path)
                            return json.dumps({
                                'schema': 'aegis_device_guard_main_binding_v1',
                                'boot_id': boot_file.read_text().strip(),
                                'netns_ino': namespace.stat().st_ino,
                                'private_unit': 'aegis-auto@' + 'a' * 64 + '.service',
                                'worker_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                                'stage_dev': 1, 'stage_ino': 2}).encode()
                        return json.dumps({
                            'schema':'aegis_auto_guardian_install_v1',
                            'worker_sha256':('f' * 64 if private_main else
                                             hashlib.sha256(binary.read_bytes()).hexdigest())}).encode()
                    stack.enter_context(mock.patch.object(policy, 'trusted_read', side_effect=installation_only))
                    stack.enter_context(mock.patch.object(policy, '_capture_executable_sha',
                        side_effect=lambda path, _metadata: hashlib.sha256(path.read_bytes()).hexdigest()))
                if private_main:
                    stack.enter_context(mock.patch.object(policy.subprocess, 'run', return_value=
                        subprocess.CompletedProcess([], 0, b'MainPID=200\n', b'')))
                stack.enter_context(mock.patch.object(policy, "Path", side_effect=paths))
                stack.enter_context(mock.patch.object(policy.os, "stat", side_effect=metadata))
                stack.enter_context(mock.patch.object(policy.socket, "if_nametoindex", return_value=9))
                return policy.capture_tun_owner({"ifindex": 9})

    def test_owner_requires_executable_unit_namespace_and_exact_fd(self):
        self.assertTrue(self.owner_fixture())
        self.assertFalse(self.owner_fixture(foreign_executable=True))
        self.assertFalse(self.owner_fixture(cgroup="0::/user.slice/foreign.service\n"))
        self.assertFalse(self.owner_fixture(iff="foreign-tun"))

    def test_install_receipt_binds_custom_worker_digest(self):
        self.assertTrue(self.owner_fixture(installed=True))
        self.assertFalse(self.owner_fixture(installed=True, foreign_executable=True))

    def test_private_main_uses_stage_pinned_digest_before_late_grant(self):
        private = "0::/system.slice/aegis-auto@" + "a" * 64 + ".service\n"
        self.assertTrue(self.owner_fixture(cgroup=private, private_main=True))
        self.assertFalse(self.owner_fixture(cgroup=private, private_main=True,
                                            foreign_executable=True))

    def test_late_binding_requires_live_main_fd_type_and_same_ifindex(self):
        unit = 'aegis-auto@' + 'a' * 64 + '.service'
        boot = '11111111-2222-3333-4444-555555555555'
        capture_binding = {
            'schema': 'aegis_device_guard_capture_binding_v1',
            'boot_id': boot, 'netns_ino': 99, 'private_unit': unit,
            'invocation_id': 'b' * 32, 'main_pid': 200, 'ifindex': 9,
            'worker_sha256': 'c' * 64,
            'client_path': 'system.slice/' + unit,
            'client_inode': '1234', 'client_invocation': 'b' * 32}
        client = {'boot_id': boot, 'path': 'system.slice/' + unit,
                  'inode': '1234', 'invocation': 'b' * 32}
        facts = {'ActiveState': 'active', 'SubState': 'running',
                 'MainPID': '200', 'InvocationID': 'b' * 32,
                 'ControlPID': '0'}
        fake_capture = SimpleNamespace(
            IP='/usr/sbin/ip', _service=lambda _unit: facts,
            _pidfd_identity=lambda _fd, _pid: None,
            _pid_live=lambda _pid, _sha, _group: None,
            _tun_owned_by_pid=lambda _pid: None,
            _cgroup=lambda _unit: '/system.slice/' + unit,
            _link=lambda: (9, 'UP'),
            _json=lambda _args: [{'ifindex': 9, 'linkinfo': {
                'info_kind': 'tun', 'info_data': {'type': 'tun',
                                                 'persist': False}}}])
        real_stat = Path.stat
        def stat_path(path, *args, **kwargs):
            if str(path) == '/proc/200/ns/net':
                return SimpleNamespace(st_ino=99)
            return real_stat(path, *args, **kwargs)
        def read(path, _limit=0):
            return capture_binding if path == guardian.CAPTURE_BINDING else client
        with mock.patch.object(guardian, 'own_source'), \
             mock.patch.object(guardian, '_held_lock'), \
             mock.patch.object(guardian, 'record', side_effect=read), \
             mock.patch.object(guardian, 'host_anchor', return_value={
                 'boot_id': boot, 'netns_ino': 99}), \
             mock.patch.object(guardian, 'verified_module', return_value=fake_capture), \
             mock.patch.object(guardian.os, 'pidfd_open', return_value=15, create=True), \
             mock.patch.object(guardian.os, 'close'), \
             mock.patch.object(guardian.select, 'select', return_value=([], [], [])), \
             mock.patch.object(guardian.socket, 'if_nametoindex', return_value=9), \
             mock.patch.object(Path, 'stat', stat_path):
            self.assertEqual(guardian.capture_binding_index(9), 9)
            fake_capture._json = lambda _args: [{'ifindex': 9, 'linkinfo': {
                'info_kind': 'dummy'}}]
            with self.assertRaisesRegex(guardian.Refused,
                                        'capture_binding_interface_type_changed'):
                guardian.capture_binding_index(9)

    @unittest.skipUnless(os.geteuid() == 0, 'real trusted-file digest requires Linux root fixture')
    def test_worker_digest_observes_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'worker'
            path.write_bytes(b'first worker')
            path.chmod(0o555)
            first = policy._capture_executable_sha(path, path.stat())
            self.assertEqual(first, hashlib.sha256(b'first worker').hexdigest())
            self.assertEqual(policy._capture_executable_sha(path, path.stat()), first)
            path.chmod(0o755)
            path.write_bytes(b'other worker')
            path.chmod(0o555)
            self.assertEqual(policy._capture_executable_sha(path, path.stat()),
                             hashlib.sha256(b'other worker').hexdigest())


if __name__ == "__main__":
    unittest.main()
