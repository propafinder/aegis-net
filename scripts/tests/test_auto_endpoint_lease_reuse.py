"""The minted QA endpoint lease is reused; its revalidation keeps every check.

Not native acceptance evidence. The root-owner predicate is exercised with a
patched fstat because these fixtures run unprivileged.
"""
import contextlib
import hashlib
import importlib.util
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "lib/aegis_auto_capture.py"
SPEC = importlib.util.spec_from_file_location("aegis_auto_capture", SOURCE)
capture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = capture
SPEC.loader.exec_module(capture)
ENDPOINT_SPEC = importlib.util.spec_from_file_location(
    "aegis_auto_endpoint", SOURCE.with_name("aegis_auto_endpoint.py"))
endpoint = importlib.util.module_from_spec(ENDPOINT_SPEC)
sys.modules[ENDPOINT_SPEC.name] = endpoint
ENDPOINT_SPEC.loader.exec_module(endpoint)


class HeldFileRevalidation(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.directory.name) / "pinned"
        self.path.write_bytes(b"pinned-bytes")
        self.path.chmod(0o600)
        self.real_fstat = os.fstat
        self.uid = 0

    def tearDown(self):
        self.directory.cleanup()

    def fstat(self, fd):
        value = self.real_fstat(fd)
        view = SimpleNamespace(**{name: getattr(value, name) for name in dir(value)
                                  if name.startswith("st_")})
        view.st_uid = self.uid
        return view

    @contextlib.contextmanager
    def root_view(self, ancestors=None):
        with patch.object(capture, "_trusted_ancestors",
                          side_effect=ancestors) as walked, \
             patch.object(capture.os, "fstat", side_effect=self.fstat):
            yield walked

    def held(self, maximum=4096):
        with self.root_view():
            return capture._held_file(self.path, maximum, 0o600,
                                      hashlib.sha256(b"pinned-bytes").hexdigest())

    def refused(self, held, reason, **kw):
        with self.root_view(**kw):
            with self.assertRaisesRegex(capture.CaptureRefused, reason):
                held.revalidate()

    def test_unchanged_file_revalidates_and_walks_ancestors(self):
        held = self.held()
        try:
            self.assertEqual((held.mode, held.maximum), (0o600, 4096))
            with self.root_view() as walked:
                held.revalidate()
            walked.assert_called_once_with(self.path)
        finally:
            held.close()

    def test_mode_owner_link_size_and_ancestor_changes_refuse(self):
        held = self.held()
        try:
            self.path.chmod(0o640)
            self.refused(held, "endpoint_file_untrusted")
            self.path.chmod(0o600)
            self.uid = 1000
            self.refused(held, "endpoint_file_untrusted")
            self.uid = 0
            extra = self.path.with_name("second-link")
            os.link(self.path, extra)
            self.refused(held, "endpoint_file_untrusted")
            extra.unlink()
            with self.root_view():
                held.revalidate()
            self.refused(held, "ancestor", ancestors=capture.CaptureRefused(
                "endpoint_path_ancestor_untrusted"))
        finally:
            held.close()
        small = self.held(maximum=len(b"pinned-bytes"))
        try:
            small.maximum = 4
            self.refused(small, "endpoint_file_untrusted")
        finally:
            small.close()

    def test_same_size_rewrite_with_restored_mtime_refuses_content(self):
        held = self.held()
        try:
            before = self.path.stat()
            with open(self.path, "r+b") as stream:
                stream.write(b"PINNED")
            os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.refused(held, "endpoint_pinned_file_content_changed")
        finally:
            held.close()


class MintedLeaseReuse(unittest.TestCase):
    def mint(self, admitted, verify_failures=()):
        effect = Mock()
        effect.facts = {"mode": "FULL_TUN_UDP", "children": [{}]}
        calls = iter([None, *verify_failures])
        def verify():
            failure = next(calls, None)
            if failure is not None:
                raise failure
        effect.verify.side_effect = verify
        install = {"unit": "aegis-qa-relay.service", "auth_profile": "legacy_shared_token",
                   "server_binary_path": "/b", "server_binary_sha256": "1" * 64,
                   "config_path": "/c", "config_sha256": "2" * 64, "cert_path": "/d",
                   "cert_sha256": "3" * 64, "key_path": "/e", "key_sha256": "4" * 64,
                   "outer_ca_path": "/f", "outer_ca_sha256": "5" * 64,
                   "auth_token_sha256": "6" * 64, "listen_ipv4": "10.0.0.1",
                   "listen_port": 443}
        boot = SimpleNamespace(read_text=lambda **_kw: "boot\n")
        with patch.object(endpoint, "Path", side_effect=lambda _value: boot), \
             patch.object(endpoint.os, "stat", return_value=SimpleNamespace(st_ino=12)), \
             patch.object(endpoint, "_relay_install", return_value=install), \
             patch.object(endpoint, "_server_pid", return_value=(77, "/system.slice/r.service")), \
             patch.object(endpoint, "_actor", return_value={}), \
             patch.object(endpoint, "_publish"), \
             patch.object(endpoint, "retire_endpoint_receipt") as retire, \
             patch.object(capture, "admit_endpoint_receipt", side_effect=admitted) as admit:
            try:
                return endpoint.mint_endpoint_receipt(
                    effect_lease=effect, unit="aegis-auto@" + "a" * 64 + ".service",
                    mode="full-wide-tun", boot_id="boot", netns_ino=12,
                    installed_generation="7" * 64, manifest="8" * 64), retire, admit
            finally:
                self.retire, self.admit = retire, admit

    def test_mint_returns_its_open_admitted_lease_once(self):
        lease = Mock()
        result, retire, admit = self.mint(lambda **_kw: lease)
        self.assertIs(result, lease)
        admit.assert_called_once()
        lease.close.assert_not_called()
        retire.assert_not_called()
        self.assertFalse(hasattr(endpoint, "admit_endpoint"))

    def test_failed_verify_after_admission_closes_and_retires(self):
        lease = Mock()
        with self.assertRaisesRegex(capture.CaptureRefused, "changed"):
            self.mint(lambda **_kw: lease, [capture.CaptureRefused("changed")])
        lease.close.assert_called_once_with()
        self.retire.assert_called_once_with()

    def test_failed_admission_retires(self):
        with self.assertRaisesRegex(capture.CaptureRefused, "refused"):
            self.mint(Mock(side_effect=capture.CaptureRefused("refused")))
        self.retire.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
