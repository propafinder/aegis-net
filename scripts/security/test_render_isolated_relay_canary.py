import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from render_isolated_relay_canary import cleanup, render


PRIMARY = "ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1"
CANARY = "f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca"


def sha(data):
    return hashlib.sha256(data).hexdigest()


class IsolatedRenderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-isolated-render-", dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.candidate = self.root / "candidate.toml"
        self.candidate.write_text(
            'listen = "127.0.0.1:18443"\ncert = "fixture-cert.pem"\n'
            'key = "fixture-key.pem"\n'
            f'auth_token = "{PRIMARY}"\n\n[[legacy_auth_tokens]]\n'
            f'id = "canary-fixture"\nauth_token = "{CANARY}"\n'
            f'not_after_unix_secs = {int(time.time()) + 600}\n')
        self.candidate.chmod(0o600)
        self.cert = self.root / "synthetic-cert.pem"
        self.cert.write_text("-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n")
        self.cert.chmod(0o600)
        self.key = self.root / "synthetic-key.pem"
        self.key.write_text("-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n")
        self.key.chmod(0o600)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.out = self.root / "rendered-r1"

    def call(self, **kwargs):
        values = dict(candidate=self.candidate, cert=self.cert, key=self.key,
                      out_dir=self.out, port=self.port,
                      expected_sha256=sha(self.candidate.read_bytes()))
        values.update(kwargs)
        return render(**values)

    def test_render_private_and_exact_never_launched_cleanup(self):
        source = self.candidate.read_bytes()
        receipt = self.call()
        self.assertTrue(receipt["rendered"])
        self.assertEqual(self.candidate.read_bytes(), source)
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o700)
        for name in ("config.toml", "cert.pem", "key.pem", "manifest.json"):
            self.assertEqual(stat.S_IMODE((self.out/name).stat().st_mode), 0o600)
        body = (self.out/"config.toml").read_text()
        self.assertIn(f'127.0.0.1:{self.port}', body)
        self.assertNotIn("0.0.0.0:443", body)
        self.assertNotIn(CANARY, (self.out/"manifest.json").read_text())
        manifest_sha = sha((self.out/"manifest.json").read_bytes())
        if sys.platform.startswith("linux") and os.geteuid() != 0:
            # A regular Linux user cannot establish all /proc/*/fd references.
            # Exercise the fail-closed cleanup path; the root CLI test below
            # covers successful native cleanup.
            before = {path.name: sha(path.read_bytes()) for path in self.out.iterdir()}
            original_listdir = os.listdir

            def deny_proc_fds(path):
                if str(path).startswith("/proc/") and str(path).endswith("/fd"):
                    raise PermissionError("inaccessible process descriptors")
                return original_listdir(path)

            with mock.patch("render_isolated_relay_canary.os.listdir", side_effect=deny_proc_fds):
                with self.assertRaisesRegex(ValueError, "process references cannot be established"):
                    cleanup(self.out, manifest_sha, True)
            self.assertTrue(self.out.exists())
            self.assertEqual({path.name: sha(path.read_bytes()) for path in self.out.iterdir()}, before)
            return
        self.assertEqual(cleanup(self.out, manifest_sha, True),
                         {"cleaned": True, "manifest_sha256": manifest_sha})
        self.assertFalse(self.out.exists())

    def test_occupied_port_and_443_refuse_before_output(self):
        with socket.socket() as held:
            held.bind(("127.0.0.1", self.port))
            held.listen(1)
            with self.assertRaises(OSError):
                self.call()
        self.assertFalse(self.out.exists())
        with self.assertRaisesRegex(ValueError, "port"):
            self.call(port=443)
        self.assertFalse(self.out.exists())

    def test_wrong_digest_and_symlink_refuse(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.call(expected_sha256="0"*64)
        link = self.root/"linked.toml"
        link.symlink_to(self.candidate)
        with self.assertRaises(OSError):
            self.call(candidate=link)
        self.assertFalse(self.out.exists())

    def test_extra_source_fields_refuse_live_shape(self):
        with self.candidate.open("a") as f:
            f.write("\n[bundle_endpoint]\nenabled = true\n")
        with self.assertRaisesRegex(ValueError, "minimal synthetic"):
            self.call()
        self.assertFalse(self.out.exists())

    def test_insecure_certificate_refuses(self):
        self.cert.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "mode-0600"):
            self.call()
        self.assertFalse(self.out.exists())

    def test_linux_untrusted_ancestor_owner_refuses(self):
        if not sys.platform.startswith("linux") or os.geteuid() != 0:
            self.skipTest("root Linux chown required")
        ancestor = self.root / "untrusted"
        ancestor.mkdir(mode=0o755)
        private = ancestor / "private"
        private.mkdir(mode=0o700)
        nested = private / "candidate.toml"
        nested.write_bytes(self.candidate.read_bytes())
        nested.chmod(0o600)
        os.chown(ancestor, 65534, 65534)
        with self.assertRaisesRegex(ValueError, "ancestor owner"):
            self.call(candidate=nested)
        self.assertFalse(self.out.exists())

    def test_linux_acl_on_mode_0600_certificate_refuses(self):
        if not sys.platform.startswith("linux") or os.geteuid() != 0:
            self.skipTest("root Linux POSIX ACL required")
        acl = struct.pack("<I", 2)
        for tag, perm, ident in ((1, 6, 0xffffffff), (2, 0, 65534),
                                 (4, 0, 0xffffffff), (16, 0, 0xffffffff),
                                 (32, 0, 0xffffffff)):
            acl += struct.pack("<HHI", tag, perm, ident)
        os.setxattr(self.cert, "system.posix_acl_access", acl)
        self.assertEqual(stat.S_IMODE(self.cert.stat().st_mode), 0o600)
        with self.assertRaisesRegex(ValueError, "extended ACL"):
            self.call()
        self.assertFalse(self.out.exists())

    def test_existing_output_refuses(self):
        self.out.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            self.call()

    def test_cleanup_refuses_tamper_and_open_listener(self):
        self.call()
        manifest_sha = sha((self.out/"manifest.json").read_bytes())
        with self.assertRaisesRegex(ValueError, "never-launched"):
            cleanup(self.out, manifest_sha)
        with socket.socket() as held:
            held.bind(("127.0.0.1", self.port))
            held.listen(1)
            with self.assertRaises(OSError):
                cleanup(self.out, manifest_sha, True)
        (self.out/"config.toml").write_text("tampered")
        with self.assertRaisesRegex(ValueError, "identity changed"):
            cleanup(self.out, manifest_sha, True)
        self.assertTrue(self.out.exists())

    def test_cleanup_refuses_manifest_mismatch_and_extra_file(self):
        self.call()
        manifest_sha = sha((self.out/"manifest.json").read_bytes())
        with self.assertRaisesRegex(ValueError, "manifest SHA-256 mismatch"):
            cleanup(self.out, "0"*64, True)
        (self.out/"unexpected").write_text("x")
        with self.assertRaisesRegex(ValueError, "contents changed"):
            cleanup(self.out, manifest_sha, True)

    def test_exact_server_config_check_when_supplied(self):
        server = os.environ.get("AEGIS_B09_TEST_SERVER_BIN")
        if not server:
            self.skipTest("exact installed binary not supplied locally")
        self.call()
        result = subprocess.run([server, "--config", str(self.out/"config.toml"), "config-check"],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"config ok: current=1 legacy=1 active_legacy=1", result.stdout)

    def test_linux_root_cli_render_cleanup_isolated_python(self):
        if not sys.platform.startswith("linux") or os.geteuid() != 0:
            self.skipTest("root Linux CLI required")
        script = Path(__file__).with_name("render_isolated_relay_canary.py")
        command = ["/usr/bin/python3", "-I", "-S", "-B", str(script), "render",
                   "--candidate", str(self.candidate), "--cert", str(self.cert),
                   "--key", str(self.key), "--out-dir", str(self.out),
                   "--port", str(self.port), "--expected-candidate-sha256",
                   sha(self.candidate.read_bytes())]
        env = {"PATH": "/usr/bin:/bin"}
        first = subprocess.run(command, capture_output=True, timeout=10, env=env)
        self.assertEqual(first.returncode, 0, first.stderr.decode(errors="replace"))
        self.assertNotIn(CANARY.encode(), first.stdout)
        manifest_sha = sha((self.out/"manifest.json").read_bytes())
        second = subprocess.run(["/usr/bin/python3", "-I", "-S", "-B", str(script),
                                 "cleanup", "--out-dir", str(self.out),
                                 "--expected-manifest-sha256", manifest_sha,
                                 "--never-launched"], capture_output=True, timeout=10, env=env)
        self.assertEqual(second.returncode, 0, second.stderr.decode(errors="replace"))
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
