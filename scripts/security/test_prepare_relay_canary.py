import hashlib
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from prepare_relay_canary import prepare


PRIMARY = "ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1"


class PrepareRelayCanaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-canary-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.config = self.root / "server.toml"
        self.config.write_text(
            'listen = "127.0.0.1:8443"\n'
            'cert = "cert.pem"\nkey = "key.pem"\n'
            f'auth_token = "{PRIMARY}"\n'
        )
        self.config.chmod(0o600)
        self.sha = hashlib.sha256(self.config.read_bytes()).hexdigest()

    def call(self, **kwargs):
        values = dict(config=self.config, out_dir=self.root / "out",
                      canary_id="canary-one", ttl=120,
                      expected_sha256=self.sha, now=1_800_000_000)
        values.update(kwargs)
        return prepare(**values)

    def test_issues_distinct_secret_exact_rollback_and_bounded_expiry(self):
        before = self.config.read_bytes()
        result = self.call()
        self.assertFalse(result["applied"])
        self.assertEqual(result["expires_at_unix_secs"], 1_800_000_120)
        self.assertEqual(self.config.read_bytes(), before)
        output = self.root / "out"
        self.assertEqual((output / "rollback.toml").read_bytes(), before)
        candidate = tomllib.loads((output / "candidate.toml").read_text())
        entry = candidate["legacy_auth_tokens"][0]
        self.assertEqual(entry["id"], "canary-one")
        self.assertEqual(entry["not_after_unix_secs"], 1_800_000_120)
        self.assertEqual(candidate["auth_token"], PRIMARY)
        self.assertEqual(len(entry["auth_token"]), 64)
        self.assertNotEqual(entry["auth_token"], PRIMARY)
        self.assertEqual((output / "client-token").read_text().strip(), entry["auth_token"])
        self.assertNotIn(entry["auth_token"], (output / "receipt.json").read_text())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for path in output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_wrong_sha_refuses_without_output(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.call(expected_sha256="0" * 64)
        self.assertFalse((self.root / "out").exists())

    def test_inner_tls_refuses_without_output(self):
        with self.config.open("a") as stream:
            stream.write("\n[transport.inner_tls]\nserver_name = 'fixture'\n")
        self.sha = hashlib.sha256(self.config.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "inner-TLS"):
            self.call()
        self.assertFalse((self.root / "out").exists())

    def test_capacity_and_duplicate_id_refuse(self):
        with self.config.open("a") as stream:
            for index in range(3):
                stream.write(f'\n[[legacy_auth_tokens]]\nid = "old-{index}"\n'
                             f'auth_token = "{index + 2:064x}"\n'
                             'not_after_unix_secs = 1800000200\n')
        self.sha = hashlib.sha256(self.config.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "capacity"):
            self.call()
        self.assertFalse((self.root / "out").exists())

    def test_duplicate_id_refuses_with_free_capacity(self):
        with self.config.open("a") as stream:
            stream.write('\n[[legacy_auth_tokens]]\nid = "canary-one"\n'
                         'auth_token = "f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca"\n'
                         'not_after_unix_secs = 1800000200\n')
        self.sha = hashlib.sha256(self.config.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.call()
        self.assertFalse((self.root / "out").exists())

    def test_real_server_validator_accepts_candidate(self):
        server = os.environ.get("AEGIS_B09_TEST_SERVER_BIN")
        if not server:
            self.skipTest("exact server binary not supplied")
        self.call()
        result = subprocess.run([server, "--config", str(self.root / "out/candidate.toml"),
                                 "config-check"], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"config ok: current=1 legacy=1 active_legacy=1", result.stdout)

    def test_symlink_and_open_output_refuse(self):
        target = self.root / "link"
        target.symlink_to(self.config)
        with self.assertRaises(OSError):
            self.call(config=target)
        (self.root / "out").mkdir()
        with self.assertRaises(FileExistsError):
            self.call()

    def test_insecure_parent_and_ttl_refuse(self):
        self.root.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "input parent"):
            self.call()
        self.root.chmod(0o700)
        for ttl in (0, 59, 901):
            with self.assertRaisesRegex(ValueError, "ttl"):
                self.call(ttl=ttl)
        self.assertFalse((self.root / "out").exists())

    def test_world_readable_config_and_placeholder_primary_refuse(self):
        self.config.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "mode-0600"):
            self.call()
        self.config.chmod(0o600)
        self.config.write_text(self.config.read_text().replace(PRIMARY, "a1" * 32))
        self.sha = hashlib.sha256(self.config.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "valid primary"):
            self.call()
        self.assertFalse((self.root / "out").exists())


if __name__ == "__main__":
    unittest.main()
