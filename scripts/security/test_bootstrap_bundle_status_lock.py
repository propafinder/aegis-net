import os
import fcntl
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import bootstrap_bundle_status_lock as bootstrap


WORKSPACE = Path(os.environ.get("AEGIS_B09_TEST_ROOT", str(Path.cwd())))


class BootstrapInertTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".b09-sidecar-test-", dir=WORKSPACE)
        self.path = Path(self.temp.name)
        self.store = self.path / "store.json"
        self.store.write_bytes(b"synthetic-no-token")
        self.store.chmod(0o600)
        self.fd = bootstrap.open_trusted_parent(str(self.store), os.geteuid())
        meta = self.store.stat()
        self.dev, self.ino = meta.st_dev, meta.st_ino
        self.parent = bootstrap.directory_identity(self.fd)
        self.identity = (123, 456)

    def tearDown(self):
        os.close(self.fd)
        self.temp.cleanup()

    def call(self, apply=False, **overrides):
        return bootstrap.bootstrap_leaf(
            self.fd, self.store.name, os.geteuid(),
            overrides.get("dev", self.dev), overrides.get("ino", self.ino),
            self.parent, overrides.get("parent_again", lambda: self.parent),
            self.identity, overrides.get("again", lambda: self.identity),
            overrides.get("config_again", lambda: True), apply,
            overrides.get("writable", bootstrap.parent_writable),
        )

    def test_dry_run_does_not_create_or_change_store(self):
        before = self.store.read_bytes()
        self.assertEqual(self.call(), "DRY_RUN_READY")
        self.assertFalse((self.path / "store.json.lock").exists())
        self.assertEqual(self.store.read_bytes(), before)

    def test_create_is_empty_private_and_cannot_repeat_or_unlink(self):
        self.assertEqual(self.call(apply=True), "CREATED_READBACK_PASS")
        sidecar = self.path / "store.json.lock"
        first = sidecar.stat()
        self.assertEqual(first.st_size, 0)
        self.assertEqual(stat.S_IMODE(first.st_mode), 0o600)
        self.assertEqual(first.st_uid, os.geteuid())
        with self.assertRaises(bootstrap.Refused):
            self.call(apply=True)
        self.assertEqual(sidecar.stat().st_ino, first.st_ino)
        self.assertEqual(self.store.read_bytes(), b"synthetic-no-token")

    def test_foreign_symlink_or_unsafe_store_refuses_without_touching(self):
        target = self.path / "foreign"
        target.write_bytes(b"sentinel")
        (self.path / "store.json.lock").symlink_to(target)
        with self.assertRaises(bootstrap.Refused):
            self.call(apply=True)
        self.assertEqual(target.read_bytes(), b"sentinel")
        (self.path / "store.json.lock").unlink()
        self.store.chmod(0o644)
        with self.assertRaises(bootstrap.Refused):
            self.call(apply=True)
        self.assertFalse((self.path / "store.json.lock").exists())

    def test_store_inode_mismatch_refuses_before_create(self):
        with self.assertRaises(bootstrap.Refused):
            self.call(apply=True, ino=self.ino + 1)
        self.assertFalse((self.path / "store.json.lock").exists())

    def test_process_change_before_create_refuses(self):
        with self.assertRaises(bootstrap.Refused):
            self.call(apply=True, again=lambda: (123, 457))
        self.assertFalse((self.path / "store.json.lock").exists())

    def test_process_change_after_create_retains_sidecar_for_review(self):
        calls = iter((self.identity, (123, 457)))
        with self.assertRaises(bootstrap.Refused):
            self.call(apply=True, again=lambda: next(calls))
        sidecar = self.path / "store.json.lock"
        self.assertTrue(sidecar.is_file())
        self.assertEqual(sidecar.stat().st_size, 0)
        self.assertEqual(self.store.read_bytes(), b"synthetic-no-token")

    def test_config_change_before_create_refuses_without_leaf(self):
        with self.assertRaises(bootstrap.Refused):
            self.call(apply=True, config_again=lambda: False)
        self.assertFalse((self.path / "store.json.lock").exists())

    def test_config_change_after_create_is_partial_and_keeps_leaf(self):
        calls = iter((True, False))
        with self.assertRaises(bootstrap.Refused):
            self.call(apply=True, config_again=lambda: next(calls))
        sidecar = self.path / "store.json.lock"
        self.assertTrue(sidecar.is_file())
        self.assertEqual(sidecar.stat().st_size, 0)
        self.assertEqual(self.store.read_bytes(), b"synthetic-no-token")

    def test_competing_create_refuses_without_truncation(self):
        sidecar = self.path / "store.json.lock"
        def competitor():
            sidecar.write_bytes(b"foreign-sentinel")
            sidecar.chmod(0o600)
            return self.identity
        with self.assertRaises(bootstrap.Refused):
            self.call(apply=True, again=competitor)
        self.assertEqual(sidecar.read_bytes(), b"foreign-sentinel")
        self.assertEqual(self.store.read_bytes(), b"synthetic-no-token")

    def test_writable_parent_refuses_traversal(self):
        self.path.chmod(0o777)
        with self.assertRaises(bootstrap.Refused):
            bootstrap.open_trusted_parent(str(self.store), os.geteuid())
        self.path.chmod(0o700)

    def test_root_owned_0755_parent_is_not_dry_run_ready(self):
        fd = os.open("/etc", os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.assertFalse(bootstrap.parent_writable(fd))
        finally:
            os.close(fd)
        with self.assertRaises(bootstrap.Refused):
            self.call(writable=lambda _fd: False)

    def test_parent_swap_before_create_refuses_without_leaf(self):
        with self.assertRaises(bootstrap.Refused):
            self.call(apply=True, parent_again=lambda: (self.parent[0], self.parent[1] + 1))
        self.assertFalse((self.path / "store.json.lock").exists())

    def test_parent_swap_after_create_is_partial_and_keeps_leaf(self):
        values = iter((self.parent, self.parent, (self.parent[0], self.parent[1] + 1)))
        with self.assertRaises(bootstrap.Refused):
            self.call(apply=True, parent_again=lambda: next(values))
        self.assertTrue((self.path / "store.json.lock").is_file())

    def test_writer_lock_continuity_on_created_inode(self):
        self.assertEqual(self.call(apply=True), "CREATED_READBACK_PASS")
        sidecar = self.path / "store.json.lock"
        with sidecar.open("r+b") as writer, sidecar.open("rb") as reader:
            fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                fcntl.flock(reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.assertEqual(writer.fileno() >= 0, True)
            self.assertEqual(writer.read(), b"")
            fcntl.flock(writer, fcntl.LOCK_UN)

    def test_systemctl_calls_are_bounded(self):
        with mock.patch.object(bootstrap.subprocess, "run") as run:
            run.side_effect = subprocess.TimeoutExpired(["systemctl"], 3)
            with self.assertRaises(subprocess.TimeoutExpired):
                bootstrap.service_pid()
            self.assertEqual(run.call_args.kwargs["timeout"], 3)
        with mock.patch.object(bootstrap.subprocess, "run") as run, \
                mock.patch.object(bootstrap.subprocess, "check_output") as output:
            run.return_value.returncode = 0
            output.side_effect = subprocess.TimeoutExpired(["systemctl"], 3)
            with self.assertRaises(subprocess.TimeoutExpired):
                bootstrap.service_pid()
            self.assertEqual(output.call_args.kwargs["timeout"], 3)


if __name__ == "__main__":
    unittest.main()
