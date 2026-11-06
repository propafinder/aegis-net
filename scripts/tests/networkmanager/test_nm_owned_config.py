"""Real filesystem/crash tests, confined to a private synthetic root.

ROOT and OWNER_UID are literal fixture rebases only; no production CLI override.
No network daemon, system service, VM, credentials or host settings are touched.
"""
import importlib.util
import fcntl
import json
import os
from pathlib import Path
import signal
import select
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).with_name("nm_owned_config.py")


def load(root):
    spec = importlib.util.spec_from_file_location("nm_owner", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT, module.OWNER_UID = str(root), os.geteuid()
    return module


CHILD = r'''
import importlib.util,json,os,signal,sys
spec=importlib.util.spec_from_file_location('nm_owner',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.ROOT=sys.argv[2];m.OWNER_UID=os.geteuid();cut=sys.argv[4]
def checkpoint(name):
    if name==cut:os.kill(os.getpid(),signal.SIGKILL)
    if cut=='hold_ownership' and name=='ownership_locked':
        print('ownership lock held before intent',flush=True);sys.stdin.read(1)
m._checkpoint=checkpoint
if cut=='stage_prefix':
    original=m._write_all
    def partial(fd,data):
        if data.startswith(b'# Aegis device guard owner='):
            os.write(fd,data[:31]);os.fsync(fd);os.kill(os.getpid(),signal.SIGKILL)
        original(fd,data)
    m._write_all=partial
print(json.dumps(m.run(sys.argv[3])))
'''


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-nm-owned-fixture-")
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.m = load(self.root)
        self.target = self.root / self.m.TARGET
        self.receipt = self.root / self.m.RECEIPT
        self.target.parent.mkdir(parents=True, mode=0o700)

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self):
        result = {}
        for p in self.root.rglob("*"):
            s = p.lstat()
            key = str(p.relative_to(self.root))
            result[key] = (s.st_mode, s.st_ino, s.st_nlink,
                           os.readlink(p) if p.is_symlink() else p.read_bytes() if p.is_file() else None)
        return result

    def refuse_unchanged(self, action):
        before = self.snapshot()
        with self.assertRaises((ValueError, OSError)):
            self.m.run(action)
        self.assertEqual(self.snapshot(), before)

    def crash(self, action, cut):
        p = subprocess.run([sys.executable, "-c", CHILD, str(SOURCE), str(self.root), action, cut],
                           capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, -signal.SIGKILL, (cut, p.stdout, p.stderr))

    def stage(self):
        record = json.loads(self.receipt.read_text())
        return self.target.parent / self.m._stage_name(record)

    def test_inspect_absent_and_remove_absent_are_read_only(self):
        before = self.snapshot()
        self.assertEqual(self.m.run("inspect"), {"ownership": "absent"})
        self.assertEqual(self.m.run("remove"), {"ownership": "absent"})
        self.assertEqual(self.snapshot(), before)

    def test_prepare_verify_retry_remove_exact_owned_file(self):
        self.m.run("prepare")
        record = json.loads(self.receipt.read_text())
        self.assertRegex(record["nonce"], "^[0-9a-f]{32}$")
        self.assertEqual(self.target.read_bytes(),
                         ("# Aegis device guard owner=" + record["nonce"] + "\n[main]\ndhcp=internal\n").encode())
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        target_inode = self.target.stat().st_ino
        self.assertEqual(self.m.run("verify"), {"ownership": "owned"})
        self.m.run("prepare")
        self.assertEqual(self.target.stat().st_ino, target_inode)
        self.assertFalse(self.stage().exists())
        self.m.run("remove")
        self.assertFalse(self.target.exists() or self.receipt.exists())
        self.assertEqual(self.m.run("remove"), {"ownership": "absent"})

    def test_preexisting_file_is_never_adopted_even_identical_policy(self):
        self.target.write_bytes(b"[main]\ndhcp=internal\n")
        self.target.chmod(0o600)
        for action in ("inspect", "prepare", "verify", "remove"):
            self.refuse_unchanged(action)
        self.assertFalse(self.receipt.parent.exists())

    def test_prepare_all_durable_crash_cuts_resume_same_nonce(self):
        for cut in ("intent_durable", "stage_created", "stage_prefix", "stage_durable",
                    "target_linked", "target_durable", "published_inode_durable",
                    "stage_unlinked_before_sync", "stage_removed", "installed_durable"):
            with self.subTest(cut=cut):
                self.crash("prepare", cut)
                record = json.loads(self.receipt.read_text())
                nonce = record["nonce"]
                self.assertEqual(self.m.run("inspect"), {"ownership": "owned"})
                if cut in ("target_linked", "target_durable"):
                    self.assertEqual(self.stage().stat().st_ino, self.target.stat().st_ino)
                    self.assertEqual(self.target.stat().st_nlink, 2)
                    self.refuse_unchanged("verify")
                self.m.run("prepare")
                self.m.run("verify")
                self.assertEqual(json.loads(self.receipt.read_text())["nonce"], nonce)
                self.assertEqual(self.target.stat().st_nlink, 1)
                self.assertFalse(self.stage().exists())
                self.m.run("remove")

    def test_remove_all_durable_crash_cuts_are_retryable(self):
        for cut in ("removing_durable", "target_unlinked_before_sync", "target_removed", "receipt_removed"):
            with self.subTest(cut=cut):
                self.m.run("prepare")
                self.crash("remove", cut)
                if self.receipt.exists():
                    self.refuse_unchanged("prepare")
                    self.refuse_unchanged("verify")
                self.m.run("remove")
                self.assertFalse(self.target.exists() or self.receipt.exists())

    def test_remove_pending_private_prefix_and_two_link_publication(self):
        for cut in ("stage_created", "stage_prefix", "target_linked"):
            with self.subTest(cut=cut):
                self.crash("prepare", cut)
                stage = self.stage()
                self.m.run("remove")
                self.assertFalse(stage.exists() or self.target.exists() or self.receipt.exists())

    def test_unknown_or_partial_public_target_never_resumes(self):
        self.crash("prepare", "intent_durable")
        nonce = json.loads(self.receipt.read_text())["nonce"]
        for data in (b"", self.m.content(nonce)[:31], self.m.content(nonce), b"[main]\ndhcp=external\n"):
            self.target.write_bytes(data)
            self.target.chmod(0o600)
            for action in ("inspect", "prepare", "verify", "remove"):
                self.refuse_unchanged(action)
            self.target.unlink()

    def test_changed_installed_bytes_or_inode_refuse_all_mutations(self):
        self.m.run("prepare")
        original = self.target.read_bytes()
        self.target.write_bytes(original + b"# administrator change\n")
        for action in ("inspect", "prepare", "verify", "remove"):
            self.refuse_unchanged(action)
        # Retain the original inode so the filesystem cannot immediately reuse
        # its number for this distinct same-content replacement.
        self.target.rename(self.target.with_name("retained-original-inode"))
        self.target.write_bytes(original)
        self.target.chmod(0o600)
        for action in ("inspect", "prepare", "verify", "remove"):
            self.refuse_unchanged(action)

    def test_missing_installed_policy_requires_explicit_owned_cleanup(self):
        self.m.run("prepare")
        self.target.unlink()
        for action in ("inspect", "prepare", "verify"):
            self.refuse_unchanged(action)
        self.m.run("remove")
        self.assertFalse(self.receipt.exists())

    def test_unrecognized_private_stage_prefix_is_preserved(self):
        self.crash("prepare", "stage_created")
        self.stage().write_bytes(b"unrelated data")
        for action in ("inspect", "prepare", "verify", "remove"):
            self.refuse_unchanged(action)

    def test_symlink_hardlink_and_world_writable_target_refuse(self):
        self.m.run("prepare")
        outside = self.root / "unrelated"
        outside.write_bytes(b"private unrelated fixture")
        saved = self.target.read_bytes()
        self.target.unlink()
        for kind in ("symlink", "hardlink", "mode"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    self.target.symlink_to(outside)
                elif kind == "hardlink":
                    os.link(outside, self.target)
                else:
                    self.target.write_bytes(saved)
                    self.target.chmod(0o666)
                self.refuse_unchanged("remove")
                self.target.unlink()
        self.assertEqual(outside.read_bytes(), b"private unrelated fixture")

    def test_receipt_bounds_unknown_fields_duplicate_fields_and_hash(self):
        self.m.run("prepare")
        initial = self.receipt.read_bytes()
        record = json.loads(initial)
        malformed = [initial[:-1] + b"junk", b"x" * 4097,
                     json.dumps(record | {"extra": 1}).encode(),
                     json.dumps(record | {"sha256": "0" * 64}).encode(),
                     initial.replace(b'"schema":', b'"schema":"duplicate","schema":')]
        for data in malformed:
            self.receipt.write_bytes(data)
            self.refuse_unchanged("prepare")
            self.refuse_unchanged("remove")
        self.receipt.write_bytes(initial)
        self.m.run("verify")

    def test_parent_permissions_and_symlink_refuse_before_writes(self):
        self.target.parent.chmod(0o777)
        self.refuse_unchanged("prepare")
        self.target.parent.chmod(0o700)
        moved = self.target.parent.with_name("kept-conf.d")
        self.target.parent.rename(moved)
        self.target.parent.symlink_to(moved)
        self.refuse_unchanged("prepare")

    def test_publication_is_same_directory_even_with_split_logical_roots(self):
        original = self.m.os.link
        seen = []
        def linked(source, destination, **kwargs):
            self.assertEqual(os.fstat(kwargs["src_dir_fd"]).st_ino,
                             os.fstat(kwargs["dst_dir_fd"]).st_ino)
            self.assertFalse(source.endswith(".conf"))
            seen.append((source, destination))
            return original(source, destination, **kwargs)
        self.m.os.link = linked
        try:
            self.m.run("prepare")
        finally:
            self.m.os.link = original
        self.assertEqual(len(seen), 1)

    def test_existing_lock_serializes_absent_inspection_and_cleanup(self):
        for action in ("inspect", "remove"):
            with self.subTest(action=action):
                producer = subprocess.Popen(
                    [sys.executable, "-c", CHILD, str(SOURCE), str(self.root), "prepare", "hold_ownership"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                observer = None
                try:
                    self.assertTrue(select.select([producer.stdout], [], [], 5)[0], "producer did not reach lock")
                    self.assertEqual(producer.stdout.readline().strip(), "ownership lock held before intent")
                    self.assertFalse(self.receipt.exists())
                    observer = subprocess.Popen(
                        [sys.executable, "-c", CHILD, str(SOURCE), str(self.root), action, "none"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    with self.assertRaises(subprocess.TimeoutExpired):
                        observer.wait(timeout=0.2)
                    producer_out, producer_error = producer.communicate("x", timeout=5)
                    self.assertEqual(producer.returncode, 0, (producer_out, producer_error))
                    observer_out, observer_error = observer.communicate(timeout=5)
                    self.assertEqual(observer.returncode, 0, (observer_out, observer_error))
                    expected = "owned" if action == "inspect" else "absent"
                    self.assertEqual(json.loads(observer_out), {"ownership": expected})
                    self.assertEqual(self.target.exists(), action == "inspect")
                    self.m.run("remove")
                finally:
                    for process in (observer, producer):
                        if process is not None:
                            if process.poll() is None:
                                process.kill()
                            process.communicate(timeout=5)

    def test_busy_existing_lock_is_bounded_and_does_not_mutate(self):
        self.m.run("prepare")
        lock_path = self.receipt.with_name(self.receipt.name + ".lock")
        before = self.snapshot()
        with lock_path.open("rb") as locked_file:
            fcntl.flock(locked_file, fcntl.LOCK_EX)
            started = time.monotonic()
            outcome = subprocess.run(
                [sys.executable, "-c", CHILD, str(SOURCE), str(self.root), "remove", "none"],
                capture_output=True, text=True, timeout=8)
            elapsed = time.monotonic() - started
            self.assertNotEqual(outcome.returncode, 0)
            self.assertIn("ownership lock busy", outcome.stderr)
            self.assertGreaterEqual(elapsed, 4.9)
            self.assertLess(elapsed, 8)
        self.assertEqual(self.snapshot(), before)

    def test_retry_directory_barrier_precedes_forgetting_unlink_intent(self):
        for action, cut in (("prepare", "stage_unlinked_before_sync"),
                            ("remove", "target_unlinked_before_sync")):
            with self.subTest(action=action):
                if action == "remove":
                    self.m.run("prepare")
                self.crash(action, cut)
                original_sync, original_save, original_unlink = self.m.os.fsync, self.m._save, self.m.os.unlink
                config_inode = self.target.parent.stat().st_ino
                config_synced = []
                def synced(fd):
                    if os.fstat(fd).st_ino == config_inode:
                        config_synced.append(True)
                    return original_sync(fd)
                def saved(fd, name, record):
                    if record["phase"] == "installed":
                        self.assertTrue(config_synced, "installed receipt preceded config directory barrier")
                    return original_save(fd, name, record)
                def unlinked(name, **kwargs):
                    if name == self.receipt.name:
                        self.assertTrue(config_synced, "removal receipt deleted before config directory barrier")
                    return original_unlink(name, **kwargs)
                self.m.os.fsync, self.m._save, self.m.os.unlink = synced, saved, unlinked
                try:
                    self.m.run(action)
                finally:
                    self.m.os.fsync, self.m._save, self.m.os.unlink = original_sync, original_save, original_unlink
                self.assertTrue(config_synced)
                self.m.run("remove")


if __name__ == "__main__":
    unittest.main(verbosity=2)
