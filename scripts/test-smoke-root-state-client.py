#!/usr/bin/env python3
"""Inert filesystem contracts; mocked root/Linux checks are not native proof."""

import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "smoke_root_state_client", Path(__file__).resolve().parent / "lib/smoke-root-state-client.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
REAL_ROOT_CHECK = HELPER._require_linux_root


class SmokeStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-smoke-stage-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.staging = self.root / "run"
        self.staging.mkdir(mode=0o755)
        self.source = self.root / "build-client"
        self.data = b"synthetic inert build bytes\n"
        self.source.write_bytes(self.data)
        self.digest = hashlib.sha256(self.data).hexdigest()
        # No native privilege is used: redirect the fixed base to this test's
        # temporary directory and model ownership with the current test UID.
        patches = [
            mock.patch.object(HELPER, "STAGING_ROOT", str(self.staging)),
            mock.patch.object(HELPER, "_require_linux_root"),
            mock.patch.object(HELPER, "_set_root_owner"),
            mock.patch.object(HELPER, "_root_owned",
                              side_effect=lambda info: (info.st_uid, info.st_gid) == (os.geteuid(), os.getegid())),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def stage(self):
        directory, identity = HELPER.stage(str(self.source), self.digest)
        return Path(directory), identity

    def assert_stage_refused(self, source=None, digest=None):
        with self.assertRaises((HELPER.StagingError, OSError)):
            HELPER.stage(str(source or self.source), digest or self.digest)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_pinned_copy_and_exact_cleanup(self):
        directory, identity = self.stage()
        binary = directory / HELPER.BINARY
        self.assertEqual(binary.read_bytes(), self.data)
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
        self.assertEqual(binary.stat().st_nlink, 1)
        self.assertNotEqual(binary.stat().st_ino, self.source.stat().st_ino)
        self.assertEqual(identity, f"{directory.stat().st_dev}:{directory.stat().st_ino}")
        HELPER.cleanup(str(directory), identity)
        self.assertFalse(directory.exists())
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_input_cargo_hardlink_is_allowed_but_output_is_single_link(self):
        os.link(self.source, self.root / "cargo-output-link")
        self.assertEqual(self.source.stat().st_nlink, 2)
        directory, identity = self.stage()
        self.assertEqual((directory / HELPER.BINARY).stat().st_nlink, 1)
        HELPER.cleanup(str(directory), identity)

    def test_measure_stage_and_cleanup_use_one_exact_leaf(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = HELPER.main(["stage", "--source", str(self.source), "--sha256", self.digest,
                                  "--binary-name", "aegis-measure"])
        self.assertEqual(result, 0)
        directory_text, identity = output.getvalue().strip().split(" ")
        directory = Path(directory_text)
        self.assertEqual({path.name for path in directory.iterdir()}, {"aegis-measure"})
        binary = directory / "aegis-measure"
        self.assertEqual(binary.read_bytes(), self.data)
        self.assertEqual(binary.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o755)
        HELPER.cleanup(directory_text, identity)
        self.assertFalse(directory.exists())

    def test_measure_wrong_digest_removes_known_partial_leaf(self):
        with self.assertRaisesRegex(HELPER.StagingError, "SHA-256 mismatch"):
            HELPER.stage(str(self.source), "0" * 64, "aegis-measure")
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_invalid_binary_name_refuses_before_staging(self):
        for name in ("other", "../aegis-client", "/aegis-measure", "aegis-client/extra"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(HELPER.StagingError, "unsupported smoke binary name"):
                    HELPER.stage(str(self.source), self.digest, name)
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    HELPER.main(["stage", "--source", str(self.source), "--sha256", self.digest,
                                  "--binary-name", name])
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(list(self.staging.iterdir()), [])

    def test_restrictive_umask_is_normalized_on_owned_outputs(self):
        previous = os.umask(0o277)
        try:
            directory, identity = self.stage()
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((directory / HELPER.BINARY).stat().st_mode), 0o755)
        HELPER.cleanup(str(directory), identity)

    def test_wrong_digest_never_makes_private_copy_public(self):
        real_chmod = HELPER.os.fchmod
        with mock.patch.object(HELPER.os, "fchmod", wraps=real_chmod) as chmod:
            self.assert_stage_refused(digest="0" * 64)
        self.assertNotIn(0o755, [call.args[1] for call in chmod.call_args_list])

    def test_digest_and_absolute_source_syntax_fail_before_staging(self):
        for source, digest in [(str(self.source), "A" * 64), (str(self.source), "0" * 63),
                               ("relative", self.digest), (str(self.root / ".." / "build-client"), self.digest)]:
            with self.subTest(source=source, digest=digest):
                self.assert_stage_refused(source=source, digest=digest)

    def test_source_symlink_and_symlink_ancestor_are_rejected(self):
        linked = self.root / "linked"
        linked.symlink_to(self.source)
        self.assert_stage_refused(source=linked)
        linked_dir = self.root / "linked-parent"
        linked_dir.symlink_to(self.root, target_is_directory=True)
        self.assert_stage_refused(source=linked_dir / self.source.name)

    def test_nonregular_fifo_and_directory_are_rejected_without_waiting(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        self.assert_stage_refused(source=fifo)
        self.assert_stage_refused(source=self.root)

    def test_source_bound_and_empty_file(self):
        with mock.patch.object(HELPER, "MAX_SOURCE_BYTES", len(self.data) - 1):
            self.assert_stage_refused()
        self.source.write_bytes(b"")
        self.assert_stage_refused(digest=hashlib.sha256(b"").hexdigest())

    def test_source_replacement_during_copy_is_rejected(self):
        real_copy = HELPER._copy_and_hash

        def replace_after_copy(*args):
            result = real_copy(*args)
            self.source.unlink()
            self.source.write_bytes(self.data)
            return result

        with mock.patch.object(HELPER, "_copy_and_hash", side_effect=replace_after_copy):
            self.assert_stage_refused()

    def test_source_metadata_change_during_copy_is_rejected(self):
        real_copy = HELPER._copy_and_hash

        def change_after_copy(*args):
            result = real_copy(*args)
            info = self.source.stat()
            os.utime(self.source, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000_000))
            return result

        with mock.patch.object(HELPER, "_copy_and_hash", side_effect=change_after_copy):
            self.assert_stage_refused()

    def test_source_growth_during_copy_is_bounded(self):
        real_read = HELPER.os.read
        changed = False

        def grow_after_read(fd, count):
            nonlocal changed
            block = real_read(fd, count)
            if not changed:
                changed = True
                with self.source.open("ab") as stream:
                    stream.write(b"growth")
            return block

        with mock.patch.object(HELPER.os, "read", side_effect=grow_after_read):
            self.assert_stage_refused()

    def test_stage_failure_preserves_other_directory_and_unknown_inventory(self):
        kept = self.staging / (HELPER.PREFIX + "0" * 32)
        kept.mkdir()
        (kept / "unrelated").write_text("keep")

        def injected_failure(_source_fd, output_fd, _size):
            directory = next(path for path in self.staging.iterdir() if path != kept)
            (directory / "unknown").write_text("do not delete")
            os.write(output_fd, b"partial")
            raise OSError("injected copy failure")

        with mock.patch.object(HELPER, "_copy_and_hash", side_effect=injected_failure):
            with self.assertRaisesRegex(HELPER.StagingError, "partial state retained"):
                HELPER.stage(str(self.source), self.digest)
        self.assertEqual((kept / "unrelated").read_text(), "keep")
        partial = next(path for path in self.staging.iterdir() if path != kept)
        self.assertEqual({path.name for path in partial.iterdir()}, {HELPER.BINARY, "unknown"})
        self.assertEqual(stat.S_IMODE(partial.stat().st_mode), 0o700)

    def test_copy_failure_removes_only_known_owned_partial_output(self):
        def injected_failure(_source_fd, output_fd, _size):
            os.write(output_fd, b"partial")
            raise OSError("injected copy failure")

        with mock.patch.object(HELPER, "_copy_and_hash", side_effect=injected_failure):
            self.assert_stage_refused()
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_cleanup_identity_mismatch_preserves_binary(self):
        directory, identity = self.stage()
        device, inode = identity.split(":")
        with self.assertRaisesRegex(HELPER.StagingError, "identity mismatch"):
            HELPER.cleanup(str(directory), f"{device}:{int(inode) + 1}")
        self.assertEqual((directory / HELPER.BINARY).read_bytes(), self.data)

    def test_cleanup_unknown_inventory_refuses_before_unlink(self):
        directory, identity = self.stage()
        (directory / "unknown").write_text("keep")
        with self.assertRaisesRegex(HELPER.StagingError, "unknown staging inventory"):
            HELPER.cleanup(str(directory), identity)
        self.assertEqual((directory / HELPER.BINARY).read_bytes(), self.data)
        self.assertEqual((directory / "unknown").read_text(), "keep")

    def test_cleanup_both_allowed_binary_leaves_refuses_before_unlink(self):
        directory, identity = self.stage()
        measure = directory / "aegis-measure"
        measure.write_bytes(b"second staged leaf")
        measure.chmod(0o755)
        with self.assertRaisesRegex(HELPER.StagingError, "unknown staging inventory"):
            HELPER.cleanup(str(directory), identity)
        self.assertEqual((directory / HELPER.BINARY).read_bytes(), self.data)
        self.assertEqual(measure.read_bytes(), b"second staged leaf")

    def test_cleanup_empty_inventory_refuses(self):
        directory, identity = self.stage()
        (directory / HELPER.BINARY).unlink()
        with self.assertRaisesRegex(HELPER.StagingError, "unknown staging inventory"):
            HELPER.cleanup(str(directory), identity)
        self.assertTrue(directory.exists())

    def test_cleanup_symlink_or_hardlink_binary_refuses(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                directory, identity = self.stage()
                binary = directory / HELPER.BINARY
                if kind == "symlink":
                    binary.unlink()
                    binary.symlink_to(self.source)
                else:
                    os.link(binary, self.root / "extra-staged-link")
                with self.assertRaisesRegex(HELPER.StagingError, "untrusted staged binary"):
                    HELPER.cleanup(str(directory), identity)
                self.assertTrue(binary.exists())
                self.assertEqual(self.source.read_bytes(), self.data)

    def test_cleanup_replaced_directory_or_directory_symlink_refuses(self):
        directory, identity = self.stage()
        moved = self.staging / "kept-owned-directory"
        directory.rename(moved)
        directory.mkdir(mode=0o700)
        with self.assertRaisesRegex(HELPER.StagingError, "identity mismatch"):
            HELPER.cleanup(str(directory), identity)
        directory.rmdir()
        directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(OSError):
            HELPER.cleanup(str(directory), identity)
        self.assertEqual((moved / HELPER.BINARY).read_bytes(), self.data)

    def test_cleanup_untrusted_owner_or_mode_refuses(self):
        directory, identity = self.stage()
        with mock.patch.object(HELPER, "_root_owned", return_value=False):
            with self.assertRaisesRegex(HELPER.StagingError, "untrusted staging root"):
                HELPER.cleanup(str(directory), identity)
        directory.chmod(0o777)
        with self.assertRaisesRegex(HELPER.StagingError, "untrusted staging directory"):
            HELPER.cleanup(str(directory), identity)
        self.assertEqual((directory / HELPER.BINARY).read_bytes(), self.data)

    def test_cleanup_namespace_and_identity_syntax(self):
        directory, identity = self.stage()
        for path, receipt in [(str(directory) + "/", identity), (str(self.root), identity),
                              (str(directory), "-1:2"), (str(directory), "1:0"),
                              (str(directory), f"{2**64}:1")]:
            with self.subTest(path=path, receipt=receipt):
                with self.assertRaises(HELPER.StagingError):
                    HELPER.cleanup(path, receipt)
        self.assertTrue((directory / HELPER.BINARY).exists())

    def test_cli_success_is_one_receipt_line_and_cleanup_is_silent(self):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = HELPER.main(["stage", "--source", str(self.source), "--sha256", self.digest])
        self.assertEqual(result, 0)
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        directory, identity = output.getvalue().strip().split(" ")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = HELPER.main(["cleanup", "--directory", directory, "--identity", identity])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "")

    def test_cli_failure_has_no_success_receipt(self):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = HELPER.main(["stage", "--source", str(self.source), "--sha256", "0" * 64])
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("SHA-256 mismatch", errors.getvalue())
        self.assertEqual(list(self.staging.iterdir()), [])


class NativeBoundaryTests(unittest.TestCase):
    def test_real_entry_guard_rejects_nonlinux_and_nonroot(self):
        for platform, uid in [("darwin", 0), ("linux", 1000)]:
            with self.subTest(platform=platform, uid=uid):
                with mock.patch.object(HELPER.sys, "platform", platform), \
                        mock.patch.object(HELPER.os, "geteuid", return_value=uid):
                    with self.assertRaisesRegex(HELPER.StagingError, "requires Linux root"):
                        REAL_ROOT_CHECK()

    def test_cli_has_no_staging_root_or_privilege_bypass_option(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            HELPER.main(["stage", "--source", "/unused", "--sha256", "0" * 64,
                         "--staging-root", "/tmp"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
