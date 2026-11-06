"""AUTO runtime output custody; Linux controls use only disposable directories."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "auto_runtime_log_root", REPO / "scripts/lib/aegis_installer_auto_v2.py")
AUTO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTO)
LEGACY = Path("/var/log/aegis-client/runtime/runtime-events.jsonl")


class LogSelection(unittest.TestCase):
    def test_installer_selects_path_before_prepare_and_keeps_explicit_opt_out(self):
        source = (REPO / "install.sh").read_text()
        role = source.split("install_client_role() {", 1)[1]
        block = role[role.index('  local runtime_events_path='):
                     role.index('  local install_manifest_path')]
        program = ('select_events() {\nlocal log_dir="$1"\n' + block +
                   '\nprintf "%s\\n" "$runtime_events_path"\n}\nselect_events "$1"')
        for auto, disabled, log_dir, code, expected in (
                ("1", "0", "/var/log/aegis-client", 0, str(AUTO.AUTO_RUNTIME_EVENTS)),
                ("1", "1", "/var/log/aegis-client", 0, "/dev/null"),
                ("0", "0", "/var/log/aegis-client", 0,
                 "/var/log/aegis-client/runtime-events.jsonl"),
                ("1", "0", "/tmp/custom-log-root", 1, "")):
            with self.subTest(auto=auto, disabled=disabled, log_dir=log_dir):
                result = subprocess.run(
                    ["/bin/bash", "-c", program, "select-events", log_dir],
                    env={**os.environ, "AUTO_PROFILE": auto,
                         "NO_RUNTIME_EVENTS": disabled},
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, code)
                self.assertEqual(result.stdout.strip(), expected)

    def test_opt_out_does_not_open_or_create_a_directory(self):
        with mock.patch.object(AUTO, "directory", side_effect=AssertionError):
            AUTO.ensure_runtime_events_directory(Path("/dev/null"), "root")

    def test_unknown_or_sealed_state_path_refuses_before_open(self):
        for value in ("/var/lib/aegis-client/runtime-events.jsonl", "/tmp/events",
                      str(AUTO.AUTO_RUNTIME_EVENTS)):
            with self.subTest(path=value), \
                    mock.patch.object(AUTO, "directory", side_effect=AssertionError):
                with self.assertRaises(AUTO.Refused):
                    AUTO.ensure_runtime_events_directory(Path(value), "root")

    def test_prepared_scalar_binds_policy_before_any_log_directory_write(self):
        for user, expected in (("root", AUTO.AUTO_ROOT_RUNTIME_EVENTS),
                               ("aegis-svc", AUTO.AUTO_SERVICE_RUNTIME_EVENTS)):
            with self.subTest(user=user), \
                    mock.patch.object(AUTO, "worker_phase", return_value=str(expected)) as phase, \
                    mock.patch.object(AUTO, "directory", side_effect=AssertionError):
                self.assertEqual(AUTO.prepared_runtime_events(
                    object(), AUTO.AUTO_RUNTIME_EVENTS, user, 1), expected)
                self.assertEqual(phase.call_args.args[1],
                                 ["inspect", "--field", "runtime-events-path"])
            for wrong in (AUTO.AUTO_RUNTIME_EVENTS, Path("/tmp/events"),
                          AUTO.AUTO_ROOT_RUNTIME_EVENTS if user == "aegis-svc"
                          else AUTO.AUTO_SERVICE_RUNTIME_EVENTS):
                with self.subTest(user=user, wrong=wrong), \
                        mock.patch.object(AUTO, "worker_phase", return_value=str(wrong)), \
                        mock.patch.object(AUTO, "directory", side_effect=AssertionError):
                    with self.assertRaises(AUTO.Refused):
                        AUTO.prepared_runtime_events(object(), AUTO.AUTO_RUNTIME_EVENTS, user, 1)

    def test_legacy_or_opt_out_keeps_prepared_request_without_new_inspect(self):
        with mock.patch.object(AUTO, "worker_phase", side_effect=AssertionError):
            for requested in (LEGACY, Path("/dev/null")):
                self.assertEqual(AUTO.prepared_runtime_events(
                    object(), requested, "root", 1), requested)

    def test_concrete_output_refuses_policy_mismatch_before_open(self):
        for requested, user in ((AUTO.AUTO_ROOT_RUNTIME_EVENTS, "aegis-svc"),
                                (AUTO.AUTO_SERVICE_RUNTIME_EVENTS, "root")):
            with self.subTest(requested=requested), \
                    mock.patch.object(AUTO, "directory", side_effect=AssertionError):
                with self.assertRaises(AUTO.Refused):
                    AUTO.ensure_runtime_events_directory(requested, user)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "requires isolated Linux root; never changes host paths")
class LinuxLogCustody(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.lib = self.base / "var-lib"
        self.log = self.base / "stock-var-log"
        self.lib.mkdir(mode=0o755)
        self.lib.chmod(0o755)
        self.log.mkdir(mode=0o775)
        self.log.chmod(0o775)
        os.chown(self.log, 0, 102)
        original = AUTO.directory

        def mapped_directory(path, mode=None):
            self.assertIn(path, ("/var/lib", "/var/log"))
            return original(str(self.lib if path == "/var/lib" else self.log), mode)

        self.patch = mock.patch.object(AUTO, "directory", side_effect=mapped_directory)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.parent = self.lib / "aegis-client-logs"
        self.runtime = self.parent / "root"
        self.events = self.runtime / "runtime-events.jsonl"

    def ensure(self, user="root"):
        AUTO.ensure_runtime_events_directory(
            AUTO.selected_runtime_events(AUTO.AUTO_RUNTIME_EVENTS, user), user)

    def make_runtime(self):
        self.parent.mkdir(mode=0o755)
        self.parent.chmod(0o755)
        self.runtime.mkdir(mode=0o700)
        self.runtime.chmod(0o700)

    def test_stock_log_parent_is_unchanged_and_new_parent_is_idempotent(self):
        before = self.log.stat()
        with self.assertRaises(AUTO.Refused):
            AUTO.ensure_runtime_events_directory(LEGACY, "root")
        self.ensure()
        self.ensure()
        self.assertEqual((self.parent.stat().st_uid, self.parent.stat().st_gid,
                          stat.S_IMODE(self.parent.stat().st_mode)), (0, 0, 0o755))
        self.assertEqual((self.runtime.stat().st_uid, self.runtime.stat().st_gid,
                          stat.S_IMODE(self.runtime.stat().st_mode)), (0, 0, 0o700))
        after = self.log.stat()
        self.assertEqual((before.st_uid, before.st_gid, before.st_mode,
                          before.st_ino, before.st_mtime_ns),
                         (after.st_uid, after.st_gid, after.st_mode,
                          after.st_ino, after.st_mtime_ns))
        self.assertFalse(self.events.exists())

    def test_service_runtime_has_only_the_validated_account_ownership(self):
        with mock.patch.object(AUTO, "runtime_account_identity", return_value=(999, 988)):
            self.ensure("aegis-svc")
        self.assertEqual((self.parent.stat().st_uid, self.parent.stat().st_gid), (0, 0))
        service = self.parent / "service"
        self.assertEqual((service.stat().st_uid, service.stat().st_gid,
                          stat.S_IMODE(service.stat().st_mode)), (999, 988, 0o700))
        self.assertFalse(self.runtime.exists())

    def test_root_service_root_and_service_root_service_keep_both_files(self):
        with mock.patch.object(AUTO, "runtime_account_identity", return_value=(999, 988)):
            for user in ("root", "aegis-svc", "root", "aegis-svc", "root", "aegis-svc"):
                self.ensure(user)
                uid, gid = (0, 0) if user == "root" else (999, 988)
                child = self.parent / ("root" if user == "root" else "service")
                events = child / "runtime-events.jsonl"
                if not events.exists():
                    events.write_bytes(user.encode())
                    os.chown(events, uid, gid)
                    events.chmod(0o600)
                self.assertEqual((child.stat().st_uid, child.stat().st_gid), (uid, gid))
                self.assertEqual(events.read_bytes(), user.encode())
                self.ensure(user)
            self.assertEqual(self.events.read_bytes(), b"root")
            self.assertEqual((self.parent / "service/runtime-events.jsonl").read_bytes(), b"aegis-svc")

    def test_unsafe_new_ancestor_refuses_without_normalizing_it(self):
        self.lib.chmod(0o775)
        with self.assertRaises(AUTO.Refused):
            self.ensure()
        self.assertEqual(stat.S_IMODE(self.lib.stat().st_mode), 0o775)
        self.assertFalse(self.parent.exists())

    def test_foreign_or_writable_parent_refuses(self):
        self.parent.mkdir(mode=0o755)
        for uid, gid, mode in ((0, 0, 0o775), (999, 0, 0o755), (0, 988, 0o755)):
            with self.subTest(uid=uid, gid=gid, mode=mode):
                os.chown(self.parent, uid, gid)
                self.parent.chmod(mode)
                with self.assertRaises(AUTO.Refused):
                    self.ensure()
                self.assertFalse(self.runtime.exists())

    def test_parent_and_runtime_symlinks_refuse(self):
        self.parent.symlink_to(self.log, target_is_directory=True)
        with self.assertRaises(OSError):
            self.ensure()
        self.parent.unlink()
        self.parent.mkdir(mode=0o755)
        self.parent.chmod(0o755)
        self.runtime.symlink_to(self.log, target_is_directory=True)
        with self.assertRaises(OSError):
            self.ensure()

    def test_foreign_or_open_runtime_refuses(self):
        self.make_runtime()
        for uid, gid, mode in ((0, 0, 0o755), (999, 0, 0o700), (0, 988, 0o700)):
            with self.subTest(uid=uid, gid=gid, mode=mode):
                os.chown(self.runtime, uid, gid)
                self.runtime.chmod(mode)
                with self.assertRaises(AUTO.Refused):
                    self.ensure()

    def test_existing_leaf_substitution_refuses_and_private_file_survives(self):
        self.make_runtime()
        self.events.write_bytes(b"existing\n")
        self.events.chmod(0o600)
        self.ensure()
        self.assertEqual(self.events.read_bytes(), b"existing\n")
        for uid, gid, mode in ((0, 0, 0o660), (999, 0, 0o600), (0, 988, 0o600)):
            with self.subTest(uid=uid, gid=gid, mode=mode):
                os.chown(self.events, uid, gid)
                self.events.chmod(mode)
                with self.assertRaises(AUTO.Refused):
                    self.ensure()
        os.chown(self.events, 0, 0)
        self.events.chmod(0o600)
        link = self.runtime / "second-name"
        os.link(self.events, link)
        with self.assertRaises(AUTO.Refused):
            self.ensure()
        link.unlink()
        self.events.unlink()
        self.events.symlink_to(self.log)
        with self.assertRaises(OSError):
            self.ensure()
        self.events.unlink()
        os.mkfifo(self.events, 0o600)
        with self.assertRaises(AUTO.Refused):
            self.ensure()


if __name__ == "__main__":
    unittest.main()
