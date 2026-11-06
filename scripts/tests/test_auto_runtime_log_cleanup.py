"""Filesystem controls for the installed AUTO runtime log cleanup wrappers."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
PURGE = SCRIPTS / "purge-installed-aegis.sh"
UNINSTALL = SCRIPTS / "aegis-ubuntu-uninstall.sh"


class RuntimeLogCleanup(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-log-cleanup-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "fixture"
        self.root.mkdir(mode=0o700)
        (self.root / "var").mkdir(mode=0o755)
        (self.root / "var/lib").mkdir(mode=0o755)
        self.logs = self.root / "var/lib/aegis-client-logs"
        self.env = os.environ.copy()
        self.env.update(
            AEGIS_PURGE_ROOT=str(self.root),
            AEGIS_PURGE_TMPDIR=str(self.base),
            AEGIS_UNINSTALL_FAKE_ROOT=str(self.root),
            AEGIS_UNINSTALL_SKIP_ROOT_CHECK="1",
        )

    def make_logs(self, *, service=True):
        # A previous complete purge may have removed the empty /var/lib fixture.
        for parent in (self.root / "var", self.root / "var/lib"):
            parent.mkdir(mode=0o755, exist_ok=True)
            parent.chmod(0o755)
        self.logs.mkdir(mode=0o755)
        self.logs.chmod(0o755)
        names = ("root", "service") if service else ("root",)
        for name in names:
            child = self.logs / name
            child.mkdir(mode=0o700)
            (child / "runtime-events.jsonl").write_text("event\n")
            (child / "runtime-events.jsonl").chmod(0o600)

    def run_purge(self, role="client"):
        return subprocess.run(
            ["bash", str(PURGE), role, "--force"], env=self.env,
            text=True, capture_output=True, timeout=30,
        )

    def run_uninstall(self, action="purge"):
        return subprocess.run(
            ["bash", str(UNINSTALL), action], env=self.env,
            text=True, capture_output=True, timeout=30,
        )

    def assert_refusal_intact(self):
        result = self.run_purge()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("AUTO log cleanup refused", result.stderr)
        self.assertTrue((self.logs / "root/runtime-events.jsonl").exists())
        self.assertTrue((self.logs / "service/runtime-events.jsonl").exists())

    def test_purge_removes_both_roles_and_is_idempotent(self):
        self.make_logs()
        result = self.run_purge()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.logs.exists())
        result = self.run_purge()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_server_scope_preserves_client_log_root(self):
        self.make_logs()
        result = self.run_purge("server")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.logs / "root/runtime-events.jsonl").exists())
        self.assertTrue((self.logs / "service/runtime-events.jsonl").exists())

    def test_all_scope_removes_logs_before_server_helpers(self):
        self.make_logs()
        server = self.root / "usr/local/bin/aegis-server"
        server.parent.mkdir(parents=True)
        server.write_text("server")
        stub_dir = self.base / "bin"
        stub_dir.mkdir()
        rm_stub = stub_dir / "rm"
        rm_stub.write_text(
            "#!/bin/sh\n"
            f"case \"$*\" in *aegis-server*) test ! -e '{self.logs}' || exit 71;; esac\n"
            "exec /bin/rm \"$@\"\n"
        )
        rm_stub.chmod(0o700)
        self.env["PATH"] = f"{stub_dir}:{self.env['PATH']}"
        result = self.run_purge("all")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.logs.exists())
        self.assertFalse(server.exists())

    def test_verify_reports_log_root_and_manual_uninstall_removes_it(self):
        self.make_logs()
        result = self.run_uninstall("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verify=leftover path=/var/lib/aegis-client-logs", result.stdout)
        result = self.run_uninstall()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.logs.exists())
        self.assertIn("verify=clean path=/var/lib/aegis-client-logs", result.stdout)

    def test_bootstrap_helper_sees_logs_removed_before_helper_deletion(self):
        self.make_logs()
        manifest = self.root / "var/lib/aegis-install/client/install-manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("{}")
        marker = self.base / "helper-saw-clean-logs"
        helper = self.base / "purge-helper"
        helper.write_text(
            "#!/bin/bash\n"
            f"test ! -e '{self.logs}' || exit 71\n"
            f"touch '{marker}'\n"
            f"exec '{PURGE}' client --force\n"
        )
        helper.chmod(0o700)
        self.env["AEGIS_UNINSTALL_PURGE_HELPER"] = str(helper)
        result = self.run_uninstall()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(marker.exists(), result.stdout + result.stderr)
        self.assertFalse(manifest.exists())

    def test_v2_owner_refuses_before_log_or_manifest_mutation(self):
        self.make_logs()
        owner = self.root / "var/lib/aegis-auto/control"
        owner.mkdir(parents=True)
        result = self.run_uninstall()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AUTO V2 ownership", result.stderr)
        self.assertTrue((self.logs / "root/runtime-events.jsonl").exists())

    def test_symlink_parent_and_foreign_entry_refuse_without_partial_delete(self):
        self.make_logs()
        foreign = self.logs / "service/foreign"
        foreign.write_text("retain")
        self.assert_refusal_intact()
        foreign.unlink()
        external = self.base / "external"
        external.mkdir()
        (external / "sentinel").write_text("retain")
        shutil.rmtree(self.logs)
        self.logs.symlink_to(external, target_is_directory=True)
        result = self.run_purge()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((external / "sentinel").exists())

    def test_symlink_log_file_refuses_without_partial_delete(self):
        self.make_logs()
        target = self.base / "external-log"
        target.write_text("retain")
        service_log = self.logs / "service/runtime-events.jsonl"
        service_log.unlink()
        service_log.symlink_to(target)
        result = self.run_purge()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("untrusted log file", result.stderr)
        self.assertTrue((self.logs / "root/runtime-events.jsonl").exists())
        self.assertEqual(target.read_text(), "retain")

    def test_hardlink_and_unsafe_mode_refuse_without_partial_delete(self):
        self.make_logs()
        service_log = self.logs / "service/runtime-events.jsonl"
        alias = self.base / "hardlink-alias"
        os.link(service_log, alias)
        self.assert_refusal_intact()
        alias.unlink()
        service_log.chmod(0o622)
        self.assert_refusal_intact()

    def test_fifo_and_wrong_child_mode_refuse_without_partial_delete(self):
        self.make_logs()
        service_log = self.logs / "service/runtime-events.jsonl"
        service_log.unlink()
        os.mkfifo(service_log)
        self.assert_refusal_intact()
        service_log.unlink()
        service_log.write_text("event\n")
        service_log.chmod(0o600)
        (self.logs / "service").chmod(0o755)
        self.assert_refusal_intact()

    def test_standalone_requires_explicit_stopped_unit_readback(self):
        # Source inside a fake root, then exercise only the shell readback
        # function with a stubbed manager; no host systemd command runs.
        self.make_logs()
        source = f"source '{UNINSTALL}'\nROOT_PREFIX=''\n"
        for payload, expected in (
            ("LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0", 0),
            ("LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=99\nControlPID=0", 1),
            ("LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0", 1),
        ):
            script = source + (
                "systemctl() { [[ $1 == stop ]] && return 1; "
                "[[ $1 == show ]] || return 1; cat <<'STATUS'\n"
                + payload + "\nSTATUS\n}\nstop_client_before_log_cleanup\n"
            )
            result = subprocess.run(["bash", "-c", script], env=self.env,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                         "requires Linux root to model distinct service UID/GID")
    def test_distinct_service_identity_and_wrong_owner(self):
        self.make_logs()
        self.env["AEGIS_AUTO_LOG_FIXTURE_SVC_UID"] = "65534"
        self.env["AEGIS_AUTO_LOG_FIXTURE_SVC_GID"] = "65534"
        service = self.logs / "service"
        service_log = service / "runtime-events.jsonl"
        os.chown(service, 65534, 65534)
        os.chown(service_log, 65534, 65534)
        result = self.run_purge()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.make_logs()
        os.chown(self.logs / "service", 65534, 65534)
        self.assert_refusal_intact()


if __name__ == "__main__":
    unittest.main()
