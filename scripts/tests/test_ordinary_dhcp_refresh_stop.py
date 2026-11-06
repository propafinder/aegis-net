"""Source-derived ordinary DHCP Stop ordering; no installed unit mutation."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest


SOURCE = (Path(__file__).resolve().parents[2] /
          "scripts/aegis-device-egress-guard.sh").read_text()


class OrdinaryDhcpStop(unittest.TestCase):
    def test_source_checker_compiles_and_requires_named_loaded_hooks(self):
        body = SOURCE.split("<<'PY_ORDINARY_STOP'\n", 1)[1].split(
            "\nPY_ORDINARY_STOP", 1)[0]
        compile(body, "<ordinary-stop-owner>", "exec")
        for required in ("MainPID", "ControlPID", "InvocationID", "ControlGroup",
                         "FragmentPath", "DropInPaths", "NeedDaemonReload",
                         "ExecStopPost", "/proc/{pid}/exe", "cgroup.events"):
            self.assertIn(required, body)

    def fixture(self, *, capture=True, profile="full-wide-tun",
                owner_ok=True, stop_ok=True):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            state = directory / "device-guard.conf"
            state.write_text("guard")
            (directory / "device-guard.conf.client-binding").write_text("client")
            if capture:
                (directory / "device-guard.conf.capture-binding").write_text("capture")
            lock = directory / "guard.lock"
            lock.touch()
            body = SOURCE.split("ordinary_named_lease_stop() {\n", 1)[1].split(
                "\n}\n\nrefresh_manager_lease_service()", 1)[0]
            body = body.replace("/var/lib/aegis-install/client/device-guard.conf",
                                str(state))
            service = SOURCE.split("refresh_manager_lease_service() {\n", 1)[1].split(
                "\n}\n\ncase \"$ACTION\"", 1)[0]
            script = """
set -euo pipefail
STATE=$1
EVENTS=$2
AUTO_INSTALL=$3
schema=aegis_device_guard_v2
service=aegis-client.service
capture_profile=$5
state_text=guard
client_path=''
manager_path=''
manager=aegis-manager.service
resolved_path=system.slice/aegis-client.service
resolved_invocation=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
fail(){ echo "$*" >> "$EVENTS"; exit 88; }
read_binding(){ echo read-client >> "$EVENTS"; return "${OWNER_REFUSE:-0}"; }
capture_binding_index_legacy(){ echo verify-capture >> "$EVENTS"; printf '2\\n'; }
ordinary_named_lease_stop_facts(){ echo "$1-facts" >> "$EVENTS"; }
timeout(){ echo stop >> "$EVENTS"; [ "${STOP_REFUSE:-0}" = 0 ] || return 1;
  rm -f "$STATE.client-binding" "$STATE.capture-binding"; }
lease_refresh_needed(){ return 0; }
lock_guard(){ flock -w 2 -x 9; echo lock >> "$EVENTS"; }
aegis_root_read(){ cat "$1"; }
auto_stop_pending(){ return 1; }
collect_v2_bindings(){ client_path=''; manager_path=system.slice/manager.service; }
refresh_manager_lease(){ echo refresh >> "$EVENTS"; }
ordinary_named_lease_stop() {
""" + body + """
}
refresh_manager_lease_service() {
""" + service + """
}
exec 9>"$4"
refresh_manager_lease_service
"""
            events = directory / "events"
            result = subprocess.run(["bash", "-c", script, "fixture", str(state),
                                     str(events), str(directory / "no-auto"), str(lock),
                                     profile],
                                    env={**os.environ,
                                         "OWNER_REFUSE": "0" if owner_ok else "1",
                                         "STOP_REFUSE": "0" if stop_ok else "1"},
                                    capture_output=True, text=True, timeout=8)
            return result, events.read_text().splitlines() if events.exists() else []

    def test_changed_lease_stops_before_real_flock_and_refreshes(self):
        result, events = self.fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, ["read-client", "verify-capture", "active-facts",
                                  "stop", "stopped-facts", "lock", "refresh"])

    def test_unadmitted_ordinary_redirect_refuses_without_stop(self):
        result, events = self.fixture(capture=False, profile="wide-redirect-safe")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("stop", events)
        self.assertNotIn("refresh", events)

    def test_missing_capture_or_owner_or_stop_refuses_without_refresh(self):
        for options in ({"capture": False}, {"owner_ok": False},
                        {"stop_ok": False}):
            with self.subTest(options=options):
                result, events = self.fixture(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("refresh", events)
                if not options.get("stop_ok", True):
                    self.assertNotIn("lock", events)


if __name__ == "__main__":
    unittest.main()
