"""The timer never rotates an active capture's immutable guard policy."""

from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = (Path(__file__).resolve().parents[1] /
          "aegis-device-egress-guard.sh").read_text()
FUNCTIONS = SOURCE[SOURCE.index("lease_refresh_needed() {"):
                   SOURCE.index("\ncase \"$ACTION\" in", SOURCE.index("lease_refresh_needed() {"))]


class RefreshService(unittest.TestCase):
    def run_case(self, *, observed="10.77.0.1", stop_ok=True,
                 stop_status="stopped"):
        with tempfile.TemporaryDirectory() as directory:
            script = f"""
set -eu
fail() {{ echo "refused:$*" >&2; exit 1; }}
STATE={directory}/device-guard.conf
AUTO_INSTALL={directory}/auto-guardian-install.json
manager=systemd-networkd.service
schema=aegis_device_guard_v2
state_text=state-v1
manager_ifindex=3
manager_dhcp4_server=10.77.0.1
manager_dhcp6_server=''
client_path=''
manager_path=system.slice/systemd-networkd.service
printf 'receipt-v1\\n' > "$STATE.manager-binding"
touch "$AUTO_INSTALL"
touch {directory}/coordinator
event={directory}/events
aegis_root_read() {{ case "$1" in "$STATE") echo state-v1;; "$STATE.manager-binding") echo receipt-v1;; esac; }}
read_binding() {{ return 0; }}
networkmanager_check() {{ return 0; }}
lease_servers() {{ printf '3\\t{observed}\\tnone\\n'; }}
aegis_root_trusted_executable() {{ return 0; }}
timeout() {{ echo stop >> "$event"; test {'0' if stop_ok else '1'} -eq 0 && echo '{{"status":"{stop_status}"}}'; }}
lock_guard() {{ echo lock >> "$event"; }}
auto_stop_pending() {{ return 1; }}
collect_v2_bindings() {{ echo collect >> "$event"; }}
refresh_manager_lease() {{ echo refresh >> "$event"; }}
revoke_failed_lease_refresh() {{ fail "$*"; }}
{FUNCTIONS.replace("local coordinator='/usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py'", f"local coordinator='{directory}/coordinator'")}
refresh_manager_lease_service
cat "$event" 2>/dev/null || :
"""
            return subprocess.run(["bash", "-c", script], capture_output=True,
                                  text=True, timeout=4)

    def test_same_server_renews_without_lock_or_stop(self):
        result = self.run_case()
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, "", ""))

    def test_server_change_stops_before_new_guard_transaction(self):
        result = self.run_case(observed="10.77.0.2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ["stop", "lock", "collect", "refresh"])

    def test_failed_authenticated_stop_retains_old_pin(self):
        result = self.run_case(observed="10.77.0.2", stop_ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authenticated AUTO Stop refused", result.stderr)
        self.assertNotIn("lock", result.stdout)

    def test_recovery_required_does_not_rotate_pin(self):
        result = self.run_case(observed="10.77.0.2",
                               stop_status="recovery_required")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archived terminal", result.stderr)
        self.assertNotIn("lock", result.stdout)


if __name__ == "__main__":
    unittest.main()
