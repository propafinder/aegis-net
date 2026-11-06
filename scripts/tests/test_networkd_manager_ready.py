"""Bounded source hook readiness without touching a host manager or nft."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "aegis-device-egress-guard.sh"


class NetworkdReadyContract(unittest.TestCase):
    def run_hook(self, *, dhcp4, dhcp6, responses, ifindex="3"):
        source = SOURCE.read_text()
        matches = re.findall(r"(?ms)^networkd_ready_lease\(\) \{\n.*?^\}\n", source)
        self.assertEqual(len(matches), 1)
        with tempfile.TemporaryDirectory(prefix="aegis-networkd-ready-") as work:
            rows = Path(work) / "lease-rows"
            rows.write_text("\n".join(responses) + "\n")
            script = ("set -euo pipefail\n"
                      f"manager=systemd-networkd.service; dhcp4={dhcp4}; dhcp6={dhcp6}; "
                      f"manager_ifindex={ifindex}\n"
                      f"rows={rows}\n"
                      "resolve_unit_cgroup() { [[ \"$1\" == systemd-networkd.service && \"$2\" == 1 ]]; }\n"
                      "lease_servers() {\n"
                      "  [[ -s \"$rows\" ]] || return 1\n"
                      "  IFS= read -r line < \"$rows\"\n"
                      "  sed '1d' \"$rows\" > \"$rows.next\"; mv \"$rows.next\" \"$rows\"\n"
                      "  [[ \"$line\" != unavailable ]] || return 1\n"
                      "  printf '%b\\n' \"$line\"\n"
                      "}\n"
                      "sleep() { SECONDS=$((SECONDS+20)); }\n"
                      + matches[0] +
                      "networkd_ready_lease\n")
            return subprocess.run(["bash", "-c", script], capture_output=True,
                                  text=True, timeout=5)

    def test_ipv4_lease_arrival_pins_while_optional_ipv6_absent(self):
        result = self.run_hook(dhcp4=1, dhcp6=1,
                               responses=["3\tnone\tnone", "3\t10.77.0.1\tnone"])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_static_ipv4_with_optional_dhcp6_does_not_wait(self):
        result = self.run_hook(dhcp4=0, dhcp6=1, responses=["unavailable"])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_changed_ifindex_and_missing_lease_refuse(self):
        changed = self.run_hook(dhcp4=1, dhcp6=0,
                                responses=["4\t10.77.0.1\tnone"])
        self.assertNotEqual(changed.returncode, 0)
        missing = self.run_hook(dhcp4=1, dhcp6=1,
                                responses=["3\tnone\tnone"])
        self.assertNotEqual(missing.returncode, 0)


if __name__ == "__main__":
    unittest.main()
