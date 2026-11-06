"""A late numeric TUN grant also checks the packet's output link kind."""

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))
sys.path.insert(0, str(ROOT / "scripts" / "tests"))

import aegis_auto_guard_policy as policy
import auto_guard_render_harness as harness


def capture_rule(rules):
    found = [row for row in rules["output"] if any(
        expression.get("match", {}).get("left") == {"meta": {"key": "oif"}}
        for expression in row["expr"])]
    assert len(found) == 1
    return found[0]


class TunKindGrant(unittest.TestCase):
    def test_source_renderer_checks_tun_kind_in_both_hooks(self):
        client = {"boot_id": "11111111-2222-3333-4444-555555555555",
                  "state_sha256": "1" * 64, "path": "system.slice/aegis-client.service",
                  "inode": "12", "invocation": "2" * 32}
        rc, batch, error = harness.render(profile="full-wide-tun", uplink="up0",
            management_ports="", client=client, scoped=None, tun_ifindex=9)
        self.assertEqual(rc, 0, error)
        for chain in ("output", "postroute"):
            self.assertIn(f'add rule inet aegis_device_guard {chain} '
                          'meta oif 9 meta oifkind "tun" counter accept', batch)
        self.assertNotIn('oifname "aegis-tun0" counter accept', batch)

    def test_v2_semantic_policy_requires_same_kind_predicate(self):
        state = policy.parse_state(
            b'schema=aegis_device_guard_v2\narmed=1\nservice=aegis-client.service\n'
            b'uplink=up0\nmanager=systemd-networkd.service\n'
            b'capture_interface=aegis-tun0\nmanagement_address_policy=current_local\n'
            b'management_ports=\ndhcp4=0\ndhcp6=0\n'
            b'initramfs_network=absent_verified\n')
        rule = capture_rule(policy._expected(state, None, None,
                                            capture_binding={"ifindex": 9}))
        self.assertIn({"match": {"op": "==", "left": {"meta": {"key": "oifkind"}},
                                 "right": "tun"}}, rule["expr"])

    def test_v1_semantic_policy_requires_same_kind_predicate(self):
        state = {"uplink": "up0", "management_ipv4": "198.18.1.1",
                 "management_ipv6": "", "management_ports": "22",
                 "dhcp4": "0", "dhcp6": "0"}
        rule = capture_rule(policy._legacy_expected(state, None,
                                                    {"ifindex": 9}))
        self.assertIn({"match": {"op": "==", "left": {"meta": {"key": "oifkind"}},
                                 "right": "tun"}}, rule["expr"])


if __name__ == "__main__":
    unittest.main()
