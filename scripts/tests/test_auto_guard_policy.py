"""Countercases for the installed v2 semantic nft policy seal."""
import copy
import hashlib
import json
import subprocess
import sys
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from aegis_auto_guard_policy import (PolicyRefused, _canonical_rules, _expected,
                                     _expected_with_elided_levels, _text_binding_levels,
                                     parse_state, require_capture_profile,
                                     verify_expected_policy)
from aegis_auto_native_witness import NativeWitnessRefused, policy_projection
import aegis_auto_guard_policy as scoped_policy
import aegis_auto_endpoint as endpoint_policy
sys.path.insert(0, str(Path(__file__).resolve().parent))
import auto_guard_render_harness as harness  # noqa: E402

STATE = b"""schema=aegis_device_guard_v2
armed=1
service=aegis-client.service
uplink=eth0
manager=systemd-networkd.service
capture_interface=aegis-tun0
management_address_policy=current_local
management_ports=22
dhcp4=1
dhcp6=1
initramfs_network=absent_verified
"""
BOOT_ID = "11111111-2222-3333-4444-555555555555"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


class LocalOutputRedirectContract(unittest.TestCase):
    """Actual nft 1.0.6 JSON/text control and source policy countercases."""

    def setUp(self):
        self.raw_json = (FIXTURES / "aegis-auto-local-output-nft-1.0.6.json").read_bytes()
        self.raw_text = (FIXTURES / "aegis-auto-local-output-nft-1.0.6.txt").read_bytes()
        row = json.loads(self.raw_json)["nftables"][3]["rule"]
        self.inode = int(row["expr"][0]["match"]["right"])
        self.binding = {"private_unit": "aegis-auto@" + "a" * 64 + ".service",
                        "profile": "output_only_safe", "listen_port": 15080,
                        "management_ports": [], "dhcp4": False,
                        "uplink": "eth0", "manager_binding": None}
        self.bound = {"cgroup_path": "fixture", "cgroup_inode": self.inode}

    def _project(self, raw_json=None, raw_text=None):
        def read(args, **_kw):
            raw = (self.raw_text if "--json" not in args else self.raw_json)
            if "--json" not in args and raw_text is not None:
                raw = raw_text
            if "--json" in args and raw_json is not None:
                raw = raw_json
            return subprocess.CompletedProcess(args, 0, raw, b"")
        with mock.patch.object(scoped_policy, "_scoped_nft", side_effect=read), \
             mock.patch.object(scoped_policy, "_local_intent", return_value={
                 "owner_marker": "aegis-local-control"}):
            return scoped_policy._local_projection(self.binding, self.bound)

    def test_real_nft_json_and_text_are_both_required(self):
        observed = self._project()
        self.assertEqual(set(observed), {
            "policy_sha256", "output_chain_handle", "cgroup_exempt_handle",
            "dns_redirect_handle", "loopback_exempt_handle",
            "tcp_redirect_handle"})
        self.assertEqual(observed["tcp_redirect_handle"], 5)
        self.assertEqual(observed["dns_redirect_handle"], 3)
        self.assertEqual(self.raw_text.count(b"socket cgroupv2 level 1"), 1)

    def test_real_nft_countercases_refuse(self):
        rows = json.loads(self.raw_json)
        modified = copy.deepcopy(rows)
        modified["nftables"][3]["rule"]["expr"][0]["match"]["right"] = \
            str(self.inode + 1)
        with self.assertRaises(PolicyRefused):
            self._project(raw_json=encoded(modified))
        modified = copy.deepcopy(rows)
        modified["nftables"][4]["rule"]["expr"][0]["match"]["right"] = 54
        with self.assertRaises(PolicyRefused):
            self._project(raw_json=encoded(modified))
        modified = copy.deepcopy(rows)
        modified["nftables"].append(copy.deepcopy(modified["nftables"][6]))
        with self.assertRaises(PolicyRefused):
            self._project(raw_json=encoded(modified))
        with self.assertRaises(PolicyRefused):
            self._project(raw_text=self.raw_text.replace(
                b"socket cgroupv2 level 1", b"socket cgroupv2 level 2"))
        with self.assertRaises(PolicyRefused):
            self._project(raw_text=self.raw_text.replace(
                b"# handle 2", b"# handle 9"))

    def test_output_renderer_captures_all_ipv4_tcp_and_dns_before_loopback(self):
        with mock.patch.object(scoped_policy, "_local_intent", return_value={
                "owner_marker": "aegis-local-control"}):
            source = scoped_policy._local_script(self.binding, self.bound).decode()
        self.assertLess(source.index("socket cgroupv2"), source.index("udp dport 53"))
        self.assertLess(source.index("udp dport 53"), source.index('oifname "lo"'))
        self.assertLess(source.index('oifname "lo"'),
                        source.index("meta l4proto tcp"))
        self.assertNotIn("192.0.2.251", source)
        self.assertNotIn("udp dport !=", source)

    def test_fulltun_renderer_adds_only_generic_ipv4_udp_carry(self):
        binding = dict(self.binding, profile="full_wide_tun",
                       listen_port=980, udp_port=981)
        with mock.patch.object(scoped_policy, "_local_intent", return_value={
                "owner_marker": "aegis-local-control"}):
            source = scoped_policy._local_script(binding, self.bound).decode()
            expected = scoped_policy._local_expected(binding, self.bound)
        self.assertLess(source.index("udp dport 53"),
                        source.index('oifname "lo"'))
        self.assertLess(source.index('oifname "lo"'),
                        source.index("meta l4proto udp"))
        self.assertLess(source.index("meta l4proto udp"),
                        source.index("meta l4proto tcp"))
        self.assertIn("redirect to :981", source)
        self.assertIn("redirect to :980", source)
        self.assertEqual(len([row for row in expected if "rule" in row]), 5)

    def test_management_exemptions_require_guard_tuple_and_manager_cgroup(self):
        manager = {"schema": "aegis_device_guard_binding_v1",
                   "boot_id": BOOT_ID, "state_sha256": "1" * 64,
                   "path": "system.slice/systemd-networkd.service",
                   "inode": "12345", "invocation": "2" * 32}
        binding = dict(self.binding, management_ports=[22], dhcp4=True,
                       manager_binding=manager)
        with mock.patch.object(scoped_policy, "_local_intent", return_value={
                "owner_marker": "aegis-local-control"}):
            script = scoped_policy._local_script(binding, self.bound).decode()
            rules = [row["rule"] for row in
                     scoped_policy._local_expected(binding, self.bound)
                     if "rule" in row]
        self.assertLess(script.index("ct direction reply"),
                        script.index("udp dport 53"))
        self.assertLess(script.index("udp sport 68 udp dport 67"),
                        script.index("output meta l4proto tcp counter redirect"))
        self.assertIn('oifname "eth0" meta l4proto tcp ct direction reply '
                      'ct mark 0xa3610002 '
                      'ct original proto-dst 22 tcp sport 22', script)
        self.assertIn('socket cgroupv2 level 2 '
                      '"system.slice/systemd-networkd.service"', script)
        self.assertEqual(len(rules), 6)
        self.assertEqual(rules[1]["expr"][2]["match"]["right"], 0xa3610002)
        self.assertEqual(rules[2]["expr"][3]["match"]["right"],
                         manager["path"])
        with self.assertRaises(PolicyRefused):
            scoped_policy._local_binding(
                dict(binding, manager_binding=dict(manager, inode="0")),
                check_host=False)

    def test_actual_management_json_text_readback_refuses_tuple_tamper(self):
        raw_json = (FIXTURES /
                    "aegis-auto-management-local-output-nft-1.0.6.json").read_bytes()
        raw_text = (FIXTURES /
                    "aegis-auto-management-local-output-nft-1.0.6.txt").read_bytes()
        parsed = json.loads(raw_json)
        rules = [item["rule"] for item in parsed["nftables"] if "rule" in item]
        manager_path = rules[2]["expr"][3]["match"]["right"]
        marker = rules[0]["comment"]
        bound = {"cgroup_path": "/", "cgroup_inode": int(
            rules[0]["expr"][0]["match"]["right"])}
        binding = dict(self.binding, profile="full_wide_tun", listen_port=980,
                       udp_port=15081, uplink="veth0", management_ports=[22],
                       dhcp4=True, manager_binding={"path": manager_path,
                                                       "inode": "12345"})
        def project(payload=raw_json, text=raw_text):
            def read(args, **_kw):
                return subprocess.CompletedProcess(
                    args, 0, payload if "--json" in args else text, b"")
            with mock.patch.object(scoped_policy, "_scoped_nft", side_effect=read), \
                 mock.patch.object(scoped_policy, "_local_intent", return_value={
                     "owner_marker": marker}):
                return scoped_policy._local_projection(binding, bound)
        actual = project()
        self.assertEqual(actual["management_reply_22_handle"], 3)
        self.assertEqual(actual["dhcp4_exempt_handle"], 4)
        for row, expression, wrong in ((1, 2, 0), (1, 3, 23),
                                       (2, 1, 69), (2, 3, "foreign")):
            changed = copy.deepcopy(parsed)
            entries = [item["rule"] for item in changed["nftables"]
                       if "rule" in item]
            entries[row]["expr"][expression]["match"]["right"] = wrong
            with self.assertRaises(PolicyRefused):
                project(encoded(changed))
        with self.assertRaises(PolicyRefused):
            project(text=raw_text.replace(
                b"socket cgroupv2 level 2", b"socket cgroupv2 level 1"))

    def test_real_fulltun_nft_readback_and_udp_tamper(self):
        raw_json = (FIXTURES /
                    "aegis-auto-fulltun-local-output-nft-1.0.6.json").read_bytes()
        raw_text = (FIXTURES /
                    "aegis-auto-fulltun-local-output-nft-1.0.6.txt").read_bytes()
        parsed = json.loads(raw_json)
        inode = int(parsed["nftables"][3]["rule"]["expr"][0]["match"]["right"])
        binding = dict(self.binding, profile="full_wide_tun", listen_port=980,
                       udp_port=981)
        bound = {"cgroup_path": "/", "cgroup_inode": inode}
        # The actual marker is retained in every kernel rule and text line.
        marker = parsed["nftables"][3]["rule"]["comment"]
        def read(args, **_kw):
            return subprocess.CompletedProcess(
                args, 0, raw_json if "--json" in args else raw_text, b"")
        with mock.patch.object(scoped_policy, "_scoped_nft", side_effect=read), \
             mock.patch.object(scoped_policy, "_local_intent",
                               return_value={"owner_marker": marker}):
            observed = scoped_policy._local_projection(binding, bound)
        self.assertIn("udp_redirect_handle", observed)
        self.assertEqual(len(set(observed.values())), len(observed))
        bad = copy.deepcopy(parsed)
        bad["nftables"][6]["rule"]["expr"][-1]["redirect"]["port"] = 982
        with mock.patch.object(scoped_policy, "_scoped_nft",
                               side_effect=lambda args, **_kw:
                               subprocess.CompletedProcess(
                                   args, 0, encoded(bad) if "--json" in args
                                   else raw_text, b"")), \
             mock.patch.object(scoped_policy, "_local_intent",
                               return_value={"owner_marker": marker}):
            with self.assertRaises(PolicyRefused):
                scoped_policy._local_projection(binding, bound)

    def test_fulltun_rendered_pair_is_980_981_and_own_dns(self):
        config = (b"[ingress]\nprimary='wide'\n[ingress.wide]\n"
                  b"enabled=true\nplatform_backend='linux_redirect'\n"
                  b"listen='127.0.0.1:980'\nipv6_tun_carried=true\n"
                  b"capture_dns=true\ndns_preview_listen='127.0.0.1:53'\n"
                  b"udp_capture_contract='generic_capture_unstable'\n")
        recipe = {"context": {"mode": "FullWideTun"}}
        self.assertEqual(endpoint_policy._local_fulltun_values(recipe, config)[:4],
                         ("127.0.0.1", 980, 53, 981))
        for changed in (config.replace(b":980", b":981"),
                        config.replace(b"capture_dns=true", b"capture_dns=false"),
                        config.replace(b"generic_capture_unstable",
                                       b"preview_allowlist_only"),
                        config + b"udp_redirect_port=0\n",
                        config + b"udp_redirect_port=65536\n",
                        config + b"udp_redirect_port=53\n",
                        config + b"udp_redirect_port=980\n"):
            with self.assertRaises(Exception):
                endpoint_policy._local_fulltun_values(recipe, changed)
        self.assertEqual(endpoint_policy._local_fulltun_values(
            recipe, config + b"udp_redirect_port=15081\n")[3], 15081)

    def test_bound_receipt_survives_stopped_private_cgroup(self):
        binding = {
            "stage_dev": 1, "stage_ino": 2,
            "private_unit": "aegis-auto@" + "a" * 64 + ".service",
            "transaction_nonce": "b" * 32,
            "planned_generation": "c" * 64,
            "boot_id": BOOT_ID, "netns_ino": 3,
            "config_sha256_initial": "d" * 64,
            "config_semantic_sha256": "e" * 64,
            "listen_ipv4": "127.0.0.1", "listen_port": 15080,
            "dns_port": 53, "udp_port": None,
            "profile": "output_only_safe", "first_arm_sha256": None,
            "guard_policy_sha256": "f" * 64,
            "guard_state_sha256": "1" * 64, "uplink": "eth0",
            "management_ports": [], "dhcp4": False, "manager_binding": None,
        }
        intent = scoped_policy._local_intent(binding)
        bound = {"schema": "aegis_auto_local_redirect_bound_v1",
                 "intent_sha256": scoped_policy._scoped_hash(intent),
                 "invocation_id": "1" * 32,
                 "cgroup_path": "system.slice/" + binding["private_unit"],
                 "cgroup_inode": 12345}
        def held_receipt(path):
            return intent if path == scoped_policy.LOCAL_INTENT else bound
        with mock.patch.object(scoped_policy, "_scoped_read",
                               side_effect=held_receipt):
            self.assertEqual(scoped_policy._local_bound(
                binding, bound["invocation_id"], check_host=False), bound)
            changed = dict(bound, cgroup_inode=0)
            with mock.patch.object(scoped_policy, "_scoped_read",
                                   side_effect=lambda path: intent if path ==
                                   scoped_policy.LOCAL_INTENT else changed):
                with self.assertRaises(PolicyRefused):
                    scoped_policy._local_bound(
                        binding, bound["invocation_id"], check_host=False)

    def test_fulltun_binding_requires_exact_receipt_and_runtime_ports(self):
        binding = {
            "stage_dev": 1, "stage_ino": 2,
            "private_unit": "aegis-auto@" + "a" * 64 + ".service",
            "transaction_nonce": "b" * 32,
            "planned_generation": "c" * 64,
            "boot_id": BOOT_ID, "netns_ino": 3,
            "config_sha256_initial": "d" * 64,
            "config_semantic_sha256": "e" * 64,
            "listen_ipv4": "127.0.0.1", "listen_port": 980,
            "dns_port": 53, "udp_port": 981,
            "profile": "full_wide_tun", "first_arm_sha256": "2" * 64,
            "guard_policy_sha256": "f" * 64,
            "guard_state_sha256": "1" * 64, "uplink": "eth0",
            "management_ports": [], "dhcp4": False, "manager_binding": None,
        }
        self.assertEqual(scoped_policy._local_binding(
            binding, check_host=False), binding)
        alternate = dict(binding, udp_port=15081)
        self.assertEqual(scoped_policy._local_binding(
            alternate, check_host=False), alternate)
        with mock.patch.object(scoped_policy, "_local_intent", return_value={
                "owner_marker": "aegis-local-control"}):
            self.assertIn("redirect to :15081",
                          scoped_policy._local_script(alternate,
                                                      self.bound).decode())
        for key, wrong in (("listen_port", 15080), ("udp_port", 0),
                           ("first_arm_sha256", None),
                           ("profile", "output_only_safe")):
            with self.assertRaises(PolicyRefused):
                scoped_policy._local_binding(
                    dict(binding, **{key: wrong}), check_host=False)

    def test_local_rendered_config_is_exact_and_scoped_remains_distinct(self):
        config = (b"[ingress]\nprimary='wide'\n[ingress.wide]\n"
                  b"enabled=true\nplatform_backend='linux_redirect'\n"
                  b"rollout_profile='output_only_safe'\nlisten='127.0.0.1:15080'\n"
                  b"dns_preview_listen='127.0.0.1:53'\n"
                  b"dns_preview_fake_ip_pool='198.18.0.0/15'\n"
                  b"dns_preview_fake_ip_ttl_secs=60\n"
                  b"udp_capture_contract='preview_allowlist_only'\n")
        recipe = {"context": {"mode": "WideRedirectSafe"}}
        self.assertEqual(endpoint_policy._local_redirect_values(
            recipe, config)[:3], ("127.0.0.1", 15080, 53))
        self.assertIsNone(endpoint_policy._scoped_redirect_values(recipe, config))
        for changed in (config.replace(b"127.0.0.1:53", b"127.0.0.1:54"),
                        config.replace(b"output_only_safe", b"prerouting_scoped"),
                        config.replace(b"preview_allowlist_only", b"generic_capture")):
            with self.assertRaises(Exception):
                endpoint_policy._local_redirect_values(recipe, changed)


def kernel_rows(state=STATE, client=None, manager=None, scoped_reply=None,
                capture_binding=None):
    rules = _expected(parse_state(state), client, manager, scoped_reply,
                      capture_binding=capture_binding)
    rows = [{"table": {"family": "inet", "name": "aegis_device_guard", "handle": 1}}]
    for name, hook, prio, policy in (("incoming", "prerouting", -190, "accept"),
                                     ("output", "output", 2147483647, "drop"),
                                     ("forward", "forward", 10, "drop"),
                                     ("postroute", "postrouting", 2147483647, "drop")):
        rows.append({"chain": {"family": "inet", "table": "aegis_device_guard",
                               "name": name, "type": "filter", "hook": hook,
                               "prio": prio, "policy": policy, "handle": len(rows) + 1}})
    for chain in ("incoming", "output", "forward", "postroute"):
        for rule in rules[chain]:
            row = copy.deepcopy(rule)
            row["handle"] = len(rows) + 1
            rows.append({"rule": row})
    return {"nftables": rows}


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def kernel_text(table):
    lines = []
    for item in table["nftables"]:
        kind, row = next(iter(item.items()))
        if kind == "table":
            lines.append(f'table inet aegis_device_guard {{ # handle {row["handle"]}')
        elif kind == "chain":
            lines.append(f' chain {row["name"]} {{ # handle {row["handle"]}')
        elif kind == "rule":
            numeric = [expr["match"]["right"] for expr in row["expr"]
                       if "match" in expr and
                       expr["match"].get("left") == {"meta": {"key": "oif"}}]
            if numeric and "comment" not in row:
                lines.append(f'  meta oif {numeric[0]} counter packets 0 bytes 0 '
                             f'accept # handle {row["handle"]}')
                continue
            if "comment" in row:
                if row["comment"].startswith("aegis-post-"):
                    prefix = f'meta oif {numeric[0]} ' if numeric else ''
                    lines.append(f'  {prefix}meta mark counter accept comment "{row["comment"]}" # handle {row["handle"]}')
                    continue
                if row["comment"].startswith("aegis-auto-scoped-reply-"):
                    lines.append(f'  tcp flags & (syn | ack) == syn | ack '
                                 f'counter accept comment "{row["comment"]}" '
                                 f'# handle {row["handle"]}')
                    continue
                socket = next(expression["match"]["left"]["socket"]
                              for expression in row["expr"]
                              if "match" in expression and
                              "socket" in expression["match"]["left"])
                path = next(expression["match"]["right"]
                            for expression in row["expr"]
                            if "match" in expression and
                            "socket" in expression["match"]["left"])
                prefix = f'meta oif {numeric[0]} ' if numeric else ''
                lines.append(f'  {prefix}socket cgroupv2 level {socket["level"]} "{path}" '
                             f'counter packets 0 bytes 0 accept comment "{row["comment"]}" '
                             f'# handle {row["handle"]}')
            else:
                lines.append(f'  counter drop # handle {row["handle"]}')
    return ("\n".join(lines) + "\n").encode()


class PolicySealTests(unittest.TestCase):
    def test_legacy_capture_requires_real_nonpersistent_tun_detail(self):
        detail = {'ifname': 'aegis-tun0', 'ifindex': 37,
                  'linkinfo': {'info_kind': 'tun',
                               'info_data': {'type': 'tun', 'persist': False}}}
        with mock.patch.object(scoped_policy.subprocess, 'run') as run, \
             mock.patch('aegis_auto_guard_policy.socket.if_nametoindex', return_value=37):
            run.return_value = mock.Mock(returncode=0, stderr=b'')
            for field, value in ((None, None), ('info_kind', 'dummy'),
                                 ('type', 'tap'), ('persist', True),
                                 ('ifindex', 38)):
                changed = copy.deepcopy(detail)
                if field == 'info_kind':
                    changed['linkinfo']['info_kind'] = value
                elif field in ('type', 'persist'):
                    changed['linkinfo']['info_data'][field] = value
                elif field == 'ifindex':
                    changed[field] = value
                run.return_value.stdout = json.dumps([changed]).encode()
                if field is None:
                    scoped_policy._legacy_tun_detail(37)
                else:
                    with self.assertRaises(PolicyRefused):
                        scoped_policy._legacy_tun_detail(37)

    @mock.patch.object(scoped_policy.socket, "if_nametoindex", return_value=37)
    def test_late_numeric_capture_grant_requires_exact_receipt_and_text(self, _index):
        client = {"schema": "aegis_device_guard_binding_v1",
                  "boot_id": BOOT_ID,
                  "state_sha256": hashlib.sha256(STATE.rstrip(b"\n")).hexdigest(),
                  "path": "system.slice/aegis-auto@" + "a" * 64 + ".service",
                  "inode": "1234", "invocation": "b" * 32}
        capture = {"schema": "aegis_device_guard_capture_binding_v1",
                   "boot_id": BOOT_ID, "netns_ino": 99,
                   "private_unit": client["path"].rsplit("/", 1)[-1],
                   "invocation_id": "b" * 32, "main_pid": 2345,
                   "ifindex": 37, "worker_sha256": "c" * 64,
                   "client_path": client["path"],
                   "client_inode": client["inode"],
                   "client_invocation": client["invocation"]}
        before = kernel_rows(client=client)
        self.assertEqual(64, len(verify_expected_policy(
            STATE, encoded(before), kernel_text(before),
            client_binding=client, boot_id=BOOT_ID)))
        after = kernel_rows(client=client, capture_binding=capture)
        text = kernel_text(after)
        self.assertEqual(64, len(verify_expected_policy(
            STATE, encoded(after), text, client_binding=client,
            capture_binding=capture, boot_id=BOOT_ID)))
        with self.assertRaises(PolicyRefused):
            verify_expected_policy(STATE, encoded(after), text,
                                   client_binding=client, boot_id=BOOT_ID)
        with self.assertRaises(PolicyRefused):
            verify_expected_policy(STATE, encoded(before), kernel_text(before),
                                   client_binding=client, capture_binding=capture,
                                   boot_id=BOOT_ID)
        with self.assertRaises(PolicyRefused):
            verify_expected_policy(STATE, encoded(after),
                                   text.replace(b'meta oif 37', b'meta oif 38'),
                                   client_binding=client, capture_binding=capture,
                                   boot_id=BOOT_ID)

    def test_live_nft_oif_name_resolution_still_binds_numeric_index(self):
        client = {"schema": "aegis_device_guard_binding_v1",
                  "boot_id": BOOT_ID,
                  "state_sha256": hashlib.sha256(STATE.rstrip(b"\n")).hexdigest(),
                  "path": "system.slice/aegis-auto@" + "a" * 64 + ".service",
                  "inode": "1234", "invocation": "b" * 32}
        capture = {"schema": "aegis_device_guard_capture_binding_v1",
                   "boot_id": BOOT_ID, "netns_ino": 99,
                   "private_unit": client["path"].rsplit("/", 1)[-1],
                   "invocation_id": "b" * 32, "main_pid": 2345,
                   "ifindex": 37, "worker_sha256": "c" * 64,
                   "client_path": client["path"],
                   "client_inode": client["inode"],
                   "client_invocation": client["invocation"]}
        rows = kernel_rows(client=client, capture_binding=capture)
        resolved = copy.deepcopy(rows)
        numeric = [expression["match"] for item in resolved["nftables"]
                   if "rule" in item for expression in item["rule"]["expr"]
                   if "match" in expression and
                   expression["match"].get("left") == {"meta": {"key": "oif"}}]
        self.assertEqual(len(numeric), 2)
        for match in numeric:
            match["right"] = "aegis-tun0"
        text = kernel_text(rows).replace(b'meta oif 37', b'oif "aegis-tun0"')
        with mock.patch.object(scoped_policy.socket, "if_nametoindex", return_value=37):
            self.assertEqual(64, len(verify_expected_policy(
                STATE, encoded(resolved), text, client_binding=client,
                capture_binding=capture, boot_id=BOOT_ID)))
            mismatched_invocation = {**capture, "invocation_id": "d" * 32}
            with self.assertRaises(PolicyRefused):
                verify_expected_policy(STATE, encoded(resolved), text,
                    client_binding=client, capture_binding=mismatched_invocation,
                    boot_id=BOOT_ID)
        with mock.patch.object(scoped_policy.socket, "if_nametoindex", return_value=38):
            with self.assertRaises(PolicyRefused):
                verify_expected_policy(STATE, encoded(resolved), text,
                    client_binding=client, capture_binding=capture, boot_id=BOOT_ID)
        disguised = copy.deepcopy(resolved)
        for item in disguised["nftables"]:
            if "rule" not in item:
                continue
            for expression in item["rule"]["expr"]:
                if expression.get("match", {}).get("left") == {"meta": {"key": "oif"}}:
                    expression["match"]["left"]["meta"]["key"] = "oifname"
        with mock.patch.object(scoped_policy.socket, "if_nametoindex", return_value=37):
            with self.assertRaises(PolicyRefused):
                verify_expected_policy(STATE, encoded(disguised), text,
                    client_binding=client, capture_binding=capture, boot_id=BOOT_ID)

    def test_manager_dhcp_acquisition_destinations_are_exact_in_both_hooks(self):
        manager = {"schema": "aegis_device_guard_binding_v2",
                   "ifindex": 3, "dhcp4_server": None, "dhcp6_server": None,
                   "path": "system.slice/systemd-networkd.service",
                   "inode": "12345", "invocation": "2" * 32,
                   "boot_id": BOOT_ID, "state_sha256": "1" * 64}
        rules = _expected(parse_state(STATE), None, manager)
        for chain in ("output", "postroute"):
            dhcp = [rule for rule in rules[chain]
                    if rule.get("comment", "").startswith("aegis-")]
            self.assertEqual(len(dhcp), 2)
            for rule in dhcp:
                self.assertIn({"op": "==", "left": {"meta": {"key": "oif"}},
                               "right": 3},
                              [expr["match"] for expr in rule["expr"]
                               if "match" in expr])
            actual = {}
            for rule in dhcp:
                matches = [expr["match"] for expr in rule["expr"]
                           if "match" in expr]
                family = next(("ipv4" if match["left"]["payload"]["protocol"] == "ip"
                               else "ipv6") for match in matches
                              if isinstance(match.get("left"), dict) and
                              isinstance(match["left"].get("payload"), dict) and
                              match["left"]["payload"].get("field") == "daddr")
                actual[family] = next(match["right"] for match in matches
                                      if match["left"] ==
                                      {"payload": {"protocol":
                                                   "ip" if family == "ipv4" else "ip6",
                                                   "field": "daddr"}})
            self.assertEqual(actual, {"ipv4": "255.255.255.255",
                                      "ipv6": "ff02::1:2"})

    def test_manager_v2_server_pin_is_exact_in_both_final_hooks(self):
        manager = {"schema": "aegis_device_guard_binding_v2",
                   "path": "system.slice/systemd-networkd.service",
                   "inode": "12345", "invocation": "2" * 32,
                   "boot_id": BOOT_ID,
                   "state_sha256": hashlib.sha256(STATE.rstrip(b"\n")).hexdigest(),
                   "ifindex": 3, "dhcp4_server": "10.77.0.1",
                   "dhcp6_server": "fd00:77::1"}
        rules = _expected(parse_state(STATE), None, manager)
        for chain in ("output", "postroute"):
            dhcp = [rule for rule in rules[chain]
                    if rule.get("comment", "").startswith("aegis-")]
            self.assertEqual(len(dhcp), 2)
            destinations = [expr["match"]["right"] for rule in dhcp
                            for expr in rule["expr"] if "match" in expr and
                            expr["match"]["left"].get("payload", {}).get("field") ==
                            "daddr"]
            self.assertEqual(destinations,
                             [{"set": ["10.77.0.1", "255.255.255.255"]},
                              {"set": ["fd00:77::1", "ff02::1:2"]}])
        table = kernel_rows(STATE, manager=manager)
        with mock.patch.object(scoped_policy.socket, "if_nametoindex", return_value=3):
            verify_expected_policy(STATE, encoded(table), kernel_text(table),
                                   None, manager, boot_id=BOOT_ID)
        for wrong in ("203.0.113.7", "255.255.255.255", "127.0.0.1"):
            altered = dict(manager, dhcp4_server=wrong)
            with self.assertRaises(PolicyRefused):
                verify_expected_policy(STATE, encoded(table), kernel_text(table),
                                       None, altered, boot_id=BOOT_ID)

    def test_combined_numeric_capture_and_manager_resolved_readback(self):
        state_sha = hashlib.sha256(STATE.rstrip(b"\n")).hexdigest()
        client = {"schema": "aegis_device_guard_binding_v1",
                  "boot_id": BOOT_ID, "state_sha256": state_sha,
                  "path": "system.slice/aegis-auto@" + "a" * 64 + ".service",
                  "inode": "1234", "invocation": "b" * 32}
        manager = {"schema": "aegis_device_guard_binding_v2",
                   "boot_id": BOOT_ID, "state_sha256": state_sha,
                   "path": "system.slice/systemd-networkd.service",
                   "inode": "12345", "invocation": "2" * 32,
                   "ifindex": 3, "dhcp4_server": "10.77.0.1",
                   "dhcp6_server": "fd00:77::1"}
        capture = {"schema": "aegis_device_guard_capture_binding_v1",
                   "boot_id": BOOT_ID, "netns_ino": 99,
                   "private_unit": client["path"].rsplit("/", 1)[-1],
                   "invocation_id": client["invocation"], "main_pid": 2345,
                   "ifindex": 37, "worker_sha256": "c" * 64,
                   "client_path": client["path"], "client_inode": client["inode"],
                   "client_invocation": client["invocation"]}
        table = kernel_rows(STATE, client=client, manager=manager,
                            capture_binding=capture)
        text = kernel_text(table)
        resolved = copy.deepcopy(table)
        manager_marker = scoped_policy._marker(manager, "manager")
        manager_post_marker = manager_marker.replace("aegis-v2-", "aegis-post-", 1)
        for item in resolved["nftables"]:
            if "rule" not in item:
                continue
            rule = item["rule"]
            role = "eth0" if rule.get("comment") in (
                manager_marker, manager_post_marker) else "aegis-tun0"
            for expr in rule["expr"]:
                if expr.get("match", {}).get("left") == {"meta": {"key": "oif"}}:
                    number = expr["match"]["right"]
                    expr["match"]["right"] = role
                    text = text.replace(f"meta oif {number} ".encode(),
                                        f'oif "{role}" '.encode(), 1)
        indexes = {"eth0": 3, "aegis-tun0": 37}
        with mock.patch.object(scoped_policy.socket, "if_nametoindex",
                               side_effect=lambda name: indexes[name]):
            self.assertEqual(64, len(verify_expected_policy(
                STATE, encoded(resolved), text, client, manager,
                boot_id=BOOT_ID, capture_binding=capture)))
            for changed in (dict(manager, ifindex=4),
                            dict(manager, dhcp4_server="10.77.0.2")):
                with self.assertRaises(PolicyRefused):
                    verify_expected_policy(STATE, encoded(resolved), text, client,
                                           changed, boot_id=BOOT_ID,
                                           capture_binding=capture)
            forged = copy.deepcopy(resolved)
            for item in forged["nftables"]:
                if "rule" not in item:
                    continue
                for expr in item["rule"]["expr"]:
                    match = expr.get("match", {})
                    if match.get("left", {}).get("payload", {}).get("field") == "daddr" and match.get("right") == {"set": ["10.77.0.1", "255.255.255.255"]}:
                        match["right"] = {"set": ["10.77.0.2", "255.255.255.255"]}
            with self.assertRaises(PolicyRefused):
                verify_expected_policy(STATE, encoded(forged), text, client,
                                       manager, boot_id=BOOT_ID,
                                       capture_binding=capture)
            disguised = copy.deepcopy(resolved)
            for item in disguised["nftables"]:
                if "rule" not in item:
                    continue
                for expr in item["rule"]["expr"]:
                    if expr.get("match", {}).get("left") == {"meta": {"key": "oif"}}:
                        expr["match"]["left"]["meta"]["key"] = "oifname"
            with self.assertRaises(PolicyRefused):
                verify_expected_policy(STATE, encoded(disguised), text, client,
                                       manager, boot_id=BOOT_ID,
                                       capture_binding=capture)
        with mock.patch.object(scoped_policy.socket, "if_nametoindex",
                               side_effect=lambda name: 4 if name == "eth0" else 37):
            with self.assertRaises(PolicyRefused):
                verify_expected_policy(STATE, encoded(resolved), text, client,
                                       manager, boot_id=BOOT_ID,
                                       capture_binding=capture)
        with mock.patch.object(scoped_policy.socket, "if_nametoindex",
                               side_effect=OSError("missing")):
            with self.assertRaises(PolicyRefused):
                verify_expected_policy(STATE, encoded(resolved), text, client,
                                       manager, boot_id=BOOT_ID,
                                       capture_binding=capture)

    def test_profiled_redirect_omits_tun_grant_and_refuses_legacy_readback(self):
        redirect = STATE + b"capture_profile=wide-redirect-safe\n"
        full = STATE + b"capture_profile=full-wide-tun\n"
        require_capture_profile(parse_state(STATE), "full-wide-tun")
        require_capture_profile(parse_state(full), "full-wide-tun")
        require_capture_profile(parse_state(redirect), "wide-redirect-safe")
        for state, mode in ((STATE, "wide-redirect-safe"),
                            (redirect, "full-wide-tun"),
                            (redirect, "socks-only")):
            with self.assertRaises(PolicyRefused):
                require_capture_profile(parse_state(state), mode)
        self.assertEqual(_expected(parse_state(STATE), None, None),
                         _expected(parse_state(full), None, None))
        old_rules = _expected(parse_state(STATE), None, None)["output"]
        redirect_rules = _expected(parse_state(redirect), None, None)["output"]
        self.assertEqual(old_rules, redirect_rules)
        self.assertNotIn('"right": "aegis-tun0"', json.dumps(old_rules))
        self.assertNotIn('"right": "aegis-tun0"', json.dumps(redirect_rules))
        actual = kernel_rows(redirect)
        self.assertEqual(64, len(verify_expected_policy(
            redirect, encoded(actual), kernel_text(actual), boot_id=BOOT_ID)))
        # A late-created or renamed interface cannot turn the old TUN rule
        # into a Redirect grant: exact semantic readback rejects the rule.
        legacy = kernel_rows()
        legacy["nftables"].append({"rule": {
            **scoped_policy._rule("output", scoped_policy._accept([
                scoped_policy._cmp(scoped_policy._meta("oifname"), "aegis-tun0")])),
            "handle": 999}})
        with self.assertRaises(PolicyRefused):
            verify_expected_policy(redirect, encoded(legacy), kernel_text(legacy),
                                   boot_id=BOOT_ID)
        for suffix in (b"capture_profile=\n",
                       b"capture_profile=unknown\n",
                       b"capture_profile=wide-redirect-safe\ncapture_profile=full-wide-tun\n"):
            with self.assertRaises(PolicyRefused):
                parse_state(STATE + suffix)

    def test_actual_ubuntu_nft109_unbound_readback(self):
        # Exact bytes captured from the unchanged helper renderer in an
        # isolated Ubuntu 24.04 namespace; source-and-shape.json in the
        # retained native-runner artifact records the source and raw hashes.
        raw = (FIXTURES / "auto_guard_nft109_unbound.json").read_bytes()
        text = (FIXTURES / "auto_guard_nft109_unbound.txt").read_bytes()
        self.assertEqual("657f121f7d6b8fff74ba4f355291dd3df094b3751d8e64e84ed77e2cc775cbe1",
                         hashlib.sha256(raw).hexdigest())
        self.assertEqual("44031af4be8d79cff43fb5f755d5abca7b32911f4be7cb2b14c8a4c7f1395fc3",
                         hashlib.sha256(text).hexdigest())
        with self.assertRaises(PolicyRefused):
            verify_expected_policy(STATE, raw, text, boot_id=BOOT_ID)
        with self.assertRaises(PolicyRefused):
            verify_expected_policy(STATE, raw, text.replace(b"# handle 12", b"# handle 999"),
                                   boot_id=BOOT_ID)
        widened = json.loads(raw)
        widened["nftables"][6]["rule"]["expr"] = [{"accept": None}]
        with self.assertRaises(PolicyRefused):
            verify_expected_policy(STATE, encoded(widened), text, boot_id=BOOT_ID)

    def test_actual_ubuntu_nft109_bound_rule_shape(self):
        # The native diagnostic used ssh.service as a parser input; public
        # verifier intentionally refuses it as a production client binding.
        raw = (FIXTURES / "auto_guard_nft109_bound_both.json").read_bytes()
        text = (FIXTURES / "auto_guard_nft109_bound_both.txt").read_bytes()
        self.assertEqual("6e71e024ab0d6c914bce3b5c0539ee37e70d7b1061b706ed408301c570a191c9",
                         hashlib.sha256(raw).hexdigest())
        self.assertEqual("d14ba48b319a64e116aeca4ba3b9d6e6596259f2391761046b75221f6fc5da36",
                         hashlib.sha256(text).hexdigest())
        stub = {"boot_id": BOOT_ID, "state_sha256": "0" * 64,
                "inode": "1", "invocation": "0" * 32}
        client = {**stub, "path": "system.slice/ssh.service"}
        manager = {**stub, "path": "system.slice/systemd-networkd.service"}
        # Historical three-chain bytes stay immutable and now fail closed.
        with self.assertRaises(NativeWitnessRefused):
            policy_projection(raw)
        with self.assertRaises(PolicyRefused):
            verify_expected_policy(STATE, raw, text, client, manager, boot_id=BOOT_ID)

    def test_exact_unbound_policy_and_counter_changes(self):
        table = kernel_rows()
        before = verify_expected_policy(STATE, encoded(table),
                                        kernel_text(table), boot_id=BOOT_ID)
        for item in table["nftables"]:
            if "rule" in item:
                for expr in item["rule"]["expr"]:
                    if "counter" in expr:
                        expr["counter"] = {"packets": 7, "bytes": 364}
        self.assertEqual(before, verify_expected_policy(
            STATE, encoded(table), kernel_text(table), boot_id=BOOT_ID))

    def test_broad_accept_extra_jump_and_changed_predicate_refused(self):
        baseline = kernel_rows()
        cases = []
        broad = copy.deepcopy(baseline)
        broad["nftables"][6]["rule"]["expr"] = [{"accept": None}]
        cases.append(broad)
        changed = copy.deepcopy(baseline)
        loopback = next(r['rule'] for r in changed['nftables'] if 'rule' in r and r['rule']['chain']=='output' and any(e.get('match',{}).get('right')=='lo' for e in r['rule']['expr']))
        loopback['expr'][0]['match']['right'] = 'eth0' 
        cases.append(changed)
        jumped = copy.deepcopy(baseline)
        jumped["nftables"].insert(-1, {"rule": {"family": "inet",
            "table": "aegis_device_guard", "chain": "output", "handle": 999,
            "expr": [{"jump": {"target": "foreign"}}]}})
        cases.append(jumped)
        policy = copy.deepcopy(baseline)
        policy["nftables"][2]["chain"]["policy"] = "accept"
        cases.append(policy)
        for index, table in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(PolicyRefused):
                    verify_expected_policy(STATE, encoded(table),
                                           kernel_text(baseline), boot_id=BOOT_ID)

    def test_cgroup_level_requires_matching_text_handle(self):
        state_sha = hashlib.sha256(STATE.rstrip(b"\n")).hexdigest()
        binding = {"schema": "aegis_device_guard_binding_v1",
                   "boot_id": BOOT_ID,
                   "state_sha256": state_sha,
                   "path": "system.slice/aegis-client.service", "inode": "1234",
                   "invocation": "a" * 32}
        table = kernel_rows(client=binding)
        bound = next(item["rule"] for item in table["nftables"]
                     if "rule" in item and "comment" in item["rule"])
        marker = bound["comment"]
        handle = bound["handle"]
        path = binding["path"]
        text = kernel_text(table)
        self.assertEqual(64, len(verify_expected_policy(STATE, encoded(table), text,
                                                         client_binding=binding, boot_id=BOOT_ID)))
        with self.assertRaises(PolicyRefused):
            verify_expected_policy(STATE, encoded(table), text,
                                   client_binding=binding,
                                   boot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        # Some nft versions omit level in JSON. Text must still prove it.
        del bound["expr"][0]["match"]["left"]["socket"]["level"]
        self.assertEqual(64, len(verify_expected_policy(STATE, encoded(table), text,
                                                         client_binding=binding, boot_id=BOOT_ID)))
        for bad in (text.replace(b"level 2", b"level 1"),
                    text.replace(f"handle {handle}".encode(), b"handle 999")):
            with self.assertRaises(PolicyRefused):
                verify_expected_policy(STATE, encoded(table), bad,
                                       client_binding=binding, boot_id=BOOT_ID)
        broadened = copy.deepcopy(table)
        bound_rule = next(item["rule"] for item in broadened["nftables"]
                          if "rule" in item and "comment" in item["rule"])
        bound_rule["expr"].insert(0, {"accept": None})
        with self.assertRaises(PolicyRefused):
            verify_expected_policy(STATE, encoded(broadened), text,
                                   client_binding=binding, boot_id=BOOT_ID)


    def test_postroute_policy_and_mark_handoff_countercases(self):
        state_sha = hashlib.sha256(STATE.rstrip(b"\n")).hexdigest()
        client = {"schema":"aegis_device_guard_binding_v1","boot_id":BOOT_ID,
                  "state_sha256":state_sha,"path":"system.slice/aegis-client.service",
                  "inode":"1234","invocation":"a"*32}
        baseline = kernel_rows(client=client)
        self.assertEqual(64,len(verify_expected_policy(STATE,encoded(baseline),kernel_text(baseline),client,boot_id=BOOT_ID)))
        def mutate(kind):
            value = copy.deepcopy(baseline)
            rows=value['nftables']
            if kind=='missing_chain':
                rows[:]=[r for r in rows if not ('chain' in r and r['chain']['name']=='postroute' or 'rule' in r and r['rule']['chain']=='postroute')]
            elif kind in ('accept_policy','wrong_priority'):
                chain=next(r['chain'] for r in rows if 'chain' in r and r['chain']['name']=='postroute')
                chain['policy' if kind=='accept_policy' else 'prio']='accept' if kind=='accept_policy' else 100
            elif kind=='missing_tag_clear':
                rows.remove(next(r for r in rows if 'rule' in r and r['rule']['chain']=='output' and any('mangle' in e and e['mangle']['value']==0 for e in r['rule']['expr'])))
            else:
                post=next(r['rule'] for r in rows if 'rule' in r and r['rule']['chain']=='postroute' and str(r['rule'].get('comment','')).startswith('aegis-post-'))
                if kind=='wrong_tag':post['expr'][0]['match']['right']=0xa361c002
                elif kind=='unconsumed_tag':post['expr']=[e for e in post['expr'] if 'mangle' not in e]
                elif kind=='broad_accept':post['expr']=[{'accept':None}]
            return value
        for kind in ('missing_chain','accept_policy','wrong_priority','missing_tag_clear','wrong_tag','unconsumed_tag','broad_accept'):
            with self.subTest(kind=kind),self.assertRaises(PolicyRefused):
                changed=mutate(kind)
                verify_expected_policy(STATE,encoded(changed),kernel_text(baseline),client,boot_id=BOOT_ID)


class ScopedRedirectPolicyTests(unittest.TestCase):
    def binding(self):
        return {"stage_dev": 11, "stage_ino": 12,
                "private_unit": "aegis-auto@" + "a" * 64 + ".service",
                "transaction_nonce": "b" * 32,
                "planned_generation": "c" * 64,
                "boot_id": BOOT_ID, "netns_ino": 42,
                "config_sha256_initial": "d" * 64,
                "config_semantic_sha256": "e" * 64,
                "interface": "aegisacp0", "ifindex": 7,
                "listen_ipv4": "10.231.80.1", "listen_port": 15080,
                "guard_policy_sha256": "f" * 64}

    def kernel(self, binding, active):
        rows = [{"metainfo": {"json_schema_version": 1}}]
        for number, item in enumerate(
                scoped_policy._scoped_expected(binding, active=active), 1):
            row = copy.deepcopy(item)
            next(iter(row.values()))["handle"] = number
            rows.append(row)
        return encoded({"nftables": rows})

    def test_scoped_input_gate_denies_direct_listener_and_marks_nat(self):
        binding = self.binding()
        scoped_policy._scoped_binding(binding, check_host=False)
        script = scoped_policy._scoped_script(binding, active=False).decode()
        self.assertIn('iifname "aegisacp0" ip daddr 10.231.80.1', script)
        self.assertIn('ct status dnat ct mark 0x', script)
        self.assertIn('tcp dport 15080 counter drop', script)
        self.assertNotIn("flush", script)
        self.assertNotIn("tproxy", script.lower())
        active = scoped_policy._scoped_script(binding, active=True).decode()
        self.assertIn("fib daddr type != local", active)
        self.assertIn("ct mark != { 0xa3610001, 0xa3610002 }", active)
        self.assertIn("redirect to :15080", active)
        self.assertNotIn("100", active.split("priority dstnat", 1)[-1].split("ct mark", 1)[0])

    def test_scoped_readback_refuses_direct_bypass_or_foreign_extra_rule(self):
        binding = self.binding()
        raw = self.kernel(binding, True)
        complete = lambda payload: subprocess.CompletedProcess(
            ["nft"], 0, stdout=payload, stderr=b"")
        with mock.patch.object(scoped_policy, "_scoped_nft",
                               return_value=complete(raw)):
            accepted = scoped_policy._scoped_projection(binding, active=True)
        self.assertEqual(set(accepted), {"policy_sha256", "input_gate_chain_handle",
                                         "input_allow_handle", "input_drop_handle",
                                         "prerouting_chain_handle", "redirect_handle"})
        changed = json.loads(raw)
        # A DNAT packet from a foreign rule cannot bypass the direct-listener
        # gate without this source-owned connection mark predicate.
        changed["nftables"][4]["rule"]["expr"] = [
            expression for expression in changed["nftables"][4]["rule"]["expr"]
            if not ("match" in expression and
                    expression["match"]["left"] == {"ct": {"key": "mark"}})]
        with mock.patch.object(scoped_policy, "_scoped_nft",
                               return_value=complete(encoded(changed))):
            with self.assertRaises(PolicyRefused):
                scoped_policy._scoped_projection(binding, active=True)
        changed = json.loads(raw)
        changed["nftables"].append(copy.deepcopy(changed["nftables"][-1]))
        changed["nftables"][-1]["rule"]["handle"] += 100
        with mock.patch.object(scoped_policy, "_scoped_nft",
                               return_value=complete(encoded(changed))):
            with self.assertRaises(PolicyRefused):
                scoped_policy._scoped_projection(binding, active=True)

    def test_scoped_bind_deadline_blocks_late_owner_receipt(self):
        binding = self.binding()
        with mock.patch.object(scoped_policy, "_scoped_binding",
                               return_value=binding), \
             mock.patch.object(scoped_policy, "_scoped_prepared",
                               side_effect=lambda *_args, **_kwargs:
                               (time.sleep(0.02), {})[1]), \
             mock.patch.object(scoped_policy, "_scoped_write") as write:
            with self.assertRaises(PolicyRefused):
                scoped_policy.scoped_bind_invocation(
                    binding, "1" * 32, deadline=time.monotonic() + 0.005)
            write.assert_not_called()

    def test_exact_scoped_reply_requires_owned_client_and_all_predicates(self):
        binding = self.binding()
        client = {"schema": "aegis_device_guard_binding_v1",
                  "boot_id": BOOT_ID,
                  "state_sha256": hashlib.sha256(STATE.rstrip(b"\n")).hexdigest(),
                  "path": "system.slice/" + binding["private_unit"],
                  "inode": "1234", "invocation": "a" * 32}
        marker = "aegis-auto-scoped-reply-" + hashlib.sha256(
            scoped_policy._scoped_json({
                "binding": binding,
                "client": {key: client[key] for key in
                           ("path", "inode", "invocation")}})).hexdigest()
        scoped = {"binding": binding, "mark": 0x12345678,
                  "marker": marker}
        table = kernel_rows(client=client, scoped_reply=scoped)
        text = kernel_text(table)
        with mock.patch.object(scoped_policy, "_scoped_reply_binding",
                               return_value=scoped):
            self.assertEqual(64, len(verify_expected_policy(
                STATE, encoded(table), text, client_binding=client,
                boot_id=BOOT_ID)))
            outputs = [row["rule"] for row in table["nftables"]
                       if "rule" in row and row["rule"].get("comment") == marker]
            # Captured Ubuntu 24.04 nft 1.0.9 readback of the postroute twins:
            # the IPv4 ct reply saddr elides its meta nfproto dependency.
            self.assertEqual([9, 9, 13, 9, 9, 12], [len(row["expr"]) for row in outputs])
            self.assertEqual({"output": 3, "postroute": 3},
                             {name: sum(row["chain"] == name for row in outputs)
                              for name in ("output", "postroute")})
            for rule_index, output in enumerate(outputs):
                for index in range(len(output["expr"]) - 2):
                    changed = copy.deepcopy(table)
                    changed_rules = [row["rule"] for row in changed["nftables"]
                                     if "rule" in row and
                                     row["rule"].get("comment") == marker]
                    changed_rules[rule_index]["expr"].pop(index)
                    with self.subTest(rule=rule_index, predicate=index), self.assertRaises(PolicyRefused):
                        verify_expected_policy(STATE, encoded(changed), text,
                                               client_binding=client, boot_id=BOOT_ID)
            absent = kernel_rows(client=client)
            with self.assertRaises(PolicyRefused):
                verify_expected_policy(STATE, encoded(absent), kernel_text(absent),
                                       client_binding=client, boot_id=BOOT_ID)
        # BLOCK and STOP have no client grant even if a stale scoped intent
        # exists. A residual reply rule cannot masquerade as deny.
        with mock.patch.object(scoped_policy, "_scoped_reply_binding",
                               return_value=None):
            with self.assertRaises(PolicyRefused):
                verify_expected_policy(STATE, encoded(table), text,
                                       boot_id=BOOT_ID)

    def test_scoped_dnat_reply_postroute_is_nat_invariant(self):
        # r15 #36: srcnat (100) rewrites the redirected listener's reply
        # source to the original target before postroute (2147483647). A postroute
        # rule for a reply-direction DNAT flow must bind the conntrack reply
        # tuple and never a header field that NAT rewrites.
        binding = self.binding()
        client = {"schema": "aegis_device_guard_binding_v1", "boot_id": BOOT_ID,
                  "state_sha256": hashlib.sha256(STATE.rstrip(b"\n")).hexdigest(),
                  "path": "system.slice/" + binding["private_unit"],
                  "inode": "1234", "invocation": "a" * 32}
        scoped = {"binding": binding, "mark": 0x12345678,
                  "marker": "aegis-auto-scoped-reply-" + "c" * 64}
        rules = _expected(parse_state(STATE), client, None, scoped)

        def match(rule, left):
            return [item["match"] for item in rule["expr"]
                    if "match" in item and item["match"]["left"] == left]

        def header(rule):
            return [item["match"]["left"]["payload"] for item in rule["expr"]
                    if "match" in item and "payload" in item["match"]["left"] and
                    item["match"]["left"]["payload"].get("field") in
                    ("saddr", "daddr", "sport", "dport")]

        reply_dnat = [rule for rule in rules["postroute"]
                      if match(rule, {"ct": {"key": "direction"}}) ==
                      [{"op": "==", "left": {"ct": {"key": "direction"}}, "right": "reply"}]
                      and match(rule, {"ct": {"key": "status"}}) ==
                      [{"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}]]
        self.assertEqual(3, len(reply_dnat))
        outputs = [rule for rule in rules["output"] if rule.get("comment") == scoped["marker"]]
        self.assertEqual(3, len(outputs))
        for post, output in zip(reply_dnat, outputs):
            self.assertEqual(scoped["marker"], post["comment"])
            self.assertEqual([], header(post))
            for left, right in (({"meta": {"key": "oifname"}}, "aegisacp0"),
                                ({"ct": {"key": "mark"}}, 0x12345678),
                                ({"ct": {"key": "saddr", "dir": "reply"}}, "10.231.80.1"),
                                ({"ct": {"key": "proto-src", "dir": "reply"}}, 15080)):
                self.assertEqual([right], [item["right"] for item in match(post, left)])
            # The flags or ICMP-type test is the OUTPUT rule's own.
            self.assertEqual(output["expr"][-3], post["expr"][-3])
        self.assertEqual([{"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "icmp"}],
                         match(reply_dnat[2], {"meta": {"key": "l4proto"}}))
        # The OUTPUT exceptions themselves are frozen and unchanged.
        common = [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "aegisacp0"}},
                  {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                             "right": "10.231.80.1"}},
                  {"match": {"op": "==", "left": {"ct": {"key": "direction"}}, "right": "reply"}},
                  {"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}},
                  {"match": {"op": "==", "left": {"ct": {"key": "mark"}}, "right": 0x12345678}},
                  {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "sport"}},
                             "right": 15080}}]
        tail = [{"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]
        self.assertEqual([
            common + [{"match": {"op": "==", "left": {"&": [
                {"payload": {"protocol": "tcp", "field": "flags"}}, ["syn", "ack"]]},
                "right": ["syn", "ack"]}}] + tail,
            common + [{"match": {"op": "==", "left": {"&": [
                {"payload": {"protocol": "tcp", "field": "flags"}}, "rst"]},
                "right": "rst"}}] + tail,
            common[:2] + [
                {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "icmp"}},
                {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "related"}}]
            + common[2:5] + [
                {"match": {"op": "==", "left": {"ct": {"key": "protocol"}}, "right": "tcp"}},
                {"match": {"op": "==", "left": {"ct": {"key": "proto-src", "dir": "reply"}},
                           "right": 15080}},
                {"match": {"op": "==", "left": {"ct": {"key": "saddr", "dir": "reply"}},
                           "right": "10.231.80.1"}},
                {"match": {"op": "==", "left": {"payload": {"base": "th", "offset": 0, "len": 8}},
                           "right": {"set": [3, 11, 12]}}}] + tail],
            [rule["expr"] for rule in outputs])
        # No other bound postroute rule matches a reply-direction DNAT flow.
        unscoped = _expected(parse_state(STATE), client, None)
        self.assertEqual([], [rule for rule in unscoped["postroute"]
                              if match(rule, {"ct": {"key": "status"}}) and
                              match(rule, {"ct": {"key": "direction"}})])


class GuardRendererContract(unittest.TestCase):
    """The committed render() function only (bash >= 4, PATH=/usr/bin:/bin)."""

    MARKER = "aegis-auto-scoped-reply-" + "c" * 64

    def client(self):
        return {"schema": "aegis_device_guard_binding_v1", "boot_id": BOOT_ID,
                "state_sha256": "0" * 64,
                "path": "system.slice/aegis-auto@" + "a" * 64 + ".service",
                "inode": "1234", "invocation": "a" * 32}

    def scoped(self):
        return {"binding": {"interface": "aegisacp0", "listen_ipv4": "10.231.80.1",
                            "listen_port": 15080},
                "mark": 0x12345678, "marker": self.MARKER}

    def render(self, profile="wide-redirect-safe", scoped=True, client=True, mutate=None):
        code, out, err = harness.render(profile=profile, uplink="eth0", management_ports="22",
                                        client=self.client() if client else None,
                                        scoped=self.scoped() if scoped else None,
                                        mutate=mutate)
        self.assertEqual((0, ""), (code, err))
        return out.splitlines()

    @staticmethod
    def rules(lines, chain):
        return [line for line in lines if line.split()[:5] ==
                ["add", "rule", "inet", harness.TABLE, chain]]

    def twin_line(self, needle):
        rows = [line for line in harness.render_function().splitlines(keepends=True)
                if "printf 'postroute-only " in line and needle in line]
        self.assertEqual(1, len(rows))
        return rows[0]

    def test_scoped_twins_replace_the_verbatim_mirror_in_place(self):
        comment = f' comment "{self.MARKER}"'
        for profile in ("wide-redirect-safe", "full-wide-tun"):
            with self.subTest(profile=profile):
                lines = self.render(profile)
                self.assertNotIn(harness.REFUSED, lines)
                self.assertFalse(any("postroute-only" in line for line in lines))
                output = self.rules(lines, "output")
                post = self.rules(lines, "postroute")
                prefix = "add rule inet aegis_device_guard output "
                self.assertEqual([
                    prefix + 'oifname "aegisacp0" ip saddr 10.231.80.1 meta l4proto tcp '
                    "ct direction reply ct status dnat ct mark 0x12345678 tcp sport 15080 "
                    "tcp flags & (syn | ack) == syn | ack counter accept" + comment,
                    prefix + 'oifname "aegisacp0" ip saddr 10.231.80.1 meta l4proto tcp '
                    "ct direction reply ct status dnat ct mark 0x12345678 tcp sport 15080 "
                    "tcp flags & rst == rst counter accept" + comment,
                    prefix + 'oifname "aegisacp0" ip saddr 10.231.80.1 meta l4proto icmp '
                    "ct state related ct direction reply ct status dnat ct mark 0x12345678 "
                    "ct protocol tcp ct reply proto-src 15080 ct reply saddr 10.231.80.1 "
                    "@th,0,8 { 3, 11, 12 } counter accept" + comment],
                    [line for line in output if line.endswith(comment)])
                # The mark-clear rule is OUTPUT-only; every other OUTPUT rule
                # has exactly one postroute rule at the same position.
                self.assertIn("meta mark { 0xa361c001, 0xa361c002 } meta mark set 0", output[0])
                self.assertEqual(len(output) - 1, len(post))
                twins = 0
                for out, mirrored in zip(output[1:], post):
                    if out.endswith(comment):
                        twins += 1
                        self.assertTrue(mirrored.endswith(comment))
                        self.assertNotIn(" ip saddr ", mirrored)
                        self.assertNotIn(" tcp sport ", mirrored)
                        self.assertIn(' oifname "aegisacp0" meta nfproto ipv4 ', mirrored)
                        self.assertIn(" ct direction reply ct status dnat ct mark 0x12345678 ",
                                      mirrored)
                        self.assertIn(" ct reply saddr 10.231.80.1", mirrored)
                        self.assertIn(" ct reply proto-src 15080 ", mirrored)
                        test = out.split(" counter accept")[0].rsplit(
                            " tcp flags ", 1)[-1] if " tcp flags " in out else "@th"
                        self.assertIn(test, mirrored)
                    elif " socket cgroupv2 " in out:
                        self.assertIn(" meta mark 0xa361c001 meta mark set 0 counter accept"
                                      ' comment "aegis-post-', mirrored)
                    else:
                        self.assertEqual(harness.output_mirror(out), mirrored)
                self.assertEqual(3, twins)

    def test_unscoped_tables_keep_the_generic_mirror(self):
        for profile in ("wide-redirect-safe", "full-wide-tun"):
            for client in (True, False):
                with self.subTest(profile=profile, client=client):
                    lines = self.render(profile, scoped=False, client=client)
                    self.assertNotIn(harness.REFUSED, lines)
                    self.assertFalse(any("aegis-auto-scoped-reply-" in line or
                                         "postroute-only" in line or
                                         " ct reply saddr " in line for line in lines))
                    output = self.rules(lines, "output")
                    post = self.rules(lines, "postroute")
                    self.assertEqual(len(output) - 1, len(post))
                    for out, mirrored in zip(output[1:], post):
                        if " socket cgroupv2 " not in out:
                            self.assertEqual(harness.output_mirror(out), mirrored)

    def test_unpaired_misplaced_or_mismatched_twin_emits_unparsable_sentinel(self):
        rst = self.twin_line("rst == rst")
        synack = self.twin_line("(syn | ack)")
        icmp = self.twin_line("meta l4proto icmp")
        cases = {
            "removed": (rst, ""),
            "last_removed": (icmp, ""),
            "duplicated": (rst, rst + rst),
            "other_chain": (rst, rst.replace(" postroute oifname ", " output oifname ", 1)),
            "other_comment": (synack, synack.replace('comment "%s"', 'comment "%sx"', 1)),
            "unmarked_twin": (synack, synack.replace("printf 'postroute-only add rule",
                                                     "printf 'add rule", 1)),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                self.assertNotEqual(mutate[0], mutate[1])
                lines = self.render(mutate=mutate)
                self.assertGreaterEqual(lines.count(harness.REFUSED), 1)
                self.assertFalse(any(line.startswith("postroute-only") for line in lines))


class DeniedManagerGrantContract(unittest.TestCase):
    """Exercise the guardian classifier itself, including numeric DHCP rules."""

    def setUp(self):
        import aegis_auto_guardian as guardian
        self.guardian = guardian
        self.manager = {"schema": "aegis_device_guard_binding_v2",
                        "boot_id": BOOT_ID,
                        "state_sha256": hashlib.sha256(STATE.rstrip(b"\n")).hexdigest(),
                        "path": "system.slice/systemd-networkd.service",
                        "inode": "12345", "invocation": "b" * 32,
                        "ifindex": 3, "dhcp4_server": "192.0.2.1",
                        "dhcp6_server": "2001:db8::1"}
        self.state = STATE
        self.raw_manager = encoded(self.manager)
        self.client_present = False
        self.capture_present = False
        self.client_symlink = False
        self.index = 3
        def exists(path):
            name = str(path)
            if name.endswith(".manager-binding"):
                return True
            if name.endswith(".client-binding"):
                return self.client_present
            if path == guardian.CAPTURE_BINDING:
                return self.capture_present
            return False
        def symlink(path):
            return self.client_symlink and str(path).endswith(".client-binding")
        def protected(path, *_args):
            return self.raw_manager if str(path).endswith(".manager-binding") else self.state
        for patch in (mock.patch.object(guardian.Path, "exists", exists),
                      mock.patch.object(guardian.Path, "is_symlink", symlink),
                      mock.patch.object(guardian, "regular", side_effect=protected),
                      mock.patch.object(guardian, "verified_module", return_value=scoped_policy),
                      mock.patch.object(guardian, "host_anchor", return_value={"boot_id": BOOT_ID}),
                      mock.patch.object(scoped_policy.socket, "if_nametoindex",
                                        side_effect=lambda _name: self.index)):
            patch.start()
            self.addCleanup(patch.stop)

    def projection(self, table=None):
        from aegis_auto_native_witness import policy_projection
        return policy_projection(encoded(table or kernel_rows(
            state=self.state, manager=self.manager)))[0]

    def denied(self, table=None):
        try:
            return self.guardian._no_client_grant(self.projection(table))
        except (self.guardian.Refused, PolicyRefused):
            return False

    def test_real_renderer_numeric_dhcp_survives_client_stop(self):
        for profile in (b"full-wide-tun", b"wide-redirect-safe"):
            with self.subTest(profile=profile):
                self.state = STATE + b"capture_profile=" + profile + b"\n"
                self.manager["state_sha256"] = hashlib.sha256(self.state.rstrip(b"\n")).hexdigest()
                self.raw_manager = encoded(self.manager)
                self.assertTrue(self.denied())

    def test_nft_display_names_and_elided_levels_keep_protected_identity(self):
        table = kernel_rows(manager=self.manager)
        for item in table["nftables"]:
            for expr in item.get("rule", {}).get("expr", []):
                match = expr.get("match", {})
                if match.get("left") == {"meta": {"key": "oif"}}:
                    match["right"] = "eth0"
                if "socket" in match.get("left", {}):
                    match["left"]["socket"].pop("level")
        self.assertTrue(self.denied(table))

    def test_acquisition_only_and_single_family_pins_are_not_client_grants(self):
        for family in (4, 6):
            with self.subTest(family=family):
                other = 6 if family == 4 else 4
                self.state = STATE.replace(f"dhcp{other}=1".encode(), f"dhcp{other}=0".encode())
                self.manager.update(state_sha256=hashlib.sha256(self.state.rstrip(b"\n")).hexdigest(),
                                    dhcp4_server=None, dhcp6_server=None)
                self.raw_manager = encoded(self.manager)
                self.assertTrue(self.denied())

    def test_changed_protected_state_manager_or_live_index_is_refused(self):
        table = kernel_rows(manager=self.manager)
        for path in ("state", "manager"):
            with self.subTest(path=path):
                calls = {"state": 0, "manager": 0}
                def read(name, *_args):
                    role = "manager" if str(name).endswith(".manager-binding") else "state"
                    calls[role] += 1
                    raw = self.raw_manager if role == "manager" else self.state
                    return raw + b" " if role == path and calls[role] > 1 else raw
                with mock.patch.object(self.guardian, "regular", side_effect=read):
                    self.assertFalse(self.denied(table))
        self.index = 4
        self.assertFalse(self.denied(table))

    def test_each_dhcp_predicate_and_postroute_twin_stays_exact(self):
        baseline = kernel_rows(manager=self.manager)
        for chain in ("output", "postroute"):
            original = next(item["rule"] for item in baseline["nftables"]
                            if item.get("rule", {}).get("chain") == chain
                            and "comment" in item["rule"])
            for index in range(len(original["expr"]) - 2):
                with self.subTest(chain=chain, omitted=index):
                    table = copy.deepcopy(baseline)
                    rule = next(item["rule"] for item in table["nftables"]
                                if item.get("rule", {}).get("handle") == original["handle"])
                    rule["expr"].pop(index)
                    self.assertFalse(self.denied(table))
            for field, value in (("comment", "aegis-v2-" + "0" * 64),):
                table = copy.deepcopy(baseline)
                next(item["rule"] for item in table["nftables"]
                     if item.get("rule", {}).get("handle") == original["handle"])[field] = value
                self.assertFalse(self.denied(table))

    def test_wrong_lease_ifindex_boot_or_state_is_not_a_manager_grant(self):
        table = kernel_rows(manager=self.manager)
        for key, value in (("dhcp4_server", "192.0.2.2"), ("dhcp6_server", "2001:db8::2"),
                           ("ifindex", 4), ("boot_id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                           ("state_sha256", "0" * 64), ("invocation", "c" * 32)):
            with self.subTest(field=key):
                self.raw_manager = encoded(dict(self.manager, **{key: value}))
                self.assertFalse(self.denied(table))

    def test_client_socket_numeric_tun_and_dnat_cannot_impersonate_dhcp(self):
        baseline = kernel_rows(manager=self.manager)
        for expr in ([{"match": {"op": "==", "left": {"meta": {"key": "oif"}},
                                   "right": 37}}, {"accept": None}],
                     [{"match": {"op": "==", "left": {"socket": {"key": "cgroupv2", "level": 2}},
                                   "right": "system.slice/aegis-client.service"}}, {"accept": None}],
                     [{"match": {"op": "in", "left": {"ct": {"key": "status"}},
                                   "right": "dnat"}}, {"accept": None}]):
            table = copy.deepcopy(baseline)
            terminal = next(index for index, item in enumerate(table["nftables"])
                            if item.get("rule", {}).get("chain") == "output"
                            and {"drop": None} in item["rule"]["expr"])
            table["nftables"].insert(terminal, {"rule": {"family": "inet", "table": "aegis_device_guard",
                "chain": "output", "handle": 10000, "expr": expr}})
            self.assertFalse(self.denied(table))

    def test_stopped_client_binding_or_dangling_symlink_is_refused(self):
        for field in ("client_present", "capture_present", "client_symlink"):
            with self.subTest(field=field):
                setattr(self, field, True)
                self.assertFalse(self.denied())
                setattr(self, field, False)


class CrossbootManagerRetirementContract(unittest.TestCase):
    def test_exact_old_manager_dhcp_rules_are_only_subtraction(self):
        manager = {"schema": "aegis_device_guard_binding_v2",
                   "path": "system.slice/systemd-networkd.service",
                   "inode": "12345", "invocation": "2" * 32,
                   "boot_id": BOOT_ID,
                   "state_sha256": hashlib.sha256(STATE.rstrip(b"\n")).hexdigest(),
                   "ifindex": 3, "dhcp4_server": None,
                   "dhcp6_server": None}
        scoped_policy.prove_manager_only_retirement(STATE, manager)
        live = policy_projection(encoded(kernel_rows(STATE, manager=manager)))[0]
        base = policy_projection(encoded(kernel_rows(STATE)))[0]
        self.assertEqual(scoped_policy.without_current_manager(
            live, STATE, manager), base)
        for changed in ({**manager, "state_sha256": "0" * 64},
                        {**manager, "schema": "aegis_device_guard_binding_v1"},
                        {**manager, "path": "system.slice/foreign.service"}):
            with self.assertRaises(PolicyRefused):
                scoped_policy.prove_manager_only_retirement(STATE, changed)
        original = scoped_policy._expected
        def foreign_rule(state, client, binding, *args, **kwargs):
            rows = original(state, client, binding, *args, **kwargs)
            if binding is not None:
                rows["output"].append({"family": "inet", "table": "aegis_device_guard",
                                       "chain": "output", "expr": [{"accept": None}]})
            return rows
        with mock.patch.object(scoped_policy, "_expected", side_effect=foreign_rule):
            with self.assertRaises(PolicyRefused):
                scoped_policy.prove_manager_only_retirement(STATE, manager)
        forged = json.loads(live)
        forged.append({"rule": {"family": "inet", "table": "aegis_device_guard",
                                  "chain": "output", "expr": [{"accept": None}]}})
        with self.assertRaises(PolicyRefused):
            scoped_policy.without_current_manager(encoded(forged), STATE, manager)


if __name__ == "__main__":
    unittest.main()
