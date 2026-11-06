#!/usr/bin/env python3
"""Source-derived semantic seal for the installed v2 device guard table.

The trusted administrative state and optional live unit-binding receipts select
one exact renderer output. Kernel handles and counters are the only normalized
fields. nft text readback binds cgroup levels omitted by some nft JSON builds
to the same rule handles. The separate scoped redirect API below owns only
its dedicated nft table; the v2 device guard verifier remains read-only.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import select
import socket
import stat
import subprocess
import time
from collections import Counter
from pathlib import Path

from aegis_auto_native_witness import policy_projection

TABLE = "aegis_device_guard"
MAX_INPUT = 1 << 20
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
IFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
PATH = re.compile(r"[A-Za-z0-9_.@:-]+(?:/[A-Za-z0-9_.@:-]+)*\Z")
PRIVATE = re.compile(r"aegis-auto@[0-9a-f]{64}\.service\Z")


class PolicyRefused(ValueError):
    """The installed nft table is not the exact configured v2 policy."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise PolicyRefused(reason)


def unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse_state(raw: bytes) -> dict[str, str]:
    need(type(raw) is bytes and 0 < len(raw) <= 16384, "invalid guard state size")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise PolicyRefused("non-ASCII guard state") from error
    result = {}
    allowed = {"schema", "armed", "service", "uplink", "manager",
               "capture_interface", "capture_profile", "management_address_policy", "management_ports",
               "dhcp4", "dhcp6", "initramfs_network", "manager_connection_uuid",
               "manager_ipv4_method", "manager_ipv6_method", "foreign_policy", "ufw_integrity_sha256"}
    for line in text.splitlines():
        need(bool(line) and "=" in line, "invalid guard state line")
        key, value = line.split("=", 1)
        need(key in allowed and key not in result, "unknown or duplicate guard state field")
        result[key] = value
    required = {"schema", "armed", "service", "uplink", "manager",
                "capture_interface", "management_address_policy", "management_ports",
                "dhcp4", "dhcp6", "initramfs_network"}
    need(required <= result.keys() and result["schema"] == "aegis_device_guard_v2" and
         result["armed"] == "1" and result["service"] == "aegis-client.service" and
         IFACE.fullmatch(result["uplink"]) is not None and
         result["uplink"] not in ("lo", "aegis-tun0") and
         result["capture_interface"] == "aegis-tun0" and
         result.get("capture_profile", "full-wide-tun") in
         ("full-wide-tun", "wide-redirect-safe") and
         result["manager"] in ("NetworkManager.service", "systemd-networkd.service") and
         result["management_address_policy"] == "current_local" and
         result["dhcp4"] in ("0", "1") and result["dhcp6"] in ("0", "1") and
         result["initramfs_network"] == "absent_verified", "invalid v2 guard state")
    ports = result["management_ports"].split(",") if result["management_ports"] else []
    need(len(ports) <= 8 and len(set(ports)) == len(ports) and
         all(p.isascii() and p.isdecimal() and str(int(p)) == p and
             1 <= int(p) <= 65535 for p in ports), "invalid management ports")
    foreign_fields = {"foreign_policy", "ufw_integrity_sha256"} & result.keys()
    need(not foreign_fields or foreign_fields == {"foreign_policy", "ufw_integrity_sha256"}
         and result["foreign_policy"] == "filter_only" and
         HEX64.fullmatch(result["ufw_integrity_sha256"]) is not None,
         "invalid foreign policy metadata")
    required |= foreign_fields
    if result["manager"] == "NetworkManager.service":
        need(set(result) == required | ({"capture_profile"} if "capture_profile" in result else set()) | {"manager_connection_uuid", "manager_ipv4_method",
                                        "manager_ipv6_method"}, "invalid NM state fields")
        need(BOOT.fullmatch(result["manager_connection_uuid"]) is not None and
             result["manager_ipv4_method"] in ("auto", "manual") and
             result["manager_ipv6_method"] in
             ("auto", "dhcp", "manual", "disabled", "ignore", "link-local") and
             (result["manager_ipv4_method"] == "auto") == (result["dhcp4"] == "1") and
             (result["manager_ipv6_method"] in ("auto", "dhcp")) ==
             (result["dhcp6"] == "1"), "inconsistent NM state")
    else:
        need(set(result) == required | ({"capture_profile"} if "capture_profile" in result else set()),
             "unexpected networkd state fields")
    return result


def require_capture_profile(state: dict[str, str], mode: str) -> None:
    """Bind a sealed local AUTO mode to the current guarded policy epoch."""
    need(mode in ("full-wide-tun", "wide-redirect-safe") and
         state.get("capture_profile", "full-wide-tun") == mode,
         "local_guard_capture_profile_changed")


def _binding(value: bytes | dict | None, role: str, state_sha: str,
             expected_unit: str) -> tuple[str, int, str] | None:
    if value is None:
        return None
    if type(value) is bytes:
        need(0 < len(value) <= 4096, "invalid binding size")
        try:
            value = json.loads(value, object_pairs_hook=unique)
        except (UnicodeError, ValueError) as error:
            raise PolicyRefused("invalid binding JSON") from error
    need(type(value) is dict, f"invalid {role} binding")
    base = {"schema", "boot_id", "state_sha256", "path", "inode", "invocation"}
    pinned = role == "manager" and value.get("schema") == "aegis_device_guard_binding_v2"
    need(type(value) is dict and set(value) ==
         (base | {"ifindex", "dhcp4_server", "dhcp6_server"} if pinned else base) and
         value["schema"] == ("aegis_device_guard_binding_v2" if pinned else
                              "aegis_device_guard_binding_v1") and
         value["state_sha256"] == state_sha and
         type(value["boot_id"]) is str and BOOT.fullmatch(value["boot_id"]) is not None and
         type(value["path"]) is str and PATH.fullmatch(value["path"]) is not None and
         (value["path"].rsplit("/", 1)[-1] == expected_unit or
          (role == "client" and
           PRIVATE.fullmatch(value["path"].rsplit("/", 1)[-1]) is not None)) and
         type(value["inode"]) is str and value["inode"].isascii() and
         value["inode"].isdecimal() and str(int(value["inode"])) == value["inode"] and
         int(value["inode"]) > 0 and
         type(value["invocation"]) is str and
         HEX32.fullmatch(value["invocation"]) is not None,
         f"invalid {role} binding")
    if pinned:
        need(type(value["ifindex"]) is int and value["ifindex"] > 0,
             "invalid manager interface identity")
        for key, family in (("dhcp4_server", 4), ("dhcp6_server", 6)):
            address = value[key]
            need(address is None or type(address) is str,
                 "invalid manager lease pin")
            if address is not None:
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError as error:
                    raise PolicyRefused("invalid manager lease pin") from error
                need(parsed.version == family and str(parsed) == address and
                     not (parsed.is_unspecified or parsed.is_multicast or
                          parsed.is_loopback or parsed.is_link_local and family == 4),
                     "invalid manager lease pin")
    return value["path"], len(value["path"].split("/")), value["boot_id"]


def _marker(binding: dict, role: str) -> str:
    material = [binding[k] for k in ("boot_id", "state_sha256")]
    material.extend([role, binding["path"], binding["inode"], binding["invocation"]])
    return "aegis-v2-" + hashlib.sha256(json.dumps(
        material, separators=(",", ":")).encode()).hexdigest()


def _cmp(left: dict, right: object) -> dict:
    return {"match": {"op": "==", "left": left, "right": right}}


def _in(left: dict, right: object) -> dict:
    return {"match": {"op": "in", "left": left, "right": right}}


def _meta(key: str) -> dict:
    return {"meta": {"key": key}}


def _payload(protocol: str, field: str) -> dict:
    return {"payload": {"protocol": protocol, "field": field}}


def _ct(key: str, direction: str | None = None) -> dict:
    value = {"key": key}
    if direction is not None:
        value["dir"] = direction
    return {"ct": value}


def _rule(chain: str, expr: list[dict], comment: str | None = None) -> dict:
    value = {"family": "inet", "table": TABLE, "chain": chain, "expr": expr}
    if comment is not None:
        value["comment"] = comment
    return value


def _accept(expr: list[dict]) -> list[dict]:
    return expr + [{"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]


def _expected(state: dict[str, str], client: dict | None,
              manager: dict | None, scoped_reply: dict | None = None,
              local_dnat_ports: tuple[tuple[str, int], ...] = (),
              capture_binding: dict | None = None
              ) -> dict[str, list[dict]]:
    uplink = state["uplink"]
    rules = {"incoming": [], "output": [], "forward": [], "postroute": []}
    scoped_post = []
    rules["output"].append(_rule("output", _accept([_cmp(_meta("oifname"), "lo")])))
    if capture_binding is not None:
        rules["output"].append(_rule("output", _accept([
            _cmp(_meta("oif"), capture_binding["ifindex"]),
            _cmp(_meta("oifkind"), "tun")])))
    if client is not None:
        path = client["path"]
        level = len(path.split("/"))
        rules["output"].append(_rule("output", _accept([
            _cmp({"socket": {"key": "cgroupv2", "level": level}}, path)]),
            _marker(client, "client")))
        if scoped_reply is not None:
            binding = scoped_reply["binding"]
            reply = [
                _cmp(_meta("oifname"), binding["interface"]),
                _cmp(_payload("ip", "saddr"), binding["listen_ipv4"]),
                _cmp(_ct("direction"), "reply"),
                _in(_ct("status"), "dnat"),
                _cmp(_ct("mark"), scoped_reply["mark"]),
                _cmp(_payload("tcp", "sport"), binding["listen_port"]),
            ]
            rules["output"].append(_rule("output", _accept(reply + [
                _cmp({"&": [_payload("tcp", "flags"), ["syn", "ack"]]},
                     ["syn", "ack"]),
            ]), scoped_reply["marker"]))
            rules["output"].append(_rule("output", _accept(reply + [
                _cmp({"&": [_payload("tcp", "flags"), "rst"]}, "rst"),
            ]), scoped_reply["marker"]))
            rules["output"].append(_rule("output", _accept([
                _cmp(_meta("oifname"), binding["interface"]),
                _cmp(_payload("ip", "saddr"), binding["listen_ipv4"]),
                _cmp(_meta("l4proto"), "icmp"),
                _in(_ct("state"), "related"),
                _cmp(_ct("direction"), "reply"),
                _in(_ct("status"), "dnat"),
                _cmp(_ct("mark"), scoped_reply["mark"]),
                _cmp(_ct("protocol"), "tcp"),
                _cmp(_ct("proto-src", "reply"), binding["listen_port"]),
                _cmp(_ct("saddr", "reply"), binding["listen_ipv4"]),
                _cmp({"payload": {"base": "th", "offset": 0, "len": 8}},
                     {"set": [3, 11, 12]}),
            ]), scoped_reply["marker"]))
            # srcnat (100) rewrites the reply source to the original target
            # before postroute (2147483647). The twins bind the same reply through
            # the NAT-invariant conntrack reply tuple, never header fields.
            # nft 1.0.9 lists the renderer's explicit "meta nfproto ipv4" as
            # the elided dependency of the IPv4 "ct reply saddr" (captured
            # Ubuntu 24.04 readback: 9, 9 and 12 expressions); the IPv4 string
            # value can only be listed with that network-layer context.
            twin = [
                _cmp(_meta("oifname"), binding["interface"]),
                _cmp(_ct("direction"), "reply"),
                _in(_ct("status"), "dnat"),
                _cmp(_ct("mark"), scoped_reply["mark"]),
                _cmp(_ct("saddr", "reply"), binding["listen_ipv4"]),
                _cmp(_ct("proto-src", "reply"), binding["listen_port"]),
            ]
            scoped_post = [
                _rule("postroute", _accept(twin + [
                    _cmp({"&": [_payload("tcp", "flags"), ["syn", "ack"]]},
                         ["syn", "ack"]),
                ]), scoped_reply["marker"]),
                _rule("postroute", _accept(twin + [
                    _cmp({"&": [_payload("tcp", "flags"), "rst"]}, "rst"),
                ]), scoped_reply["marker"]),
                _rule("postroute", _accept([
                    _cmp(_meta("oifname"), binding["interface"]),
                    _cmp(_meta("l4proto"), "icmp"),
                    _in(_ct("state"), "related"),
                    _cmp(_ct("direction"), "reply"),
                    _in(_ct("status"), "dnat"),
                    _cmp(_ct("mark"), scoped_reply["mark"]),
                    _cmp(_ct("protocol"), "tcp"),
                    _cmp(_ct("proto-src", "reply"), binding["listen_port"]),
                    _cmp(_ct("saddr", "reply"), binding["listen_ipv4"]),
                    _cmp({"payload": {"base": "th", "offset": 0, "len": 8}},
                         {"set": [3, 11, 12]}),
                ]), scoped_reply["marker"]),
            ]
        for protocol, port in (("tcp", 15080), ("udp", 15081)) + local_dnat_ports:
            rules["output"].append(_rule("output", _accept([
                _cmp(_payload("ip", "daddr"), "127.0.0.1"),
                _in(_ct("status"), "dnat"),
                _cmp(_payload(protocol, "dport"), port)])))
    for raw_port in state["management_ports"].split(",") if state["management_ports"] else []:
        port = int(raw_port)
        rules["incoming"].append(_rule("incoming", [
            _cmp(_meta("iifname"), uplink),
            _cmp({"fib": {"result": "type", "flags": ["daddr"]}}, "local"),
            _cmp(_payload("tcp", "dport"), port),
            _cmp(_ct("direction"), "original"),
            _cmp(_ct("state"), {"set": ["established", "new"]}),
            {"mangle": {"key": _ct("mark"), "value": 0xa3610002}},
        ]))
        rules["output"].append(_rule("output", _accept([
            _cmp(_meta("oifname"), uplink),
            _cmp(_ct("direction"), "reply"),
            _cmp(_ct("mark"), 0xa3610002),
            _cmp(_ct("proto-dst", "original"), port),
            _cmp(_payload("tcp", "sport"), port),
        ])))
    if manager is not None:
        need(manager.get("schema") == "aegis_device_guard_binding_v2" and
             type(manager.get("ifindex")) is int and manager["ifindex"] > 0,
             "DHCP manager has no protected uplink ifindex")
        path = manager["path"]
        level = len(path.split("/"))
        marker = _marker(manager, "manager")
        for enabled, family, sport, dport in ((state["dhcp4"], "ipv4", 68, 67),
                                              (state["dhcp6"], "ipv6", 546, 547)):
            if enabled == "1":
                acquisition = "255.255.255.255" if family == "ipv4" else "ff02::1:2"
                pin = manager.get("dhcp4_server" if family == "ipv4" else
                                  "dhcp6_server")
                destination = ({"set": [pin, acquisition]} if pin is not None
                               else acquisition)
                rules["output"].append(_rule("output", _accept([
                    _cmp(_meta("oifname"), uplink),
                    # Keep the protected numeric uplink identity. nft can
                    # print its name in readback; only the comparison view
                    # normalizes that display form.
                    _cmp(_meta("oif"), manager["ifindex"]),
                    _cmp(_payload("ip" if family == "ipv4" else "ip6", "daddr"),
                         destination),
                    _cmp(_payload("udp", "sport"), sport),
                    _cmp(_payload("udp", "dport"), dport),
                    _cmp({"socket": {"key": "cgroupv2", "level": level}}, path),
                ]), marker))
    rules["output"].append(_rule("output", _accept([
        _cmp(_meta("oifname"), uplink),
        _cmp(_payload("ip6", "hoplimit"), 255),
        _cmp(_payload("ip6", "daddr"), {"set": [
            {"prefix": {"addr": "fe80::", "len": 10}},
            {"prefix": {"addr": "ff02::", "len": 16}},
        ]}),
        _cmp(_payload("icmpv6", "type"), {"set": [
            "nd-router-solicit", "nd-neighbor-solicit", "nd-neighbor-advert"]}),
    ])))
    rules["output"].append(_rule("output", [{"counter": {"packets": 0, "bytes": 0}},
                                           {"drop": None}]))
    rules["forward"].append(_rule("forward", [{"counter": {"packets": 0, "bytes": 0}},
                                             {"drop": None}]))
    # nft socket expressions cannot be installed in POSTROUTING on Linux7.0.
    # Preserve every non-socket predicate; carry only the source-authorized
    # cgroup decision in a consumed packet tag. Never use a conntrack mark.
    # A scoped reply rule takes its NAT-invariant twin at the same position.
    twins = list(scoped_post)
    for rule in rules["output"]:
        if scoped_reply is not None and rule.get("comment") == scoped_reply["marker"]:
            need(bool(twins), "scoped reply twin missing")
            rules["postroute"].append(twins.pop(0))
            continue
        post = json.loads(json.dumps(rule))
        post["chain"] = "postroute"
        sockets = [e for e in rule["expr"] if "match" in e and
                   isinstance(e["match"].get("left"), dict) and
                   "socket" in e["match"]["left"]]
        if sockets:
            manager_rule = any("match" in e and e["match"].get("left") ==
                               _payload("udp", "sport") for e in rule["expr"])
            tag = 0xa361c002 if manager_rule else 0xa361c001
            rule["expr"].insert(-2, {"mangle": {"key": _meta("mark"), "value": tag}})
            for index, expression in enumerate(post["expr"]):
                if expression == sockets[0]:
                    post["expr"][index] = _cmp(_meta("mark"), tag)
            post["expr"].insert(-2, {"mangle": {"key": _meta("mark"), "value": 0}})
            if "comment" in post:
                post["comment"] = post["comment"].replace("aegis-v2-", "aegis-post-", 1)
        rules["postroute"].append(post)
    need(not twins, "scoped reply twin unconsumed")
    rules["output"].insert(0, _rule("output", [
        _cmp(_meta("mark"), {"set": [0xa361c001, 0xa361c002]}),
        {"mangle": {"key": _meta("mark"), "value": 0}},
    ]))
    return rules


def _canonical_rules(projected: bytes) -> tuple[dict[str, list[dict]], dict[str, object]]:
    rows = json.loads(projected)
    need(len(rows) <= 80, "guard table has too many objects")
    result = {"incoming": [], "output": [], "forward": [], "postroute": []}
    chains = {}
    tables = []
    for item in rows:
        kind, body = next(iter(item.items()))
        if kind == "table":
            tables.append(body)
        elif kind == "chain":
            chains[body["name"]] = body
        else:
            result[body["chain"]].append(body)
    need(tables == [{"family": "inet", "name": TABLE}], "guard table fields changed")
    expected_chains = {name: {"family": "inet", "table": TABLE, "name": name,
                              "type": "filter", "hook": hook, "prio": priority,
                              "policy": policy}
                       for name, hook, priority, policy in
                       (("incoming", "prerouting", -190, "accept"),
                        ("output", "output", 2147483647, "drop"),
                        ("forward", "forward", 10, "drop"),
                        ("postroute", "postrouting", 2147483647, "drop"))}
    need(chains == expected_chains, "guard chain semantics changed")
    return result, chains


def _text_binding_levels(text: bytes, actual_raw: bytes,
                         expected: dict[str, list[dict]],
                         capture: dict | None = None,
                         capture_interface: str | None = None,
                         manager: dict | None = None,
                         manager_interface: str | None = None) -> None:
    need(type(text) is bytes and 0 < len(text) <= MAX_INPUT, "nft text readback missing")
    try:
        lines = text.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise PolicyRefused("non-ASCII nft text readback") from error
    raw = json.loads(actual_raw, object_pairs_hook=unique)["nftables"]
    json_handles = Counter()
    for item in raw:
        kind, body = next(iter(item.items()))
        if kind in ("table", "chain", "rule"):
            need(type(body.get("handle")) is int and body["handle"] > 0,
                 "nft JSON handle missing")
            json_handles[(kind, body["handle"])] += 1
    text_handles = Counter()
    for line in lines:
        stripped = line.strip()
        if "# handle" not in stripped:
            continue
        match = re.search(r"# handle ([1-9][0-9]*)$", stripped)
        need(match is not None, "malformed nft text handle")
        kind = ("table" if stripped.startswith("table ") else
                "chain" if stripped.startswith("chain ") else "rule")
        text_handles[(kind, int(match.group(1)))] += 1
    need(text_handles == json_handles, "nft text and JSON handle inventory differs")
    wanted = {}
    for rules in expected.values():
        for rule in rules:
            marker = rule.get("comment")
            if marker is None:
                continue
            socket_rules = [expr["match"] for expr in rule["expr"]
                            if "match" in expr and isinstance(expr["match"].get("left"), dict)
                            and "socket" in expr["match"]["left"]]
            if not marker.startswith("aegis-v2-"):
                continue
            need(len(socket_rules) == 1, "expected cgroup predicate missing")
            predicate = socket_rules[0]
            wanted.setdefault(marker, []).append((predicate["left"]["socket"]["level"],
                                                    predicate["right"]))
    observed = []
    for item in raw:
        if "rule" not in item:
            continue
        rule = item["rule"]
        if "comment" not in rule or not str(rule["comment"]).startswith("aegis-v2-"):
            continue
        socket_matches = [expr["match"]
                          for expr in rule["expr"] if "match" in expr and
                          isinstance(expr["match"].get("left"), dict) and
                          "socket" in expr["match"]["left"]]
        need(len(socket_matches) == 1 and type(rule.get("handle")) is int,
             "bound rule has no unique socket handle")
        observed.append((rule["comment"], rule["handle"], socket_matches[0]))
    need(Counter(marker for marker, _, _ in observed) ==
         Counter(marker for marker, values in wanted.items() for _ in values),
         "binding marker inventory changed")
    matched = []
    for marker, handle, predicate in observed:
        candidates = wanted.get(marker, [])
        socket_value = predicate["left"]["socket"]
        numeric_manager = (manager is not None and
                           marker == _marker(manager, "manager") and
                           predicate["right"] == manager["inode"] and
                           any(path == manager["path"] for _, path in candidates))
        need(type(socket_value) is dict and
             socket_value.get("key") == "cgroupv2" and
             set(socket_value) in ({"key"}, {"key", "level"}) and
             any((predicate["right"] == path or
                  (numeric_manager and path == manager["path"])) and
                 ("level" not in socket_value or socket_value["level"] == level)
                 for level, path in candidates),
             "binding socket predicate changed")
        level, path = next((level, path) for level, path in candidates
                           if predicate["right"] == path or
                           (numeric_manager and path == manager["path"]))
        observed_cgroup = (re.escape(manager["inode"]) if numeric_manager else
                           r'"' + re.escape(path) + r'"')
        pattern = re.compile(r'(?<!\S)socket cgroupv2 level ' + str(level) +
                             r' ' + observed_cgroup + r' .*?accept comment "' +
                             re.escape(marker) + r'" # handle ' + str(handle) + r'$')
        need(sum(bool(pattern.search(line.strip())) for line in lines) == 1,
             "nft text cgroup level or handle changed")
        matched.append(handle)
    need(len(set(matched)) == len(matched), "duplicate bound rule handle")
    # nft JSON is the primary semantic view; both numeric interface grants
    # must identify their own protected ifindex at the same text handle.
    numeric = []
    for item in raw:
        if "rule" not in item:
            continue
        row = item["rule"]
        values = [expr["match"]["right"] for expr in row["expr"]
                  if "match" in expr and
                  expr["match"].get("left") == {"meta": {"key": "oif"}}]
        if values:
            need(len(values) == 1 and
                 type(values[0]) in (int, str) and
                 type(row.get("handle")) is int,
                 "numeric capture grant invalid")
            identity = _numeric_oif_identity(row, capture, capture_interface,
                                             manager, manager_interface)
            numeric.append((row["handle"], values[0], identity))
    for handle, readback, (name, ifindex) in numeric:
        if type(readback) is str:
            need(readback == name and
                 IFACE.fullmatch(readback) is not None,
                 "numeric grant resolved name invalid")
            token = '"' + readback + '"'
        else:
            need(readback == ifindex, "numeric grant index invalid")
            token = str(readback)
        # `meta oif` is a numeric interface comparison in the kernel even
        # when nft prints its current name. `oifname` remains distinct and
        # cannot satisfy this JSON predicate or the text handle check.
        pattern = re.compile(r'(?<!\S)(?:meta )?oif ' + re.escape(token) +
                             r'(?=\s) .*?accept(?: .*?)? # handle ' + str(handle) + r'$')
        need(sum(bool(pattern.search(line.strip())) for line in lines) == 1,
             "nft text numeric ifindex or handle changed")


def _live_capture_index(name: str, expected: int) -> None:
    _live_interface_index(name, expected, "capture")


def _live_interface_index(name: str, expected: int, role: str) -> None:
    try:
        observed = socket.if_nametoindex(name)
    except OSError as error:
        raise PolicyRefused(f"{role} interface identity unavailable") from error
    need(observed == expected, f"{role} interface identity changed")


def _numeric_oif_identity(rule: dict, capture: dict | None,
                          capture_interface: str | None,
                          manager: dict | None,
                          manager_interface: str | None) -> tuple[str, int]:
    marker = _marker(manager, "manager") if manager is not None else None
    manager_markers = (marker, marker.replace("aegis-v2-", "aegis-post-", 1)) \
        if marker is not None else ()
    if rule.get("comment") in manager_markers:
        need(manager is not None and
             manager.get("schema") == "aegis_device_guard_binding_v2" and
             manager_interface is not None,
             "numeric manager grant has no protected receipt")
        return manager_interface, manager["ifindex"]
    need(capture is not None and capture_interface is not None and
         rule.get("comment") is None,
         "numeric capture grant has no protected receipt")
    return capture_interface, capture["ifindex"]


def _normalized_numeric_oif(actual: dict[str, list[dict]],
                            capture: dict | None,
                            capture_interface: str,
                            manager: dict | None,
                            manager_interface: str) -> dict[str, list[dict]]:
    """Compare nft's resolved display name as the protected numeric ifindex.

    Only each role's `meta oif` expression is normalized against its own
    protected receipt; `oifname` and every other expression remain exact.
    The returned copy is used for comparison only, never as the policy hash.
    """
    normalized = json.loads(json.dumps(actual))
    for rules in normalized.values():
        for rule in rules:
            numeric = [expression.get("match") for expression in rule.get("expr", [])
                       if expression.get("match", {}).get("left") ==
                       {"meta": {"key": "oif"}}]
            if not numeric:
                continue
            need(len(numeric) == 1, "duplicate numeric interface grant")
            name, ifindex = _numeric_oif_identity(
                rule, capture, capture_interface, manager, manager_interface)
            for expression in rule.get("expr", []):
                match = expression.get("match")
                if not isinstance(match, dict) or match.get("left") != {
                        "meta": {"key": "oif"}}:
                    continue
                value = match.get("right")
                if type(value) is str:
                    need(value == name and
                         IFACE.fullmatch(value) is not None,
                         "numeric grant resolved name changed")
                    _live_interface_index(value, ifindex, "numeric grant")
                    match["right"] = ifindex
                else:
                    need(type(value) is int and value == ifindex,
                         "numeric grant index changed")
    return normalized


def _expected_with_elided_levels(expected: dict[str, list[dict]],
                                 actual: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Permit nft's documented omission only when text proves exact level."""
    copy = json.loads(json.dumps(expected))
    for chain in copy:
        if len(copy[chain]) != len(actual[chain]):
            return copy
        for wanted, seen in zip(copy[chain], actual[chain]):
            if len(wanted["expr"]) != len(seen.get("expr", [])):
                continue
            for wanted_expr, seen_expr in zip(wanted["expr"], seen["expr"]):
                if "match" not in wanted_expr or "match" not in seen_expr:
                    continue
                left = wanted_expr["match"].get("left")
                observed_left = seen_expr["match"].get("left")
                if (type(left) is dict and "socket" in left and
                        type(observed_left) is dict and
                        observed_left == {"socket": {"key": "cgroupv2"}} and
                        type(left["socket"]) is dict and
                        set(left["socket"]) == {"key", "level"}):
                    del left["socket"]["level"]
    return copy


def canonical_manager_projection(projection: bytes,
                                 manager: bytes | dict | None) -> bytes:
    """Keep a proved manager socket predicate's original named seal.

    Call only after the full JSON/text policy verifier has checked the
    protected binding, marker, level and handle. Client predicates remain
    byte-for-byte strict. The live named form returns its original bytes.
    """
    if manager is None:
        return projection
    if type(manager) is bytes:
        manager = json.loads(manager, object_pairs_hook=unique)
    need(type(manager) is dict and type(manager.get("path")) is str and
         type(manager.get("inode")) is str and
         manager["inode"].isascii() and manager["inode"].isdecimal() and
         str(int(manager["inode"])) == manager["inode"] and
         int(manager["inode"]) > 0,
         "canonical manager binding invalid")
    rows = json.loads(projection, object_pairs_hook=unique)
    need(type(rows) is list, "canonical guard projection invalid")
    marker = _marker(manager, "manager")
    changes = 0
    manager_rules = set()
    for item in rows:
        if type(item) is not dict or type(item.get("rule")) is not dict:
            continue
        rule = item["rule"]
        if rule.get("comment") != marker:
            continue
        need(rule.get("chain") == "output" and type(rule.get("expr")) is list,
             "canonical manager rule invalid")
        matches = [expr["match"] for expr in rule["expr"]
                   if type(expr) is dict and type(expr.get("match")) is dict and
                   type(expr["match"].get("left")) is dict and
                   "socket" in expr["match"]["left"]]
        need(len(matches) == 1, "canonical manager socket invalid")
        match = matches[0]
        need(match.get("right") in (manager["path"], manager["inode"]),
             "canonical manager inode changed")
        if match["right"] == manager["inode"]:
            match["right"] = manager["path"]
            changes += 1
        # The renderer can own one IPv4 and one IPv6 DHCP output rule. The
        # caller already checked the complete JSON/text renderer; this bound
        # still refuses a duplicate or third marker before sealing the view.
        identity = json.dumps(rule, sort_keys=True, separators=(",", ":"))
        need(identity not in manager_rules, "canonical manager duplicate")
        manager_rules.add(identity)
    need(len(manager_rules) <= 2 and changes <= len(manager_rules),
         "canonical manager duplicate")
    return (json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
            if changes else projection)


def prove_manager_only_retirement(state_bytes: bytes, manager: dict) -> None:
    """The old and new trusted renderers differ only by old manager DHCP ACCEPTs.

    This is a structural proof, not a way to admit a kernel readback. The
    caller separately authenticates the old terminal seal and verifies the
    current full JSON/text table against the no-manager renderer.
    """
    state = parse_state(state_bytes)
    need(type(manager) is dict and
         manager.get("schema") == "aegis_device_guard_binding_v2" and
         manager.get("state_sha256") ==
         hashlib.sha256(state_bytes.rstrip(b"\n")).hexdigest(),
         "retired manager binding invalid")
    _binding(manager, "manager", manager["state_sha256"], state["manager"])
    old = _expected(state, None, manager)
    current = _expected(state, None, None)
    marker = _marker(manager, "manager")
    post_marker = marker.replace("aegis-v2-", "aegis-post-", 1)
    removed = {"output": [], "postroute": []}
    for chain in old:
        retained = []
        for rule in old[chain]:
            if rule.get("comment") in (marker, post_marker):
                need(chain in removed and
                     rule.get("comment") ==
                     (marker if chain == "output" else post_marker) and
                     rule.get("expr", [])[-1:] == [{"accept": None}],
                     "retired manager rule invalid")
                removed[chain].append(rule)
            else:
                retained.append(rule)
        need(retained == current[chain], "manager retirement changed another rule")
    count = int(state["dhcp4"] == "1") + int(state["dhcp6"] == "1")
    need(count > 0 and len(removed["output"]) == count and
         len(removed["postroute"]) == count,
         "manager retirement has no bounded DHCP exception")


def without_current_manager(projection: bytes, state_bytes: bytes,
                            manager: dict) -> bytes:
    """Project a fully verified live manager policy onto its exact deny base.

    The caller must first verify the entire live JSON/text table, protected
    binding, and PID1 manager identity. Only the two renderer-owned DHCP rule
    pairs may be removed from this comparison view; the kernel is unchanged.
    """
    state = parse_state(state_bytes)
    expected = int(state["dhcp4"] == "1") + int(state["dhcp6"] == "1")
    if expected:
        prove_manager_only_retirement(state_bytes, manager)
    else:
        _binding(manager, "manager",
                 hashlib.sha256(state_bytes.rstrip(b"\n")).hexdigest(),
                 state["manager"])
    rows = json.loads(projection, object_pairs_hook=unique)
    need(type(rows) is list, "current manager projection invalid")
    marker = _marker(manager, "manager")
    post_marker = marker.replace("aegis-v2-", "aegis-post-", 1)
    count = {"output": 0, "postroute": 0}
    retained = []
    for item in rows:
        rule = item.get("rule") if type(item) is dict else None
        comment = rule.get("comment") if type(rule) is dict else None
        if comment in (marker, post_marker):
            chain = rule.get("chain")
            need(chain in count and
                 comment == (marker if chain == "output" else post_marker),
                 "current manager projection rule changed")
            count[chain] += 1
        else:
            retained.append(item)
    need(count == {"output": expected, "postroute": expected},
         "current manager projection incomplete")
    result = json.dumps(retained, sort_keys=True, separators=(",", ":")).encode()
    rules, _chains = _canonical_rules(result)
    need(rules == _expected(state, None, None),
         "current manager changed deny base")
    return result


def verify_expected_policy(state_bytes: bytes, nft_json_bytes: bytes,
                           nft_text_bytes: bytes, client_binding: bytes | dict | None = None,
                           manager_binding: bytes | dict | None = None, *,
                           boot_id: str, capture_binding: bytes | dict | None = None) -> str:
    """Return the full kernel policy projection SHA only for exact v2 semantics.

    Inputs must be read under the same held guard flock by the installed
    caller. A protected receipt must retain the state and policy hashes.
    """
    state = parse_state(state_bytes)
    need(type(boot_id) is str and BOOT.fullmatch(boot_id) is not None,
         "live boot identity missing")
    state_sha = hashlib.sha256(state_bytes.rstrip(b"\n")).hexdigest()
    def decode_binding(value: bytes | dict | None) -> dict | None:
        if type(value) is bytes:
            need(0 < len(value) <= 4096, "invalid binding size")
            try:
                return json.loads(value, object_pairs_hook=unique)
            except (UnicodeError, ValueError) as error:
                raise PolicyRefused("invalid binding JSON") from error
        return value
    client = decode_binding(client_binding)
    manager = decode_binding(manager_binding)
    capture = decode_binding(capture_binding)
    _binding(client, "client", state_sha, "aegis-client.service")
    _binding(manager, "manager", state_sha, state["manager"])
    for binding in (client, manager):
        if binding is not None:
            need(binding["boot_id"] == boot_id, "binding boot differs from host")
    if capture is not None:
        need(type(capture) is dict and set(capture) == {
            "schema", "boot_id", "netns_ino", "private_unit", "invocation_id",
            "main_pid", "ifindex", "worker_sha256", "client_path", "client_inode", "client_invocation"
        } and capture["schema"] == "aegis_device_guard_capture_binding_v1" and
            capture["boot_id"] == boot_id and client is not None and
            state.get("capture_profile", "full-wide-tun") == "full-wide-tun" and
            capture["private_unit"] == client["path"].rsplit("/", 1)[-1] and
            capture["client_path"] == client["path"] and
            capture["client_inode"] == client["inode"] and
            capture["client_invocation"] == client["invocation"] and
            capture["invocation_id"] == client["invocation"] and
            type(capture["netns_ino"]) is int and capture["netns_ino"] > 0 and
            type(capture["main_pid"]) is int and capture["main_pid"] > 1 and
            type(capture["ifindex"]) is int and capture["ifindex"] > 0 and
            type(capture["worker_sha256"]) is str and HEX64.fullmatch(capture["worker_sha256"]) is not None and
            type(capture["invocation_id"]) is str and
            HEX32.fullmatch(capture["invocation_id"]) is not None,
            "capture binding invalid")
        _live_capture_index(state["capture_interface"], capture["ifindex"])
    if manager is not None:
        need(manager.get("schema") == "aegis_device_guard_binding_v2",
             "DHCP manager has no protected uplink ifindex")
        _live_interface_index(state["uplink"], manager["ifindex"], "manager")
    need(type(nft_json_bytes) is bytes and 0 < len(nft_json_bytes) <= MAX_INPUT,
         "invalid nft JSON readback size")
    try:
        projection, _handles, _counters = policy_projection(nft_json_bytes)
    except (ValueError, RuntimeError) as error:
        raise PolicyRefused("invalid full nft policy readback") from error
    actual, _chains = _canonical_rules(projection)
    scoped_reply = _scoped_reply_binding(client, boot_id)
    expected = _expected(state, client, manager, scoped_reply,
                         local_guard_dnat_ports(state_bytes, client, boot_id), capture)
    _text_binding_levels(nft_text_bytes, nft_json_bytes, expected, capture,
                         state["capture_interface"], manager, state["uplink"])
    normalized = _normalized_numeric_oif(actual, capture,
                                         state["capture_interface"], manager,
                                         state["uplink"])
    if manager is not None:
        for rule in normalized["output"]:
            if rule.get("comment") != _marker(manager, "manager"):
                continue
            matches = [expr["match"] for expr in rule["expr"]
                       if type(expr) is dict and type(expr.get("match")) is dict and
                       type(expr["match"].get("left")) is dict and
                       "socket" in expr["match"]["left"]]
            need(len(matches) == 1 and
                 matches[0].get("right") in (manager["path"], manager["inode"]),
                 "manager socket predicate changed")
            if matches[0]["right"] == manager["inode"]:
                matches[0]["right"] = manager["path"]
    need(normalized == _expected_with_elided_levels(expected, normalized),
         "kernel guard differs from trusted v2 renderer")
    if capture is not None:
        _live_capture_index(state["capture_interface"], capture["ifindex"])
    if manager is not None:
        _live_interface_index(state["uplink"], manager["ifindex"], "manager")
    return hashlib.sha256(projection).hexdigest()


def _legacy_state(raw: bytes) -> dict[str, str]:
    """The v1 networking.service state has static management addresses."""
    need(type(raw) is bytes and 0 < len(raw) <= 16384, "invalid v1 state size")
    try:
        lines = raw.decode("ascii").splitlines()
        pairs = [line.split("=", 1) for line in lines]
    except (UnicodeError, ValueError) as error:
        raise PolicyRefused("invalid v1 state encoding") from error
    required = {"schema", "armed", "service", "uplink", "manager",
                "capture_interface", "management_ipv4", "management_ipv6",
                "management_ports", "dhcp4", "dhcp6", "initramfs_network"}
    need(all(len(pair) == 2 for pair in pairs) and
         len(pairs) == len({key for key, _ in pairs}), "invalid v1 state fields")
    state = dict(pairs)
    need(set(state) == required and state["schema"] == "aegis_device_guard_v1" and
         state["armed"] == "1" and state["service"] == "aegis-client.service" and
         state["manager"] in ("networking.service", "systemd-networkd.service",
                              "NetworkManager.service") and
         IFACE.fullmatch(state["uplink"]) is not None and
         state["uplink"] not in ("lo", "aegis-tun0") and
         state["capture_interface"] == "aegis-tun0" and
         state["dhcp4"] in ("0", "1") and state["dhcp6"] in ("0", "1") and
         state["initramfs_network"] == "absent_verified", "invalid v1 state")
    addresses = (state["management_ipv4"], state["management_ipv6"])
    for version, address in ((4, addresses[0]), (6, addresses[1])):
        if address:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError as error:
                raise PolicyRefused("invalid v1 management address") from error
            need(parsed.version == version and not (parsed.is_unspecified or
                 parsed.is_multicast or parsed.is_loopback), "invalid v1 address")
    ports = state["management_ports"].split(",") if state["management_ports"] else []
    need(len(ports) <= 8 and len(ports) == len(set(ports)) and
         all(p.isascii() and p.isdecimal() and 1 <= int(p) <= 65535 and
             str(int(p)) == p for p in ports) and
         (not ports or any(addresses)), "invalid v1 management ports")
    return state


def _legacy_expected(state: dict[str, str], cgroup: str | None,
                     capture: dict | None) -> dict[str, list[dict]]:
    """Mirror only the installed v1 renderer; unknown accepts never match."""
    uplink = state["uplink"]
    rules: dict[str, list[dict]] = {name: [] for name in
                                    ("incoming", "output", "forward", "postroute")}
    out = rules["output"]
    out.append(_rule("output", [_cmp(_meta("mark"),
        {"set": [0xa361c001, 0xa361c002]}),
        {"mangle": {"key": _meta("mark"), "value": 0}}]))
    out.append(_rule("output", _accept([_cmp(_meta("oifname"), "lo")])))
    if capture is not None:
        out.append(_rule("output", _accept([
            _cmp(_meta("oif"), capture["ifindex"]),
            _cmp(_meta("oifkind"), "tun")])))
    if cgroup is not None:
        level = len(cgroup.split("/"))
        out.append(_rule("output", _accept([
            _cmp({"socket": {"key": "cgroupv2", "level": level}}, cgroup)])))
        for protocol, port in (("tcp", 15080), ("udp", 15081)):
            out.append(_rule("output", _accept([
                _cmp(_payload("ip", "daddr"), "127.0.0.1"),
                _in(_ct("status"), "dnat"),
                _cmp(_payload(protocol, "dport"), port)])))
    for family, address in (("ip", state["management_ipv4"]),
                            ("ip6", state["management_ipv6"])):
        if not address:
            continue
        for value in filter(None, state["management_ports"].split(",")):
            port = int(value)
            rules["incoming"].append(_rule("incoming", [
                _cmp(_meta("iifname"), uplink),
                _cmp(_payload(family, "daddr"), address),
                _cmp(_payload("tcp", "dport"), port),
                _cmp(_ct("direction"), "original"),
                _cmp(_ct("state"), {"set": ["established", "new"]}),
                {"mangle": {"key": _ct("mark"), "value": 0xa3610001}}]))
            out.append(_rule("output", _accept([
                _cmp(_meta("oifname"), uplink),
                _cmp(_payload(family, "saddr"), address),
                _cmp(_ct("direction"), "reply"),
                _cmp(_ct("mark"), 0xa3610001),
                _cmp(_ct(family + " daddr", "original"), address),
                _cmp(_ct("proto-dst", "original"), port),
                _cmp(_payload("tcp", "sport"), port)])))
    if state["dhcp4"] == "1":
        out.append(_rule("output", _accept([
            _cmp(_meta("oifname"), uplink),
            _cmp(_payload("ip", "daddr"), "255.255.255.255"),
            _cmp(_payload("udp", "sport"), 68),
            _cmp(_payload("udp", "dport"), 67)])))
    if state["dhcp6"] == "1":
        out.append(_rule("output", _accept([
            _cmp(_meta("oifname"), uplink),
            _cmp(_payload("ip6", "saddr"), {"prefix": {"addr": "fe80::", "len": 10}}),
            _cmp(_payload("ip6", "daddr"), "ff02::1:2"),
            _cmp(_payload("udp", "sport"), 546),
            _cmp(_payload("udp", "dport"), 547)])))
    out.append(_rule("output", _accept([
        _cmp(_meta("oifname"), uplink),
        _cmp(_payload("ip6", "hoplimit"), 255),
        _cmp(_payload("ip6", "daddr"), {"set": [
            {"prefix": {"addr": "fe80::", "len": 10}},
            {"prefix": {"addr": "ff02::", "len": 16}}]}),
        _cmp(_payload("icmpv6", "type"), {"set": [
            "nd-router-solicit", "nd-neighbor-solicit", "nd-neighbor-advert"]})])))
    out.append(_rule("output", [{"counter": {"packets": 0, "bytes": 0}},
                                {"drop": None}]))
    rules["forward"].append(_rule("forward", [
        {"counter": {"packets": 0, "bytes": 0}}, {"drop": None}]))
    for rule in out[1:]:
        twin = json.loads(json.dumps(rule))
        twin["chain"] = "postroute"
        for expr in twin["expr"]:
            if ("match" in expr and isinstance(expr["match"].get("left"), dict) and
                    "socket" in expr["match"]["left"]):
                expr["match"] = {"op": "==", "left": _meta("mark"),
                                 "right": 0xa361c001}
                twin["expr"].insert(-2, {"mangle": {"key": _meta("mark"),
                                                  "value": 0}})
                break
        rules["postroute"].append(twin)
    if cgroup is not None:
        for rule in out:
            if any("match" in expr and "socket" in expr["match"].get("left", {})
                   for expr in rule["expr"]):
                rule["expr"].insert(-2, {"mangle": {"key": _meta("mark"),
                                                   "value": 0xa361c001}})
    return rules


def _legacy_unit_facts() -> tuple[str | None, dict[str, str]]:
    command = ("/usr/bin/systemctl", "show", "aegis-client.service", "--no-pager",
               "-p", "MainPID", "-p", "ControlPID", "-p", "ActiveState",
               "-p", "SubState", "-p", "InvocationID", "-p", "ControlGroup")
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=3, check=False)
    need(result.returncode == 0 and len(result.stdout) <= 4096,
         "v1 PID1 identity unavailable")
    try:
        pairs = [line.split("=", 1) for line in result.stdout.decode("ascii").splitlines()]
    except UnicodeError as error:
        raise PolicyRefused("v1 PID1 identity encoding") from error
    need(all(len(pair) == 2 for pair in pairs) and
         len(pairs) == len({key for key, _ in pairs}), "v1 PID1 identity malformed")
    facts = dict(pairs)
    need(set(facts) == {"MainPID", "ControlPID", "ActiveState", "SubState",
                        "InvocationID", "ControlGroup"}, "v1 PID1 facts changed")
    group = "/system.slice/aegis-client.service"
    active = facts["ActiveState"] in ("active", "activating", "deactivating")
    running = any(facts[key].isascii() and facts[key].isdecimal() and
                  int(facts[key]) > 1 for key in ("MainPID", "ControlPID"))
    if not active or not running:
        return None, facts
    need(facts["ControlGroup"] == group and
         HEX32.fullmatch(facts["InvocationID"]) is not None and
         (Path("/sys/fs/cgroup") / group.lstrip("/")).is_dir(),
         "v1 active cgroup differs from PID1")
    return group.lstrip("/"), facts


def _legacy_tun_detail(expected_index: int) -> None:
    result = subprocess.run(("/usr/sbin/ip", "-j", "-d", "link", "show", "dev",
                             "aegis-tun0"), stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=3, check=False)
    need(result.returncode == 0 and 0 < len(result.stdout) <= 4096 and
         len(result.stderr) <= 4096, "v1 capture link detail unavailable")
    try:
        detail = json.loads(result.stdout, object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise PolicyRefused("v1 capture link detail malformed") from error
    need(type(detail) is list and len(detail) == 1 and type(detail[0]) is dict,
         "v1 capture link detail shape changed")
    info = detail[0].get("linkinfo")
    need(type(info) is dict and type(info.get("info_data")) is dict,
         "v1 capture link metadata changed")
    need(
         detail[0].get("ifname") == "aegis-tun0" and
         detail[0].get("ifindex") == expected_index and
         type(detail[0].get("ifindex")) is int and
         info.get("info_kind") == "tun" and
         info["info_data"].get("type") == "tun" and
         info["info_data"].get("persist") is False,
         "v1 capture is not the owned nonpersistent TUN")
    _live_capture_index("aegis-tun0", expected_index)


def _legacy_capture(capture: bytes | None, boot_id: str,
                    cgroup: str | None, facts: dict[str, str]) -> dict | None:
    if capture is None:
        return None
    need(type(capture) is bytes and 0 < len(capture) <= 4096,
         "invalid v1 capture receipt size")
    try:
        value = json.loads(capture, object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise PolicyRefused("invalid v1 capture receipt") from error
    group = "system.slice/aegis-client.service"
    need(type(value) is dict and set(value) == {
        "schema", "boot_id", "netns_ino", "private_unit", "invocation_id",
        "main_pid", "ifindex", "worker_sha256", "client_path", "client_inode",
        "client_invocation"} and
        value["schema"] == "aegis_device_guard_capture_binding_v1" and
        value["boot_id"] == boot_id and value["private_unit"] == "aegis-client.service" and
        value["client_path"] == group and cgroup == group and
        value["invocation_id"] == value["client_invocation"] == facts["InvocationID"] and
        type(value["main_pid"]) is int and value["main_pid"] > 1 and
        facts["MainPID"] == str(value["main_pid"]) and
        type(value["ifindex"]) is int and value["ifindex"] > 0 and
        type(value["netns_ino"]) is int and value["netns_ino"] > 0 and
        type(value["client_inode"]) is str and
        value["client_inode"].isascii() and value["client_inode"].isdecimal() and
        value["client_inode"] == str((Path("/sys/fs/cgroup") / group).stat().st_ino) and
        type(value["worker_sha256"]) is str and
        HEX64.fullmatch(value["worker_sha256"]) is not None,
        "v1 capture owner receipt differs from PID1")
    _legacy_tun_detail(value["ifindex"])
    pid = value["main_pid"]
    pidfd = os.pidfd_open(pid, 0)
    try:
        need(not select.select([pidfd], [], [], 0)[0] and
             Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
             f"0::/{group}\n" and
             Path(f"/proc/{pid}/ns/net").stat().st_ino ==
             value["netns_ino"] == Path("/proc/1/ns/net").stat().st_ino,
             "v1 capture process changed")
        binary = Path("/usr/local/bin/aegis-client")
        installed = binary.stat(follow_symlinks=False)
        actual = Path(f"/proc/{pid}/exe").stat()
        need(stat.S_ISREG(installed.st_mode) and installed.st_uid == 0 and
             installed.st_mode & 0o022 == 0 and installed.st_nlink == 1 and
             0 < installed.st_size <= 512 << 20 and
             (installed.st_dev, installed.st_ino) == (actual.st_dev, actual.st_ino),
             "v1 installed client changed")
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode,
            item.st_uid, item.st_nlink, item.st_size, item.st_mtime_ns,
            item.st_ctime_ns)
        digest = hashlib.sha256()
        executable_fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(identity(os.fstat(executable_fd)) == identity(installed),
                 "v1 installed client descriptor changed")
            with os.fdopen(executable_fd, "rb", closefd=False) as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
            after_image = Path(f"/proc/{pid}/exe").stat()
            need(identity(os.fstat(executable_fd)) == identity(installed) ==
                 identity(binary.stat(follow_symlinks=False)) and
                 (after_image.st_dev, after_image.st_ino) ==
                 (installed.st_dev, installed.st_ino) and
                 digest.hexdigest() == value["worker_sha256"],
             "v1 installed client digest changed")
        finally:
            os.close(executable_fd)
        descriptors = list(Path(f"/proc/{pid}/fd").iterdir())
        need(len(descriptors) <= 4096, "v1 capture descriptor inventory unbounded")
        owns = False
        for descriptor in descriptors:
            if not descriptor.name.isdecimal():
                continue
            try:
                if os.readlink(descriptor) != "/dev/net/tun":
                    continue
                info = Path(f"/proc/{pid}/fdinfo/{descriptor.name}").read_text(
                    encoding="ascii")
            except (FileNotFoundError, ProcessLookupError):
                continue
            need(len(info) <= 4096, "v1 capture fdinfo unbounded")
            if any(line == "iff:\taegis-tun0" for line in info.splitlines()):
                owns = True
                break
        need(owns and not select.select([pidfd], [], [], 0)[0],
             "v1 capture TUN FD lost")
        _, after_facts = _legacy_unit_facts()
        need(after_facts == facts, "v1 PID1 owner changed during proof")
        _legacy_tun_detail(value["ifindex"])
    finally:
        os.close(pidfd)
    _live_capture_index("aegis-tun0", value["ifindex"])
    return value


def verify_expected_legacy_policy(state_bytes: bytes, nft_json_bytes: bytes,
                                  nft_text_bytes: bytes, *, boot_id: str,
                                  capture_binding: bytes | None = None) -> str:
    """Admit an installed v1 guard only through its exact renderer and owner."""
    state = _legacy_state(state_bytes)
    need(BOOT.fullmatch(boot_id) is not None, "v1 boot identity invalid")
    cgroup, facts = _legacy_unit_facts()
    capture = _legacy_capture(capture_binding, boot_id, cgroup, facts)
    try:
        projection, _, _ = policy_projection(nft_json_bytes)
    except (ValueError, RuntimeError) as error:
        raise PolicyRefused("invalid v1 full nft readback") from error
    actual, _ = _canonical_rules(projection)
    normalized = _normalized_numeric_oif(actual, capture, "aegis-tun0", None, state["uplink"])
    candidates = [cgroup] if capture is not None else [None, cgroup]
    for candidate in dict.fromkeys(candidates):
        expected = _legacy_expected(state, candidate, capture)
        try:
            _text_binding_levels(nft_text_bytes, nft_json_bytes, expected,
                                 capture, "aegis-tun0")
            need(normalized == _expected_with_elided_levels(expected, normalized),
                 "v1 guard differs from trusted renderer")
            if candidate is not None:
                raw = json.loads(nft_json_bytes, object_pairs_hook=unique)["nftables"]
                bound = [item["rule"] for item in raw if "rule" in item and
                         any(expr.get("match", {}).get("left", {}).get("socket", {}).get("key") ==
                             "cgroupv2" for expr in item["rule"].get("expr", []))]
                need(len(bound) == 1, "v1 cgroup rule inventory changed")
                handle = bound[0]["handle"]
                level = len(candidate.split("/"))
                pattern = re.compile(r'socket cgroupv2 level ' + str(level) +
                                     r' "' + re.escape(candidate) +
                                     r'" .*?accept # handle ' + str(handle) + r'$')
                need(sum(bool(pattern.search(line.strip())) for line in
                         nft_text_bytes.decode("ascii").splitlines()) == 1,
                     "v1 cgroup text level changed")
            if capture is not None:
                _live_capture_index("aegis-tun0", capture["ifindex"])
            return hashlib.sha256(projection).hexdigest()
        except PolicyRefused:
            continue
    raise PolicyRefused("v1 guard differs from every authenticated candidate")


# An explicit prerouting_scoped LinuxRedirect owns this table alone.  Neither
# its renderer nor its inverse touches the persistent device-guard table or
# any pre-existing foreign policy.  A live receipt is one-use and survives
# process failure until the exact private owner has been stopped and denied.
SCOPED_TABLE = "aegis_auto_redirect"
SCOPED_PARENT = Path("/var/lib/aegis-install/client")
SCOPED_INTENT = SCOPED_PARENT / "auto-redirect-intent.json"
SCOPED_PREPARED = SCOPED_PARENT / "auto-redirect-prepared.json"
SCOPED_BOUND = SCOPED_PARENT / "auto-redirect-bound.json"
SCOPED_ACTIVE = SCOPED_PARENT / "auto-redirect-active.json"
SCOPED_RETIRE_INTENT = SCOPED_PARENT / "auto-redirect-retire-intent.json"
SCOPED_NFT = Path("/usr/sbin/nft")
SCOPED_IP = Path("/usr/sbin/ip")
SCOPED_MAX_READBACK = 1 << 20


def _scoped_json(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _scoped_hash(value: dict) -> str:
    return hashlib.sha256(_scoped_json(value)).hexdigest()


def _scoped_bytes(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                 os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
             before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
             0 < before.st_size <= 16384, "untrusted scoped receipt")
        raw = os.read(fd, 16385)
        after = os.fstat(fd)
        named = path.stat(follow_symlinks=False)
        def identity(info: os.stat_result) -> tuple[int, ...]:
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                    info.st_nlink, info.st_size, info.st_mtime_ns,
                    info.st_ctime_ns)
        need(len(raw) == before.st_size and
             identity(before) == identity(after) == identity(named),
             "scoped receipt changed")
        return raw
    finally:
        os.close(fd)


def _scoped_read(path: Path) -> dict:
    return json.loads(_scoped_bytes(path), object_pairs_hook=unique)


def _scoped_write(path: Path, value: dict) -> str:
    parent = SCOPED_PARENT.stat(follow_symlinks=False)
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
         not parent.st_mode & 0o022, "untrusted scoped parent")
    raw = _scoped_json(value)
    need(0 < len(raw) <= 16384, "scoped receipt oversized")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), "scoped receipt short write")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(SCOPED_PARENT, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    need(_scoped_read(path) == value, "scoped receipt not durable")
    return hashlib.sha256(raw).hexdigest()


def _scoped_binding(binding: dict, *, check_host: bool = True) -> dict:
    fields = {"stage_dev", "stage_ino", "private_unit", "transaction_nonce",
              "planned_generation", "boot_id", "netns_ino",
              "config_sha256_initial", "config_semantic_sha256", "interface",
              "ifindex", "listen_ipv4", "listen_port", "guard_policy_sha256"}
    need(type(binding) is dict and set(binding) == fields,
         "scoped binding fields invalid")
    need(type(binding["private_unit"]) is str and
         PRIVATE.fullmatch(binding["private_unit"]) is not None and
         type(binding["transaction_nonce"]) is str and
         HEX32.fullmatch(binding["transaction_nonce"]) is not None and
         type(binding["boot_id"]) is str and
         BOOT.fullmatch(binding["boot_id"]) is not None and
         all(type(binding[k]) is str and HEX64.fullmatch(binding[k]) is not None
             for k in ("planned_generation", "config_sha256_initial",
                       "config_semantic_sha256", "guard_policy_sha256")) and
         all(type(binding[k]) is int and binding[k] > 0
             for k in ("stage_dev", "stage_ino", "netns_ino", "ifindex")) and
         type(binding["interface"]) is str and
         IFACE.fullmatch(binding["interface"]) is not None and
         binding["interface"] != "lo" and
         type(binding["listen_ipv4"]) is str and
         binding["listen_port"] == 15080,
         "scoped binding invalid")
    address = ipaddress.ip_address(binding["listen_ipv4"])
    need(type(address) is ipaddress.IPv4Address and
         not (address.is_loopback or address.is_unspecified or
              address.is_multicast or address.is_link_local),
         "scoped listen address invalid")
    if check_host:
        need(binding["boot_id"] == Path("/proc/sys/kernel/random/boot_id")
             .read_text(encoding="ascii").strip() and
             binding["netns_ino"] == os.stat("/proc/self/ns/net").st_ino and
             socket.if_nametoindex(binding["interface"]) == binding["ifindex"],
             "scoped host identity changed")
        result = subprocess.run(
            [str(SCOPED_IP), "-j", "-4", "address", "show", "dev",
             binding["interface"]], capture_output=True, timeout=2,
            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
        need(result.returncode == 0 and len(result.stdout) <= 16384 and
             len(result.stderr) <= 4096, "scoped interface readback unavailable")
        rows = json.loads(result.stdout, object_pairs_hook=unique)
        need(type(rows) is list and len(rows) == 1 and
             rows[0].get("ifname") == binding["interface"] and
             rows[0].get("ifindex") == binding["ifindex"] and
             type(rows[0].get("addr_info")) is list,
             "scoped interface address changed")
        primary = [item.get("local") for item in rows[0]["addr_info"]
                   if type(item) is dict and item.get("family") == "inet" and
                   item.get("secondary", False) is False]
        # nft REDIRECT chooses the ingress interface's primary IPv4.  A
        # secondary or ambiguous multi-primary listener is not that target.
        need(primary == [binding["listen_ipv4"]],
             "scoped interface address changed")
    return binding


def _scoped_marker(binding: dict) -> tuple[str, int]:
    owner = hashlib.sha256(_scoped_json(binding)).hexdigest()
    mark = int(owner[:8], 16)
    if mark in (0, 0xa3610001, 0xa3610002):
        mark ^= 0x5a5a5a5a
    return "aegis-scoped-" + owner, mark


def _scoped_nft(args: list[str], *, script: bytes | None = None,
                timeout: float = 2.0) -> subprocess.CompletedProcess[bytes]:
    need(os.geteuid() == 0 and SCOPED_NFT.is_file(),
         "scoped nft authority unavailable")
    result = subprocess.run([str(SCOPED_NFT), *args], input=script,
                            capture_output=True, timeout=timeout,
                            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C",
                                 "LC_ALL": "C"})
    need(len(result.stdout) <= SCOPED_MAX_READBACK and
         len(result.stderr) <= 4096, "scoped nft output unbounded")
    return result


def _scoped_absent() -> bool:
    # A failed table query alone may mean permissions or netlink failure.
    # Require a successful full-ruleset readback before claiming absence.
    result = _scoped_nft(["--json", "list", "ruleset"])
    need(result.returncode == 0 and result.stdout,
         "scoped ruleset absence unavailable")
    parsed = json.loads(result.stdout, object_pairs_hook=unique)
    need(type(parsed) is dict and set(parsed) == {"nftables"} and
         type(parsed["nftables"]) is list, "scoped ruleset invalid")
    for row in parsed["nftables"]:
        need(type(row) is dict and len(row) == 1,
             "scoped ruleset item invalid")
        kind, value = next(iter(row.items()))
        if kind in ("table", "chain", "rule"):
            need(type(value) is dict, "scoped ruleset body invalid")
            if value.get("family") == "ip" and value.get(
                    "table", value.get("name")) == SCOPED_TABLE:
                return False
    return True


def _scoped_expected(binding: dict, *, active: bool) -> list[dict]:
    marker, mark = _scoped_marker(binding)
    interface = binding["interface"]
    address = binding["listen_ipv4"]
    port = binding["listen_port"]

    def match(left: dict, right: object, op: str = "==") -> dict:
        return {"match": {"op": op, "left": left, "right": right}}

    iif = match({"meta": {"key": "iifname"}}, interface)
    daddr = match({"payload": {"protocol": "ip", "field": "daddr"}}, address)
    dport = match({"payload": {"protocol": "tcp", "field": "dport"}}, port)
    ctmark = match({"ct": {"key": "mark"}}, mark)
    dnat = match({"ct": {"key": "status"}}, "dnat", "in")
    counter = {"counter": {"packets": 0, "bytes": 0}}

    def rule(chain: str, expr: list[dict]) -> dict:
        return {"rule": {"family": "ip", "table": SCOPED_TABLE,
                         "chain": chain, "comment": marker, "expr": expr}}

    rows = [
        {"table": {"family": "ip", "name": SCOPED_TABLE}},
        {"chain": {"family": "ip", "table": SCOPED_TABLE,
                   "name": "input_gate", "type": "filter", "hook": "input",
                   "prio": 0, "policy": "accept"}},
    ]
    if active:
        rows.append({"chain": {"family": "ip", "table": SCOPED_TABLE,
                                "name": "prerouting", "type": "nat",
                                "hook": "prerouting", "prio": -100,
                                "policy": "accept"}})
    # nft's table listing groups base chains before their rule bodies.
    rows.extend([
        rule("input_gate", [iif, daddr, dport, dnat, ctmark,
                            counter, {"accept": None}]),
        rule("input_gate", [daddr, dport, counter, {"drop": None}]),
    ])
    if active:
        rows.extend([
            rule("prerouting", [
                iif,
                match({"fib": {"result": "type", "flags": ["daddr"]}},
                      "local", "!="),
                match({"payload": {"protocol": "tcp", "field": "dport"}},
                      port, "!="),
                match({"ct": {"key": "mark"}},
                      {"set": [0xa3610001, 0xa3610002]}, "!="),
                {"mangle": {"key": {"ct": {"key": "mark"}}, "value": mark}},
                counter, {"redirect": {"port": port}},
            ]),
        ])
    return rows


def _scoped_expected_sha(binding: dict, *, active: bool) -> str:
    raw = json.dumps(_scoped_expected(binding, active=active),
                     sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _scoped_projection(binding: dict, *, active: bool,
                       timeout: float = 2.0) -> dict[str, object]:
    result = _scoped_nft(["--json", "--handle", "list", "table", "ip",
                          SCOPED_TABLE], timeout=timeout)
    need(result.returncode == 0 and result.stdout,
         "scoped table readback unavailable")
    parsed = json.loads(result.stdout, object_pairs_hook=unique)
    need(type(parsed) is dict and set(parsed) == {"nftables"} and
         type(parsed["nftables"]) is list and
         4 <= len(parsed["nftables"]) <= 9,
         "scoped table readback invalid")
    rows: list[dict] = []
    handles: dict[str, int] = {}
    counts = {"input_gate": 0, "prerouting": 0}
    for row in parsed["nftables"]:
        need(type(row) is dict and len(row) == 1,
             "scoped table item invalid")
        kind, body = next(iter(row.items()))
        if kind == "metainfo":
            continue
        need(kind in ("table", "chain", "rule") and type(body) is dict,
             "scoped table item unexpected")
        clone = dict(body)
        handle = clone.pop("handle", None)
        if kind == "chain":
            need(type(handle) is int and handle > 0 and
                 body.get("name") in ("input_gate", "prerouting"),
                 "scoped chain handle invalid")
            handles[body["name"] + "_chain_handle"] = handle
        if kind == "rule":
            chain = body.get("chain")
            need(type(handle) is int and handle > 0 and
                 chain in counts and
                 body.get("comment") == _scoped_marker(binding)[0],
                 "scoped rule handle invalid")
            index = counts[chain]
            counts[chain] += 1
            key = ("input_allow_handle" if chain == "input_gate" and index == 0
                   else "input_drop_handle" if chain == "input_gate" and index == 1
                   else "redirect_handle" if chain == "prerouting" and index == 0
                   else None)
            need(key is not None, "scoped extra rule")
            handles[key] = handle
            expr = clone.get("expr")
            need(type(expr) is list, "scoped expressions invalid")
            normalized = []
            for item in expr:
                need(type(item) is dict and len(item) == 1,
                     "scoped expression invalid")
                if "counter" in item:
                    counter = item["counter"]
                    need(type(counter) is dict and
                         set(counter) == {"packets", "bytes"} and
                         all(type(v) is int and v >= 0
                             for v in counter.values()),
                         "scoped counter invalid")
                    normalized.append({"counter": {"packets": 0,
                                                   "bytes": 0}})
                else:
                    normalized.append(item)
            clone["expr"] = normalized
        rows.append({kind: clone})
    need(rows == _scoped_expected(binding, active=active) and
         counts == {"input_gate": 2, "prerouting": 1 if active else 0} and
         len(set(handles.values())) == len(handles),
         "scoped kernel policy differs from renderer")
    raw = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return {"policy_sha256": hashlib.sha256(raw).hexdigest(), **handles}


def _scoped_script(binding: dict, *, active: bool) -> bytes:
    marker, mark = _scoped_marker(binding)
    interface = binding["interface"]
    address = binding["listen_ipv4"]
    port = binding["listen_port"]
    if active:
        return (f"add chain ip {SCOPED_TABLE} prerouting "
                "{ type nat hook prerouting priority dstnat; policy accept; }\n"
                f'add rule ip {SCOPED_TABLE} prerouting iifname "{interface}" '
                f"fib daddr type != local tcp dport != {port} "
                "ct mark != { 0xa3610001, 0xa3610002 } "
                f"ct mark set 0x{mark:08x} counter redirect to :{port} "
                f'comment "{marker}"\n').encode("ascii")
    return (f"add table ip {SCOPED_TABLE}\n"
            f"add chain ip {SCOPED_TABLE} input_gate "
            "{ type filter hook input priority 0; policy accept; }\n"
            f'add rule ip {SCOPED_TABLE} input_gate iifname "{interface}" '
            f"ip daddr {address} tcp dport {port} ct status dnat "
            f"ct mark 0x{mark:08x} counter accept "
            f'comment "{marker}"\n'
            f"add rule ip {SCOPED_TABLE} input_gate ip daddr {address} "
            f"tcp dport {port} counter drop "
            f'comment "{marker}"\n').encode("ascii")


def _scoped_intent(binding: dict) -> dict:
    marker, mark = _scoped_marker(binding)
    return {"schema": "aegis_auto_scoped_redirect_intent_v1",
            "binding": binding, "owner_marker": marker, "conntrack_mark": mark}


def scoped_prepare(binding: dict) -> dict[str, object]:
    """Prepare a direct-listener INPUT gate before the private Main can bind.

    The caller must hold the original stage/install/guard authority and have
    armed the independent watchdog.  A crash after INTENT is recovery-only.
    """
    binding = _scoped_binding(binding)
    need(all(not path.exists() and not path.is_symlink() for path in
             (SCOPED_INTENT, SCOPED_PREPARED, SCOPED_BOUND, SCOPED_ACTIVE,
              SCOPED_RETIRE_INTENT, LOCAL_INTENT, LOCAL_BOUND, LOCAL_ACTIVE,
              LOCAL_RETIRE_INTENT)) and _scoped_absent() and
         _local_absent(),
         "prior scoped redirect requires recovery")
    intent = _scoped_intent(binding)
    intent_sha = _scoped_write(SCOPED_INTENT, intent)
    result = _scoped_nft(["-f", "-"], script=_scoped_script(binding, active=False))
    need(result.returncode == 0, "scoped input gate install failed")
    actual = _scoped_projection(binding, active=False)
    prepared = {"schema": "aegis_auto_scoped_redirect_prepared_v1",
                "intent_sha256": intent_sha, "policy": actual}
    _scoped_write(SCOPED_PREPARED, prepared)
    return actual


def _scoped_prepared(binding: dict, *, live: bool = False,
                     deadline: float | None = None) -> dict:
    need(_scoped_read(SCOPED_INTENT) == _scoped_intent(binding),
         "scoped intent changed")
    prepared = _scoped_read(SCOPED_PREPARED)
    need(type(prepared) is dict and
         set(prepared) == {"schema", "intent_sha256", "policy"} and
         prepared["schema"] == "aegis_auto_scoped_redirect_prepared_v1" and
         prepared["intent_sha256"] == _scoped_hash(_scoped_intent(binding)) and
         type(prepared["policy"]) is dict and
         set(prepared["policy"]) == {"policy_sha256", "input_gate_chain_handle",
                                     "input_allow_handle", "input_drop_handle"} and
         prepared["policy"]["policy_sha256"] ==
         _scoped_expected_sha(binding, active=False) and
         all(type(value) is int and value > 0
             for key, value in prepared["policy"].items()
             if key != "policy_sha256"),
         "scoped prepared receipt changed")
    if live:
        remaining = (2.0 if deadline is None else
                     min(2.0, deadline - time.monotonic()))
        need(remaining > 0, "scoped bind deadline elapsed")
        need(prepared["policy"] == _scoped_projection(
            binding, active=False, timeout=remaining),
             "scoped input gate changed")
        need(deadline is None or time.monotonic() < deadline,
             "scoped bind deadline elapsed")
    return prepared


def _scoped_reply_binding(client: dict | None, boot_id: str) -> dict | None:
    """Admit only a protected, prepared scope owned by the live client binding."""
    if client is None:
        return None
    if not SCOPED_INTENT.exists() and not SCOPED_INTENT.is_symlink():
        return None
    intent = _scoped_read(SCOPED_INTENT)
    need(type(intent) is dict and type(intent.get("binding")) is dict,
         "scoped reply intent invalid")
    binding = _scoped_binding(intent["binding"])
    need(intent == _scoped_intent(binding) and
         binding["boot_id"] == boot_id == client["boot_id"] and
         client["path"].rsplit("/", 1)[-1] == binding["private_unit"],
         "scoped reply owner changed")
    _scoped_prepared(binding)
    material = {"binding": binding,
                "client": {key: client[key]
                           for key in ("path", "inode", "invocation")}}
    owner = hashlib.sha256(_scoped_json(material)).hexdigest()
    return {"binding": binding, "mark": intent["conntrack_mark"],
            "marker": "aegis-auto-scoped-reply-" + owner}


def scoped_bind_invocation(binding: dict, invocation_id: str,
                           *, deadline: float) -> dict:
    """Bind the already-installed gate to the authenticated ExecStartPre PID1.

    This performs no nft mutation inside the five-second BIND_SEAL window.
    """
    binding = _scoped_binding(binding)
    need(type(invocation_id) is str and HEX32.fullmatch(invocation_id) is not None,
         "scoped invocation invalid")
    need(type(deadline) is float and time.monotonic() < deadline,
         "scoped bind deadline elapsed")
    prepared = _scoped_prepared(binding, live=True, deadline=deadline)
    need(time.monotonic() < deadline, "scoped bind deadline elapsed")
    bound = {"schema": "aegis_auto_scoped_redirect_bound_v1",
             "prepared_sha256": _scoped_hash(prepared),
             "private_unit": binding["private_unit"],
             "invocation_id": invocation_id}
    _scoped_write(SCOPED_BOUND, bound)
    return bound


def _scoped_bound(binding: dict, invocation_id: str) -> dict:
    prepared = _scoped_prepared(binding)
    expected = {"schema": "aegis_auto_scoped_redirect_bound_v1",
                "prepared_sha256": _scoped_hash(prepared),
                "private_unit": binding["private_unit"],
                "invocation_id": invocation_id}
    need(_scoped_read(SCOPED_BOUND) == expected,
         "scoped private invocation changed")
    return expected


def scoped_activate(binding: dict, invocation_id: str) -> dict[str, object]:
    """Install scoped REDIRECT only after the exact Main is active and held."""
    binding = _scoped_binding(binding)
    bound = _scoped_bound(binding, invocation_id)
    need(not SCOPED_ACTIVE.exists() and not SCOPED_ACTIVE.is_symlink(),
         "scoped redirect already active")
    result = _scoped_nft(["-f", "-"], script=_scoped_script(binding, active=True))
    need(result.returncode == 0, "scoped redirect install failed")
    actual = _scoped_projection(binding, active=True)
    active = {"schema": "aegis_auto_scoped_redirect_active_v1",
              "bound_sha256": _scoped_hash(bound), "policy": actual}
    _scoped_write(SCOPED_ACTIVE, active)
    return scoped_verify(binding, invocation_id,
                         config_semantic_sha256=binding[
                             "config_semantic_sha256"], active=True)


def scoped_verify(binding: dict, invocation_id: str, *,
                  config_semantic_sha256: str,
                  active: bool) -> dict[str, object]:
    """Reopen both the protected owner chain and exact live nft policy."""
    binding = _scoped_binding(binding)
    need(type(config_semantic_sha256) is str and
         config_semantic_sha256 == binding["config_semantic_sha256"],
         "scoped config semantics changed")
    bound = _scoped_bound(binding, invocation_id)
    actual = _scoped_projection(binding, active=active)
    if active:
        need(_scoped_read(SCOPED_ACTIVE) == {
            "schema": "aegis_auto_scoped_redirect_active_v1",
            "bound_sha256": _scoped_hash(bound), "policy": actual},
            "scoped active receipt changed")
    else:
        need(not SCOPED_ACTIVE.exists() and not SCOPED_ACTIVE.is_symlink(),
             "unexpected scoped active receipt")
    _marker, mark = _scoped_marker(binding)
    return {**actual, "private_unit": binding["private_unit"],
            "invocation_id": invocation_id,
            "interface": binding["interface"],
            "ifindex": binding["ifindex"],
            "listen_ipv4": binding["listen_ipv4"],
            "listen_port": binding["listen_port"],
            "conntrack_mark": mark}


def scoped_retire(*, unit: str, deny_check: object,
                  stopped_check: object, reboot: bool = False) -> dict:
    """Retire only this owner's table after independent deny and PID1 stop.

    Both checks are source-owned callables that perform fresh readbacks. They
    run before and after deletion. A failed check or unmatched kernel table
    leaves the sticky receipt for recovery; foreign nft objects are untouched.
    The watchdog may invoke this from its original journal after owner loss.
    """
    need(type(unit) is str and PRIVATE.fullmatch(unit) is not None and
         callable(deny_check) and callable(stopped_check),
         "scoped retire authority invalid")
    intent = _scoped_read(SCOPED_INTENT)
    need(type(intent) is dict and
         intent.get("schema") == "aegis_auto_scoped_redirect_intent_v1" and
         type(intent.get("binding")) is dict and
         intent["binding"].get("private_unit") == unit,
         "foreign scoped retire intent")
    binding = _scoped_binding(intent["binding"], check_host=not reboot)
    need(intent == _scoped_intent(binding), "scoped retire owner changed")
    if reboot:
        need(binding["boot_id"] != Path("/proc/sys/kernel/random/boot_id")
             .read_text(encoding="ascii").strip(),
             "scoped reboot inverse not needed")
    else:
        need(binding["boot_id"] == Path("/proc/sys/kernel/random/boot_id")
             .read_text(encoding="ascii").strip(),
             "scoped boot changed without reboot inverse")
    need(deny_check() is True and stopped_check() is True,
         "scoped deny or private stop not proven")
    suffix = unit[len("aegis-auto@"): -len(".service")]
    archive = SCOPED_PARENT / f"auto-redirect-retired-{suffix}.json"
    if archive.exists():
        # A previous owner may have completed the kernel inverse and crashed
        # while retiring separate immutable live leaves.  The archive holds
        # their exact hashes and the durable pre-delete intent; finish only
        # that already-proven retirement, never issue another nft mutation.
        archived = _scoped_read(archive)
        prior_retire = archived.get("retire_intent")
        need(type(prior_retire) is dict and archived == {
            "schema": "aegis_auto_scoped_redirect_retired_v1",
            "private_unit": unit,
            "original_boot_id": binding["boot_id"],
            "original_stage": [binding["stage_dev"], binding["stage_ino"]],
            "table_absent": True, "retire_intent": prior_retire} and
            prior_retire.get("intent_sha256") == _scoped_hash(intent) and
            _scoped_absent(), "scoped retired archive changed")
        for path, field in ((SCOPED_ACTIVE, "active_sha256"),
                            (SCOPED_BOUND, "bound_sha256"),
                            (SCOPED_PREPARED, "prepared_sha256"),
                            (SCOPED_RETIRE_INTENT, None)):
            if path.exists():
                current = _scoped_read(path)
                expected = (_scoped_hash(prior_retire) if field is None else
                            prior_retire[field])
                need(_scoped_hash(current) == expected,
                     "scoped retired leaf changed")
                path.unlink()
        need(_scoped_read(SCOPED_INTENT) == intent and
             deny_check() is True and stopped_check() is True and
             _scoped_absent(), "scoped retirement changed")
        SCOPED_INTENT.unlink()
        directory = os.open(SCOPED_PARENT, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return {"archive_sha256": _scoped_hash(archived),
                "native_inverse_sha256": _scoped_hash(prior_retire)}
    prepared = (_scoped_read(SCOPED_PREPARED)
                if SCOPED_PREPARED.exists() else None)
    bound = _scoped_read(SCOPED_BOUND) if SCOPED_BOUND.exists() else None
    active = _scoped_read(SCOPED_ACTIVE) if SCOPED_ACTIVE.exists() else None
    if prepared is not None:
        need(prepared.get("schema") ==
             "aegis_auto_scoped_redirect_prepared_v1" and
             prepared.get("intent_sha256") == _scoped_hash(intent),
             "scoped prepared chain changed")
    if bound is not None:
        need(prepared is not None and bound.get("schema") ==
             "aegis_auto_scoped_redirect_bound_v1" and
             bound.get("prepared_sha256") == _scoped_hash(prepared) and
             bound.get("private_unit") == unit and
             type(bound.get("invocation_id")) is str and
             HEX32.fullmatch(bound["invocation_id"]) is not None,
             "scoped bound chain changed")
    if active is not None:
        need(bound is not None and active.get("schema") ==
             "aegis_auto_scoped_redirect_active_v1" and
             active.get("bound_sha256") == _scoped_hash(bound),
             "scoped active chain changed")
    prior = None
    present = not _scoped_absent()
    if present:
        need(not reboot, "scoped table survived reboot")
        try:
            prior = _scoped_projection(binding, active=active is not None)
        except PolicyRefused:
            # A crash between the atomic NAT mutation and ACTIVE receipt may
            # leave the full active table with only BOUND recorded.
            need(active is None and bound is not None,
                 "scoped foreign policy present")
            prior = _scoped_projection(binding, active=True)
        if active is not None:
            need(active.get("policy") == prior,
                 "scoped active policy changed")
        elif prepared is not None and "redirect_handle" not in prior:
            need(prepared.get("policy") == prior,
                 "scoped prepared policy changed")
    retire = {"schema": "aegis_auto_scoped_redirect_retire_intent_v1",
              "intent_sha256": _scoped_hash(intent),
              "prepared_sha256": _scoped_hash(prepared) if prepared else None,
              "bound_sha256": _scoped_hash(bound) if bound else None,
              "active_sha256": _scoped_hash(active) if active else None,
              "prior_policy": prior, "reboot": reboot}
    if SCOPED_RETIRE_INTENT.exists():
        old = _scoped_read(SCOPED_RETIRE_INTENT)
        need(old["schema"] == retire["schema"] and
             all(old.get(key) == retire[key] for key in
                 ("intent_sha256", "prepared_sha256", "bound_sha256",
                  "active_sha256", "reboot")),
             "scoped retire intent changed")
        # The table may already have been deleted after the durable intent.
        need(prior == old.get("prior_policy") or
             (prior is None and _scoped_absent()),
             "scoped retire policy changed")
        retire = old
    else:
        need(not (active is not None and prior is None and not reboot),
             "scoped active table vanished before retire intent")
        _scoped_write(SCOPED_RETIRE_INTENT, retire)
    if present:
        need(_scoped_projection(binding, active="redirect_handle" in prior) ==
             prior, "scoped policy changed before delete")
        result = _scoped_nft(["-f", "-"], script=(
            f"delete table ip {SCOPED_TABLE}\n").encode("ascii"))
        need(result.returncode == 0, "scoped owned table delete failed")
    need(_scoped_absent() and deny_check() is True and
         stopped_check() is True, "scoped inverse not verified")
    archived = {"schema": "aegis_auto_scoped_redirect_retired_v1",
                "private_unit": unit, "retire_intent": retire,
                "original_boot_id": binding["boot_id"],
                "original_stage": [binding["stage_dev"], binding["stage_ino"]],
                "table_absent": True}
    if archive.exists():
        need(_scoped_read(archive) == archived,
             "scoped retired archive changed")
    else:
        _scoped_write(archive, archived)
    for path, expected in ((SCOPED_ACTIVE, active), (SCOPED_BOUND, bound),
                           (SCOPED_PREPARED, prepared),
                           (SCOPED_RETIRE_INTENT, retire),
                           (SCOPED_INTENT, intent)):
        if expected is not None:
            need(_scoped_read(path) == expected,
                 "scoped live receipt changed before retirement")
            path.unlink()
    directory = os.open(SCOPED_PARENT, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    need(_scoped_absent(), "scoped table reappeared after retirement")
    return {"archive_sha256": _scoped_hash(archived),
            "native_inverse_sha256": _scoped_hash(retire)}


# The default output_only_safe profile has a separate owner and table. Its
# rules capture host IPv4 TCP and DNS; the scoped PREROUTING renderer above is
# deliberately unchanged. The persistent device guard still denies native
# generic UDP and IPv6 egress.
LOCAL_TABLE = "aegis_auto_local_redirect"
LOCAL_INTENT = SCOPED_PARENT / "auto-local-redirect-intent.json"
LOCAL_BOUND = SCOPED_PARENT / "auto-local-redirect-bound.json"
LOCAL_ACTIVE = SCOPED_PARENT / "auto-local-redirect-active.json"
LOCAL_RETIRE_INTENT = SCOPED_PARENT / "auto-local-redirect-retire-intent.json"


def local_guard_dnat_ports(state_bytes: bytes, client: dict | None,
                           boot_id: str) -> tuple[tuple[str, int], ...]:
    """Loopback DNAT destinations of this exact local capture owner only.

    OUTPUT still carries the old uplink before the kernel's NAT reroute.
    The loopback-interface rule alone therefore cannot admit these packets.
    Both the shell renderer and semantic reader use the protected intent;
    a missing client binding grants nothing, including during typed Stop.
    """
    if client is None or (not LOCAL_INTENT.exists() and
                          not LOCAL_INTENT.is_symlink()):
        return ()
    state = parse_state(state_bytes)
    state_sha = hashlib.sha256(state_bytes.rstrip(b"\n")).hexdigest()
    _binding(client, "client", state_sha, "aegis-client.service")
    intent = _scoped_read(LOCAL_INTENT)
    need(type(intent) is dict and type(intent.get("binding")) is dict,
         "local_guard_dnat_intent_invalid")
    binding = _local_binding(intent["binding"])
    need(intent == _local_intent(binding) and
         binding["boot_id"] == boot_id == client["boot_id"] and
         binding["guard_state_sha256"] == state_sha and
         binding["uplink"] == state["uplink"] and
         binding["profile"] == ("output_only_safe" if
             state.get("capture_profile") == "wide-redirect-safe" else
             "full_wide_tun") and
         client["path"] == "system.slice/" + binding["private_unit"],
         "local_guard_dnat_owner_changed")
    info = (Path("/sys/fs/cgroup") / client["path"]).stat(
        follow_symlinks=False)
    need(stat.S_ISDIR(info.st_mode) and info.st_ino == int(client["inode"]),
         "local_guard_dnat_cgroup_changed")
    ports = (("udp", binding["dns_port"]),)
    if binding["profile"] == "full_wide_tun":
        ports += (("tcp", binding["listen_port"]),
                  ("udp", binding["udp_port"]))
    return tuple(pair for pair in ports
                 if pair not in (("tcp", 15080), ("udp", 15081)))


def _local_binding(binding: dict, *, check_host: bool = True) -> dict:
    fields = {"stage_dev", "stage_ino", "private_unit", "transaction_nonce",
              "planned_generation", "boot_id", "netns_ino",
              "config_sha256_initial", "config_semantic_sha256",
              "listen_ipv4", "listen_port", "dns_port", "udp_port",
              "profile", "first_arm_sha256", "guard_policy_sha256",
              "guard_state_sha256", "uplink", "management_ports",
              "dhcp4", "manager_binding"}
    need(type(binding) is dict and set(binding) == fields,
         "local binding fields invalid")
    need(type(binding["private_unit"]) is str and
         PRIVATE.fullmatch(binding["private_unit"]) is not None and
         type(binding["transaction_nonce"]) is str and
         HEX32.fullmatch(binding["transaction_nonce"]) is not None and
         type(binding["boot_id"]) is str and
         BOOT.fullmatch(binding["boot_id"]) is not None and
         all(type(binding[key]) is str and HEX64.fullmatch(binding[key]) is not None
             for key in ("planned_generation", "config_sha256_initial",
                         "config_semantic_sha256", "guard_policy_sha256")) and
         all(type(binding[key]) is int and binding[key] > 0
             for key in ("stage_dev", "stage_ino", "netns_ino")) and
         binding["listen_ipv4"] == "127.0.0.1" and
         type(binding["dns_port"]) is int and binding["dns_port"] == 53,
         "local binding invalid")
    need(type(binding["guard_state_sha256"]) is str and
         HEX64.fullmatch(binding["guard_state_sha256"]) is not None and
         type(binding["uplink"]) is str and
         IFACE.fullmatch(binding["uplink"]) is not None and
         binding["uplink"] not in ("lo", "aegis-tun0") and
         type(binding["management_ports"]) is list and
         len(binding["management_ports"]) <= 8 and
         len(set(binding["management_ports"])) == len(binding["management_ports"]) and
         all(type(port) is int and 1 <= port <= 65535
             for port in binding["management_ports"]) and
         type(binding["dhcp4"]) is bool,
         "local management policy invalid")
    manager = binding["manager_binding"]
    if manager is not None:
        need(type(manager) is dict and
             type(manager.get("path")) is str and
             manager["path"].rsplit("/", 1)[-1] in
             ("NetworkManager.service", "systemd-networkd.service"),
             "local manager binding invalid")
        _binding(manager, "manager", binding["guard_state_sha256"],
                 manager["path"].rsplit("/", 1)[-1])
        need(manager["boot_id"] == binding["boot_id"],
             "local manager identity invalid")
        if check_host:
            info = (Path("/sys/fs/cgroup") / manager["path"]).stat(
                follow_symlinks=False)
            need(stat.S_ISDIR(info.st_mode) and info.st_ino ==
                 int(manager["inode"]), "local manager cgroup changed")
    need(not binding["dhcp4"] or manager is not None,
         "local DHCP manager absent")
    need((binding["profile"] == "output_only_safe" and
          type(binding["listen_port"]) is int and
          binding["listen_port"] == 15080 and
          binding["udp_port"] is None and
          binding["first_arm_sha256"] is None) or
         (binding["profile"] == "full_wide_tun" and
          type(binding["listen_port"]) is int and
          binding["listen_port"] == 980 and
          type(binding["udp_port"]) is int and
          1 <= binding["udp_port"] <= 65535 and
          binding["udp_port"] not in (53, 980) and
          type(binding["first_arm_sha256"]) is str and
          HEX64.fullmatch(binding["first_arm_sha256"]) is not None),
         "local binding profile invalid")
    if check_host:
        need(binding["boot_id"] == Path("/proc/sys/kernel/random/boot_id")
             .read_text(encoding="ascii").strip() and
             binding["netns_ino"] == os.stat("/proc/self/ns/net").st_ino,
             "local host identity changed")
    return binding


def _local_intent(binding: dict) -> dict:
    return {"schema": "aegis_auto_local_redirect_intent_v1",
            "binding": binding,
            "owner_marker": "aegis-local-" + _scoped_hash(binding)}


def _local_absent() -> bool:
    result = _scoped_nft(["--json", "list", "ruleset"])
    need(result.returncode == 0 and 0 < len(result.stdout) <= SCOPED_MAX_READBACK,
         "local ruleset unavailable")
    parsed = json.loads(result.stdout, object_pairs_hook=unique)
    need(type(parsed) is dict and type(parsed.get("nftables")) is list,
         "local ruleset invalid")
    return not any(type(row) is dict and type(body) is dict and
                   body.get("family") == "ip" and
                   body.get("table", body.get("name")) == LOCAL_TABLE
                   for row in parsed["nftables"]
                   for body in row.values())


def _local_bound(binding: dict, invocation_id: str, *, check_host: bool = True) -> dict:
    _local_binding(binding, check_host=check_host)
    need(type(invocation_id) is str and HEX32.fullmatch(invocation_id) is not None,
         "local invocation invalid")
    intent = _local_intent(binding)
    need(_scoped_read(LOCAL_INTENT) == intent, "local intent changed")
    bound = _scoped_read(LOCAL_BOUND)
    need(type(bound) is dict and set(bound) ==
         {"schema", "intent_sha256", "invocation_id", "cgroup_path",
          "cgroup_inode"} and
         bound["schema"] == "aegis_auto_local_redirect_bound_v1" and
         bound["intent_sha256"] == _scoped_hash(intent) and
         bound["invocation_id"] == invocation_id and
         type(bound["cgroup_path"]) is str and
         bound["cgroup_path"] == "system.slice/" + binding["private_unit"] and
         type(bound["cgroup_inode"]) is int and bound["cgroup_inode"] > 0,
         "local bound owner changed")
    if check_host:
        info = (Path("/sys/fs/cgroup") / bound["cgroup_path"]).stat(
            follow_symlinks=False)
        need(stat.S_ISDIR(info.st_mode) and info.st_ino == bound["cgroup_inode"],
             "local cgroup changed")
    return bound


def _local_expected(binding: dict, bound: dict) -> list[dict]:
    marker = _local_intent(binding)["owner_marker"]
    def match(left: dict, right: object) -> dict:
        return {"match": {"op": "==", "left": left, "right": right}}
    counter = {"counter": {"packets": 0, "bytes": 0}}
    def rule(expr: list[dict]) -> dict:
        return {"rule": {"family": "ip", "table": LOCAL_TABLE,
                         "chain": "output", "comment": marker, "expr": expr}}
    rows = [
        {"table": {"family": "ip", "name": LOCAL_TABLE}},
        {"chain": {"family": "ip", "table": LOCAL_TABLE,
                   "name": "output", "type": "nat", "hook": "output",
                   "prio": -100, "policy": "accept"}},
        # nft JSON retains the resolved cgroup inode but drops its level.
        # _local_projection additionally checks the text level on this handle.
        rule([match({"socket": {"key": "cgroupv2"}},
                    str(bound["cgroup_inode"])), counter, {"return": None}]),
    ]
    for port in binding["management_ports"]:
        rows.append(rule([
            match({"meta": {"key": "oifname"}}, binding["uplink"]),
            match({"ct": {"key": "direction"}}, "reply"),
            match({"ct": {"key": "mark"}}, 0xa3610002),
            match({"ct": {"key": "proto-dst", "dir": "original"}}, port),
            match({"payload": {"protocol": "tcp", "field": "sport"}}, port),
            counter, {"return": None}]))
    if binding["dhcp4"]:
        rows.append(rule([
            match({"meta": {"key": "oifname"}}, binding["uplink"]),
            match({"payload": {"protocol": "udp", "field": "sport"}}, 68),
            match({"payload": {"protocol": "udp", "field": "dport"}}, 67),
            match({"socket": {"key": "cgroupv2"}},
                  binding["manager_binding"]["path"]),
            counter, {"return": None}]))
    rows.extend([
        rule([match({"payload": {"protocol": "udp", "field": "dport"}}, 53),
              counter, {"redirect": {"port": 53}}]),
        rule([match({"meta": {"key": "oifname"}}, "lo"),
              counter, {"return": None}]),
    ])
    if binding["profile"] == "full_wide_tun":
        rows.append(rule([match({"meta": {"key": "l4proto"}}, "udp"),
                          counter, {"redirect": {"port": binding["udp_port"]}}]))
    rows.append(rule([match({"meta": {"key": "l4proto"}}, "tcp"),
                      counter, {"redirect": {"port": binding["listen_port"]}}]))
    return rows


def _local_script(binding: dict, bound: dict) -> bytes:
    marker = _local_intent(binding)["owner_marker"]
    path = bound["cgroup_path"]
    level = len(path.split("/"))
    udp = (f'add rule ip {LOCAL_TABLE} output meta l4proto udp counter '
           f'redirect to :{binding["udp_port"]} comment "{marker}"\n'
           if binding["profile"] == "full_wide_tun" else "")
    management = "".join(
        f'add rule ip {LOCAL_TABLE} output oifname "{binding["uplink"]}" '
        f'meta l4proto tcp ct direction reply ct mark 0xa3610002 '
        f'ct original proto-dst {port} '
        f'tcp sport {port} counter return comment "{marker}"\n'
        for port in binding["management_ports"])
    manager = binding["manager_binding"]
    dhcp = (f'add rule ip {LOCAL_TABLE} output oifname "{binding["uplink"]}" '
            f'udp sport 68 udp dport 67 socket cgroupv2 level '
            f'{len(manager["path"].split("/"))} "{manager["path"]}" '
            f'counter return comment "{marker}"\n'
            if binding["dhcp4"] else "")
    return (f"add table ip {LOCAL_TABLE}\n"
            f"add chain ip {LOCAL_TABLE} output "
            "{ type nat hook output priority -100; policy accept; }\n"
            f'add rule ip {LOCAL_TABLE} output socket cgroupv2 level {level} '
            f'"{path}" counter return comment "{marker}"\n'
            + management + dhcp +
            f'add rule ip {LOCAL_TABLE} output udp dport 53 counter '
            f'redirect to :53 comment "{marker}"\n'
            f'add rule ip {LOCAL_TABLE} output oifname "lo" counter return '
            f'comment "{marker}"\n'
            + udp +
            f'add rule ip {LOCAL_TABLE} output meta l4proto tcp counter '
            f'redirect to :{binding["listen_port"]} comment "{marker}"\n').encode("ascii")


def _local_projection(binding: dict, bound: dict) -> dict:
    result = _scoped_nft(["--json", "--handle", "list", "table", "ip", LOCAL_TABLE])
    need(result.returncode == 0 and 0 < len(result.stdout) <= SCOPED_MAX_READBACK,
         "local table readback unavailable")
    parsed = json.loads(result.stdout, object_pairs_hook=unique)
    need(type(parsed) is dict and type(parsed.get("nftables")) is list and
         6 <= len(parsed["nftables"]) <= 18, "local table readback invalid")
    rows = []
    handles = {}
    names = (["cgroup_exempt_handle"] +
             [f"management_reply_{port}_handle" for port in
              binding["management_ports"]] +
             (["dhcp4_exempt_handle"] if binding["dhcp4"] else []) +
             ["dns_redirect_handle",
              "loopback_exempt_handle"] +
             (["udp_redirect_handle"] if binding["profile"] ==
              "full_wide_tun" else []) + ["tcp_redirect_handle"])
    for item in parsed["nftables"]:
        need(type(item) is dict and len(item) == 1, "local table item invalid")
        kind, body = next(iter(item.items()))
        if kind == "metainfo":
            continue
        need(kind in ("table", "chain", "rule") and type(body) is dict,
             "local table item unexpected")
        clone = dict(body)
        handle = clone.pop("handle", None)
        if kind == "chain":
            need(type(handle) is int and handle > 0 and
                 body.get("name") == "output", "local chain handle invalid")
            handles["output_chain_handle"] = handle
        if kind == "rule":
            index = len([row for row in rows if "rule" in row])
            need(type(handle) is int and handle > 0 and index < len(names) and
                 body.get("comment") == _local_intent(binding)["owner_marker"] and
                 body.get("chain") == "output", "local rule handle invalid")
            handles[names[index]] = handle
            expr = clone.get("expr")
            need(type(expr) is list, "local expressions invalid")
            normalized = []
            for part in expr:
                need(type(part) is dict and len(part) == 1,
                     "local expression invalid")
                if "counter" in part:
                    counts = part["counter"]
                    need(type(counts) is dict and set(counts) == {"packets", "bytes"} and
                         all(type(value) is int and 0 <= value < 2**64
                             for value in counts.values()), "local counter invalid")
                    normalized.append({"counter": {"packets": 0, "bytes": 0}})
                else:
                    normalized.append(part)
            clone["expr"] = normalized
        rows.append({kind: clone})
    expected = _local_expected(binding, bound)
    # Some nft builds resolve the client's inode back to its exact live name.
    # Accept that spelling only while the already-bound path still names the
    # original inode, before and after the paired JSON/text readback. Numeric
    # readback remains valid for stopped-unit retirement after its cgroup is gone.
    def pin_named_client() -> None:
        need(bound["cgroup_path"] == "system.slice/" + binding["private_unit"] and
             type(bound["cgroup_inode"]) is int and bound["cgroup_inode"] > 0,
             "local named cgroup binding invalid")
        info = (Path("/sys/fs/cgroup") / bound["cgroup_path"]).stat(
            follow_symlinks=False)
        need(stat.S_ISDIR(info.st_mode) and info.st_ino == bound["cgroup_inode"],
             "local named cgroup inode changed")
    named_client = rows[2]["rule"]["expr"][0] == {
        "match": {"op": "==", "left": {"socket": {"key": "cgroupv2"}},
                  "right": bound["cgroup_path"]}}
    if named_client:
        pin_named_client()
        expected[2]["rule"]["expr"][0]["match"]["right"] = bound["cgroup_path"]
    # nft versions may render a cgroup path as the pinned name or its inode.
    # Both values are independently bound to the held manager receipt above.
    if binding["dhcp4"]:
        manager = binding["manager_binding"]
        manager_row = 3 + len(binding["management_ports"])
        observed_cgroup = rows[manager_row]["rule"]["expr"][3]
        if observed_cgroup == {"match": {"op": "==",
                "left": {"socket": {"key": "cgroupv2"}},
                "right": manager["inode"]}}:
            expected[manager_row]["rule"]["expr"][3]["match"]["right"] = \
                manager["inode"]
    need(rows == expected and
         set(handles) == {"output_chain_handle", *names} and
         len(set(handles.values())) == len(names) + 1,
         "local kernel policy differs from renderer")
    text = _scoped_nft(["-a", "list", "table", "ip", LOCAL_TABLE])
    need(text.returncode == 0 and
         0 < len(text.stdout) <= SCOPED_MAX_READBACK,
         "local text readback unavailable")
    level = len(bound["cgroup_path"].split("/"))
    marker = _local_intent(binding)["owner_marker"]
    pattern = (r'(?m)^\s*socket cgroupv2 level ' + str(level) + r' ' +
               r'(?:' + str(bound["cgroup_inode"]) + r'|"' +
               re.escape(bound["cgroup_path"]) + r'")' +
               r' counter packets [0-9]+ bytes [0-9]+ return comment "' +
               re.escape(marker) + r'" # handle ' +
               str(handles["cgroup_exempt_handle"]) + r'$')
    text_data = text.stdout.decode("ascii")
    manager_pattern = None
    if binding["dhcp4"]:
        manager = binding["manager_binding"]
        manager_pattern = (r'(?m)^\s*oifname "' + re.escape(binding["uplink"]) +
                           r'" udp sport 68 udp dport 67 socket cgroupv2 level ' +
                           str(len(manager["path"].split("/"))) + r' ' +
                           r'(?:' + re.escape(manager["inode"]) + r'|"' +
                           re.escape(manager["path"]) + r'")' +
                           r' counter packets [0-9]+ bytes [0-9]+ return comment "' +
                           re.escape(marker) + r'" # handle ' +
                           str(handles["dhcp4_exempt_handle"]) + r'$')
    need(len(re.findall(pattern, text_data)) == 1 and
         (manager_pattern is None or
          len(re.findall(manager_pattern, text_data)) == 1) and
         text.stdout.count(b"socket cgroupv2") == (2 if binding["dhcp4"] else 1),
         "local cgroup text level changed")
    if named_client or ('"' + bound["cgroup_path"] + '"') in text_data:
        pin_named_client()
    # After both strict readbacks, canonicalize only the already-proved
    # cgroup spelling. nft resolves live names but returns the same inode
    # numerically once PID1 removes the cgroup; that is not a policy change.
    rows[2]["rule"]["expr"][0]["match"]["right"] = str(bound["cgroup_inode"])
    if binding["dhcp4"]:
        rows[3 + len(binding["management_ports"])]["rule"]["expr"][3]["match"]["right"] = \
            binding["manager_binding"]["path"]
    policy_sha = hashlib.sha256(json.dumps(rows, sort_keys=True,
                                           separators=(",", ":")).encode()).hexdigest()
    return {"policy_sha256": policy_sha, **handles}


def local_prepare(binding: dict) -> None:
    binding = _local_binding(binding)
    need(all(not path.exists() and not path.is_symlink() for path in
             (LOCAL_INTENT, LOCAL_BOUND, LOCAL_ACTIVE, LOCAL_RETIRE_INTENT,
              SCOPED_INTENT, SCOPED_PREPARED, SCOPED_BOUND, SCOPED_ACTIVE,
              SCOPED_RETIRE_INTENT)) and _local_absent() and _scoped_absent(),
         "prior local redirect requires recovery")
    _scoped_write(LOCAL_INTENT, _local_intent(binding))


def local_bind_invocation(binding: dict, invocation_id: str,
                          cgroup_path: str, cgroup_inode: int,
                          *, deadline: float) -> None:
    binding = _local_binding(binding)
    need(time.monotonic() < deadline and type(invocation_id) is str and
         HEX32.fullmatch(invocation_id) is not None and
         cgroup_path == "system.slice/" + binding["private_unit"] and
         type(cgroup_inode) is int and cgroup_inode > 0 and
         (Path("/sys/fs/cgroup") / cgroup_path).stat(
             follow_symlinks=False).st_ino == cgroup_inode and
         _scoped_read(LOCAL_INTENT) == _local_intent(binding) and
         not LOCAL_BOUND.exists() and _local_absent(),
         "local invocation binding invalid")
    _scoped_write(LOCAL_BOUND, {
        "schema": "aegis_auto_local_redirect_bound_v1",
        "intent_sha256": _scoped_hash(_local_intent(binding)),
        "invocation_id": invocation_id, "cgroup_path": cgroup_path,
        "cgroup_inode": cgroup_inode})


def local_activate(binding: dict, invocation_id: str) -> dict:
    bound = _local_bound(binding, invocation_id)
    need(not LOCAL_ACTIVE.exists() and _local_absent(),
         "local redirect already active")
    result = _scoped_nft(["-f", "-"], script=_local_script(binding, bound))
    need(result.returncode == 0, "local redirect install failed")
    policy = _local_projection(binding, bound)
    _scoped_write(LOCAL_ACTIVE, {
        "schema": "aegis_auto_local_redirect_active_v1",
        "bound_sha256": _scoped_hash(bound), "policy": policy})
    return local_verify(binding, invocation_id,
                        config_semantic_sha256=binding["config_semantic_sha256"])


def local_verify(binding: dict, invocation_id: str, *,
                 config_semantic_sha256: str) -> dict:
    need(config_semantic_sha256 == binding["config_semantic_sha256"],
         "local config semantics changed")
    bound = _local_bound(binding, invocation_id)
    return _local_verified_policy(binding, invocation_id, bound)


def _local_verified_policy(binding: dict, invocation_id: str, bound: dict) -> dict:
    policy = _local_projection(binding, bound)
    need(_scoped_read(LOCAL_ACTIVE) == {
        "schema": "aegis_auto_local_redirect_active_v1",
        "bound_sha256": _scoped_hash(bound), "policy": policy},
        "local active receipt changed")
    return {**policy, "private_unit": binding["private_unit"],
            "invocation_id": invocation_id,
            "listen_ipv4": binding["listen_ipv4"],
            "listen_port": binding["listen_port"],
            "dns_port": binding["dns_port"],
            "udp_port": binding["udp_port"],
            "profile": binding["profile"],
            "cgroup_path": bound["cgroup_path"],
            "cgroup_inode": bound["cgroup_inode"]}


def verify_stopping_guard(unit: str, invocation_id: str | None = None) -> dict:
    """Read a durable exact Stop intent and independently prove complete deny.

    No caller boolean, stale policy digest or absent process is deny evidence.
    The original guard lock must span these reads in the invoking owner.
    """
    need(type(unit) is str and PRIVATE.fullmatch(unit), "stopping_guard_unit_invalid")
    state_path = SCOPED_PARENT / "device-guard.conf"
    intent_path = SCOPED_PARENT / "auto-stop-intent.json"
    client_path = Path(str(state_path) + ".client-binding")
    need(not client_path.exists() and not client_path.is_symlink(),
         "stopping_guard_client_binding_retained")
    raw = _scoped_bytes(state_path)
    state = parse_state(raw)
    need(state["armed"] == "1", "stopping_guard_not_armed")
    intent = _scoped_read(intent_path)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    need(type(intent) is dict and set(intent) ==
         {"schema", "boot_id", "service", "invocation_id", "phase"} and
         intent["schema"] == "aegis_auto_stop_intent_v1" and
         intent["boot_id"] == boot and intent["service"] == unit and
         type(intent["invocation_id"]) is str and HEX32.fullmatch(intent["invocation_id"]) and
         (invocation_id is None or intent["invocation_id"] == invocation_id) and
         intent["phase"] in ("pending_deny", "deny_proven"),
         "stopping_guard_intent_changed")
    manager_path = Path(str(state_path) + ".manager-binding")
    manager = (_scoped_read(manager_path) if manager_path.exists() or
               manager_path.is_symlink() else None)
    def manager_cgroup() -> str:
        if manager is None:
            return "none"
        path = Path("/sys/fs/cgroup") / manager["path"]
        try:
            info = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return "absent"
        need(stat.S_ISDIR(info.st_mode) and info.st_ino == int(manager["inode"]),
             "stopping_guard_manager_changed")
        return "named"
    if manager is not None:
        _binding(manager, "manager", hashlib.sha256(raw.rstrip(b"\n")).hexdigest(),
                 state["manager"])
        need(manager["boot_id"] == boot, "stopping_guard_manager_changed")
    manager_mode = manager_cgroup()
    def denied() -> str:
        actual = _scoped_nft(["--json", "--handle", "list", "table", "inet", TABLE])
        text = _scoped_nft(["-a", "list", "table", "inet", TABLE])
        need(actual.returncode == text.returncode == 0,
             "stopping_guard_readback_unavailable")
        raw_sha = verify_expected_policy(raw, actual.stdout, text.stdout,
                                         None, manager, boot_id=boot)
        projection, _handles, _counters = policy_projection(actual.stdout)
        need(raw_sha == hashlib.sha256(projection).hexdigest(),
             "stopping_guard_raw_seal_changed")
        canonical = canonical_manager_projection(projection, manager)
        if manager_mode == "absent":
            manager_rules = any(type(item) is dict and
                                type(item.get("rule")) is dict and
                                item["rule"].get("comment") ==
                                _marker(manager, "manager")
                                for item in json.loads(projection))
            need(not manager_rules or canonical != projection,
                 "stopping_guard_manager_numeric_required")
        return hashlib.sha256(canonical).hexdigest()
    policy_sha = denied()
    need(_scoped_bytes(state_path) == raw and _scoped_read(intent_path) == intent and
         (None if not manager_path.exists() and not manager_path.is_symlink()
          else _scoped_read(manager_path)) == manager and
         manager_cgroup() == manager_mode and
         not client_path.exists() and not client_path.is_symlink() and
         denied() == policy_sha, "stopping_guard_changed_during_readback")
    return {"policy_sha256": policy_sha,
            "state_sha256": hashlib.sha256(raw.rstrip(b"\n")).hexdigest(),
            "invocation_id": intent["invocation_id"], "boot_id": boot}


def local_verify_stopping(binding: dict, invocation_id: str, *,
                          config_semantic_sha256: str) -> dict:
    """Classify the exact residual NAT table only while independent deny holds.

    This is not runtime capture readiness: Main's cgroup may already be gone.
    Numeric retirement still checks every table/rule/handle/level/owner atom.
    """
    _local_binding(binding, check_host=False)
    def stopping_host() -> None:
        need(binding["boot_id"] == Path("/proc/sys/kernel/random/boot_id")
             .read_text(encoding="ascii").strip() and
             binding["netns_ino"] == os.stat("/proc/self/ns/net").st_ino,
             "local_stopping_host_changed")
    stopping_host()
    need(config_semantic_sha256 == binding["config_semantic_sha256"],
         "local config semantics changed")
    deny = verify_stopping_guard(binding["private_unit"], invocation_id)
    need(deny["state_sha256"] == binding["guard_state_sha256"] and
         deny["boot_id"] == binding["boot_id"], "local_stopping_guard_changed")
    bound = _local_bound(binding, invocation_id, check_host=False)
    path = Path("/sys/fs/cgroup") / bound["cgroup_path"]
    if path.exists():
        info = path.stat(follow_symlinks=False)
        need(stat.S_ISDIR(info.st_mode) and info.st_ino == bound["cgroup_inode"],
             "local_stopping_cgroup_replaced")
    actual = _local_verified_policy(binding, invocation_id, bound)
    _local_binding(binding, check_host=False)
    stopping_host()
    need(verify_stopping_guard(binding["private_unit"], invocation_id) == deny,
         "local_stopping_deny_changed")
    return actual


def local_counters(binding: dict, invocation_id: str) -> dict[str, int]:
    """Read exact source-owned counters after the full semantic policy check."""
    verified = local_verify(binding, invocation_id,
                            config_semantic_sha256=binding["config_semantic_sha256"])
    result = _scoped_nft(["--json", "--handle", "list", "table", "ip", LOCAL_TABLE])
    need(result.returncode == 0 and 0 < len(result.stdout) <= SCOPED_MAX_READBACK,
         "local counters unavailable")
    parsed = json.loads(result.stdout, object_pairs_hook=unique)
    need(type(parsed) is dict and type(parsed.get("nftables")) is list,
         "local counters invalid")
    rows: dict[str, int] = {}
    for item in parsed["nftables"]:
        rule = item.get("rule") if type(item) is dict else None
        if type(rule) is not dict:
            continue
        handle = rule.get("handle")
        keys = [name for name in verified if name.endswith("_handle") and
                name != "output_chain_handle"
                if name in verified and verified[name] == handle]
        need(len(keys) == 1 and type(rule.get("expr")) is list,
             "local counter handle changed")
        counts = [part["counter"] for part in rule["expr"]
                  if type(part) is dict and "counter" in part]
        need(len(counts) == 1 and type(counts[0]) is dict and
             type(counts[0].get("packets")) is int and
             0 <= counts[0]["packets"] < 2**64,
             "local counter changed")
        rows[keys[0]] = counts[0]["packets"]
    need(len(rows) == (5 if binding["profile"] == "full_wide_tun" else 4) +
         len(binding["management_ports"]) + int(binding["dhcp4"]),
         "local counters incomplete")
    return rows


def local_retire(*, unit: str, deny_check: object,
                 stopped_check: object, reboot: bool = False) -> dict:
    """Delete only the exact local OUTPUT policy after deny and private Stop."""
    need(type(unit) is str and PRIVATE.fullmatch(unit) is not None and
         callable(deny_check) and callable(stopped_check),
         "local retire authority invalid")
    intent = _scoped_read(LOCAL_INTENT)
    need(type(intent) is dict and
         intent.get("schema") == "aegis_auto_local_redirect_intent_v1" and
         type(intent.get("binding")) is dict and
         intent["binding"].get("private_unit") == unit,
         "foreign local retire intent")
    # A stopped/restarted network manager may have released its old cgroup.
    # Retirement authenticates the original receipt and exact kernel table;
    # it must not require that stale cgroup to remain live after private Stop.
    binding = _local_binding(intent["binding"], check_host=False)
    need(intent == _local_intent(binding), "local retire owner changed")
    current_boot = Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="ascii").strip()
    need((binding["boot_id"] != current_boot) if reboot else
         (binding["boot_id"] == current_boot), "local retire boot changed")
    if not reboot:
        need(binding["netns_ino"] == os.stat("/proc/self/ns/net").st_ino,
             "local retire namespace changed")
    need(deny_check() is True and stopped_check() is True,
         "local deny or private stop not proven")
    suffix = unit[len("aegis-auto@"): -len(".service")]
    archive = SCOPED_PARENT / f"auto-local-redirect-retired-{suffix}.json"
    if archive.exists():
        archived = _scoped_read(archive)
        retired = archived.get("retire_intent")
        need(type(retired) is dict and archived == {
            "schema": "aegis_auto_local_redirect_retired_v1",
            "private_unit": unit, "original_boot_id": binding["boot_id"],
            "original_stage": [binding["stage_dev"], binding["stage_ino"]],
            "retire_intent": retired, "table_absent": True} and
            retired.get("intent_sha256") == _scoped_hash(intent) and
            _local_absent(), "local retired archive changed")
        for path, key in ((LOCAL_ACTIVE, "active_sha256"),
                          (LOCAL_BOUND, "bound_sha256"),
                          (LOCAL_RETIRE_INTENT, None)):
            if path.exists():
                leaf = _scoped_read(path)
                expected = (_scoped_hash(retired) if key is None else retired[key])
                need(_scoped_hash(leaf) == expected,
                     "local retired leaf changed")
                path.unlink()
        need(_scoped_read(LOCAL_INTENT) == intent and
             deny_check() is True and stopped_check() is True and
             _local_absent(), "local retirement changed")
        LOCAL_INTENT.unlink()
        directory = os.open(SCOPED_PARENT, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return {"archive_sha256": _scoped_hash(archived),
                "native_inverse_sha256": _scoped_hash(retired)}
    bound = _scoped_read(LOCAL_BOUND) if LOCAL_BOUND.exists() else None
    active = _scoped_read(LOCAL_ACTIVE) if LOCAL_ACTIVE.exists() else None
    if bound is not None:
        need(type(bound) is dict and
             bound.get("schema") == "aegis_auto_local_redirect_bound_v1" and
             bound.get("intent_sha256") == _scoped_hash(intent) and
             type(bound.get("invocation_id")) is str and
             HEX32.fullmatch(bound["invocation_id"]) is not None,
             "local retire bound changed")
        # Stop may already have removed the private cgroup. Its inode remains
        # bound by the protected BOUND receipt and the exact nft readback.
        _local_bound(binding, bound["invocation_id"], check_host=False)
    if active is not None:
        need(bound is not None and type(active) is dict and
             active.get("schema") == "aegis_auto_local_redirect_active_v1" and
             active.get("bound_sha256") == _scoped_hash(bound),
             "local retire active changed")
    present = not _local_absent()
    prior = None
    if present:
        need(not reboot and bound is not None, "local table survived reboot")
        prior = _local_projection(binding, bound)
        if active is not None:
            need(active["policy"] == prior, "local active policy changed")
    old_retire = _scoped_read(LOCAL_RETIRE_INTENT) if LOCAL_RETIRE_INTENT.exists() else None
    if old_retire is None:
        need(not (active is not None and not present and not reboot),
             "local active table vanished before retire intent")
        retire = {"schema": "aegis_auto_local_redirect_retire_intent_v1",
                  "intent_sha256": _scoped_hash(intent),
                  "bound_sha256": _scoped_hash(bound) if bound else None,
                  "active_sha256": _scoped_hash(active) if active else None,
                  "prior_policy": prior, "reboot": reboot}
        _scoped_write(LOCAL_RETIRE_INTENT, retire)
    else:
        retire = old_retire
        need(retire == {"schema": "aegis_auto_local_redirect_retire_intent_v1",
                        "intent_sha256": _scoped_hash(intent),
                        "bound_sha256": _scoped_hash(bound) if bound else None,
                        "active_sha256": _scoped_hash(active) if active else None,
                        "prior_policy": retire.get("prior_policy"),
                        "reboot": reboot} and
             (prior == retire["prior_policy"] or
              (prior is None and _local_absent())),
             "local retire intent changed")
    if present:
        need(_local_projection(binding, bound) == prior,
             "local policy changed before delete")
        result = _scoped_nft(["-f", "-"], script=(
            f"delete table ip {LOCAL_TABLE}\n").encode("ascii"))
        need(result.returncode == 0, "local owned table delete failed")
    need(_local_absent() and deny_check() is True and stopped_check() is True,
         "local inverse not verified")
    archived = {"schema": "aegis_auto_local_redirect_retired_v1",
                "private_unit": unit, "original_boot_id": binding["boot_id"],
                "original_stage": [binding["stage_dev"], binding["stage_ino"]],
                "retire_intent": retire, "table_absent": True}
    if archive.exists():
        need(_scoped_read(archive) == archived, "local retired archive changed")
    else:
        _scoped_write(archive, archived)
    for path, expected in ((LOCAL_ACTIVE, active), (LOCAL_BOUND, bound),
                           (LOCAL_RETIRE_INTENT, retire), (LOCAL_INTENT, intent)):
        if expected is not None and path.exists():
            need(_scoped_read(path) == expected,
                 "local live receipt changed before retirement")
            path.unlink()
    directory = os.open(SCOPED_PARENT, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    need(_local_absent(), "local table reappeared after retirement")
    return {"archive_sha256": _scoped_hash(archived),
            "native_inverse_sha256": _scoped_hash(retire)}
