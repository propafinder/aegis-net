#!/usr/bin/env python3
"""Inert source-derived checks for the v2 nft binding readback predicate."""
import pathlib
import re
import subprocess
import sys
import json


source = (pathlib.Path(__file__).resolve().parent / "aegis-device-egress-guard.sh").read_text()
blocks = re.findall(r'nft --json list table inet "\$TABLE" \| python3 -c \'(.*?)\'', source, re.S)
assert len(blocks) == 3, "guard JSON predicates changed; review fixture extraction"
binding = blocks[0]
shape = blocks[2]
text_blocks = re.findall(r'nft -a list table inet "\$TABLE" \| python3 -c \'(.*?)\'', source, re.S)
assert len(text_blocks) == 1, "guard text level predicate changed; review fixture extraction"
text_binding = text_blocks[0]
marker = "aegis-v2-synthetic-local-control"
path = "system.slice/aegis-client.service"


def match(cgroup=path, level=2):
    return {"match": {"op": "==", "left": {"socket": {"key": "cgroupv2", "level": level}}, "right": cgroup}}


def rule(expr, comment=None):
    if comment == marker and any('match' in e and isinstance(e['match'].get('left'),dict) and 'socket' in e['match']['left'] for e in expr):
        tag = 0xa361c002 if any('match' in e and e['match'].get('left')=={'payload':{'protocol':'udp','field':'sport'}} for e in expr) else 0xa361c001
        position = next((i for i,e in enumerate(expr) if 'counter' in e), len(expr)-1)
        expr = expr[:position]+[{'mangle':{'key':{'meta':{'key':'mark'}},'value':tag}}]+expr[position:]
    value = {"family": "inet", "table": "aegis_device_guard", "chain": "output", "expr": expr}
    if comment is not None:
        value["comment"] = comment
    return {"rule": value}


def admitted(rows, count=1, role="client", dhcp4="1", dhcp6="1"):
    rows = json.loads(json.dumps(rows))
    for index, item in enumerate(rows, 1):
        if "rule" in item:
            item["rule"].setdefault("handle", index)
    result = subprocess.run(
        [sys.executable, "-I", "-c", binding, marker, str(count), path,
         "2", "111", role, "eth0", dhcp4, dhcp6, "none", "none", "7"],
        input=json.dumps({"nftables": rows}), text=True, capture_output=True, timeout=5,
    )
    return result.returncode == 0


base = [rule([match(), {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}], marker)]
assert admitted(base)
wrong_tag = json.loads(json.dumps(base))
wrong_tag[0]['rule']['expr'][1]['mangle']['value'] = 0xa361c002
assert not admitted(wrong_tag)
missing_tag = json.loads(json.dumps(base))
missing_tag[0]['rule']['expr'].pop(1)
assert not admitted(missing_tag)
double_tag = json.loads(json.dumps(base))
double_tag[0]['rule']['expr'].insert(1, double_tag[0]['rule']['expr'][1])
assert not admitted(double_tag)
elided = json.loads(json.dumps(base))
del elided[0]["rule"]["expr"][0]["match"]["left"]["socket"]["level"]
assert admitted(elided), "real nft JSON omits the level; text readback must prove it"
missing_handle = json.loads(json.dumps(base))
missing_handle[0]["rule"]["handle"] = None
assert not admitted(missing_handle)
assert admitted([rule([match(111), {"accept": None}], marker)])
assert admitted([rule([{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}}, {"accept": None}]), *base])
assert admitted([rule([{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}}, {"accept": None}])], 0)
assert not admitted([rule([{"accept": None}])], 0)
assert not admitted([rule([match("system.slice/foreign.service"), {"accept": None}], marker)])
assert not admitted([rule([match(222), {"accept": None}], marker)])
assert not admitted([rule([match(level=1), {"accept": None}], marker)])
assert not admitted([rule([{"match": {"op": "==", "left": 1, "right": 1}}, {"accept": None}], marker)])
assert not admitted([rule([{"accept": None}]), *base])
assert not admitted([rule([{"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]), *base])
assert not admitted(base + base)
assert not admitted([])
assert not admitted([{"rule": {**base[0]["rule"], "chain": "forward"}}])
assert admitted([rule([match(), {"accept": None}], marker), rule([match(), {"accept": None}], marker)], 2)


def eq(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}


def manager_rule(family, sport, dport):
    protocol, destination = (("ip", "255.255.255.255") if family == "ipv4"
                             else ("ip6", "ff02::1:2"))
    return rule([
        eq({"meta": {"key": "oifname"}}, "eth0"),
        eq({"meta": {"key": "oif"}}, "eth0"),
        eq({"payload": {"protocol": protocol, "field": "daddr"}}, destination),
        eq({"payload": {"protocol": "udp", "field": "sport"}}, sport),
        eq({"payload": {"protocol": "udp", "field": "dport"}}, dport),
        match(), {"counter": {"packets": 0, "bytes": 0}}, {"accept": None},
    ], marker)


v4 = manager_rule("ipv4", 68, 67)
v6 = manager_rule("ipv6", 546, 547)
assert admitted([v4, v6], 2, "manager")
same_handle = json.loads(json.dumps([v4, v6]))
for item in same_handle:
    item["rule"]["handle"] = 7
assert not admitted(same_handle, 2, "manager")
assert admitted([v4], 1, "manager", "1", "0")
assert admitted([v6], 1, "manager", "0", "1")
assert admitted([], 0, "manager", "0", "0")
implicit = json.loads(json.dumps(v4))
implicit["rule"]["expr"].insert(2, eq({"meta": {"key": "l4proto"}}, "udp"))
assert admitted([implicit], 1, "manager", "1", "0")
for index in range(5):
    stripped = json.loads(json.dumps(v4))
    stripped["rule"]["expr"].pop(index)
    assert not admitted([stripped, v6], 2, "manager")
assert not admitted([v4, v4], 2, "manager")
assert not admitted([v4], 1, "manager", "0", "1")
for index, value in ((0, "eth1"), (1, "other0"),
                     (2, "198.18.0.9"), (3, 69), (4, 68)):
    changed = json.loads(json.dumps(v4))
    changed["rule"]["expr"][index]["match"]["right"] = value
    assert not admitted([changed, v6], 2, "manager")


def text_admitted(lines, count=1, handles="1"):
    result = subprocess.run(
        [sys.executable, "-I", "-c", text_binding, marker, str(count), path, "2", handles, "client"],
        input="table inet aegis_device_guard {\n\tchain output {\n" + "".join(lines) + "\t}\n}\n",
        text=True, capture_output=True, timeout=5,
    )
    return result.returncode == 0


def text_rule(level=2, target=path, handle=1, prefix=""):
    return (f'\t{prefix}socket cgroupv2 level {level} "{target}" '
            f'meta mark set 0xa361c001 counter packets 0 bytes 0 accept comment "{marker}" # handle {handle}\n')


assert text_admitted([text_rule()])
assert text_admitted([text_rule(handle=1), text_rule(handle=2, prefix='oifname "eth0" ')], 2, "1,2")
assert text_admitted([], 0, "")
assert not text_admitted([text_rule(level=1)])
assert not text_admitted([text_rule(target="system.slice/foreign.service")])
assert not text_admitted([text_rule(handle=2)])
assert not text_admitted([])
assert not text_admitted([text_rule(), text_rule()], 2, "1,2")
assert not text_admitted([f'\tsocket cgroupv2 level 2 "{path}" comment "{marker}" # handle 1\n'])


def shape_admitted(rows, counts=(0, 2, 1, 2)):
    table = {"table": {"family": "inet", "name": "aegis_device_guard"}}
    chains = [
        {"chain": {"family": "inet", "table": "aegis_device_guard", "name": name,
                   "hook": hook, "prio": prio, "policy": policy}}
        for name, hook, prio, policy in (
            ("incoming", "prerouting", -190, "accept"),
            ("output", "output", 2147483647, "drop"),
            ("forward", "forward", 10, "drop"),
            ("postroute", "postrouting", 2147483647, "drop"),
        )
    ]
    result = subprocess.run(
        [sys.executable, "-I", "-c", shape, *map(str, counts)],
        input=json.dumps({"nftables": [table, *chains, *rows]}),
        text=True, capture_output=True, timeout=5,
    )
    return result.returncode == 0


safe_shape = [
    rule([eq({"meta": {"key": "oifname"}}, "lo"), {"accept": None}]),
    rule([{"counter": {"packets": 0, "bytes": 0}}, {"drop": None}]),
    {"rule": {"family": "inet", "table": "aegis_device_guard", "chain": "forward",
              "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"drop": None}]}},
]
safe_shape += [{"rule": {**r["rule"],"chain":"postroute"}} for r in safe_shape if r["rule"]["chain"]=="output"]
assert shape_admitted(safe_shape)
assert not shape_admitted(safe_shape + [rule([eq({"meta": {"key": "oifname"}}, "eth0"), {"accept": None}])])
assert not shape_admitted([*safe_shape, {"chain": {"family": "inet", "table": "aegis_device_guard",
                                                     "name": "extra", "hook": "output", "prio": -1,
                                                     "policy": "accept"}}])
assert not shape_admitted([*safe_shape, {"rule": {"family": "inet", "table": "aegis_device_guard",
                                                    "chain": "incoming", "expr": [{"accept": None}]}}], (1, 2, 1, 2))
assert not shape_admitted([rule([{"jump": {"target": "foreign"}}]), *safe_shape[1:]])
assert not shape_admitted([rule([{"goto": {"target": "foreign"}}]), *safe_shape[1:]])
assert not shape_admitted(safe_shape, (0, 1, 1, 2))

# The selected relay transition is appended to the same batch, but its typed
# renderer owns a distinct netdev table. Keep that composition boundary exact:
# a future inet rule in the selected renderer must trigger a review rather
# than silently changing the shape expected from the primary guard render.
relay = (pathlib.Path(__file__).resolve().parent.parent /
         "aegis-core/src/relay_geneva/installed_guard.rs").read_text()
assert 'pub const TABLE: &str = "aegis_relay_geneva_device_guard";' in relay
render = relay.split('pub fn transaction_text(', 1)[1].split('\nfn canonical(', 1)[0]
commands = re.findall(r'"((?:add|create|delete) (?:table|chain|rule) (?:inet|netdev) \{TABLE\}[^"\\]*)', render)
assert len(commands) == 4 and all(' netdev ' in command for command in commands)
assert 'local -a args=(profile relay-geneva guard-prepare)' in source
assert 'rules+=$\'\\n\'"$selected_relay_script"' in source
print("PASS: source-derived v2 nft binding and table-shape cases; no kernel actions")
