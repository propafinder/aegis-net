"""Merged dual-family native witness: one lease, one window, every check kept.

These fixtures do not claim installed Linux packet evidence. They drive the
real prove_deny_dual control flow against a recording fake kernel, the real
14-row trace predicate and the real topology preconditions.
"""
import copy
import hashlib
import json
import os
import selectors
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import aegis_auto_foreign_policy as foreign
import aegis_auto_native_witness as witness
import aegis_auto_trace_rollback as trace_rollback
import aegis_auto_witness_topology as topology
from aegis_auto_native_witness import Challenge, NativeWitnessRefused

ACTOR = bytes(range(32))
SOURCES = {4: "198.18.77.1", 6: "2001:db8:ae61:77::1"}


def guard_table(output):
    rows = [
        {"metainfo": {"version": "1.0.9"}},
        {"table": {"family": "inet", "name": "aegis_device_guard", "handle": 1}},
        {"chain": {"family": "inet", "table": "aegis_device_guard", "name": "incoming", "hook": "prerouting", "prio": -190, "policy": "accept", "handle": 2}},
        {"chain": {"family": "inet", "table": "aegis_device_guard", "name": "output", "hook": "output", "prio": 2147483647, "policy": "drop", "handle": 3}},
        {"chain": {"family": "inet", "table": "aegis_device_guard", "name": "forward", "hook": "forward", "prio": 10, "policy": "drop", "handle": 4}},
        {"rule": {"family": "inet", "table": "aegis_device_guard", "chain": "output", "expr": [{"match": {"left": "oifname", "right": "lo"}}, {"accept": None}], "handle": 5}},
        {"rule": {"family": "inet", "table": "aegis_device_guard", "chain": "output", "expr": [{"counter": {"packets": output, "bytes": output * 60}}, {"drop": None}], "handle": 6}},
        {"rule": {"family": "inet", "table": "aegis_device_guard", "chain": "forward", "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"drop": None}], "handle": 7}},
        {"chain": {"family": "inet", "table": "aegis_device_guard", "name": "postroute", "hook": "postrouting", "prio": 2147483647, "policy": "drop", "handle": 8}},
        {"rule": {"family": "inet", "table": "aegis_device_guard", "chain": "postroute", "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"drop": None}], "handle": 9}}]
    return json.dumps({"nftables": rows}, separators=(",", ":")).encode()


def challenges(source4=48001, source6=48002):
    return (Challenge("aegisaw0", "198.18.77.2", source4, 47001, ACTOR),
            Challenge("aegisaw0", "2001:db8:ae61:77::2", source6, 47002,
                      witness.ipv6_challenge_nonce(ACTOR)))


def episode(challenge, value, ident, handle=6, unknown_rule=False):
    family = "ip6" if ":" in challenge.peer_ipv4 else "ip"
    source = SOURCES[6 if family == "ip6" else 4]
    prefix = int.from_bytes(value.nonce[:12], "big")
    body = (f'packet: oif "{challenge.egress_interface}" {family} saddr {source} '
            f'{family} daddr {challenge.peer_ipv4} udp sport {challenge.source_port} '
            f'udp dport {challenge.sink_port} udp length 24 @th,64,96 0x{prefix:x}')
    # Real nft caches the ruleset when `monitor trace` subscribes. A rule
    # added after that is printed without its text (r17c G1 evidence).
    own_rule = ("unknown rule handle 9 (verdict continue)" if unknown_rule else
                f'rule oifname "{challenge.egress_interface}" '
                f"{family} daddr {challenge.peer_ipv4} udp sport {challenge.source_port} "
                f"udp dport {challenge.sink_port} @th,64,96 0x{prefix:x} meta nftrace set 1 "
                f"# handle 9 (verdict continue)")
    lines = [f"trace id {ident} inet aegis_auto_witness trace_out {body}",
             f"trace id {ident} inet aegis_auto_witness trace_out {own_rule}",
             f"trace id {ident} inet aegis_auto_witness trace_out policy accept ",
             f"trace id {ident} inet aegis_device_guard output {body}",
             f"trace id {ident} inet aegis_device_guard output rule counter packets 4 "
             f"bytes 200 drop # handle {handle} (verdict drop)"]
    return ("\n".join(lines) + "\n").encode()


def rendered(expected):
    """The nft JSON rows `nft --json list ruleset` prints for one batch."""
    rows = [{"table": {"family": "inet", "name": "aegis_auto_witness", "handle": 40}},
            {"chain": {"family": "inet", "table": "aegis_auto_witness", "name": "trace_out",
                       "handle": 1, "type": "filter", "hook": "output", "prio": -200,
                       "policy": "accept"}}]
    for index, rule in enumerate(expected["rules"]):
        def match(left, right):
            return {"match": {"op": "==", "left": left, "right": right}}
        rows.append({"rule": {"family": "inet", "table": "aegis_auto_witness",
                              "chain": "trace_out", "handle": index + 2, "expr": [
            match({"meta": {"key": "oifname"}}, rule["oifname"]),
            match({"payload": {"protocol": rule["family"], "field": "daddr"}}, rule["daddr"]),
            match({"payload": {"protocol": "udp", "field": "sport"}}, rule["sport"]),
            match({"payload": {"protocol": "udp", "field": "dport"}}, rule["dport"]),
            match({"payload": {"base": "th", "offset": 64, "len": 96}}, hex(rule["prefix"])),
            {"mangle": {"key": {"meta": {"key": "nftrace"}}, "value": 1}}]}})
    return {"nftables": rows}


class DualBatchAndPredicate(unittest.TestCase):
    def test_ipv6_nonce_is_domain_separated_and_bound_to_actor(self):
        nonce = witness.ipv6_challenge_nonce(ACTOR)
        self.assertEqual(nonce, hashlib.sha256(
            b"AEGIS native witness v6 challenge v1\0" + ACTOR).digest())
        self.assertNotEqual(nonce, ACTOR)
        self.assertNotEqual(witness.ipv6_challenge_nonce(bytes(32)), nonce)
        for bad in (b"", ACTOR[:31], ACTOR + b"x", "x" * 32):
            with self.assertRaises(NativeWitnessRefused):witness.ipv6_challenge_nonce(bad)

    def test_batch_is_one_atomic_fourteen_row_table_with_distinct_prefixes(self):
        raw, expected = witness._dual_batch(*challenges())
        lines = raw.decode().splitlines()
        self.assertEqual(len(lines), 14)
        self.assertTrue(lines[0].startswith("add table inet aegis_auto_witness"))
        self.assertEqual(sum("ip6 daddr" in line for line in lines), 6)
        self.assertEqual(sum(" ip daddr" in line for line in lines), 6)
        self.assertEqual(len({rule["prefix"] for rule in expected["rules"]}), 12)
        self.assertLessEqual(len(raw), 4096)
        foreign.verify_active_trace_table(rendered(expected), expected)
        foreign.verify_active_trace_table(rendered(expected))

    def test_batch_refuses_shared_tuple_parts(self):
        c4, c6 = challenges()
        same_port = Challenge(c6.egress_interface, c6.peer_ipv4, c4.source_port,
                              c6.sink_port, c6.nonce)
        same_nonce = Challenge(c6.egress_interface, c6.peer_ipv4, c6.source_port,
                               c6.sink_port, c4.nonce)
        other_iface = Challenge("aegisaw9", c6.peer_ipv4, c6.source_port, c6.sink_port, c6.nonce)
        for first, second in ((c4, same_port), (c4, same_nonce), (c4, other_iface),
                              (c6, c4), (c4, c4), (c6, c6)):
            with self.subTest(first=first, second=second), self.assertRaises(NativeWitnessRefused):
                witness._dual_batch(first, second)

    def test_fourteen_row_predicate_refusals(self):
        _raw, expected = witness._dual_batch(*challenges())
        base = rendered(expected)
        rules = list(range(2, 14))

        def mutate(name):
            value = copy.deepcopy(base)
            rows = value["nftables"]
            def expr(index, field):
                return rows[index]["rule"]["expr"][field]["match"]
            if name == "thirteen":rows.pop()
            elif name == "fifteen":rows.append(copy.deepcopy(rows[-1]))
            elif name == "seven_five":
                for field in (1, 2, 3):
                    expr(8, field)["right"] = expr(2, field)["right"]
                rows[8]["rule"]["expr"][1]["match"]["left"]["payload"]["protocol"] = "ip"
            elif name == "third_tuple":expr(13, 2)["right"] = 48999
            elif name == "two_ip":
                for index in range(8, 14):
                    rows[index]["rule"]["expr"][1]["match"]["left"]["payload"]["protocol"] = "ip"
                    expr(index, 1)["right"] = "198.18.77.6"
            elif name == "two_ip6":
                for index in range(2, 8):
                    rows[index]["rule"]["expr"][1]["match"]["left"]["payload"]["protocol"] = "ip6"
                    expr(index, 1)["right"] = "2001:db8:ae61:77::6"
            elif name == "mixed_oifname":
                for index in range(8, 14):expr(index, 0)["right"] = "aegisaw9"
            elif name == "equal_source_ports":
                for index in range(8, 14):expr(index, 2)["right"] = expr(2, 2)["right"]
            elif name == "duplicate_within":expr(3, 4)["right"] = expr(4, 4)["right"]
            elif name == "duplicate_across":expr(9, 4)["right"] = expr(3, 4)["right"]
            elif name == "out_of_prefix":
                for index in range(8, 14):expr(index, 1)["right"] = "2001:4860::1"
            elif name == "accept":rows[9]["rule"]["expr"][5] = {"accept": None}
            elif name == "mark":rows[9]["rule"]["expr"][5] = {"mangle": {"key": {"meta": {"key": "mark"}}, "value": 1}}
            elif name == "drop_chain":rows[1]["chain"]["policy"] = "drop"
            return value
        for name in ("thirteen", "fifteen", "seven_five", "third_tuple", "two_ip", "two_ip6",
                     "mixed_oifname", "equal_source_ports", "duplicate_within",
                     "duplicate_across", "out_of_prefix", "accept", "mark", "drop_chain"):
            with self.subTest(name=name), self.assertRaises((ValueError, TypeError, KeyError)):
                foreign.verify_active_trace_table(mutate(name))
        self.assertTrue(rules)

    def test_exact_batch_mode_refuses_any_single_field_change(self):
        _raw, expected = witness._dual_batch(*challenges())
        value = rendered(expected)
        foreign.verify_active_trace_table(value, expected)
        for index in range(12):
            for field in ("oifname", "daddr", "sport", "dport", "prefix"):
                changed = copy.deepcopy(expected)
                rule = changed["rules"][index]
                rule[field] = {"oifname": "aegisaw1", "daddr": "198.18.77.6" if rule["family"] == "ip"
                               else "2001:db8:ae61:77::6", "sport": 48777,
                               "dport": 47777, "prefix": rule["prefix"] ^ 1}[field]
                with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                    foreign.verify_active_trace_table(value, changed)
        swapped = copy.deepcopy(expected)
        swapped["rules"][0], swapped["rules"][1] = swapped["rules"][1], swapped["rules"][0]
        for bad in (swapped, {"schema": "other", "rules": expected["rules"]},
                    {"schema": expected["schema"], "rules": expected["rules"][:-1]}):
            with self.assertRaises(ValueError):foreign.verify_active_trace_table(value, bad)

    def test_single_family_shape_is_still_admitted(self):
        c4, _c6 = challenges()
        rules = [{"family": "ip", "oifname": c4.egress_interface, "daddr": c4.peer_ipv4,
                  "sport": c4.source_port, "dport": c4.sink_port,
                  "prefix": int.from_bytes(v.nonce[:12], "big")}
                 for v in [c4, *witness._calibration_challenges(c4)]]
        foreign.verify_active_trace_table(rendered({"rules": rules}))

    def test_expected_batch_requires_present_table_and_allowance(self):
        _raw, expected = witness._dual_batch(*challenges())
        with self.assertRaisesRegex(foreign.ForeignPolicyRefused, "installed trace batch missing"):
            foreign.verified_owned_tables({"nftables": []}, Path("/nonexistent/state"),
                                          allow_active_trace=True,
                                          expected_active_trace=expected)
        with self.assertRaisesRegex(foreign.ForeignPolicyRefused, "installed trace batch missing"):
            foreign.verified_owned_tables(rendered(expected), Path("/nonexistent/state"),
                                          expected_active_trace=expected)
        self.assertEqual(foreign.verified_owned_tables(
            rendered(expected), Path("/nonexistent/state"), allow_active_trace=True,
            expected_active_trace=expected), {("inet", "aegis_auto_witness")})


class TraceAttribution(unittest.TestCase):
    def test_episodes_split_by_family_and_reused_ids_follow_packet_lines(self):
        c4, c6 = challenges()
        cal4 = witness._calibration_challenges(c4)[0]
        raw = (episode(c4, cal4, "aa") + episode(c4, c4, "bb") +
               episode(c6, c6, "aa") + b"trace id cc inet aegis_device_guard output stray\n")
        families = ((4, c4, SOURCES[4]), (6, c6, SOURCES[6]))
        buffers, other = witness._attribute_trace(raw, families)
        self.assertEqual(buffers[4], episode(c4, cal4, "aa") + episode(c4, c4, "bb"))
        self.assertEqual(buffers[6], episode(c6, c6, "aa"))
        self.assertEqual(other, b"trace id cc inet aegis_device_guard output stray\n")
        self.assertEqual(witness._trace_drop(buffers[4], c4, 6, SOURCES[4]), "bb")
        self.assertEqual(witness._trace_drop(buffers[6], c6, 6, SOURCES[6]), "aa")
        self.assertEqual(witness._trace_drop(raw, c6, 6, SOURCES[6]), "aa")
        # A v6 packet reusing a v4 id takes the id's later lines with it.
        late = episode(c4, c4, "dd").splitlines(keepends=True)
        interleaved = (late[0] + late[1] + episode(c6, c6, "dd") +
                       late[2] + late[3] + late[4])
        buffers, _ = witness._attribute_trace(interleaved, families)
        with self.assertRaises(NativeWitnessRefused):witness._trace_drop(buffers[4], c4, 6, SOURCES[4])
        with self.assertRaises(NativeWitnessRefused):witness._trace_drop(interleaved, c4, 6, SOURCES[4])
        with self.assertRaises(NativeWitnessRefused):witness._attribute_trace(b"\xff\n", families)

    def test_native_unknown_rule_lines_never_prove_a_trace(self):
        """r17c G1: a rule added after `nft monitor trace` subscribed prints
        as "unknown rule handle N". The packet still reaches the guard DROP,
        but without the rule text no episode is proven, for either family."""
        c4, c6 = challenges()
        for challenge in (c4, c6):
            source = SOURCES[6 if ":" in challenge.peer_ipv4 else 4]
            with self.subTest(family=challenge.peer_ipv4):
                known = episode(challenge, challenge, "7b52a138")
                self.assertEqual(witness._trace_drop(known, challenge, 6, source), "7b52a138")
                unknown = episode(challenge, challenge, "7b52a138", unknown_rule=True)
                self.assertIn(b"trace_out unknown rule handle 9 (verdict continue)", unknown)
                self.assertIn(b"drop # handle 6 (verdict drop)", unknown)
                with self.assertRaisesRegex(NativeWitnessRefused, "persistent terminal DROP"):
                    witness._trace_drop(unknown, challenge, 6, source)
                # Neither a known episode on another id nor a calibration
                # nonce can lend its rule text to the unknown episode.
                calibration = witness._calibration_challenges(challenge)[0]
                mixed = episode(challenge, calibration, "aa") + unknown
                with self.assertRaises(NativeWitnessRefused):
                    witness._trace_drop(mixed, challenge, 6, source)
                self.assertEqual(witness._trace_drop(mixed, calibration, 6, source), "aa")


class FakeSelector:
    def __init__(self, kernel):
        self.kernel = kernel
        self.closed = False

    def register(self, fileobj, events):
        self.fileobj = fileobj

    def get_map(self):
        return {} if self.closed else {1: self.fileobj}

    def select(self, timeout):
        if self.kernel.chunks:
            self.kernel.now += 0.005
            return [(mock.Mock(fileobj=self.fileobj), selectors.EVENT_READ)]
        self.kernel.now += max(0.0, timeout)
        return []

    def close(self):
        self.closed = True


class FakeKernel:
    """Recording fake for nft, the monitor, both sinks and the senders."""

    def __init__(self, test):
        self.test = test
        self.now = 100.0
        self.events = []
        self.chunks = []
        self.counter = 4
        self.ident = 0
        self.received = {4: 0, 6: 0}
        self.trace_families = {4, 6}
        self.challenge_trace = {4, 6}
        self.times = {}
        self.count_families = {4, 6}
        self.policy_change_at = None
        self.guard_reads = 0
        self.foreign = {"schema": "aegis_foreign_policy_v1", "class": "filter_only",
                        "backend": "nf_tables", "foreign_projection_sha256": "f" * 64,
                        "ufw_class": "absent", "ufw_integrity_sha256": "a" * 64,
                        "ufw_enabled": False}
        self.mid = dict(self.foreign)
        self.batch = None
        self.monitor_knows_batch = None
        self.challenges = challenges()
        self.grant_refuse_at = None
        # The kernel emits a trace event only while nft is subscribed. By
        # default nft has joined the trace group when the bounded wait runs;
        # a positive value keeps it unsubscribed for that many packets.
        self.listening = False
        self.subscribe_after_lost = 0
        self.lost = []

    def family(self, challenge):
        return 6 if ":" in challenge.peer_ipv4 else 4

    def command(self, fd, args, *, input_data=None, deadline=None):
        if args == ["--json", "list", "tables"]:
            self.events.append("tables")
            return b'{"nftables":[{"table":{"family":"inet","name":"aegis_device_guard"}}]}'
        if args[:4] == ["--json", "--handle", "list", "table"]:
            self.guard_reads += 1
            self.events.append("guard%d" % self.guard_reads)
            raw = guard_table(self.counter)
            if self.policy_change_at == self.guard_reads:
                raw = raw.replace(b'"right":"lo"', b'"right":"eth0"')
            return raw
        if args == ["-f", "-"]:
            self.events.append("install")
            self.batch = input_data
            return b""
        if args == ["delete", "table", "inet", "aegis_auto_witness"]:
            self.events.append("delete")
            return b""
        raise AssertionError(args)

    def sink_message(self, sink, message, timeout):
        family = sink
        self.events.append(message["op"] + str(family))
        self.times[message["op"] + str(family)] = self.now
        if message["op"] == "ARM":
            return {"state": "READY", "sha256": message["sha256"], "received": 0,
                    "session": message["session"]}
        return {"state": "COMPLETE", "sha256": message["sha256"],
                "received": self.received[family], "session": message["session"]}

    def open_sender(self, challenge):
        family = self.family(challenge)
        self.events.append("open%d" % family)
        sender = mock.Mock()
        sender.close.side_effect = lambda: self.events.append("close%d" % family)
        sender.family = family
        return sender

    def send_on(self, sender, value, *, may_drop):
        self.test.assertTrue(may_drop)
        challenge = self.challenges[0 if sender.family == 4 else 1]
        kind = "challenge" if value.nonce == challenge.nonce else "calibration"
        self.events.append("send%d-%s" % (sender.family, kind))
        if sender.family in self.count_families:
            self.counter += 1
        if not self.listening:
            # Dropped by the guard, but no listener: no trace event exists.
            self.lost.append(kind)
            self.listening = len(self.lost) >= self.subscribe_after_lost
            return None
        if sender.family in self.trace_families and (
                kind == "calibration" or sender.family in self.challenge_trace):
            self.ident += 1
            self.test.assertIsNotNone(self.monitor_knows_batch)
            self.chunks.append(episode(challenge, value, "%x" % self.ident,
                                       unknown_rule=not self.monitor_knows_batch))
        return None

    def monitor_started(self):
        self.events.append("monitor")
        # The subscription snapshot: rules installed later stay unknown.
        self.monitor_knows_batch = self.batch is not None

    def await_subscription(self, monitor):
        self.events.append("subscription_wait")
        if self.subscribe_after_lost == 0:
            self.listening = True
        return self.listening

    def read(self, fd, size):
        return self.chunks.pop(0) if self.chunks else b""

    def assess(self, uplink, **kwargs):
        if kwargs.get("expected_active_trace") is not None:
            self.events.append("foreign_mid")
            self.test.assertTrue(kwargs["allow_active_trace"] and kwargs["require_guard"])
            self.test.assertEqual(kwargs["expected_active_trace"],
                                  witness._dual_batch(*self.challenges)[1])
            return dict(self.mid)
        self.events.append("foreign")
        self.test.assertEqual(kwargs, {"mode": "full-wide-tun", "require_guard": True})
        return dict(self.foreign)

    def grant_check(self, projection):
        self.events.append("grant")
        if self.grant_refuse_at == self.events.count("grant"):
            raise NativeWitnessRefused("client_grant_during_deny_witness")


class MergedProof(unittest.TestCase):
    def run_proof(self, kernel):
        c4, c6 = kernel.challenges
        positives = []
        for family, challenge in ((4, c4), (6, c6)):
            positives.append(witness.PositiveSinkControl(
                hashlib.sha256(b"baseline%d" % family).hexdigest(), "%032x" % family,
                900 + family, 77, 55, challenge.sink_port, challenge.egress_interface,
                challenge.peer_ipv4, challenge.source_port, SOURCES[family],
                "02:00:00:00:00:01", "02:00:00:00:00:02", 9, "af_packet_l2", kernel.now))
        rollback = trace_rollback.RollbackClient()
        rollback.arm = mock.Mock(side_effect=lambda **kw: kernel.events.append("rollback_arm"))
        rollback.live = mock.Mock(return_value=True)
        rollback.disarm = mock.Mock(side_effect=lambda: kernel.events.append("disarm"))
        monitor = mock.Mock()
        monitor.poll.return_value = None
        monitor.communicate.return_value = (b"", b"")
        def popen(argv, **kw):
            kernel.monitor_started()
            self.assertEqual(argv, ["/usr/sbin/nft", "-a", "monitor", "trace"])
            return monitor
        admitted = {id(positives[0]): (904, 77, 55), id(positives[1]): (906, 77, 55)}
        lease = mock.Mock(side_effect=lambda: kernel.events.append("lease_verify"))
        self.failures = []
        with open(os.devnull) as lock, \
             mock.patch.object(witness.os, "name", "posix"), \
             mock.patch.object(witness.os, "geteuid", return_value=0), \
             mock.patch.object(witness, "Path", side_effect=lambda value: mock.Mock(exists=lambda: True)), \
             mock.patch.object(witness, "_foreign_state", return_value={"uplink": "eth0"}), \
             mock.patch.object(foreign, "assess_foreign_policy", side_effect=kernel.assess), \
             mock.patch.object(witness, "_admit_positive_control",
                               side_effect=lambda c, p, s: admitted[id(p)]), \
             mock.patch.object(witness, "_pin_nft", side_effect=lambda path: os.open(os.devnull, os.O_RDONLY)), \
             mock.patch.object(witness, "_command", side_effect=kernel.command), \
             mock.patch.object(witness, "_sink_message", side_effect=kernel.sink_message), \
             mock.patch.object(witness, "_peer", side_effect=lambda sink: (900 + sink, 77)), \
             mock.patch.object(witness.subprocess, "Popen", side_effect=popen), \
             mock.patch.object(witness.selectors, "DefaultSelector", side_effect=lambda: FakeSelector(kernel)), \
             mock.patch.object(witness.os, "read", side_effect=kernel.read), \
             mock.patch.object(witness, "_open_sender", side_effect=kernel.open_sender), \
             mock.patch.object(witness, "_send_on", side_effect=kernel.send_on), \
             mock.patch.object(witness, "_await_trace_subscription",
                               side_effect=kernel.await_subscription), \
             mock.patch.object(witness, "_write_trace_subscription_failure",
                               side_effect=lambda *a: self.failures.append(a)), \
             mock.patch.object(witness.time, "monotonic", side_effect=lambda: kernel.now):
            return witness.prove_deny_dual(
                Path("/usr/sbin/nft"), lock.fileno(), hashlib.sha256(
                    witness.policy_projection(guard_table(0))[0]).hexdigest(),
                (c4, c6), tuple(positives), (4, 6), rollback,
                lease_verify=lease, grant_check=kernel.grant_check)

    def test_one_window_keeps_every_family_check_in_order(self):
        kernel = FakeKernel(self)
        result = self.run_proof(kernel)
        order = [e for e in kernel.events if not e.startswith("tables")]
        self.assertEqual(order, [
            "foreign", "guard1", "grant", "ARM4", "rollback_arm", "install", "monitor",
            "subscription_wait", "open4", "send4-calibration", "send4-challenge", "close4",
            "guard2", "grant", "ARM6",
            "open6", "send6-calibration", "send6-challenge", "close6",
            "foreign_mid", "lease_verify", "FINISH4", "FINISH6", "guard3", "grant",
            "delete", "disarm", "foreign"])
        self.assertEqual(kernel.batch, witness._dual_batch(*kernel.challenges)[0])
        self.assertEqual((result.ipv4.address_family, result.ipv6.address_family), (4, 6))
        self.assertEqual((result.ipv4.guard_output_drop_delta,
                          result.ipv6.guard_output_drop_delta), (2, 2))
        self.assertEqual(result.ipv4.challenge_sha256, hashlib.sha256(ACTOR).hexdigest())
        self.assertEqual(result.ipv6.challenge_sha256, hashlib.sha256(
            witness.ipv6_challenge_nonce(ACTOR)).hexdigest())
        self.assertNotEqual(result.ipv4.trace_sha256, result.ipv6.trace_sha256)
        self.assertEqual(result.ipv4.guard_after_sha256, result.ipv6.guard_before_sha256)
        self.assertGreaterEqual(result.ipv4_dwell_seconds, 1.1)
        self.assertGreaterEqual(result.ipv6_dwell_seconds, 1.1)
        self.assertEqual(result.foreign_before_sha256, result.foreign_mid_sha256)
        self.assertEqual(result.ipv4.foreign_mid_sha256, result.foreign_mid_sha256)
        self.assertEqual((result.ipv4.sink_received, result.ipv6.sink_received), (0, 0))
        self.assertEqual(self.failures, [])

    def refused(self, kernel, pattern):
        with self.assertRaisesRegex(NativeWitnessRefused, pattern):self.run_proof(kernel)
        # Every refusal still removes the trace table and disarms rollback.
        self.assertIn("monitor", kernel.events)
        if "install" in kernel.events:
            self.assertIn("delete", kernel.events)
        self.assertIn("disarm", kernel.events)

    def test_monitor_subscribes_only_after_the_batch_exists(self):
        kernel = FakeKernel(self)
        self.run_proof(kernel)
        events = kernel.events
        self.assertLess(events.index("rollback_arm"), events.index("install"))
        self.assertLess(events.index("install"), events.index("monitor"))
        self.assertLess(events.index("monitor"), events.index("send4-calibration"))
        self.assertEqual(events.count("monitor"), 1)
        self.assertIs(kernel.monitor_knows_batch, True)
        # One calibration per family suffices when the rule text is known.
        self.assertEqual(events.count("send4-calibration"), 1)
        self.assertEqual(events.count("send6-calibration"), 1)

    def test_monitor_subscribed_before_the_batch_refuses_fail_closed(self):
        """The G1 native failure, reproduced: every calibration reaches the
        guard DROP but prints "unknown rule", so the witness refuses after
        all calibration windows and never sends the IPv4 challenge."""
        kernel = FakeKernel(self)
        real = kernel.command

        def command(fd, args, *, input_data=None, deadline=None):
            if args == ["-f", "-"] and kernel.monitor_knows_batch is None:
                # The subscription snapshot predates the batch (c611c099).
                kernel.monitor_knows_batch = False
                kernel.monitor_started = lambda: kernel.events.append("monitor")
            return real(fd, args, input_data=input_data, deadline=deadline)
        kernel.command = command
        self.refused(kernel, "subscription not ready")
        self.assertIs(kernel.monitor_knows_batch, False)
        self.assertEqual(kernel.events.count("send4-calibration"),
                         witness.CALIBRATION_ATTEMPTS)
        self.assertNotIn("send4-challenge", kernel.events)
        self.assertNotIn("ARM6", kernel.events)
        self.assertEqual([(f[0], f[1], f[2]) for f in self.failures], [
            (hashlib.sha256(ACTOR).hexdigest(), "trace_unmatched", "calibration_subscription")])

    def test_first_calibration_follows_the_subscription_wait(self):
        """G2 scheduling: the first IPv4 calibration is sent only after the
        bounded wait for nft's trace-group membership, so it is not lost and
        ARM4 to ARM6 holds no idle 0.4 s calibration window."""
        kernel = FakeKernel(self)
        self.run_proof(kernel)
        events = kernel.events
        self.assertLess(events.index("monitor"), events.index("subscription_wait"))
        self.assertLess(events.index("subscription_wait"), events.index("open4"))
        self.assertEqual(events.count("subscription_wait"), 1)
        self.assertEqual(kernel.lost, [])
        self.assertEqual(events.count("send4-calibration"), 1)
        self.assertLess(kernel.times["ARM6"] - kernel.times["ARM4"], 0.4)

    def test_late_subscription_costs_one_calibration_window(self):
        """The G2 slow mode, reproduced: without a subscribed listener the
        first calibration leaves no trace, and the next one waits for its
        whole 0.4 s window. Every check still holds and the proof passes."""
        kernel = FakeKernel(self)
        kernel.subscribe_after_lost = 1
        result = self.run_proof(kernel)
        self.assertEqual(kernel.lost, ["calibration"])
        self.assertEqual(kernel.events.count("send4-calibration"), 2)
        self.assertEqual(kernel.events.count("send6-calibration"), 1)
        self.assertGreaterEqual(kernel.times["ARM6"] - kernel.times["ARM4"], 0.4)
        self.assertGreaterEqual(result.ipv4_dwell_seconds, 1.1)
        self.assertGreaterEqual(result.ipv6_dwell_seconds, 1.1)
        self.assertEqual(self.failures, [])

    def test_subscription_wait_grants_nothing(self):
        """A completed wait is not a readiness proof: without a calibration
        trace on the installed rule the witness refuses after every window,
        exactly as before, and never sends the IPv4 challenge."""
        kernel = FakeKernel(self)
        kernel.trace_families = set()
        self.refused(kernel, "subscription not ready")
        self.assertIn("subscription_wait", kernel.events)
        self.assertEqual(kernel.events.count("send4-calibration"),
                         witness.CALIBRATION_ATTEMPTS)
        self.assertNotIn("send4-challenge", kernel.events)
        self.assertNotIn("ARM6", kernel.events)

    def test_mid_window_foreign_change_is_refused(self):
        kernel = FakeKernel(self)
        kernel.mid["foreign_projection_sha256"] = "e" * 64
        self.refused(kernel, "foreign policy changed")

    def test_ipv4_counter_must_grow_before_ipv6_arm(self):
        kernel = FakeKernel(self)
        kernel.count_families = {6}
        self.refused(kernel, "DROP counter changed")
        self.assertNotIn("ARM6", kernel.events)

    def test_ipv6_counter_must_grow_by_c2(self):
        kernel = FakeKernel(self)
        kernel.count_families = {4}
        self.refused(kernel, "DROP counter changed")

    def test_policy_change_at_any_sample_is_refused(self):
        for read in (1, 2, 3):
            with self.subTest(read=read):
                kernel = FakeKernel(self)
                kernel.policy_change_at = read
                with self.assertRaises(NativeWitnessRefused):self.run_proof(kernel)

    def test_grant_check_runs_at_c0_c1_c2(self):
        for index in (1, 2, 3):
            with self.subTest(index=index):
                kernel = FakeKernel(self)
                kernel.grant_refuse_at = index
                with self.assertRaisesRegex(NativeWitnessRefused, "client_grant"):
                    self.run_proof(kernel)

    def test_each_sink_must_receive_nothing(self):
        for family in (4, 6):
            with self.subTest(family=family):
                kernel = FakeKernel(self)
                kernel.received[family] = 1
                self.refused(kernel, "reached independent sink")

    def test_each_dwell_is_measured_from_its_own_arm(self):
        kernel = FakeKernel(self)
        self.run_proof(kernel)
        self.assertGreater(kernel.times["ARM6"], kernel.times["ARM4"])
        for family in (4, 6):
            self.assertGreaterEqual(kernel.times["FINISH%d" % family] -
                                    kernel.times["ARM%d" % family], 1.1)

    def test_missing_ipv6_challenge_trace_times_out(self):
        kernel = FakeKernel(self)
        kernel.challenge_trace = {4}
        self.refused(kernel, "trace timed out")
        self.assertEqual([failure[2] for failure in self.failures], ["challenge_timeout"])
        self.assertEqual(self.failures[0][0], hashlib.sha256(
            witness.ipv6_challenge_nonce(ACTOR)).hexdigest())

    def test_missing_ipv4_challenge_trace_never_arms_ipv6(self):
        kernel = FakeKernel(self)
        kernel.challenge_trace = {6}
        self.refused(kernel, "trace timed out")
        self.assertNotIn("ARM6", kernel.events)
        self.assertEqual(self.failures[0][0], hashlib.sha256(ACTOR).hexdigest())

    def test_missing_ipv6_trace_times_out_with_ipv6_evidence(self):
        kernel = FakeKernel(self)
        kernel.trace_families = {4}
        self.refused(kernel, "subscription not ready")
        self.assertEqual(len(self.failures), 1)
        self.assertEqual(self.failures[0][0], hashlib.sha256(
            witness.ipv6_challenge_nonce(ACTOR)).hexdigest())
        self.assertNotIn("FINISH4", kernel.events)


class DualTopologyFences(unittest.TestCase):
    def patches(self, root):
        return [mock.patch.object(topology, "RUNTIME", root),
                mock.patch.object(topology, "STATE", root / "state"),
                mock.patch.object(topology, "SINK_SOCKET", root / "socket"),
                mock.patch.object(topology, "SINK6_SOCKET", root / "socket6"),
                mock.patch.object(topology, "_watchdog_ready"),
                mock.patch.object(topology, "_link", return_value=None),
                mock.patch.object(topology, "_namespace_present", return_value=False)]

    def test_any_retained_receipt_or_socket_fences_the_dual_lease(self):
        for name in ("sink-receipt-" + ACTOR.hex() + ".json",
                     "sink-receipt-4-" + ACTOR.hex() + ".json",
                     "sink-receipt-6-" + ACTOR.hex() + ".json", "socket", "socket6", "state"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / name).write_bytes(b"retained")
                patches = self.patches(root)
                for item in patches:item.start()
                try:
                    with mock.patch.object(topology, "_route_snapshot") as routes:
                        with self.assertRaisesRegex(topology.Refused, "existing_witness_topology"):
                            topology._prepare_dual(ACTOR)
                        routes.assert_not_called()
                    if name == "socket6":
                        with mock.patch.object(topology, "_route_snapshot") as routes:
                            with self.assertRaisesRegex(topology.Refused, "existing_witness_topology"):
                                topology._prepare(ACTOR, 4)
                            routes.assert_not_called()
                finally:
                    for item in patches:item.stop()
                self.assertEqual((root / name).read_bytes(), b"retained")

    def test_receipt_paths_are_the_family_fences(self):
        legacy, four, six = topology._receipt_paths(ACTOR)
        self.assertEqual(legacy.name, "sink-receipt-" + ACTOR.hex() + ".json")
        self.assertEqual(four.name, "sink-receipt-4-" + ACTOR.hex() + ".json")
        self.assertEqual(six.name, "sink-receipt-6-" + ACTOR.hex() + ".json")

    def facts(self):
        legacy, four, six = topology._receipt_paths(ACTOR)
        return {"schema": "aegis_auto_witness_topology_dual_v1", "root_if": "aegisaw0",
                "address_family": "dual", "actor_challenge_hex": ACTOR.hex(),
                "challenge_nonce_hex": ACTOR.hex(), "root_ifindex": 9, "sink_netns_ino": 77,
                "families": {
                    "4": {"address_family": 4, "sink_pid": 904, "peer_ip": topology.PEER_IP,
                          "sink_port": 47001, "source_port": 48001, "sink_receipt": str(four),
                          "baseline_nonce_hex": "1" * 64},
                    "6": {"address_family": 6, "sink_pid": 906, "peer_ip": topology.PEER_IPV6,
                          "sink_port": 47002, "source_port": 48002, "sink_receipt": str(six),
                          "baseline_nonce_hex": "2" * 64}}}

    def test_dual_facts_refuse_shared_or_foreign_values(self):
        self.assertTrue(topology._dual_facts_valid(self.facts(), ACTOR))
        mutations = {
            "same_source": lambda f: f["families"]["6"].update(source_port=48001),
            "same_sink_pid": lambda f: f["families"]["6"].update(sink_pid=904),
            "same_baseline": lambda f: f["families"]["6"].update(baseline_nonce_hex="1" * 64),
            "wrong_peer": lambda f: f["families"]["4"].update(peer_ip="198.18.77.6"),
            "wrong_receipt": lambda f: f["families"]["4"].update(
                sink_receipt=f["families"]["6"]["sink_receipt"]),
            "other_challenge": lambda f: f.update(challenge_nonce_hex="0" * 64),
            "single_schema": lambda f: f.update(schema="aegis_auto_witness_topology_v1"),
            "third_family": lambda f: f["families"].update({"5": {}}),
            "port_range": lambda f: f["families"]["4"].update(source_port=47001),
            "extra_field": lambda f: f["families"]["4"].update(extra=1)}
        for name, change in mutations.items():
            value = copy.deepcopy(self.facts())
            change(value)
            with self.subTest(name=name):
                self.assertFalse(topology._dual_facts_valid(value, ACTOR))

    def test_distinct_ports_never_collide(self):
        values = iter([(5).to_bytes(2, "big"), (1005).to_bytes(2, "big"), (7).to_bytes(2, "big")])
        with mock.patch.object(topology.os, "urandom", side_effect=lambda n: next(values)):
            self.assertEqual(topology._distinct_ports(48000), (48005, 48007))

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() != 0, "non-root owner check")
    def test_receipts_retained_requires_root_regular_0600_single_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(topology, "RUNTIME", root):
                facts = self.facts()
                for family in (4, 6):
                    path = topology._receipt_paths(ACTOR)[1 if family == 4 else 2]
                    facts["families"][str(family)]["sink_receipt"] = str(path)
                lease = topology.DualTopologyLease(None, {}, facts, ACTOR, -1, {}, closed=True)
                with self.assertRaises(FileNotFoundError):lease.receipts_retained()
                for family in (4, 6):
                    path = topology._receipt_paths(ACTOR)[1 if family == 4 else 2]
                    path.write_bytes(b"{}")
                    path.chmod(0o600)
                # Owned by this non-root test user, so the root-owner check refuses.
                with self.assertRaisesRegex(topology.Refused, "sink_receipt_not_retained"):
                    lease.receipts_retained()
                open_lease = topology.DualTopologyLease(None, {}, facts, ACTOR, -1, {})
                with self.assertRaisesRegex(topology.Refused, "still_open"):
                    open_lease.receipts_retained()


NETLINK_HEADER = ("sk               Eth Pid        Groups   Rmem     Wmem     Dump  "
                  "Locks    Drops    Inode")


def netlink_row(protocol, groups, inode, portid=4242):
    """One /proc/<pid>/net/netlink row in the kernel's seq_printf layout."""
    return ("0000000000000000 %-3d %-10u %08x %-8d %-8d %-5d %-8d %-8u %-8u"
            % (protocol, portid, groups, 0, 0, 0, 2, 0, inode))


class TraceSubscriptionWait(unittest.TestCase):
    def test_membership_requires_netfilter_protocol_trace_bit_and_own_inode(self):
        own = frozenset({5001, 5002})
        trace = 1 << (witness.NFNLGRP_NFTRACE - 1)
        tables = (1 << (7 - 1))
        cases = [
            ([netlink_row(12, trace, 5002)], True),
            ([netlink_row(12, trace | tables, 5001)], True),
            ([netlink_row(12, tables, 5001)], False),          # NFTABLES only
            ([netlink_row(12, 0, 5001)], False),               # not yet joined
            ([netlink_row(0, trace, 5001)], False),            # NETLINK_ROUTE
            ([netlink_row(12, trace, 6001)], False),           # another socket
            ([netlink_row(12, trace, 5001) + " extra"], False),  # malformed row
            ([netlink_row(12, trace, 5001).replace("00000100", "100")], False),
        ]
        for rows, expected in cases:
            with self.subTest(rows=rows):
                table = "\n".join([NETLINK_HEADER, netlink_row(16, 0, 1), *rows]) + "\n"
                self.assertIs(witness._netlink_trace_member(table, own), expected)
        row = netlink_row(12, trace, 5001)
        self.assertFalse(witness._netlink_trace_member(row + "\n", own))
        self.assertFalse(witness._netlink_trace_member("", own))
        self.assertFalse(witness._netlink_trace_member(
            NETLINK_HEADER + "\n" + row + "\n", frozenset()))

    def wait(self, monitor, tables, inodes=frozenset({5001}), read_error=None):
        clock = {"now": 10.0, "reads": 0, "sleeps": 0}

        def read(pid):
            self.assertEqual(pid, 4321)
            clock["reads"] += 1
            if read_error is not None:
                raise read_error
            return tables[min(clock["reads"], len(tables)) - 1]

        def sleep(seconds):
            self.assertEqual(seconds, 0.002)
            clock["sleeps"] += 1
            clock["now"] += seconds

        with mock.patch.object(witness, "_socket_inodes", return_value=inodes), \
             mock.patch.object(witness, "_read_netlink_table", side_effect=read), \
             mock.patch.object(witness.time, "monotonic", side_effect=lambda: clock["now"]), \
             mock.patch.object(witness.time, "sleep", side_effect=sleep):
            result = witness._await_trace_subscription(monitor)
        return result, clock

    def monitor(self, exited_after=None):
        monitor = mock.Mock()
        monitor.pid = 4321
        polls = {"n": 0}

        def poll():
            polls["n"] += 1
            return 0 if exited_after is not None and polls["n"] > exited_after else None
        monitor.poll.side_effect = poll
        return monitor

    def test_wait_returns_once_nft_has_joined_the_trace_group(self):
        joined = "\n".join([NETLINK_HEADER, netlink_row(12, 1 << 8, 5001)]) + "\n"
        pending = "\n".join([NETLINK_HEADER, netlink_row(12, 0, 5001)]) + "\n"
        result, clock = self.wait(self.monitor(), [pending, pending, joined])
        self.assertTrue(result)
        self.assertEqual((clock["reads"], clock["sleeps"]), (3, 2))

    def test_wait_is_bounded_and_never_raises(self):
        pending = "\n".join([NETLINK_HEADER, netlink_row(12, 0, 5001)]) + "\n"
        result, clock = self.wait(self.monitor(), [pending])
        self.assertFalse(result)
        elapsed = clock["now"] - 10.0
        self.assertGreaterEqual(elapsed, witness.SUBSCRIPTION_SECONDS - 0.001)
        self.assertLessEqual(elapsed, witness.SUBSCRIPTION_SECONDS + 0.003)
        # A monitor that exits, a failed /proc read, a process without any
        # socket yet, or a pid that is not a real child: no wait, no raise.
        result, clock = self.wait(self.monitor(exited_after=1), [pending])
        self.assertFalse(result)
        self.assertEqual(clock["reads"], 1)
        for error in (OSError("gone"), UnicodeDecodeError("ascii", b"\xff", 0, 1, "x")):
            result, clock = self.wait(self.monitor(), [pending], read_error=error)
            self.assertFalse(result)
            self.assertEqual(clock["reads"], 1)
        result, clock = self.wait(self.monitor(), [pending], inodes=frozenset())
        self.assertFalse(result)
        self.assertEqual(clock["reads"], 0)
        for pid in (None, 1, "4321", mock.Mock()):
            monitor = mock.Mock()
            monitor.pid = pid
            result, clock = self.wait(monitor, [pending])
            self.assertFalse(result)
            self.assertEqual((clock["reads"], clock["sleeps"]), (0, 0))

    @unittest.skipUnless(Path("/proc/self/net/netlink").exists(), "Linux procfs only")
    def test_real_proc_table_parses_without_claiming_membership(self):
        # This test process holds no netfilter trace socket.
        own = witness._socket_inodes(os.getpid())
        table = witness._read_netlink_table(os.getpid())
        self.assertIsNotNone(witness.NETLINK_TABLE.fullmatch(table.splitlines()[0].strip()))
        self.assertFalse(witness._netlink_trace_member(table, own))


if __name__ == "__main__":
    unittest.main()
