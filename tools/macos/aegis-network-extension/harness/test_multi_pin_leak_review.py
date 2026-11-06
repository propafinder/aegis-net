#!/usr/bin/python3 -I
"""Exact-pin controls for the B-06 physical capture reviewer; no network I/O."""
import importlib.util
import contextlib
import hashlib
import ipaddress
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("leak_review", Path(__file__).with_name("leak_review.py"))
reviewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reviewer)


def frame(destination, port):
    source = ipaddress.IPv4Address("192.0.2.10").packed
    destination = ipaddress.IPv4Address(destination).packed
    ethernet = bytes.fromhex("aabbccddeeff0011223344550800")
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, source, destination)
    tcp = struct.pack("!HHIIHHHH", 50000, port, 0, 0, 0x5002, 65535, 0, 0)
    return ethernet + ip + tcp


def udp_frame(destination, port):
    source = ipaddress.IPv4Address("192.0.2.10").packed
    destination = ipaddress.IPv4Address(destination).packed
    ethernet = bytes.fromhex("aabbccddeeff0011223344550800")
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0, source, destination)
    udp = struct.pack("!HHHH", 50000, port, 8, 0)
    return ethernet + ip + udp


def capture(*frames):
    header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    records = b"".join(struct.pack("<IIII", 100 + i, 0, len(f), len(f)) + f
                       for i, f in enumerate(frames))
    return header + records


def review(*frames, extras=(), relay_protos=("tcp", "udp"),
           signed_tcp_indices=None, signed_udp_indices=None):
    return reviewer.review(capture(*frames), "198.51.100.1", 443, 99, 110, guard=0,
                           local=("192.0.2.10",), local_mac="00:11:22:33:44:55",
                           relay_protos=relay_protos, extra_relay_pins=extras,
                           signed_tcp_relay_pins=signed_tcp_indices,
                           signed_udp_relay_pins=signed_udp_indices)


class MultiPinReview(unittest.TestCase):
    def test_provider_routes_bind_only_quic_udp_and_keep_primary_endpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            profile = {"relay_server": "198.51.100.1:443", "relay_endpoints": [
                {"server": "198.51.100.1:443", "server_name": "web.test"},
                {"server": "198.51.100.2:8443", "server_name": "quic.test"},
                {"server": "198.51.100.3:9443", "server_name": "direct.test"}],
                "carrier_program": {"routes": [
                    {"channel": "direct_h2", "endpoint_index": 2},
                    {"channel": "masque_quic", "endpoint_index": 1},
                    {"channel": "web_response", "endpoint_index": 0}]}}
            members = {"bundle.json": json.dumps(profile).encode(), "outer-ca.pem": b"outer",
                       "inner-ca.pem": b"inner", "device-ca.pem": b"device"}
            digest = hashlib.sha256()
            for name, data in members.items():
                (directory / name).write_bytes(data)
                digest.update(name.encode())
                digest.update(len(data).to_bytes(8, "little"))
                digest.update(data)
            pins, tcp, udp = reviewer.pin_policy_from_public_bundle(
                directory, digest.hexdigest(), "198.51.100.1", 443)
            self.assertEqual([str(ip) for ip, _ in pins],
                             ["198.51.100.1", "198.51.100.2", "198.51.100.3"])
            self.assertEqual(tcp, (pins[2], pins[0]))
            self.assertEqual(udp, (pins[1],))
            pcap = directory / "capture.pcap"
            output = directory / "review.json"
            argv = ["--pcap", str(pcap), "--relay-ip", "198.51.100.1",
                    "--relay-port", "443", "--bundle-dir", str(directory),
                    "--profile-sha256", digest.hexdigest(), "--relay-proto", "tcp",
                    "--local-addr", "192.0.2.10", "--local-mac", "00:11:22:33:44:55",
                    "--connected-at", "99", "--disconnect-at", "110", "--guard", "0",
                    "--out", str(output)]
            for other, passed in ((frame("198.51.100.2", 8443), False),
                                  (udp_frame("198.51.100.2", 8443), True)):
                pcap.write_bytes(capture(frame("198.51.100.1", 443), other))
                with contextlib.redirect_stdout(io.StringIO()):
                    code = reviewer.main(argv)
                report = json.loads(output.read_text())
                self.assertEqual(code, 0 if passed else 1)
                self.assertIs(report["pass"], passed)
                self.assertIs(report["mac_sent_pass"], passed)
            profile["carrier_program"]["routes"][1]["channel"] = "web_response"
            members["bundle.json"] = json.dumps(profile).encode()
            (directory / "bundle.json").write_bytes(members["bundle.json"])
            changed = hashlib.sha256()
            for name, data in members.items():
                changed.update(name.encode())
                changed.update(len(data).to_bytes(8, "little"))
                changed.update(data)
            _, tcp, udp = reviewer.pin_policy_from_public_bundle(
                directory, changed.hexdigest(), "198.51.100.1", 443)
            self.assertEqual(udp, ())
            self.assertEqual(len(tcp), 3)

    def test_extra_pin_requires_exact_provider_digest_and_signed_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            profile = {"relay_server": "198.51.100.1:443", "relay_endpoints": [
                {"server": "198.51.100.1:443", "server_name": "direct.test"},
                {"server": "198.51.100.2:8443", "server_name": "front.test"},
            ]}
            members = {"bundle.json": json.dumps(profile).encode(), "outer-ca.pem": b"outer",
                       "inner-ca.pem": b"inner", "device-ca.pem": b"device"}
            digest = hashlib.sha256()
            for name, data in members.items():
                (directory / name).write_bytes(data)
                digest.update(name.encode())
                digest.update(len(data).to_bytes(8, "little"))
                digest.update(data)
            expected = digest.hexdigest()
            pins = reviewer.pins_from_public_bundle(directory, expected, "198.51.100.1", 443)
            self.assertEqual(len(pins), 2)
            with self.assertRaises(ValueError):
                reviewer.pins_from_public_bundle(directory, "0" * 64, "198.51.100.1", 443)
            with self.assertRaises(ValueError):
                reviewer.pins_from_public_bundle(directory, expected, "198.51.100.3", 443)
            reordered = {**profile, "relay_endpoints": profile["relay_endpoints"] + [
                {"server": "198.51.100.3:443", "server_name": "bridge.test"}],
                "carrier_program": {"routes": [
                    {"channel": "direct_h2", "endpoint_index": 0},
                    {"channel": "fronted_h2", "endpoint_index": 2},
                    {"channel": "own_https_bridge", "endpoint_index": 1}]}}
            members["bundle.json"] = json.dumps(reordered).encode()
            (directory / "bundle.json").write_bytes(members["bundle.json"])
            route_digest = hashlib.sha256()
            for name, data in members.items():
                route_digest.update(name.encode())
                route_digest.update(len(data).to_bytes(8, "little"))
                route_digest.update(data)
            ordered = reviewer.pins_from_public_bundle(directory, route_digest.hexdigest(),
                                                        "198.51.100.1", 443)
            self.assertEqual([str(ip) for ip, _ in ordered],
                             ["198.51.100.1", "198.51.100.2", "198.51.100.3"])
            (directory / "bundle.json").write_bytes(json.dumps({
                **profile, "relay_endpoints": profile["relay_endpoints"] + [
                    {"server": "198.51.100.99:443", "server_name": "rogue.test"}]
            }).encode())
            with self.assertRaises(ValueError):
                reviewer.pins_from_public_bundle(directory, expected, "198.51.100.1", 443)

    def test_signed_second_pin_is_exact_and_counts_as_relay(self):
        packets = (frame("198.51.100.1", 443), frame("198.51.100.2", 8443))
        without = review(*packets)
        self.assertFalse(without["pass"])
        self.assertEqual(without["leak_count"], 1)
        with_pin = review(*packets, extras=("198.51.100.2:8443",))
        self.assertTrue(with_pin["pass"])
        self.assertTrue(with_pin["mac_sent_pass"])
        self.assertEqual(with_pin["relay_packets"], 2)
        self.assertEqual(with_pin["relay_pin_count"], 2)

    def test_wrong_port_and_foreign_host_still_leak_with_two_pins(self):
        primary = frame("198.51.100.1", 443)
        for other in (frame("198.51.100.2", 8444), frame("198.51.100.3", 8443)):
            result = review(primary, other, extras=("198.51.100.2:8443",))
            self.assertFalse(result["pass"])
            self.assertFalse(result["mac_sent_pass"])
            self.assertEqual(result["leak_count"], 1)
        no_authorized_pin = review(frame("198.51.100.99", 443),
                                   extras=("198.51.100.2:8443",))
        self.assertFalse(no_authorized_pin["pass"])
        self.assertEqual(no_authorized_pin["relay_packets"], 0)
        self.assertEqual(no_authorized_pin["leak_count"], 1)

    def test_pin_set_rejects_duplicate_malformed_and_unbounded(self):
        for extras in (("198.51.100.1:443",), ("198.51.100.2:0",),
                       ("224.0.0.1:443",), ("2001:db8::1:443",),
                       tuple(f"198.51.100.{i}:443" for i in range(2, 18))):
            with self.assertRaises(ValueError):
                reviewer.parse_relay_pins("198.51.100.1", 443, extras)
        pins = reviewer.parse_relay_pins("198.51.100.1", 443, ("[2001:db8::1]:443",))
        self.assertEqual(len(pins), 2)

    def test_only_signed_quic_pin_excludes_udp_and_wrong_port_still_leaks(self):
        extras = ("198.51.100.2:8443", "198.51.100.3:9443")
        admitted = review(frame("198.51.100.1", 443),
                          udp_frame("198.51.100.2", 8443), extras=extras,
                          relay_protos=("tcp",), signed_tcp_indices=(0, 2),
                          signed_udp_indices=(1,))
        self.assertTrue(admitted["pass"])
        self.assertTrue(admitted["mac_sent_pass"])
        self.assertEqual(admitted["signed_udp_pin_count"], 1)
        self.assertEqual(admitted["signed_tcp_pin_count"], 2)
        self.assertEqual(admitted["signed_tcp_pin_indices"], [0, 2])
        self.assertEqual(admitted["signed_udp_pin_indices"], [1])
        for denied in (frame("198.51.100.2", 8443),
                       udp_frame("198.51.100.1", 443),
                       udp_frame("198.51.100.3", 9443),
                       udp_frame("198.51.100.2", 8444),
                       udp_frame("198.51.100.99", 8443)):
            result = review(frame("198.51.100.1", 443), denied, extras=extras,
                            relay_protos=("tcp",), signed_tcp_indices=(0, 2),
                            signed_udp_indices=(1,))
            self.assertFalse(result["pass"])
            self.assertFalse(result["mac_sent_pass"])
            self.assertEqual(result["leak_count"], 1)
        for indices in ((3,), (True,), (1, 1)):
            with self.assertRaises(ValueError):
                review(frame("198.51.100.1", 443), extras=extras,
                       relay_protos=("tcp",), signed_tcp_indices=(0, 2),
                       signed_udp_indices=indices)
        with self.assertRaises(ValueError):
            review(frame("198.51.100.1", 443), extras=extras,
                   relay_protos=("tcp",), signed_tcp_indices=(0, True),
                   signed_udp_indices=(1,))
        with self.assertRaises(ValueError):
            review(frame("198.51.100.1", 443), extras=extras,
                   relay_protos=("tcp",), signed_udp_indices=(1,))


if __name__ == "__main__":
    unittest.main()
