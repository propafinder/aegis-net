"""Refusal tests for the installed capture witness; not a native acceptance run."""

import base64
import contextlib
import ctypes
import errno
import hashlib
import io
import importlib.util
import json
import os
import pathlib
import re
import select
import socket
import struct
import sys
import subprocess
import tempfile
import threading
import time
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SOURCE = pathlib.Path(__file__).resolve().parents[1] / "lib/aegis_auto_capture.py"
SPEC = importlib.util.spec_from_file_location("aegis_auto_capture", SOURCE)
capture = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = capture
SPEC.loader.exec_module(capture)
ENDPOINT_SOURCE = SOURCE.with_name("aegis_auto_endpoint.py")
ENDPOINT_SPEC = importlib.util.spec_from_file_location(
    "aegis_auto_endpoint", ENDPOINT_SOURCE)
endpoint = importlib.util.module_from_spec(ENDPOINT_SPEC)
sys.modules[ENDPOINT_SPEC.name] = endpoint
ENDPOINT_SPEC.loader.exec_module(endpoint)


@contextlib.contextmanager
def isolated_actor(filename, alias):
    previous = sys.modules.get(alias)
    spec = importlib.util.spec_from_file_location(alias, SOURCE.with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        if previous is None:
            sys.modules.pop(alias, None)
        else:
            sys.modules[alias] = previous


def connect_control_when_listening(peer, control, setup_deadline):
    # bind() publishes the pathname before chmod()/listen(). A pathname alone
    # cannot prove readiness; retain this fixture's original absolute budget.
    while True:
        remaining = setup_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("control listener setup deadline")
        try:
            peer.connect(str(control))
            return
        except OSError as error:
            if error.errno not in (errno.ECONNREFUSED, errno.ENOENT):
                raise
            time.sleep(min(0.005, remaining))


class CaptureRefusalTests(unittest.TestCase):
    def test_tun_sniffer_uses_all_protocol_and_closes_failed_bind(self):
        fake = Mock()
        with patch.object(capture.socket, "socket", return_value=fake) as make:
            self.assertIs(capture._tun_ipv6_sniffer(), fake)
        make.assert_called_once_with(
            socket.AF_PACKET, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC,
            socket.htons(capture.ETH_P_ALL))
        fake.bind.assert_called_once_with((capture.TUN, capture.ETH_P_ALL))
        fake.bind.side_effect = OSError(errno.ENODEV, "gone")
        with patch.object(capture.socket, "socket", return_value=fake):
            with self.assertRaises(OSError):
                capture._tun_ipv6_sniffer()
        fake.close.assert_called_once()

    def test_tun_outgoing_requires_ipv6_protocol_direction_tuple_and_nonce(self):
        target = "2001:db8:ae61::f"
        nonce = b"bounded nonce sample"
        header = bytearray(40)
        header[0] = 0x60
        header[4:6] = struct.pack("!H", 8 + len(nonce))
        header[6] = 17
        header[7] = 64
        header[24:40] = socket.inet_pton(socket.AF_INET6, target)
        packet = bytes(header) + struct.pack("!HHHH", 12345, 49271,
                                             8 + len(nonce), 0) + nonce
        address = (capture.TUN, capture.ETH_P_IPV6, socket.PACKET_OUTGOING)
        self.assertTrue(capture._tun_udp_outgoing(packet, address, target,
                                                   49271, nonce))
        for changed_packet, changed_address, changed_target, changed_port, changed_nonce in (
            (packet, (capture.TUN, 0x0800, socket.PACKET_OUTGOING), target, 49271, nonce),
            (packet, (capture.TUN, capture.ETH_P_IPV6, socket.PACKET_HOST), target, 49271, nonce),
            (packet, ("foreign-tun", capture.ETH_P_IPV6, socket.PACKET_OUTGOING), target, 49271, nonce),
            (packet, address, "a001:db8:ae61::f", 49271, nonce),
            (packet, address, target, 49272, nonce),
            (packet, address, target, 49271, b"foreign nonce sample"),
            (packet[:6] + b"\x3a" + packet[7:], address, target, 49271, nonce),
            (packet[:-1], address, target, 49271, nonce),
        ):
            with self.subTest(address=changed_address, target=changed_target,
                              port=changed_port, nonce=changed_nonce):
                self.assertFalse(capture._tun_udp_outgoing(
                    changed_packet, changed_address, changed_target,
                    changed_port, changed_nonce))

    def test_sink_local_route_uses_real_iproute2_json_for_both_families(self):
        for name, target in (("auto_sink_route_ipv4.json", "10.231.82.2"),
                             ("auto_sink_route_ipv6.json", "fd77:ae91:1::2")):
            with self.subTest(fixture=name):
                rows = json.loads((SOURCE.parent.parent / "tests/fixtures" / name).read_bytes())
                self.assertEqual(len(rows), 1)
                route = rows[0]
                self.assertNotIn("local", route)
                self.assertTrue(capture._sink_route_is_local(route, target))
                for changed in ({**route, "dev": "uplink0"},
                                {**route, "type": "unicast"},
                                {**route, "dst": "192.0.2.250"},
                                {"dev": "lo", "local": target},
                                {**route, "multipath": [{"dev": "uplink0"}]},
                                {**route, "nexthops": [{"dev": "uplink0"}]},
                                {**route, "nhid": 7}):
                    self.assertFalse(capture._sink_route_is_local(changed, target))

    def test_capture_routes_refuse_unparsed_next_hop_sets(self):
        for field, value in (("multipath", [{"dev": "uplink0"}]),
                             ("nexthops", [{"dev": "uplink0"}]),
                             ("nhid", 7)):
            with self.subTest(field=field):
                rows = [{"dst": prefix, "dev": capture.TUN, field: value}
                        for prefix, _target in capture.ROUTE_TARGETS]
                def route_json(argv):
                    return rows if "show" in argv else [{"dst": argv[-1],
                                                           "dev": capture.TUN}]
                with patch.object(capture, "_json", side_effect=route_json):
                    with self.assertRaises(capture.CaptureRefused):
                        capture._routes(123)

    def test_redirect_probe_route_refuses_unparsed_next_hop_sets(self):
        with isolated_actor("aegis_auto_capture_topology.py",
                            "aegis_auto_capture_topology_route_test") as topology:
            shown = {"dst": topology.RUNTIME_REDIRECT_TARGET + "/32",
                     "gateway": topology.HOST_PROBE_IP, "dev": topology.P_HOST,
                     "flags": []}
            selected = {"dst": topology.RUNTIME_REDIRECT_TARGET,
                        "gateway": topology.HOST_PROBE_IP,
                        "dev": topology.P_HOST, "prefsrc": topology.PROBE_IP}
            with patch.object(topology, "_run", side_effect=[
                    json.dumps([shown]).encode(), json.dumps([selected]).encode()]):
                topology._probe_redirect_route()
            for field, value in (("multipath", [{"dev": "uplink0"}]),
                                 ("nexthops", [{"dev": "uplink0"}]),
                                 ("nhid", 7)):
                for affected in ("shown", "selected"):
                    with self.subTest(field=field, affected=affected):
                        changed = ({**shown, field: value}, selected) if affected == "shown" else (
                            shown, {**selected, field: value})
                        with patch.object(topology, "_run", side_effect=[
                                json.dumps([row]).encode() for row in changed]):
                            with self.assertRaises(topology.Refused):
                                topology._probe_redirect_route()

    def test_control_waits_consume_one_deadline_without_a_timeout_floor(self):
        # These portable helpers require message boundaries, not Linux peer
        # credentials. Native SEQPACKET ownership is checked separately.
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            child.send(b'{"state":"first"}')
            with patch.object(capture.time, "monotonic", return_value=9.2):
                self.assertEqual(capture._control_recv(parent, 10), {"state": "first"})
            self.assertAlmostEqual(parent.gettimeout(), 0.8)
            child.send(b'{"state":"second"}')
            with patch.object(capture.time, "monotonic", return_value=9.98):
                self.assertEqual(capture._control_recv(parent, 10), {"state": "second"})
            self.assertAlmostEqual(parent.gettimeout(), 0.02)
            with patch.object(capture.time, "monotonic", return_value=10):
                with self.assertRaises(TimeoutError):
                    capture._control_recv(parent, 10)
                with self.assertRaises(TimeoutError):
                    capture._control_send(parent, {"op": "late"}, 10)
            child.setblocking(False)
            with self.assertRaises(BlockingIOError):
                child.recv(256)
        finally:
            parent.close()
            child.close()

    def test_probe_arm_requires_current_owner_deadline_and_reuses_remaining_budget(self):
        with isolated_actor("aegis_auto_sink.py", "_test_probe_deadline") as sink:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            nonce = b"a" * 32
            message = {"op": "PROBE_ARM", "nonce_hex": nonce.hex(),
                       "sha256": hashlib.sha256(nonce).hexdigest(),
                       "target_ip": "192.0.2.251", "target_port": 18080,
                       "deadline_monotonic_ns": 10_000_000_000}
            try:
                with patch.object(sink.time, "monotonic_ns", return_value=9_000_000_000):
                    parent.send(json.dumps(message).encode())
                    self.assertEqual(sink.receive_probe_arm(child), message)
                    for bad in ({**message, "deadline_monotonic_ns": 9_000_000_000},
                                {**message, "deadline_monotonic_ns": 18_000_000_000},
                                {**message, "deadline_monotonic_ns": True}):
                        parent.send(json.dumps(bad).encode())
                        with self.assertRaises(sink.Refused):
                            sink.receive_probe_arm(child)
                with patch.object(sink.time, "monotonic", return_value=9.99):
                    sink._probe_socket_timeout(child, 10)
                    self.assertAlmostEqual(child.gettimeout(), 0.01)
                with patch.object(sink.time, "monotonic", return_value=10):
                    with self.assertRaises(TimeoutError):
                        sink._probe_socket_timeout(child, 10)
            finally:
                parent.close()
                child.close()

    def test_phase_callback_failure_does_not_change_control_result(self):
        callback = Mock(side_effect=RuntimeError("private-path-token"))
        capture._capture_phase(callback, "redirect_await_observed")
        callback.assert_called_once_with("redirect_await_observed")

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                         "Linux root probe failure record control")
    def test_probe_connect_failure_uses_parent_budget_and_is_retained(self):
        with isolated_actor("aegis_auto_sink.py", "_test_probe_budget_failure") as sink:
            with tempfile.TemporaryDirectory() as directory:
                control = pathlib.Path(directory) / "effect.sock"
                receipt = pathlib.Path(directory) / "effect.json"
                real_socket = socket.socket
                pid = os.fork()
                if pid == 0:
                    try:
                        class FailedConnect:
                            def __enter__(self):
                                return self
                            def __exit__(self, *_args):
                                pass
                            def settimeout(self, value):
                                self.timeout = value
                            def connect(self, _target):
                                # The old effect-lifetime timeout was 60s;
                                # this I/O must consume the owner's <1s budget.
                                if not 0 < self.timeout < 1:
                                    raise AssertionError("probe budget reset")
                                raise TimeoutError("private-network-details")
                        def sockets(family, *args, **kwargs):
                            if family == socket.AF_INET:
                                return FailedConnect()
                            return real_socket(family, *args, **kwargs)
                        with patch.object(sink.socket, "socket", side_effect=sockets), \
                             patch.object(sink, "_peer", return_value=(os.getppid(), 1, 2)):
                            try:
                                sink.serve_probe_tcp(control, receipt, maximum_seconds=60)
                            except TimeoutError:
                                os._exit(0)
                        os._exit(2)
                    except BaseException:
                        os._exit(3)
                parent = None
                try:
                    setup_deadline = time.monotonic() + 3
                    while not control.exists() and time.monotonic() < setup_deadline:
                        time.sleep(0.005)
                    self.assertTrue(control.exists())
                    parent = real_socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    parent.settimeout(1)
                    connect_control_when_listening(parent, control, setup_deadline)
                    nonce = b"b" * 32
                    deadline = time.monotonic() + 1
                    parent.send(json.dumps({"op": "PROBE_ARM", "nonce_hex": nonce.hex(),
                        "sha256": hashlib.sha256(nonce).hexdigest(),
                        "target_ip": "192.0.2.251", "target_port": 18080,
                        "deadline_monotonic_ns": int(deadline * 1_000_000_000)}).encode())
                    self.assertEqual(json.loads(parent.recv(4096))["state"], "PROBE_READY")
                    failure = receipt.with_suffix(".failure.json")
                    while not failure.exists() and time.monotonic() < deadline:
                        time.sleep(0.005)
                    self.assertTrue(failure.exists())
                    recorded = json.loads(failure.read_bytes())
                    self.assertEqual(recorded["phase"], "connect")
                    self.assertEqual(recorded["class"], "timeout")
                    self.assertNotIn(b"private-network-details", failure.read_bytes())
                    self.assertFalse(receipt.exists())
                    stopped, status = os.waitpid(pid, 0)
                    self.assertEqual(stopped, pid)
                    pid = None
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                finally:
                    if parent is not None:
                        parent.close()
                    if pid is not None:
                        os.kill(pid, 9)
                        os.waitpid(pid, 0)

    def test_runtime_redirect_probe_has_exact_route_and_rejects_drift(self):
        with isolated_actor("aegis_auto_capture_topology.py", "_test_probe_route") as actor:
            self.assertEqual(actor.RUNTIME_REDIRECT_TARGET,
                             capture.RUNTIME_TCP_TARGET)
            reserved = (SOURCE.parents[2] / "aegis-core/src/auto_capture_probe.rs").read_text(
                encoding="utf-8")
            self.assertEqual(re.findall(r'(?m)^pub const TCP_HOST: &str = "([^"]+)";$',
                                        reserved), [actor.RUNTIME_REDIRECT_TARGET])
            self.assertEqual(re.findall(r'(?m)^pub const PORT: u16 = ([0-9]+);$',
                                        reserved), [str(capture.RUNTIME_PROBE_PORT)])
            base_shown = [{"dst": actor.RUNTIME_REDIRECT_TARGET,
                           "gateway": actor.HOST_PROBE_IP, "dev": actor.P_HOST,
                           "flags": []}]
            base_selected = [{"dst": actor.RUNTIME_REDIRECT_TARGET,
                              "gateway": actor.HOST_PROBE_IP, "dev": actor.P_HOST,
                              "prefsrc": actor.PROBE_IP, "flags": []}]
            shown, selected = base_shown, base_selected
            def routes(args, timeout=3.0):
                self.assertEqual(args[:6], [actor.IP, "netns", "exec",
                                            actor.PROBE_NS, actor.IP, "-j"])
                return json.dumps(shown if "show" in args else selected).encode()
            with patch.object(actor, "_run", side_effect=routes):
                actor._probe_redirect_route()
                for bad_show, bad_get in (([], base_selected),
                                          (base_shown, [{**base_selected[0], "dev": "lo"}]),
                                          ([{**base_shown[0], "dst": "default"}], base_selected),
                                          (base_shown, [{**base_selected[0], "prefsrc": "10.231.81.9"}])):
                    with self.subTest(show=bad_show, get=bad_get):
                        shown, selected = bad_show, bad_get
                        with self.assertRaisesRegex(actor.Refused,
                                                    "capture_runtime_probe_route_changed"):
                            actor._probe_redirect_route()

    @unittest.skipUnless(os.geteuid() == 0, "root failure receipt regression")
    def test_runtime_probe_failure_receipt_is_private_and_cannot_mask_error(self):
        with isolated_actor("aegis_auto_sink.py", "_test_probe_failure") as sink:
            with tempfile.TemporaryDirectory() as directory:
                receipt = pathlib.Path(directory) / "effect-test.json"
                original = OSError(errno.ENETUNREACH,
                                   "private-path-and-token-must-not-appear")
                def failed(_control, _receipt, _maximum, _release, phase, mark,
                           _socket_published):
                    mark("connect")
                    raise original
                with patch.object(sink, "_serve_probe_tcp", side_effect=failed):
                    with self.assertRaises(OSError) as raised:
                        sink.serve_probe_tcp(pathlib.Path(directory) / "effect.sock",
                                             receipt)
                self.assertIs(raised.exception, original)
                named = receipt.with_suffix(".failure.json")
                self.assertEqual(named.stat().st_mode & 0o777, 0o600)
                raw = named.read_bytes()
                self.assertLessEqual(len(raw), 256)
                self.assertNotIn(b"private-path-and-token", raw)
                recorded = json.loads(raw)
                self.assertEqual({key: value for key, value in recorded.items()
                                  if key != "line"}, {
                    "schema": "aegis_auto_probe_failure_v1",
                    "phase": "connect", "class": "os_error",
                    "errno": errno.ENETUNREACH, "source": "sink"})
                self.assertTrue(type(recorded["line"]) is int and
                                1 <= recorded["line"] <= 10000)
                phase = receipt.with_name(receipt.stem + ".phase-connect.json")
                self.assertEqual(phase.stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(phase.read_bytes()), {
                    "schema": "aegis_auto_probe_phase_v1", "source": "sink",
                    "phase": "connect"})
                self.assertNotIn(b"private-path-and-token", phase.read_bytes())
                with patch.object(sink, "_probe_phase_record",
                                  side_effect=OSError(errno.EACCES, "private-token")):
                    with patch.object(sink, "_serve_probe_tcp", side_effect=failed):
                        with self.assertRaises(OSError) as diagnostic_failure:
                            sink.serve_probe_tcp(pathlib.Path(directory) / "effect2.sock",
                                                 receipt.with_name("effect2.json"))
                self.assertIs(diagnostic_failure.exception, original)
                with self.assertRaises(FileExistsError):
                    sink._probe_failure_record(receipt, "connect", original)
                send_receipt = receipt.with_name("effect-send.json")
                sink._probe_failure_record(send_receipt, "send", original)
                self.assertEqual(json.loads(
                    send_receipt.with_suffix(".failure.json").read_bytes())["phase"],
                    "send")
                # A retained positive child receipt cannot replace the
                # parent's required PROBE_COMPLETE control reply.
                receipt.write_bytes(b'{"state":"PROBE_COMPLETE"}\n')
                parent, child = socket.socketpair(socket.AF_UNIX,
                                                  socket.SOCK_SEQPACKET)
                try:
                    child.close()
                    with self.assertRaisesRegex(capture.CaptureRefused,
                                                "echo_control_truncated"):
                        capture._control_recv(parent)
                finally:
                    parent.close()

    @unittest.skipUnless(os.geteuid() == 0 and hasattr(os, "fork"),
                         "root killed-child phase regression")
    def test_probe_phase_survives_kill_while_child_is_blocked(self):
        with isolated_actor("aegis_auto_sink.py", "_test_probe_killed") as sink:
            with tempfile.TemporaryDirectory() as directory:
                receipt = pathlib.Path(directory) / "effect-killed.json"
                ready_read, ready_write = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(ready_read)
                    try:
                        def blocked(_control, _receipt, _maximum, _release,
                                    _phase, mark, _socket_published):
                            mark("connect")
                            mark("send")
                            mark("echo")
                            os.write(ready_write, b"1")
                            select.select([], [], [], 30)
                        with patch.object(sink, "_serve_probe_tcp", side_effect=blocked):
                            sink.serve_probe_tcp(pathlib.Path(directory) / "effect.sock",
                                                 receipt)
                    finally:
                        os._exit(1)
                os.close(ready_write)
                try:
                    readable, _, _ = select.select([ready_read], [], [], 3)
                    self.assertTrue(readable)
                    self.assertEqual(os.read(ready_read, 1), b"1")
                    os.kill(pid, 15)
                    _, status = os.waitpid(pid, 0)
                    pid = None
                    self.assertTrue(os.WIFSIGNALED(status))
                    phases = ["startup", "connect", "send", "echo"]
                    for label in phases:
                        named = receipt.with_name(receipt.stem +
                                                  ".phase-" + label + ".json")
                        self.assertEqual(named.stat().st_mode & 0o777, 0o600)
                        raw = named.read_bytes()
                        self.assertLessEqual(len(raw), 128)
                        self.assertEqual(json.loads(raw)["phase"], label)
                    self.assertFalse(receipt.with_suffix(".failure.json").exists())
                finally:
                    os.close(ready_read)
                    if pid is not None:
                        os.kill(pid, 9)
                        os.waitpid(pid, 0)

    def test_completed_effect_waits_for_owner_release_and_retains_deadline(self):
        with isolated_actor("aegis_auto_sink.py", "_test_effect_sink") as sink:
            read_fd, write_fd = os.pipe()
            try:
                # A real child waits on the inherited read descriptor. Only
                # closing this owner's writer releases the completed actor.
                child = subprocess.Popen(
                    [sys.executable, "-I", "-B", "-c",
                     "import importlib.util,sys,time; "
                     "s=importlib.util.spec_from_file_location('sink',sys.argv[1]); "
                     "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                     "print('ready',flush=True); "
                     "m._effect_completion_lifetime(int(sys.argv[2]),time.monotonic()+3); "
                     "print('released',flush=True)",
                     str(SOURCE.with_name("aegis_auto_sink.py")), str(read_fd)],
                    pass_fds=(read_fd,), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                try:
                    self.assertTrue(select.select([child.stdout], [], [], 3)[0],
                                    "release child readiness deadline")
                    self.assertEqual(child.stdout.readline(), b"ready\n")
                    self.assertIsNone(child.poll())
                    self.assertFalse(select.select([child.stdout], [], [], 0)[0])
                    os.close(write_fd)
                    write_fd = -1
                    output, error = child.communicate(timeout=3)
                    self.assertEqual((child.returncode, output, error),
                                     (0, b"released\n", b""))
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=2)
            finally:
                os.close(read_fd)
                if write_fd >= 0:
                    os.close(write_fd)
            read_fd, write_fd = os.pipe()
            try:
                with self.assertRaisesRegex(sink.Refused,
                                            "effect_completion_lease_expired"):
                    sink._effect_completion_lifetime(read_fd, time.monotonic() - 1)
                os.write(write_fd, b"x")
                with self.assertRaisesRegex(sink.Refused,
                                            "effect_release_data_refused"):
                    sink._effect_completion_lifetime(read_fd, time.monotonic() + 1)
            finally:
                os.close(read_fd)
                os.close(write_fd)
            with tempfile.TemporaryFile() as regular:
                with self.assertRaisesRegex(sink.Refused, "invalid_effect_release_fd"):
                    sink._effect_completion_lifetime(regular.fileno(), time.monotonic() + 1)

    def test_effect_abort_closes_authority_without_successful_close(self):
        with isolated_actor("aegis_auto_capture_topology.py", "_test_effect_abort") as actor:
            # Abort owns descriptor lifetime; it must not send any wire frame.
            peer, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            read_fd, write_fd = os.pipe()
            lease = actor.CaptureEffectLease(peer, read_fd, {}, b"x" * 32)
            try:
                lease.abort()
                self.assertTrue(lease.closed)
                self.assertEqual(remote.recv(4096), b"")
                with self.assertRaises(OSError):
                    os.fstat(read_fd)
                with self.assertRaisesRegex(actor.Refused, "capture_effect_already_closed"):
                    lease.close()
            finally:
                peer.close()
                remote.close()
                os.close(write_fd)

    @unittest.skipUnless(sys.platform == "linux", "actor pipe2 lifecycle is Linux only")
    def test_effect_cleanup_failure_cannot_replace_primary_refusal(self):
        with isolated_actor("aegis_auto_capture_topology.py", "_test_effect_primary") as actor:
            read_fd, write_fd = os.pipe()
            primary = actor.Refused("private-primary")
            cleanup = actor.Refused("private-cleanup")
            output = io.StringIO()
            try:
                with patch.object(actor, "_verify_fixture"), \
                     patch.object(actor, "_peer", return_value=read_fd), \
                     patch.object(actor, "_start_children", side_effect=primary), \
                     patch.object(actor, "_cleanup_effect_children", side_effect=cleanup), \
                     contextlib.redirect_stderr(output):
                    with self.assertRaises(actor.Refused) as raised:
                        actor._effect(Mock(), {"op": "OPEN", "mode": "REDIRECT_PROBE_TCP",
                                              "effect_nonce": "a" * 64}, {})
                self.assertIs(raised.exception, primary)
                with self.assertRaises(OSError):
                    os.fstat(read_fd)
                self.assertNotIn("private-primary", output.getvalue())
                self.assertNotIn("private-cleanup", output.getvalue())
            finally:
                os.close(write_fd)

    @unittest.skipUnless(os.geteuid() == 0, "owned socket cleanup requires root")
    def test_effect_socket_cleanup_rejects_replacement_and_preserves_receipt(self):
        with isolated_actor("aegis_auto_capture_topology.py", "_test_effect_socket") as actor, \
                tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "effect.sock"
            receipt = pathlib.Path(directory) / "effect.json"
            receipt.write_bytes(b"retained-failure-evidence")
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as control:
                control.bind(str(path))
                path.chmod(0o600)
                named = path.stat()
                item = {"socket": str(path), "socket_dev": named.st_dev,
                        "socket_ino": named.st_ino}
                actor._unlink_child_socket(item)
                self.assertFalse(path.exists())
                actor._unlink_child_socket(item)
                path.write_bytes(b"foreign")
                with self.assertRaisesRegex(actor.Refused, "capture_child_socket_replaced"):
                    actor._unlink_child_socket(item)
                self.assertEqual(path.read_bytes(), b"foreign")
                self.assertEqual(receipt.read_bytes(), b"retained-failure-evidence")

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                         "protected child diagnostic requires Linux root")
    def test_topology_child_startup_diagnostic_requires_exact_owner_and_action(self):
        with isolated_actor("aegis_auto_capture_topology.py", "_test_startup_diag") as actor, \
                tempfile.TemporaryDirectory() as directory:
            runtime = pathlib.Path(directory)
            runtime.chmod(0o700)
            path = runtime / ("effect-" + "a" * 16 + "-1.startup-failure.json")
            expected = {"schema": "aegis_auto_sink_startup_failure_v1",
                        "action": "serve-probe-tcp", "phase": "before_socket",
                        "class": "os_error", "errno": 98, "source": "sink",
                        "line": 731, "pid": 1234}
            path.write_text(json.dumps(expected) + "\n")
            path.chmod(0o600)
            with patch.object(actor, "RUNTIME", runtime):
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    actor._child_startup_diagnostic(path, "serve-probe-tcp", 1234)
                self.assertIn('"action":"serve-probe-tcp"', output.getvalue())
                self.assertIn('"errno":98', output.getvalue())
                for changed in (dict(expected, action="serve-echo-tcp"),
                                dict(expected, pid=1235),
                                dict(expected, **{"private_token": "secret"})):
                    path.write_text(json.dumps(changed) + "\n")
                    with contextlib.redirect_stderr(output := io.StringIO()):
                        actor._child_startup_diagnostic(path, "serve-probe-tcp", 1234)
                    self.assertNotIn("aegis_auto_capture_child_startup:",
                                     output.getvalue())
                    self.assertNotIn("secret", output.getvalue())
                path.unlink()
                path.symlink_to(runtime / "foreign")
                with contextlib.redirect_stderr(output := io.StringIO()):
                    actor._child_startup_diagnostic(path, "serve-probe-tcp", 1234)
                self.assertNotIn("aegis_auto_capture_child_startup:",
                                 output.getvalue())

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                         "actual TCP listener reuse requires Linux root")
    def test_tcp_echo_listener_reuses_port_after_completed_exchange(self):
        with isolated_actor("aegis_auto_sink.py", "_test_repeated_tcp_echo") as sink, \
                tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            root.chmod(0o700)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserve:
                reserve.bind(("127.0.0.1", 0))
                port = reserve.getsockname()[1]
            address = SimpleNamespace(is_multicast=False, is_unspecified=False,
                                      is_loopback=False)
            with patch.object(sink.ipaddress, "IPv4Address", return_value=address), \
                 patch.object(sink, "_peer", return_value=(os.getpid(), 1, 2)):
                for index in range(2):
                    control = root / f"effect-{index}.sock"
                    receipt = root / f"effect-{index}.json"
                    failures = []
                    def run():
                        try:
                            sink.serve_echo_tcp(control, "127.0.0.1", port,
                                                receipt, 3.0)
                        except BaseException as error:
                            failures.append(error)
                    worker = threading.Thread(target=run, daemon=True)
                    worker.start()
                    deadline = time.monotonic() + 2
                    while not control.exists() and time.monotonic() < deadline:
                        time.sleep(0.005)
                    self.assertTrue(control.exists(), failures)
                    nonce = bytes([index + 1]) * 32
                    digest = hashlib.sha256(nonce).hexdigest()
                    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
                        peer.settimeout(2)
                        connect_control_when_listening(peer, control, deadline)
                        peer.send(json.dumps({"op": "ECHO_ARM", "sha256": digest}).encode())
                        ready = json.loads(peer.recv(4096))
                        self.assertEqual(ready["state"], "ECHO_READY")
                        with socket.create_connection(("127.0.0.1", port), timeout=2) as tcp:
                            tcp.sendall(nonce)
                            self.assertEqual(tcp.recv(32), nonce)
                        peer.send(json.dumps({"op": "ECHO_FINISH", "sha256": digest,
                                              "session": ready["session"]}).encode())
                        self.assertEqual(json.loads(peer.recv(4096))["state"],
                                         "ECHO_COMPLETE")
                    worker.join(2)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(failures, [])
                    self.assertEqual(json.loads(receipt.read_bytes())["received"], 1)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as foreign:
                    foreign.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    foreign.bind(("127.0.0.1", port))
                    foreign.listen(1)
                    with self.assertRaises(OSError) as raised:
                        sink.serve_echo_tcp(root / "foreign.sock", "127.0.0.1", port,
                                            root / "foreign.json", 3.0)
                    self.assertEqual(raised.exception.errno, errno.EADDRINUSE)

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                         "protected startup failure receipt requires Linux root")
    def test_sink_startup_failure_receipt_covers_os_and_unexpected_without_overwrite(self):
        with isolated_actor("aegis_auto_sink.py", "_test_startup_writer") as sink, \
                tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            root.chmod(0o700)
            for index, failure in enumerate((
                    OSError(errno.EADDRINUSE, "private-listener"),
                    RuntimeError("private-unexpected"))):
                receipt = root / f"effect-{index}.json"
                diagnostic = root / f"effect-{index}.startup-failure.json"
                argv = [str(SOURCE.with_name("aegis_auto_sink.py")),
                        "serve-echo-tcp", "--socket",
                        str(root / f"effect-{index}.sock"), "--receipt",
                        str(receipt), "--listen-ip", "10.231.82.2", "--port",
                        "18080", "--startup-failure-receipt", str(diagnostic)]
                with patch.object(sys, "argv", argv), \
                     patch.object(sink, "serve_echo_tcp", side_effect=failure), \
                     contextlib.redirect_stderr(io.StringIO()):
                    if isinstance(failure, RuntimeError):
                        with self.assertRaises(RuntimeError):
                            sink.main()
                    else:
                        self.assertEqual(sink.main(), 2)
                data = diagnostic.read_bytes()
                self.assertLessEqual(len(data), 256)
                self.assertEqual(diagnostic.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(b"private", data)
                value = json.loads(data)
                self.assertEqual(value["action"], "serve-echo-tcp")
                self.assertEqual(value["phase"], "before_socket")
                self.assertEqual(value["class"],
                                 "os_error" if index == 0 else "unexpected")
                self.assertEqual(value["errno"],
                                 errno.EADDRINUSE if index == 0 else 0)
                self.assertEqual(value["pid"], os.getpid())
                self.assertFalse(receipt.exists())
                # A second failure cannot replace the first durable receipt.
                with self.assertRaises(FileExistsError):
                    sink._startup_failure_record(diagnostic, "serve-echo-tcp", failure)
                self.assertEqual(diagnostic.read_bytes(), data)
            symlink = root / "effect-link.startup-failure.json"
            symlink.symlink_to(root / "foreign")
            with self.assertRaises(FileExistsError):
                sink._startup_failure_record(
                    symlink, "serve-probe-tcp", OSError(errno.EPERM, "private"))
            self.assertTrue(symlink.is_symlink())

    def test_topology_refusal_journal_omits_private_error_fields(self):
        source = SOURCE.with_name("aegis_auto_capture_topology.py")
        alias = "_test_aegis_auto_capture_topology"
        previous = sys.modules.get(alias)
        spec = importlib.util.spec_from_file_location(alias, source)
        actor = importlib.util.module_from_spec(spec)
        sys.modules[alias] = actor
        try:
            spec.loader.exec_module(actor)

            namespace = {}
            exec(compile("def need():\n"
                         "    raise OSError(13, 'private-key-value', '/secret/path')\n"
                         "def operation():\n"
                         "    need()\n", str(actor.SOURCE), "exec"), namespace)
            try:
                namespace["operation"]()
            except OSError as error:
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    actor._log_refusal(error)
            self.assertEqual(output.getvalue(),
                             "aegis_auto_capture_topology_refused:os_error "
                             "errno=13 source=capture_topology line=4\n")
            self.assertNotIn("private-key-value", output.getvalue())
            self.assertNotIn("/secret/path", output.getvalue())

            try:
                raise OSError(9999, "untrusted-private-value")
            except OSError as error:
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    actor._log_refusal(error)
            self.assertEqual(output.getvalue(),
                             "aegis_auto_capture_topology_refused:os_error "
                             "errno=0 source=unknown line=0\n")
            self.assertNotIn("untrusted-private-value", output.getvalue())

            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                actor._log_refusal(actor.Refused("private-refusal-value"))
            self.assertEqual(output.getvalue(),
                             "aegis_auto_capture_topology_refused:refused "
                             "errno=0 source=unknown line=0\n")
            self.assertNotIn("private-refusal-value", output.getvalue())
        finally:
            if previous is None:
                sys.modules.pop(alias, None)
            else:
                sys.modules[alias] = previous

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                         "actual proc namespace permission requires Linux root")
    def test_topology_peer_namespace_requires_declared_ptrace_capability(self):
        """Exercise the real kernel check used by topology._peer, not a mock."""
        root = SOURCE.parents[2]

        def declared_caps(name):
            source = (root / "packaging/systemd" / name).read_text()
            values = {}
            for line in source.splitlines():
                if line.startswith(("CapabilityBoundingSet=", "AmbientCapabilities=")):
                    key, value = line.split("=", 1)
                    values[key] = set(value.split())
            self.assertEqual(values["CapabilityBoundingSet"],
                             values["AmbientCapabilities"])
            return values["CapabilityBoundingSet"]

        old_topology = {"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_ADMIN"}
        topology_caps = declared_caps("aegis-auto-capture-topology.service")
        guardian_caps = declared_caps("aegis-auto-guardian.service")
        self.assertEqual(topology_caps, old_topology | {"CAP_SYS_PTRACE"})
        self.assertEqual(guardian_caps,
                         {"CAP_DAC_READ_SEARCH", "CAP_NET_ADMIN",
                          "CAP_NET_RAW", "CAP_SYS_PTRACE"})

        numbers = {"CAP_DAC_READ_SEARCH": 2,
                   "CAP_NET_ADMIN": 12, "CAP_NET_RAW": 13,
                   "CAP_SYS_PTRACE": 19, "CAP_SYS_ADMIN": 21}
        mask = lambda names: sum(1 << numbers[name] for name in names)
        available = int(next(line.split("\t", 1)[1] for line in
                             pathlib.Path("/proc/self/status").read_text().splitlines()
                             if line.startswith("CapPrm:")), 16)
        required = mask(topology_caps | guardian_caps)
        if available & required != required:
            self.skipTest("kernel capability control unavailable in this Linux runner")

        class Header(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

        class Data(ctypes.Structure):
            _fields_ = [("effective", ctypes.c_uint32),
                        ("permitted", ctypes.c_uint32),
                        ("inheritable", ctypes.c_uint32)]

        libc = ctypes.CDLL(None, use_errno=True)

        def set_caps(names):
            bits = mask(names)
            header = Header(0x20080522, 0)
            data = (Data * 2)()
            for index in range(2):
                data[index].effective = (bits >> (index * 32)) & 0xffffffff
                data[index].permitted = data[index].effective
            if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
                raise OSError(ctypes.get_errno(), "capset")

        ready_read, ready_write = os.pipe()
        release_read, release_write = os.pipe()
        target = os.fork()
        if target == 0:
            try:
                os.close(ready_read)
                os.close(release_write)
                set_caps(guardian_caps)
                if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
                    raise OSError(ctypes.get_errno(), "prctl")
                os.write(ready_write, b"R")
                os.read(release_read, 1)
                os._exit(0)
            except BaseException:
                os._exit(2)
        os.close(ready_write)
        os.close(release_read)
        try:
            readable, _, _ = select.select([ready_read], [], [], 3.0)
            self.assertTrue(readable, "guardian-like child readiness timed out")
            self.assertEqual(os.read(ready_read, 1), b"R")

            def namespace_errno(caps):
                result_read, result_write = os.pipe()
                caller = os.fork()
                if caller == 0:
                    try:
                        os.close(result_read)
                        os.close(release_write)
                        set_caps(caps)
                        try:
                            os.stat(f"/proc/{target}/ns/net")
                            result = 0
                        except OSError as error:
                            result = error.errno
                        os.write(result_write, str(result).encode("ascii"))
                        os._exit(0)
                    except BaseException:
                        os._exit(2)
                os.close(result_write)
                try:
                    readable, _, _ = select.select([result_read], [], [], 3.0)
                    self.assertTrue(readable, "namespace control timed out")
                    value = os.read(result_read, 16)
                    self.assertTrue(value, "namespace control failed before stat")
                    return int(value)
                finally:
                    os.close(result_read)
                    deadline = time.monotonic() + 3.0
                    while time.monotonic() < deadline:
                        done, _ = os.waitpid(caller, os.WNOHANG)
                        if done:
                            break
                        time.sleep(0.01)
                    else:
                        os.kill(caller, 9)
                        os.waitpid(caller, 0)
                        self.fail("namespace control child did not exit")

            self.assertEqual(namespace_errno(old_topology), errno.EACCES)
            self.assertEqual(namespace_errno(topology_caps), 0)
        finally:
            os.close(ready_read)
            try:
                os.write(release_write, b"X")
            except BrokenPipeError:
                pass
            os.close(release_write)
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                done, _ = os.waitpid(target, os.WNOHANG)
                if done:
                    break
                time.sleep(0.01)
            else:
                os.kill(target, 9)
                os.waitpid(target, 0)
                self.fail("guardian-like child did not exit")

    def test_runtime_redirect_probe_uses_one_held_actor_and_exact_configured_iif(self):
        effect = Mock(facts={
            "mode": "REDIRECT_PROBE_TCP",
            "host_probe_ifindex": 9,
            "children": [{"action": "serve-probe-tcp", "source": "/source",
                          "pid": 100, "netns_ino": 77, "socket": "/run/probe.sock"}]})
        runtime = Mock(mode="wide-redirect-safe",
                       redirect_ingress_ifname="aegisacp0",
                       redirect_listen_port=15080)
        topology = Mock(H_PROBE="aegisacp0", SINK_SOURCE="/source")
        with patch.object(endpoint.socket, "if_nametoindex", return_value=9), \
             patch.object(endpoint.os, "stat", return_value=SimpleNamespace(st_ino=77)):
            probe = endpoint.admit_runtime_redirect_probe(effect, runtime,
                                                           topology)
        self.assertIsInstance(probe, capture.RuntimeRedirectEndpoint)
        self.assertEqual(probe.probe_pid, 100)
        self.assertFalse(hasattr(probe, "sink_pid"))
        topology.get_fixture.assert_not_called()
        runtime.redirect_ingress_ifname = "eth0"
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    "runtime_redirect_ingress_peer_not_configured"):
            endpoint.admit_runtime_redirect_probe(effect, runtime, topology)

    def test_relay_auth_lineage_binds_token_and_inner_authority(self):
        credential = Mock(path=pathlib.Path("/etc/aegis/client/ca.pem"),
                          sha256="a" * 64)
        legacy = tomllib.loads(
            '[relay]\nserver="192.0.2.4:443"\n'
            'server_name="relay.example"\nauth_token="' + "A" * 32 + '"\n')["relay"]
        reformatted = tomllib.loads(
            '[relay]\nauth_token = "' + "A" * 32 + '"\n'
            'server_name = "relay.example"\nserver = "192.0.2.4:443"\n')["relay"]
        original = endpoint._credential_lineage(legacy, (credential,))
        self.assertEqual(original,
                         endpoint._credential_lineage(reformatted,
                                                      (credential,)))
        changed_token = dict(legacy, auth_token="B" * 32)
        self.assertNotEqual(original,
                            endpoint._credential_lineage(changed_token,
                                                         (credential,)))
        inner = {"server": "192.0.2.4:443", "server_name": "relay.example",
                 "auth_token": "", "inner_tls": {"server_name": "device.example"}}
        baseline = endpoint._credential_lineage(inner, (credential,))
        changed_inner = dict(inner, inner_tls={"server_name": "foreign.example"})
        self.assertNotEqual(baseline,
                            endpoint._credential_lineage(changed_inner,
                                                         (credential,)))

    @unittest.skipUnless(os.geteuid() == 0, "protected relay receipt requires root")
    def test_installed_device_relay_holds_every_identity_and_rejects_profile_mix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            root.chmod(0o700)
            receipt = root / "relay-install.json"
            facts = {
                "schema": "aegis_auto_capture_relay_install_v1",
                "head": "a" * 40,
                "server_source_closure_sha256": "b" * 64,
                "unit": "aegis-auto-capture-relay-" + "c" * 32 + ".service",
                "auth_profile": "device_inner_tls",
                "listen_ipv4": "10.231.80.2", "listen_port": 443,
            }
            files = ("server_binary", "config", "cert", "key", "outer_ca",
                     "inner_cert", "inner_key", "client_ca", "device_cert",
                     "device_key", "device_qa_key")
            for name in files:
                path = root / name
                raw = (name + "-fixed-test-bytes").encode()
                path.write_bytes(raw)
                path.chmod(0o500 if name == "server_binary" else 0o600)
                facts[name + "_path"] = str(path)
                facts[name + "_sha256"] = hashlib.sha256(raw).hexdigest()

            def write(value):
                receipt.write_text(json.dumps(value))
                receipt.chmod(0o600)

            with patch.object(endpoint, "RELAY_INSTALL", receipt), \
                 patch.object(capture, "_trusted_ancestors"):
                write(facts)
                self.assertEqual(endpoint._relay_install(), facts)
                for changed in (
                    dict(facts, auth_token_sha256="d" * 64),
                    {key: value for key, value in facts.items()
                     if key != "device_key_sha256"},
                    {key: value for key, value in facts.items()
                     if key != "device_qa_key_sha256"},
                    dict(facts, device_key_sha256="not-a-sha256"),
                    dict(facts, device_qa_key_sha256="not-a-sha256"),
                    dict(facts, device_qa_key_path=facts["device_key_path"]),
                    dict(facts, auth_profile="legacy_shared_token"),
                ):
                    write(changed)
                    with self.assertRaises(capture.CaptureRefused):
                        endpoint._relay_install()
                write(facts)
                pathlib.Path(facts["device_key_path"]).write_bytes(b"replacement-key")
                with self.assertRaises(capture.CaptureRefused):
                    endpoint._relay_install()
                pathlib.Path(facts["device_key_path"]).write_bytes(
                    b"device_key-fixed-test-bytes")
                pathlib.Path(facts["device_qa_key_path"]).write_bytes(
                    b"replacement-qa-key")
                with self.assertRaises(capture.CaptureRefused):
                    endpoint._relay_install()

    @unittest.skipUnless(os.geteuid() == 0, "protected endpoint receipt requires root")
    def test_device_endpoint_schema_requires_separate_qa_key(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = pathlib.Path(directory) / "endpoint.json"
            unit = "aegis-auto@" + "a" * 64 + ".service"
            server = {name + suffix: ("/fixture/" + name if suffix == "_path"
                                      else "d" * 64)
                      for name in ("inner_cert", "inner_key", "client_ca",
                                   "device_cert", "device_key")
                      for suffix in ("_path", "_sha256")}
            server.update({
                "pid": 1, "netns_ino": 1, "cgroup": "/system.slice/" + unit,
                "argv": ["/fixture/server", "--config", "/fixture/server.toml"],
                "exe_path": "/fixture/server", "exe_sha256": "d" * 64,
                "config_path": "/fixture/server.toml", "config_sha256": "d" * 64,
                "cert_path": "/fixture/outer.pem", "cert_sha256": "d" * 64,
                "key_path": "/fixture/outer.key", "key_sha256": "d" * 64,
                "outer_ca_path": "/fixture/outer-ca.pem",
                "outer_ca_sha256": "d" * 64,
                "auth_profile": "device_inner_tls",
                "listen_ipv4": "10.231.80.2", "listen_port": 443,
            })
            facts = {
                "schema": "aegis_auto_capture_endpoint_v1", "boot_id": "boot",
                "root_netns_ino": 1, "mode": "full-wide-tun",
                "private_unit": unit, "installed_generation": "b" * 64,
                "installed_manifest_sha256": "c" * 64,
                "server": server, "sink": {},
            }
            receipt.write_text(json.dumps(facts))
            receipt.chmod(0o600)
            with patch.object(capture, "_trusted_ancestors"):
                with self.assertRaisesRegex(capture.CaptureRefused,
                                            "endpoint_server_schema_invalid"):
                    capture.admit_endpoint_receipt(
                        receipt_path=receipt, unit=unit, mode="full-wide-tun",
                        boot_id="boot", netns_ino=1,
                        installed_generation="b" * 64,
                        manifest="c" * 64, effect_lease=Mock())

    @unittest.skipUnless(sys.platform == "linux", "actual AF_PACKET requires Linux")
    def test_packet_bind_uses_host_order_ethertype(self):
        with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM,
                           socket.htons(0x86dd)) as packet:
            packet.bind(("lo", 0x86dd))
            self.assertEqual(packet.getsockname()[1], 0x86dd)

    def test_configured_pool_binds_ordered_failover_and_masque_names(self):
        relay = {"server": "192.0.2.4:443", "server_name": "first.example",
                 "masque_server": "[2001:db8::4]:443",
                 "masque_server_name": "h3.example",
                 "endpoints": [
                     {"server": "192.0.2.4:443",
                      "server_name": "first.example"},
                     {"server": "192.0.2.5:443",
                      "server_name": "backup.example",
                      "masque_server": "[2001:db8::5]:443",
                      "masque_server_name": "backup-h3.example"}]}
        self.assertEqual(endpoint._configured_relay_pool(relay), (
            ("ordinary", "192.0.2.4:443", "first.example"),
            ("masque", "[2001:db8::4]:443", "h3.example"),
            ("ordinary", "192.0.2.5:443", "backup.example"),
            ("masque", "[2001:db8::5]:443", "backup-h3.example")))
        relay["endpoints"][0]["server"] = "192.0.2.9:443"
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    "runtime_relay_pool_primary_changed"):
            endpoint._configured_relay_pool(relay)

    def test_masque_pool_authority_matches_client_fallback_rules(self):
        relay = {"server": "192.0.2.4:443", "server_name": "primary.example",
                 "masque_server": "[2001:db8::4]:443",
                 "masque_server_name": "", "endpoints": [
                     {"server": "192.0.2.4:443",
                      "server_name": "primary.example"},
                     {"server": "192.0.2.5:443",
                      "server_name": "backup.example"},
                     {"server": "192.0.2.6:443",
                      "server_name": "private.example",
                      "masque_server": "[2001:db8::6]:443"}]}
        self.assertEqual(endpoint._configured_relay_pool(relay), (
            ("ordinary", "192.0.2.4:443", "primary.example"),
            ("masque", "[2001:db8::4]:443", "primary.example"),
            ("ordinary", "192.0.2.5:443", "backup.example"),
            ("masque", "[2001:db8::4]:443", "primary.example"),
            ("ordinary", "192.0.2.6:443", "private.example"),
            ("masque", "[2001:db8::6]:443", "private.example")))

    def test_host_route_queries_current_namespace_without_nsenter(self):
        with patch.object(capture, "_run", return_value=b'[{"dev":"eth0"}]') as run:
            self.assertEqual(endpoint._host_route("-4", "192.0.2.4", 0.5),
                             {"dev": "eth0"})
        self.assertEqual(run.call_args.args[0],
                         [str(capture.IP), "-j", "-4", "route", "get",
                          "192.0.2.4"])
        self.assertEqual(run.call_args.kwargs["timeout"], 0.5)

    def test_failed_runtime_endpoint_enter_releases_held_identity(self):
        lease = endpoint.RuntimeEndpointLease(
            -1, Mock(), (), "aegis-auto@" + "a" * 64 + ".service",
            "full-wide-tun", "n", "g",
            (("ordinary", "192.0.2.4:443", "relay.example"),), "a" * 64,
            "legacy_shared_token", "a" * 64, "b" * 64)
        with patch.object(lease, "revalidate",
                          side_effect=capture.CaptureRefused("changed")), \
             patch.object(lease, "close") as close:
            with self.assertRaisesRegex(capture.CaptureRefused, "changed"):
                with lease:
                    self.fail("changed endpoint admitted")
        close.assert_called_once_with()

    def test_malformed_existing_qa_receipt_is_not_treated_as_absent(self):
        with tempfile.TemporaryDirectory() as root:
            relay = pathlib.Path(root) / "relay-install.json"
            endpoint_receipt = pathlib.Path(root) / "endpoint.json"
            with patch.object(endpoint, "RELAY_INSTALL", relay), \
                 patch.object(endpoint, "RECEIPT", endpoint_receipt):
                self.assertFalse(endpoint.qa_relay_receipt_present())
                relay.symlink_to(pathlib.Path(root) / "missing")
                self.assertTrue(endpoint.qa_relay_receipt_present())
                relay.unlink()
                endpoint_receipt.write_text("malformed", encoding="ascii")
                self.assertTrue(endpoint.qa_relay_receipt_present())

    def test_runtime_endpoint_admits_current_preprojection_recipe_only_when_sealed(self):
        config = (b'mode = "relay"\n[relay]\nserver = "192.0.2.4:443"\n'
                  b'server_name = "relay.example"\nauth_token = "' +
                  b'A' * 32 + b'"\n')
        recipe = {"schema": 2,
                  "context": {"mode": "FullWideTun",
                              "logical_final_base": "/etc/aegis/client"},
                  "config_leaf": "aegis.toml",
                  "config": base64.b64encode(config).decode(),
                  "references": []}
        recipe_raw = json.dumps(recipe).encode()
        header = {"render_recipe": "accepted/render-recipe.json",
                  "leaves": {"accepted/render-recipe.json":
                             hashlib.sha256(recipe_raw).hexdigest()},
                  "transaction_nonce": "n", "planned_generation": "g",
                  "mode": "full-wide-tun",
                  "config_root": "/etc/aegis/client",
                  "runtime_binding": {"identity": {"uid": 0, "gid": 0}}}
        held_config = Mock()
        def staged(_fd, name, _maximum):
            return json.dumps(header).encode() if name == "header.json" else recipe_raw

        with tempfile.TemporaryFile() as stage, \
             patch.object(endpoint, "_stage_bytes", side_effect=staged), \
             patch.object(endpoint, "_runtime_file", return_value=held_config), \
             patch.object(endpoint.RuntimeEndpointLease, "revalidate"):
            with endpoint.admit_runtime_endpoint(
                    stage_fd=stage.fileno(),
                    unit="aegis-auto@" + "a" * 64 + ".service",
                    mode="full-wide-tun", transaction_nonce="n",
                    planned_generation="g") as admitted:
                self.assertEqual(admitted.configured_relay_pool,
                                 (("ordinary", "192.0.2.4:443",
                                   "relay.example"),
                                  ("masque", "192.0.2.4:443",
                                   "relay.example")))
                self.assertEqual(admitted.auth_profile, "legacy_shared_token")
        held_config.close.assert_called_once_with()
        header["leaves"]["accepted/render-recipe.json"] = "0" * 64
        with tempfile.TemporaryFile() as stage, \
             patch.object(endpoint, "_stage_bytes", side_effect=staged):
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        "runtime_endpoint_recipe_unsealed"):
                endpoint.admit_runtime_endpoint(
                    stage_fd=stage.fileno(),
                    unit="aegis-auto@" + "a" * 64 + ".service",
                    mode="full-wide-tun", transaction_nonce="n",
                    planned_generation="g")

    @unittest.skipUnless(os.geteuid() == 0, "root file owner regression")
    def test_runtime_credentials_use_sealed_uid_gid_and_file_bytes(self):
        uid, gid = 23456, 23457
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            paths = {name: root / ("ca.pem" if name == "bundle-ca.pem" else name) for name in
                     ("aegis.toml", "bundle-ca.pem", "reference-ca.pem",
                      "device-cert.pem", "device-key.pem", "bridge-key.pem")}
            material = {"bundle-ca.pem": b"bundle-ca\n",
                        "reference-ca.pem": b"reference-ca\n",
                        "device-cert.pem": b"device-cert\n",
                        "device-key.pem": b"device-key\n",
                        "bridge-key.pem": b"bridge-key\n"}
            for name, raw in material.items():
                path = paths[name]
                path.write_bytes(raw)
                private = name in ("device-key.pem", "bridge-key.pem")
                os.chown(path, uid if private else 0, gid)
                path.chmod(0o600 if private else 0o640)
            config_bytes = (b'[relay]\nserver="192.0.2.4:443"\n'
                            b'server_name="relay.example"\n'
                            + f'ca_cert="{paths["bundle-ca.pem"]}"\n'.encode()
                            + b'[relay.inner_tls]\n'
                            + f'server_ca="{paths["reference-ca.pem"]}"\n'.encode()
                            + f'cert="{paths["device-cert.pem"]}"\n'.encode()
                            + f'key="{paths["device-key.pem"]}"\n'.encode()
                            + b'[relay.https_bridge]\n'
                            + f'credential_file="{paths["bridge-key.pem"]}"\n'.encode())
            config_path = paths["aegis.toml"]
            config_path.write_bytes(config_bytes)
            os.chown(config_path, 0, gid)
            config_path.chmod(0o640)
            recipe = {"schema": 2,
                      "context": {"mode": "FullWideTun",
                                  "logical_final_base": str(root)},
                      "config_leaf": config_path.name,
                      "config": base64.b64encode(config_bytes).decode(),
                      "references": [
                          {"original": name, "final_path": str(paths[name]),
                           "bytes": base64.b64encode(material[name]).decode()}
                          for name in ("reference-ca.pem", "device-cert.pem",
                                       "device-key.pem", "bridge-key.pem")]}
            recipe_raw = json.dumps(recipe).encode()
            header = {"render_recipe": "accepted/render-recipe.json",
                      "leaves": {"accepted/render-recipe.json":
                                 hashlib.sha256(recipe_raw).hexdigest(),
                                 endpoint.BUNDLE_CA_LEAF:
                                 hashlib.sha256(material["bundle-ca.pem"]).hexdigest()},
                      "transaction_nonce": "n", "planned_generation": "g",
                      "mode": "full-wide-tun", "config_root": str(root),
                      "runtime_binding": {"identity": {"uid": uid, "gid": gid}},
                      "phase": "metadata", "capture_started": True,
                      "pending": None, "unit_pending": None}

            def staged(_fd, name, _maximum):
                return {"header.json": json.dumps(header).encode(),
                        "accepted/render-recipe.json": recipe_raw,
                        endpoint.BUNDLE_CA_LEAF: material["bundle-ca.pem"]}[name]

            def admit():
                stage = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    return endpoint.admit_runtime_endpoint(
                        stage_fd=stage,
                        unit="aegis-auto@" + "a" * 64 + ".service",
                        mode="full-wide-tun", transaction_nonce="n",
                        planned_generation="g")
                finally:
                    os.close(stage)

            with patch.object(endpoint, "_stage_bytes", side_effect=staged), \
                 patch.object(capture, "_trusted_ancestors"), \
                 patch.object(endpoint, "_host_route", return_value={"dev": "eth0"}):
                with admit() as lease:
                    self.assertEqual(lease.auth_profile, "device_inner_tls")
                    self.assertEqual(len(lease.credentials), 5)
                    self.assertEqual([item.sha256 for item in lease.credentials],
                                     [hashlib.sha256(material[name]).hexdigest()
                                      for name in ("bundle-ca.pem", "reference-ca.pem",
                                                   "device-cert.pem", "device-key.pem",
                                                   "bridge-key.pem")])
                formatted = b"# formatter\n" + config_bytes
                config_path.write_bytes(formatted)
                with admit() as lease:
                    self.assertEqual(lease.config.sha256,
                                     hashlib.sha256(formatted).hexdigest())
                header["phase"] = "finalized"
                with self.assertRaisesRegex(capture.CaptureRefused,
                                            "runtime_published_content_changed"):
                    admit()
                header["phase"] = "metadata"
                for name, owner, group, mode, content, reason in (
                        ("device-cert.pem", uid, gid, 0o640, material["device-cert.pem"],
                         "runtime_published_file_untrusted"),
                        ("reference-ca.pem", 0, gid + 1, 0o640,
                         material["reference-ca.pem"], "runtime_published_file_untrusted"),
                        ("device-key.pem", uid, gid, 0o640, material["device-key.pem"],
                         "runtime_published_file_untrusted"),
                        ("bridge-key.pem", uid, gid, 0o640, material["bridge-key.pem"],
                         "runtime_published_file_untrusted"),
                        ("bridge-key.pem", uid, gid, 0o600, b"changed-key\n",
                         "runtime_published_content_changed"),
                        ("bundle-ca.pem", 0, gid, 0o640, b"changed-ca\n",
                         "runtime_published_content_changed")):
                    with self.subTest(name=name, reason=reason):
                        path = paths[name]
                        # Fixture mutation uses ownership authority; the
                        # endpoint admission below still needs read-only DAC
                        # access to service-owned 0600 credentials.
                        os.chown(path, 0, gid)
                        path.write_bytes(content)
                        os.chown(path, owner, group)
                        path.chmod(mode)
                        with self.assertRaisesRegex(capture.CaptureRefused, reason):
                            admit()
                        os.chown(path, 0, gid)
                        path.write_bytes(material[name])
                        private = name in ("device-key.pem", "bridge-key.pem")
                        os.chown(path, uid if private else 0, gid)
                        path.chmod(0o600 if private else 0o640)

    def test_runtime_recipe_rejects_noncanonical_config_bytes(self):
        good = base64.b64encode(b"[relay]\nserver = '192.0.2.4:443'\n").decode()
        self.assertEqual(endpoint._decode_recipe_config(good),
                         b"[relay]\nserver = '192.0.2.4:443'\n")
        for bad in (good + "=", "!!!!", "", base64.b64encode(b"x" *
                    ((4 << 20) + 1)).decode()):
            with self.subTest(bad_len=len(bad)), \
                 self.assertRaises(capture.CaptureRefused):
                endpoint._decode_recipe_config(bad)

    def test_formatter_admission_pins_actual_bytes_and_full_toml(self):
        original = b"[relay]\nserver='192.0.2.4:443'\n[ingress.wide]\nenabled=true\n"
        formatted = b'# formatter\n[relay]\nserver = "192.0.2.4:443"\n\n[ingress.wide]\nenabled = true\n'
        with tempfile.TemporaryDirectory() as root, \
             patch.object(capture, "_trusted_ancestors"):
            path = pathlib.Path(root) / "aegis.toml"
            path.write_bytes(formatted)
            path.chmod(0o600)
            digest = hashlib.sha256(original).hexdigest()
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        "runtime_published_content_changed"):
                endpoint._runtime_file(path, 4096, os.geteuid(), os.getegid(),
                                       0o600, digest)
            held = endpoint._runtime_file(path, 4096, os.geteuid(), os.getegid(),
                                          0o600, digest, semantic_config=original)
            try:
                self.assertEqual(held.sha256, hashlib.sha256(formatted).hexdigest())
                held.revalidate()
                path.write_bytes(formatted + b"future = true\n")
                with self.assertRaises(capture.CaptureRefused):
                    held.revalidate()
                with self.assertRaisesRegex(capture.CaptureRefused,
                                            "runtime_config_semantics_changed"):
                    endpoint._runtime_file(path, 4096, os.geteuid(), os.getegid(),
                                           0o600, digest, semantic_config=original)
            finally:
                held.close()
            # A changed non-relay table and malformed UTF-8 cannot hide behind
            # a still-valid relay endpoint or a matching subset of TOML.
            for changed in (formatted.replace(b"true", b"false"), b"\xff"):
                path.write_bytes(changed)
                with self.assertRaisesRegex(capture.CaptureRefused,
                                            "runtime_config_semantics_changed"):
                    endpoint._runtime_file(path, 4096, os.geteuid(), os.getegid(),
                                           0o600, digest, semantic_config=original)

    def test_formatter_semantics_allowed_only_in_nonpending_captured_metadata(self):
        config = b"[ingress.wide]\nenabled=true\n"
        recipe = {"schema": 2, "context": {"mode": "FullWideTun",
                  "logical_final_base": "/etc/aegis/client"},
                  "config_leaf": "aegis.toml",
                  "config": base64.b64encode(config).decode()}
        raw = json.dumps(recipe).encode()
        header = {"render_recipe": "accepted/render-recipe.json",
                  "leaves": {"accepted/render-recipe.json": hashlib.sha256(raw).hexdigest()},
                  "transaction_nonce": "n", "planned_generation": "g",
                  "mode": "full-wide-tun", "config_root": "/etc/aegis/client",
                  "runtime_binding": {"identity": {"uid": 0, "gid": 0}},
                  "phase": "metadata", "capture_started": True,
                  "pending": None, "unit_pending": None}
        def staged(_fd, name, _maximum):
            return json.dumps(header).encode() if name == "header.json" else raw
        cases = ({}, {"phase": "finalized"}, {"phase": "prepared"},
                 {"capture_started": False}, {"pending": {}}, {"unit_pending": {}})
        for changes in cases:
            with self.subTest(changes=changes):
                current = dict(header)
                header.update(changes)
                with patch.object(endpoint, "_stage_bytes", side_effect=staged), \
                     patch.object(endpoint, "_runtime_file") as admit:
                    endpoint._admit_rendered_config(5, "full-wide-tun", "n", "g")
                    self.assertEqual(admit.call_args.kwargs["semantic_config"],
                                     None if changes else config)
                header = current

    def test_scoped_redirect_requires_explicit_sealed_interface_and_listener(self):
        recipe = {"context": {"wide_interface": "eth0"}}
        base = (b"[ingress]\nprimary='wide'\n[ingress.wide]\nenabled=true\n"
                b"platform_backend='linux_redirect'\nrollout_profile='prerouting_scoped'\n"
                b"prerouting_interface='eth0'\nlisten='192.0.2.1:15080'\n")
        interface = [{"ifname": "eth0", "ifindex": 7,
                      "addr_info": [{"family": "inet", "local": "192.0.2.1"}]}]
        with patch.object(socket, "if_nametoindex", return_value=7), \
             patch.object(capture, "_json", return_value=interface):
            admitted = endpoint._scoped_redirect_values(recipe, base)
            self.assertEqual(admitted[:4], ("eth0", 7, "192.0.2.1", 15080))
            self.assertEqual(admitted, endpoint._scoped_redirect_values(recipe, b"# fmt\n" + base))
            for changed in (base.replace(b"192.0.2.1", b"127.0.0.1"),
                            base.replace(b"192.0.2.1", b"0.0.0.0"),
                            base.replace(b"192.0.2.1", b"224.0.0.1"),
                            base.replace(b"15080", b"15081"),
                            base.replace(b"interface='eth0'", b"interface='eth1'")):
                with self.subTest(changed=changed), self.assertRaises(capture.CaptureRefused):
                    endpoint._scoped_redirect_values(recipe, changed)
            local = base.replace(b"prerouting_scoped", b"output_only_safe").replace(
                b"192.0.2.1", b"127.0.0.1")
            self.assertIsNone(endpoint._scoped_redirect_values(recipe, local))
            interface[0]["addr_info"][0]["secondary"] = True
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        "scoped_redirect_primary_address_changed"):
                endpoint._scoped_redirect_values(recipe, base)

    def test_failed_endpoint_enter_releases_held_identity(self):
        lease = capture.EndpointLease(None, None, None, None, None, (),
                                      None, None, -1, -1, None, {}, Mock())
        with patch.object(lease, "revalidate",
                          side_effect=capture.CaptureRefused("changed")), \
             patch.object(lease, "close") as close:
            with self.assertRaisesRegex(capture.CaptureRefused, "changed"):
                with lease:
                    self.fail("changed endpoint admitted")
        close.assert_called_once_with()

    def test_capture_accepts_only_private_unique_instance_identity(self):
        unit = "aegis-auto@" + "a" * 64 + ".service"
        self.assertEqual(capture._cgroup(unit), "/system.slice/" + unit)
        for foreign in ("aegis-client.service", "aegis-auto@fixture.service",
                        "aegis-auto@" + "a" * 63 + ".service"):
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        "foreign_auto_unit"):
                capture._cgroup(foreign)

    def test_redirect_requires_actual_ingress_jump_and_tproxy_handles(self):
        nft = {"nftables": [
            {"metainfo": {"version": "1.0.9"}},
            {"table": {"family": "ip", "name": "aegis_wide_tproxy", "handle": 3}},
            {"chain": {"family": "ip", "table": "aegis_wide_tproxy",
                       "name": "prerouting", "hook": "prerouting", "prio": -150,
                       "policy": "accept", "handle": 1}},
            {"chain": {"family": "ip", "table": "aegis_wide_tproxy",
                       "name": "AEGIS_WIDE_TPROXY", "handle": 2}},
            {"rule": {"family": "ip", "table": "aegis_wide_tproxy",
                      "chain": "prerouting", "handle": 7,
                      "comment": "aegis:prerouting:tcp:AEGIS_WIDE_TPROXY",
                      "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}},
                               {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
                               {"jump": {"target": "AEGIS_WIDE_TPROXY"}}]}},
            {"rule": {"family": "ip", "table": "aegis_wide_tproxy",
                      "chain": "AEGIS_WIDE_TPROXY", "handle": 3,
                      "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
                               {"return": None}]}},
            {"rule": {"family": "ip", "table": "aegis_wide_tproxy",
                      "chain": "AEGIS_WIDE_TPROXY", "handle": 4,
                      "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 15080}},
                               {"return": None}]}},
            {"rule": {"family": "ip", "table": "aegis_wide_tproxy",
                      "chain": "AEGIS_WIDE_TPROXY", "handle": 5,
                      "expr": [{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
                               {"match": {"op": "==", "left": {"socket": {"key": "transparent"}}, "right": 1}},
                               {"mangle": {"key": {"meta": {"key": "mark"}}, "value": 1}},
                               {"return": None}]}},
            {"rule": {"family": "ip", "table": "aegis_wide_tproxy",
                      "chain": "AEGIS_WIDE_TPROXY", "handle": 8,
                      "expr": [{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
                               {"tproxy": {"port": 15080}},
                               {"mangle": {"key": {"meta": {"key": "mark"}}, "value": 1}},
                               {"accept": None}]}}
        ]}
        with patch.object(capture, "_run",
                          side_effect=lambda _argv: json.dumps(nft).encode()):
            original = capture._tproxy_policy("eth0", 15080)
            self.assertEqual(original[1:], (7, 8))
            nft["nftables"][-1]["rule"]["handle"] = 9
            self.assertNotEqual(capture._tproxy_policy("eth0", 15080), original)
            nft["nftables"][-1]["rule"]["expr"][1]["tproxy"]["port"] = 15081
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        "redirect_tproxy_not_admitted"):
                capture._tproxy_policy("eth0", 15080)
            nft["nftables"][-1]["rule"]["expr"][1]["tproxy"]["port"] = 15080
            nft["nftables"].insert(4, {"rule": {"chain": "prerouting", "expr": [{"accept": None}]}})
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        "redirect_nft_extra_or_missing_objects"):
                capture._tproxy_policy("eth0", 15080)

    def test_redirect_requires_owned_scoped_live_policy_and_exact_invocation(self):
        policy = {"policy_sha256": "a" * 64, "input_gate_chain_handle": 1,
                  "input_allow_handle": 3, "input_drop_handle": 4,
                  "prerouting_chain_handle": 2, "redirect_handle": 5,
                  "private_unit": "aegis-auto@" + "b" * 64 + ".service",
                  "invocation_id": "c" * 32, "interface": "eth0", "ifindex": 7,
                  "listen_ipv4": "192.0.2.1", "listen_port": 15080,
                  "conntrack_mark": 0x12345678}
        verify = Mock(return_value=dict(policy))
        args = {"scoped_policy": policy, "scoped_verify": verify,
                "unit_name": policy["private_unit"],
                "invocation_id": policy["invocation_id"]}
        with patch.object(socket, "if_nametoindex", return_value=7):
            self.assertEqual(capture._redirect_policy("eth0", 15080, **args),
                             ("a" * 64, 2, 5))
            verify.assert_called_once_with()
            # No old global TPROXY policy or a receipt-only dict can stand in
            # for the source-owned full receipt chain + kernel callback.
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        "redirect_scoped_owner_required"):
                capture._redirect_policy("eth0", 15080)
            for field, changed in (("redirect_handle", 6), ("policy_sha256", "d" * 64),
                                   ("private_unit", "aegis-auto@" + "d" * 64 + ".service"),
                                   ("listen_ipv4", "192.0.2.2"),
                                   ("conntrack_mark", 0x87654321)):
                with self.subTest(field=field):
                    verify.return_value = dict(policy, **{field: changed})
                    with self.assertRaisesRegex(capture.CaptureRefused,
                                                "redirect_scoped_policy_changed"):
                        capture._redirect_policy("eth0", 15080, **args)
            verify.return_value = dict(policy)
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        "redirect_scoped_identity_changed"):
                capture._redirect_policy("eth0", 15080,
                    **dict(args, invocation_id="e" * 32))
            for changed in ({"ifindex": 8}, {"conntrack_mark": 0xa3610001},
                            {"input_drop_handle": 3}, {"listen_port": True}):
                with self.subTest(changed=changed):
                    bad = dict(policy, **changed)
                    with self.assertRaises(capture.CaptureRefused):
                        capture._redirect_policy("eth0", 15080,
                            **dict(args, scoped_policy=bad, scoped_verify=lambda: bad))

    def test_nat_inverse_requires_only_owned_table_absence(self):
        foreign = {"nftables": [
            {"table": {"family": "ip", "name": "aegis_wide_tproxy"}},
            {"table": {"family": "inet", "name": "foreign"}}]}
        with patch.object(capture, "_run", return_value=json.dumps(foreign).encode()) as run:
            capture._redirect_artifacts_absent()
            self.assertEqual(run.call_count, 1)
            foreign["nftables"].append({"table": {"family": "ip",
                                       "name": "aegis_auto_redirect"}})
            run.return_value = json.dumps(foreign).encode()
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        "redirect_capture_table_remains"):
                capture._redirect_artifacts_absent()

    def test_same_projection_with_replaced_drop_handle_refuses(self):
        projection = b"stable-rule-projection"
        digest = hashlib.sha256(projection).hexdigest()
        snapshots = iter([(projection, {"output": 41}, {}),
                          (projection, {"output": 42}, {})])
        self.assertEqual(capture._policy(digest, 41, lambda _: next(snapshots)),
                         (digest, 41))
        with self.assertRaisesRegex(capture.CaptureRefused,
                                    "capture_deny_policy_changed"):
            capture._policy(digest, 41, lambda _: next(snapshots))

    def test_both_halves_require_unique_tun_routes_and_effective_lookup(self):
        def native(argv):
            if "show" in argv:
                return [{"dst": "::/1", "dev": "aegis-tun0"},
                        {"dst": "8000::/1", "dev": "aegis-tun0"}]
            return [{"dst": argv[-1], "dev": "aegis-tun0"}]

        with patch.object(capture, "_json", side_effect=native):
            self.assertEqual(len(capture._routes(7)), 2)

        def foreign_effective(argv):
            result = native(argv)
            if "get" in argv and argv[-1].startswith("a001:"):
                result[0]["dev"] = "eth0"
            return result

        with patch.object(capture, "_json", side_effect=foreign_effective):
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        "effective_capture_route_missing"):
                capture._routes(7)

        def duplicate(argv):
            result = native(argv)
            if "show" in argv:
                result.append({"dst": "::/1", "dev": "aegis-tun0"})
            return result

        with patch.object(capture, "_json", side_effect=duplicate):
            with self.assertRaisesRegex(capture.CaptureRefused,
                                        "capture_route_missing_or_ambiguous"):
                capture._routes(7)

if __name__ == "__main__":
    unittest.main()
