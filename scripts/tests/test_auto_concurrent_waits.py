"""Event-driven waits and concurrent child starts keep every bound and check.

Timing-independent: real children exit or are killed; no assertion depends
on how long a wait took, only on what it returned and what was reaped.
"""
import contextlib
import importlib.util
import os
import pathlib
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

LIB = pathlib.Path(__file__).resolve().parents[1] / "lib"
sys.path.insert(0, str(LIB))


def load(name):
    spec = importlib.util.spec_from_file_location("_waits_" + name, LIB / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardian = load("aegis_auto_guardian")
capture_topology = load("aegis_auto_capture_topology")
witness_topology = load("aegis_auto_witness_topology")


@unittest.skipUnless(pathlib.Path("/bin/sh").exists(), "POSIX shell required")
class GuardianExitWait(unittest.TestCase):
    def test_returns_exit_status_and_times_out_under_the_same_bound(self):
        proc = subprocess.Popen(["/bin/sh", "-c", "exit 7"])
        self.assertEqual(guardian._wait_exit(proc, 6), 7)
        proc = subprocess.Popen(["/bin/sh", "-c", "exec sleep 30"])
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                guardian._wait_exit(proc, 0.2)
            self.assertIsNone(proc.poll())
        finally:
            proc.kill()
            proc.wait(timeout=5)

    def test_helper_wait_uses_the_event_driven_wait(self):
        source = (LIB / "aegis_auto_guardian.py").read_text()
        body = source.split("def _run_helper_in_cgroup(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("_wait_capture_bind_helper(proc, assist, guard_fd, nonce)", body)
        self.assertIn("else _wait_exit(proc, 6)", body)
        self.assertIn('"populated 0\\n" in events', body)
        self.assertLessEqual(guardian.FLOCK_RETRY_SECONDS, 0.01)
        for marker in ('"guard_handoff_busy"', '"stop_guard_lock_busy"'):
            loop = source.split(marker, 1)[0].rsplit("while True:", 1)[1]
            self.assertIn("fcntl.LOCK_EX | fcntl.LOCK_NB", loop)


class FakeChild:
    def __init__(self, argv, events, exits_before_socket=False, **_kwargs):
        self.argv = argv
        self.pid = 4000 + len([e for e in events if e[0] == "spawn"])
        self.events = events
        self.returncode = 1 if exits_before_socket else None
        self.socket_path = argv[argv.index("--socket") + 1]
        events.append(("spawn", self.pid))
        if not exits_before_socket:
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener.bind(self.socket_path)
            os.chmod(self.socket_path, 0o600)

    def poll(self):
        return self.returncode

    def kill(self):
        self.events.append(("kill", self.pid))
        self.returncode = -9

    def wait(self, timeout=None):
        self.events.append(("wait", self.pid))
        return self.returncode


class CaptureChildrenStartTogether(unittest.TestCase):
    @contextlib.contextmanager
    def host(self, fail_ordinal=None):
        events = []
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "sink.py"
            source.write_bytes(b"# sink\n")
            real_stat = pathlib.Path.stat
            real_os_stat = os.stat

            def path_stat(path, *args, **kwargs):
                value = real_stat(path, *args, **kwargs)
                if str(path).startswith(directory):
                    view = SimpleNamespace(**{n: getattr(value, n) for n in dir(value)
                                              if n.startswith("st_")})
                    view.st_uid = 0
                    return view
                return value

            def os_stat(path, *args, **kwargs):
                if str(path).startswith("/proc/") and str(path).endswith("/ns/net"):
                    return SimpleNamespace(st_ino=99)
                return real_os_stat(path, *args, **kwargs)

            spawned = []
            def popen(argv, **kwargs):
                child = FakeChild(argv, events, exits_before_socket=(
                    fail_ordinal is not None and len(spawned) == fail_ordinal))
                spawned.append(child)
                return child

            with mock.patch.object(capture_topology, "RUNTIME", root), \
                 mock.patch.object(capture_topology, "SINK_SOURCE", str(source)), \
                 mock.patch.object(capture_topology, "_ns_ino", return_value=99), \
                 mock.patch.object(capture_topology.os, "stat", side_effect=os_stat), \
                 mock.patch.object(pathlib.Path, "stat", path_stat), \
                 mock.patch.object(capture_topology, "_child_startup_diagnostic") as diagnostic, \
                 mock.patch.object(capture_topology, "_log_refusal"), \
                 mock.patch.object(capture_topology.subprocess, "Popen", side_effect=popen):
                try:
                    yield events, spawned, diagnostic
                finally:
                    for child in spawned:
                        if hasattr(child, "listener"):
                            child.listener.close()

    KINDS = [("aegisacs", "serve-echo-tcp", "10.231.82.1"), ("aegisacp", "serve-probe-tcp", None)]

    def test_all_children_spawn_before_admission_and_keep_their_checks(self):
        with self.host() as (events, spawned, _diagnostic):
            children, facts = capture_topology._start_children(self.KINDS, "a" * 16, 9)
        self.assertEqual([e[0] for e in events], ["spawn", "spawn"])
        self.assertEqual(children, spawned)
        self.assertEqual([f["action"] for f in facts], ["serve-echo-tcp", "serve-probe-tcp"])
        for child, item in zip(children, facts):
            self.assertEqual((item["pid"], item["netns_ino"]), (child.pid, 99))
            self.assertEqual(item["socket"], child.socket_path)
            self.assertIn("--completion-release-fd", child.argv)

    def test_early_exit_refuses_and_reaps_every_started_child(self):
        with self.host(fail_ordinal=1) as (events, spawned, diagnostic):
            with self.assertRaisesRegex(capture_topology.Refused,
                                        "capture_child_exited_before_socket"):
                capture_topology._start_children(self.KINDS, "b" * 16, 9)
        diagnostic.assert_called_once()
        self.assertEqual(len(spawned), 2)
        for child in spawned:
            self.assertIn(("wait", child.pid), events)

    def test_reused_path_refuses_before_any_spawn(self):
        with self.host() as (events, _spawned, _diagnostic):
            (capture_topology.RUNTIME / ("effect-" + "c" * 16 + "-1.json")).write_bytes(b"{}")
            with self.assertRaisesRegex(capture_topology.Refused, "capture_child_path_reused"):
                capture_topology._start_children(self.KINDS, "c" * 16, 9)
        self.assertEqual([e for e in events if e[0] == "spawn"], [("spawn", 4000)])
        self.assertIn(("wait", 4000), events)


class WitnessSinksStartTogether(unittest.TestCase):
    def test_one_bound_for_both_sinks_and_early_exit_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first, second = root / "sink.sock", root / "sink6.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(first))
            os.chmod(first, 0o600)
            try:
                alive = SimpleNamespace(poll=lambda: None)
                dead = SimpleNamespace(poll=lambda: 1)
                with mock.patch.object(witness_topology, "SINK_READY_SECONDS", 0.05):
                    with self.assertRaisesRegex(witness_topology.Refused,
                                                "independent_sink_exited"):
                        witness_topology._await_sink_sockets([(alive, first), (dead, second)])
                    with self.assertRaises(FileNotFoundError):
                        witness_topology._await_sink_sockets([(alive, second), (alive, first)])
                if os.geteuid() != 0:
                    with self.assertRaisesRegex(witness_topology.Refused,
                                                "independent_sink_socket_missing"):
                        witness_topology._await_sink_sockets([(alive, first)])
            finally:
                listener.close()
        self.assertLessEqual(witness_topology.SINK_READY_POLL, 0.01)
        self.assertEqual(witness_topology.SINK_READY_SECONDS, 2.0)


capture = load("aegis_auto_capture")


class CaptureIndependentReads(unittest.TestCase):
    def test_local_call_stays_in_caller_and_first_failure_in_order_wins(self):
        import threading
        import time as clock
        caller = threading.get_ident()
        seen = {}
        def record(name, value=None, error=None, pause=0.0):
            def call():
                clock.sleep(pause)
                seen[name] = threading.get_ident()
                if error is not None:
                    raise error
                return value
            return call
        results = capture._concurrent_reads(
            [record("local", 1), record("slow", 2, pause=0.05), record("fast", 3)], local=0)
        self.assertEqual(results, [1, 2, 3])
        self.assertEqual(seen["local"], caller)
        self.assertNotEqual(seen["slow"], caller)
        first, later = capture.CaptureRefused("first_in_order"), capture.CaptureRefused("later")
        output = __import__("io").StringIO()
        with contextlib.redirect_stderr(output):
            with self.assertRaisesRegex(capture.CaptureRefused, "first_in_order"):
                capture._concurrent_reads([record("a", error=first, pause=0.05),
                                           record("b", error=later)])
            with self.assertRaisesRegex(capture.CaptureRefused, "later"):
                capture._concurrent_reads([record("c", 1), record("d", error=later, pause=0.02)],
                                          local=0)
        self.assertEqual(output.getvalue(), "")

    def test_capture_ready_binds_pidfd_then_joins_all_reads_before_traffic(self):
        import threading
        events = []
        lock = threading.Lock()
        def mark(name, value=None):
            def call(*_args, **_kwargs):
                with lock:
                    events.append((name, threading.get_ident()))
                return value
            return call
        unit = "aegis-auto@" + "a" * 64 + ".service"
        facts = {"ActiveState": "active", "SubState": "running", "InvocationID": "b" * 32,
                 "MainPID": "123", "ControlPID": "0"}
        echo = object()
        lease = capture.EndpointLease.__new__(capture.EndpointLease)
        lease.revalidate = mark("revalidate")
        lease.exchange_completed = False
        caller = threading.get_ident()
        def packet(*_args):
            names = {name for name, _thread in events}
            self.assertTrue({"revalidate", "pid_live", "tun", "link", "routes",
                             "policy"} <= names)
            events.append(("packet", caller))
            return "c" * 64
        with mock.patch.object(capture.EndpointLease, "endpoint", new=echo), \
             mock.patch.object(capture, "Path", side_effect=lambda *_a: SimpleNamespace(
                 read_text=lambda **_kw: "boot\n")), \
             mock.patch.object(capture.os, "stat", return_value=SimpleNamespace(st_ino=7)), \
             mock.patch.object(capture.os, "pidfd_open", create=True, side_effect=lambda *_a: os.open(os.devnull, os.O_RDONLY)), \
             mock.patch.object(capture, "_service", side_effect=lambda *_a, **_k: (mark("service")(), dict(facts))[1]), \
             mock.patch.object(capture, "_pidfd_identity", side_effect=mark("pidfd")), \
             mock.patch.object(capture, "_pid_live", side_effect=mark("pid_live")), \
             mock.patch.object(capture, "_tun_owned_by_pid", side_effect=mark("tun")), \
             mock.patch.object(capture, "_link", side_effect=mark("link", (9, "UP"))), \
             mock.patch.object(capture, "_routes", side_effect=mark("routes", ())), \
             mock.patch.object(capture, "_policy", side_effect=mark("policy", ("d" * 64, 6))), \
             mock.patch.object(capture, "_packet_on_tun", side_effect=packet), \
             mock.patch.object(capture, "_echo_through_service", side_effect=mark("echo", "echo")), \
             mock.patch.object(capture.select, "select", return_value=([], [], [])), \
             mock.patch.object(capture.socket, "if_nametoindex", return_value=9):
            witness = capture.capture_ready(
                mode="full-wide-tun", unit_name=unit, boot_id="boot", netns_ino=7,
                invocation_id="b" * 32, main_pid=123, worker_sha256="e" * 64,
                policy_sha256="d" * 64, output_drop_handle=6, snapshot_policy=object(),
                echo_endpoint=echo, endpoint_lease=lease)
        self.assertEqual(witness.packet_sha256, "c" * 64)
        names = [name for name, _thread in events]
        self.assertEqual(names[:3], ["service", "pidfd", "service"])
        self.assertLess(names.index("pidfd"), names.index("revalidate"))
        threads = {name: thread for name, thread in events}
        self.assertEqual(threads["revalidate"], caller)
        after = names[names.index("echo") + 1:]
        for name in ("pid_live", "tun", "service", "routes", "policy", "revalidate"):
            self.assertIn(name, after)
        self.assertTrue(lease.exchange_completed)

if __name__ == "__main__":
    unittest.main()
