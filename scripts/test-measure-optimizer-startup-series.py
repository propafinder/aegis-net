#!/usr/bin/env python3
"""Inert process contracts for the bounded B-07 local startup runner."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


RUNNER = Path(__file__).with_name("measure-optimizer-startup-series.py")
SPEC = importlib.util.spec_from_file_location("startup_series", RUNNER)
SERIES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERIES)
REPORT = (
    "optimizer_startup attempts=1 completed=1 failures=0 "
    "total_wall_us=10 total_process_cpu_us=4 "
    "process_cpu_samples=1 scope=prebind_process_aggregate"
)
READY = ('2026-10-13T00:00:00.000000Z  INFO aegis_server: '
         'required server listeners are ready; application reachability is not yet verified '
         'event_code="server_ingress_ready" tcp_listener_bound=true '
         'quic_listener_bound=true quic_required=false')


class StartupSeriesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "server.toml"
        self.config.write_text(
            'listen = "127.0.0.1:0"\n'
            '[transport]\nquic_listen = "127.0.0.1:0"\n', encoding="utf-8"
        )

    def child(self, lines):
        path = self.root / "dummy-server"
        path.write_text(
            "#!" + sys.executable + "\n"
            "import signal, sys, time\n"
            "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n"
            + "\n".join(f"print({line!r}, flush=True)" for line in lines)
            + "\nwhile True: time.sleep(0.05)\n", encoding="utf-8"
        )
        path.chmod(0o700)
        return path

    def run_series(self, child, ready_timeout="0.5"):
        output = self.root / "runs"
        result = subprocess.run(
            [sys.executable, str(RUNNER), str(child), str(self.config), str(output),
             "--runs", "1", "--last-dwell", "0.1", "--ready-timeout", ready_timeout],
            capture_output=True, text=True, timeout=12, check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertTrue(result.stdout, result.stderr)
        return result, json.loads(result.stdout), output

    def test_valid_complete_report_and_event_stay_live(self):
        result, rows, output = self.run_series(self.child([REPORT, READY]), "2")
        self.assertEqual(result.returncode, 0, result.stderr or str(rows))
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["ready_and_reported"])
        self.assertTrue(rows[0]["alive_during_dwell"])
        self.assertEqual(rows[0]["exit_code"], 0)
        self.assertIsNone(rows[0]["log_refusal"])
        self.assertTrue((output / "run-01.log").is_file())

    def test_message_mention_is_not_readiness(self):
        result, rows, _ = self.run_series(self.child([
            REPORT, 'INFO message="not ready event_code=server_ingress_ready but still starting"'
        ]))
        self.assertEqual(result.returncode, 1)
        self.assertFalse(rows[0]["ready_and_reported"])

    def test_duplicate_report_is_not_readiness(self):
        result, rows, _ = self.run_series(self.child([REPORT, REPORT, READY]))
        self.assertEqual(result.returncode, 1)
        self.assertFalse(rows[0]["ready_and_reported"])

    def test_nonloopback_config_refused_before_run_directory(self):
        self.config.write_text('listen = "0.0.0.0:0"\n'
                               '[transport]\nquic_listen = "127.0.0.1:0"\n')
        output = self.root / "runs"
        result = subprocess.run(
            [sys.executable, str(RUNNER), str(self.child([REPORT, READY])),
             str(self.config), str(output), "--runs", "1"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

    def test_status_socket_and_bundle_endpoint_refused_before_launch(self):
        child = self.child([REPORT, READY])
        base = self.config.read_text()
        for extra in ('device_policy_status_socket = "/tmp/other.sock"\n',
                      '[bundle_endpoint]\nenabled = true\n'):
            with self.subTest(extra=extra):
                self.config.write_text(base + extra)
                output = self.root / "runs"
                result = subprocess.run(
                    [sys.executable, str(RUNNER), str(child), str(self.config), str(output),
                     "--runs", "1"],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())

    def test_device_registry_refused_before_launch(self):
        self.config.write_text(self.config.read_text() +
                               '[transport.inner_tls]\n'
                               'device_registry = "/tmp/operator-registry.json"\n')
        output = self.root / "runs"
        result = subprocess.run(
            [sys.executable, str(RUNNER), str(self.child([REPORT, READY])),
             str(self.config), str(output), "--runs", "1"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

    def test_nonfinite_or_unbounded_dwell_refused_before_launch(self):
        child = self.child([REPORT, READY])
        for value in ("nan", "inf", "601", "0"):
            with self.subTest(value=value):
                output = self.root / "runs"
                result = subprocess.run(
                    [sys.executable, str(RUNNER), str(child), str(self.config),
                     str(output), "--last-dwell", value],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())

    def test_child_log_has_kernel_enforced_size_cap(self):
        child = self.root / "flood-server"
        child.write_text(
            "#!" + sys.executable + "\n"
            "import sys\n"
            + f"print({REPORT!r}, flush=True)\n"
            + f"print({READY!r}, flush=True)\n"
            + "sys.stdout.write('x' * (4 * 1024 * 1024))\n"
            + "sys.stdout.flush()\n", encoding="utf-8"
        )
        child.chmod(0o700)
        result, rows, output = self.run_series(child)
        self.assertEqual(result.returncode, 1)
        self.assertLessEqual((output / "run-01.log").stat().st_size, 2 * 1024 * 1024)
        self.assertFalse(rows[0]["alive_during_dwell"])

    def test_exactly_saturated_log_refused_while_child_stays_live(self):
        child = self.root / "exact-cap-server"
        child.write_text(
            "#!" + sys.executable + "\n"
            "import signal,sys,time\n"
            "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n"
            + f"prefix = ({REPORT!r} + '\\n' + {READY!r} + '\\n').encode()\n"
            "remaining = 2 * 1024 * 1024 - len(prefix)\n"
            "filler = (b'x' * 4095 + b'\\n') * (remaining // 4096) + "
            "b'x' * (remaining % 4096)\n"
            "sys.stdout.buffer.write(prefix + filler)\n"
            "sys.stdout.buffer.flush()\n"
            "while True: time.sleep(0.05)\n", encoding="utf-8"
        )
        child.chmod(0o700)
        result, rows, output = self.run_series(child, "2")
        self.assertEqual(result.returncode, 1)
        self.assertEqual((output / "run-01.log").stat().st_size, 2 * 1024 * 1024)
        self.assertEqual(rows[0]["log_refusal"], "saturated run log")
        self.assertFalse(rows[0]["ready_and_reported"])

    def test_exited_leader_cannot_leave_descendant_running(self):
        marker = self.root / "orphan-marker"
        child = self.root / "fork-server"
        child.write_text(
            "#!" + sys.executable + "\n"
            "import subprocess,sys\n"
            "subprocess.Popen([sys.executable, '-c', "
            + repr(f"import time,pathlib;time.sleep(1);pathlib.Path({str(marker)!r}).write_text('survived')")
            + "])\n"
            + f"print({REPORT!r}, flush=True)\n"
            + f"print({READY!r}, flush=True)\n", encoding="utf-8"
        )
        child.chmod(0o700)
        result, rows, _ = self.run_series(child)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(rows[0]["alive_during_dwell"])
        time.sleep(1.2)
        self.assertFalse(marker.exists())

    def test_natural_exit_during_final_dwell_sleep_refuses(self):
        child = self.root / "early-exit-server"
        child.write_text(
            "#!" + sys.executable + "\n"
            "import time\n"
            + f"print({REPORT!r}, flush=True)\n"
            + f"print({READY!r}, flush=True)\n"
            + "time.sleep(0.08)\n", encoding="utf-8"
        )
        child.chmod(0o700)
        result, rows, _ = self.run_series(child)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(rows[0]["alive_during_dwell"])

    def test_group_signals_precede_leader_reap(self):
        events = []

        class FakeChild:
            pid = 42
            returncode = None

            def wait(self, timeout):
                events.append("reap")
                self.returncode = 0
                return 0

        def record_signal(pgid, sig):
            self.assertEqual(pgid, 42)
            self.assertNotIn("reap", events)
            events.append(sig)

        with mock.patch.object(SERIES.os, "killpg", side_effect=record_signal), \
             mock.patch.object(SERIES, "exited_unreaped", return_value=True):
            self.assertEqual(SERIES.finish(FakeChild(), signal.SIGTERM), 0)
        self.assertEqual(events, [signal.SIGTERM, signal.SIGKILL, "reap"])

    def test_zombie_only_eperm_requires_group_absent_after_reap(self):
        class FakeChild:
            pid = 42
            returncode = None

            def wait(self, timeout):
                self.returncode = 0
                return 0

        for final_probe, expected in ((ProcessLookupError(), None),
                                      (PermissionError(), PermissionError),
                                      (None, RuntimeError)):
            with self.subTest(final_probe=final_probe):
                seen = []

                def record_signal(pgid, sig):
                    seen.append(sig)
                    if sig in (signal.SIGTERM, signal.SIGKILL):
                        raise PermissionError()
                    if final_probe is not None:
                        raise final_probe

                with mock.patch.object(SERIES.os, "killpg", side_effect=record_signal), \
                     mock.patch.object(SERIES, "exited_unreaped", return_value=True):
                    if expected is None:
                        self.assertEqual(SERIES.finish(FakeChild(), signal.SIGTERM), 0)
                    else:
                        with self.assertRaises(expected):
                            SERIES.finish(FakeChild(), signal.SIGTERM)
                self.assertEqual(seen, [signal.SIGTERM, signal.SIGKILL, 0])


if __name__ == "__main__":
    unittest.main()
