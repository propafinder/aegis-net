#!/usr/bin/env python3
"""Contract checks for the strict B-07 startup observation collector."""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("collect-optimizer-startup.py")
SPEC = importlib.util.spec_from_file_location("startup_collector", MODULE_PATH)
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def report(wall: int = 10, failures: int = 0) -> str:
    return (
        f"optimizer_startup attempts=1 completed=1 failures={failures} "
        f"total_wall_us={wall} total_process_cpu_us=4 "
        "process_cpu_samples=1 scope=prebind_process_aggregate\n"
        '2026-10-13T00:00:00.000000Z  INFO aegis_server: '
        'required server listeners are ready; application reachability is not yet verified '
        'event_code="server_ingress_ready" tcp_listener_bound=true '
        'quic_listener_bound=true quic_required=false\n'
    )


class StartupCollectorTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        root = Path(self.dir.name)
        self.binary = root / "aegis-server"
        self.config = root / "server.toml"
        self.log1 = root / "run-1.log"
        self.log2 = root / "run-2.log"
        self.binary.write_bytes(b"binary")
        self.config.write_bytes(b"config")
        self.log1.write_text(report(10))
        self.log2.write_text(report(20))

    def collect(self, logs=None, count=2, binary_hash=None):
        return COLLECTOR.collect(
            self.binary, binary_hash or digest(b"binary"), self.config,
            digest(b"config"), logs or [self.log1, self.log2], count
        )

    def test_binds_artifacts_and_repeated_ready_runs(self):
        receipt = self.collect()
        self.assertEqual(receipt["wall_us"]["median"], 15)
        self.assertEqual(receipt["process_cpu_us"]["per_run"], [4, 4])
        self.assertEqual(receipt["run_log_sha256"], [
            digest(self.log1.read_bytes()), digest(self.log2.read_bytes())
        ])
        self.assertEqual(receipt["scope"], "binary_startup_observation_only")
        self.assertNotIn("server.toml", str(receipt))

    def test_refuses_wrong_identity_or_missing_run(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.collect(binary_hash="0" * 64)
        with self.assertRaisesRegex(ValueError, "run count"):
            self.collect(count=3)
        with self.assertRaisesRegex(ValueError, "distinct"):
            self.collect(logs=[self.log1, self.log1])

    def test_refuses_duplicate_report_and_refusal(self):
        self.log1.write_text(report() + report())
        with self.assertRaisesRegex(ValueError, "exactly one complete"):
            self.collect()
        self.log1.write_text(report(failures=1))
        with self.assertRaisesRegex(ValueError, "incomplete or refused"):
            self.collect()

    def test_refuses_missing_readiness_and_mixed_counts(self):
        self.log1.write_text(report().replace('event_code="server_ingress_ready"', 'message="server_ingress_ready"'))
        with self.assertRaisesRegex(ValueError, "readiness"):
            self.collect()
        self.log1.write_text(
            report().replace("attempts=1 completed=1", "attempts=2 completed=2")
                    .replace("process_cpu_samples=1", "process_cpu_samples=2")
        )
        with self.assertRaisesRegex(ValueError, "mixed preparation"):
            self.collect()

    def test_refuses_ready_token_inside_quoted_message(self):
        self.log1.write_text(
            report().splitlines()[0] + '\n'
            '2026-10-13T00:00:00.000000Z  INFO aegis_server: '
            'message="not ready event_code=server_ingress_ready '
            'tcp_listener_bound=true quic_listener_bound=true quic_required=false"\n'
        )
        with self.assertRaisesRegex(ValueError, "readiness"):
            self.collect()

    def test_refuses_unquoted_diagnostic_prose_with_all_ready_tokens(self):
        self.log1.write_text(
            report().splitlines()[0] + '\n'
            '2026-10-13T00:00:00.000000Z  INFO aegis_server: '
            'diagnostic text says event_code=server_ingress_ready '
            'tcp_listener_bound=true quic_listener_bound=true quic_required=true\n'
        )
        with self.assertRaisesRegex(ValueError, "readiness"):
            self.collect()

    def test_refuses_ready_event_without_bound_listener_evidence(self):
        valid = report()
        for altered in (
            valid.replace("tcp_listener_bound=true", "tcp_listener_bound=false"),
            valid.replace("tcp_listener_bound=true ", ""),
            valid.replace("quic_listener_bound=true quic_required=false",
                          "quic_listener_bound=false quic_required=true"),
            valid.replace("quic_listener_bound=true ", ""),
            valid.replace("quic_required=false", "quic_required=unknown"),
            valid.replace("tcp_listener_bound=true", "tcp_listener_bound=true tcp_listener_bound=false"),
        ):
            with self.subTest(altered=altered):
                self.log1.write_text(altered)
                with self.assertRaisesRegex(ValueError, "readiness"):
                    self.collect()

    def test_refuses_oversized_single_line_before_field_parse(self):
        self.log1.write_text(report() + "x" * (16 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "oversized run log line"):
            self.collect()

    def test_refuses_malformed_extra_report(self):
        self.log1.write_text(report() + "optimizer_startup malformed\n")
        with self.assertRaisesRegex(ValueError, "exactly one complete"):
            self.collect()

    def test_cli_preserves_existing_receipt(self):
        output = Path(self.dir.name) / "receipt.json"
        output.write_text("existing receipt")
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH),
             "--binary", str(self.binary), "--binary-sha256", digest(b"binary"),
             "--config", str(self.config), "--config-sha256", digest(b"config"),
             "--expected-runs", "2", "--output", str(output),
             str(self.log1), str(self.log2)],
            capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(), "existing receipt")
        output.unlink()
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH),
             "--binary", str(self.binary), "--binary-sha256", digest(b"binary"),
             "--config", str(self.config), "--config-sha256", digest(b"config"),
             "--expected-runs", "2", "--output", str(output),
             str(self.log1), str(self.log2)],
            capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text())["wall_us"]["per_run"], [10, 20])


if __name__ == "__main__":
    unittest.main()
