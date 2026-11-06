#!/usr/bin/env python3
from __future__ import annotations

import base64
import datetime as dt
import json
import pathlib
import subprocess
import tempfile
import unittest
import uuid
from unittest import mock

import monitor


class HarnessTests(unittest.TestCase):
    @staticmethod
    def config() -> dict:
        return {
            "candidate": {"source": "a" * 40, "binary": "/opt/aegis/aegis-server", "binary_sha256": "b" * 64},
            "units": [{"name": "candidate.service", "candidate": True, "immutable_pid": True}],
            "listeners": [
                {"protocol": "tcp", "address": "127.0.0.1", "port": 9443},
                {"protocol": "udp", "address": "127.0.0.1", "port": 9443},
            ],
            "journal_units": ["candidate.service"],
            "semantic_probes": [{"name": "health", "argv": ["/bin/health"], "stdout_equals": "healthy\n"}],
            "thresholds": {"minimum_duration_seconds": 86400, "minimum_samples": 1400, "maximum_gap_seconds": 180},
        }

    @staticmethod
    def probe(argv: list[str], stdout: bytes, timeout: float = 30.0) -> dict:
        return {
            "argv": argv,
            "started_at_utc": "2026-10-03T00:00:00+00:00",
            "elapsed_monotonic_ns": 1,
            "timeout_seconds": timeout,
            "timed_out": False,
            "returncode": 0,
            "exception": None,
            "stdout_b64": base64.b64encode(stdout).decode(),
            "stderr_b64": "",
            "stdout_sha256": monitor.sha256(stdout),
            "stderr_sha256": monitor.sha256(b""),
            "stdout_bytes": len(stdout),
            "stderr_bytes": 0,
        }

    @staticmethod
    def anchor_keys(root: pathlib.Path, prefix: str = "anchor") -> tuple[pathlib.Path, pathlib.Path, bytes]:
        private = root / f"{prefix}.key"
        public = root / f"{prefix}.pub"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(private)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        private.chmod(0o600)
        subprocess.run(
            ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return private, public, public.read_bytes()

    @staticmethod
    def signed_receipt(
        private: pathlib.Path,
        entry: dict,
        previous_receipt_sha256: str,
        sequence_time: int | None = None,
        anchor_id: str = "test-anchor",
    ) -> dict:
        second = entry["sequence"] if sequence_time is None else sequence_time
        receipt = {
            "schema": monitor.ANCHOR_SCHEMA,
            "anchor_id": anchor_id,
            "attempt_id": entry["attempt_id"],
            "config_sha256": entry["config_sha256"],
            "sequence": entry["sequence"],
            "entry_sha256": monitor.sha256(monitor.canonical(entry)),
            "previous_receipt_sha256": previous_receipt_sha256,
            "anchored_at_utc": (dt.datetime(2026, 10, 3, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=second)).isoformat(),
        }
        with tempfile.TemporaryDirectory() as tmp:
            message = pathlib.Path(tmp) / "message.bin"
            signature = pathlib.Path(tmp) / "signature.bin"
            message.write_bytes(monitor.anchor_message(receipt))
            subprocess.run(
                [
                    "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private),
                    "-in", str(message), "-out", str(signature),
                ],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            receipt["signature_b64"] = base64.b64encode(signature.read_bytes()).decode()
        return receipt

    def append_anchored(
        self,
        root: pathlib.Path,
        path: pathlib.Path,
        config_sha256: str,
        private: pathlib.Path,
        public_raw: bytes,
        **receipt_overrides,
    ) -> None:
        def issue(_command, entry, previous_receipt_sha256, _public):
            return self.signed_receipt(
                private, entry, previous_receipt_sha256, **receipt_overrides,
            )

        with mock.patch.object(monitor, "obtain_anchor_receipt", side_effect=issue):
            monitor.append_sample_chain(
                root, path, "attempt-1", config_sha256,
                pathlib.Path("/test/anchor"), public_raw,
            )

    def valid_sample(self) -> dict:
        config = self.config()
        unit_argv = [
            "systemctl", "show", "candidate.service",
            "-p", "ActiveState", "-p", "MainPID", "-p", "NRestarts",
            "-p", "ActiveEnterTimestampMonotonic",
        ]
        probes = {
            "boot_id": self.probe(["cat", "/proc/sys/kernel/random/boot_id"], b"12345678-1234-1234-1234-123456789abc\n"),
            "unit:candidate.service": self.probe(unit_argv, b"ActiveState=active\nMainPID=42\nNRestarts=0\nActiveEnterTimestampMonotonic=1\n"),
            "candidate_executable": self.probe(["readlink", "-f", "/proc/42/exe"], b"/opt/aegis/aegis-server\n"),
            "candidate_sha256": self.probe(["sha256sum", "/proc/42/exe"], ("b" * 64 + "  /proc/42/exe\n").encode()),
            "candidate_version": self.probe(["/opt/aegis/aegis-server", "--version"], ("aegis " + "a" * 40 + "\n").encode()),
            "listeners": self.probe(
                ["ss", "-H", "-lntup"],
                b'udp UNCONN 0 0 127.0.0.1:9443 0.0.0.0:* users:(("aegis",pid=42,fd=7))\n'
                b'tcp LISTEN 0 128 127.0.0.1:9443 0.0.0.0:* users:(("aegis",pid=42,fd=8))\n',
            ),
            "semantic:health": self.probe(["/bin/health"], b"healthy\n"),
        }
        row = {
            "schema": monitor.SCHEMA,
            "sample_id": str(uuid.uuid4()),
            "observed_at_utc": "2026-10-03T00:00:01+00:00",
            "boottime_before_ns": 1,
            "boottime_after_ns": 2,
            "probes": probes,
        }
        row["assessment"] = monitor.assess_sample(config, row)
        return row

    def test_probe_preserves_exact_binary_stderr_and_returncode(self) -> None:
        completed = subprocess.CompletedProcess(["probe"], 23, b"out\x00", b"err\xff\n")
        with mock.patch.object(monitor.subprocess, "run", return_value=completed):
            row = monitor.run_probe(["probe"])
        self.assertEqual(row["returncode"], 23)
        self.assertFalse(row["timed_out"])
        self.assertEqual(base64.b64decode(row["stdout_b64"]), b"out\x00")
        self.assertEqual(base64.b64decode(row["stderr_b64"]), b"err\xff\n")
        self.assertGreaterEqual(row["elapsed_monotonic_ns"], 0)

    def test_exclusive_writer_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "receipt.json"
            monitor.write_exclusive(path, b"first")
            with self.assertRaises(FileExistsError):
                monitor.write_exclusive(path, b"second")
            self.assertEqual(path.read_bytes(), b"first")

    def test_config_rejects_relaxed_p3_thresholds(self) -> None:
        config = {
            "candidate": {"source": "a" * 40, "binary": "/x", "binary_sha256": "b" * 64},
            "units": [{"name": "candidate.service", "candidate": True, "immutable_pid": True}],
            "listeners": [
                {"protocol": "tcp", "address": "127.0.0.1", "port": 1},
                {"protocol": "udp", "address": "127.0.0.1", "port": 1},
            ],
            "journal_units": ["candidate.service"],
            "semantic_probes": [{"name": "health", "argv": ["/bin/true"], "stdout_equals": "ok"}],
            "thresholds": {"minimum_duration_seconds": 86399, "minimum_samples": 1400, "maximum_gap_seconds": 180},
        }
        with self.assertRaisesRegex(ValueError, "86400"):
            monitor.valid_config(config)
        config["thresholds"]["minimum_duration_seconds"] = 86400
        config["thresholds"]["minimum_samples"] = 1399
        with self.assertRaisesRegex(ValueError, "1400"):
            monitor.valid_config(config)

    def test_config_rejects_empty_semantic_assertions(self) -> None:
        for assertion in ({"json_equals": {}}, {"stdout_contains": []}, {"stdout_equals": ""}):
            config = self.config()
            config["semantic_probes"] = [{"name": "health", "argv": ["/bin/true"], **assertion}]
            with self.subTest(assertion=assertion), self.assertRaisesRegex(ValueError, "semantic"):
                monitor.valid_config(config)

    def test_config_rejects_non_finite_numbers(self) -> None:
        for field in ("minimum_duration_seconds", "minimum_samples", "maximum_gap_seconds"):
            config = self.config()
            config["thresholds"][field] = float("nan")
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "finite"):
                monitor.valid_config(config)
        config = self.config()
        config["semantic_probes"][0]["timeout_seconds"] = float("inf")
        with self.assertRaisesRegex(ValueError, "finite"):
            monitor.valid_config(config)

    def test_listener_requires_exact_endpoint_and_pid(self) -> None:
        lines = ['tcp LISTEN 0 128 127.0.0.1:94430 0.0.0.0:* users:(("aegis",pid=420,fd=8))']
        self.assertFalse(monitor.listener_owned_by(lines, "tcp", "127.0.0.1:9443", "42"))
        self.assertTrue(monitor.listener_owned_by(
            ['tcp LISTEN 0 128 127.0.0.1:9443 0.0.0.0:* users:(("aegis",pid=42,fd=8))'],
            "tcp", "127.0.0.1:9443", "42",
        ))

    def test_fabricated_assessment_without_probes_is_rejected(self) -> None:
        row = self.valid_sample()
        row["probes"] = {}
        row["assessment"] = {"status": "PASS", "failures": [], "boot_id": "x", "units": {}}
        filename = f"{row['boottime_before_ns']:020d}-{row['sample_id']}.json"
        failures = monitor.sample_integrity_failures(self.config(), row, filename)
        self.assertIn("probe_set", failures)
        self.assertIn("assessment_mismatch", failures)

    def test_complete_sample_evidence_revalidates(self) -> None:
        row = self.valid_sample()
        filename = f"{row['boottime_before_ns']:020d}-{row['sample_id']}.json"
        self.assertEqual(monitor.sample_integrity_failures(self.config(), row, filename), [])
        self.assertEqual(row["assessment"]["status"], "PASS")

    def test_malformed_probe_bytes_fail_closed_without_crashing(self) -> None:
        row = self.valid_sample()
        row["probes"]["boot_id"]["stdout_b64"] = "%%%"
        filename = f"{row['boottime_before_ns']:020d}-{row['sample_id']}.json"
        failures = monitor.sample_integrity_failures(self.config(), row, filename)
        self.assertIn("probe:boot_id:invalid_base64", failures)
        self.assertIn("assessment_unreadable", failures)

    def test_sample_chain_rejects_unlisted_injected_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "samples").mkdir()
            (root / "anchors").mkdir()
            private, _, public_raw = self.anchor_keys(root)
            row = self.valid_sample()
            path = monitor.store_sample(root, row)
            config_sha256 = monitor.sha256(monitor.canonical(self.config()))
            self.append_anchored(root, path, config_sha256, private, public_raw)
            (root / "samples" / "injected.json").write_text("{}\n")
            _, failures, *_ = monitor.verify_sample_chain(root, "attempt-1", config_sha256, public_raw)
            self.assertIn("sample_chain_file_set", failures)

    def test_sample_chain_requires_independently_pinned_signer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "samples").mkdir()
            (root / "anchors").mkdir()
            private, _, public_raw = self.anchor_keys(root, "good")
            _, _, wrong_public_raw = self.anchor_keys(root, "wrong")
            row = self.valid_sample()
            path = monitor.store_sample(root, row)
            config_sha256 = monitor.sha256(monitor.canonical(self.config()))
            self.append_anchored(root, path, config_sha256, private, public_raw)
            _, failures, *_ = monitor.verify_sample_chain(root, "attempt-1", config_sha256, wrong_public_raw)
            self.assertIn("sample_chain_anchor_signature:0", failures)

    def test_sample_chain_rejects_noncanonical_anchor_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "samples").mkdir()
            (root / "anchors").mkdir()
            private, _, public_raw = self.anchor_keys(root)
            row = self.valid_sample()
            path = monitor.store_sample(root, row)
            config_sha256 = monitor.sha256(monitor.canonical(self.config()))
            self.append_anchored(root, path, config_sha256, private, public_raw)
            receipt_path = next((root / "anchors").glob("*.anchor.json"))
            receipt = json.loads(receipt_path.read_bytes())
            receipt_path.write_bytes(json.dumps(receipt, indent=2).encode() + b"\n")
            _, failures, *_ = monitor.verify_sample_chain(root, "attempt-1", config_sha256, public_raw)
            self.assertIn("sample_chain_anchor_noncanonical:0", failures)

    def test_sample_chain_verifies_receipt_links_and_anchor_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "samples").mkdir()
            (root / "anchors").mkdir()
            private, _, public_raw = self.anchor_keys(root)
            config_sha256 = monitor.sha256(monitor.canonical(self.config()))
            first = monitor.store_sample(root, self.valid_sample())
            self.append_anchored(root, first, config_sha256, private, public_raw)
            second = monitor.store_sample(root, self.valid_sample())
            self.append_anchored(root, second, config_sha256, private, public_raw)
            samples, failures, entries, _, anchor_times, _ = monitor.verify_sample_chain(
                root, "attempt-1", config_sha256, public_raw,
            )
            self.assertEqual(failures, [])
            self.assertEqual(len(samples), 2)
            self.assertEqual(len(entries), 2)
            self.assertLess(anchor_times[0], anchor_times[1])

            second_receipt = root / "anchors" / f"{second.name}.anchor.json"
            forged = self.signed_receipt(
                private,
                entries[1],
                monitor.sha256((root / "anchors" / f"{first.name}.anchor.json").read_bytes()),
                anchor_id="replacement-anchor",
            )
            second_receipt.write_bytes(monitor.canonical(forged))
            _, failures, *_ = monitor.verify_sample_chain(root, "attempt-1", config_sha256, public_raw)
            self.assertIn("sample_chain_anchor_id_changed:1", failures)

    def test_single_read_rejects_hardlinked_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            original = root / "sample.json"
            linked = root / "linked.json"
            original.write_bytes(b"{}\n")
            linked.hardlink_to(original)
            with self.assertRaisesRegex(RuntimeError, "multiply-linked"):
                monitor.read_regular_once(original)

    def test_example_is_valid_after_exact_placeholder_replacement(self) -> None:
        path = pathlib.Path(__file__).with_name("config.example.json")
        config = json.loads(path.read_text())
        config["candidate"] = {
            "source": "a" * 40,
            "binary": "/opt/aegis/final/bin/aegis-server",
            "binary_sha256": "b" * 64,
        }
        config["semantic_probes"][0]["argv"][0] = config["candidate"]["binary"]
        monitor.valid_config(config)

    def test_evaluator_fails_closed_on_bad_sample_and_journal(self) -> None:
        config = self.config()
        first = self.valid_sample()
        first["boottime_before_ns"] = 0
        first["boottime_after_ns"] = 1
        second = self.valid_sample()
        second["boottime_before_ns"] = 86_400_000_000_001
        second["boottime_after_ns"] = 86_400_000_000_002
        bad = b"unhealthy\n"
        second["probes"]["semantic:health"]["stdout_b64"] = base64.b64encode(bad).decode()
        second["probes"]["semantic:health"]["stdout_sha256"] = monitor.sha256(bad)
        second["probes"]["semantic:health"]["stdout_bytes"] = len(bad)
        second["assessment"] = monitor.assess_sample(config, second)
        samples = [first, second]
        journal_probe = {
            "returncode": 0, "timed_out": False,
            "stdout_b64": base64.b64encode(b'{"MESSAGE":"warning"}\n').decode(),
        }
        result = monitor.evaluate(config, samples, {"candidate.service": {"cursor_error": False, "probe": journal_probe}})
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("failed_sample", result["reasons"])
        self.assertIn("journal_entries:candidate.service", result["reasons"])


if __name__ == "__main__":
    unittest.main()
