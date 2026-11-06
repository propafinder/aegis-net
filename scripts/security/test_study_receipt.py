#!/usr/bin/env python3
"""Independent inert receipt contracts; no study execution or network access."""

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "study_receipt_validator", Path(__file__).with_name("check-study-receipt.py")
)
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class StudyReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="aegis-inert-study-", dir=os.path.realpath(tempfile.gettempdir())
        )
        self.base = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def receipt(self, **changes):
        value = {
            "schema_version": 1,
            "attempt_id": "study-" + "a" * 32,
            "release_sha256": "b" * 64,
            "profile_class": "baseline",
            "environment_class": "controlled-lab",
            "network_cohort": "withheld",
            "confirmed_ready_at": None,
            "started_at": None,
            "ended_at": None,
            "capture_confirmed_ready_at": None,
            "capture_started_at": None,
            "capture_ended_at": None,
            "independent_witness": "absent",
            "attempts": 0,
            "authenticated_sessions": 0,
            "delivered_bytes": 0,
            "traffic_bytes_total": 0,
            "elapsed_ms": 0,
            "termination": "not-run",
            "rollback": "not-run",
            "publication_approval": False,
        }
        value.update(changes)
        return value

    def run_receipt(self, **changes):
        return self.receipt(
            confirmed_ready_at="2026-10-11T12:00:00Z",
            started_at="2026-10-11T12:00:01Z",
            ended_at="2026-10-11T12:00:02Z",
            attempts=1, authenticated_sessions=1, delivered_bytes=1024,
            traffic_bytes_total=2048, elapsed_ms=1000, termination="completed",
            rollback="restored", **changes,
        )

    def changed_run(self, **changes):
        value = self.run_receipt()
        value.update(changes)
        return value

    def captured_run(self, **changes):
        value = self.run_receipt()
        value.update({
            "capture_confirmed_ready_at": "2026-10-11T11:59:59Z",
            "capture_started_at": "2026-10-11T12:00:00Z",
            "capture_ended_at": "2026-10-11T12:00:03Z",
            "independent_witness": "approved-study-role",
        })
        value.update(changes)
        return value

    def valid(self, value):
        before = copy.deepcopy(value)
        result = VALIDATOR.validate_receipt(value)
        self.assertTrue(result["valid"])
        self.assertEqual(result["privacy_acceptance"], "not-established")
        self.assertIs(result["acceptance_established"], False)
        self.assertEqual(value, before)
        return result

    def invalid(self, value):
        result = VALIDATOR.validate_receipt(value)
        self.assertFalse(result["valid"])
        self.assertEqual(result["privacy_acceptance"], "not-established")
        return result

    def cli(self, raw=None, args=None):
        if args is None:
            source = self.base / "INVALID_PRIVATE_FILENAME.json"
            source.write_bytes(raw if raw is not None else json.dumps(self.receipt()).encode())
            args = [str(source)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = VALIDATOR.main(args)
        self.assertEqual(err.getvalue(), "")
        result = json.loads(out.getvalue())
        self.assertNotIn(str(self.base), out.getvalue())
        self.assertNotIn("INVALID_PRIVATE_FILENAME", out.getvalue())
        self.assertNotIn("study-" + "a" * 32, out.getvalue())
        self.assertNotIn("b" * 64, out.getvalue())
        return code, result, out.getvalue()

    def test_not_run_defaults_are_not_evidence(self):
        result = self.valid(self.receipt())
        self.assertEqual(result["status"], "not-run")
        self.assertEqual(result["capture_evidence"], "absent")
        self.assertIsNone(result["capture_elapsed_ms"])

    def test_refusal_is_valid_without_identity_or_success(self):
        result = self.valid(self.receipt(termination="refused"))
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["capture_evidence"], "absent")

    def test_refusal_cannot_carry_completed_run_counters(self):
        for field in ("attempts", "authenticated_sessions", "delivered_bytes", "traffic_bytes_total", "elapsed_ms"):
            with self.subTest(field=field):
                self.invalid(self.receipt(termination="refused", **{field: 1}))

    def test_no_run_cannot_claim_witness_or_rollback(self):
        self.invalid(self.receipt(independent_witness="approved-study-role"))
        self.invalid(self.receipt(rollback="restored"))

    def test_orphan_capture_confirmation_is_rejected(self):
        self.invalid(self.receipt(capture_confirmed_ready_at="2026-10-11T12:00:00Z"))
        self.invalid(self.changed_run(capture_confirmed_ready_at="2026-10-11T12:00:00Z"))

    def test_completed_record_without_capture_is_not_privacy_acceptance(self):
        result = self.valid(self.run_receipt())
        self.assertEqual(result["capture_evidence"], "absent")

    def test_unknown_missing_and_nonobject_records_are_rejected(self):
        value = self.receipt()
        value["UNAPPROVED_IDENTITY_FIELD"] = "INVALID_SECRET_MARKER"
        self.invalid(value)
        value = self.receipt()
        del value["release_sha256"]
        self.invalid(value)
        for value in (None, [], 1, "INVALID_SECRET_MARKER"):
            self.invalid(value)

    def test_boolean_is_not_version_or_integer_counter(self):
        self.invalid(self.receipt(schema_version=True))
        for field in ("attempts", "authenticated_sessions", "delivered_bytes", "traffic_bytes_total", "elapsed_ms"):
            with self.subTest(field=field):
                self.invalid(self.receipt(**{field: False}))

    def test_counter_negative_float_string_and_overlimit_are_rejected(self):
        caps = {"attempts": 2, "authenticated_sessions": 2, "delivered_bytes": 10485760, "traffic_bytes_total": 10485760, "elapsed_ms": 120000}
        for field, cap in caps.items():
            for value in (-1, 1.0, "1", cap + 1):
                with self.subTest(field=field, value=value):
                    self.invalid(self.changed_run(**{field: value}))

    def test_total_wire_traffic_includes_cover_and_cannot_be_less_than_payload(self):
        self.invalid(self.changed_run(traffic_bytes_total=1023))
        self.invalid(self.changed_run(delivered_bytes=1, traffic_bytes_total=10485761))
        self.valid(self.changed_run(delivered_bytes=0, traffic_bytes_total=10485760))

    def test_attempt_auth_and_delivery_counter_relations(self):
        self.invalid(self.changed_run(attempts=1, authenticated_sessions=2))
        self.invalid(self.changed_run(authenticated_sessions=0))
        self.valid(self.changed_run(attempts=2, authenticated_sessions=2))

    def test_binary_digest_is_exact_lowercase_sha256(self):
        for value in ("b" * 63, "b" * 65, "B" * 64, "z" * 64, "sha256:" + "b" * 64, None):
            with self.subTest(value=value):
                self.invalid(self.receipt(release_sha256=value))

    def test_attempt_identifier_cannot_carry_personal_data(self):
        for value in ("study-user@example.invalid", "study-127.0.0.1", "study-" + "a" * 31, "study-" + "A" * 32):
            with self.subTest(value=value):
                self.invalid(self.receipt(attempt_id=value))

    def test_coarse_labels_reject_addresses_urls_and_secret_strings(self):
        for field in ("profile_class", "environment_class", "network_cohort", "independent_witness"):
            for value in ("127.0.0.1", "user@example.invalid", "https://example.invalid/visited", "ghp_INVALID_SECRET_MARKER", "INVALID_DEVICE_ID"):
                with self.subTest(field=field, value=value):
                    self.invalid(self.receipt(**{field: value}))

    def test_publication_approval_is_boolean_and_never_accepts_privacy(self):
        for value in (0, 1, "yes", None):
            self.invalid(self.receipt(publication_approval=value))
        self.valid(self.captured_run(publication_approval=True))

    def test_timestamp_requires_utc_valid_calendar_and_millisecond_precision(self):
        for value in ("2026-10-11T12:00:00", "2026-10-11T12:00:00+01:00", "2026-02-30T12:00:00Z", "2026-10-11T12:00:00.0001Z", "2026-10-11T12:00:00Z\n", True):
            with self.subTest(value=value):
                self.invalid(self.changed_run(confirmed_ready_at=value))
        self.valid(self.changed_run(confirmed_ready_at="2026-10-11T12:00:00+00:00"))

    def test_start_end_are_paired_and_ordered(self):
        self.invalid(self.changed_run(started_at=None))
        self.invalid(self.changed_run(ended_at=None))
        self.invalid(self.changed_run(ended_at="2026-10-11T12:00:00Z"))

    def test_run_readiness_is_required_and_precedes_start(self):
        self.invalid(self.changed_run(confirmed_ready_at=None))
        self.invalid(self.changed_run(confirmed_ready_at="2026-10-11T12:00:02Z"))

    def test_elapsed_matches_full_run_and_duration_cap(self):
        self.invalid(self.changed_run(elapsed_ms=999))
        self.invalid(self.changed_run(ended_at="2026-10-11T12:00:01Z", elapsed_ms=0))
        self.valid(self.changed_run(ended_at="2026-10-11T12:02:01Z", elapsed_ms=120000))
        self.invalid(self.changed_run(ended_at="2026-10-11T12:02:02Z", elapsed_ms=120000))

    def test_completed_requires_authenticated_session_and_restored_rollback(self):
        self.invalid(self.changed_run(authenticated_sessions=0, delivered_bytes=0))
        self.invalid(self.changed_run(rollback="failed"))
        self.invalid(self.changed_run(rollback="not-run"))

    def test_stopped_and_failed_preserve_failure_status(self):
        for status in ("stopped", "failed"):
            result = self.valid(self.changed_run(termination=status, rollback="failed"))
            self.assertEqual(result["status"], status)
        self.valid(self.receipt(termination="failed"))

    def test_capture_confirmation_is_separate_from_run_readiness(self):
        self.invalid(self.captured_run(capture_confirmed_ready_at=None))
        self.invalid(self.captured_run(capture_confirmed_ready_at="2026-10-11T12:00:00Z"))
        self.invalid(self.captured_run(capture_confirmed_ready_at="2026-10-11T12:00:01Z"))

    def test_capture_pairs_order_and_independent_duration_cap(self):
        self.invalid(self.captured_run(capture_started_at=None))
        self.invalid(self.captured_run(capture_ended_at=None))
        self.invalid(self.captured_run(capture_ended_at="2026-10-11T11:59:59Z"))
        self.invalid(self.captured_run(capture_ended_at="2026-10-11T12:02:01Z"))

    def test_capture_duration_is_entire_recording_separate_from_confirmation(self):
        result = self.valid(self.captured_run())
        self.assertEqual(result["capture_elapsed_ms"], 3000)
        self.assertEqual(result["capture_evidence"], "full-interval-with-witness")
        self.assertNotEqual(result["capture_elapsed_ms"], self.run_receipt()["elapsed_ms"])

    def test_capture_cap_is_independent_of_short_application_run(self):
        result = self.valid(self.captured_run(capture_ended_at="2026-10-11T12:02:00Z"))
        self.assertEqual(result["capture_elapsed_ms"], 120000)
        self.assertEqual(result["capture_evidence"], "full-interval-with-witness")

    def test_short_capture_and_absent_witness_remain_partial(self):
        result = self.valid(self.captured_run(independent_witness="absent"))
        self.assertEqual(result["capture_evidence"], "partial")
        result = self.valid(self.captured_run(capture_ended_at="2026-10-11T12:00:01.500Z"))
        self.assertEqual(result["capture_evidence"], "partial")
        result = self.valid(self.captured_run(capture_started_at="2026-10-11T12:00:01.500Z"))
        self.assertEqual(result["capture_evidence"], "partial")

    def test_valid_cli_emits_aggregates_not_record_identifiers_or_paths(self):
        code, result, _ = self.cli()
        self.assertEqual(code, 0)
        self.assertTrue(result["valid"])
        self.assertEqual(result["privacy_acceptance"], "not-established")

    def test_cli_errors_are_generic_without_raw_untrusted_values(self):
        marker = "INVALID_SECRET_MARKER_123"
        for raw in (b"not-json", ("{\"private\":\"" + marker + "\"}").encode(), b"[", b"{\"attempts\": NaN}"):
            with self.subTest(raw=raw):
                code, result, out = self.cli(raw)
                self.assertNotEqual(code, 0)
                self.assertFalse(result["valid"])
                self.assertNotIn(marker, out)
        for args in ([], ["--INVALID_SECRET_MARKER"], ["/INVALID_SECRET_MARKER/missing.json"], ["one", "two"]):
            code, result, out = self.cli(args=args)
            self.assertNotEqual(code, 0)
            self.assertNotIn(marker, out)
            for argument in args:
                self.assertNotIn(argument, out)

    def test_cli_rejects_duplicate_keys_oversize_and_nonfinite_json(self):
        raw = json.dumps(self.receipt()).encode()
        for candidate in (b'{"schema_version":1,' + raw[1:], b" " * 65537, b'{"schema_version":Infinity}', b'{"schema_version":NaN}'):
            code, result, _ = self.cli(candidate)
            self.assertNotEqual(code, 0)
            self.assertFalse(result["valid"])

    def test_cli_refuses_symlink_input(self):
        source = self.base / "source.json"
        source.write_text(json.dumps(self.receipt()), encoding="utf-8")
        alias = self.base / "alias.json"
        alias.symlink_to(source)
        code, result, _ = self.cli(args=[str(alias)])
        self.assertNotEqual(code, 0)
        self.assertFalse(result["valid"])

    def test_cli_open_is_nonblocking_before_regular_file_check(self):
        # Do not create a FIFO: a bad implementation would hang the test itself.
        # Observe admission flags against an inert regular file instead.
        original = VALIDATOR.os.open
        flags_seen = []

        def observed(path, flags, *args, **kwargs):
            flags_seen.append(flags)
            return original(path, flags, *args, **kwargs)

        with patch.object(VALIDATOR.os, "open", observed):
            self.cli()
        self.assertTrue(flags_seen)
        self.assertTrue(all(flags & os.O_NONBLOCK for flags in flags_seen))
        self.assertTrue(all(flags & os.O_NOFOLLOW for flags in flags_seen))


if __name__ == "__main__":
    unittest.main()
