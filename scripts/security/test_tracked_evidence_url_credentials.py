#!/usr/bin/env python3
"""Synthetic regressions for historical URL-bearer containment."""
from pathlib import Path
import importlib.util
import contextlib
import io
from unittest import mock
from types import SimpleNamespace
import json
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("url_guard", Path(__file__).with_name("check-tracked-evidence-url-credentials.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class UrlGuardTests(unittest.TestCase):
    def scan(self, content, suffix=".raw"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = "scripts/tests/fixtures/evidence/SYNTHETIC_PATH/receipt" + suffix
            path = root / name
            path.parent.mkdir(parents=True)
            path.write_text(content)
            result = guard.scan(root, [name])
            self.assertNotIn("SYNTHETIC_PATH", json.dumps(result))
            self.assertNotIn("c0" * 32, json.dumps(result))
            return result

    def test_raw_log_and_stdout_bearer_rejected(self):
        for suffix in (".raw", ".log", ".stdout", ".txt"):
            self.assertEqual(self.scan("https://example.invalid/bundle?token=" + "c0" * 32, suffix)["findings"][0]["class"], "unredacted_url_credential")

    def test_percent_encoded_key_value_and_case_rejected(self):
        for query in ("%74oken=" + "c0" * 32, "ToKeN=%63%30", "access_token=c0"):
            self.assertTrue(self.scan("https://example.invalid/bundle?" + query)["findings"])

    def test_semantic_json_escaped_url_rejected(self):
        raw = '{"url":"https:\\u002f\\u002fexample.invalid/bundle?\\u0074oken=c0"}'
        self.assertTrue(self.scan(raw, ".json")["findings"])

    def test_semantic_json_escaped_url_in_nested_object_key_rejected(self):
        raw = r'{"nested":[{"https:\u002f\u002fexample.invalid/bundle?\u0074oken=c0":"value"}]}'
        self.assertTrue(self.scan(raw, ".json")["findings"])

    def test_inventory_non_utf8_refused_without_path_or_bytes(self):
        inventory = SimpleNamespace(returncode=0, stdout=b"scripts/tests/fixtures/evidence/SYNTHETIC_PATH/\xff.raw\x00")
        stdout = io.StringIO(); stderr = io.StringIO()
        with mock.patch.object(guard.subprocess, "run", return_value=inventory), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(guard.main(), 1)
        self.assertEqual(json.loads(stdout.getvalue())["error"], "inventory_unavailable")
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn("SYNTHETIC_PATH", stdout.getvalue())
        self.assertNotIn("\\xff", stdout.getvalue())

    def test_inventory_os_error_does_not_disclose_path(self):
        stdout = io.StringIO(); stderr = io.StringIO()
        with mock.patch.object(guard.subprocess, "run", side_effect=OSError("SYNTHETIC_PATH")), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(guard.main(), 1)
        self.assertEqual(json.loads(stdout.getvalue())["error"], "inventory_unavailable")
        self.assertNotIn("SYNTHETIC_PATH", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_redacted_and_empty_credentials_admitted(self):
        for query in ("token=", "token=REDACTED_BUNDLE_CREDENTIAL", "token=%5BREDACTED%5D", "token=REDACTED"):
            self.assertEqual(self.scan("https://example.invalid/bundle?" + query)["findings"], [])

    def test_pure_shell_query_template_admitted_but_literal_suffix_rejected(self):
        for value in ("${bundle_token}", "${bundle_token}${suffix}"):
            self.assertEqual(self.scan("https://example.invalid/bundle?token=" + value)["findings"], [])
        for value in ("${bundle_token}literal", "literal${bundle_token}", "${bundle_token}c0", "${bundle_token}\\x"):
            self.assertTrue(self.scan("https://example.invalid/bundle?token=" + value)["findings"])

    def test_escaped_shell_quote_after_redacted_value_admitted(self):
        content = "curl \\'https://example.invalid/bundle\\?token=REDACTED_BUNDLE_CREDENTIAL\\'"
        self.assertEqual(self.scan(content)["findings"], [])

    def test_false_redaction_prefix_rejected(self):
        self.assertTrue(self.scan("https://example.invalid/bundle?token=REDACTED.real-material")["findings"])

    def test_userinfo_and_invalid_authority_rejected(self):
        for url in ("https://synthetic@example.invalid/", "https://[invalid/bundle?token=c0"):
            self.assertTrue(self.scan(url)["findings"])

    def test_utf16_receipt_is_inspected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); name = "scripts/tests/fixtures/evidence/x/receipt.raw"
            path = root / name; path.parent.mkdir(parents=True)
            path.write_bytes("https://example.invalid/bundle?token=c0".encode("utf-16"))
            self.assertTrue(guard.scan(root, [name])["findings"])

    def test_binary_raw_ascii_bearer_is_rejected_without_disclosing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); name = "scripts/tests/fixtures/evidence/x/packet.raw"
            path = root / name; path.parent.mkdir(parents=True)
            path.write_bytes(b"\xff\x00 " + b"https://example.invalid/bundle?token=" + b"c0" * 32 + b" \xff")
            result = guard.scan(root, [name])
            self.assertEqual(result["raw_byte_scanned_files"], 1)
            self.assertEqual(result["findings"][0]["class"], "unredacted_url_credential")
            self.assertNotIn("c0" * 32, json.dumps(result))

    def test_binary_raw_no_url_marker_is_scanned_not_excluded(self):
        result = self.scan_binary(b"\xff\x00\xfe" + b"clienthello" + b"\x80")
        self.assertEqual(result["raw_byte_scanned_files"], 1)
        self.assertEqual(result["findings"], [])

    def test_binary_raw_malformed_and_utf16_no_bom_refuse(self):
        for payload in (
            b"\xff https://example.invalid/bundle?token=abc\xff",
            b"\xff " + "https://example.invalid/bundle?token=abc".encode("utf-16-le"),
            b"\xff https://[invalid/bundle?token=abc ",
        ):
            result = self.scan_binary(payload)
            self.assertEqual(result["raw_byte_scanned_files"], 1)
            self.assertTrue(result["findings"])

    def test_bomless_utf16_ascii_code_units_cannot_bypass_raw_byte_scan(self):
        literal = "https://example.invalid/bundle?token=" + "c0" * 32
        redacted = "https://example.invalid/bundle?token=REDACTED_BUNDLE_CREDENTIAL"
        for encoding in ("utf-16-le", "utf-16-be"):
            raw = literal.encode(encoding)
            self.assertEqual(raw.decode("utf-8").count("\x00") > 0, True)
            result = self.scan_binary(raw)
            self.assertEqual(result["raw_byte_scanned_files"], 1)
            self.assertEqual(result["non_utf8_raw_files"], 0)
            self.assertIn("unredacted_url_credential", [f["class"] for f in result["findings"]])
            self.assertNotIn("c0" * 32, json.dumps(result))
            safe = self.scan_binary(redacted.encode(encoding))
            self.assertEqual(safe["findings"], [])

    def test_utf16_bom_and_odd_alignment_keep_literal_detection(self):
        literal = "https://example.invalid/bundle?token=" + "c0" * 32
        redacted = "https://example.invalid/bundle?token=REDACTED_BUNDLE_CREDENTIAL"
        for bom, encoding in ((b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
            found = self.scan_binary(bom + literal.encode(encoding))
            self.assertIn("unredacted_url_credential", [f["class"] for f in found["findings"]])
            self.assertEqual(self.scan_binary(bom + redacted.encode(encoding))["findings"], [])
        shifted = self.scan_binary(b"\x00" + literal.encode("utf-16-le"))
        self.assertIn("unredacted_url_credential", [f["class"] for f in shifted["findings"]])

    def test_bomless_utf16_overlong_and_ambiguous_urls_refuse(self):
        for encoding in ("utf-16-le", "utf-16-be"):
            overlong = ("https://example.invalid/" + "a" * (guard.MAX_BINARY_URL_BYTES + 1)).encode(encoding)
            ambiguous = "https://example.invalid/bundle?token=abcé".encode(encoding)
            for payload in (overlong, ambiguous):
                result = self.scan_binary(payload)
                self.assertIn("malformed_url", [f["class"] for f in result["findings"]])

    def test_binary_raw_non_utf8_limit_refuses_unterminated_url(self):
        result = self.scan_binary(b"\xff https://example.invalid/" + b"a" * (guard.MAX_BINARY_URL_BYTES + 1))
        self.assertEqual(result["findings"][0]["class"], "malformed_url")

    def test_oversized_raw_is_a_failing_finding(self):
        result = self.scan_binary(b"x" * (guard.guard.MAX_TEXT_BYTES + 1))
        self.assertEqual(result["findings"][0]["class"], "oversized_raw_evidence")
        self.assertEqual(result["excluded_files"], 0)
        self.assertEqual(result["raw_byte_scanned_files"], 0)

    def test_dense_ascii_and_utf16_markers_hit_bounded_budget(self):
        dense_ascii = b"http:// " * (guard.MAX_BINARY_URL_CANDIDATES + 1)
        dense_utf16 = ("http:// ".encode("utf-16-le") *
                       (guard.MAX_BINARY_URL_CANDIDATES + 1))
        for payload in (dense_ascii, dense_utf16):
            result = self.scan_binary(payload)
            self.assertIn("binary_url_candidate_limit", [f["class"] for f in result["findings"]])

    def test_nested_fragment_url_rejected_in_ascii_and_utf16_raw(self):
        nested = "http://benign.invalid/#https://inner.invalid/bundle?token=synthetic "
        for payload in (b"\xff " + nested.encode("ascii"), nested.encode("utf-8"),
                        nested.encode("utf-16-le"), nested.encode("utf-16-be")):
            result = self.scan_binary(payload)
            self.assertIn("nested_url_marker", [f["class"] for f in result["findings"]])
            self.assertNotIn("synthetic", json.dumps(result))
        self.assertIn("nested_url_marker", [f["class"] for f in self.scan(nested, ".txt")["findings"]])

    def test_exact_shell_url_alternation_is_not_a_nested_url(self):
        self.assertEqual(self.scan("case x in http://*|https://*)", ".sh")["findings"], [])
        altered = "http://*|https://inner.invalid/bundle?token=synthetic)"
        self.assertIn("nested_url_marker", [f["class"] for f in self.scan(altered, ".sh")["findings"]])

    def test_raw_growth_after_stat_is_failing_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); name = "scripts/tests/fixtures/evidence/x/packet.raw"
            path = root / name; path.parent.mkdir(parents=True)
            path.write_bytes(b"x" * (guard.guard.MAX_TEXT_BYTES + 1))
            original_stat = Path.stat

            def stale_stat(candidate, *args, **kwargs):
                if candidate == path and kwargs.get("follow_symlinks", True):
                    return SimpleNamespace(st_size=0)
                return original_stat(candidate, *args, **kwargs)

            with mock.patch.object(Path, "stat", stale_stat):
                result = guard.scan(root, [name])
            self.assertEqual(result["findings"][0]["class"], "oversized_raw_evidence")

    def test_raw_read_error_reports_opaque_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); name = "scripts/tests/fixtures/evidence/x/packet.raw"
            path = root / name; path.parent.mkdir(parents=True)
            path.write_bytes(b"x")
            with mock.patch.object(Path, "open", side_effect=OSError("SYNTHETIC_SECRET")):
                result = guard.scan(root, [name])
            self.assertEqual(result["findings"][0]["class"], "unreadable_evidence")
            self.assertNotIn("SYNTHETIC_SECRET", json.dumps(result))

    def scan_binary(self, data):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); name = "scripts/tests/fixtures/evidence/x/packet.raw"
            path = root / name; path.parent.mkdir(parents=True)
            path.write_bytes(data)
            return guard.scan(root, [name])

    def test_exclusions_do_not_claim_history_or_revocation(self):
        report = self.scan("x" * (guard.guard.MAX_TEXT_BYTES + 1), ".txt")
        self.assertEqual(report["excluded_files"], 1)
        self.assertFalse(report["history_and_archive_scan_complete"])
        self.assertFalse(report["live_validity_or_revocation_verified"])


if __name__ == "__main__":
    unittest.main()
