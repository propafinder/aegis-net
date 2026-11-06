#!/usr/bin/env python3
"""Synthetic credential containment and redacted-diagnostic contracts."""
from pathlib import Path
import importlib.util
import json
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("evidence_guard", Path(__file__).with_name("check-tracked-evidence-secrets.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class EvidenceGuardTests(unittest.TestCase):
    def check(self, content, name="scripts/tests/fixtures/evidence/fixture/client.toml"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / name
            path.parent.mkdir(parents=True)
            path.write_text(content)
            return guard.scan(root, [name])

    def test_live_shaped_toml_and_json_rejected_without_value_in_diagnostic(self):
        value = "c0" * 32  # Synthetic, never used as a credential.
        for content in (f'auth_token = "{value}"', f'{{"auth_token": "{value}"}}'):
            report = self.check(content)
            self.assertEqual(report["findings"][0]["kind"], "unredacted_relay_credential")
            self.assertNotIn(value, json.dumps(report))

    def test_private_url_and_key_rejected_without_contents(self):
        for name, content, kind in (
            ("scripts/tests/fixtures/evidence/x/bundle-url.private", "https://example.invalid/private/SYNTHETIC", "private_bundle_url"),
            ("scripts/tests/fixtures/evidence/x/key.pem", "-----BEGIN PRIVATE KEY-----\nSYNTHETIC", "private_key_material"),
            ("scripts/tests/fixtures/evidence/x/.env.local", "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC", "private_key_material"),
        ):
            report = self.check(content, name)
            self.assertEqual(report["findings"][0]["kind"], kind)
            self.assertNotIn("SYNTHETIC", json.dumps(report))

    def test_semantic_toml_quoted_keys_and_multiline_values_are_rejected(self):
        value = "c0" * 32
        for key in ('auth_token', '"auth_token"', "'auth_token'", '"\\u0061uth_token"'):
            for quoted in ('"' + value + '"', "'" + value + "'",
                           '"""\n' + value + '"""', "'''\n" + value + "'''"):
                report = self.check('[relay]\n' + key + ' = ' + quoted + '\n')
                self.assertTrue(report["findings"], "valid TOML credential must be refused")
                self.assertNotIn(value, json.dumps(report))

    def test_semantic_json_escaped_keys_and_values_are_rejected(self):
        value = "c0" * 32
        encoded = '{"relay":{"\\u0061uth_token":"' + value + '"}}'
        report = self.check(encoded, "scripts/tests/fixtures/evidence/fixture/client.json")
        self.assertTrue(report["findings"])
        self.assertNotIn(value, json.dumps(report))

    def test_explicit_redactions_and_empty_token_admitted(self):
        for content in ('auth_token = ""', 'auth_token="REDACTED_RELAY_CREDENTIAL"', 'auth_token="<REDACTED>"'):
            self.assertEqual(self.check(content)["findings"], [])
        report = self.check("https://redacted.invalid/private-bundle-url-removed", "scripts/tests/fixtures/evidence/x/bundle-url.private")
        self.assertEqual(report["findings"], [])

    def test_misleading_redaction_prefix_not_admitted(self):
        self.assertTrue(self.check('auth_token="REDACTED_followed.by.real.material"')["findings"])

    def test_parser_source_is_not_mistaken_for_a_literal_configuration(self):
        self.assertEqual(self.check("token = text.split('auth_token = \\\"').split('\\\"')[0]", "scripts/tests/fixtures/evidence/x/parser.py")["findings"], [])
        self.assertEqual(self.check('auth_token="${AEGIS_TEST_AUTH_TOKEN}"', "scripts/tests/fixtures/evidence/x/template.sh")["findings"], [])
        self.assertTrue(self.check('auth_token="secret-${AEGIS_TEST_AUTH_TOKEN}"', "scripts/tests/fixtures/evidence/x/template.sh")["findings"])

    def test_windows_unicode_configuration_is_inspected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "scripts/tests/fixtures/evidence/x/client.log"
            path.parent.mkdir(parents=True)
            path.write_bytes(('auth_token = "' + "c0" * 32 + '"').encode("utf-16"))
            self.assertEqual(guard.scan(root, ["scripts/tests/fixtures/evidence/x/client.log"])["findings"][0]["kind"], "unredacted_relay_credential")

    def test_excluded_large_content_is_reported_not_a_history_claim(self):
        report = self.check("x" * (guard.MAX_TEXT_BYTES + 1))
        self.assertEqual(report["inspected_files"], 0)
        self.assertEqual(report["excluded_binary_large_or_other_files"], 1)
        self.assertFalse(report["history_archives_and_credential_revocation_verified"])


if __name__ == "__main__":
    unittest.main()
