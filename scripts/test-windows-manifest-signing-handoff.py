#!/usr/bin/env python3
"""Real offline handoff verifier with inert ZIP data; no Authenticode acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts/verify-windows-manifest-signing-handoff.py"
ABSENT = object()
LICENSES = ("LICENSE-MIT", "LICENSE-APACHE", "NOTICE")
SOURCE = "a" * 40
WORKFLOW = "example-org/aegis:.github/workflows/windows-package.yml"
REF = "refs/heads/main"


class WindowsManifestHandoff(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-inert-manifest-handoff-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.case_number = 0

    def fixture(self, schema=3, declaration=ABSENT, licenses=None,
                omit=(), tamper=None, mutate=None, duplicate=None,
                notice_mode=None, mixed_manifest=False):
        self.case_number += 1
        directory = self.base / str(self.case_number)
        directory.mkdir()
        names = ["README.txt", "WINTUN-LICENSE.txt", "aegis-client.exe", "aegis-winctl.exe", "wintun.dll"]
        if schema == 5:
            names += ["aegis-measure.exe", "aegis-transport-lab.exe", "research-operators.json"]
        if licenses is None:
            licenses = declaration is True
        if licenses:
            names += list(LICENSES)
        contents = {name: ("INERT_NOT_SIGNED_DATA:" + name + "\n").encode() for name in names}
        manifest = {"schema": schema, "platform": "windows-x86_64", "source_commit": SOURCE,
                    "signed_release": True, "authenticode": {},
                    "files": {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}}
        if declaration is not ABSENT:
            manifest["project_licenses"] = declaration
        handoff = {"schema": "aegis_windows_authenticode_handoff_v1", "source_commit": SOURCE,
                   "workflow": WORKFLOW, "ref": REF, "archive": "windows-signed-release.zip",
                   "signed_release": False, "manifest_signature_status": "required_external_sidecar"}
        if mutate:
            mutate(manifest, contents, handoff)
        raw = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        (directory / "manifest.json").write_bytes(raw)
        # Trusted archive/handoff pins are deliberately recomputed after any
        # archive mutation so a failure demonstrates the license contract,
        # not merely rejection at the earlier outer ZIP digest check.
        import warnings
        import zipfile
        archive = directory / handoff["archive"]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(archive, "w") as stream:
                for name, data in contents.items():
                    if name not in omit:
                        entry = name
                        if name == "NOTICE" and notice_mode is not None:
                            entry = zipfile.ZipInfo(name)
                            entry.create_system = 3
                            entry.external_attr = notice_mode << 16
                        stream.writestr(entry, data + b"TAMPER" if name == tamper else data)
                stream.writestr("manifest.json", b" " + raw if mixed_manifest else raw)
                if duplicate:
                    stream.writestr(duplicate, contents[duplicate])
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        handoff["archive_sha256"] = digest
        handoff["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        (directory / "handoff.json").write_text(json.dumps(handoff), encoding="utf-8")
        return directory, digest

    def verify(self, prepared, expected_source=SOURCE, digest=None):
        directory, actual_digest = prepared
        provenance = directory / "provenance.json"
        result = subprocess.run(
            [sys.executable, "-I", str(VERIFIER),
             "--manifest", str(directory / "manifest.json"),
             "--archive", str(directory / "windows-signed-release.zip"),
             "--handoff", str(directory / "handoff.json"),
             "--expected-source", expected_source,
             "--expected-workflow", WORKFLOW, "--expected-ref", REF,
             "--expected-inner-zip-sha256", actual_digest if digest is None else digest,
             "--expected-github-artifact-digest", "c" * 64,
             "--provenance-output", str(provenance)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=5, check=False,
        )
        return result, provenance

    def accepted(self, prepared):
        result, provenance = self.verify(prepared)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"bounded Windows manifest signing handoff: PASS", result.stdout)
        record = json.loads(provenance.read_text())
        self.assertEqual(record["source_commit"], SOURCE)
        self.assertEqual(record["inner_zip_sha256"], prepared[1])
        self.assertEqual(record["github_artifact_digest"], "c" * 64)
        self.assertNotEqual(record["inner_zip_sha256"], record["github_artifact_digest"])

    def rejected(self, prepared, expected_reason=None, **kwargs):
        result, provenance = self.verify(prepared, **kwargs)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(provenance.exists(), "Refusal must precede provenance output")
        self.assertNotIn(b"bounded Windows manifest signing handoff: PASS", result.stdout)
        if expected_reason:
            self.assertIn(expected_reason.encode(), result.stderr)

    def test_legacy_absent_or_false_keeps_closed_six_and_nine_entries(self):
        for schema in (3, 5):
            for declaration in (ABSENT, False):
                with self.subTest(schema=schema, declaration=declaration):
                    self.accepted(self.fixture(schema=schema, declaration=declaration))

    def test_legacy_minimal_metadata_behavior_is_preserved(self):
        def legacy_minimal(manifest, contents, handoff):
            manifest["files"] = {}
            manifest.pop("authenticode")
            manifest.pop("platform")
        self.accepted(self.fixture(mutate=legacy_minimal))

    def test_licensed_schema_three_and_five_pass_real_verifier(self):
        for schema in (3, 5):
            with self.subTest(schema=schema):
                self.accepted(self.fixture(schema=schema, declaration=True))

    def test_each_license_missing_from_zip_is_rejected(self):
        for schema in (3, 5):
            for name in LICENSES:
                with self.subTest(schema=schema, name=name):
                    self.rejected(self.fixture(schema=schema, declaration=True, omit=(name,)), "unexpected ZIP file set")

    def test_each_tampered_license_refused_despite_matching_outer_archive_pin(self):
        for name in LICENSES:
            with self.subTest(name=name):
                self.rejected(self.fixture(declaration=True, tamper=name), "project license ZIP digest mismatch")

    def test_flag_absent_and_false_do_not_admit_license_extras(self):
        for schema in (3, 5):
            for declaration in (ABSENT, False):
                with self.subTest(schema=schema, declaration=declaration):
                    self.rejected(self.fixture(schema=schema, declaration=declaration, licenses=True), "unexpected ZIP file set")

    def test_license_declaration_requires_actual_boolean(self):
        for declaration in (None, 0, 1, "true", "false", [], {}):
            with self.subTest(declaration=declaration):
                self.rejected(self.fixture(declaration=declaration, licenses=False), "license declaration must be boolean")

    def test_licensed_manifest_rejects_unknown_or_missing_top_fields(self):
        def extra(manifest, contents, handoff):
            manifest["unapproved_extra"] = "inert"
        def missing(manifest, contents, handoff):
            manifest.pop("authenticode")
        for change in (extra, missing):
            self.rejected(self.fixture(declaration=True, mutate=change), "manifest schema fields rejected")

    def test_each_license_requires_manifest_digest_entry(self):
        for name in LICENSES:
            def change(manifest, contents, handoff, name=name):
                del manifest["files"][name]
            self.rejected(self.fixture(declaration=True, mutate=change), "licensed manifest payload inventory rejected")

    def test_licensed_manifest_file_inventory_is_closed(self):
        def extra(manifest, contents, handoff):
            manifest["files"]["unexpected.txt"] = "d" * 64
        def wrong_type(manifest, contents, handoff):
            manifest["files"] = []
        for change in (extra, wrong_type):
            self.rejected(self.fixture(declaration=True, mutate=change), "licensed manifest payload inventory rejected")

    def test_license_digest_requires_lowercase_hex_string(self):
        for digest in (None, True, "b" * 63, "B" * 64, "z" * 64):
            def change(manifest, contents, handoff, digest=digest):
                manifest["files"]["NOTICE"] = digest
            self.rejected(self.fixture(declaration=True, mutate=change), "project license manifest digest rejected")

    def test_unrelated_extra_zip_entry_is_never_admitted(self):
        for declaration in (ABSENT, False, True):
            def change(manifest, contents, handoff):
                contents["unexpected.txt"] = b"inert"
            self.rejected(self.fixture(declaration=declaration, mutate=change), "unexpected ZIP file set")

    def test_duplicate_license_zip_member_is_not_admitted(self):
        self.rejected(self.fixture(declaration=True, duplicate="NOTICE"), "unexpected ZIP file set")

    def test_license_zip_entry_cannot_be_symlink_or_directory(self):
        for mode in (0o120777, 0o040755):
            self.rejected(self.fixture(declaration=True, notice_mode=mode), "project license ZIP entry rejected")

    def test_archive_manifest_must_match_standalone_bytes(self):
        self.rejected(self.fixture(declaration=True, mixed_manifest=True), "archive/manifest mix")

    def test_empty_and_oversized_license_payloads_are_rejected(self):
        for payload in (b"", b"x" * (2 * 1024 * 1024 + 1)):
            def change(manifest, contents, handoff, payload=payload):
                contents["NOTICE"] = payload
                manifest["files"]["NOTICE"] = hashlib.sha256(payload).hexdigest()
            self.rejected(self.fixture(declaration=True, mutate=change), "project license ZIP entry rejected")

    def test_trusted_source_and_archive_pin_remain_required(self):
        self.rejected(self.fixture(declaration=True), "identity rejected", expected_source="d" * 40)
        self.rejected(self.fixture(declaration=True), "trusted inner ZIP digest", digest="d" * 64)

    def test_handoff_sidecar_and_signed_manifest_semantics_are_unchanged(self):
        def manifest_unsigned(manifest, contents, handoff):
            manifest["signed_release"] = False
        def handoff_signed(manifest, contents, handoff):
            handoff["signed_release"] = True
        def wrong_sidecar(manifest, contents, handoff):
            handoff["manifest_signature_status"] = "not-required"
        for change in (manifest_unsigned, handoff_signed, wrong_sidecar):
            self.rejected(self.fixture(declaration=True, mutate=change), "identity rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, default=VERIFIER,
                        help="Frozen old/candidate handoff verifier path")
    args, rest = parser.parse_known_args()
    VERIFIER = args.verifier.resolve()
    unittest.main(argv=[sys.argv[0], *rest])
