#!/usr/bin/env python3
"""Inert ZIP tamper controls for the unsigned Windows kit handoff."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

MODULE = Path(__file__).with_name("verify-unsigned-kit-archive.py")
SPEC = importlib.util.spec_from_file_location("kit_archive", MODULE)
kit_archive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kit_archive)
SOURCE = "a" * 40


def sha(data):
    return hashlib.sha256(data).hexdigest()


class KitArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-kit-zip-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, *, research=False, change=None):
        files = {name: name.encode() for name in kit_archive.BASE}
        if research:
            files.update({name: name.encode() for name in kit_archive.RESEARCH})
        manifest = {
            "schema": 4 if research else 2,
            "platform": "windows-x86_64" if research else "windows-aarch64",
            "source_commit": SOURCE,
            "signed_release": False,
            "project_licenses": True,
            "files": {name: sha(data) for name, data in files.items()},
        }
        raw = json.dumps(manifest, sort_keys=True).encode()
        members = {**files, "manifest.json": raw}
        if change:
            change(members, manifest)
        path = self.root / "candidate.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)
        return path, sha(raw)

    def test_arm64_and_research_archives_pass_exact_bytes(self):
        for research in (False, True):
            with self.subTest(research=research):
                path, digest = self.fixture(research=research)
                result = kit_archive.verify(path, SOURCE, digest, research)
                self.assertEqual(result["archive_sha256"], sha(path.read_bytes()))
                self.assertEqual(result["manifest_sha256"], digest)
                self.assertEqual(
                    result["platform"],
                    "windows-x86_64" if research else "windows-aarch64",
                )

    def test_same_length_payload_swap_refused(self):
        path, digest = self.fixture(
            change=lambda members, _: members.__setitem__("aegis-client.exe", b"X" * len(members["aegis-client.exe"]))
        )
        with self.assertRaisesRegex(ValueError, "payload digest mismatch"):
            kit_archive.verify(path, SOURCE, digest, False)

    def test_unknown_member_refused(self):
        path, digest = self.fixture(
            change=lambda members, _: members.__setitem__("unlisted.txt", b"x")
        )
        with self.assertRaisesRegex(ValueError, "member count refused"):
            kit_archive.verify(path, SOURCE, digest, False)

    def test_duplicate_member_refused(self):
        path, digest = self.fixture()
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("README.txt", b"duplicate")
        with self.assertRaisesRegex(ValueError, "member count refused"):
            kit_archive.verify(path, SOURCE, digest, False)

    def test_changed_manifest_and_source_refused(self):
        path, digest = self.fixture()
        with self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
            kit_archive.verify(path, SOURCE, "b" * 64, False)
        with self.assertRaisesRegex(ValueError, "manifest identity refused"):
            kit_archive.verify(path, "b" * 40, digest, False)

    def test_research_architecture_and_flag_refused(self):
        path, digest = self.fixture(research=True)
        with self.assertRaisesRegex(ValueError, "member count refused"):
            kit_archive.verify(path, SOURCE, digest, False)
        def change(members, manifest):
            manifest["platform"] = "windows-aarch64"
            members["manifest.json"] = json.dumps(manifest, sort_keys=True).encode()
        path, _ = self.fixture(research=True, change=change)
        digest = sha(zipfile.ZipFile(path).read("manifest.json"))
        with self.assertRaisesRegex(ValueError, "manifest identity refused"):
            kit_archive.verify(path, SOURCE, digest, True)

    def test_cli_tamper_exit_is_nonzero(self):
        path, digest = self.fixture(
            change=lambda members, _: members.__setitem__("wintun.dll", b"tampered")
        )
        run = subprocess.run(
            [sys.executable, "-I", "-B", str(MODULE), "--archive", str(path),
             "--source-commit", SOURCE, "--manifest-sha256", digest],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(run.returncode, 1)
        self.assertIn("payload digest mismatch", run.stderr)
        self.assertEqual(run.stdout, "")

    def test_cli_positive_reports_verified_archive_hash(self):
        path, digest = self.fixture()
        run = subprocess.run(
            [sys.executable, "-I", "-B", str(MODULE), "--archive", str(path),
             "--source-commit", SOURCE, "--manifest-sha256", digest],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["archive_sha256"], sha(path.read_bytes()))

    @unittest.skipUnless(os.name == "nt", "Windows sharing semantics")
    def test_held_archive_refuses_writer_and_replacement(self):
        path, _ = self.fixture()
        replacement = self.root / "replacement.zip"
        replacement.write_bytes(b"replacement")
        with kit_archive._held_read(path) as held:
            with self.assertRaises(OSError):
                with open(path, "r+b") as writer:
                    writer.write(b"X")
            with self.assertRaises(OSError):
                os.replace(replacement, path)
            self.assertEqual(held.read(2), b"PK")


if __name__ == "__main__":
    unittest.main()
