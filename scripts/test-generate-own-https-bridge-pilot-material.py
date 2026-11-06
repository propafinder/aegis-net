#!/usr/bin/env python3
"""Inert source and exclusive-private-output contracts for pilot material."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("generate-own-https-bridge-pilot-material.py")
SPEC = importlib.util.spec_from_file_location("ownbridge_material", SCRIPT)
MATERIAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIAL)
ROOT = Path(__file__).resolve().parents[1]
SOURCE = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                 text=True).strip()


class PrivateMaterialContract(unittest.TestCase):
    def test_clean_exact_source_and_stale_refusal(self):
        MATERIAL.source_bound(SOURCE)
        with self.assertRaisesRegex(ValueError, "source_checkout_or_generator_not_exact"):
            MATERIAL.source_bound("513794265f0ad74fcf0c9f43553c8635fa4a642b")

    def test_new_private_output_and_symlink_parent_refusal(self):
        with tempfile.TemporaryDirectory(prefix="aegis-ownbridge-material-unit-",
                                         dir="/private/tmp") as scratch:
            parent = Path(scratch)
            os.chmod(parent, 0o700)
            stage = MATERIAL.PrivateStage(parent / "fresh")
            try:
                stage.mkdir("private")
                stage.mkdir("private/relay")
                self.assertEqual(stage.path("private/relay/pin.hex"),
                                 "private/relay/pin.hex")
                stage.write_new("private/relay/pin.hex", b"public-test-only")
                self.assertEqual(stage.read("private/relay/pin.hex"), b"public-test-only")
                stage.finish()
            finally:
                stage.close()
            with self.assertRaisesRegex(ValueError, "fresh_private_output_required"):
                MATERIAL.PrivateStage(parent / "fresh")
            (parent / "linked").symlink_to(parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "fresh_private_output_required"):
                MATERIAL.PrivateStage(parent / "linked" / "redirected")
            os.chmod(parent, 0o755)
            with self.assertRaisesRegex(ValueError, "private_parent_required"):
                MATERIAL.PrivateStage(parent / "public")


if __name__ == "__main__":
    unittest.main()
