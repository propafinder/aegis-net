#!/usr/bin/env python3
"""Inert input-identity contracts for the ARM64/MSVC Clang overlay."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("prepare-arm64-clang-neon.py")
SPEC = importlib.util.spec_from_file_location("arm64_clang_neon", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OverlayContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="aegis-arm64-neon-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.resource = self.root / "resource"
        self.headers = self.resource / "include"
        self.headers.mkdir(parents=True)
        self.xwin_root = self.root / "xwin-root"
        header_names = (
            "intrin.h", "intrin0.h", "arm64intr.h", "arm_neon.h",
            "arm_vector_types.h", "arm_bf16.h",
        )
        xwin_names = (
            "crt/include/intrin.h", "crt/include/arm64_neon.h",
            "sdk/lib/um/aarch64/kernel32.lib",
        )
        header_hashes = {}
        for name in header_names:
            path = self.headers / name
            path.write_text("Clang fixture " + name)
            header_hashes[name] = MODULE.sha256(path)
        for name in xwin_names:
            path = self.xwin_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("xwin fixture " + name)
        for directory in (
            "sdk/include/ucrt", "sdk/include/shared", "sdk/include/um",
            "crt/include", "sdk/lib/ucrt/aarch64", "crt/lib/aarch64",
        ):
            (self.xwin_root / directory).mkdir(parents=True, exist_ok=True)
        self.manifest = self.root / "inputs.json"
        self.manifest.write_text(json.dumps({
            "clang_version": "21.1.8",
            "xwin_version": "0.10.0",
            "clang_headers": header_hashes,
            "xwin_tree_sha256": MODULE.tree_sha256(self.xwin_root),
        }))
        self.clang = self.root / "clang"
        self.clang.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = --version ]; then echo 'Homebrew clang version 21.1.8'; "
            "elif [ \"$1\" = -print-resource-dir ]; then echo '" + str(self.resource) + "'; "
            "else exit 17; fi\n"
        )
        self.clang.chmod(0o700)
        self.xwin = self.root / "xwin"
        self.xwin.write_text("#!/bin/sh\necho 'xwin 0.10.0'\n")
        self.xwin.chmod(0o700)

    def prepare(self, name):
        return MODULE.prepare(self.manifest, self.clang, self.xwin, self.xwin_root, self.root / name)

    def test_valid_inputs_create_matching_overlay_and_wrapper(self):
        wrapper = self.prepare("valid")
        self.assertTrue(wrapper.is_file())
        self.assertTrue((wrapper.parent / "headers/arm_neon.h").is_symlink())
        contents = wrapper.read_text()
        self.assertIn("--target=aarch64-pc-windows-msvc", contents)
        self.assertIn(str(wrapper.parent / "headers"), contents)
        self.assertNotIn("-U__ARM_NEON", contents)
        self.assertTrue((wrapper.parent / "verified-inputs.json").is_file())

    def test_changed_clang_header_refuses_before_writing(self):
        (self.headers / "arm_neon.h").write_text("changed")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.prepare("changed")
        self.assertFalse((self.root / "changed").exists())

    def test_changed_xwin_input_refuses_before_writing(self):
        (self.xwin_root / "crt/include/arm64_neon.h").write_text("changed")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.prepare("changed")
        self.assertFalse((self.root / "changed").exists())

    def test_unlisted_xwin_input_refuses_before_writing(self):
        (self.xwin_root / "sdk/include/um/other.h").write_text("changed outside sampled headers")
        with self.assertRaisesRegex(ValueError, "tree hash mismatch"):
            self.prepare("changed-unlisted")
        self.assertFalse((self.root / "changed-unlisted").exists())

    def test_version_or_nonempty_output_refuses(self):
        self.xwin.write_text("#!/bin/sh\necho 'xwin 0.11.0'\n")
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            self.prepare("wrong-version")
        self.xwin.write_text("#!/bin/sh\necho 'xwin 0.10.0'\n")
        occupied = self.root / "occupied"
        occupied.mkdir()
        (occupied / "existing").write_text("keep")
        with self.assertRaisesRegex(ValueError, "must be empty"):
            self.prepare("occupied")
        self.assertEqual((occupied / "existing").read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
