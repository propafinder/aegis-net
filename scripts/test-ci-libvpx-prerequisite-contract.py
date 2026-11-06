#!/usr/bin/env python3
"""Guard source-pinned VPX setup before every CI all-features SFU build."""

import importlib.util
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
HELPER = ROOT / "scripts/qa/sfu-libvpx-native-r1.py"


def job(text, name):
    match = re.search(r"^  " + re.escape(name) + r":\s*$", text, re.M)
    assert match is not None, name
    next_job = re.search(r"^  [a-z][a-z0-9_-]*:\s*$", text[match.end():], re.M)
    return text[match.end():match.end() + next_job.start() if next_job else len(text)]


class NativeVpxPrerequisite(unittest.TestCase):
    def test_source_pinned_setup_precedes_all_features_in_three_jobs(self):
        workflow = WORKFLOW.read_text()
        for name in ("rust", "linux-arm64", "darwin-contract"):
            with self.subTest(job=name):
                body = job(workflow, name)
                first_all_features = body.find("--all-features")
                self.assertGreaterEqual(first_all_features, 0)
                preparation = body.find("- name: Prepare source-pinned libvpx 1.17.0")
                self.assertGreaterEqual(preparation, 0)
                self.assertLess(preparation, first_all_features)
                step = body[preparation:first_all_features]
                self.assertIn("sfu-libvpx-native-r1.py", step)
                self.assertIn("PKG_CONFIG_LIBDIR", step)
                self.assertIn("GITHUB_ENV", step)
                self.assertIn("refs/tags/v1.17.0", step)
                self.assertNotIn("continue-on-error: true", step)
                self.assertNotIn("|| true", step)

    def test_native_source_identity_and_windows_feature_scope(self):
        helper = HELPER.read_text()
        for literal in ('TAG = "v1.17.0"',
                        'TAG_OBJECT = "82615ff0733cd4063838c352bc2e2ab225f37ade"',
                        'COMMIT = "6df3ec34557879fff673706f4a1d9fbd0f3a6f0e"',
                        'TREE = "f83d33a1ba18b3a203e43596b5223042b62417a3"'):
            self.assertIn(literal, helper)
        for symbol in ("vpx_codec_vp8_cx", "vpx_codec_vp8_dx",
                       "vpx_codec_vp9_cx", "vpx_codec_vp9_dx"):
            self.assertIn(symbol, helper)
        self.assertIn('if sys.platform == "darwin"', helper)
        self.assertIn('"--defined-only"', helper)
        self.assertIn('os.environ.get("GITHUB_ACTIONS") != "true"', helper)
        self.assertIn('os.environ.get("RUNNER_TEMP") != str(root.parent)', helper)
        self.assertIn("os.WNOWAIT", helper)
        self.assertIn("live_group_members(child.pid)", helper)
        self.assertIn('"group_gone": True', helper)
        windows = job(WORKFLOW.read_text(), "windows-rust")
        self.assertNotIn("--all-features", windows)
        self.assertNotIn("sfu-media-vp8", windows)

    def test_native_child_group_closure(self):
        spec = importlib.util.spec_from_file_location("native_vpx", HELPER)
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        with tempfile.TemporaryDirectory(prefix="aegis-vpx-group-") as scratch:
            root = Path(scratch)
            logs = root / "logs"
            logs.mkdir()
            clean = native.run("clean", [sys.executable, "-c", "pass"], root,
                               os.environ.copy(), logs, 5, root, 0)
            self.assertEqual(clean["exit_code"], 0)
            self.assertTrue(clean["group_gone"])
            orphan = ('import subprocess,sys;'
                      'subprocess.Popen([sys.executable,"-c",'
                      '"import time;time.sleep(5)"])')
            with self.assertRaisesRegex(RuntimeError, "orphan_descendants_after_leader"):
                native.run("orphan", [sys.executable, "-c", orphan], root,
                           os.environ.copy(), logs, 5, root, 0)


if __name__ == "__main__":
    unittest.main()
