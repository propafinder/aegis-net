"""Inert Cargo JSON and target-runner admission checks; no native build."""

import importlib.util
import json
from pathlib import Path
import tomllib
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "qa/prepare-darwin-test-task-runner-r1.py"
SPEC = importlib.util.spec_from_file_location("darwin_preparer", SOURCE)
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
MANIFEST = Path("/private/tmp/source/tools/macos/aegis-network-extension/Cargo.toml")
EXE = "/private/tmp/target/aarch64-apple-darwin/debug/deps/aegis_network_extension-0123abcd"


def artifact(*, name=PREP.TARGET_NAME, kind=None, manifest=MANIFEST,
             test=True, executable=EXE, opt_level="0", debug_assertions=True,
             overflow_checks=True):
    return {"reason": "compiler-artifact", "manifest_path": str(manifest),
            "target": {"name": name, "kind": ["lib"] if kind is None else kind},
            "profile": {"test": test, "opt_level": opt_level, "debuginfo": 0,
                        "debug_assertions": debug_assertions, "overflow_checks": overflow_checks},
            "executable": executable}


class PreparerAdmissionTests(unittest.TestCase):
    def test_exact_one_test_lib_artifact_and_unrelated_build_are_allowed(self):
        data = "\n".join(json.dumps(row) for row in
                         ({"reason": "build-finished", "success": True},
                          artifact(test=False), artifact()))
        self.assertEqual(PREP.select_test_artifact(data, MANIFEST), Path(EXE))

    def test_zero_duplicate_wrong_manifest_kind_and_profile_refuse(self):
        cases = ([], [artifact(), artifact()],
                 [artifact(manifest=Path("/private/tmp/other/Cargo.toml"))],
                 [artifact(kind=["bin"])], [artifact(test=False)],
                 [artifact(name="other")], [artifact(executable=None)],
                 [artifact(test=1)], [artifact(test="yes")], [artifact(test=None)])
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                PREP.select_test_artifact("\n".join(json.dumps(r) for r in rows),
                                          MANIFEST)
        with self.assertRaises(RuntimeError):
            PREP.select_test_artifact("{invalid", MANIFEST)

    def test_optimized_profile_keeps_both_safety_checks_and_exact_artifact(self):
        record = artifact(opt_level="1")
        path, profile = PREP.select_test_record(json.dumps(record), MANIFEST, "1")
        self.assertEqual(path, Path(EXE))
        self.assertEqual(profile, record["profile"])
        for changed in (artifact(opt_level="0"), artifact(opt_level="3"),
                        artifact(opt_level="1", debug_assertions=False),
                        artifact(opt_level="1", overflow_checks=False),
                        artifact(opt_level="1", debug_assertions=1),
                        artifact(opt_level="1", overflow_checks="true")):
            with self.subTest(profile=changed["profile"]), self.assertRaises(RuntimeError):
                PREP.select_test_record(json.dumps(changed), MANIFEST, "1")
        with self.assertRaises(RuntimeError):
            PREP.select_test_record(json.dumps(record), MANIFEST, "3")

    def test_config_preserves_original_cargo_appended_argv(self):
        argv = PREP.runner_array("/usr/bin/python3", Path("/tmp/runner.py"),
                                 Path("/tmp/repo"), "a" * 40,
                                 Path("/tmp/source-manifest.json"), "b" * 64,
                                 "c" * 64, Path("/tmp/execution"),
                                 Path("/tmp/lib.dylib"), "d" * 64,
                                 Path("/tmp/target/aarch64-apple-darwin/debug/deps"),
                                 "e" * 64)
        self.assertEqual(argv[-1], "--")
        self.assertEqual(argv[:3], ["/usr/bin/python3", "-I", "-B"])
        self.assertEqual(argv[argv.index("--mode") + 1], "normalize")
        text = PREP.config_text("aarch64-apple-darwin", argv)
        self.assertEqual(tomllib.loads(text)["target"]["aarch64-apple-darwin"]["runner"],
                         argv)
        self.assertIn('runner=["/usr/bin/python3","-I","-B"', text)
        self.assertTrue(text.endswith(',"--"]\n'))
        for bad in ("aarch64-apple-linux", "../../bad", "AARCH64-apple-darwin"):
            with self.subTest(host=bad), self.assertRaises(RuntimeError):
                PREP.config_text(bad, argv)


if __name__ == "__main__":
    unittest.main()
