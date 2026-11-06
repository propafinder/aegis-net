#!/usr/bin/env bash
# Actual source-contract fixtures only; no compiler, wire traffic or upstream test.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 -I - "$ROOT/scripts/test-h2-pseudo-header-order-contract.sh" "$ROOT/Cargo.toml" <<'PY_FIXTURES'
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

contract = Path(sys.argv[1]).read_bytes()
current_manifest = Path(sys.argv[2]).read_text(encoding="utf-8")
reviewed_headers = "// AEGIS PATCH fixture\npseudo.authority.take();\npseudo.scheme.take();\n"

class ManifestContract(unittest.TestCase):
    def run_case(self, manifest, expected, headers=reviewed_headers):
        with tempfile.TemporaryDirectory(prefix="aegis-h2-manifest-contract-") as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "third_party/h2/src/frame").mkdir(parents=True)
            path = root / "scripts/test-h2-pseudo-header-order-contract.sh"
            path.write_bytes(contract)
            (root / "Cargo.toml").write_text(manifest, encoding="utf-8")
            (root / "third_party/h2/src/frame/headers.rs").write_text(headers, encoding="utf-8")
            completed = subprocess.run(["bash", str(path)], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertLess(len(completed.stdout) + len(completed.stderr), 8192)
            self.assertEqual(completed.returncode, expected)

    def test_actual_current_manifest_with_version(self):
        self.run_case(current_manifest, 0)

    def test_valid_semantic_patch_forms(self):
        for manifest in [
            '[patch.crates-io]\nh2 = { path = "third_party/h2" }\n',
            '[patch.crates-io]\nh2 = { package = "h2", version = "0.4.16", path = "third_party/h2" }\n',
            '[patch.crates-io]\nh2 = { path = "third_party/h2", version = "0.4.16" }\n',
            '[patch.crates-io.h2]\nversion = "0.4.16"\npath = "./third_party/h2"\n',
        ]:
            with self.subTest(manifest=manifest):
                self.run_case(manifest, 0)

    def test_wrong_path_comment_and_other_section_do_not_patch_h2(self):
        for manifest in [
            '[patch.crates-io]\nh2 = { path = "elsewhere" }\n',
            '# h2 = { path = "third_party/h2" }\n[package]\nname = "fixture"\n',
            '[dependencies]\nh2 = { path = "third_party/h2" }\n',
            '[patch.crates-io]\nh2 = { path = "elsewhere" } # h2 = { path = "third_party/h2" }\n',
            '[patch.crates-io]\nh2 = "0.4.16"\n',
            '[patch.crates-io]\nh2 = { package = "other-package", path = "third_party/h2" }\n',
        ]:
            with self.subTest(manifest=manifest):
                self.run_case(manifest, 1)

    def test_malformed_toml_refuses(self):
        self.run_case('[patch.crates-io]\nh2 = { path = "third_party/h2" }\nbroken = [\n', 1)

    def test_upstream_header_order_and_missing_marker_refuse(self):
        valid = '[patch.crates-io]\nh2 = { path = "third_party/h2" }\n'
        self.run_case(valid, 1, '// AEGIS PATCH fixture\npseudo.scheme.take();\npseudo.authority.take();\n')
        self.run_case(valid, 1, 'pseudo.authority.take();\npseudo.scheme.take();\n')

unittest.main(argv=["h2 manifest contract fixtures"])
PY_FIXTURES
