#!/usr/bin/env python3
"""Exercise the real CI roster gate with a fake Cargo; no database or Rust build."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]


def integration_step():
    source = (ROOT / ".github/workflows/ci.yml").read_text()
    marker = "      - name: PostgreSQL session fence integration\n"
    assert source.count(marker) == 1
    step = source.split(marker, 1)[1].split("\n      - name:", 1)[0]
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


class PostgresRosterAdmission(unittest.TestCase):
    def setUp(self):
        source = (ROOT / "aegis-web-carrier/tests/postgres_ledger.rs").read_text()
        self.names = re.findall(r"#\[tokio::test\]\s+async fn (\w+)\(", source)
        self.assertEqual(len(self.names), 4)
        self.assertIn("owner_release_reclaims_postgres_capacity_and_revokes_sequence", self.names)

    def execute(self, names):
        with tempfile.TemporaryDirectory(prefix="aegis-ci-postgres-roster-") as directory:
            fixture = Path(directory)
            marker = fixture / "executed.json"
            cargo = fixture / "cargo"
            cargo.write_text(
                f"#!{sys.executable}\n"
                "import json, os, pathlib, sys\n"
                "if '--list' in sys.argv:\n"
                "    print('\\n'.join(n + ': test' for n in json.loads(os.environ['FIXTURE_NAMES'])))\n"
                "else:\n"
                "    pathlib.Path(os.environ['FIXTURE_MARKER']).write_text(json.dumps(sys.argv[1:]))\n"
            )
            cargo.chmod(0o700)
            timeout = fixture / "timeout"
            timeout.write_text(f"#!{sys.executable}\nimport os, sys\nassert sys.argv[1] == '9m'\nos.execvp(sys.argv[2], sys.argv[2:])\n")
            timeout.chmod(0o700)
            env = dict(os.environ, PATH=str(fixture) + os.pathsep + os.defpath,
                       FIXTURE_NAMES=json.dumps(names), FIXTURE_MARKER=str(marker),
                       AEGIS_TEST_POSTGRES_DSN="fixture-only-not-a-real-dsn")
            result = subprocess.run(["/bin/bash", "-c", integration_step()], cwd=fixture,
                                    env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, timeout=8)
            args = json.loads(marker.read_text()) if marker.exists() else None
            return result, args

    def test_complete_real_roster_reaches_serial_integration(self):
        result, args = self.execute(self.names)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args, ["test", "--locked", "-p", "aegis-web-carrier", "--test",
                                "postgres_ledger", "--features", "postgres-integration", "--",
                                "--test-threads=1"])

    def test_each_missing_test_refuses_before_integration(self):
        for name in self.names:
            with self.subTest(name=name):
                result, args = self.execute([n for n in self.names if n != name])
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(args)

    def test_duplicate_or_unreviewed_extra_test_refuses(self):
        for names in (self.names + self.names[:1], self.names + ["unreviewed_extra_test"]):
            result, args = self.execute(names)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
