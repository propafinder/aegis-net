"""Public/no-inspector boot path must prove the same cloud-init absence.

Execute the actual installer gate, redirecting only its read paths and PID1
command to isolated fixtures; no host boot state or services are changed.
"""
import ast
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PublicCloudAbsence(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        source = (ROOT / 'install.sh').read_text()
        function = re.search(r'^device_verify_initramfs\(\) \{\n.*?^\}', source, re.M | re.S)[0]
        program = function.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        self.program = program.split("need(not pathlib.Path('/sys/firmware/ibft')", 1)[0]
        self.units, self.generators = self.root / 'units', self.root / 'generators'
        self.units.mkdir(); self.generators.mkdir()
        for key, values in (
            ('CLOUD_INDICATORS', [str(self.root / 'no-cloud-binary')]),
            ('CLOUD_UNIT_DIRS', [str(self.units)]),
            ('CLOUD_GENERATOR_DIRS', [str(self.generators)])):
            self.program, count = re.subn(key + r' = \(.*?\)\n',
                key + ' = ' + repr(tuple(values)) + '\n', self.program, flags=re.S)
            self.assertEqual(count, 1)
        self.program += '\nprint("boot_checks_reached")\n'
        binary = self.root / 'bin'; binary.mkdir()
        command = binary / 'systemctl'
        command.write_text('#!/bin/sh\nprintf "%s" "$FIXTURE_CLOUD_ROWS"\nexit "${FIXTURE_CLOUD_STATUS:-0}"\n')
        command.chmod(0o700)
        self.env = {**os.environ, 'PATH': str(binary) + os.pathsep + os.environ['PATH'],
                    'FIXTURE_CLOUD_ROWS': ''}

    def run_gate(self, *, rows='', status=0):
        return subprocess.run([sys.executable, '-I', '-B', '-c', self.program,
            '', '', str(self.root / 'no-AUTO-inspectors')],
            env={**self.env, 'FIXTURE_CLOUD_ROWS': rows,
                 'FIXTURE_CLOUD_STATUS': str(status)},
            text=True, capture_output=True, timeout=10)

    def test_absent_cloud_does_not_require_AUTO_inspectors(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'boot_checks_reached')

    def test_unlisted_cloud_unit_or_generator_refuses_without_binary(self):
        for directory in (self.units, self.generators):
            with self.subTest(directory=directory.name):
                path = directory / 'cloud-init-nonstandard.service'
                path.symlink_to(self.root / 'absent-target')
                result = self.run_gate()
                path.unlink()
                self.assertEqual(result.returncode, 78, result.stderr)

    def test_cloud_unit_held_by_PID1_refuses_without_fragment(self):
        result = self.run_gate(rows='cloud-init-transient.service loaded active running fixture\n')
        self.assertEqual(result.returncode, 78, result.stderr)

    def test_failed_PID1_absence_inspection_refuses(self):
        result = self.run_gate(status=1)
        self.assertEqual(result.returncode, 78, result.stderr)

    def test_dependency_only_not_found_unit_is_not_active_cloud(self):
        result = self.run_gate(rows='cloud-init-dependency.service not-found inactive dead fixture\n')
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
