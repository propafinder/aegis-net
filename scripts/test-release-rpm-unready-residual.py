#!/usr/bin/env python3
"""Exercise the real unready-RPM residual guard with inert temporary files."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'scripts/build-release-delivery.sh').read_text()
START = 'if [[ "${RPM_STATUS}" != "ready" ]]; then\n'
END = '\n# The public client is a separate artifact;'
assert SOURCE.count(START) == SOURCE.count(END) == 1
BLOCK = START + SOURCE.split(START, 1)[1].split(END, 1)[0]


class UnreadyRpmResidual(unittest.TestCase):
    def run_case(self, filename=None, symlink=False):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name)
            if filename:
                target = output / filename
                if symlink:
                    target.symlink_to(output / 'missing-target')
                else:
                    target.write_text('inert stale data')
            script = 'set -euo pipefail\n' + BLOCK
            return subprocess.run(['bash', '-c', script], env={'OUTPUT_DIR': str(output),
                                                               'RPM_STATUS': 'unavailable',
                                                               'PATH': '/usr/bin:/bin'},
                                  capture_output=True, text=True)

    def test_clean_unavailable_directory_passes(self):
        self.assertEqual(self.run_case().returncode, 0)

    def test_marker_only_refused(self):
        self.assertNotEqual(self.run_case('rpm-packages.manifest.json').returncode, 0)

    def test_arch_specific_marker_only_refused(self):
        self.assertNotEqual(self.run_case('rpm-packages-aarch64.manifest.json').returncode, 0)

    def test_dangling_marker_symlink_refused(self):
        self.assertNotEqual(self.run_case('rpm-packages.manifest.json', symlink=True).returncode, 0)

    def test_orphan_sidecar_refused(self):
        self.assertNotEqual(self.run_case('orphan.rpm.sha256').returncode, 0)


if __name__ == '__main__':
    unittest.main()
