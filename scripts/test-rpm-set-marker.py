#!/usr/bin/env python3
"""Synthetic completion marker and sidecar regression cases; no RPM execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / 'scripts/verify-rpm-package-set.py'


class RpmMarker(unittest.TestCase):
    def fixture(self, directory):
        packages, split = {}, {}
        for role in ('server', 'client'):
            package = f'aegis-{role}'
            name = f'{package}-0.3.50-1.el9.x86_64.rpm'
            data = f'only inert {role} bytes'.encode()
            (directory / name).write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            (directory / f'{name}.sha256').write_text(f'{digest}  {name}\n')
            packages[package] = {'rpm_file': name, 'sha256_file': f'{name}.sha256'}
            split[role] = {'path': name, 'sha256_path': f'{name}.sha256', 'sha256': digest}
        marker = directory / 'rpm-packages.manifest.json'
        marker.write_text(json.dumps({'version': '0.3.50', 'arch': 'x86_64', 'packages': packages}))
        release = directory / 'release.manifest.json'
        release.write_text(json.dumps({'schema': 'aegis_linux_release_manifest_v1',
                                       'version': '0.3.50', 'arch': 'x86_64', 'git_sha': 'abcd',
                                       'artifacts': {'rpm': {'status': 'ready',
                                                             'manifest_path': marker.name,
                                                             'split': split}}}))
        return marker, release

    def add_arm_peer(self, directory):
        packages, split = {}, {}
        for role in ('server', 'client'):
            package = f'aegis-{role}'
            name = f'{package}-0.3.50-1.el9.aarch64.rpm'
            data = f'only inert arm {role} bytes'.encode()
            (directory / name).write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            (directory / f'{name}.sha256').write_text(f'{digest}  {name}\n')
            packages[package] = {'rpm_file': name, 'sha256_file': f'{name}.sha256'}
            split[role] = {'path': name, 'sha256_path': f'{name}.sha256', 'sha256': digest}
        marker = directory / 'rpm-packages-aarch64.manifest.json'
        marker.write_text(json.dumps({'version': '0.3.50', 'arch': 'aarch64', 'packages': packages}))
        release = directory / 'release.manifest-aarch64.json'
        release.write_text(json.dumps({'schema': 'aegis_linux_release_manifest_v1',
                                       'version': '0.3.50', 'arch': 'aarch64', 'git_sha': 'abcd',
                                       'artifacts': {'rpm': {'status': 'ready',
                                                             'manifest_path': marker.name,
                                                             'split': split}}}))
        return marker, release

    def verify(self, directory, release):
        return subprocess.run([sys.executable, '-I', '-B', str(VERIFIER), str(directory),
                               '--arch', 'x86_64', '--version', '0.3.50',
                               '--release-manifest', str(release), '--source-sha', 'abcd'],
                              capture_output=True, text=True)

    def test_complete_set_passes(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _, release = self.fixture(directory)
            self.assertEqual(self.verify(directory, release).returncode, 0)

    def test_missing_last_marker_refused(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            marker, release = self.fixture(directory)
            marker.unlink()
            self.assertNotEqual(self.verify(directory, release).returncode, 0)

    def test_stale_sidecar_refused(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _, release = self.fixture(directory)
            (directory / 'aegis-client-0.3.50-1.el9.x86_64.rpm.sha256').write_text('stale\n')
            self.assertNotEqual(self.verify(directory, release).returncode, 0)

    def test_outer_release_hash_refused(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _, release = self.fixture(directory)
            data = json.loads(release.read_text())
            data['artifacts']['rpm']['split']['client']['sha256'] = '0' * 64
            release.write_text(json.dumps(data))
            self.assertNotEqual(self.verify(directory, release).returncode, 0)

    def test_extra_release_number_refused(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _, release = self.fixture(directory)
            (directory / 'aegis-server-0.3.50-2.el9.x86_64.rpm').write_bytes(b'extra')
            self.assertNotEqual(self.verify(directory, release).returncode, 0)

    def test_orphan_rpm_sidecar_refused(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _, release = self.fixture(directory)
            (directory / 'orphan.rpm.sha256').write_text('orphan\n')
            self.assertNotEqual(self.verify(directory, release).returncode, 0)

    def test_unbound_arm_rpm_refused(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _, release = self.fixture(directory)
            (directory / 'aegis-server-0.3.50-1.el9.aarch64.rpm').write_bytes(b'extra')
            self.assertNotEqual(self.verify(directory, release).returncode, 0)

    def test_flattened_two_architectures_pass(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _, release = self.fixture(directory)
            self.add_arm_peer(directory)
            self.assertEqual(self.verify(directory, release).returncode, 0)

    def test_flattened_peer_missing_release_refused(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _, release = self.fixture(directory)
            _, peer_release = self.add_arm_peer(directory)
            peer_release.unlink()
            self.assertNotEqual(self.verify(directory, release).returncode, 0)

    def test_flattened_peer_corruption_refused(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _, release = self.fixture(directory)
            self.add_arm_peer(directory)
            (directory / 'aegis-client-0.3.50-1.el9.aarch64.rpm').write_bytes(b'changed')
            self.assertNotEqual(self.verify(directory, release).returncode, 0)


if __name__ == '__main__':
    unittest.main()
