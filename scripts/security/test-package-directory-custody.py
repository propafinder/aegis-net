#!/usr/bin/env python3
"""Real directory substitution controls; all files live in private fixtures."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name('inventory-package-root.py')
SPEC = importlib.util.spec_from_file_location('inventory', SCRIPT)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def fixture(base, name, commit):
    package = base / name
    leaf = package / 'rootfs/usr/share/aegis/data.txt'
    leaf.parent.mkdir(parents=True)
    leaf.write_text('identical public fixture payload\n')
    digest = hashlib.sha256(leaf.read_bytes()).hexdigest()
    (package / 'package-root.manifest.json').write_text(json.dumps({
        'schema': 'aegis_package_root_manifest_v2', 'rootfs_dir': 'rootfs',
        'package_name': 'fixture', 'git_sha': commit,
        'target_triple': 'x86_64-unknown-linux-gnu',
        'files': ['usr/share/aegis/data.txt'], 'binaries': {}}))
    (package / 'SHA256SUMS').write_text(digest + '  usr/share/aegis/data.txt\n')
    return package


class Custody(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='aegis-package-dir-custody-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.package = fixture(self.base, 'package', 'a' * 40)
        self.forged = fixture(self.base, 'forged', 'b' * 40)

    def scan(self):
        return m.inventory(self.package, None, None)

    def test_unchanged_package_reports_the_admitted_manifest(self):
        self.assertEqual(self.scan()['source_commit'], 'a' * 40)

    def test_package_symlink_swap_before_metadata_refuses(self):
        original = m.read_package_metadata
        changed = []
        def read(*args, **kwargs):
            if not changed:
                changed.append(True)
                self.package.rename(self.base / 'held-package')
                self.package.symlink_to(self.forged, target_is_directory=True)
            return original(*args, **kwargs)
        with mock.patch.object(m, 'read_package_metadata', side_effect=read):
            with self.assertRaises((ValueError, OSError)):
                self.scan()
        self.assertEqual(changed, [True])

    def test_temporary_swap_cannot_mix_forged_manifest_and_genuine_rootfs(self):
        original = m.read_package_metadata
        changed = []
        def read(*args, **kwargs):
            if changed:
                return original(*args, **kwargs)
            changed.append(True)
            held = self.base / 'held-package'
            self.package.rename(held)
            self.package.symlink_to(self.forged, target_is_directory=True)
            try:
                return original(*args, **kwargs)
            finally:
                self.package.unlink()
                held.rename(self.package)
        with mock.patch.object(m, 'read_package_metadata', side_effect=read):
            try:
                report = self.scan()
            except (ValueError, OSError):
                pass
            else:
                self.assertEqual(report['source_commit'], 'a' * 40)
        self.assertEqual(changed, [True])

    def test_package_directory_swap_without_symlink_refuses(self):
        original = m.read_package_metadata
        changed = []
        def read(*args, **kwargs):
            if not changed:
                changed.append(True)
                self.package.rename(self.base / 'held-package')
                self.forged.rename(self.package)
            return original(*args, **kwargs)
        with mock.patch.object(m, 'read_package_metadata', side_effect=read):
            with self.assertRaises((ValueError, OSError)):
                self.scan()
        self.assertEqual(changed, [True])

    def test_rootfs_swap_after_checksums_refuses(self):
        original = m.read_package_metadata
        changed = []
        def read(path, *args, **kwargs):
            raw = original(path, *args, **kwargs)
            if Path(path).name == 'SHA256SUMS' and not changed:
                changed.append(True)
                (self.package / 'rootfs').rename(self.base / 'held-rootfs')
                (self.package / 'rootfs').symlink_to(self.forged / 'rootfs', target_is_directory=True)
            return raw
        with mock.patch.object(m, 'read_package_metadata', side_effect=read):
            with self.assertRaises((ValueError, OSError)):
                self.scan()
        self.assertEqual(changed, [True])

    def test_rootfs_subdirectory_swap_before_leaf_hash_refuses(self):
        original = m.hash_regular
        changed = []
        def hash_leaf(*args, **kwargs):
            if not changed:
                changed.append(True)
                (self.package / 'rootfs/usr').rename(self.base / 'held-usr')
                (self.package / 'rootfs/usr').symlink_to(self.forged / 'rootfs/usr', target_is_directory=True)
            return original(*args, **kwargs)
        with mock.patch.object(m, 'hash_regular', side_effect=hash_leaf):
            with self.assertRaises((ValueError, OSError)):
                self.scan()
        self.assertEqual(changed, [True])

    def test_metadata_mutation_after_read_is_not_reported_as_stable(self):
        original = m.hash_regular
        changed = []
        def hash_leaf(*args, **kwargs):
            if not changed:
                changed.append(True)
                manifest = self.package / 'package-root.manifest.json'
                data = json.loads(manifest.read_text()); data['git_sha'] = 'b' * 40
                manifest.write_text(json.dumps(data))
            return original(*args, **kwargs)
        # Same-size writes can share an inode timestamp tick on Linux.
        # Force that real condition instead of depending on scheduler timing.
        manifest = self.package / 'package-root.manifest.json'
        original_facts = m.file_facts
        before = manifest.stat(); frozen = original_facts(before)
        def facts(value):
            return frozen if (value.st_dev, value.st_ino) == (before.st_dev, before.st_ino) else original_facts(value)
        with mock.patch.object(m, 'hash_regular', side_effect=hash_leaf), mock.patch.object(m, 'file_facts', side_effect=facts):
            with self.assertRaises((ValueError, OSError)):
                self.scan()
        self.assertEqual(changed, [True])

    def test_later_leaf_cannot_hide_prior_payload_mutation_in_same_timestamp_tick(self):
        data = self.package / 'rootfs/usr/share/aegis/data.txt'
        later = data.with_name('later.txt'); later.write_text('later public fixture\n')
        manifest = self.package / 'package-root.manifest.json'
        record = json.loads(manifest.read_text())
        record['files'].append('usr/share/aegis/later.txt'); manifest.write_text(json.dumps(record))
        sums = self.package / 'SHA256SUMS'
        with sums.open('a') as stream:stream.write(hashlib.sha256(later.read_bytes()).hexdigest() + '  usr/share/aegis/later.txt\n')
        before = data.stat(); original_facts = m.file_facts; frozen = original_facts(before)
        original_hash = m.hash_regular; changed = []
        def hash_leaf(path, *args, **kwargs):
            if Path(path).name == 'later.txt' and not changed:
                changed.append(True)
                raw = data.read_bytes(); data.write_bytes(b'X' + raw[1:])
                os.utime(data, ns=(before.st_atime_ns, before.st_mtime_ns))
            return original_hash(path, *args, **kwargs)
        def facts(value):
            return frozen if (value.st_dev, value.st_ino) == (before.st_dev, before.st_ino) else original_facts(value)
        with mock.patch.object(m, 'hash_regular', side_effect=hash_leaf), mock.patch.object(m, 'file_facts', side_effect=facts):
            with self.assertRaises((ValueError, OSError)):
                self.scan()
        self.assertEqual(changed, [True])


if __name__ == '__main__':
    unittest.main()
