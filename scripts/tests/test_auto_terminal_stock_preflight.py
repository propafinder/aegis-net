"""Real root-owned files for the terminal stock preflight and final gate."""
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
SOURCE = Path(__file__).resolve().parents[1] / 'lib' / 'aegis_auto_terminal_boot_store.py'

STOCK_BYTES = {
    'fwupd.shutdown': base64.b64decode('IyEvYmluL3NoCgojIG5vIGhpc3RvcnkgZGF0YWJhc2UgZXhpc3RzClsgLWYgL3Zhci9saWIvZnd1cGQvcGVuZGluZy5kYiBdIHx8IGV4aXQgMAoKIyBhY3RpdmF0ZSBmaXJtd2FyZSB3aGVuIHdlIGhhdmUgYSByZWFkLW9ubHkgZmlsZXN5c3RlbQppZiAhIC91c3IvYmluL2Z3dXBkdG9vbCBhY3RpdmF0ZTsgdGhlbgogICAgcmV0PSQ/CiAgICBbICIkcmV0IiAtZXEgIjIiIF0gJiYgZXhpdCAwCiAgICBleGl0ICRyZXQKZmkK'),
    'mdadm.shutdown': base64.b64decode('IyEvYmluL3NoCiMgV2UgbmVlZCB0byBlbnN1cmUgYWxsIG1kIGFycmF5cyB3aXRoIGV4dGVybmFsIG1ldGFkYXRhCiMgKGUuZy4gSU1TTSwgRERGKSBhcmUgY2xlYW4gYmVmb3JlIGNvbXBsZXRpbmcgdGhlIHNodXRkb3duLgovc2Jpbi9tZGFkbSAtLXdhaXQtY2xlYW4gLS1zY2FuCg=='),
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class TerminalStockPreflight(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform, 'linux')
        self.assertEqual(os.geteuid(), 0)
        self.private = tempfile.TemporaryDirectory(prefix='aegis-stock-preflight-',
                                                    dir='/var/tmp')
        self.addCleanup(self.private.cleanup)
        self.root = Path(self.private.name)
        self.assertEqual(self.root.stat().st_dev, os.stat('/').st_dev)
        self.source = self.root / 'aegis_auto_terminal_boot_store.py'
        source_raw = SOURCE.read_bytes()
        self.source.write_bytes(source_raw)
        self.source.chmod(0o444)
        self.assertEqual((self.source.stat().st_uid, self.source.stat().st_nlink), (0, 1))
        spec = importlib.util.spec_from_file_location('aegis_stock_preflight_fixture', self.source)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.assertEqual(self.source.read_bytes(), source_raw)
        self.var = self.root / 'var'
        self.varlib = self.var / 'lib'
        self.fwupd = self.varlib / 'fwupd'
        self.hooks = self.root / 'shutdown'
        self.block = self.root / 'sys-class-block'
        for directory in (self.var, self.varlib, self.fwupd, self.hooks,
                          self.block):
            directory.mkdir(mode=0o755)
            self.assertEqual(directory.stat().st_uid, 0)
        self.mdstat = self.root / 'mdstat'
        self.mdstat.write_bytes(b'Personalities :\nunused devices: <none>\n')
        self.mdstat.chmod(0o600)
        for name, expected in self.helper.STOCK_HOOKS.items():
            raw = STOCK_BYTES[name]
            self.assertEqual(digest(raw), expected)
            target = self.hooks / name
            target.write_bytes(raw)
            target.chmod(0o755)
            self.assertEqual(target.stat().st_uid, 0)
        self.own = self.hooks / 'aegis-auto-terminal-hook'
        self.own_raw = b'#!/bin/sh\nexit 0\n'
        self.config = {'helper_sha256': digest(source_raw),
                       'hook_path': str(self.own),
                       'hook_sha256': digest(self.own_raw)}
        mapping = {'/var': self.var, '/var/lib': self.varlib,
                   '/var/lib/fwupd': self.fwupd,
                   '/sys/class/block': self.block}
        real_open = os.open

        def mapped_path(*parts):
            path = Path(*parts)
            return mapping.get(str(path), path)

        def mapped_open(path, flags, *args):
            if str(path) == '/proc/mdstat':
                if not self.md_available:
                    raise FileNotFoundError('/proc/mdstat')
                return real_open(self.mdstat, flags, *args)
            return real_open(path, flags, *args)

        self.md_available = True
        for patcher in (mock.patch.object(self.helper, 'HOOK_DIR', str(self.hooks)),
                        mock.patch.object(self.helper, 'Path', side_effect=mapped_path),
                        mock.patch.object(self.helper, 'mounts', return_value=[
                            {'target': '/proc', 'fstype': 'proc'},
                            {'target': '/sys', 'fstype': 'sysfs'}]),
                        mock.patch.object(self.helper.os, 'open', side_effect=mapped_open)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def complete_site(self):
        self.own.write_bytes(self.own_raw)
        self.own.chmod(0o755)

    def assert_refused(self, predicate, reason):
        with self.assertRaises(self.helper.Refusal) as raised:
            predicate(self.config)
        self.assertEqual(str(raised.exception), reason)

    def snapshot(self):
        result = {}
        for path in self.root.rglob('*'):
            info = path.lstat()
            result[str(path.relative_to(self.root))] = (
                info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
                info.st_size, info.st_mtime_ns,
                digest(path.read_bytes()) if stat.S_ISREG(info.st_mode) else None)
        return result

    def test_missing_own_hook_preflight_passes_final_refuses(self):
        self.helper.preflight_sources(self.config)
        self.assert_refused(self.helper.check_sources, 'foreign_shutdown_hook')

    def test_complete_exact_site_passes_both_gates(self):
        self.complete_site()
        self.helper.preflight_sources(self.config)
        self.helper.check_sources(self.config)

    def test_existing_empty_pending_db_refuses_without_mutation(self):
        self.complete_site()
        pending = self.fwupd / 'pending.db'
        pending.write_bytes(b'')
        pending.chmod(0o644)
        before = self.snapshot()
        self.assert_refused(self.helper.preflight_sources, 'fwupd_pending_exists')
        self.assert_refused(self.helper.check_sources, 'fwupd_pending_exists')
        self.assertEqual(self.snapshot(), before)

    def test_foreign_shutdown_hook_refused(self):
        foreign = self.hooks / 'foreign.shutdown'
        foreign.write_bytes(b'#!/bin/sh\nexit 0\n')
        foreign.chmod(0o755)
        self.assert_refused(self.helper.preflight_sources, 'foreign_shutdown_hook')

    def test_stock_hook_wrong_bytes_refused(self):
        target = self.hooks / 'fwupd.shutdown'
        target.write_bytes(b'#!/bin/sh\nexit 0\n')
        target.chmod(0o755)
        self.assert_refused(self.helper.preflight_sources, 'stock_hook_changed')

    def test_own_hook_symlink_mode_and_hash_refused(self):
        self.own.symlink_to(self.hooks / 'fwupd.shutdown')
        self.assert_refused(self.helper.preflight_sources, 'hook_changed')
        self.own.unlink()
        self.complete_site()
        self.own.chmod(0o644)
        self.assert_refused(self.helper.preflight_sources, 'hook_changed')
        self.own.write_bytes(b'#!/bin/sh\nexit 1\n')
        self.own.chmod(0o755)
        self.assert_refused(self.helper.preflight_sources, 'hook_changed')

    def test_active_and_unavailable_mdstat_refused(self):
        self.mdstat.write_bytes(b'Personalities : [raid1]\n'
                                b'md0 : active raid1 sda1[0] sdb1[1]\n'
                                b'unused devices: <none>\n')
        self.assert_refused(self.helper.preflight_sources,
                            'md_arrays_present_or_mdstat_untrusted')
        self.md_available = False
        self.assert_refused(self.helper.preflight_sources, 'mdstat_unavailable')

    def test_exact_source_bytes_require_root_owned_file(self):
        self.assertEqual(self.helper.file_sha(self.source), self.config['helper_sha256'])
        foreign = self.root / 'foreign-helper.py'
        foreign.write_bytes(self.source.read_bytes())
        foreign.chmod(0o444)
        os.chown(foreign, 65534, 65534)
        self.assertEqual(foreign.stat().st_uid, 65534)
        self.assert_refused(lambda _c: self.helper.file_sha(foreign), 'source_metadata')


if __name__ == '__main__':
    unittest.main()
