#!/usr/bin/env python3
import importlib.util
import io
import os
from pathlib import Path
import plistlib
import stat
import struct
import tempfile
import unittest
import zipfile

s = importlib.util.spec_from_file_location('inventory', Path(__file__).with_name('inventory-macos-bundle.py'))
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)


def macho(name='/usr/lib/libSystem.B.dylib'):
    payload = name.encode() + b'\0'
    length = (24 + len(payload) + 7) // 8 * 8
    command = struct.pack('<IIIIII', 0xc, length, 24, 0, 0x10000, 0x10000) + payload
    command = command.ljust(length, b'\0')
    return struct.pack('<IiiIIIII', 0xfeedfacf, 0x100000c, 0, 2, 1, len(command), 0, 0) + command


def apple_double(payload=bytes(32)):
    return (bytes.fromhex('0005160700020000') + b'Mac OS X        ' +
            struct.pack('>H', 2) + struct.pack('>III', 9, 50, len(payload)) +
            struct.pack('>III', 2, 50 + len(payload), 0) + payload)


def product_zip(metadata=apple_double(), metadata_name='__MACOSX/AEGIS.app/Contents/._file'):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as z:
        for name in ('AEGIS.app/', 'AEGIS.app/Contents/', '__MACOSX/',
                     '__MACOSX/AEGIS.app/', '__MACOSX/AEGIS.app/Contents/'):
            info = zipfile.ZipInfo(name);info.external_attr = (stat.S_IFDIR | 0o775) << 16
            z.writestr(info, b'')
        info = zipfile.ZipInfo('AEGIS.app/Contents/file')
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        z.writestr(info, b'payload')
        info = zipfile.ZipInfo(metadata_name)
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        z.writestr(info, metadata)
    buffer.seek(0)
    return buffer


class Boundaries(unittest.TestCase):
    def test_real_load_command_shape_and_architecture(self):
        parsed = m.parse_macho(macho())
        self.assertEqual(parsed['dynamic_libraries'][0]['name'], '/usr/lib/libSystem.B.dylib')
        self.assertEqual(parsed['architecture'], 'aarch64-apple-darwin')

    def test_truncated_commands_wrong_arch_and_bad_name_offset_refuse(self):
        for raw in (macho()[:-1], macho()[:4] + struct.pack('<i', 7) + macho()[8:],
                    macho()[:40] + struct.pack('<I', 1) + macho()[44:]):
            with self.assertRaises(ValueError): m.parse_macho(raw)

    def test_extra_native_command_bytes_refuse(self):
        raw = bytearray(macho())
        struct.pack_into('<I', raw, 20, len(raw) - 32 + 8)
        raw += bytes(8)
        with self.assertRaises(ValueError): m.parse_macho(raw)

    def test_unhandled_fat64_is_detected_as_native_not_hidden_resource(self):
        for magic in (b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'):
            self.assertIn(magic, m.MACH_MAGICS)
            with self.assertRaises(ValueError): m.parse_macho(magic + bytes(60))

    def test_zip_traversal_duplicate_and_symlink_refuse(self):
        for names, mode in ((['AEGIS.app/../escape'], stat.S_IFREG | 0o644),
                            (['AEGIS.app/file', 'AEGIS.app/file'], stat.S_IFREG | 0o644),
                            (['AEGIS.app/file', '__MACOSX/hidden'], stat.S_IFREG | 0o644),
                            (['AEGIS.app/link'], stat.S_IFLNK | 0o777)):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as z:
                for name in names:
                    info = zipfile.ZipInfo(name);info.external_attr = mode << 16
                    z.writestr(info, b'payload')
            buffer.seek(0)
            with zipfile.ZipFile(buffer) as z, self.assertRaises(ValueError): m.zip_inventory(z, 'AEGIS.app')

    def test_appledouble_archive_metadata_is_explicit_and_paired(self):
        with zipfile.ZipFile(product_zip()) as z:
            files, metadata, directories, product_dirs = m.zip_inventory(z, 'AEGIS.app')
        self.assertEqual(set(files), {'Contents/file'})
        self.assertEqual(metadata['__MACOSX/AEGIS.app/Contents/._file']['paired_with'],
                         'AEGIS.app/Contents/file')
        self.assertEqual(metadata['__MACOSX/AEGIS.app/Contents/._file']['entries'][1]['id'], 2)
        self.assertIn('__MACOSX/AEGIS.app/Contents/', directories)
        self.assertIn('AEGIS.app/Contents/', directories)
        self.assertEqual(product_dirs['AEGIS.app/Contents'], 0o775)

    def test_appledouble_unpaired_bad_header_and_nonempty_fork_refuse(self):
        wrong = bytearray(apple_double());wrong[0] = 1
        fork = bytearray(apple_double());struct.pack_into('>I', fork, 46, 1)
        overlap = bytearray(apple_double());struct.pack_into('>I', overlap, 42, 49)
        for raw, name in ((bytes(wrong), '__MACOSX/AEGIS.app/Contents/._file'),
                          (bytes(fork), '__MACOSX/AEGIS.app/Contents/._file'),
                          (bytes(overlap), '__MACOSX/AEGIS.app/Contents/._file'),
                          (apple_double(), '__MACOSX/AEGIS.app/Contents/._ghost')):
            with zipfile.ZipFile(product_zip(raw, name)) as z, self.assertRaises(ValueError):
                m.zip_inventory(z, 'AEGIS.app')

    def test_directory_alias_and_file_directory_conflict_refuse(self):
        for extra in ('AEGIS.app/Contents', 'AEGIS.app/Contents/file/',
                      '__MACOSX/AEGIS.app/Contents'):
            buffer = product_zip()
            with zipfile.ZipFile(buffer, 'a') as z:
                info = zipfile.ZipInfo(extra)
                info.external_attr = (stat.S_IFDIR | 0o775) << 16
                z.writestr(info, b'')
            buffer.seek(0)
            with zipfile.ZipFile(buffer) as z, self.assertRaises(ValueError):
                m.zip_inventory(z, 'AEGIS.app')

    def test_native_files_must_be_declared_host_and_provider_executables(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp).resolve() / 'AEGIS.app'
            roots = [('Contents', 'dev.aegis.macos', 'APPL', 'host'),
                     ('Contents/Library/SystemExtensions/dev.aegis.macos.PacketTunnel.systemextension/Contents',
                      'dev.aegis.macos.PacketTunnel', 'SYSX', 'provider')]
            for contents, identifier, kind, executable in roots:
                directory = bundle / contents
                (directory / 'MacOS').mkdir(parents=True)
                (directory / 'Info.plist').write_bytes(plistlib.dumps({
                    'CFBundleVersion': '42', 'CFBundleIdentifier': identifier,
                    'CFBundlePackageType': kind, 'CFBundleExecutable': executable}))
                path = directory / 'MacOS' / executable
                path.write_bytes(macho());path.chmod(0o755)
            with ExitStack() as stack:
                files, _, _ = m.held_tree(bundle, stack)
                self.assertEqual(len(m.executable_roster(files, '42')), 2)
            # Two unrelated native files cannot hide a non-native real entrypoint.
            (bundle / 'Contents/MacOS/host').write_bytes(b'not an executable')
            (bundle / 'Contents/MacOS/decoy').write_bytes(macho())
            with ExitStack() as stack:
                files, _, _ = m.held_tree(bundle, stack)
                with self.assertRaisesRegex(ValueError, 'declared_bundle_executable'):
                    m.executable_roster(files, '42')
            (bundle / 'Contents/MacOS/host').write_bytes(macho())
            with ExitStack() as stack:
                files, _, _ = m.held_tree(bundle, stack)
                with self.assertRaisesRegex(ValueError, 'unclassified_native_payload'):
                    m.executable_roster(files, '42')

    def test_held_tree_detects_added_file_and_same_size_mutation(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp).resolve() / 'AEGIS.app';bundle.mkdir()
            (bundle / 'file').write_bytes(b'one')
            with ExitStack() as stack:
                _, _, recheck = m.held_tree(bundle, stack)
                (bundle / 'file').write_bytes(b'two')
                with self.assertRaises(ValueError): recheck()
            with ExitStack() as stack:
                _, _, recheck = m.held_tree(bundle, stack)
                (bundle / 'extra').write_bytes(b'new')
                with self.assertRaises(ValueError): recheck()

    def test_held_tree_rejects_external_symlink(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve();bundle = root / 'AEGIS.app';bundle.mkdir()
            (root / 'outside').write_bytes(b'not shipped')
            (bundle / 'link').symlink_to(root / 'outside')
            with ExitStack() as stack, self.assertRaises(ValueError): m.held_tree(bundle, stack)


if __name__ == '__main__': unittest.main()
