#!/usr/bin/env python3
"""Real ar/xz/tar ownership regressions for the DEB publication gate."""

import io
import importlib.util
import lzma
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


CHECKER = Path(__file__).with_name('verify-deb-archive-ownership.py')


def archive(owners):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as tar:
        for row in owners:
            name, is_dir, uid, gid = row[:4]
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
            info.uid, info.gid = uid, gid
            info.mode = row[4] if len(row) == 5 else (0o755 if is_dir else 0o644)
            if not is_dir:
                payload = b'test\n'
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            else:
                tar.addfile(info)
    return lzma.compress(output.getvalue())


def ar_member(name, payload):
    header = (f'{name}/'.ljust(16) + '0'.ljust(12) + '0'.ljust(6)
              + '0'.ljust(6) + '100644'.ljust(8)
              + str(len(payload)).ljust(10) + '`\n').encode('ascii')
    assert len(header) == 60
    return header + payload + (b'\n' if len(payload) % 2 else b'')


def deb(control, data):
    return deb_archives(archive(control), archive(data))


def deb_archives(control, data):
    return (b'!<arch>\n' + ar_member('debian-binary', b'2.0\n')
            + ar_member('control.tar.xz', control)
            + ar_member('data.tar.xz', data))


class OwnershipContract(unittest.TestCase):
    def test_decoded_stream_cap_includes_hidden_tar_metadata(self):
        spec = importlib.util.spec_from_file_location('deb_owner', CHECKER)
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        bounded = checker.BoundedReader(io.BytesIO(b'metadata'), 4)
        with self.assertRaises(checker.InvalidDeb):
            bounded.read(8)

    def check(self, control, data, expected):
        with tempfile.TemporaryDirectory(prefix='aegis-deb-owner-') as tmp:
            path = Path(tmp) / 'test.deb'
            path.write_bytes(deb(control, data))
            result = subprocess.run([sys.executable, '-I', '-B', str(CHECKER), str(path)],
                                    capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, expected, result.stderr)

    def test_root_control_and_data_pass(self):
        self.check([('./', True, 0, 0), ('./control', False, 0, 0)],
                   [('./', True, 0, 0), ('./usr/', True, 0, 0),
                    ('./usr/app', False, 0, 0)], 0)

    def test_nonroot_data_file_refused(self):
        self.check([('./', True, 0, 0), ('./control', False, 0, 0)],
                   [('./', True, 0, 0), ('./usr/app', False, 501, 0)], 1)

    def test_nonroot_data_directory_refused(self):
        self.check([('./', True, 0, 0), ('./control', False, 0, 0)],
                   [('./', True, 0, 0), ('./usr/', True, 0, 501)], 1)

    def test_group_writable_data_directory_refused(self):
        self.check([('./', True, 0, 0), ('./control', False, 0, 0)],
                   [('./', True, 0, 0), ('./usr/', True, 0, 0, 0o775)], 1)

    def test_world_writable_control_directory_refused(self):
        self.check([('./', True, 0, 0, 0o777), ('./control', False, 0, 0)],
                   [('./', True, 0, 0), ('./usr/app', False, 0, 0)], 1)

    def test_nonroot_control_file_refused(self):
        self.check([('./', True, 0, 0), ('./postinst', False, 501, 0)],
                   [('./', True, 0, 0), ('./usr/app', False, 0, 0)], 1)

    def test_nonroot_control_directory_refused(self):
        self.check([('./', True, 501, 0), ('./postinst', False, 0, 0)],
                   [('./', True, 0, 0), ('./usr/app', False, 0, 0)], 1)

    def test_expanded_size_refused_before_member_payload(self):
        raw = bytearray(lzma.decompress(archive([('./', True, 0, 0),
                                                 ('./usr/app', False, 0, 0)])))
        header = 512  # The second tar member follows the root directory.
        raw[header + 124:header + 136] = b'10000000001\0'  # More than 1 GiB.
        raw[header + 148:header + 156] = b'        '
        checksum = sum(raw[header:header + 512])
        raw[header + 148:header + 156] = f'{checksum:06o}\0 '.encode()
        with tempfile.TemporaryDirectory(prefix='aegis-deb-owner-') as tmp:
            path = Path(tmp) / 'test.deb'
            path.write_bytes(deb_archives(archive([('./', True, 0, 0),
                                                   ('./control', False, 0, 0)]),
                                          lzma.compress(raw)))
            result = subprocess.run([sys.executable, '-I', '-B', str(CHECKER), str(path)],
                                    capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn('expanded members exceed 1 GiB', result.stderr)


if __name__ == '__main__':
    unittest.main()
