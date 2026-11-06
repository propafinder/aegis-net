#!/usr/bin/env python3
"""Source-level controls for the inherited cold package lock parser."""
import ast
import os
from pathlib import Path
import re
import stat
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'lib/aegis_installer_auto_v2.py'
TREE = ast.parse(SOURCE.read_text(encoding='utf-8'), filename=str(SOURCE))
NODE = next(node for node in TREE.body if isinstance(node, ast.FunctionDef)
            and node.name == '_cold_full_flock')
NS = {'os':os, 're':re}
exec(compile(ast.Module(body=[NODE], type_ignores=[]), str(SOURCE), 'exec'), NS)
full_flock = NS['_cold_full_flock']


class Identity:
    st_dev = os.makedev(8, 1)
    st_ino = 12345


def row(*, device='08:01:12345', access='WRITE', span='0 EOF'):
    return f'lock: 1: FLOCK ADVISORY {access} 42 {device} {span}\n'


class ColdLockTests(unittest.TestCase):
    def test_exact_inherited_whole_file_lock(self):
        self.assertTrue(full_flock(row(), Identity()))

    def test_refuses_other_inodes_and_devices(self):
        for device in ('08:01:12346', '08:02:12345'):
            with self.subTest(device=device):
                self.assertFalse(full_flock(row(device=device), Identity()))

    def test_refuses_shared_partial_duplicate_and_unbounded(self):
        for value in (row(access='READ'), row(span='0 4095'),
                      row()+row(), row()+'x'*4096, ''):
            with self.subTest(value=value[:40]):
                self.assertFalse(full_flock(value, Identity()))


if __name__ == '__main__':
    unittest.main()
