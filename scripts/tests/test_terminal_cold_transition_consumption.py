#!/usr/bin/env python3
"""Real filesystem controls for the cold intent/pending consumption cut."""
import ast
import ctypes
import os
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'lib/aegis_auto_boot_transition.py'


def load_function():
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                and n.name == '_cold_rename_consumed')
    scope = {'Path': Path, 'ctypes': ctypes, 'os': os}
    def need(value, reason):
        if not value:
            raise RuntimeError(reason)
    def read(path, limit=8192):
        need(not Path(path).is_symlink(), 'read_symlink')
        raw = Path(path).read_bytes()
        need(len(raw) <= limit, 'read_limit')
        return raw
    scope.update(need=need, read=read)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), scope)
    return scope['_cold_rename_consumed']


@unittest.skipUnless(hasattr(ctypes.CDLL(None), 'renameat2'), 'Linux renameat2 required')
class ColdConsumption(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aegis-cold-consume-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.active = root / 'active'; self.active.mkdir()
        self.history = root / 'history'; self.history.mkdir()
        self.move = load_function()

    def test_atomic_consumption_and_idempotent_replay(self):
        raw = b'{"schema":"fixed"}\n'
        source = self.active / 'intent.json'
        target = self.history / ('intent-consumed-' + 'a' * 64 + '.json')
        # Use a fixed leaf without relying on the name policy here; source
        # qualification and hash-derived names are checked by the caller.
        source.write_bytes(raw)
        self.move(source, target, raw)
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), raw)
        self.move(source, target, raw)
        self.assertEqual(target.read_bytes(), raw)

    def test_collision_and_changed_source_refuse_without_deletion(self):
        source = self.active / 'pending.json'; target = self.history / 'consumed.json'
        source.write_bytes(b'expected\n')
        target.write_bytes(b'foreign\n')
        with self.assertRaises(RuntimeError):
            self.move(source, target, b'expected\n')
        self.assertEqual(source.read_bytes(), b'expected\n')
        self.assertEqual(target.read_bytes(), b'foreign\n')
        target.unlink(); source.write_bytes(b'changed\n')
        with self.assertRaises(RuntimeError):
            self.move(source, target, b'expected\n')
        self.assertEqual(source.read_bytes(), b'changed\n')

    def test_symlink_source_refuses(self):
        source = self.active / 'pending.json'; target = self.history / 'consumed.json'
        foreign = self.active / 'foreign'; foreign.write_bytes(b'content\n')
        source.symlink_to(foreign)
        with self.assertRaises(RuntimeError):
            self.move(source, target, b'content\n')
        self.assertTrue(source.is_symlink())
        self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
