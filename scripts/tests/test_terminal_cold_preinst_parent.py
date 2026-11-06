"""The generated preinst rejects aliases and foreign cold parent directories."""
import ast
import os
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
import unittest


SOURCE = Path(__file__).resolve().parents[2] / 'scripts/build-split-deb-packages.sh'
PARTS = ('var','lib','aegis-install','client','terminal-migrations',
         'cold-recovery')


class _RootedOS:
    def __init__(self, root):
        self.root = root
        self.opened = []

    def open(self, path, flags, *args, **kwargs):
        self.opened.append(path)
        if path == '/':
            path = str(self.root)
        return os.open(path, flags, *args, **kwargs)

    def fstat(self, fd):
        # The temp tree is owned by the test user on macOS; preserve its
        # actual mode while exercising the generated root-owned path policy.
        value = os.fstat(fd)
        return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_gid=0)

    def __getattr__(self, name):
        return getattr(os, name)


def generated_namespace(root):
    body = SOURCE.read_text().split("cat > \"$path\" <<'PY'\n",1)[1].split('\nPY\n',1)[0]
    tree = ast.parse(body)
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                and node.name in ('cold_dir_fd','cold_current_head')]
    if len(selected) != 2:
        raise AssertionError('generated cold parent functions missing')
    namespace = {'os':_RootedOS(root),'stat':stat,'pathlib':__import__('pathlib'),
                 're':re,'need':lambda value: value or (_ for _ in ()).throw(
                     ValueError('generated preinst refused'))}
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(SOURCE),'exec'),
         namespace)
    return namespace


class ColdPreinstParent(unittest.TestCase):
    def test_missing_optional_cold_parent_is_typed_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(generated_namespace(root)['cold_current_head']())

    def test_symlink_to_empty_directory_refuses_before_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root.joinpath(*PARTS[:-1])
            parent.mkdir(parents=True,mode=0o700)
            for path in (root/'var',root/'var/lib',root/'var/lib/aegis-install',
                         parent, parent.parent):
                path.chmod(0o700)
            empty = root/'empty'; empty.mkdir(mode=0o700)
            (parent/PARTS[-1]).symlink_to(empty, target_is_directory=True)
            namespace = generated_namespace(root)
            with self.assertRaises(OSError):
                namespace['cold_current_head']()
            self.assertIn('cold-recovery', namespace['os'].opened)

    def test_writable_client_parent_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root.joinpath(*PARTS)
            parent.mkdir(parents=True,mode=0o700)
            for path in (root/'var',root/'var/lib',root/'var/lib/aegis-install',
                         parent.parent.parent,parent.parent,parent):
                path.chmod(0o700)
            (root/'var/lib/aegis-install/client').chmod(0o777)
            namespace = generated_namespace(root)
            with self.assertRaises(ValueError):
                namespace['cold_current_head']()
            self.assertIn('client', namespace['os'].opened)


if __name__ == '__main__':
    unittest.main()
