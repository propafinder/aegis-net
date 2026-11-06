#!/usr/bin/env python3
"""Exercise actual generated removal scripts and the passive/active owner fences."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


def main():
    source = (ROOT / 'scripts/build-split-deb-packages.sh').read_text()
    def function(name, following):
        match = re.search(r'(' + name + r'\(\) \{\n.*?\n\})\n(?:#[^\n]*\n|\n)*' + following + r'\(\)', source, re.S)
        assert match is not None, name
        return match.group(1)
    with tempfile.TemporaryDirectory(prefix='aegis-prerm-v2-') as temporary:
        root = Path(temporary)
        generator = root / 'generator.sh'
        generator.write_text(function('write_client_removal_hook', 'write_client_upgrade_roster') + '\n' +
                             function('write_prerm', 'write_postrm') + '\n')
        tools = root / 'bin'; tools.mkdir()
        systemctl = tools / 'systemctl'
        calls = root / 'calls'; calls.write_text('')
        systemctl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$AEGIS_CALLS"\n')
        systemctl.chmod(0o755)
        env = os.environ | {'PATH': f'{tools}:/usr/bin:/bin', 'AEGIS_CALLS': str(calls)}
        for package in ('aegis-client', 'aegis-server'):
            path = root / (package + '.prerm')
            subprocess.run(['/bin/bash', '-c', 'source "$1"; write_prerm "$2" "$3"',
                            'bash', str(generator), str(path), package], check=True, timeout=5)
            if package == 'aegis-client':
                # Missing authenticated build roster must refuse remove and
                # deconfigure before any system mutation, on every host UID.
                path.write_text(path.read_text().replace('AEGIS_INCOMING_ROSTER_JSON', repr('{}')))
                compile(path.read_text(), str(path), 'exec')
                for action in ('remove', 'deconfigure'):
                    result = subprocess.run(['python3', '-I', '-B', str(path), action],
                                            env=env, capture_output=True, timeout=5)
                    assert result.returncode != 0 and b'typed serial teardown' in result.stderr
                    assert calls.read_text() == ''
                subprocess.run(['python3', '-I', '-B', str(path), 'upgrade'], env=env,
                               check=True, capture_output=True, timeout=5)
            else:
                subprocess.run(['/bin/sh', str(path), 'remove'], env=env, check=True, timeout=5)
                assert 'disable --now aegis-server.service' in calls.read_text()
    spec = importlib.util.spec_from_file_location('passive_removal_contract',
        ROOT / 'scripts/tests/test_auto_passive_package_uninstall.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromModule(module))
    assert result.wasSuccessful(), 'passive/active owner regression'
    print('PASS: split DEB prerm passive/active owner and authenticated-source gates')


if __name__ == '__main__':
    main()
