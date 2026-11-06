#!/usr/bin/env python3
"""Exercise generated split DEB postinst scripts with inert system tools."""

import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def stub(directory, name, body):
    path = directory / name
    path.write_text('#!/bin/sh\n' + body)
    path.chmod(0o755)


def run(script, args, env, success=True):
    result = subprocess.run(['/bin/sh', str(script), *args], env=env,
                            capture_output=True, text=True, timeout=5)
    if (result.returncode == 0) != success:
        raise AssertionError(f'{script.name} {args}: exit {result.returncode}; {result.stderr}')


def main():
    source = (ROOT / 'scripts/build-split-deb-packages.sh').read_text()
    match = re.search(r'(write_postinst\(\) \{\n.*?\n\})\n\nwrite_prerm\(\)', source, re.S)
    if match is None:
        raise AssertionError('split DEB postinst generator unavailable')
    with tempfile.TemporaryDirectory(prefix='aegis-split-scriptlets-') as scratch:
        work = Path(scratch)
        helper = work / 'generator.sh'
        helper.write_text(match.group(1) + '\n')
        bins = work / 'bin'
        bins.mkdir()
        live = work / 'live-systemd'
        live.mkdir()
        init_root = work / 'init-root'
        init_root.touch()
        config = work / 'client-config'
        config.mkdir()
        calls = work / 'calls'
        state = work / 'enabled-state'
        stub(bins, 'systemd-sysusers', '[ "${AEGIS_FAIL:-}" != sysusers ]\n')
        stub(bins, 'systemd-tmpfiles', '[ "${AEGIS_FAIL:-}" != tmpfiles ]\n')
        stub(bins, 'stat', '''if [ "${AEGIS_FOREIGN_ROOT:-0}" = 0 ] || [ "${3:-}" = / ]; then
  printf '1:2\\n'
else
  printf '3:4\\n'
fi
''')
        stub(bins, 'systemctl', '''printf '%s\\n' "$*" >> "$AEGIS_CALLS"
[ "${AEGIS_FAIL:-}" = systemctl ] && exit 1
[ "$1" = preset ] && printf 'enabled\\n' > "$AEGIS_STATE"
exit 0
''')
        env = os.environ | {
            'PATH': f'{bins}:/usr/bin:/bin',
            'AEGIS_CALLS': str(calls),
            'AEGIS_STATE': str(state),
        }
        for package in ('aegis-server', 'aegis-client'):
            postinst = work / f'{package}.postinst'
            subprocess.run(['/bin/bash', '-c', 'source "$1"; write_postinst "$2" "$3"',
                            'bash', str(helper), str(postinst), package], check=True, timeout=5)
            text = postinst.read_text()
            for original, replacement in (
                ('/run/systemd/system', str(live)),
                ('/proc/1/root', str(init_root)),
                ('CLIENT_CONFIG_DIR="/etc/aegis/client"', f'CLIENT_CONFIG_DIR="{config}"'),
            ):
                text = text.replace(original, replacement)
            postinst.write_text(text)
            subprocess.run(['/bin/sh', '-n', str(postinst)], check=True, timeout=5)
            state.write_text('absent\n')
            calls.write_text('')
            run(postinst, ['configure'], env)
            if state.read_text() != 'enabled\n' or calls.read_text().count('preset ') != 1:
                raise AssertionError(f'{package}: first install did not preset exactly once')
            state.write_text('disabled\n')
            calls.write_text('')
            run(postinst, ['configure', '0.3.49'], env)
            if state.read_text() != 'disabled\n' or calls.read_text() != 'daemon-reload\n':
                raise AssertionError(f'{package}: upgrade changed administrator state')
            for failure in (('sysusers', 'tmpfiles', 'systemctl') if package == 'aegis-server'
                            else ('tmpfiles', 'systemctl')):
                run(postinst, ['configure'], env | {'AEGIS_FAIL': failure}, success=False)
            calls.write_text('')
            run(postinst, ['configure'], env | {'AEGIS_FOREIGN_ROOT': '1', 'AEGIS_FAIL': 'systemctl'})
            if calls.read_text():
                raise AssertionError(f'{package}: foreign root contacted systemctl')
            print(f'PASS: {package} initial/upgrade/failures/foreign-root')


if __name__ == '__main__':
    main()
