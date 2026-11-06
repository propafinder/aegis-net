#!/usr/bin/env python3
"""Exercise the generated DEB/RPM install scriptlets with inert system tools."""

import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def extract_scriptlets():
    deb = (ROOT / 'scripts/build-deb-package.sh').read_text()
    match = re.search(r'cat > "\$\{DEBIAN_DIR\}/postinst" <<\'EOF\'\n(.*?)\nEOF', deb, re.S)
    if match is None:
        raise AssertionError('DEB postinst source unavailable')
    scripts = {'deb': match.group(1)}
    rpm = (ROOT / 'scripts/build-rpm-packages.sh').read_text()
    for name in ('SERVER_POST', 'CLIENT_POST'):
        match = re.search(rf"^{name}='(.*?)'\n", rpm, re.M | re.S)
        if match is None:
            raise AssertionError(f'RPM {name} source unavailable')
        body = match.group(1)
        assigned = subprocess.run(
            ['/bin/bash', '-c', f"{name}='{body}'\nprintf '%s' \"${name}\""],
            capture_output=True, text=True, check=True, timeout=5,
        ).stdout
        if assigned != body:
            raise AssertionError(f'RPM {name} assignment differs from extracted script')
        scripts[name] = '#!/bin/sh\n' + body
    return scripts


def write_stub(directory, name, body):
    path = directory / name
    path.write_text('#!/bin/sh\n' + body)
    path.chmod(0o755)


def run(script, arguments, env, expected):
    result = subprocess.run(
        ['/bin/sh', str(script), *arguments],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )
    if (result.returncode == 0) != expected:
        raise AssertionError(f'{script.name} {arguments}: exit {result.returncode}; stderr={result.stderr!r}')


def main():
    scripts = extract_scriptlets()
    with tempfile.TemporaryDirectory(prefix='aegis-scriptlets-') as scratch:
        work = Path(scratch)
        runtime = work / 'runtime-systemd'
        runtime.mkdir()
        proc_root = work / 'proc-init-root'
        proc_root.touch()
        bins = work / 'bin'
        bins.mkdir()
        state = work / 'enabled-state'
        calls = work / 'systemctl-calls'
        write_stub(bins, 'systemd-sysusers', '[ "${AEGIS_FAIL:-}" != sysusers ]\n')
        write_stub(bins, 'systemd-tmpfiles', '[ "${AEGIS_FAIL:-}" != tmpfiles ]\n')
        write_stub(bins, 'stat', '''if [ "${AEGIS_FOREIGN_ROOT:-0}" = 0 ] || [ "${3:-}" = / ]; then
  printf '1:2\\n'
else
  printf '3:4\\n'
fi
''')
        write_stub(bins, 'systemctl', '''printf '%s\\n' "$*" >> "$AEGIS_CALLS"
[ "${AEGIS_FAIL:-}" = systemctl ] && exit 1
[ "$1" = preset ] && printf 'enabled\\n' > "$AEGIS_STATE"
exit 0
''')
        env = os.environ.copy()
        env.update({
            'PATH': f'{bins}:/usr/bin:/bin',
            'AEGIS_STATE': str(state),
            'AEGIS_CALLS': str(calls),
        })
        for name, source in scripts.items():
            if '/run/systemd/system' not in source or '/proc/1/root' not in source:
                raise AssertionError(f'{name}: expected live-root source checks missing')
            # Substitute only the test copy; original builder source stays exact.
            source = source.replace('/run/systemd/system', str(runtime))
            source = source.replace('/proc/1/root', str(proc_root))
            path = work / f'{name}.sh'
            path.write_text(source + '\n')
            subprocess.run(['/bin/sh', '-n', str(path)], check=True, timeout=5)
            initial = ['configure'] if name == 'deb' else ['1']
            upgrade = ['configure', '0.1.0'] if name == 'deb' else ['2']
            state.write_text('absent\n')
            calls.write_text('')
            run(path, initial, env, True)
            if state.read_text() != 'enabled\n' or 'preset' not in calls.read_text():
                raise AssertionError(f'{name}: first install did not preset')
            state.write_text('disabled\n')  # independent admin choice
            calls.write_text('')
            run(path, upgrade, env, True)
            if state.read_text() != 'disabled\n' or 'daemon-reload' not in calls.read_text() or 'preset' in calls.read_text():
                raise AssertionError(f'{name}: upgrade changed admin enablement')
            failures = ('tmpfiles', 'systemctl') if name == 'CLIENT_POST' else ('sysusers', 'tmpfiles', 'systemctl')
            for failure in failures:
                run(path, initial, env | {'AEGIS_FAIL': failure}, False)
            calls.write_text('')
            run(path, initial, env | {'AEGIS_FOREIGN_ROOT': '1', 'AEGIS_FAIL': 'systemctl'}, True)
            if calls.read_text():
                raise AssertionError(f'{name}: foreign root contacted systemctl')
            print(f'PASS: {name} initial/upgrade/failures/foreign-root')


if __name__ == '__main__':
    main()
