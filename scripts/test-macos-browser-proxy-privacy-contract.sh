#!/usr/bin/env bash
# Exercise the generated installer with synthetic credentials and mocked OS tools.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "${ROOT}" <<'PY'
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

root = Path(sys.argv[1])
source = Path(os.environ.get('AEGIS_TEST_MACOS_BUILDER_SOURCE', root / 'scripts/build-macos-client-tarball.sh')).read_text()
match = re.search(r'^cat > "\$\{BUNDLE_DIR\}/install-macos-client.sh" <<\'EOF\'\n(.*?)^EOF$', source, re.M | re.S)
assert match, 'generated installer missing'
token = '42' * 32  # Fixture only: never a real device or local proxy credential.
real_awk = shutil.which('awk')
assert real_awk, 'awk required'

with tempfile.TemporaryDirectory(prefix='aegis-macos-proxy-contract-') as temporary:
    work = Path(temporary)
    package = work / 'package'
    (package / 'bin').mkdir(parents=True)
    installer = package / 'install-macos-client.sh'
    installer_text = match[1]
    # The generated installer admits authored public texts before fetching the
    # private config. Populate that real prerequisite without mocking the Rust
    # helper or weakening any browser credential/privacy assertion below.
    project_placeholders = {
        'LICENSE-MIT': '__AEGIS_PROJECT_LICENSE_MIT_SHA256__',
        'LICENSE-APACHE': '__AEGIS_PROJECT_LICENSE_APACHE_SHA256__',
        'NOTICE': '__AEGIS_PROJECT_NOTICE_SHA256__',
    }
    for name, placeholder in project_placeholders.items():
        source_text = root / name
        assert source_text.is_file() and not source_text.is_symlink(), 'regular authored project text required'
        public_bytes = source_text.read_bytes()
        assert 0 < len(public_bytes) <= 65536, 'project text exceeds typed public payload bound'
        assert installer_text.count(placeholder) == 1, 'generated closed project hash placeholder missing or duplicated'
        destination_text = package / name
        destination_text.write_bytes(public_bytes)
        destination_text.chmod(0o644)
        assert destination_text.read_bytes() == public_bytes, 'synthetic package project bytes differ'
        installer_text = installer_text.replace(placeholder, hashlib.sha256(public_bytes).hexdigest())
    assert all(placeholder not in installer_text for placeholder in project_placeholders.values()), 'project hash placeholder retained'
    installer.write_text(installer_text)
    client = package / 'bin/aegis-client'
    actual_client = Path(os.environ.get('AEGIS_TEST_SECRET_CLIENT', root / 'target/debug/aegis-client')).resolve()
    assert actual_client.is_file() and os.access(actual_client, os.X_OK), 'actual compiled Rust client required'
    shutil.copyfile(actual_client, client);client.chmod(0o755)
    manifest = dict(version='fixture', git_sha='fixture', build_timestamp='fixture', platform='macos', arch='aarch64', target_triple='aarch64-apple-darwin')
    (package / 'macos-client-bundle.manifest.json').write_text(json.dumps(manifest, indent=2))
    templates = package / 'packaging/launchd'
    templates.mkdir(parents=True)
    shutil.copyfile(root / 'packaging/launchd/dev.aegis.client.plist', templates / 'dev.aegis.client.plist')
    bundle = work / 'client-bundle'
    bundle.mkdir()
    (bundle / 'aegis-client.toml').write_text('mode = "relay"\n[socks]\nlisten = "127.0.0.1:1080"\nauth_user = "desktop-test"\n[relay]\nauth_token = "synthetic-relay-fixture"\nserver = "192.0.2.9:443"\nserver_name = "fixture.example"\nca_cert = "__CLIENT_CA_CERT_PATH__"\n')
    (bundle / 'ca.pem').write_text('fixture-only\n')
    archive = work / 'bundle.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        tar.add(bundle, arcname='client-bundle')

    access = work / 'client-access-url.txt'
    access.write_text('file://' + str(archive));access.chmod(0o600)

    mocks = work / 'mocks'
    mocks.mkdir()
    def executable(path, text):
        path.write_text(text)
        path.chmod(0o755)
    executable(mocks / 'awk', '#!' + sys.executable + '\n' + '''import os, sys
from pathlib import Path
if any('42' * 32 in arg for arg in sys.argv[1:]):
    Path(os.environ['AEGIS_TEST_ARGV_LEAK']).write_text('synthetic credential crossed argv')
    raise SystemExit(91)
os.execv(os.environ['AEGIS_TEST_REAL_AWK'], [os.environ['AEGIS_TEST_REAL_AWK']] + sys.argv[1:])
''')
    executable(mocks / 'openssl', '#!/bin/sh\n[ "$1 $2 $3" = "rand -hex 32" ] || exit 92\nprintf "%s\\n" "' + token + '"\n')
    executable(mocks / 'launchctl', '#!/bin/sh\nprintf "%s\\n" "$*" >> "$AEGIS_TEST_LAUNCHCTL"\nexit 0\n')
    executable(mocks / 'networksetup', '#!/bin/sh\nexit 93\n')
    helper = package / 'bin/aegis-proxy-keychain'
    executable(helper, '#!' + sys.executable + '\n' + '''import os, sys
from pathlib import Path
if sys.argv[1:] != ['1080', 'desktop-test']:
    raise SystemExit(94)
if sys.stdin.buffer.read() != ('42' * 32 + '\\n').encode():
    raise SystemExit(95)
Path(os.environ['AEGIS_TEST_HELPER_CALLED']).write_text('stdin-only credential received')
raise SystemExit(int(os.environ['AEGIS_TEST_HELPER_STATUS']))
''')
    if os.geteuid() == 0:
        raise SystemExit('this contract requires a non-root runner; it never uses a real Keychain')
    for failure in (False, True):
        home = work / ('failure-home' if failure else 'success-home')
        home.mkdir()
        argv_leak = home / 'argv-leak'
        launchctl = home / 'launchctl-calls'
        called = home / 'helper-called'
        env = dict(os.environ, AEGIS_INSTALL_TMPDIR_CANDIDATES=str(home), PATH=str(mocks) + os.pathsep + os.environ['PATH'],
                   AEGIS_TEST_REAL_AWK=real_awk, AEGIS_TEST_ARGV_LEAK=str(argv_leak),
                   AEGIS_TEST_LAUNCHCTL=str(launchctl), AEGIS_TEST_HELPER_CALLED=str(called),
                   AEGIS_TEST_HELPER_STATUS='23' if failure else '0')
        result = subprocess.run(['/bin/bash', str(installer), '--bundle-url-file', str(access),
                                 '--prepare-browser-proxy', '--service-mode', 'launchagent', '--user-home', str(home)],
                                cwd=package, env=env, capture_output=True, timeout=30)
        assert not argv_leak.exists(), 'config writer exposed synthetic credential in argv'
        assert token.encode() not in result.stdout + result.stderr, 'installer printed synthetic credential'
        assert called.exists(), 'helper did not receive the credential exclusively via stdin'
        config = home / '.config/aegis/aegis.toml'
        content = config.read_text()
        assert f'auth_token = "{token}"' in content, 'private config credential differs from helper stdin'
        assert 'auth_user = "desktop-test"' in content and 'server = "192.0.2.9:443"' in content
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        if failure:
            assert result.returncode != 0, 'helper failure incorrectly reported success'
            assert b'client installed' not in result.stdout and b'Browser credential ready.' not in result.stdout
            assert not launchctl.exists(), 'service was launched despite credential preparation failure'
        else:
            assert result.returncode == 0, 'synthetic successful installation failed'
            assert 'bootstrap' in launchctl.read_text(), 'successful preparation did not precede service start'
        assert not list(home.glob('aegis-bundle.*')), 'temporary bundle directory retained'

print('PASS: macOS installer keeps proxy credentials out of argv/output and refuses service start after preparation failure')
PY
