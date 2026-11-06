#!/usr/bin/env bash
# Exercise the real config writer in temporary files without installing anything.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "${ROOT}" <<'PY'
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

source = (Path(sys.argv[1]) / 'install.sh').read_text()
match = re.search(r'^inject_client_socks_auth_token\(\) \{\n.*?^\}', source, re.M | re.S)
assert match, 'production SOCKS credential writer missing'
random_helper = re.search(r'^random_token\(\) \{\n.*?^\}', source, re.M | re.S)
assert random_helper, 'production token helper missing'

with tempfile.TemporaryDirectory(prefix='aegis-socks-token-contract-') as temporary:
    work = Path(temporary)
    wrapper = work / 'python3'
    wrapper.write_text('''#!/usr/bin/env bash
set -euo pipefail
# Only isolated mode, the stdin marker and config path may cross this boundary.
[[ $# -eq 3 && "$1" == '-I' && "$2" == '-' && "$3" == "$AEGIS_TEST_CONFIG" ]] || exit 91
exec "$AEGIS_TEST_REAL_PYTHON" "$@"
''')
    wrapper.chmod(0o755)
    harness = work / 'writer.sh'
    harness.write_text('set -euo pipefail\n' + random_helper[0] + '\n' + match[0] +
                       '\ninject_client_socks_auth_token "$1"\n')
    config = work / 'client.toml'
    env = dict(os.environ, PATH=str(work) + os.pathsep + os.environ['PATH'],
               AEGIS_TEST_REAL_PYTHON=sys.executable, AEGIS_TEST_CONFIG=str(config))
    prefix = '[relay]\nserver = "relay.example.test:443"\nauth_token = "fixture-only"\n'
    for socks in ['', '[socks]\nlisten = "127.0.0.1:1080"\n',
                  '[socks]\nlisten = "127.0.0.1:1080"\nauth_token = "old-fixture-only"\n']:
        original = tomllib.loads(prefix + socks)
        config.write_text(prefix + socks)
        config.chmod(0o644)
        previous = None
        for _ in range(2):
            result = subprocess.run(['bash', str(harness), str(config)], env=env,
                                    capture_output=True, timeout=10)
            assert result.returncode == 0, 'writer failed or passed extra interpreter arguments'
            assert not result.stdout and not result.stderr, 'writer emitted unexpected output'
            parsed = tomllib.loads(config.read_text())
            token = parsed['socks']['auth_token']
            assert re.fullmatch('[0-9a-f]{64}', token) and token != previous
            assert parsed['relay'] == original['relay']
            if 'socks' in original:
                assert parsed['socks']['listen'] == original['socks']['listen']
            assert stat.S_IMODE(config.stat().st_mode) == 0o600
            previous = token

print('PASS: SOCKS credential writer has no token argument/output, preserves config and rotates private credentials')
PY
