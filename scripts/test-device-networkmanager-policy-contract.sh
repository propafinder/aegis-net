#!/usr/bin/env bash
# Exercise the shipped helper bodies in a private filesystem with inert NM/D-Bus.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 -I - "$ROOT" <<'PY'
import pathlib, shutil, subprocess, sys, tempfile
root = pathlib.Path(sys.argv[1])
source = (root / 'scripts/aegis-device-egress-guard.sh').read_text()
with tempfile.TemporaryDirectory(prefix='aegis-nm-contract-') as temporary:
    target = pathlib.Path(temporary)
    shutil.copyfile(root / 'install.sh', target / 'install.sh')
    for marker, module, test in (
        ('PY_NM_POLICY', 'nm_owned_config.py', 'test_nm_owned_config.py'),
        ('PY_NM_VALIDATE', 'validator.py', 'test_validator.py'),
    ):
        start = "<<'" + marker + "'\n"
        assert source.count(start) == 1 and source.count('\n' + marker + '\n') == 1
        body = source.split(start, 1)[1].split('\n' + marker + '\n', 1)[0]
        (target / module).write_text(body + '\n')
        fixture = (root / 'scripts/tests/networkmanager' / test).read_text()
        if test == 'test_validator.py':
            # The copied deadline fixture must require the shipped isolated
            # assessor invocation; its cases and policy assertions stay intact.
            old = "body.split(\"python3 -c '\\n\", 1)"
            new = "body.split(\"python3 -I -c '\\n\", 1)"
            assert fixture.count(old) == 1
            fixture = fixture.replace(old, new, 1)
        (target / test).write_text(fixture)
        subprocess.run([sys.executable, '-I', str(target / test)], check=True, timeout=90)
print('PASS: production NetworkManager ownership crash/retry and applied-policy contracts; no native networking claim')
PY
