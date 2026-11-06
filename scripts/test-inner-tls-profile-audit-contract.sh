#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
import json,pathlib,shutil,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1])
with tempfile.TemporaryDirectory() as raw:
    target=pathlib.Path(raw)/'units'
    shutil.copytree(root/'packaging/systemd/profiles/inner-tls',target)
    def check(status):
        result=subprocess.run([sys.executable,str(root/'scripts/audit-inner-tls-profile.py'),'--role','relay','--role','authority','--role','ingress','--systemd-dir',str(target)],capture_output=True,text=True,check=False)
        receipt=json.loads(result.stdout)
        assert receipt['status']==status and result.returncode==(0 if status=='MATCH' else 1)
        assert receipt['writes_performed'] is False
        return receipt
    check('MATCH')
    unit=target/'aegis-v3-online.target';original=unit.read_bytes()
    unit.write_bytes(original+b'# drift\n');check('DRIFT');unit.write_bytes(original)
    unit.unlink();check('DRIFT')
    unit.symlink_to(root/'Cargo.toml');r=check('DRIFT')
    assert next(x for x in r['files'] if x['path']==unit.name)['status']=='UNREADABLE'
    assert 'deployed_sha256' not in next(x for x in r['files'] if x['path']==unit.name)
print('PASS: matching, modified, missing and symlink deployment files')
PY
