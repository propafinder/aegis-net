#!/usr/bin/env bash
# Execute the installer's actual packaged provenance boundary on bounded files.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 -I - "$ROOT" <<'PY'
import hashlib,json,re,subprocess,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1])
source=(root/'install.sh').read_text()
marker='python3 -I - "${ROOT}/bundle.manifest.json" "${ROOT}" "${ROLE}" <<\'PY\'\n'
assert source.count(marker)==1
program=source.split(marker,1)[1].split('\nPY\n',1)[0]
# Obtain the producer's immutable v1 leaves, then independently exercise the
# consumer's fixed policy with matching, omitted and malicious inventories.
producer=(root/'tools/measure/src/public_client_delivery.rs').read_text()
array=producer.split('const PAYLOAD: &[&str] = &[',1)[1].split('];',1)[0]
v1=set(re.findall(r'"([^"\n]+)"',array))|{'SHA256SUMS'}
assert len(v1)==18
guard='scripts/aegis-device-egress-guard.sh'
cases=0
with tempfile.TemporaryDirectory(prefix='aegis-client-provenance-') as raw:
    work=Path(raw)
    def check(schema,leaves,ok=True,role='client',mutation=None):
        global cases
        cases+=1
        case=work/str(cases);case.mkdir()
        for name in leaves:
            path=case/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'synthetic public fixture\n')
        manifest={'schema':schema,'cargo_lock_sha256':'00'*32,'files':sorted(leaves),
            'binaries':{'aegis-client':{'path':'bin/aegis-client',
                'sha256':hashlib.sha256((case/'bin/aegis-client').read_bytes()).hexdigest(),
                'features':['raw-socket','chrome-like-tls','chrome-like-quic']}}}
        if mutation:mutation(case,manifest)
        path=case/'bundle.manifest.json';path.write_text(json.dumps(manifest))
        result=subprocess.run([sys.executable,'-I','-c',program,str(path),str(case),role],capture_output=True,text=True)
        assert (result.returncode==0)==ok,(cases,result.stdout,result.stderr)
    for version,leaves in [('v1',v1),('v2',v1|{guard})]:
        schema='aegis_client_release_bundle_manifest_'+version
        check(schema,leaves)
        check(schema,leaves,False,role='server')
        for extra in ['bin/aegis-server','Cargo.lock','src/private.rs','credentials.txt']:
            check(schema,leaves|{extra},False)
        check(schema,leaves-{'scripts/lib/root-state.sh'},False)
        check(schema,leaves,False,mutation=lambda p,m:m['files'].append({}))
        check(schema,leaves,False,mutation=lambda p,m:m['files'].append('install.sh'))
        check(schema,leaves,False,mutation=lambda p,m:(p/'unexpected').write_text('extra'))
        check(schema,leaves,False,mutation=lambda p,m:(p/'linked').symlink_to('README.txt'))
        check(schema,leaves,False,mutation=lambda p,m:(p/'hardlinked').hardlink_to(p/'README.txt'))
    check('aegis_client_release_bundle_manifest_v1',v1|{guard},False)
    check('aegis_client_release_bundle_manifest_v2',v1,False)
    check('aegis_client_release_bundle_manifest_v3',v1|{guard},False)
print(f'PASS: {cases} actual installer provenance cases; immutable v1/v2 inventory, roles and links')
PY
