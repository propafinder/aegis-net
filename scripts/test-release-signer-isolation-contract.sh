#!/usr/bin/env bash
# Offline workflow execution with ephemeral test keys and inert metadata only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import copy, datetime, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path
root=Path(sys.argv[1]); text=(root/'.github/workflows/release.yml').read_text()
signer=text.split('\n  sign-release-manifests:\n',1)[1].split('\n  prepare-public-client:\n',1)[0]
assembler=text.split('\n  assemble-delivery:\n',1)[1].split('\n  sign-release-manifests:\n',1)[0]
verification=text.split('\n  prepare-public-client:\n',1)[1].split('\n  publish:\n',1)[0]
publisher=text.split('\n  publish:\n',1)[1]
assert 'environment: release' in signer
assert 'environment: release' not in assembler+verification
assert 'SIGNING_KEY' not in assembler+verification
for forbidden in ('actions/checkout@','rust-toolchain@','rust-cache@','cargo ', './scripts/', 'tar -', 'bash ./'):
    assert forbidden not in signer, ('signer executes release code', forbidden)
assert signer.count('secrets.AEGIS_MANIFEST_SIGNING_KEY')==1
assert 'name: unsigned-release-manifests' in signer and 'unsigned-operator-delivery' not in signer
assert 'needs: [assemble-delivery, sign-release-manifests]' in verification
assert 'publish_release:' in text
assert 'inputs.publish_release' not in signer+assembler+verification
assert "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && !inputs.build_only && inputs.publish_release" in publisher

def step(name):
    start=text.index('      - name: '+name+'\n')
    tail=text[start:]; marker='        run: |\n'; tail=tail.split(marker,1)[1]
    lines=[]
    for line in tail.splitlines():
        if line and not line.startswith('          '): break
        lines.append(line[10:] if line else '')
    return '\n'.join(lines)+'\n'
validate=step('Validate signing input without executing release code')
sign=step('Sign release manifest (ed25519 anchor)')
assert '${{' not in validate+sign
pin=re.search(r'AEGIS_MANIFEST_PINNED_PUBKEY="(.*?)"',(root/'bootstrap-install.sh').read_text(),re.S)[1]
assert pin in sign, 'workflow pin differs from bootstrap pin'
openssl=shutil.which('openssl'); assert openssl
with tempfile.TemporaryDirectory(prefix='aegis-signer-fixture-') as tmp:
    work=Path(tmp); manifests=work/'manifests'; manifests.mkdir()
    env={**os.environ,'GITHUB_SHA':'a'*40,'GITHUB_EVENT_NAME':'workflow_dispatch',
        'AEGIS_INPUT_TAG_NAME':'v0.0.1-rc.7','GITHUB_REPOSITORY':'fixture-owner/fixture-repo','GITHUB_RUN_NUMBER':'123','GITHUB_RUN_ID':'456',
        'GH_TOKEN':'inert-fixture-only','RUNNER_TEMP':str(work),
        'AEGIS_GOVERNANCE_CHECKED_AT':str(int(time.time())), 'AEGIS_GOVERNANCE_SOURCE_SHA':'a'*40}
    run_identity={'id':456,'run_number':123,'head_sha':'a'*40,'path':'.github/workflows/release.yml','event':'workflow_dispatch',
        'repository':{'full_name':'fixture-owner/fixture-repo'},'head_repository':{'full_name':'fixture-owner/fixture-repo'},
        'created_at':datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
    env['FIXTURE_RUN_JSON']=json.dumps(run_identity)
    validate_body=validate.split("<<'PYCODE'\n",1)[1].split('\nPYCODE',1)[0]
    # Execute the complete real validator with only its HTTP transport mocked.
    # No network request or production signing credential is used.
    api_fixture='''import io, os, urllib.request
class FixtureApi:
    def open(self, request, timeout):
        assert request.full_url == 'https://api.github.com/repos/fixture-owner/fixture-repo/actions/runs/456'
        assert request.get_header('Authorization') == 'Bearer inert-fixture-only'
        assert timeout == 15
        return io.BytesIO(os.environ['FIXTURE_RUN_JSON'].encode())
urllib.request.build_opener = lambda *args: FixtureApi()
'''
    files={}
    for arch,suffix in [('x86_64',''),('aarch64','-aarch64')]:
        for public in [False,True]:
            prefix='aegis-client' if public else 'aegis'
            name=('client-release' if public else 'release')+f'.manifest{suffix}.json'
            m={'schema':'aegis_linux_release_manifest_v1','git_sha':'a'*40,'version':'0.0.1','channel':'rc','prerelease':True,
                'platform':'linux','arch':arch,'target_triple':f'{arch}-unknown-linux-gnu',
                'artifacts':{'bundle':{'archive':{'path':f'{prefix}-0.0.1-linux-{arch}.tar.gz','sha256':'b'*64}}}}
            if not public:
                research_name=f'aegis-research-0.0.1-linux-{arch}'
                m['distribution']='private_administrative_operator'
                m['artifacts']['deb']={'status':'ready',
                    'manifest_path':'split-deb-packages.manifest.json' if arch=='x86_64' else 'split-deb-packages-aarch64.manifest.json',
                    'manifest_sha256':'f'*64}
                m['artifacts']['delivery_inventory']={'path':'operator-files.manifest.json','sha256':'9'*64}
                m['artifacts']['private_research']={'schema':'aegis_private_research_delivery_v1','distribution':'private_research_only',
                    'directory':research_name,'target_triple':f'{arch}-unknown-linux-gnu','source_commit':'a'*40,
                    'manifest_path':f'{research_name}/research.manifest.json','manifest_sha256':'d'*64,
                    'archive':{'path':research_name+'.tar.gz','sha256_path':research_name+'.tar.gz.sha256','sha256':'e'*64},
                    'automatic_service_activation':False,'installed_fullwide_owner':False}
            if public: m.update(distribution='public_client',bootstrap={'sha256':'c'*64})
            files[name]=m
    def write(items):
        for path in manifests.iterdir(): path.unlink()
        for name,value in items.items(): (manifests/name).write_text(json.dumps(value))
    def run(script,good=True,extra=None):
        # The production workflow selects Linux /usr/bin/openssl. The fixture
        # uses the host OpenSSL for Darwin compatibility; no production pin or
        # workflow bytes are modified on disk.
        argv=[sys.executable,'-I','-c',api_fixture+'\nexec('+repr(validate_body)+')'] if script==validate else ['bash','-c',script.replace('/usr/bin/openssl',openssl)]
        result=subprocess.run(argv,cwd=work,
            env={**env,**(extra or {})},capture_output=True,text=True,timeout=25)
        assert (result.returncode==0)==good,(result.stdout,result.stderr)
        return result
    write(files); run(validate)
    policies=[json.loads((manifests/name).read_text())['release_policy'] for name in files]
    assert all(p==policies[0] for p in policies)
    assert policies[0]['sequence']==123 and policies[0]['expires_at_unix']-policies[0]['issued_at_unix']==30*86400
    first_bytes={name:(manifests/name).read_bytes() for name in files}
    run(validate)
    assert first_bytes=={name:(manifests/name).read_bytes() for name in files}, 'same run regenerated signed policy bytes'
    for field,value in [('id',999),('run_number',1),('head_sha','f'*40),('path','.github/workflows/other.yml'),
                        ('event','pull_request'),('created_at','2000-01-01T00:00:00Z'),('created_at','2099-01-01T00:00:00Z')]:
        bad={**run_identity,field:value};write(files);run(validate,False,{'FIXTURE_RUN_JSON':json.dumps(bad)})
    for field,value in [('git_sha','d'*40),('arch','other'),('version','1.0.0'),('prerelease',False)]:
        bad=copy.deepcopy(files);bad['client-release.manifest.json'][field]=value;write(bad);run(validate,False)
    for field,value in [('distribution','private_administrative_operator'),('source_commit','f'*40),
                        ('manifest_path','../research.manifest.json'),('manifest_sha256','unknown'),
                        ('automatic_service_activation',True),('installed_fullwide_owner',True)]:
        bad=copy.deepcopy(files);bad['release.manifest.json']['artifacts']['private_research'][field]=value;write(bad);run(validate,False)
    for field,value in [('path','aegis-0.0.1-linux-x86_64.tar.gz'),('sha256_path','../hash'),('sha256','unknown')]:
        bad=copy.deepcopy(files);bad['release.manifest.json']['artifacts']['private_research']['archive'][field]=value;write(bad);run(validate,False)
    for field,value in [('manifest_path','../split-deb-packages.manifest.json'),('manifest_sha256','unknown')]:
        bad=copy.deepcopy(files);bad['release.manifest.json']['artifacts']['deb'][field]=value;write(bad);run(validate,False)
    for field,value in [('path','../operator-files.manifest.json'),('sha256','unknown')]:
        bad=copy.deepcopy(files);bad['release.manifest.json']['artifacts']['delivery_inventory'][field]=value;write(bad);run(validate,False)
    bad=copy.deepcopy(files);bad['release.manifest-aarch64.json']['artifacts']['delivery_inventory']['sha256']='8'*64;write(bad);run(validate,False)
    bad=copy.deepcopy(files);del bad['release.manifest.json']['artifacts']['private_research'];write(bad);run(validate,False)
    bad=copy.deepcopy(files);bad['release.manifest.json']['distribution']='private_research_only';write(bad);run(validate,False)
    write(files);(manifests/'extra.json').write_text('{}');run(validate,False)
    write(files);(manifests/'release.manifest.json').write_bytes(b'x'*65537);run(validate,False)
    write(files);run(validate)
    key=work/'fixture.key';pub=work/'fixture.pub'
    subprocess.run([openssl,'genpkey','-algorithm','ed25519','-out',str(key)],check=True,capture_output=True)
    subprocess.run([openssl,'pkey','-in',str(key),'-pubout','-out',str(pub)],check=True,capture_output=True)
    fixture_sign=sign.replace(pin,pub.read_text().strip())
    expired = run(fixture_sign,False,extra={'AEGIS_MANIFEST_SIGNING_KEY_PEM':key.read_text(),
                 'AEGIS_GOVERNANCE_CHECKED_AT':str(int(time.time())-301)})
    assert 'before credential use' in expired.stderr
    assert not list(manifests.glob('*.sig')), 'expired admission produced a signature'
    assert not list(work.glob('aegis-signer.*')), 'expired admission retained key material'
    run(fixture_sign,extra={'AEGIS_MANIFEST_SIGNING_KEY_PEM':key.read_text()})
    for name in files:
        subprocess.run([openssl,'pkeyutl','-verify','-pubin','-inkey',str(pub),'-rawin','-in',str(manifests/name),'-sigfile',str(manifests/(name+'.sig'))],check=True,capture_output=True)
    assert not list(work.glob('aegis-signer.*')), 'temporary signing key directory retained'
print('PASS: isolated signer, four exact-source manifests, fixed trust anchor, scoped expiry policy, negative metadata fixtures, four ephemeral signatures')
PY
