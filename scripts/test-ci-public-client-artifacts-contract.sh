#!/usr/bin/env bash
# Synthetic public bytes only; no release build, network or artifact upload.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
import hashlib, io, json, pathlib, runpy, sys, tarfile, tempfile
root = pathlib.Path(sys.argv[1])
module = runpy.run_path(str(root / 'scripts/verify-ci-public-client-artifacts.py'))
verify, public = module['verify'], module['PUBLIC']
commit = 'a' * 40
bundle = 'aegis-client-0.3.50-linux-x86_64'
archive_name = bundle + '.tar.gz'
checksum_name = archive_name + '.sha256'

def fixture(directory, mutation=lambda receipt, contents, manifest: None):
    manifest = dict(schema='aegis_client_release_bundle_manifest_v2', distribution='public_client',
                    bundle_name=bundle, git_sha=commit, platform='linux', arch='x86_64', target_triple='x86_64-unknown-linux-gnu',
                    binaries={'aegis-client': {'path': 'bin/aegis-client', 'sha256': hashlib.sha256(b'inert public test bytes').hexdigest()}},
                    files=sorted(public - {'bundle.manifest.json'}))
    contents = {bundle + '/' + name: b'inert public test bytes' for name in public}
    receipt = dict(schema='aegis_release_contract_public_artifacts_v1', contract_result='PASS', contract_exit_code=0,
                   retention_result='PUBLIC_CLIENT_ARTIFACTS_COPIED', public_bundle=bundle,
                   public_bundle_schema=manifest['schema'], recorded_at_utc='fixture', scope='synthetic public input')
    mutation(receipt, contents, manifest)
    contents[bundle + '/bundle.manifest.json'] = json.dumps(manifest).encode()
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode='w:gz') as archive:
        for name, data in contents.items():
            member = tarfile.TarInfo(name); member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    data = archive_bytes.getvalue()
    (directory / archive_name).write_bytes(data)
    (directory / checksum_name).write_text(hashlib.sha256(data).hexdigest() + '  ' + archive_name + '\n')
    contents[archive_name] = data
    contents[checksum_name] = (directory / checksum_name).read_bytes()
    receipt['copied_file_sha256'] = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
    (directory / 'receipt.json').write_text(json.dumps(receipt))

cases = 0
def check(name, mutation=lambda r,c,m: None, after=lambda p: None, expected=commit, ok=False):
    global cases
    with tempfile.TemporaryDirectory(prefix='aegis-ci-public-artifacts-') as temporary:
        directory = pathlib.Path(temporary)
        fixture(directory, mutation); after(directory)
        try:
            selected = verify(directory, expected)
        except (AssertionError, OSError, ValueError, KeyError, tarfile.TarError):
            assert not ok, name
        else:
            assert ok and selected == archive_name, name
        cases += 1
        print('PASS artifact selector:', name)

check('exact successful public source', ok=True)
check('unselected operator-shaped sibling cannot enter upload paths', after=lambda p: (p/'operator.tar.gz').write_bytes(b'inert excluded bytes'), ok=True)
check('failed contract', lambda r,c,m: r.update(contract_result='FAIL'))
check('nonzero contract exit', lambda r,c,m: r.update(contract_exit_code=1))
check('retention failure', lambda r,c,m: r.update(retention_result='RETENTION_FAILED_AFTER_CONTRACT_PASS'))
check('unexpected receipt schema', lambda r,c,m: r.update(schema='unknown'))
check('unknown receipt contents refused', lambda r,c,m: r.update(unreviewed_private_data='inert rejected value'))
check('source differs from checkout', expected='b'*40)
check('wrong architecture', lambda r,c,m: m.update(arch='aarch64'))
check('wrong platform', lambda r,c,m: m.update(platform='darwin'))
check('binary manifest hash differs', lambda r,c,m: m['binaries']['aegis-client'].update(sha256='0'*64))
check('binary manifest path differs', lambda r,c,m: m['binaries']['aegis-client'].update(path='bin/aegis-server'))
check('duplicate manifest file', lambda r,c,m: m['files'].append(m['files'][0]))
check('operator distribution', lambda r,c,m: m.update(distribution='operator'))
check('server payload refused', lambda r,c,m: c.update({bundle+'/bin/aegis-server': b'inert excluded bytes'}))
check('source payload refused', lambda r,c,m: c.update({bundle+'/Cargo.lock': b'inert excluded bytes'}))
check('archive changed after retention', after=lambda p: (p/archive_name).write_bytes(b'changed'))
check('missing archive', after=lambda p: (p/archive_name).unlink())
check('checksum changed', after=lambda p: (p/checksum_name).write_text('incorrect'))
def linked(p):
    target=p/'archive-original'; (p/archive_name).rename(target); (p/archive_name).symlink_to(target)
check('linked archive refused', after=linked)

workflow = (root/'.github/workflows/ci.yml').read_text()
selection = workflow.split('      - name: "Contract: release bundle installer preflight"',1)[1].split('      - name: Phase D proof scaffold contracts',1)[0]
assert selection.count('bash ./scripts/test-release-bundle-contract.sh') == 1
assert 'AEGIS_RELEASE_CONTRACT_ARTIFACT_DIR: ${{ runner.temp }}/aegis-ci-public-client' in selection
assert '"$GITHUB_SHA" >> "$GITHUB_OUTPUT"' in selection
assert 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' in selection
assert 'retention-days: 7' in selection and 'if-no-files-found: error' in selection
paths = selection.split('          path: |\n',1)[1].strip().splitlines()
assert [p.strip() for p in paths] == [
    '${{ runner.temp }}/aegis-ci-public-client/${{ steps.public-client-artifact.outputs.archive }}',
    '${{ runner.temp }}/aegis-ci-public-client/${{ steps.public-client-artifact.outputs.archive }}.sha256',
    '${{ runner.temp }}/aegis-ci-public-client/receipt.json']
assert 'always()' not in selection and 'continue-on-error' not in selection
print(f'PASS: {cases} artifact selection cases and exact three-file successful-only CI upload contract')
PY
