#!/usr/bin/env python3
"""Inert offline intake regressions; no API, signing key or candidate execution."""
import copy
import datetime
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('intake', ROOT/'scripts/verify-linux-offline-release-intake.py')
intake = importlib.util.module_from_spec(spec); spec.loader.exec_module(intake)
sha = intake.sha
FEATURES = ['raw-socket', 'chrome-like-tls', 'chrome-like-quic']


def raw(value):
    return (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()


def bundle(manifest, public, leak=False, client_contents=None, client_sha=None, client_path=None,
           extra_dirs=0, extension=None):
    directory = manifest['artifacts']['bundle']['directory']
    payload = intake.module('shipping_client_inventory', (ROOT/'scripts/lib/shipping_client_inventory.py').read_bytes())
    helper = intake.module('test_inventory', (ROOT/'scripts/lib/device_candidate_verify.py').read_bytes())
    names = helper.public_payload(helper.CLIENT_BUNDLE_SCHEMA_V3) if public else {'bin/aegis-server', 'bin/aegis-client', helper.DEVICE_GUARD_PAYLOAD}
    files = {name: b'inert fixture payload\n' for name in names}
    if client_contents is not None:
        files['bin/aegis-client'] = client_contents
    if leak:
        files['src/private.rs'] = b'inert forbidden public source\n'
    sums = ''.join(f'{sha(contents)}  {name}\n' for name, contents in sorted(files.items())).encode()
    files['SHA256SUMS'] = sums
    inner = {key: manifest[key] for key in ('version', 'git_sha', 'arch', 'platform', 'target_triple')}
    inner.update(schema='aegis_client_release_bundle_manifest_v3' if public else 'aegis_release_bundle_manifest_v2',
                 distribution=manifest['distribution'], bundle_name=directory, files=sorted(files),
                 binaries={name: {'path': 'bin/'+name, 'sha256': sha(files['bin/'+name]),
                                  'features': FEATURES if name == 'aegis-client' else []}
                           for name in (('aegis-client',) if public else ('aegis-client', 'aegis-server'))})
    if client_sha is not None:
        inner['binaries']['aegis-client']['sha256'] = client_sha
    if client_path is not None:
        inner['binaries']['aegis-client']['path'] = client_path
    if public:
        inner.update(build_timestamp='2026-10-12T00:00:00Z', cargo_lock_sha256='b'*64,
                     runtime_abi={}, install_entrypoints=[])
        identity = 'c'*64; key = 'aegis-client@0.0.1#'+identity; sorted_features = sorted(FEATURES)
        resolved = sorted(FEATURES+['default']); binary_hash = sha(files['bin/aegis-client'])
        inventory = {'schema':'aegis_shipping_client_cargo_inventory_v1',
                     'scope':'selected_target_filtered_cargo_graph_not_compiler_linkage',
                     'native_payload_complete':False, 'compiler_linkage_proven':False,
                     'source_revision':inner['git_sha'], 'target_triple':inner['target_triple'],
                     'default_features':True, 'requested_features':sorted_features,
                     'cargo_lock_sha256':inner['cargo_lock_sha256'], 'client_binary_sha256':binary_hash,
                     'cargo_metadata_sha256':'d'*64, 'root_component':key,
                     'components':[{'key':key, 'name':'aegis-client', 'version':'0.0.1',
                                    'source_kind':'reviewed_local_manifest', 'source_identity_sha256':identity,
                                    'features':resolved, 'dependencies':[]}],
                     'producer':{'schema':'aegis_linux_client_build_record_v1', 'source_revision':inner['git_sha'],
                                 'target_triple':inner['target_triple'], 'cargo_lock_sha256':inner['cargo_lock_sha256'],
                                 'binary_sha256':binary_hash, 'default_features':True, 'requested_features':sorted_features,
                                 'resolved_root_features':resolved, 'compiler_artifact_message_sha256':'e'*64,
                                 'build_message_stream_sha256':'f'*64,
                                 'target_evidence':'explicit_cargo_target_and_fixed_producer_invocation'}}
        files[helper.CARGO_INVENTORY_PAYLOAD] = raw(inventory)
    files['SHA256SUMS'] = ''.join(f'{sha(contents)}  {name}\n' for name, contents in sorted(files.items())
                                if name != 'SHA256SUMS').encode()
    inner['files'] = sorted(files)
    files['bundle.manifest.json'] = raw(inner)
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as archive:
        for index in range(extra_dirs):
            info = tarfile.TarInfo(directory+'/inert-directory-'+str(index)); info.type = tarfile.DIRTYPE
            archive.addfile(info)
        if extension == 'gnu':
            contents = b'unsafe-hidden-long-name\x00'; info = tarfile.TarInfo('././@LongLink')
            info.type = tarfile.GNUTYPE_LONGNAME; info.size = len(contents)
            archive.addfile(info, io.BytesIO(contents))
        for name, contents in sorted(files.items()):
            info = tarfile.TarInfo(directory+'/'+name); info.size = len(contents); info.mode = 0o600
            if extension == 'pax' and name == sorted(files)[0]:
                info.pax_headers = {'comment': 'x'*(4*1024*1024)}
            archive.addfile(info, io.BytesIO(contents))
    return out.getvalue()


def fixture():
    now = int(time.time()); source = 'a'*40; repository = 'fixture-owner/fixture-repo'
    created = datetime.datetime.fromtimestamp(now-60, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    builder = {'id': 456, 'run_number': 123, 'run_attempt': 2, 'head_sha': source,
               'path': '.github/workflows/release.yml', 'event': 'workflow_dispatch', 'head_branch': 'main',
               'repository': {'full_name': repository}, 'head_repository': {'full_name': repository},
               'created_at': created, 'status': 'completed', 'conclusion': 'success'}
    ci = {**builder, 'id': 42, 'run_attempt': 3, 'event': 'push', 'path': '.github/workflows/ci.yml'}
    jobs = [{'id': i, 'name': name, 'run_id': 42, 'head_sha': source, 'status': 'completed', 'conclusion': 'success'}
            for i, name in enumerate(('rust', 'linux-arm64', 'darwin-contract', 'windows-rust', 'dependency-security'), 1)]
    record = {'schema': 'aegis_linux_offline_intake_record_v1', 'repository': repository, 'source_sha': source,
              'tag': 'v0.0.1-rc.7', 'captured_at_unix': now, 'author': 'author', 'last_pusher': 'pusher',
              'builder': builder, 'expected_builder': {'run_id': 456, 'run_attempt': 2},
              'source_ci': {'runs': [ci], 'current': ci, 'jobs': jobs}, 'expected_ci': {'run_id': 42, 'run_attempt': 3},
              'client_bundle_schema': 'aegis_client_release_bundle_manifest_v3', 'client_features': FEATURES}
    policy = {'schema': 'aegis_release_policy_v1', 'authority': f'github:{repository}:.github/workflows/release.yml',
              'sequence': 123, 'tag': record['tag'], 'issued_at_unix': now-60, 'expires_at_unix': now-60+30*86400}
    files = {'bootstrap-install.sh': b'#!/bin/sh\n# inert fixture; never executed\n'}
    manifests = {}
    for arch, suffix in [('x86_64', ''), ('aarch64', '-aarch64')]:
        for public in (False, True):
            prefix = 'aegis-client' if public else 'aegis'
            directory = f'{prefix}-0.0.1-linux-{arch}'; asset = directory+'.tar.gz'
            name = ('client-release' if public else 'release')+f'.manifest{suffix}.json'
            m = {'schema': 'aegis_linux_release_manifest_v1', 'git_sha': source, 'version': '0.0.1',
                 'channel': 'rc', 'prerelease': True, 'platform': 'linux', 'arch': arch,
                 'target_triple': arch+'-unknown-linux-gnu', 'release_policy': policy,
                 'distribution': 'public_client' if public else 'private_administrative_operator',
                 'artifacts': {'bundle': {'status': 'ready', 'directory': directory, 'archive': {'path': asset}}}}
            if public:
                m['bootstrap'] = {'path': 'bootstrap-install.sh', 'sha256': sha(files['bootstrap-install.sh'])}
            else:
                research_name = f'aegis-research-0.0.1-linux-{arch}'
                detached = raw({'schema': 'inert-fixture'})
                files[research_name+'.manifest.json'] = detached
                research_tar = io.BytesIO()
                with tarfile.open(fileobj=research_tar, mode='w:gz') as archive:
                    info = tarfile.TarInfo(research_name+'/research.manifest.json'); info.size = len(detached)
                    archive.addfile(info, io.BytesIO(detached))
                files[research_name+'.tar.gz'] = research_tar.getvalue()
                m['artifacts']['private_research'] = {
                    'schema': 'aegis_private_research_delivery_v1', 'distribution': 'private_research_only',
                    'directory': research_name, 'target_triple': m['target_triple'], 'source_commit': source,
                    'manifest_path': research_name+'/research.manifest.json', 'manifest_sha256': sha(detached),
                    'archive': {'path': research_name+'.tar.gz', 'sha256_path': research_name+'.tar.gz.sha256',
                                'sha256': sha(files[research_name+'.tar.gz'])},
                    'automatic_service_activation': False, 'installed_fullwide_owner': False}
            files[asset] = bundle(m, public)
            m['artifacts']['bundle']['archive']['sha256'] = sha(files[asset])
            files[name] = raw(m); manifests[name] = m
    ledger = {'schema': 'aegis_linux_offline_intake_ledger_v1', 'authority': policy['authority'],
              'minimum_sequence': 122, 'entries': []}
    approval = {'schema': 'aegis_linux_offline_intake_approval_v1', 'purpose': 'intake_only',
                'reviewer': 'independent-reviewer', 'issued_at_unix': now, 'expires_at_unix': now+3600}
    return record, approval, ledger, files, manifests


# The installed verifier refuses group-writable ancestry. Set fixture custody
# explicitly so a host's default umask (for example 0002) cannot make a
# positive test fail before it reaches the intake contract.
os.umask(0o077)
with tempfile.TemporaryDirectory(prefix='aegis-intake-regressions-') as temp:
    work = Path(temp)
    installed = work/'independently-installed-verifier'; installed.mkdir()
    for name in intake.BUNDLE_FILES:
        target = installed/name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/name, target); target.chmod(0o444)
    verifier_sha, payloads = intake.frozen_bundle(ROOT)
    anchor = intake.re.search(r'AEGIS_MANIFEST_PINNED_PUBKEY="(.*?)"', payloads['bootstrap-install.sh'].decode(), intake.re.S)[1].encode()+b'\n'
    cases = 0
    def run(label, alter=None, expected=True, zip_alter=None, extra_args=None, raw_alter=None, zip_link=False, program=None):
        global cases
        record, approval, ledger, files, manifests = fixture()
        if alter:
            alter(record, approval, ledger, files, manifests)
        case = work/label; case.mkdir(mode=0o700)
        path = case/'transport.zip'
        with zipfile.ZipFile(path, 'w') as z:
            for name, contents in files.items():
                if zip_link and name == 'bootstrap-install.sh':
                    info = zipfile.ZipInfo(name); info.create_system = 3; info.external_attr = (stat.S_IFLNK|0o777)<<16
                    z.writestr(info, contents)
                else:
                    z.writestr(name, contents)
            if zip_alter:
                zip_alter(z)
        record['files'] = {name: sha(contents) for name, contents in files.items()}
        record['transport_sha256'] = sha(path.read_bytes())
        approval.update(record_sha256=sha(raw(record)), verifier_sha256=verifier_sha,
                        ledger_sha256=sha(raw(ledger)), release_key_sha256=sha(anchor), files=record['files'])
        for name, contents in [('record', raw(record)), ('approval', raw(approval)), ('ledger', raw(ledger)), ('anchor', anchor)]:
            (case/name).write_bytes(contents)
        args = [sys.executable, '-I', str(program or installed/'scripts/verify-linux-offline-release-intake.py'),
                '--transport', str(path), '--record', str(case/'record'), '--approval', str(case/'approval'),
                '--ledger', str(case/'ledger'), '--trust-anchor', str(case/'anchor'), '--output', str(case/'receipt-r1'),
                '--expected-verifier-sha256', verifier_sha, '--expected-record-sha256', sha(raw(record)),
                '--expected-approval-sha256', sha(raw(approval)), '--expected-ledger-sha256', sha(raw(ledger))]
        if raw_alter:
            raw_alter(case)
        if extra_args:
            for flag, value in extra_args.items():
                args[args.index(flag)+1] = value
        result = subprocess.run(args, capture_output=True, timeout=40, text=True, cwd=case)
        assert (result.returncode == 0) == expected, (label, result.stdout, result.stderr)
        assert 'Traceback' not in result.stderr, (label, 'malformed input exposed a traceback')
        if expected:
            receipt = json.loads((case/'receipt-r1/receipt.json').read_text())
            assert receipt['status'] == 'INTAKE_ONLY' and receipt['files'] == record['files']
            assert not list(case.rglob('*.sig'))
            assert all(stat.S_IMODE(p.stat().st_mode) == 0o400 for p in (case/'receipt-r1/snapshot').iterdir())
            repeated = subprocess.run(args, capture_output=True, timeout=40)
            assert repeated.returncode != 0, 'receipt overwrite accepted'
        else:
            assert not (case/'receipt-r1/receipt.json').exists(), 'failed intake wrote success receipt'
        cases += 1
        return case
    accepted = run('accepted')
    # A producer can package the same final policy-bearing bytes for independent
    # custody without manufacturing an approval, ledger or signature.
    exporter = ROOT/'scripts/build-linux-offline-intake-transport.py'
    stage = work/'producer-final-files'; stage.mkdir(mode=0o700)
    with zipfile.ZipFile(accepted/'transport.zip') as source_zip:
        for name in source_zip.namelist():
            (stage/name).write_bytes(source_zip.read(name))
    transport = work/'producer-transport.zip'
    command = [sys.executable, '-I', str(exporter), '--source-dir', str(stage),
               '--tag', 'v0.0.1-rc.7', '--output', str(transport)]
    produced = subprocess.run(command, capture_output=True, text=True, timeout=40)
    assert produced.returncode == 0, produced.stderr
    claim = json.loads(produced.stdout)
    assert claim['status'] == 'PRODUCER_ONLY' and claim['transport_sha256'] == sha(transport.read_bytes())
    with zipfile.ZipFile(transport) as package:
        assert set(package.namelist()) == set(claim['files'])
        assert all(sha(package.read(name)) == digest for name, digest in claim['files'].items())
    exported_record = json.loads((accepted/'record').read_bytes())
    exported_approval = json.loads((accepted/'approval').read_bytes())
    exported_record['transport_sha256'] = claim['transport_sha256']
    exported_approval['record_sha256'] = sha(raw(exported_record))
    (accepted/'exported-record').write_bytes(raw(exported_record))
    (accepted/'exported-approval').write_bytes(raw(exported_approval))
    exported_intake = subprocess.run([sys.executable, '-I', str(installed/'scripts/verify-linux-offline-release-intake.py'),
        '--transport', str(transport), '--record', str(accepted/'exported-record'),
        '--approval', str(accepted/'exported-approval'), '--ledger', str(accepted/'ledger'),
        '--trust-anchor', str(accepted/'anchor'), '--output', str(accepted/'exported-intake-r1'),
        '--expected-verifier-sha256', verifier_sha, '--expected-record-sha256', sha(raw(exported_record)),
        '--expected-approval-sha256', sha(raw(exported_approval)),
        '--expected-ledger-sha256', sha((accepted/'ledger').read_bytes())],
        capture_output=True, text=True, timeout=40)
    assert exported_intake.returncode == 0, exported_intake.stderr
    assert json.loads((accepted/'exported-intake-r1/receipt.json').read_text())['status'] == 'INTAKE_ONLY'
    assert subprocess.run(command, capture_output=True, timeout=40).returncode != 0, 'exporter overwrote output'
    (stage/'bootstrap-install.sh').write_bytes(b'producer tamper')
    assert subprocess.run(command[:-1]+[str(work/'producer-tamper.zip')], capture_output=True,
                          timeout=40).returncode != 0, 'exporter accepted final manifest digest mismatch'
    assert not (work/'producer-tamper.zip').exists()
    (stage/'bootstrap-install.sh').unlink()
    (stage/'bootstrap-install.sh').symlink_to(accepted/'anchor')
    assert subprocess.run(command[:-1]+[str(work/'producer-link.zip')], capture_output=True,
                          timeout=40).returncode != 0, 'exporter followed a staged symlink'
    assert not (work/'producer-link.zip').exists()
    run('accepted-same-sequence-identical', lambda r,a,l,f,m: l['entries'].append(
        {'sequence':123, 'manifests':{name:sha(f[name]) for name in intake.MANIFESTS}}))
    run('checkout-verifier-refused', expected=False, program=ROOT/'scripts/verify-linux-offline-release-intake.py')
    helper_path = installed/'scripts/check-release-source-ci.py'
    helper_path.chmod(0o644)
    run('writable-installed-helper', expected=False)
    marker = work/'UNSAFE_HELPER_EXECUTED'
    helper_path.write_bytes(('from pathlib import Path\nPath('+repr(str(marker))+').touch()\n').encode()); helper_path.chmod(0o444)
    run('unpinned-installed-helper', expected=False)
    assert not marker.exists(), 'unapproved installed helper was executed before its pin check'
    helper_path.chmod(0o644); helper_path.write_bytes(payloads['scripts/check-release-source-ci.py']); helper_path.chmod(0o444)
    workflow_path = installed/'.github/workflows/release.yml'
    workflow_path.chmod(0o644); workflow_path.write_bytes(payloads['.github/workflows/release.yml']+b'\n# unapproved edit\n'); workflow_path.chmod(0o444)
    run('unpinned-installed-workflow', expected=False)
    workflow_path.chmod(0o644); workflow_path.write_bytes(payloads['.github/workflows/release.yml']); workflow_path.chmod(0o444)
    run('bad-verifier-pin', expected=False, extra_args={'--expected-verifier-sha256': 'f'*64})
    run('bad-record-pin', expected=False, extra_args={'--expected-record-sha256': 'f'*64})
    run('bad-approval-pin', expected=False, extra_args={'--expected-approval-sha256': 'f'*64})
    run('bad-ledger-pin', expected=False, extra_args={'--expected-ledger-sha256': 'f'*64})
    run('unapproved-key', expected=False, raw_alter=lambda c: (c/'anchor').write_bytes(b'not an approved public key\n'))
    run('missing-approval', expected=False, raw_alter=lambda c: (c/'approval').unlink())
    run('stale-capture', lambda r,a,l,f,m: r.update(captured_at_unix=int(time.time())-3601), False)
    run('stale-approval', lambda r,a,l,f,m: a.update(issued_at_unix=int(time.time())-3601), False)
    run('expired-approval', lambda r,a,l,f,m: a.update(expires_at_unix=int(time.time())-1), False)
    run('dependent-reviewer', lambda r,a,l,f,m: a.update(reviewer='AUTHOR'), False)
    run('builder-running', lambda r,a,l,f,m: r['builder'].update(status='in_progress'), False)
    run('builder-failed', lambda r,a,l,f,m: r['builder'].update(conclusion='failure'), False)
    run('builder-attempt-mismatch', lambda r,a,l,f,m: r['expected_builder'].update(run_attempt=1), False)
    run('ci-attempt-mismatch', lambda r,a,l,f,m: r['expected_ci'].update(run_attempt=2), False)
    run('ci-reread-attempt-changed', lambda r,a,l,f,m: r['source_ci'].update(
        current={**r['source_ci']['current'], 'run_attempt':4}), False)
    run('ci-required-skipped', lambda r,a,l,f,m: r['source_ci']['jobs'][0].update(conclusion='skipped'), False)
    run('ci-newer-failure', lambda r,a,l,f,m: r['source_ci']['runs'].append({**r['source_ci']['current'], 'id': 43, 'conclusion': 'failure'}), False)
    run('ci-duplicate-job', lambda r,a,l,f,m: r['source_ci']['jobs'].append(r['source_ci']['jobs'][0]), False)
    run('extra-file', lambda r,a,l,f,m: f.update({'extra.py': b'raise Exception("never execute")\n'}), False)
    run('duplicate-zip', expected=False, zip_alter=lambda z: z.writestr('bootstrap-install.sh', b'duplicate'))
    def link(z):
        info = zipfile.ZipInfo('extra-link'); info.create_system = 3; info.external_attr = (stat.S_IFLNK|0o777)<<16
        z.writestr(info, 'bootstrap-install.sh')
    run('zip-link', expected=False, zip_alter=link)
    run('allowlisted-zip-link', expected=False, zip_link=True)
    run('raw-transport-tamper', expected=False, raw_alter=lambda c: (c/'transport.zip').write_bytes(b'not the pinned transport'))
    run('transport-hardlink', expected=False, raw_alter=lambda c: os.link(c/'transport.zip', c/'transport-link.zip'))
    run('approval-symlink', expected=False, raw_alter=lambda c: ((c/'approval').rename(c/'real-approval'), (c/'approval').symlink_to(c/'real-approval')))
    def manifest_change(field, value):
        def mutate(r,a,l,f,m):
            name = 'client-release.manifest.json'; m[name][field] = value; f[name] = raw(m[name])
        return mutate
    run('wrong-role', manifest_change('distribution', 'private_administrative_operator'), False)
    run('wrong-source', manifest_change('git_sha', 'b'*40), False)
    run('wrong-arch', manifest_change('arch', 'aarch64'), False)
    def expired(r,a,l,f,m):
        r['builder']['created_at'] = '2000-01-01T00:00:00Z'
    run('expired-run-policy', expired, False)
    def altered_policy(r,a,l,f,m):
        name = 'release.manifest.json'; m[name]['release_policy']['sequence'] += 1; f[name] = raw(m[name])
    run('builder-policy-equivocation', altered_policy, False)
    run('ledger-equivocation', lambda r,a,l,f,m: l['entries'].append({'sequence':123,'manifests':{name:'f'*64 for name in intake.MANIFESTS}}), False)
    run('ledger-rollback', lambda r,a,l,f,m: l.update(minimum_sequence=124), False)
    def leak(r,a,l,f,m):
        name = 'client-release.manifest.json'; asset = m[name]['artifacts']['bundle']['archive']['path']
        f[asset] = bundle(m[name], True, leak=True); m[name]['artifacts']['bundle']['archive']['sha256'] = sha(f[asset]); f[name] = raw(m[name])
    run('public-source-leak', leak, False)
    def archive_mismatch(r,a,l,f,m):
        f['aegis-client-0.0.1-linux-x86_64.tar.gz'] += b'changed independently reapproved outer bytes'
    run('manifest-archive-mismatch', archive_mismatch, False)
    def operator_client(**changes):
        def alter(r,a,l,f,m):
            name = 'release.manifest.json'; asset = m[name]['artifacts']['bundle']['archive']['path']
            f[asset] = bundle(m[name], False, **changes)
            m[name]['artifacts']['bundle']['archive']['sha256'] = sha(f[asset]); f[name] = raw(m[name])
        return alter
    run('operator-client-hash-unbound', operator_client(client_sha='f'*64), False)
    run('operator-client-path-unbound', operator_client(client_path='bin/aegis-server'), False)
    run('operator-public-client-divergence', operator_client(client_contents=b'different inert operator client\n'), False)
    def unsafe_public_tar(**changes):
        def alter(r,a,l,f,m):
            name = 'client-release.manifest.json'; asset = m[name]['artifacts']['bundle']['archive']['path']
            f[asset] = bundle(m[name], True, **changes)
            m[name]['artifacts']['bundle']['archive']['sha256'] = sha(f[asset]); f[name] = raw(m[name])
        return alter
    run('raw-tar-5000-directories', unsafe_public_tar(extra_dirs=5000), False)
    run('raw-tar-pax-comment-4mib', unsafe_public_tar(extension='pax'), False)
    run('raw-tar-gnu-longname', unsafe_public_tar(extension='gnu'), False)
    def concatenated(r,a,l,f,m):
        name = 'client-release.manifest.json'; asset = m[name]['artifacts']['bundle']['archive']['path']
        f[asset] += gzip.compress(b'\x00'*1024)
        m[name]['artifacts']['bundle']['archive']['sha256'] = sha(f[asset]); f[name] = raw(m[name])
    run('concatenated-gzip-members', concatenated, False)
    def raw_tar_case(label, headers, after=b'\x00'*1024, good=False):
        global cases
        path = work/(label+'.tar.gz'); path.write_bytes(gzip.compress(b''.join(headers)+after))
        try:
            intake.bounded_raw_tar(path, 'fixture-root')
            accepted = True
        except (ValueError, zlib.error):
            accepted = False
        assert accepted == good, (label, 'raw tar admission mismatch')
        cases += 1
    directory = tarfile.TarInfo('fixture-root/empty'); directory.type = tarfile.DIRTYPE
    directory_header = directory.tobuf(format=tarfile.USTAR_FORMAT)
    raw_tar_case('raw-directory-positive', [directory_header], good=True)
    # Exercise the release producer's current staged path inventory with the
    # host tar implementation, including a path that needs the USTAR prefix
    # field. Every payload here is inert; the producer and binaries are not run.
    producer = (ROOT/'scripts/build-release-bundle.sh').read_text()
    assert 'tar --format=ustar -C "${OUTPUT_DIR}" -czf "${ARCHIVE_PATH}" "${BUNDLE_NAME}"' in producer
    assert 'tar --format=ustar -C "${OUTPUT_DIR}" -czf "${RESEARCH_ARCHIVE}" "${RESEARCH_NAME}"' in producer
    helper_block = producer.split('HELPER_SCRIPTS=(', 1)[1].split('\n)', 1)[0]
    operator_paths = ['scripts/'+name for name in re.findall(r'"([^"]+)"', helper_block)]
    operator_paths += ['packaging/'+str(path.relative_to(ROOT/'packaging'))
                       for path in (ROOT/'packaging').rglob('*') if path.is_file()]
    # Direct BUNDLE_DIR references mix files with mkdir/chmod directory names.
    # The helper and packaging inventories contain the long staged leaf paths.
    version = re.search(r'^version = "([^"]+)"', (ROOT/'aegis-server/Cargo.toml').read_text(), re.M)[1]
    operator_root = 'aegis-'+version+'-linux-x86_64'
    operator_paths = sorted(set(operator_paths))
    longest = max(operator_paths, key=lambda name: len(name.encode('ascii')))
    archive_name = operator_root+'/'+longest
    assert len(archive_name.encode('ascii')) > 100, 'fixture no longer exercises USTAR prefix splitting'
    native_stage = work/'native-ustar-stage'
    inert_bytes = b'inert operator pathname fixture\n'
    for name in operator_paths:
        inert_file = native_stage/operator_root/name
        inert_file.parent.mkdir(parents=True, exist_ok=True)
        inert_file.write_bytes(inert_bytes)
    native_archive = work/'native-ustar-operator-path.tar.gz'
    try:
        native_result = subprocess.run([shutil.which('tar') or 'tar', '--format=ustar',
                                        '-C', str(native_stage), '-czf', str(native_archive), operator_root],
                                       capture_output=True, text=True, timeout=20)
        assert native_result.returncode == 0, ('native USTAR producer', native_result.stderr)
        intake.bounded_raw_tar(native_archive, operator_root)
        with tarfile.open(native_archive, 'r:gz') as produced:
            for name in operator_paths:
                assert produced.extractfile(operator_root+'/'+name).read() == inert_bytes
        cases += 1
    except Exception:
        # Keep the failing inert artifact available after TemporaryDirectory cleanup.
        failure = Path(tempfile.mkdtemp(prefix='aegis-native-ustar-failure-'))
        if native_archive.exists():
            shutil.copyfile(native_archive, failure/native_archive.name)
        (failure/'pathname.txt').write_text(archive_name+'\n')
        print('Preserved inert USTAR failure fixture: '+str(failure), file=sys.stderr)
        raise
    # The same real producer pathname requires a forbidden LongLink under GNU
    # tar format. This catches accidentally broadening intake to accept it.
    gnu_archive = work/'gnu-operator-path.tar.gz'
    with tarfile.open(gnu_archive, 'w:gz', format=tarfile.GNU_FORMAT) as produced:
        entry = tarfile.TarInfo(archive_name); entry.size = len(inert_bytes)
        produced.addfile(entry, io.BytesIO(inert_bytes))
    try:
        intake.bounded_raw_tar(gnu_archive, operator_root)
    except ValueError:
        cases += 1
    else:
        raise AssertionError('GNU LongLink operator pathname unexpectedly admitted')
    raw_tar_case('raw-duplicate-directory', [directory_header, directory_header])
    traversal = tarfile.TarInfo('fixture-root/../escape'); traversal.type = tarfile.DIRTYPE
    raw_tar_case('raw-path-traversal', [traversal.tobuf(format=tarfile.USTAR_FORMAT)])
    for typeflag, label in ((tarfile.GNUTYPE_SPARSE, 'sparse'), (tarfile.GNUTYPE_LONGLINK, 'longlink'),
                            (tarfile.XGLTYPE, 'global-pax'), (tarfile.SYMTYPE, 'symlink')):
        info = tarfile.TarInfo('fixture-root/unsafe'); info.type = typeflag
        raw_tar_case('raw-'+label, [info.tobuf(format=tarfile.GNU_FORMAT)])
    oversized = tarfile.TarInfo('fixture-root/oversized'); oversized.size = 512*1024*1024+1
    raw_tar_case('raw-oversized-body', [oversized.tobuf(format=tarfile.USTAR_FORMAT)])
    raw_tar_case('raw-single-zero-terminator', [directory_header], after=b'\x00'*512)
    raw_tar_case('raw-trailing-data', [directory_header], after=b'\x00'*1024+b'not tar padding')
    cap = intake.MAX_ARCHIVE
    try:
        intake.MAX_ARCHIVE = 16384
        raw_tar_case('raw-decompressed-total-bound', [directory_header], after=b'\x00'*65536)
    finally:
        intake.MAX_ARCHIVE = cap
    run('bootstrap-mismatch', lambda r,a,l,f,m: f.update({'bootstrap-install.sh': b'changed bootstrap\n'}), False)
    run('research-mismatch', lambda r,a,l,f,m: f.update({'aegis-research-0.0.1-linux-x86_64.manifest.json':b'changed research manifest\n'}), False)
    run('unknown-record-fields', lambda r,a,l,f,m: r.update(candidate_verifier='evil.py'), False)
    run('tag-traversal', lambda r,a,l,f,m: r.update(tag='v0.0.1/../../escape'), False)
    run('tag-backslash', lambda r,a,l,f,m: r.update(tag='v0.0.1\\escape'), False)
    run('zip-traversal', expected=False, zip_alter=lambda z: z.writestr('../ESCAPE', b'unsafe'))
    assert not (work/'ESCAPE').exists(), 'ZIP wrote outside its snapshot'
    run('zip-backslash', expected=False, zip_alter=lambda z: z.writestr('..\\ESCAPE', b'unsafe'))
    malformed_dir = work/'bounded-directory-fixture.zip'
    with zipfile.ZipFile(malformed_dir, 'w') as z:
        z.writestr('x', b'fixture')
    contents = bytearray(malformed_dir.read_bytes())
    end = contents.rfind(b'PK\x05\x06')
    size, offset = struct.unpack_from('<LL', contents, end+12)
    zip64_end = struct.pack('<4sQ2H2L4Q', b'PK\x06\x06', 44, 45, 45, 0, 0, 1, 1, size, offset)
    locator = struct.pack('<4sLQL', b'PK\x06\x07', 0, end, 1)
    legacy = bytearray(contents[end:]); struct.pack_into('<HHLL', legacy, 8, 65535, 65535, 0xffffffff, 0xffffffff)
    zip64 = work/'bounded-zip64-fixture.zip'; zip64.write_bytes(contents[:end]+zip64_end+locator+legacy)
    intake.bounded_zip_directory(zip64, 1)
    with zipfile.ZipFile(zip64) as z:
        assert z.read('x') == b'fixture'
    cases += 1
    non_sentinel = bytearray(contents[:end]+zip64_end+locator+contents[end:])
    struct.pack_into('<Q', non_sentinel, end+40, 65537)
    zip64.write_bytes(non_sentinel)
    try:
        intake.bounded_zip_directory(zip64, 1)
    except intake.IntakeError:
        cases += 1
    else:
        raise AssertionError('non-sentinel ZIP64 central directory bypass accepted')
    conflicting = bytearray(contents[:end]+zip64_end+locator+contents[end:])
    struct.pack_into('<QQ', conflicting, end+24, 2, 2)
    zip64.write_bytes(conflicting)
    try:
        intake.bounded_zip_directory(zip64, 2)
    except intake.IntakeError:
        cases += 1
    else:
        raise AssertionError('legacy/ZIP64 conflicting entry count accepted')
    # More than 64 KiB of central metadata must refuse before ZipFile opens.
    struct.pack_into('<L', contents, end+12, 65537)
    malformed_dir.write_bytes(contents)
    try:
        intake.bounded_zip_directory(malformed_dir, 1)
    except intake.IntakeError:
        cases += 1
    else:
        raise AssertionError('unbounded central directory accepted')
    def malformed_approval(c):
        (c/'approval').write_bytes(b'\xff PRIVATE_APPROVAL_SENTINEL')
    malformed = run('malformed-approval', expected=False, raw_alter=malformed_approval)
    # Pin mismatch precedes parsing; a deliberately pinned malformed record
    # must also fail without printing private bytes or parser tracebacks.
    bad = b'\xff PRIVATE_APPROVAL_SENTINEL'
    args = [sys.executable, '-I', str(installed/'scripts/verify-linux-offline-release-intake.py'),
            '--transport', str(malformed/'transport.zip'), '--record', str(malformed/'record'),
            '--approval', str(malformed/'approval'), '--ledger', str(malformed/'ledger'),
            '--trust-anchor', str(malformed/'anchor'), '--output', str(malformed/'receipt-r2'),
            '--expected-verifier-sha256', verifier_sha,
            '--expected-record-sha256', sha((malformed/'record').read_bytes()),
            '--expected-approval-sha256', sha(bad), '--expected-ledger-sha256', sha((malformed/'ledger').read_bytes())]
    result = subprocess.run(args, capture_output=True, timeout=40, text=True)
    assert result.returncode != 0 and 'Traceback' not in result.stderr and 'PRIVATE_APPROVAL_SENTINEL' not in result.stderr
    cases += 1
    unsafe = work/'unsafe-parent'; unsafe.mkdir(); unsafe.chmod(0o777)
    run('writable-output-parent', expected=False, extra_args={'--output': str(unsafe/'receipt')})
    linked = work/'linked-parent'; linked.symlink_to(work, target_is_directory=True)
    run('linked-output-parent', expected=False, extra_args={'--output': str(linked/'receipt')})
    run('feature-mismatch', lambda r,a,l,f,m: r.update(client_features=['raw-socket']), False)
    run('legacy-schema-downgrade', lambda r,a,l,f,m: r.update(client_bundle_schema='aegis_client_release_bundle_manifest_v1'), False)
    # The hosted workflow is not edited or weakened; reuse its exact validator.
    assert intake.policy_body(payloads['.github/workflows/release.yml']).startswith('import datetime, json, os, re, stat, time, urllib.request\n')
print(f'PASS: {cases} inert offline intake cases; no Actions, signing or candidate execution')
