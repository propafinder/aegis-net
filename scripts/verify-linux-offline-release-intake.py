#!/usr/bin/env python3
"""Verify an independently pinned Linux unsigned handoff; never sign or publish.

Install this script with the listed BUNDLE_FILES from an independently reviewed
source. Invoke with python3 -I and an independently obtained bundle SHA256. The
ZIP contains exactly four final policy-bearing manifests, four bundles, two
private research archives and their detached manifests, and bootstrap-install.sh.
Trusted record, approval, ledger and public anchor are separate regular files
outside the ZIP. Their SHA256 pins must arrive through independent custody, not
from the producer. JSON schemas are demonstrated by the inert regression fixture.
A pinned capture is evidence supplied by its custodian, not authenticated GitHub
API evidence by itself. An intake receipt is never signing/publication authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import types
import zipfile
import zlib

BUNDLE_FILES = ('scripts/verify-linux-offline-release-intake.py',
                'scripts/check-release-source-ci.py', 'scripts/lib/device_candidate_verify.py',
                'scripts/lib/shipping_client_inventory.py', '.github/workflows/release.yml',
                'bootstrap-install.sh')
MANIFESTS = ('release.manifest.json', 'release.manifest-aarch64.json',
             'client-release.manifest.json', 'client-release.manifest-aarch64.json')
MAX_TRANSPORT = 8 * 1024**3
MAX_ARCHIVE = 1024**3
HEX = re.compile(r'[0-9a-f]{64}\Z')


class IntakeError(ValueError):
    """Only fixed verifier-authored reasons may reach diagnostics."""


def require(value, reason):
    if not value:
        raise IntakeError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def local_path(path):
    path = Path(path).absolute()
    # Resolve only documented system aliases, never arbitrary parent symlinks.
    if sys.platform == 'darwin':
        for prefix in ('/tmp/', '/var/', '/etc/'):
            if str(path).startswith(prefix):
                path = Path('/private' + str(path))
                break
    require('..' not in path.parts, 'path traversal')
    return path


def protected_ancestry(path):
    for parent in path.parents:
        info = parent.lstat()
        sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()), 'untrusted/linked ancestry')
        require(not info.st_mode & 0o022 or sticky_root, 'writable ancestry')


def regular(path, limit):
    """Open once, refusing directory aliases, links, devices and hardlinks."""
    path = local_path(path)
    protected_ancestry(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit,
                'input must be a bounded single-link regular file')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def read(path, limit):
    with regular(path, limit) as stream:
        raw = stream.read(limit + 1)
    require(0 < len(raw) <= limit, 'input grew beyond bound')
    return raw


def pinned(path, digest, limit=1024*1024):
    require(isinstance(digest, str) and HEX.fullmatch(digest), 'missing independent SHA256 pin')
    raw = read(path, limit)
    require(sha(raw) == digest, 'independent file pin mismatch')
    return raw


def frozen_bundle(root):
    # Length-prefix each path and payload: no ambiguous concatenation or import
    # from cwd/PYTHONPATH. Load exactly the bytes hashed, never reread helpers.
    payloads = {name: read(root / name, 4*1024*1024) for name in BUNDLE_FILES}
    digest = hashlib.sha256()
    for name in sorted(payloads):
        for raw in (name.encode(), payloads[name]):
            digest.update(len(raw).to_bytes(8, 'big')); digest.update(raw)
    return digest.hexdigest(), payloads


def module(name, raw):
    result = types.ModuleType(name)
    sys.modules[name] = result
    exec(compile(raw, '<frozen-' + name + '>', 'exec'), result.__dict__)
    return result


def policy_body(workflow):
    text = workflow.decode()
    step = text.split('      - name: Validate signing input without executing release code\n', 1)[1]
    body = step.split("          /usr/bin/python3 -I - <<'PYCODE'\n", 1)[1].split('          PYCODE\n', 1)[0]
    return '\n'.join(line[10:] if line else '' for line in body.splitlines()) + '\n'


def verify_hosted_policy(payloads, record, snapshot):
    # Reuse the actual hosted validator, from the externally pinned installed
    # workflow. Candidate bytes are JSON only. HTTP is replaced with one exact
    # custodian capture; no token, network transport or repository checkout.
    with tempfile.TemporaryDirectory(prefix='aegis-intake-policy-') as tmp:
        work = Path(tmp); manifests = work / 'manifests'; manifests.mkdir()
        original = {name: read(snapshot/name, 65536) for name in MANIFESTS}
        for name, raw in original.items():
            (manifests/name).write_bytes(raw)
        stub = '''import io, os, urllib.request
class CapturedApi:
    def open(self, request, timeout):
        assert request.full_url == os.environ['CAPTURED_URL'] and timeout == 15
        return io.BytesIO(os.environ['CAPTURED_RUN'].encode())
urllib.request.build_opener = lambda *args: CapturedApi()
'''
        env = {'PATH': os.defpath, 'GITHUB_REPOSITORY': record['repository'],
               'GITHUB_SHA': record['source_sha'], 'GITHUB_EVENT_NAME': 'workflow_dispatch',
               'GITHUB_REF_NAME': 'main', 'GITHUB_RUN_NUMBER': str(record['builder']['run_number']),
               'GITHUB_RUN_ID': str(record['builder']['id']), 'AEGIS_INPUT_TAG_NAME': record['tag'],
               'GH_TOKEN': 'inert-offline-no-credential',
               'CAPTURED_RUN': json.dumps(record['builder']),
               'CAPTURED_URL': f"https://api.github.com/repos/{record['repository']}/actions/runs/{record['builder']['id']}"}
        result = subprocess.run([sys.executable, '-I', '-c', stub + '\n' + policy_body(payloads['.github/workflows/release.yml'])],
                                cwd=work, env=env, capture_output=True, timeout=30)
        require(result.returncode == 0, 'frozen hosted role/source/freshness validator refused')
        require(all(read(manifests/name, 65536) == raw for name, raw in original.items()),
                'manifest is not the exact final hosted policy bytes')


def source_ci(gate, record):
    ci = record['source_ci']; repository = record['repository']; prefix = f'/repos/{repository}/actions'
    def fetch(path, params=None):
        if path == prefix + '/workflows/ci.yml/runs':
            items, key = ci['runs'], 'workflow_runs'
        elif path == prefix + f"/runs/{ci['current']['id']}/attempts/{ci['current']['run_attempt']}/jobs":
            items, key = ci['jobs'], 'jobs'
        elif path == prefix + f"/runs/{ci['current']['id']}":
            return ci['current']
        else:
            raise IntakeError('captured CI request/attempt mismatch')
        require(isinstance(items, list) and len(items) <= gate.MAX_ITEMS, 'unbounded CI capture')
        first = (params['page'] - 1)*params['per_page']
        return {'total_count': len(items), key: items[first:first+params['per_page']]}
    try:
        return gate.check_source_ci(fetch, repository, record['source_sha'])
    except gate.GateError as error:
        raise IntakeError('captured source CI refused: '+str(error)) from error


def expected_files(record):
    number = r'(?:0|[1-9][0-9]*)'
    require(isinstance(record['tag'], str) and re.fullmatch(
        rf'v{number}\.{number}\.{number}(?:-(?:rc|nightly)\.{number})?', record['tag']),
        'invalid release tag before snapshot')
    version = record['tag'].split('-', 1)[0].removeprefix('v')
    files = set(MANIFESTS) | {'bootstrap-install.sh'}
    for arch in ('x86_64', 'aarch64'):
        files |= {f'aegis-{version}-linux-{arch}.tar.gz', f'aegis-client-{version}-linux-{arch}.tar.gz',
                  f'aegis-research-{version}-linux-{arch}.tar.gz', f'aegis-research-{version}-linux-{arch}.manifest.json'}
    return files


def safe_leaf(name):
    return (isinstance(name, str) and 0 < len(name) <= 200 and name not in ('.', '..')
            and not any(char in name for char in ('/', '\\', '\x00'))
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name) is not None)


def bounded_zip_directory(path, expected_count):
    """Bound central metadata before ZipFile allocates/parses the directory."""
    with regular(path, MAX_TRANSPORT) as stream:
        size = os.fstat(stream.fileno()).st_size
        stream.seek(max(0, size-65557)); tail = stream.read(65557)
        index = tail.rfind(b'PK\x05\x06')
        require(index >= 0 and len(tail)-index >= 22, 'ZIP end record missing')
        values = struct.unpack('<4s4H2LH', tail[index:index+22])
        _, disk, directory_disk, disk_count, count, directory_size, offset, comment = values
        end_offset = size-len(tail)+index
        require(index+22+comment == len(tail) and comment <= 1024 and disk == directory_disk == 0,
                'ZIP trailing/ambiguous/multidisk metadata')
        # CPython reads a preceding ZIP64 locator even when the legacy EOCD
        # has no sentinel fields. Mirror that rule before allocating metadata.
        locator_raw = b''
        if end_offset >= 20:
            stream.seek(end_offset-20); locator_raw = stream.read(20)
        sentinel = count == 65535 or disk_count == 65535 or directory_size == 0xffffffff or offset == 0xffffffff
        if sentinel or locator_raw.startswith(b'PK\x06\x07'):
            legacy = (disk_count, count, directory_size, offset)
            require(end_offset >= 20, 'ZIP64 locator missing')
            signature, locator_disk, location, disks = struct.unpack('<4sLQL', locator_raw)
            require(signature == b'PK\x06\x07' and locator_disk == 0 and disks == 1
                    and 0 <= location <= end_offset-76, 'ZIP64 locator invalid')
            stream.seek(location)
            values = struct.unpack('<4sQ2H2L4Q', stream.read(56))
            signature, record_size, _, _, disk, directory_disk, disk_count, count, directory_size, offset = values
            # CPython reads the fixed 56-byte record immediately before its
            # locator; reject extensible records/alternate pointed records.
            require(signature == b'PK\x06\x06' and record_size == 44
                    and location+12+record_size == end_offset-20 and disk == directory_disk == 0,
                    'ZIP64 end record invalid')
            require(all(old == marker or old == new for old, new, marker in
                        zip(legacy, (disk_count, count, directory_size, offset),
                            (65535, 65535, 0xffffffff, 0xffffffff))), 'ZIP/ZIP64 metadata conflict')
            end_offset = location
        require(disk_count == count == expected_count and 0 < directory_size <= 65536
                and 0 <= offset and offset+directory_size <= end_offset, 'ZIP central directory is unbounded or conflicting')


def transport_snapshot(path, digest, files, output):
    require(HEX.fullmatch(digest), 'invalid transport pin')
    require(all(safe_leaf(name) for name in files), 'unsafe expected transport basename')
    with regular(path, MAX_TRANSPORT) as incoming, (output/'transport.zip').open('xb') as target:
        total = 0; hashed = hashlib.sha256()
        while block := incoming.read(1024*1024):
            total += len(block); require(total <= MAX_TRANSPORT, 'transport grew beyond bound')
            hashed.update(block); target.write(block)
        target.flush(); os.fsync(target.fileno())
    require(hashed.hexdigest() == digest, 'transport digest mismatch')
    bounded_zip_directory(output/'transport.zip', len(files))
    snapshot = output/'snapshot'; snapshot.mkdir(mode=0o700)
    hashes = {}; total = 0
    with zipfile.ZipFile(output/'transport.zip') as archive:
        entries = archive.infolist()
        require(all(safe_leaf(entry.filename) for entry in entries), 'unsafe ZIP basename')
        require(len(entries) == len(files) and {entry.filename for entry in entries} == files,
                'unexpected/duplicate transport inventory')
        for entry in entries:
            mode = stat.S_IFMT(entry.external_attr >> 16)
            limit = MAX_ARCHIVE if entry.filename.endswith('.tar.gz') else (256*1024 if entry.filename == 'bootstrap-install.sh' else 65536)
            require(not entry.is_dir() and mode in (0, stat.S_IFREG) and not entry.flag_bits & 1
                    and 0 < entry.file_size <= limit, 'unsafe ZIP regular-file input')
            total += entry.file_size; require(total <= MAX_TRANSPORT, 'decompressed transport limit')
            digest = hashlib.sha256(); count = 0
            with archive.open(entry) as incoming, (snapshot/entry.filename).open('xb') as target:
                while block := incoming.read(65536):
                    count += len(block); require(count <= limit, 'ZIP entry grew beyond bound')
                    digest.update(block); target.write(block)
                target.flush(); os.fsync(target.fileno())
            require(count == entry.file_size, 'truncated ZIP entry')
            (snapshot/entry.filename).chmod(0o400)
            hashes[entry.filename] = digest.hexdigest()
    return snapshot, hashes


def bounded_raw_tar(path, expected_root):
    """Admit raw headers before tarfile can process hidden extension bodies.

    One gzip member and one canonical tar stream; no extraction or TarInfo
    parser is used here. Bounds include directories, headers and zero padding.
    """
    require(safe_leaf(expected_root), 'unsafe tar root')
    maximum = 2*MAX_ARCHIVE
    with regular(path, MAX_ARCHIVE) as incoming:
        decoder = zlib.decompressobj(31)
        def chunks():
            total = 0
            while compressed := incoming.read(65536):
                pending = compressed
                while pending:
                    block = decoder.decompress(pending, 65536)
                    pending = decoder.unconsumed_tail
                    total += len(block); require(total <= maximum, 'tar decompressed byte bound')
                    if block:
                        yield block
                    if decoder.eof:
                        require(not decoder.unused_data and not incoming.read(1), 'concatenated/trailing gzip stream')
                        return
            require(decoder.eof, 'truncated gzip stream')
        stream = iter(chunks()); buffer = bytearray(); ended = False
        def take(count):
            nonlocal ended
            while len(buffer) < count and not ended:
                try:
                    buffer.extend(next(stream))
                except StopIteration:
                    ended = True
            require(len(buffer) >= count, 'truncated tar header/body')
            result = bytes(buffer[:count]); del buffer[:count]
            return result
        def octal(field):
            token = field.strip(b'\x00 ')
            require(token and re.fullmatch(b'[0-7]+', token), 'non-octal/base256 tar numeric field')
            return int(token, 8)
        def text(field):
            head, separator, rest = field.partition(b'\x00')
            require(not separator or not any(rest), 'ambiguous tar text field')
            return head.decode('ascii')
        seen = set(); count = 0
        while True:
            header = take(512)
            if header == bytes(512):
                require(take(512) == bytes(512), 'ambiguous tar terminator')
                padding = len(buffer); require(not any(buffer), 'data after tar terminator'); buffer.clear()
                require(padding <= 10240, 'excessive tar trailing padding')
                for block in stream:
                    padding += len(block)
                    require(padding <= 10240 and not any(block), 'excessive/nonzero tar trailing padding')
                require(padding % 512 == 0, 'unaligned tar trailing padding')
                return
            count += 1; require(count <= 4096, 'tar total header/member bound')
            require(octal(header[148:156]) == sum(header[:148])+8*32+sum(header[156:]), 'tar checksum mismatch')
            kind = header[156:157]
            require(kind in (b'0', b'\x00', b'5'), 'tar extension/link/special header refused')
            magic = header[257:265]
            require(magic in (b'ustar\x0000', b'ustar  \x00'), 'unsupported tar header dialect')
            name = text(header[:100])
            if magic == b'ustar\x0000':
                prefix = text(header[345:500]); name = prefix+'/'+name if prefix else name
            else:
                require(not any(header[345:500]), 'GNU sparse/extended metadata refused')
            directory = kind == b'5'
            if directory and name.endswith('/'):
                name = name[:-1]
            parts = name.split('/')
            require(0 < len(name) <= 256 and parts[0] == expected_root and '\\' not in name
                    and all(part and part not in ('.', '..') for part in parts), 'noncanonical tar name/root')
            require(name not in seen and not any(header[157:257]), 'duplicate tar member/link field')
            seen.add(name)
            for field in (header[100:108], header[108:116], header[116:124], header[136:148]):
                require(octal(field) < 2**53, 'tar numeric metadata bound')
            size = octal(header[124:136])
            require(0 <= size <= 512*1024*1024 and (not directory or size == 0), 'tar member/body bound')
            remaining = size
            while remaining:
                block = min(remaining, 65536); take(block); remaining -= block
            padding = (-size) % 512
            require(not any(take(padding)), 'nonzero tar member padding')


def verify(a):
    require(sys.flags.isolated, 'invoke installed verifier with python3 -I')
    root = Path(__file__).resolve().parent.parent
    require(not any((parent/'.git').exists() for parent in (root, *root.parents)),
            'verifier must be independently installed outside a Git checkout')
    require(all(not (root/name).lstat().st_mode & 0o222 for name in BUNDLE_FILES),
            'installed verifier bundle must be read-only')
    bundle_digest, payloads = frozen_bundle(root)
    require(HEX.fullmatch(a.expected_verifier_sha256) and bundle_digest == a.expected_verifier_sha256,
            'installed verifier bundle pin mismatch')
    record = decode(pinned(a.record, a.expected_record_sha256))
    approval = decode(pinned(a.approval, a.expected_approval_sha256))
    ledger = decode(pinned(a.ledger, a.expected_ledger_sha256))
    anchor = read(a.trust_anchor, 16384)
    match = re.search(r'AEGIS_MANIFEST_PINNED_PUBKEY="(.*?)"', payloads['bootstrap-install.sh'].decode(), re.S)
    require(match and anchor == (match[1]+'\n').encode(), 'unapproved release trust anchor')
    require(record['schema'] == 'aegis_linux_offline_intake_record_v1'
            and approval['schema'] == 'aegis_linux_offline_intake_approval_v1'
            and ledger['schema'] == 'aegis_linux_offline_intake_ledger_v1', 'unknown custody schema')
    require(set(record) == {'schema', 'repository', 'source_sha', 'tag', 'captured_at_unix', 'author', 'last_pusher',
                           'builder', 'expected_builder', 'source_ci', 'expected_ci', 'client_bundle_schema',
                           'client_features', 'files', 'transport_sha256'}
            and set(approval) == {'schema', 'purpose', 'reviewer', 'issued_at_unix', 'expires_at_unix',
                                  'record_sha256', 'verifier_sha256', 'ledger_sha256', 'release_key_sha256', 'files'}
            and set(ledger) == {'schema', 'authority', 'minimum_sequence', 'entries'}
            and set(record['source_ci']) == {'runs', 'current', 'jobs'}, 'unknown custody fields')
    now = int(time.time())
    require(type(record['captured_at_unix']) is int and 0 <= now-record['captured_at_unix'] <= 3600,
            'stale/future trusted capture')
    require(all(type(approval[key]) is int for key in ('issued_at_unix', 'expires_at_unix'))
            and 0 <= now-approval['issued_at_unix'] <= 3600 and now < approval['expires_at_unix']
            <= approval['issued_at_unix']+3600, 'missing/stale approval')
    require(approval['purpose'] == 'intake_only' and approval['record_sha256'] == a.expected_record_sha256
            and approval['verifier_sha256'] == bundle_digest and approval['ledger_sha256'] == a.expected_ledger_sha256
            and approval['release_key_sha256'] == sha(anchor), 'approval custody binding mismatch')
    identities = (approval['reviewer'], record['author'], record['last_pusher'])
    require(all(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,99}', value) for value in identities)
            and identities[0].casefold() not in {value.casefold() for value in identities[1:]},
            'reviewer is missing or not independent')
    gate = module('offline_source_ci', payloads['scripts/check-release-source-ci.py'])
    ci = source_ci(gate, record)
    builder = record['builder']
    require(all(type(builder[key]) is int and builder[key] > 0 for key in ('id', 'run_number', 'run_attempt'))
            and builder['head_branch'] == 'main'
            and builder['status'] == 'completed' and builder['conclusion'] == 'success', 'builder not completed main success')
    require(record['expected_ci'] == {'run_id': ci['run_id'], 'run_attempt': ci['run_attempt']}
            and record['expected_builder'] == {'run_id': builder['id'], 'run_attempt': builder['run_attempt']},
            'run/attempt pin mismatch')
    files = expected_files(record)
    require(record['client_bundle_schema'] == 'aegis_client_release_bundle_manifest_v3',
            'current intake requires public v3 shipping inventory; no legacy downgrade')
    require(set(record['files']) == files and approval['files'] == record['files']
            and all(isinstance(value, str) and HEX.fullmatch(value) for value in record['files'].values()),
            'approval file allowlist/digests mismatch')
    # Exclusive receipt directory; failures remain for diagnosis and unique retry.
    output = local_path(a.output); protected_ancestry(output); output.mkdir(mode=0o700)
    try:
        snapshot, hashes = transport_snapshot(a.transport, record['transport_sha256'], files, output)
        require(hashes == record['files'], 'snapshot differs from independent approval bytes')
        verify_hosted_policy(payloads, record, snapshot)
        module('shipping_client_inventory', payloads['scripts/lib/shipping_client_inventory.py'])
        inventory = module('offline_device_verifier', payloads['scripts/lib/device_candidate_verify.py'])
        policies = []; clients = {}; guards = {}
        for name in MANIFESTS:
            manifest = decode(read(snapshot/name, 65536)); policies.append(manifest['release_policy'])
            public = name.startswith('client-'); arch = manifest['arch']
            expected = types.SimpleNamespace(client_bundle_schema=record['client_bundle_schema'])
            bundle = manifest['artifacts']['bundle']
            bounded_raw_tar(snapshot/bundle['archive']['path'], bundle['directory'])
            result = inventory.inventory(snapshot/name, manifest, expected, 'client' if public else 'server')
            client_binary = result['inner']['binaries']['aegis-client']
            require(client_binary['path'] == 'bin/aegis-client'
                    and client_binary['sha256'] == result['file_hashes']['bin/aegis-client'],
                    'operator/public nested client hash or path mismatch')
            role = 'public' if public else 'operator'
            clients[(arch, role)] = client_binary['sha256']
            guards[(arch, role)] = result['file_hashes'].get(inventory.DEVICE_GUARD_PAYLOAD)
            require(result['inner']['binaries']['aegis-client']['features'] == record['client_features'], 'build feature pin mismatch')
            require(record['client_features'] == ['raw-socket', 'chrome-like-tls', 'chrome-like-quic'], 'unsupported client feature scope')
            if public:
                require(manifest['bootstrap']['path'] == 'bootstrap-install.sh'
                        and manifest['bootstrap']['sha256'] == hashes['bootstrap-install.sh'], 'bootstrap binding mismatch')
            else:
                research = manifest['artifacts']['private_research']; asset = research['archive']['path']
                detached = research['directory'] + '.manifest.json'
                require(research['archive']['sha256'] == hashes[asset]
                        and research['manifest_sha256'] == hashes[detached], 'private research digest binding mismatch')
                bounded_raw_tar(snapshot/asset, research['directory'])
        for arch in ('x86_64', 'aarch64'):
            require(clients[(arch, 'public')] == clients[(arch, 'operator')], 'operator/public client bytes differ')
            if record['client_bundle_schema'] in (inventory.CLIENT_BUNDLE_SCHEMA_V2, inventory.CLIENT_BUNDLE_SCHEMA_V3):
                require(guards[(arch, 'public')] == guards[(arch, 'operator')], 'operator/public device guard differs')
        require(all(policy == policies[0] for policy in policies), 'four-role policy mismatch')
        policy = policies[0]
        require(ledger['authority'] == policy['authority'] and type(ledger['minimum_sequence']) is int
                and 0 < ledger['minimum_sequence'] <= policy['sequence'], 'independent sequence floor mismatch')
        require(isinstance(ledger['entries'], list) and len(ledger['entries']) <= 1000, 'unbounded custody ledger')
        seen = set()
        for entry in ledger['entries']:
            require(set(entry) == {'sequence', 'manifests'} and set(entry['manifests']) == set(MANIFESTS)
                    and all(isinstance(value, str) and HEX.fullmatch(value) for value in entry['manifests'].values()),
                    'malformed ledger entry')
            sequence = entry['sequence']
            require(type(sequence) is int and sequence > 0 and sequence not in seen, 'ambiguous ledger sequence')
            seen.add(sequence)
            require(sequence <= policy['sequence'], 'release rollback below ledger')
            if sequence == policy['sequence']:
                require(entry['manifests'] == {name: hashes[name] for name in MANIFESTS}, 'same-sequence equivocation')
        receipt = {'schema': 'aegis_linux_offline_intake_receipt_v1', 'status': 'INTAKE_ONLY',
                   'scope': 'four Linux final manifests, operator/client bundles, research digest bindings and bootstrap only',
                   'source_sha': record['source_sha'], 'source_ci': ci, 'builder': record['expected_builder'],
                   'verifier_sha256': bundle_digest, 'record_sha256': a.expected_record_sha256,
                   'approval_sha256': a.expected_approval_sha256, 'ledger_sha256': a.expected_ledger_sha256,
                   'release_key_sha256': sha(anchor), 'transport_sha256': record['transport_sha256'],
                   'release_policy': policy, 'files': hashes,
                   'boundary': 'No signing, publication, live approval authenticity or custody acceptance; ledger not advanced. Additional operator packages and research archive inventory not admitted.'}
        (output/'receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')
        (output/'transport.zip').chmod(0o400)
        return receipt
    except BaseException:
        (output/'failure.json').write_text('{"status":"REFUSED","boundary":"No signing or publication"}\n')
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('transport', 'record', 'approval', 'ledger', 'trust-anchor', 'output',
                 'expected-verifier-sha256', 'expected-record-sha256', 'expected-approval-sha256', 'expected-ledger-sha256'):
        p.add_argument('--'+name, required=True)
    a = p.parse_args()
    def expired(_signal, _frame):
        raise IntakeError('intake total verification budget exhausted')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(120)
    try:
        verify(a)
    except Exception as error:
        # Never print candidate/approval/private receipt content on malformed data.
        reason = str(error) if type(error) is IntakeError else 'malformed or unavailable intake input'
        print('offline-linux-intake: REFUSED: '+reason, file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)
    print('offline-linux-intake: INTAKE_ONLY; no signing or publication authority')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
