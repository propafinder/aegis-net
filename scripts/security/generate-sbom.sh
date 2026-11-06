#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ $# -eq 2 ]] || { echo 'Usage: generate-sbom.sh NEW_OUTPUT_DIRECTORY TARGET_TRIPLE' >&2; exit 2; }
[[ "$(cargo cyclonedx --version)" == 'cargo-cyclonedx-cyclonedx 0.5.9' ]] || {
  echo 'Install the reviewed cargo-cyclonedx 0.5.9; refusing an unpinned tool.' >&2; exit 2;
}
# Verification glue only. The established CycloneDX CLI supplies the SBOM model.
python3 - "${ROOT}" "$1" "$2" <<'PY'
import hashlib, json, os, pathlib, re, subprocess, sys, tomllib, uuid
root = pathlib.Path(sys.argv[1]); out = pathlib.Path(sys.argv[2]).absolute()
target = sys.argv[3]
if not re.fullmatch(r'[a-z0-9_]+(?:-[a-z0-9_]+){2,4}', target):
    raise SystemExit('Supply an explicit target triple')
for path in [out, *out.parents]:
    if path.is_symlink():
        raise SystemExit('Symlink output ancestry is forbidden')
source_commit = subprocess.check_output(['git', 'rev-parse', '--verify', 'HEAD'], cwd=root, text=True).strip()
if not re.fullmatch(r'[0-9a-f]{40}', source_commit):
    raise SystemExit('Source commit identity unavailable')
epoch = os.environ.get('SOURCE_DATE_EPOCH')
if epoch is None:
    epoch = subprocess.check_output(['git', 'show', '-s', '--format=%ct', source_commit], cwd=root, text=True).strip()
if not re.fullmatch(r'[0-9]+', epoch):
    raise SystemExit('SOURCE_DATE_EPOCH must be an integer')
env = dict(os.environ, SOURCE_DATE_EPOCH=epoch, CARGO_NET_OFFLINE='true')
manifest = tomllib.loads((root / 'Cargo.toml').read_text())
members = [root / p for p in manifest['workspace']['members']]
inputs = [root / 'Cargo.toml', root / 'Cargo.lock', root / 'third_party/h2/Cargo.toml',
          root / 'third_party/tungstenite/Cargo.toml']
inputs += [p / 'Cargo.toml' for p in members]
pins = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
for relative, digest in pins.items():
    try:
        committed = subprocess.check_output(['git', 'show', f'{source_commit}:{relative}'], cwd=root, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        raise SystemExit('source input differs from HEAD') from None
    if hashlib.sha256(committed).hexdigest() != digest:
        raise SystemExit('source input differs from HEAD')
out.mkdir(mode=0o700, parents=False, exist_ok=False)
receipt = {'tool': 'cargo-cyclonedx 0.5.9', 'spec': 'CycloneDX 1.5', 'target': target,
           'source_commit': source_commit, 'source_date_epoch': epoch,
           'features': 'workspace defaults', 'inputs': pins,
           'scope': 'resolved Cargo metadata, not shipping artifact completeness', 'passes': []}
(out / 'started.json').write_text(json.dumps(receipt, indent=2) + '\n')
for repeat in (1, 2):
    prefix = '.aegis-sbom-' + uuid.uuid4().hex
    paths = [p / (prefix + '.json') for p in members]
    if any(p.exists() or p.is_symlink() for p in paths):
        raise SystemExit('Refusing to overwrite an SBOM output')
    dest = out / ('pass-' + str(repeat)); dest.mkdir(mode=0o700)
    argv = ['cargo', 'cyclonedx', '--manifest-path', str(root / 'Cargo.toml'),
            '--format', 'json', '--spec-version', '1.5',
            '--all', '--target', target, '--override-filename', prefix]
    with (dest / 'tool.log').open('xb') as log:
        result = subprocess.run(argv, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    outputs = {}
    for member, path in zip(members, paths):
        if path.exists() and not path.is_symlink():
            name = tomllib.loads((member / 'Cargo.toml').read_text())['package']['name']
            saved = dest / (name + '.cdx.json'); path.rename(saved)
            data = json.loads(saved.read_text())
            if data.get('bomFormat') != 'CycloneDX' or data.get('specVersion') != '1.5':
                raise SystemExit('Unexpected SBOM format')
            # Key order is insignificant JSON; no timestamps, IDs or components are discarded.
            outputs[name] = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    receipt['passes'].append({'returncode': result.returncode, 'outputs': outputs})
    (dest / 'receipt.json').write_text(json.dumps(receipt['passes'][-1], indent=2) + '\n')
    after = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    if after != pins or result.returncode or len(outputs) != len(members):
        raise SystemExit('SBOM failed, inputs changed, or workspace output incomplete; receipts preserved')
if receipt['passes'][0]['outputs'] != receipt['passes'][1]['outputs']:
    raise SystemExit('SBOM repeatability failed; both attempts preserved')
receipt['status'] = 'PASS'; receipt['binary_reproducibility'] = 'not assessed'
(out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
print('PASS: two matching Cargo-metadata SBOM inventories; release payload coverage remains separate')
PY
