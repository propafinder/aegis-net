#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"
[[ $# -eq 0 ]] || { echo 'This policy accepts no bypass arguments.' >&2; exit 2; }
[[ "$(cargo deny --version)" == 'cargo-deny 0.20.2' ]] || {
  echo 'Install the reviewed cargo-deny 0.20.2; refusing an unpinned tool.' >&2; exit 2;
}
# Metadata only: do not build or execute workspace/native targets.
python3 - "${ROOT}" <<'PY'
import hashlib, json, pathlib, re, sys, tomllib
root = pathlib.Path(sys.argv[1])
manifest = tomllib.loads((root / 'Cargo.toml').read_text())
expected = {}
for member in manifest['workspace']['members']:
    package = tomllib.loads((root / member / 'Cargo.toml').read_text())['package']
    expected[package['name']] = package['version']
vendors = [root / 'third_party/h2', root / 'third_party/tungstenite']
for vendor in vendors:
    package = tomllib.loads((vendor / 'Cargo.toml').read_text())['package']
    expected[package['name']] = package['version']
for package in tomllib.loads((root / 'Cargo.lock').read_text())['package']:
    source = package.get('source')
    if source is None:
        if expected.get(package['name']) != package['version']:
            raise SystemExit('Unreviewed local dependency identity')
    elif source != 'registry+https://github.com/rust-lang/crates.io-index':
        raise SystemExit('Unreviewed dependency source')
    elif not re.fullmatch(r'[0-9a-f]{64}', package.get('checksum', '')):
        raise SystemExit('Registry dependency lacks a SHA-256 checksum')
# Verify vendor byte provenance without reading or executing transport bodies.
for vendor in vendors:
    proof = json.loads((vendor / 'UPSTREAM.json').read_text())
    for name, digest in proof['upstream_files_sha256'].items():
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts:
            raise SystemExit('Unsafe vendor provenance path')
        wanted = proof.get('local_patches', {}).get(name, {}).get('patched_sha256', digest)
        file = vendor / path
        if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != wanted:
            raise SystemExit('Vendor provenance mismatch')
    for name, patch in proof.get('local_patches', {}).items():
        file = vendor / patch['patch_file']
        if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != patch['patch_sha256']:
            raise SystemExit('Vendor patch provenance mismatch')
print('PASS: locked registry checksums and reviewed local dependency identities')
PY
cargo deny --offline --locked --manifest-path "${ROOT}/Cargo.toml" --config "${ROOT}/deny.toml" check licenses bans sources
mkdir -p "${ROOT}/target"
policy_output="${ROOT}/target/supply-chain-policy-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
python3 -I -B "${ROOT}/scripts/security/check-license-profiles.py" --output "${policy_output}"
python3 -I -B "${ROOT}/scripts/generate-third-party-notices.py" --check
# Vulnerability checking retains the independently maintained RustSec policy.
bash "${ROOT}/scripts/security/audit-dependencies.sh"
