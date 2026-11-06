#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POLICY="${ROOT}/scripts/security/cargo-audit.toml"
AUDIT_WORKDIR="$(mktemp -d)"
trap 'rm -rf "${AUDIT_WORKDIR}"' EXIT
mkdir "${AUDIT_WORKDIR}/.cargo"
cp "${POLICY}" "${AUDIT_WORKDIR}/.cargo/audit.toml"
# cargo-audit 0.22.2 discovers policy by working directory. Isolate it from
# ignored editor/local Cargo configuration without weakening the audit.
cd "${AUDIT_WORKDIR}"
for lockfile in \
  "${ROOT}/Cargo.lock" \
  "${ROOT}/tools/macos/aegis-network-extension/Cargo.lock" \
  "${ROOT}/third_party/h2/Cargo.lock"; do
  cargo audit --deny warnings --file "${lockfile}" "$@"
done
