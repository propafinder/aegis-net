#!/usr/bin/env bash
# Contract: packaging scripts and the Rust manifest builder must agree on the
# architecture name they put in artifact file names.
#
# They did not: `uname -m` says `arm64` on Apple Silicon while
# `std::env::consts::ARCH` says `aarch64`, so the scripts produced
# `...-linux-arm64.tar.gz` and the manifest builder looked for
# `...-linux-aarch64.tar.gz`. Release delivery died with a bare
# `Error: Os { code: 2, kind: NotFound }` and no manifest on every aarch64
# builder. Needs only bash, so it fails on a laptop rather than in a release.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/lib/host-arch.sh
. "${ROOT}/scripts/lib/host-arch.sh"

# 1. The normaliser maps the known aliases and passes anything else through.
[[ "$(uname -m)" != "arm64" || "$(host_arch)" == "aarch64" ]] || {
  echo "FAIL: host_arch did not normalise arm64 -> aarch64" >&2; exit 1; }
echo "PASS: host_arch on this machine = $(host_arch) (uname -m = $(uname -m))"

# 2. No script that names or looks for artifacts may take the arch straight
#    from `uname -m` again — the contract scripts search for the files the
#    build scripts produce, so a mismatch there breaks just as loudly.
offenders="$(
  grep -ln 'ARCH="\$(uname -m)"' "${ROOT}"/scripts/build-*.sh "${ROOT}"/scripts/test-*.sh 2>/dev/null \
    | grep -v 'test-host-arch-naming-contract.sh' || true
)"
if [[ -n "${offenders}" ]]; then
  echo "FAIL: these scripts still take the arch from uname -m:" >&2
  printf '  %s\n' ${offenders} >&2
  exit 1
fi
echo "PASS: every packaging and contract script uses host_arch"

# 3. The name the scripts use must match the one Rust puts in the manifest.
rust_arch="$(cd "${ROOT}" && cargo run -q -p aegis-measure -- host-arch)"
if [[ -z "${rust_arch}" ]]; then
  echo "FAIL: could not read the architecture name from aegis-measure" >&2
  exit 1
fi
if [[ "${rust_arch}" != "$(host_arch)" ]]; then
  echo "FAIL: shell says $(host_arch), Rust says ${rust_arch}" >&2
  exit 1
fi
echo "PASS: shell and Rust agree on the architecture name (${rust_arch})"
