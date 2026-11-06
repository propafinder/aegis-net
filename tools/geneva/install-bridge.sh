#!/usr/bin/env bash
# Explicit source installation. Never starts a daemon or changes networking.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
if [[ $# != 2 || "$1" != --prefix || "$2" != /* ]]; then
  echo 'usage: install.sh geneva-bridge --prefix /absolute/new/prefix' >&2
  exit 2
fi
prefix="$2"
if [[ -e "${prefix}" || -L "${prefix}" ]]; then
  echo 'Geneva bridge installation requires a fresh prefix; existing state is retained.' >&2
  exit 1
fi
if [[ "$(uname -s)" != Linux ]]; then
  echo 'Geneva bridge is supported on Linux only.' >&2
  exit 1
fi
binary="${root}/bin/aegis-geneva-bridge"
if [[ -f "${binary}" && ! -L "${binary}" ]]; then
  [[ -f "${root}/SHA256SUMS" && ! -L "${root}/SHA256SUMS" ]] || { echo 'missing bundle checksums' >&2; exit 1; }
  expected="$(awk '$2 == "bin/aegis-geneva-bridge" { print $1 }' "${root}/SHA256SUMS")"
  [[ "${expected}" =~ ^[0-9a-f]{64}$ ]] || { echo 'invalid or duplicate bridge checksum' >&2; exit 1; }
  actual="$(sha256sum -- "${binary}" | awk '{print $1}')"
  [[ "${actual}" == "${expected}" ]] || { echo 'bridge checksum differs from bundle' >&2; exit 1; }
else
  cargo build --locked --release --target-dir "${root}/target" --manifest-path "${root}/Cargo.toml" -p aegis-geneva --features live-linux --bin aegis-geneva-bridge
  binary="${root}/target/release/aegis-geneva-bridge"
fi
"${binary}" --version >/dev/null
# mkdir without -p prevents taking over an existing prefix and follows no final symlink.
mkdir -- "${prefix}"
mkdir -- "${prefix}/bin"
install -m 0755 -- "${binary}" "${prefix}/bin/aegis-geneva-bridge"
printf 'Installed %s/bin/aegis-geneva-bridge; opt-in invocation is documented in docs/geneva-live-bridge.md.\n' "${prefix}"
