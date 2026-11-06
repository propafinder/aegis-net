#!/usr/bin/env bash
# Canonical host architecture name, shared by every packaging script.
#
# `uname -m` is not portable enough to name artifacts with: Apple Silicon
# reports `arm64` while Linux reports `aarch64` for the same architecture, and
# the Rust side (tools/measure) names artifacts from `std::env::consts::ARCH`,
# which is always `aarch64`. Mixing the two produced files called
# `...-linux-arm64.tar.gz` that the manifest builder then looked for under
# `...-linux-aarch64.tar.gz`, so the whole release delivery died with a bare
# `Error: Os { code: 2, kind: NotFound }` on any Apple Silicon builder.
#
# Normalise to the Rust spelling, since that is what ends up in the manifest.
host_arch() {
  local raw
  raw="$(uname -m)"
  case "${raw}" in
    arm64) printf 'aarch64\n' ;;
    amd64) printf 'x86_64\n' ;;
    *) printf '%s\n' "${raw}" ;;
  esac
}
