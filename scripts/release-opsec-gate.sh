#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -n "${AEGIS_MEASURE_BIN:-}" ]]; then
  exec "${AEGIS_MEASURE_BIN}" release-opsec-gate "$@"
fi
exec cargo run --locked --manifest-path "${ROOT}/Cargo.toml" -q -p aegis-measure -- release-opsec-gate "$@"
