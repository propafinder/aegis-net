#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

cargo run -q -p aegis-measure -- phase-c-bundle-mirrors-evidence "$@"
