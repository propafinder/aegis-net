#!/usr/bin/env bash
# Inert inventory/extracted-copy checks; no builder/helper/runtime execution.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${ROOT}/scripts/test-private-nfqueue-packaging-inert.py" "$@"
