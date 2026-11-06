#!/usr/bin/env bash
# Synthetic bounded staging/export only; no native driver, namespace or sudo.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 -I "${ROOT}/scripts/test-deviceguard-private-stage-inert.py" "$@"
