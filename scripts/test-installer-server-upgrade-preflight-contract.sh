#!/usr/bin/env bash
# Portable early-gate source contract; no ignored evidence or installed paths.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 -I "${ROOT}/scripts/test-installer-server-upgrade-preflight-contract.py" "$@"
