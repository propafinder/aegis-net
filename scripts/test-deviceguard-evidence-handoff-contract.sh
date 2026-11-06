#!/usr/bin/env bash
# Only synthetic handoff inventory and mocked chown; no native driver execution.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 -I "${ROOT}/scripts/test-deviceguard-evidence-handoff-inert.py" "$@"
