#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'macOS relay-reference contract INVALID: Python3 unavailable' >&2
  exit 2
fi
BASH_BIN="${BASH_FOR_MACOS_RELAY_REFERENCE_CONTRACT:-${BASH}}"
if [[ "$BASH_BIN" != /* || ! -x "$BASH_BIN" ]]; then
  printf '%s\n' 'macOS relay-reference contract INVALID: actual Bash unavailable' >&2
  exit 2
fi
EVIDENCE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aegis-macos-relay-reference-contract.XXXXXX")"
chmod 0700 "$EVIDENCE_ROOT"
python3 -I "${ROOT}/scripts/test-macos-relay-reference-contract.py" \
  --source-root "$ROOT" --bash "$BASH_BIN" --evidence "${EVIDENCE_ROOT}/cases"
