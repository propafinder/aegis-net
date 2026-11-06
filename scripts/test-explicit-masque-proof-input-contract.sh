#!/usr/bin/env bash
# Contract only: copied script prefixes and two owned temporary rewrite leaves.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# The aggregate CI owner discovers this wrapper and supplies no arguments.
# Keep its complete fixture/evidence private; explicit invocations stay exact.
if [[ "$#" -eq 0 ]]; then
  umask 077
  evidence_parent="$(mktemp -d "${TMPDIR:-/tmp}/aegis-masque-input-contract.XXXXXXXX")"
  chmod 700 "$evidence_parent"
  exec python3 -I "$SCRIPT_DIR/test-explicit-masque-proof-input-contract.py" \
    --root "$SCRIPT_DIR/.." --phase all --evidence-dir "$evidence_parent/whole"
fi
exec python3 -I "$SCRIPT_DIR/test-explicit-masque-proof-input-contract.py" "$@"
