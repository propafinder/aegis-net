#!/usr/bin/env bash
# Current-source offline admission/comparator gate; no historical private source.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRILL_SCRIPT="${AEGIS_EGRESS_CONTRACT_SCRIPT:-${SCRIPT_DIR}/aegis-full-ubuntu-live-drill.sh}"
BASH_FOR_CONTRACT="${BASH_FOR_EGRESS_CONTRACT:-${BASH:-/bin/bash}}"
EVIDENCE="${AEGIS_EGRESS_CONTRACT_EVIDENCE:-}"
if [[ -z "$EVIDENCE" ]]; then
    PRIVATE_WORK="$(mktemp -d "${TMPDIR:-/tmp}/aegis-ubuntu-egress-contract.XXXXXX")"
    chmod 0700 "$PRIVATE_WORK"
    EVIDENCE="${PRIVATE_WORK}/cases"
fi
# The Python QA requires actual Bash4+ and real local public-key lookup. Missing
# dependencies are INVALID, never a skip or an accepted zero-case invocation.
# Receipts remain private on success/failure; outer process supervision is the
# caller's responsibility. No private baseline/history is a CI prerequisite.
python3 -I "${SCRIPT_DIR}/test-full-ubuntu-live-drill-egress-contract.py" \
    --script "$DRILL_SCRIPT" --bash "$BASH_FOR_CONTRACT" --evidence "$EVIDENCE"
