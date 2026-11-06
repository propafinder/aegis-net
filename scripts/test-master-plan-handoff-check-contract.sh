#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-master-plan-handoff-check.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

bash "${ROOT}/scripts/test-master-plan-handoff-contract.sh"

mkdir -p "${TMP_DIR}/artifact"
touch \
  "${TMP_DIR}/artifact/phase-b-score-parity-gate.json" \
  "${TMP_DIR}/artifact/phase-c-multi-relay-evidence.json" \
  "${TMP_DIR}/artifact/phase-c-bundle-mirrors-evidence.json"

cat >"${TMP_DIR}/phase-c.json" <<JSON
{
  "status": "PHASE_C_RESILIENCE_BLOCKED",
  "phase_c_exit_status": "EXIT_NOT_READY",
  "acceptance_degraded": true,
  "blockers": ["cdn_fronted_transport:cdn_fronted_transport_evidence_missing"],
  "artifacts": {
    "phase_b_score_parity_json": "${TMP_DIR}/artifact/phase-b-score-parity-gate.json",
    "multi_relay_json": "${TMP_DIR}/artifact/phase-c-multi-relay-evidence.json",
    "bundle_mirrors_json": "${TMP_DIR}/artifact/phase-c-bundle-mirrors-evidence.json"
  }
}
JSON
cat >"${TMP_DIR}/phase-d.json" <<'JSON'
{
  "status": "PHASE_D_REACH_BLOCKED",
  "phase_d_exit_status": "EXIT_NOT_READY",
  "acceptance_degraded": true,
  "blockers": ["phase_c_resilience_not_ready"]
}
JSON

bash "${ROOT}/scripts/build-master-plan-handoff.sh" \
  --phase-c-resilience-json "${TMP_DIR}/phase-c.json" \
  --phase-d-reach-json "${TMP_DIR}/phase-d.json" \
  --artifact-dir "${TMP_DIR}/next" \
  --output-json "${TMP_DIR}/handoff.json"

cargo run -q -p aegis-measure -- master-plan-handoff-check \
  --handoff-json "${TMP_DIR}/handoff.json"

sed \
  -e 's/ --phase-b-score-parity-json [^"]*//' \
  -e 's/ --multi-relay-json [^"]*//' \
  -e 's/ --bundle-mirrors-json [^"]*//' \
  "${TMP_DIR}/handoff.json" >"${TMP_DIR}/broken.json"

if cargo run -q -p aegis-measure -- master-plan-handoff-check \
  --handoff-json "${TMP_DIR}/broken.json" >"${TMP_DIR}/broken.out" 2>"${TMP_DIR}/broken.err"; then
  echo "expected broken handoff check to fail" >&2
  exit 1
fi
grep -q 'phase c fronted follow-up gate inputs' "${TMP_DIR}/broken.err"

echo "ok"
