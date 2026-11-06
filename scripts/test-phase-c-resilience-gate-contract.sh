#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-c-resilience.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/phase-b-ready.json" <<'JSON'
{
  "status": "PHASE_B_SCORE_PARITY_READY",
  "phase_b_exit_status": "EXIT_READY",
  "acceptance_degraded": false
}
JSON

cat >"${TMP_DIR}/multi-relay-pass.json" <<'JSON'
{
  "status": "PASS",
  "primary_block_recovery_median_secs": 12.5,
  "mid_session_primary_block_survived": true,
  "single_relay_backward_compatible": true,
  "observed_relay_servers": ["relay-a:443", "relay-b:443"]
}
JSON

cat >"${TMP_DIR}/bundle-mirrors-pass.json" <<'JSON'
{
  "status": "PASS",
  "primary_bundle_host_block_survives": true,
  "voucher_expiry_revoke_pass": true,
  "signed_bundle_verification_preserved": true,
  "operator_mirror_setup_documented": true
}
JSON

cat >"${TMP_DIR}/fronted-pass.json" <<'JSON'
{
  "status": "PASS",
  "fronted_masque_pass_rate": 0.97,
  "operator_provider_constraints_documented": true,
  "adversarial_scenario_coverage": true,
  "provider_boundary_evidence": true
}
JSON

if bash "${ROOT}/scripts/build-phase-c-resilience-gate.sh" \
  --phase-b-score-parity-json "${TMP_DIR}/phase-b-ready.json" \
  --output-json "${TMP_DIR}/missing.json"; then
  echo "expected missing Phase C evidence to block" >&2
  exit 1
fi
grep -q '"status": "PHASE_C_RESILIENCE_BLOCKED"' "${TMP_DIR}/missing.json"
grep -q 'multi_relay_pool:multi_relay_pool_evidence_missing' "${TMP_DIR}/missing.json"
grep -q 'implement_and_measure_multi_relay_pool' "${TMP_DIR}/missing.json"

bash "${ROOT}/scripts/build-phase-c-resilience-gate.sh" \
  --phase-b-score-parity-json "${TMP_DIR}/phase-b-ready.json" \
  --multi-relay-json "${TMP_DIR}/multi-relay-pass.json" \
  --bundle-mirrors-json "${TMP_DIR}/bundle-mirrors-pass.json" \
  --fronted-transport-json "${TMP_DIR}/fronted-pass.json" \
  --output-json "${TMP_DIR}/ready.json" \
  --output-markdown "${TMP_DIR}/ready.md"

grep -q '"status": "PHASE_C_RESILIENCE_READY"' "${TMP_DIR}/ready.json"
grep -q '"phase_c_exit_status": "EXIT_READY"' "${TMP_DIR}/ready.json"
grep -q 'Phase C Resilience Gate' "${TMP_DIR}/ready.md"

cat >"${TMP_DIR}/slow-multi-relay.json" <<'JSON'
{
  "status": "PASS",
  "primary_block_recovery_median_secs": 30.0,
  "mid_session_primary_block_survived": true,
  "single_relay_backward_compatible": true
}
JSON

if bash "${ROOT}/scripts/build-phase-c-resilience-gate.sh" \
  --phase-b-score-parity-json "${TMP_DIR}/phase-b-ready.json" \
  --multi-relay-json "${TMP_DIR}/slow-multi-relay.json" \
  --bundle-mirrors-json "${TMP_DIR}/bundle-mirrors-pass.json" \
  --fronted-transport-json "${TMP_DIR}/fronted-pass.json" \
  --output-json "${TMP_DIR}/slow.json"; then
  echo "expected slow primary-block recovery to block" >&2
  exit 1
fi
grep -q 'primary_block_recovery_median_not_below_30s' "${TMP_DIR}/slow.json"

cat >"${TMP_DIR}/weak-multi-relay.json" <<'JSON'
{
  "status": "PASS",
  "primary_block_recovery_median_secs": 12.5,
  "mid_session_primary_block_survived": true,
  "single_relay_backward_compatible": true,
  "observed_relay_servers": ["relay-a:443"]
}
JSON

if bash "${ROOT}/scripts/build-phase-c-resilience-gate.sh" \
  --phase-b-score-parity-json "${TMP_DIR}/phase-b-ready.json" \
  --multi-relay-json "${TMP_DIR}/weak-multi-relay.json" \
  --bundle-mirrors-json "${TMP_DIR}/bundle-mirrors-pass.json" \
  --fronted-transport-json "${TMP_DIR}/fronted-pass.json" \
  --output-json "${TMP_DIR}/weak-multi.json"; then
  echo "expected single observed relay endpoint to block" >&2
  exit 1
fi
grep -q 'fewer_than_two_relay_endpoints_observed' "${TMP_DIR}/weak-multi.json"

cat >"${TMP_DIR}/phase-b-blocked.json" <<'JSON'
{
  "status": "PHASE_B_SCORE_PARITY_BLOCKED",
  "phase_b_exit_status": "EXIT_NOT_READY",
  "acceptance_degraded": true
}
JSON

if bash "${ROOT}/scripts/build-phase-c-resilience-gate.sh" \
  --phase-b-score-parity-json "${TMP_DIR}/phase-b-blocked.json" \
  --multi-relay-json "${TMP_DIR}/multi-relay-pass.json" \
  --bundle-mirrors-json "${TMP_DIR}/bundle-mirrors-pass.json" \
  --fronted-transport-json "${TMP_DIR}/fronted-pass.json" \
  --output-json "${TMP_DIR}/phase-b-blocked-out.json"; then
  echo "expected blocked Phase B gate to block Phase C" >&2
  exit 1
fi
grep -q 'phase_b_exit_not_ready' "${TMP_DIR}/phase-b-blocked-out.json"

echo "ok"
