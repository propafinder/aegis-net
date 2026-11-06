#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/ubuntu-release-wave-status.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-ubuntu-release-wave-status.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

PILOT_INPUTS="${TMP_DIR}/ubuntu-controlled-pilot-inputs.json"
RELEASE_HANDOFF="${TMP_DIR}/ubuntu-release-gate-handoff.json"
RELEASE_SUMMARY="${TMP_DIR}/ubuntu-product-release-summary.json"
PILOT_REVIEW="${TMP_DIR}/pilot-review.manifest.json"

cat > "${RELEASE_HANDOFF}" <<'EOF'
{"artifact_schema":"ubuntu_release_gate_handoff_v1","ship_ready":true,"release_readiness":"ship_ready","bypass_ready":true,"next_required_action":"none"}
EOF

cat > "${RELEASE_SUMMARY}" <<'EOF'
{"artifact_schema":"ubuntu_product_release_summary_v2","ship_ready":true,"release_readiness":"ship_ready","service_health_verdict":"green","baseline_bypass_verdict":"proven","baseline_bypass_ready":true,"bypass_verdict":"proven","bypass_ready":true,"bypass_support_tier":"baseline_transport_runtime","hostile_path_verdict":"missing_evidence","hostile_path_ready":false,"fully_proven":false}
EOF

cat > "${TMP_DIR}/release-review.json" <<'EOF'
{"artifact_schema":"ubuntu_release_review_v1","review_verdict":"ready","ship_decision":"ship","baseline_bypass_ready":true,"bypass_verdict":"proven","bypass_ready":true,"bypass_support_tier":"wire_level_supported_hostile_path","hostile_path_verdict":"proven","hostile_path_ready":true,"fully_proven":true,"product_proof_status":"fully_proven_hostile_path","mimicry_closure_scope":"ubuntu_witness_correlated_hostile_path_release_boundary","mimicry_program_boundary":"full_packet_level_impersonation_remains_post_release_program","wire_mimicry_verdict":"green","wire_hostile_path_support_ready":true,"wire_hostile_path_support_tier":"wire_level_supported_hostile_path","independent_witness_correlation_status":"matched","independent_witness_records_matched":1,"independent_witness_records_mismatched":0,"must_pass_verdict":"pass","must_pass_failures":[],"advisory_verdict":"pass","advisory_followups":[]}
EOF

cat > "${PILOT_REVIEW}" <<EOF
{
  "artifact_schema": "ubuntu_controlled_pilot_review_bundle_v1",
  "release_review_json": "${TMP_DIR}/release-review.json",
  "pilot_verdict": "green",
  "operator_canary_verdict": "green",
  "restart_canary_ready": true,
  "rollback_canary_ready": true,
  "reapply_canary_ready": true,
  "next_required_action": "none"
}
EOF

cat > "${PILOT_INPUTS}" <<EOF
{
  "artifact_schema": "ubuntu_controlled_pilot_inputs_v1",
  "release_gate_handoff_json": "${RELEASE_HANDOFF}",
  "release_summary_json": "${RELEASE_SUMMARY}"
}
EOF

bash "${SCRIPT}" \
  --pilot-inputs "${PILOT_INPUTS}" \
  --pilot-review-manifest "${PILOT_REVIEW}" \
  --output "${TMP_DIR}/status.json"

jq -e '
  .artifact_schema == "ubuntu_release_wave_status_v1"
  and .ship_ready == true
  and .ship_decision == "ship"
  and .review_verdict == "ready"
  and .bypass_verdict == "proven"
  and .bypass_ready == true
  and .bypass_support_tier == "wire_level_supported_hostile_path"
  and .hostile_path_verdict == "proven"
  and .hostile_path_ready == true
  and .fully_proven == true
  and .product_proof_status == "fully_proven_hostile_path"
  and .mimicry_closure_scope == "ubuntu_witness_correlated_hostile_path_release_boundary"
  and .mimicry_program_boundary == "full_packet_level_impersonation_remains_post_release_program"
  and .wire_mimicry_verdict == "green"
  and .wire_hostile_path_support_ready == true
  and .wire_hostile_path_support_tier == "wire_level_supported_hostile_path"
  and .independent_witness_correlation_status == "matched"
  and .independent_witness_records_matched == 1
  and .independent_witness_records_mismatched == 0
  and .pilot_verdict == "green"
  and .operator_canary_verdict == "green"
  and .restart_canary_ready == true
  and .rollback_canary_ready == true
  and .reapply_canary_ready == true
  and .must_pass_verdict == "pass"
  and .must_pass_failures == []
  and .advisory_verdict == "pass"
  and .advisory_followups == []
  and .wave_status == "fully_proven_hostile_path"
  and .next_required_action == "none"
' "${TMP_DIR}/status.json" >/dev/null

echo "ubuntu-release-wave-status contract: ok"
