#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-ubuntu-release-review.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-ubuntu-release-review.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/release-summary.json" <<'EOF'
{"artifact_schema":"ubuntu_product_release_summary_v2","ship_ready":true,"release_readiness":"ship_ready","service_health_verdict":"green","baseline_bypass_verdict":"proven","baseline_bypass_ready":true,"bypass_verdict":"proven","bypass_ready":true,"bypass_support_tier":"baseline_transport_runtime","hostile_path_verdict":"missing_evidence","hostile_path_ready":false,"fully_proven":false}
EOF

cat > "${TMP_DIR}/pilot-summary.json" <<'EOF'
{"artifact_schema":"ubuntu_controlled_pilot_bundle_v1","pilot_verdict":"green","baseline_bypass_verdict":"proven","baseline_bypass_ready":true,"bypass_verdict":"proven","bypass_ready":true,"bypass_support_tier":"wire_level_supported_hostile_path","hostile_path_verdict":"proven","hostile_path_ready":true,"fully_proven":true,"wire_mimicry_verdict":"green","must_pass_verdict":"pass","must_pass_failures":[],"advisory_verdict":"pass","advisory_followups":[]}
EOF

cat > "${TMP_DIR}/matrix-manifest.json" <<'EOF'
{"artifact_schema":"linux_package_acceptance_matrix_bundle_v1","next_expansion_candidate":"rhel-dnf"}
EOF

cat > "${TMP_DIR}/wire-summary.json" <<'EOF'
{"artifact_schema":"wire_host_acceptance_summary_v1","verdict":"green","independent_witness_correlation_status":"matched","independent_witness_records_matched":1,"hostile_path_support_ready":true}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out" \
  --release-summary "${TMP_DIR}/release-summary.json" \
  --pilot-bundle "${TMP_DIR}/pilot-summary.json" \
  --matrix-manifest "${TMP_DIR}/matrix-manifest.json" \
  --wire-acceptance-summary "${TMP_DIR}/wire-summary.json" >/dev/null

OUTPUT_JSON="${TMP_DIR}/out/release-review.json"
OUTPUT_MD="${TMP_DIR}/out/release-review.md"

jq -e '
  .artifact_schema == "ubuntu_release_review_v1"
  and .review_verdict == "ready"
  and .ship_decision == "ship"
  and .blocking_reasons == []
  and .bypass_ready == true
  and .bypass_support_tier == "wire_level_supported_hostile_path"
  and .bypass_confidence == "bypass_succeeded_with_correlated_wire_backed_hostile_path_support"
  and .hostile_path_ready == true
  and .fully_proven == true
  and .product_proof_status == "fully_proven_hostile_path"
  and .mimicry_closure_scope == "ubuntu_witness_correlated_hostile_path_release_boundary"
  and .mimicry_program_boundary == "full_packet_level_impersonation_remains_post_release_program"
  and .wire_mimicry_verdict == "green"
  and .must_pass_verdict == "pass"
  and .advisory_verdict == "pass"
  and .wire_mimicry_verdict_reason == null
  and .wire_hostile_path_support_ready == true
  and .wire_hostile_path_support_tier == "wire_level_supported_hostile_path"
  and .independent_witness_correlation_status == "matched"
  and .independent_witness_records_matched == 1
  and .independent_witness_records_mismatched == 0
  and (.non_blocking_notes | index("next_linux_expansion_candidate=rhel-dnf") != null)
  and (.non_blocking_notes | index("wire_proof_verdict=green") != null)
' "${OUTPUT_JSON}" >/dev/null

grep -Fq -- "Ubuntu Release Review" "${OUTPUT_MD}"
grep -Fq -- "- Review verdict: \`ready\`" "${OUTPUT_MD}"
grep -Fq -- "- Bypass support tier: \`wire_level_supported_hostile_path\`" "${OUTPUT_MD}"
grep -Fq -- "- Must-pass verdict: \`pass\`" "${OUTPUT_MD}"
grep -Fq -- "- Independent witness correlation: \`matched\`" "${OUTPUT_MD}"

echo "ubuntu release review contract: ok"
