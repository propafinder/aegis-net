#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-macos-pf-operator-acceptance-summary.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-macos-pf-operator-summary.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

require_file_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq -- "${expected}" "${file}"; then
    echo "expected ${file} to contain: ${expected}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

ROOTED_LIVE_DIR="${TMP_DIR}/rooted-live"
PHASE1_DIR="${ROOTED_LIVE_DIR}/phase1"
PHASE2_DIR="${ROOTED_LIVE_DIR}/phase2"
PHASE3_DIR="${ROOTED_LIVE_DIR}/phase3-boundary"
mkdir -p "${PHASE1_DIR}" "${PHASE2_DIR}" "${PHASE3_DIR}"

cat > "${PHASE1_DIR}/helper-check.json" <<'EOF'
{"reason_code":"ready_for_apply"}
EOF

cat > "${PHASE1_DIR}/helper-apply.json" <<'EOF'
{"runtime_claim":"tcp_only_phase1_active","runtime_active":true}
EOF

cat > "${PHASE1_DIR}/helper-evidence.json" <<'EOF'
{"current_verdict":"tcp_only_phase1_helper_materialized"}
EOF

cat > "${PHASE1_DIR}/runtime-events.jsonl" <<'EOF'
{"event_code":"ingress_backend_started","fields":{"backend_runtime_id":"wide_primary_macos","wide_backend_current_stage":"tcp_only_phase1_live","wide_runtime_readiness":"ready"}}
EOF

cat > "${PHASE2_DIR}/helper-apply.json" <<'EOF'
{"runtime_claim":"dns_preview_phase2_active","runtime_active":true}
EOF

cat > "${PHASE2_DIR}/helper-evidence.json" <<'EOF'
{"current_verdict":"dns_preview_phase2_helper_materialized"}
EOF

cat > "${PHASE2_DIR}/udp-probe.json" <<'EOF'
{"matched":true}
EOF

cat > "${PHASE2_DIR}/runtime-events.jsonl" <<'EOF'
{"event_code":"ingress_backend_started","fields":{"backend_runtime_id":"wide_primary_macos","wide_backend_current_stage":"dns_preview_phase2_live","wide_udp_capture_runtime_scope":"macos_ipv4_loopback_preview"}}
EOF

cat > "${PHASE3_DIR}/boundary-summary.json" <<'EOF'
{"helper_apply_runtime_claim":"system_wide_phase3_prepared_boundary_only","helper_status_runtime_claim":"system_wide_phase3_prepared_boundary_only","strict_event_code":"ingress_startup_selection_failed","strict_selection_error_code":"wide_backend_boundary_only","strict_wide_runtime_readiness":"prepared_boundary","fallback_event_code":"ingress_backend_started","fallback_backend_runtime_id":"socks5_fallback","fallback_startup_fallback_reason_code":"wide_backend_boundary_only"}
EOF

cat > "${PHASE3_DIR}/helper-evidence.json" <<'EOF'
{"current_verdict":"system_wide_phase3_prepared_boundary_materialized"}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out" --rooted-live-dir "${ROOTED_LIVE_DIR}" >/dev/null

SUMMARY_JSON="${TMP_DIR}/out/macos-pf-operator-acceptance-summary.json"
SUMMARY_MD="${TMP_DIR}/out/macos-pf-operator-acceptance-summary.md"
require_file_contains "${SUMMARY_JSON}" '"artifact_schema": "macos_pf_operator_acceptance_summary_v1"'
require_file_contains "${SUMMARY_JSON}" '"supported_platform_track": "macos_pf_epic"'
require_file_contains "${SUMMARY_JSON}" '"supported_acceptance_scope": "rooted_local_phase1_phase2_plus_phase3_prepared_boundary_only"'
require_file_contains "${SUMMARY_JSON}" '"operator_acceptance_verdict": "green"'
require_file_contains "${SUMMARY_JSON}" '"next_required_action": "broader_runtime_still_not_opened"'
require_file_contains "${SUMMARY_JSON}" '"broader_system_wide_runtime_claim": "not_proven"'
require_file_contains "${SUMMARY_JSON}" '"broader_system_wide_runtime_claim_status": "not_opened"'
require_file_contains "${SUMMARY_JSON}" '"tcp_only_phase1"'
require_file_contains "${SUMMARY_JSON}" '"dns_preview_phase2"'
require_file_contains "${SUMMARY_JSON}" '"system_wide_phase3_prepared_boundary_only"'
require_file_contains "${SUMMARY_JSON}" '"phase1_helper_check_reason_code": "ready_for_apply"'
require_file_contains "${SUMMARY_JSON}" '"phase1_helper_apply_runtime_claim": "tcp_only_phase1_active"'
require_file_contains "${SUMMARY_JSON}" '"phase1_runtime_backend_id": "wide_primary_macos"'
require_file_contains "${SUMMARY_JSON}" '"phase2_helper_apply_runtime_claim": "dns_preview_phase2_active"'
require_file_contains "${SUMMARY_JSON}" '"phase2_udp_probe_matched": true'
require_file_contains "${SUMMARY_JSON}" '"phase2_runtime_backend_id": "wide_primary_macos"'
require_file_contains "${SUMMARY_JSON}" '"phase2_runtime_udp_scope": "macos_ipv4_loopback_preview"'
require_file_contains "${SUMMARY_JSON}" '"phase3_helper_apply_runtime_claim": "system_wide_phase3_prepared_boundary_only"'
require_file_contains "${SUMMARY_JSON}" '"phase3_prepared_boundary": true'
require_file_contains "${SUMMARY_JSON}" '"phase3_strict_selection_error_code": "wide_backend_boundary_only"'
require_file_contains "${SUMMARY_JSON}" '"phase3_fallback_backend_runtime_id": "socks5_fallback"'
require_file_contains "${SUMMARY_JSON}" '"phase3_fallback_reason_code": "wide_backend_boundary_only"'
require_file_contains "${SUMMARY_JSON}" '"failed_checks": []'
require_file_contains "${SUMMARY_JSON}" '"passed": true'
require_file_contains "${SUMMARY_MD}" "# macOS PF Operator Acceptance Summary"
require_file_contains "${SUMMARY_MD}" '- Operator acceptance verdict: `green`'
require_file_contains "${SUMMARY_MD}" '- Broader system-wide runtime claim: `not_opened`'
require_file_contains "${SUMMARY_MD}" '- Accepted milestones: `tcp_only_phase1, dns_preview_phase2, system_wide_phase3_prepared_boundary_only`'

############################################
# B1 acceptance gate: phase4 positive fixture
############################################

PHASE4_DIR="${ROOTED_LIVE_DIR}/phase4"
mkdir -p "${PHASE4_DIR}"

cat > "${PHASE4_DIR}/helper-apply.json" <<'EOF'
{"runtime_claim":"system_wide_phase4_active","runtime_active":true}
EOF

cat > "${PHASE4_DIR}/helper-evidence.json" <<'EOF'
{"current_verdict":"system_wide_phase4_helper_materialized"}
EOF

cat > "${PHASE4_DIR}/runtime-events.jsonl" <<'EOF'
{"event_code":"ingress_backend_started","fields":{"backend_runtime_id":"wide_primary_macos","wide_backend_current_stage":"system_wide_phase4_live","wide_runtime_readiness":"ready"}}
EOF

cat > "${PHASE4_DIR}/resolution-summary.json" <<'EOF'
{"strict_event_code":"ingress_backend_started","strict_wide_runtime_readiness":"ready","strict_selection_error_code":null,"fallback_startup_fallback_reason_code":null}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out-phase4-green" \
  --rooted-live-dir "${ROOTED_LIVE_DIR}" \
  --phase4-dir "${PHASE4_DIR}" >/dev/null

PHASE4_GREEN_JSON="${TMP_DIR}/out-phase4-green/macos-pf-operator-acceptance-summary.json"
PHASE4_GREEN_MD="${TMP_DIR}/out-phase4-green/macos-pf-operator-acceptance-summary.md"
require_file_contains "${PHASE4_GREEN_JSON}" '"artifact_schema": "macos_pf_operator_acceptance_summary_v2"'
require_file_contains "${PHASE4_GREEN_JSON}" '"supported_acceptance_scope": "rooted_local_phase1_phase2_phase3_plus_phase4_bind_capable"'
require_file_contains "${PHASE4_GREEN_JSON}" '"operator_acceptance_verdict": "green"'
require_file_contains "${PHASE4_GREEN_JSON}" '"broader_system_wide_runtime_claim": "proven"'
require_file_contains "${PHASE4_GREEN_JSON}" '"broader_system_wide_runtime_claim_status": "green"'
require_file_contains "${PHASE4_GREEN_JSON}" '"next_required_action": "phase4_live_hostile_path_validation_or_broader_release_claim"'
require_file_contains "${PHASE4_GREEN_JSON}" '"system_wide_phase4_bind_capable"'
require_file_contains "${PHASE4_GREEN_JSON}" '"phase4_helper_apply_runtime_claim": "system_wide_phase4_active"'
require_file_contains "${PHASE4_GREEN_JSON}" '"phase4_runtime_backend_id": "wide_primary_macos"'
require_file_contains "${PHASE4_GREEN_JSON}" '"phase4_runtime_backend_current_stage": "system_wide_phase4_live"'
require_file_contains "${PHASE4_GREEN_JSON}" '"phase4_runtime_wide_runtime_readiness": "ready"'
require_file_contains "${PHASE4_GREEN_JSON}" '"phase4_resolution_strict_event_code": "ingress_backend_started"'
require_file_contains "${PHASE4_GREEN_JSON}" '"phase4_resolution_fallback_fallback_reason_code": null'
require_file_contains "${PHASE4_GREEN_JSON}" '"failed_checks": []'
require_file_contains "${PHASE4_GREEN_MD}" "## Phase 4 Bind-Capable Checks (B1 gate)"
require_file_contains "${PHASE4_GREEN_MD}" '- Broader system-wide runtime claim: `green`'

############################################
# B1 acceptance gate: phase4 negative fixture — strict path still fails on boundary_only
############################################

PHASE4_BAD_DIR="${ROOTED_LIVE_DIR}/phase4-still-boundary"
mkdir -p "${PHASE4_BAD_DIR}"

cat > "${PHASE4_BAD_DIR}/helper-apply.json" <<'EOF'
{"runtime_claim":"system_wide_phase4_active","runtime_active":true}
EOF

cat > "${PHASE4_BAD_DIR}/helper-evidence.json" <<'EOF'
{"current_verdict":"system_wide_phase4_helper_materialized"}
EOF

cat > "${PHASE4_BAD_DIR}/runtime-events.jsonl" <<'EOF'
{"event_code":"ingress_backend_started","fields":{"backend_runtime_id":"wide_primary_macos","wide_backend_current_stage":"system_wide_phase4_live","wide_runtime_readiness":"ready"}}
EOF

# Resolution still rejects strict path with boundary_only — phase-4 B2 implementation regression scenario
cat > "${PHASE4_BAD_DIR}/resolution-summary.json" <<'EOF'
{"strict_event_code":"ingress_startup_selection_failed","strict_wide_runtime_readiness":"boundary_only","strict_selection_error_code":"wide_backend_boundary_only","fallback_startup_fallback_reason_code":"wide_backend_boundary_only"}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out-phase4-degraded" \
  --rooted-live-dir "${ROOTED_LIVE_DIR}" \
  --phase4-dir "${PHASE4_BAD_DIR}" >/dev/null

PHASE4_DEGRADED_JSON="${TMP_DIR}/out-phase4-degraded/macos-pf-operator-acceptance-summary.json"
require_file_contains "${PHASE4_DEGRADED_JSON}" '"artifact_schema": "macos_pf_operator_acceptance_summary_v2"'
require_file_contains "${PHASE4_DEGRADED_JSON}" '"operator_acceptance_verdict": "degraded"'
require_file_contains "${PHASE4_DEGRADED_JSON}" '"broader_system_wide_runtime_claim": "not_proven"'
require_file_contains "${PHASE4_DEGRADED_JSON}" '"broader_system_wide_runtime_claim_status": "degraded"'
require_file_contains "${PHASE4_DEGRADED_JSON}" '"resolution_strict_path_succeeds"'
require_file_contains "${PHASE4_DEGRADED_JSON}" '"next_required_action": "resolution_strict_path_succeeds"'
require_file_contains "${PHASE4_DEGRADED_JSON}" '"helper_apply_system_wide_phase4_active"'
require_file_contains "${PHASE4_DEGRADED_JSON}" '"helper_evidence_system_wide_phase4_materialized"'
require_file_contains "${PHASE4_DEGRADED_JSON}" '"runtime_backend_started_system_wide_phase4_bind_capable"'
require_file_contains "${PHASE4_DEGRADED_JSON}" '"passed": false'

echo "build-macos-pf-operator-acceptance-summary contract: ok"
