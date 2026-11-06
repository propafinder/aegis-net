#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-ubuntu-controlled-pilot-bundle.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-ubuntu-pilot.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

VALIDATION_DIR="${TMP_DIR}/validation"
SERVER_STATUS="${VALIDATION_DIR}/runtime/server-systemctl-status.log"
SERVER_JOURNAL="${VALIDATION_DIR}/runtime/server-journal.log"
CLIENT_PREFLIGHT="${VALIDATION_DIR}/runtime/client-preflight.json"
CLIENT_STARTUP="${VALIDATION_DIR}/runtime/client-startup-probe.json"
CLIENT_RUNTIME="${VALIDATION_DIR}/runtime/client-runtime-events-summary.json"
CLIENT_OPERATOR="${VALIDATION_DIR}/runtime/client-operator-evidence.json"
OPERATOR_LOOP="${VALIDATION_DIR}/runtime/client-operator-loop-summary.json"
VALIDATION_SUMMARY="${VALIDATION_DIR}/validation-summary.json"
RELEASE_SUMMARY="${VALIDATION_DIR}/ubuntu-product-release-summary.json"
RELEASE_HANDOFF="${VALIDATION_DIR}/ubuntu-release-gate-handoff.json"
PILOT_INPUTS="${VALIDATION_DIR}/ubuntu-controlled-pilot-inputs.json"
WIRE_WITNESS="${TMP_DIR}/wire-witness-summary.json"
OUTPUT_DIR="${TMP_DIR}/bundle"

mkdir -p "${VALIDATION_DIR}/runtime"

cat > "${SERVER_STATUS}" <<'EOF'
aegis-server.service active (running)
EOF

cat > "${SERVER_JOURNAL}" <<'EOF'
stub journal line
EOF

cat > "${CLIENT_PREFLIGHT}" <<'EOF'
{"status":"ok","selection":{"selected_backend":"linux_tproxy"}}
EOF

cat > "${CLIENT_STARTUP}" <<'EOF'
{"status":"ok","startup":{"code":"ok","started_backend":"linux_tproxy"}}
EOF

cat > "${CLIENT_RUNTIME}" <<'EOF'
{"record_count":2,"latest_event_code":"ingress_backend_started","latest_level":"info","startup_health":"healthy"}
EOF

cat > "${CLIENT_OPERATOR}" <<'EOF'
{"artifact_schema":"wide_linux_operator_evidence_v1","backend":"linux_tproxy","startup_health":"healthy","runtime_status":"healthy","product_verdict":"green","runtime_degradation_count":0,"failover_count":0,"terminal_failure_count":0}
EOF

cat > "${OPERATOR_LOOP}" <<'EOF'
{"artifact_schema":"ubuntu_product_operator_loop_summary_v2","overall_status":"green","service_health_verdict":"green","product_verdict":"green","baseline_bypass_verdict":"proven","baseline_bypass_ready":true,"bypass_verdict":"proven","bypass_ready":true,"bypass_support_tier":"baseline_transport_runtime","dns_support_tier":"disabled","dns_runtime_verdict":"not_requested","dns_runtime_ready":false,"hostile_path_verdict":"missing_evidence","hostile_path_ready":false,"fully_proven":false}
EOF

cat > "${VALIDATION_SUMMARY}" <<'EOF'
{"artifact_schema":"debian_package_host_run_summary_v2","product_verdict":"green","service_health_verdict":"green","baseline_bypass_verdict":"proven","baseline_bypass_ready":true,"bypass_verdict":"proven","bypass_ready":true,"bypass_support_tier":"baseline_transport_runtime","dns_support_tier":"disabled","dns_runtime_verdict":"not_requested","dns_runtime_ready":false,"hostile_path_verdict":"missing_evidence","hostile_path_ready":false,"fully_proven":false}
EOF

cat > "${RELEASE_SUMMARY}" <<'EOF'
{"artifact_schema":"ubuntu_product_release_summary_v2","ship_ready":true,"release_readiness":"ship_ready","service_health_verdict":"green","baseline_bypass_verdict":"proven","baseline_bypass_ready":true,"bypass_verdict":"proven","bypass_ready":true,"bypass_support_tier":"baseline_transport_runtime","dns_support_tier":"disabled","dns_runtime_verdict":"not_requested","dns_runtime_ready":false,"hostile_path_verdict":"missing_evidence","hostile_path_ready":false,"fully_proven":false}
EOF

cat > "${RELEASE_HANDOFF}" <<'EOF'
{"artifact_schema":"ubuntu_release_gate_handoff_v1","ship_ready":true,"release_readiness":"ship_ready","bypass_ready":true}
EOF

cat > "${PILOT_INPUTS}" <<EOF
{
  "artifact_schema": "ubuntu_controlled_pilot_inputs_v1",
  "validation_summary_json": "${VALIDATION_SUMMARY}",
  "release_summary_json": "${RELEASE_SUMMARY}",
  "operator_loop_summary_json": "${OPERATOR_LOOP}",
  "release_gate_handoff_json": "${RELEASE_HANDOFF}",
  "server_systemctl_status_log": "${SERVER_STATUS}",
  "server_journal_log": "${SERVER_JOURNAL}",
  "client_preflight_json": "${CLIENT_PREFLIGHT}",
  "client_startup_probe_json": "${CLIENT_STARTUP}",
  "client_runtime_events_summary_json": "${CLIENT_RUNTIME}",
  "client_operator_evidence_json": "${CLIENT_OPERATOR}"
}
EOF

cat > "${WIRE_WITNESS}" <<'EOF'
{"artifact_schema":"wire_mimicry_independent_witness_summary_v1","records":[]}
EOF

bash "${SCRIPT}" "${OUTPUT_DIR}" \
  --pilot-inputs "${PILOT_INPUTS}" \
  --wire-witness-summary "${WIRE_WITNESS}" \
  --server-host "pilot-relay" \
  --client-host "pilot-client" >/dev/null

SUMMARY_JSON="${OUTPUT_DIR}/pilot-summary.json"
MANIFEST_JSON="${OUTPUT_DIR}/bundle.manifest.json"

jq -e '
  .artifact_schema == "ubuntu_controlled_pilot_bundle_v1"
  and .pilot_verdict == "green"
  and (.pilot_blockers | index("wire_acceptance_summary_missing") != null)
  and .service_health_verdict == "green"
  and .baseline_bypass_ready == true
  and .bypass_verdict == "proven"
  and .bypass_ready == true
  and .bypass_support_tier == "baseline_transport_runtime"
  and .dns_support_tier == "disabled"
  and .dns_runtime_verdict == "not_requested"
  and .dns_runtime_ready == false
  and .hostile_path_verdict == "missing_evidence"
  and .hostile_path_ready == false
  and .fully_proven == false
  and .rollout_acceptance.must_pass_verdict == "pass"
  and .rollout_acceptance.must_pass_failures == []
  and .rollout_acceptance.advisory_verdict == "follow_up_required"
  and (.rollout_acceptance.advisory_followups | index("hostile_path_ready") != null)
  and .rollout_acceptance.must_pass_checks.baseline_bypass_ready.passed == true
  and .rollout_acceptance.advisory_checks.dns_runtime_ready_when_requested.passed == true
  and .server_host_label == "pilot-relay"
  and .client_host_label == "pilot-client"
  and .client.operator_product_verdict == "green"
  and (.validation_summary_json | endswith("validation-summary.json"))
  and (.release_summary_json | endswith("ubuntu-product-release-summary.json"))
  and (.client.operator_loop_summary_json | endswith("client-operator-loop-summary.json"))
  and .wire_witness_schema == "wire_mimicry_independent_witness_summary_v1"
' "${SUMMARY_JSON}" >/dev/null

jq -e '
  .artifact_schema == "ubuntu_controlled_pilot_manifest_v1"
  and .blocked_shape_label == "hostile_or_blocked_network_shape"
  and .hostile_path_ready == false
  and .fully_proven == false
  and .bypass_ready == true
  and .bypass_support_tier == "baseline_transport_runtime"
  and .dns_support_tier == "disabled"
  and .dns_runtime_verdict == "not_requested"
  and .dns_runtime_ready == false
  and .pilot_verdict == "green"
  and .must_pass_verdict == "pass"
  and .advisory_verdict == "follow_up_required"
' "${MANIFEST_JSON}" >/dev/null

echo "build-ubuntu-controlled-pilot-bundle contract: ok"
