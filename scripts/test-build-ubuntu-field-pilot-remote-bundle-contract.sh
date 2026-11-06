#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-ubuntu-field-pilot-remote-bundle.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-field-pilot-remote.XXXXXX")"
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
{"artifact_schema":"ubuntu_product_operator_loop_summary_v2","overall_status":"green","service_health_verdict":"green","product_verdict":"green","baseline_bypass_verdict":"proven","baseline_bypass_ready":true,"bypass_verdict":"proven","bypass_ready":true,"bypass_support_tier":"baseline_transport_runtime","hostile_path_verdict":"missing_evidence","hostile_path_ready":false,"fully_proven":false}
EOF

cat > "${VALIDATION_SUMMARY}" <<'EOF'
{"artifact_schema":"debian_package_host_run_summary_v2","product_verdict":"green","service_health_verdict":"green","baseline_bypass_verdict":"proven","baseline_bypass_ready":true,"bypass_verdict":"proven","bypass_ready":true,"bypass_support_tier":"baseline_transport_runtime","hostile_path_verdict":"missing_evidence","hostile_path_ready":false,"fully_proven":false,"upgrade_reapply_mode":"same_version_reapply","phase_results":[{"name":"service_restart","status":"passed","detail":"server/client services survived explicit restart"},{"name":"reboot_contract","status":"passed","detail":"daemon-reload plus restart kept both services healthy"},{"name":"remove","status":"passed","detail":"remove preserved conffiles and removed package payload"},{"name":"reinstall","status":"passed","detail":"packages reinstall cleanly after remove"},{"name":"upgrade_reapply","status":"passed","detail":"same-version dpkg reapply kept installed payload coherent"}]}
EOF

cat > "${RELEASE_SUMMARY}" <<'EOF'
{"artifact_schema":"ubuntu_product_release_summary_v2","ship_ready":true,"release_readiness":"ship_ready","service_health_verdict":"green","baseline_bypass_verdict":"proven","baseline_bypass_ready":true,"bypass_verdict":"proven","bypass_ready":true,"bypass_support_tier":"baseline_transport_runtime","hostile_path_verdict":"missing_evidence","hostile_path_ready":false,"fully_proven":false}
EOF

cat > "${RELEASE_HANDOFF}" <<'EOF'
{"artifact_schema":"ubuntu_release_gate_handoff_v1","ship_ready":true,"release_readiness":"ship_ready","bypass_ready":true,"next_required_action":"none"}
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

bash "${SCRIPT}" "${OUTPUT_DIR}" \
  --pilot-inputs "${PILOT_INPUTS}" \
  --relay-host "pilot-relay" \
  --client-host "pilot-client" \
  --blocked-shape "blocked-lab-shape" \
  --bundle-url-file "/remote/client-access-url.txt" >/dev/null

OUTPUT_JSON="${OUTPUT_DIR}/field-pilot-remote-bundle.json"
OUTPUT_MD="${OUTPUT_DIR}/field-pilot-remote-bundle.md"

jq -e '
  .artifact_schema == "ubuntu_field_pilot_remote_bundle_v1"
  and .bundle_url_example == null
  and .bundle_input == {"kind":"url_file","path":"/remote/client-access-url.txt"}
  and .relay_host_label == "pilot-relay"
  and .client_host_label == "pilot-client"
  and .operator_canary_verdict == "green"
  and .restart_canary_ready == true
  and .rollback_canary_ready == true
  and .reapply_canary_ready == true
  and .field_pilot_status == "remote_shape_ready_for_live_evidence"
  and .wave_status == "baseline_ship_ready"
  and .next_required_action == "collect_blocked_shape_wire_proof_to_reach_fully_proven"
' "${OUTPUT_JSON}" >/dev/null

for path in \
  "$(jq -r '.pilot_review_manifest_json' "${OUTPUT_JSON}")" \
  "$(jq -r '.release_wave_manifest_json' "${OUTPUT_JSON}")"; do
  if [[ ! -f "${path}" ]]; then
    echo "missing expected generated file: ${path}" >&2
    exit 1
  fi
done

grep -Fq -- "Ubuntu Field Pilot Remote Bundle" "${OUTPUT_MD}"
grep -Fq -- "- Operator canary verdict: \`green\`" "${OUTPUT_MD}"


# The remote private pathname above need not exist on this planning host.
# Deprecated values must be refused before any new output directory is made.
for form in split equals; do
  refused_dir="${TMP_DIR}/rejected-${form}"
  if [[ "$form" == split ]]; then
    deprecated=(--bundle-url 'https://fixture.invalid/?token=INLINE_PRIVATE_SENTINEL')
  else
    deprecated=('--bundle-url=https://fixture.invalid/?token=INLINE_PRIVATE_SENTINEL')
  fi
  if bash "${SCRIPT}" "$refused_dir" "${deprecated[@]}" >"${TMP_DIR}/refusal-${form}.log" 2>&1; then
    echo "deprecated inline bundle form accepted" >&2
    exit 1
  fi
  [[ ! -e "$refused_dir" ]] || { echo "deprecated form created outputs" >&2; exit 1; }
  if grep -q 'INLINE_PRIVATE_SENTINEL' "${TMP_DIR}/refusal-${form}.log"; then
    echo "deprecated form reflected private material" >&2
    exit 1
  fi
  grep -q 'Use --bundle-url-file' "${TMP_DIR}/refusal-${form}.log"
done

echo "build-ubuntu-field-pilot-remote-bundle contract: ok"
