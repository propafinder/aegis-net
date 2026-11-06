#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-ubuntu-operator-reapply-canary.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-ubuntu-operator-canary.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

VALIDATION_SUMMARY="${TMP_DIR}/validation-summary.json"
RELEASE_SUMMARY="${TMP_DIR}/ubuntu-product-release-summary.json"
OPERATOR_LOOP="${TMP_DIR}/client-operator-loop-summary.json"
PILOT_INPUTS="${TMP_DIR}/ubuntu-controlled-pilot-inputs.json"

cat > "${VALIDATION_SUMMARY}" <<'EOF'
{
  "artifact_schema": "debian_package_host_run_summary_v2",
  "service_health_verdict": "green",
  "baseline_bypass_ready": true,
  "baseline_bypass_verdict": "proven",
  "bypass_support_tier": "baseline_transport_runtime",
  "upgrade_reapply_mode": "same_version_reapply",
  "lifecycle_phases": [
    "install",
    "preset_policy",
    "service_start",
    "service_restart",
    "reboot_contract",
    "remove",
    "reinstall",
    "upgrade_reapply",
    "purge"
  ],
  "required_runtime_artifacts": [
    "validation-summary.json",
    "runtime/server-systemctl-status.log"
  ],
  "phase_results": [
    {"name":"service_restart","status":"passed","detail":"server/client services survived explicit restart"},
    {"name":"reboot_contract","status":"passed","detail":"daemon-reload plus restart kept both services healthy"},
    {"name":"remove","status":"passed","detail":"remove preserved conffiles and removed package payload"},
    {"name":"reinstall","status":"passed","detail":"packages reinstall cleanly after remove"},
    {"name":"upgrade_reapply","status":"passed","detail":"same-version dpkg reapply kept installed payload coherent"}
  ]
}
EOF

cat > "${RELEASE_SUMMARY}" <<'EOF'
{"artifact_schema":"ubuntu_product_release_summary_v2","service_health_verdict":"green","baseline_bypass_ready":true,"baseline_bypass_verdict":"proven","bypass_support_tier":"baseline_transport_runtime"}
EOF

cat > "${OPERATOR_LOOP}" <<'EOF'
{"artifact_schema":"ubuntu_product_operator_loop_summary_v2","overall_status":"green"}
EOF

cat > "${PILOT_INPUTS}" <<EOF
{
  "artifact_schema": "ubuntu_controlled_pilot_inputs_v1",
  "validation_summary_json": "${VALIDATION_SUMMARY}",
  "release_summary_json": "${RELEASE_SUMMARY}",
  "operator_loop_summary_json": "${OPERATOR_LOOP}"
}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out" --pilot-inputs "${PILOT_INPUTS}" >/dev/null

OUTPUT_JSON="${TMP_DIR}/out/ubuntu-operator-reapply-canary.json"
OUTPUT_MD="${TMP_DIR}/out/ubuntu-operator-reapply-canary.md"

jq -e '
  .artifact_schema == "ubuntu_operator_reapply_canary_v1"
  and .operator_canary_verdict == "green"
  and .restart_canary_ready == true
  and .rollback_canary_ready == true
  and .reapply_canary_ready == true
  and .restart_failures == []
  and .rollback_failures == []
  and .reapply_failures == []
  and .restart_checks.service_restart_passed.passed == true
  and .rollback_checks.remove_passed.passed == true
  and .reapply_checks.upgrade_reapply_passed.passed == true
  and .next_required_action == "none"
' "${OUTPUT_JSON}" >/dev/null

grep -Fq -- "Ubuntu Operator Reapply Canary" "${OUTPUT_MD}"
grep -Fq -- "- Operator canary verdict: \`green\`" "${OUTPUT_MD}"

echo "build-ubuntu-operator-reapply-canary contract: ok"
