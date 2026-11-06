#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

REPO_ONLY_OUT="${TMP_DIR}/repo-green.json"
HOST_SUMMARY="${TMP_DIR}/validation-summary.json"
HOST_OUT="${TMP_DIR}/ship-ready.json"

bash "${ROOT}/scripts/ubuntu-release-gate-status.sh" --repo-green --output "${REPO_ONLY_OUT}"

jq -e '
  .artifact_schema == "ubuntu_release_gate_handoff_v1"
  and .repo_contract_status == "passed"
  and .ubuntu_host_evidence_present == false
  and .ship_ready == false
  and .release_readiness == "repo_green_only"
  and .ship_blocker_reason == "ubuntu_host_evidence_missing"
  and (.next_required_action | endswith("scripts/validate-debian-package-host.sh --run"))
' "${REPO_ONLY_OUT}" >/dev/null

cat >"${HOST_SUMMARY}" <<'EOF'
{
  "release_gate_status": "passed",
  "ship_decision": "ship",
  "product_verdict": "green",
  "required_lifecycle_phases": ["install", "purge"],
  "required_runtime_artifacts": ["validation-summary.json", "runtime/client-runtime-events-summary.json"]
}
EOF

bash "${ROOT}/scripts/ubuntu-release-gate-status.sh" --host-summary "${HOST_SUMMARY}" --output "${HOST_OUT}"

jq -e --arg summary_path "${HOST_SUMMARY}" '
  .ubuntu_host_evidence_present == true
  and .ubuntu_host_summary_path == $summary_path
  and .ship_ready == true
  and .release_readiness == "ship_ready"
  and .ship_blocker_reason == null
  and .next_required_action == "none"
  and .required_lifecycle_phases == ["install", "purge"]
  and .required_runtime_artifacts == [
    "validation-summary.json",
    "runtime/client-runtime-events-summary.json"
  ]
' "${HOST_OUT}" >/dev/null

echo "ubuntu-release-gate-status contract: ok"
