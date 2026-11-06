#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/validate-ubuntu-product-release.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-ubuntu-product-release.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

make_fake_host_helper() {
  local path="$1"
  cat > "${path}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mode="check"
artifact_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) mode="check"; shift ;;
    --run) mode="run"; shift ;;
    --json) shift ;;
    --artifact-dir) artifact_dir="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [[ "${mode}" == "check" ]]; then
  cat <<'JSON'
{"artifact_schema":"debian_package_host_validation_v1","mode":"check","ready":true,"helper_exit_code":0}
JSON
  exit 0
fi

mkdir -p "${artifact_dir}"
cat > "${artifact_dir}/ubuntu-product-release-summary.json" <<'JSON'
{
  "artifact_schema": "ubuntu_product_release_summary_v2",
  "product_verdict": "green",
  "service_health_verdict": "green",
  "bypass_verdict": "proven",
  "bypass_ready": true,
  "bypass_support_tier": "baseline_transport_runtime",
  "ship_ready": true,
  "release_readiness": "ship_ready",
  "ship_blocker_reason": null,
  "next_required_action": "none",
  "host_validation_summary_json": "/tmp/fake/validation-summary.json",
  "release_gate_handoff_json": "/tmp/fake/ubuntu-release-gate-handoff.json"
}
JSON
EOF
  chmod +x "${path}"
}

HOST_HELPER="${TMP_DIR}/validate-debian-package-host.sh"
make_fake_host_helper "${HOST_HELPER}"

CHECK_JSON="${TMP_DIR}/check.json"
AEGIS_UBUNTU_PRODUCT_RELEASE_HOST_VALIDATION_SCRIPT="${HOST_HELPER}" \
  bash "${SCRIPT}" --check --json > "${CHECK_JSON}"

jq -e '
  .artifact_schema == "debian_package_host_validation_v1"
  and .mode == "check"
  and .ready == true
  and .helper_exit_code == 0
' "${CHECK_JSON}" >/dev/null

RUN_DIR="${TMP_DIR}/run"
RUN_JSON="${TMP_DIR}/run.json"
AEGIS_UBUNTU_PRODUCT_RELEASE_HOST_VALIDATION_SCRIPT="${HOST_HELPER}" \
  bash "${SCRIPT}" --run --artifact-dir "${RUN_DIR}" --json > "${RUN_JSON}"

jq -e '
  .artifact_schema == "ubuntu_product_release_summary_v2"
  and .ship_ready == true
  and .release_readiness == "ship_ready"
  and .product_verdict == "green"
  and .bypass_ready == true
  and .bypass_support_tier == "baseline_transport_runtime"
  and .next_required_action == "none"
  and (.host_validation_summary_json | endswith("validation-summary.json"))
  and (.release_gate_handoff_json | endswith("ubuntu-release-gate-handoff.json"))
' "${RUN_JSON}" >/dev/null

echo "validate-ubuntu-product-release contract: ok"
