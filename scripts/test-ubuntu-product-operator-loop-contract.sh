#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/ubuntu-product-operator-loop.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-ubuntu-operator-loop.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cargo build -q -p aegis-measure
export AEGIS_MEASURE_BIN="${ROOT}/target/debug/aegis-measure"

CLIENT_CONFIG="${TMP_DIR}/aegis.toml"
RUNTIME_EVENTS="${TMP_DIR}/runtime-events.jsonl"
OPERATOR_EVIDENCE="${TMP_DIR}/runtime-events.jsonl.operator-evidence.json"
HELPER_SCRIPT="${TMP_DIR}/setup-wide-linux-tproxy.sh"

printf 'mode = "client"\n' > "${CLIENT_CONFIG}"
printf '{"event_code":"ingress_backend_started","level":"info","message":"ok","fields":{}}\n' > "${RUNTIME_EVENTS}"

cat > "${HELPER_SCRIPT}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
action="${1:-}"
case "${action}" in
  doctor)
    echo "doctor green"
    exit 0
    ;;
  probe)
    echo "probe green"
    exit 0
    ;;
  events)
    cat > "${AEGIS_OPERATOR_EVIDENCE_JSON}" <<'JSON'
{
  "artifact_schema": "wide_linux_operator_evidence_v1",
  "startup_health": "healthy",
  "runtime_status": "healthy",
  "product_verdict": "green",
  "failover_count": 0,
  "terminal_failure_count": 0
}
JSON
    echo "events green"
    exit 0
    ;;
  *)
    exit 1
    ;;
esac
EOF
chmod +x "${HELPER_SCRIPT}"

CHECK_JSON="${TMP_DIR}/check.json"
AEGIS_UBUNTU_OPERATOR_LOOP_HELPER_SCRIPT="${HELPER_SCRIPT}" \
AEGIS_CLIENT_CONFIG="${CLIENT_CONFIG}" \
AEGIS_RUNTIME_EVENTS_JSONL="${RUNTIME_EVENTS}" \
AEGIS_OPERATOR_EVIDENCE_JSON="${OPERATOR_EVIDENCE}" \
  bash "${SCRIPT}" --check --json > "${CHECK_JSON}"

jq -e '
  .artifact_schema == "ubuntu_product_operator_loop_v1"
  and .mode == "check"
  and .ready == true
  and .helper_exit_code == 0
' "${CHECK_JSON}" >/dev/null

RUN_DIR="${TMP_DIR}/run"
RUN_JSON="${TMP_DIR}/run.json"
AEGIS_UBUNTU_OPERATOR_LOOP_HELPER_SCRIPT="${HELPER_SCRIPT}" \
AEGIS_CLIENT_CONFIG="${CLIENT_CONFIG}" \
AEGIS_RUNTIME_EVENTS_JSONL="${RUNTIME_EVENTS}" \
AEGIS_OPERATOR_EVIDENCE_JSON="${OPERATOR_EVIDENCE}" \
  bash "${SCRIPT}" --run --artifact-dir "${RUN_DIR}" --json > "${RUN_JSON}"

jq -e '
  .artifact_schema == "ubuntu_product_operator_loop_summary_v1"
  and .overall_status == "green"
  and .startup_health == "healthy"
  and .runtime_status == "healthy"
  and .product_verdict == "green"
  and ([.actions[].name] == ["doctor", "probe", "events"])
  and all(.actions[]; .exit_code == 0)
' "${RUN_JSON}" >/dev/null

jq -e '.product_verdict == "green"' "${OPERATOR_EVIDENCE}" >/dev/null

echo "ubuntu-product-operator-loop contract: ok"
