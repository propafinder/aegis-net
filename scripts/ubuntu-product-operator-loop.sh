#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="check"
JSON_OUTPUT=0
READY=0
ARTIFACT_DIR="${AEGIS_UBUNTU_OPERATOR_LOOP_ARTIFACT_DIR:-}"
HELPER_SCRIPT="${AEGIS_UBUNTU_OPERATOR_LOOP_HELPER_SCRIPT:-${ROOT}/scripts/setup-wide-linux-tproxy.sh}"
CLIENT_CONFIG="${AEGIS_CLIENT_CONFIG:-}"
RUNTIME_EVENTS_JSONL="${AEGIS_RUNTIME_EVENTS_JSONL:-}"
OPERATOR_EVIDENCE_JSON="${AEGIS_OPERATOR_EVIDENCE_JSON:-}"
SUPPORTED_PRODUCT_CONTOUR="ubuntu_first_operator_loop"
SUPPORTED_OPERATOR_SCOPE="ubuntu_first_doctor_probe_events"
ERROR_CODE=""
HELPER_EXIT_CODE=0
REQUIREMENT_STATUS_ARGS=()
MISSING_REQUIREMENTS=()

run_aegis_measure() {
  if [[ -x "${AEGIS_MEASURE_BIN:-}" ]]; then
    "${AEGIS_MEASURE_BIN}" "$@"
  elif [[ -x "${ROOT}/target/debug/aegis-measure" ]] &&
    "${ROOT}/target/debug/aegis-measure" build-ubuntu-product-operator-loop-check-report --help >/dev/null 2>&1
  then
    "${ROOT}/target/debug/aegis-measure" "$@"
  else
    cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- "$@"
  fi
}

default_installed_client_config() {
  local candidate="/etc/aegis/client/aegis.toml"
  if [[ -f "${candidate}" ]]; then
    printf '%s\n' "${candidate}"
  fi
}

default_runtime_events_jsonl() {
  local installed="/var/log/aegis-client/runtime-events.jsonl"
  if [[ -e "${installed}" ]]; then
    printf '%s\n' "${installed}"
  else
    printf '%s\n' "${ROOT}/aegis-client-runtime.jsonl"
  fi
}

if [[ -z "${CLIENT_CONFIG}" ]]; then
  CLIENT_CONFIG="$(default_installed_client_config)"
fi
if [[ -z "${RUNTIME_EVENTS_JSONL}" ]]; then
  RUNTIME_EVENTS_JSONL="$(default_runtime_events_jsonl)"
fi
if [[ -z "${OPERATOR_EVIDENCE_JSON}" ]]; then
  OPERATOR_EVIDENCE_JSON="${RUNTIME_EVENTS_JSONL}.operator-evidence.json"
fi

usage() {
  cat <<'EOF'
Usage:
  scripts/ubuntu-product-operator-loop.sh [--check|--run] [--json] [--artifact-dir <dir>]

Modes:
  --check             Validate canonical operator-loop prerequisites.
  --run               Execute doctor -> probe -> events and materialize one summary.
  --json              Emit machine-readable JSON to stdout.
  --artifact-dir DIR  Directory for operator-loop artifacts.
EOF
}

record_requirement_status() {
  local name="$1"
  local status="$2"
  local detail="$3"
  REQUIREMENT_STATUS_ARGS+=(--requirement "${name}"$'\t'"${status}"$'\t'"${detail}")
  if [[ "${status}" != "ok" ]]; then
    MISSING_REQUIREMENTS+=("${name}")
  fi
}

print_json_report() {
  local ready_value="false"
  local entry=""
  local args=()

  if [[ "${READY}" -eq 1 ]]; then
    ready_value="true"
  fi

  args+=(
    build-ubuntu-product-operator-loop-check-report
    --mode "${MODE}"
    --supported-product-contour "${SUPPORTED_PRODUCT_CONTOUR}"
    --supported-operator-scope "${SUPPORTED_OPERATOR_SCOPE}"
    --helper-script "${HELPER_SCRIPT}"
    --ready "${ready_value}"
    --helper-exit-code "${HELPER_EXIT_CODE}"
  )
  [[ -n "${CLIENT_CONFIG}" ]] && args+=(--client-config "${CLIENT_CONFIG}")
  [[ -n "${RUNTIME_EVENTS_JSONL}" ]] && args+=(--runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}")
  [[ -n "${OPERATOR_EVIDENCE_JSON}" ]] && args+=(--operator-evidence-json "${OPERATOR_EVIDENCE_JSON}")
  [[ -n "${ARTIFACT_DIR}" ]] && args+=(--artifact-dir "${ARTIFACT_DIR}")
  [[ -n "${ERROR_CODE}" ]] && args+=(--error-code "${ERROR_CODE}")
  if (( ${#REQUIREMENT_STATUS_ARGS[@]} != 0 )); then
    args+=("${REQUIREMENT_STATUS_ARGS[@]}")
  fi
  if (( ${#MISSING_REQUIREMENTS[@]} != 0 )); then
    for entry in "${MISSING_REQUIREMENTS[@]}"; do
      args+=(--missing-requirement "${entry}")
    done
  fi

  run_aegis_measure "${args[@]}"
}

print_text_report() {
  echo "mode=${MODE}"
  echo "supported_product_contour=${SUPPORTED_PRODUCT_CONTOUR}"
  echo "supported_operator_scope=${SUPPORTED_OPERATOR_SCOPE}"
  echo "ready=${READY}"
  echo "helper_script=${HELPER_SCRIPT}"
  if [[ -n "${CLIENT_CONFIG}" ]]; then
    echo "client_config=${CLIENT_CONFIG}"
  fi
  if [[ -n "${RUNTIME_EVENTS_JSONL}" ]]; then
    echo "runtime_events_jsonl=${RUNTIME_EVENTS_JSONL}"
  fi
  if [[ -n "${OPERATOR_EVIDENCE_JSON}" ]]; then
    echo "operator_evidence_json=${OPERATOR_EVIDENCE_JSON}"
  fi
}

fail_helper() {
  local error_code="$1"
  local exit_code="${2:-1}"
  READY=0
  HELPER_EXIT_CODE="${exit_code}"
  ERROR_CODE="${error_code}"
  if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
    print_json_report
  else
    print_text_report >&2
  fi
  exit "${exit_code}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)
      MODE="check"
      shift
      ;;
    --run)
      MODE="run"
      shift
      ;;
    --json)
      JSON_OUTPUT=1
      shift
      ;;
    --artifact-dir)
      ARTIFACT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      HELPER_EXIT_CODE=1
      ERROR_CODE="unknown_argument"
      if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
        print_json_report
      else
        usage >&2
      fi
      exit 1
      ;;
  esac
done

if [[ -f "${HELPER_SCRIPT}" ]]; then
  record_requirement_status "operator_helper" "ok" "setup-wide-linux-tproxy helper exists"
else
  record_requirement_status "operator_helper" "missing" "setup-wide-linux-tproxy helper exists"
fi
if [[ -n "${CLIENT_CONFIG}" && -f "${CLIENT_CONFIG}" ]]; then
  record_requirement_status "client_config" "ok" "client config for doctor/probe loop is available"
else
  record_requirement_status "client_config" "missing" "client config for doctor/probe loop is available"
fi
if [[ -n "${RUNTIME_EVENTS_JSONL}" && -e "${RUNTIME_EVENTS_JSONL}" ]]; then
  record_requirement_status "runtime_events_jsonl" "ok" "runtime JSONL exists for events/evidence loop"
else
  record_requirement_status "runtime_events_jsonl" "missing" "runtime JSONL exists for events/evidence loop"
fi

if [[ "${MODE}" == "check" ]]; then
  if (( ${#MISSING_REQUIREMENTS[@]} == 0 )); then
    READY=1
    HELPER_EXIT_CODE=0
  else
    READY=0
    HELPER_EXIT_CODE=1
  fi
  if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
    print_json_report
  else
    print_text_report
  fi
  exit "${HELPER_EXIT_CODE}"
fi

[[ -f "${HELPER_SCRIPT}" ]] || fail_helper "operator_helper_missing" 2
[[ -n "${CLIENT_CONFIG}" && -f "${CLIENT_CONFIG}" ]] || fail_helper "client_config_missing" 2

if [[ -z "${ARTIFACT_DIR}" ]]; then
  ARTIFACT_DIR="${ROOT}/dist/ubuntu-operator-loop"
fi
mkdir -p "${ARTIFACT_DIR}"

DOCTOR_LOG="${ARTIFACT_DIR}/doctor.txt"
PROBE_LOG="${ARTIFACT_DIR}/probe.txt"
EVENTS_LOG="${ARTIFACT_DIR}/events.txt"
SUMMARY_JSON="${ARTIFACT_DIR}/ubuntu-product-operator-loop-summary.json"

run_action_capture() {
  local action="$1"
  local log_path="$2"
  local status=0
  set +e
  AEGIS_CLIENT_CONFIG="${CLIENT_CONFIG}" \
    AEGIS_RUNTIME_EVENTS_JSONL="${RUNTIME_EVENTS_JSONL}" \
    AEGIS_OPERATOR_EVIDENCE_JSON="${OPERATOR_EVIDENCE_JSON}" \
    bash "${HELPER_SCRIPT}" "${action}" > "${log_path}" 2>&1
  status=$?
  set -e
  printf '%s' "${status}"
}

doctor_status="$(run_action_capture "doctor" "${DOCTOR_LOG}")"
probe_status="$(run_action_capture "probe" "${PROBE_LOG}")"
events_status="$(run_action_capture "events" "${EVENTS_LOG}")"

run_aegis_measure build-ubuntu-product-operator-loop-summary \
  --output "${SUMMARY_JSON}" \
  --client-config "${CLIENT_CONFIG}" \
  --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}" \
  --operator-evidence-json "${OPERATOR_EVIDENCE_JSON}" \
  --doctor-log "${DOCTOR_LOG}" \
  --probe-log "${PROBE_LOG}" \
  --events-log "${EVENTS_LOG}" \
  --doctor-status "${doctor_status}" \
  --probe-status "${probe_status}" \
  --events-status "${events_status}"

READY=1
HELPER_EXIT_CODE=0
if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
  cat "${SUMMARY_JSON}"
else
  echo "ubuntu_product_operator_loop_summary_json=${SUMMARY_JSON}"
  echo "operator_evidence_json=${OPERATOR_EVIDENCE_JSON}"
fi

grep -q '"overall_status": "green"' "${SUMMARY_JSON}"
