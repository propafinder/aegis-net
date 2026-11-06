#!/usr/bin/env bash
# Privileged Linux acceptance helper for the narrow wire mimicry contour.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="check"
JSON_OUTPUT=0
ARTIFACT_DIR="${AEGIS_MIMICRY_WIRE_ARTIFACT_DIR:-}"
RUNTIME_EVENTS_JSONL="${AEGIS_MIMICRY_WIRE_RUNTIME_EVENTS_JSONL:-}"
WITNESS_SUMMARY_JSON="${AEGIS_MIMICRY_WIRE_WITNESS_SUMMARY_JSON:-}"
CONTRACT_SCRIPT="${AEGIS_MIMICRY_WIRE_CONTRACT_SCRIPT:-${ROOT}/scripts/mimicry-wire-validation-contract.sh}"
SUPPORTED_OPERATOR_SCOPE="privileged_linux_wire_mimicry_acceptance"
SUPPORTED_PRODUCT_CONTOUR="future_packet_wire_linux_only"
READY=0
HELPER_EXIT_CODE=0
ERROR_CODE=""
REQUIREMENT_STATUS_ARGS=()
MISSING_REQUIREMENTS=()

run_aegis_measure() {
  if [[ -x "${AEGIS_MEASURE_BIN:-}" ]]; then
    "${AEGIS_MEASURE_BIN}" "$@"
  elif [[ -x "${ROOT}/target/debug/aegis-measure" ]] &&
    "${ROOT}/target/debug/aegis-measure" build-mimicry-wire-host-helper-report --help >/dev/null 2>&1
  then
    "${ROOT}/target/debug/aegis-measure" "$@"
  else
    cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- "$@"
  fi
}

env_override_bool() {
  local name="$1"
  local value="${!name-}"
  case "${value}" in
    1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Oo][Nn]) printf '1' ;;
    0|[Ff][Aa][Ll][Ss][Ee]|[Nn][Oo]|[Oo][Ff][Ff]) printf '0' ;;
    *) printf '' ;;
  esac
}

linux_cap_eff_mask() {
  local status_path="${AEGIS_MIMICRY_WIRE_PROC_STATUS_PATH:-/proc/self/status}"
  [[ -r "${status_path}" ]] || return 1
  local cap_eff=""
  cap_eff="$(awk -F '\t' '$1 == "CapEff:" { print $2; exit }' "${status_path}")"
  [[ -n "${cap_eff}" ]] || return 1
  printf '%s' "${cap_eff}"
}

has_linux_capability_bit() {
  local bit="$1"
  local override_name="$2"
  local override=""
  override="$(env_override_bool "${override_name}")"
  if [[ -n "${override}" ]]; then
    [[ "${override}" == "1" ]]
    return
  fi
  local cap_eff=""
  cap_eff="$(linux_cap_eff_mask)" || return 1
  local mask=$((16#${cap_eff}))
  (( (mask & (1 << bit)) != 0 ))
}

usage() {
  cat <<'EOF'
Usage:
  scripts/validate-mimicry-wire-host.sh [--check|--run] [--json] [--runtime-events <path>] [--artifact-dir <dir>] [--witness-summary <path>]

Modes:
  --check                Validate Linux host prerequisites for narrow wire mimicry acceptance.
  --run                  Parse runtime JSONL evidence and materialize:
                         - capture-replay-summary.json
                         - wire-host-acceptance-summary.json
  --json                 Emit machine-readable JSON to stdout.
  --runtime-events PATH  Runtime events JSONL to analyze.
  --artifact-dir DIR     Output directory for acceptance artifacts.
  --witness-summary PATH Optional independent wire witness summary JSON.
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
    build-mimicry-wire-host-helper-report
    --mode "${MODE}"
    --supported-operator-scope "${SUPPORTED_OPERATOR_SCOPE}"
    --supported-product-contour "${SUPPORTED_PRODUCT_CONTOUR}"
    --ready "${ready_value}"
    --helper-exit-code "${HELPER_EXIT_CODE}"
  )
  if [[ -n "${RUNTIME_EVENTS_JSONL}" ]]; then
    args+=(--runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}")
  fi
  if [[ -n "${WITNESS_SUMMARY_JSON}" ]]; then
    args+=(--witness-summary-json "${WITNESS_SUMMARY_JSON}")
  fi
  if [[ -n "${ARTIFACT_DIR}" ]]; then
    args+=(--artifact-dir "${ARTIFACT_DIR}")
  fi
  if [[ -n "${ERROR_CODE}" ]]; then
    args+=(--error-code "${ERROR_CODE}")
  fi
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
  echo "supported_operator_scope=${SUPPORTED_OPERATOR_SCOPE}"
  echo "supported_product_contour=${SUPPORTED_PRODUCT_CONTOUR}"
  echo "ready=${READY}"
  if [[ -n "${RUNTIME_EVENTS_JSONL}" ]]; then
    echo "runtime_events_jsonl=${RUNTIME_EVENTS_JSONL}"
  fi
  if [[ -n "${WITNESS_SUMMARY_JSON}" ]]; then
    echo "witness_summary_json=${WITNESS_SUMMARY_JSON}"
  fi
  if [[ -n "${ARTIFACT_DIR}" ]]; then
    echo "artifact_dir=${ARTIFACT_DIR}"
  fi
  if (( ${#MISSING_REQUIREMENTS[@]} != 0 )); then
    echo "missing_requirements=${MISSING_REQUIREMENTS[*]}"
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
    --runtime-events)
      RUNTIME_EVENTS_JSONL="${2:-}"
      shift 2
      ;;
    --artifact-dir)
      ARTIFACT_DIR="${2:-}"
      shift 2
      ;;
    --witness-summary)
      WITNESS_SUMMARY_JSON="${2:-}"
      shift 2
      ;;
    --help|-h)
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

if [[ -z "${ARTIFACT_DIR}" && -n "${RUNTIME_EVENTS_JSONL}" ]]; then
  ARTIFACT_DIR="$(dirname "${RUNTIME_EVENTS_JSONL}")/wire-acceptance"
fi

record_requirement_status "linux_host" "$([[ "$(uname -s)" == "Linux" ]] && printf 'ok' || printf 'missing')" "wire acceptance helper targets Linux only"
if [[ -f "${CONTRACT_SCRIPT}" ]]; then
  record_requirement_status "mimicry_wire_contract" "ok" "machine-readable wire validation contract"
else
  record_requirement_status "mimicry_wire_contract" "missing" "machine-readable wire validation contract"
fi
if command -v cargo >/dev/null 2>&1; then
  record_requirement_status "cargo" "ok" "Rust evidence builder runtime"
else
  record_requirement_status "cargo" "missing" "Rust evidence builder runtime"
fi
if has_linux_capability_bit 13 "AEGIS_MIMICRY_WIRE_FORCE_CAP_NET_RAW"; then
  record_requirement_status "CAP_NET_RAW" "ok" "required for privileged raw IPv4 send"
else
  record_requirement_status "CAP_NET_RAW" "missing" "required for privileged raw IPv4 send"
fi
if has_linux_capability_bit 12 "AEGIS_MIMICRY_WIRE_FORCE_CAP_NET_ADMIN"; then
  record_requirement_status "CAP_NET_ADMIN" "ok" "required for TCP_REPAIR-backed wire contour"
else
  record_requirement_status "CAP_NET_ADMIN" "missing" "required for TCP_REPAIR-backed wire contour"
fi

if [[ "${MODE}" == "check" ]]; then
  if [[ "$(uname -s)" == "Linux" ]] \
    && [[ -f "${CONTRACT_SCRIPT}" ]] \
    && command -v cargo >/dev/null 2>&1 \
    && has_linux_capability_bit 13 "AEGIS_MIMICRY_WIRE_FORCE_CAP_NET_RAW" \
    && has_linux_capability_bit 12 "AEGIS_MIMICRY_WIRE_FORCE_CAP_NET_ADMIN"; then
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

if [[ "${MODE}" == "check" ]] && [[ "$(uname -s)" != "Linux" ]]; then
  fail_helper "unsupported_host_platform" 2
fi
[[ -f "${CONTRACT_SCRIPT}" ]] || fail_helper "contract_script_missing" 2
command -v cargo >/dev/null 2>&1 || fail_helper "cargo_missing" 2
[[ -n "${RUNTIME_EVENTS_JSONL}" ]] || fail_helper "runtime_events_required" 2
[[ -f "${RUNTIME_EVENTS_JSONL}" ]] || fail_helper "runtime_events_missing" 2
[[ -z "${WITNESS_SUMMARY_JSON}" || -f "${WITNESS_SUMMARY_JSON}" ]] || fail_helper "witness_summary_missing" 2
[[ -n "${ARTIFACT_DIR}" ]] || fail_helper "artifact_dir_required" 2

mkdir -p "${ARTIFACT_DIR}"

contract_tmp="$(mktemp "${TMPDIR:-/tmp}/aegis-mimicry-wire-contract.XXXXXX.json")"
trap 'rm -f "${contract_tmp}"' EXIT
bash "${CONTRACT_SCRIPT}" --output "${contract_tmp}"

capture_summary_json="${ARTIFACT_DIR}/capture-replay-summary.json"
host_summary_json="${ARTIFACT_DIR}/wire-host-acceptance-summary.json"

rust_args=(
  cargo run -q -p aegis-measure --
  build-mimicry-wire-host-acceptance
  --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}"
  --contract-json "${contract_tmp}"
  --capture-summary-json "${capture_summary_json}"
  --host-summary-json "${host_summary_json}"
)
if [[ -n "${WITNESS_SUMMARY_JSON}" ]]; then
  rust_args+=(--witness-summary-json "${WITNESS_SUMMARY_JSON}")
fi
"${rust_args[@]}"

READY=1
HELPER_EXIT_CODE=0
if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
  cat "${host_summary_json}"
else
  echo "capture_replay_summary_json=${capture_summary_json}"
  echo "wire_host_acceptance_summary_json=${host_summary_json}"
fi
