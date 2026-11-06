#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/build-ubuntu-controlled-pilot-bundle.sh <output-dir> --pilot-inputs <ubuntu-controlled-pilot-inputs.json> \
    [--blocked-shape <label>] \
    [--wire-witness-summary <path>] \
    [--wire-acceptance-summary <path>] \
    [--server-host <label>] \
    [--client-host <label>]

  or

  scripts/build-ubuntu-controlled-pilot-bundle.sh <output-dir> \
    --server-systemctl-status <path> \
    --server-journal <path> \
    --client-preflight <path> \
    --client-startup-probe <path> \
    --client-runtime-events-summary <path> \
    --client-operator-evidence <path> \
    [--release-handoff <path>] \
    [--blocked-shape <label>] \
    [--wire-witness-summary <path>] \
    [--wire-acceptance-summary <path>] \
    [--server-host <label>] \
    [--client-host <label>]

Builds one machine-readable Ubuntu controlled-pilot evidence bundle from
already collected server/client artifacts.
EOF
}

if [[ $# -lt 13 ]]; then
  if [[ $# -lt 3 ]]; then
    usage >&2
    exit 1
  fi
fi

OUTPUT_DIR="$1"
shift

PILOT_INPUTS=""
SERVER_STATUS=""
SERVER_JOURNAL=""
CLIENT_PREFLIGHT=""
CLIENT_STARTUP_PROBE=""
CLIENT_RUNTIME_EVENTS_SUMMARY=""
CLIENT_OPERATOR_EVIDENCE=""
VALIDATION_SUMMARY=""
RELEASE_SUMMARY=""
OPERATOR_LOOP_SUMMARY=""
RELEASE_HANDOFF=""
WIRE_WITNESS_SUMMARY=""
WIRE_ACCEPTANCE_SUMMARY=""
SERVER_HOST_LABEL="ubuntu-relay-host"
CLIENT_HOST_LABEL="ubuntu-client-host"
BLOCKED_SHAPE_LABEL="hostile_or_blocked_network_shape"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pilot-inputs)
      PILOT_INPUTS="$2"
      shift 2
      ;;
    --server-systemctl-status)
      SERVER_STATUS="$2"
      shift 2
      ;;
    --server-journal)
      SERVER_JOURNAL="$2"
      shift 2
      ;;
    --client-preflight)
      CLIENT_PREFLIGHT="$2"
      shift 2
      ;;
    --client-startup-probe)
      CLIENT_STARTUP_PROBE="$2"
      shift 2
      ;;
    --client-runtime-events-summary)
      CLIENT_RUNTIME_EVENTS_SUMMARY="$2"
      shift 2
      ;;
    --client-operator-evidence)
      CLIENT_OPERATOR_EVIDENCE="$2"
      shift 2
      ;;
    --validation-summary)
      VALIDATION_SUMMARY="$2"
      shift 2
      ;;
    --release-summary)
      RELEASE_SUMMARY="$2"
      shift 2
      ;;
    --operator-loop-summary)
      OPERATOR_LOOP_SUMMARY="$2"
      shift 2
      ;;
    --release-handoff)
      RELEASE_HANDOFF="$2"
      shift 2
      ;;
    --wire-witness-summary)
      WIRE_WITNESS_SUMMARY="$2"
      shift 2
      ;;
    --wire-acceptance-summary)
      WIRE_ACCEPTANCE_SUMMARY="$2"
      shift 2
      ;;
    --blocked-shape)
      BLOCKED_SHAPE_LABEL="$2"
      shift 2
      ;;
    --server-host)
      SERVER_HOST_LABEL="$2"
      shift 2
      ;;
    --client-host)
      CLIENT_HOST_LABEL="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -n "${PILOT_INPUTS}" ]]; then
  if [[ ! -f "${PILOT_INPUTS}" ]]; then
    echo "Missing pilot inputs manifest: ${PILOT_INPUTS}" >&2
    exit 1
  fi
  PILOT_FIELDS=()
  while IFS= read -r item; do
    PILOT_FIELDS+=("${item}")
  done < <(cargo run -q -p aegis-measure -- ubuntu-controlled-pilot-input-fields --pilot-inputs "${PILOT_INPUTS}")
  [[ -n "${VALIDATION_SUMMARY}" ]] || VALIDATION_SUMMARY="${PILOT_FIELDS[0]}"
  [[ -n "${RELEASE_SUMMARY}" ]] || RELEASE_SUMMARY="${PILOT_FIELDS[1]}"
  [[ -n "${OPERATOR_LOOP_SUMMARY}" ]] || OPERATOR_LOOP_SUMMARY="${PILOT_FIELDS[2]}"
  [[ -n "${RELEASE_HANDOFF}" ]] || RELEASE_HANDOFF="${PILOT_FIELDS[3]}"
  [[ -n "${SERVER_STATUS}" ]] || SERVER_STATUS="${PILOT_FIELDS[4]}"
  [[ -n "${SERVER_JOURNAL}" ]] || SERVER_JOURNAL="${PILOT_FIELDS[5]}"
  [[ -n "${CLIENT_PREFLIGHT}" ]] || CLIENT_PREFLIGHT="${PILOT_FIELDS[6]}"
  [[ -n "${CLIENT_STARTUP_PROBE}" ]] || CLIENT_STARTUP_PROBE="${PILOT_FIELDS[7]}"
  [[ -n "${CLIENT_RUNTIME_EVENTS_SUMMARY}" ]] || CLIENT_RUNTIME_EVENTS_SUMMARY="${PILOT_FIELDS[8]}"
  [[ -n "${CLIENT_OPERATOR_EVIDENCE}" ]] || CLIENT_OPERATOR_EVIDENCE="${PILOT_FIELDS[9]}"
fi

for path_var in \
  SERVER_STATUS \
  SERVER_JOURNAL \
  CLIENT_PREFLIGHT \
  CLIENT_STARTUP_PROBE \
  CLIENT_RUNTIME_EVENTS_SUMMARY \
  CLIENT_OPERATOR_EVIDENCE
do
  path_value="${!path_var}"
  if [[ -z "${path_value}" || ! -f "${path_value}" ]]; then
    echo "Missing required artifact: ${path_var}" >&2
    exit 1
  fi
done
for optional_path in "${WIRE_WITNESS_SUMMARY}" "${WIRE_ACCEPTANCE_SUMMARY}"; do
  if [[ -n "${optional_path}" && ! -f "${optional_path}" ]]; then
    echo "Missing optional input: ${optional_path}" >&2
    exit 1
  fi
done

mkdir -p "${OUTPUT_DIR}"

CMD=(
  cargo run -q -p aegis-measure -- build-ubuntu-controlled-pilot-bundle
  --output-dir "${OUTPUT_DIR}"
  --server-status "${SERVER_STATUS}"
  --server-journal "${SERVER_JOURNAL}"
  --client-preflight "${CLIENT_PREFLIGHT}"
  --client-startup-probe "${CLIENT_STARTUP_PROBE}"
  --client-runtime-events-summary "${CLIENT_RUNTIME_EVENTS_SUMMARY}"
  --client-operator-evidence "${CLIENT_OPERATOR_EVIDENCE}"
  --server-host "${SERVER_HOST_LABEL}"
  --client-host "${CLIENT_HOST_LABEL}"
  --blocked-shape "${BLOCKED_SHAPE_LABEL}"
)
[[ -n "${VALIDATION_SUMMARY}" ]] && CMD+=(--validation-summary "${VALIDATION_SUMMARY}")
[[ -n "${RELEASE_SUMMARY}" ]] && CMD+=(--release-summary "${RELEASE_SUMMARY}")
[[ -n "${OPERATOR_LOOP_SUMMARY}" ]] && CMD+=(--operator-loop-summary "${OPERATOR_LOOP_SUMMARY}")
[[ -n "${RELEASE_HANDOFF}" ]] && CMD+=(--release-handoff "${RELEASE_HANDOFF}")
[[ -n "${PILOT_INPUTS}" ]] && CMD+=(--pilot-inputs "${PILOT_INPUTS}")
[[ -n "${WIRE_WITNESS_SUMMARY}" ]] && CMD+=(--wire-witness-summary "${WIRE_WITNESS_SUMMARY}")
[[ -n "${WIRE_ACCEPTANCE_SUMMARY}" ]] && CMD+=(--wire-acceptance-summary "${WIRE_ACCEPTANCE_SUMMARY}")
"${CMD[@]}"

cat <<EOF
Ubuntu controlled pilot bundle created
------------------------------------
Artifacts:
  ${OUTPUT_DIR}/pilot-summary.json
  ${OUTPUT_DIR}/pilot-summary.md
  ${OUTPUT_DIR}/bundle.manifest.json
EOF
