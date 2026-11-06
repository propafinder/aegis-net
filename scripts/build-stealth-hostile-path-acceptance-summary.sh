#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELAY_SURFACE_RUNTIME_SCRIPT="${ROOT}/scripts/build-relay-surface-runtime-summary.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-stealth-hostile-path-acceptance-summary.sh <output-dir> \
    --wire-acceptance-summary <wire-host-acceptance-summary.json> \
    --polymorphism-acceptance-summary <stealth-polymorphism-acceptance-summary.json> \
    [--relay-surface-runtime-summary <relay-surface-runtime-summary.json>] \
    [--runtime-events <runtime-events.jsonl>]

Build one machine-readable and human-readable acceptance summary that combines:
- live hostile-path / witness-correlated wire acceptance
- repo-side stealth polymorphism acceptance

The helper does not rerun validation. It materializes one explicit stealth-wave
acceptance verdict so the live wire proof and repo-side polymorphism proof do
not need to be read separately.
EOF
}

if [[ $# -lt 5 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

WIRE_ACCEPTANCE_SUMMARY=""
POLYMORPHISM_ACCEPTANCE_SUMMARY=""
RELAY_SURFACE_RUNTIME_SUMMARY=""
RUNTIME_EVENTS_JSONL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wire-acceptance-summary)
      WIRE_ACCEPTANCE_SUMMARY="$2"
      shift 2
      ;;
    --polymorphism-acceptance-summary)
      POLYMORPHISM_ACCEPTANCE_SUMMARY="$2"
      shift 2
      ;;
    --relay-surface-runtime-summary)
      RELAY_SURFACE_RUNTIME_SUMMARY="$2"
      shift 2
      ;;
    --runtime-events)
      RUNTIME_EVENTS_JSONL="$2"
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

for required_path in "${WIRE_ACCEPTANCE_SUMMARY}" "${POLYMORPHISM_ACCEPTANCE_SUMMARY}"; do
  if [[ -z "${required_path}" || ! -f "${required_path}" ]]; then
    echo "Missing required input: ${required_path}" >&2
    exit 1
  fi
done

if [[ -n "${RELAY_SURFACE_RUNTIME_SUMMARY}" && ! -f "${RELAY_SURFACE_RUNTIME_SUMMARY}" ]]; then
  echo "Missing optional input: ${RELAY_SURFACE_RUNTIME_SUMMARY}" >&2
  exit 1
fi

if [[ -n "${RUNTIME_EVENTS_JSONL}" && ! -f "${RUNTIME_EVENTS_JSONL}" ]]; then
  echo "Missing optional input: ${RUNTIME_EVENTS_JSONL}" >&2
  exit 1
fi

if [[ -n "${RELAY_SURFACE_RUNTIME_SUMMARY}" && -n "${RUNTIME_EVENTS_JSONL}" ]]; then
  echo "Pass either --relay-surface-runtime-summary or --runtime-events, not both" >&2
  exit 1
fi

if [[ -n "${RUNTIME_EVENTS_JSONL}" ]]; then
  if [[ ! -f "${RELAY_SURFACE_RUNTIME_SCRIPT}" ]]; then
    echo "Missing helper script: ${RELAY_SURFACE_RUNTIME_SCRIPT}" >&2
    exit 1
  fi
fi

mkdir -p "${OUTPUT_DIR}"

if [[ -n "${RUNTIME_EVENTS_JSONL}" ]]; then
  AUTO_RELAY_SURFACE_DIR="${OUTPUT_DIR}/relay-surface-runtime"
  bash "${RELAY_SURFACE_RUNTIME_SCRIPT}" "${AUTO_RELAY_SURFACE_DIR}" \
    --runtime-events "${RUNTIME_EVENTS_JSONL}" >/dev/null
  RELAY_SURFACE_RUNTIME_SUMMARY="${AUTO_RELAY_SURFACE_DIR}/relay-surface-runtime-summary.json"
fi

cmd=(
  cargo run -q -p aegis-measure -- build-stealth-hostile-path-acceptance-summary
  --output-dir "${OUTPUT_DIR}"
  --wire-acceptance-summary "${WIRE_ACCEPTANCE_SUMMARY}"
  --polymorphism-acceptance-summary "${POLYMORPHISM_ACCEPTANCE_SUMMARY}"
)
if [[ -n "${RELAY_SURFACE_RUNTIME_SUMMARY}" ]]; then
  cmd+=(--relay-surface-runtime-summary "${RELAY_SURFACE_RUNTIME_SUMMARY}")
fi
"${cmd[@]}"

cat <<EOF
Stealth hostile-path acceptance summary created
----------------------------------------------
Artifacts:
  ${OUTPUT_DIR}/stealth-hostile-path-acceptance-summary.json
  ${OUTPUT_DIR}/stealth-hostile-path-acceptance-summary.md
EOF
