#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/build-relay-surface-runtime-summary.sh <output-dir> \
    --runtime-events <runtime-events.jsonl>

Build one machine-readable and human-readable summary for live relay runtime
request-shape evidence. The helper scans relay runtime JSONL and verifies that
relay lifecycle events publish the expected `relay_surface_*` fields.
EOF
}

if [[ $# -lt 3 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

RUNTIME_EVENTS_JSONL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
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

if [[ -z "${RUNTIME_EVENTS_JSONL}" || ! -f "${RUNTIME_EVENTS_JSONL}" ]]; then
  echo "Missing runtime events JSONL: ${RUNTIME_EVENTS_JSONL}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

cargo run -q -p aegis-measure -- build-relay-surface-runtime-summary \
  --output-dir "${OUTPUT_DIR}" \
  --runtime-events "${RUNTIME_EVENTS_JSONL}"

cat <<EOF
Relay surface runtime summary created
------------------------------------
Artifacts:
  ${OUTPUT_DIR}/relay-surface-runtime-summary.json
  ${OUTPUT_DIR}/relay-surface-runtime-summary.md
EOF
