#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POLYMORPHISM_SCRIPT="${ROOT}/scripts/build-stealth-polymorphism-acceptance-summary.sh"
HOSTILE_PATH_SCRIPT="${ROOT}/scripts/build-stealth-hostile-path-acceptance-summary.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-stealth-live-acceptance-bundle.sh <output-dir> \
    --wire-acceptance-summary <wire-host-acceptance-summary.json> \
    --runtime-events <runtime-events.jsonl> \
    [--relay-runtime-events <runtime-events.jsonl>] \
    [--config <config.example.toml>] \
    [--now-secs <unix-seconds>]

Builds one top-level post-release stealth acceptance bundle by materializing:
  - repo-side polymorphism acceptance summary
  - live relay runtime surface summary
  - combined stealth hostile-path acceptance summary
EOF
}

if [[ $# -lt 5 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

WIRE_ACCEPTANCE_SUMMARY=""
RUNTIME_EVENTS_JSONL=""
RELAY_RUNTIME_EVENTS_JSONL=""
CONFIG_PATH="${ROOT}/config.example.toml"
NOW_SECS="10000"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wire-acceptance-summary)
      WIRE_ACCEPTANCE_SUMMARY="$2"
      shift 2
      ;;
    --runtime-events)
      RUNTIME_EVENTS_JSONL="$2"
      shift 2
      ;;
    --relay-runtime-events)
      RELAY_RUNTIME_EVENTS_JSONL="$2"
      shift 2
      ;;
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --now-secs)
      NOW_SECS="$2"
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

for required_path in "${WIRE_ACCEPTANCE_SUMMARY}" "${RUNTIME_EVENTS_JSONL}" "${CONFIG_PATH}"; do
  if [[ -z "${required_path}" || ! -f "${required_path}" ]]; then
    echo "Missing required input: ${required_path}" >&2
    exit 1
  fi
done

if [[ -z "${RELAY_RUNTIME_EVENTS_JSONL}" ]]; then
  RELAY_RUNTIME_EVENTS_JSONL="${RUNTIME_EVENTS_JSONL}"
fi

if [[ ! -f "${RELAY_RUNTIME_EVENTS_JSONL}" ]]; then
  echo "Missing relay runtime events input: ${RELAY_RUNTIME_EVENTS_JSONL}" >&2
  exit 1
fi

for helper_script in "${POLYMORPHISM_SCRIPT}" "${HOSTILE_PATH_SCRIPT}"; do
  if [[ ! -f "${helper_script}" ]]; then
    echo "Missing helper script: ${helper_script}" >&2
    exit 1
  fi
done

mkdir -p "${OUTPUT_DIR}"

POLYMORPHISM_DIR="${OUTPUT_DIR}/polymorphism-acceptance"
HOSTILE_PATH_DIR="${OUTPUT_DIR}/hostile-path-acceptance"

bash "${POLYMORPHISM_SCRIPT}" "${POLYMORPHISM_DIR}" \
  --config "${CONFIG_PATH}" \
  --now-secs "${NOW_SECS}" >/dev/null

bash "${HOSTILE_PATH_SCRIPT}" "${HOSTILE_PATH_DIR}" \
  --wire-acceptance-summary "${WIRE_ACCEPTANCE_SUMMARY}" \
  --polymorphism-acceptance-summary "${POLYMORPHISM_DIR}/stealth-polymorphism-acceptance-summary.json" \
  --runtime-events "${RELAY_RUNTIME_EVENTS_JSONL}" >/dev/null

cargo run -q -p aegis-measure -- build-stealth-live-acceptance-bundle \
  --output-dir "${OUTPUT_DIR}" \
  --wire-acceptance-summary "${WIRE_ACCEPTANCE_SUMMARY}" \
  --runtime-events "${RUNTIME_EVENTS_JSONL}" \
  --relay-runtime-events "${RELAY_RUNTIME_EVENTS_JSONL}" \
  --config "${CONFIG_PATH}" \
  --polymorphism-summary "${POLYMORPHISM_DIR}/stealth-polymorphism-acceptance-summary.json" \
  --relay-surface-runtime-summary "${HOSTILE_PATH_DIR}/relay-surface-runtime/relay-surface-runtime-summary.json" \
  --hostile-path-summary "${HOSTILE_PATH_DIR}/stealth-hostile-path-acceptance-summary.json"

cat <<EOF
Stealth live acceptance bundle created
-------------------------------------
Artifacts:
  ${POLYMORPHISM_DIR}/stealth-polymorphism-acceptance-summary.json
  ${HOSTILE_PATH_DIR}/relay-surface-runtime/relay-surface-runtime-summary.json
  ${HOSTILE_PATH_DIR}/stealth-hostile-path-acceptance-summary.json
  ${OUTPUT_DIR}/stealth-live-acceptance-bundle.json
  ${OUTPUT_DIR}/stealth-live-acceptance.manifest.json
  ${OUTPUT_DIR}/stealth-live-acceptance-bundle.md
EOF
