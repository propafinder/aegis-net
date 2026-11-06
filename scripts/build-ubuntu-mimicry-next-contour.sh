#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WIRE_CONTRACT_SCRIPT="${ROOT}/scripts/mimicry-wire-validation-contract.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-ubuntu-mimicry-next-contour.sh <output-dir> \
    [--stealth-summary <stealth-wave-summary.json>]

Builds one machine-readable and human-readable handoff for the next Ubuntu-only
wire-level mimicry implementation contour after the post-release stealth wave.
EOF
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

STEALTH_SUMMARY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stealth-summary)
      STEALTH_SUMMARY="$2"
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

if [[ -n "${STEALTH_SUMMARY}" && ! -f "${STEALTH_SUMMARY}" ]]; then
  echo "Missing stealth summary: ${STEALTH_SUMMARY}" >&2
  exit 1
fi
if [[ ! -f "${WIRE_CONTRACT_SCRIPT}" ]]; then
  echo "Missing helper script: ${WIRE_CONTRACT_SCRIPT}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

CONTRACT_JSON="${OUTPUT_DIR}/wire-validation-contract.json"
bash "${WIRE_CONTRACT_SCRIPT}" --output "${CONTRACT_JSON}" >/dev/null

CMD=(
  cargo run -q -p aegis-measure --
  build-ubuntu-mimicry-next-contour
  --output-dir "${OUTPUT_DIR}"
  --wire-contract "${CONTRACT_JSON}"
)
if [[ -n "${STEALTH_SUMMARY}" ]]; then
  CMD+=(--stealth-summary "${STEALTH_SUMMARY}")
fi
"${CMD[@]}"

cat <<EOF
Ubuntu mimicry next contour created
----------------------------------
Artifacts:
  ${OUTPUT_DIR}/wire-validation-contract.json
  ${OUTPUT_DIR}/ubuntu-mimicry-next-contour.json
  ${OUTPUT_DIR}/ubuntu-mimicry-next-contour.md
EOF
