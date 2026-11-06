#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/ubuntu-release-wave-status.sh \
    --pilot-inputs <ubuntu-controlled-pilot-inputs.json> \
    --pilot-review-manifest <pilot-review.manifest.json> \
    --output <path>

This helper materializes the machine-readable handoff for the current Ubuntu
release wave using validation-generated pilot inputs and the latest pilot/review
bundle manifest.
EOF
}

PILOT_INPUTS=""
PILOT_REVIEW_MANIFEST=""
OUTPUT_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pilot-inputs)
      PILOT_INPUTS="$2"
      shift 2
      ;;
    --pilot-review-manifest)
      PILOT_REVIEW_MANIFEST="$2"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="$2"
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

if [[ -z "${PILOT_INPUTS}" || -z "${PILOT_REVIEW_MANIFEST}" || -z "${OUTPUT_PATH}" ]]; then
  usage >&2
  exit 1
fi
if [[ ! -f "${PILOT_INPUTS}" ]]; then
  echo "Missing pilot inputs manifest: ${PILOT_INPUTS}" >&2
  exit 1
fi
if [[ ! -f "${PILOT_REVIEW_MANIFEST}" ]]; then
  echo "Missing pilot review manifest: ${PILOT_REVIEW_MANIFEST}" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUTPUT_PATH}")"

cargo run -q -p aegis-measure -- build-ubuntu-release-wave-status \
  --pilot-inputs "${PILOT_INPUTS}" \
  --pilot-review-manifest "${PILOT_REVIEW_MANIFEST}" \
  --output "${OUTPUT_PATH}"
