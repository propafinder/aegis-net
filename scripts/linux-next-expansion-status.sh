#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/linux-next-expansion-status.sh \
    --matrix-manifest <bundle.manifest.json> \
    --output <path> \
    [--review-json <next-expansion-review.json>]

This helper materializes the machine-readable handoff for the current
non-Ubuntu Linux evidence expansion wave using the latest matrix bundle and an
optional latest review artifact.
EOF
}

MATRIX_MANIFEST=""
OUTPUT_PATH=""
REVIEW_JSON=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix-manifest)
      MATRIX_MANIFEST="$2"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --review-json)
      REVIEW_JSON="$2"
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

if [[ -z "${MATRIX_MANIFEST}" || -z "${OUTPUT_PATH}" ]]; then
  usage >&2
  exit 1
fi
if [[ ! -f "${MATRIX_MANIFEST}" ]]; then
  echo "Missing matrix manifest: ${MATRIX_MANIFEST}" >&2
  exit 1
fi
if [[ -n "${REVIEW_JSON}" && ! -f "${REVIEW_JSON}" ]]; then
  echo "Missing review JSON: ${REVIEW_JSON}" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUTPUT_PATH}")"

cmd=(
  cargo run -q -p aegis-measure -- build-linux-next-expansion-status
  --matrix-manifest "${MATRIX_MANIFEST}"
  --output "${OUTPUT_PATH}"
)
if [[ -n "${REVIEW_JSON}" ]]; then
  cmd+=(--review-json "${REVIEW_JSON}")
fi
"${cmd[@]}"
