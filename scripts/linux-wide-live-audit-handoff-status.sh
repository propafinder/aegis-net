#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/linux-wide-live-audit-handoff-status.sh \
    --manifest <live-audit.manifest.json> \
    --output <path>

This helper materializes a compact machine-readable post-run handoff status from
the canonical `operator_handoff` object inside a Linux wide mimicry live-audit
manifest.
EOF
}

MANIFEST_PATH=""
OUTPUT_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST_PATH="$2"
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

if [[ -z "${MANIFEST_PATH}" || -z "${OUTPUT_PATH}" ]]; then
  usage >&2
  exit 1
fi
if [[ ! -f "${MANIFEST_PATH}" ]]; then
  echo "Missing live-audit manifest: ${MANIFEST_PATH}" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUTPUT_PATH}")"

cargo run -q -p aegis-measure -- build-linux-wide-live-audit-handoff-status \
  --manifest "${MANIFEST_PATH}" \
  --output "${OUTPUT_PATH}"
