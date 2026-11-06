#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/build-post-release-stealth-wave-summary.sh <output-dir> \
    [--ubuntu-release-wave-status <ubuntu-release-wave-status.json>] \
    [--wire-acceptance-summary <wire-host-acceptance-summary.json>]

Builds one machine-readable summary for the post-release stealth / mimicry /
anti-DPI wave, intentionally separated from the Ubuntu ship-ready gate.
EOF
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift
UBUNTU_RELEASE_WAVE_STATUS=""
WIRE_ACCEPTANCE_SUMMARY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ubuntu-release-wave-status)
      UBUNTU_RELEASE_WAVE_STATUS="$2"
      shift 2
      ;;
    --wire-acceptance-summary)
      WIRE_ACCEPTANCE_SUMMARY="$2"
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

for optional_path in "${UBUNTU_RELEASE_WAVE_STATUS}" "${WIRE_ACCEPTANCE_SUMMARY}"; do
  if [[ -n "${optional_path}" && ! -f "${optional_path}" ]]; then
    echo "Missing optional input: ${optional_path}" >&2
    exit 1
  fi
done

mkdir -p "${OUTPUT_DIR}"

cmd=(
  cargo run -q -p aegis-measure -- build-post-release-stealth-wave-summary
  --output-dir "${OUTPUT_DIR}"
)
if [[ -n "${UBUNTU_RELEASE_WAVE_STATUS}" ]]; then
  cmd+=(--ubuntu-release-wave-status "${UBUNTU_RELEASE_WAVE_STATUS}")
fi
if [[ -n "${WIRE_ACCEPTANCE_SUMMARY}" ]]; then
  cmd+=(--wire-acceptance-summary "${WIRE_ACCEPTANCE_SUMMARY}")
fi
"${cmd[@]}"

cat <<EOF
Post-release stealth wave summary created
----------------------------------------
Artifacts:
  ${OUTPUT_DIR}/stealth-wave-summary.json
  ${OUTPUT_DIR}/stealth-wave-summary.md
EOF
