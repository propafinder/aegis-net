#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/build-linux-release-program-bundle.sh <output-dir> \
    --ubuntu-wave-manifest <ubuntu-release-wave.manifest.json> \
    [--next-expansion-status <linux-next-expansion-status.json>] \
    [--stealth-summary <stealth-wave-summary.json>] \
    [--mimicry-next-contour <ubuntu-mimicry-next-contour.json>]

Builds one top-level Linux release-program bundle that summarizes:
  - the primary Ubuntu release wave
  - the current next-family evidence wave
  - the post-release stealth planning track
EOF
}

if [[ $# -lt 3 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

UBUNTU_WAVE_MANIFEST=""
NEXT_EXPANSION_STATUS=""
STEALTH_SUMMARY=""
MIMICRY_NEXT_CONTOUR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ubuntu-wave-manifest)
      UBUNTU_WAVE_MANIFEST="$2"
      shift 2
      ;;
    --next-expansion-status)
      NEXT_EXPANSION_STATUS="$2"
      shift 2
      ;;
    --stealth-summary)
      STEALTH_SUMMARY="$2"
      shift 2
      ;;
    --mimicry-next-contour)
      MIMICRY_NEXT_CONTOUR="$2"
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

if [[ -z "${UBUNTU_WAVE_MANIFEST}" || ! -f "${UBUNTU_WAVE_MANIFEST}" ]]; then
  echo "Missing Ubuntu wave manifest: ${UBUNTU_WAVE_MANIFEST}" >&2
  exit 1
fi
for optional_path in "${NEXT_EXPANSION_STATUS}" "${STEALTH_SUMMARY}" "${MIMICRY_NEXT_CONTOUR}"; do
  if [[ -n "${optional_path}" && ! -f "${optional_path}" ]]; then
    echo "Missing optional input: ${optional_path}" >&2
    exit 1
  fi
done

mkdir -p "${OUTPUT_DIR}"

CMD=(
  cargo run -q -p aegis-measure --
  build-linux-release-program-bundle
  --output-dir "${OUTPUT_DIR}"
  --ubuntu-wave-manifest "${UBUNTU_WAVE_MANIFEST}"
)
if [[ -n "${NEXT_EXPANSION_STATUS}" ]]; then
  CMD+=(--next-expansion-status "${NEXT_EXPANSION_STATUS}")
fi
if [[ -n "${STEALTH_SUMMARY}" ]]; then
  CMD+=(--stealth-summary "${STEALTH_SUMMARY}")
fi
if [[ -n "${MIMICRY_NEXT_CONTOUR}" ]]; then
  CMD+=(--mimicry-next-contour "${MIMICRY_NEXT_CONTOUR}")
fi
"${CMD[@]}"

cat <<EOF
Linux release program bundle created
-----------------------------------
Artifacts:
  ${OUTPUT_DIR}/linux-release-program-status.json
  ${OUTPUT_DIR}/linux-release-program.manifest.json
  ${OUTPUT_DIR}/linux-release-program.md
EOF
