#!/usr/bin/env bash
set -euo pipefail

# Refuse deprecated private bytes before output paths, Cargo or parsing errors.
for argument in "$@"; do
  case "$argument" in
    --bundle-url|--bundle-url=*)
      echo "Inline bundle URLs are no longer accepted. Use --bundle-url-file or --bundle." >&2
      exit 2
      ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE_WAVE_BUNDLE_SCRIPT="${ROOT}/scripts/build-ubuntu-release-wave-bundle.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-ubuntu-field-pilot-remote-bundle.sh <output-dir> \
    --pilot-inputs <ubuntu-controlled-pilot-inputs.json> \
    [--relay-host <label>] \
    [--client-host <label>] \
    [--blocked-shape <label>] \
    [--bundle <archive-path> | --bundle-url-file <private-record-path>] \
    [--matrix-manifest <bundle.manifest.json>] \
    [--wire-witness-summary <path>] \
    [--wire-acceptance-summary <path>]

Builds one Ubuntu-only field-pilot bundle for the separate relay/client shape by
materializing:
  - the operator canary inside the pilot review bundle
  - the Ubuntu release wave bundle
  - one top-level field-pilot remote manifest
EOF
}

if [[ $# -lt 3 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

PILOT_INPUTS=""
RELAY_HOST_LABEL="ubuntu-relay-host"
CLIENT_HOST_LABEL="ubuntu-client-host"
BLOCKED_SHAPE_LABEL="hostile_or_blocked_network_shape"
BUNDLE_INPUT_ARGS=(--bundle /tmp/client-bundle.tar.gz)
BUNDLE_INPUT_SELECTED=0
MATRIX_MANIFEST=""
WIRE_WITNESS_SUMMARY=""
WIRE_ACCEPTANCE_SUMMARY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pilot-inputs)
      PILOT_INPUTS="$2"
      shift 2
      ;;
    --relay-host)
      RELAY_HOST_LABEL="$2"
      shift 2
      ;;
    --client-host)
      CLIENT_HOST_LABEL="$2"
      shift 2
      ;;
    --blocked-shape)
      BLOCKED_SHAPE_LABEL="$2"
      shift 2
      ;;
    --bundle|--bundle-url-file)
      if [[ $# -lt 2 || "${BUNDLE_INPUT_SELECTED}" != 0 ]]; then
        echo "Select one bundle input pathname." >&2
        exit 2
      fi
      BUNDLE_INPUT_ARGS=("$1" "$2")
      BUNDLE_INPUT_SELECTED=1
      shift 2
      ;;
    --matrix-manifest)
      MATRIX_MANIFEST="$2"
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

if [[ -z "${PILOT_INPUTS}" || ! -f "${PILOT_INPUTS}" ]]; then
  echo "Missing pilot inputs manifest: ${PILOT_INPUTS}" >&2
  exit 1
fi
for optional_path in "${MATRIX_MANIFEST}" "${WIRE_WITNESS_SUMMARY}" "${WIRE_ACCEPTANCE_SUMMARY}"; do
  if [[ -n "${optional_path}" && ! -f "${optional_path}" ]]; then
    echo "Missing optional input: ${optional_path}" >&2
    exit 1
  fi
done
if [[ ! -f "${RELEASE_WAVE_BUNDLE_SCRIPT}" ]]; then
  echo "Missing helper script: ${RELEASE_WAVE_BUNDLE_SCRIPT}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

RELEASE_WAVE_DIR="${OUTPUT_DIR}/release-wave"
release_wave_cmd=(
  bash "${RELEASE_WAVE_BUNDLE_SCRIPT}" "${RELEASE_WAVE_DIR}"
  --pilot-inputs "${PILOT_INPUTS}"
  --relay-host "${RELAY_HOST_LABEL}"
  --client-host "${CLIENT_HOST_LABEL}"
  --blocked-shape "${BLOCKED_SHAPE_LABEL}"
  "${BUNDLE_INPUT_ARGS[@]}"
)
if [[ -n "${MATRIX_MANIFEST}" ]]; then
  release_wave_cmd+=(--matrix-manifest "${MATRIX_MANIFEST}")
fi
if [[ -n "${WIRE_WITNESS_SUMMARY}" ]]; then
  release_wave_cmd+=(--wire-witness-summary "${WIRE_WITNESS_SUMMARY}")
fi
if [[ -n "${WIRE_ACCEPTANCE_SUMMARY}" ]]; then
  release_wave_cmd+=(--wire-acceptance-summary "${WIRE_ACCEPTANCE_SUMMARY}")
fi

"${release_wave_cmd[@]}" >/dev/null

cargo run -q -p aegis-measure -- build-ubuntu-field-pilot-remote-bundle-manifest \
  --output-dir "${OUTPUT_DIR}" \
  --pilot-inputs "${PILOT_INPUTS}" \
  --pilot-review-manifest "${RELEASE_WAVE_DIR}/pilot-review-bundle/pilot-review.manifest.json" \
  --release-wave-status "${RELEASE_WAVE_DIR}/ubuntu-release-wave-status.json" \
  --release-wave-manifest "${RELEASE_WAVE_DIR}/ubuntu-release-wave.manifest.json"

cat <<EOF
Ubuntu field pilot remote bundle created
---------------------------------------
Artifacts:
  ${RELEASE_WAVE_DIR}/pilot-review-bundle/pilot-review.manifest.json
  ${RELEASE_WAVE_DIR}/ubuntu-release-wave-status.json
  ${RELEASE_WAVE_DIR}/ubuntu-release-wave.manifest.json
  ${OUTPUT_DIR}/field-pilot-remote-bundle.json
  ${OUTPUT_DIR}/field-pilot-remote-bundle.md
EOF
