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
PILOT_REVIEW_BUNDLE_SCRIPT="${ROOT}/scripts/build-ubuntu-controlled-pilot-review-bundle.sh"
STATUS_SCRIPT="${ROOT}/scripts/ubuntu-release-wave-status.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-ubuntu-release-wave-bundle.sh <output-dir> \
    --pilot-inputs <ubuntu-controlled-pilot-inputs.json> \
    [--relay-host <label>] \
    [--client-host <label>] \
    [--blocked-shape <label>] \
    [--bundle <archive-path> | --bundle-url-file <private-record-path>] \
    [--matrix-manifest <bundle.manifest.json>] \
    [--wire-witness-summary <path>] \
    [--wire-acceptance-summary <path>]

Builds one top-level Ubuntu release/pilot wave bundle by materializing:
  - the pilot/review bundle
  - the top-level Ubuntu release wave status
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
for helper_script in "${PILOT_REVIEW_BUNDLE_SCRIPT}" "${STATUS_SCRIPT}"; do
  if [[ ! -f "${helper_script}" ]]; then
    echo "Missing helper script: ${helper_script}" >&2
    exit 1
  fi
done

mkdir -p "${OUTPUT_DIR}"

PILOT_REVIEW_DIR="${OUTPUT_DIR}/pilot-review-bundle"

pilot_review_cmd=(
  bash "${PILOT_REVIEW_BUNDLE_SCRIPT}" "${PILOT_REVIEW_DIR}"
  --pilot-inputs "${PILOT_INPUTS}"
  --relay-host "${RELAY_HOST_LABEL}"
  --client-host "${CLIENT_HOST_LABEL}"
  --blocked-shape "${BLOCKED_SHAPE_LABEL}"
  "${BUNDLE_INPUT_ARGS[@]}"
)
if [[ -n "${MATRIX_MANIFEST}" ]]; then
  pilot_review_cmd+=(--matrix-manifest "${MATRIX_MANIFEST}")
fi
if [[ -n "${WIRE_WITNESS_SUMMARY}" ]]; then
  pilot_review_cmd+=(--wire-witness-summary "${WIRE_WITNESS_SUMMARY}")
fi
if [[ -n "${WIRE_ACCEPTANCE_SUMMARY}" ]]; then
  pilot_review_cmd+=(--wire-acceptance-summary "${WIRE_ACCEPTANCE_SUMMARY}")
fi

"${pilot_review_cmd[@]}" >/dev/null
bash "${STATUS_SCRIPT}" \
  --pilot-inputs "${PILOT_INPUTS}" \
  --pilot-review-manifest "${PILOT_REVIEW_DIR}/pilot-review.manifest.json" \
  --output "${OUTPUT_DIR}/ubuntu-release-wave-status.json"

cargo run -q -p aegis-measure -- build-ubuntu-release-wave-bundle-manifest \
  --output-dir "${OUTPUT_DIR}" \
  --pilot-review-manifest "${PILOT_REVIEW_DIR}/pilot-review.manifest.json" \
  --wave-status "${OUTPUT_DIR}/ubuntu-release-wave-status.json"

cat <<EOF
Ubuntu release wave bundle created
---------------------------------
Artifacts:
  ${PILOT_REVIEW_DIR}/pilot-review.manifest.json
  ${OUTPUT_DIR}/ubuntu-release-wave-status.json
  ${OUTPUT_DIR}/ubuntu-release-wave.manifest.json
EOF
