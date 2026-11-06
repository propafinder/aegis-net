#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLAYBOOK_SCRIPT="${ROOT}/scripts/build-linux-next-expansion-playbook.sh"
REVIEW_BUNDLE_SCRIPT="${ROOT}/scripts/build-linux-next-expansion-review-bundle.sh"
STATUS_SCRIPT="${ROOT}/scripts/linux-next-expansion-status.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-linux-next-expansion-wave-bundle.sh <output-dir> \
    --matrix-manifest <bundle.manifest.json> \
    [--target-evidence <host-validation.json>] \
    [--target-family <host-family-id>] \
    [--host-label <label>]

Builds one top-level bundle for the current non-Ubuntu Linux evidence wave.

Without --target-evidence:
  - materializes the next-expansion playbook
  - materializes the current next-expansion status

With --target-evidence:
  - materializes the next-expansion review bundle
  - materializes the refreshed next-expansion status
EOF
}

if [[ $# -lt 3 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

MATRIX_MANIFEST=""
TARGET_EVIDENCE=""
TARGET_FAMILY=""
HOST_LABEL="next-linux-validation-host"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix-manifest)
      MATRIX_MANIFEST="$2"
      shift 2
      ;;
    --target-evidence)
      TARGET_EVIDENCE="$2"
      shift 2
      ;;
    --target-family)
      TARGET_FAMILY="$2"
      shift 2
      ;;
    --host-label)
      HOST_LABEL="$2"
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

if [[ -z "${MATRIX_MANIFEST}" || ! -f "${MATRIX_MANIFEST}" ]]; then
  echo "Missing matrix manifest: ${MATRIX_MANIFEST}" >&2
  exit 1
fi
if [[ -n "${TARGET_EVIDENCE}" && ! -f "${TARGET_EVIDENCE}" ]]; then
  echo "Missing target evidence: ${TARGET_EVIDENCE}" >&2
  exit 1
fi

for helper_script in "${PLAYBOOK_SCRIPT}" "${REVIEW_BUNDLE_SCRIPT}" "${STATUS_SCRIPT}"; do
  if [[ ! -f "${helper_script}" ]]; then
    echo "Missing helper script: ${helper_script}" >&2
    exit 1
  fi
done

mkdir -p "${OUTPUT_DIR}"

PLAYBOOK_DIR="${OUTPUT_DIR}/next-expansion-playbook"
STATUS_JSON="${OUTPUT_DIR}/next-expansion-status.json"

if [[ -z "${TARGET_EVIDENCE}" ]]; then
  playbook_cmd=(
    bash "${PLAYBOOK_SCRIPT}" "${PLAYBOOK_DIR}"
    --matrix-manifest "${MATRIX_MANIFEST}"
    --host-label "${HOST_LABEL}"
  )
  if [[ -n "${TARGET_FAMILY}" ]]; then
    playbook_cmd+=(--target-family "${TARGET_FAMILY}")
  fi

  "${playbook_cmd[@]}" >/dev/null
  bash "${STATUS_SCRIPT}" \
    --matrix-manifest "${MATRIX_MANIFEST}" \
    --output "${STATUS_JSON}"

  cargo run -q -p aegis-measure -- \
    build-linux-next-expansion-wave-manifest \
    --output "${OUTPUT_DIR}/next-expansion-wave.manifest.json" \
    --mode plan_only \
    --source-json "${PLAYBOOK_DIR}/next-expansion-playbook.json" \
    --status-json "${STATUS_JSON}"
else
  REVIEW_DIR="${OUTPUT_DIR}/next-expansion-review-bundle"
  review_cmd=(
    bash "${REVIEW_BUNDLE_SCRIPT}" "${REVIEW_DIR}"
    --matrix-manifest "${MATRIX_MANIFEST}"
    --target-evidence "${TARGET_EVIDENCE}"
    --host-label "${HOST_LABEL}"
  )
  if [[ -n "${TARGET_FAMILY}" ]]; then
    review_cmd+=(--target-family "${TARGET_FAMILY}")
  fi

  "${review_cmd[@]}" >/dev/null
  bash "${STATUS_SCRIPT}" \
    --matrix-manifest "${REVIEW_DIR}/refreshed-matrix/bundle.manifest.json" \
    --review-json "${REVIEW_DIR}/next-expansion-review.json" \
    --output "${STATUS_JSON}"

  cargo run -q -p aegis-measure -- \
    build-linux-next-expansion-wave-manifest \
    --output "${OUTPUT_DIR}/next-expansion-wave.manifest.json" \
    --mode review_with_evidence \
    --source-json "${REVIEW_DIR}/next-expansion-review.manifest.json" \
    --status-json "${STATUS_JSON}"
fi

cat <<EOF
Linux next expansion wave bundle created
---------------------------------------
Artifacts:
  ${STATUS_JSON}
  ${OUTPUT_DIR}/next-expansion-wave.manifest.json
EOF
