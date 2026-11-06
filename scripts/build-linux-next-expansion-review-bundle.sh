#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLAYBOOK_SCRIPT="${ROOT}/scripts/build-linux-next-expansion-playbook.sh"
MATRIX_SCRIPT="${ROOT}/scripts/build-linux-package-acceptance-matrix.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-linux-next-expansion-review-bundle.sh <output-dir> \
    --matrix-manifest <bundle.manifest.json> \
    --target-evidence <host-validation.json> \
    [--target-family <host-family-id>] \
    [--host-label <label>]

Builds one top-level review bundle for the next non-Ubuntu Linux evidence wave by:
  - materializing the next-expansion playbook
  - refreshing the Linux package acceptance matrix with the new host evidence
  - producing a review artifact for the collected family
EOF
}

if [[ $# -lt 5 ]]; then
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
if [[ -z "${TARGET_EVIDENCE}" || ! -f "${TARGET_EVIDENCE}" ]]; then
  echo "Missing target evidence: ${TARGET_EVIDENCE}" >&2
  exit 1
fi
for helper_script in "${PLAYBOOK_SCRIPT}" "${MATRIX_SCRIPT}"; do
  if [[ ! -f "${helper_script}" ]]; then
    echo "Missing helper script: ${helper_script}" >&2
    exit 1
  fi
done

mkdir -p "${OUTPUT_DIR}"

TARGET_FAMILY_RESOLVED=""
EXISTING_EVIDENCE_PATHS=()
while IFS= read -r item; do
  if [[ "${item}" == __TARGET_FAMILY__=* ]]; then
    TARGET_FAMILY_RESOLVED="${item#__TARGET_FAMILY__=}"
  elif [[ -n "${item}" ]]; then
    EXISTING_EVIDENCE_PATHS+=("${item}")
  fi
done < <(
  review_inputs_cmd=(
    cargo run -q -p aegis-measure --
    linux-next-expansion-review-inputs
    --matrix-manifest "${MATRIX_MANIFEST}"
    --target-evidence "${TARGET_EVIDENCE}"
  )
  if [[ -n "${TARGET_FAMILY}" ]]; then
    review_inputs_cmd+=(--target-family "${TARGET_FAMILY}")
  fi
  "${review_inputs_cmd[@]}"
)

if [[ -z "${TARGET_FAMILY_RESOLVED}" ]]; then
  echo "Unable to resolve target family from matrix manifest" >&2
  exit 1
fi

PLAYBOOK_DIR="${OUTPUT_DIR}/next-expansion-playbook"
REFRESHED_MATRIX_DIR="${OUTPUT_DIR}/refreshed-matrix"

playbook_cmd=(
  bash "${PLAYBOOK_SCRIPT}" "${PLAYBOOK_DIR}"
  --matrix-manifest "${MATRIX_MANIFEST}"
  --target-family "${TARGET_FAMILY_RESOLVED}"
  --host-label "${HOST_LABEL}"
)

matrix_cmd=(
  bash "${MATRIX_SCRIPT}" "${REFRESHED_MATRIX_DIR}"
)
if (( ${#EXISTING_EVIDENCE_PATHS[@]} > 0 )); then
  for evidence_path in "${EXISTING_EVIDENCE_PATHS[@]}"; do
    matrix_cmd+=(--evidence "${evidence_path}")
  done
fi
matrix_cmd+=(--evidence "${TARGET_EVIDENCE}")

"${playbook_cmd[@]}" >/dev/null
"${matrix_cmd[@]}" >/dev/null

cargo run -q -p aegis-measure -- \
  build-linux-next-expansion-review-bundle-artifacts \
  --output-dir "${OUTPUT_DIR}" \
  --previous-matrix-manifest "${MATRIX_MANIFEST}" \
  --target-evidence "${TARGET_EVIDENCE}" \
  --playbook-json "${PLAYBOOK_DIR}/next-expansion-playbook.json" \
  --refreshed-matrix-manifest "${REFRESHED_MATRIX_DIR}/bundle.manifest.json" \
  --host-label "${HOST_LABEL}"

cat <<EOF
Linux next expansion review bundle created
-----------------------------------------
Artifacts:
  ${OUTPUT_DIR}/next-expansion-playbook/next-expansion-playbook.json
  ${OUTPUT_DIR}/refreshed-matrix/bundle.manifest.json
  ${OUTPUT_DIR}/next-expansion-review.json
  ${OUTPUT_DIR}/next-expansion-review.md
  ${OUTPUT_DIR}/next-expansion-review.manifest.json
EOF
