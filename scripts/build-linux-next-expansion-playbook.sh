#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/build-linux-next-expansion-playbook.sh <output-dir> \
    --matrix-manifest <bundle.manifest.json> \
    [--target-family <host-family-id>] \
    [--host-label <label>]

Builds a machine-readable and human-readable playbook for the next non-Ubuntu
Linux package-evidence expansion wave.
EOF
}

if [[ $# -lt 3 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

MATRIX_MANIFEST=""
TARGET_FAMILY=""
HOST_LABEL="next-linux-validation-host"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix-manifest)
      MATRIX_MANIFEST="$2"
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

mkdir -p "${OUTPUT_DIR}"

CMD=(
  cargo run -q -p aegis-measure --
  build-linux-next-expansion-playbook
  --output-dir "${OUTPUT_DIR}"
  --matrix-manifest "${MATRIX_MANIFEST}"
  --host-label "${HOST_LABEL}"
)

if [[ -n "${TARGET_FAMILY}" ]]; then
  CMD+=(--target-family "${TARGET_FAMILY}")
fi

"${CMD[@]}"

cat <<EOF
Linux next expansion playbook created
------------------------------------
Artifacts:
  ${OUTPUT_DIR}/next-expansion-playbook.json
  ${OUTPUT_DIR}/next-expansion-playbook.md
EOF
