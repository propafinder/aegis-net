#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/build-ubuntu-operator-reapply-canary.sh <output-dir> \
    --pilot-inputs <ubuntu-controlled-pilot-inputs.json>

Builds one machine-readable and human-readable operator canary artifact for the
current Ubuntu field-pilot contour. The helper does not rerun the lifecycle
itself; instead it reads the live validation-generated evidence and classifies
restart, rollback/reinstall and same-version reapply readiness.
EOF
}

if [[ $# -lt 3 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

PILOT_INPUTS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pilot-inputs)
      PILOT_INPUTS="$2"
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

mkdir -p "${OUTPUT_DIR}"

cargo run -q -p aegis-measure -- \
  build-ubuntu-operator-reapply-canary \
  --output-dir "${OUTPUT_DIR}" \
  --pilot-inputs "${PILOT_INPUTS}"

cat <<EOF
Ubuntu operator reapply canary created
-------------------------------------
Artifacts:
  ${OUTPUT_DIR}/ubuntu-operator-reapply-canary.json
  ${OUTPUT_DIR}/ubuntu-operator-reapply-canary.md
EOF
