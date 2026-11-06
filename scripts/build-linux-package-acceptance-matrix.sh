#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/build-linux-package-acceptance-matrix.sh <output-dir> --evidence <helper-json> [--evidence <helper-json> ...]

Collects machine-readable host validation evidence from:
  - scripts/validate-debian-package-host.sh --run --json
  - scripts/validate-rpm-package-host.sh --run --json

Outputs:
  <output-dir>/matrix.targets.json
  <output-dir>/matrix.results.json
  <output-dir>/matrix-summary.md
  <output-dir>/bundle.manifest.json
EOF
}

if [[ $# -lt 3 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift
EVIDENCE_PATHS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence)
      EVIDENCE_PATHS+=("$2")
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

if [[ ${#EVIDENCE_PATHS[@]} -eq 0 ]]; then
  echo "At least one --evidence path is required" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

CMD=(
  cargo run -q -p aegis-measure -- build-linux-package-acceptance-matrix
  --output-dir "${OUTPUT_DIR}"
)
for evidence_path in "${EVIDENCE_PATHS[@]}"; do
  CMD+=(--evidence "${evidence_path}")
done
"${CMD[@]}"

cat <<EOF
Linux package acceptance matrix created
-------------------------------------
Artifacts:
  ${OUTPUT_DIR}/matrix.targets.json
  ${OUTPUT_DIR}/matrix.results.json
  ${OUTPUT_DIR}/matrix-summary.md
  ${OUTPUT_DIR}/bundle.manifest.json
EOF
