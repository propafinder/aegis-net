#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/build-ubuntu-release-review.sh <output-dir> \
    --release-summary <ubuntu-product-release-summary.json> \
    --pilot-bundle <pilot-summary.json> \
    [--matrix-manifest <bundle.manifest.json>] \
    [--wire-acceptance-summary <wire-host-acceptance-summary.json>]

Builds one release-review artifact that combines Ubuntu release evidence with
the controlled pilot verdict. It now keeps two honest product tiers:
baseline transport/runtime ship-readiness and fully-proven hostile-path support.
EOF
}

if [[ $# -lt 5 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

RELEASE_SUMMARY=""
PILOT_BUNDLE=""
MATRIX_MANIFEST=""
WIRE_ACCEPTANCE_SUMMARY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-summary)
      RELEASE_SUMMARY="$2"
      shift 2
      ;;
    --pilot-bundle)
      PILOT_BUNDLE="$2"
      shift 2
      ;;
    --matrix-manifest)
      MATRIX_MANIFEST="$2"
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

for required_path in "${RELEASE_SUMMARY}" "${PILOT_BUNDLE}"; do
  if [[ -z "${required_path}" || ! -f "${required_path}" ]]; then
    echo "Missing required review input: ${required_path}" >&2
    exit 1
  fi
done

mkdir -p "${OUTPUT_DIR}"

CMD=(
  cargo run -q -p aegis-measure -- build-ubuntu-release-review
  --output-dir "${OUTPUT_DIR}"
  --release-summary "${RELEASE_SUMMARY}"
  --pilot-bundle "${PILOT_BUNDLE}"
)

if [[ -n "${MATRIX_MANIFEST}" ]]; then
  CMD+=(--matrix-manifest "${MATRIX_MANIFEST}")
fi

if [[ -n "${WIRE_ACCEPTANCE_SUMMARY}" ]]; then
  CMD+=(--wire-acceptance-summary "${WIRE_ACCEPTANCE_SUMMARY}")
fi

"${CMD[@]}"

cat <<EOF
Ubuntu release review created
----------------------------
Artifacts:
  ${OUTPUT_DIR}/release-review.json
  ${OUTPUT_DIR}/release-review.md
EOF
