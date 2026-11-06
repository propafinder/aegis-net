#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/build-macos-pf-operator-acceptance-summary.sh <output-dir> \
    --rooted-live-dir <evidence-dir/macos-pf-live/.../rooted-live> \
    [--phase4-dir <evidence-dir/macos-pf-live/.../rooted-live/phase4>]

Builds one machine-readable and human-readable operator acceptance summary for
the current macOS PF epic. The helper does not rerun rooted validation; it
classifies the already captured phase-1 / phase-2 / phase-3-boundary artifacts
into one explicit local-acceptance verdict while keeping broader system-wide
claims outside the current green boundary.

When --phase4-dir is provided the schema switches from v1 to v2 and the
"broader system-wide runtime claim" transitions from `not_opened` to one of
`green` / `degraded` based on whether the phase-4 bind-capable contour is
reproduced end-to-end. This is the B1 acceptance gate for the phase-4
implementation wave: it is expected to be consumed BEFORE phase-4 code in
scripts/macos-wide-pf.sh and aegis-client runtime enforcement is completed,
so that phase-4 work has an explicit target shape.
EOF
}

if [[ $# -lt 3 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

ROOTED_LIVE_DIR=""
PHASE4_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rooted-live-dir)
      ROOTED_LIVE_DIR="$2"
      shift 2
      ;;
    --phase4-dir)
      PHASE4_DIR="$2"
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

if [[ -z "${ROOTED_LIVE_DIR}" || ! -d "${ROOTED_LIVE_DIR}" ]]; then
  echo "Missing rooted live artifact directory: ${ROOTED_LIVE_DIR}" >&2
  exit 1
fi

if [[ -n "${PHASE4_DIR}" && ! -d "${PHASE4_DIR}" ]]; then
  echo "Missing phase4 artifact directory: ${PHASE4_DIR}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

cmd=(
  cargo run -q -p aegis-measure --
  build-macos-pf-operator-acceptance-summary
  --output-dir "${OUTPUT_DIR}"
  --rooted-live-dir "${ROOTED_LIVE_DIR}"
)

if [[ -n "${PHASE4_DIR}" ]]; then
  cmd+=(--phase4-dir "${PHASE4_DIR}")
fi

"${cmd[@]}"

cat <<EOF
macOS PF operator acceptance summary created
------------------------------------------
Artifacts:
  ${OUTPUT_DIR}/macos-pf-operator-acceptance-summary.json
  ${OUTPUT_DIR}/macos-pf-operator-acceptance-summary.md
EOF
