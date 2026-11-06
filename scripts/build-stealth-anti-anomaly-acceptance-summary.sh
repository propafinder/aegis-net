#!/usr/bin/env bash
# Track C (anti-anomaly) baseline metric harness.
#
# Materializes one machine-readable + human-readable acceptance summary that
# scores the current DPI-evasion stealth contour on six orthogonal dimensions
# and a composite score. The helper does NOT open network traffic; it reads
# source files only and is intended as the deterministic target for Track C
# improvements (C2 catalog expansion, C3 intra-session drift, C4 configurable
# TTL sets). The BASELINE must be materialized and committed BEFORE any C2..C4
# source changes so later improvements can be verified as measurable numeric
# increases on the same rubric.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-stealth-anti-anomaly-acceptance-summary.sh <output-dir> \
    [--repo-root <path>]

Build the Track C anti-anomaly baseline acceptance summary from current repo
sources (direct/relay catalogs, stealth_rotation surfaces, strategies, default
path pools, runtime event catalog). Scores each of six dimensions on 0-100 and
emits one composite anti-anomaly score with a weak/medium/strong verdict.
EOF
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

REPO_ROOT="${ROOT}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root)
      REPO_ROOT="$2"
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

mkdir -p "${OUTPUT_DIR}"

cargo run -q -p aegis-measure -- \
  build-stealth-anti-anomaly-acceptance-summary \
  --output-dir "${OUTPUT_DIR}" \
  --repo-root "${REPO_ROOT}"

cat <<EOF
Stealth anti-anomaly acceptance summary created
----------------------------------------------
Artifacts:
  ${OUTPUT_DIR}/stealth-anti-anomaly-acceptance-summary.json
  ${OUTPUT_DIR}/stealth-anti-anomaly-acceptance-summary.md
EOF
