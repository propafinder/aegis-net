#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/build-stealth-polymorphism-acceptance-summary.sh <output-dir> \
    [--config <config.example.toml>] \
    [--now-secs <unix-seconds>]

Build one machine-readable and human-readable long-run statistical acceptance
summary for the current stealth polymorphism layer. The helper does not execute
live traffic; it materializes the repo-side direct/relay sampling contract into
one explicit verdict artifact.
EOF
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_PATH="${ROOT}/config.example.toml"
NOW_SECS="10000"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --now-secs)
      NOW_SECS="$2"
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

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Missing config path: ${CONFIG_PATH}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

cargo run -q -p aegis-measure -- build-stealth-polymorphism-acceptance-summary \
  --output-dir "${OUTPUT_DIR}" \
  --config "${CONFIG_PATH}" \
  --repo-root "${ROOT}" \
  --now-secs "${NOW_SECS}"

cat <<EOF
Stealth polymorphism acceptance summary created
----------------------------------------------
Artifacts:
  ${OUTPUT_DIR}/stealth-polymorphism-acceptance-summary.json
  ${OUTPUT_DIR}/stealth-polymorphism-acceptance-summary.md
EOF
