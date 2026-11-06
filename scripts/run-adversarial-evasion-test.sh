#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_JSONL=""
DRY_RUN=0
LIVE_COMMAND=""
ARGS=()

usage() {
  cat >&2 <<'EOF'
Usage:
  run-adversarial-evasion-test.sh --dry-run --output-jsonl PATH [runner args]
  run-adversarial-evasion-test.sh --live-command COMMAND --scenario NAME --network-profile NAME --output-jsonl PATH
  run-adversarial-evasion-test.sh --live-command COMMAND --live-matrix --output-jsonl PATH

Dry-run validates scenario/profile wiring. --live-command executes a bounded
operator probe and records measured PASS/FAIL/TIMEOUT events; when run inside a
prepared gateway container, that command is the measured gateway probe.
Use --live-matrix to run the same bounded command across the full selected or
default scenario/profile matrix.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      ARGS+=("$1")
      shift
      ;;
    --output-jsonl)
      OUTPUT_JSONL="${2:?missing --output-jsonl value}"
      ARGS+=("$1" "$2")
      shift 2
      ;;
    --live-command)
      LIVE_COMMAND="${2:?missing --live-command value}"
      ARGS+=("$1" "$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ "${DRY_RUN}" == "1" && -n "${LIVE_COMMAND}" ]]; then
  echo "--dry-run conflicts with --live-command" >&2
  usage
  exit 2
fi

if [[ "${DRY_RUN}" != "1" && -z "${LIVE_COMMAND}" ]]; then
  echo "use --dry-run or provide --live-command" >&2
  usage
  exit 2
fi

if [[ -z "${OUTPUT_JSONL}" ]]; then
  echo "--output-jsonl is required" >&2
  usage
  exit 2
fi

cd "${ROOT}"
cargo run -q -p aegis-measure -- adversarial-runner "${ARGS[@]}"
