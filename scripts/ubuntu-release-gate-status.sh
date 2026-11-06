#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/ubuntu-release-gate-status.sh --repo-green --output <path>
  scripts/ubuntu-release-gate-status.sh --host-summary <validation-summary.json> --output <path>

This helper materializes the machine-readable handoff between:
  - repo-side green contract status
  - Ubuntu host evidence from validate-debian-package-host.sh --run

Outputs a JSON artifact describing whether the current state is only repo-green
or actually ship-ready for the Ubuntu-first release contour.
EOF
}

MODE=""
HOST_SUMMARY=""
OUTPUT_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-green)
      MODE="repo_green"
      shift
      ;;
    --host-summary)
      MODE="host_summary"
      HOST_SUMMARY="$2"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="$2"
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

if [[ -z "${MODE}" || -z "${OUTPUT_PATH}" ]]; then
  usage >&2
  exit 1
fi

if [[ "${MODE}" == "host_summary" && -z "${HOST_SUMMARY}" ]]; then
  echo "--host-summary requires a path" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUTPUT_PATH}")"

cmd=(
  cargo run -q -p aegis-measure -- build-ubuntu-release-gate-status
  --output "${OUTPUT_PATH}"
)
if [[ "${MODE}" == "host_summary" ]]; then
  cmd+=(--host-summary "${HOST_SUMMARY}")
fi
"${cmd[@]}"
