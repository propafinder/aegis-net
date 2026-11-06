#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR=""
SCENARIO=""
NETWORK_PROFILE=""
LIVE_COMMAND=""
IMAGE_TAG="aegis-adversarial-gateway:local"
DOCKER_BIN="${AEGIS_DOCKER_BIN:-docker}"

usage() {
  cat >&2 <<'EOF'
Usage:
  run-adversarial-gateway-docker.sh --output-dir DIR --scenario NAME --network-profile NAME --live-command COMMAND [options]

Options:
  --image-tag TAG       Docker image tag, default: aegis-adversarial-gateway:local

Outputs:
  DIR/events.jsonl
  DIR/docker-build.stdout.log
  DIR/docker-build.stderr.log
  DIR/docker-run.stdout.log
  DIR/docker-run.stderr.log
  DIR/commands.txt

Boundary:
  This wrapper runs the bounded adversarial measured-command path inside the
  Docker gateway image. A stronger live claim still requires the command to
  exercise a real AEGIS traffic path and packet capture to be archived.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="${2:?missing --output-dir value}"
      shift 2
      ;;
    --scenario)
      SCENARIO="${2:?missing --scenario value}"
      shift 2
      ;;
    --network-profile)
      NETWORK_PROFILE="${2:?missing --network-profile value}"
      shift 2
      ;;
    --live-command)
      LIVE_COMMAND="${2:?missing --live-command value}"
      shift 2
      ;;
    --image-tag)
      IMAGE_TAG="${2:?missing --image-tag value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${OUTPUT_DIR}" || -z "${SCENARIO}" || -z "${NETWORK_PROFILE}" || -z "${LIVE_COMMAND}" ]]; then
  echo "--output-dir, --scenario, --network-profile, and --live-command are required" >&2
  usage
  exit 2
fi

if ! command -v "${DOCKER_BIN}" >/dev/null 2>&1; then
  echo "docker is required; set AEGIS_DOCKER_BIN to override" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"
COMMANDS_TXT="${OUTPUT_DIR}/commands.txt"
: >"${COMMANDS_TXT}"

BUILD_CMD=(
  "${DOCKER_BIN}" build
  -f "${ROOT}/tests/adversarial/Dockerfile.dpi-gateway"
  -t "${IMAGE_TAG}"
  "${ROOT}"
)
RUN_CMD=(
  "${DOCKER_BIN}" run
  --rm
  -v "${OUTPUT_DIR}:/out"
  "${IMAGE_TAG}"
  --scenario "${SCENARIO}"
  --network-profile "${NETWORK_PROFILE}"
  --live-command "${LIVE_COMMAND}"
  --output-jsonl "/out/events.jsonl"
)

{
  printf 'docker_build='
  printf '%q ' "${BUILD_CMD[@]}"
  printf '\n'
  printf 'docker_run='
  printf '%q ' "${RUN_CMD[@]}"
  printf '\n'
} >"${COMMANDS_TXT}"

"${BUILD_CMD[@]}" >"${OUTPUT_DIR}/docker-build.stdout.log" 2>"${OUTPUT_DIR}/docker-build.stderr.log"
"${RUN_CMD[@]}" >"${OUTPUT_DIR}/docker-run.stdout.log" 2>"${OUTPUT_DIR}/docker-run.stderr.log"

if [[ ! -s "${OUTPUT_DIR}/events.jsonl" ]]; then
  echo "gateway runner did not write events: ${OUTPUT_DIR}/events.jsonl" >&2
  exit 1
fi

echo "PASS: adversarial gateway docker artifact written to ${OUTPUT_DIR}"
