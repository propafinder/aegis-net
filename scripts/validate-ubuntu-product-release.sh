#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST_VALIDATION_SCRIPT="${AEGIS_UBUNTU_PRODUCT_RELEASE_HOST_VALIDATION_SCRIPT:-${ROOT}/scripts/validate-debian-package-host.sh}"
MODE="check"
JSON_OUTPUT=0
ARTIFACT_DIR="${AEGIS_UBUNTU_PRODUCT_RELEASE_ARTIFACT_DIR:-}"

usage() {
  cat <<'EOF'
Usage:
  scripts/validate-ubuntu-product-release.sh [--check|--run] [--json] [--artifact-dir <dir>]

Compatibility shim:
  The canonical orchestration now lives directly inside
  `scripts/validate-debian-package-host.sh`.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)
      MODE="check"
      shift
      ;;
    --run)
      MODE="run"
      shift
      ;;
    --json)
      JSON_OUTPUT=1
      shift
      ;;
    --artifact-dir)
      ARTIFACT_DIR="$2"
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

if [[ "${MODE}" == "check" ]]; then
  if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
    exec "${HOST_VALIDATION_SCRIPT}" --check --json
  fi
  exec "${HOST_VALIDATION_SCRIPT}" --check
fi

if [[ -z "${ARTIFACT_DIR}" ]]; then
  ARTIFACT_DIR="${ROOT}/dist/ubuntu-product-release"
fi

if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
  set +e
  "${HOST_VALIDATION_SCRIPT}" --run --artifact-dir "${ARTIFACT_DIR}" >/dev/null
  status=$?
  set -e
  if [[ -f "${ARTIFACT_DIR}/ubuntu-product-release-summary.json" ]]; then
    cat "${ARTIFACT_DIR}/ubuntu-product-release-summary.json"
  fi
  exit "${status}"
fi

exec "${HOST_VALIDATION_SCRIPT}" --run --artifact-dir "${ARTIFACT_DIR}"
