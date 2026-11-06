#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT="${2:-}"
      shift 2
      ;;
    *)
      echo "usage: $0 --output <path>" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${OUTPUT}" ]]; then
  echo "usage: $0 --output <path>" >&2
  exit 1
fi

cargo run -q -p aegis-measure -- build-mimicry-wire-validation-contract \
  --output "${OUTPUT}" \
  --repo-root "${ROOT}"
