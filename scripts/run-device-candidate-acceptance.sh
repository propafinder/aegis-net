#!/usr/bin/env bash
# Lab controller only. See --help and docs/operations/device-candidate-acceptance.md.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
exec python3 "${ROOT}/scripts/lib/device_candidate_acceptance.py" "$@"
