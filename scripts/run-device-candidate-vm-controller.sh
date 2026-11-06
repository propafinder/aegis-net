#!/usr/bin/env bash
# Executes only on an explicitly prepared KVM host; never deploys itself.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
exec python3 "${ROOT}/scripts/lib/device_candidate_vm.py" "$@"
