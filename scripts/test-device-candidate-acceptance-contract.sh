#!/usr/bin/env bash
# Synthetic Ed25519 fixture only. No network, systemd, installed config or VPS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
if [[ -z "${AEGIS_DEVICE_SERVER:-}" ]]; then
  (cd "${ROOT}" && cargo build --locked -p aegis-server --bin aegis-server)
fi
exec python3 "${ROOT}/scripts/lib/test_device_candidate_acceptance.py"
