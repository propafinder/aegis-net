#!/usr/bin/env bash
# Actual Rust/private-input CLI plus controlled loopback HTTP/TLS; no public network.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
args=(--client "${AEGIS_TEST_SECRET_CLIENT:-${ROOT}/target/debug/aegis-client}"
      --role "${AEGIS_TEST_HTTPS_ROLE:-candidate}")
if [[ -n "${AEGIS_TEST_HTTPS_RECEIPT_DIR:-}" ]]; then
  args+=(--receipt-dir "${AEGIS_TEST_HTTPS_RECEIPT_DIR}")
fi
exec python3 "${ROOT}/scripts/test-installer-secret-https-policy.py" "${args[@]}"
