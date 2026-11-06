#!/usr/bin/env bash
# Real previously built host client only; no build, network, or installer apply.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
args=()
if [[ -n "${AEGIS_TEST_SECRET_CLIENT:-}" ]]; then
  [[ -f "${AEGIS_TEST_SECRET_CLIENT}" && -x "${AEGIS_TEST_SECRET_CLIENT}" ]] || {
    echo "INVALID: actual previously built host client is required." >&2; exit 2;
  }
  args+=(--client "${AEGIS_TEST_SECRET_CLIENT}")
elif [[ -n "${RUNNER_TEMP:-}" && -n "${GITHUB_RUN_ID:-}" && -n "${GITHUB_RUN_ATTEMPT:-}" && -n "${GITHUB_SHA:-}" ]]; then
  args+=(--prebuild-root "${RUNNER_TEMP}/installer-source-prebuild-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
         --source-root "${ROOT}" --expected-head "${GITHUB_SHA}")
else
  echo "INVALID: actual previously built host client is required." >&2
  exit 2
fi
if [[ -n "${AEGIS_TEST_LOCAL_COPY_RECEIPT_DIR:-}" ]]; then
  args+=(--receipt-dir "${AEGIS_TEST_LOCAL_COPY_RECEIPT_DIR}")
fi
exec python3 -I "${ROOT}/scripts/test-installer-secret-local-copy-mode-contract.py" "${args[@]}"
