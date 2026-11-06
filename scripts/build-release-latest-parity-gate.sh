#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${EVIDENCE_ROOT}/live/2026-05-03/release-latest-parity-gate}"
SERVER_RESULT_JSON="${SERVER_RESULT_JSON:-${EVIDENCE_ROOT}/live/2026-04-28/installer-server-one-command-live/result.json}"
CLIENT_RESULT_JSON="${CLIENT_RESULT_JSON:-${EVIDENCE_ROOT}/live/2026-04-28/installer-client-one-command-live/result.json}"
NEGATIVE_RESULT_JSON="${NEGATIVE_RESULT_JSON:-${EVIDENCE_ROOT}/live/2026-04-28/installer-negative-live/result.json}"

mkdir -p "${ARTIFACT_DIR}"

set +e
cargo run -q -p aegis-measure -- release-latest-parity \
  --server-result-json "${SERVER_RESULT_JSON}" \
  --client-result-json "${CLIENT_RESULT_JSON}" \
  --negative-result-json "${NEGATIVE_RESULT_JSON}" \
  --output-json "${ARTIFACT_DIR}/result.json" \
  --output-markdown "${ARTIFACT_DIR}/README.md"
STATUS=$?
set -e

{
  echo "server_result_json=${SERVER_RESULT_JSON}"
  echo "client_result_json=${CLIENT_RESULT_JSON}"
  echo "negative_result_json=${NEGATIVE_RESULT_JSON}"
  echo "output_json=${ARTIFACT_DIR}/result.json"
  echo "output_markdown=${ARTIFACT_DIR}/README.md"
  echo "aegis_measure_exit_status=${STATUS}"
} >"${ARTIFACT_DIR}/commands.txt"

cat >"${ARTIFACT_DIR}/environment.txt" <<EOF
artifact=release-latest-parity-gate
scope=release_latest_parity_validation
claim_boundary=existing installer artifact validation only
does_not_claim_new_live_redeploy=true
does_not_claim_phase_d_exit=true
EOF

if [[ "${STATUS}" -ne 0 ]]; then
  echo "release latest parity gate: BLOCKED (see ${ARTIFACT_DIR}/result.json)" >&2
  exit 1
fi

echo "release latest parity gate: READY (${ARTIFACT_DIR}/result.json)"
