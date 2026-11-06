#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [[ "$#" -gt 0 ]]; then
  cargo run -q -p aegis-measure -- master-plan-handoff "$@"
  exit 0
fi

# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"

ARTIFACT_DIR="${EVIDENCE_ROOT}/live/2026-05-03/master-plan-current-handoff"

cargo run -q -p aegis-measure -- master-plan-handoff \
  --phase-c-resilience-json "${EVIDENCE_ROOT}/live/2026-05-03/phase-c-cloudflare-grpc-stream-fronted-live/phase-c-resilience-gate.json" \
  --phase-d-reach-json "${EVIDENCE_ROOT}/live/2026-05-03/phase-d-reach-prep-current/phase-d-reach-gate.json" \
  --artifact-dir "${ARTIFACT_DIR}" \
  --output-json "${ARTIFACT_DIR}/master-plan-handoff.json" \
  --output-markdown "${ARTIFACT_DIR}/master-plan-handoff.md"
