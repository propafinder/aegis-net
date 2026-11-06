#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [[ "$#" -gt 0 ]]; then
  cargo run -q -p aegis-measure -- phase-d-reach-gate "$@"
  exit 0
fi

# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"

ARTIFACT_DIR="${EVIDENCE_ROOT}/live/2026-05-03/phase-d-reach-prep-current"

cargo run -q -p aegis-measure -- phase-d-reach-gate \
  --phase-c-resilience-json "${EVIDENCE_ROOT}/live/2026-05-03/phase-c-cloudflare-grpc-stream-fronted-live/phase-c-resilience-gate.json" \
  --windows-reach-json "${ARTIFACT_DIR}/windows-reach-evidence.json" \
  --macos-reach-json "${ARTIFACT_DIR}/macos-reach-evidence.json" \
  --android-reach-json "${ARTIFACT_DIR}/android-reach-evidence.json" \
  --output-json "${ARTIFACT_DIR}/phase-d-reach-gate.json" \
  --output-markdown "${ARTIFACT_DIR}/phase-d-reach-gate.md"
