#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"
OUT_DIR="${1:-${EVIDENCE_ROOT}/live/2026-05-03/master-plan-desktop-core-handoff/brain-external-calibration-runtime-proof}"

cd "${ROOT}"
cargo run -q -p aegis-measure -- brain-external-calibration-runtime-proof \
  --artifact-dir "${OUT_DIR}" \
  --output-json "${OUT_DIR}/result.json"
