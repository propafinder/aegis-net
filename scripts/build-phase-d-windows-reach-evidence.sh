#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [[ "$#" -gt 0 ]]; then
  cargo run -q -p aegis-measure -- phase-d-windows-reach-evidence "$@"
  exit 0
fi

# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"

ARTIFACT_DIR="${EVIDENCE_ROOT}/live/2026-05-03/phase-d-reach-prep-current"

cargo run -q -p aegis-measure -- phase-d-windows-reach-evidence \
  --socks-client-artifact "${EVIDENCE_ROOT}/live/2026-05-01/windows-socks-client-baseline" \
  --service-artifact "${EVIDENCE_ROOT}/live/2026-05-03/windows-service-baseline" \
  --controlled-wfp-artifact "${EVIDENCE_ROOT}/live/2026-05-01/windows-wfp-aegis-wide-controlled-tcp" \
  --dynamic-original-dst-artifact "${EVIDENCE_ROOT}/live/2026-05-01/windows-wfp-aegis-original-dst-dynamic" \
  --controlled-process-artifact "${EVIDENCE_ROOT}/live/2026-05-01/windows-wfp-controlled-process-capture" \
  --controlled-browser-artifact "${EVIDENCE_ROOT}/live/2026-05-01/windows-wfp-controlled-browser-capture" \
  --dns-policy-json "${EVIDENCE_ROOT}/live/2026-05-01/windows-dns-policy-proof/result.json" \
  --udp-policy-json "${EVIDENCE_ROOT}/live/2026-05-01/windows-udp-policy-proof/result.json" \
  --ipv6-policy-json "${EVIDENCE_ROOT}/live/2026-05-01/windows-ipv6-policy-proof/result.json" \
  --service-persistence-json "${EVIDENCE_ROOT}/live/2026-05-01/windows-wide-service-persistence-proof" \
  --service-reboot-json "${EVIDENCE_ROOT}/live/2026-05-03/master-plan-current-handoff/windows-wide-service-reboot-persistence-proof" \
  --dns-udp-next-scope-json "${EVIDENCE_ROOT}/live/2026-05-01/windows-wfp-controlled-dns-udp-proof/result.json" \
  --rollback-matrix-json "${EVIDENCE_ROOT}/live/2026-05-01/windows-wide-rollback-matrix" \
  --output-json "${ARTIFACT_DIR}/windows-reach-evidence.json" \
  --output-markdown "${ARTIFACT_DIR}/windows-reach-evidence.md"
