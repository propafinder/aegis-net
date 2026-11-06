#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-b-baseline.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/phase-a-exit.json" <<'JSON'
{"status":"EXIT_READY","acceptance_degraded":false}
JSON
cat >"${TMP_DIR}/gate.json" <<'JSON'
{"a3_brain_integration":{"status":"APPLIED","calibration_status":"MEASURED"}}
JSON
cat >"${TMP_DIR}/classifier.json" <<'JSON'
{"status":"PASS","classifier_records":4,"verdict_counts":{"pass":4,"fail":0,"unknown":0}}
JSON
cat >"${TMP_DIR}/calibration.json" <<'JSON'
{
  "witness": {
    "labels": [
      {"label": "legacy_tls", "combined_avg": 0.72},
      {"label": "https_ws", "combined_avg": 0.71},
      {"label": "masque_derived", "combined_avg": 0.70}
    ]
  },
  "adversarial": {
    "transports": [
      {"transport": "legacy_tls", "measured": 4, "pass_rate": 0.90},
      {"transport": "https_ws", "measured": 4, "pass_rate": 0.90},
      {"transport": "masque_derived", "measured": 4, "pass_rate": 0.90}
    ]
  }
}
JSON

bash "${ROOT}/scripts/build-phase-b-baseline-review.sh" \
  --phase-a-exit-json "${TMP_DIR}/phase-a-exit.json" \
  --calibration-json "${TMP_DIR}/calibration.json" \
  --gate-review-json "${TMP_DIR}/gate.json" \
  --classifier-json "${TMP_DIR}/classifier.json" \
  --output-json "${TMP_DIR}/baseline.json" \
  --output-markdown "${TMP_DIR}/baseline.md"

cargo run -q -p aegis-measure -- phase-b-baseline-review \
  --phase-a-exit-json "${TMP_DIR}/phase-a-exit.json" \
  --calibration-json "${TMP_DIR}/calibration.json" \
  --gate-review-json "${TMP_DIR}/gate.json" \
  --classifier-json "${TMP_DIR}/classifier.json" \
  --output-json "${TMP_DIR}/baseline-direct.json"

grep -q '"status": "BASELINE_READY"' "${TMP_DIR}/baseline.json"
grep -q '"acceptance_degraded": false' "${TMP_DIR}/baseline.json"
grep -q 'Phase B Baseline Review' "${TMP_DIR}/baseline.md"

cat >"${TMP_DIR}/bad-calibration.json" <<'JSON'
{
  "witness": {"labels": [{"label": "legacy_tls", "combined_avg": 0.1}]},
  "adversarial": {"transports": [{"transport": "legacy_tls", "measured": 1, "pass_rate": 0.1}]}
}
JSON

bash "${ROOT}/scripts/build-phase-b-baseline-review.sh" \
  --phase-a-exit-json "${TMP_DIR}/phase-a-exit.json" \
  --calibration-json "${TMP_DIR}/bad-calibration.json" \
  --gate-review-json "${TMP_DIR}/gate.json" \
  --classifier-json "${TMP_DIR}/classifier.json" \
  --output-json "${TMP_DIR}/blocked.json"

grep -q '"status": "BASELINE_BLOCKED"' "${TMP_DIR}/blocked.json"
grep -q 'phase-b-first-pass-witness-below-target' "${TMP_DIR}/blocked.json"
grep -q 'phase-b-first-pass-adversarial-below-target' "${TMP_DIR}/blocked.json"

echo "PASS: Phase B baseline review contract"
