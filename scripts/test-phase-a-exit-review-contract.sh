#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-a-exit.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/gate.json" <<'JSON'
{
  "a2_adversarial": {"packet_evidence_records": 2},
  "a25_knowledge": {"status": "PASS"},
  "a3_brain_integration": {"status": "APPLIED"}
}
JSON

cat >"${TMP_DIR}/calibration-pass.json" <<'JSON'
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
      {"transport": "legacy_tls", "measured": 3, "pass_rate": 0.90, "threshold": 0.85},
      {"transport": "https_ws", "measured": 3, "pass_rate": 0.90, "threshold": 0.85},
      {"transport": "masque_derived", "measured": 3, "pass_rate": 1.0, "threshold": 0.85}
    ]
  }
}
JSON

cat >"${TMP_DIR}/classifier-pass.json" <<'JSON'
{"status":"PASS","classifier_records":4,"verdict_counts":{"pass":4,"fail":0,"unknown":0}}
JSON

printf '# threat model\n' >"${TMP_DIR}/threat.md"
printf '# knowledge architecture\n' >"${TMP_DIR}/knowledge.md"

bash "${ROOT}/scripts/build-phase-a-exit-review.sh" \
  --gate-review-json "${TMP_DIR}/gate.json" \
  --calibration-json "${TMP_DIR}/calibration-pass.json" \
  --classifier-json "${TMP_DIR}/classifier-pass.json" \
  --threat-model "${TMP_DIR}/threat.md" \
  --knowledge-architecture "${TMP_DIR}/knowledge.md" \
  --output-json "${TMP_DIR}/exit-pass.json" \
  --output-markdown "${TMP_DIR}/exit-pass.md"

cat >"${TMP_DIR}/calibration-partial.json" <<'JSON'
{
  "witness": {
    "labels": [
      {"label": "legacy_tls", "combined_avg": 0.0}
    ]
  },
  "adversarial": {
    "transports": [
      {"transport": "masque_derived", "measured": 2, "pass_rate": 1.0, "threshold": 0.85}
    ]
  }
}
JSON

cat >"${TMP_DIR}/classifier-fail.json" <<'JSON'
{"status":"FAIL","classifier_records":4,"verdict_counts":{"pass":2,"fail":0,"unknown":2}}
JSON

bash "${ROOT}/scripts/build-phase-a-exit-review.sh" \
  --gate-review-json "${TMP_DIR}/gate.json" \
  --calibration-json "${TMP_DIR}/calibration-partial.json" \
  --classifier-json "${TMP_DIR}/classifier-fail.json" \
  --threat-model "${TMP_DIR}/threat.md" \
  --knowledge-architecture "${TMP_DIR}/knowledge.md" \
  --output-json "${TMP_DIR}/exit-partial.json" \
  --output-markdown "${TMP_DIR}/exit-partial.md"

jq -e '
  .event == "phase_a_exit_review"
  and .status == "EXIT_READY"
  and .reasons == []
' "${TMP_DIR}/exit-pass.json" >/dev/null

if [[ ! -f "${TMP_DIR}/exit-pass.md" ]]; then
  echo "missing Phase A exit markdown" >&2
  exit 1
fi

jq -e '
  .status == "NOT_EXIT_READY"
  and (.reasons | index("missing-primary-witness-scores") != null)
  and (.reasons | index("primary-witness-score-below-target") != null)
  and (.reasons | index("missing-primary-adversarial-pass-rates") != null)
  and (.reasons | index("hostile-classifier-not-pass") != null)
  and .a1_witness.missing_primary_transports == ["https_ws", "masque_derived"]
  and .a2_adversarial.missing_primary_transports == ["legacy_tls", "https_ws"]
' "${TMP_DIR}/exit-partial.json" >/dev/null

echo "PASS: Phase A exit review contract"
