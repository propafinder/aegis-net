#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-b-live-evidence.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/baseline-ready.json" <<'JSON'
{"event":"phase_b_baseline_review","status":"BASELINE_READY","acceptance_degraded":false,"reasons":[]}
JSON
cat >"${TMP_DIR}/tls-wire-pass.json" <<'JSON'
{"event":"phase_b_tls_wire_review","status":"PASS","checked_events":3,"reasons":[]}
JSON
cat >"${TMP_DIR}/relay-shape-pass.json" <<'JSON'
{"event":"phase_b_relay_shape_review","status":"PASS","checked_events":2,"require_diversity":true,"reasons":[]}
JSON
cat >"${TMP_DIR}/active-probe-pass.json" <<'JSON'
{"event":"phase_b_active_probe_review","status":"PASS","counts":{"launched":1,"finished":1},"reasons":[]}
JSON

cargo run -q -p aegis-measure -- phase-b-live-evidence-review \
  --baseline-json "${TMP_DIR}/baseline-ready.json" \
  --tls-wire-json "${TMP_DIR}/tls-wire-pass.json" \
  --relay-shape-json "${TMP_DIR}/relay-shape-pass.json" \
  --active-probe-json "${TMP_DIR}/active-probe-pass.json" \
  --output-json "${TMP_DIR}/live-evidence-ready.json" \
  --output-markdown "${TMP_DIR}/live-evidence-ready.md"
grep -q '"status": "LIVE_EVIDENCE_READY"' "${TMP_DIR}/live-evidence-ready.json"
grep -q 'Phase B Live Evidence Review' "${TMP_DIR}/live-evidence-ready.md"

cat >"${TMP_DIR}/tls-wire-fail.json" <<'JSON'
{"event":"phase_b_tls_wire_review","status":"FAIL","checked_events":1,"reasons":["tls-wire-target-mismatch"]}
JSON

if cargo run -q -p aegis-measure -- phase-b-live-evidence-review \
  --baseline-json "${TMP_DIR}/baseline-ready.json" \
  --tls-wire-json "${TMP_DIR}/tls-wire-fail.json" \
  --relay-shape-json "${TMP_DIR}/relay-shape-pass.json" \
  --active-probe-json "${TMP_DIR}/active-probe-pass.json" \
  --output-json "${TMP_DIR}/live-evidence-blocked.json" >/dev/null 2>&1; then
  echo "expected Phase B live evidence blocked failure" >&2
  exit 1
fi
grep -q '"status": "LIVE_EVIDENCE_BLOCKED"' "${TMP_DIR}/live-evidence-blocked.json"
grep -q 'phase-b-tls_wire-not-ready' "${TMP_DIR}/live-evidence-blocked.json"

echo "PASS: Phase B live evidence review contract"
