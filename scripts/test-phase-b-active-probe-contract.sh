#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-b-active-probe.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/active-probe-pass.jsonl" <<'JSONL'
{"event_code":"direct_active_stall_probe_launched","planned_probe_preferred_ttl":64,"planned_probe_budget":2,"planned_probe_ttl_candidates":[64,128],"target":"example.com","port":443}
{"event_code":"direct_active_stall_probe_finished","probe_outcome_class":"path_freeze","observation_contract":"capture_backed","capture_status":"CaptureBacked","planned_probe_preferred_ttl":64,"planned_probe_budget":2,"planned_probe_ttl_candidates":[64,128],"latency_ms":27,"target":"example.com","port":443}
{"event_code":"direct_relay_failover_triggered","active_stall_probe_retry_attempted":true,"probe_terminal_stage":"active_probe_first_response_timeout"}
JSONL

cargo run -q -p aegis-measure -- phase-b-active-probe-review \
  --runtime-events-jsonl "${TMP_DIR}/active-probe-pass.jsonl" \
  --output-json "${TMP_DIR}/active-probe-review-pass.json" \
  --output-markdown "${TMP_DIR}/active-probe-review-pass.md" \
  --require-finished-probe
grep -q '"status": "PASS"' "${TMP_DIR}/active-probe-review-pass.json"
grep -q 'Phase B Active Probe Review' "${TMP_DIR}/active-probe-review-pass.md"

cat >"${TMP_DIR}/active-probe-fail.jsonl" <<'JSONL'
{"event_code":"direct_active_stall_probe_launched","planned_probe_preferred_ttl":64,"planned_probe_budget":2,"planned_probe_ttl_candidates":[64,128],"target":"example.com","port":443}
JSONL

if cargo run -q -p aegis-measure -- phase-b-active-probe-review \
  --runtime-events-jsonl "${TMP_DIR}/active-probe-fail.jsonl" \
  --output-json "${TMP_DIR}/active-probe-review-fail.json" >/dev/null 2>&1; then
  echo "expected Phase B active probe launched-without-finish failure" >&2
  exit 1
fi
grep -q '"status": "FAIL"' "${TMP_DIR}/active-probe-review-fail.json"
grep -q 'active-probe-launched-without-finish' "${TMP_DIR}/active-probe-review-fail.json"

echo "PASS: Phase B active probe contract"
