#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-brain-calibration-proof.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

bash "${ROOT}/scripts/run-brain-external-calibration-runtime-proof.sh" "${TMP_DIR}/artifact"

grep -q '"artifact": "brain-external-calibration-runtime-proof"' "${TMP_DIR}/artifact/result.json"
grep -q '"verdict": "PASS"' "${TMP_DIR}/artifact/result.json"
grep -q '"calibration_snapshot_loaded": true' "${TMP_DIR}/artifact/result.json"
grep -q '"external_calibration_applied_event_present": true' "${TMP_DIR}/artifact/result.json"
grep -q '"select_order_changed_after_calibration": true' "${TMP_DIR}/artifact/result.json"
grep -q '"stale_calibration_ignored": true' "${TMP_DIR}/artifact/result.json"
grep -q '"runtime_success_overrode_weak_prior": true' "${TMP_DIR}/artifact/result.json"
grep -q '"high_confidence_fail_closed_hard_block": true' "${TMP_DIR}/artifact/result.json"
grep -q '"android_status": "DEFERRED_OPTIONAL_PLATFORM_REACH"' "${TMP_DIR}/artifact/result.json"
grep -q '"phase_d_exit_claimed": false' "${TMP_DIR}/artifact/result.json"
grep -q '"event_code":"external_calibration_applied"' "${TMP_DIR}/artifact/runtime-events.jsonl"
grep -q '"event_code":"brain_select_order_explained"' "${TMP_DIR}/artifact/runtime-events.jsonl"
grep -q '"reward_selected_order"' "${TMP_DIR}/artifact/calibrated-trace.json"
grep -q '"belief_source": "l1_l2_l3_adaptive_posterior"' "${TMP_DIR}/artifact/calibrated-trace.json"
grep -q '"belief_hard_blocked": true' "${TMP_DIR}/artifact/hard-block-trace.json"
test -s "${TMP_DIR}/artifact/external-calibration-snapshot.json"
test -s "${TMP_DIR}/artifact/README.md"

echo "ok"
