#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-brain-operational-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

bash "${ROOT}/scripts/run-brain-operational-live-calibrated-transport-proof.sh" "${TMP_DIR}/artifact"

python3 - "${TMP_DIR}/artifact" <<'PY'
import json
import pathlib
import sys

artifact = pathlib.Path(sys.argv[1])
result = json.loads((artifact / "result.json").read_text())
assert result["artifact"] == "brain-operational-live-calibrated-transport-proof", result
assert result["verdict"] == "PASS", result
assert result["completion_claim_allowed"] is False, result
assert result["full_aegis_completion_claimed"] is False, result
assert result["mimicry_reference_maturity_status"] == "PARTIAL_UNCHANGED", result
assert result["runtime_log_mode"] == "explicit_diagnostics_synthetic_fixture", result
checks = result["checks"]
for key in [
    "calibration_snapshot_penalizes_legacy_tls_and_prefers_http_like",
    "client_loads_calibration",
    "external_calibration_applied_event_present",
    "strategy_score_explanation_present",
    "calibrated_order_applied",
    "selected_transport_matches_calibrated_expectation",
    "relay_session_succeeded_present",
    "socks_egress_proof_works",
    "stale_calibration_negative_ignored",
    "no_fallback_contamination",
    "stale_no_fallback_contamination",
]:
    assert checks[key] is True, (key, result)

calibrated = [
    json.loads(line)
    for line in (artifact / "calibrated-runtime-events.jsonl").read_text().splitlines()
    if line.strip()
]
stale = [
    json.loads(line)
    for line in (artifact / "stale-runtime-events.jsonl").read_text().splitlines()
    if line.strip()
]
codes = [event["event_code"] for event in calibrated]
assert "external_calibration_applied" in codes, codes
assert "brain_select_order_explained" in codes, codes
assert "relay_transport_selected" in codes, codes
assert "relay_session_succeeded" in codes, codes
assert "relay_transport_failed" not in codes, codes
stale_codes = [event["event_code"] for event in stale]
assert "brain_select_order_explained" in stale_codes, stale_codes
assert "relay_session_succeeded" in stale_codes, stale_codes
assert "relay_transport_failed" not in stale_codes, stale_codes
assert (artifact / "README.md").is_file()
assert (artifact / "client-calibrated.sanitized.toml").is_file()
PY

echo "ok"
