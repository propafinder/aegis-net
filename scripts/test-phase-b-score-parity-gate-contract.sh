#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-b-score-parity.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/baseline.json" <<'JSON'
{
  "status": "BASELINE_READY",
  "acceptance_degraded": false,
  "witness": [
    {"transport":"legacy_tls","combined_avg":1.0,"status":"PASS"},
    {"transport":"https_ws","combined_avg":0.92,"status":"PASS"},
    {"transport":"masque_derived","combined_avg":0.9,"status":"PASS"}
  ],
  "adversarial": [
    {"transport":"legacy_tls","measured":4,"pass_rate":1.0,"status":"PASS"},
    {"transport":"https_ws","measured":4,"pass_rate":0.95,"status":"PASS"},
    {"transport":"masque_derived","measured":4,"pass_rate":0.9,"status":"PASS"}
  ]
}
JSON

cat >"${TMP_DIR}/runtime-manifest.json" <<'JSON'
{
  "status": "BUNDLE_READY",
  "acceptance_degraded": false,
  "reviews": {
    "tls_wire": {"status":"PASS","checked_events":15},
    "relay_shape": {"status":"PASS","checked_events":21,"require_diversity":true},
    "active_probe": {"status":"PASS","counts":{"finished":2}},
    "live_evidence": {"status":"LIVE_EVIDENCE_READY","acceptance_degraded":false}
  }
}
JSON

cat >"${TMP_DIR}/transport-ready.json" <<'JSON'
{
  "status": "READY",
  "next_action": "open_next_phase_b_score_and_parity_gate",
  "blockers": [],
  "checks": {
    "hostile_classifier_pass": true,
    "witness_pcap_present": true
  }
}
JSON

cat >"${TMP_DIR}/wire-correlation.json" <<'JSON'
{
  "product_verdict": "green",
  "acceptance_status": "passed",
  "hostile_path_support_ready": true,
  "independent_witness_correlation_status": "matched",
  "independent_witness_records_matched": 1
}
JSON

cat >"${TMP_DIR}/two-vps-parity.json" <<'JSON'
{
  "status": "PASS",
  "transport_scope": "http_like",
  "transport_priority": ["https_ws", "grpc_stream", "masque_derived"],
  "legacy_tls_included": false,
  "server": {"host":"198.51.100.22", "platform":"ubuntu-22.04"},
  "client": {"host":"198.51.100.77", "platform":"debian-12"}
}
JSON

cat >"${TMP_DIR}/classifier-summary.json" <<'JSON'
{
  "status": "PASS",
  "acceptance_degraded": false,
  "classifier_records": 2,
  "classifiers": ["ndpi", "suricata"],
  "verdict_counts": {"pass":2, "fail":0, "unknown":0}
}
JSON

cat >"${TMP_DIR}/live-manifest.json" <<'JSON'
{
  "server_host": "198.51.100.22",
  "client_host": "198.51.100.77",
  "acceptance_overview": {"overall_status":"acceptance_green"},
  "wire_host_acceptance_product_verdict": "green",
  "wire_host_acceptance_status": "passed",
  "wire_host_acceptance_witness_correlation_status": "matched",
  "stealth_live_acceptance_bundle_verdict": "green",
  "stealth_live_acceptance_bundle_status": "ready_for_runtime_surface_hostile_path_validation"
}
JSON

bash "${ROOT}/scripts/build-phase-b-score-parity-gate.sh" \
  --baseline-json "${TMP_DIR}/baseline.json" \
  --runtime-manifest-json "${TMP_DIR}/runtime-manifest.json" \
  --transport-camouflage-validation-json "${TMP_DIR}/transport-ready.json" \
  --witness-wire-correlation-json "${TMP_DIR}/wire-correlation.json" \
  --two-vps-parity-json "${TMP_DIR}/two-vps-parity.json" \
  --classifier-summary-json "${TMP_DIR}/classifier-summary.json" \
  --live-manifest-json "${TMP_DIR}/live-manifest.json" \
  --output-json "${TMP_DIR}/ready.json" \
  --output-markdown "${TMP_DIR}/ready.md"

grep -q '"status": "PHASE_B_SCORE_PARITY_READY"' "${TMP_DIR}/ready.json"
grep -q '"phase_b_exit_status": "EXIT_READY"' "${TMP_DIR}/ready.json"
grep -q '"formula_override": false' "${TMP_DIR}/ready.json"
grep -q '"legacy_tls_excluded_from_http_like_gate": true' "${TMP_DIR}/ready.json"
grep -q 'Phase B Score And Parity Gate' "${TMP_DIR}/ready.md"

cat >"${TMP_DIR}/missing-platform-parity.json" <<'JSON'
{
  "status": "PASS",
  "transport_scope": "http_like",
  "transport_priority": ["https_ws", "grpc_stream", "masque_derived"],
  "legacy_tls_included": false,
  "server": {"host":"198.51.100.22"},
  "client": {"host":"198.51.100.77"}
}
JSON

if bash "${ROOT}/scripts/build-phase-b-score-parity-gate.sh" \
  --baseline-json "${TMP_DIR}/baseline.json" \
  --runtime-manifest-json "${TMP_DIR}/runtime-manifest.json" \
  --transport-camouflage-validation-json "${TMP_DIR}/transport-ready.json" \
  --witness-wire-correlation-json "${TMP_DIR}/wire-correlation.json" \
  --two-vps-parity-json "${TMP_DIR}/missing-platform-parity.json" \
  --classifier-summary-json "${TMP_DIR}/classifier-summary.json" \
  --live-manifest-json "${TMP_DIR}/live-manifest.json" \
  --output-json "${TMP_DIR}/missing-platform.json"; then
  echo "expected missing platform evidence to block" >&2
  exit 1
fi
grep -q 'server_client_platform_evidence_missing' "${TMP_DIR}/missing-platform.json"

cat >"${TMP_DIR}/low-score-baseline.json" <<'JSON'
{
  "status": "BASELINE_READY",
  "acceptance_degraded": false,
  "witness": [
    {"transport":"legacy_tls","combined_avg":0.69,"status":"PASS"},
    {"transport":"https_ws","combined_avg":0.92,"status":"PASS"},
    {"transport":"masque_derived","combined_avg":0.9,"status":"PASS"}
  ],
  "adversarial": [
    {"transport":"legacy_tls","measured":4,"pass_rate":1.0,"status":"PASS"},
    {"transport":"https_ws","measured":4,"pass_rate":0.84,"status":"PASS"},
    {"transport":"masque_derived","measured":4,"pass_rate":0.9,"status":"PASS"}
  ]
}
JSON

if bash "${ROOT}/scripts/build-phase-b-score-parity-gate.sh" \
  --baseline-json "${TMP_DIR}/low-score-baseline.json" \
  --runtime-manifest-json "${TMP_DIR}/runtime-manifest.json" \
  --transport-camouflage-validation-json "${TMP_DIR}/transport-ready.json" \
  --witness-wire-correlation-json "${TMP_DIR}/wire-correlation.json" \
  --two-vps-parity-json "${TMP_DIR}/two-vps-parity.json" \
  --classifier-summary-json "${TMP_DIR}/classifier-summary.json" \
  --live-manifest-json "${TMP_DIR}/live-manifest.json" \
  --output-json "${TMP_DIR}/low-score.json"; then
  echo "expected low score evidence to block" >&2
  exit 1
fi
grep -q 'phase_b_score_targets_not_met' "${TMP_DIR}/low-score.json"
grep -q 'tune_mimicry_scores_without_manual_weight_override' "${TMP_DIR}/low-score.json"

cat >"${TMP_DIR}/legacy-included-parity.json" <<'JSON'
{
  "status": "PASS",
  "transport_scope": "http_like",
  "transport_priority": ["https_ws", "grpc_stream", "legacy_tls", "masque_derived"],
  "legacy_tls_included": true,
  "server": {"host":"198.51.100.22", "platform":"ubuntu-22.04"},
  "client": {"host":"198.51.100.77", "platform":"debian-12"}
}
JSON

if bash "${ROOT}/scripts/build-phase-b-score-parity-gate.sh" \
  --baseline-json "${TMP_DIR}/baseline.json" \
  --runtime-manifest-json "${TMP_DIR}/runtime-manifest.json" \
  --transport-camouflage-validation-json "${TMP_DIR}/transport-ready.json" \
  --witness-wire-correlation-json "${TMP_DIR}/wire-correlation.json" \
  --two-vps-parity-json "${TMP_DIR}/legacy-included-parity.json" \
  --classifier-summary-json "${TMP_DIR}/classifier-summary.json" \
  --live-manifest-json "${TMP_DIR}/live-manifest.json" \
  --output-json "${TMP_DIR}/legacy-included.json"; then
  echo "expected LegacyTls in HTTP-like scope to block" >&2
  exit 1
fi
grep -q 'legacy_tls_counted_in_http_like_camouflage_gate' "${TMP_DIR}/legacy-included.json"

cat >"${TMP_DIR}/classifier-degraded.json" <<'JSON'
{
  "status": "FAIL",
  "acceptance_degraded": true,
  "classifier_records": 2,
  "classifiers": ["ndpi", "suricata"],
  "verdict_counts": {"pass":1, "fail":1, "unknown":0}
}
JSON

if bash "${ROOT}/scripts/build-phase-b-score-parity-gate.sh" \
  --baseline-json "${TMP_DIR}/baseline.json" \
  --runtime-manifest-json "${TMP_DIR}/runtime-manifest.json" \
  --transport-camouflage-validation-json "${TMP_DIR}/transport-ready.json" \
  --witness-wire-correlation-json "${TMP_DIR}/wire-correlation.json" \
  --two-vps-parity-json "${TMP_DIR}/two-vps-parity.json" \
  --classifier-summary-json "${TMP_DIR}/classifier-degraded.json" \
  --live-manifest-json "${TMP_DIR}/live-manifest.json" \
  --output-json "${TMP_DIR}/classifier-degraded-out.json"; then
  echo "expected degraded classifier summary to block" >&2
  exit 1
fi
grep -q 'hostile_classifier_summary_not_pass' "${TMP_DIR}/classifier-degraded-out.json"
grep -q 'degraded_or_blocked_evidence_present' "${TMP_DIR}/classifier-degraded-out.json"

echo "ok"
