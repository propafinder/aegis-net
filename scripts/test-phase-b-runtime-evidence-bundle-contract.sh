#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-b-runtime-bundle.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/baseline-ready.json" <<'JSON'
{"event":"phase_b_baseline_review","status":"BASELINE_READY","acceptance_degraded":false,"reasons":[]}
JSON

cat >"${TMP_DIR}/runtime-events-pass.jsonl" <<'JSONL'
{"event_code":"relay_session_started","relay_surface_profile_id":"browser_like_balanced","relay_surface_write_chunk_size":16384,"relay_surface_inter_chunk_delay_ms":0,"relay_surface_tls_profile_target_class":"https_ws","relay_surface_tls_profile_target_alpn":["h2","http/1.1"]}
{"event_code":"relay_transport_selected","transport":"LegacyTls","relay_surface_profile_id":"mobile_safari_tight","relay_surface_write_chunk_size":6144,"relay_surface_inter_chunk_delay_ms":3,"relay_surface_tls_profile_target_class":"legacy_tls","relay_surface_tls_profile_target_alpn":["http/1.1"],"relay_surface_tls_wire_adapter":"legacy_tls_target_http11","relay_surface_tls_wire_alpn":["http/1.1"]}
{"event_code":"direct_active_stall_probe_launched","planned_probe_preferred_ttl":64,"planned_probe_budget":2,"planned_probe_ttl_candidates":[64,128],"target":"example.com","port":443}
{"event_code":"direct_active_stall_probe_finished","probe_outcome_class":"path_freeze","observation_contract":"capture_backed","capture_status":"CaptureBacked","planned_probe_preferred_ttl":64,"planned_probe_budget":2,"planned_probe_ttl_candidates":[64,128],"latency_ms":27,"target":"example.com","port":443}
JSONL

cat >"${TMP_DIR}/runtime-events-nested-pass.jsonl" <<'JSONL'
{"event_code":"relay_session_started","fields":{"relay_surface_profile_id":"browser_like_balanced","relay_surface_write_chunk_size":16384,"relay_surface_inter_chunk_delay_ms":0,"relay_surface_tls_profile_target_class":"https_ws","relay_surface_tls_profile_target_alpn":["h2","http/1.1"]}}
{"event_code":"relay_transport_selected","fields":{"transport":"GrpcStream","relay_surface_profile_id":"desktop_chrome_streaming","relay_surface_write_chunk_size":16384,"relay_surface_inter_chunk_delay_ms":0,"relay_surface_tls_profile_target_class":"https_ws","relay_surface_tls_profile_target_alpn":["h2","http/1.1"],"relay_surface_tls_wire_adapter":"grpc_h2_fixed","relay_surface_tls_wire_alpn":["h2"]}}
{"event_code":"direct_active_stall_probe_finished","fields":{"probe_outcome_class":"path_freeze","observation_contract":"capture_backed","capture_status":"CaptureBacked","planned_probe_preferred_ttl":64,"planned_probe_budget":2,"planned_probe_ttl_candidates":[64,128],"latency_ms":27,"target":"example.com","port":443}}
JSONL

bash scripts/build-phase-b-runtime-evidence-bundle.sh \
  --baseline-json "${TMP_DIR}/baseline-ready.json" \
  --runtime-events-jsonl "${TMP_DIR}/runtime-events-pass.jsonl" \
  --output-dir "${TMP_DIR}/bundle" \
  --require-relay-shape-diversity \
  --require-finished-probe

grep -q '"status": "PASS"' "${TMP_DIR}/bundle/phase-b-tls-wire-review.json"
grep -q '"status": "PASS"' "${TMP_DIR}/bundle/phase-b-relay-shape-review.json"
grep -q '"status": "PASS"' "${TMP_DIR}/bundle/phase-b-active-probe-review.json"
grep -q '"status": "LIVE_EVIDENCE_READY"' "${TMP_DIR}/bundle/phase-b-live-evidence-review.json"
grep -q '"status": "BUNDLE_READY"' "${TMP_DIR}/bundle/phase-b-runtime-evidence.manifest.json"
grep -q 'Phase B Runtime Evidence Manifest' "${TMP_DIR}/bundle/phase-b-runtime-evidence.manifest.md"
cargo run -q -p aegis-measure -- phase-b-runtime-evidence-manifest-check \
  --manifest-json "${TMP_DIR}/bundle/phase-b-runtime-evidence.manifest.json"
grep -q '"status": "PHASE_B_RUNTIME_EVIDENCE_READY"' "${TMP_DIR}/bundle/phase-b-master-plan-status.json"
grep -q '"phase_b_exit_status": "EXIT_NOT_CLAIMED"' "${TMP_DIR}/bundle/phase-b-master-plan-status.json"
grep -q 'Phase B Master Plan Status' "${TMP_DIR}/bundle/phase-b-master-plan-status.md"

bash scripts/build-phase-b-runtime-evidence-bundle.sh \
  --baseline-json "${TMP_DIR}/baseline-ready.json" \
  --runtime-events-jsonl "${TMP_DIR}/runtime-events-nested-pass.jsonl" \
  --output-dir "${TMP_DIR}/bundle-nested"
grep -q '"status": "PASS"' "${TMP_DIR}/bundle-nested/phase-b-tls-wire-review.json"
grep -q '"status": "PASS"' "${TMP_DIR}/bundle-nested/phase-b-relay-shape-review.json"

mkdir -p "${TMP_DIR}/artifact-dir-mode"
cp "${TMP_DIR}/baseline-ready.json" "${TMP_DIR}/artifact-dir-mode/phase-b-baseline-review.json"
cp "${TMP_DIR}/runtime-events-pass.jsonl" "${TMP_DIR}/artifact-dir-mode/runtime-events.jsonl"
bash scripts/build-phase-b-runtime-evidence-bundle.sh \
  --artifact-dir "${TMP_DIR}/artifact-dir-mode" \
  --require-relay-shape-diversity \
  --require-finished-probe >/dev/null
grep -q '"status": "LIVE_EVIDENCE_READY"' \
  "${TMP_DIR}/artifact-dir-mode/phase-b-runtime-evidence/phase-b-live-evidence-review.json"
grep -q '"artifact_dir":' \
  "${TMP_DIR}/artifact-dir-mode/phase-b-runtime-evidence/phase-b-runtime-evidence.manifest.json"
cargo run -q -p aegis-measure -- phase-b-runtime-evidence-manifest-check \
  --manifest-json "${TMP_DIR}/artifact-dir-mode/phase-b-runtime-evidence/phase-b-runtime-evidence.manifest.json"
grep -q '"status": "PHASE_B_RUNTIME_EVIDENCE_READY"' \
  "${TMP_DIR}/artifact-dir-mode/phase-b-runtime-evidence/phase-b-master-plan-status.json"

cat >"${TMP_DIR}/runtime-events-fail.jsonl" <<'JSONL'
{"event_code":"relay_transport_selected","transport":"LegacyTls","relay_surface_profile_id":"bad_shape","relay_surface_write_chunk_size":16,"relay_surface_inter_chunk_delay_ms":500,"relay_surface_tls_profile_target_class":"legacy_tls","relay_surface_tls_profile_target_alpn":["http/1.1"],"relay_surface_tls_wire_adapter":"legacy_tls_default","relay_surface_tls_wire_alpn":[]}
{"event_code":"direct_active_stall_probe_launched","planned_probe_preferred_ttl":64,"planned_probe_budget":2,"planned_probe_ttl_candidates":[64,128],"target":"example.com","port":443}
JSONL

if bash scripts/build-phase-b-runtime-evidence-bundle.sh \
  --baseline-json "${TMP_DIR}/baseline-ready.json" \
  --runtime-events-jsonl "${TMP_DIR}/runtime-events-fail.jsonl" \
  --output-dir "${TMP_DIR}/bundle-fail" \
  --require-finished-probe >/dev/null 2>&1; then
  echo "expected Phase B runtime evidence bundle failure" >&2
  exit 1
fi
grep -q '"status": "FAIL"' "${TMP_DIR}/bundle-fail/phase-b-tls-wire-review.json"
if [[ -f "${TMP_DIR}/bundle-fail/phase-b-runtime-evidence.manifest.json" ]]; then
  echo "blocked bundle should stop before ready manifest" >&2
  exit 1
fi

bash scripts/build-phase-b-runtime-evidence-bundle.sh \
  --baseline-json "${TMP_DIR}/baseline-ready.json" \
  --runtime-events-jsonl "${TMP_DIR}/runtime-events-fail.jsonl" \
  --output-dir "${TMP_DIR}/bundle-blocked" \
  --require-finished-probe \
  --allow-review-failures >/dev/null
grep -q '"status": "BUNDLE_BLOCKED"' "${TMP_DIR}/bundle-blocked/phase-b-runtime-evidence.manifest.json"
grep -q '"status": "PHASE_B_RUNTIME_EVIDENCE_BLOCKED"' "${TMP_DIR}/bundle-blocked/phase-b-master-plan-status.json"

echo "PASS: Phase B runtime evidence bundle contract"
