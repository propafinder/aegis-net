#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-stealth-hostile-path-acceptance-summary.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-stealth-hostile-path.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/wire-host-acceptance-summary.json" <<'EOF'
{
  "artifact_schema": "wire_mimicry_host_acceptance_v1",
  "product_verdict": "green",
  "acceptance_status": "passed",
  "hostile_path_support_ready": true,
  "hostile_path_support_tier": "wire_level_supported_hostile_path",
  "independent_witness_correlation_status": "matched",
  "active_runtime_records_with_required_ready_fields": 1,
  "active_runtime_records_missing_required_ready_fields": 0
}
EOF

cat > "${TMP_DIR}/stealth-polymorphism-acceptance-summary.json" <<'EOF'
{
  "artifact_schema": "stealth_polymorphism_acceptance_summary_v1",
  "verdict": "green",
  "status": "acceptance_green",
  "checks": {
    "direct_window_stability": true,
    "relay_catalog_and_path_coverage": true,
    "cross_layer_independence": true
  }
}
EOF

cat > "${TMP_DIR}/relay-surface-runtime-summary.json" <<'EOF'
{
  "artifact_schema": "relay_surface_runtime_summary_v1",
  "verdict": "green",
  "status": "runtime_surface_green",
  "relay_events_scanned": 4,
  "relay_events_with_complete_surface": 4,
  "relay_events_missing_surface": 0,
  "checks": {
    "relay_session_started_observed": true,
    "relay_transport_selected_observed": true,
    "terminal_relay_outcome_observed": true,
    "surface_fields_complete_on_all_relay_events": true
  }
}
EOF

cat > "${TMP_DIR}/runtime-events.jsonl" <<'EOF'
{"event_code":"relay_session_started","ts_unix_ms":1710000000000,"fields":{"target":"example.com","port":443,"transport":"websocket","relay_session_kind":"relay_tunnel","relay_surface_profile_id":"browser_like_balanced","relay_surface_websocket_path":"/ws","relay_surface_grpc_path":"/rpc.TunnelService/Connect","relay_surface_masque_path":"/.well-known/masque/udp/example","relay_surface_accept_language":"en-US,en;q=0.9","relay_surface_cache_control":"max-age=0","relay_surface_websocket_origin":"https://example.com","relay_surface_grpc_accept_encoding":"identity","relay_surface_grpc_encoding":"identity","relay_surface_grpc_timeout":"15S","relay_surface_grpc_message_type":"TunnelRequest","relay_surface_masque_alt_used":"example.com"}}
{"event_code":"relay_transport_selected","ts_unix_ms":1710000000100,"fields":{"target":"example.com","port":443,"chosen_transport":"grpc","relay_session_kind":"relay_tunnel","relay_surface_profile_id":"browser_like_balanced","relay_surface_websocket_path":"/ws","relay_surface_grpc_path":"/rpc.TunnelService/Connect","relay_surface_masque_path":"/.well-known/masque/udp/example","relay_surface_accept_language":"en-US,en;q=0.9","relay_surface_cache_control":"max-age=0","relay_surface_websocket_origin":"https://example.com","relay_surface_grpc_accept_encoding":"identity","relay_surface_grpc_encoding":"identity","relay_surface_grpc_timeout":"15S","relay_surface_grpc_message_type":"TunnelRequest","relay_surface_masque_alt_used":"example.com"}}
{"event_code":"relay_session_succeeded","ts_unix_ms":1710000000200,"fields":{"target":"example.com","port":443,"transport":"masque","relay_session_kind":"relay_tunnel","relay_surface_profile_id":"browser_like_balanced","relay_surface_websocket_path":"/ws","relay_surface_grpc_path":"/rpc.TunnelService/Connect","relay_surface_masque_path":"/.well-known/masque/udp/example","relay_surface_accept_language":"en-US,en;q=0.9","relay_surface_cache_control":"max-age=0","relay_surface_websocket_origin":"https://example.com","relay_surface_grpc_accept_encoding":"identity","relay_surface_grpc_encoding":"identity","relay_surface_grpc_timeout":"15S","relay_surface_grpc_message_type":"TunnelRequest","relay_surface_masque_alt_used":"example.com"}}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out" \
  --wire-acceptance-summary "${TMP_DIR}/wire-host-acceptance-summary.json" \
  --polymorphism-acceptance-summary "${TMP_DIR}/stealth-polymorphism-acceptance-summary.json" \
  --relay-surface-runtime-summary "${TMP_DIR}/relay-surface-runtime-summary.json" >/dev/null

bash "${SCRIPT}" "${TMP_DIR}/out-auto-runtime" \
  --wire-acceptance-summary "${TMP_DIR}/wire-host-acceptance-summary.json" \
  --polymorphism-acceptance-summary "${TMP_DIR}/stealth-polymorphism-acceptance-summary.json" \
  --runtime-events "${TMP_DIR}/runtime-events.jsonl" >/dev/null

bash "${SCRIPT}" "${TMP_DIR}/out-no-runtime" \
  --wire-acceptance-summary "${TMP_DIR}/wire-host-acceptance-summary.json" \
  --polymorphism-acceptance-summary "${TMP_DIR}/stealth-polymorphism-acceptance-summary.json" >/dev/null

PAYLOAD_JSON="${TMP_DIR}/out/stealth-hostile-path-acceptance-summary.json"
OUTPUT_MD="${TMP_DIR}/out/stealth-hostile-path-acceptance-summary.md"
LEGACY_JSON="${TMP_DIR}/out-no-runtime/stealth-hostile-path-acceptance-summary.json"
AUTO_JSON="${TMP_DIR}/out-auto-runtime/stealth-hostile-path-acceptance-summary.json"
AUTO_RUNTIME_JSON="${TMP_DIR}/out-auto-runtime/relay-surface-runtime/relay-surface-runtime-summary.json"

jq -e '
  .artifact_schema == "stealth_hostile_path_acceptance_summary_v1"
  and .verdict == "green"
  and .status == "ready_for_runtime_surface_hostile_path_validation"
  and .wire.product_verdict == "green"
  and .wire.hostile_path_support_tier == "wire_level_supported_hostile_path"
  and .wire.independent_witness_correlation_status == "matched"
  and .polymorphism.verdict == "green"
  and .relay_surface_runtime.verdict == "green"
  and .relay_surface_runtime.relay_events_scanned == 4
  and .combined_requirements.live_wire_green == true
  and .combined_requirements.wire_hostile_path_ready == true
  and .combined_requirements.independent_witness_matched == true
  and .combined_requirements.repo_side_polymorphism_green == true
  and .combined_requirements.runtime_relay_surface_green == true
  and .next_action == "open_runtime_surface_correlated_transport_camouflage_validation"
' "${PAYLOAD_JSON}" >/dev/null

jq -e '
  .status == "ready_for_runtime_surface_hostile_path_validation"
  and (.relay_surface_runtime_summary_json | endswith("relay-surface-runtime/relay-surface-runtime-summary.json"))
  and .combined_requirements.runtime_relay_surface_green == true
' "${AUTO_JSON}" >/dev/null

jq -e '.verdict == "green"' "${AUTO_RUNTIME_JSON}" >/dev/null

jq -e '
  .status == "ready_for_transport_camouflage_live_acceptance"
  and .combined_requirements.runtime_relay_surface_green == null
' "${LEGACY_JSON}" >/dev/null

grep -Fq -- "Stealth Hostile-Path Acceptance" "${OUTPUT_MD}"
grep -Fq -- "- Verdict: \`green\`" "${OUTPUT_MD}"
grep -Fq -- "- \`live_wire_green\`: \`true\`" "${OUTPUT_MD}"
grep -Fq -- "- Witness correlation: \`matched\`" "${OUTPUT_MD}"
grep -Fq -- "- Runtime relay surface verdict: \`green\`" "${OUTPUT_MD}"

echo "stealth hostile-path acceptance summary contract: ok"
