#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-stealth-live-acceptance-bundle.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-stealth-live-bundle.XXXXXX")"
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

cat > "${TMP_DIR}/runtime-events.jsonl" <<'EOF'
{"event_code":"relay_session_started","ts_unix_ms":1710000000000,"fields":{"target":"example.com","port":443,"transport":"websocket","relay_session_kind":"relay_tunnel","relay_surface_profile_id":"browser_like_balanced","relay_surface_websocket_path":"/ws","relay_surface_grpc_path":"/rpc.TunnelService/Connect","relay_surface_masque_path":"/.well-known/masque/udp/example","relay_surface_accept_language":"en-US,en;q=0.9","relay_surface_cache_control":"max-age=0","relay_surface_websocket_origin":"https://example.com","relay_surface_grpc_accept_encoding":"identity","relay_surface_grpc_encoding":"identity","relay_surface_grpc_timeout":"15S","relay_surface_grpc_message_type":"TunnelRequest","relay_surface_masque_alt_used":"example.com"}}
{"event_code":"relay_transport_selected","ts_unix_ms":1710000000100,"fields":{"target":"example.com","port":443,"chosen_transport":"grpc","relay_session_kind":"relay_tunnel","relay_surface_profile_id":"browser_like_balanced","relay_surface_websocket_path":"/ws","relay_surface_grpc_path":"/rpc.TunnelService/Connect","relay_surface_masque_path":"/.well-known/masque/udp/example","relay_surface_accept_language":"en-US,en;q=0.9","relay_surface_cache_control":"max-age=0","relay_surface_websocket_origin":"https://example.com","relay_surface_grpc_accept_encoding":"identity","relay_surface_grpc_encoding":"identity","relay_surface_grpc_timeout":"15S","relay_surface_grpc_message_type":"TunnelRequest","relay_surface_masque_alt_used":"example.com"}}
{"event_code":"relay_session_succeeded","ts_unix_ms":1710000000200,"fields":{"target":"example.com","port":443,"transport":"masque","relay_session_kind":"relay_tunnel","relay_surface_profile_id":"browser_like_balanced","relay_surface_websocket_path":"/ws","relay_surface_grpc_path":"/rpc.TunnelService/Connect","relay_surface_masque_path":"/.well-known/masque/udp/example","relay_surface_accept_language":"en-US,en;q=0.9","relay_surface_cache_control":"max-age=0","relay_surface_websocket_origin":"https://example.com","relay_surface_grpc_accept_encoding":"identity","relay_surface_grpc_encoding":"identity","relay_surface_grpc_timeout":"15S","relay_surface_grpc_message_type":"TunnelRequest","relay_surface_masque_alt_used":"example.com"}}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out" \
  --wire-acceptance-summary "${TMP_DIR}/wire-host-acceptance-summary.json" \
  --runtime-events "${TMP_DIR}/runtime-events.jsonl" \
  --config "${ROOT}/config.example.toml" \
  --now-secs 10000 >/dev/null

cat > "${TMP_DIR}/wire-host-acceptance-summary-degraded.json" <<'EOF'
{
  "artifact_schema": "wire_mimicry_host_acceptance_v1",
  "product_verdict": "green",
  "acceptance_status": "passed",
  "hostile_path_support_ready": false,
  "hostile_path_support_tier": "not_proven",
  "independent_witness_correlation_status": "not_provided",
  "active_runtime_records_with_required_ready_fields": 1,
  "active_runtime_records_missing_required_ready_fields": 0
}
EOF

cat > "${TMP_DIR}/runtime-events-missing-surface.jsonl" <<'EOF'
{"event_code":"relay_session_started","ts_unix_ms":1710000000000,"fields":{"target":"example.com","port":443,"transport":"websocket","relay_session_kind":"relay_tunnel"}}
{"event_code":"relay_session_succeeded","ts_unix_ms":1710000000200,"fields":{"target":"example.com","port":443,"transport":"masque","relay_session_kind":"relay_tunnel"}}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out-degraded" \
  --wire-acceptance-summary "${TMP_DIR}/wire-host-acceptance-summary-degraded.json" \
  --runtime-events "${TMP_DIR}/runtime-events-missing-surface.jsonl" \
  --config "${ROOT}/config.example.toml" \
  --now-secs 10000 >/dev/null

PAYLOAD_JSON="${TMP_DIR}/out/stealth-live-acceptance-bundle.json"
MANIFEST_JSON="${TMP_DIR}/out/stealth-live-acceptance.manifest.json"
OUTPUT_MD="${TMP_DIR}/out/stealth-live-acceptance-bundle.md"
DEGRADED_JSON="${TMP_DIR}/out-degraded/stealth-live-acceptance-bundle.json"

jq -e '
  .artifact_schema == "stealth_live_acceptance_bundle_v1"
  and .bundle_verdict == "green"
  and .bundle_status == "ready_for_runtime_surface_hostile_path_validation"
  and .polymorphism.verdict == "green"
  and .relay_surface_runtime.verdict == "green"
  and .hostile_path_acceptance.verdict == "green"
  and (.relay_surface_runtime_summary_json | endswith("relay-surface-runtime-summary.json"))
  and .active_blockers == []
  and .primary_blocker == null
' "${PAYLOAD_JSON}" >/dev/null

for path in \
  "$(jq -r '.polymorphism_acceptance_summary_json' "${PAYLOAD_JSON}")" \
  "$(jq -r '.relay_surface_runtime_summary_json' "${PAYLOAD_JSON}")" \
  "$(jq -r '.stealth_hostile_path_acceptance_summary_json' "${PAYLOAD_JSON}")"; do
  if [[ ! -f "${path}" ]]; then
    echo "missing expected generated file: ${path}" >&2
    exit 1
  fi
done

jq -e '
  .artifact_schema == "stealth_live_acceptance_bundle_manifest_v1"
  and .bundle_verdict == "green"
  and .bundle_status == "ready_for_runtime_surface_hostile_path_validation"
  and .active_blockers == []
  and .primary_blocker == null
' "${MANIFEST_JSON}" >/dev/null

if [[ ! -f "$(jq -r '.bundle_json' "${MANIFEST_JSON}")" ]]; then
  echo "missing manifest bundle json target" >&2
  exit 1
fi

grep -Fq -- "Stealth Live Acceptance Bundle" "${OUTPUT_MD}"
grep -Fq -- "- Bundle verdict: \`green\`" "${OUTPUT_MD}"
grep -Fq -- "- Relay runtime verdict: \`green\`" "${OUTPUT_MD}"
grep -Fq -- "- \`none\`" "${OUTPUT_MD}"

jq -e '
  .bundle_verdict == "yellow"
  and .bundle_status == "blocked_on_multiple_acceptance_gaps"
  and .next_action == "resolve_active_acceptance_blockers_in_priority_order"
  and [.active_blockers[].id] == [
    "witness_correlated_hostile_path_proof",
    "runtime_relay_surface_evidence"
  ]
  and .primary_blocker.id == "witness_correlated_hostile_path_proof"
' "${DEGRADED_JSON}" >/dev/null

echo "stealth live acceptance bundle contract: ok"
