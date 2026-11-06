#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-relay-surface-runtime-summary.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-relay-surface-runtime.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/runtime-events.jsonl" <<'EOF'
{"event_code":"relay_session_started","ts_unix_ms":1710000000000,"fields":{"target":"example.com","port":443,"transport":"websocket","relay_session_kind":"relay_tunnel","relay_surface_profile_id":"browser_like_balanced","relay_surface_websocket_path":"/ws","relay_surface_grpc_path":"/rpc.TunnelService/Connect","relay_surface_masque_path":"/.well-known/masque/udp/example","relay_surface_accept_language":"en-US,en;q=0.9","relay_surface_cache_control":"max-age=0","relay_surface_websocket_origin":"https://example.com","relay_surface_grpc_accept_encoding":"identity","relay_surface_grpc_encoding":"identity","relay_surface_grpc_timeout":"15S","relay_surface_grpc_message_type":"TunnelRequest","relay_surface_masque_alt_used":"example.com"}}
{"event_code":"relay_transport_selected","ts_unix_ms":1710000000100,"fields":{"target":"example.com","port":443,"chosen_transport":"grpc","relay_session_kind":"relay_tunnel","relay_surface_profile_id":"browser_like_balanced","relay_surface_websocket_path":"/ws","relay_surface_grpc_path":"/rpc.TunnelService/Connect","relay_surface_masque_path":"/.well-known/masque/udp/example","relay_surface_accept_language":"en-US,en;q=0.9","relay_surface_cache_control":"max-age=0","relay_surface_websocket_origin":"https://example.com","relay_surface_grpc_accept_encoding":"identity","relay_surface_grpc_encoding":"identity","relay_surface_grpc_timeout":"15S","relay_surface_grpc_message_type":"TunnelRequest","relay_surface_masque_alt_used":"example.com"}}
{"event_code":"relay_session_succeeded","ts_unix_ms":1710000000200,"fields":{"target":"example.com","port":443,"transport":"masque","relay_session_kind":"relay_tunnel","relay_surface_profile_id":"browser_like_balanced","relay_surface_websocket_path":"/ws","relay_surface_grpc_path":"/rpc.TunnelService/Connect","relay_surface_masque_path":"/.well-known/masque/udp/example","relay_surface_accept_language":"en-US,en;q=0.9","relay_surface_cache_control":"max-age=0","relay_surface_websocket_origin":"https://example.com","relay_surface_grpc_accept_encoding":"identity","relay_surface_grpc_encoding":"identity","relay_surface_grpc_timeout":"15S","relay_surface_grpc_message_type":"TunnelRequest","relay_surface_masque_alt_used":"example.com"}}
EOF

bash "${SCRIPT}" "${TMP_DIR}/out" \
  --runtime-events "${TMP_DIR}/runtime-events.jsonl" >/dev/null

SUMMARY_JSON="${TMP_DIR}/out/relay-surface-runtime-summary.json"
SUMMARY_MD="${TMP_DIR}/out/relay-surface-runtime-summary.md"

jq -e '
  .artifact_schema == "relay_surface_runtime_summary_v1"
  and .verdict == "green"
  and .status == "runtime_surface_green"
  and .relay_events_scanned == 3
  and .relay_events_with_complete_surface == 3
  and .relay_events_missing_surface == 0
  and .checks.relay_session_started_observed == true
  and .checks.relay_transport_selected_observed == true
  and .checks.terminal_relay_outcome_observed == true
  and .checks.surface_fields_complete_on_all_relay_events == true
  and .relay_surface.profile_ids_seen == ["browser_like_balanced"]
  and .relay_surface.websocket_origin_variants_seen == ["https://example.com"]
  and .relay_surface.grpc_timeout_variants_seen == ["15S"]
  and .relay_surface.grpc_message_type_variants_seen == ["TunnelRequest"]
  and .relay_surface.masque_alt_used_variants_seen == ["example.com"]
  and .next_action == "use_runtime_surface_summary_in_live_hostile_path_validation"
' "${SUMMARY_JSON}" >/dev/null

grep -Fq -- "Relay Surface Runtime Summary" "${SUMMARY_MD}"
grep -Fq -- "- Verdict: \`green\`" "${SUMMARY_MD}"
grep -Fq -- "- \`surface_fields_complete_on_all_relay_events\`: \`true\`" "${SUMMARY_MD}"

echo "relay surface runtime summary contract: ok"
