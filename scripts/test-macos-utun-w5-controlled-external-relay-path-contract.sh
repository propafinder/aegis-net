#!/usr/bin/env bash
set -euo pipefail

# Independent fixture reference; the original native/evidence assertions remain unchanged.
export AEGIS_RELAY_IP="192.0.2.20"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-macos-utun-w5.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/route" "${TMP_DIR}/w4" "${TMP_DIR}/phase-c" "${TMP_DIR}/out"

cat >"${TMP_DIR}/route/result.json" <<'JSON'
{
  "schema_version": 1,
  "artifact": "macos-utun-w1-controlled-route-proof-lab",
  "status": "PASS",
  "verdict": "PASS",
  "packet_loop_pass": true,
  "route_proof_pass": true,
  "controlled_peer": "1.1.1.1",
  "controlled_route_prefix": "/32",
  "relay_ip": "198.51.100.229",
  "relay_ip_excluded_from_utun": true,
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "dns_claimed": false,
  "udp_claimed": false,
  "ipv6_claimed": false
}
JSON
cat >"${TMP_DIR}/route/route-proof.json" <<'JSON'
{
  "schema_version": 1,
  "artifact": "macos-utun-w1-controlled-ipv4-route-proof",
  "status": "PASS",
  "verdict": "PASS",
  "scope": "LAB_CONTROLLED_IPV4_32_ROUTE_ONLY",
  "ifname": "utun5",
  "controlled_peer": "1.1.1.1",
  "relay_ip": "198.51.100.229",
  "controlled_route_prefix": "/32",
  "controlled_route_present": true,
  "relay_ip_excluded_from_utun": true,
  "controlled_route_removed_after_cleanup": true,
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "dns_claimed": false,
  "udp_claimed": false,
  "ipv6_claimed": false,
  "routes_before": "Routing tables\n\nInternet:\ndefault 192.168.1.1 UGScg en0\n",
  "routes_after_add": "Routing tables\n\nInternet:\ndefault 192.168.1.1 UGScg en0\n1.1.1.1 utun5 UHS utun5\n",
  "routes_after_cleanup": "Routing tables\n\nInternet:\ndefault 192.168.1.1 UGScg en0\n"
}
JSON
cat >"${TMP_DIR}/route/runtime-events.jsonl" <<'JSONL'
{"event_code":"macos_utun_packet_observed","fields":{"scope":"lab_controlled_utun_w0","ifname":"utun5","address_family":2,"ip_version":4}}
{"event_code":"macos_utun_cleanup_completed","fields":{"scope":"lab_controlled_utun_w0","aegis_owned_route_only":true}}
JSONL

cat >"${TMP_DIR}/w4/result.json" <<'JSON'
{
  "schema_version": 1,
  "artifact": "macos-utun-w4-policy-cleanup-matrix-lab",
  "status": "PASS",
  "verdict": "PASS",
  "tcp_ipv4_controlled_route_relay_bridge_pass": true,
  "policy_matrix_explicit": true,
  "relay_ip_exclusion_verified": true,
  "default_route_changed": false,
  "cleanup_only_aegis_owned_state": true,
  "cleanup_restores_baseline_route_state": true,
  "cleanup_after_simulated_helper_client_stop_verified": true,
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "dns_claimed": false,
  "udp_claimed": false,
  "ipv6_claimed": false,
  "network_extension_claimed": false,
  "product_ready_claim": false
}
JSON

cat >"${TMP_DIR}/phase-c/result.json" <<'JSON'
{
  "schema_version": 1,
  "artifact": "phase-c-cloudflare-https-ws-fronted-live",
  "status": "PASS",
  "verdict": "PASS",
  "provider_type": "cloudflare_http_proxy",
  "front_authority": "example.com",
  "transport_scope": "https_ws",
  "selected_transport": "HttpsWs",
  "aegis_relay_session_status": "PASS",
  "socks_egress_status": "PASS",
  "socks_egress_detail": "198.51.100.229",
  "cloudflare_tls_status": "PASS"
}
JSON
cat >"${TMP_DIR}/phase-c/runtime-events.jsonl" <<'JSONL'
{"event_code":"relay_session_succeeded","fields":{"chosen_transport":"HttpsWs","relay_server":"example.com:443"}}
JSONL

AEGIS_UTUN_W5_USE_EXISTING_ROUTE_ARTIFACT=true \
  AEGIS_UTUN_W5_ROUTE_ARTIFACT="${TMP_DIR}/route" \
  AEGIS_UTUN_W4_ARTIFACT="${TMP_DIR}/w4" \
  AEGIS_PHASE_C_HTTPS_WS_ARTIFACT="${TMP_DIR}/phase-c" \
  bash "${ROOT}/scripts/run-macos-utun-w5-controlled-external-relay-path.sh" "${TMP_DIR}/out"

grep -q '"artifact": "macos-utun-w5-controlled-external-relay-path-lab"' "${TMP_DIR}/out/result.json"
grep -q '"verdict": "PASS"' "${TMP_DIR}/out/result.json"
grep -q '"baseline_direct_route_recorded": true' "${TMP_DIR}/out/result.json"
grep -q '"relay_ip_exclusion_recorded": true' "${TMP_DIR}/out/result.json"
grep -q '"aegis_owned_32_route_added": true' "${TMP_DIR}/out/result.json"
grep -q '"packet_loop_observed": true' "${TMP_DIR}/out/result.json"
grep -q '"relay_session_succeeded": true' "${TMP_DIR}/out/result.json"
grep -q '"selected_transport": "HttpsWs"' "${TMP_DIR}/out/result.json"
grep -q '"external_egress_proof_collected": true' "${TMP_DIR}/out/result.json"
grep -q '"macos_utun_external_relay_path_succeeded_event": true' "${TMP_DIR}/out/result.json"
grep -q '"baseline_route_restored": true' "${TMP_DIR}/out/result.json"
grep -q '"default_route_untouched": true' "${TMP_DIR}/out/result.json"
grep -q '"broad_system_wide_claim": false' "${TMP_DIR}/out/result.json"
grep -q '"dns_claimed": false' "${TMP_DIR}/out/result.json"
grep -q '"udp_claimed": false' "${TMP_DIR}/out/result.json"
grep -q '"ipv6_claimed": false' "${TMP_DIR}/out/result.json"
grep -q '"network_extension_claimed": false' "${TMP_DIR}/out/result.json"
grep -q '"event_code":"macos_utun_external_relay_path_succeeded"' "${TMP_DIR}/out/runtime-events.jsonl"

cp "${TMP_DIR}/route/result.json" "${TMP_DIR}/route/result.ok.json"
sed 's/"relay_ip_excluded_from_utun": true/"relay_ip_excluded_from_utun": false/' \
  "${TMP_DIR}/route/result.ok.json" >"${TMP_DIR}/route/result.json"
if AEGIS_UTUN_W5_USE_EXISTING_ROUTE_ARTIFACT=true \
  AEGIS_UTUN_W5_ROUTE_ARTIFACT="${TMP_DIR}/route" \
  AEGIS_UTUN_W4_ARTIFACT="${TMP_DIR}/w4" \
  AEGIS_PHASE_C_HTTPS_WS_ARTIFACT="${TMP_DIR}/phase-c" \
  bash "${ROOT}/scripts/run-macos-utun-w5-controlled-external-relay-path.sh" "${TMP_DIR}/out-fail"; then
  echo "expected missing relay IP exclusion to fail W5" >&2
  exit 1
fi
grep -q '"failure_classification": "RELAY_IP_EXCLUSION_FAILED"' "${TMP_DIR}/out-fail/result.json"

echo "ok"
