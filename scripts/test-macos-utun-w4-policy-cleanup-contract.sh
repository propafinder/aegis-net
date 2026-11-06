#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-macos-utun-w4.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/w1" "${TMP_DIR}/w2" "${TMP_DIR}/w3" "${TMP_DIR}/out"

cat >"${TMP_DIR}/w1/result.json" <<'JSON'
{
  "artifact": "macos-utun-w1-controlled-route-proof-lab",
  "verdict": "PASS",
  "route_proof_pass": true,
  "controlled_route_prefix": "/32",
  "relay_ip_excluded_from_utun": true,
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "dns_claimed": false,
  "udp_claimed": false,
  "ipv6_claimed": false
}
JSON
cat >"${TMP_DIR}/w1/route-proof.json" <<'JSON'
{
  "artifact": "macos-utun-w1-controlled-ipv4-route-proof",
  "verdict": "PASS",
  "relay_ip_excluded_from_utun": true,
  "controlled_route_removed_after_cleanup": true,
  "default_route_claim": false
}
JSON
cat >"${TMP_DIR}/w1/runtime-events.jsonl" <<'JSONL'
{"event_code":"macos_utun_cleanup_completed","fields":{"scope":"lab_controlled_utun_w1"}}
JSONL

cat >"${TMP_DIR}/w2/result.json" <<'JSON'
{
  "artifact": "macos-utun-w2-stateful-tcp-edge-proof-lab",
  "verdict": "PASS",
  "tcp_synack_lab_pass": true,
  "tcp_ack_observed": true,
  "relay_session_claimed": false
}
JSON
cat >"${TMP_DIR}/w2/runtime-events.jsonl" <<'JSONL'
{"event_code":"macos_utun_cleanup_completed","fields":{"scope":"lab_controlled_utun_w2"}}
JSONL

cat >"${TMP_DIR}/w3/result.json" <<'JSON'
{
  "artifact": "macos-utun-w3-local-relay-bridge-proof-lab",
  "verdict": "PASS",
  "relay_session_succeeded": true,
  "utun_to_relay_bridge_linkage_proven": true,
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "network_extension_claimed": false
}
JSON

AEGIS_UTUN_W1_ARTIFACT="${TMP_DIR}/w1" \
AEGIS_UTUN_W2_ARTIFACT="${TMP_DIR}/w2" \
AEGIS_UTUN_W3_ARTIFACT="${TMP_DIR}/w3" \
  bash "${ROOT}/scripts/run-macos-utun-w4-policy-cleanup-matrix.sh" "${TMP_DIR}/out"

grep -q '"artifact": "macos-utun-w4-policy-cleanup-matrix-lab"' "${TMP_DIR}/out/result.json"
grep -q '"verdict": "PASS"' "${TMP_DIR}/out/result.json"
grep -q '"tcp_ipv4_controlled_route_relay_bridge_pass": true' "${TMP_DIR}/out/result.json"
grep -q '"dns_policy": "OUT_OF_SCOPE"' "${TMP_DIR}/out/result.json"
grep -q '"udp_policy": "OUT_OF_SCOPE"' "${TMP_DIR}/out/result.json"
grep -q '"ipv6_policy": "OUT_OF_SCOPE"' "${TMP_DIR}/out/result.json"
grep -q '"relay_ip_exclusion_verified": true' "${TMP_DIR}/out/result.json"
grep -q '"default_route_changed": false' "${TMP_DIR}/out/result.json"
grep -q '"cleanup_only_aegis_owned_state": true' "${TMP_DIR}/out/result.json"
grep -q '"cleanup_restores_baseline_route_state": true' "${TMP_DIR}/out/result.json"
grep -q '"cleanup_after_simulated_helper_client_stop_verified": true' "${TMP_DIR}/out/result.json"
grep -q '"dns_claimed": false' "${TMP_DIR}/out/result.json"
grep -q '"udp_claimed": false' "${TMP_DIR}/out/result.json"
grep -q '"ipv6_claimed": false' "${TMP_DIR}/out/result.json"
grep -q '"event_code":"macos_utun_policy_decision"' "${TMP_DIR}/out/runtime-events.jsonl"
grep -q '"event_code":"macos_utun_cleanup_matrix_completed"' "${TMP_DIR}/out/runtime-events.jsonl"

cat >"${TMP_DIR}/w3/result.json" <<'JSON'
{
  "artifact": "macos-utun-w3-local-relay-bridge-proof-lab",
  "verdict": "NOT_PASS",
  "relay_session_succeeded": false,
  "utun_to_relay_bridge_linkage_proven": false,
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "network_extension_claimed": false
}
JSON

if AEGIS_UTUN_W1_ARTIFACT="${TMP_DIR}/w1" \
  AEGIS_UTUN_W2_ARTIFACT="${TMP_DIR}/w2" \
  AEGIS_UTUN_W3_ARTIFACT="${TMP_DIR}/w3" \
    bash "${ROOT}/scripts/run-macos-utun-w4-policy-cleanup-matrix.sh" "${TMP_DIR}/out"; then
  echo "expected missing W3 relay bridge to block W4" >&2
  exit 1
fi
grep -q '"status": "BLOCKED_BY_W3_RELAY_BRIDGE_MISSING"' "${TMP_DIR}/out/result.json"
grep -q '"verdict": "NOT_PASS"' "${TMP_DIR}/out/result.json"

cat >"${TMP_DIR}/w3/result.json" <<'JSON'
{
  "artifact": "macos-utun-w3-local-relay-bridge-proof-lab",
  "verdict": "PASS",
  "relay_session_succeeded": true,
  "utun_to_relay_bridge_linkage_proven": true,
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "network_extension_claimed": false
}
JSON
cat >"${TMP_DIR}/w1/route-proof.json" <<'JSON'
{
  "artifact": "macos-utun-w1-controlled-ipv4-route-proof",
  "verdict": "PASS",
  "relay_ip_excluded_from_utun": true,
  "controlled_route_removed_after_cleanup": false,
  "default_route_claim": false
}
JSON

if AEGIS_UTUN_W1_ARTIFACT="${TMP_DIR}/w1" \
  AEGIS_UTUN_W2_ARTIFACT="${TMP_DIR}/w2" \
  AEGIS_UTUN_W3_ARTIFACT="${TMP_DIR}/w3" \
    bash "${ROOT}/scripts/run-macos-utun-w4-policy-cleanup-matrix.sh" "${TMP_DIR}/out"; then
  echo "expected missing route cleanup to block W4" >&2
  exit 1
fi
grep -q '"status": "BLOCKED_BY_ROUTE_CLEANUP_MISSING"' "${TMP_DIR}/out/result.json"
grep -q '"cleanup_restores_baseline_route_state": false' "${TMP_DIR}/out/result.json"

echo "ok"
