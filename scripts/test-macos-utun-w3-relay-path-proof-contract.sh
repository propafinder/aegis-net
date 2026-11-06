#!/usr/bin/env bash
set -euo pipefail

# Independent fixture reference; the original native/evidence assertions remain unchanged.
export AEGIS_RELAY_IP="192.0.2.20"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-macos-utun-w3.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/w2" "${TMP_DIR}/relay" "${TMP_DIR}/out"

cat >"${TMP_DIR}/w2/result.json" <<'JSON'
{
  "verdict": "PASS",
  "tcp_flow_observed": true,
  "tcp_synack_lab_pass": true,
  "tcp_ack_observed": true
}
JSON
touch "${TMP_DIR}/w2/runtime-events.jsonl"

cat >"${TMP_DIR}/relay/runtime-events.jsonl" <<'JSONL'
{"event_code":"relay_session_succeeded","fields":{"chosen_transport":"HttpsWs"}}
{"event_code":"macos_utun_relay_bridge_session_succeeded","fields":{"scope":"lab_controlled_utun_w3"}}
JSONL

AEGIS_UTUN_W2_ARTIFACT="${TMP_DIR}/w2" \
AEGIS_UTUN_RELAY_RUNTIME_EVENTS="${TMP_DIR}/relay/runtime-events.jsonl" \
  bash "${ROOT}/scripts/run-macos-utun-w3-relay-path-proof.sh" "${TMP_DIR}/out"
grep -q '"verdict": "PASS"' "${TMP_DIR}/out/result.json"
grep -q '"tcp_synack_lab_pass": true' "${TMP_DIR}/out/result.json"
grep -q '"utun_to_relay_bridge_linkage_proven": true' "${TMP_DIR}/out/result.json"

cat >"${TMP_DIR}/w2/result.json" <<'JSON'
{
  "verdict": "PASS",
  "tcp_flow_observed": true,
  "tcp_synack_lab_pass": false,
  "tcp_ack_observed": false
}
JSON
AEGIS_UTUN_W2_ARTIFACT="${TMP_DIR}/w2" \
AEGIS_UTUN_RELAY_RUNTIME_EVENTS="${TMP_DIR}/relay/runtime-events.jsonl" \
  bash "${ROOT}/scripts/run-macos-utun-w3-relay-path-proof.sh" "${TMP_DIR}/out"
grep -q '"status": "BLOCKED_BY_STATEFUL_TCP_EDGE_MISSING"' "${TMP_DIR}/out/result.json"
grep -q '"verdict": "NOT_PASS"' "${TMP_DIR}/out/result.json"

cat >"${TMP_DIR}/w2/result.json" <<'JSON'
{
  "verdict": "PASS",
  "tcp_flow_observed": true,
  "tcp_synack_lab_pass": true,
  "tcp_ack_observed": true
}
JSON
cat >"${TMP_DIR}/relay/runtime-events.jsonl" <<'JSONL'
{"event_code":"relay_session_succeeded","fields":{"chosen_transport":"HttpsWs"}}
JSONL
AEGIS_UTUN_W2_ARTIFACT="${TMP_DIR}/w2" \
AEGIS_UTUN_RELAY_RUNTIME_EVENTS="${TMP_DIR}/relay/runtime-events.jsonl" \
  bash "${ROOT}/scripts/run-macos-utun-w3-relay-path-proof.sh" "${TMP_DIR}/out"
grep -q '"status": "BLOCKED_BY_PACKET_TO_RELAY_BRIDGE_MISSING"' "${TMP_DIR}/out/result.json"
grep -q '"utun_to_relay_bridge_linkage_proven": false' "${TMP_DIR}/out/result.json"
