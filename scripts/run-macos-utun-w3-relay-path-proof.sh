#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"
OUT_DIR="${1:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-w3-relay-path-proof-lab}"
W2_ARTIFACT="${AEGIS_UTUN_W2_ARTIFACT:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-w2-stateful-tcp-edge-proof-lab}"
RELAY_RUNTIME_EVENTS="${AEGIS_UTUN_RELAY_RUNTIME_EVENTS:-}"
CONTROLLED_PEER="${AEGIS_UTUN_CONTROLLED_PEER:-198.18.0.2}"
# Operator relay reference only; this W3 owner records metadata, not an egress or trust verdict.
RELAY_IP="${AEGIS_RELAY_IP:-}"

relay_ip_ready() {
  local value="$1" octet
  local -a octets
  [[ "${#value}" -le 15 && "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a octets <<<"$value"
  [[ "${#octets[@]}" -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}
if ! relay_ip_ready "$RELAY_IP"; then
  printf '%s\n' 'AEGIS_RELAY_IP must be an explicit canonical IPv4 address' >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"

{
  printf 'artifact=%s\n' "${OUT_DIR}"
  printf 'w2_artifact=%s\n' "${W2_ARTIFACT}"
  printf 'relay_runtime_events=%s\n' "${RELAY_RUNTIME_EVENTS:-NOT_PROVIDED}"
  printf 'controlled_peer=%s\n' "${CONTROLLED_PEER}"
  printf 'relay_ip=%s\n' "${RELAY_IP}"
} >"${OUT_DIR}/environment.txt"

{
  printf '%s\n' "AEGIS_UTUN_W2_ARTIFACT=${W2_ARTIFACT} AEGIS_UTUN_RELAY_RUNTIME_EVENTS=${RELAY_RUNTIME_EVENTS:-} bash scripts/run-macos-utun-w3-relay-path-proof.sh ${OUT_DIR}"
} >"${OUT_DIR}/commands.txt"

W2_PASS=false
TCP_FLOW_OBSERVED=false
TCP_SYNACK_LAB_PASS=false
TCP_ACK_OBSERVED=false
RELAY_RUNTIME_PRESENT=false
RELAY_SESSION_SUCCEEDED=false
UTUN_RELAY_BRIDGE_EVENT=false

if [[ -f "${W2_ARTIFACT}/result.json" ]]; then
  grep -q '"verdict": "PASS"' "${W2_ARTIFACT}/result.json" && W2_PASS=true
  grep -q '"tcp_flow_observed": true' "${W2_ARTIFACT}/result.json" && TCP_FLOW_OBSERVED=true
  grep -q '"tcp_synack_lab_pass": true' "${W2_ARTIFACT}/result.json" && TCP_SYNACK_LAB_PASS=true
  grep -q '"tcp_ack_observed": true' "${W2_ARTIFACT}/result.json" && TCP_ACK_OBSERVED=true
fi

if [[ -n "${RELAY_RUNTIME_EVENTS}" && -f "${RELAY_RUNTIME_EVENTS}" ]]; then
  RELAY_RUNTIME_PRESENT=true
  grep -q '"event_code":"relay_session_succeeded"' "${RELAY_RUNTIME_EVENTS}" && RELAY_SESSION_SUCCEEDED=true
  grep -q '"event_code":"macos_utun_relay_bridge_session_succeeded"' "${RELAY_RUNTIME_EVENTS}" && UTUN_RELAY_BRIDGE_EVENT=true
  cp "${RELAY_RUNTIME_EVENTS}" "${OUT_DIR}/relay-runtime-events.jsonl"
fi

{
  cat "${W2_ARTIFACT}/runtime-events.jsonl" 2>/dev/null || true
  if [[ -f "${OUT_DIR}/relay-runtime-events.jsonl" ]]; then
    cat "${OUT_DIR}/relay-runtime-events.jsonl"
  fi
} >"${OUT_DIR}/runtime-events.jsonl"

if [[ "${W2_PASS}" == "true" && "${TCP_FLOW_OBSERVED}" == "true" && "${TCP_SYNACK_LAB_PASS}" == "true" && "${TCP_ACK_OBSERVED}" == "true" && "${RELAY_SESSION_SUCCEEDED}" == "true" && "${UTUN_RELAY_BRIDGE_EVENT}" == "true" ]]; then
  STATUS="PASS"
  VERDICT="PASS"
  BLOCKER=null
elif [[ "${TCP_FLOW_OBSERVED}" == "true" && ( "${TCP_SYNACK_LAB_PASS}" != "true" || "${TCP_ACK_OBSERVED}" != "true" ) ]]; then
  STATUS="BLOCKED_BY_STATEFUL_TCP_EDGE_MISSING"
  VERDICT="NOT_PASS"
  BLOCKER='"W2.1 stateful TCP edge proof is missing: SYN/SYN-ACK/ACK over utun is required before W3 relay linkage"'
elif [[ "${W2_PASS}" != "true" || "${TCP_FLOW_OBSERVED}" != "true" ]]; then
  STATUS="BLOCKED_BY_W2_PACKET_FLOW_MISSING"
  VERDICT="NOT_PASS"
  BLOCKER='"W2 controlled TCP packet-flow proof is missing or not PASS"'
elif [[ "${RELAY_RUNTIME_PRESENT}" != "true" ]]; then
  STATUS="BLOCKED_BY_RELAY_RUNTIME_EVENTS_MISSING"
  VERDICT="NOT_PASS"
  BLOCKER='"relay runtime-events were not provided, so W3 cannot verify relay_session_succeeded"'
elif [[ "${RELAY_SESSION_SUCCEEDED}" != "true" ]]; then
  STATUS="BLOCKED_BY_RELAY_SESSION_MISSING"
  VERDICT="NOT_PASS"
  BLOCKER='"relay runtime-events do not contain relay_session_succeeded"'
else
  STATUS="BLOCKED_BY_PACKET_TO_RELAY_BRIDGE_MISSING"
  VERDICT="NOT_PASS"
  BLOCKER='"relay succeeded separately, but no macos_utun_relay_bridge_session_succeeded event proves utun packet-to-relay linkage"'
fi

cat >"${OUT_DIR}/result.json" <<JSON
{
  "schema_version": 1,
  "artifact": "macos-utun-w3-relay-path-proof-lab",
  "status": "${STATUS}",
  "verdict": "${VERDICT}",
  "w2_packet_flow_pass": ${W2_PASS},
  "tcp_flow_observed": ${TCP_FLOW_OBSERVED},
  "tcp_synack_lab_pass": ${TCP_SYNACK_LAB_PASS},
  "tcp_ack_observed": ${TCP_ACK_OBSERVED},
  "relay_runtime_events_present": ${RELAY_RUNTIME_PRESENT},
  "relay_session_succeeded": ${RELAY_SESSION_SUCCEEDED},
  "utun_to_relay_bridge_linkage_proven": ${UTUN_RELAY_BRIDGE_EVENT},
  "controlled_peer": "${CONTROLLED_PEER}",
  "relay_ip": "${RELAY_IP}",
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "dns_claimed": false,
  "udp_claimed": false,
  "ipv6_claimed": false,
  "network_extension_claimed": false,
  "blocker": ${BLOCKER}
}
JSON

{
  printf '# macOS utun W3 Relay Path Proof Lab\n\n'
  printf 'Verdict: `%s`.\n\n' "${VERDICT}"
  printf -- '- W2 packet-flow pass: `%s`\n' "${W2_PASS}"
  printf -- '- W2.1 SYN/SYN-ACK/ACK pass: `%s`\n' "${TCP_SYNACK_LAB_PASS}"
  printf -- '- W2.1 TCP ACK observed: `%s`\n' "${TCP_ACK_OBSERVED}"
  printf -- '- relay session succeeded: `%s`\n' "${RELAY_SESSION_SUCCEEDED}"
  printf -- '- utun-to-relay bridge linkage proven: `%s`\n' "${UTUN_RELAY_BRIDGE_EVENT}"
  printf -- '- broad system-wide claim: `false`\n'
  printf -- '- DNS/UDP/IPv6 claim: `false`\n'
  printf -- '- NetworkExtension claim: `false`\n'
} >"${OUT_DIR}/README.md"
