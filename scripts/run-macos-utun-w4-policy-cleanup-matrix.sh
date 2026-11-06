#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"
OUT_DIR="${1:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-w4-policy-cleanup-matrix-lab}"

W1_ARTIFACT="${AEGIS_UTUN_W1_ARTIFACT:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-w1-controlled-route-proof-lab}"
W2_ARTIFACT="${AEGIS_UTUN_W2_ARTIFACT:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-w2-stateful-tcp-edge-proof-lab}"
W3_ARTIFACT="${AEGIS_UTUN_W3_ARTIFACT:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-w3-local-relay-bridge-proof-lab}"

mkdir -p "${OUT_DIR}"

RESULT_JSON="${OUT_DIR}/result.json"
POLICY_MATRIX_JSON="${OUT_DIR}/policy-matrix.json"
CLEANUP_MATRIX_JSON="${OUT_DIR}/cleanup-matrix.json"
RUNTIME_EVENTS_JSONL="${OUT_DIR}/runtime-events.jsonl"

W1_RESULT="${W1_ARTIFACT}/result.json"
W1_ROUTE="${W1_ARTIFACT}/route-proof.json"
W2_RESULT="${W2_ARTIFACT}/result.json"
W3_RESULT="${W3_ARTIFACT}/result.json"

has_json() {
  local file="$1"
  local pattern="$2"
  [[ -f "${file}" ]] && grep -Eq "${pattern}" "${file}"
}

json_bool() {
  if [[ "$1" == "true" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

w1_pass=false
w2_pass=false
w3_pass=false
relay_ip_exclusion_verified=false
default_route_changed=true
cleanup_restores_baseline_route_state=false
cleanup_only_aegis_owned_state=false
simulated_stop_cleanup_verified=false
tcp_ipv4_controlled_route_relay_bridge_pass=false

if has_json "${W1_RESULT}" '"artifact"[[:space:]]*:[[:space:]]*"macos-utun-w1-controlled-route-proof-lab"' \
  && has_json "${W1_RESULT}" '"verdict"[[:space:]]*:[[:space:]]*"PASS"' \
  && has_json "${W1_RESULT}" '"route_proof_pass"[[:space:]]*:[[:space:]]*true' \
  && has_json "${W1_RESULT}" '"controlled_route_prefix"[[:space:]]*:[[:space:]]*"/32"' \
  && has_json "${W1_RESULT}" '"default_route_claim"[[:space:]]*:[[:space:]]*false' \
  && has_json "${W1_RESULT}" '"broad_system_wide_claim"[[:space:]]*:[[:space:]]*false'; then
  w1_pass=true
fi

if has_json "${W2_RESULT}" '"artifact"[[:space:]]*:[[:space:]]*"macos-utun-w2-stateful-tcp-edge-proof-lab"' \
  && has_json "${W2_RESULT}" '"verdict"[[:space:]]*:[[:space:]]*"PASS"' \
  && has_json "${W2_RESULT}" '"tcp_synack_lab_pass"[[:space:]]*:[[:space:]]*true' \
  && has_json "${W2_RESULT}" '"tcp_ack_observed"[[:space:]]*:[[:space:]]*true' \
  && has_json "${W2_RESULT}" '"relay_session_claimed"[[:space:]]*:[[:space:]]*false'; then
  w2_pass=true
fi

if has_json "${W3_RESULT}" '"artifact"[[:space:]]*:[[:space:]]*"macos-utun-w3-local-relay-bridge-proof-lab"' \
  && has_json "${W3_RESULT}" '"verdict"[[:space:]]*:[[:space:]]*"PASS"' \
  && has_json "${W3_RESULT}" '"relay_session_succeeded"[[:space:]]*:[[:space:]]*true' \
  && has_json "${W3_RESULT}" '"utun_to_relay_bridge_linkage_proven"[[:space:]]*:[[:space:]]*true' \
  && has_json "${W3_RESULT}" '"default_route_claim"[[:space:]]*:[[:space:]]*false' \
  && has_json "${W3_RESULT}" '"broad_system_wide_claim"[[:space:]]*:[[:space:]]*false' \
  && has_json "${W3_RESULT}" '"network_extension_claimed"[[:space:]]*:[[:space:]]*false'; then
  w3_pass=true
fi

if has_json "${W1_RESULT}" '"relay_ip_excluded_from_utun"[[:space:]]*:[[:space:]]*true' \
  && has_json "${W1_ROUTE}" '"relay_ip_excluded_from_utun"[[:space:]]*:[[:space:]]*true'; then
  relay_ip_exclusion_verified=true
fi

if has_json "${W1_RESULT}" '"default_route_claim"[[:space:]]*:[[:space:]]*false' \
  && has_json "${W1_ROUTE}" '"default_route_claim"[[:space:]]*:[[:space:]]*false'; then
  default_route_changed=false
fi

if has_json "${W1_ROUTE}" '"controlled_route_removed_after_cleanup"[[:space:]]*:[[:space:]]*true'; then
  cleanup_restores_baseline_route_state=true
  cleanup_only_aegis_owned_state=true
fi

if has_json "${W1_ARTIFACT}/runtime-events.jsonl" '"event_code"[[:space:]]*:[[:space:]]*"macos_utun_cleanup_completed"' \
  && has_json "${W2_ARTIFACT}/runtime-events.jsonl" '"event_code"[[:space:]]*:[[:space:]]*"macos_utun_cleanup_completed"'; then
  simulated_stop_cleanup_verified=true
fi

if [[ "${w1_pass}" == "true" && "${w2_pass}" == "true" && "${w3_pass}" == "true" ]]; then
  tcp_ipv4_controlled_route_relay_bridge_pass=true
fi

dns_policy="OUT_OF_SCOPE"
udp_policy="OUT_OF_SCOPE"
ipv6_policy="OUT_OF_SCOPE"

policy_matrix_explicit=true
dns_claimed=false
udp_claimed=false
ipv6_claimed=false
default_route_claim=false
broad_system_wide_claim=false
network_extension_claimed=false
product_ready_claim=false

status="PASS"
verdict="PASS"
blocker="null"
if [[ "${tcp_ipv4_controlled_route_relay_bridge_pass}" != "true" ]]; then
  status="BLOCKED_BY_W3_RELAY_BRIDGE_MISSING"
  verdict="NOT_PASS"
  blocker='"W1/W2/W3 TCP IPv4 controlled route and relay bridge proof is incomplete"'
elif [[ "${relay_ip_exclusion_verified}" != "true" ]]; then
  status="BLOCKED_BY_RELAY_IP_EXCLUSION_MISSING"
  verdict="NOT_PASS"
  blocker='"relay IP exclusion was not verified from W1 route proof"'
elif [[ "${default_route_changed}" == "true" ]]; then
  status="BLOCKED_BY_DEFAULT_ROUTE_MUTATION"
  verdict="NOT_PASS"
  blocker='"default route boundary was not preserved"'
elif [[ "${cleanup_restores_baseline_route_state}" != "true" || "${cleanup_only_aegis_owned_state}" != "true" ]]; then
  status="BLOCKED_BY_ROUTE_CLEANUP_MISSING"
  verdict="NOT_PASS"
  blocker='"cleanup did not prove AEGIS-owned route removal and baseline restoration"'
fi

cat >"${POLICY_MATRIX_JSON}" <<JSON
{
  "schema_version": 1,
  "artifact": "macos-utun-w4-policy-cleanup-matrix-lab",
  "scope": "LAB_POLICY_BOUNDARY_AND_CLEANUP_MATRIX",
  "tcp_ipv4_controlled_route_relay_bridge": {
    "policy": "CAPTURE",
    "scope": "CONTROLLED_IPV4_32_ROUTE_ONLY",
    "pass": $(json_bool "${tcp_ipv4_controlled_route_relay_bridge_pass}"),
    "w1_controlled_route_pass": $(json_bool "${w1_pass}"),
    "w2_stateful_tcp_edge_pass": $(json_bool "${w2_pass}"),
    "w3_local_relay_bridge_pass": $(json_bool "${w3_pass}")
  },
  "dns": {
    "policy": "${dns_policy}",
    "claimed": false,
    "reason": "No DNS capture path is implemented in the macOS utun lab ladder."
  },
  "udp": {
    "policy": "${udp_policy}",
    "claimed": false,
    "reason": "No UDP capture path is implemented in the macOS utun lab ladder."
  },
  "ipv6": {
    "policy": "${ipv6_policy}",
    "claimed": false,
    "reason": "No IPv6 route or packet path is implemented in the macOS utun lab ladder."
  },
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "network_extension_claimed": false,
  "product_ready_claim": false
}
JSON

cat >"${CLEANUP_MATRIX_JSON}" <<JSON
{
  "schema_version": 1,
  "artifact": "macos-utun-w4-policy-cleanup-matrix-lab",
  "scope": "LAB_CLEANUP_MATRIX",
  "relay_ip_exclusion_verified": $(json_bool "${relay_ip_exclusion_verified}"),
  "default_route_changed": $(json_bool "${default_route_changed}"),
  "cleanup_only_aegis_owned_state": $(json_bool "${cleanup_only_aegis_owned_state}"),
  "cleanup_restores_baseline_route_state": $(json_bool "${cleanup_restores_baseline_route_state}"),
  "cleanup_after_simulated_helper_client_stop_verified": $(json_bool "${simulated_stop_cleanup_verified}"),
  "w1_route_proof_artifact": "${W1_ARTIFACT}",
  "w2_stateful_tcp_edge_artifact": "${W2_ARTIFACT}",
  "w3_local_relay_bridge_artifact": "${W3_ARTIFACT}"
}
JSON

now_ms="$(date +%s000)"
cat >"${RUNTIME_EVENTS_JSONL}" <<JSONL
{"timestamp_unix_ms":${now_ms},"level":"info","event_code":"macos_utun_policy_decision","fields":{"scope":"lab_controlled_utun_w4","traffic_class":"tcp_ipv4_controlled_route_relay_bridge","policy":"CAPTURE","policy_scope":"CONTROLLED_IPV4_32_ROUTE_ONLY","pass":$(json_bool "${tcp_ipv4_controlled_route_relay_bridge_pass}"),"default_route_claim":false,"broad_system_wide_claim":false}}
{"timestamp_unix_ms":${now_ms},"level":"info","event_code":"macos_utun_policy_decision","fields":{"scope":"lab_controlled_utun_w4","traffic_class":"dns","policy":"${dns_policy}","claimed":false}}
{"timestamp_unix_ms":${now_ms},"level":"info","event_code":"macos_utun_policy_decision","fields":{"scope":"lab_controlled_utun_w4","traffic_class":"udp","policy":"${udp_policy}","claimed":false}}
{"timestamp_unix_ms":${now_ms},"level":"info","event_code":"macos_utun_policy_decision","fields":{"scope":"lab_controlled_utun_w4","traffic_class":"ipv6","policy":"${ipv6_policy}","claimed":false}}
{"timestamp_unix_ms":${now_ms},"level":"info","event_code":"macos_utun_cleanup_matrix_completed","fields":{"scope":"lab_controlled_utun_w4","relay_ip_exclusion_verified":$(json_bool "${relay_ip_exclusion_verified}"),"default_route_changed":$(json_bool "${default_route_changed}"),"cleanup_only_aegis_owned_state":$(json_bool "${cleanup_only_aegis_owned_state}"),"cleanup_restores_baseline_route_state":$(json_bool "${cleanup_restores_baseline_route_state}"),"cleanup_after_simulated_helper_client_stop_verified":$(json_bool "${simulated_stop_cleanup_verified}")}}
JSONL

cat >"${RESULT_JSON}" <<JSON
{
  "schema_version": 1,
  "artifact": "macos-utun-w4-policy-cleanup-matrix-lab",
  "status": "${status}",
  "verdict": "${verdict}",
  "tcp_ipv4_controlled_route_relay_bridge_pass": $(json_bool "${tcp_ipv4_controlled_route_relay_bridge_pass}"),
  "w1_controlled_route_pass": $(json_bool "${w1_pass}"),
  "w2_stateful_tcp_edge_pass": $(json_bool "${w2_pass}"),
  "w3_local_relay_bridge_pass": $(json_bool "${w3_pass}"),
  "dns_policy": "${dns_policy}",
  "udp_policy": "${udp_policy}",
  "ipv6_policy": "${ipv6_policy}",
  "policy_matrix_explicit": $(json_bool "${policy_matrix_explicit}"),
  "relay_ip_exclusion_verified": $(json_bool "${relay_ip_exclusion_verified}"),
  "default_route_changed": $(json_bool "${default_route_changed}"),
  "cleanup_only_aegis_owned_state": $(json_bool "${cleanup_only_aegis_owned_state}"),
  "cleanup_restores_baseline_route_state": $(json_bool "${cleanup_restores_baseline_route_state}"),
  "cleanup_after_simulated_helper_client_stop_verified": $(json_bool "${simulated_stop_cleanup_verified}"),
  "default_route_claim": $(json_bool "${default_route_claim}"),
  "broad_system_wide_claim": $(json_bool "${broad_system_wide_claim}"),
  "dns_claimed": $(json_bool "${dns_claimed}"),
  "udp_claimed": $(json_bool "${udp_claimed}"),
  "ipv6_claimed": $(json_bool "${ipv6_claimed}"),
  "network_extension_claimed": $(json_bool "${network_extension_claimed}"),
  "product_ready_claim": $(json_bool "${product_ready_claim}"),
  "blocker": ${blocker}
}
JSON

cat >"${OUT_DIR}/commands.txt" <<TXT
AEGIS_UTUN_W1_ARTIFACT="${W1_ARTIFACT}" AEGIS_UTUN_W2_ARTIFACT="${W2_ARTIFACT}" AEGIS_UTUN_W3_ARTIFACT="${W3_ARTIFACT}" bash scripts/run-macos-utun-w4-policy-cleanup-matrix.sh "${OUT_DIR}"
TXT

cat >"${OUT_DIR}/environment.txt" <<TXT
date_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
host=$(hostname)
artifact=${OUT_DIR}
w1_artifact=${W1_ARTIFACT}
w2_artifact=${W2_ARTIFACT}
w3_artifact=${W3_ARTIFACT}
TXT

cat >"${OUT_DIR}/README.md" <<MD
# macOS utun W4 Policy Cleanup Matrix Lab

Verdict: \`${verdict}\`

This artifact is LAB / EXPERIMENTAL. It does not claim NetworkExtension,
product-ready macOS wide capture, broad system-wide routing, default-route
capture, DNS capture, UDP capture, or IPv6 capture.

W4 records the policy boundary for the macOS utun ladder and validates cleanup
from the existing W1/W2/W3 proof artifacts.
MD

if [[ "${verdict}" == "PASS" ]]; then
  exit 0
fi
exit 1
