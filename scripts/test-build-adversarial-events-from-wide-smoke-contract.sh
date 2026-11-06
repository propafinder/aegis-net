#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wide-smoke-adversarial.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/contract.json" <<'JSON'
{
  "runtime_delivery_stage": "completed_return_delivery_tail",
  "runtime_health_status": "healthy",
  "runtime_response_action": "local_udp",
  "runtime_response_stage": "local_udp_send_done",
  "runtime_target_host": "198.18.0.55",
  "runtime_target_port": 54321,
  "runtime_transport_status": "completed",
  "udp_capture_contract": "generic_capture_unstable",
  "wide_udp_capture_policy": "any_target_port_linux_ipv4_unstable",
  "wide_udp_capture_runtime_scope": "linux_ipv4_only",
  "wide_udp_capture_support_tier": "guarded_unstable"
}
JSON

cat >"${TMP_DIR}/runtime-events.jsonl" <<'JSONL'
{"event_code":"ingress_udp_datagram_observed","fields":{"target_host":"198.18.0.55","target_port":54321,"wide_udp_capture_contract":"generic_capture_unstable"}}
{"event_code":"relay_session_succeeded","fields":{"chosen_transport":"MasqueDerived","target":"198.18.0.55","port":54321}}
{"event_code":"ingress_udp_datagram_completed","fields":{"target_host":"198.18.0.55","target_port":54321,"wide_udp_capture_contract":"generic_capture_unstable","wide_udp_capture_support_tier":"guarded_unstable","wide_udp_capture_policy":"any_target_port_linux_ipv4_unstable","wide_udp_capture_runtime_scope":"linux_ipv4_only"}}
JSONL
printf '\324\303\262\241' >"${TMP_DIR}/packets.pcap"
dd if=/dev/zero bs=64 count=1 >>"${TMP_DIR}/packets.pcap" 2>/dev/null
cat >"${TMP_DIR}/tcpdump.log" <<'LOG'
tcpdump_filter=ip and udp
3 packets captured
3 packets received by filter
0 packets dropped by kernel
LOG

bash "${ROOT}/scripts/build-adversarial-events-from-wide-smoke.sh" \
  --contract-json "${TMP_DIR}/contract.json" \
  --runtime-events-jsonl "${TMP_DIR}/runtime-events.jsonl" \
  --output-jsonl "${TMP_DIR}/events.jsonl" \
  --artifact-dir "${TMP_DIR}/artifact" \
  --packet-capture "${TMP_DIR}/packets.pcap" \
  --tcpdump-log "${TMP_DIR}/tcpdump.log"

if [[ "$(wc -l <"${TMP_DIR}/events.jsonl" | tr -d ' ')" != "1" ]]; then
  echo "expected exactly one adversarial event" >&2
  exit 1
fi

jq -e '
  .event == "adversarial_scenario_measured"
  and .mode == "live_aegis_runtime_artifact"
  and .status == "PASS"
  and .transport == "masque_derived"
  and .threshold == 0.85
  and .runtime_health_status == "healthy"
  and .runtime_transport_status == "completed"
  and .relay_chosen_transport == "MasqueDerived"
  and .runtime_event_count == 3
  and (.packet_capture | endswith("packets.pcap"))
  and .packet_capture_size_bytes > 24
  and .packet_evidence_status == "present"
  and (.tcpdump_log | endswith("tcpdump.log"))
  and .tcpdump_packets_captured == 3
  and .tcpdump_packets_dropped_by_kernel == 0
' "${TMP_DIR}/events.jsonl" >/dev/null

jq '.runtime_transport_status = "failed"' "${TMP_DIR}/contract.json" >"${TMP_DIR}/contract.failed.json"
mv "${TMP_DIR}/contract.failed.json" "${TMP_DIR}/contract.json"

if bash "${ROOT}/scripts/build-adversarial-events-from-wide-smoke.sh" \
  --contract-json "${TMP_DIR}/contract.json" \
  --runtime-events-jsonl "${TMP_DIR}/runtime-events.jsonl" \
  --output-jsonl "${TMP_DIR}/events-fail.jsonl" >/dev/null 2>&1; then
  echo "expected unhealthy smoke artifact to fail" >&2
  exit 1
fi

echo "PASS: wide smoke adversarial event contract"
