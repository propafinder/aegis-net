#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-mimicry-wire-witness-summary.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wire-witness-builder.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

FAKE_PCAP="${TMP_DIR}/capture.pcapng"
RUNTIME_EVENTS="${TMP_DIR}/runtime-events.jsonl"
OUTPUT_JSON="${TMP_DIR}/wire-witness-summary.json"
FAKE_TSHARK="${TMP_DIR}/fake-tshark"

touch "${FAKE_PCAP}"

cat > "${FAKE_TSHARK}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '1710000000.100\t192.0.2.10\t198.51.100.20\t60\t0x10\t0x1234\t1\t0\t0\t52344\t443\t1\t0\t0\t64240\t1460\t8\t1\t123456\t0\t1000\n'
printf '1710000000.120\t192.0.2.10\t198.51.100.20\t60\t0x10\t0x1234\t1\t0\t0\t52344\t443\t0\t1\t40\t64240\t\t\t\t\t\t1000\n'
printf '1710000000.121\t192.0.2.10\t198.51.100.20\t60\t0x10\t0x1234\t1\t0\t0\t52344\t443\t0\t1\t8\t64240\t\t\t\t\t\t1032\n'
EOF
chmod +x "${FAKE_TSHARK}"

cat > "${RUNTIME_EVENTS}" <<'JSONL'
{"ts_unix_ms":1709999999900,"event_code":"direct_session_succeeded","fields":{"target":"example.test","port":443,"mimicry_capability_wire_active":false}}
{"ts_unix_ms":1710000000000,"event_code":"direct_planner_order_selected","fields":{"target":"example.test","port":443,"mimicry_capability_wire_active":true,"mimicry_capability_wire_runtime_slice":"linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface"}}
JSONL

bash "${SCRIPT}" \
  --pcap "${FAKE_PCAP}" \
  --runtime-events "${RUNTIME_EVENTS}" \
  --output "${OUTPUT_JSON}" \
  --tshark-bin "${FAKE_TSHARK}" \
  --window-ms 2000

jq -e '
  .artifact_schema == "wire_mimicry_independent_witness_summary_v1"
  and .producer == "build-mimicry-wire-witness-summary.sh"
  and .active_runtime_records_seen == 1
  and .capture_backed_records_seen == 1
  and .hostile_path_capture_ready == true
  and .witness_window_ms == 2000
  and (.records | length) == 1
  and .records[0].target == "example.test"
  and .records[0].port == 443
  and .records[0].runtime_slice == "linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface"
  and .records[0].ttl_preface == 60
  and .records[0].window_preface == 64240
  and .records[0].ipv4_header_shaping == {
    "tos": 16,
    "ip_id": 4660,
    "dont_fragment": true
  }
  and .records[0].negotiated_options == {
    "mss": 1460,
    "window_scale": 8,
    "sack_permitted": true,
    "timestamp_mode": "syn_timestamp_offer_layout20"
  }
  and .records[0].fragment_choreography == {
    "first_payload_len": null,
    "disorder_split_at": null,
    "overlap": null
  }
  and .records[0].packet_count_considered == 3
' "${OUTPUT_JSON}" >/dev/null

echo "build-mimicry-wire-witness-summary contract: ok"
