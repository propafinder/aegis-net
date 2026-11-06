#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-traffic-shape.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cd "${ROOT}"

cat >"${TMP_DIR}/runtime-pass.jsonl" <<'JSONL'
{"event_code":"relay_transport_selected","fields":{"transport":"HttpsWs","relay_surface_write_chunk_size":4096,"relay_surface_inter_chunk_delay_ms":4}}
{"event_code":"relay_session_succeeded","fields":{"chosen_transport":"HttpsWs","relay_surface_write_chunk_size":4096,"relay_surface_inter_chunk_delay_ms":4}}
JSONL

cat >"${TMP_DIR}/classifier-pass.json" <<'JSON'
{
  "status": "PASS",
  "verdict_counts": {
    "fail": 0,
    "pass": 2,
    "unknown": 0
  },
  "ndpi_risk_count": 0,
  "suricata_alert_count": 0
}
JSON

cat >"${TMP_DIR}/pcap-summary.json" <<'JSON'
{
  "packet_count": 12,
  "byte_count": 40960,
  "upload_bytes": 10240,
  "download_bytes": 30720,
  "packet_sizes": [96, 1280, 1400, 1400],
  "inter_arrival_ms_summary": {
    "count": 4,
    "p50": 4
  },
  "burst_count": 2,
  "session_duration_ms": 1200,
  "tls_record_size_summary": {
    "count": 2
  }
}
JSON

cargo run -q -p aegis-measure -- traffic-shape-score \
  --transport https_ws \
  --runtime-events-jsonl "${TMP_DIR}/runtime-pass.jsonl" \
  --classifier-summary-json "${TMP_DIR}/classifier-pass.json" \
  --pcap-summary-json "${TMP_DIR}/pcap-summary.json" \
  --output-json "${TMP_DIR}/score-pass.json" \
  --output-markdown "${TMP_DIR}/score-pass.md"

python3 - <<'PY' "${TMP_DIR}/score-pass.json"
import json, sys
score = json.load(open(sys.argv[1], encoding="utf-8"))
assert score["artifact_schema"] == "traffic_shape_score_v1"
assert score["transport"] == "https_ws"
assert score["score_status"] == "PASS"
assert score["classifier_clean"] is True
assert score["timing_present"] is True
assert score["ratio_present"] is True
assert score["pcap_present"] is True
assert score["runtime_linked"] is True
assert score["ja3_status"] == "NOT_MEASURED"
assert score["ja4_status"] == "NOT_MEASURED"
PY

cargo run -q -p aegis-measure -- traffic-shape-score \
  --transport https_ws \
  --runtime-events-jsonl "${TMP_DIR}/runtime-pass.jsonl" \
  --classifier-summary-json "${TMP_DIR}/classifier-pass.json" \
  --output-json "${TMP_DIR}/score-blocked.json"

python3 - <<'PY' "${TMP_DIR}/score-blocked.json"
import json, sys
score = json.load(open(sys.argv[1], encoding="utf-8"))
assert score["score_status"] == "BLOCKED"
assert "relay_only_pcap_missing" in score["blockers"]
assert score["next_action"] == "collect_per_transport_relay_only_pcap"
PY

echo "traffic-shape-score contract: ok"
