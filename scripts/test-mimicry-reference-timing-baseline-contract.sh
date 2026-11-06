#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-reference-baseline.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cd "${ROOT}"

for transport in https_ws grpc_stream; do
  for profile in clean_fiber mobile_peak congested_wifi slow_mobile middlebox_delay; do
    mkdir -p "${TMP_DIR}/matrix/${transport}/${profile}"
    cat >"${TMP_DIR}/matrix/${transport}/${profile}/witness-score.json" <<JSON
{
  "transport": "${transport}",
  "netem_profile": "${profile}",
  "score_status": "PARTIAL",
  "runtime_linked": true,
  "pcap_present": true,
  "packet_size_p50": 127,
  "inter_arrival_ms_p50": 5,
  "upload_download_ratio": 0.45,
  "session_duration_ms": 900
}
JSON
  done
done

cat >"${TMP_DIR}/ws-blocked.json" <<'JSON'
{
  "artifact": "websocket-reference",
  "verdict": "BLOCKED_REFERENCE_ENDPOINT_MISSING",
  "client_type": "not_available",
  "sample_count": 0,
  "profiles_covered": [],
  "source": "controlled_websocket_reference_endpoint_probe"
}
JSON

cat >"${TMP_DIR}/grpc-blocked.json" <<'JSON'
{
  "artifact": "grpc-reference",
  "verdict": "BLOCKED_REFERENCE_ENDPOINT_MISSING",
  "client_type": "not_available",
  "sample_count": 0,
  "profiles_covered": [],
  "source": "controlled_grpc_reference_endpoint_probe"
}
JSON

cargo run -q -p aegis-measure -- reference-timing-baseline \
  --matrix-root "${TMP_DIR}/matrix" \
  --websocket-reference-json "${TMP_DIR}/ws-blocked.json" \
  --grpc-reference-json "${TMP_DIR}/grpc-blocked.json" \
  --output-json "${TMP_DIR}/blocked-baseline.json"

python3 - <<'PY' "${TMP_DIR}/blocked-baseline.json"
import json, sys
baseline = json.load(open(sys.argv[1], encoding="utf-8"))
assert baseline["verdict"] == "PARTIAL"
assert baseline["status"] == "PARTIAL_REFERENCE_ENDPOINT_MISSING"
assert baseline["ready_reference_count"] == 0
assert baseline["required_reference_count"] == 2
assert "websocket_reference:reference_endpoint_missing" in baseline["blockers"]
assert "grpc_reference:reference_endpoint_missing" in baseline["blockers"]
assert baseline["next_action"] == "create_controlled_websocket_grpc_reference_endpoints"
PY

cat >"${TMP_DIR}/ws-ready.json" <<'JSON'
{
  "artifact": "websocket-reference",
  "verdict": "SCOPED_REFERENCE_READY",
  "client_type": "non_browser_ws_client",
  "sample_count": 4,
  "profiles_covered": ["clean_fiber", "mobile_peak"],
  "source": "controlled_websocket_reference_endpoint"
}
JSON

cat >"${TMP_DIR}/grpc-ready.json" <<'JSON'
{
  "artifact": "grpc-reference",
  "verdict": "SCOPED_REFERENCE_READY",
  "client_type": "grpcurl",
  "sample_count": 4,
  "profiles_covered": ["clean_fiber", "mobile_peak"],
  "source": "controlled_grpc_reference_endpoint"
}
JSON

cargo run -q -p aegis-measure -- reference-timing-baseline \
  --matrix-root "${TMP_DIR}/matrix" \
  --websocket-reference-json "${TMP_DIR}/ws-ready.json" \
  --grpc-reference-json "${TMP_DIR}/grpc-ready.json" \
  --output-json "${TMP_DIR}/ready-baseline.json"

python3 - <<'PY' "${TMP_DIR}/ready-baseline.json"
import json, sys
baseline = json.load(open(sys.argv[1], encoding="utf-8"))
assert baseline["verdict"] == "SCOPED_REFERENCE_READY"
assert baseline["status"] == "SCOPED_REFERENCE_READY"
assert baseline["ready_reference_count"] == 2
assert baseline["reference_endpoint_sample_count"] == 8
assert baseline["next_action"] == "brain_operational_live_calibrated_transport_proof"
PY

echo "mimicry reference-timing-baseline contract: ok"
