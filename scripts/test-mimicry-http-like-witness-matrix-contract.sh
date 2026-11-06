#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-witness-matrix.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cd "${ROOT}"

write_cell() {
  local transport="$1"
  local profile="$2"
  local status="$3"
  mkdir -p "${TMP_DIR}/matrix/${transport}/${profile}"
  cat >"${TMP_DIR}/matrix/${transport}/${profile}/witness-score.json" <<JSON
{
  "transport": "${transport}",
  "netem_profile": "${profile}",
  "score_status": "${status}",
  "runtime_linked": true,
  "pcap_present": true,
  "classifier_clean": true,
  "ndpi_risk_count": 0,
  "suricata_alert_count": 0,
  "inter_arrival_ms_p50": 3,
  "ja3_status": "MEASURED",
  "ja3_hash": "fixture-ja3",
  "ja4_status": "MEASURED",
  "ja4_fingerprint": "fixture-ja4",
  "witness_indistinguishability_score": 0.8,
  "blockers": []
}
JSON
}

write_cell https_ws clean_fiber PASS
write_cell grpc_stream clean_fiber PASS

cargo run -q -p aegis-measure -- mimicry-matrix-review \
  --matrix-root "${TMP_DIR}/matrix" \
  --output-json "${TMP_DIR}/clean-fiber-only.json" \
  --output-markdown "${TMP_DIR}/clean-fiber-only.md"

python3 - <<'PY' "${TMP_DIR}/clean-fiber-only.json"
import json, sys
review = json.load(open(sys.argv[1], encoding="utf-8"))
assert review["verdict"] == "SCOPED_PASS"
assert review["next_action"] == "expand_netem_matrix_and_collect_reference_baseline"
assert review["ja3_status"] == "PARTIAL"
assert review["ja4_status"] == "PARTIAL"
assert "clean_fiber" in review["netem_profiles_covered"]
assert "mobile_peak" not in review["netem_profiles_covered"]
PY

for transport in https_ws grpc_stream; do
  for profile in mobile_peak congested_wifi slow_mobile middlebox_delay; do
    write_cell "${transport}" "${profile}" PASS
  done
done

cargo run -q -p aegis-measure -- mimicry-matrix-review \
  --matrix-root "${TMP_DIR}/matrix" \
  --output-json "${TMP_DIR}/no-reference.json"

cat >"${TMP_DIR}/reference-pass.json" <<'JSON'
{"verdict":"PASS"}
JSON

cat >"${TMP_DIR}/reference-scoped.json" <<'JSON'
{"verdict":"SCOPED_REFERENCE_READY"}
JSON

cargo run -q -p aegis-measure -- mimicry-matrix-review \
  --matrix-root "${TMP_DIR}/matrix" \
  --reference-status-json "${TMP_DIR}/reference-pass.json" \
  --output-json "${TMP_DIR}/full-pass.json"

cargo run -q -p aegis-measure -- mimicry-matrix-review \
  --matrix-root "${TMP_DIR}/matrix" \
  --reference-status-json "${TMP_DIR}/reference-scoped.json" \
  --output-json "${TMP_DIR}/scoped-pass.json"

python3 - <<'PY' "${TMP_DIR}/no-reference.json" "${TMP_DIR}/full-pass.json" "${TMP_DIR}/scoped-pass.json"
import json, sys
no_ref = json.load(open(sys.argv[1], encoding="utf-8"))
full = json.load(open(sys.argv[2], encoding="utf-8"))
scoped = json.load(open(sys.argv[3], encoding="utf-8"))
assert no_ref["verdict"] == "PARTIAL"
assert "reference_baseline_not_pass" in no_ref["blockers"]
assert full["verdict"] == "PASS"
assert full["next_action"] == "brain_operational_live_calibrated_transport_proof"
assert full["per_profile_summary"]["mobile_peak"]["status"] == "PASS"
assert scoped["verdict"] == "SCOPED_PASS_REFERENCE_READY"
assert scoped["next_action"] == "brain_operational_live_calibrated_transport_proof"
PY

for transport in https_ws grpc_stream; do
  for profile in clean_fiber mobile_peak congested_wifi slow_mobile middlebox_delay; do
    mkdir -p "${TMP_DIR}/missing-ja/${transport}/${profile}"
    cat >"${TMP_DIR}/missing-ja/${transport}/${profile}/witness-score.json" <<JSON
{
  "transport": "${transport}",
  "netem_profile": "${profile}",
  "score_status": "PASS",
  "runtime_linked": true,
  "pcap_present": true,
  "classifier_clean": true,
  "ndpi_risk_count": 0,
  "suricata_alert_count": 0,
  "inter_arrival_ms_p50": 3,
  "ja3_status": "NOT_MEASURED",
  "ja4_status": "NOT_MEASURED",
  "witness_indistinguishability_score": 0.8,
  "blockers": []
}
JSON
  done
done

cargo run -q -p aegis-measure -- mimicry-matrix-review \
  --matrix-root "${TMP_DIR}/missing-ja" \
  --reference-status-json "${TMP_DIR}/reference-pass.json" \
  --output-json "${TMP_DIR}/missing-ja.json"

python3 - <<'PY' "${TMP_DIR}/missing-ja.json"
import json, sys
review = json.load(open(sys.argv[1], encoding="utf-8"))
assert review["verdict"] != "PASS"
assert review["ja3_status"] == "NOT_MEASURED"
assert review["ja4_status"] == "NOT_MEASURED"
assert any("ja3_not_measured" in item for item in review["blockers"])
assert any("ja4_not_measured" in item for item in review["blockers"])
PY

mkdir -p "${TMP_DIR}/blocked/https_ws/clean_fiber"
cat >"${TMP_DIR}/blocked/https_ws/clean_fiber/witness-score.json" <<'JSON'
{
  "transport": "https_ws",
  "netem_profile": "clean_fiber",
  "score_status": "BLOCKED",
  "runtime_linked": false,
  "pcap_present": true,
  "classifier_clean": true,
  "ndpi_risk_count": 0,
  "suricata_alert_count": 0,
  "ja3_status": "NOT_MEASURED",
  "ja4_status": "NOT_MEASURED",
  "witness_indistinguishability_score": 0.2,
  "blockers": ["runtime_linkage_missing"]
}
JSON

cargo run -q -p aegis-measure -- mimicry-matrix-review \
  --matrix-root "${TMP_DIR}/blocked" \
  --output-json "${TMP_DIR}/blocked.json"

python3 - <<'PY' "${TMP_DIR}/blocked.json"
import json, sys
review = json.load(open(sys.argv[1], encoding="utf-8"))
assert review["verdict"] == "PARTIAL"
assert any("runtime_linkage_missing" in item for item in review["blockers"])
assert any("witness_score_missing" in item for item in review["blockers"])
PY

echo "mimicry http-like witness matrix contract: ok"
