#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-hostile-classifier.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/adversarial.jsonl" <<'JSONL'
{"event":"adversarial_scenario_measured","schema_version":1,"scenario":"masque_derived","transport":"masque_derived","network_profile":"two-vps-linux-tproxy-generic-udp","threshold":0.85,"status":"PASS","packet_evidence_status":"present","packet_capture_size_bytes":473,"tcpdump_packets_captured":1,"tcpdump_packets_dropped_by_kernel":0}
JSONL

bash "${ROOT}/scripts/build-hostile-classifier-summary.sh" \
  --adversarial-jsonl "${TMP_DIR}/adversarial.jsonl" \
  --output-json "${TMP_DIR}/summary-not-run.json" \
  --output-markdown "${TMP_DIR}/summary-not-run.md"

cat >"${TMP_DIR}/classifier-pass.jsonl" <<'JSONL'
{"event":"hostile_classifier_verdict","schema_version":1,"classifier":"suricata","status":"NO_ALERT","scenario":"masque_derived"}
{"event":"hostile_classifier_verdict","schema_version":1,"classifier":"ndpi","status":"CLEAN","scenario":"masque_derived"}
JSONL

bash "${ROOT}/scripts/build-hostile-classifier-summary.sh" \
  --adversarial-jsonl "${TMP_DIR}/adversarial.jsonl" \
  --classifier-jsonl "${TMP_DIR}/classifier-pass.jsonl" \
  --output-json "${TMP_DIR}/summary-pass.json" \
  --output-markdown "${TMP_DIR}/summary-pass.md"

cat >"${TMP_DIR}/classifier-fail.jsonl" <<'JSONL'
{"event":"hostile_classifier_verdict","schema_version":1,"classifier":"suricata","status":"ALERT","scenario":"masque_derived"}
JSONL

bash "${ROOT}/scripts/build-hostile-classifier-summary.sh" \
  --adversarial-jsonl "${TMP_DIR}/adversarial.jsonl" \
  --classifier-jsonl "${TMP_DIR}/classifier-fail.jsonl" \
  --output-json "${TMP_DIR}/summary-fail.json"

jq -e '
  .event == "hostile_classifier_summary" and
  .status == "NOT_RUN" and
  .packet_evidence_records == 1 and
  (.reasons | index("missing-hostile-classifier-events") != null)
' "${TMP_DIR}/summary-not-run.json" >/dev/null
test -f "${TMP_DIR}/summary-not-run.md"

jq -e '
  .status == "PASS" and
  .acceptance_degraded == false and
  .classifier_records == 2 and
  .classifiers == ["ndpi", "suricata"] and
  .verdict_counts.pass == 2
' "${TMP_DIR}/summary-pass.json" >/dev/null

jq -e '
  .status == "FAIL" and
  .verdict_counts.fail == 1 and
  (.reasons | index("hostile-classifier-detected-or-blocked") != null)
' "${TMP_DIR}/summary-fail.json" >/dev/null

echo "PASS: hostile classifier summary contract"
