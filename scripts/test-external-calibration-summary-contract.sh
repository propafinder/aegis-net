#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-calibration-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/witness.jsonl" <<'JSONL'
{"event":"witness_tls_classification","schema_version":1,"label":"https_ws","score":{"combined":0.8,"ja3_present":1.0,"alpn_match":1.0,"sni_structure":0.6}}
{"event":"witness_tls_classification","schema_version":1,"label":"https_ws","score":{"combined":0.6,"ja3_present":1.0,"alpn_match":0.5,"sni_structure":0.5}}
JSONL

cat >"${TMP_DIR}/adversarial.jsonl" <<'JSONL'
{"event":"adversarial_scenario_result","schema_version":1,"transport":"https_ws","network_profile":"clean-fiber","threshold":0.85,"status":"PASS"}
{"event":"adversarial_scenario_result","schema_version":1,"transport":"https_ws","network_profile":"mobile-lossy","threshold":0.85,"status":"FAIL"}
{"event":"adversarial_scenario_planned","schema_version":1,"transport":"legacy_tls","network_profile":"clean-fiber","threshold":0.85,"status":"PLANNED"}
JSONL

bash "${ROOT}/scripts/build-external-calibration-summary.sh" \
  --witness-jsonl "${TMP_DIR}/witness.jsonl" \
  --adversarial-jsonl "${TMP_DIR}/adversarial.jsonl" \
  --output-json "${TMP_DIR}/summary.json" \
  --output-markdown "${TMP_DIR}/summary.md"

cargo run -q -p aegis-measure -- external-calibration-contract-check \
  --summary-json "${TMP_DIR}/summary.json" \
  --summary-markdown "${TMP_DIR}/summary.md"

echo "PASS: external calibration summary contract"
