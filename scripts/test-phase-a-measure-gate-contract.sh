#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-a-gate-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

FAKE_WITNESS="${TMP_DIR}/aegis-witness"
cat >"${FAKE_WITNESS}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

events=""
summary_json=""
summary_markdown=""
label="unlabeled"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-jsonl)
      events="$2"
      shift 2
      ;;
    --summary-json)
      summary_json="$2"
      shift 2
      ;;
    --summary-markdown)
      summary_markdown="$2"
      shift 2
      ;;
    --label)
      label="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

mkdir -p "$(dirname "${events}")"
cat >"${events}" <<JSONL
{"event":"witness_tls_classification","label":"${label}","score":{"combined":0.75,"ja3_present":1.0,"alpn_match":0.8,"sni_structure":0.7}}
JSONL
cat >"${summary_json}" <<JSON
{"schema_version":1,"total_records":1,"groups":[{"label":"${label}","total_records":1,"combined_avg":0.75}]}
JSON
printf '# Witness Summary\n\n| Label | Records |\n|---|---:|\n| %s | 1 |\n' "${label}" >"${summary_markdown}"
EOF
chmod +x "${FAKE_WITNESS}"

AEGIS_WITNESS_BIN="${FAKE_WITNESS}" \
bash "${ROOT}/scripts/run-phase-a-measure-gate.sh" \
  --output-dir "${TMP_DIR}/gate" \
  --witness-input-hex "1603010000" \
  --witness-label https_ws \
  --skip-build \
  --skip-knowledge-check >/dev/null

AEGIS_WITNESS_BIN="${FAKE_WITNESS}" \
bash "${ROOT}/scripts/run-phase-a-measure-gate.sh" \
  --output-dir "${TMP_DIR}/gate-measured" \
  --witness-input-hex "1603010000" \
  --witness-label https_ws \
  --adversarial-scenario https_ws \
  --adversarial-network-profile clean-fiber \
  --adversarial-live-command "true" \
  --skip-build \
  --skip-knowledge-check >/dev/null

AEGIS_WITNESS_BIN="${FAKE_WITNESS}" \
bash "${ROOT}/scripts/run-phase-a-measure-gate.sh" \
  --output-dir "${TMP_DIR}/gate-measured-matrix" \
  --witness-input-hex "1603010000" \
  --witness-label https_ws \
  --adversarial-live-matrix \
  --adversarial-live-command "true" \
  --skip-build \
  --skip-knowledge-check >/dev/null

cat >"${TMP_DIR}/imported-adversarial.jsonl" <<'JSONL'
{"event":"adversarial_scenario_measured","schema_version":1,"scenario":"masque_derived","transport":"masque_derived","network_profile":"two-vps-linux-tproxy-generic-udp","threshold":0.85,"status":"PASS","packet_evidence_status":"present","packet_capture_size_bytes":473,"tcpdump_packets_captured":1,"tcpdump_packets_dropped_by_kernel":0}
JSONL
cat >"${TMP_DIR}/classifier-pass.jsonl" <<'JSONL'
{"event":"hostile_classifier_verdict","schema_version":1,"classifier":"suricata","status":"NO_ALERT","scenario":"masque_derived"}
JSONL

AEGIS_WITNESS_BIN="${FAKE_WITNESS}" \
bash "${ROOT}/scripts/run-phase-a-measure-gate.sh" \
  --output-dir "${TMP_DIR}/gate-imported" \
  --witness-input-hex "1603010000" \
  --witness-label https_ws \
  --adversarial-events-jsonl "${TMP_DIR}/imported-adversarial.jsonl" \
  --hostile-classifier-jsonl "${TMP_DIR}/classifier-pass.jsonl" \
  --skip-build \
  --skip-knowledge-check >/dev/null

cat >"${TMP_DIR}/imported-witness.jsonl" <<'JSONL'
{"event":"witness_tls_classification","schema_version":1,"label":"legacy_tls","record":null,"classification":{"is_tls_client_hello":true,"legacy_version":771,"cipher_suites":[47],"extension_types":[0,16],"supported_groups":[],"sni":"legacy.example","alpn":["h2"],"ja3":"771,47,0-16,,","ja3_md5":"0123456789abcdef0123456789abcdef"},"score":{"combined":1.0,"ja3_present":1.0,"alpn_match":1.0,"sni_structure":1.0,"extension_structure":1.0}}
{"event":"witness_tls_classification","schema_version":1,"label":"https_ws","record":null,"classification":{"is_tls_client_hello":true,"legacy_version":771,"cipher_suites":[47],"extension_types":[0,16],"supported_groups":[],"sni":"ws.example","alpn":["h2"],"ja3":"771,47,0-16,,","ja3_md5":"0123456789abcdef0123456789abcdef"},"score":{"combined":1.0,"ja3_present":1.0,"alpn_match":1.0,"sni_structure":1.0,"extension_structure":1.0}}
JSONL

bash "${ROOT}/scripts/run-phase-a-measure-gate.sh" \
  --output-dir "${TMP_DIR}/gate-imported-witness" \
  --witness-events-jsonl "${TMP_DIR}/imported-witness.jsonl" \
  --adversarial-events-jsonl "${TMP_DIR}/imported-adversarial.jsonl" \
  --skip-build \
  --skip-knowledge-check >/dev/null

cargo run -q -p aegis-measure -- phase-a-measure-gate-contract-check \
  --gate "${TMP_DIR}/gate" \
  --measured-gate "${TMP_DIR}/gate-measured" \
  --matrix-gate "${TMP_DIR}/gate-measured-matrix" \
  --imported-gate "${TMP_DIR}/gate-imported" \
  --imported-witness-gate "${TMP_DIR}/gate-imported-witness"

if bash "${ROOT}/scripts/run-phase-a-measure-gate.sh" --output-dir "${TMP_DIR}/bad" >/dev/null 2>&1; then
  echo "expected missing witness input failure" >&2
  exit 1
fi

if bash "${ROOT}/scripts/run-phase-a-measure-gate.sh" \
  --output-dir "${TMP_DIR}/bad-live" \
  --witness-input-hex "1603010000" \
  --adversarial-live-command "true" >/dev/null 2>&1; then
  echo "expected live command without scenario/profile failure" >&2
  exit 1
fi

if bash "${ROOT}/scripts/run-phase-a-measure-gate.sh" \
  --output-dir "${TMP_DIR}/bad-matrix" \
  --witness-input-hex "1603010000" \
  --adversarial-live-matrix >/dev/null 2>&1; then
  echo "expected live matrix without command failure" >&2
  exit 1
fi

if bash "${ROOT}/scripts/run-phase-a-measure-gate.sh" \
  --output-dir "${TMP_DIR}/bad-import-combo" \
  --witness-input-hex "1603010000" \
  --adversarial-events-jsonl "${TMP_DIR}/imported-adversarial.jsonl" \
  --adversarial-live-command "true" >/dev/null 2>&1; then
  echo "expected imported adversarial events plus live command failure" >&2
  exit 1
fi

if bash "${ROOT}/scripts/run-phase-a-measure-gate.sh" \
  --output-dir "${TMP_DIR}/bad-classifier" \
  --witness-input-hex "1603010000" \
  --hostile-classifier-jsonl "${TMP_DIR}/missing-classifier.jsonl" >/dev/null 2>&1; then
  echo "expected missing hostile classifier jsonl failure" >&2
  exit 1
fi

if bash "${ROOT}/scripts/run-phase-a-measure-gate.sh" \
  --output-dir "${TMP_DIR}/bad-witness-import-combo" \
  --witness-events-jsonl "${TMP_DIR}/imported-witness.jsonl" \
  --witness-input-hex "1603010000" >/dev/null 2>&1; then
  echo "expected imported witness events plus witness input failure" >&2
  exit 1
fi

echo "PASS: Phase A measure gate contract"
