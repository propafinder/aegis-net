#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-hostile-classifier-pcap.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

printf 'pcap-placeholder-with-bytes\n' >"${TMP_DIR}/capture.pcap"

FAKE_SURICATA="${TMP_DIR}/suricata"
cat >"${FAKE_SURICATA}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -l)
      out="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "${out}"
cat >"${out}/eve.json" <<'JSONL'
{"event_type":"flow","proto":"UDP"}
JSONL
EOF
chmod +x "${FAKE_SURICATA}"

FAKE_NDPI="${TMP_DIR}/ndpiReader"
cat >"${FAKE_NDPI}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -j|-w)
      json="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '{"detected_protocols":[]}\n' >"${json}"
EOF
chmod +x "${FAKE_NDPI}"

AEGIS_SURICATA_BIN="${FAKE_SURICATA}" \
AEGIS_NDPI_READER_BIN="${FAKE_NDPI}" \
bash "${ROOT}/scripts/run-hostile-classifier-pcap.sh" \
  --pcap "${TMP_DIR}/capture.pcap" \
  --output-dir "${TMP_DIR}/out" \
  --scenario masque_derived \
  --transport masque_derived >/dev/null

jq -s -e '
  (map(select(.classifier == "suricata"))[0].status == "NO_ALERT") and
  (map(select(.classifier == "suricata"))[0].alert_count == 0) and
  (map(select(.classifier == "ndpi"))[0].status == "CLEAN") and
  (map(select(.classifier == "ndpi"))[0].risk_count == 0) and
  (map(select(.classifier == "ndpi"))[0].json_output | endswith("ndpi.json"))
' <"${TMP_DIR}/out/verdicts.jsonl" >/dev/null
test -f "${TMP_DIR}/out/commands.txt"

cat >"${TMP_DIR}/ndpi-risk.stdout" <<'EOF'
Risk stats [found 2 (100.0 %) flows with risks]:
	Known Protocol on Non Standard Port          1 [50.0 %]
	Missing SNI TLS Extension                    1 [50.0 %]

	NOTE: as one flow can have multiple risks set, the sum of the
EOF

RISK_COUNT="$(
  cd "${ROOT}" && cargo run -q -p aegis-measure -- ndpi-risk-count \
    --ndpi-output "${TMP_DIR}/ndpi-risk.stdout"
)"
if [[ "${RISK_COUNT}" != "2" ]]; then
  echo "expected nDPI risk count 2, got ${RISK_COUNT}" >&2
  exit 1
fi

RISK_VERDICT="$(
  cd "${ROOT}" && cargo run -q -p aegis-measure -- classifier-verdict \
    --classifier ndpi \
    --status CLEAN \
    --scenario masque_derived \
    --transport masque_derived \
    --pcap "${TMP_DIR}/capture.pcap" \
    --reason ndpi-reader-completed \
    --risk-count "${RISK_COUNT}"
)"
if ! jq -e '.status == "DETECTED" and .reason == "ndpi-risk-stats-detected" and .risk_count == 2' \
  <<<"${RISK_VERDICT}" >/dev/null; then
  echo "expected nDPI risk verdict to be detected: ${RISK_VERDICT}" >&2
  exit 1
fi

if bash "${ROOT}/scripts/run-hostile-classifier-pcap.sh" \
  --pcap "${TMP_DIR}/missing.pcap" \
  --output-dir "${TMP_DIR}/bad" >/dev/null 2>&1; then
  echo "expected missing pcap failure" >&2
  exit 1
fi

echo "PASS: hostile classifier pcap contract"
