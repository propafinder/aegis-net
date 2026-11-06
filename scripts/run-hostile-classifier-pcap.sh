#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MEASURE=(cargo run -q -p aegis-measure --)

PCAP=""
OUTPUT_DIR=""
SCENARIO="unknown"
TRANSPORT="unknown"
SURICATA_BIN="${AEGIS_SURICATA_BIN:-suricata}"
NDPI_READER_BIN="${AEGIS_NDPI_READER_BIN:-ndpiReader}"

usage() {
  cat >&2 <<'EOF'
Usage:
  run-hostile-classifier-pcap.sh --pcap PATH --output-dir DIR [options]

Options:
  --scenario NAME       Scenario label copied into verdict events
  --transport NAME      Transport label copied into verdict events

Outputs:
  DIR/verdicts.jsonl
  DIR/suricata/
  DIR/ndpi.json
  DIR/commands.txt

Boundary:
  This wrapper runs available hostile classifier tools over an archived pcap.
  Suricata PASS means no alert records were emitted for the capture. nDPI PASS
  means the reader completed and produced JSON; protocol interpretation remains
  a separate reviewed rule gate.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pcap)
      PCAP="${2:?missing --pcap value}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?missing --output-dir value}"
      shift 2
      ;;
    --scenario)
      SCENARIO="${2:?missing --scenario value}"
      shift 2
      ;;
    --transport)
      TRANSPORT="${2:?missing --transport value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${PCAP}" || -z "${OUTPUT_DIR}" ]]; then
  echo "--pcap and --output-dir are required" >&2
  usage
  exit 2
fi
if [[ ! -s "${PCAP}" ]]; then
  echo "pcap must exist and be non-empty: ${PCAP}" >&2
  exit 2
fi

mkdir -p "${OUTPUT_DIR}/suricata"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"
PCAP="$(cd "$(dirname "${PCAP}")" && pwd)/$(basename "${PCAP}")"
VERDICTS_JSONL="${OUTPUT_DIR}/verdicts.jsonl"
COMMANDS_TXT="${OUTPUT_DIR}/commands.txt"
: >"${VERDICTS_JSONL}"
: >"${COMMANDS_TXT}"

write_verdict() {
  (cd "${ROOT}" && "${MEASURE[@]}" classifier-verdict "$@") >>"${VERDICTS_JSONL}"
}

NDPI_PCAP="${PCAP}"
(cd "${ROOT}" && "${MEASURE[@]}" sll2-to-raw-ip \
  --input-pcap "${PCAP}" \
  --output-pcap "${OUTPUT_DIR}/ndpi-input-rawip.pcap")
if [[ -s "${OUTPUT_DIR}/ndpi-input-rawip.pcap" ]]; then
  NDPI_PCAP="${OUTPUT_DIR}/ndpi-input-rawip.pcap"
fi

if command -v "${SURICATA_BIN}" >/dev/null 2>&1; then
  SURICATA_CMD=("${SURICATA_BIN}" -r "${PCAP}" -l "${OUTPUT_DIR}/suricata" -k none)
  {
    printf 'suricata='
    printf '%q ' "${SURICATA_CMD[@]}"
    printf '\n'
  } >>"${COMMANDS_TXT}"
  if "${SURICATA_CMD[@]}" >"${OUTPUT_DIR}/suricata.stdout.log" 2>"${OUTPUT_DIR}/suricata.stderr.log"; then
    ALERT_COUNT=0
    if [[ -s "${OUTPUT_DIR}/suricata/eve.json" ]]; then
      ALERT_COUNT="$(cd "${ROOT}" && "${MEASURE[@]}" suricata-alert-count --eve-json "${OUTPUT_DIR}/suricata/eve.json")"
    fi
    if [[ "${ALERT_COUNT}" -eq 0 ]]; then
      write_verdict \
        --classifier suricata \
        --status NO_ALERT \
        --scenario "${SCENARIO}" \
        --transport "${TRANSPORT}" \
        --pcap "${PCAP}" \
        --reason "suricata-completed-without-alerts" \
        --alert-count "${ALERT_COUNT}"
    else
      write_verdict \
        --classifier suricata \
        --status ALERT \
        --scenario "${SCENARIO}" \
        --transport "${TRANSPORT}" \
        --pcap "${PCAP}" \
        --reason "suricata-emitted-alerts" \
        --alert-count "${ALERT_COUNT}"
    fi
  else
    write_verdict \
      --classifier suricata \
      --status UNKNOWN \
      --scenario "${SCENARIO}" \
      --transport "${TRANSPORT}" \
      --pcap "${PCAP}" \
      --reason "suricata-execution-failed"
  fi
else
  write_verdict \
    --classifier suricata \
    --status UNKNOWN \
    --scenario "${SCENARIO}" \
    --transport "${TRANSPORT}" \
    --pcap "${PCAP}" \
    --reason "suricata-missing"
fi

if command -v "${NDPI_READER_BIN}" >/dev/null 2>&1; then
  NDPI_JSON="${OUTPUT_DIR}/ndpi.json"
  NDPI_CMD=("${NDPI_READER_BIN}" -i "${NDPI_PCAP}" -w "${NDPI_JSON}")
  {
    printf 'ndpi='
    printf '%q ' "${NDPI_CMD[@]}"
    printf '\n'
  } >>"${COMMANDS_TXT}"
  if "${NDPI_CMD[@]}" >"${OUTPUT_DIR}/ndpi.stdout.log" 2>"${OUTPUT_DIR}/ndpi.stderr.log"; then
    if [[ -s "${NDPI_JSON}" ]]; then
      NDPI_RISK_COUNT="$(cd "${ROOT}" && "${MEASURE[@]}" ndpi-risk-count --ndpi-output "${OUTPUT_DIR}/ndpi.stdout.log")"
      write_verdict \
        --classifier ndpi \
        --status CLEAN \
        --scenario "${SCENARIO}" \
        --transport "${TRANSPORT}" \
        --pcap "${PCAP}" \
        --reason "ndpi-reader-completed" \
        --risk-count "${NDPI_RISK_COUNT}" \
        --json-output "${NDPI_JSON}" \
        --ndpi-input-pcap "${NDPI_PCAP}"
    else
      write_verdict \
        --classifier ndpi \
        --status UNKNOWN \
        --scenario "${SCENARIO}" \
        --transport "${TRANSPORT}" \
        --pcap "${PCAP}" \
        --reason "ndpi-json-output-missing"
    fi
  else
    write_verdict \
      --classifier ndpi \
      --status UNKNOWN \
      --scenario "${SCENARIO}" \
      --transport "${TRANSPORT}" \
      --pcap "${PCAP}" \
      --reason "ndpi-reader-failed"
  fi
else
  write_verdict \
    --classifier ndpi \
    --status UNKNOWN \
    --scenario "${SCENARIO}" \
    --transport "${TRANSPORT}" \
    --pcap "${PCAP}" \
    --reason "ndpi-reader-missing"
fi

if [[ ! -s "${VERDICTS_JSONL}" ]]; then
  echo "classifier wrapper did not write verdicts: ${VERDICTS_JSONL}" >&2
  exit 1
fi

echo "PASS: hostile classifier verdicts written to ${VERDICTS_JSONL}"
