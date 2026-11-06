#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR=""
LABEL="unlabeled"
INPUT_KIND=""
INPUT_VALUE=""
DURATION_SECONDS="10"

usage() {
  cat >&2 <<'EOF'
Usage:
  run-hostile-witness-audit.sh --output-dir DIR --label LABEL [input]

Inputs, choose exactly one:
  --input-pcap PATH       Classic PCAP file with IPv4 TCP packets
  --input-file PATH       Raw TLS record bytes
  --input-hex HEX         Hex-encoded TLS record
  --stdin                 Read raw TLS record bytes from stdin
  --interface IFACE       Capture with tcpdump, then classify the resulting PCAP

Options:
  --duration SECONDS      Interface capture duration, default: 10

Outputs:
  DIR/events.jsonl
  DIR/summary.json
  DIR/summary.md
  DIR/capture.pcap        Only for --interface input
  DIR/tcpdump.stdout.log  Only for --interface input
  DIR/tcpdump.stderr.log  Only for --interface input
  DIR/stdout.log
  DIR/stderr.log
  DIR/commands.txt
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="${2:?missing --output-dir value}"
      shift 2
      ;;
    --label)
      LABEL="${2:?missing --label value}"
      shift 2
      ;;
    --duration)
      DURATION_SECONDS="${2:?missing --duration value}"
      shift 2
      ;;
    --input-pcap|--input-file|--input-hex|--interface)
      if [[ -n "${INPUT_KIND}" ]]; then
        echo "choose exactly one input source" >&2
        usage
        exit 2
      fi
      INPUT_KIND="$1"
      INPUT_VALUE="${2:?missing $1 value}"
      shift 2
      ;;
    --stdin)
      if [[ -n "${INPUT_KIND}" ]]; then
        echo "choose exactly one input source" >&2
        usage
        exit 2
      fi
      INPUT_KIND="$1"
      shift
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

if [[ -z "${OUTPUT_DIR}" ]]; then
  echo "--output-dir is required" >&2
  usage
  exit 2
fi

if [[ -z "${INPUT_KIND}" ]]; then
  echo "one input source is required" >&2
  usage
  exit 2
fi

mkdir -p "${OUTPUT_DIR}"

EVENTS_JSONL="${OUTPUT_DIR}/events.jsonl"
SUMMARY_JSON="${OUTPUT_DIR}/summary.json"
SUMMARY_MD="${OUTPUT_DIR}/summary.md"
STDOUT_LOG="${OUTPUT_DIR}/stdout.log"
STDERR_LOG="${OUTPUT_DIR}/stderr.log"
COMMANDS_TXT="${OUTPUT_DIR}/commands.txt"
TCPDUMP_STDOUT_LOG="${OUTPUT_DIR}/tcpdump.stdout.log"
TCPDUMP_STDERR_LOG="${OUTPUT_DIR}/tcpdump.stderr.log"
CAPTURE_PCAP="${OUTPUT_DIR}/capture.pcap"

if [[ "${INPUT_KIND}" == "--interface" ]]; then
  TCPDUMP_BIN="${AEGIS_TCPDUMP_BIN:-tcpdump}"
  if ! command -v "${TCPDUMP_BIN}" >/dev/null 2>&1; then
    echo "tcpdump is required for --interface capture" >&2
    exit 1
  fi

  TCPDUMP_CMD=("${TCPDUMP_BIN}" -i "${INPUT_VALUE}" -s 0 -w "${CAPTURE_PCAP}" tcp)
  {
    printf 'tcpdump_command='
    printf '%q ' "${TCPDUMP_CMD[@]}"
    printf '\n'
  } >>"${COMMANDS_TXT}"

  "${TCPDUMP_CMD[@]}" >"${TCPDUMP_STDOUT_LOG}" 2>"${TCPDUMP_STDERR_LOG}" &
  TCPDUMP_PID=$!
  sleep "${DURATION_SECONDS}"
  kill -INT "${TCPDUMP_PID}" >/dev/null 2>&1 || true
  wait "${TCPDUMP_PID}" >/dev/null 2>&1 || true

  if [[ ! -f "${CAPTURE_PCAP}" ]]; then
    echo "tcpdump did not write capture: ${CAPTURE_PCAP}" >&2
    exit 1
  fi

  INPUT_KIND="--input-pcap"
  INPUT_VALUE="${CAPTURE_PCAP}"
fi

WITNESS_BIN="${AEGIS_WITNESS_BIN:-}"
CMD=()
if [[ -n "${WITNESS_BIN}" ]]; then
  CMD=("${WITNESS_BIN}")
elif [[ -x "${ROOT}/target/release/aegis-witness" ]]; then
  CMD=("${ROOT}/target/release/aegis-witness")
elif [[ -x "${ROOT}/target/debug/aegis-witness" ]]; then
  CMD=("${ROOT}/target/debug/aegis-witness")
else
  CMD=(cargo run -p aegis-witness --)
fi

CMD+=(
  "${INPUT_KIND}"
)
if [[ "${INPUT_KIND}" != "--stdin" ]]; then
  CMD+=("${INPUT_VALUE}")
fi
CMD+=(
  --label "${LABEL}"
  --output-jsonl "${EVENTS_JSONL}"
  --summary-json "${SUMMARY_JSON}"
  --summary-markdown "${SUMMARY_MD}"
)

{
  printf 'cwd=%q\n' "${ROOT}"
  printf 'command='
  printf '%q ' "${CMD[@]}"
  printf '\n'
} >"${COMMANDS_TXT}"

"${CMD[@]}" >"${STDOUT_LOG}" 2>"${STDERR_LOG}"

if [[ ! -s "${EVENTS_JSONL}" ]]; then
  echo "witness did not write events: ${EVENTS_JSONL}" >&2
  exit 1
fi
if [[ ! -s "${SUMMARY_JSON}" ]]; then
  echo "witness did not write summary json: ${SUMMARY_JSON}" >&2
  exit 1
fi
if [[ ! -s "${SUMMARY_MD}" ]]; then
  echo "witness did not write summary markdown: ${SUMMARY_MD}" >&2
  exit 1
fi

echo "PASS: hostile witness audit output written to ${OUTPUT_DIR}"
