#!/usr/bin/env bash
set -euo pipefail

PCAP_PATH=""
RUNTIME_EVENTS_JSONL=""
OUTPUT_PATH=""
TSHARK_BIN="${AEGIS_MIMICRY_WIRE_TSHARK_BIN:-tshark}"
WINDOW_MS="${AEGIS_MIMICRY_WIRE_WITNESS_WINDOW_MS:-2000}"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-mimicry-wire-witness-summary.sh \
    --pcap <path> \
    --runtime-events <path> \
    --output <path> \
    [--tshark-bin <path>] \
    [--window-ms <ms>]

Build an independent wire witness summary from an external pcap/tshark view.

Required:
  --pcap PATH            Input pcap/pcapng file.
  --runtime-events PATH  Runtime events JSONL to correlate against.
  --output PATH          Output witness summary JSON.

Optional:
  --tshark-bin PATH      tshark binary to use (default: tshark).
  --window-ms MS         Symmetric capture window around active runtime events.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pcap)
      PCAP_PATH="${2:-}"
      shift 2
      ;;
    --runtime-events)
      RUNTIME_EVENTS_JSONL="${2:-}"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="${2:-}"
      shift 2
      ;;
    --tshark-bin)
      TSHARK_BIN="${2:-}"
      shift 2
      ;;
    --window-ms)
      WINDOW_MS="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
done

[[ -n "${PCAP_PATH}" ]] || { usage >&2; exit 1; }
[[ -f "${PCAP_PATH}" ]] || { echo "pcap file not found: ${PCAP_PATH}" >&2; exit 1; }
[[ -n "${RUNTIME_EVENTS_JSONL}" ]] || { usage >&2; exit 1; }
[[ -f "${RUNTIME_EVENTS_JSONL}" ]] || { echo "runtime events file not found: ${RUNTIME_EVENTS_JSONL}" >&2; exit 1; }
[[ -n "${OUTPUT_PATH}" ]] || { usage >&2; exit 1; }
command -v "${TSHARK_BIN}" >/dev/null 2>&1 || { echo "tshark not found: ${TSHARK_BIN}" >&2; exit 1; }
mkdir -p "$(dirname "${OUTPUT_PATH}")"

cargo run -q -p aegis-measure -- build-mimicry-wire-witness-summary \
  --pcap "${PCAP_PATH}" \
  --runtime-events "${RUNTIME_EVENTS_JSONL}" \
  --output "${OUTPUT_PATH}" \
  --tshark-bin "${TSHARK_BIN}" \
  --window-ms "${WINDOW_MS}"
