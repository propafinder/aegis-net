#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR=""
WITNESS_LABEL="legacy_tls"
WITNESS_INPUT_KIND=""
WITNESS_INPUT_VALUE=""
WITNESS_EVENTS_JSONL=""
SKIP_BUILD=0
SKIP_KNOWLEDGE_CHECK=0
APPLY_CLIENT_CONFIG=""
ADVERSARIAL_LIVE_COMMAND=""
ADVERSARIAL_SCENARIO=""
ADVERSARIAL_NETWORK_PROFILE=""
ADVERSARIAL_LIVE_MATRIX=0
ADVERSARIAL_EVENTS_JSONL=""
HOSTILE_CLASSIFIER_JSONL=""

usage() {
  cat >&2 <<'EOF'
Usage:
  run-phase-a-measure-gate.sh --output-dir DIR --witness-input-hex HEX [options]
  run-phase-a-measure-gate.sh --output-dir DIR --witness-input-file PATH [options]
  run-phase-a-measure-gate.sh --output-dir DIR --witness-input-pcap PATH [options]

Options:
  --witness-label LABEL          Label for witness events, default: legacy_tls
  --witness-events-jsonl PATH    Import an existing witness JSONL stream
  --apply-client-config PATH     Apply generated calibration summary to this client config/state
  --adversarial-live-command CMD Run one bounded measured adversarial probe
  --adversarial-scenario NAME    Scenario for --adversarial-live-command
  --adversarial-network-profile NAME
                                  Network profile for --adversarial-live-command
  --adversarial-live-matrix       Run --adversarial-live-command across the
                                  default scenario/profile matrix
  --adversarial-events-jsonl PATH Import an existing measured/planned
                                  adversarial JSONL evidence stream
  --hostile-classifier-jsonl PATH Import hostile classifier verdict JSONL
  --skip-build                   Skip cargo build -p aegis-witness --release
  --skip-knowledge-check         Skip scripts/check-knowledge-corpus.sh

Outputs:
  DIR/witness/events.jsonl
  DIR/witness/summary.json
  DIR/adversarial/events.jsonl
  DIR/classifier/summary.json
  DIR/classifier/summary.md
  DIR/calibration/summary.json
  DIR/calibration/summary.md
  DIR/phase-a-gate-review.json
  DIR/phase-a-gate-review.md

Boundary:
  This runner creates Phase A measurement evidence. Without
  --adversarial-live-command the adversarial side remains planned-only.
  With --adversarial-live-command it records a bounded measured command
  result; stronger live claims still require the command to exercise a real
  AEGIS traffic path and packet capture to be archived.
  With --adversarial-events-jsonl it imports an existing A2 evidence stream;
  the evidence boundary is inherited from that stream.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="${2:?missing --output-dir value}"
      shift 2
      ;;
    --witness-label)
      WITNESS_LABEL="${2:?missing --witness-label value}"
      shift 2
      ;;
    --witness-input-hex)
      WITNESS_INPUT_KIND="--input-hex"
      WITNESS_INPUT_VALUE="${2:?missing --witness-input-hex value}"
      shift 2
      ;;
    --witness-input-file)
      WITNESS_INPUT_KIND="--input-file"
      WITNESS_INPUT_VALUE="${2:?missing --witness-input-file value}"
      shift 2
      ;;
    --witness-input-pcap)
      WITNESS_INPUT_KIND="--input-pcap"
      WITNESS_INPUT_VALUE="${2:?missing --witness-input-pcap value}"
      shift 2
      ;;
    --witness-events-jsonl)
      WITNESS_EVENTS_JSONL="${2:?missing --witness-events-jsonl value}"
      shift 2
      ;;
    --apply-client-config)
      APPLY_CLIENT_CONFIG="${2:?missing --apply-client-config value}"
      shift 2
      ;;
    --adversarial-live-command)
      ADVERSARIAL_LIVE_COMMAND="${2:?missing --adversarial-live-command value}"
      shift 2
      ;;
    --adversarial-scenario)
      ADVERSARIAL_SCENARIO="${2:?missing --adversarial-scenario value}"
      shift 2
      ;;
    --adversarial-network-profile)
      ADVERSARIAL_NETWORK_PROFILE="${2:?missing --adversarial-network-profile value}"
      shift 2
      ;;
    --adversarial-live-matrix)
      ADVERSARIAL_LIVE_MATRIX=1
      shift
      ;;
    --adversarial-events-jsonl)
      ADVERSARIAL_EVENTS_JSONL="${2:?missing --adversarial-events-jsonl value}"
      shift 2
      ;;
    --hostile-classifier-jsonl)
      HOSTILE_CLASSIFIER_JSONL="${2:?missing --hostile-classifier-jsonl value}"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --skip-knowledge-check)
      SKIP_KNOWLEDGE_CHECK=1
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

if [[ -n "${WITNESS_EVENTS_JSONL}" ]]; then
  if [[ -n "${WITNESS_INPUT_KIND}" ]]; then
    echo "--witness-events-jsonl cannot be combined with witness input flags" >&2
    usage
    exit 2
  fi
  if [[ ! -s "${WITNESS_EVENTS_JSONL}" ]]; then
    echo "--witness-events-jsonl must point to a non-empty file" >&2
    usage
    exit 2
  fi
elif [[ -z "${WITNESS_INPUT_KIND}" ]]; then
  echo "one witness input or --witness-events-jsonl is required" >&2
  usage
  exit 2
fi

if [[ -n "${HOSTILE_CLASSIFIER_JSONL}" && ! -s "${HOSTILE_CLASSIFIER_JSONL}" ]]; then
  echo "--hostile-classifier-jsonl must point to a non-empty file" >&2
  usage
  exit 2
fi

if [[ -n "${ADVERSARIAL_EVENTS_JSONL}" ]]; then
  if [[ -n "${ADVERSARIAL_LIVE_COMMAND}" || "${ADVERSARIAL_LIVE_MATRIX}" == "1" ]]; then
    echo "--adversarial-events-jsonl cannot be combined with --adversarial-live-command or --adversarial-live-matrix" >&2
    usage
    exit 2
  fi
  if [[ ! -s "${ADVERSARIAL_EVENTS_JSONL}" ]]; then
    echo "--adversarial-events-jsonl must point to a non-empty file" >&2
    usage
    exit 2
  fi
elif [[ -n "${ADVERSARIAL_LIVE_COMMAND}" ]]; then
  if [[ "${ADVERSARIAL_LIVE_MATRIX}" != "1" && ( -z "${ADVERSARIAL_SCENARIO}" || -z "${ADVERSARIAL_NETWORK_PROFILE}" ) ]]; then
    echo "--adversarial-live-command requires --adversarial-scenario and --adversarial-network-profile unless --adversarial-live-matrix is set" >&2
    usage
    exit 2
  fi
elif [[ "${ADVERSARIAL_LIVE_MATRIX}" == "1" ]]; then
  echo "--adversarial-live-matrix requires --adversarial-live-command" >&2
  usage
  exit 2
fi

mkdir -p "${OUTPUT_DIR}/witness" "${OUTPUT_DIR}/adversarial" "${OUTPUT_DIR}/classifier" "${OUTPUT_DIR}/calibration"

COMMANDS_TXT="${OUTPUT_DIR}/commands.txt"
: >"${COMMANDS_TXT}"

run_and_log() {
  local name="$1"
  shift
  {
    printf '%s=' "${name}"
    printf '%q ' "$@"
    printf '\n'
  } >>"${COMMANDS_TXT}"
  "$@"
}

if [[ "${SKIP_BUILD}" != "1" ]]; then
  run_and_log build_witness cargo build -p aegis-witness --release
fi

if [[ "${SKIP_KNOWLEDGE_CHECK}" != "1" ]]; then
  run_and_log knowledge_check bash "${ROOT}/scripts/check-knowledge-corpus.sh" \
    >"${OUTPUT_DIR}/knowledge.stdout.log" \
    2>"${OUTPUT_DIR}/knowledge.stderr.log"
fi

if [[ -n "${WITNESS_EVENTS_JSONL}" ]]; then
  run_and_log witness_import cp "${WITNESS_EVENTS_JSONL}" "${OUTPUT_DIR}/witness/events.jsonl"
  run_and_log witness_import_summary cargo run -p aegis-witness -- \
    --summarize-jsonl "${OUTPUT_DIR}/witness/events.jsonl" \
    --summary-json "${OUTPUT_DIR}/witness/summary.json" \
    --summary-markdown "${OUTPUT_DIR}/witness/summary.md"
else
  run_and_log witness_audit bash "${ROOT}/scripts/run-hostile-witness-audit.sh" \
    --output-dir "${OUTPUT_DIR}/witness" \
    --label "${WITNESS_LABEL}" \
    "${WITNESS_INPUT_KIND}" "${WITNESS_INPUT_VALUE}"
fi

if [[ -n "${ADVERSARIAL_EVENTS_JSONL}" ]]; then
  run_and_log adversarial_import cp "${ADVERSARIAL_EVENTS_JSONL}" "${OUTPUT_DIR}/adversarial/events.jsonl"
elif [[ -n "${ADVERSARIAL_LIVE_COMMAND}" ]]; then
  if [[ "${ADVERSARIAL_LIVE_MATRIX}" == "1" ]]; then
    run_and_log adversarial_measured_matrix bash "${ROOT}/scripts/run-adversarial-evasion-test.sh" \
      --live-matrix \
      --live-command "${ADVERSARIAL_LIVE_COMMAND}" \
      --output-jsonl "${OUTPUT_DIR}/adversarial/events.jsonl"
  else
    run_and_log adversarial_measured bash "${ROOT}/scripts/run-adversarial-evasion-test.sh" \
      --scenario "${ADVERSARIAL_SCENARIO}" \
      --network-profile "${ADVERSARIAL_NETWORK_PROFILE}" \
      --live-command "${ADVERSARIAL_LIVE_COMMAND}" \
      --output-jsonl "${OUTPUT_DIR}/adversarial/events.jsonl"
  fi
else
  run_and_log adversarial_dry_run bash "${ROOT}/scripts/run-adversarial-evasion-test.sh" \
    --dry-run \
    --output-jsonl "${OUTPUT_DIR}/adversarial/events.jsonl"
fi

run_and_log calibration_summary bash "${ROOT}/scripts/build-external-calibration-summary.sh" \
  --witness-jsonl "${OUTPUT_DIR}/witness/events.jsonl" \
  --adversarial-jsonl "${OUTPUT_DIR}/adversarial/events.jsonl" \
  --output-json "${OUTPUT_DIR}/calibration/summary.json" \
  --output-markdown "${OUTPUT_DIR}/calibration/summary.md"

CLASSIFIER_CMD=(
  bash "${ROOT}/scripts/build-hostile-classifier-summary.sh"
  --adversarial-jsonl "${OUTPUT_DIR}/adversarial/events.jsonl"
  --output-json "${OUTPUT_DIR}/classifier/summary.json"
  --output-markdown "${OUTPUT_DIR}/classifier/summary.md"
)
if [[ -n "${HOSTILE_CLASSIFIER_JSONL}" ]]; then
  CLASSIFIER_CMD+=(--classifier-jsonl "${HOSTILE_CLASSIFIER_JSONL}")
fi
run_and_log hostile_classifier_summary "${CLASSIFIER_CMD[@]}"

if [[ -n "${APPLY_CLIENT_CONFIG}" ]]; then
  run_and_log apply_calibration cargo run -p aegis-client -- \
    --config "${APPLY_CLIENT_CONFIG}" \
    --runtime-events-jsonl "${OUTPUT_DIR}/calibration/runtime-events.jsonl" \
    --apply-external-calibration-summary "${OUTPUT_DIR}/calibration/summary.json" \
    --json \
    >"${OUTPUT_DIR}/calibration/apply.stdout.log" \
    2>"${OUTPUT_DIR}/calibration/apply.stderr.log"
fi

GATE_REVIEW_CMD=(cargo run -q -p aegis-measure -- phase-a-measure-gate-review --output-dir "${OUTPUT_DIR}")
if [[ "${SKIP_KNOWLEDGE_CHECK}" == "1" ]]; then
  GATE_REVIEW_CMD+=(--skip-knowledge-check)
fi
if [[ -n "${APPLY_CLIENT_CONFIG}" ]]; then
  GATE_REVIEW_CMD+=(--applied)
fi
run_and_log phase_a_gate_review "${GATE_REVIEW_CMD[@]}"

echo "PASS: Phase A measure gate artifacts written to ${OUTPUT_DIR}"
