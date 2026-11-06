#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

BASELINE_JSON=""
RUNTIME_EVENTS_JSONL=""
OUTPUT_DIR=""
ARTIFACT_DIR=""
REQUIRE_RELAY_SHAPE_DIVERSITY=0
REQUIRE_FINISHED_PROBE=0
ALLOW_REVIEW_FAILURES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-dir)
      ARTIFACT_DIR="${2:?missing --artifact-dir value}"
      shift 2
      ;;
    --baseline-json)
      BASELINE_JSON="${2:?missing --baseline-json value}"
      shift 2
      ;;
    --runtime-events-jsonl)
      RUNTIME_EVENTS_JSONL="${2:?missing --runtime-events-jsonl value}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?missing --output-dir value}"
      shift 2
      ;;
    --require-relay-shape-diversity)
      REQUIRE_RELAY_SHAPE_DIVERSITY=1
      shift
      ;;
    --require-finished-probe)
      REQUIRE_FINISHED_PROBE=1
      shift
      ;;
    --allow-review-failures)
      ALLOW_REVIEW_FAILURES=1
      shift
      ;;
    -h|--help)
      cat <<'USAGE'
Usage:
  scripts/build-phase-b-runtime-evidence-bundle.sh \
    --baseline-json <phase-b-baseline-review.json> \
    --runtime-events-jsonl <runtime-events.jsonl> \
    --output-dir <artifact-dir> \
    [--require-relay-shape-diversity] \
    [--require-finished-probe] \
    [--allow-review-failures]

  scripts/build-phase-b-runtime-evidence-bundle.sh \
    --artifact-dir <live-artifact-dir> \
    [--baseline-json <phase-b-baseline-review.json>] \
    [--runtime-events-jsonl <runtime-events.jsonl>] \
    [--output-dir <artifact-dir>/phase-b-runtime-evidence] \
    [--allow-review-failures]
USAGE
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -n "${ARTIFACT_DIR}" ]]; then
  if [[ -z "${BASELINE_JSON}" ]]; then
    BASELINE_JSON="${ARTIFACT_DIR}/phase-b-baseline-review.json"
  fi
  if [[ -z "${RUNTIME_EVENTS_JSONL}" ]]; then
    RUNTIME_EVENTS_JSONL="${ARTIFACT_DIR}/runtime-events.jsonl"
  fi
  if [[ -z "${OUTPUT_DIR}" ]]; then
    OUTPUT_DIR="${ARTIFACT_DIR}/phase-b-runtime-evidence"
  fi
fi

if [[ -z "${BASELINE_JSON}" || -z "${RUNTIME_EVENTS_JSONL}" || -z "${OUTPUT_DIR}" ]]; then
  echo "missing required --artifact-dir or explicit --baseline-json, --runtime-events-jsonl, and --output-dir" >&2
  exit 2
fi
if [[ ! -f "${BASELINE_JSON}" ]]; then
  echo "baseline json not found: ${BASELINE_JSON}" >&2
  exit 2
fi
if [[ ! -f "${RUNTIME_EVENTS_JSONL}" ]]; then
  echo "runtime events jsonl not found: ${RUNTIME_EVENTS_JSONL}" >&2
  exit 2
fi

mkdir -p "${OUTPUT_DIR}"

run_review_command() {
  local rc=0
  "$@" || rc=$?
  if [[ "${rc}" -ne 0 && "${ALLOW_REVIEW_FAILURES}" -ne 1 ]]; then
    exit "${rc}"
  fi
  return 0
}

TLS_WIRE_JSON="${OUTPUT_DIR}/phase-b-tls-wire-review.json"
TLS_WIRE_MD="${OUTPUT_DIR}/phase-b-tls-wire-review.md"
RELAY_SHAPE_JSON="${OUTPUT_DIR}/phase-b-relay-shape-review.json"
RELAY_SHAPE_MD="${OUTPUT_DIR}/phase-b-relay-shape-review.md"
ACTIVE_PROBE_JSON="${OUTPUT_DIR}/phase-b-active-probe-review.json"
ACTIVE_PROBE_MD="${OUTPUT_DIR}/phase-b-active-probe-review.md"
LIVE_EVIDENCE_JSON="${OUTPUT_DIR}/phase-b-live-evidence-review.json"
LIVE_EVIDENCE_MD="${OUTPUT_DIR}/phase-b-live-evidence-review.md"
MANIFEST_JSON="${OUTPUT_DIR}/phase-b-runtime-evidence.manifest.json"
MANIFEST_MD="${OUTPUT_DIR}/phase-b-runtime-evidence.manifest.md"
MASTER_PLAN_STATUS_JSON="${OUTPUT_DIR}/phase-b-master-plan-status.json"
MASTER_PLAN_STATUS_MD="${OUTPUT_DIR}/phase-b-master-plan-status.md"

run_review_command cargo run -q -p aegis-measure -- phase-b-tls-wire-review \
  --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}" \
  --output-json "${TLS_WIRE_JSON}" \
  --output-markdown "${TLS_WIRE_MD}"

relay_shape_args=(
  --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}"
  --output-json "${RELAY_SHAPE_JSON}"
  --output-markdown "${RELAY_SHAPE_MD}"
)
if [[ "${REQUIRE_RELAY_SHAPE_DIVERSITY}" -eq 1 ]]; then
  relay_shape_args+=(--require-diversity)
fi
run_review_command cargo run -q -p aegis-measure -- phase-b-relay-shape-review "${relay_shape_args[@]}"

active_probe_args=(
  --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}"
  --output-json "${ACTIVE_PROBE_JSON}"
  --output-markdown "${ACTIVE_PROBE_MD}"
)
if [[ "${REQUIRE_FINISHED_PROBE}" -eq 1 ]]; then
  active_probe_args+=(--require-finished-probe)
fi
run_review_command cargo run -q -p aegis-measure -- phase-b-active-probe-review "${active_probe_args[@]}"

run_review_command bash scripts/build-phase-b-live-evidence-review.sh \
  --baseline-json "${BASELINE_JSON}" \
  --tls-wire-json "${TLS_WIRE_JSON}" \
  --relay-shape-json "${RELAY_SHAPE_JSON}" \
  --active-probe-json "${ACTIVE_PROBE_JSON}" \
  --output-json "${LIVE_EVIDENCE_JSON}" \
  --output-markdown "${LIVE_EVIDENCE_MD}"

manifest_args=(
  --tls-wire-json "${TLS_WIRE_JSON}"
  --relay-shape-json "${RELAY_SHAPE_JSON}"
  --active-probe-json "${ACTIVE_PROBE_JSON}"
  --live-evidence-json "${LIVE_EVIDENCE_JSON}"
  --output-json "${MANIFEST_JSON}"
  --output-markdown "${MANIFEST_MD}"
  --baseline-json "${BASELINE_JSON}"
  --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}"
)
if [[ -n "${ARTIFACT_DIR}" ]]; then
  manifest_args+=(--artifact-dir "${ARTIFACT_DIR}")
fi
run_review_command cargo run -q -p aegis-measure -- phase-b-runtime-evidence-manifest "${manifest_args[@]}"

run_review_command cargo run -q -p aegis-measure -- phase-b-master-plan-status \
  --baseline-json "${BASELINE_JSON}" \
  --runtime-manifest-json "${MANIFEST_JSON}" \
  --output-json "${MASTER_PLAN_STATUS_JSON}" \
  --output-markdown "${MASTER_PLAN_STATUS_MD}"

echo "Phase B runtime evidence bundle created"
echo "  ${TLS_WIRE_JSON}"
echo "  ${RELAY_SHAPE_JSON}"
echo "  ${ACTIVE_PROBE_JSON}"
echo "  ${LIVE_EVIDENCE_JSON}"
echo "  ${MANIFEST_JSON}"
echo "  ${MASTER_PLAN_STATUS_JSON}"
