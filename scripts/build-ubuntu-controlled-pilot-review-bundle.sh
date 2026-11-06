#!/usr/bin/env bash
set -euo pipefail

# Refuse deprecated private bytes before output paths, Cargo or parsing errors.
for argument in "$@"; do
  case "$argument" in
    --bundle-url|--bundle-url=*)
      echo "Inline bundle URLs are no longer accepted. Use --bundle-url-file or --bundle." >&2
      exit 2
      ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLAYBOOK_SCRIPT="${ROOT}/scripts/build-ubuntu-controlled-pilot-playbook.sh"
OPERATOR_CANARY_SCRIPT="${ROOT}/scripts/build-ubuntu-operator-reapply-canary.sh"
PILOT_BUNDLE_SCRIPT="${ROOT}/scripts/build-ubuntu-controlled-pilot-bundle.sh"
RELEASE_REVIEW_SCRIPT="${ROOT}/scripts/build-ubuntu-release-review.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-ubuntu-controlled-pilot-review-bundle.sh <output-dir> \
    --pilot-inputs <ubuntu-controlled-pilot-inputs.json> \
    [--relay-host <label>] \
    [--client-host <label>] \
    [--blocked-shape <label>] \
    [--bundle <archive-path> | --bundle-url-file <private-record-path>] \
    [--matrix-manifest <bundle.manifest.json>] \
    [--wire-witness-summary <path>] \
    [--wire-acceptance-summary <path>]

Builds one top-level Ubuntu pilot/review bundle by materializing:
  - the controlled pilot playbook
  - the pilot evidence bundle
  - the release review

All release/runtime paths are sourced from validation-generated
ubuntu-controlled-pilot-inputs.json to avoid hand-maintained path drift.
EOF
}

if [[ $# -lt 3 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

PILOT_INPUTS=""
RELAY_HOST_LABEL="ubuntu-relay-host"
CLIENT_HOST_LABEL="ubuntu-client-host"
BLOCKED_SHAPE_LABEL="hostile_or_blocked_network_shape"
BUNDLE_INPUT_ARGS=(--bundle /tmp/client-bundle.tar.gz)
BUNDLE_INPUT_SELECTED=0
MATRIX_MANIFEST=""
WIRE_WITNESS_SUMMARY=""
WIRE_ACCEPTANCE_SUMMARY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pilot-inputs)
      PILOT_INPUTS="$2"
      shift 2
      ;;
    --relay-host)
      RELAY_HOST_LABEL="$2"
      shift 2
      ;;
    --client-host)
      CLIENT_HOST_LABEL="$2"
      shift 2
      ;;
    --blocked-shape)
      BLOCKED_SHAPE_LABEL="$2"
      shift 2
      ;;
    --bundle|--bundle-url-file)
      if [[ $# -lt 2 || "${BUNDLE_INPUT_SELECTED}" != 0 ]]; then
        echo "Select one bundle input pathname." >&2
        exit 2
      fi
      BUNDLE_INPUT_ARGS=("$1" "$2")
      BUNDLE_INPUT_SELECTED=1
      shift 2
      ;;
    --matrix-manifest)
      MATRIX_MANIFEST="$2"
      shift 2
      ;;
    --wire-witness-summary)
      WIRE_WITNESS_SUMMARY="$2"
      shift 2
      ;;
    --wire-acceptance-summary)
      WIRE_ACCEPTANCE_SUMMARY="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${PILOT_INPUTS}" || ! -f "${PILOT_INPUTS}" ]]; then
  echo "Missing pilot inputs manifest: ${PILOT_INPUTS}" >&2
  exit 1
fi

for optional_path in "${MATRIX_MANIFEST}" "${WIRE_WITNESS_SUMMARY}" "${WIRE_ACCEPTANCE_SUMMARY}"; do
  if [[ -n "${optional_path}" && ! -f "${optional_path}" ]]; then
    echo "Missing optional input: ${optional_path}" >&2
    exit 1
  fi
done

for helper_script in "${PLAYBOOK_SCRIPT}" "${OPERATOR_CANARY_SCRIPT}" "${PILOT_BUNDLE_SCRIPT}" "${RELEASE_REVIEW_SCRIPT}"; do
  if [[ ! -f "${helper_script}" ]]; then
    echo "Missing helper script: ${helper_script}" >&2
    exit 1
  fi
done

# Keep the review glued to validation-generated truth so operators do not
# have to retype release-summary paths by hand for each live pilot run.
RELEASE_SUMMARY=""
while IFS= read -r item; do
  if [[ -n "${item}" ]]; then
    RELEASE_SUMMARY="${item}"
    break
  fi
done < <(cargo run -q -p aegis-measure -- ubuntu-pilot-inputs-release-summary --pilot-inputs "${PILOT_INPUTS}")
if [[ -z "${RELEASE_SUMMARY}" || ! -f "${RELEASE_SUMMARY}" ]]; then
  echo "Pilot inputs do not point to a valid release summary: ${RELEASE_SUMMARY}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

PLAYBOOK_DIR="${OUTPUT_DIR}/pilot-playbook"
OPERATOR_CANARY_DIR="${OUTPUT_DIR}/operator-canary"
PILOT_BUNDLE_DIR="${OUTPUT_DIR}/pilot-bundle"
RELEASE_REVIEW_DIR="${OUTPUT_DIR}/release-review"

playbook_cmd=(
  bash "${PLAYBOOK_SCRIPT}" "${PLAYBOOK_DIR}"
  --relay-host "${RELAY_HOST_LABEL}"
  --client-host "${CLIENT_HOST_LABEL}"
  --blocked-shape "${BLOCKED_SHAPE_LABEL}"
  "${BUNDLE_INPUT_ARGS[@]}"
)

operator_canary_cmd=(
  bash "${OPERATOR_CANARY_SCRIPT}" "${OPERATOR_CANARY_DIR}"
  --pilot-inputs "${PILOT_INPUTS}"
)

pilot_bundle_cmd=(
  bash "${PILOT_BUNDLE_SCRIPT}" "${PILOT_BUNDLE_DIR}"
  --pilot-inputs "${PILOT_INPUTS}"
  --blocked-shape "${BLOCKED_SHAPE_LABEL}"
  --server-host "${RELAY_HOST_LABEL}"
  --client-host "${CLIENT_HOST_LABEL}"
)

release_review_cmd=(
  bash "${RELEASE_REVIEW_SCRIPT}" "${RELEASE_REVIEW_DIR}"
  --release-summary "${RELEASE_SUMMARY}"
  --pilot-bundle "${PILOT_BUNDLE_DIR}/pilot-summary.json"
)

if [[ -n "${WIRE_WITNESS_SUMMARY}" ]]; then
  pilot_bundle_cmd+=(--wire-witness-summary "${WIRE_WITNESS_SUMMARY}")
fi
if [[ -n "${WIRE_ACCEPTANCE_SUMMARY}" ]]; then
  pilot_bundle_cmd+=(--wire-acceptance-summary "${WIRE_ACCEPTANCE_SUMMARY}")
fi
if [[ -n "${MATRIX_MANIFEST}" ]]; then
  release_review_cmd+=(--matrix-manifest "${MATRIX_MANIFEST}")
fi
if [[ -n "${WIRE_ACCEPTANCE_SUMMARY}" ]]; then
  release_review_cmd+=(--wire-acceptance-summary "${WIRE_ACCEPTANCE_SUMMARY}")
fi

"${playbook_cmd[@]}" >/dev/null
"${operator_canary_cmd[@]}" >/dev/null
"${pilot_bundle_cmd[@]}" >/dev/null
"${release_review_cmd[@]}" >/dev/null

manifest_cmd=(
  cargo run -q -p aegis-measure -- build-ubuntu-controlled-pilot-review-bundle-manifest
  --output-dir "${OUTPUT_DIR}"
  --pilot-inputs "${PILOT_INPUTS}"
  --playbook-json "${PLAYBOOK_DIR}/pilot-playbook.json"
  --operator-canary-json "${OPERATOR_CANARY_DIR}/ubuntu-operator-reapply-canary.json"
  --pilot-summary-json "${PILOT_BUNDLE_DIR}/pilot-summary.json"
  --release-review-json "${RELEASE_REVIEW_DIR}/release-review.json"
)
if [[ -n "${MATRIX_MANIFEST}" ]]; then
  manifest_cmd+=(--matrix-manifest "${MATRIX_MANIFEST}")
fi
if [[ -n "${WIRE_WITNESS_SUMMARY}" ]]; then
  manifest_cmd+=(--wire-witness-summary "${WIRE_WITNESS_SUMMARY}")
fi
if [[ -n "${WIRE_ACCEPTANCE_SUMMARY}" ]]; then
  manifest_cmd+=(--wire-acceptance-summary "${WIRE_ACCEPTANCE_SUMMARY}")
fi
"${manifest_cmd[@]}"

cat <<EOF
Ubuntu controlled pilot review bundle created
-------------------------------------------
Artifacts:
  ${OUTPUT_DIR}/pilot-playbook/pilot-playbook.json
  ${OUTPUT_DIR}/operator-canary/ubuntu-operator-reapply-canary.json
  ${OUTPUT_DIR}/pilot-bundle/pilot-summary.json
  ${OUTPUT_DIR}/release-review/release-review.json
  ${OUTPUT_DIR}/pilot-review.manifest.json
  ${OUTPUT_DIR}/pilot-review.md
EOF
