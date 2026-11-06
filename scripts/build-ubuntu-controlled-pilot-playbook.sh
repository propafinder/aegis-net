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

usage() {
  cat <<'EOF'
Usage:
  scripts/build-ubuntu-controlled-pilot-playbook.sh <output-dir> \
    [--relay-host <label>] \
    [--client-host <label>] \
    [--blocked-shape <label>] \
    [--bundle <archive-path> | --bundle-url-file <private-record-path>]

Builds one machine-readable and human-readable playbook for the canonical
Ubuntu relay/client controlled pilot.
EOF
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
shift

RELAY_HOST_LABEL="ubuntu-relay-host"
CLIENT_HOST_LABEL="ubuntu-client-host"
BLOCKED_SHAPE_LABEL="hostile_or_blocked_network_shape"
BUNDLE_INPUT_ARGS=(--bundle /tmp/client-bundle.tar.gz)
BUNDLE_INPUT_SELECTED=0

while [[ $# -gt 0 ]]; do
  case "$1" in
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

mkdir -p "${OUTPUT_DIR}"

cargo run -q -p aegis-measure -- \
  build-ubuntu-controlled-pilot-playbook \
  --output-dir "${OUTPUT_DIR}" \
  --relay-host "${RELAY_HOST_LABEL}" \
  --client-host "${CLIENT_HOST_LABEL}" \
  --blocked-shape "${BLOCKED_SHAPE_LABEL}" \
  "${BUNDLE_INPUT_ARGS[@]}"

cat <<EOF
Ubuntu controlled pilot playbook created
---------------------------------------
Artifacts:
  ${OUTPUT_DIR}/pilot-playbook.json
  ${OUTPUT_DIR}/pilot-playbook.md
EOF
