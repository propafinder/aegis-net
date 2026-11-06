#!/usr/bin/env bash
# Operator convenience wrapper. Typed validation and public-only output are
# owned by the Rust device command, shared with the receiving installer.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
source "${SCRIPT_DIR}/lib/root-state.sh"
client="${AEGIS_DEVICE_CLIENT:-/usr/local/bin/aegis-client}"
aegis_root_trusted_executable "${client}" || {
  echo "Use an administrator-owned verified client binary via AEGIS_DEVICE_CLIENT." >&2
  exit 1
}
exec "${client}" device bundle-create "$@"
