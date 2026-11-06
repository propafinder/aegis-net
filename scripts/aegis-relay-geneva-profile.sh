#!/usr/bin/env bash
# Explicit selected service hook. No default profile or global sysctl changes.
set -euo pipefail
[[ $# == 1 && "$1" == recover ]] || { echo 'ERROR: expected recover' >&2; exit 2; }
[[ "$EUID" == 0 ]] || { echo 'ERROR: root required' >&2; exit 1; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ "$ROOT" == /usr/local/lib/aegis ]] || { echo 'ERROR: fixed installed helper required' >&2; exit 1; }
source "$ROOT/lib/root-state.sh"
aegis_root_state_init
client=/usr/local/bin/aegis-client
aegis_root_trusted_executable "$client" || { echo 'ERROR: trusted installed client required' >&2; exit 1; }
# Block is committed before recovery. The ordinary helper serializes both owned
# tables in one batch; its lock is released before the recovery CLI takes it.
/bin/bash "$ROOT/aegis-device-egress-guard.sh" block
"$client" profile relay-geneva recover
