#!/usr/bin/env bash
# Explicit selected teardown only; generic purge must retain selected ownership.
set -euo pipefail
[[ "$EUID" == 0 ]] || { echo 'ERROR: root required' >&2; exit 1; }
if (( $# != 0 )); then
  [[ $# == 2 && "$1" == --resume-token && "$2" =~ ^[0-9a-f]{32}$ ]] || {
    echo 'Usage: install.sh relay-geneva-profile-remove [--resume-token TOKEN]' >&2
    exit 2
  }
fi
client=/usr/local/bin/aegis-client
source /usr/local/lib/aegis/lib/root-state.sh
aegis_root_state_init
aegis_root_trusted_executable "$client" || { echo 'ERROR: trusted installed client required' >&2; exit 1; }
# Product independently verifies stopped role, every ownership pin, archive and
# both canonical blocked policies. No stop, kill, purge or recovery-shell fallback.
exec "$client" profile relay-geneva teardown "$@"
