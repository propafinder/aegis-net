#!/usr/bin/env bash
# Source-only launcher: it does not invoke a helper, sudo or network APIs.

aegis_utun_validate_main_identity() {
  local caller_uid="$1" expected_uid="$2"
  unset AEGIS_UTUN_MAIN_UID
  if [[ ! "$caller_uid" =~ ^[1-9][0-9]*$ ||
        ! "$expected_uid" =~ ^[1-9][0-9]*$ ||
        "$caller_uid" != "$expected_uid" ]]; then
    printf '%s\n' 'utun main requires the expected non-root caller UID' >&2
    return 2
  fi
  AEGIS_UTUN_MAIN_UID="$caller_uid"
}

aegis_utun_require_main_user() {
  local caller_uid expected_uid
  unset AEGIS_UTUN_MAIN_UID
  if [[ "$#" != 1 || -z "${1:-}" || "${1:-}" == -* ]]; then
    printf '%s\n' 'utun main requires one nonempty account name or UID, not an option' >&2
    return 2
  fi
  caller_uid="$(id -u)" || return 2
  expected_uid="$(id -u "$1")" || return 2
  aegis_utun_validate_main_identity "$caller_uid" "$expected_uid"
}

aegis_utun_start_main() {
  unset AEGIS_UTUN_MAIN_PID
  [[ "${AEGIS_UTUN_MAIN_UID:-}" =~ ^[1-9][0-9]*$ ]] || return 2
  # exec preserves this direct child's PID. There is no sudo process between
  # the wrapper and main; the helper still verifies the connected kernel peer.
  (
    cd / || exit 2
    exec "$@"
  ) &
  AEGIS_UTUN_MAIN_PID="$!"
}
