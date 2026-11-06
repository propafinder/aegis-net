#!/usr/bin/env bash
# Inert identity/argv regression only: no Aegis binary, sudo, socket or routes.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/scripts/macos-utun-main-launch.sh"

for user in '-r' ''; do
  AEGIS_UTUN_MAIN_UID=501
  if aegis_utun_require_main_user "$user" 2>/dev/null; then
    printf '%s\n' 'invalid account argument unexpectedly accepted' >&2
    exit 1
  fi
  [[ -z "${AEGIS_UTUN_MAIN_UID:-}" ]]
done
if aegis_utun_require_main_user 2>/dev/null ||
   aegis_utun_require_main_user caller extra 2>/dev/null; then
  printf '%s\n' 'invalid account argument count unexpectedly accepted' >&2
  exit 1
fi

for pair in '0 501' '501 0' '501 502' 'invalid 501'; do
  read -r caller expected <<<"$pair"
  if aegis_utun_validate_main_identity "$caller" "$expected" 2>/dev/null; then
    printf '%s\n' 'invalid identity unexpectedly accepted' >&2
    exit 1
  fi
done
aegis_utun_validate_main_identity 501 501
[[ "$AEGIS_UTUN_MAIN_UID" == 501 ]]
unset AEGIS_UTUN_MAIN_UID
if aegis_utun_start_main /bin/false; then
  printf '%s\n' 'missing identity unexpectedly spawned a child' >&2
  exit 1
fi
[[ -z "${AEGIS_UTUN_MAIN_PID:-}" ]]

caller_uid="$(id -u)"
[[ "$caller_uid" =~ ^[1-9][0-9]*$ ]] || {
  printf '%s\n' 'fixture requires a non-root caller; no launch performed' >&2
  exit 2
}
aegis_utun_require_main_user "$(id -un)"
[[ "$AEGIS_UTUN_MAIN_UID" == "$caller_uid" ]]
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-utun-launch-inert.XXXXXXXX")"
trap 'rm -rf "$fixture_dir"' EXIT
cat >"$fixture_dir/child.sh" <<'CHILD'
set -eu
printf '%s\n' "$$" "$(id -u)" "$#"
printf '%s\n' "$@"
CHILD
aegis_utun_start_main /bin/bash "$fixture_dir/child.sh" 'argument with spaces' '--literal' '' \
  >"$fixture_dir/child.txt"
expected_pid="$AEGIS_UTUN_MAIN_PID"
wait "$expected_pid"
{
  IFS= read -r actual_pid
  IFS= read -r actual_uid
  IFS= read -r argc
  IFS= read -r first
  IFS= read -r second
  IFS= read -r third
} <"$fixture_dir/child.txt"
[[ "$actual_pid" == "$expected_pid" && "$actual_uid" == "$caller_uid" ]]
[[ "$argc" == 3 && "$first" == 'argument with spaces' && "$second" == '--literal' && -z "$third" ]]
printf '%s\n' 'PASS: refusal before spawn, direct exec PID/UID, exact argv'
