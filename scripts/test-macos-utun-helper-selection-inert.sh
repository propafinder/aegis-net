#!/usr/bin/env bash
# One inert case per invocation; use a finite outer process deadline.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case_name="${1:-}"
case "$case_name" in absent|nonexecutable|directory|symlink|relative|regular-with-spaces) ;; *) exit 2 ;; esac
caller_uid="$(id -u)"
[[ "$caller_uid" =~ ^[1-9][0-9]*$ ]] || exit 2
caller_name="$(id -un)"
private_tmp="$(mktemp -d "${TMPDIR:-/tmp}/aegis-W0-selection-inert.XXXXXXXX")"
trap 'rm -rf "$private_tmp"' EXIT
chmod 700 "$private_tmp"
mkdir "$private_tmp/stubs"
cat >"$private_tmp/stubs/cargo" <<'CARGO'
#!/bin/bash
printf '%s\n' 'cargo' >>"${INERT_CARGO_MARK:?}"
exit 97
CARGO
for command in security spctl sudo; do
  cat >"$private_tmp/stubs/$command" <<'FORBIDDEN'
#!/bin/bash
printf '%s\n' 'unexpected native boundary' >>"${INERT_UNEXPECTED_MARK:?}"
exit 98
FORBIDDEN
  chmod 700 "$private_tmp/stubs/$command"
done
chmod 700 "$private_tmp/stubs/cargo"
helper="$private_tmp/regular helper with spaces"
cat >"$helper" <<'HELPER'
#!/bin/bash
printf '%s\n' 'helper executed unexpectedly' >>"${INERT_HELPER_MARK:?}"
exit 98
HELPER
chmod 700 "$helper"
selected="$helper"
case "$case_name" in
 absent) selected="$private_tmp/absent" ;;
 nonexecutable) chmod 600 "$helper" ;;
 directory) selected="$private_tmp/directory"; mkdir "$selected" ;;
 symlink) selected="$private_tmp/symlink"; ln -s "$helper" "$selected" ;;
 relative) cp "$helper" "$private_tmp/relative-helper"; selected='relative-helper' ;;
esac
output="$private_tmp/operator output"
export INERT_CARGO_MARK="$private_tmp/cargo-called"
export INERT_HELPER_MARK="$private_tmp/helper-called"
export INERT_UNEXPECTED_MARK="$private_tmp/native-called"
set +e
(
  cd "$private_tmp"
  PATH="$private_tmp/stubs:/usr/bin:/bin" AEGIS_USER="$caller_name" \
    AEGIS_RELAY_IP='192.0.2.10' AEGIS_MACOS_UTUN_HELPER="$selected" \
    /bin/bash "$ROOT/scripts/run-macos-utun-helper-fd-loop-lab.sh" "$output"
) >"$private_tmp/stdout" 2>"$private_tmp/stderr"
status=$?
set -e
[[ ! -e "$INERT_HELPER_MARK" && ! -e "$INERT_UNEXPECTED_MARK" ]]
if [[ "$case_name" == regular-with-spaces ]]; then
  [[ "$status" == 97 && -d "$output" && -f "$INERT_CARGO_MARK" ]]
  [[ "$(cat "$INERT_CARGO_MARK")" == cargo ]]
else
  [[ "$status" == 2 && ! -e "$output" && ! -e "$INERT_CARGO_MARK" ]]
  grep -Fxq 'AEGIS_MACOS_UTUN_HELPER must select an absolute regular non-symlink executable' "$private_tmp/stderr"
fi
printf '{"case":"%s","wrapper_status":%s,"unexpected_helper_or_native":false}\n' "$case_name" "$status"
