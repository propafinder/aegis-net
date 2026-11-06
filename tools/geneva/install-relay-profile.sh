#!/usr/bin/env bash
# Source installer for one explicit, independently pinned selected profile.
# The normal client and armed v2 device guard must already be installed/stopped.
set -euo pipefail
[[ "$EUID" == 0 && $# == 2 && "$1" == --manifest ]] || {
  echo 'Usage: install.sh relay-geneva-profile --manifest /root/accepted-public-profile.json' >&2
  exit 2
}
manifest="$2"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
lib=/usr/local/lib/aegis
client=/usr/local/bin/aegis-client
dropin=/etc/systemd/system/aegis-client.service.d/25-relay-geneva-profile.conf
helper="$lib/aegis-relay-geneva-profile.sh"
source "$lib/lib/root-state.sh"
aegis_root_state_init
aegis_root_trusted_executable "$client" || { echo 'ERROR: trusted installed client required' >&2; exit 1; }
aegis_root_read "$manifest" >/dev/null
props="$(/usr/bin/timeout --signal=KILL 5s /usr/bin/systemctl show aegis-client.service --property=LoadState,ActiveState,SubState,MainPID,ControlPID --no-pager)"
for exact in LoadState=loaded ActiveState=inactive SubState=dead MainPID=0 ControlPID=0; do
  grep -Fxq "$exact" <<<"$props" || { echo 'ERROR: loaded stopped client required; no stop or retry performed' >&2; exit 1; }
done
# Immutable public intent precedes either file write and pins source, manifest,
# exact new bytes and independently checked old stopped unit/file ownership.
"$client" profile relay-geneva prepare-install --manifest "$manifest" --recovery-helper "$root/scripts/aegis-relay-geneva-profile.sh" --drop-in "$root/packaging/systemd/25-relay-geneva-profile.conf"
for file in "$helper" "$dropin" /var/lib/aegis-install/client/relay-geneva-profile.json; do
  [[ ! -e "$file" && ! -L "$file" ]] || { echo 'ERROR: existing selected ownership refused' >&2; exit 1; }
done
# Trusted metadata CLI validates every parent and writes without runtime-owned
# symlinks. Exclusive absent intent is checked above; no force/overwrite mode.
# Install the refusing preflight first: until both helper and exact staged
# manifest exist, ExecStartPre cannot reach the original client ExecStart.
"$client" profile metadata write --path "$dropin" --mode 0644 --exclusive <"$root/packaging/systemd/25-relay-geneva-profile.conf"
/usr/bin/systemctl daemon-reload
"$client" profile metadata write --path "$helper" --mode 0644 --exclusive <"$root/scripts/aegis-relay-geneva-profile.sh"
# The Rust gate independently verifies full exact file pins + inactive unit,
# source/config/endpoints/guard state and duplicate-free public JSON before stage.
"$client" profile relay-geneva stage --manifest "$manifest"
/bin/bash "$lib/aegis-device-egress-guard.sh" block
# Recovery runs only in the selected service pre-start cgroup, before bind.
echo 'selected relay profile staged blocked; explicit service start and runtime validation remain required'
