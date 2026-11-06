#!/usr/bin/env bash
# Exercise actual administrative metadata writes and sysctl restore logic with
# an isolated filesystem and inert kernel/service commands. No host state changes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TASK_TMP="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wide-sysctl.XXXXXX")"
TASK_TMP="$(cd "$TASK_TMP" && pwd -P)"
trap 'rm -rf "$TASK_TMP"' EXIT
BIN="$TASK_TMP/bin"
LOG="$TASK_TMP/commands.log"
SYSCTL_FILE="$TASK_TMP/etc/sysctl.d/99-aegis-wide.conf"
SNAPSHOT="$TASK_TMP/var/lib/aegis-install/client/wide-sysctl-original.txt"
CLIENT="${AEGIS_TEST_CLIENT_BINARY:-$ROOT/target/debug/aegis-client}"
[[ -x "$CLIENT" ]] || { echo 'Build aegis-client before this contract test.' >&2; exit 1; }
CLIENT="$(cd "$(dirname "$CLIENT")" && pwd -P)/$(basename "$CLIENT")"
"$CLIENT" profile metadata --help >/dev/null
mkdir -p "$BIN/lib" "$TASK_TMP/etc/sysctl.d" "$TASK_TMP/run" "$(dirname "$SNAPSHOT")"
printf 'nameserver 192.0.2.53\n' > "$TASK_TMP/etc/resolv.conf"
chmod 600 "$TASK_TMP/etc/resolv.conf"
# Relocate literal host paths only in fixture copies, including the shared
# library. Keep production preflight, typed Rust metadata and restore logic.
python3 - "$ROOT" "$TASK_TMP" <<'PY'
from pathlib import Path
import sys
root, work = map(Path, sys.argv[1:])
for name in ('aegis-wide-enable.sh', 'aegis-wide-disable.sh', 'lib/root-state.sh'):
    text=(root/'scripts'/name).read_text()
    for prefix in ('/var/lib/', '/etc/', '/run/'):
        text=text.replace(prefix, str(work)+prefix)
    (work/'bin'/name).write_text(text)
PY
export AEGIS_FIXTURE_LOG="$LOG" AEGIS_FIXTURE_REAL_ID="$(command -v id)"
cat > "$BIN/mock" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
name="${0##*/}"
printf '%s %s\n' "$name" "$*" >> "$AEGIS_FIXTURE_LOG"
case "$name" in
  id)
    if [[ "${1:-}" == -u && -n "${2:-}" ]]; then echo 424
    else exec "$AEGIS_FIXTURE_REAL_ID" "$@"; fi ;;
  iptables|ip6tables)
    for arg in "$@"; do [[ "$arg" != -C ]] || exit 1; done ;;
  nft) exit 1 ;;
  ip)
    if [[ "$*" == 'link show aegis-tun0' ]]; then exit 1; fi
    if [[ "$*" == '-4 route show' ]]; then echo 'default via 192.0.2.1 dev eth0'; fi ;;
  systemctl) [[ "${1:-}" != is-active ]] || exit 3 ;;
  sysctl) [[ "${1:-}" != -n ]] || echo 0 ;;
  setsid|sudo) echo 'Unexpected detached or privileged execution' >&2; exit 99 ;;
esac
exit 0
MOCK
chmod +x "$BIN/mock"
for name in ip iptables ip6tables iptables-save ip6tables-save nft sysctl systemctl logger id journalctl setsid sudo setup-wide-linux-tproxy.sh setup-wide-linux-redirect.sh janitor-wide-linux-tproxy.sh; do
  cp "$BIN/mock" "$BIN/$name"
done
export PATH="$BIN:$PATH" AEGIS_ROOT_STATE_CLIENT="$CLIENT"
export AEGIS_WIDE_SKIP_ROOT_CHECK=1 AEGIS_WIDE_SYSCTL_FILE="$SYSCTL_FILE"
export AEGIS_WIDE_SYSCTL_SNAPSHOT="$SNAPSHOT"
export AEGIS_CONFIG_FILE="$TASK_TMP/etc/aegis/client/aegis.toml"
export AEGIS_WIDE_RESOLVER_SNAPSHOT="$TASK_TMP/var/lib/aegis-install/client/resolver-original.json"
export AEGIS_WIDE_PROFILE_STATE="$TASK_TMP/var/lib/aegis-install/client/wide-profile.json"
fail() { echo "FAIL: $*" >&2; sed -n '1,400p' "$LOG" >&2; exit 1; }
bash "$BIN/aegis-wide-enable.sh" --yes --no-rollback --mode=tproxy \
  --interface=eth0 --dns=off --ipv6=block --ssh-safe-ports=22 >>"$LOG" 2>&1 \
  || fail 'enable failed'
[[ -s "$SNAPSHOT" && -s "$SYSCTL_FILE" ]] || fail 'snapshot or persistent file missing'
for key in net.ipv4.ip_forward net.ipv4.conf.all.route_localnet net.ipv4.conf.eth0.route_localnet; do
  grep -Fxq "$key=0" "$SNAPSHOT" || fail "original value missing: $key"
  grep -Fxq "$key=1" "$SYSCTL_FILE" || fail "persistent value missing: $key"
done
grep -Fq "sysctl -p $SYSCTL_FILE" "$LOG" || fail 'persistent file not applied'
printf '%s\n' 'DISABLE-PHASE' >> "$LOG"
bash "$BIN/aegis-wide-disable.sh" >>"$LOG" 2>&1 || fail 'disable failed'
[[ ! -e "$SYSCTL_FILE" && ! -e "$SNAPSHOT" ]] || fail 'snapshot or persistent file not removed'
awk '/^DISABLE-PHASE$/{found=1; next} found' "$LOG" > "$TASK_TMP/disable.log"
for key in net.ipv4.ip_forward net.ipv4.conf.all.route_localnet net.ipv4.conf.eth0.route_localnet; do
  grep -Fxq "sysctl -wq $key=0" "$TASK_TMP/disable.log" || fail "original value not restored: $key"
done
# A trusted-owned file still must not authorize arbitrary sysctl keys. This
# deliberately invalid inert record must fail before any kernel mutation.
printf 'kernel.randomize_va_space=0\n' > "$SNAPSHOT"; chmod 600 "$SNAPSHOT"
: > "$LOG"
if bash "$BIN/aegis-wide-disable.sh" >>"$LOG" 2>&1; then fail 'invalid snapshot accepted'; fi
if grep -Eq '^(sysctl|iptables|ip6tables|systemctl) ' "$LOG"; then fail 'mutation preceded snapshot validation'; fi
echo 'PASS: sysctl persistence + exact restore, Rust metadata boundary, invalid record rejected before mutation; all host paths isolated'
