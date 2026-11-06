#!/usr/bin/env bash
# Real metadata CLI + real gateway parser; no networking or root services.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
FIXTURE="$(mktemp -d /private/tmp/aegis-gateway-state.XXXXXX 2>/dev/null || mktemp -d /tmp/aegis-gateway-state.XXXXXX)"
trap 'rm -rf "$FIXTURE"' EXIT
. "$ROOT/scripts/lib/root-state.sh"
AEGIS_ROOT_STATE_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-$ROOT/target/debug/aegis-client}"
aegis_root_state_init
SYSCTL_BAK="$FIXTURE/state/snapshot"
SYSCTLS=(net.ipv4.ip_forward net.ipv4.conf.all.route_localnet net.ipv4.conf.eth0.route_localnet net.ipv4.conf.all.rp_filter net.ipv4.conf.eth0.rp_filter)
# Extract just the production read/validation function, never top-level apply.
sed -n '/^sysctl_checked_snapshot() {$/,/^}$/p' "$ROOT/scripts/aegis-rpi-gateway.sh" > "$FIXTURE/parser.sh"
. "$FIXTURE/parser.sh"
valid=$'net.ipv4.ip_forward=0\nnet.ipv4.conf.all.route_localnet=0\nnet.ipv4.conf.eth0.route_localnet=1\nnet.ipv4.conf.all.rp_filter=2\nnet.ipv4.conf.eth0.rp_filter=1'
printf '%s\n' "$valid" | aegis_root_write "$SYSCTL_BAK"
[[ "$(sysctl_checked_snapshot)" == "$valid" ]]
for invalid in \
  "${valid/net.ipv4.ip_forward/kernel.core_pattern}" \
  "${valid/eth0/eth1}" \
  "${valid/rp_filter=2/rp_filter=9}" \
  "$valid"$'\nnet.ipv4.ip_forward=1' \
  $'net.ipv4.ip_forward=0'; do
  printf '%s\n' "$invalid" | aegis_root_write "$SYSCTL_BAK"
  if sysctl_checked_snapshot >/dev/null 2>&1; then echo 'FAIL: unsafe snapshot accepted' >&2; exit 1; fi
done
printf '%s\n' "$valid" > "$FIXTURE/untrusted"
chmod 0666 "$FIXTURE/untrusted"
if sysctl_checked_snapshot "$FIXTURE/untrusted" >/dev/null 2>&1; then exit 1; fi
ln -s "$SYSCTL_BAK" "$FIXTURE/link"
if sysctl_checked_snapshot "$FIXTURE/link" >/dev/null 2>&1; then exit 1; fi
echo 'PASS: gateway restore requires trusted bounded state, exact keys/interface, legal values'
