#!/usr/bin/env bash
# Exercise the production AP function with inert network commands and real
# metadata files. No top-level gateway script, root check or host service runs.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FIXTURE="$(mktemp -d)"
FIXTURE="$(cd "$FIXTURE" && pwd -P)"
trap 'rm -rf "$FIXTURE"' EXIT
. "$ROOT/scripts/lib/root-state.sh"
AEGIS_ROOT_STATE_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-$ROOT/target/debug/aegis-client}"
aegis_root_state_init
sed -n '/^setup_ap() {$/,/^}$/p' "$ROOT/scripts/aegis-rpi-gateway.sh" > "$FIXTURE/setup-ap.sh"
[[ -s "$FIXTURE/setup-ap.sh" ]]
. "$FIXTURE/setup-ap.sh"

AP_SSID=fixture-network
AP_PASS=synthetic-fixture-pass
AP_SUBNET=10.99.1
HOSTAPD_CONF="$FIXTURE/hostapd.conf"
DNSMASQ_CONF="$FIXTURE/dnsmasq.conf"
DNSMASQ_PID="$FIXTURE/dnsmasq.pid"
LOG="$FIXTURE/calls.log"
nmcli() { printf 'nmcli %s\n' "$*" >> "$LOG"; }
systemctl() { printf 'systemctl %s\n' "$*" >> "$LOG"; }
ip() { printf 'ip %s\n' "$*" >> "$LOG"; }
iw() { printf 'country US\n'; }
pkill() { printf 'pkill %s\n' "$*" >> "$LOG"; }
hostapd() { printf 'hostapd %s\n' "$*" >> "$LOG"; }
dnsmasq() { printf 'dnsmasq %s\n' "$*" >> "$LOG"; }
apt-get() { printf 'unexpected apt-get\n' >> "$LOG"; return 94; }
aegis_root_write() {
    [[ "$1" != "$FAILED_PATH" ]] || return 91
    [[ "$1" == "$FIXTURE/"* ]] || return 92
    aegis_root_state write --path "$1" --mode 0600
}

for FAILED_PATH in "$HOSTAPD_CONF" "$DNSMASQ_CONF"; do
    : > "$LOG"
    rm -f "$HOSTAPD_CONF" "$DNSMASQ_CONF"
    # This conditional deliberately matches the production caller. It disables
    # Bash's implicit errexit inside setup_ap, so explicit guards are required.
    if setup_ap fixture0 > "$FIXTURE/output" 2>&1; then
        echo 'FAIL: AP setup succeeded despite failed configuration write' >&2
        exit 1
    fi
    [[ ! -e "$FAILED_PATH" ]]
    [[ ! -s "$LOG" ]]
    ! grep -q 'WiFi access point up' "$FIXTURE/output"
done
echo 'PASS: failed gateway metadata write cannot change network/services or report success'
