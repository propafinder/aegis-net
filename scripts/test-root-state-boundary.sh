#!/usr/bin/env bash
# Exercise the real Rust administrative state boundary on inert temporary files.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT="${AEGIS_TEST_CLIENT_BINARY:-${ROOT}/target/debug/aegis-client}"
[[ -x "$CLIENT" ]] || { echo 'Build aegis-client first.' >&2; exit 1; }
FIXTURE="$(mktemp -d /private/tmp/aegis-root-state.XXXXXX 2>/dev/null || mktemp -d /tmp/aegis-root-state.XXXXXX)"
trap 'rm -rf "$FIXTURE"' EXIT
# Do not create stubs that could mutate networking; this test only invokes the
# metadata CLI and the library's filesystem/shape guards.
. "$ROOT/scripts/lib/root-state.sh"
AEGIS_ROOT_STATE_CLIENT="$CLIENT"
aegis_root_state_init
record="$FIXTURE/root/metadata.json"
aegis_root_validate "$record"
printf '%s' '{"fixture":true}' | aegis_root_write "$record"
[[ "$(aegis_root_read "$record")" == '{"fixture":true}' ]]
ln -s "$record" "$FIXTURE/link"
if aegis_root_validate "$FIXTURE/link" 2>/dev/null; then echo 'FAIL: final link accepted' >&2; exit 1; fi
chmod 0777 "$FIXTURE/root"
if aegis_root_read "$record" 2>/dev/null; then echo 'FAIL: writable ancestor accepted' >&2; exit 1; fi
chmod 0700 "$FIXTURE/root"
sysctls="$FIXTURE/root/sysctls"
printf 'net.ipv4.ip_forward=0\nnet.ipv4.conf.all.route_localnet=0\nnet.ipv4.conf.eth0.route_localnet=1\n' | aegis_root_write "$sysctls"
aegis_root_sysctl_check "$sysctls"
printf 'kernel.core_pattern=malicious\nnet.ipv4.conf.all.route_localnet=0\nnet.ipv4.conf.eth0.route_localnet=1\n' | aegis_root_write "$sysctls"
if aegis_root_sysctl_check "$sysctls"; then echo 'FAIL: arbitrary sysctl accepted' >&2; exit 1; fi
printf 'net.ipv4.ip_forward=99\nnet.ipv4.conf.all.route_localnet=0\nnet.ipv4.conf.eth0.route_localnet=1\n' | aegis_root_write "$sysctls"
if aegis_root_sysctl_check "$sysctls"; then echo 'FAIL: out-of-range sysctl accepted' >&2; exit 1; fi
# The shell must reject an unsafe executable before even running its help.
cp "$CLIENT" "$FIXTURE/unsafe-client"
chmod 0777 "$FIXTURE/unsafe-client"
AEGIS_ROOT_STATE_CLIENT="$FIXTURE/unsafe-client"
if aegis_root_state_init >/dev/null 2>&1; then echo 'FAIL: writable client executed' >&2; exit 1; fi
AEGIS_ROOT_STATE_CLIENT="$FIXTURE/link"
if aegis_root_state_init >/dev/null 2>&1; then echo 'FAIL: linked client executed' >&2; exit 1; fi
printf 'PASS: Rust root-state CLI, unsafe files/executables, sysctl allowlist (no network/system mutation)\n'
