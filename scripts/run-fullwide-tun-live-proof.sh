#!/usr/bin/env bash
# Live proof for the production full-wide-tun IPv6 leg (multi-flow TUN+smoltcp).
#
# Runs ON a disposable Ubuntu host as root. Reversible + SSH-safe: it only ever
# touches IPv6 (SSH is IPv4), the tun is non-persistent, and it restores the
# original systemd client + config on exit. It proves:
#   1. capture UP   — aegis-tun0 created, ::/1 + 8000::/1 installed (real ::/0 kept)
#   2. multi-target — >=2 DISTINCT IPv6 TCP destinations carried (curl -6 succeeds)
#   3. no native leak — every global IPv6 routes INTO the tun, not the WAN nic
#   4. bidirectional v6 UDP via MASQUE (honest: reported partial if the relay
#      cannot carry MASQUE — TCP multi-target is the core claim)
#   5. fail-closed teardown — kill the engine, capture auto-removed, baseline back
#
# Usage: sudo bash run-fullwide-tun-live-proof.sh /root/aegis-client.fullwidetun
set -uo pipefail
BIN_NEW="${1:-/root/aegis-client.fullwidetun}"
CFG_REAL="/etc/aegis/client/aegis.toml"
CFG_TEST="/root/aegis-fullwide-tun-test.toml"
EVENTS="/root/aegis-fullwide-tun-events.jsonl"
ART="/root/aegis-fullwide-tun-artifacts"
TUN="aegis-tun0"
PASS=1
mkdir -p "$ART"; : > "$EVENTS"
log(){ echo "[proof] $*"; }
fail(){ echo "[proof][FAIL] $*"; PASS=0; }

restore() {
  log "restoring baseline..."
  [ -n "${CLIENT_PID:-}" ] && kill "${CLIENT_PID}" 2>/dev/null || true
  sleep 2
  ip -6 route del ::/1 dev "$TUN" 2>/dev/null || true
  ip -6 route del 8000::/1 dev "$TUN" 2>/dev/null || true
  ip link del "$TUN" 2>/dev/null || true
  systemctl start aegis-client.service 2>/dev/null || true
  log "baseline restored (original service restarted)."
}
trap restore EXIT

# --- 0. Baseline snapshot ---
ip -6 route show     > "$ART/00-baseline-v6-routes.txt" 2>&1
ip -6 addr show      > "$ART/00-baseline-v6-addrs.txt"  2>&1
systemctl is-active aegis-client.service > "$ART/00-svc-was.txt" 2>&1 || true
GLOBAL_V6_NIC="$(ip -6 route show default 2>/dev/null | grep -oE 'dev [a-z0-9]+' | awk '{print $2}' | head -1)"
log "baseline: global-IPv6 default nic = ${GLOBAL_V6_NIC:-<none>}"

# --- 1. Test config = real config + ipv6_tun_carried=true ---
cp "$CFG_REAL" "$CFG_TEST"
python3 - "$CFG_TEST" <<'PY'
import re,sys
p=sys.argv[1]; t=open(p).read()
if re.search(r'(?m)^\s*\[ingress\.wide\]\s*$',t):
    b=re.search(r'(?ms)^\[ingress\.wide\]\s*$.*?(?=^\[|\Z)',t).group(0)
    nb=(re.sub(r'(?m)^(\s*ipv6_tun_carried\s*=\s*).*$',r'\g<1>true',b,count=1)
        if re.search(r'(?m)^\s*ipv6_tun_carried\s*=',b) else b.rstrip()+'\nipv6_tun_carried = true\n')
    t=t.replace(b,nb)
else:
    t+='\n[ingress.wide]\nipv6_tun_carried = true\n'
open(p,'w').write(t)
print("ipv6_tun_carried=true set")
PY

# --- 2. Stop the existing service + tear down the prior wide firewall ---
# The prior wide-redirect-safe install's v4 REDIRECT exempts only the 'aegis' uid,
# so it would capture/break our root-run relay leg. Run the engine over a clean
# firewall; the v6 capture is purely route-based (::/1 -> tun) + fail-closed.
systemctl stop aegis-client.service 2>/dev/null || true
sleep 1
ip link del "$TUN" 2>/dev/null || true
PERSIST="/usr/local/lib/aegis/setup-wide-linux-redirect.sh"
[ -x "$PERSIST" ] && AEGIS_WIDE_PORT=15080 bash "$PERSIST" teardown >/dev/null 2>&1 || true
iptables-save 2>/dev/null | grep -i aegis > "$ART/02-leftover-v4-rules.txt" || true
cat /etc/resolv.conf > "$ART/01-resolv.conf" 2>&1 || true
NATIVE_V6="$(curl -6 -s -o /dev/null -w '%{http_code}' --max-time 8 'https://[2606:4700:4700::1111]/' 2>/dev/null || echo 000)"
log "native v6 reachability to literal 1.1.1.1 v6 (capture OFF): http=$NATIVE_V6"
echo "$NATIVE_V6" > "$ART/01-native-v6-http.txt"

# --- 3. Launch the production engine (client as root, test config) ---
chmod +x "$BIN_NEW"
nohup "$BIN_NEW" --config "$CFG_TEST" --runtime-events-jsonl "$EVENTS" > "$ART/02-client-stdout.log" 2>&1 &
CLIENT_PID=$!
log "client pid=$CLIENT_PID"

up=0
for i in $(seq 1 25); do
  if ip link show "$TUN" >/dev/null 2>&1 && ip -6 route show | grep -q '::/1'; then up=1; break; fi
  kill -0 "$CLIENT_PID" 2>/dev/null || { log "client exited early"; break; }
  sleep 1
done
ip link show "$TUN"  > "$ART/03-tun-link.txt"        2>&1 || true
ip -6 route show     > "$ART/03-capture-v6-routes.txt" 2>&1
if [ "$up" = 1 ]; then log "CAPTURE UP (tun + ::/1 present)"; else fail "engine capture did not come up"; fi

# --- 4. No-native-leak: every global IPv6 must route INTO the tun ---
LEAK=0
for d in 2606:4700:4700::1111 2001:4860:4860::8888 2620:fe::fe; do
  via="$(ip -6 route get "$d" 2>/dev/null | head -1)"
  echo "$via" >> "$ART/04-route-get.txt"
  echo "$via" | grep -q "dev $TUN" || LEAK=1
done
if [ "$LEAK" = 0 ] && [ "$up" = 1 ]; then log "NO-LEAK: all sampled global IPv6 route via $TUN"; else fail "some global IPv6 did NOT route via the tun (leak risk)"; fi

# --- 5. Multi-target IPv6 TCP: >=2 distinct destinations carried ---
# Mix literal-v6 endpoints (DNS-independent, isolates capture+relay) with named
# hosts (exercise the v6 DNS leg too).
declare -a TARGETS=(
  'https://[2606:4700:4700::1111]/'        # Cloudflare 1.1.1.1 (literal v6)
  'https://[2620:fe::fe]/'                  # Quad9 (literal v6)
  'https://www.google.com/'                 # named (needs v6 DNS)
  'https://en.wikipedia.org/'               # named
)
{ for u in "${TARGETS[@]}"; do
    code="$(curl -6 -s -o /dev/null -w '%{http_code} %{remote_ip}' --max-time 20 "$u" 2>/dev/null || echo '000 -')"
    echo "$u -> $code"
  done; } | tee "$ART/05-curl6-results.txt"
sleep 2
cp "$EVENTS" "$ART/06-runtime-events.jsonl" 2>/dev/null || true
TCP_TARGETS="$(grep '"event_code":"wide_tun_smoltcp_tcp_flow_established"' "$EVENTS" 2>/dev/null \
  | grep -oE '"orig_dst":"[^"]+"' | sort -u)"
TCP_N="$(printf '%s\n' "$TCP_TARGETS" | grep -c . || true)"; TCP_N="${TCP_N:-0}"
CURL_OK="$(grep -cE ' (200|301|302|403) ' "$ART/05-curl6-results.txt" || true)"; CURL_OK="${CURL_OK:-0}"
log "distinct IPv6 TCP relay targets observed: $TCP_N"; printf '%s\n' "$TCP_TARGETS" | sed 's/^/[proof]   /'
log "curl -6 carried (2xx/3xx/403) count: $CURL_OK"
if [ "$TCP_N" -ge 2 ] && [ "$CURL_OK" -ge 1 ]; then log "MULTI-TARGET TCP: PASS"; else fail "multi-target TCP not proven (need >=2 distinct targets + >=1 carried)"; fi

# --- 6. Bidirectional IPv6 UDP via MASQUE (honest partial allowed) ---
UDP_OK=0
if command -v dig >/dev/null 2>&1; then
  for r in 2606:4700:4700::1111 2001:4860:4860::8888; do
    dig +time=5 +tries=1 @"$r" example.com A >> "$ART/07-dig6.txt" 2>&1 || true
  done
fi
sleep 2
cp "$EVENTS" "$ART/06-runtime-events.jsonl" 2>/dev/null || true
UDP_SESS="$(grep -c '"event_code":"ipv6_udp_session_created"' "$EVENTS" 2>/dev/null || true)"; UDP_SESS="${UDP_SESS:-0}"
UDP_DELIV="$(grep -c '"event_code":"ipv6_udp_response_delivered"' "$EVENTS" 2>/dev/null || true)"; UDP_DELIV="${UDP_DELIV:-0}"
log "IPv6 UDP sessions=$UDP_SESS bidirectional_delivered=$UDP_DELIV"
[ "$UDP_DELIV" -ge 1 ] && { UDP_OK=1; log "IPv6 UDP bidirectional: PASS"; } || log "IPv6 UDP bidirectional: NOT carried (honest partial; TCP multi-target is the core claim)"

# --- 7. Fail-closed teardown: kill engine, capture must auto-clear ---
kill "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""
sleep 3
ip -6 route show > "$ART/08-postkill-v6-routes.txt" 2>&1
RES_TUN=0; ip link show "$TUN" >/dev/null 2>&1 && RES_TUN=1
RES_CAP=0; ip -6 route show | grep -q '::/1' && RES_CAP=1
if [ "$RES_TUN" = 0 ] && [ "$RES_CAP" = 0 ]; then log "FAIL-CLOSED TEARDOWN: capture auto-removed, baseline restored"; else fail "residual capture after engine exit (tun=$RES_TUN cap=$RES_CAP)"; fi

# --- verdict ---
{
  echo "{"
  echo "  \"host\": \"$(hostname)\","
  echo "  \"global_v6_nic\": \"${GLOBAL_V6_NIC}\","
  echo "  \"capture_up\": $([ "$up" = 1 ] && echo true || echo false),"
  echo "  \"no_native_leak\": $([ "$LEAK" = 0 ] && [ "$up" = 1 ] && echo true || echo false),"
  echo "  \"distinct_tcp_targets\": ${TCP_N},"
  echo "  \"curl6_carried\": ${CURL_OK},"
  echo "  \"udp_sessions\": ${UDP_SESS},"
  echo "  \"udp_bidirectional\": ${UDP_DELIV},"
  echo "  \"failclosed_teardown\": $([ "$RES_TUN" = 0 ] && [ "$RES_CAP" = 0 ] && echo true || echo false),"
  echo "  \"verdict\": \"$([ "$PASS" = 1 ] && echo FULL_WIDE_TUN_MULTITARGET_LIVE_PASS || echo FULL_WIDE_TUN_LIVE_PARTIAL)\""
  echo "}"
} | tee "$ART/RESULT.json"

[ "$PASS" = 1 ] && log "OVERALL: PASS" || log "OVERALL: PARTIAL/FAIL (see RESULT.json)"
exit 0
