#!/usr/bin/env bash
# Turnkey + teardown-matrix + bounded-soak live harness for full-wide-tun,
# exercising the SYSTEMD-managed path (not a manual binary run): the exact unit
# drop-in install.sh writes for full-wide-tun (root + CAP_NET_ADMIN + SIGKILL-safe
# ExecStopPost), the IPv6-into-tun firewall, and the masque direct config. Runs on
# a disposable host as root. Idempotent + reversible: backs up binary/config/unit
# state and restores the original service on exit. SSH is IPv4, only IPv6 touched.
#
# Args: <new-binary> <masque-origin ip:port> <cf-origin-ca.pem> <redirect-helper.sh>
set -uo pipefail
BIN_NEW="${1:-/root/aegis-client.fullwidetun}"
MASQUE_DIRECT="${2:-}"
# BEGIN explicit MASQUE proof input admission
# The direct transport parses a numeric SocketAddr. Admit its numeric forms
# before any output, trap, config mutation, helper or native operation.
# The contract differentially checks this shell predicate against Rust's parser.
aegis_masque_uint_ready() {
  local raw="$1" limit="$2" zero_allowed="$3" significant
  local LC_ALL=C
  [[ "$raw" =~ ^[0-9]+$ ]] || return 1
  significant="${raw#"${raw%%[!0]*}"}"
  if [[ -z "$significant" ]]; then
    [[ "$zero_allowed" == yes ]]
    return
  fi
  [[ ${#significant} -le ${#limit} ]] || return 1
  (( 10#$significant <= limit ))
}
aegis_masque_ipv4_ready() {
  local address="$1" octet
  local LC_ALL=C
  local -a octets
  [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<< "$address"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ ${#octet} -eq 1 || "$octet" != 0* ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}
aegis_masque_ipv6_ready() {
  local address="$1" scope tail left right section hextet groups=0 compressed=no
  local LC_ALL=C
  local -a hextets
  if [[ "$address" == *%* ]]; then
    scope="${address#*%}"
    address="${address%%\%*}"
    aegis_masque_uint_ready "$scope" 4294967295 yes || return 1
  fi
  [[ ${#address} -le 45 && "$address" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
  if [[ "$address" == *.* ]]; then
    tail="${address##*:}"
    [[ "$tail" != "$address" ]] || return 1
    aegis_masque_ipv4_ready "$tail" || return 1
    address="${address%:*}:0:0"
  fi
  if [[ "$address" == *::* ]]; then
    compressed=yes
    left="${address%%::*}"
    right="${address#*::}"
    [[ "$right" != *::* ]] || return 1
  else
    left="$address"
    right=""
  fi
  for section in "$left" "$right"; do
    [[ -n "$section" ]] || continue
    [[ "$section" != :* && "$section" != *: ]] || return 1
    IFS=: read -r -a hextets <<< "$section"
    for hextet in "${hextets[@]}"; do
      [[ "$hextet" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
      groups=$((groups + 1))
    done
  done
  if [[ "$compressed" == yes ]]; then
    [[ "$groups" -lt 8 ]]
  else
    [[ "$groups" -eq 8 ]]
  fi
}
aegis_masque_endpoint_ready() {
  local endpoint="$1" address port
  local LC_ALL=C
  local v4='^([0-9.]+):([0-9]+)$'
  local v6='^\[([0-9A-Fa-f:.%]+)\]:([0-9]+)$'
  if [[ "$endpoint" =~ $v4 ]]; then
    address="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    aegis_masque_ipv4_ready "$address" || return 1
  elif [[ "$endpoint" =~ $v6 ]]; then
    address="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    aegis_masque_ipv6_ready "$address" || return 1
  else
    return 1
  fi
  aegis_masque_uint_ready "$port" 65535 no
}
if ! aegis_masque_endpoint_ready "$MASQUE_DIRECT"; then
  printf '%s\n' 'explicit numeric MASQUE endpoint required' >&2
  exit 64
fi
# END explicit MASQUE proof input admission
CF_ROOT="${3:-/root/cf_origin_ecc_root.pem}"
REDIR_SRC="${4:-/root/setup-wide-linux-redirect.sh}"
BIN_DST="/usr/local/bin/aegis-client"
CFG="/etc/aegis/client/aegis.toml"
MASQUE_CA="/etc/aegis/client/masque-ca.pem"
DROPIN_DIR="/etc/systemd/system/aegis-client.service.d"
DROPIN="${DROPIN_DIR}/20-ipv6-tun.conf"
UIDDROPIN="${DROPIN_DIR}/10-dedicated-uid.conf"
HELPER="/usr/local/lib/aegis/setup-wide-linux-redirect.sh"
TUN="aegis-tun0"
ART="/root/aegis-turnkey-artifacts"
BK="/root/aegis-turnkey-backup"
PASS=1
mkdir -p "$ART" "$BK"
log(){ echo "[turnkey] $*"; }
fail(){ echo "[turnkey][FAIL] $*"; PASS=0; }

restore() {
  log "=== RESTORE ==="
  systemctl stop aegis-client.service 2>/dev/null || true
  [ -x "$HELPER" ] && AEGIS_WIDE_PORT=15080 bash "$HELPER" teardown >/dev/null 2>&1 || true
  ip -6 route del ::/1 dev "$TUN" 2>/dev/null || true
  ip -6 route del 8000::/1 dev "$TUN" 2>/dev/null || true
  ip link del "$TUN" 2>/dev/null || true
  rm -f "$DROPIN" "$MASQUE_CA"
  # restore the dedicated-uid drop-in we moved aside (host had wide-redirect-safe)
  [ -f "$BK/10-dedicated-uid.conf" ] && cp -f "$BK/10-dedicated-uid.conf" "$UIDDROPIN"
  [ -f "$BK/aegis.toml" ] && cp -f "$BK/aegis.toml" "$CFG"
  [ -f "$BK/aegis-client.bin" ] && install -m0755 "$BK/aegis-client.bin" "$BIN_DST"
  systemctl daemon-reload 2>/dev/null || true
  systemctl start aegis-client.service 2>/dev/null || true
  sleep 2
  log "restored; service: $(systemctl is-active aegis-client.service); residual tun: $(ip link show $TUN >/dev/null 2>&1 && echo PRESENT || echo none)"
}
trap restore EXIT

# ---------- backup ----------
cp -f "$CFG" "$BK/aegis.toml"
cp -f "$BIN_DST" "$BK/aegis-client.bin" 2>/dev/null || true
systemctl is-active aegis-client.service > "$ART/00-svc-before.txt" 2>&1 || true
ip -6 route show > "$ART/00-baseline-v6-routes.txt" 2>&1

# ================= PHASE 1: turnkey activation (systemd) =================
log "=== PHASE 1: full-wide-tun activation (systemd-managed) ==="
systemctl stop aegis-client.service 2>/dev/null || true; sleep 1
ip link del "$TUN" 2>/dev/null || true
[ -x "$HELPER" ] && AEGIS_WIDE_PORT=15080 bash "$HELPER" teardown >/dev/null 2>&1 || true

# binary + redirect helper (with the IPv6-into-tun exemption) + masque CA
install -m0755 "$BIN_NEW" "$BIN_DST"
mkdir -p /usr/local/lib/aegis
[ -f "$REDIR_SRC" ] && install -m0755 "$REDIR_SRC" "$HELPER"
cat "$(grep -E '^\s*ca_cert' "$CFG" | sed -E 's/.*=\s*"?([^"]*)"?.*/\1/')" "$CF_ROOT" > "$MASQUE_CA"
chown aegis:aegis "$MASQUE_CA" 2>/dev/null || true

# config: ipv6_tun_carried + masque_server + masque_ca_cert (exact installer keys)
python3 - "$CFG" "$MASQUE_DIRECT" "$MASQUE_CA" <<'PY'
import re,sys
p,md,ca=sys.argv[1],sys.argv[2],sys.argv[3]; t=open(p).read()
b=re.search(r'(?ms)^\[ingress\.wide\]\s*$.*?(?=^\[|\Z)',t).group(0)
nb=(re.sub(r'(?m)^(\s*ipv6_tun_carried\s*=\s*).*$',r'\g<1>true',b,count=1) if re.search(r'(?m)^\s*ipv6_tun_carried\s*=',b) else b.rstrip()+'\nipv6_tun_carried = true\n')
nb=re.sub(r'(?m)^(\s*platform_backend\s*=\s*).*$',r'\g<1>"linux_redirect"',nb,count=1) if re.search(r'(?m)^\s*platform_backend\s*=',nb) else nb
t=t.replace(b,nb)
b=re.search(r'(?ms)^\[relay\]\s*$.*?(?=^\[|\Z)',t).group(0); nb=b
def sk(s,k,v):
    return (re.sub(r'(?m)^(\s*%s\s*=\s*).*$'%k,r'\g<1>"%s"'%v,s,count=1) if re.search(r'(?m)^\s*%s\s*='%k,s) else s.rstrip()+'\n%s = "%s"\n'%(k,v))
nb=sk(nb,'masque_server',md); nb=sk(nb,'masque_ca_cert',ca); t=t.replace(b,nb)
open(p,'w').write(t); print("config patched: ipv6_tun_carried=true, masque_server=%s"%md)
PY

# A fresh `install.sh --profile full-wide-tun` installs NO dedicated-uid drop-in
# (it runs the client as root). This host previously ran wide-redirect-safe, whose
# 10-dedicated-uid.conf pins CapabilityBoundingSet=CAP_NET_BIND_SERVICE — which would
# cap out our CAP_NET_ADMIN. Move it aside to match a fresh full-wide-tun install.
if [ -f "$UIDDROPIN" ]; then
  cp -f "$UIDDROPIN" "$BK/10-dedicated-uid.conf"
  rm -f "$UIDDROPIN"
  log "moved aside 10-dedicated-uid.conf (CapabilityBoundingSet conflict; fresh full-wide-tun has none)"
fi
# systemd drop-in: VERBATIM what install.sh's install_client_ipv6_tun_dropin writes,
# plus User=root override.
mkdir -p "$DROPIN_DIR"
cat > "$DROPIN" <<'EOF'
[Service]
User=root
Group=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStopPost=/bin/sh -c 'ip -6 route del ::/1 dev aegis-tun0 2>/dev/null; ip -6 route del 8000::/1 dev aegis-tun0 2>/dev/null; ip link del aegis-tun0 2>/dev/null; true'
EOF
systemctl daemon-reload

# firewall: REDIRECT v4 + IPv6 backstop that EXEMPTS the tun (the new knob)
AEGIS_WIDE_PORT=15080 AEGIS_EXEMPT_UID=0 AEGIS_WIDE_BLOCK_LEAKS=1 \
  AEGIS_WIDE_BLOCK_UDP=1 AEGIS_WIDE_BLOCK_TCP_DNS=0 AEGIS_WIDE_BLOCK_IPV6=1 \
  AEGIS_WIDE_IPV6_TUN_DEV="$TUN" bash "$HELPER" apply >"$ART/01-firewall-apply.log" 2>&1 || log "firewall apply rc=$?"

systemctl restart aegis-client.service
up=0
for i in $(seq 1 25); do
  if systemctl is-active --quiet aegis-client.service && ip link show "$TUN" >/dev/null 2>&1 && ip -6 route show | grep -q '::/1'; then up=1; break; fi
  sleep 1
done
systemctl show aegis-client.service -p User -p MainPID -p ActiveState > "$ART/02-service-props.txt" 2>&1
ip6tables -t filter -S 2>/dev/null | grep -E "aegis-tun0|REJECT" > "$ART/02-ip6-rules.txt" 2>&1 || true
systemctl cat aegis-client.service 2>/dev/null | grep -E "User=|ExecStopPost|AmbientCap" > "$ART/02-unit-effective.txt" 2>&1 || true
if [ "$up" = 1 ]; then log "PHASE1 PASS: service active (root), engine up (tun + ::/1)"; else
  fail "service/engine did not come up"
  journalctl -u aegis-client.service -n 40 --no-pager > "$ART/02-journal-fail.txt" 2>&1 || true
  tail -20 /var/log/aegis-client/runtime-events.jsonl > "$ART/02-events-tail.txt" 2>&1 || true
  log "journal tail:"; journalctl -u aegis-client.service -n 8 --no-pager 2>&1 | sed 's/^/[journal] /' | tail -8
fi
grep -q "User=root" "$ART/02-service-props.txt" && log "service runs as root (CAP_NET_ADMIN)" || fail "service not running as root"
grep -q "ExecStopPost" "$ART/02-unit-effective.txt" && log "ExecStopPost drop-in present" || fail "ExecStopPost missing"
grep -q "o aegis-tun0 .*RETURN\|aegis-tun0" "$ART/02-ip6-rules.txt" && log "IPv6 backstop exempts the tun" || log "note: tun exempt rule not matched in dump"

# ================= PHASE 2: five legs via the service =================
log "=== PHASE 2: traffic via the systemd service ==="
EVENTS="/var/log/aegis-client/runtime-events.jsonl"
{ for u in 'https://[2606:4700:4700::1111]/' 'https://[2620:fe::fe]/'; do
    echo "$u -> $(curl -6 -s -o /dev/null -w '%{http_code} %{remote_ip}' --max-time 20 "$u" 2>/dev/null || echo '000 -')"
  done; } | tee "$ART/03-curl6.txt"
# per-flow UDP: one socket, 5 datagrams
python3 - <<'PY' | tee "$ART/03-udp6.txt"
import socket,struct,time
def q(t):
    h=struct.pack(">HHHHHH",t,0x0100,1,0,0,0)
    qn=b''.join(bytes([len(p)])+p.encode() for p in "example.com".split('.'))+b'\x00'
    return h+qn+struct.pack(">HH",1,1)
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.bind(("::",0)); s.settimeout(6)
ok=0
for i in range(5):
    try: s.sendto(q(0x2000+i),("2606:4700:4700::1111",53)); s.recvfrom(2048); ok+=1; time.sleep(0.2)
    except Exception as e: print("err",i,e)
print("one-socket DNS sent=5 answered=%d"%ok)
PY
sleep 2
TCP_T=$(grep '"event_code":"wide_tun_smoltcp_tcp_flow_established"' "$EVENTS" 2>/dev/null | grep -oE '"orig_dst":"[^"]+"' | sort -u | wc -l)
UDP_S=$(grep -c '"event_code":"ipv6_udp_session_created"' "$EVENTS" 2>/dev/null || true); UDP_S="${UDP_S:-0}"
UDP_D=$(grep -c '"event_code":"ipv6_udp_response_delivered"' "$EVENTS" 2>/dev/null || true); UDP_D="${UDP_D:-0}"
CURL_OK=$(grep -cE ' (200|301|302|403|404) ' "$ART/03-curl6.txt" || true); CURL_OK="${CURL_OK:-0}"
log "v6 TCP distinct targets=$TCP_T curl_carried=$CURL_OK ; v6 UDP sessions=$UDP_S deliveries=$UDP_D"
{ [ "$TCP_T" -ge 2 ] && [ "$CURL_OK" -ge 1 ]; } && log "PHASE2 v6 TCP PASS" || fail "v6 TCP via service not proven"
[ "$UDP_D" -ge 1 ] && log "PHASE2 v6 UDP PASS" || fail "v6 UDP via service not carried"

# ================= PHASE 3: teardown matrix =================
log "=== PHASE 3: teardown matrix ==="
# (a) SIGTERM = systemctl stop -> clean
systemctl stop aegis-client.service; sleep 3
RT=0; ip link show "$TUN" >/dev/null 2>&1 && RT=1
RC=0; ip -6 route show | grep -q '::/1' && RC=1
{ [ "$RT" = 0 ] && [ "$RC" = 0 ]; } && log "SIGTERM: clean (no residual tun/capture)" || fail "SIGTERM left residual (tun=$RT cap=$RC)"
echo "post-SIGTERM:" > "$ART/04-teardown.txt"; ip -6 route show | grep -E '::/1|8000::|aegis-tun' >> "$ART/04-teardown.txt" 2>&1 || echo "(none)" >> "$ART/04-teardown.txt"

# (b) SIGKILL -> ExecStopPost + non-persistent tun. Restart, then hard-kill MainPID.
systemctl start aegis-client.service; sleep 4
for i in $(seq 1 15); do ip link show "$TUN" >/dev/null 2>&1 && ip -6 route show | grep -q '::/1' && break; sleep 1; done
PID=$(systemctl show aegis-client.service -p MainPID --value)
log "hard-killing MainPID=$PID (SIGKILL)"
systemctl kill -s KILL aegis-client.service 2>/dev/null || kill -9 "$PID" 2>/dev/null || true
sleep 1
# capture immediate state, then stop to disable auto-restart for the assertion
systemctl stop aegis-client.service 2>/dev/null || true; sleep 2
RT2=0; ip link show "$TUN" >/dev/null 2>&1 && RT2=1
RC2=0; ip -6 route show | grep -q '::/1' && RC2=1
{ [ "$RT2" = 0 ] && [ "$RC2" = 0 ]; } && log "SIGKILL: capture removed (ExecStopPost + non-persistent tun)" || fail "SIGKILL left residual (tun=$RT2 cap=$RC2)"
echo "post-SIGKILL:" >> "$ART/04-teardown.txt"; ip -6 route show | grep -E '::/1|8000::|aegis-tun' >> "$ART/04-teardown.txt" 2>&1 || echo "(none)" >> "$ART/04-teardown.txt"
# (c) no-leak when engine down: a global v6 must NOT route to a dead tun
GV=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | head -1)
echo "engine-down route: $GV" >> "$ART/04-teardown.txt"
echo "$GV" | grep -q "dev $TUN" && fail "global v6 still routes to a dead tun" || log "no-leak: v6 falls back to baseline when engine down"

# ================= PHASE 4: bounded soak + perf =================
log "=== PHASE 4: bounded soak (${SOAK_SECS:-180}s) ==="
systemctl start aegis-client.service; sleep 4
for i in $(seq 1 20); do ip link show "$TUN" >/dev/null 2>&1 && ip -6 route show | grep -q '::/1' && break; sleep 1; done
SOAK_SECS="${SOAK_SECS:-180}"; t_end=$(( $(date +%s) + SOAK_SECS ))
tot=0; okc=0; lat_sum=0
while [ "$(date +%s)" -lt "$t_end" ]; do
  tot=$((tot+1))
  c="$(curl -6 -s -o /dev/null -w '%{http_code}:%{time_total}' --max-time 15 'https://[2606:4700:4700::1111]/' 2>/dev/null || echo '000:0')"
  code="${c%%:*}"; tt="${c##*:}"
  case "$code" in 200|301|302|403|404) okc=$((okc+1)); lat_sum=$(awk -v a="$lat_sum" -v b="$tt" 'BEGIN{print a+b}');; esac
  sleep 12
done
PID=$(systemctl show aegis-client.service -p MainPID --value)
RSS=$(awk '/VmRSS/{print $2" "$3}' /proc/"$PID"/status 2>/dev/null || echo "n/a")
RESID=$(ip -6 route show | grep -cE '::/1|8000::')
AVG=$(awk -v s="$lat_sum" -v n="$okc" 'BEGIN{ if(n>0) printf "%.3f", s/n; else print "n/a" }')
log "soak: attempts=$tot ok=$okc avg_latency=${AVG}s RSS=$RSS capture_routes_present=$RESID"
echo "{\"attempts\":$tot,\"ok\":$okc,\"avg_latency_s\":\"$AVG\",\"rss\":\"$RSS\",\"capture_routes\":$RESID}" > "$ART/05-soak.json"
{ [ "$okc" -gt 0 ] && [ "$RESID" -ge 2 ]; } && log "PHASE4 soak PASS (sustained carry, capture stable)" || fail "soak: no successful carries or capture lost"

# ================= verdict =================
{
  echo "{"
  echo "  \"phase1_turnkey_systemd\": $([ "$up" = 1 ] && echo true || echo false),"
  echo "  \"v6_tcp_targets\": ${TCP_T}, \"v6_udp_deliveries\": ${UDP_D},"
  echo "  \"sigterm_clean\": $([ "${RT:-1}" = 0 ] && [ "${RC:-1}" = 0 ] && echo true || echo false),"
  echo "  \"sigkill_clean\": $([ "${RT2:-1}" = 0 ] && [ "${RC2:-1}" = 0 ] && echo true || echo false),"
  echo "  \"soak_ok\": ${okc:-0}, \"soak_attempts\": ${tot:-0},"
  echo "  \"verdict\": \"$([ "$PASS" = 1 ] && echo FULL_WIDE_TUN_TURNKEY_LIVE_PASS || echo FULL_WIDE_TUN_TURNKEY_PARTIAL)\""
  echo "}"
} | tee "$ART/RESULT.json"
[ "$PASS" = 1 ] && log "OVERALL PASS" || log "OVERALL PARTIAL/FAIL"
