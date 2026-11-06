#!/usr/bin/env bash
# Diagnose the full-wide-tun IPv6 UDP leg via a DIRECT-MASQUE origin (bypassing
# Cloudflare, which 405s MASQUE). Sets relay.masque_server to a direct origin,
# then (A) isolates direct-MASQUE with --masque-udp-health, (B) drives real IPv6
# UDP (dig over v6) through the tun engine and checks bidirectional delivery.
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
CFG_REAL="/etc/aegis/client/aegis.toml"
CFG_TEST="/root/aegis-udp-test.toml"
EVENTS="/root/aegis-udp-events.jsonl"
TUN="aegis-tun0"
: > "$EVENTS"
cleanup(){ [ -n "${CPID:-}" ] && kill "$CPID" 2>/dev/null || true; sleep 1; ip link del "$TUN" 2>/dev/null || true; systemctl start aegis-client.service 2>/dev/null || true; }
trap cleanup EXIT

systemctl stop aegis-client.service 2>/dev/null || true; sleep 1; ip link del "$TUN" 2>/dev/null || true
PERSIST="/usr/local/lib/aegis/setup-wide-linux-redirect.sh"
[ -x "$PERSIST" ] && AEGIS_WIDE_PORT=15080 bash "$PERSIST" teardown >/dev/null 2>&1 || true

cp "$CFG_REAL" "$CFG_TEST"
python3 - "$CFG_TEST" "$MASQUE_DIRECT" <<'PY'
import re,sys
p,md=sys.argv[1],sys.argv[2]; t=open(p).read()
# [ingress.wide] ipv6_tun_carried=true
if re.search(r'(?m)^\s*\[ingress\.wide\]\s*$',t):
    b=re.search(r'(?ms)^\[ingress\.wide\]\s*$.*?(?=^\[|\Z)',t).group(0)
    nb=(re.sub(r'(?m)^(\s*ipv6_tun_carried\s*=\s*).*$',r'\g<1>true',b,count=1)
        if re.search(r'(?m)^\s*ipv6_tun_carried\s*=',b) else b.rstrip()+'\nipv6_tun_carried = true\n')
    t=t.replace(b,nb)
# [relay] masque_server = direct origin
b=re.search(r'(?ms)^\[relay\]\s*$.*?(?=^\[|\Z)',t).group(0)
nb=(re.sub(r'(?m)^(\s*masque_server\s*=\s*).*$',r'\g<1>"%s"'%md,b,count=1)
    if re.search(r'(?m)^\s*masque_server\s*=',b) else b.rstrip()+'\nmasque_server = "%s"\n'%md)
t=t.replace(b,nb)
open(p,'w').write(t); print("masque_server=%s + ipv6_tun_carried=true"%md)
PY

chmod +x "$BIN_NEW"
echo "=== (A) isolate DIRECT-MASQUE: --masque-udp-health to a v6 DNS resolver ==="
timeout 25 "$BIN_NEW" --config "$CFG_TEST" --masque-udp-health '[2606:4700:4700::1111]:53' 2>&1 | grep -iE 'masque|health|udp|200|405|connect|ok|fail|error' | head -12 || true

echo "=== (B) full tun engine: IPv6 UDP via direct MASQUE ==="
nohup "$BIN_NEW" --config "$CFG_TEST" --runtime-events-jsonl "$EVENTS" >/root/aegis-udp-client.log 2>&1 &
CPID=$!
for i in $(seq 1 20); do ip link show "$TUN" >/dev/null 2>&1 && ip -6 route show | grep -q '::/1' && break; sleep 1; done
echo "engine up: $(ip link show "$TUN" >/dev/null 2>&1 && echo yes || echo no)"
# Drive real IPv6 UDP DNS to two distinct resolvers.
for r in 2606:4700:4700::1111 2001:4860:4860::8888; do
  echo "dig @[$r] over v6:"; dig +time=6 +tries=1 +short @"$r" example.com A 2>&1 | head -3 || true
done
sleep 2
echo "=== UDP events ==="
grep -E 'ipv6_udp_session_created|ipv6_udp_response_delivered|ipv6_udp_fail_closed' "$EVENTS" 2>/dev/null | head
echo "=== client log: MASQUE connect outcome (200 vs 405) ==="
grep -iE 'connect_start|status 200|status 405|datagram stage|masque.*error|405|response_delivered' /root/aegis-udp-client.log 2>/dev/null | tail -15
SESS=$(grep -c '"event_code":"ipv6_udp_session_created"' "$EVENTS" 2>/dev/null || true); SESS="${SESS:-0}"
DELIV=$(grep -c '"event_code":"ipv6_udp_response_delivered"' "$EVENTS" 2>/dev/null || true); DELIV="${DELIV:-0}"
echo "=== VERDICT: udp_sessions=$SESS udp_bidirectional_delivered=$DELIV ==="
[ "$DELIV" -ge 1 ] && echo "IPV6_UDP_DIRECT_MASQUE_PASS" || echo "IPV6_UDP_DIRECT_MASQUE_FAIL"
rm -f "$CFG_TEST"
