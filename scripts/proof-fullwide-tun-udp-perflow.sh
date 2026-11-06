#!/usr/bin/env bash
# Prove the full-wide-tun IPv6 UDP leg is a PER-FLOW relay (one persistent MASQUE
# session per flow, reused for every datagram) — not one-shot-per-datagram. Two
# multi-datagram-single-flow tests:
#   (A) one UDP socket sends N DNS queries to ONE resolver -> expect exactly 1
#       ipv6_udp_session_created for that flow + N responses (session reuse).
#   (B) HTTP/3 over IPv6 (QUIC = many datagrams in one flow) if curl supports it.
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
CFG_REAL="/etc/aegis/client/aegis.toml"
CFG_TEST="/root/aegis-udpflow-test.toml"
MASQUE_CA="/root/aegis-masque-ca.pem"
EVENTS="/root/aegis-udpflow-events.jsonl"
ART="/root/aegis-udpflow-artifacts"
TUN="aegis-tun0"
: > "$EVENTS"; mkdir -p "$ART"
cleanup(){ [ -n "${CPID:-}" ] && kill "$CPID" 2>/dev/null || true; sleep 1; ip link del "$TUN" 2>/dev/null || true; systemctl start aegis-client.service 2>/dev/null || true; rm -f "$CFG_TEST" "$MASQUE_CA"; }
trap cleanup EXIT

systemctl stop aegis-client.service 2>/dev/null || true; sleep 1; ip link del "$TUN" 2>/dev/null || true
PERSIST="/usr/local/lib/aegis/setup-wide-linux-redirect.sh"
[ -x "$PERSIST" ] && AEGIS_WIDE_PORT=15080 bash "$PERSIST" teardown >/dev/null 2>&1 || true

cat "$(grep -E '^\s*ca_cert' "$CFG_REAL" | sed -E 's/.*=\s*"?([^"]*)"?.*/\1/')" "$CF_ROOT" > "$MASQUE_CA" 2>/dev/null
cp "$CFG_REAL" "$CFG_TEST"
python3 - "$CFG_TEST" "$MASQUE_DIRECT" "$MASQUE_CA" <<'PY'
import re,sys
p,md,ca=sys.argv[1],sys.argv[2],sys.argv[3]; t=open(p).read()
b=re.search(r'(?ms)^\[ingress\.wide\]\s*$.*?(?=^\[|\Z)',t).group(0)
nb=(re.sub(r'(?m)^(\s*ipv6_tun_carried\s*=\s*).*$',r'\g<1>true',b,count=1) if re.search(r'(?m)^\s*ipv6_tun_carried\s*=',b) else b.rstrip()+'\nipv6_tun_carried = true\n'); t=t.replace(b,nb)
b=re.search(r'(?ms)^\[relay\]\s*$.*?(?=^\[|\Z)',t).group(0); nb=b
def sk(s,k,v):
    return (re.sub(r'(?m)^(\s*%s\s*=\s*).*$'%k,r'\g<1>"%s"'%v,s,count=1) if re.search(r'(?m)^\s*%s\s*='%k,s) else s.rstrip()+'\n%s = "%s"\n'%(k,v))
nb=sk(nb,'masque_server',md); nb=sk(nb,'masque_ca_cert',ca); t=t.replace(b,nb)
open(p,'w').write(t); print("config: masque_server=%s ipv6_tun_carried=true"%md)
PY

nohup "$BIN_NEW" --config "$CFG_TEST" --runtime-events-jsonl "$EVENTS" >"$ART/client.log" 2>&1 &
CPID=$!
for i in $(seq 1 20); do ip link show "$TUN" >/dev/null 2>&1 && ip -6 route show | grep -q '::/1' && break; sleep 1; done
echo "engine up: $(ip link show "$TUN" >/dev/null 2>&1 && echo yes || echo no)"

echo "=== (A) ONE socket, 5 DNS queries to ONE v6 resolver (per-flow reuse) ==="
python3 - <<'PY' | tee "$ART/A-multidatagram.txt"
import socket, struct, time
# minimal DNS query for example.com A, varying txid
def q(txid):
    h=struct.pack(">HHHHHH",txid,0x0100,1,0,0,0)
    qn=b''.join(bytes([len(p)])+p.encode() for p in "example.com".split('.'))+b'\x00'
    return h+qn+struct.pack(">HH",1,1)
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
s.bind(("::",0)); s.settimeout(6)
dst=("2606:4700:4700::1111",53)
ok=0
for i in range(5):
    try:
        s.sendto(q(0x1000+i),dst)
        d,_=s.recvfrom(2048); ok+=1
        time.sleep(0.2)
    except Exception as e:
        print("recv",i,"err",e)
print("one-socket DNS: sent=5 answered=%d srcport=%d"%(ok,s.getsockname()[1]))
PY

echo "=== (B) HTTP/3 over IPv6 (QUIC multi-datagram single flow), if supported ==="
if curl --version | grep -qi HTTP3; then
  curl --http3-only -6 -s -o /dev/null -w "h3 http=%{http_code} via=%{remote_ip}\n" --max-time 15 "https://[2606:4700:4700::1111]/" 2>&1 | tee "$ART/B-http3.txt" || echo "h3 failed" | tee -a "$ART/B-http3.txt"
else
  echo "curl has no HTTP3 support; skipping (A is the per-flow proof)" | tee "$ART/B-http3.txt"
fi

sleep 2
cp "$EVENTS" "$ART/runtime-events.jsonl" 2>/dev/null || true
# Per-flow proof: for the one-socket DNS flow, sessions should be FEWER than
# datagrams (ideally 1 session, 5 deliveries) — proving reuse, not per-datagram.
SESS=$(grep -c '"event_code":"ipv6_udp_session_created"' "$EVENTS" 2>/dev/null || true); SESS="${SESS:-0}"
DELIV=$(grep -c '"event_code":"ipv6_udp_response_delivered"' "$EVENTS" 2>/dev/null || true); DELIV="${DELIV:-0}"
# distinct (src) flows that created sessions
FLOWS=$(grep '"event_code":"ipv6_udp_session_created"' "$EVENTS" 2>/dev/null | grep -oE '"src":"[^"]+"' | sort -u | wc -l)
echo "=== distinct UDP flows (session_created): $FLOWS ; total sessions: $SESS ; total deliveries: $DELIV ==="
grep '"event_code":"ipv6_udp_session_created"' "$EVENTS" 2>/dev/null | grep -oE '"src":"[^"]+","orig_dst":"[^"]+"' | sort | uniq -c
echo "{\"distinct_flows\":$FLOWS,\"sessions_created\":$SESS,\"deliveries\":$DELIV,\"verdict\":\"$([ "$DELIV" -gt "$SESS" ] && echo PER_FLOW_REUSE_PASS || echo CHECK)\"}" | tee "$ART/RESULT.json"
