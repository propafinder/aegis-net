#!/usr/bin/env bash
# Controlled Linux hostile-path proof for the live Geneva payload-decoy bridge.
#
# The topology is four network namespaces:
#
#   client -- gateway/censor -- transit router -- HTTP server
#
# The gateway remembers the first PSH payload for each TCP flow. If it contains
# "secret", that flow is blocked. Otherwise the flow is allowed. The Geneva
# case sends a corrupted TTL=1 duplicate first: the gateway sees and accepts
# that decoy, Linux expires it before the server, and the unchanged kernel TCP
# segment then reaches the server on the already-allowed flow.
set -euo pipefail

CLIENT_BIN=""
OUT_DIR=""

usage() {
  echo "usage: $0 --client-bin PATH --out-dir DIR" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --client-bin) CLIENT_BIN="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: network namespaces, raw sockets and packet capture are required" >&2
  exit 2
fi
if [[ -z "${CLIENT_BIN}" || ! -x "${CLIENT_BIN}" || -z "${OUT_DIR}" ]]; then
  usage
  exit 2
fi
for tool in ip iptables iptables-save ip6tables-save tcpdump curl python3 ss sha256sum cmp sed; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "missing required tool: ${tool}" >&2
    exit 2
  }
done

CLIENT_BIN="$(readlink -f "${CLIENT_BIN}")"
mkdir -p "${OUT_DIR}"
OUT_DIR="$(readlink -f "${OUT_DIR}")"

# Immutable provenance plus a root-namespace before/after contour. The actual
# censor lives only in the temporary namespaces below; these snapshots prove
# that its veths, routes and firewall rules did not leak into the host.
date -u +'%Y-%m-%dT%H:%M:%SZ' >"${OUT_DIR}/started-at-utc.txt"
uname -a >"${OUT_DIR}/host-uname.txt"
if [[ -r /etc/os-release ]]; then
  cp /etc/os-release "${OUT_DIR}/host-os-release.txt"
fi
"${CLIENT_BIN}" --version >"${OUT_DIR}/client-version.txt"
sha256sum "${CLIENT_BIN}" >"${OUT_DIR}/client-binary.sha256"
ip netns list >"${OUT_DIR}/host-netns-before.txt"
ip -o link show >"${OUT_DIR}/host-links-before.txt"
ip route show table all >"${OUT_DIR}/host-routes-before.txt"
iptables-save >"${OUT_DIR}/host-iptables-before.txt"
ip6tables-save >"${OUT_DIR}/host-ip6tables-before.txt"
sed -E 's/expires [0-9]+sec/expires <dynamic>sec/g' \
  "${OUT_DIR}/host-routes-before.txt" >"${OUT_DIR}/host-routes-before.canonical.txt"
sed -E -e '/^#/d' \
  -e 's/^(:[^ ]+ [A-Z-]+) \[[0-9]+:[0-9]+\]$/\1 [COUNTERS]/' \
  "${OUT_DIR}/host-iptables-before.txt" >"${OUT_DIR}/host-iptables-before.canonical.txt"
sed -E -e '/^#/d' \
  -e 's/^(:[^ ]+ [A-Z-]+) \[[0-9]+:[0-9]+\]$/\1 [COUNTERS]/' \
  "${OUT_DIR}/host-ip6tables-before.txt" >"${OUT_DIR}/host-ip6tables-before.canonical.txt"

suffix="$$"
client_ns="aegis-geneva-client-${suffix}"
gateway_ns="aegis-geneva-gateway-${suffix}"
server_ns="aegis-geneva-server-${suffix}"
transit_ns="aegis-geneva-transit-${suffix}"
client_veth="agc${suffix}"
gateway_client_veth="agx${suffix}"
gateway_server_veth="agy${suffix}"
transit_gateway_veth="agt${suffix}"
transit_server_veth="agu${suffix}"
server_veth="ags${suffix}"
server_pid=""
client_pid=""
client_capture_pid=""
server_capture_pid=""

cleanup() {
  set +e
  for pid in "${client_capture_pid}" "${server_capture_pid}"; do
    if [[ -n "${pid}" ]]; then
      kill -INT "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  client_capture_pid=""
  server_capture_pid=""
  for pid in "${client_pid}" "${server_pid}"; do
    if [[ -n "${pid}" ]]; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  ip netns del "${client_ns}" 2>/dev/null || true
  ip netns del "${gateway_ns}" 2>/dev/null || true
  ip netns del "${transit_ns}" 2>/dev/null || true
  ip netns del "${server_ns}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ip netns add "${client_ns}"
ip netns add "${gateway_ns}"
ip netns add "${transit_ns}"
ip netns add "${server_ns}"

ip link add "${client_veth}" type veth peer name "${gateway_client_veth}"
ip link add "${gateway_server_veth}" type veth peer name "${transit_gateway_veth}"
ip link add "${transit_server_veth}" type veth peer name "${server_veth}"
ip link set "${client_veth}" netns "${client_ns}"
ip link set "${gateway_client_veth}" netns "${gateway_ns}"
ip link set "${gateway_server_veth}" netns "${gateway_ns}"
ip link set "${transit_gateway_veth}" netns "${transit_ns}"
ip link set "${transit_server_veth}" netns "${transit_ns}"
ip link set "${server_veth}" netns "${server_ns}"

ip -n "${client_ns}" link set "${client_veth}" name eth0
ip -n "${gateway_ns}" link set "${gateway_client_veth}" name gc0
ip -n "${gateway_ns}" link set "${gateway_server_veth}" name gs0
ip -n "${transit_ns}" link set "${transit_gateway_veth}" name tg0
ip -n "${transit_ns}" link set "${transit_server_veth}" name ts0
ip -n "${server_ns}" link set "${server_veth}" name eth0

for ns in "${client_ns}" "${gateway_ns}" "${transit_ns}" "${server_ns}"; do
  ip -n "${ns}" link set lo up
done
ip -n "${client_ns}" address add 10.203.1.2/24 dev eth0
ip -n "${gateway_ns}" address add 10.203.1.1/24 dev gc0
ip -n "${gateway_ns}" address add 10.203.2.1/24 dev gs0
ip -n "${transit_ns}" address add 10.203.2.2/24 dev tg0
ip -n "${transit_ns}" address add 10.203.3.1/24 dev ts0
ip -n "${server_ns}" address add 10.203.3.2/24 dev eth0
ip -n "${client_ns}" link set eth0 up
ip -n "${gateway_ns}" link set gc0 up
ip -n "${gateway_ns}" link set gs0 up
ip -n "${transit_ns}" link set tg0 up
ip -n "${transit_ns}" link set ts0 up
ip -n "${server_ns}" link set eth0 up
ip -n "${client_ns}" route add default via 10.203.1.1
ip -n "${gateway_ns}" route add 10.203.3.0/24 via 10.203.2.2
ip -n "${transit_ns}" route add 10.203.1.0/24 via 10.203.2.1
ip -n "${server_ns}" route add default via 10.203.3.1
ip netns exec "${gateway_ns}" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "${transit_ns}" sysctl -q -w net.ipv4.ip_forward=1
ip -n "${server_ns}" address show >"${OUT_DIR}/server-addresses.txt"

# First data packet decides the connection. The rules are deliberately in
# PREROUTING: a TTL=1 decoy reaches this controlled censor, then expires before
# Linux can forward it to the server-facing interface. KMP is required here:
# the kernel's BM text search can miss a word that lives in a non-linear skb,
# which produced a false unblocked baseline on the RHEL 9 nftables backend.
ip netns exec "${gateway_ns}" iptables -t mangle -A PREROUTING \
  -i gc0 -p tcp --dport 18080 --tcp-flags PSH PSH \
  -m connmark --mark 0 -m string --string secret --algo kmp \
  -j CONNMARK --set-mark 2
ip netns exec "${gateway_ns}" iptables -t mangle -A PREROUTING \
  -i gc0 -p tcp --dport 18080 --tcp-flags PSH PSH \
  -m connmark --mark 0 -j CONNMARK --set-mark 1
ip netns exec "${gateway_ns}" iptables -t mangle -A PREROUTING \
  -i gc0 -p tcp --dport 18080 -m connmark --mark 2 -j DROP

# Python's stock HTTPServer performs a reverse-DNS lookup in server_bind;
# this intentionally DNS-less namespace would make readiness wait on resolver
# timeout. Use a minimal deterministic socket server with no name lookup.
cat >"${OUT_DIR}/http-server.py" <<'PY'
import json
from pathlib import Path
import socket
import sys

ambiguous_receipt = Path(sys.argv[1])

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", 18080))
listener.listen(16)
ambiguous_connections = 0
while True:
    conn, _ = listener.accept()
    # A deliberately blocked first-data packet leaves an otherwise established
    # TCP connection at the server. Bound that incomplete request so this
    # single-process fixture can accept the following independent test flow.
    conn.settimeout(1.0)
    request = bytearray()
    try:
        while b"\r\n\r\n" not in request and len(request) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            request.extend(chunk)
    # Python releases differ in whether socket.timeout is an alias/subclass
    # caught by TimeoutError. Name both so a deliberately incomplete blocked
    # flow cannot kill the fixture before the independent prime/Geneva flows.
    except (TimeoutError, socket.timeout):
        conn.close()
        print("incomplete-request-timeout", flush=True)
        continue
    path = bytes(request).split(b" ", 2)[1] if b" " in request else b"/"
    if path == b"/ambiguous":
        ambiguous_connections += 1
        receipt = {
            "connections": ambiguous_connections,
            "request_len": len(request),
            "path": "/ambiguous",
        }
        ambiguous_receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        conn.close()
        print("ambiguous-canonical-received", flush=True)
        continue
    body = b"geneva-hostile-path-ok\n" if path == b"/secret" else b"prime-ok\n"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        + b"Content-Type: text/plain\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )
    conn.sendall(response)
    conn.close()
    print(path.decode("ascii", "replace"), flush=True)
PY
ip netns exec "${server_ns}" python3 "${OUT_DIR}/http-server.py" \
  "${OUT_DIR}/ambiguous-server-receipt.json" \
  >"${OUT_DIR}/server.log" 2>&1 &
server_pid=$!

for _ in $(seq 1 50); do
  if ip netns exec "${server_ns}" curl -sS --max-time 1 \
    http://10.203.3.2:18080/secret >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
ps -o pid,ppid,stat,etime,cmd -p "${server_pid}" >"${OUT_DIR}/server-process.txt" || true
ip netns exec "${server_ns}" ss -ltnp >"${OUT_DIR}/server-listeners.txt" || true
ip netns exec "${server_ns}" curl -sS --max-time 1 \
  http://10.203.3.2:18080/secret >/dev/null

# Capture the tiny isolated interface without an ingress BPF. AlmaLinux 9's
# nftables/veth combination reported packets to tcpdump but rejected the live
# `tcp port` filter, leaving a header-only pcap. Apply exact filters offline
# below, where the evidence is deterministic and portable.
ip netns exec "${gateway_ns}" tcpdump -U -n -i gc0 -w "${OUT_DIR}/client-facing.pcap" \
  >"${OUT_DIR}/client-facing-tcpdump.log" 2>&1 &
client_capture_pid=$!
ip netns exec "${gateway_ns}" tcpdump -U -n -i gs0 -w "${OUT_DIR}/server-facing.pcap" \
  >"${OUT_DIR}/server-facing-tcpdump.log" 2>&1 &
server_capture_pid=$!
sleep 0.5

write_config() {
  local path="$1"
  local state_path="$2"
  local strategy="$3"
  local geneva_line=""
  if [[ "${strategy}" == "geneva" ]]; then
    geneva_line="geneva_strategy = '[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:1}(tamper{TCP:load:corrupt}()),)-| \\/'"
  fi
  cat >"${path}" <<EOF
mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:19081"

[direct]
state_path = "${state_path}"
strategies = ["${strategy}"]
${geneva_line}
epsilon = 0.0
first_chunk_timeout_ms = 1800
freeze_threshold_bytes = 1
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:9"
server_name = "localhost"
auth_token = "dedb4d0dd0a80819d30142a74251c597656bbec45c9842503ed8dec1c8de27f6"
transport_priority = ["legacy_tls"]
EOF
  chmod 600 "${path}"
}

write_hybrid_ambiguous_config() {
  local path="$1"
  local state_path="$2"
  cat >"${path}" <<EOF
mode = "auto"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:19081"

[direct]
state_path = "${state_path}"
strategies = ["geneva"]
geneva_strategy = '[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:1}(tamper{TCP:load:corrupt}()),)-| \/'
hybrid_geneva = true
epsilon = 0.0
first_chunk_timeout_ms = 1800
freeze_threshold_bytes = 1
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:9"
server_name = "localhost"
auth_token = "929c0e1bd5b47adaa4202e1bb406da543372bb5cf70d9a55a1d2a3073aa608ae"
transport_priority = ["grpc_stream"]
udp_transport_priority = ["masque_derived", "grpc_datagram"]
masque_server = "127.0.0.1:9"
masque_server_name = "localhost"
EOF
  chmod 600 "${path}"
}

start_client() {
  local config="$1"
  local events="$2"
  local log="$3"
  ip netns exec "${client_ns}" env RUST_LOG=info "${CLIENT_BIN}" \
    --config "${config}" --runtime-events-jsonl "${events}" >"${log}" 2>&1 &
  client_pid=$!
  for _ in $(seq 1 80); do
    if ip netns exec "${client_ns}" ss -H -ltn | grep -q ':19081'; then
      return 0
    fi
    if ! kill -0 "${client_pid}" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

stop_client() {
  if [[ -n "${client_pid}" ]]; then
    kill "${client_pid}" 2>/dev/null || true
    wait "${client_pid}" 2>/dev/null || true
    client_pid=""
  fi
}

wait_for_direct_success() {
  local events="$1"
  for _ in $(seq 1 50); do
    if grep -q '"event_code":"direct_session_succeeded"' "${events}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "direct session did not publish success: ${events}" >&2
  return 1
}

wait_for_event() {
  local events="$1" event_code="$2"
  for _ in $(seq 1 80); do
    if grep -q "\"event_code\":\"${event_code}\"" "${events}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "runtime event not published: ${event_code}" >&2
  return 1
}

baseline_config="${OUT_DIR}/baseline.toml"
baseline_events="${OUT_DIR}/baseline-events.jsonl"
write_config "${baseline_config}" "${OUT_DIR}/baseline.state" passthrough
start_client "${baseline_config}" "${baseline_events}" "${OUT_DIR}/baseline-client.log"
set +e
baseline_http="$(ip netns exec "${client_ns}" curl -sS --max-time 4 \
  --socks5-hostname 127.0.0.1:19081 -o /dev/null -w '%{http_code}' \
  http://10.203.3.2:18080/secret 2>"${OUT_DIR}/baseline-curl.stderr")"
baseline_status=$?
set -e
ip netns exec "${gateway_ns}" iptables-save -t mangle -c >"${OUT_DIR}/iptables-after-baseline.txt"
stop_client
if [[ "${baseline_status}" -eq 0 ]]; then
  echo "baseline unexpectedly bypassed the controlled censor (HTTP ${baseline_http})" >&2
  exit 1
fi
ip -n "${client_ns}" address del 10.203.1.2/24 dev eth0
ip -n "${client_ns}" address add 10.203.1.3/24 dev eth0
ip -n "${client_ns}" route replace default via 10.203.1.1

prime_config="${OUT_DIR}/prime.toml"
prime_events="${OUT_DIR}/prime-events.jsonl"
geneva_state="${OUT_DIR}/geneva.state"
write_config "${prime_config}" "${geneva_state}" passthrough
start_client "${prime_config}" "${prime_events}" "${OUT_DIR}/prime-client.log"
prime_http="$(ip netns exec "${client_ns}" curl -sS --max-time 4 \
  --socks5-hostname 127.0.0.1:19081 -o /dev/null -w '%{http_code}' \
  http://10.203.3.2:18080/prime)"
wait_for_direct_success "${prime_events}"
stop_client
[[ "${prime_http}" == "200" ]]
[[ -s "${geneva_state}" ]]
ip -n "${client_ns}" address del 10.203.1.3/24 dev eth0
ip -n "${client_ns}" address add 10.203.1.4/24 dev eth0
ip -n "${client_ns}" route replace default via 10.203.1.1

geneva_config="${OUT_DIR}/geneva.toml"
geneva_events="${OUT_DIR}/geneva-events.jsonl"
write_config "${geneva_config}" "${geneva_state}" geneva
start_client "${geneva_config}" "${geneva_events}" "${OUT_DIR}/geneva-client.log"
geneva_body="$(ip netns exec "${client_ns}" curl -sS --max-time 4 \
  --socks5-hostname 127.0.0.1:19081 http://10.203.3.2:18080/secret)"
wait_for_direct_success "${geneva_events}"
stop_client
[[ "${geneva_body}" == "geneva-hostile-path-ok" ]]

# A second hybrid Geneva flow proves the at-most-once safety boundary. The
# server receives the canonical request and then closes without a response.
# At that point replaying the application payload through gRPC would be
# ambiguous and potentially duplicate side effects, so the client must block
# without starting a relay session.
ip -n "${client_ns}" address del 10.203.1.4/24 dev eth0
ip -n "${client_ns}" address add 10.203.1.5/24 dev eth0
ip -n "${client_ns}" route replace default via 10.203.1.1
ambiguous_config="${OUT_DIR}/ambiguous.toml"
ambiguous_events="${OUT_DIR}/ambiguous-events.jsonl"
write_hybrid_ambiguous_config "${ambiguous_config}" "${geneva_state}"
start_client "${ambiguous_config}" "${ambiguous_events}" "${OUT_DIR}/ambiguous-client.log"
set +e
ambiguous_http="$(ip netns exec "${client_ns}" curl -sS --max-time 5 \
  --socks5-hostname 127.0.0.1:19081 -o /dev/null -w '%{http_code}' \
  http://10.203.3.2:18080/ambiguous 2>"${OUT_DIR}/ambiguous-curl.stderr")"
ambiguous_status=$?
set -e
wait_for_event "${ambiguous_events}" hybrid_flow_blocked_fail_closed
stop_client
sleep 0.5
[[ "${ambiguous_status}" -ne 0 ]]
[[ -s "${OUT_DIR}/ambiguous-server-receipt.json" ]]

ip netns exec "${gateway_ns}" iptables-save -t mangle -c >"${OUT_DIR}/iptables-final.txt"
# The Geneva session is intentionally very short. Let tcpdump drain the AF_PACKET
# receive queue before SIGINT so the persisted pcap contains the final flow.
sleep 1
kill -INT "${client_capture_pid}" "${server_capture_pid}" 2>/dev/null || true
wait "${client_capture_pid}" 2>/dev/null || true
wait "${server_capture_pid}" 2>/dev/null || true
client_capture_pid=""
server_capture_pid=""

client_ttl1="$(tcpdump -nn -r "${OUT_DIR}/client-facing.pcap" \
  'src host 10.203.1.4 and dst host 10.203.3.2 and tcp dst port 18080 and ip[8] = 1' \
  2>/dev/null | wc -l | awk '{print $1}')"
server_ttl1="$(tcpdump -nn -r "${OUT_DIR}/server-facing.pcap" \
  'src host 10.203.1.4 and dst host 10.203.3.2 and tcp dst port 18080 and ip[8] = 1' \
  2>/dev/null | wc -l | awk '{print $1}')"

python3 - "${prime_events}" "${geneva_events}" "${ambiguous_events}" \
  "${OUT_DIR}/ambiguous-server-receipt.json" "${OUT_DIR}/result.json" \
  "${baseline_status}" "${baseline_http}" "${prime_http}" "${geneva_body}" \
  "${client_ttl1}" "${server_ttl1}" "${ambiguous_status}" "${ambiguous_http}" <<'PY'
import json
import sys

prime_path, geneva_path, ambiguous_path, receipt_path, result_path = sys.argv[1:6]
baseline_status = int(sys.argv[6])
baseline_http = sys.argv[7]
prime_http = sys.argv[8]
geneva_body = sys.argv[9]
client_ttl1 = int(sys.argv[10])
server_ttl1 = int(sys.argv[11])
ambiguous_status = int(sys.argv[12])
ambiguous_http = sys.argv[13]

def events(path):
    with open(path, encoding="utf-8") as source:
        return [json.loads(line) for line in source if line.strip()]

prime = events(prime_path)
geneva = events(geneva_path)
ambiguous = events(ambiguous_path)
with open(receipt_path, encoding="utf-8") as source:
    receipt = json.load(source)
prime_success = next(
    event for event in prime
    if event.get("event_code") == "direct_session_succeeded"
)
geneva_success = next(
    event for event in geneva
    if event.get("event_code") == "direct_session_succeeded"
)
prime_hops = prime_success["fields"].get("reference_path_hops")
geneva_strategy = geneva_success["fields"].get("strategy")
ambiguous_codes = [event.get("event_code") for event in ambiguous]
ambiguous_failure = next(
    event for event in ambiguous
    if event.get("event_code") == "geneva_direct_attempt_failed"
)
ambiguous_block = next(
    event for event in ambiguous
    if event.get("event_code") == "hybrid_flow_blocked_fail_closed"
)
ambiguous_passed = all((
    ambiguous_status != 0,
    ambiguous_failure["fields"].get("relay_replay_safe") is False,
    ambiguous_block["fields"].get("relay_replay_safe") is False,
    ambiguous_block["fields"].get("terminal_action") == "block",
    ambiguous_block["fields"].get("no_native_fallback") is True,
    "direct_relay_handoff_started" not in ambiguous_codes,
    "relay_session_started" not in ambiguous_codes,
    receipt.get("connections") == 1,
    receipt.get("path") == "/ambiguous",
    receipt.get("request_len", 0) > 0,
))
passed = all((
    baseline_status != 0,
    prime_http == "200",
    geneva_body == "geneva-hostile-path-ok",
    isinstance(prime_hops, int) and prime_hops > 1,
    geneva_strategy == "geneva",
    client_ttl1 >= 1,
    server_ttl1 == 0,
    ambiguous_passed,
))
result = {
    "artifact": "geneva-controlled-hostile-netns-live",
    "schema_version": 1,
    "status": "PASS" if passed else "FAIL",
    "boundary": "controlled stateful first-payload Linux middlebox; not an external commercial or national DPI",
    "baseline": {
        "blocked": baseline_status != 0,
        "curl_status": baseline_status,
        "http_code": baseline_http,
    },
    "observation_prime": {
        "http_code": prime_http,
        "strategy": prime_success["fields"].get("strategy"),
        "reference_path_hops": prime_hops,
    },
    "geneva": {
        "response_body": geneva_body,
        "strategy": geneva_strategy,
        "reference_path_hops": geneva_success["fields"].get("reference_path_hops"),
        "client_facing_ttl1_packets": client_ttl1,
        "server_facing_ttl1_packets": server_ttl1,
    },
    "ambiguous_post_send": {
        "curl_status": ambiguous_status,
        "http_code": ambiguous_http,
        "canonical_receipts": receipt.get("connections"),
        "canonical_request_len": receipt.get("request_len"),
        "relay_replay_safe": ambiguous_failure["fields"].get("relay_replay_safe"),
        "terminal_action": ambiguous_block["fields"].get("terminal_action"),
        "relay_handoff_started": "direct_relay_handoff_started" in ambiguous_codes,
        "relay_session_started": "relay_session_started" in ambiguous_codes,
        "status": "PASS" if ambiguous_passed else "FAIL",
    },
}
with open(result_path, "w", encoding="utf-8") as output:
    json.dump(result, output, indent=2)
    output.write("\n")
raise SystemExit(0 if passed else 1)
PY

# Run cleanup before declaring the host contour clean. The EXIT trap remains
# until the explicit cleanup succeeds and is then disabled to keep it
# idempotent if a later artifact check fails.
cleanup
set -e
trap - EXIT INT TERM
ip netns list >"${OUT_DIR}/host-netns-after.txt"
ip -o link show >"${OUT_DIR}/host-links-after.txt"
ip route show table all >"${OUT_DIR}/host-routes-after.txt"
iptables-save >"${OUT_DIR}/host-iptables-after.txt"
ip6tables-save >"${OUT_DIR}/host-ip6tables-after.txt"
sed -E 's/expires [0-9]+sec/expires <dynamic>sec/g' \
  "${OUT_DIR}/host-routes-after.txt" >"${OUT_DIR}/host-routes-after.canonical.txt"
sed -E -e '/^#/d' \
  -e 's/^(:[^ ]+ [A-Z-]+) \[[0-9]+:[0-9]+\]$/\1 [COUNTERS]/' \
  "${OUT_DIR}/host-iptables-after.txt" >"${OUT_DIR}/host-iptables-after.canonical.txt"
sed -E -e '/^#/d' \
  -e 's/^(:[^ ]+ [A-Z-]+) \[[0-9]+:[0-9]+\]$/\1 [COUNTERS]/' \
  "${OUT_DIR}/host-ip6tables-after.txt" >"${OUT_DIR}/host-ip6tables-after.canonical.txt"

netns_unchanged=false
links_unchanged=false
routes_unchanged=false
iptables_unchanged=false
ip6tables_unchanged=false
cmp -s "${OUT_DIR}/host-netns-before.txt" "${OUT_DIR}/host-netns-after.txt" && netns_unchanged=true
cmp -s "${OUT_DIR}/host-links-before.txt" "${OUT_DIR}/host-links-after.txt" && links_unchanged=true
cmp -s "${OUT_DIR}/host-routes-before.canonical.txt" "${OUT_DIR}/host-routes-after.canonical.txt" && routes_unchanged=true
cmp -s "${OUT_DIR}/host-iptables-before.canonical.txt" "${OUT_DIR}/host-iptables-after.canonical.txt" && iptables_unchanged=true
cmp -s "${OUT_DIR}/host-ip6tables-before.canonical.txt" "${OUT_DIR}/host-ip6tables-after.canonical.txt" && ip6tables_unchanged=true

python3 - "${OUT_DIR}" "${netns_unchanged}" "${links_unchanged}" \
  "${routes_unchanged}" "${iptables_unchanged}" "${ip6tables_unchanged}" <<'PY'
import json
from pathlib import Path
import sys

artifact = Path(sys.argv[1])
flags = [value == "true" for value in sys.argv[2:]]
result_path = artifact / "result.json"
result = json.loads(result_path.read_text(encoding="utf-8"))
binary_sha = (artifact / "client-binary.sha256").read_text(encoding="utf-8").split()[0]
result["provenance"] = {
    "client_version": (artifact / "client-version.txt").read_text(encoding="utf-8").strip(),
    "client_sha256": binary_sha,
    "host_uname": (artifact / "host-uname.txt").read_text(encoding="utf-8").strip(),
}
result["host_cleanup"] = {
    "netns_unchanged": flags[0],
    "links_unchanged": flags[1],
    "routes_unchanged": flags[2],
    "iptables_unchanged": flags[3],
    "ip6tables_unchanged": flags[4],
}
if not all(flags):
    result["status"] = "FAIL"
with result_path.open("w", encoding="utf-8") as output:
    json.dump(result, output, indent=2)
    output.write("\n")
print(json.dumps(result, ensure_ascii=False))
raise SystemExit(0 if result["status"] == "PASS" else 1)
PY

sha256sum \
  "${OUT_DIR}/client-facing.pcap" \
  "${OUT_DIR}/server-facing.pcap" \
  "${OUT_DIR}/prime-events.jsonl" \
  "${OUT_DIR}/geneva-events.jsonl" \
  "${OUT_DIR}/ambiguous-events.jsonl" \
  "${OUT_DIR}/ambiguous-server-receipt.json" \
  "${OUT_DIR}/iptables-final.txt" \
  "${OUT_DIR}/result.json" >"${OUT_DIR}/sha256sums.txt"

echo "PASS: controlled Geneva hostile-path artifact written to ${OUT_DIR}"
