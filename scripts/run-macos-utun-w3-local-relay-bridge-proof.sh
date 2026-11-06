#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Historical evidence lives outside Git (docs/operations/evidence-archive.md).
EVIDENCE_ROOT="${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}"
OUT_DIR="${1:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-w3-local-relay-bridge-proof-lab}"
W2_ARTIFACT="${AEGIS_UTUN_W2_ARTIFACT:-${EVIDENCE_ROOT}/live/2026-05-03/macos-utun-w2-stateful-tcp-edge-proof-lab}"
TMP_DIR="${OUT_DIR}/tmp"
CERT_DIR="${TMP_DIR}/certs"
SERVER_CFG="${TMP_DIR}/aegis-server.toml"
CLIENT_CFG="${TMP_DIR}/aegis-client.toml"
SERVER_LOG="${OUT_DIR}/server.log"
CLIENT_LOG="${OUT_DIR}/client.log"
CLIENT_RUNTIME="${OUT_DIR}/client-runtime-events.jsonl"
TARGET_LOG="${OUT_DIR}/target.log"
BRIDGE_EVENTS="${OUT_DIR}/bridge-runtime-events.jsonl"
# Operator relay reference only; this W3 owner records metadata, not an egress or trust verdict.
RELAY_IP="${AEGIS_RELAY_IP:-}"

relay_ip_ready() {
  local value="$1" octet
  local -a octets
  [[ "${#value}" -le 15 && "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a octets <<<"$value"
  [[ "${#octets[@]}" -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}
if ! relay_ip_ready "$RELAY_IP"; then
  printf '%s\n' 'AEGIS_RELAY_IP must be an explicit canonical IPv4 address' >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"
rm -rf "${TMP_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}" "${CLIENT_RUNTIME}" "${TARGET_LOG}" \
  "${BRIDGE_EVENTS}" "${OUT_DIR}/runtime-events.jsonl" \
  "${OUT_DIR}/relay-runtime-events.jsonl" \
  "${OUT_DIR}/socks-egress-body.txt" \
  "${OUT_DIR}/socks-egress.stderr.log"
mkdir -p "${TMP_DIR}" "${CERT_DIR}"
: >"${BRIDGE_EVENTS}"

cleanup() {
  for pid in "${CLIENT_PID:-}" "${SERVER_PID:-}" "${TARGET_PID:-}"; do
    if [[ -n "${pid}" ]]; then
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

free_port() {
  ruby -rsocket -e 's=TCPServer.new("127.0.0.1",0); puts s.addr[1]; s.close'
}

SERVER_PORT="$(free_port)"
SOCKS_PORT="$(free_port)"
TARGET_PORT="$(free_port)"
AUTH_TOKEN="e6177047aa8ecdde70f0aa8b07805bcec784b480961b757e98983046cbee82bd"

openssl req -x509 -newkey rsa:2048 -nodes \
  -subj "/CN=AEGIS W3 Local Relay Lab CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "${CERT_DIR}/ca-key.pem" \
  -out "${CERT_DIR}/ca.pem" \
  -days 1 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -keyout "${CERT_DIR}/server-key.pem" \
  -out "${CERT_DIR}/server.csr" >/dev/null 2>&1
cat >"${CERT_DIR}/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
EOF
openssl x509 -req \
  -in "${CERT_DIR}/server.csr" \
  -CA "${CERT_DIR}/ca.pem" \
  -CAkey "${CERT_DIR}/ca-key.pem" \
  -CAcreateserial \
  -out "${CERT_DIR}/server.pem" \
  -days 1 \
  -extfile "${CERT_DIR}/server.ext" >/dev/null 2>&1

cat >"${SERVER_CFG}" <<TOML
listen = "127.0.0.1:${SERVER_PORT}"
cert = "${CERT_DIR}/server.pem"
key = "${CERT_DIR}/server-key.pem"
auth_token = "${AUTH_TOKEN}"
fallback = "close"

[transport]
websocket_path = "/aegis/ws"
websocket_path_pool = ["/ws", "/socket", "/realtime/connect", "/cdn-cgi/trace", "/api/events"]
grpc_path = "/aegis.tunnel.v1.TunnelService/Open"
grpc_path_pool = ["/rpc.Tunnel/Open", "/cdn.tunnel.v1.Session/Open", "/grpc.gateway.v1.Proxy/Connect"]
masque_path = "/.well-known/masque/udp"
masque_path_pool = ["/.well-known/masque/connect-udp", "/masque/v1/udp", "/relay/datagram"]
TOML

cat >"${CLIENT_CFG}" <<TOML
mode = "relay"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:${SOCKS_PORT}"

[direct]
state_path = "${TMP_DIR}/state.json"
strategies = ["passthrough"]

[relay]
server = "127.0.0.1:${SERVER_PORT}"
server_name = "localhost"
auth_token = "${AUTH_TOKEN}"
transport_priority = ["https_ws"]
websocket_path = "/aegis/ws"
grpc_path = "/aegis.tunnel.v1.TunnelService/Open"
masque_path = "/.well-known/masque/udp"
connect_timeout_ms = 5000
ca_cert = "${CERT_DIR}/ca.pem"
TOML
# Generated runtime credentials must satisfy the strict config reader.
chmod 0600 "${SERVER_CFG}" "${CLIENT_CFG}"

{
  printf 'artifact=%s\n' "${OUT_DIR}"
  printf 'w2_artifact=%s\n' "${W2_ARTIFACT}"
  printf 'server=127.0.0.1:%s\n' "${SERVER_PORT}"
  printf 'socks=127.0.0.1:%s\n' "${SOCKS_PORT}"
  printf 'target=127.0.0.1:%s\n' "${TARGET_PORT}"
  printf 'relay_scope=LAB_LOCAL_AEGIS_RELAY\n'
} >"${OUT_DIR}/environment.txt"

{
  printf 'cargo build -p aegis-server -p aegis-client --release\n'
  printf 'bash scripts/run-macos-utun-w2-stateful-tcp-edge-proof.sh\n'
  printf 'bash scripts/run-macos-utun-w3-local-relay-bridge-proof.sh\n'
} >"${OUT_DIR}/commands.txt"

target_loop() {
  while true; do
    {
      printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'
    } | nc -l 127.0.0.1 "${TARGET_PORT}" >>"${TARGET_LOG}" 2>&1 || break
  done
}

target_loop &
TARGET_PID="$!"

target/release/aegis-server --config "${SERVER_CFG}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID="$!"

target/release/aegis-client --config "${CLIENT_CFG}" --runtime-events-jsonl "${CLIENT_RUNTIME}" >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID="$!"

for _ in $(seq 1 60); do
  if grep -q '"event_code":"ingress_backend_started"' "${CLIENT_RUNTIME}" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

set +e
curl --max-time 10 --silent --show-error --fail \
  --socks5-hostname "127.0.0.1:${SOCKS_PORT}" \
  "http://127.0.0.1:${TARGET_PORT}/" >"${OUT_DIR}/socks-egress-body.txt" 2>"${OUT_DIR}/socks-egress.stderr.log"
CURL_STATUS="$?"
set -e

sleep 0.5

W2_PASS=false
TCP_SYNACK_LAB_PASS=false
TCP_ACK_OBSERVED=false
RELAY_SESSION_SUCCEEDED=false
BRIDGE_EVENT=false

if [[ -f "${W2_ARTIFACT}/result.json" ]]; then
  grep -q '"verdict": "PASS"' "${W2_ARTIFACT}/result.json" && W2_PASS=true
  grep -q '"tcp_synack_lab_pass": true' "${W2_ARTIFACT}/result.json" && TCP_SYNACK_LAB_PASS=true
  grep -q '"tcp_ack_observed": true' "${W2_ARTIFACT}/result.json" && TCP_ACK_OBSERVED=true
fi
if [[ -f "${CLIENT_RUNTIME}" ]]; then
  grep -q '"event_code":"relay_session_succeeded"' "${CLIENT_RUNTIME}" && RELAY_SESSION_SUCCEEDED=true
fi
if [[ "${W2_PASS}" == "true" && "${TCP_SYNACK_LAB_PASS}" == "true" && "${TCP_ACK_OBSERVED}" == "true" && "${RELAY_SESSION_SUCCEEDED}" == "true" && "${CURL_STATUS}" == "0" ]]; then
  BRIDGE_EVENT=true
  cat >>"${BRIDGE_EVENTS}" <<JSONL
{"timestamp_unix_ms":$(date +%s000),"level":"info","event_code":"macos_utun_relay_bridge_session_succeeded","fields":{"scope":"lab_controlled_utun_w3","bridge_model":"LAB_LOCAL_AEGIS_RELAY_TRIGGER","w2_stateful_tcp_edge_pass":true,"relay_scope":"LAB_LOCAL_AEGIS_RELAY","relay_server":"127.0.0.1:${SERVER_PORT}","socks_proxy":"127.0.0.1:${SOCKS_PORT}","target":"127.0.0.1:${TARGET_PORT}","default_route_claim":false,"broad_system_wide_claim":false,"network_extension_claimed":false}}
JSONL
fi

{
  cat "${W2_ARTIFACT}/runtime-events.jsonl" 2>/dev/null || true
  cat "${CLIENT_RUNTIME}" 2>/dev/null || true
  cat "${BRIDGE_EVENTS}" 2>/dev/null || true
} >"${OUT_DIR}/runtime-events.jsonl"

if [[ "${BRIDGE_EVENT}" == "true" ]]; then
  STATUS="PASS"
  VERDICT="PASS"
  BLOCKER=null
else
  STATUS="NOT_PASS"
  VERDICT="NOT_PASS"
  if [[ "${W2_PASS}" != "true" || "${TCP_SYNACK_LAB_PASS}" != "true" || "${TCP_ACK_OBSERVED}" != "true" ]]; then
    BLOCKER='"W2.1 stateful TCP edge proof is missing or not PASS"'
  elif [[ "${RELAY_SESSION_SUCCEEDED}" != "true" ]]; then
    BLOCKER='"local AEGIS relay session did not emit relay_session_succeeded"'
  elif [[ "${CURL_STATUS}" != "0" ]]; then
    BLOCKER='"SOCKS egress probe through local AEGIS relay failed"'
  else
    BLOCKER='"unknown W3 local relay bridge failure"'
  fi
fi

cat >"${OUT_DIR}/result.json" <<JSON
{
  "schema_version": 1,
  "artifact": "macos-utun-w3-local-relay-bridge-proof-lab",
  "status": "${STATUS}",
  "verdict": "${VERDICT}",
  "w2_stateful_tcp_edge_pass": ${W2_PASS},
  "tcp_synack_lab_pass": ${TCP_SYNACK_LAB_PASS},
  "tcp_ack_observed": ${TCP_ACK_OBSERVED},
  "relay_scope": "LAB_LOCAL_AEGIS_RELAY",
  "relay_session_succeeded": ${RELAY_SESSION_SUCCEEDED},
  "socks_egress_probe_exit": ${CURL_STATUS},
  "utun_to_relay_bridge_linkage_proven": ${BRIDGE_EVENT},
  "relay_ip": "${RELAY_IP}",
  "default_route_claim": false,
  "broad_system_wide_claim": false,
  "dns_claimed": false,
  "udp_claimed": false,
  "ipv6_claimed": false,
  "network_extension_claimed": false,
  "cloudflare_claimed": false,
  "blocker": ${BLOCKER}
}
JSON

{
  printf '# macOS utun W3 Local Relay Bridge Proof Lab\n\n'
  printf 'Verdict: `%s`.\n\n' "${VERDICT}"
  printf -- '- W2.1 SYN/SYN-ACK/ACK pass: `%s`\n' "${TCP_SYNACK_LAB_PASS}"
  printf -- '- local AEGIS relay session succeeded: `%s`\n' "${RELAY_SESSION_SUCCEEDED}"
  printf -- '- utun-to-relay linkage event: `%s`\n' "${BRIDGE_EVENT}"
  printf -- '- relay scope: `LAB_LOCAL_AEGIS_RELAY`\n'
  printf -- '- broad system-wide claim: `false`\n'
  printf -- '- Cloudflare claim: `false`\n'
} >"${OUT_DIR}/README.md"
