#!/usr/bin/env bash
# Best-effort smoke for Linux wide ingress via REDIRECT.
# By default it validates the existing local OUTPUT TCP/HTTP path in direct
# mode. The optional DNS relay mode instead exercises the narrow Linux DNS
# preview path through an interface-scoped PREROUTING lab topology so the
# intercepted UDP packet reaches the same ingress/original-dst path as a real
# inbound redirect flow.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"
. "${ROOT}/scripts/lib/smoke-preflight-exit-codes.sh"
. "${ROOT}/scripts/lib/smoke-root-state-client.sh"

TARGET_URL="${AEGIS_WIDE_SMOKE_URL:-http://example.com/}"
WIDE_PORT="${AEGIS_WIDE_PORT:-15080}"
SOCKS_PORT="${AEGIS_SOCKS_PORT:-1080}"
CLIENT_UID="${AEGIS_EXEMPT_UID:-$(id -u)}"
SMOKE_USER="${AEGIS_WIDE_SMOKE_USER:-nobody}"
STARTUP_WAIT_SECS="${AEGIS_WIDE_STARTUP_WAIT_SECS:-2}"
SMOKE_PROTOCOL="${AEGIS_WIDE_SMOKE_PROTOCOL:-http}"
SELF_TEST_SCENARIO="${AEGIS_SMOKE_SELF_TEST_SCENARIO:-}"
PREFLIGHT_SELF_TEST_SCENARIO="${AEGIS_SMOKE_PREFLIGHT_SELF_TEST_SCENARIO:-}"
ENABLE_PREROUTING="${AEGIS_ENABLE_PREROUTING:-0}"
PREROUTING_INTERFACE="${AEGIS_WIDE_INTERFACE:-}"
ENABLE_DNS_PREVIEW="${AEGIS_ENABLE_DNS_PREVIEW:-0}"
DNS_PORT="${AEGIS_DNS_PORT:-53}"
UDP_PREVIEW_PORTS="${AEGIS_UDP_PREVIEW_PORTS:-}"
DNS_TARGET_IP="${AEGIS_WIDE_DNS_TARGET_IP:-198.18.0.53}"
RELAY_PORT="${AEGIS_RELAY_PORT:-}"
NS_SUFFIX="${AEGIS_WIDE_SMOKE_SUFFIX:-$$}"
SMOKE_NS="${AEGIS_WIDE_SMOKE_NAMESPACE:-aegis-redir-dns-${NS_SUFFIX}}"
VETH_HOST="${AEGIS_WIDE_SMOKE_HOST_IFACE:-aegisrh${NS_SUFFIX}}"
VETH_NS="${AEGIS_WIDE_SMOKE_NS_IFACE:-aegisrn${NS_SUFFIX}}"
HOST_IP="${AEGIS_WIDE_SMOKE_HOST_IP:-198.19.0.1}"
NS_IP="${AEGIS_WIDE_SMOKE_NS_IP:-198.19.0.2}"
CIDR_PREFIX="${AEGIS_WIDE_SMOKE_CIDR_PREFIX:-30}"
CFG_PATH="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-smoke.XXXXXX.toml")"
CLIENT_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-client.XXXXXX.log")"
PREFLIGHT_JSON="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-preflight.XXXXXX.json")"
PREFLIGHT_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-preflight.XXXXXX.log")"
SERVER_CFG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-relay.XXXXXX.toml")"
SERVER_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-relay.XXXXXX.log")"
UDP_ECHO_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-dns-echo.XXXXXX.log")"
SMOKE_CERT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wide-certs.XXXXXX")"
CLIENT_PID=""
SERVER_PID=""
UDP_ECHO_PID=""

if [[ "${SMOKE_PROTOCOL}" == "dns" ]]; then
  # The current Linux preview path only promotes intercepted datagrams whose
  # original destination port is exactly :53.
  ENABLE_DNS_PREVIEW=1
  DNS_PORT=53
  UDP_PREVIEW_PORTS=""
  # DNS relay smoke needs ingress-facing REDIRECT semantics, so force the lab
  # through an interface-scoped PREROUTING path instead of local OUTPUT.
  ENABLE_PREROUTING=1
  PREROUTING_INTERFACE="${PREROUTING_INTERFACE:-${VETH_HOST}}"
fi

UDP_PREVIEW_PORTS_LINE=""
if [[ -n "${UDP_PREVIEW_PORTS}" ]]; then
  UDP_PREVIEW_PORTS_LINE="udp_preview_ports = [${UDP_PREVIEW_PORTS}]"
fi

cleanup() {
  if [[ -n "${UDP_ECHO_PID}" ]] && kill -0 "${UDP_ECHO_PID}" 2>/dev/null; then
    sudo kill "${UDP_ECHO_PID}" 2>/dev/null || true
    wait "${UDP_ECHO_PID}" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  if [[ -n "${CLIENT_PID}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi
  if [[ "${SMOKE_PROTOCOL}" == "dns" ]]; then
    sudo ip addr del "${DNS_TARGET_IP}/32" dev lo >/dev/null 2>&1 || true
    sudo ip link del "${VETH_HOST}" >/dev/null 2>&1 || true
    sudo ip netns del "${SMOKE_NS}" >/dev/null 2>&1 || true
  fi
  if [[ "${AEGIS_SMOKE_HELPER_STARTED}" == 1 ]]; then
    if ! sudo AEGIS_ROOT_STATE_CLIENT="${AEGIS_ROOT_STATE_CLIENT:-}" \
      AEGIS_CLIENT_BIN="${AEGIS_CLIENT_BIN:-}" \
      AEGIS_WIDE_PORT="${WIDE_PORT}" \
      AEGIS_EXEMPT_UID="${CLIENT_UID}" \
      AEGIS_ENABLE_PREROUTING="${ENABLE_PREROUTING}" \
      AEGIS_WIDE_INTERFACE="${PREROUTING_INTERFACE}" \
      AEGIS_ENABLE_DNS_PREVIEW="${ENABLE_DNS_PREVIEW}" \
      AEGIS_DNS_PORT="${DNS_PORT}" \
      AEGIS_UDP_PREVIEW_PORTS="${UDP_PREVIEW_PORTS}" \
      bash "${ROOT}/scripts/setup-wide-linux-redirect.sh" teardown >/dev/null 2>&1; then
      echo "smoke helper teardown failed; trusted metadata client retained at ${AEGIS_ROOT_STATE_CLIENT}" >&2
    else
      AEGIS_SMOKE_HELPER_STARTED=0
    fi
  fi
  if [[ "${AEGIS_SMOKE_HELPER_STARTED}" == 0 ]]; then
    aegis_smoke_cleanup_root_state_client || echo "smoke metadata cleanup refused; owned path retained" >&2
  fi
  rm -f "${CFG_PATH}" "${CLIENT_LOG}" "${PREFLIGHT_JSON}" "${PREFLIGHT_LOG}" \
    "${SERVER_CFG}" "${SERVER_LOG}" "${UDP_ECHO_LOG}"
  rm -rf "${SMOKE_CERT_DIR}"
}
trap cleanup EXIT

fail_client_exited_early() {
  echo "aegis-client exited early" >&2
  sed -n '1,160p' "${CLIENT_LOG}" >&2 || true
  exit "${EXIT_RUNTIME_CLIENT_EXITED_EARLY}"
}

fail_smoke_request() {
  echo "Smoke request failed; client log follows" >&2
  if [[ "${SMOKE_PROTOCOL}" == "dns" && -z "${SELF_TEST_SCENARIO}" ]]; then
    echo "=== redirect helper status ===" >&2
    sudo -n AEGIS_ROOT_STATE_CLIENT="${AEGIS_ROOT_STATE_CLIENT:-}" \
      AEGIS_CLIENT_BIN="${AEGIS_CLIENT_BIN:-}" \
      AEGIS_WIDE_PORT="${WIDE_PORT}" \
      AEGIS_EXEMPT_UID="${CLIENT_UID}" \
      AEGIS_ENABLE_PREROUTING="${ENABLE_PREROUTING}" \
      AEGIS_WIDE_INTERFACE="${PREROUTING_INTERFACE}" \
      AEGIS_ENABLE_DNS_PREVIEW="${ENABLE_DNS_PREVIEW}" \
      AEGIS_DNS_PORT="${DNS_PORT}" \
      AEGIS_UDP_PREVIEW_PORTS="${UDP_PREVIEW_PORTS}" \
      bash "${ROOT}/scripts/setup-wide-linux-redirect.sh" status >&2 || true
  fi
  sed -n '1,200p' "${CLIENT_LOG}" >&2 || true
  if [[ -f "${SERVER_LOG}" ]]; then
    sed -n '1,200p' "${SERVER_LOG}" >&2 || true
  fi
  if [[ -f "${UDP_ECHO_LOG}" ]]; then
    sed -n '1,120p' "${UDP_ECHO_LOG}" >&2 || true
  fi
  exit "${EXIT_RUNTIME_SMOKE_REQUEST_FAILED}"
}

reserve_tcp_port() {
  cargo run -q -p aegis-measure -- reserve-tcp-port
}

wait_for_tcp_port() {
  local host="$1"
  local port="$2"
  local timeout_secs="$3"
  cargo run -q -p aegis-measure -- wait-tcp-port \
    --host "${host}" \
    --port "${port}" \
    --timeout-secs "${timeout_secs}"
}

generate_smoke_certs() {
  local ext_file="${SMOKE_CERT_DIR}/server-ext.cnf"
  cat > "${ext_file}" <<'EOF'
subjectAltName=DNS:localhost
extendedKeyUsage=serverAuth
EOF

  openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
    -keyout "${SMOKE_CERT_DIR}/ca-key.pem" \
    -out "${SMOKE_CERT_DIR}/ca.pem" \
    -subj "/CN=AEGIS Smoke CA" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes \
    -keyout "${SMOKE_CERT_DIR}/server-key.pem" \
    -out "${SMOKE_CERT_DIR}/server.csr" \
    -subj "/CN=localhost" >/dev/null 2>&1

  openssl x509 -req -in "${SMOKE_CERT_DIR}/server.csr" \
    -CA "${SMOKE_CERT_DIR}/ca.pem" \
    -CAkey "${SMOKE_CERT_DIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${SMOKE_CERT_DIR}/server.pem" \
    -days 825 \
    -extfile "${ext_file}" >/dev/null 2>&1
}

wait_for_wide_backend() {
  local deadline=$((SECONDS + STARTUP_WAIT_SECS))
  while (( SECONDS <= deadline )); do
    # Match the stable startup event/message rather than exact field spacing;
    # colored tracing output can vary the rendered `backend = "..."` shape.
    if command -v rg >/dev/null 2>&1; then
      if rg -q 'ingress_backend_started|client ingress backend started' "${CLIENT_LOG}"; then
        return 0
      fi
    elif grep -Eq 'ingress_backend_started|client ingress backend started' "${CLIENT_LOG}"; then
      return 0
    fi
    if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
      break
    fi
    sleep 1
  done

  echo "wide_primary backend did not start successfully" >&2
  sed -n '1,200p' "${CLIENT_LOG}" >&2 || true
  return "${EXIT_RUNTIME_WIDE_BACKEND_NOT_READY}"
}

run_self_test_scenario() {
  if [[ -z "${SELF_TEST_SCENARIO}" ]]; then
    return 0
  fi

  # Self-test mode lets CI validate stable runtime exit semantics without
  # needing a real listener startup or root-level packet redirection.
  STARTUP_WAIT_SECS=0
  : > "${CLIENT_LOG}"

  case "${SELF_TEST_SCENARIO}" in
    client_exited_early)
      echo "self-test: simulated early client exit" > "${CLIENT_LOG}"
      fail_client_exited_early
      ;;
    wide_backend_not_ready)
      echo "self-test: simulated backend not ready" > "${CLIENT_LOG}"
      CLIENT_PID=999999
      wait_for_wide_backend
      exit "$?"
      ;;
    smoke_request_failed)
      echo "self-test: simulated smoke request failure" > "${CLIENT_LOG}"
      fail_smoke_request
      ;;
    *)
      echo "Unknown AEGIS_SMOKE_SELF_TEST_SCENARIO=${SELF_TEST_SCENARIO}" >&2
      exit 64
      ;;
  esac
}

run_self_test_scenario

map_preflight_exit() {
  local status="$1"
  cargo run -q -p aegis-measure -- wide-redirect-preflight-exit \
    --preflight-json "${PREFLIGHT_JSON}" \
    --preflight-log "${PREFLIGHT_LOG}" \
    --status "${status}" \
    --exit-listener-conflict "${EXIT_PREFLIGHT_LISTENER_CONFLICT}" \
    --exit-listener-busy "${EXIT_PREFLIGHT_LISTENER_BUSY}" \
    --exit-unsupported-adapter "${EXIT_PREFLIGHT_UNSUPPORTED_ADAPTER}" \
    --exit-socks-bind-failed "${EXIT_PREFLIGHT_SOCKS_BIND_FAILED}" \
    --exit-rollout-prerequisites "${EXIT_PREFLIGHT_ROLLOUT_PREREQUISITES}" \
    --expected-interface "${PREROUTING_INTERFACE}"
}

run_preflight_self_test_scenario() {
  if [[ -z "${PREFLIGHT_SELF_TEST_SCENARIO}" ]]; then
    return 0
  fi

  case "${PREFLIGHT_SELF_TEST_SCENARIO}" in
    config_error)
      cat > "${PREFLIGHT_JSON}" <<'EOF'
{"status":"error","selection":{"selected_backend":"wide_primary","wide_platform_family_supported":true,"wide_runtime_readiness":"config_error","wide_prerouting_interface":null,"selection_error_code":"rollout_profile_prerequisites","backend_notes":[]}}
EOF
      map_preflight_exit 1
      exit "$?"
      ;;
    unsupported_adapter)
      cat > "${PREFLIGHT_JSON}" <<'EOF'
{"status":"error","selection":{"selected_backend":"socks5_fallback","wide_platform_family_supported":false,"wide_runtime_readiness":"unsupported_adapter","wide_prerouting_interface":null,"selection_error_code":"unsupported_wide_backend","backend_notes":[{"code":"platform_adapter_stub"}]}}
EOF
      map_preflight_exit 1
      exit "$?"
      ;;
    *)
      echo "Unknown AEGIS_SMOKE_PREFLIGHT_SELF_TEST_SCENARIO=${PREFLIGHT_SELF_TEST_SCENARIO}" >&2
      exit 64
      ;;
  esac
}

run_preflight_self_test_scenario

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This smoke helper is Linux-only" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required" >&2
  exit 1
fi
CARGO_BIN="$(command -v cargo)"

if [[ "${SMOKE_PROTOCOL}" == "http" ]] && ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required" >&2
  exit 1
fi

if [[ "${SMOKE_PROTOCOL}" == "dns" ]] && ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required for DNS smoke certificates" >&2
  exit 1
fi

if [[ "${SMOKE_PROTOCOL}" != "http" && "${SMOKE_PROTOCOL}" != "dns" ]]; then
  echo "Unsupported AEGIS_WIDE_SMOKE_PROTOCOL=${SMOKE_PROTOCOL}; expected http or dns" >&2
  exit 64
fi

SMOKE_CARGO_TARGET_DIRECTORY="$(aegis_smoke_cargo_target_directory)"

run_preflight() {
  local status

  echo "Running ingress preflight..."
  set +e
  (
    cd "${ROOT}"
    cargo run -p aegis-client -- --config "${CFG_PATH}" --ingress-preflight --json > "${PREFLIGHT_JSON}" 2> "${PREFLIGHT_LOG}"
  )
  status=$?
  set -e

  map_preflight_exit "${status}"
}

REDIRECT_ROLLOUT_PROFILE="output_only_safe"
PREROUTING_INTERFACE_LINE=""
if [[ "${ENABLE_PREROUTING}" == "1" ]]; then
  # PREROUTING redirect smoke should stay interface-scoped rather than widening to all ingress.
  REDIRECT_ROLLOUT_PROFILE="prerouting_scoped"
  if [[ -n "${PREROUTING_INTERFACE}" ]]; then
    PREROUTING_INTERFACE_LINE="prerouting_interface = \"${PREROUTING_INTERFACE}\""
  fi
fi

if [[ -z "${RELAY_PORT}" ]]; then
  RELAY_PORT="$(reserve_tcp_port)"
fi

CLIENT_MODE="direct"
RELAY_AUTH_TOKEN=""
RELAY_CA_CERT_LINE=""
RELAY_PRIORITY_LINE=""
if [[ "${SMOKE_PROTOCOL}" == "dns" ]]; then
  generate_smoke_certs
  CLIENT_MODE="relay"
  RELAY_AUTH_TOKEN="35e6bc7bad59524e75314ee8bbee9c6d16da3bd5e5262ec99bcda65cec8274f0"
  RELAY_CA_CERT_LINE="ca_cert = \"${SMOKE_CERT_DIR}/ca.pem\""
  # DNS preview runtime currently relies on the UDP-capable CONNECT-UDP path.
  RELAY_PRIORITY_LINE='transport_priority = ["masque_derived"]'
fi

cat > "${CFG_PATH}" <<EOF
mode = "${CLIENT_MODE}"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
# Use the explicit REDIRECT baseline so NAT smoke and transparent TPROXY mode
# stay separate in the config contract.
platform_backend = "linux_redirect"
rollout_profile = "${REDIRECT_ROLLOUT_PROFILE}"
${PREROUTING_INTERFACE_LINE}
listen = "0.0.0.0:${WIDE_PORT}"
capture_dns = true
dns_port = ${DNS_PORT}
${UDP_PREVIEW_PORTS_LINE}
default_mark = 0

[socks]
listen = "127.0.0.1:${SOCKS_PORT}"

[direct]
state_path = "${SMOKE_CERT_DIR}/state.json"
strategies = ["passthrough"]
epsilon = 0.1
first_chunk_timeout_ms = 8000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:${RELAY_PORT}"
server_name = "localhost"
auth_token = "${RELAY_AUTH_TOKEN}"
${RELAY_CA_CERT_LINE}
${RELAY_PRIORITY_LINE}
EOF

if [[ "${SMOKE_PROTOCOL}" == "dns" ]]; then
  cat > "${SERVER_CFG}" <<EOF
listen = "127.0.0.1:${RELAY_PORT}"
cert = "${SMOKE_CERT_DIR}/server.pem"
key = "${SMOKE_CERT_DIR}/server-key.pem"
auth_token = "35e6bc7bad59524e75314ee8bbee9c6d16da3bd5e5262ec99bcda65cec8274f0"
fallback = "close"

[target_policy]
# This disposable relay only targets the lab address installed on loopback.
# Production relays retain the safer public_internet default.
profile = "full_vpn_egress"
allowed_ports = [${DNS_PORT}]
EOF
fi

echo "Building aegis-client..."
(
  cd "${ROOT}"
  if [[ "${SMOKE_PROTOCOL}" == "dns" ]]; then
    cargo build -p aegis-client -p aegis-server
  else
    cargo build -p aegis-client
  fi
)

run_preflight

if [[ "${SMOKE_PROTOCOL}" == "dns" ]]; then
  echo "Preparing temporary namespace ${SMOKE_NS} for redirect DNS target..."
  sudo ip netns add "${SMOKE_NS}"
  sudo ip link add "${VETH_HOST}" type veth peer name "${VETH_NS}"
  sudo ip link set "${VETH_NS}" netns "${SMOKE_NS}"
  sudo ip addr add "${HOST_IP}/${CIDR_PREFIX}" dev "${VETH_HOST}"
  sudo ip link set "${VETH_HOST}" up
  sudo ip netns exec "${SMOKE_NS}" ip addr add "${NS_IP}/${CIDR_PREFIX}" dev "${VETH_NS}"
  sudo ip netns exec "${SMOKE_NS}" ip link set lo up
  sudo ip netns exec "${SMOKE_NS}" ip link set "${VETH_NS}" up
  sudo ip netns exec "${SMOKE_NS}" ip route add default via "${HOST_IP}"
  echo "Starting local relay server for DNS smoke..."
  (
    cd "${ROOT}"
    cargo run -p aegis-server -- --config "${SERVER_CFG}" >"${SERVER_LOG}" 2>&1
  ) &
  SERVER_PID="$!"
  if ! wait_for_tcp_port "127.0.0.1" "${RELAY_PORT}" 20; then
    echo "relay server did not become ready on 127.0.0.1:${RELAY_PORT}" >&2
    sed -n '1,200p' "${SERVER_LOG}" >&2 || true
    exit "${EXIT_RUNTIME_SMOKE_REQUEST_FAILED}"
  fi

  echo "Starting local UDP echo target on ${DNS_TARGET_IP}:${DNS_PORT}..."
  sudo ip addr add "${DNS_TARGET_IP}/32" dev lo
  sudo "${CARGO_BIN}" run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- udp-echo-server \
    --host "${DNS_TARGET_IP}" \
    --port "${DNS_PORT}" >"${UDP_ECHO_LOG}" 2>&1 &
  UDP_ECHO_PID="$!"
  sleep 1
fi

echo "Starting wide-mode client..."
(
  cd "${ROOT}"
  cargo run -p aegis-client -- --config "${CFG_PATH}" --diagnostic-logs >"${CLIENT_LOG}" 2>&1
) &
CLIENT_PID="$!"

sleep "${STARTUP_WAIT_SECS}"

if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
  fail_client_exited_early
fi

wait_for_wide_backend

aegis_smoke_stage_root_state_client "${AEGIS_CLIENT_BIN:-${SMOKE_CARGO_TARGET_DIRECTORY}/debug/aegis-client}"
echo "Applying REDIRECT helper..."
AEGIS_SMOKE_HELPER_STARTED=1
sudo AEGIS_ROOT_STATE_CLIENT="${AEGIS_ROOT_STATE_CLIENT:-}" \
  AEGIS_CLIENT_BIN="${AEGIS_CLIENT_BIN:-}" \
  AEGIS_WIDE_PORT="${WIDE_PORT}" \
  AEGIS_EXEMPT_UID="${CLIENT_UID}" \
  AEGIS_ENABLE_PREROUTING="${ENABLE_PREROUTING}" \
  AEGIS_WIDE_INTERFACE="${PREROUTING_INTERFACE}" \
  AEGIS_ENABLE_DNS_PREVIEW="${ENABLE_DNS_PREVIEW}" \
  AEGIS_DNS_PORT="${DNS_PORT}" \
  AEGIS_UDP_PREVIEW_PORTS="${UDP_PREVIEW_PORTS}" \
  bash "${ROOT}/scripts/setup-wide-linux-redirect.sh" apply

if [[ "${SMOKE_PROTOCOL}" == "dns" ]]; then
  echo "Running DNS preview smoke from namespace ${SMOKE_NS} -> ${DNS_TARGET_IP}:${DNS_PORT}"
  if sudo ip netns exec "${SMOKE_NS}" "${CARGO_BIN}" run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- udp-echo-client \
    --host "${DNS_TARGET_IP}" \
    --port "${DNS_PORT}" \
    --timeout-secs 15; then
    echo "Wide REDIRECT DNS preview smoke completed successfully"
  else
    fail_smoke_request
  fi
else
  echo "Running smoke request via user ${SMOKE_USER} -> ${TARGET_URL}"
  if sudo -u "${SMOKE_USER}" curl --silent --show-error --max-time 15 "${TARGET_URL}" >/dev/null; then
    echo "Wide REDIRECT smoke completed successfully"
  else
    fail_smoke_request
  fi
fi
