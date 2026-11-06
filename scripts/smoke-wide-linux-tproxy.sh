#!/usr/bin/env bash
# Best-effort smoke for Linux wide ingress via PREROUTING TPROXY.
# By default it validates the existing TCP/HTTP path in direct mode. An
# optional relay-backed UDP modes can also exercise the narrow Linux preview
# path end-to-end against a local relay server and UDP echo target. Negative
# preview-drop mode intentionally expects a dropped datagram so CI can assert
# the machine-readable drop vocabulary on real runtime events.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"
. "${ROOT}/scripts/lib/smoke-preflight-exit-codes.sh"
. "${ROOT}/scripts/lib/smoke-root-state-client.sh"

TARGET_HOST="${AEGIS_WIDE_SMOKE_HOST:-example.com}"
TARGET_IP="${AEGIS_WIDE_SMOKE_IP:-93.184.216.34}"
TARGET_PORT="${AEGIS_WIDE_SMOKE_PORT:-80}"
TARGET_URL="${AEGIS_WIDE_SMOKE_URL:-http://${TARGET_HOST}/}"
WIDE_PORT="${AEGIS_WIDE_PORT:-}"
SOCKS_PORT="${AEGIS_SOCKS_PORT:-}"
FWMARK="${AEGIS_WIDE_FWMARK:-1}"
ROUTE_TABLE="${AEGIS_WIDE_ROUTE_TABLE:-100}"
FIREWALL_BACKEND="${AEGIS_WIDE_FIREWALL_BACKEND:-auto}"
STARTUP_WAIT_SECS="${AEGIS_WIDE_STARTUP_WAIT_SECS:-2}"
REQUEST_TIMEOUT_SECS="${AEGIS_WIDE_REQUEST_TIMEOUT_SECS:-15}"
SMOKE_PROTOCOL="${AEGIS_WIDE_SMOKE_PROTOCOL:-http}"
SMOKE_IP_FAMILY="${AEGIS_WIDE_SMOKE_IP_FAMILY:-ipv4}"
SMOKE_HOST_SHAPE="${AEGIS_WIDE_SMOKE_HOST_SHAPE:-unspecified}"
SELF_TEST_SCENARIO="${AEGIS_SMOKE_SELF_TEST_SCENARIO:-}"
PREFLIGHT_SELF_TEST_SCENARIO="${AEGIS_SMOKE_PREFLIGHT_SELF_TEST_SCENARIO:-}"
CONTRACT_SELF_TEST_SCENARIO="${AEGIS_SMOKE_CONTRACT_SELF_TEST_SCENARIO:-}"
CONTRACT_SELF_TEST_VARIANT="${AEGIS_SMOKE_CONTRACT_SELF_TEST_VARIANT:-}"
CLIENT_BIN_OVERRIDE="${AEGIS_CLIENT_BIN:-}"
CLIENT_BIN_SELF_TEST_SCENARIO="${AEGIS_SMOKE_CLIENT_BIN_SELF_TEST_SCENARIO:-}"
ENABLE_DNS_PREVIEW="${AEGIS_ENABLE_DNS_PREVIEW:-0}"
DNS_PORT="${AEGIS_DNS_PORT:-53}"
UDP_PREVIEW_PORTS="${AEGIS_UDP_PREVIEW_PORTS:-}"
UDP_CAPTURE_CONTRACT="${AEGIS_UDP_CAPTURE_CONTRACT:-preview_allowlist_only}"
FORCE_ALL_UDP_TPROXY="${AEGIS_WIDE_FORCE_ALL_UDP_TPROXY:-0}"
DNS_TARGET_IP="${AEGIS_WIDE_DNS_TARGET_IP:-198.18.0.53}"
DNS_TARGET_IPV6="${AEGIS_WIDE_DNS_TARGET_IPV6:-2001:db8:53::53}"
UDP_PREVIEW_TARGET_IP="${AEGIS_WIDE_UDP_PREVIEW_TARGET_IP:-198.18.0.54}"
UDP_PREVIEW_PORT="${AEGIS_WIDE_UDP_PREVIEW_PORT:-5353}"
UDP_PREVIEW_DROP_TARGET_IP="${AEGIS_WIDE_UDP_PREVIEW_DROP_TARGET_IP:-198.18.0.56}"
UDP_PREVIEW_DROP_TARGET_PORT="${AEGIS_WIDE_UDP_PREVIEW_DROP_TARGET_PORT:-5300}"
GENERIC_UDP_TARGET_IP="${AEGIS_WIDE_GENERIC_UDP_TARGET_IP:-198.18.0.55}"
GENERIC_UDP_TARGET_IPV6="${AEGIS_WIDE_GENERIC_UDP_TARGET_IPV6:-2001:db8:55::55}"
GENERIC_UDP_TARGET_PORT="${AEGIS_WIDE_GENERIC_UDP_TARGET_PORT:-54321}"
RELAY_PORT="${AEGIS_RELAY_PORT:-}"
NS_SUFFIX="${AEGIS_WIDE_SMOKE_SUFFIX:-$$}"
PORT_SUFFIX="$(( $$ % 1000 ))"
port_is_listening() {
  local port="$1"
  if ! command -v ss >/dev/null 2>&1; then
    return 1
  fi
  ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|[:.])${port}$|\\]:${port}$"
}

choose_smoke_port() {
  local base="$1"
  local offset candidate
  for offset in $(seq 0 999); do
    candidate="$((base + ((PORT_SUFFIX + offset) % 1000)))"
    if ! port_is_listening "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  echo "failed to find an available smoke port near ${base}" >&2
  return 1
}

if [[ -z "${WIDE_PORT}" ]]; then
  WIDE_PORT="$(choose_smoke_port 15080)"
fi
if [[ -z "${SOCKS_PORT}" ]]; then
  SOCKS_PORT="$(choose_smoke_port 11080)"
fi
SMOKE_NS="${AEGIS_WIDE_SMOKE_NAMESPACE:-aegis-smoke-${NS_SUFFIX}}"
VETH_HOST="${AEGIS_WIDE_SMOKE_HOST_IFACE:-aegisvh${NS_SUFFIX}}"
VETH_NS="${AEGIS_WIDE_SMOKE_NS_IFACE:-aegisvn${NS_SUFFIX}}"
HOST_IP="${AEGIS_WIDE_SMOKE_HOST_IP:-198.18.0.1}"
NS_IP="${AEGIS_WIDE_SMOKE_NS_IP:-198.18.0.2}"
CIDR_PREFIX="${AEGIS_WIDE_SMOKE_CIDR_PREFIX:-30}"
HOST_IPV6="${AEGIS_WIDE_SMOKE_HOST_IPV6:-2001:db8:100::1}"
NS_IPV6="${AEGIS_WIDE_SMOKE_NS_IPV6:-2001:db8:100::2}"
CIDR_PREFIX_IPV6="${AEGIS_WIDE_SMOKE_CIDR_PREFIX_IPV6:-64}"
CFG_PATH="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-smoke.XXXXXX")"
TEMP_CFG_PATH="${CFG_PATH}"
ADMIN_CFG_PATH=""
CLIENT_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-client.XXXXXX")"
RUNTIME_EVENTS_JSONL="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-runtime.XXXXXX")"
RUNTIME_EVENTS_ARTIFACT="${AEGIS_WIDE_SMOKE_RUNTIME_EVENTS_ARTIFACT:-}"
CONTRACT_ARTIFACT="${AEGIS_WIDE_SMOKE_CONTRACT_ARTIFACT:-}"
DEBUG_ARTIFACT_DIR="${AEGIS_WIDE_SMOKE_DEBUG_ARTIFACT_DIR:-}"
PREFLIGHT_JSON="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-preflight.XXXXXX")"
PREFLIGHT_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-preflight.XXXXXX")"
PROBE_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-probe.XXXXXX")"
SERVER_CFG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-relay.XXXXXX")"
SERVER_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-relay.XXXXXX")"
UDP_ECHO_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-dns-echo.XXXXXX")"
UDP_REQUEST_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-udp-request.XXXXXX")"
HELPER_APPLY_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-helper-apply.XXXXXX")"
HELPER_STATUS_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-helper-status.XXXXXX")"
NETWORK_STATUS_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-network-status.XXXXXX")"
TCPDUMP_LOG="$(mktemp "${TMPDIR:-/tmp}/aegis-wide-tproxy-tcpdump.XXXXXX")"
TCPDUMP_PCAP_ARTIFACT="${AEGIS_WIDE_SMOKE_TCPDUMP_PCAP_ARTIFACT:-}"
TCPDUMP_INTERFACE="${AEGIS_WIDE_SMOKE_TCPDUMP_INTERFACE:-${VETH_HOST}}"
SMOKE_CERT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wide-tproxy-certs.XXXXXX")"
CLIENT_PID=""
SERVER_PID=""
UDP_ECHO_PID=""
TCPDUMP_PID=""

SMOKE_UDP_TARGET_IP=""
SMOKE_UDP_TARGET_PORT=""
SMOKE_UDP_LABEL=""
SMOKE_UDP_PAYLOAD=""
WIDE_LISTEN_VALUE="0.0.0.0:${WIDE_PORT}"

if [[ "${SMOKE_PROTOCOL}" == "dns" ]]; then
  # The current Linux preview path only promotes intercepted datagrams whose
  # original destination port is exactly :53.
  ENABLE_DNS_PREVIEW=1
  DNS_PORT=53
  UDP_PREVIEW_PORTS=""
  SMOKE_UDP_TARGET_IP="${DNS_TARGET_IP}"
  SMOKE_UDP_TARGET_PORT="${DNS_PORT}"
  SMOKE_UDP_LABEL="DNS preview"
  SMOKE_UDP_PAYLOAD="wide-dns-smoke"
elif [[ "${SMOKE_PROTOCOL}" == "dns_ipv6" ]]; then
  SMOKE_IP_FAMILY="ipv6"
  ENABLE_DNS_PREVIEW=1
  DNS_PORT=53
  UDP_PREVIEW_PORTS=""
  SMOKE_UDP_TARGET_IP="${DNS_TARGET_IPV6}"
  SMOKE_UDP_TARGET_PORT="${DNS_PORT}"
  SMOKE_UDP_LABEL="DNS preview IPv6"
  SMOKE_UDP_PAYLOAD="wide-dns-ipv6-smoke"
elif [[ "${SMOKE_PROTOCOL}" == "udp_preview" ]]; then
  ENABLE_DNS_PREVIEW=1
  UDP_PREVIEW_PORTS="${UDP_PREVIEW_PORT}"
  SMOKE_UDP_TARGET_IP="${UDP_PREVIEW_TARGET_IP}"
  SMOKE_UDP_TARGET_PORT="${UDP_PREVIEW_PORT}"
  SMOKE_UDP_LABEL="UDP preview"
  SMOKE_UDP_PAYLOAD="wide-udp-preview-smoke"
elif [[ "${SMOKE_PROTOCOL}" == "udp_preview_drop" ]]; then
  ENABLE_DNS_PREVIEW=1
  UDP_PREVIEW_PORTS="${UDP_PREVIEW_PORT}"
  # Force helper-side UDP interception so the runtime allowlist gate, not a
  # firewall bypass, decides whether the non-preview datagram is dropped.
  FORCE_ALL_UDP_TPROXY=1
  SMOKE_UDP_TARGET_IP="${UDP_PREVIEW_DROP_TARGET_IP}"
  SMOKE_UDP_TARGET_PORT="${UDP_PREVIEW_DROP_TARGET_PORT}"
  SMOKE_UDP_LABEL="UDP preview drop"
  SMOKE_UDP_PAYLOAD="wide-udp-preview-drop-smoke"
elif [[ "${SMOKE_PROTOCOL}" == "generic_udp" ]]; then
  ENABLE_DNS_PREVIEW=1
  UDP_CAPTURE_CONTRACT="generic_capture_unstable"
  UDP_PREVIEW_PORTS=""
  if [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
    SMOKE_UDP_TARGET_IP="${GENERIC_UDP_TARGET_IPV6}"
    SMOKE_UDP_LABEL="generic UDP IPv6"
    SMOKE_UDP_PAYLOAD="wide-generic-udp-ipv6-smoke"
  else
    SMOKE_UDP_TARGET_IP="${GENERIC_UDP_TARGET_IP}"
    SMOKE_UDP_LABEL="generic UDP"
    SMOKE_UDP_PAYLOAD="wide-generic-udp-smoke"
  fi
  SMOKE_UDP_TARGET_PORT="${GENERIC_UDP_TARGET_PORT}"
fi

if [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
  WIDE_LISTEN_VALUE="[::]:${WIDE_PORT}"
fi

UDP_PREVIEW_PORTS_LINE=""
if [[ -n "${UDP_PREVIEW_PORTS}" ]]; then
  UDP_PREVIEW_PORTS_LINE="udp_preview_ports = [${UDP_PREVIEW_PORTS}]"
fi

cleanup() {
  if [[ -n "${DEBUG_ARTIFACT_DIR}" ]]; then
    mkdir -p "${DEBUG_ARTIFACT_DIR}"
    cp "${CLIENT_LOG}" "${DEBUG_ARTIFACT_DIR}/client.log" 2>/dev/null || true
    cp "${SERVER_LOG}" "${DEBUG_ARTIFACT_DIR}/server.log" 2>/dev/null || true
    cp "${UDP_ECHO_LOG}" "${DEBUG_ARTIFACT_DIR}/udp-echo.log" 2>/dev/null || true
    cp "${UDP_REQUEST_LOG}" "${DEBUG_ARTIFACT_DIR}/udp-request.log" 2>/dev/null || true
    cp "${PREFLIGHT_JSON}" "${DEBUG_ARTIFACT_DIR}/preflight.json" 2>/dev/null || true
    cp "${PREFLIGHT_LOG}" "${DEBUG_ARTIFACT_DIR}/preflight.log" 2>/dev/null || true
    cp "${PROBE_LOG}" "${DEBUG_ARTIFACT_DIR}/probe.log" 2>/dev/null || true
    cp "${HELPER_APPLY_LOG}" "${DEBUG_ARTIFACT_DIR}/helper-apply.log" 2>/dev/null || true
    cp "${HELPER_STATUS_LOG}" "${DEBUG_ARTIFACT_DIR}/helper-status.log" 2>/dev/null || true
    cp "${NETWORK_STATUS_LOG}" "${DEBUG_ARTIFACT_DIR}/network-status.log" 2>/dev/null || true
    cp "${TCPDUMP_LOG}" "${DEBUG_ARTIFACT_DIR}/tcpdump.log" 2>/dev/null || true
    cp "${CFG_PATH}" "${DEBUG_ARTIFACT_DIR}/client-config.toml" 2>/dev/null || true
    cp "${SERVER_CFG}" "${DEBUG_ARTIFACT_DIR}/relay-config.toml" 2>/dev/null || true
  fi
  if [[ -n "${RUNTIME_EVENTS_ARTIFACT}" && -f "${RUNTIME_EVENTS_JSONL}" ]]; then
    mkdir -p "$(dirname "${RUNTIME_EVENTS_ARTIFACT}")"
    cp "${RUNTIME_EVENTS_JSONL}" "${RUNTIME_EVENTS_ARTIFACT}" 2>/dev/null || true
    chmod a+r "${RUNTIME_EVENTS_ARTIFACT}" 2>/dev/null || true
  fi
  if [[ -n "${UDP_ECHO_PID}" ]] && kill -0 "${UDP_ECHO_PID}" 2>/dev/null; then
    sudo kill "${UDP_ECHO_PID}" 2>/dev/null || true
    wait "${UDP_ECHO_PID}" 2>/dev/null || true
  fi
  if [[ -n "${TCPDUMP_PID}" ]] && kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
    sudo kill "${TCPDUMP_PID}" 2>/dev/null || true
    wait "${TCPDUMP_PID}" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      kill -0 "${SERVER_PID}" 2>/dev/null || break
      sleep 1
    done
    kill -0 "${SERVER_PID}" 2>/dev/null && kill -KILL "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  if [[ -n "${CLIENT_PID}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      kill -0 "${CLIENT_PID}" 2>/dev/null || break
      sleep 1
    done
    kill -0 "${CLIENT_PID}" 2>/dev/null && kill -KILL "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi
  if [[ "${AEGIS_SMOKE_HELPER_STARTED}" == 1 ]]; then
    if ! sudo AEGIS_ROOT_STATE_CLIENT="${AEGIS_ROOT_STATE_CLIENT:-}" \
      AEGIS_CLIENT_BIN="${AEGIS_CLIENT_BIN:-}" \
      AEGIS_MEASURE_BIN="${AEGIS_MEASURE_BIN:-}" \
      AEGIS_WIDE_PORT="${WIDE_PORT}" \
      AEGIS_WIDE_FWMARK="${FWMARK}" \
      AEGIS_WIDE_ROUTE_TABLE="${ROUTE_TABLE}" \
      AEGIS_WIDE_INTERFACE="${VETH_HOST}" \
      AEGIS_WIDE_IP_FAMILY="${SMOKE_IP_FAMILY}" \
      AEGIS_WIDE_FIREWALL_BACKEND="${FIREWALL_BACKEND}" \
      AEGIS_ENABLE_DNS_PREVIEW="${ENABLE_DNS_PREVIEW}" \
      AEGIS_DNS_PORT="${DNS_PORT}" \
      AEGIS_UDP_CAPTURE_CONTRACT="${UDP_CAPTURE_CONTRACT}" \
      AEGIS_WIDE_FORCE_ALL_UDP_TPROXY="${FORCE_ALL_UDP_TPROXY}" \
      AEGIS_UDP_PREVIEW_PORTS="${UDP_PREVIEW_PORTS}" \
      bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" teardown >/dev/null 2>&1; then
      echo "smoke helper teardown failed; trusted metadata client retained at ${AEGIS_ROOT_STATE_CLIENT}" >&2
    else
      AEGIS_SMOKE_HELPER_STARTED=0
    fi
  fi
  if [[ "${AEGIS_SMOKE_HELPER_STARTED}" == 0 ]]; then
    if [[ -z "${ADMIN_CFG_PATH}" ]] || sudo -n "${AEGIS_ROOT_STATE_CLIENT}" profile metadata remove --path "${ADMIN_CFG_PATH}"; then
      ADMIN_CFG_PATH=""
      aegis_smoke_cleanup_root_state_client || echo "smoke metadata cleanup refused; owned path retained" >&2
    else
      echo "smoke config cleanup refused; trusted metadata client and config retained" >&2
    fi
  fi
  if [[ "${SMOKE_PROTOCOL}" == "dns" || "${SMOKE_PROTOCOL}" == "dns_ipv6" || "${SMOKE_PROTOCOL}" == "udp_preview" || "${SMOKE_PROTOCOL}" == "udp_preview_drop" || "${SMOKE_PROTOCOL}" == "generic_udp" ]]; then
    if [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
      sudo ip -6 addr del "${SMOKE_UDP_TARGET_IP}/128" dev lo >/dev/null 2>&1 || true
    else
      sudo ip addr del "${SMOKE_UDP_TARGET_IP}/32" dev lo >/dev/null 2>&1 || true
    fi
  fi
  sudo ip link del "${VETH_HOST}" >/dev/null 2>&1 || true
  sudo ip netns del "${SMOKE_NS}" >/dev/null 2>&1 || true
  rm -f "${TEMP_CFG_PATH}" "${CLIENT_LOG}" "${PREFLIGHT_JSON}" "${PREFLIGHT_LOG}" \
    "${PROBE_LOG}" \
    "${SERVER_CFG}" "${SERVER_LOG}" "${UDP_ECHO_LOG}" "${RUNTIME_EVENTS_JSONL}" \
    "${UDP_REQUEST_LOG}" "${HELPER_APPLY_LOG}" "${HELPER_STATUS_LOG}" "${NETWORK_STATUS_LOG}" \
    "${TCPDUMP_LOG}"
  rm -rf "${SMOKE_CERT_DIR}"
}
trap cleanup EXIT

run_aegis_measure() {
  if [[ -n "${AEGIS_MEASURE_BIN:-}" ]]; then
    if [[ ! -x "${AEGIS_MEASURE_BIN}" ]]; then
      echo "AEGIS_MEASURE_BIN points to a non-executable path: ${AEGIS_MEASURE_BIN}" >&2
      return 127
    fi
    "${AEGIS_MEASURE_BIN}" "$@"
  elif command -v cargo >/dev/null 2>&1; then
    local measure_target_directory
    measure_target_directory="$(aegis_smoke_cargo_target_directory)" || return 1
    if [[ -x "${measure_target_directory}/debug/aegis-measure" ]]; then
      "${measure_target_directory}/debug/aegis-measure" "$@"
    else
      (
        cd "${ROOT}"
        cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- "$@"
      )
    fi
  else
    echo "aegis-measure is unavailable" >&2
    return 127
  fi
}

write_smoke_contract_artifact() {
  if [[ -z "${CONTRACT_ARTIFACT}" || ! -f "${HELPER_APPLY_LOG}" ]]; then
    return 0
  fi

  run_aegis_measure write-tproxy-smoke-contract-artifact \
    --helper-apply-log "${HELPER_APPLY_LOG}" \
    --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}" \
    --output "${CONTRACT_ARTIFACT}" \
    --smoke-protocol "${SMOKE_PROTOCOL}" \
    --ip-family "${SMOKE_IP_FAMILY}" \
    --host-shape "${SMOKE_HOST_SHAPE}" \
    --firewall-backend "${FIREWALL_BACKEND}" \
    --udp-capture-contract "${UDP_CAPTURE_CONTRACT}"
  chmod a+r "${CONTRACT_ARTIFACT}" 2>/dev/null || true
}

print_runtime_events_summary() {
  if [[ ! -s "${RUNTIME_EVENTS_JSONL}" ]]; then
    return 0
  fi

  echo "Runtime events summary:" >&2
  AEGIS_CLIENT_CONFIG="${CFG_PATH}" \
    AEGIS_RUNTIME_EVENTS_JSONL="${RUNTIME_EVENTS_JSONL}" \
    AEGIS_WIDE_FORCE_ALL_UDP_TPROXY="${FORCE_ALL_UDP_TPROXY}" \
    AEGIS_WIDE_FIREWALL_BACKEND="${FIREWALL_BACKEND}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" events >&2 || true
}

print_runtime_delivery_hint() {
  if [[ ! -s "${RUNTIME_EVENTS_JSONL}" || "${SMOKE_PROTOCOL}" == "http" ]]; then
    return 0
  fi
  run_aegis_measure tproxy-runtime-delivery-hint --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}" >&2 || true
}

fail_client_exited_early() {
  echo "aegis-client exited early" >&2
  print_runtime_events_summary
  sed -n '1,160p' "${CLIENT_LOG}" >&2 || true
  exit "${EXIT_RUNTIME_CLIENT_EXITED_EARLY}"
}

fail_startup_probe() {
  echo "TPROXY helper probe did not confirm a supported startup path" >&2
  echo "Policy-routing reminder: verify the helper-side fwmark/table contract (AEGIS_WIDE_FWMARK=${FWMARK}, AEGIS_WIDE_ROUTE_TABLE=${ROUTE_TABLE}) with helper apply/doctor on this host." >&2
  sed -n '1,240p' "${PROBE_LOG}" >&2 || true
  exit "${EXIT_RUNTIME_WIDE_BACKEND_NOT_READY}"
}

fail_smoke_request() {
  echo "TPROXY smoke request failed; helper status and client log follow" >&2
  echo "Policy-routing reminder: inspect whether fwmark ${FWMARK} still routes into table ${ROUTE_TABLE} and whether that table still contains local delivery to lo." >&2
  if [[ "${UDP_CAPTURE_CONTRACT}" == "generic_capture_unstable" ]]; then
    echo "Generic-capture reminder: this smoke is already outside the preview allowlist path, so inspect runtime drop/reply stages rather than AEGIS_DNS_PORT / AEGIS_UDP_PREVIEW_PORTS." >&2
  fi
  : > "${NETWORK_STATUS_LOG}"
  if [[ -z "${SELF_TEST_SCENARIO}" ]]; then
    sudo -n AEGIS_ROOT_STATE_CLIENT="${AEGIS_ROOT_STATE_CLIENT:-}" \
      AEGIS_CLIENT_BIN="${AEGIS_CLIENT_BIN:-}" \
      AEGIS_MEASURE_BIN="${AEGIS_MEASURE_BIN:-}" \
      AEGIS_WIDE_PORT="${WIDE_PORT}" \
      AEGIS_WIDE_FWMARK="${FWMARK}" \
      AEGIS_WIDE_ROUTE_TABLE="${ROUTE_TABLE}" \
      AEGIS_WIDE_INTERFACE="${VETH_HOST}" \
      AEGIS_WIDE_IP_FAMILY="${SMOKE_IP_FAMILY}" \
      AEGIS_WIDE_FIREWALL_BACKEND="${FIREWALL_BACKEND}" \
      AEGIS_ENABLE_DNS_PREVIEW="${ENABLE_DNS_PREVIEW}" \
      AEGIS_DNS_PORT="${DNS_PORT}" \
      AEGIS_UDP_CAPTURE_CONTRACT="${UDP_CAPTURE_CONTRACT}" \
      AEGIS_WIDE_FORCE_ALL_UDP_TPROXY="${FORCE_ALL_UDP_TPROXY}" \
      AEGIS_UDP_PREVIEW_PORTS="${UDP_PREVIEW_PORTS}" \
      bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" status | tee "${HELPER_STATUS_LOG}" >&2 || true
    {
      echo "=== host interface ${VETH_HOST} ==="
      sudo -n ip -s link show dev "${VETH_HOST}" || true
      echo "=== namespace interface ${VETH_NS} ==="
      sudo -n ip netns exec "${SMOKE_NS}" ip -s link show dev "${VETH_NS}" || true
      if [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
        echo "=== namespace ipv6 route get ${SMOKE_UDP_TARGET_IP} ==="
        sudo -n ip netns exec "${SMOKE_NS}" ip -6 route get "${SMOKE_UDP_TARGET_IP}" || true
      else
        echo "=== namespace ipv4 route get ${SMOKE_UDP_TARGET_IP} ==="
        sudo -n ip netns exec "${SMOKE_NS}" ip route get "${SMOKE_UDP_TARGET_IP}" || true
      fi
    } | tee "${NETWORK_STATUS_LOG}" >&2 || true
  fi
  print_runtime_events_summary
  print_runtime_delivery_hint
  sed -n '1,240p' "${CLIENT_LOG}" >&2 || true
  if [[ -f "${SERVER_LOG}" ]]; then
    sed -n '1,200p' "${SERVER_LOG}" >&2 || true
  fi
  if [[ -f "${UDP_ECHO_LOG}" ]]; then
    sed -n '1,120p' "${UDP_ECHO_LOG}" >&2 || true
  fi
  if [[ -f "${UDP_REQUEST_LOG}" ]]; then
    sed -n '1,120p' "${UDP_REQUEST_LOG}" >&2 || true
  fi
  exit "${EXIT_RUNTIME_SMOKE_REQUEST_FAILED}"
}

reserve_tcp_port() {
  "${CARGO_BIN}" run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- reserve-tcp-port
}

wait_for_tcp_port() {
  local host="$1"
  local port="$2"
  local timeout_secs="$3"
  "${CARGO_BIN}" run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- wait-tcp-port \
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

ensure_loopback_udp_target_addr() {
  if [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
    sudo ip -6 addr del "${SMOKE_UDP_TARGET_IP}/128" dev lo >/dev/null 2>&1 || true
    sudo ip -6 addr add "${SMOKE_UDP_TARGET_IP}/128" dev lo nodad
  else
    sudo ip addr del "${SMOKE_UDP_TARGET_IP}/32" dev lo >/dev/null 2>&1 || true
    sudo ip addr add "${SMOKE_UDP_TARGET_IP}/32" dev lo
  fi
}

run_self_test_scenario() {
  if [[ -z "${SELF_TEST_SCENARIO}" ]]; then
    return 0
  fi

  # Self-test mode lets CI validate stable runtime exit semantics without
  # needing a real listener startup, namespace setup, or TPROXY privileges.
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
    loopback_target_idempotent)
      ensure_loopback_udp_target_addr
      ensure_loopback_udp_target_addr
      exit 0
      ;;
    *)
      echo "Unknown AEGIS_SMOKE_SELF_TEST_SCENARIO=${SELF_TEST_SCENARIO}" >&2
      exit 64
      ;;
  esac
}

run_self_test_scenario

verify_generic_udp_runtime_contract() {
  run_aegis_measure verify-tproxy-generic-udp-runtime-contract \
    --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}" \
    --target-port "${SMOKE_UDP_TARGET_PORT}" \
    --ip-family "${SMOKE_IP_FAMILY}"
}

verify_udp_preview_drop_runtime_contract() {
  run_aegis_measure verify-tproxy-udp-preview-drop-runtime-contract \
    --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}" \
    --target-port "${SMOKE_UDP_TARGET_PORT}" \
    --dns-port "${DNS_PORT}" \
    --udp-preview-ports "${UDP_PREVIEW_PORTS}" \
    --ip-family "${SMOKE_IP_FAMILY}"
}

map_preflight_exit() {
  local status="$1"
  run_aegis_measure tproxy-preflight-exit \
    --preflight-json "${PREFLIGHT_JSON}" \
    --preflight-log "${PREFLIGHT_LOG}" \
    --status "${status}" \
    --exit-needs-cap-net-admin "${EXIT_PREFLIGHT_NEEDS_CAP_NET_ADMIN}" \
    --exit-listener-conflict "${EXIT_PREFLIGHT_LISTENER_CONFLICT}" \
    --exit-listener-busy "${EXIT_PREFLIGHT_LISTENER_BUSY}" \
    --exit-unsupported-adapter "${EXIT_PREFLIGHT_UNSUPPORTED_ADAPTER}" \
    --exit-socks-bind-failed "${EXIT_PREFLIGHT_SOCKS_BIND_FAILED}" \
    --exit-rollout-prerequisites "${EXIT_PREFLIGHT_ROLLOUT_PREREQUISITES}" \
    --expected-interface "${VETH_HOST}"
}

validate_client_bin_override() {
  if [[ -z "${CLIENT_BIN_OVERRIDE}" ]]; then
    return 0
  fi
  if [[ ! -x "${CLIENT_BIN_OVERRIDE}" ]]; then
    echo "AEGIS_CLIENT_BIN points to a non-executable path: ${CLIENT_BIN_OVERRIDE}" >&2
    exit 1
  fi
  export AEGIS_CLIENT_BIN="${CLIENT_BIN_OVERRIDE}"
}

run_client_bin_self_test_scenario() {
  if [[ -z "${CLIENT_BIN_SELF_TEST_SCENARIO}" ]]; then
    return 0
  fi

  case "${CLIENT_BIN_SELF_TEST_SCENARIO}" in
    valid)
      validate_client_bin_override
      "${CLIENT_BIN_OVERRIDE}" --aegis-client-bin-self-test-probe >/dev/null
      exit 0
      ;;
    invalid)
      validate_client_bin_override
      exit 0
      ;;
    *)
      echo "Unknown AEGIS_SMOKE_CLIENT_BIN_SELF_TEST_SCENARIO=${CLIENT_BIN_SELF_TEST_SCENARIO}" >&2
      exit 64
      ;;
  esac
}

run_client_bin_self_test_scenario

run_preflight_self_test_scenario() {
  if [[ -z "${PREFLIGHT_SELF_TEST_SCENARIO}" ]]; then
    return 0
  fi

  case "${PREFLIGHT_SELF_TEST_SCENARIO}" in
    needs_privilege)
      cat > "${PREFLIGHT_JSON}" <<EOF
{"status":"ok","selection":{"selected_backend":"wide_primary","wide_platform_family_supported":true,"wide_runtime_readiness":"needs_privilege","wide_prerouting_interface":"${VETH_HOST}","backend_notes":[{"code":"linux_tproxy_requires_ip_transparent"}]},"runtime_checks":[{"code":"needs_cap_net_admin"}]}
EOF
      map_preflight_exit 1
      exit "$?"
      ;;
    config_error)
      cat > "${PREFLIGHT_JSON}" <<EOF
{"status":"error","selection":{"selected_backend":"wide_primary","wide_platform_family_supported":true,"wide_runtime_readiness":"config_error","wide_prerouting_interface":"${VETH_HOST}","selection_error_code":"rollout_profile_prerequisites","backend_notes":[]}}
EOF
      map_preflight_exit 1
      exit "$?"
      ;;
    unsupported_adapter)
      cat > "${PREFLIGHT_JSON}" <<EOF
{"status":"error","selection":{"selected_backend":"wide_primary","wide_platform_family_supported":false,"wide_runtime_readiness":"unsupported_adapter","wide_prerouting_interface":"${VETH_HOST}","selection_error_code":"unsupported_wide_backend","backend_notes":[{"code":"platform_adapter_stub"}]}}
EOF
      map_preflight_exit 1
      exit "$?"
      ;;
    listener_busy)
      cat > "${PREFLIGHT_JSON}" <<EOF
{"status":"ok","selection":{"selected_backend":"wide_primary","wide_platform_family_supported":true,"wide_runtime_readiness":"needs_privilege","wide_prerouting_interface":"${VETH_HOST}","backend_notes":[{"code":"linux_tproxy_requires_ip_transparent"}]},"runtime_checks":[{"code":"listener_busy"}]}
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

run_contract_self_test_scenario() {
  if [[ -z "${CONTRACT_SELF_TEST_SCENARIO}" ]]; then
    return 0
  fi

  local effective_backend="xtables:iptables"
  local support_tier="supported_preview"
  local capture_policy="allowlist_ports"
  local runtime_scope="linux_ipv4_only"
  local preview_policy="allowlist_ports"

  if [[ "${FIREWALL_BACKEND}" == "nft" ]]; then
    effective_backend="nft"
  elif [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
    effective_backend="xtables:ip6tables"
  fi
  if [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
    runtime_scope="linux_ipv6_only"
  fi
  if [[ "${SMOKE_PROTOCOL}" == "generic_udp" ]]; then
    support_tier="guarded_unstable"
    preview_policy=""
    if [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
      capture_policy="any_target_port_linux_ipv6_unstable"
    else
      capture_policy="any_target_port_linux_ipv4_unstable"
    fi
  fi

  case "${CONTRACT_SELF_TEST_SCENARIO}" in
    artifacts)
      cat > "${HELPER_APPLY_LOG}" <<EOF
firewall_backend=${effective_backend}
wide_udp_capture_support_tier=${support_tier}
wide_udp_capture_policy=${capture_policy}
wide_udp_capture_runtime_scope=${runtime_scope}
EOF
      run_aegis_measure write-tproxy-contract-self-test-events \
        --output "${RUNTIME_EVENTS_JSONL}" \
        --smoke-protocol "${SMOKE_PROTOCOL}" \
        --target-host "${SMOKE_UDP_TARGET_IP}" \
        --target-port "${SMOKE_UDP_TARGET_PORT:-0}" \
        --dns-port "${DNS_PORT}" \
        --udp-preview-ports "${UDP_PREVIEW_PORTS}" \
        --support-tier "${support_tier}" \
        --capture-policy "${capture_policy}" \
        --runtime-scope "${runtime_scope}" \
        --preview-policy "${preview_policy}" \
        --variant "${CONTRACT_SELF_TEST_VARIANT:-}"

      write_smoke_contract_artifact

      if [[ "${SMOKE_PROTOCOL}" == "generic_udp" && "${CONTRACT_SELF_TEST_VARIANT}" != "transport_failure" && "${CONTRACT_SELF_TEST_VARIANT}" != "transport_recovered" ]]; then
        verify_generic_udp_runtime_contract
      elif [[ "${SMOKE_PROTOCOL}" == "udp_preview_drop" ]]; then
        verify_udp_preview_drop_runtime_contract
      fi
      exit 0
      ;;
    *)
      echo "Unknown AEGIS_SMOKE_CONTRACT_SELF_TEST_SCENARIO=${CONTRACT_SELF_TEST_SCENARIO}" >&2
      exit 64
      ;;
  esac
}

run_contract_self_test_scenario

ensure_aegis_measure_run_bin() {
  if [[ -n "${AEGIS_MEASURE_BIN:-}" && -x "${AEGIS_MEASURE_BIN}" ]]; then
    AEGIS_MEASURE_RUN_BIN="${AEGIS_MEASURE_BIN}"
    return 0
  fi
  AEGIS_MEASURE_RUN_BIN="${SMOKE_CARGO_TARGET_DIRECTORY}/debug/aegis-measure"
  if [[ ! -x "${AEGIS_MEASURE_RUN_BIN}" ]]; then
    (
      cd "${ROOT}"
      cargo build --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure >/dev/null
    )
  fi
  if [[ ! -x "${AEGIS_MEASURE_RUN_BIN}" ]]; then
    echo "aegis-measure binary is required for UDP smoke helpers" >&2
    exit 1
  fi
}

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

if ! command -v ip >/dev/null 2>&1; then
  echo "iproute2 is required" >&2
  exit 1
fi

if [[ "${SMOKE_PROTOCOL}" != "http" ]] && ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required for relay-backed UDP smoke certificates" >&2
  exit 1
fi

if [[ "${SMOKE_PROTOCOL}" != "http" && "${SMOKE_PROTOCOL}" != "dns" && "${SMOKE_PROTOCOL}" != "dns_ipv6" && "${SMOKE_PROTOCOL}" != "udp_preview" && "${SMOKE_PROTOCOL}" != "udp_preview_drop" && "${SMOKE_PROTOCOL}" != "generic_udp" ]]; then
  echo "Unsupported AEGIS_WIDE_SMOKE_PROTOCOL=${SMOKE_PROTOCOL}; expected http, dns, dns_ipv6, udp_preview, udp_preview_drop, or generic_udp" >&2
  exit 64
fi

SMOKE_CARGO_TARGET_DIRECTORY=""
if [[ -z "${CLIENT_BIN_OVERRIDE}" || -z "${AEGIS_MEASURE_BIN:-}" || ! -x "${AEGIS_MEASURE_BIN:-}" || "${SMOKE_PROTOCOL}" != "http" ]]; then
  SMOKE_CARGO_TARGET_DIRECTORY="$(aegis_smoke_cargo_target_directory)"
fi
ensure_aegis_measure_run_bin

run_preflight() {
  local status

  echo "Running ingress preflight..."
  set +e
  if [[ -n "${CLIENT_BIN_OVERRIDE}" ]]; then
    validate_client_bin_override
    echo "Using prebuilt AEGIS_CLIENT_BIN=${CLIENT_BIN_OVERRIDE} for ingress preflight..."
    "${CLIENT_BIN_OVERRIDE}" --config "${CFG_PATH}" --ingress-preflight --json > "${PREFLIGHT_JSON}" 2> "${PREFLIGHT_LOG}"
  else
    (
      cd "${ROOT}"
      cargo run -p aegis-client -- --config "${CFG_PATH}" --ingress-preflight --json > "${PREFLIGHT_JSON}" 2> "${PREFLIGHT_LOG}"
    )
  fi
  status=$?
  set -e

  map_preflight_exit "${status}"
}

if [[ -z "${RELAY_PORT}" ]]; then
  RELAY_PORT="$(reserve_tcp_port)"
fi

CLIENT_MODE="direct"
RELAY_AUTH_TOKEN=""
RELAY_CA_CERT_LINE=""
RELAY_PRIORITY_LINE=""
if [[ "${SMOKE_PROTOCOL}" != "http" ]]; then
  generate_smoke_certs
  CLIENT_MODE="relay"
  RELAY_AUTH_TOKEN="35e6bc7bad59524e75314ee8bbee9c6d16da3bd5e5262ec99bcda65cec8274f0"
  RELAY_CA_CERT_LINE="ca_cert = \"${SMOKE_CERT_DIR}/ca.pem\""
  # UDP preview runtime currently relies on the UDP-capable CONNECT-UDP path.
  RELAY_PRIORITY_LINE='transport_priority = ["masque_derived"]'
fi

cat > "${CFG_PATH}" <<EOF
mode = "${CLIENT_MODE}"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "${VETH_HOST}"
listen = "${WIDE_LISTEN_VALUE}"
capture_dns = true
udp_capture_contract = "${UDP_CAPTURE_CONTRACT}"
dns_port = ${DNS_PORT}
${UDP_PREVIEW_PORTS_LINE}
default_mark = ${FWMARK}

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

if [[ "${SMOKE_PROTOCOL}" != "http" ]]; then
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
allowed_ports = [${SMOKE_UDP_TARGET_PORT}]
EOF
fi

if [[ -n "${CLIENT_BIN_OVERRIDE}" ]]; then
  validate_client_bin_override
  echo "Using prebuilt AEGIS_CLIENT_BIN=${CLIENT_BIN_OVERRIDE}; skipping aegis-client cargo build."
  if [[ "${SMOKE_PROTOCOL}" != "http" ]]; then
    echo "Building aegis-server..."
    (
      cd "${ROOT}"
      cargo build -p aegis-server
    )
  fi
else
  echo "Building aegis-client..."
  (
    cd "${ROOT}"
    if [[ "${SMOKE_PROTOCOL}" != "http" ]]; then
      cargo build -p aegis-client -p aegis-server
    else
      cargo build -p aegis-client
    fi
  )
  # The smoke just built this exact debug binary. Pin both preflight and the
  # helper launch to it so helper fallback cannot start a separate
  # `cargo run --release` compilation whose PID/lifetime escapes the smoke's
  # startup and cleanup contract.
  CLIENT_BIN_OVERRIDE="${SMOKE_CARGO_TARGET_DIRECTORY}/debug/aegis-client"
  validate_client_bin_override
fi

aegis_smoke_stage_root_state_client "${CLIENT_BIN_OVERRIDE}" "${AEGIS_MEASURE_RUN_BIN}"
CLIENT_BIN_OVERRIDE="${AEGIS_CLIENT_BIN}"

run_preflight

# The helper plans privileged network state from administrator-owned metadata.
# Use its checked writer in the already pinned /run staging directory; a file
# directly under the caller's TMPDIR is not an administrative authority.
ADMIN_CFG_PATH="${AEGIS_SMOKE_ROOT_STATE_DIRECTORY}/client.toml"
sudo -n "${AEGIS_ROOT_STATE_CLIENT}" profile metadata write \
  --path "${ADMIN_CFG_PATH}" --mode 0600 --exclusive < "${CFG_PATH}"
if [[ "${EUID}" == 0 ]]; then
  CFG_PATH="${ADMIN_CFG_PATH}"
fi

if [[ "${SMOKE_PROTOCOL}" != "http" ]]; then
  echo "Starting local relay server for UDP smoke..."
  "${SMOKE_CARGO_TARGET_DIRECTORY}/debug/aegis-server" --config "${SERVER_CFG}" >"${SERVER_LOG}" 2>&1 &
  SERVER_PID="$!"
  if ! wait_for_tcp_port "127.0.0.1" "${RELAY_PORT}" 20; then
    echo "relay server did not become ready on 127.0.0.1:${RELAY_PORT}" >&2
    sed -n '1,200p' "${SERVER_LOG}" >&2 || true
    exit "${EXIT_RUNTIME_SMOKE_REQUEST_FAILED}"
  fi
fi

echo "Preparing temporary namespace ${SMOKE_NS}..."
sudo ip netns add "${SMOKE_NS}"
sudo ip link add "${VETH_HOST}" type veth peer name "${VETH_NS}"
sudo ip link set "${VETH_NS}" netns "${SMOKE_NS}"
if [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
  # These are synthetic one-shot lab addresses; skipping DAD keeps the
  # richer-host IPv6 matrix from racing tentative-address bring-up.
  sudo ip -6 addr add "${HOST_IPV6}/${CIDR_PREFIX_IPV6}" dev "${VETH_HOST}" nodad
else
  sudo ip addr add "${HOST_IP}/${CIDR_PREFIX}" dev "${VETH_HOST}"
fi
sudo ip link set "${VETH_HOST}" up
if [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
  sudo ip netns exec "${SMOKE_NS}" ip -6 addr add "${NS_IPV6}/${CIDR_PREFIX_IPV6}" dev "${VETH_NS}" nodad
else
  sudo ip netns exec "${SMOKE_NS}" ip addr add "${NS_IP}/${CIDR_PREFIX}" dev "${VETH_NS}"
fi
sudo ip netns exec "${SMOKE_NS}" ip link set lo up
sudo ip netns exec "${SMOKE_NS}" ip link set "${VETH_NS}" up
if [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
  sudo ip netns exec "${SMOKE_NS}" ip -6 route add default via "${HOST_IPV6}"
else
  sudo ip netns exec "${SMOKE_NS}" ip route add default via "${HOST_IP}"
fi

if [[ "${SMOKE_PROTOCOL}" != "http" ]]; then
  echo "Preparing local UDP echo target on ${SMOKE_UDP_TARGET_IP}:${SMOKE_UDP_TARGET_PORT}..."
  ensure_loopback_udp_target_addr
  "${AEGIS_MEASURE_RUN_BIN}" udp-echo-server \
    --host "${SMOKE_UDP_TARGET_IP}" \
    --port "${SMOKE_UDP_TARGET_PORT}" \
    --reuse-addr >"${UDP_ECHO_LOG}" 2>&1 &
  UDP_ECHO_PID="$!"
  sleep 1
fi

if [[ -n "${DEBUG_ARTIFACT_DIR}" ]] && command -v tcpdump >/dev/null 2>&1; then
  tcpdump_ip_filter="ip"
  tcpdump_proto_filter="udp"
  if [[ "${SMOKE_IP_FAMILY}" == "ipv6" ]]; then
    tcpdump_ip_filter="ip6"
  fi
  if [[ "${SMOKE_PROTOCOL}" == "http" ]]; then
    tcpdump_proto_filter="tcp"
  fi
  tcpdump_filter="${tcpdump_ip_filter} and ${tcpdump_proto_filter}"
  printf 'tcpdump_interface=%s\n' "${TCPDUMP_INTERFACE}" >"${TCPDUMP_LOG}"
  printf 'tcpdump_filter=%s\n' "${tcpdump_filter}" >>"${TCPDUMP_LOG}"
  TCPDUMP_CAPTURE_TIMEOUT_SECS="${AEGIS_WIDE_TCPDUMP_TIMEOUT_SECS:-$(( STARTUP_WAIT_SECS + REQUEST_TIMEOUT_SECS + 30 ))}"
  if [[ -n "${TCPDUMP_PCAP_ARTIFACT}" ]]; then
    mkdir -p "$(dirname "${TCPDUMP_PCAP_ARTIFACT}")"
    sudo -n timeout "${TCPDUMP_CAPTURE_TIMEOUT_SECS}" \
      tcpdump -U -ni "${TCPDUMP_INTERFACE}" -w "${TCPDUMP_PCAP_ARTIFACT}" "${tcpdump_filter}" >>"${TCPDUMP_LOG}" 2>&1 &
  else
    sudo -n timeout "${TCPDUMP_CAPTURE_TIMEOUT_SECS}" \
      tcpdump -ni "${TCPDUMP_INTERFACE}" "${tcpdump_filter}" >>"${TCPDUMP_LOG}" 2>&1 &
  fi
  TCPDUMP_PID="$!"
  sleep 1
fi

echo "Applying TPROXY helper on interface ${VETH_HOST}..."
AEGIS_SMOKE_HELPER_STARTED=1
sudo AEGIS_ROOT_STATE_CLIENT="${AEGIS_ROOT_STATE_CLIENT:-}" \
  AEGIS_CLIENT_BIN="${AEGIS_CLIENT_BIN:-}" \
  AEGIS_MEASURE_BIN="${AEGIS_MEASURE_BIN:-}" \
  AEGIS_WIDE_PORT="${WIDE_PORT}" \
  AEGIS_WIDE_FWMARK="${FWMARK}" \
  AEGIS_WIDE_ROUTE_TABLE="${ROUTE_TABLE}" \
  AEGIS_WIDE_INTERFACE="${VETH_HOST}" \
  AEGIS_WIDE_IP_FAMILY="${SMOKE_IP_FAMILY}" \
  AEGIS_WIDE_FIREWALL_BACKEND="${FIREWALL_BACKEND}" \
  AEGIS_ENABLE_DNS_PREVIEW="${ENABLE_DNS_PREVIEW}" \
  AEGIS_DNS_PORT="${DNS_PORT}" \
  AEGIS_UDP_CAPTURE_CONTRACT="${UDP_CAPTURE_CONTRACT}" \
  AEGIS_WIDE_FORCE_ALL_UDP_TPROXY="${FORCE_ALL_UDP_TPROXY}" \
  AEGIS_UDP_PREVIEW_PORTS="${UDP_PREVIEW_PORTS}" \
  AEGIS_CLIENT_CONFIG="${ADMIN_CFG_PATH}" \
  bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" apply | tee "${HELPER_APPLY_LOG}"

write_smoke_contract_artifact

echo "Running helper doctor after helper apply..."
if ! sudo AEGIS_ROOT_STATE_CLIENT="${AEGIS_ROOT_STATE_CLIENT:-}" \
  AEGIS_CLIENT_BIN="${AEGIS_CLIENT_BIN:-}" \
  AEGIS_MEASURE_BIN="${AEGIS_MEASURE_BIN:-}" \
  AEGIS_WIDE_PORT="${WIDE_PORT}" \
  AEGIS_WIDE_FWMARK="${FWMARK}" \
  AEGIS_WIDE_ROUTE_TABLE="${ROUTE_TABLE}" \
  AEGIS_WIDE_INTERFACE="${VETH_HOST}" \
  AEGIS_WIDE_IP_FAMILY="${SMOKE_IP_FAMILY}" \
  AEGIS_WIDE_FIREWALL_BACKEND="${FIREWALL_BACKEND}" \
  AEGIS_ENABLE_DNS_PREVIEW="${ENABLE_DNS_PREVIEW}" \
  AEGIS_DNS_PORT="${DNS_PORT}" \
  AEGIS_UDP_CAPTURE_CONTRACT="${UDP_CAPTURE_CONTRACT}" \
  AEGIS_WIDE_FORCE_ALL_UDP_TPROXY="${FORCE_ALL_UDP_TPROXY}" \
  AEGIS_UDP_PREVIEW_PORTS="${UDP_PREVIEW_PORTS}" \
  AEGIS_CLIENT_CONFIG="${ADMIN_CFG_PATH}" \
  bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" doctor >"${HELPER_STATUS_LOG}" 2>&1; then
  echo "TPROXY helper doctor did not confirm a supported host contract" >&2
  sed -n '1,240p' "${HELPER_STATUS_LOG}" >&2 || true
  exit "${EXIT_RUNTIME_WIDE_BACKEND_NOT_READY}"
fi

echo "Running helper startup probe before long-running launch..."
if ! (
  cd "${ROOT}"
  AEGIS_CLIENT_CONFIG="${CFG_PATH}" \
    AEGIS_RUNTIME_EVENTS_JSONL="${RUNTIME_EVENTS_JSONL}" \
    AEGIS_WIDE_FORCE_ALL_UDP_TPROXY="${FORCE_ALL_UDP_TPROXY}" \
    AEGIS_WIDE_FIREWALL_BACKEND="${FIREWALL_BACKEND}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" probe >"${PROBE_LOG}" 2>&1
); then
  fail_startup_probe
fi

echo "Starting wide-mode client..."
# Reuse the helper-managed launch contract so smoke and operator flows share
# the same runtime JSONL wiring. Do not wrap this in an extra background
# subshell: helper launch execs the client, so CLIENT_PID remains the actual
# runtime PID and cleanup cannot orphan it after a failed smoke.
AEGIS_CLIENT_CONFIG="${CFG_PATH}" \
  AEGIS_DIAGNOSTIC_LOGS=1 \
  AEGIS_RUNTIME_EVENTS_JSONL="${RUNTIME_EVENTS_JSONL}" \
  AEGIS_WIDE_FORCE_ALL_UDP_TPROXY="${FORCE_ALL_UDP_TPROXY}" \
  AEGIS_WIDE_FIREWALL_BACKEND="${FIREWALL_BACKEND}" \
  bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" launch >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID="$!"

sleep "${STARTUP_WAIT_SECS}"

if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
  fail_client_exited_early
fi

wait_for_wide_backend

if [[ "${SMOKE_PROTOCOL}" != "http" ]]; then
  echo "Running ${SMOKE_UDP_LABEL} smoke from namespace ${SMOKE_NS} -> ${SMOKE_UDP_TARGET_IP}:${SMOKE_UDP_TARGET_PORT}"
  : > "${UDP_REQUEST_LOG}"
  if sudo ip netns exec "${SMOKE_NS}" \
    "${AEGIS_MEASURE_RUN_BIN}" udp-echo-client \
      --host "${SMOKE_UDP_TARGET_IP}" \
      --port "${SMOKE_UDP_TARGET_PORT}" \
      --payload "${SMOKE_UDP_PAYLOAD}" \
      --timeout-secs "${REQUEST_TIMEOUT_SECS}" >"${UDP_REQUEST_LOG}" 2>&1; then
    if [[ "${SMOKE_PROTOCOL}" == "udp_preview_drop" ]]; then
      echo "UDP preview drop smoke unexpectedly succeeded" >&2
      fail_smoke_request
    fi
    if [[ "${SMOKE_PROTOCOL}" == "generic_udp" ]]; then
      if ! verify_generic_udp_runtime_contract; then
        fail_smoke_request
      fi
    fi
    if [[ "${SMOKE_PROTOCOL}" == "generic_udp" ]]; then
      echo "Wide TPROXY ${SMOKE_UDP_LABEL} smoke completed successfully under guarded_unstable contract (Linux-only broader UDP coverage; not a production-ready claim)"
    else
      echo "Wide TPROXY ${SMOKE_UDP_LABEL} smoke completed successfully under supported_preview baseline"
    fi
  else
    if [[ "${SMOKE_PROTOCOL}" == "udp_preview_drop" ]]; then
      echo "Wide TPROXY ${SMOKE_UDP_LABEL} smoke observed the expected supported_preview allowlist drop"
      write_smoke_contract_artifact
      exit "${EXIT_RUNTIME_SMOKE_REQUEST_FAILED}"
    fi
    fail_smoke_request
  fi
else
  echo "Running TPROXY smoke request from namespace ${SMOKE_NS} -> ${TARGET_URL}"
  if sudo ip netns exec "${SMOKE_NS}" \
    curl --silent --show-error --max-time 15 \
      --resolve "${TARGET_HOST}:${TARGET_PORT}:${TARGET_IP}" \
      "${TARGET_URL}" >/dev/null; then
    echo "Wide TPROXY smoke completed successfully for the TCP/HTTP path"
  else
    fail_smoke_request
  fi
fi

write_smoke_contract_artifact
