#!/usr/bin/env bash
# Запуск сервера и подсказка/генерация клиентского relay-конфига.
#
# Для более быстрого Linux wide-lab запуска можно дополнительно указать:
#   AEGIS_WIDE_PROFILE=linux_tproxy_relay
# или
#   AEGIS_WIDE_PROFILE=linux_redirect_relay
#
# Тогда скрипт сгенерирует отдельный клиентский конфиг и подскажет matching
# helper/env contract. AEGIS_SKIP_SERVER_START=1 позволяет использовать скрипт
# только как config/bootstrap helper без long-running server process, а
# AEGIS_SKIP_BUILD=1 дополнительно убирает обязательную release-сборку.
#
# Для separate relay-server/client split можно дополнительно задать:
#   AEGIS_RELAY_SERVER=relay.example.org:8443
#   AEGIS_RELAY_SERVER_NAME=relay.example.org
#   AEGIS_RELAY_CA_CERT=/path/to/ca.pem
#   AEGIS_RELAY_AUTH_TOKEN=...
# Тогда generated client config будет сразу смотреть на удалённый relay-host.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

WIDE_PROFILE="${AEGIS_WIDE_PROFILE:-}"
SKIP_SERVER_START="${AEGIS_SKIP_SERVER_START:-0}"
SKIP_BUILD="${AEGIS_SKIP_BUILD:-0}"
SERVER_CFG="${ROOT}/aegis-server.toml"
DEFAULT_CLIENT_CFG="${ROOT}/aegis.toml"
WIDE_CLIENT_CFG="${ROOT}/aegis-wide.toml"
CLIENT_CFG="${AEGIS_CLIENT_CONFIG:-}"
WIDE_LISTEN="${AEGIS_WIDE_LISTEN:-0.0.0.0:15080}"
WIDE_PREROUTING_INTERFACE="${AEGIS_WIDE_PREROUTING_INTERFACE:-${AEGIS_WIDE_INTERFACE:-}}"
WIDE_ROUTE_TABLE="${AEGIS_WIDE_ROUTE_TABLE:-100}"
DNS_PORT="${AEGIS_DNS_PORT:-53}"
UDP_PREVIEW_PORTS="${AEGIS_UDP_PREVIEW_PORTS:-}"
RELAY_SERVER="${AEGIS_RELAY_SERVER:-127.0.0.1:8443}"
RELAY_SERVER_NAME="${AEGIS_RELAY_SERVER_NAME:-localhost}"
RELAY_CA_CERT="${AEGIS_RELAY_CA_CERT:-${ROOT}/certs/ca.pem}"
RELAY_AUTH_TOKEN="${AEGIS_RELAY_AUTH_TOKEN:-}"
RELAY_MASQUE_SERVER="${AEGIS_MASQUE_SERVER:-}"

detect_default_interface() {
  if ! command -v ip >/dev/null 2>&1; then
    return 1
  fi
  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

if [[ -z "${CLIENT_CFG}" ]]; then
  if [[ -n "${WIDE_PROFILE}" ]]; then
    CLIENT_CFG="${WIDE_CLIENT_CFG}"
  else
    CLIENT_CFG="${DEFAULT_CLIENT_CFG}"
  fi
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "Установите Rust (rustup) и добавьте cargo в PATH" >&2
  exit 1
fi

parse_listen_port() {
  local listen="$1"
  local port="${listen##*:}"
  if [[ ! "${port}" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo "Некорректный AEGIS_WIDE_LISTEN=${listen}; ожидается адрес с TCP-портом, например 0.0.0.0:15080" >&2
    exit 1
  fi
  printf '%s\n' "${port}"
}

validate_udp_preview_ports_csv() {
  local csv="$1"
  local raw=""
  local port=""

  [[ -z "${csv}" ]] && return 0

  IFS=',' read -r -a UDP_PREVIEW_PORTS_LIST <<< "${csv}"
  for raw in "${UDP_PREVIEW_PORTS_LIST[@]}"; do
    port="${raw//[[:space:]]/}"
    if [[ ! "${port}" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
      echo "Некорректный AEGIS_UDP_PREVIEW_PORTS=${csv}; ожидается CSV из UDP-портов 1..65535" >&2
      exit 1
    fi
  done
}

write_udp_preview_ports_toml() {
  local csv="$1"
  local raw=""
  local port=""
  local rendered=""

  [[ -z "${csv}" ]] && return 0
  validate_udp_preview_ports_csv "${csv}"

  IFS=',' read -r -a UDP_PREVIEW_PORTS_LIST <<< "${csv}"
  for raw in "${UDP_PREVIEW_PORTS_LIST[@]}"; do
    port="${raw//[[:space:]]/}"
    if [[ -n "${rendered}" ]]; then
      rendered="${rendered}, "
    fi
    rendered="${rendered}${port}"
  done
  printf 'udp_preview_ports = [%s]\n' "${rendered}"
}

require_tproxy_profile_contract() {
  local default_mark="$1"
  local candidate_iface=""

  if [[ -z "${WIDE_PREROUTING_INTERFACE}" ]]; then
    candidate_iface="$(detect_default_interface || true)"
    echo "AEGIS_WIDE_PROFILE=linux_tproxy_relay требует explicit interface-scoped happy-path" >&2
    if [[ -n "${candidate_iface}" ]]; then
      echo "Assisted detect: Linux default route suggests interface ${candidate_iface}" >&2
      echo "Используйте AEGIS_WIDE_PREROUTING_INTERFACE=${candidate_iface} или AEGIS_WIDE_INTERFACE=${candidate_iface}, если это и есть нужный ingress interface" >&2
    fi
    echo "Поддерживаемый путь больше не опирается на all-interface fallback: задайте AEGIS_WIDE_PREROUTING_INTERFACE=<iface> или AEGIS_WIDE_INTERFACE=<iface> перед запуском scripts/run-pair.sh" >&2
    exit 1
  fi
  if [[ ! "${default_mark}" =~ ^[0-9]+$ ]] || (( default_mark == 0 )); then
    echo "AEGIS_WIDE_PROFILE=linux_tproxy_relay требует ненулевой AEGIS_WIDE_DEFAULT_MARK" >&2
    exit 1
  fi
}

extract_server_auth_token() {
  local cfg_path="$1"
  local token

  token="$(
    sed -n 's/^auth_token = "\(.*\)"/\1/p' "${cfg_path}" | sed -n '1p'
  )"
  if [[ -z "${token}" ]]; then
    token="change-me"
  fi
  printf '%s\n' "${token}"
}

using_remote_relay_target() {
  [[ "${RELAY_SERVER}" != "127.0.0.1:8443" || "${RELAY_SERVER_NAME}" != "localhost" ]]
}

write_wide_client_config() {
  local cfg_path="$1"
  local backend="$2"
  local rollout_profile="$3"
  local default_mark="$4"
  local auth_token="$5"

  {
    echo '# Auto-generated by scripts/run-pair.sh for a Linux wide lab profile.'
    echo 'mode = "relay"'
    echo
    echo '[ingress]'
    echo 'primary = "wide"'
    echo 'allow_fallback = true'
    echo
    echo '[ingress.wide]'
    echo 'enabled = true'
    printf 'platform_backend = "%s"\n' "${backend}"
    printf 'rollout_profile = "%s"\n' "${rollout_profile}"
    if [[ -n "${WIDE_PREROUTING_INTERFACE}" ]]; then
      printf 'prerouting_interface = "%s"\n' "${WIDE_PREROUTING_INTERFACE}"
    fi
    printf 'listen = "%s"\n' "${WIDE_LISTEN}"
    echo 'capture_dns = true'
    printf 'dns_port = %s\n' "${DNS_PORT}"
    write_udp_preview_ports_toml "${UDP_PREVIEW_PORTS}"
    printf 'default_mark = %s\n' "${default_mark}"
    echo
    echo '[socks]'
    echo 'listen = "127.0.0.1:1080"'
    echo
    echo '[direct]'
    echo 'state_path = "~/.cache/aegis/state.json"'
    echo 'strategies = ["passthrough"]'
    echo 'epsilon = 0.1'
    echo 'first_chunk_timeout_ms = 8000'
    echo 'freeze_threshold_bytes = 16384'
    echo 'degraded_latency_ms = 5000'
    echo 'tls_grease = false'
    echo 'sni_case_obfuscate = false'
    echo 'inject_opaque_extension = false'
    echo 'ghost_jitter_before_attempt = false'
    echo
    echo '[relay]'
    printf 'server = "%s"\n' "${RELAY_SERVER}"
    printf 'server_name = "%s"\n' "${RELAY_SERVER_NAME}"
    printf 'auth_token = "%s"\n' "${auth_token}"
    echo 'transport_priority = ["masque_derived", "https_ws", "grpc_stream", "legacy_tls"]'
    echo 'websocket_path = "/aegis/ws"'
    echo 'grpc_path = "/aegis.tunnel.v1.TunnelService/Open"'
    echo 'masque_path = "/.well-known/masque/udp"'
    if [[ -n "${RELAY_MASQUE_SERVER}" ]]; then
      printf 'masque_server = "%s"\n' "${RELAY_MASQUE_SERVER}"
    fi
    echo 'connect_timeout_ms = 5000'
    printf 'ca_cert = "%s"\n' "${RELAY_CA_CERT}"
    echo
    echo '[relay.policy]'
    echo 'rotate_transports_per_session = false'
    echo 'max_transport_attempts = 1'
    echo 'write_chunk_size = 16384'
    echo 'inter_chunk_delay_ms = 0'
  } > "${cfg_path}"
}

print_default_client_hint() {
  echo "В другом терминале: cp config.example.toml aegis.toml"
  echo '  mode = "relay"'
  echo "  [relay] server = \"${RELAY_SERVER}\" auth_token = тот же что в relay config"
  echo "  server_name = \"${RELAY_SERVER_NAME}\""
  echo "  ca_cert = \"${RELAY_CA_CERT}\""
}

print_wide_helper_hint() {
  local backend="$1"
  local default_mark="$2"
  local wide_port="$3"
  local preview_env=""

  if [[ -n "${UDP_PREVIEW_PORTS}" ]]; then
    preview_env=" AEGIS_UDP_PREVIEW_PORTS=\"${UDP_PREVIEW_PORTS}\""
  fi

  echo "Сгенерирован клиентский wide lab-config: ${CLIENT_CFG}"
  echo "Relay target: ${RELAY_SERVER} (server_name=${RELAY_SERVER_NAME})"
  if [[ -n "${RELAY_MASQUE_SERVER}" ]]; then
    echo "MASQUE UDP target: ${RELAY_MASQUE_SERVER}"
  fi
  case "${backend}" in
    linux_tproxy)
      echo "Recommended Linux TPROXY happy-path:"
      echo "  supported scope: ingress.wide.prerouting_interface == AEGIS_WIDE_INTERFACE == ${WIDE_PREROUTING_INTERFACE}"
      echo "  supported policy routing: ingress.wide.default_mark == AEGIS_WIDE_FWMARK == ${default_mark}; helper route table = ${WIDE_ROUTE_TABLE}"
      echo "  1. sudo AEGIS_WIDE_PORT=\"${wide_port}\" AEGIS_WIDE_INTERFACE=\"${WIDE_PREROUTING_INTERFACE}\" AEGIS_ENABLE_DNS_PREVIEW=1 AEGIS_DNS_PORT=\"${DNS_PORT}\"${preview_env} AEGIS_WIDE_FWMARK=\"${default_mark}\" AEGIS_WIDE_ROUTE_TABLE=\"${WIDE_ROUTE_TABLE}\" ./scripts/setup-wide-linux-tproxy.sh apply"
      echo "  2. sudo AEGIS_CLIENT_CONFIG=\"${CLIENT_CFG}\" AEGIS_WIDE_PORT=\"${wide_port}\" AEGIS_WIDE_INTERFACE=\"${WIDE_PREROUTING_INTERFACE}\" AEGIS_ENABLE_DNS_PREVIEW=1 AEGIS_DNS_PORT=\"${DNS_PORT}\"${preview_env} AEGIS_WIDE_FWMARK=\"${default_mark}\" AEGIS_WIDE_ROUTE_TABLE=\"${WIDE_ROUTE_TABLE}\" ./scripts/setup-wide-linux-tproxy.sh doctor"
      echo "  3. AEGIS_CLIENT_CONFIG=\"${CLIENT_CFG}\" AEGIS_RUNTIME_EVENTS_JSONL=\"${ROOT}/aegis-client-runtime.jsonl\" ./scripts/setup-wide-linux-tproxy.sh run"
      echo "     run assumes the same helper-side fwmark/route-table contract already passed apply + doctor on this host"
      echo "  4. sudo AEGIS_CLIENT_CONFIG=\"${CLIENT_CFG}\" AEGIS_WIDE_PORT=\"${wide_port}\" AEGIS_WIDE_INTERFACE=\"${WIDE_PREROUTING_INTERFACE}\" AEGIS_ENABLE_DNS_PREVIEW=1 AEGIS_DNS_PORT=\"${DNS_PORT}\"${preview_env} AEGIS_WIDE_FWMARK=\"${default_mark}\" AEGIS_WIDE_ROUTE_TABLE=\"${WIDE_ROUTE_TABLE}\" ./scripts/setup-wide-linux-tproxy.sh status"
      echo "  5. sudo AEGIS_WIDE_PORT=\"${wide_port}\" AEGIS_WIDE_INTERFACE=\"${WIDE_PREROUTING_INTERFACE}\" AEGIS_ENABLE_DNS_PREVIEW=1 AEGIS_DNS_PORT=\"${DNS_PORT}\"${preview_env} AEGIS_WIDE_FWMARK=\"${default_mark}\" AEGIS_WIDE_ROUTE_TABLE=\"${WIDE_ROUTE_TABLE}\" ./scripts/setup-wide-linux-tproxy.sh teardown"
      echo "     for manual step-by-step debugging you can still use separate probe / launch / events actions"
      ;;
    linux_redirect)
      echo "Recommended Linux REDIRECT happy-path:"
      echo "  1. sudo AEGIS_WIDE_PORT=\"${wide_port}\" AEGIS_EXEMPT_UID=\"$(id -u)\" AEGIS_ENABLE_DNS_PREVIEW=1 AEGIS_DNS_PORT=\"${DNS_PORT}\"${preview_env} ./scripts/setup-wide-linux-redirect.sh apply"
      echo "  2. cargo run --release -p aegis-client -- --config \"${CLIENT_CFG}\""
      echo "  3. sudo AEGIS_WIDE_PORT=\"${wide_port}\" AEGIS_ENABLE_DNS_PREVIEW=1 AEGIS_DNS_PORT=\"${DNS_PORT}\"${preview_env} ./scripts/setup-wide-linux-redirect.sh status"
      echo "  4. sudo AEGIS_WIDE_PORT=\"${wide_port}\" AEGIS_ENABLE_DNS_PREVIEW=1 AEGIS_DNS_PORT=\"${DNS_PORT}\"${preview_env} ./scripts/setup-wide-linux-redirect.sh teardown"
      ;;
  esac
}

cd "${ROOT}"
if [[ "${SKIP_BUILD}" == "1" ]]; then
  echo "AEGIS_SKIP_BUILD=1 -> release build skipped"
else
  cargo build --release
fi

if [[ ! -f "${SERVER_CFG}" ]] && ! using_remote_relay_target; then
  cp "${ROOT}/aegis-server.toml.example" "${SERVER_CFG}"
  echo "Создан ${SERVER_CFG} — проверьте auth_token и пути cert/key"
fi

if [[ -n "${WIDE_PROFILE}" ]]; then
  if [[ -n "${RELAY_AUTH_TOKEN}" ]]; then
    SERVER_AUTH_TOKEN="${RELAY_AUTH_TOKEN}"
  elif [[ -f "${SERVER_CFG}" ]]; then
    SERVER_AUTH_TOKEN="$(extract_server_auth_token "${SERVER_CFG}")"
  elif using_remote_relay_target; then
    echo "Remote relay bootstrap requires AEGIS_RELAY_AUTH_TOKEN when local ${SERVER_CFG} is absent" >&2
    exit 1
  else
    cp "${ROOT}/aegis-server.toml.example" "${SERVER_CFG}"
    echo "Создан ${SERVER_CFG} — проверьте auth_token и пути cert/key"
    SERVER_AUTH_TOKEN="$(extract_server_auth_token "${SERVER_CFG}")"
  fi
  WIDE_PORT="$(parse_listen_port "${WIDE_LISTEN}")"
  case "${WIDE_PROFILE}" in
    linux_tproxy_relay)
      require_tproxy_profile_contract "${AEGIS_WIDE_DEFAULT_MARK:-1}"
      write_wide_client_config "${CLIENT_CFG}" "linux_tproxy" "transparent_privileged" "${AEGIS_WIDE_DEFAULT_MARK:-1}" "${SERVER_AUTH_TOKEN}"
      print_wide_helper_hint "linux_tproxy" "${AEGIS_WIDE_DEFAULT_MARK:-1}" "${WIDE_PORT}"
      ;;
    linux_redirect_relay)
      write_wide_client_config "${CLIENT_CFG}" "linux_redirect" "${AEGIS_WIDE_ROLLOUT_PROFILE:-output_only_safe}" "${AEGIS_WIDE_DEFAULT_MARK:-0}" "${SERVER_AUTH_TOKEN}"
      print_wide_helper_hint "linux_redirect" "${AEGIS_WIDE_DEFAULT_MARK:-0}" "${WIDE_PORT}"
      ;;
    *)
      echo "Unsupported AEGIS_WIDE_PROFILE=${WIDE_PROFILE}" >&2
      echo "Supported profiles: linux_tproxy_relay, linux_redirect_relay" >&2
      exit 1
      ;;
  esac
else
  print_default_client_hint
fi

echo ""
if using_remote_relay_target; then
  echo "Generated client config targets remote relay-server ${RELAY_SERVER}."
  if [[ "${SKIP_SERVER_START}" != "1" ]]; then
    echo "Remote relay target detected -> local aegis-server bootstrap is skipped; use AEGIS_SKIP_SERVER_START=1 explicitly if you only want config generation." 
    exit 0
  fi
fi
if [[ "${SKIP_SERVER_START}" == "1" ]]; then
  echo "AEGIS_SKIP_SERVER_START=1 -> сервер не запускался"
  exit 0
fi

echo "Запуск aegis-server (Ctrl+C для остановки)..."
exec cargo run --release -p aegis-server -- --config "${SERVER_CFG}"
