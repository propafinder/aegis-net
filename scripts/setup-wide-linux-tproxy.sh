#!/usr/bin/env bash
# Linux TPROXY helper for AEGIS wide ingress.
# Requires sudo/root and a kernel/userspace with xt_TPROXY support.
#
# Defaults are intentionally narrow: only PREROUTING is configured here.
# OUTPUT interception should be handled separately to avoid surprising loops.
# Optional narrow UDP preview for the DNS path plus any explicitly configured
# extra ports is enabled only when AEGIS_ENABLE_DNS_PREVIEW=1 is set.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

default_installed_client_config() {
  local candidate="/etc/aegis/client/aegis.toml"
  if [[ -f "${candidate}" ]]; then
    printf '%s\n' "${candidate}"
  fi
}

default_runtime_events_jsonl() {
  local installed="/var/log/aegis-client/runtime-events.jsonl"
  if [[ -e "${installed}" ]]; then
    printf '%s\n' "${installed}"
  else
    printf '%s\n' "${ROOT}/aegis-client-runtime.jsonl"
  fi
}

ACTION="${1:-}"
CHAIN="${AEGIS_WIDE_CHAIN:-AEGIS_WIDE_TPROXY}"
INPUT_CHAIN="${AEGIS_WIDE_INPUT_CHAIN:-AEGIS_WIDE_TPROXY_IN}"
WIDE_PORT="${AEGIS_WIDE_PORT:-15080}"
FWMARK="${AEGIS_WIDE_FWMARK:-1}"
ROUTE_TABLE="${AEGIS_WIDE_ROUTE_TABLE:-100}"
INTERFACE="${AEGIS_WIDE_INTERFACE:-}"
ALLOW_ALL_INTERFACES="${AEGIS_WIDE_ALLOW_ALL_INTERFACES:-0}"
IP_FAMILY_REQUESTED="${AEGIS_WIDE_IP_FAMILY:-auto}"
FIREWALL_BACKEND_REQUESTED="${AEGIS_WIDE_FIREWALL_BACKEND:-auto}"
ENABLE_DNS_PREVIEW="${AEGIS_ENABLE_DNS_PREVIEW:-0}"
DNS_PORT="${AEGIS_DNS_PORT:-53}"
UDP_CAPTURE_CONTRACT="${AEGIS_UDP_CAPTURE_CONTRACT:-preview_allowlist_only}"
FORCE_ALL_UDP_TPROXY="${AEGIS_WIDE_FORCE_ALL_UDP_TPROXY:-0}"
ENABLE_LOCAL_OUTPUT="${AEGIS_ENABLE_LOCAL_OUTPUT:-0}"
LOCAL_OUTPUT_EXEMPT_UID="${AEGIS_EXEMPT_UID:-0}"
# Audit H4: LOCAL_OUTPUT_EXEMPT_UID is interpolated into `--uid-owner` and
# INTERFACE into `-i`/`iifname`. Reject non-numeric UIDs and malformed
# interface names so a hostile env var cannot inject firewall arguments.
if [[ ! "${LOCAL_OUTPUT_EXEMPT_UID}" =~ ^[0-9]+$ ]]; then
  echo "FATAL: AEGIS_EXEMPT_UID must be numeric (got '${LOCAL_OUTPUT_EXEMPT_UID}')" >&2
  exit 2
fi
if [[ -n "${INTERFACE}" && ! "${INTERFACE}" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{0,14}$ ]]; then
  echo "FATAL: AEGIS_WIDE_INTERFACE must be a valid interface name (got '${INTERFACE}')" >&2
  exit 2
fi
for owned_chain in "${CHAIN}" "${INPUT_CHAIN}"; do
  if [[ ! "${owned_chain}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,27}$ ]]; then
    echo "FATAL: AEGIS-owned firewall chain names must be 1-28 safe characters (got '${owned_chain}')" >&2
    exit 2
  fi
done
# Audit H3: the OUTPUT DNS-capture marking must exempt the aegis-client's OWN
# loop traffic while still capturing ordinary root-owned app DNS. The default
# uid=0 exemption is overly broad — it exempts ALL root traffic, so root apps
# leak DNS outside the tunnel. When the client's cgroup is known (it runs as a
# systemd service), prefer a cgroup match that exempts ONLY the client service
# and captures everything else. Falls back to the uid match for compatibility.
EXEMPT_CGROUP="${AEGIS_WIDE_EXEMPT_CGROUP:-}"
if [[ -n "${EXEMPT_CGROUP}" && ! "${EXEMPT_CGROUP}" =~ ^[A-Za-z0-9._/@:-]+$ ]]; then
  echo "FATAL: AEGIS_WIDE_EXEMPT_CGROUP has invalid characters (got '${EXEMPT_CGROUP}')" >&2
  exit 2
fi
if [[ -n "${EXEMPT_CGROUP}" ]]; then
  EXEMPT_MATCH=(-m cgroup ! --path "${EXEMPT_CGROUP}")
else
  EXEMPT_MATCH=(-m owner ! --uid-owner "${LOCAL_OUTPUT_EXEMPT_UID}")
fi
IPV6_POLICY="${AEGIS_WIDE_IPV6_POLICY:-out_of_scope}"
EXTRA_UDP_PREVIEW_PORTS_RAW="${AEGIS_UDP_PREVIEW_PORTS:-}"
SSH_SAFE_PORTS_RAW="${AEGIS_WIDE_SSH_SAFE_PORTS-22}"
DANGEROUS_PUBLIC_APPLY="${AEGIS_WIDE_DANGEROUS_PUBLIC_APPLY:-0}"
CLIENT_CONFIG="${AEGIS_CLIENT_CONFIG:-$(default_installed_client_config)}"
CLIENT_BIN_OVERRIDE="${AEGIS_CLIENT_BIN:-}"
RUNTIME_EVENTS_JSONL="${AEGIS_RUNTIME_EVENTS_JSONL:-$(default_runtime_events_jsonl)}"
ENABLE_RUNTIME_EVENTS_JSONL="${AEGIS_ENABLE_RUNTIME_EVENTS_JSONL:-1}"
# Detailed logs are an explicit operator opt-in, including synthetic smoke runs.
DIAGNOSTIC_LOGS="${AEGIS_DIAGNOSTIC_LOGS-0}"
if [[ "${DIAGNOSTIC_LOGS}" != "0" && "${DIAGNOSTIC_LOGS}" != "1" ]]; then
  echo "AEGIS_DIAGNOSTIC_LOGS must be 0 or 1" >&2
  exit 2
fi
RUNTIME_EVENTS_LIMIT="${AEGIS_RUNTIME_EVENTS_LIMIT:-40}"
OPERATOR_EVIDENCE_JSON="${AEGIS_OPERATOR_EVIDENCE_JSON:-${RUNTIME_EVENTS_JSONL}.operator-evidence.json}"

CFG_INGRESS_PRIMARY=""
CFG_WIDE_ENABLED=""
CFG_WIDE_BACKEND=""
CFG_WIDE_PROFILE=""
CFG_WIDE_INTERFACE=""
CFG_WIDE_LISTEN_PORT=""
CFG_WIDE_LISTEN_FAMILY=""
CFG_CAPTURE_DNS=""
CFG_DNS_PORT=""
CFG_UDP_CAPTURE_CONTRACT=""
CFG_UDP_CAPTURE_SUPPORT_TIER=""
CFG_UDP_CAPTURE_POLICY=""
CFG_UDP_CAPTURE_RUNTIME_SCOPE=""
CFG_UDP_PREVIEW_PORTS=""
CFG_DEFAULT_MARK=""
EXTRA_UDP_PREVIEW_PORTS=()
NORMALIZED_EXTRA_UDP_PREVIEW_PORTS=""
SSH_SAFE_PORTS=()
NORMALIZED_SSH_SAFE_PORTS=""
EFFECTIVE_IP_FAMILY=""
EFFECTIVE_FIREWALL_BACKEND=""
NFT_TABLE="${AEGIS_WIDE_NFT_TABLE:-aegis_wide_tproxy}"
NFT_PREROUTING_CHAIN="${AEGIS_WIDE_NFT_PREROUTING_CHAIN:-prerouting}"
FIREWALLD_STATE_FILE_OVERRIDE="${AEGIS_WIDE_FIREWALLD_STATE_FILE:-}"

PROBE_STATUS=""
PROBE_CODE=""
PROBE_STARTED_BACKEND=""
PROBE_FAILURE_CODE=""
PROBE_HINT_CODE=""
PROBE_MESSAGE=""
PROBE_HINT=""
PROBE_DNS_STATUS=""
PROBE_UDP_CAPTURE_CONTRACT=""
PROBE_UDP_CAPTURE_SUPPORT_TIER=""
PROBE_UDP_CAPTURE_POLICY=""
PROBE_UDP_CAPTURE_RUNTIME_SCOPE=""
PROBE_EXIT_CODE=0
EVENTS_TOTAL="0"
EVENTS_LATEST_CODE=""
EVENTS_LATEST_LEVEL=""
EVENTS_LATEST_MESSAGE=""
EVENTS_BACKEND=""
EVENTS_BACKEND_RUNTIME_ID=""
EVENTS_BACKEND_DNS_STATUS=""
EVENTS_BACKEND_UDP_CAPTURE_CONTRACT=""
EVENTS_BACKEND_UDP_CAPTURE_SUPPORT_TIER=""
EVENTS_BACKEND_UDP_CAPTURE_POLICY=""
EVENTS_BACKEND_UDP_CAPTURE_RUNTIME_SCOPE=""
EVENTS_PROBLEM_CODE=""
EVENTS_PROBLEM_LEVEL=""
EVENTS_PROBLEM_MESSAGE=""
EVENTS_PROBLEM_BIND_ERROR_CODE=""
EVENTS_PROBLEM_BIND_HINT_CODE=""
EVENTS_PROBLEM_SELECTION_ERROR_CODE=""
EVENTS_PROBLEM_SELECTION_HINT_CODE=""
EVENTS_PROBLEM_DROP_REASON_CODE=""
EVENTS_PROBLEM_CAPTURE_DROP_STAGE=""
EVENTS_PROBLEM_CAPTURE_DROP_REASON_CODE=""
EVENTS_PROBLEM_UDP_CAPTURE_CONTRACT=""
EVENTS_PROBLEM_UDP_CAPTURE_SUPPORT_TIER=""
EVENTS_PROBLEM_UDP_CAPTURE_POLICY=""
EVENTS_PROBLEM_UDP_CAPTURE_RUNTIME_SCOPE=""
EVENTS_PROBLEM_UDP_PREVIEW_POLICY=""
EVENTS_PROBLEM_HINT=""
EVENTS_PROBLEM_TRANSPORT=""
EVENTS_PROBLEM_RELAY_SERVER=""
EVENTS_PROBLEM_RELAY_ERROR_KIND=""
EVENTS_PROBLEM_SESSION_ERROR_KIND=""
EVENTS_PROBLEM_ERROR=""
EVENTS_PROBLEM_BACKEND=""
EVENTS_PROBLEM_RELAY_LAST_TRANSPORT=""
EVENTS_PROBLEM_ATTEMPT_INDEX=""
EVENTS_PROBLEM_ATTEMPTS_TOTAL=""
EVENTS_PROBLEM_EXPECTED_DNS_PORT=""
EVENTS_PROBLEM_EXPECTED_UDP_PREVIEW_PORTS=""
LAUNCH_CMD=()
CLIENT_EXEC_PREFIX=()

if [[ -z "${ACTION}" || ( "${ACTION}" != "apply" && "${ACTION}" != "teardown" && "${ACTION}" != "status" && "${ACTION}" != "doctor" && "${ACTION}" != "probe" && "${ACTION}" != "launch" && "${ACTION}" != "events" && "${ACTION}" != "run" ) ]]; then
  echo "Usage: sudo $0 apply|teardown|status|doctor|probe|launch|events|run" >&2
  exit 1
fi

# Reject malformed policy before probing host tooling. This keeps operator
# input errors deterministic even on unsupported/non-Linux audit hosts.
case "${IPV6_POLICY}" in
  out_of_scope|block|capture)
    ;;
  *)
    echo "AEGIS_WIDE_IPV6_POLICY must be out_of_scope, block, or capture (got ${IPV6_POLICY})" >&2
    exit 1
    ;;
esac

if ! command -v ip >/dev/null 2>&1; then
  echo "iproute2 is required" >&2
  exit 1
fi

detect_default_interface() {
  if [[ "${EFFECTIVE_IP_FAMILY:-ipv4}" == "ipv6" ]]; then
    ip -6 route show default 2>/dev/null | awk '/default/ {print $5; exit}'
  else
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
  fi
}

resolve_listen_family() {
  local listen="$1"
  if [[ -z "${listen}" ]]; then
    return 0
  fi
  if [[ "${listen}" == \[*\]:* ]]; then
    echo "ipv6"
  else
    echo "ipv4"
  fi
}

firewall_bin() {
  local family="${1:-${EFFECTIVE_IP_FAMILY:-ipv4}}"
  case "${family}" in
    ipv4) echo "iptables" ;;
    ipv6) echo "ip6tables" ;;
    *)
      echo "unsupported helper IP family: ${family}" >&2
      return 1
      ;;
  esac
}

xtables_tproxy_on_ip_args() {
  case "${EFFECTIVE_IP_FAMILY}" in
    ipv6)
      # Match the explicit IPv6 probe contract: ip6tables TPROXY is materially
      # more reliable when the interception address is spelled out instead of
      # relying on userspace/kernel defaults.
      echo "--on-ip ::"
      ;;
    *)
      echo ""
      ;;
  esac
}

resolve_firewall_family() {
  if [[ "${EFFECTIVE_IP_FAMILY}" == "ipv6" ]]; then
    echo "ip6"
  else
    echo "ip"
  fi
}

resolve_firewall_backend() {
  case "${FIREWALL_BACKEND_REQUESTED}" in
    auto)
      if command -v "$(firewall_bin "${EFFECTIVE_IP_FAMILY}")" >/dev/null 2>&1; then
        EFFECTIVE_FIREWALL_BACKEND="xtables"
      elif command -v nft >/dev/null 2>&1; then
        EFFECTIVE_FIREWALL_BACKEND="nft"
      else
        echo "$(firewall_bin "${EFFECTIVE_IP_FAMILY}") or nft is required for ${EFFECTIVE_IP_FAMILY} TPROXY helper mode" >&2
        exit 1
      fi
      ;;
    xtables|nft)
      EFFECTIVE_FIREWALL_BACKEND="${FIREWALL_BACKEND_REQUESTED}"
      ;;
    *)
      echo "AEGIS_WIDE_FIREWALL_BACKEND must be auto, xtables, or nft (got ${FIREWALL_BACKEND_REQUESTED})" >&2
      exit 1
      ;;
  esac

  # Even the native nft TPROXY backend installs its narrowly-scoped INPUT
  # allow rule through iptables/ip6tables. On distributions using UFW this puts
  # the rule inside the same INPUT base chain, before UFW's default DROP. An
  # ACCEPT in a separate nft base chain would not override a later DROP.
  if ! command -v "$(firewall_bin "${EFFECTIVE_IP_FAMILY}")" >/dev/null 2>&1; then
    echo "$(firewall_bin "${EFFECTIVE_IP_FAMILY}") is required for the ${EFFECTIVE_IP_FAMILY} TPROXY INPUT delivery path" >&2
    exit 1
  fi
  if [[ "${EFFECTIVE_FIREWALL_BACKEND}" == "nft" ]] && ! command -v nft >/dev/null 2>&1; then
    echo "nft is required for nft helper mode" >&2
    exit 1
  fi

  # The nft backend emits `tproxy` + `socket transparent` expressions, which need
  # the nft_tproxy + nft_socket kernel modules. Custom kernels (notably some
  # Raspberry Pi builds) may not ship them, and nothing else loads or checks
  # them — apply would then fail half-way under `set -e`, leaving a partly-built
  # table. Best-effort load, then PROBE that the kernel really supports the
  # tproxy expression, and fail fast with an actionable message if not.
  if [[ "${EFFECTIVE_FIREWALL_BACKEND}" == "nft" ]]; then
    modprobe nft_tproxy 2>/dev/null || true
    modprobe nft_socket 2>/dev/null || true
    local _probe="aegis_tproxy_probe_$$"
    if nft add table ip "${_probe}" 2>/dev/null; then
      if ! nft "add chain ip ${_probe} c { type filter hook prerouting priority -150 ; }" 2>/dev/null \
         || ! nft add rule ip "${_probe}" c meta l4proto tcp tproxy to :1 2>/dev/null; then
        nft delete table ip "${_probe}" 2>/dev/null || true
        echo "FATAL: this kernel lacks nft TPROXY support (nft_tproxy/nft_socket)." >&2
        echo "  gateway-tproxy cannot capture without it. Install a kernel/module with" >&2
        echo "  CONFIG_NFT_TPROXY + CONFIG_NFT_SOCKET, or use a host that provides them." >&2
        exit 1
      fi
      nft delete table ip "${_probe}" 2>/dev/null || true
    fi
  fi
}

render_firewall_backend() {
  if [[ "${EFFECTIVE_FIREWALL_BACKEND}" == "nft" ]]; then
    echo "nft"
  else
    echo "xtables:$(firewall_bin)"
  fi
}

render_firewall_surface() {
  if [[ "${EFFECTIVE_FIREWALL_BACKEND}" == "nft" ]]; then
    echo "nft $(resolve_firewall_family)/${NFT_TABLE}"
  else
    echo "$(firewall_bin) mangle"
  fi
}

render_udp_capture_runtime_scope() {
  if [[ "${EFFECTIVE_IP_FAMILY}" == "ipv6" ]]; then
    echo "linux_ipv6_only"
  else
    echo "linux_ipv4_only"
  fi
}

render_udp_capture_support_tier() {
  if [[ "${UDP_CAPTURE_CONTRACT}" == "generic_capture_unstable" ]]; then
    echo "guarded_unstable"
  else
    echo "supported_preview"
  fi
}

render_udp_capture_policy() {
  if [[ "${UDP_CAPTURE_CONTRACT}" == "generic_capture_unstable" ]]; then
    if [[ "${EFFECTIVE_IP_FAMILY}" == "ipv6" ]]; then
      echo "any_target_port_linux_ipv6_unstable"
    else
      echo "any_target_port_linux_ipv4_unstable"
    fi
  else
    echo "allowlist_ports"
  fi
}

udp_capture_uses_preview_allowlist() {
  [[ "${UDP_CAPTURE_CONTRACT}" != "generic_capture_unstable" ]]
}

helper_intercepts_all_udp() {
  [[ "${UDP_CAPTURE_CONTRACT}" == "generic_capture_unstable" || "${FORCE_ALL_UDP_TPROXY}" == "1" ]]
}

resolve_effective_ip_family() {
  local inferred_family=""
  case "${IP_FAMILY_REQUESTED}" in
    auto)
      if [[ -n "${CFG_WIDE_LISTEN_FAMILY}" ]]; then
        inferred_family="${CFG_WIDE_LISTEN_FAMILY}"
      else
        inferred_family="ipv4"
      fi
      ;;
    ipv4|ipv6)
      inferred_family="${IP_FAMILY_REQUESTED}"
      ;;
    *)
      echo "AEGIS_WIDE_IP_FAMILY must be auto, ipv4, or ipv6 (got ${IP_FAMILY_REQUESTED})" >&2
      exit 1
      ;;
  esac

  if [[ "${IP_FAMILY_REQUESTED}" != "auto" && -n "${CFG_WIDE_LISTEN_FAMILY}" && "${IP_FAMILY_REQUESTED}" != "${CFG_WIDE_LISTEN_FAMILY}" ]]; then
    echo "AEGIS_WIDE_IP_FAMILY=${IP_FAMILY_REQUESTED} does not match client listen family ${CFG_WIDE_LISTEN_FAMILY}" >&2
    exit 1
  fi

  EFFECTIVE_IP_FAMILY="${inferred_family}"
}

require_numeric_port() {
  local name="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[0-9]+$ ]] || (( value < 1 || value > 65535 )); then
    echo "${name} must be a TCP/UDP port in range 1..65535 (got ${value})" >&2
    exit 1
  fi
}

require_numeric_id() {
  local name="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[0-9]+$ ]]; then
    echo "${name} must be numeric (got ${value})" >&2
    exit 1
  fi
}

normalize_extra_udp_preview_ports() {
  local raw=""
  local port=""
  local existing=""
  local rendered=""

  EXTRA_UDP_PREVIEW_PORTS=()
  NORMALIZED_EXTRA_UDP_PREVIEW_PORTS=""
  [[ -z "${EXTRA_UDP_PREVIEW_PORTS_RAW}" ]] && return 0

  IFS=',' read -r -a EXTRA_UDP_PREVIEW_PORT_CANDIDATES <<< "${EXTRA_UDP_PREVIEW_PORTS_RAW}"
  for raw in "${EXTRA_UDP_PREVIEW_PORT_CANDIDATES[@]}"; do
    port="${raw//[[:space:]]/}"
    require_numeric_port "AEGIS_UDP_PREVIEW_PORTS" "${port}"
    if [[ "${port}" == "${DNS_PORT}" ]]; then
      continue
    fi
    for existing in "${EXTRA_UDP_PREVIEW_PORTS[@]:-}"; do
      [[ -n "${existing}" ]] || continue
      if [[ "${existing}" == "${port}" ]]; then
        port=""
        break
      fi
    done
    if [[ -n "${port}" ]]; then
      EXTRA_UDP_PREVIEW_PORTS+=("${port}")
    fi
  done

  for port in "${EXTRA_UDP_PREVIEW_PORTS[@]:-}"; do
    [[ -n "${port}" ]] || continue
    if [[ -n "${rendered}" ]]; then
      rendered="${rendered},"
    fi
    rendered="${rendered}${port}"
  done
  NORMALIZED_EXTRA_UDP_PREVIEW_PORTS="${rendered}"
}

normalize_ssh_safe_ports() {
  local raw=""
  local port=""
  local existing=""
  local rendered=""

  SSH_SAFE_PORTS=()
  NORMALIZED_SSH_SAFE_PORTS=""
  [[ -z "${SSH_SAFE_PORTS_RAW}" ]] && return 0

  IFS=',' read -r -a SSH_SAFE_PORT_CANDIDATES <<< "${SSH_SAFE_PORTS_RAW}"
  for raw in "${SSH_SAFE_PORT_CANDIDATES[@]}"; do
    port="${raw//[[:space:]]/}"
    [[ -n "${port}" ]] || continue
    require_numeric_port "AEGIS_WIDE_SSH_SAFE_PORTS" "${port}"
    for existing in "${SSH_SAFE_PORTS[@]:-}"; do
      [[ -n "${existing}" ]] || continue
      if [[ "${existing}" == "${port}" ]]; then
        port=""
        break
      fi
    done
    if [[ -n "${port}" ]]; then
      SSH_SAFE_PORTS+=("${port}")
    fi
  done

  for port in "${SSH_SAFE_PORTS[@]:-}"; do
    [[ -n "${port}" ]] || continue
    if [[ -n "${rendered}" ]]; then
      rendered="${rendered},"
    fi
    rendered="${rendered}${port}"
  done
  NORMALIZED_SSH_SAFE_PORTS="${rendered}"
}

interface_looks_public_host_path() {
  local candidate_iface=""
  candidate_iface="$(detect_default_interface || true)"
  [[ -n "${INTERFACE}" && -n "${candidate_iface}" && "${INTERFACE}" == "${candidate_iface}" ]]
}

validate_contract() {
  local candidate_iface=""
  local public_host_path=0
  require_numeric_port "AEGIS_WIDE_PORT" "${WIDE_PORT}"
  require_numeric_port "AEGIS_DNS_PORT" "${DNS_PORT}"
  normalize_extra_udp_preview_ports
  normalize_ssh_safe_ports
  require_numeric_id "AEGIS_WIDE_FWMARK" "${FWMARK}"
  require_numeric_id "AEGIS_WIDE_ROUTE_TABLE" "${ROUTE_TABLE}"
  resolve_effective_ip_family
  resolve_firewall_backend

  if [[ "${FORCE_ALL_UDP_TPROXY}" != "0" && "${FORCE_ALL_UDP_TPROXY}" != "1" ]]; then
    echo "AEGIS_WIDE_FORCE_ALL_UDP_TPROXY must be 0 or 1 (got ${FORCE_ALL_UDP_TPROXY})" >&2
    exit 1
  fi

  case "${UDP_CAPTURE_CONTRACT}" in
    preview_allowlist_only|generic_capture_unstable)
      ;;
    *)
      echo "AEGIS_UDP_CAPTURE_CONTRACT must be preview_allowlist_only or generic_capture_unstable (got ${UDP_CAPTURE_CONTRACT})" >&2
      exit 1
      ;;
  esac

  if (( FWMARK == 0 )); then
    echo "AEGIS_WIDE_FWMARK must be non-zero for the transparent_privileged TPROXY contract" >&2
    exit 1
  fi

  case "${ALLOW_ALL_INTERFACES}" in
    0|1)
      ;;
    *)
      echo "AEGIS_WIDE_ALLOW_ALL_INTERFACES must be 0 or 1 (got ${ALLOW_ALL_INTERFACES})" >&2
      exit 1
      ;;
  esac

  case "${DANGEROUS_PUBLIC_APPLY}" in
    0|1)
      ;;
    *)
      echo "AEGIS_WIDE_DANGEROUS_PUBLIC_APPLY must be 0 or 1 (got ${DANGEROUS_PUBLIC_APPLY})" >&2
      exit 1
      ;;
  esac

  if [[ "${ACTION}" == "apply" && -z "${INTERFACE}" ]]; then
    candidate_iface="$(detect_default_interface || true)"
    if [[ "${ALLOW_ALL_INTERFACES}" == "1" ]]; then
      echo "WARN: AEGIS_WIDE_ALLOW_ALL_INTERFACES=1 enables an intentionally unsafe all-interface PREROUTING helper scope" >&2
      if [[ -n "${candidate_iface}" ]]; then
        echo "Assisted detect: Linux default route suggests interface ${candidate_iface}" >&2
      fi
      echo "Supported happy-path still requires explicit AEGIS_WIDE_INTERFACE=<iface> aligned with ingress.wide.prerouting_interface" >&2
    else
      echo "AEGIS_WIDE_INTERFACE is required for the supported linux_tproxy helper path" >&2
      if [[ -n "${candidate_iface}" ]]; then
        echo "Assisted detect: Linux default route suggests interface ${candidate_iface}" >&2
      fi
      echo "Set AEGIS_WIDE_INTERFACE=<iface> so helper scope matches ingress.wide.prerouting_interface" >&2
      echo "If you intentionally need a lab-only all-interface PREROUTING run, set AEGIS_WIDE_ALLOW_ALL_INTERFACES=1 explicitly" >&2
      exit 1
    fi
  fi

  if [[ -n "${INTERFACE}" ]] && interface_looks_public_host_path; then
    public_host_path=1
  fi

  if [[ "${ACTION}" == "apply" && "${public_host_path}" == "1" ]]; then
    if [[ "${ALLOW_ALL_INTERFACES}" == "1" && "${DANGEROUS_PUBLIC_APPLY}" != "1" ]]; then
      echo "Refusing blind linux_tproxy apply on the default/public interface with AEGIS_WIDE_ALLOW_ALL_INTERFACES=1" >&2
      echo "Keep explicit interface scope plus SSH-safe bypass ports, or rerun with AEGIS_WIDE_DANGEROUS_PUBLIC_APPLY=1 for lab-only recovery-risk mode" >&2
      exit 1
    fi
    if [[ -z "${NORMALIZED_SSH_SAFE_PORTS}" && "${DANGEROUS_PUBLIC_APPLY}" != "1" ]]; then
      echo "Refusing blind linux_tproxy apply on the default/public interface without SSH-safe bypass ports" >&2
      echo "Set AEGIS_WIDE_SSH_SAFE_PORTS=22 (or your operator port list), or rerun with AEGIS_WIDE_DANGEROUS_PUBLIC_APPLY=1 for lab-only recovery-risk mode" >&2
      exit 1
    fi
  fi
}

print_contract_summary() {
  echo "TPROXY helper contract:"
  echo "  ip_family=${EFFECTIVE_IP_FAMILY}"
  echo "  firewall_backend=$(render_firewall_backend)"
  echo "  listen_port=${WIDE_PORT}"
  echo "  fwmark=${FWMARK}"
  echo "  route_table=${ROUTE_TABLE}"
  echo "  ipv6_policy=${IPV6_POLICY}"
  echo "  ssh_safe_ports=${NORMALIZED_SSH_SAFE_PORTS:-<none>}"
  echo "  dangerous_public_apply_opt_in=${DANGEROUS_PUBLIC_APPLY}"
  if [[ -n "${INTERFACE}" ]]; then
    echo "  scope_mode=explicit_interface"
    echo "  prerouting_interface=${INTERFACE}"
  elif [[ "${ALLOW_ALL_INTERFACES}" == "1" ]]; then
    echo "  scope_mode=all_interfaces_unsafe_opt_in"
    echo "  prerouting_interface=<all-interfaces>"
  else
    echo "  scope_mode=interface_unset"
    echo "  prerouting_interface=<unset>"
  fi
  echo "  dns_preview=${ENABLE_DNS_PREVIEW}"
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    echo "  udp_capture_contract=${UDP_CAPTURE_CONTRACT}"
    echo "  wide_udp_capture_support_tier=$(render_udp_capture_support_tier)"
    echo "  wide_udp_capture_policy=$(render_udp_capture_policy)"
    echo "  wide_udp_capture_runtime_scope=$(render_udp_capture_runtime_scope)"
    if udp_capture_uses_preview_allowlist; then
      echo "  dns_port=${DNS_PORT}"
      echo "  udp_preview_ports=${NORMALIZED_EXTRA_UDP_PREVIEW_PORTS:-<none>}"
    else
      echo "  dns_port=<ignored_by_generic_capture_contract>"
      echo "  udp_preview_ports=<ignored_by_generic_capture_contract>"
    fi
    if [[ "${FORCE_ALL_UDP_TPROXY}" == "1" ]]; then
      echo "  udp_firewall_scope=all_target_ports_for_runtime_drop_smoke"
    fi
  fi
}

print_next_steps() {
  local extra_udp_preview_env=""
  local udp_capture_contract_env=""
  local force_all_udp_env=""
  local allow_all_interfaces_env=""
  local ssh_safe_ports_env=""
  local dangerous_public_apply_env=""
  local owned_firewall_env=" AEGIS_WIDE_CHAIN=\"${CHAIN}\" AEGIS_WIDE_INPUT_CHAIN=\"${INPUT_CHAIN}\""
  local ip_family_env=" AEGIS_WIDE_IP_FAMILY=\"${EFFECTIVE_IP_FAMILY}\""
  local firewall_backend_env=" AEGIS_WIDE_FIREWALL_BACKEND=\"${EFFECTIVE_FIREWALL_BACKEND}\""
  local dns_preview_env=" AEGIS_ENABLE_DNS_PREVIEW=\"${ENABLE_DNS_PREVIEW}\""
  local dns_port_env=""
  if [[ -n "${FIREWALLD_STATE_FILE_OVERRIDE}" ]]; then
    owned_firewall_env+=" AEGIS_WIDE_FIREWALLD_STATE_FILE=\"${FIREWALLD_STATE_FILE_OVERRIDE}\""
  fi
  if [[ "${ALLOW_ALL_INTERFACES}" == "1" ]]; then
    allow_all_interfaces_env=" AEGIS_WIDE_ALLOW_ALL_INTERFACES=\"1\""
  fi
  if [[ -n "${NORMALIZED_SSH_SAFE_PORTS}" ]]; then
    ssh_safe_ports_env=" AEGIS_WIDE_SSH_SAFE_PORTS=\"${NORMALIZED_SSH_SAFE_PORTS}\""
  fi
  if [[ "${DANGEROUS_PUBLIC_APPLY}" == "1" ]]; then
    dangerous_public_apply_env=" AEGIS_WIDE_DANGEROUS_PUBLIC_APPLY=\"1\""
  fi
  if udp_capture_uses_preview_allowlist && [[ -n "${NORMALIZED_EXTRA_UDP_PREVIEW_PORTS}" ]]; then
    extra_udp_preview_env=" AEGIS_UDP_PREVIEW_PORTS=\"${NORMALIZED_EXTRA_UDP_PREVIEW_PORTS}\""
  fi
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    udp_capture_contract_env=" AEGIS_UDP_CAPTURE_CONTRACT=\"${UDP_CAPTURE_CONTRACT}\""
    if udp_capture_uses_preview_allowlist; then
      dns_port_env=" AEGIS_DNS_PORT=\"${DNS_PORT}\""
    fi
  fi
  if [[ "${FORCE_ALL_UDP_TPROXY}" == "1" ]]; then
    force_all_udp_env=" AEGIS_WIDE_FORCE_ALL_UDP_TPROXY=\"1\""
  fi
  echo "Next commands:"
  echo "  status: sudo AEGIS_WIDE_PORT=\"${WIDE_PORT}\" AEGIS_WIDE_FWMARK=\"${FWMARK}\" AEGIS_WIDE_ROUTE_TABLE=\"${ROUTE_TABLE}\" AEGIS_WIDE_INTERFACE=\"${INTERFACE}\"${owned_firewall_env}${allow_all_interfaces_env}${ssh_safe_ports_env}${dangerous_public_apply_env}${ip_family_env}${firewall_backend_env}${dns_preview_env}${dns_port_env}${udp_capture_contract_env}${extra_udp_preview_env}${force_all_udp_env} $0 status"
  echo "  doctor: sudo AEGIS_WIDE_PORT=\"${WIDE_PORT}\" AEGIS_WIDE_FWMARK=\"${FWMARK}\" AEGIS_WIDE_ROUTE_TABLE=\"${ROUTE_TABLE}\" AEGIS_WIDE_INTERFACE=\"${INTERFACE}\"${owned_firewall_env}${allow_all_interfaces_env}${ssh_safe_ports_env}${dangerous_public_apply_env}${ip_family_env}${firewall_backend_env}${dns_preview_env}${dns_port_env}${udp_capture_contract_env}${extra_udp_preview_env}${force_all_udp_env} AEGIS_CLIENT_CONFIG=\"${CLIENT_CONFIG}\" $0 doctor"
  if [[ -n "${CLIENT_CONFIG}" ]]; then
    # The probe should run with the same privilege model as the real client
    # launch, otherwise IP_TRANSPARENT/capability failures may hide.
    echo "  probe: AEGIS_CLIENT_CONFIG=\"${CLIENT_CONFIG}\" $0 probe"
    echo "  run: AEGIS_CLIENT_CONFIG=\"${CLIENT_CONFIG}\" AEGIS_RUNTIME_EVENTS_JSONL=\"${RUNTIME_EVENTS_JSONL}\" $0 run"
    echo "  launch: AEGIS_CLIENT_CONFIG=\"${CLIENT_CONFIG}\" AEGIS_RUNTIME_EVENTS_JSONL=\"${RUNTIME_EVENTS_JSONL}\" $0 launch"
    echo "  events: AEGIS_RUNTIME_EVENTS_JSONL=\"${RUNTIME_EVENTS_JSONL}\" $0 events"
  fi
  echo "  teardown: sudo AEGIS_WIDE_PORT=\"${WIDE_PORT}\" AEGIS_WIDE_FWMARK=\"${FWMARK}\" AEGIS_WIDE_ROUTE_TABLE=\"${ROUTE_TABLE}\" AEGIS_WIDE_INTERFACE=\"${INTERFACE}\"${owned_firewall_env}${allow_all_interfaces_env}${ssh_safe_ports_env}${dangerous_public_apply_env}${ip_family_env}${firewall_backend_env}${dns_preview_env}${dns_port_env}${udp_capture_contract_env}${extra_udp_preview_env}${force_all_udp_env} $0 teardown"
}

selected_client_binary() {
  local client=""
  if [[ "${EUID}" == 0 ]]; then
    client="${CLIENT_BIN_OVERRIDE:-${AEGIS_ROOT_STATE_CLIENT:-/usr/local/bin/aegis-client}}"
    aegis_root_trusted_executable "${client}" || return 127
    "${client}" profile metadata --help >/dev/null || return 127
  elif [[ -n "${CLIENT_BIN_OVERRIDE}" ]]; then
    client="${CLIENT_BIN_OVERRIDE}"
  elif [[ -n "${AEGIS_ROOT_STATE_CLIENT:-}" ]]; then
    client="${AEGIS_ROOT_STATE_CLIENT}"
  elif type -P aegis-client >/dev/null 2>&1; then
    client="$(type -P aegis-client)"
  elif [[ -x "${ROOT}/bin/aegis-client" ]]; then
    client="${ROOT}/bin/aegis-client"
  else
    return 127
  fi
  [[ -x "${client}" && -f "${client}" ]] || return 127
  printf '%s\n' "${client}"
}

run_client_contract_parser() {
  local client=""
  # The doctor contract must come from the same executable selected for
  # probe/run. A separate measure binary may parse TOML successfully while
  # the installed client rejects that configuration or lacks this command.
  client="$(selected_client_binary)" || return 127
  "${client}" profile tproxy-contract --config "${CLIENT_CONFIG}"
}

load_client_contract() {
  local strict_contract=0
  if [[ "${ACTION}" == apply || "${ACTION}" == run ]]; then strict_contract=1; fi
  if [[ -z "${CLIENT_CONFIG}" ]]; then
    if (( strict_contract )); then
      echo "ERROR: AEGIS_CLIENT_CONFIG is required; refusing ${ACTION}" >&2
      return 1
    fi
    return 0
  fi
  if [[ ! -f "${CLIENT_CONFIG}" ]]; then
    if (( strict_contract )); then
      echo "ERROR: configured client file is unavailable; refusing ${ACTION}" >&2
      return 1
    fi
    echo "WARN: AEGIS_CLIENT_CONFIG points to a missing file: ${CLIENT_CONFIG}" >&2
    return 0
  fi
  local parsed
  parsed="$(run_client_contract_parser)" || {
    if (( strict_contract )); then
      echo "ERROR: selected client rejected the config contract; refusing ${ACTION}" >&2
      return 1
    fi
    echo "WARN: failed to parse AEGIS_CLIENT_CONFIG=${CLIENT_CONFIG}; client contract checks are skipped" >&2
    return 0
  }
  if [[ -z "${parsed}" ]]; then
    if (( strict_contract )); then
      echo "ERROR: selected client returned an empty config contract; refusing ${ACTION}" >&2
      return 1
    fi
    echo "WARN: failed to parse AEGIS_CLIENT_CONFIG=${CLIENT_CONFIG}; client contract checks are skipped" >&2
    return 0
  fi

  while IFS=$'\t' read -r key value; do
    case "${key}" in
      CFG_INGRESS_PRIMARY) CFG_INGRESS_PRIMARY="${value}" ;;
      CFG_WIDE_ENABLED) CFG_WIDE_ENABLED="${value}" ;;
      CFG_WIDE_BACKEND) CFG_WIDE_BACKEND="${value}" ;;
      CFG_WIDE_PROFILE) CFG_WIDE_PROFILE="${value}" ;;
      CFG_WIDE_INTERFACE) CFG_WIDE_INTERFACE="${value}" ;;
      CFG_WIDE_LISTEN_PORT) CFG_WIDE_LISTEN_PORT="${value}" ;;
      CFG_WIDE_LISTEN_FAMILY) CFG_WIDE_LISTEN_FAMILY="${value}" ;;
      CFG_CAPTURE_DNS) CFG_CAPTURE_DNS="${value}" ;;
      CFG_UDP_CAPTURE_CONTRACT) CFG_UDP_CAPTURE_CONTRACT="${value}" ;;
      CFG_UDP_CAPTURE_SUPPORT_TIER) CFG_UDP_CAPTURE_SUPPORT_TIER="${value}" ;;
      CFG_UDP_CAPTURE_POLICY) CFG_UDP_CAPTURE_POLICY="${value}" ;;
      CFG_UDP_CAPTURE_RUNTIME_SCOPE) CFG_UDP_CAPTURE_RUNTIME_SCOPE="${value}" ;;
      CFG_DNS_PORT) CFG_DNS_PORT="${value}" ;;
      CFG_UDP_PREVIEW_PORTS) CFG_UDP_PREVIEW_PORTS="${value}" ;;
      CFG_DEFAULT_MARK) CFG_DEFAULT_MARK="${value}" ;;
    esac
  done <<< "${parsed}"
  if (( strict_contract )) && ! client_contract_complete; then
    echo "ERROR: selected client returned an incomplete config contract; refusing ${ACTION}" >&2
    return 1
  fi
  if (( strict_contract )) &&
    { [[ "${CFG_INGRESS_PRIMARY}" != wide || "${CFG_WIDE_ENABLED}" != 1 ||
      "${CFG_WIDE_BACKEND}" != linux_tproxy || "${CFG_WIDE_PROFILE}" != transparent_privileged ]]; }; then
    echo "ERROR: selected client is not configured for active privileged Linux TPROXY; refusing ${ACTION}" >&2
    return 1
  fi
}

# A configured doctor result cannot attest host/client alignment when the
# parser was unavailable or omitted the fields used for essential checks.
# Optional DNS/UDP detail remains conditional on the declared capture contract.
client_contract_complete() {
  [[ -n "${CFG_INGRESS_PRIMARY}" && ( "${CFG_WIDE_ENABLED}" == "0" || "${CFG_WIDE_ENABLED}" == "1" ) \
    && -n "${CFG_WIDE_BACKEND}" && -n "${CFG_WIDE_PROFILE}" \
    && -n "${CFG_WIDE_INTERFACE}" && -n "${CFG_WIDE_LISTEN_PORT}" \
    && -n "${CFG_WIDE_LISTEN_FAMILY}" && -n "${CFG_UDP_CAPTURE_CONTRACT}" \
    && ( "${CFG_CAPTURE_DNS}" == "0" || "${CFG_CAPTURE_DNS}" == "1" ) ]]
}

print_client_contract_summary() {
  if [[ -z "${CLIENT_CONFIG}" ]]; then
    return 0
  fi
  echo "Client config contract:"
  echo "  config_path=${CLIENT_CONFIG}"
  echo "  config_ingress_primary=${CFG_INGRESS_PRIMARY:-<unknown>}"
  echo "  config_wide_enabled=${CFG_WIDE_ENABLED:-<unknown>}"
  echo "  config_backend=${CFG_WIDE_BACKEND:-<unknown>}"
  echo "  config_rollout_profile=${CFG_WIDE_PROFILE:-<unknown>}"
  echo "  config_prerouting_interface=${CFG_WIDE_INTERFACE:-<none>}"
  echo "  config_listen_port=${CFG_WIDE_LISTEN_PORT:-<unknown>}"
  echo "  config_listen_family=${CFG_WIDE_LISTEN_FAMILY:-<unknown>}"
  echo "  config_default_mark=${CFG_DEFAULT_MARK:-<unknown>}"
  echo "  config_capture_dns=${CFG_CAPTURE_DNS:-<unknown>}"
  echo "  config_udp_capture_contract=${CFG_UDP_CAPTURE_CONTRACT:-<unknown>}"
  echo "  config_udp_capture_support_tier=${CFG_UDP_CAPTURE_SUPPORT_TIER:-<unknown>}"
  echo "  config_udp_capture_policy=${CFG_UDP_CAPTURE_POLICY:-<unknown>}"
  echo "  config_udp_capture_runtime_scope=${CFG_UDP_CAPTURE_RUNTIME_SCOPE:-<unknown>}"
  echo "  config_dns_port=${CFG_DNS_PORT:-<unknown>}"
  echo "  config_udp_preview_ports=${CFG_UDP_PREVIEW_PORTS:-<none>}"
}

nft_rule_comment() {
  local kind="$1"
  local proto="$2"
  printf 'aegis:%s:%s:%s' "${kind}" "${proto}" "${CHAIN}"
}

nft_has_chain() {
  nft list chain "$(resolve_firewall_family)" "${NFT_TABLE}" "$1" >/dev/null 2>&1
}

firewall_hook_present() {
  local proto="$1"
  if [[ "${EFFECTIVE_FIREWALL_BACKEND}" == "nft" ]]; then
    case "$(nft list chain "$(resolve_firewall_family)" "${NFT_TABLE}" "${NFT_PREROUTING_CHAIN}" 2>/dev/null)" in
      *"meta l4proto ${proto} jump ${CHAIN}"*) return 0 ;;
      *) return 1 ;;
    esac
  fi
  local firewall=""
  firewall="$(firewall_bin)"
  if [[ -n "${INTERFACE}" ]]; then
    "${firewall}" -t mangle -C PREROUTING -i "${INTERFACE}" -p "${proto}" -j "${CHAIN}" >/dev/null 2>&1
  else
    "${firewall}" -t mangle -C PREROUTING -p "${proto}" -j "${CHAIN}" >/dev/null 2>&1
  fi
}

input_filter_chain_present() {
  "$(firewall_bin)" -t filter -S "${INPUT_CHAIN}" >/dev/null 2>&1
}

input_filter_rule_present() {
  local proto="$1"
  "$(firewall_bin)" -t filter -C "${INPUT_CHAIN}" \
    -p "${proto}" -m mark --mark "${FWMARK}/${FWMARK}" -j ACCEPT >/dev/null 2>&1
}

input_filter_hook_present() {
  local input_interface="$1"
  if [[ -n "${input_interface}" ]]; then
    "$(firewall_bin)" -t filter -C INPUT -i "${input_interface}" -j "${INPUT_CHAIN}" >/dev/null 2>&1
  else
    "$(firewall_bin)" -t filter -C INPUT -j "${INPUT_CHAIN}" >/dev/null 2>&1
  fi
}

firewalld_nft_requires_accept_bridge() {
  command -v firewall-cmd >/dev/null 2>&1 \
    && command -v nft >/dev/null 2>&1 \
    && [[ "$(firewall-cmd --state 2>/dev/null || true)" == "running" ]] \
    && nft list chain inet firewalld filter_INPUT >/dev/null 2>&1
}

firewalld_family_name() {
  if [[ "${EFFECTIVE_IP_FAMILY}" == "ipv6" ]]; then
    echo "ipv6"
  else
    echo "ipv4"
  fi
}

firewalld_state_file() {
  if [[ -n "${FIREWALLD_STATE_FILE_OVERRIDE}" ]]; then
    printf '%s\n' "${FIREWALLD_STATE_FILE_OVERRIDE}"
  else
    printf '/var/lib/aegis-install/client/tproxy-firewalld-%s.state\n' "${EFFECTIVE_IP_FAMILY}"
  fi
}

firewalld_zone_for_interface() {
  local zone=""
  zone="$(firewall-cmd --get-zone-of-interface="${INTERFACE}" 2>/dev/null || true)"
  if [[ -z "${zone}" || "${zone}" == "no zone" ]]; then
    zone="$(firewall-cmd --get-default-zone)"
  fi
  printf '%s\n' "${zone}"
}

firewalld_source_prefixes() {
  if [[ -z "${INTERFACE}" ]]; then
    return 1
  fi
  if [[ "${EFFECTIVE_IP_FAMILY}" == "ipv6" ]]; then
    ip -6 -o route show dev "${INTERFACE}" 2>/dev/null
  else
    ip -4 -o route show dev "${INTERFACE}" 2>/dev/null
  fi | awk '
    $1 != "default" && $1 != "local" && $1 != "broadcast" && $1 != "unreachable" && $1 != "prohibit" && $1 != "blackhole" {
      print $1
    }
  ' | sort -u
}

render_port_range() {
  local first="$1"
  local last="$2"
  if (( first == last )); then
    printf '%s\n' "${first}"
  elif (( first < last )); then
    printf '%s-%s\n' "${first}" "${last}"
  fi
}

port_ranges_excluding() {
  local start=1
  local excluded=""
  while IFS= read -r excluded; do
    [[ -n "${excluded}" ]] || continue
    if (( excluded < start || excluded > 65535 )); then
      continue
    fi
    render_port_range "${start}" "$((excluded - 1))"
    start=$((excluded + 1))
  done < <(printf '%s\n' "$@" | sort -n -u)
  render_port_range "${start}" 65535
}

firewalld_tcp_port_ranges() {
  port_ranges_excluding "${SSH_SAFE_PORTS[@]:-}" "${WIDE_PORT}"
}

firewalld_udp_port_ranges() {
  if helper_intercepts_all_udp; then
    port_ranges_excluding "${WIDE_PORT}"
    return
  fi
  printf '%s\n' "${DNS_PORT}" "${EXTRA_UDP_PREVIEW_PORTS[@]:-}" | awk 'NF' | sort -n -u
}

firewalld_rich_rules() {
  local family=""
  local port=""
  local source=""
  family="$(firewalld_family_name)"
  while IFS= read -r source; do
    [[ -n "${source}" ]] || continue
    while IFS= read -r port; do
      [[ -n "${port}" ]] || continue
      printf 'rule family="%s" source address="%s" port port="%s" protocol="tcp" accept\n' \
        "${family}" "${source}" "${port}"
    done < <(firewalld_tcp_port_ranges)
    if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
      while IFS= read -r port; do
        [[ -n "${port}" ]] || continue
        printf 'rule family="%s" source address="%s" port port="%s" protocol="udp" accept\n' \
          "${family}" "${source}" "${port}"
      done < <(firewalld_udp_port_ranges)
    fi
  done < <(firewalld_source_prefixes)
}

firewalld_accept_bridge_present() {
  local firewall=""
  local port=""
  local rule=""
  local zone=""
  firewall="$(firewall_bin)"
  if ! "${firewall}" -t filter -C "${INPUT_CHAIN}" -p tcp -j DROP >/dev/null 2>&1; then
    return 1
  fi
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    if helper_intercepts_all_udp; then
      if ! "${firewall}" -t filter -C "${INPUT_CHAIN}" -p udp -j DROP >/dev/null 2>&1; then
        return 1
      fi
    else
      for port in "${DNS_PORT}" "${EXTRA_UDP_PREVIEW_PORTS[@]:-}"; do
        [[ -n "${port}" ]] || continue
        if ! "${firewall}" -t filter -C "${INPUT_CHAIN}" -p udp --dport "${port}" -j DROP >/dev/null 2>&1; then
          return 1
        fi
      done
    fi
  fi
  zone="$(firewalld_zone_for_interface)"
  while IFS= read -r rule; do
    [[ -n "${rule}" ]] || continue
    if ! firewall-cmd --zone="${zone}" --query-rich-rule="${rule}" >/dev/null 2>&1; then
      return 1
    fi
  done < <(firewalld_rich_rules)
}

ip_rule_present() {
  # Different iproute2 builds may render fwmark as `1` or `0x1`; match both.
  local mark_hex=""
  mark_hex="$(printf '0x%x' "${FWMARK}")"
  if [[ "${EFFECTIVE_IP_FAMILY}" == "ipv6" ]]; then
    ip -6 rule show | awk -v mark_dec="${FWMARK}" -v mark_hex="${mark_hex}" -v table="${ROUTE_TABLE}" '
      {
        if (!index($0, "lookup " table)) {
          next
        }
        for (i = 1; i < NF; i++) {
          if ($i == "fwmark") {
            token=tolower($(i + 1))
            sub(/\/.*/, "", token)
            if (token == tolower(mark_dec) || token == tolower(mark_hex)) {
              found=1
            }
          }
        }
      }
      END { exit(found ? 0 : 1) }
    '
  else
    ip rule show | awk -v mark_dec="${FWMARK}" -v mark_hex="${mark_hex}" -v table="${ROUTE_TABLE}" '
      {
        if (!index($0, "lookup " table)) {
          next
        }
        for (i = 1; i < NF; i++) {
          if ($i == "fwmark") {
            token=tolower($(i + 1))
            sub(/\/.*/, "", token)
            if (token == tolower(mark_dec) || token == tolower(mark_hex)) {
              found=1
            }
          }
        }
      }
      END { exit(found ? 0 : 1) }
    '
  fi
}

route_table_present() {
  # Some hosts render the local catch-all route as `default` instead of `0.0.0.0/0`/`::/0`.
  if [[ "${EFFECTIVE_IP_FAMILY}" == "ipv6" ]]; then
    ip -6 route show table "${ROUTE_TABLE}" | awk '
      $1 == "local" {
        has_lo=0
        for (i = 1; i < NF; i++) {
          if ($i == "dev" && $(i + 1) == "lo") {
            has_lo=1
          }
        }
        if (has_lo && ($2 == "::/0" || $2 == "default")) {
          found=1
        }
      }
      END { exit(found ? 0 : 1) }
    '
  else
    ip route show table "${ROUTE_TABLE}" | awk '
      $1 == "local" {
        has_lo=0
        for (i = 1; i < NF; i++) {
          if ($i == "dev" && $(i + 1) == "lo") {
            has_lo=1
          }
        }
        if (has_lo && ($2 == "0.0.0.0/0" || $2 == "default")) {
          found=1
        }
      }
      END { exit(found ? 0 : 1) }
    '
  fi
}

capture_command_output() {
  local __result_var="$1"
  shift
  local output=""
  local status=0

  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e

  printf -v "${__result_var}" '%s' "${output}"
  return "${status}"
}

doctor_check() {
  local level="$1"
  local message="$2"
  echo "- [${level}] ${message}"
}

require_client_config() {
  if [[ -z "${CLIENT_CONFIG}" ]]; then
    echo "AEGIS_CLIENT_CONFIG is required for ${ACTION}" >&2
    exit 1
  fi
  if [[ ! -f "${CLIENT_CONFIG}" ]]; then
    echo "AEGIS_CLIENT_CONFIG points to a missing file: ${CLIENT_CONFIG}" >&2
    exit 1
  fi
}

require_runtime_events_file() {
  if [[ ! "${RUNTIME_EVENTS_LIMIT}" =~ ^[0-9]+$ ]] || (( RUNTIME_EVENTS_LIMIT < 1 )); then
    echo "AEGIS_RUNTIME_EVENTS_LIMIT must be a positive integer" >&2
    exit 1
  fi
  if [[ ! -f "${RUNTIME_EVENTS_JSONL}" ]]; then
    echo "AEGIS_RUNTIME_EVENTS_JSONL points to a missing file: ${RUNTIME_EVENTS_JSONL}" >&2
    exit 1
  fi
}

resolve_client_exec_prefix() {
  if [[ "${EUID}" == 0 ]]; then
    if [[ -n "${CLIENT_BIN_OVERRIDE}" ]]; then AEGIS_ROOT_STATE_CLIENT="${CLIENT_BIN_OVERRIDE}"; fi
    aegis_root_state_init || exit 1
    CLIENT_EXEC_PREFIX=("${AEGIS_ROOT_STATE_CLIENT}")
    return 0
  fi

  local selected=""
  if selected="$(selected_client_binary)"; then
    CLIENT_EXEC_PREFIX=("${selected}")
    return 0
  fi

  if command -v cargo >/dev/null 2>&1; then
    CLIENT_EXEC_PREFIX=(cargo run --release -p aegis-client --)
    return 0
  fi

  echo "Need either an installed aegis-client binary or cargo" >&2
  exit 1
}

run_client_command() {
  resolve_client_exec_prefix
  if [[ "${CLIENT_EXEC_PREFIX[0]}" == "cargo" ]]; then
    (
      cd "${ROOT}"
      "${CLIENT_EXEC_PREFIX[@]}" "$@"
    )
    return $?
  fi

  "${CLIENT_EXEC_PREFIX[@]}" "$@"
}

load_startup_probe_result() {
  local stdout_file=""
  local stderr_file=""
  local parsed
  local parse_failed=0

  require_client_config

  stdout_file="$(mktemp)"
  stderr_file="$(mktemp)"

  set +e
  run_client_command --config "${CLIENT_CONFIG}" --ingress-startup-probe --json >"${stdout_file}" 2>"${stderr_file}"
  PROBE_EXIT_CODE=$?
  set -e

  if ! parsed="$(
    run_client_command profile tproxy-diagnostics startup-probe-fields --stdout "${stdout_file}" --stderr "${stderr_file}"
  )"; then
    parse_failed=1
  fi

  if (( parse_failed != 0 )); then
    echo "Failed to parse ingress startup probe JSON for ${CLIENT_CONFIG}" >&2
    if [[ -s "${stdout_file}" ]]; then
      echo "--- stdout ---" >&2
      sed -n '1,40p' "${stdout_file}" >&2
    fi
    if [[ -s "${stderr_file}" ]]; then
      echo "--- stderr ---" >&2
      sed -n '1,40p' "${stderr_file}" >&2
    fi
    rm -f "${stdout_file}" "${stderr_file}"
    exit 1
  fi

  while IFS=$'\t' read -r key value; do
    case "${key}" in
      PROBE_STATUS) PROBE_STATUS="${value}" ;;
      PROBE_CODE) PROBE_CODE="${value}" ;;
      PROBE_STARTED_BACKEND) PROBE_STARTED_BACKEND="${value}" ;;
      PROBE_FAILURE_CODE) PROBE_FAILURE_CODE="${value}" ;;
      PROBE_HINT_CODE) PROBE_HINT_CODE="${value}" ;;
      PROBE_MESSAGE) PROBE_MESSAGE="${value}" ;;
      PROBE_HINT) PROBE_HINT="${value}" ;;
      PROBE_DNS_STATUS) PROBE_DNS_STATUS="${value}" ;;
      PROBE_UDP_CAPTURE_CONTRACT) PROBE_UDP_CAPTURE_CONTRACT="${value}" ;;
      PROBE_UDP_CAPTURE_SUPPORT_TIER) PROBE_UDP_CAPTURE_SUPPORT_TIER="${value}" ;;
      PROBE_UDP_CAPTURE_POLICY) PROBE_UDP_CAPTURE_POLICY="${value}" ;;
      PROBE_UDP_CAPTURE_RUNTIME_SCOPE) PROBE_UDP_CAPTURE_RUNTIME_SCOPE="${value}" ;;
    esac
  done <<< "${parsed}"

  rm -f "${stdout_file}" "${stderr_file}"
}

print_probe_remediation() {
  case "${PROBE_FAILURE_CODE}" in
    needs_cap_net_admin)
      doctor_check "warn" "run the client with root/CAP_NET_ADMIN so IP_TRANSPARENT can succeed"
      ;;
    listener_busy)
      if [[ "${PROBE_HINT_CODE}" == "verify_wide_listen_is_free" ]]; then
        doctor_check "warn" "free ingress.wide.listen or pick another wide port, then rerun probe"
      elif [[ "${PROBE_HINT_CODE}" == "verify_socks_listen_is_free" ]]; then
        doctor_check "warn" "free socks.listen or change the fallback listener, then rerun probe"
      else
        doctor_check "warn" "free the busy listener and rerun probe"
      fi
      ;;
    listener_conflict)
      doctor_check "warn" "use distinct wide.listen and socks.listen values in the client config"
      ;;
    unsupported_adapter)
      doctor_check "warn" "this platform/backend combination cannot support linux_tproxy; switch backend or allow fallback while testing"
      ;;
    backend_prerequisites)
      doctor_check "warn" "verify rollout_profile/default_mark/interface prerequisites before retrying linux_tproxy"
      doctor_check "warn" "for helper-side host setup also re-check AEGIS_WIDE_FWMARK / AEGIS_WIDE_ROUTE_TABLE and rerun doctor"
      ;;
    socks_bind_failed)
      doctor_check "warn" "verify socks fallback listener settings and rerun probe"
      ;;
  esac

  case "${PROBE_HINT_CODE}" in
    needs_root_or_cap_net_admin_for_ip_transparent)
      doctor_check "warn" "the future long-running client launch must use the same elevated privilege model"
      ;;
    verify_wide_listen_is_free)
      doctor_check "warn" "the chosen wide listener is not currently available on this host"
      ;;
    use_distinct_wide_and_socks_listeners|use_distinct_socks_and_wide_listeners)
      doctor_check "warn" "do not reuse one listen address for both wide and socks listeners"
      ;;
    selected_wide_backend_unsupported_adapter)
      doctor_check "warn" "switch away from linux_tproxy on unsupported hosts or enable fallback intentionally"
      ;;
    verify_wide_listener_settings_and_backend_prerequisites)
      doctor_check "warn" "re-check helper contract, ingress.wide profile and listener settings before retrying"
      ;;
    verify_socks_fallback_listener_settings)
      doctor_check "warn" "fallback socks listener settings are invalid for the current host"
      ;;
  esac
}

run_probe() {
  load_startup_probe_result

  print_contract_summary
  print_client_contract_summary
  echo "=== startup probe summary ==="
  doctor_check "pass" "probe status=${PROBE_STATUS} code=${PROBE_CODE}"
  if [[ -n "${PROBE_STARTED_BACKEND}" ]]; then
    doctor_check "pass" "started_backend=${PROBE_STARTED_BACKEND}"
  fi
  if [[ -n "${PROBE_MESSAGE}" ]]; then
    doctor_check "pass" "${PROBE_MESSAGE}"
  fi
  if [[ -n "${PROBE_DNS_STATUS}" ]]; then
    doctor_check "pass" "wide_dns_capture_preview_status=${PROBE_DNS_STATUS}"
  fi
  if [[ -n "${PROBE_UDP_CAPTURE_CONTRACT}" ]]; then
    doctor_check "pass" "startup.wide_udp_capture_contract=${PROBE_UDP_CAPTURE_CONTRACT}"
  fi
  if [[ -n "${PROBE_UDP_CAPTURE_SUPPORT_TIER}" ]]; then
    doctor_check "pass" "startup.wide_udp_capture_support_tier=${PROBE_UDP_CAPTURE_SUPPORT_TIER}"
  fi
  if [[ -n "${PROBE_UDP_CAPTURE_POLICY}" ]]; then
    doctor_check "pass" "startup.wide_udp_capture_policy=${PROBE_UDP_CAPTURE_POLICY}"
  fi
  if [[ -n "${PROBE_UDP_CAPTURE_RUNTIME_SCOPE}" ]]; then
    doctor_check "pass" "startup.wide_udp_capture_runtime_scope=${PROBE_UDP_CAPTURE_RUNTIME_SCOPE}"
  fi

  case "${PROBE_STATUS}" in
    ok)
      echo "Probe result: client startup looks ready for linux_tproxy"
      echo "Next recommended command: AEGIS_CLIENT_CONFIG=\"${CLIENT_CONFIG}\" AEGIS_RUNTIME_EVENTS_JSONL=\"${RUNTIME_EVENTS_JSONL}\" $0 run"
      echo "Manual step-by-step path:"
      echo "  AEGIS_CLIENT_CONFIG=\"${CLIENT_CONFIG}\" AEGIS_RUNTIME_EVENTS_JSONL=\"${RUNTIME_EVENTS_JSONL}\" $0 launch"
      echo "  AEGIS_RUNTIME_EVENTS_JSONL=\"${RUNTIME_EVENTS_JSONL}\" $0 events"
      return 0
      ;;
    degraded)
      doctor_check "warn" "startup probe is degraded; supported linux_tproxy path is not active"
      ;;
    error)
      doctor_check "fail" "startup probe failed before reaching a supported linux_tproxy startup"
      ;;
    *)
      doctor_check "fail" "startup probe returned an unknown status: ${PROBE_STATUS:-<missing>}"
      return 1
      ;;
  esac

  if [[ -n "${PROBE_FAILURE_CODE}" ]]; then
    doctor_check "warn" "failure_code=${PROBE_FAILURE_CODE}"
  fi
  if [[ -n "${PROBE_HINT_CODE}" ]]; then
    doctor_check "warn" "hint_code=${PROBE_HINT_CODE}"
  fi
  if [[ -n "${PROBE_HINT}" ]]; then
    doctor_check "warn" "${PROBE_HINT}"
  fi
  print_probe_remediation
  echo "Probe result: client startup is not yet ready for a supported linux_tproxy run"
  return 1
}

load_runtime_events_summary() {
  local parsed

  require_runtime_events_file
  EVENTS_STARTUP_HEALTH=""
  EVENTS_RUNTIME_STATUS=""
  EVENTS_PRODUCT_VERDICT=""
  EVENTS_RUNTIME_DEGRADATION_COUNT="0"
  EVENTS_FAILOVER_COUNT="0"
  EVENTS_TERMINAL_FAILURE_COUNT="0"

  if ! parsed="$(
    run_client_command profile tproxy-diagnostics runtime-events-summary --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}" --limit "${RUNTIME_EVENTS_LIMIT}"
  )"; then
    echo "Failed to parse runtime events JSONL from ${RUNTIME_EVENTS_JSONL}" >&2
    exit 1
  fi

  while IFS=$'\t' read -r key value; do
    case "${key}" in
      EVENTS_TOTAL) EVENTS_TOTAL="${value}" ;;
      EVENTS_LATEST_CODE) EVENTS_LATEST_CODE="${value}" ;;
      EVENTS_LATEST_LEVEL) EVENTS_LATEST_LEVEL="${value}" ;;
      EVENTS_LATEST_MESSAGE) EVENTS_LATEST_MESSAGE="${value}" ;;
      EVENTS_BACKEND) EVENTS_BACKEND="${value}" ;;
      EVENTS_BACKEND_RUNTIME_ID) EVENTS_BACKEND_RUNTIME_ID="${value}" ;;
      EVENTS_BACKEND_DNS_STATUS) EVENTS_BACKEND_DNS_STATUS="${value}" ;;
      EVENTS_BACKEND_UDP_CAPTURE_CONTRACT) EVENTS_BACKEND_UDP_CAPTURE_CONTRACT="${value}" ;;
      EVENTS_BACKEND_UDP_CAPTURE_SUPPORT_TIER) EVENTS_BACKEND_UDP_CAPTURE_SUPPORT_TIER="${value}" ;;
      EVENTS_BACKEND_UDP_CAPTURE_POLICY) EVENTS_BACKEND_UDP_CAPTURE_POLICY="${value}" ;;
      EVENTS_BACKEND_UDP_CAPTURE_RUNTIME_SCOPE) EVENTS_BACKEND_UDP_CAPTURE_RUNTIME_SCOPE="${value}" ;;
      EVENTS_STARTUP_HEALTH) EVENTS_STARTUP_HEALTH="${value}" ;;
      EVENTS_RUNTIME_STATUS) EVENTS_RUNTIME_STATUS="${value}" ;;
      EVENTS_PRODUCT_VERDICT) EVENTS_PRODUCT_VERDICT="${value}" ;;
      EVENTS_RUNTIME_DEGRADATION_COUNT) EVENTS_RUNTIME_DEGRADATION_COUNT="${value}" ;;
      EVENTS_FAILOVER_COUNT) EVENTS_FAILOVER_COUNT="${value}" ;;
      EVENTS_TERMINAL_FAILURE_COUNT) EVENTS_TERMINAL_FAILURE_COUNT="${value}" ;;
      EVENTS_PROBLEM_CODE) EVENTS_PROBLEM_CODE="${value}" ;;
      EVENTS_PROBLEM_LEVEL) EVENTS_PROBLEM_LEVEL="${value}" ;;
      EVENTS_PROBLEM_MESSAGE) EVENTS_PROBLEM_MESSAGE="${value}" ;;
      EVENTS_PROBLEM_BIND_ERROR_CODE) EVENTS_PROBLEM_BIND_ERROR_CODE="${value}" ;;
      EVENTS_PROBLEM_BIND_HINT_CODE) EVENTS_PROBLEM_BIND_HINT_CODE="${value}" ;;
      EVENTS_PROBLEM_SELECTION_ERROR_CODE) EVENTS_PROBLEM_SELECTION_ERROR_CODE="${value}" ;;
      EVENTS_PROBLEM_SELECTION_HINT_CODE) EVENTS_PROBLEM_SELECTION_HINT_CODE="${value}" ;;
      EVENTS_PROBLEM_DROP_REASON_CODE) EVENTS_PROBLEM_DROP_REASON_CODE="${value}" ;;
      EVENTS_PROBLEM_CAPTURE_DROP_STAGE) EVENTS_PROBLEM_CAPTURE_DROP_STAGE="${value}" ;;
      EVENTS_PROBLEM_CAPTURE_DROP_REASON_CODE) EVENTS_PROBLEM_CAPTURE_DROP_REASON_CODE="${value}" ;;
      EVENTS_PROBLEM_UDP_CAPTURE_CONTRACT) EVENTS_PROBLEM_UDP_CAPTURE_CONTRACT="${value}" ;;
      EVENTS_PROBLEM_UDP_CAPTURE_SUPPORT_TIER) EVENTS_PROBLEM_UDP_CAPTURE_SUPPORT_TIER="${value}" ;;
      EVENTS_PROBLEM_UDP_CAPTURE_POLICY) EVENTS_PROBLEM_UDP_CAPTURE_POLICY="${value}" ;;
      EVENTS_PROBLEM_UDP_CAPTURE_RUNTIME_SCOPE) EVENTS_PROBLEM_UDP_CAPTURE_RUNTIME_SCOPE="${value}" ;;
      EVENTS_PROBLEM_UDP_PREVIEW_POLICY) EVENTS_PROBLEM_UDP_PREVIEW_POLICY="${value}" ;;
      EVENTS_PROBLEM_HINT) EVENTS_PROBLEM_HINT="${value}" ;;
      EVENTS_PROBLEM_TRANSPORT) EVENTS_PROBLEM_TRANSPORT="${value}" ;;
      EVENTS_PROBLEM_RELAY_SERVER) EVENTS_PROBLEM_RELAY_SERVER="${value}" ;;
      EVENTS_PROBLEM_RELAY_ERROR_KIND) EVENTS_PROBLEM_RELAY_ERROR_KIND="${value}" ;;
      EVENTS_PROBLEM_SESSION_ERROR_KIND) EVENTS_PROBLEM_SESSION_ERROR_KIND="${value}" ;;
      EVENTS_PROBLEM_ERROR) EVENTS_PROBLEM_ERROR="${value}" ;;
      EVENTS_PROBLEM_BACKEND) EVENTS_PROBLEM_BACKEND="${value}" ;;
      EVENTS_PROBLEM_RELAY_LAST_TRANSPORT) EVENTS_PROBLEM_RELAY_LAST_TRANSPORT="${value}" ;;
      EVENTS_PROBLEM_ATTEMPT_INDEX) EVENTS_PROBLEM_ATTEMPT_INDEX="${value}" ;;
      EVENTS_PROBLEM_ATTEMPTS_TOTAL) EVENTS_PROBLEM_ATTEMPTS_TOTAL="${value}" ;;
      EVENTS_PROBLEM_EXPECTED_DNS_PORT) EVENTS_PROBLEM_EXPECTED_DNS_PORT="${value}" ;;
      EVENTS_PROBLEM_EXPECTED_UDP_PREVIEW_PORTS) EVENTS_PROBLEM_EXPECTED_UDP_PREVIEW_PORTS="${value}" ;;
    esac
  done <<< "${parsed}"
}

print_events_remediation() {
  case "${EVENTS_PROBLEM_CODE}" in
    ingress_startup_selection_failed)
      doctor_check "warn" "supported linux_tproxy path never started; fix selection config before retrying"
      doctor_check "warn" "if helper-side host state was prepared separately, also re-check AEGIS_WIDE_FWMARK / AEGIS_WIDE_ROUTE_TABLE via helper doctor"
      if [[ -n "${EVENTS_PROBLEM_SELECTION_HINT_CODE}" ]]; then
        doctor_check "warn" "selection_hint_code=${EVENTS_PROBLEM_SELECTION_HINT_CODE}"
      fi
      ;;
    ingress_wide_bind_fallback)
      doctor_check "warn" "wide path fell back to SOCKS5; supported linux_tproxy path is not active"
      if [[ -n "${EVENTS_PROBLEM_BIND_ERROR_CODE}" ]]; then
        doctor_check "warn" "bind_error_code=${EVENTS_PROBLEM_BIND_ERROR_CODE}"
      fi
      if [[ -n "${EVENTS_PROBLEM_BIND_HINT_CODE}" ]]; then
        doctor_check "warn" "bind_hint_code=${EVENTS_PROBLEM_BIND_HINT_CODE}"
      fi
      ;;
    relay_transport_failed)
      doctor_check "warn" "relay transport failed during runtime; verify relay reachability, certs and transport policy"
      if [[ -n "${EVENTS_PROBLEM_TRANSPORT}" ]]; then
        doctor_check "warn" "transport=${EVENTS_PROBLEM_TRANSPORT}"
      fi
      if [[ -n "${EVENTS_PROBLEM_RELAY_SERVER}" ]]; then
        doctor_check "warn" "relay_server=${EVENTS_PROBLEM_RELAY_SERVER}"
      fi
      ;;
    ingress_session_failed|ingress_session_broker_failed)
      doctor_check "warn" "runtime session handling failed; inspect relay/backend fields and recent tracing output"
      if [[ -n "${EVENTS_PROBLEM_BACKEND}" ]]; then
        doctor_check "warn" "backend=${EVENTS_PROBLEM_BACKEND}"
      fi
      if [[ -n "${EVENTS_PROBLEM_RELAY_LAST_TRANSPORT}" ]]; then
        doctor_check "warn" "relay_last_transport=${EVENTS_PROBLEM_RELAY_LAST_TRANSPORT}"
      fi
      ;;
    ingress_accept_failed)
      doctor_check "warn" "listener accepted path is failing after startup; inspect socket conflicts or privilege drift"
      ;;
    ingress_udp_datagram_dropped)
      doctor_check "warn" "UDP datagram was dropped before session handoff; inspect capture-policy fields to see whether this is preview-only allowlist behavior or a broader future capture gate"
      if [[ -n "${EVENTS_PROBLEM_DROP_REASON_CODE}" ]]; then
        doctor_check "warn" "drop_reason_code=${EVENTS_PROBLEM_DROP_REASON_CODE}"
      fi
      if [[ -n "${EVENTS_PROBLEM_CAPTURE_DROP_STAGE}" ]]; then
        doctor_check "warn" "wide_udp_capture_drop_stage=${EVENTS_PROBLEM_CAPTURE_DROP_STAGE}"
      fi
      if [[ -n "${EVENTS_PROBLEM_CAPTURE_DROP_REASON_CODE}" ]]; then
        doctor_check "warn" "wide_udp_capture_drop_reason_code=${EVENTS_PROBLEM_CAPTURE_DROP_REASON_CODE}"
      fi
      if [[ -n "${EVENTS_PROBLEM_UDP_PREVIEW_POLICY}" ]]; then
        doctor_check "warn" "wide_udp_preview_policy=${EVENTS_PROBLEM_UDP_PREVIEW_POLICY}"
      fi
      if [[ "${EVENTS_PROBLEM_DROP_REASON_CODE}" == "target_port_not_udp_preview" ]]; then
        doctor_check "warn" "the intercepted UDP destination is outside the configured preview allowlist; keep ingress.wide.dns_port / ingress.wide.udp_preview_ports aligned with AEGIS_DNS_PORT / AEGIS_UDP_PREVIEW_PORTS"
      fi
      if [[ -n "${EVENTS_PROBLEM_EXPECTED_DNS_PORT}" ]]; then
        doctor_check "warn" "expected_dns_port=${EVENTS_PROBLEM_EXPECTED_DNS_PORT}"
      fi
      if [[ -n "${EVENTS_PROBLEM_EXPECTED_UDP_PREVIEW_PORTS}" ]]; then
        doctor_check "warn" "expected_udp_preview_ports=${EVENTS_PROBLEM_EXPECTED_UDP_PREVIEW_PORTS}"
      fi
      if [[ "${EVENTS_PROBLEM_UDP_CAPTURE_CONTRACT}" == "generic_capture_unstable" ]]; then
        doctor_check "warn" "remediation: generic_capture_unstable is already active, so inspect runtime drop stage/reason and relay path instead of preview allowlist knobs"
      else
        doctor_check "warn" "remediation: keep ingress.wide.dns_port / ingress.wide.udp_preview_ports aligned with helper env for preview_allowlist_only, or opt into ingress.wide.udp_capture_contract=generic_capture_unstable when you intentionally need broader Linux UDP interception for the selected listen family"
      fi
      ;;
  esac

  if [[ -n "${EVENTS_PROBLEM_HINT}" ]]; then
    doctor_check "warn" "${EVENTS_PROBLEM_HINT}"
  fi
  if [[ -n "${EVENTS_PROBLEM_RELAY_ERROR_KIND}" ]]; then
    doctor_check "warn" "relay_error_kind=${EVENTS_PROBLEM_RELAY_ERROR_KIND}"
  fi
  if [[ -n "${EVENTS_PROBLEM_SESSION_ERROR_KIND}" ]]; then
    doctor_check "warn" "session_error_kind=${EVENTS_PROBLEM_SESSION_ERROR_KIND}"
  fi
  if [[ -n "${EVENTS_PROBLEM_ERROR}" ]]; then
    doctor_check "warn" "${EVENTS_PROBLEM_ERROR}"
  fi
}

write_operator_evidence_summary() {
  local out_path="${OPERATOR_EVIDENCE_JSON}"
  mkdir -p "$(dirname "${out_path}")"
  run_client_command profile tproxy-diagnostics write-operator-evidence \
    --output "${out_path}" \
    --client-config "${CLIENT_CONFIG:-}" \
    --runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}" \
    --events-total "${EVENTS_TOTAL:-0}" \
    --backend "${EVENTS_BACKEND:-}" \
    --backend-runtime-id "${EVENTS_BACKEND_RUNTIME_ID:-}" \
    --startup-health "${EVENTS_STARTUP_HEALTH:-unknown}" \
    --runtime-status "${EVENTS_RUNTIME_STATUS:-unknown}" \
    --product-verdict "${EVENTS_PRODUCT_VERDICT:-unknown}" \
    --runtime-degradation-count "${EVENTS_RUNTIME_DEGRADATION_COUNT:-0}" \
    --failover-count "${EVENTS_FAILOVER_COUNT:-0}" \
    --terminal-failure-count "${EVENTS_TERMINAL_FAILURE_COUNT:-0}" \
    --latest-code "${EVENTS_LATEST_CODE:-}" \
    --latest-level "${EVENTS_LATEST_LEVEL:-}" \
    --latest-message "${EVENTS_LATEST_MESSAGE:-}" \
    --problem-code "${EVENTS_PROBLEM_CODE:-}" \
    --problem-level "${EVENTS_PROBLEM_LEVEL:-}" \
    --problem-message "${EVENTS_PROBLEM_MESSAGE:-}"
}

run_events() {
  local status_degraded=0
  load_runtime_events_summary
  write_operator_evidence_summary

  print_contract_summary
  print_client_contract_summary
  echo "=== runtime events summary ==="
  doctor_check "pass" "jsonl_path=${RUNTIME_EVENTS_JSONL}"
  doctor_check "pass" "operator_evidence_json=${OPERATOR_EVIDENCE_JSON}"
  doctor_check "pass" "records_scanned=${EVENTS_TOTAL}"
  if [[ "${EVENTS_TOTAL}" == "0" ]]; then
    doctor_check "warn" "runtime events file is empty; no startup/runtime evidence was captured yet"
    return 1
  fi
  if [[ -n "${EVENTS_BACKEND}" ]]; then
    doctor_check "pass" "last started backend=${EVENTS_BACKEND} (runtime_id=${EVENTS_BACKEND_RUNTIME_ID:-unknown})"
  fi
  if [[ -n "${EVENTS_BACKEND_DNS_STATUS}" ]]; then
    doctor_check "pass" "wide_dns_capture_preview_status=${EVENTS_BACKEND_DNS_STATUS}"
  fi
  if [[ -n "${EVENTS_BACKEND_UDP_CAPTURE_CONTRACT}" ]]; then
    doctor_check "pass" "backend.wide_udp_capture_contract=${EVENTS_BACKEND_UDP_CAPTURE_CONTRACT}"
  fi
  if [[ -n "${EVENTS_BACKEND_UDP_CAPTURE_SUPPORT_TIER}" ]]; then
    doctor_check "pass" "backend.wide_udp_capture_support_tier=${EVENTS_BACKEND_UDP_CAPTURE_SUPPORT_TIER}"
  fi
  if [[ -n "${EVENTS_BACKEND_UDP_CAPTURE_POLICY}" ]]; then
    doctor_check "pass" "backend.wide_udp_capture_policy=${EVENTS_BACKEND_UDP_CAPTURE_POLICY}"
  fi
  if [[ -n "${EVENTS_BACKEND_UDP_CAPTURE_RUNTIME_SCOPE}" ]]; then
    doctor_check "pass" "backend.wide_udp_capture_runtime_scope=${EVENTS_BACKEND_UDP_CAPTURE_RUNTIME_SCOPE}"
  fi
  doctor_check "pass" "startup_health=${EVENTS_STARTUP_HEALTH:-unknown}"
  doctor_check "pass" "runtime_status=${EVENTS_RUNTIME_STATUS:-unknown}"
  doctor_check "pass" "product_verdict=${EVENTS_PRODUCT_VERDICT:-unknown}"
  doctor_check "pass" "runtime_degradation_count=${EVENTS_RUNTIME_DEGRADATION_COUNT:-0}"
  doctor_check "pass" "failover_count=${EVENTS_FAILOVER_COUNT:-0}"
  doctor_check "pass" "terminal_failure_count=${EVENTS_TERMINAL_FAILURE_COUNT:-0}"
  if [[ -n "${EVENTS_LATEST_CODE}" ]]; then
    doctor_check "pass" "latest_event=${EVENTS_LATEST_CODE} level=${EVENTS_LATEST_LEVEL:-unknown}"
  fi
  if [[ -n "${EVENTS_LATEST_MESSAGE}" ]]; then
    doctor_check "pass" "${EVENTS_LATEST_MESSAGE}"
  fi
  if [[ "${EVENTS_STARTUP_HEALTH:-unknown}" != "healthy" ]]; then
    doctor_check "warn" "startup health stayed ${EVENTS_STARTUP_HEALTH:-unknown}; keep this run out of the clean release-gate path"
    status_degraded=1
  fi
  if [[ "${EVENTS_RUNTIME_STATUS:-unknown}" != "healthy" ]]; then
    doctor_check "warn" "runtime status stayed ${EVENTS_RUNTIME_STATUS:-unknown}; keep this run out of the clean release-gate path"
    status_degraded=1
  fi
  if [[ "${EVENTS_PRODUCT_VERDICT:-unknown}" != "green" ]]; then
    doctor_check "warn" "product verdict stayed ${EVENTS_PRODUCT_VERDICT:-unknown}; treat this run as non-green release evidence"
    status_degraded=1
  fi

  if [[ -z "${EVENTS_PROBLEM_CODE}" && "${status_degraded}" == "0" ]]; then
    echo "Events result: no warn/error runtime events were observed in the scanned JSONL window"
    return 0
  fi

  if [[ -n "${EVENTS_PROBLEM_CODE:-}" ]]; then
    doctor_check "warn" "latest_problem_event=${EVENTS_PROBLEM_CODE} level=${EVENTS_PROBLEM_LEVEL:-unknown}"
    if [[ -n "${EVENTS_PROBLEM_MESSAGE}" ]]; then
      doctor_check "warn" "${EVENTS_PROBLEM_MESSAGE}"
    fi
    if [[ -n "${EVENTS_PROBLEM_UDP_CAPTURE_CONTRACT}" ]]; then
      doctor_check "warn" "problem.wide_udp_capture_contract=${EVENTS_PROBLEM_UDP_CAPTURE_CONTRACT}"
    fi
    if [[ -n "${EVENTS_PROBLEM_UDP_CAPTURE_SUPPORT_TIER}" ]]; then
      doctor_check "warn" "problem.wide_udp_capture_support_tier=${EVENTS_PROBLEM_UDP_CAPTURE_SUPPORT_TIER}"
    fi
    if [[ -n "${EVENTS_PROBLEM_UDP_CAPTURE_POLICY}" ]]; then
      doctor_check "warn" "problem.wide_udp_capture_policy=${EVENTS_PROBLEM_UDP_CAPTURE_POLICY}"
    fi
    if [[ -n "${EVENTS_PROBLEM_UDP_CAPTURE_RUNTIME_SCOPE}" ]]; then
      doctor_check "warn" "problem.wide_udp_capture_runtime_scope=${EVENTS_PROBLEM_UDP_CAPTURE_RUNTIME_SCOPE}"
    fi
    print_events_remediation
    echo "Events result: runtime JSONL contains warn/error signals that need inspection before calling this run healthy"
    return 1
  fi

  doctor_check "warn" "product status counters stayed degraded even without a warn/error latest_problem_event"
  echo "Events result: runtime JSONL stayed parseable, but startup/runtime status is still degraded"
  return 1
}

build_launch_command() {
  resolve_client_exec_prefix
  LAUNCH_CMD=("${CLIENT_EXEC_PREFIX[@]}" --config "${CLIENT_CONFIG}")
  if [[ "${DIAGNOSTIC_LOGS}" == "1" ]]; then
    LAUNCH_CMD+=(--diagnostic-logs)
  fi
  if [[ "${ENABLE_RUNTIME_EVENTS_JSONL}" == "1" ]]; then
    LAUNCH_CMD+=(--runtime-events-jsonl "${RUNTIME_EVENTS_JSONL}")
  fi
}

print_launch_summary() {
  print_contract_summary
  print_client_contract_summary
  echo "=== launch ==="
  if [[ "${ENABLE_RUNTIME_EVENTS_JSONL}" == "1" ]]; then
    doctor_check "pass" "runtime events JSONL enabled: ${RUNTIME_EVENTS_JSONL}"
    doctor_check "pass" "post-exit operator evidence JSON: ${OPERATOR_EVIDENCE_JSON}"
  else
    doctor_check "warn" "runtime events JSONL disabled for this launch"
  fi
  doctor_check "pass" "launch should use the same privilege model that passed probe"
}

run_launch() {
  require_client_config

  build_launch_command

  print_launch_summary
  doctor_check "pass" "after the process exits, run: AEGIS_RUNTIME_EVENTS_JSONL=\"${RUNTIME_EVENTS_JSONL}\" $0 events"
  echo "Exec: ${LAUNCH_CMD[*]}"
  exec "${LAUNCH_CMD[@]}"
}

run_supervised() {
  local client_exit_code=0
  local events_exit_code=0

  require_client_config

  echo "=== supervised run precheck ==="
  if ! run_probe; then
    echo "Run result: probe did not confirm a supported linux_tproxy startup path"
    return 1
  fi

  build_launch_command
  print_launch_summary
  doctor_check "pass" "supervised run will execute post-exit events summary automatically"
  echo "Exec: ${LAUNCH_CMD[*]}"

  set +e
  "${LAUNCH_CMD[@]}"
  client_exit_code=$?
  set -e

  echo "=== supervised run exit ==="
  doctor_check "pass" "client_exit_code=${client_exit_code}"

  if [[ "${ENABLE_RUNTIME_EVENTS_JSONL}" == "1" ]]; then
    if run_events; then
      events_exit_code=0
    else
      events_exit_code=$?
    fi
  else
    doctor_check "warn" "runtime events JSONL disabled, so post-exit events summary is unavailable"
  fi

  if (( client_exit_code != 0 )); then
    echo "Run result: client exited with a non-zero code"
    return "${client_exit_code}"
  fi
  if (( events_exit_code != 0 )); then
    echo "Run result: client exited cleanly, but runtime status was not healthy"
    return 1
  fi

  echo "Run result: client exited cleanly and runtime events summary stayed healthy"
}

run_doctor() {
  local failures=0
  local warnings=0
  local candidate_iface=""
  local firewall=""
  local public_host_path=0
  local selected_client=""
  firewall="$(render_firewall_surface)"

  print_contract_summary
  print_client_contract_summary
  echo "=== doctor ==="
  doctor_check "pass" "helper ip family=${EFFECTIVE_IP_FAMILY}"
  if selected_client="$(selected_client_binary)"; then
    doctor_check "pass" "selected client executable is available for probe/run"
  else
    doctor_check "fail" "selected client executable is unavailable for probe/run"
    failures=$((failures + 1))
  fi

  if [[ -n "${INTERFACE}" ]]; then
    if ip link show dev "${INTERFACE}" >/dev/null 2>&1; then
      doctor_check "pass" "helper interface ${INTERFACE} exists on this host"
    else
      doctor_check "fail" "helper interface ${INTERFACE} does not exist on this host"
      failures=$((failures + 1))
    fi
  else
    candidate_iface="$(detect_default_interface || true)"
    doctor_check "fail" "AEGIS_WIDE_INTERFACE is unset; supported linux_tproxy path requires explicit interface scope"
    if [[ -n "${candidate_iface}" ]]; then
      doctor_check "warn" "Linux default route suggests interface ${candidate_iface}"
    fi
    if [[ "${ALLOW_ALL_INTERFACES}" == "1" ]]; then
      doctor_check "warn" "AEGIS_WIDE_ALLOW_ALL_INTERFACES=1 keeps this host in an intentionally unsafe all-interface mode"
    fi
    failures=$((failures + 1))
  fi

  if [[ -n "${INTERFACE}" ]] && interface_looks_public_host_path; then
    public_host_path=1
    doctor_check "warn" "helper interface ${INTERFACE} matches the Linux default route; treat this host path as remote/public-sensitive"
    warnings=$((warnings + 1))
  fi

  if [[ -n "${NORMALIZED_SSH_SAFE_PORTS}" ]]; then
    doctor_check "pass" "SSH-safe bypass ports are configured: ${NORMALIZED_SSH_SAFE_PORTS}"
  elif [[ "${public_host_path}" == "1" ]]; then
    doctor_check "fail" "SSH-safe bypass ports are empty on the default/public interface path"
    doctor_check "warn" "set AEGIS_WIDE_SSH_SAFE_PORTS=22 (or your operator ports) before apply, unless you intentionally opt into dangerous mode"
    failures=$((failures + 1))
    warnings=$((warnings + 1))
  else
    doctor_check "warn" "SSH-safe bypass ports are empty; this is only acceptable on isolated lab hosts"
    warnings=$((warnings + 1))
  fi

  if [[ "${ALLOW_ALL_INTERFACES}" == "1" ]]; then
    if [[ "${public_host_path}" == "1" && "${DANGEROUS_PUBLIC_APPLY}" != "1" ]]; then
      doctor_check "fail" "all-interface PREROUTING on the default/public interface requires explicit dangerous opt-in"
      failures=$((failures + 1))
    elif [[ "${DANGEROUS_PUBLIC_APPLY}" == "1" ]]; then
      doctor_check "warn" "dangerous public-apply opt-in is enabled; keep this run out of the supported remote operator path"
      warnings=$((warnings + 1))
    else
      doctor_check "warn" "all-interface PREROUTING stays lab-only even though this host path is not the detected default route"
      warnings=$((warnings + 1))
    fi
  elif [[ "${DANGEROUS_PUBLIC_APPLY}" == "1" ]]; then
    doctor_check "warn" "dangerous public-apply opt-in is enabled even though explicit interface scope is set"
    warnings=$((warnings + 1))
  fi

  if [[ "${EFFECTIVE_FIREWALL_BACKEND}" == "nft" ]]; then
    if nft_has_chain "${CHAIN}"; then
      doctor_check "pass" "${firewall}/${CHAIN} exists"
    else
      doctor_check "fail" "${firewall}/${CHAIN} is missing; run helper apply before starting traffic interception"
      failures=$((failures + 1))
    fi
  else
    if "$(firewall_bin)" -t mangle -S "${CHAIN}" >/dev/null 2>&1; then
      doctor_check "pass" "${firewall}/${CHAIN} exists"
    else
      doctor_check "fail" "${firewall}/${CHAIN} is missing; run helper apply before starting traffic interception"
      failures=$((failures + 1))
    fi
  fi

  if firewall_hook_present tcp; then
    doctor_check "pass" "${firewall} prerouting tcp hook points to ${CHAIN}"
  else
    doctor_check "fail" "${firewall} prerouting tcp hook for ${CHAIN} is missing"
    failures=$((failures + 1))
  fi

  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    if firewall_hook_present udp; then
      doctor_check "pass" "${firewall} prerouting udp hook points to ${CHAIN}"
    else
      doctor_check "fail" "${firewall} prerouting udp hook for ${CHAIN} is missing while DNS preview is enabled"
      failures=$((failures + 1))
    fi
  fi

  if input_filter_chain_present; then
    doctor_check "pass" "$(firewall_bin) filter/${INPUT_CHAIN} exists for TPROXY socket delivery"
  else
    doctor_check "fail" "$(firewall_bin) filter/${INPUT_CHAIN} is missing; host INPUT policy may drop TPROXY traffic before the client socket"
    failures=$((failures + 1))
  fi

  if input_filter_rule_present tcp; then
    doctor_check "pass" "filter/${INPUT_CHAIN} accepts AEGIS-marked TCP"
  else
    doctor_check "fail" "filter/${INPUT_CHAIN} marked TCP accept rule is missing"
    failures=$((failures + 1))
  fi

  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    if input_filter_rule_present udp; then
      doctor_check "pass" "filter/${INPUT_CHAIN} accepts AEGIS-marked UDP"
    else
      doctor_check "fail" "filter/${INPUT_CHAIN} marked UDP accept rule is missing while DNS/UDP capture is enabled"
      failures=$((failures + 1))
    fi
  fi

  if input_filter_hook_present "${INTERFACE}"; then
    doctor_check "pass" "filter INPUT delivery hook points to ${INPUT_CHAIN} for ${INTERFACE:-all interfaces}"
  else
    doctor_check "fail" "filter INPUT delivery hook for ${INPUT_CHAIN} is missing on ${INTERFACE:-all interfaces}"
    failures=$((failures + 1))
  fi

  if [[ "${ENABLE_LOCAL_OUTPUT}" == "1" && "${ENABLE_DNS_PREVIEW}" == "1" && "${INTERFACE}" != "lo" ]]; then
    if input_filter_hook_present lo; then
      doctor_check "pass" "filter INPUT delivery hook points to ${INPUT_CHAIN} for local-output loopback"
    else
      doctor_check "fail" "filter INPUT delivery hook for local-output loopback is missing"
      failures=$((failures + 1))
    fi
  fi

  if firewalld_nft_requires_accept_bridge; then
    if firewalld_accept_bridge_present; then
      doctor_check "pass" "firewalld nft INPUT compatibility bridge preserves marked TPROXY socket delivery"
    else
      doctor_check "fail" "firewalld nft INPUT compatibility bridge is missing; firewalld may reject TPROXY traffic after the iptables ACCEPT"
      failures=$((failures + 1))
    fi
  fi

  if ip_rule_present; then
    doctor_check "pass" "fwmark ${FWMARK} rule routes into table ${ROUTE_TABLE}"
  else
    doctor_check "fail" "policy rule for fwmark ${FWMARK} -> table ${ROUTE_TABLE} is missing"
    doctor_check "warn" "rerun helper apply with the intended AEGIS_WIDE_FWMARK / AEGIS_WIDE_ROUTE_TABLE and then re-check doctor"
    failures=$((failures + 1))
  fi

  if route_table_present; then
    doctor_check "pass" "route table ${ROUTE_TABLE} contains local delivery to lo"
  else
    doctor_check "fail" "route table ${ROUTE_TABLE} is missing the required local lo route"
    doctor_check "warn" "rerun helper apply or inspect conflicting policy-routing state before retrying linux_tproxy"
    failures=$((failures + 1))
  fi

  if [[ -n "${CLIENT_CONFIG}" ]]; then
    if ! client_contract_complete; then
      doctor_check "fail" "client config contract could not be parsed completely"
      failures=$((failures + 1))
    else
      if [[ "${CFG_INGRESS_PRIMARY}" == "wide" && "${CFG_WIDE_ENABLED}" == "1" ]]; then
        doctor_check "pass" "client wide ingress is active"
      else
        doctor_check "fail" "client wide ingress is inactive (primary=${CFG_INGRESS_PRIMARY}, enabled=${CFG_WIDE_ENABLED})"
        failures=$((failures + 1))
      fi
      if [[ "${CFG_WIDE_BACKEND}" == "linux_tproxy" ]]; then
        doctor_check "pass" "client config uses linux_tproxy backend"
      else
        doctor_check "fail" "client config backend is ${CFG_WIDE_BACKEND}, expected linux_tproxy"
        failures=$((failures + 1))
      fi

      case "${CFG_WIDE_PROFILE}" in
        transparent_privileged)
          doctor_check "pass" "client rollout profile ${CFG_WIDE_PROFILE} is compatible with TPROXY helper scope"
          ;;
        "")
          doctor_check "warn" "client rollout profile is missing from config contract summary"
          warnings=$((warnings + 1))
          ;;
        *)
          doctor_check "fail" "client rollout profile ${CFG_WIDE_PROFILE} is not compatible with TPROXY helper scope"
          failures=$((failures + 1))
          ;;
      esac

      if [[ -n "${CFG_WIDE_LISTEN_PORT}" && "${CFG_WIDE_LISTEN_PORT}" == "${WIDE_PORT}" ]]; then
        doctor_check "pass" "helper listen port matches client config (${WIDE_PORT})"
      elif [[ -n "${CFG_WIDE_LISTEN_PORT}" ]]; then
        doctor_check "fail" "helper listen port ${WIDE_PORT} does not match client config port ${CFG_WIDE_LISTEN_PORT}"
        failures=$((failures + 1))
      fi

      if [[ -n "${CFG_WIDE_LISTEN_FAMILY}" && "${CFG_WIDE_LISTEN_FAMILY}" == "${EFFECTIVE_IP_FAMILY}" ]]; then
        doctor_check "pass" "helper IP family matches client config (${EFFECTIVE_IP_FAMILY})"
      elif [[ -n "${CFG_WIDE_LISTEN_FAMILY}" ]]; then
        doctor_check "fail" "helper IP family ${EFFECTIVE_IP_FAMILY} does not match client listen family ${CFG_WIDE_LISTEN_FAMILY}"
        failures=$((failures + 1))
      fi

      if [[ -n "${CFG_DEFAULT_MARK}" && "${CFG_DEFAULT_MARK}" == "${FWMARK}" ]]; then
        doctor_check "pass" "helper fwmark matches client config (${FWMARK})"
      elif [[ -n "${CFG_DEFAULT_MARK}" ]]; then
        doctor_check "fail" "helper fwmark ${FWMARK} does not match client config default_mark ${CFG_DEFAULT_MARK}"
        failures=$((failures + 1))
      fi

      if [[ -n "${CFG_WIDE_INTERFACE}" && -n "${INTERFACE}" && "${CFG_WIDE_INTERFACE}" == "${INTERFACE}" ]]; then
        doctor_check "pass" "helper interface matches client config (${INTERFACE})"
      elif [[ -n "${CFG_WIDE_INTERFACE}" && -n "${INTERFACE}" ]]; then
        doctor_check "fail" "helper interface ${INTERFACE} does not match client config prerouting_interface ${CFG_WIDE_INTERFACE}"
        failures=$((failures + 1))
      elif [[ -n "${CFG_WIDE_INTERFACE}" || -n "${INTERFACE}" ]]; then
        doctor_check "fail" "helper interface scope and client config prerouting_interface are not aligned"
        failures=$((failures + 1))
      fi

      if [[ -n "${CFG_CAPTURE_DNS}" && "${CFG_CAPTURE_DNS}" == "${ENABLE_DNS_PREVIEW}" ]]; then
        doctor_check "pass" "DNS preview toggle matches client config (${ENABLE_DNS_PREVIEW})"
      elif [[ -n "${CFG_CAPTURE_DNS}" ]]; then
        doctor_check "warn" "helper DNS preview toggle ${ENABLE_DNS_PREVIEW} differs from client config capture_dns ${CFG_CAPTURE_DNS}"
        warnings=$((warnings + 1))
      fi

      if [[ "${CFG_UDP_CAPTURE_CONTRACT:-preview_allowlist_only}" == "${UDP_CAPTURE_CONTRACT}" ]]; then
        doctor_check "pass" "UDP capture contract matches client config (${UDP_CAPTURE_CONTRACT})"
      else
        doctor_check "fail" "helper UDP capture contract ${UDP_CAPTURE_CONTRACT} does not match client config udp_capture_contract ${CFG_UDP_CAPTURE_CONTRACT:-preview_allowlist_only}"
        failures=$((failures + 1))
      fi

      if [[ -n "${CFG_UDP_CAPTURE_SUPPORT_TIER}" ]]; then
        if [[ "${CFG_UDP_CAPTURE_SUPPORT_TIER}" == "$(render_udp_capture_support_tier)" ]]; then
          doctor_check "pass" "UDP capture support tier matches client config (${CFG_UDP_CAPTURE_SUPPORT_TIER})"
        else
          doctor_check "fail" "helper UDP capture support tier $(render_udp_capture_support_tier) does not match client config support tier ${CFG_UDP_CAPTURE_SUPPORT_TIER}"
          failures=$((failures + 1))
        fi
      fi

      if [[ -n "${CFG_UDP_CAPTURE_POLICY}" ]]; then
        if [[ "${CFG_UDP_CAPTURE_POLICY}" == "$(render_udp_capture_policy)" ]]; then
          doctor_check "pass" "UDP capture policy matches client config (${CFG_UDP_CAPTURE_POLICY})"
        else
          doctor_check "fail" "helper UDP capture policy $(render_udp_capture_policy) does not match client config policy ${CFG_UDP_CAPTURE_POLICY}"
          failures=$((failures + 1))
        fi
      fi

      if [[ -n "${CFG_UDP_CAPTURE_RUNTIME_SCOPE}" ]]; then
        if [[ "${CFG_UDP_CAPTURE_RUNTIME_SCOPE}" == "$(render_udp_capture_runtime_scope)" ]]; then
          doctor_check "pass" "UDP capture runtime scope matches client config (${CFG_UDP_CAPTURE_RUNTIME_SCOPE})"
        else
          doctor_check "fail" "helper UDP capture runtime scope $(render_udp_capture_runtime_scope) does not match client config runtime scope ${CFG_UDP_CAPTURE_RUNTIME_SCOPE}"
          failures=$((failures + 1))
        fi
      fi

      if udp_capture_uses_preview_allowlist; then
        if [[ -n "${CFG_DNS_PORT}" && "${CFG_DNS_PORT}" == "${DNS_PORT}" ]]; then
          doctor_check "pass" "DNS preview port matches client config (${DNS_PORT})"
        elif [[ -n "${CFG_DNS_PORT}" ]]; then
          doctor_check "fail" "helper DNS preview port ${DNS_PORT} does not match client config dns_port ${CFG_DNS_PORT}"
          failures=$((failures + 1))
        fi

        if [[ "${CFG_UDP_PREVIEW_PORTS:-}" == "${NORMALIZED_EXTRA_UDP_PREVIEW_PORTS}" ]]; then
          doctor_check "pass" "extra UDP preview ports match client config (${NORMALIZED_EXTRA_UDP_PREVIEW_PORTS:-<none>})"
        else
          doctor_check "fail" "helper extra UDP preview ports ${NORMALIZED_EXTRA_UDP_PREVIEW_PORTS:-<none>} do not match client config udp_preview_ports ${CFG_UDP_PREVIEW_PORTS:-<none>}"
          failures=$((failures + 1))
        fi
      else
        doctor_check "pass" "generic UDP capture contract is active, so dns_port / udp_preview_ports allowlist knobs are ignored"
      fi
    fi
  else
    doctor_check "fail" "client config is unavailable; host-only checks cannot establish a supported linux_tproxy run"
    failures=$((failures + 1))
  fi

  echo "=== doctor summary ==="
  echo "  failures=${failures}"
  echo "  warnings=${warnings}"
  if (( failures > 0 )); then
    echo "Doctor result: host contract is not ready for a supported linux_tproxy run"
    return 1
  fi

  echo "Doctor result: host contract looks consistent for linux_tproxy"
  if [[ -n "${CLIENT_CONFIG}" ]]; then
    echo "Next recommended check: run the helper probe with the same privilege model as the real client launch."
    echo "  AEGIS_CLIENT_CONFIG=\"${CLIENT_CONFIG}\" $0 probe"
  fi
}

create_input_filter() {
  local firewall=""
  local port=""
  firewall="$(firewall_bin)"

  # TPROXY preserves the original destination and routes the marked packet to
  # a transparent local socket. Hosts with INPUT DROP (notably UFW defaults)
  # otherwise discard that packet after successful interception. Keep this
  # exception AEGIS-owned, mark-scoped, protocol-scoped, and interface-scoped.
  "${firewall}" -t filter -N "${INPUT_CHAIN}" 2>/dev/null || true
  "${firewall}" -t filter -F "${INPUT_CHAIN}" || return 1
  for port in "${SSH_SAFE_PORTS[@]:-}"; do
    [[ -n "${port}" ]] || continue
    "${firewall}" -t filter -A "${INPUT_CHAIN}" -p tcp --dport "${port}" -j RETURN || return 1
  done
  "${firewall}" -t filter -A "${INPUT_CHAIN}" -p tcp --dport "${WIDE_PORT}" -j RETURN || return 1
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    "${firewall}" -t filter -A "${INPUT_CHAIN}" -p udp --dport "${WIDE_PORT}" -j RETURN || return 1
  fi
  "${firewall}" -t filter -A "${INPUT_CHAIN}" \
    -p tcp -m mark --mark "${FWMARK}/${FWMARK}" -j ACCEPT || return 1
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    "${firewall}" -t filter -A "${INPUT_CHAIN}" \
      -p udp -m mark --mark "${FWMARK}/${FWMARK}" -j ACCEPT || return 1
  fi

  # With firewalld's nft backend, the firewalld-native rich accept rules below
  # are necessarily wider than a packet-mark match. Drop any packet that did
  # not receive the TPROXY mark before it can reach those rules. Explicit SSH
  # and listener bypass ports already RETURNed above and retain host policy.
  if firewalld_nft_requires_accept_bridge; then
    "${firewall}" -t filter -A "${INPUT_CHAIN}" -p tcp -j DROP || return 1
    if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
      if helper_intercepts_all_udp; then
        "${firewall}" -t filter -A "${INPUT_CHAIN}" -p udp -j DROP || return 1
      else
        "${firewall}" -t filter -A "${INPUT_CHAIN}" -p udp --dport "${DNS_PORT}" -j DROP || return 1
        for port in "${EXTRA_UDP_PREVIEW_PORTS[@]:-}"; do
          [[ -n "${port}" ]] || continue
          "${firewall}" -t filter -A "${INPUT_CHAIN}" -p udp --dport "${port}" -j DROP || return 1
        done
      fi
    fi
  fi

  # Reinsert our exact hook at position 1 on every apply. This keeps delivery
  # ahead of UFW's INPUT jumps even if UFW was reloaded between helper runs,
  # while the preceding exact delete prevents duplicate AEGIS hooks.
  if [[ -n "${INTERFACE}" ]]; then
    "${firewall}" -t filter -D INPUT -i "${INTERFACE}" -j "${INPUT_CHAIN}" 2>/dev/null || true
    "${firewall}" -t filter -I INPUT 1 -i "${INTERFACE}" -j "${INPUT_CHAIN}" || return 1
  else
    "${firewall}" -t filter -D INPUT -j "${INPUT_CHAIN}" 2>/dev/null || true
    "${firewall}" -t filter -I INPUT 1 -j "${INPUT_CHAIN}" || return 1
  fi

  if [[ "${ENABLE_LOCAL_OUTPUT}" == "1" && "${ENABLE_DNS_PREVIEW}" == "1" && "${INTERFACE}" != "lo" ]]; then
    "${firewall}" -t filter -D INPUT -i lo -j "${INPUT_CHAIN}" 2>/dev/null || true
    "${firewall}" -t filter -I INPUT 1 -i lo -j "${INPUT_CHAIN}" || return 1
  fi
}

teardown_input_filter() {
  local firewall=""
  firewall="$(firewall_bin)"

  if [[ "${ENABLE_LOCAL_OUTPUT}" == "1" && "${ENABLE_DNS_PREVIEW}" == "1" && "${INTERFACE}" != "lo" ]]; then
    "${firewall}" -t filter -D INPUT -i lo -j "${INPUT_CHAIN}" 2>/dev/null || true
  fi
  if [[ -n "${INTERFACE}" ]]; then
    "${firewall}" -t filter -D INPUT -i "${INTERFACE}" -j "${INPUT_CHAIN}" 2>/dev/null || true
  else
    "${firewall}" -t filter -D INPUT -j "${INPUT_CHAIN}" 2>/dev/null || true
  fi
  "${firewall}" -t filter -F "${INPUT_CHAIN}" 2>/dev/null || true
  "${firewall}" -t filter -X "${INPUT_CHAIN}" 2>/dev/null || true
}

create_firewalld_accept_bridge() {
  local rule=""
  local state_file=""
  local source_count=0
  local state_text=""
  local zone=""

  if ! firewalld_nft_requires_accept_bridge; then
    return 0
  fi

  teardown_firewalld_accept_bridge || return 1
  while IFS= read -r rule; do
    [[ -n "${rule}" ]] || continue
    source_count=$((source_count + 1))
  done < <(firewalld_source_prefixes)
  if (( source_count == 0 )); then
    echo "firewalld compatibility requires at least one routed source prefix on ${INTERFACE}" >&2
    return 1
  fi
  zone="$(firewalld_zone_for_interface)"
  state_file="$(firewalld_state_file)"
  umask 077
  printf %s "" | aegis_root_write "${state_file}" || return 1
  while IFS= read -r rule; do
    [[ -n "${rule}" ]] || continue
    # Record the exact owned rule before mutating firewalld. If the helper is
    # interrupted immediately after the add, the next teardown still knows the
    # precise rule to remove; removing a recorded-but-never-added rule is safe.
    state_text+="$(printf '%s\t%s' "${zone}" "${rule}")"$'\n'
    printf %s "$state_text" | aegis_root_write "${state_file}" || return 1
    if ! firewall-cmd --zone="${zone}" --add-rich-rule="${rule}" >/dev/null; then
      return 1
    fi
  done < <(firewalld_rich_rules)
}

teardown_firewalld_accept_bridge() {
  local rule=""
  local state_file=""
  local zone=""
  if ! command -v firewall-cmd >/dev/null 2>&1; then
    return 0
  fi
  state_file="$(firewalld_state_file)"
  if [[ -f "${state_file}" ]]; then
    local state_text
    state_text="$(aegis_root_read "${state_file}")" || return 1
    while IFS=$'\t' read -r zone rule; do
      [[ -n "${zone}" && -n "${rule}" ]] || continue
      firewall-cmd --zone="${zone}" --remove-rich-rule="${rule}" >/dev/null 2>&1 || true
    done <<< "${state_text}"
    aegis_root_remove "${state_file}"
  else
    zone="$(firewalld_zone_for_interface 2>/dev/null || true)"
    if [[ -n "${zone}" ]]; then
      while IFS= read -r rule; do
        [[ -n "${rule}" ]] || continue
        firewall-cmd --zone="${zone}" --remove-rich-rule="${rule}" >/dev/null 2>&1 || true
      done < <(firewalld_rich_rules)
    fi
  fi
}

create_chain() {
  local firewall=""
  local family=""
  local proto=""
  local port=""
  local tproxy_on_ip_args=""
  if [[ "${EFFECTIVE_FIREWALL_BACKEND}" == "nft" ]]; then
    family="$(resolve_firewall_family)"
    nft delete table "${family}" "${NFT_TABLE}" 2>/dev/null || true
    nft add table "${family}" "${NFT_TABLE}"
    nft add chain "${family}" "${NFT_TABLE}" "${NFT_PREROUTING_CHAIN}" "{ type filter hook prerouting priority mangle; policy accept; }"
    nft add chain "${family}" "${NFT_TABLE}" "${CHAIN}"

    for port in "${SSH_SAFE_PORTS[@]:-}"; do
      [[ -n "${port}" ]] || continue
      nft add rule "${family}" "${NFT_TABLE}" "${CHAIN}" tcp dport "${port}" return
    done
    nft add rule "${family}" "${NFT_TABLE}" "${CHAIN}" tcp dport "${WIDE_PORT}" return
    if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
      nft add rule "${family}" "${NFT_TABLE}" "${CHAIN}" udp dport "${WIDE_PORT}" return
    fi

    # Packets matching existing sockets: mark for policy routing but skip TPROXY.
    nft add rule "${family}" "${NFT_TABLE}" "${CHAIN}" meta l4proto tcp socket transparent 1 meta mark set "${FWMARK}" return
    if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
      nft add rule "${family}" "${NFT_TABLE}" "${CHAIN}" meta l4proto udp socket transparent 1 meta mark set "${FWMARK}" return
    fi

    # Audit C2: build the CHAIN completely (RETURN + socket + tproxy actions)
    # BEFORE attaching the prerouting hook below. Attaching the jump first
    # leaves a window where matched packets traverse the half-built chain and
    # egress untproxied (cleartext leak) during setup.
    nft add rule "${family}" "${NFT_TABLE}" "${CHAIN}" \
      meta l4proto tcp tproxy to :"${WIDE_PORT}" meta mark set "${FWMARK}" accept
    if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
      if helper_intercepts_all_udp; then
        nft add rule "${family}" "${NFT_TABLE}" "${CHAIN}" \
          meta l4proto udp tproxy to :"${WIDE_PORT}" meta mark set "${FWMARK}" accept
      else
        nft add rule "${family}" "${NFT_TABLE}" "${CHAIN}" \
          udp dport "${DNS_PORT}" tproxy to :"${WIDE_PORT}" meta mark set "${FWMARK}" accept
        for port in "${EXTRA_UDP_PREVIEW_PORTS[@]:-}"; do
          [[ -n "${port}" ]] || continue
          nft add rule "${family}" "${NFT_TABLE}" "${CHAIN}" \
            udp dport "${port}" tproxy to :"${WIDE_PORT}" meta mark set "${FWMARK}" accept
        done
      fi
    fi

    # Hook the prerouting chain to the now-complete CHAIN last (C2).
    for proto in tcp udp; do
      if [[ "${proto}" == "udp" && "${ENABLE_DNS_PREVIEW}" != "1" ]]; then
        continue
      fi
      if [[ -n "${INTERFACE}" ]]; then
        nft add rule "${family}" "${NFT_TABLE}" "${NFT_PREROUTING_CHAIN}" \
          iifname "${INTERFACE}" meta l4proto "${proto}" jump "${CHAIN}" \
          comment "\"$(nft_rule_comment prerouting "${proto}")\""
      else
        nft add rule "${family}" "${NFT_TABLE}" "${NFT_PREROUTING_CHAIN}" \
          meta l4proto "${proto}" jump "${CHAIN}" \
          comment "\"$(nft_rule_comment prerouting "${proto}")\""
      fi
    done
    return
  fi

  firewall="$(firewall_bin)"
  tproxy_on_ip_args="$(xtables_tproxy_on_ip_args)"
  "${firewall}" -t mangle -N "${CHAIN}" 2>/dev/null || true
  "${firewall}" -t mangle -F "${CHAIN}"

  for port in "${SSH_SAFE_PORTS[@]:-}"; do
    [[ -n "${port}" ]] || continue
    "${firewall}" -t mangle -A "${CHAIN}" -p tcp --dport "${port}" -j RETURN
  done
  "${firewall}" -t mangle -A "${CHAIN}" -p tcp --dport "${WIDE_PORT}" -j RETURN
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    "${firewall}" -t mangle -A "${CHAIN}" -p udp --dport "${WIDE_PORT}" -j RETURN
  fi

  # Packets belonging to existing transparent sockets must be marked (for
  # policy routing) but NOT re-tproxied — prevents breaking established
  # connections. Use --transparent to avoid matching non-transparent sockets
  # (e.g. local echo/test listeners that should not bypass TPROXY).
  "${firewall}" -t mangle -A "${CHAIN}" -p tcp -m socket --transparent -j MARK --set-mark "${FWMARK}/${FWMARK}"
  "${firewall}" -t mangle -A "${CHAIN}" -p tcp -m socket --transparent -j RETURN
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    "${firewall}" -t mangle -A "${CHAIN}" -p udp -m socket --transparent -j MARK --set-mark "${FWMARK}/${FWMARK}"
    "${firewall}" -t mangle -A "${CHAIN}" -p udp -m socket --transparent -j RETURN
  fi

  # Audit C2: build the CHAIN completely (TCP + UDP tproxy actions) BEFORE
  # attaching any PREROUTING/OUTPUT hook below, so no packet traverses a
  # half-built chain and egresses untproxied (cleartext leak) during setup.
  "${firewall}" -t mangle -A "${CHAIN}" -p tcp -j TPROXY \
    ${tproxy_on_ip_args:+${tproxy_on_ip_args}} \
    --on-port "${WIDE_PORT}" \
    --tproxy-mark "${FWMARK}/${FWMARK}"

  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    if helper_intercepts_all_udp; then
      # Generic mode intentionally widens the helper rule too, otherwise the
      # broader Linux runtime contract for the selected family would stay
      # unreachable in smoke/lab runs. The smoke-only force override reuses the
      # same wider rule so preview allowlist drops remain observable at runtime.
      "${firewall}" -t mangle -A "${CHAIN}" -p udp -j TPROXY \
        ${tproxy_on_ip_args:+${tproxy_on_ip_args}} \
        --on-port "${WIDE_PORT}" \
        --tproxy-mark "${FWMARK}/${FWMARK}"
    else
      # Preview-only contract keeps UDP interception intentionally controlled:
      # the primary DNS port plus any explicitly configured extra preview ports.
      "${firewall}" -t mangle -A "${CHAIN}" -p udp --dport "${DNS_PORT}" -j TPROXY \
        ${tproxy_on_ip_args:+${tproxy_on_ip_args}} \
        --on-port "${WIDE_PORT}" \
        --tproxy-mark "${FWMARK}/${FWMARK}"
      for port in "${EXTRA_UDP_PREVIEW_PORTS[@]:-}"; do
        [[ -n "${port}" ]] || continue
        "${firewall}" -t mangle -A "${CHAIN}" -p udp --dport "${port}" -j TPROXY \
          ${tproxy_on_ip_args:+${tproxy_on_ip_args}} \
          --on-port "${WIDE_PORT}" \
          --tproxy-mark "${FWMARK}/${FWMARK}"
      done
    fi
  fi

  # Hooks attach last, once the CHAIN is complete (C2).
  if [[ -n "${INTERFACE}" ]]; then
    if ! "${firewall}" -t mangle -C PREROUTING -i "${INTERFACE}" -p tcp -j "${CHAIN}" 2>/dev/null; then
      "${firewall}" -t mangle -A PREROUTING -i "${INTERFACE}" -p tcp -j "${CHAIN}"
    fi
    if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]] && ! "${firewall}" -t mangle -C PREROUTING -i "${INTERFACE}" -p udp -j "${CHAIN}" 2>/dev/null; then
      "${firewall}" -t mangle -A PREROUTING -i "${INTERFACE}" -p udp -j "${CHAIN}"
    fi
  else
    if ! "${firewall}" -t mangle -C PREROUTING -p tcp -j "${CHAIN}" 2>/dev/null; then
      "${firewall}" -t mangle -A PREROUTING -p tcp -j "${CHAIN}"
    fi
    if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]] && ! "${firewall}" -t mangle -C PREROUTING -p udp -j "${CHAIN}" 2>/dev/null; then
      "${firewall}" -t mangle -A PREROUTING -p udp -j "${CHAIN}"
    fi
  fi

  # For client machines (not gateways), locally-originated UDP DNS needs OUTPUT
  # chain marking so it loops through policy routing into PREROUTING/TPROXY.
  # TCP is NOT marked here — use nat/REDIRECT (setup-wide-linux-redirect.sh)
  # for TCP on client machines; TPROXY OUTPUT marking for TCP breaks local
  # routing because policy-routed packets loop through lo instead of egress.
  # For client machines (not gateways): mark locally-originated DNS in OUTPUT
  # so policy routing loops it through PREROUTING/TPROXY, and hook lo in
  # PREROUTING so the re-routed packet gets caught by the TPROXY chain.
  if [[ "${ENABLE_LOCAL_OUTPUT}" == "1" && "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    "${firewall}" -t mangle -A OUTPUT -p udp -o lo -j RETURN
    "${firewall}" -t mangle -A OUTPUT -p udp --dport "${DNS_PORT}" "${EXEMPT_MATCH[@]}" -j MARK --set-mark "${FWMARK}/${FWMARK}"
    for port in "${EXTRA_UDP_PREVIEW_PORTS[@]:-}"; do
      [[ -n "${port}" ]] || continue
      "${firewall}" -t mangle -A OUTPUT -p udp --dport "${port}" "${EXEMPT_MATCH[@]}" -j MARK --set-mark "${FWMARK}/${FWMARK}"
    done
    # Marked packets loop via lo after policy routing; hook PREROUTING on lo
    # so TPROXY catches them. Socket-matching in the chain protects
    # local-listener DNS (e.g. systemd-resolved on 127.0.0.53) from being
    # TPROXYed since an existing socket will match and RETURN.
    if ! "${firewall}" -t mangle -C PREROUTING -i lo -p udp -j "${CHAIN}" 2>/dev/null; then
      "${firewall}" -t mangle -A PREROUTING -i lo -p udp -j "${CHAIN}"
    fi
  fi
}

setup_policy_routing() {
  local rule_output=""
  local route_output=""
  local rule_add_failed=0
  local route_add_failed=0

  if [[ "${EFFECTIVE_IP_FAMILY}" == "ipv6" ]]; then
    capture_command_output rule_output ip -6 rule add fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" || rule_add_failed=1
    capture_command_output route_output ip -6 route add local ::/0 dev lo table "${ROUTE_TABLE}" || route_add_failed=1
  else
    capture_command_output rule_output ip rule add fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" || rule_add_failed=1
    capture_command_output route_output ip route add local 0.0.0.0/0 dev lo table "${ROUTE_TABLE}" || route_add_failed=1
  fi

  # iproute2 may report duplicates while the desired state is already present,
  # so helper apply validates the post-condition instead of trusting add exits.
  if ! ip_rule_present; then
    echo "Failed to materialize required fwmark rule ${FWMARK} -> table ${ROUTE_TABLE}" >&2
    if [[ -n "${rule_output}" ]]; then
      echo "ip rule add output: ${rule_output}" >&2
    fi
    return 1
  fi
  if ! route_table_present; then
    echo "Failed to materialize required local route in table ${ROUTE_TABLE}" >&2
    if [[ -n "${route_output}" ]]; then
      echo "ip route add output: ${route_output}" >&2
    fi
    return 1
  fi

  if (( rule_add_failed != 0 )) && [[ -n "${rule_output}" ]]; then
    echo "WARN: ip rule add reported: ${rule_output}" >&2
  fi
  if (( route_add_failed != 0 )) && [[ -n "${route_output}" ]]; then
    echo "WARN: ip route add reported: ${route_output}" >&2
  fi
}

ipv6_block_chain() {
  printf '%s_V6_BLOCK\n' "${CHAIN}"
}

apply_ipv6_policy() {
  if [[ "${IPV6_POLICY}" != "block" ]]; then
    return 0
  fi
  if ! command -v ip6tables >/dev/null 2>&1; then
    echo "ip6tables is required for AEGIS_WIDE_IPV6_POLICY=block" >&2
    return 1
  fi
  local chain_v6=""
  chain_v6="$(ipv6_block_chain)"
  ip6tables -t filter -N "${chain_v6}" 2>/dev/null || true
  ip6tables -t filter -F "${chain_v6}"
  ip6tables -t filter -A "${chain_v6}" -j DROP
  if ! ip6tables -t filter -C OUTPUT -j "${chain_v6}" 2>/dev/null; then
    ip6tables -t filter -I OUTPUT 1 -j "${chain_v6}"
  fi
  if ! ip6tables -t filter -C FORWARD -j "${chain_v6}" 2>/dev/null; then
    ip6tables -t filter -I FORWARD 1 -j "${chain_v6}"
  fi
}

teardown_ipv6_policy() {
  if [[ "${IPV6_POLICY}" != "block" ]]; then
    return 0
  fi
  if ! command -v ip6tables >/dev/null 2>&1; then
    return 0
  fi
  local chain_v6=""
  chain_v6="$(ipv6_block_chain)"
  ip6tables -t filter -D OUTPUT -j "${chain_v6}" 2>/dev/null || true
  ip6tables -t filter -D FORWARD -j "${chain_v6}" 2>/dev/null || true
  ip6tables -t filter -F "${chain_v6}" 2>/dev/null || true
  ip6tables -t filter -X "${chain_v6}" 2>/dev/null || true
}

teardown_policy_routing() {
  if [[ "${EFFECTIVE_IP_FAMILY}" == "ipv6" ]]; then
    ip -6 rule del fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" 2>/dev/null || true
    ip -6 route del local ::/0 dev lo table "${ROUTE_TABLE}" 2>/dev/null || true
  else
    ip rule del fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" 2>/dev/null || true
    ip route del local 0.0.0.0/0 dev lo table "${ROUTE_TABLE}" 2>/dev/null || true
  fi
}

teardown_chain() {
  if [[ "${EFFECTIVE_FIREWALL_BACKEND}" == "nft" ]]; then
    nft delete table "$(resolve_firewall_family)" "${NFT_TABLE}" 2>/dev/null || true
    return
  fi

  local firewall=""
  firewall="$(firewall_bin)"

  # Clean up only AEGIS-owned OUTPUT and lo PREROUTING rules added by
  # ENABLE_LOCAL_OUTPUT; never flush the host OUTPUT chain.
  "${firewall}" -t mangle -D OUTPUT -p udp -o lo -j RETURN 2>/dev/null || true
  "${firewall}" -t mangle -D OUTPUT -p udp --dport "${DNS_PORT}" "${EXEMPT_MATCH[@]}" -j MARK --set-mark "${FWMARK}/${FWMARK}" 2>/dev/null || true
  for port in "${EXTRA_UDP_PREVIEW_PORTS[@]:-}"; do
    [[ -n "${port}" ]] || continue
    "${firewall}" -t mangle -D OUTPUT -p udp --dport "${port}" "${EXEMPT_MATCH[@]}" -j MARK --set-mark "${FWMARK}/${FWMARK}" 2>/dev/null || true
  done
  "${firewall}" -t mangle -D PREROUTING -i lo -p udp -j "${CHAIN}" 2>/dev/null || true

  if [[ -n "${INTERFACE}" ]]; then
    "${firewall}" -t mangle -D PREROUTING -i "${INTERFACE}" -p tcp -j "${CHAIN}" 2>/dev/null || true
    if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
      "${firewall}" -t mangle -D PREROUTING -i "${INTERFACE}" -p udp -j "${CHAIN}" 2>/dev/null || true
    fi
  else
    "${firewall}" -t mangle -D PREROUTING -p tcp -j "${CHAIN}" 2>/dev/null || true
    if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
      "${firewall}" -t mangle -D PREROUTING -p udp -j "${CHAIN}" 2>/dev/null || true
    fi
  fi
  "${firewall}" -t mangle -F "${CHAIN}" 2>/dev/null || true
  "${firewall}" -t mangle -X "${CHAIN}" 2>/dev/null || true
}

show_status() {
  local firewall=""
  local ip_rule_output=""
  local mark_hex=""
  local rule=""
  firewall="$(render_firewall_surface)"
  mark_hex="$(printf '0x%x' "${FWMARK}")"
  print_contract_summary
  print_client_contract_summary
  if [[ "${EFFECTIVE_FIREWALL_BACKEND}" == "nft" ]]; then
    echo "=== ${firewall} ==="
    nft list table "$(resolve_firewall_family)" "${NFT_TABLE}" 2>/dev/null || echo "(table missing)"
  else
    local xtables_firewall=""
    xtables_firewall="$(firewall_bin)"
    echo "=== ${firewall}/${CHAIN} ==="
    "${xtables_firewall}" -t mangle -S "${CHAIN}" 2>/dev/null || echo "(chain missing)"
    echo "=== ${firewall}/${CHAIN} counters ==="
    "${xtables_firewall}" -t mangle -L "${CHAIN}" -n -v 2>/dev/null || echo "(chain missing)"
    echo "=== ${firewall}/PREROUTING hooks ==="
    "${xtables_firewall}" -t mangle -S PREROUTING | sed -n "/${CHAIN}/p" || true
    echo "=== ${firewall}/PREROUTING counters ==="
    "${xtables_firewall}" -t mangle -L PREROUTING -n -v | sed -n "/${CHAIN}/p" || true
  fi
  local input_firewall=""
  input_firewall="$(firewall_bin)"
  echo "=== ${input_firewall} filter/${INPUT_CHAIN} ==="
  "${input_firewall}" -t filter -S "${INPUT_CHAIN}" 2>/dev/null || echo "(chain missing)"
  echo "=== ${input_firewall} filter/${INPUT_CHAIN} counters ==="
  "${input_firewall}" -t filter -L "${INPUT_CHAIN}" -n -v 2>/dev/null || echo "(chain missing)"
  echo "=== ${input_firewall} filter/INPUT hooks ==="
  "${input_firewall}" -t filter -S INPUT | sed -n "/${INPUT_CHAIN}/p" || true
  if firewalld_nft_requires_accept_bridge; then
    local firewalld_zone=""
    firewalld_zone="$(firewalld_zone_for_interface)"
    echo "=== firewalld zone ${firewalld_zone} TPROXY compatibility ==="
    while IFS= read -r rule; do
      [[ -n "${rule}" ]] || continue
      if firewall-cmd --zone="${firewalld_zone}" --query-rich-rule="${rule}" >/dev/null 2>&1; then
        printf '%s\n' "${rule}"
      else
        printf '(missing) %s\n' "${rule}"
      fi
    done < <(firewalld_rich_rules)
    echo "state_file=$(firewalld_state_file)"
  fi
  echo "=== ip ${EFFECTIVE_IP_FAMILY} rule ==="
  if [[ "${EFFECTIVE_IP_FAMILY}" == "ipv6" ]]; then
    ip_rule_output="$(ip -6 rule show | awk -v mark_dec="${FWMARK}" -v mark_hex="${mark_hex}" '
      {
        for (i = 1; i < NF; i++) {
          if ($i == "fwmark") {
            token=tolower($(i + 1))
            sub(/\/.*/, "", token)
            if (token == tolower(mark_dec) || token == tolower(mark_hex)) {
              print
            }
          }
        }
      }
    ' || true)"
    if [[ -n "${ip_rule_output}" ]]; then
      printf '%s\n' "${ip_rule_output}"
    else
      ip -6 rule show || true
    fi
  else
    ip_rule_output="$(ip rule show | awk -v mark_dec="${FWMARK}" -v mark_hex="${mark_hex}" '
      {
        for (i = 1; i < NF; i++) {
          if ($i == "fwmark") {
            token=tolower($(i + 1))
            sub(/\/.*/, "", token)
            if (token == tolower(mark_dec) || token == tolower(mark_hex)) {
              print
            }
          }
        }
      }
    ' || true)"
    if [[ -n "${ip_rule_output}" ]]; then
      printf '%s\n' "${ip_rule_output}"
    else
      ip rule show || true
    fi
  fi
  echo "=== route table ${ROUTE_TABLE} ==="
  if [[ "${EFFECTIVE_IP_FAMILY}" == "ipv6" ]]; then
    ip -6 route show table "${ROUTE_TABLE}" || true
  else
    ip route show table "${ROUTE_TABLE}" || true
  fi
}

# The administrative config and executable must be trusted before they can
# influence a root network plan or launch. Read-only parsing keeps its old path
# for nonroot diagnostics; root never builds/executes a daemon-owned checkout.
# shellcheck source=scripts/lib/root-state.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/root-state.sh"
if [[ "${ACTION}" == apply || "${ACTION}" == teardown || "${ACTION}" == run ]]; then
  if [[ -n "${CLIENT_BIN_OVERRIDE}" ]]; then AEGIS_ROOT_STATE_CLIENT="${CLIENT_BIN_OVERRIDE}"; fi
  aegis_root_state_init || exit 1
  if [[ -n "${CLIENT_CONFIG}" ]]; then
    aegis_root_validate "${CLIENT_CONFIG}" || exit 1
  fi
fi

load_client_contract
validate_contract

if [[ "${ACTION}" == apply || "${ACTION}" == teardown || "${ACTION}" == run ]]; then
  # shellcheck source=scripts/lib/root-state.sh
  . "$(dirname "${BASH_SOURCE[0]}")/lib/root-state.sh"
  aegis_root_state_init || exit 1
  aegis_root_validate "$(firewalld_state_file)" || exit 1
  legacy_state="/run/aegis-wide-tproxy-firewalld-${EFFECTIVE_IP_FAMILY}.state"
  if [[ -e "$legacy_state" || -L "$legacy_state" ]]; then
    aegis_root_validate "$legacy_state" || exit 1
    if [[ ! -e "$(firewalld_state_file)" ]]; then
      aegis_root_read "$legacy_state" | aegis_root_write "$(firewalld_state_file)" || exit 1
    fi
    aegis_root_remove "$legacy_state" || exit 1
  fi
fi

case "${ACTION}" in
  apply)
    create_chain
    if ! create_input_filter; then
      echo "TPROXY INPUT delivery apply failed; rolling back helper state" >&2
      teardown_input_filter
      teardown_chain
      exit 1
    fi
    if ! create_firewalld_accept_bridge; then
      echo "firewalld TPROXY delivery bridge apply failed; rolling back helper state" >&2
      teardown_firewalld_accept_bridge
      teardown_input_filter
      teardown_chain
      exit 1
    fi
    if ! apply_ipv6_policy; then
      echo "IPv6 policy apply failed; rolling back helper state" >&2
      teardown_ipv6_policy
      teardown_firewalld_accept_bridge
      teardown_input_filter
      teardown_chain
      exit 1
    fi
    if ! setup_policy_routing; then
      echo "Policy-routing apply failed; rolling back helper state" >&2
      teardown_policy_routing
      teardown_ipv6_policy
      teardown_firewalld_accept_bridge
      teardown_input_filter
      teardown_chain
      exit 1
    fi
    print_contract_summary
    echo "Policy routing contract is ready: fwmark ${FWMARK} -> table ${ROUTE_TABLE}"
    echo "Applied Linux TPROXY helper (${EFFECTIVE_IP_FAMILY}, $(render_firewall_backend)) on port ${WIDE_PORT} with fwmark ${FWMARK} table ${ROUTE_TABLE}"
    if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
      if udp_capture_uses_preview_allowlist; then
        echo "UDP preview TPROXY is enabled for primary destination port ${DNS_PORT}"
        if [[ -n "${NORMALIZED_EXTRA_UDP_PREVIEW_PORTS}" ]]; then
          echo "Additional UDP preview ports: ${NORMALIZED_EXTRA_UDP_PREVIEW_PORTS}"
        fi
        if [[ "${FORCE_ALL_UDP_TPROXY}" == "1" ]]; then
          echo "UDP interception is widened to all target ports for runtime drop smoke verification"
        fi
      else
        echo "Generic UDP TPROXY is enabled for any target port in the selected ${EFFECTIVE_IP_FAMILY} family (guarded_unstable contract)"
      fi
    fi
    echo "Run aegis-client with [ingress.wide].platform_backend = \"linux_tproxy\" and matching listen port."
    echo "The client must be able to set IP_TRANSPARENT successfully (typically root/CAP_NET_ADMIN)."
    print_next_steps
    ;;
  teardown)
    teardown_firewalld_accept_bridge
    teardown_input_filter
    teardown_chain
    teardown_ipv6_policy
    teardown_policy_routing
    print_contract_summary
    echo "Removed Linux TPROXY helper chain ${CHAIN} for ${EFFECTIVE_IP_FAMILY}"
    ;;
  status)
    show_status
    ;;
  doctor)
    run_doctor
    ;;
  probe)
    run_probe
    ;;
  launch)
    run_launch
    ;;
  events)
    run_events
    ;;
  run)
    run_supervised
    ;;
esac
