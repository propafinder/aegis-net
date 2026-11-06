#!/usr/bin/env bash
# Lab-only helper for Linux wide ingress redirection.
# This script redirects local TCP OUTPUT traffic by default and fail-closes
# leak-prone lanes that are not captured by the TCP redirect contour:
# outbound UDP, DNS-over-TCP, and IPv6 egress. Narrow UDP preview capture can
# still be enabled explicitly with AEGIS_ENABLE_DNS_PREVIEW=1; redirected UDP
# preview packets are allowed to reach the local wide listener.
#
# Important:
# - run under sudo/root
# - TUN installs require the verified service cgroup for OUTPUT loop avoidance
# - compatibility mode uses AEGIS_EXEMPT_UID for a dedicated non-root client
# - this is a bootstrap helper, not a production firewall manager
set -euo pipefail

# The legacy TUN guard has independent ownership from the capture chains below.
# Keep it in this already signed/shipped helper so old release inventories stay
# valid. Capture apply/teardown must never flush or remove this inet table.
legacy_tun_guard() {
  local action="$1" state="${AEGIS_LEGACY_TUN_GUARD_STATE:-/var/lib/aegis-install/client/legacy-tun-guard.conf}"
  local table=aegis_legacy_tun_guard schema='' armed='' service='' tun='' tcp_port='' udp_port='' management_ports='' seen='|' key value text rules path='' inode='' pid='' control=0
  [[ "$action" != guard-version ]] || { echo aegis_legacy_tun_guard_v1; return 0; }
  [[ "$EUID" == 0 ]] || { echo 'ERROR: legacy TUN guard requires root' >&2; return 1; }
  for key in nft flock systemctl; do
    command -v "$key" >/dev/null || { echo "ERROR: legacy TUN guard requires $key" >&2; return 1; }
  done
  # Trusted administrative metadata is never shell-sourced.
  . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/root-state.sh"
  aegis_root_state_init || return 1
  aegis_root_validate "$state" && aegis_root_validate "$state.lock" || return 1
  exec 9>"$state.lock" || return 1
  flock -w 30 9 || { echo 'ERROR: legacy TUN guard lock timed out' >&2; return 1; }
  text="$(aegis_root_read "$state")" || return 1
  while IFS='=' read -r key value; do
    [[ -n "$key" && "$seen" != *"|$key|"* ]] || return 1
    seen+="$key|"
    case "$key" in
      schema) schema="$value";; armed) armed="$value";; service) service="$value";;
      tun) tun="$value";; tcp_port) tcp_port="$value";; udp_port) udp_port="$value";;
      management_ports) management_ports="$value";; *) return 1;;
    esac
  done <<< "$text"
  [[ "$schema" == aegis_legacy_tun_guard_v1 && "$armed" =~ ^[01]$ &&
     "$service" == aegis-client.service && "$tun" == aegis-tun0 &&
     "$tcp_port" == 980 && "$udp_port" == 981 &&
     "$management_ports" =~ ^[0-9]+(,[0-9]+)*$ ]] || {
    echo 'ERROR: invalid legacy TUN guard policy; existing block retained' >&2; return 1;
  }
  local -a ports=()
  IFS=',' read -r -a ports <<< "$management_ports"
  (( ${#ports[@]} <= 16 )) || return 1
  for value in "${ports[@]}"; do
    [[ "$value" =~ ^[1-9][0-9]{0,4}$ ]] && (( value <= 65535 )) || return 1
  done

  legacy_guard_resolve() {
    local expected="$1" member
    path="$(systemctl show "$service" -p ControlGroup --value)" || return 1
    [[ "$path" == /* ]] || return 1
    path="${path#/}"
    [[ "$path" =~ ^[A-Za-z0-9_.@:/-]+$ && "$path" != */ &&
       "$path" != *//* && "/$path/" != */./* && "/$path/" != */../* &&
       "$path" == */aegis-client.service ]] || return 1
    pid="$(systemctl show "$service" -p "$expected" --value)" || return 1
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ "$control" == 0 || "$pid" == "$$" ]] || return 1
    member="$(awk -F: '$1 == "0" && $2 == "" {print $3}' "/proc/$pid/cgroup")" || return 1
    [[ "$member" == "/$path" && "$(stat -f -c %T /sys/fs/cgroup)" == cgroup2fs &&
       -d "/sys/fs/cgroup/$path" ]] || return 1
    inode="$(stat -c %i "/sys/fs/cgroup/$path")" || return 1
  }
  legacy_guard_render() {
    local binding="${1:-}" port level
    printf 'add table inet %s\nflush table inet %s\n' "$table" "$table"
    printf 'add chain inet %s incoming { type filter hook prerouting priority -190; policy accept; }\n' "$table"
    printf 'add chain inet %s output { type filter hook output priority 10; policy drop; }\n' "$table"
    printf 'add chain inet %s forward { type filter hook forward priority 10; policy drop; }\n' "$table"
    printf 'add rule inet %s output oifname "lo" counter accept\n' "$table"
    printf 'add rule inet %s output meta nfproto ipv6 oifname "%s" counter accept\n' "$table" "$tun"
    if [[ -n "$binding" ]]; then
      level="$(awk -F/ '{print NF}' <<< "$binding")"
      printf 'add rule inet %s output socket cgroupv2 level %s "%s" counter accept\n' "$table" "$level" "$binding"
      # OUTPUT still has the uplink before REDIRECT rerouting. Only the fixed
      # loopback DNAT tuples reach capture; an external :980/:981 is denied.
      printf 'add rule inet %s output ip daddr 127.0.0.1 ct status dnat tcp dport %s counter accept\n' "$table" "$tcp_port"
      printf 'add rule inet %s output ip daddr 127.0.0.1 ct status dnat udp dport %s counter accept\n' "$table" "$udp_port"
    fi
    for port in "${ports[@]}"; do
      printf 'add rule inet %s incoming fib daddr type local tcp dport %s ct direction original ct state { new, established } ct mark set 0xa3610010\n' "$table" "$port"
      printf 'add rule inet %s output meta l4proto tcp ct direction reply ct mark 0xa3610010 ct original proto-dst %s tcp sport %s counter accept\n' "$table" "$port" "$port"
    done
    # Bootstrap exceptions are narrow protocols, never native DNS or general
    # established egress. DHCP raw packet handling/initramfs remains a separate
    # native acceptance gate; this guard begins at network-pre in the root OS.
    printf 'add rule inet %s output ip daddr 255.255.255.255 udp sport 68 udp dport 67 counter accept\n' "$table"
    printf 'add rule inet %s output ip6 saddr fe80::/10 ip6 daddr ff02::1:2 udp sport 546 udp dport 547 counter accept\n' "$table"
    printf 'add rule inet %s output ip6 hoplimit 255 ip6 daddr { fe80::/10, ff02::/16 } icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } counter accept\n' "$table"
    printf 'add rule inet %s output counter drop\nadd rule inet %s forward counter drop\n' "$table" "$table"
  }
  legacy_guard_apply() {
    local data="$1"
    nft --check --file - <<< "$data" && nft --file - <<< "$data"
  }
  if [[ "$action" == guard-release ]]; then
    # A direct console recovery uses the same cleanup-last boundary as the
    # disconnect wrapper. Missing/failed inspectors never count as clean.
    local inspected
    for key in iptables-save ip6tables-save ip; do command -v "$key" >/dev/null || return 1; done
    if systemctl is-active --quiet aegis-wide-tun-firewall.service ||
       systemctl is-active --quiet aegis-wide.service; then
      echo 'ERROR: stop capture persistence before releasing the legacy guard' >&2; return 1
    fi
    for key in iptables-save ip6tables-save; do
      inspected="$("$key")" || return 1
      [[ "$inspected" != *AEGIS_WIDE* ]] || { echo 'ERROR: capture firewall remains; guard retained' >&2; return 1; }
    done
    inspected="$(ip -o link show)" || return 1
    [[ "$inspected" != *aegis-tun* ]] || { echo 'ERROR: capture TUN remains; guard retained' >&2; return 1; }
    inspected="$(nft list tables)" || return 1
    [[ "$inspected" != *aegis_wide* ]] || { echo 'ERROR: capture nft table remains; guard retained' >&2; return 1; }
    # Durable disarm first; a crash leaves the table and recovery record. A
    # surviving old unit may run block/bind, but armed=0 never deletes policy.
    printf '%s\n' "${text/armed=1/armed=0}" | aegis_root_write "$state" 0600 || return 1
    systemctl disable aegis-legacy-tun-guard.service || return 1
    aegis_root_remove /etc/systemd/system/aegis-client.service.d/29-legacy-tun-guard.conf || return 1
    for key in NetworkManager systemd-networkd networking; do
      aegis_root_remove "/etc/systemd/system/$key.service.d/29-aegis-legacy-tun-guard.conf" || return 1
    done
    aegis_root_remove /etc/systemd/system/aegis-legacy-tun-guard.service || return 1
    systemctl daemon-reload || return 1
    # Remove loaded Requires edges before stopping the guard so recovery does
    # not cascade-stop the restored SOCKS client or the network manager.
    systemctl stop aegis-legacy-tun-guard.service || return 1
    local tables
    tables="$(nft list tables)" || return 1
    if grep -Fxq "table inet $table" <<< "$tables"; then
      nft delete table inet "$table" || return 1
    fi
    # Keep the disarmed record as a retryable recovery receipt.
    return 0
  fi
  [[ "$armed" == 1 ]] || return 0
  case "$action" in
    guard-block) rules="$(legacy_guard_render)"; legacy_guard_apply "$rules";;
    guard-bind|guard-refresh|guard-preflight)
      local expected=MainPID previous_path previous_inode previous_pid
      local unprivileged_start
      read -r unprivileged_start < /proc/sys/net/ipv4/ip_unprivileged_port_start || return 1
      [[ "$unprivileged_start" =~ ^[0-9]{1,5}$ ]] && (( unprivileged_start > 981 && unprivileged_start <= 65535 )) || {
        echo 'ERROR: kernel permits unprivileged capture-port binding; guard retained' >&2; return 1;
      }
      if [[ "$action" == guard-bind ]]; then expected=ControlPID; control=1; fi
      legacy_guard_resolve "$expected" || { echo 'ERROR: no verified current client cgroup; guard retained' >&2; return 1; }
      previous_path="$path"; previous_inode="$inode"; previous_pid="$pid"
      rules="$(legacy_guard_render "$path")" || return 1
      nft --check --file - <<< "$rules" || return 1
      [[ "$action" != guard-preflight ]] || return 0
      nft --file - <<< "$rules" || return 1
      if ! legacy_guard_resolve "$expected" || [[ "$path" != "$previous_path" || "$inode" != "$previous_inode" || "$pid" != "$previous_pid" ]]; then
        legacy_guard_apply "$(legacy_guard_render)" || { echo 'ERROR: emergency legacy guard block failed' >&2; return 1; }
        echo 'ERROR: client cgroup changed during binding; guard re-blocked' >&2
        return 1
      fi;;
    *) echo 'ERROR: unknown legacy TUN guard action' >&2; return 2;;
  esac
}
case "${1:-}" in
  guard-version|guard-block|guard-bind|guard-refresh|guard-preflight|guard-release)
    [[ $# == 1 ]] || { echo 'ERROR: guard action accepts no extra arguments' >&2; exit 2; }
    legacy_tun_guard "$1"
    exit $?;;
esac

ACTION="${1:-}"
CHAIN="${AEGIS_WIDE_CHAIN:-AEGIS_WIDE}"
OUTPUT_CHAIN="${CHAIN}_OUTPUT"
PREROUTING_CHAIN="${CHAIN}_PREROUTING"
FILTER_CHAIN="${CHAIN}_FILTER"
FORWARD_FILTER_CHAIN="${CHAIN}_FORWARD"
IPV6_FILTER_CHAIN="${CHAIN}_V6"
WIDE_PORT="${AEGIS_WIDE_PORT:-15080}"
EXEMPT_UID="${AEGIS_EXEMPT_UID:-}"
ENABLE_PREROUTING="${AEGIS_ENABLE_PREROUTING:-0}"
INTERFACE="${AEGIS_WIDE_INTERFACE:-}"
ENABLE_DNS_PREVIEW="${AEGIS_ENABLE_DNS_PREVIEW:-0}"
# When 1, this script also repoints /etc/resolv.conf at the client's fake-IP DNS
# listener (127.0.0.1:53) and stops systemd-resolved's stub, restoring both on
# teardown. Only the install.sh direct/tun path sets this (the aegis-wide-enable.sh
# wrapper does its own resolv.conf handling, so it MUST leave this at 0 to avoid
# double-management). Without it the fake-IP DNS server is silently bypassed.
MANAGE_RESOLV="${AEGIS_WIDE_MANAGE_RESOLV:-0}"
NETWORKMANAGER_DNS_CONF="/run/NetworkManager/conf.d/90-aegis-wide-dns.conf"
DNS_PORT="${AEGIS_DNS_PORT:-53}"
ENABLE_BLOCK_POLICY="${AEGIS_WIDE_BLOCK_LEAKS:-1}"
BLOCK_UDP="${AEGIS_WIDE_BLOCK_UDP:-1}"
# Management exceptions are replies to incoming local TCP connections only.
# This does not admit an application-originated established connection.
MANAGEMENT_PORTS_RAW="${AEGIS_WIDE_MANAGEMENT_PORTS:-22}"
MANAGEMENT_PORTS=()
# Compatibility-only destination exclusions. Strict service-cgroup mode ignores
# these entirely, so another application reaching the relay/CDN IP is captured.
RELAY_EXCLUDE_IPS="${AEGIS_WIDE_RELAY_EXCLUDE_IPS:-}"
CAPTURE_ROOT="${AEGIS_WIDE_CAPTURE_ROOT:-0}"
# Compatibility-only socket mark exception. Strict mode ignores it; a marked
# socket outside the verified service cgroup must remain captured.
DIRECT_SOCKET_MARK="${AEGIS_DIRECT_SOCKET_MARK:-}"
# Strict OUTPUT exemption: a service cgroup replaces broad uid/IP exceptions.
# EXEMPT_CGROUP is a cgroup-v2 path relative to /sys/fs/cgroup. When a service is
# named, require systemd's current MainPID to belong to that exact cgroup and
# re-resolve it on every apply (kernel matches bind to the current cgroup object).
REQUIRE_CGROUP="${AEGIS_WIDE_REQUIRE_CGROUP:-0}"
EXEMPT_CGROUP="${AEGIS_WIDE_EXEMPT_CGROUP:-}"
EXEMPT_SERVICE="${AEGIS_WIDE_EXEMPT_SERVICE:-}"
EXPECTED_SERVICE_PID="${AEGIS_WIDE_EXPECTED_SERVICE_PID:-}"
EXPECTED_CGROUP_INODE="${AEGIS_WIDE_EXPECTED_CGROUP_INODE:-}"
# Optional listener-readiness generation admission. Both pins are required and
# only the verified live systemd service can satisfy them; no UID/IP fallback.
case "${ACTION}" in
  apply|preflight|cgroup-path)
    if [[ -n "${EXPECTED_SERVICE_PID}${EXPECTED_CGROUP_INODE}" ]]; then
      [[ "${EXPECTED_SERVICE_PID}" =~ ^[1-9][0-9]*$ &&
         "${EXPECTED_CGROUP_INODE}" =~ ^[1-9][0-9]*$ && -n "${EXEMPT_SERVICE}" ]] || {
        echo 'FATAL: expected service generation requires a valid paired PID/inode and verified service' >&2; exit 2;
      }
    fi
    ;;
  *)
    # Independent teardown/status must work after a stop or interrupted caller.
    # Common namespace, path, bounds and rollback-file guards still apply.
    EXPECTED_SERVICE_PID=""
    EXPECTED_CGROUP_INODE=""
    ;;
esac
CGROUP_MODE=0
CGROUP_PID=""
CGROUP_INODE=""
if [[ "$REQUIRE_CGROUP" != 0 && "$REQUIRE_CGROUP" != 1 ]]; then
  echo 'FATAL: AEGIS_WIDE_REQUIRE_CGROUP must be 0 or 1' >&2
  exit 2
fi
if [[ "$REQUIRE_CGROUP" == 1 || -n "$EXEMPT_CGROUP$EXEMPT_SERVICE" ]]; then
  CGROUP_MODE=1
fi

valid_cgroup_path() {
  local value="$1"
  [[ -n "$value" && "$value" != /* && "$value" != */ && "$value" != *//* &&
     "$value" =~ ^[A-Za-z0-9_.@:/-]+$ &&
     "/$value/" != */./* && "/$value/" != */../* ]]
}

networkmanager_dns_hold() {
  systemctl is-active --quiet NetworkManager 2>/dev/null || return 0
  if [[ -e "${NETWORKMANAGER_DNS_CONF}" ]] &&
     ! grep -q '^# Managed by Aegis wide DNS preview$' "${NETWORKMANAGER_DNS_CONF}" 2>/dev/null; then
    echo "FATAL: refusing to replace non-Aegis NetworkManager DNS configuration at ${NETWORKMANAGER_DNS_CONF}" >&2
    return 1
  fi
  install -d -m 0755 "$(dirname "${NETWORKMANAGER_DNS_CONF}")"
  cat > "${NETWORKMANAGER_DNS_CONF}" <<'EOF'
# Managed by Aegis wide DNS preview
[main]
dns=none
EOF
  chmod 0644 "${NETWORKMANAGER_DNS_CONF}"
  if ! systemctl reload NetworkManager 2>/dev/null; then
    rm -f "${NETWORKMANAGER_DNS_CONF}"
    echo "FATAL: NetworkManager refused the temporary dns=none guard" >&2
    return 1
  fi
}

networkmanager_dns_release() {
  if [[ -f "${NETWORKMANAGER_DNS_CONF}" ]] &&
     grep -q '^# Managed by Aegis wide DNS preview$' "${NETWORKMANAGER_DNS_CONF}" 2>/dev/null; then
    rm -f "${NETWORKMANAGER_DNS_CONF}"
    systemctl reload NetworkManager 2>/dev/null || true
  fi
}

resolve_service_cgroup() {
  [[ "$CGROUP_MODE" == 1 ]] || return 0
  local resolved="$EXEMPT_CGROUP" pid="" member=""
  if [[ -n "$EXEMPT_SERVICE" ]]; then
    if [[ ! "$EXEMPT_SERVICE" =~ ^[A-Za-z0-9][A-Za-z0-9_.@:-]*\.service$ ]]; then
      echo 'FATAL: invalid cgroup exemption service name' >&2; return 1
    fi
    [[ "$(systemctl show "$EXEMPT_SERVICE" -p ActiveState --value)" == active ]] || {
      echo 'FATAL: cgroup exemption service is not active' >&2; return 1;
    }
    pid="$(systemctl show "$EXEMPT_SERVICE" -p MainPID --value)" || return 1
    [[ "$pid" =~ ^[0-9]+$ && "$pid" != 0 ]] || {
      echo 'FATAL: cgroup exemption service has no live MainPID' >&2; return 1;
    }
    resolved="$(systemctl show "$EXEMPT_SERVICE" -p ControlGroup --value)" || return 1
    [[ "$resolved" == /* ]] || return 1
    resolved="${resolved#/}"
    [[ -z "$EXEMPT_CGROUP" || "$resolved" == "$EXEMPT_CGROUP" ]] || {
      echo 'FATAL: service cgroup differs from the recorded capture identity' >&2; return 1;
    }
    member="$(awk -F: '$1 == "0" && $2 == "" { print $3 }' "/proc/$pid/cgroup")" || return 1
    [[ "$member" == "/$resolved" ]] || {
      echo 'FATAL: service MainPID does not belong to the reported cgroup' >&2; return 1;
    }
  fi
  valid_cgroup_path "$resolved" || {
    echo 'FATAL: strict capture requires a non-root canonical cgroup path' >&2; return 1;
  }
  [[ "$(stat -f -c %T /sys/fs/cgroup)" == cgroup2fs &&
     -d "/sys/fs/cgroup/$resolved" && -r "/sys/fs/cgroup/$resolved/cgroup.procs" ]] || {
    echo 'FATAL: strict capture requires an existing readable cgroup-v2 path' >&2; return 1;
  }
  EXEMPT_CGROUP="$resolved"
  CGROUP_PID="$pid"
  CGROUP_INODE="$(stat -c %i "/sys/fs/cgroup/$resolved")" || return 1
  if [[ -n "${EXPECTED_SERVICE_PID}" ]]; then
    [[ "${CGROUP_PID}" == "${EXPECTED_SERVICE_PID}" && "${CGROUP_INODE}" == "${EXPECTED_CGROUP_INODE}" ]] || {
      echo 'FATAL: service generation differs from listener readiness; capture refused' >&2; return 1;
    }
  fi
}

probe_cgroup_match() {
  local command="$1" table="$2" probe="AEGIS_CG_${BASHPID:-$$}" result=0
  # Probe an unhooked owned chain. Unsupported kernel/path matches fail before
  # touching the active AEGIS chains or network hooks; never fall back to uid/IP.
  "$command" -t "$table" -N "$probe" || return 1
  "$command" -t "$table" -A "$probe" -m cgroup --path "$EXEMPT_CGROUP" -j RETURN || result=1
  "$command" -t "$table" -F "$probe" || result=1
  "$command" -t "$table" -X "$probe" || result=1
  return "$result"
}

preflight_cgroup() {
  [[ "$CGROUP_MODE" == 1 ]] || return 0
  resolve_service_cgroup || return 1
  if ! probe_cgroup_match iptables nat || ! probe_cgroup_match iptables filter ||
     { [[ "$ENABLE_BLOCK_POLICY" == 1 && "$BLOCK_IPV6" == 1 ]] && ! probe_cgroup_match ip6tables filter; }; then
    echo 'FATAL: kernel cgroup match unavailable; strict capture was not activated' >&2
    return 1
  fi
}

verify_cgroup_identity() {
  [[ "$CGROUP_MODE" == 1 ]] || return 0
  local previous_pid="$CGROUP_PID" previous_inode="$CGROUP_INODE"
  resolve_service_cgroup || return 1
  [[ "$CGROUP_PID" == "$previous_pid" && "$CGROUP_INODE" == "$previous_inode" ]] || {
    echo 'FATAL: client restarted while preparing cgroup capture; retry after readiness' >&2; return 1;
  }
}

# Audit H4: EXEMPT_UID is interpolated into `iptables ... --uid-owner` and
# INTERFACE into `iptables ... -i`. Reject anything that is not a plain numeric
# UID / a well-formed interface name so a hostile env var cannot inject extra
# iptables arguments or rules (e.g. a leading '-' or embedded whitespace).
if [[ -n "${EXEMPT_UID}" && ! "${EXEMPT_UID}" =~ ^[0-9]+$ ]]; then
  echo "FATAL: AEGIS_EXEMPT_UID must be numeric (got '${EXEMPT_UID}')" >&2
  exit 2
fi
if [[ -n "${DIRECT_SOCKET_MARK}" ]] &&
   { [[ ! "${DIRECT_SOCKET_MARK}" =~ ^[0-9]+$ ]] ||
     (( DIRECT_SOCKET_MARK < 1 || DIRECT_SOCKET_MARK > 4294967295 )); }; then
  echo "FATAL: AEGIS_DIRECT_SOCKET_MARK must be a non-zero u32 (got '${DIRECT_SOCKET_MARK}')" >&2
  exit 2
fi
if [[ -n "${INTERFACE}" && ! "${INTERFACE}" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{0,14}$ ]]; then
  echo "FATAL: AEGIS_WIDE_INTERFACE must be a valid interface name (got '${INTERFACE}')" >&2
  exit 2
fi
# Audit H4 hygiene: every RELAY_EXCLUDE_IPS entry is interpolated into
# `iptables ... -d`, so reject anything that is not a plain IPv4 literal (optionally
# with a /prefix) before it reaches iptables.
for _rip in ${RELAY_EXCLUDE_IPS}; do
  if [[ ! "${_rip}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]]; then
    echo "FATAL: AEGIS_WIDE_RELAY_EXCLUDE_IPS entry is not an IPv4 address (got '${_rip}')" >&2
    exit 2
  fi
done

# Keep the client's own relay/MASQUE egress off `${chain}` by DESTINATION IP
# (both TCP and UDP), so loop-avoidance holds even when the client runs as root.
add_relay_exclude_returns() {
  local table="$1" chain="$2" ip
  [[ "$CGROUP_MODE" == 0 ]] || return 0
  for ip in ${RELAY_EXCLUDE_IPS}; do
    iptables -t "${table}" -A "${chain}" -d "${ip}" -p tcp -j RETURN
    iptables -t "${table}" -A "${chain}" -d "${ip}" -p udp -j RETURN
  done
}
# Bidirectional generic-UDP carry: when set to a port, outbound UDP (including
# external DNS) is REDIRECTed to the AEGIS UDP redirect proxy. The proxy uses
# conntrack to recover the pre-NAT destination, carries the datagram over
# MASQUE direct, and injects the response transparently. Loopback is returned
# before this catch-all, so the local fake-IP DNS listener remains reachable.
# The filter chain still drops anything NOT redirected, preventing native UDP
# leaks.
UDP_REDIRECT_PORT="${AEGIS_WIDE_UDP_REDIRECT_PORT:-}"
BLOCK_TCP_DNS="${AEGIS_WIDE_BLOCK_TCP_DNS:-1}"
BLOCK_IPV6="${AEGIS_WIDE_BLOCK_IPV6:-1}"
# full-wide-tun: when set, IPv6 routed INTO this TUN device is allowed (it is
# carried by the smoltcp engine -> relay), and only IPv6 escaping to the real WAN
# is rejected. Empty (default) = plain fail-closed IPv6 block (no tun).
IPV6_TUN_DEV="${AEGIS_WIDE_IPV6_TUN_DEV:-}"
EXTRA_UDP_PREVIEW_PORTS_RAW="${AEGIS_UDP_PREVIEW_PORTS:-}"
EXTRA_UDP_PREVIEW_PORTS=()

require_numeric_port() {
  local name="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[0-9]+$ ]] || (( value < 1 || value > 65535 )); then
    echo "${name} must be a TCP/UDP port in range 1..65535 (got ${value})" >&2
    exit 1
  fi
}

normalize_management_ports() {
  local port seen='|'
  [[ "$MANAGEMENT_PORTS_RAW" =~ ^[1-9][0-9]{0,4}(,[1-9][0-9]{0,4})*$ ]] || {
    echo 'AEGIS_WIDE_MANAGEMENT_PORTS requires canonical TCP ports' >&2; return 1;
  }
  IFS=',' read -r -a MANAGEMENT_PORTS <<< "$MANAGEMENT_PORTS_RAW"
  (( ${#MANAGEMENT_PORTS[@]} <= 16 )) || return 1
  for port in "${MANAGEMENT_PORTS[@]}"; do
    (( port <= 65535 )) && [[ "$seen" != *"|$port|"* ]] || return 1
    seen+="$port|"
  done
}

normalize_extra_udp_preview_ports() {
  local raw=""
  local port=""
  local existing=""

  EXTRA_UDP_PREVIEW_PORTS=()
  [[ -z "${EXTRA_UDP_PREVIEW_PORTS_RAW}" ]] && return 0

  IFS=',' read -r -a EXTRA_UDP_PREVIEW_PORT_CANDIDATES <<< "${EXTRA_UDP_PREVIEW_PORTS_RAW}"
  for raw in "${EXTRA_UDP_PREVIEW_PORT_CANDIDATES[@]}"; do
    port="${raw//[[:space:]]/}"
    require_numeric_port "AEGIS_UDP_PREVIEW_PORTS" "${port}"
    if [[ "${port}" == "${DNS_PORT}" ]]; then
      continue
    fi
    for existing in "${EXTRA_UDP_PREVIEW_PORTS[@]}"; do
      if [[ "${existing}" == "${port}" ]]; then
        port=""
        break
      fi
    done
    if [[ -n "${port}" ]]; then
      EXTRA_UDP_PREVIEW_PORTS+=("${port}")
    fi
  done
}

if [[ -z "${ACTION}" || ( "${ACTION}" != "apply" && "${ACTION}" != "teardown" && "${ACTION}" != "status" && "${ACTION}" != "preflight" && "${ACTION}" != "cgroup-path" ) ]]; then
  echo "Usage: sudo $0 apply|teardown|status|preflight|cgroup-path" >&2
  exit 1
fi

if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables is required" >&2
  exit 1
fi

if [[ "${ENABLE_BLOCK_POLICY}" == "1" && "${BLOCK_IPV6}" == "1" ]] && ! command -v ip6tables >/dev/null 2>&1; then
  echo "ip6tables is required when AEGIS_WIDE_BLOCK_IPV6=1" >&2
  exit 1
fi

create_output_chain() {
  iptables -t nat -N "${OUTPUT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "${OUTPUT_CHAIN}"

  iptables -t nat -A "${OUTPUT_CHAIN}" -o lo -j RETURN
  if [[ "$CGROUP_MODE" == 1 ]]; then
    iptables -t nat -A "${OUTPUT_CHAIN}" -m cgroup --path "$EXEMPT_CGROUP" -j RETURN
  elif [[ -n "${DIRECT_SOCKET_MARK}" ]]; then
    iptables -t nat -A "${OUTPUT_CHAIN}" -m mark --mark "${DIRECT_SOCKET_MARK}" -j RETURN
  fi
  # Legacy IP exemptions are disabled by add_relay_exclude_returns in strict mode.
  add_relay_exclude_returns nat "${OUTPUT_CHAIN}"
  if [[ "$CGROUP_MODE" == 1 ]]; then
    : # only the verified service cgroup is exempt, including root runtime
  elif [[ "${CAPTURE_ROOT}" == "1" && -n "${RELAY_EXCLUDE_IPS}" ]]; then
    # Root-capture mode: the relay leg is exempted by IP above, so we deliberately
    # do NOT exempt uid 0 — root-originated traffic is captured like everyone
    # else (closes the multi-service-host leak where root daemons egress natively).
    :
  elif [[ -n "${EXEMPT_UID}" ]]; then
    # Owner-based loop avoidance is only valid for locally generated OUTPUT
    # traffic, so keep it out of the PREROUTING path entirely.
    iptables -t nat -A "${OUTPUT_CHAIN}" -m owner --uid-owner "${EXEMPT_UID}" -j RETURN
  else
    echo "WARN: AEGIS_EXEMPT_UID is not set; redirected traffic may loop back into aegis-client" >&2
  fi
  # A listener port is exempt only when the destination belongs to this host.
  # Matching the port alone would let applications reach any external host on
  # that port without passing through the relay. The earlier lo rule also keeps
  # loopback listeners reachable, including post-REDIRECT traffic.
  iptables -t nat -A "${OUTPUT_CHAIN}" -m addrtype --dst-type LOCAL -p tcp --dport "${WIDE_PORT}" -j RETURN
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" && -z "${UDP_REDIRECT_PORT}" ]]; then
    iptables -t nat -A "${OUTPUT_CHAIN}" -m addrtype --dst-type LOCAL -p udp --dport "${WIDE_PORT}" -j RETURN
  fi
  iptables -t nat -A "${OUTPUT_CHAIN}" -p tcp -j REDIRECT --to-ports "${WIDE_PORT}"
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" && -z "${UDP_REDIRECT_PORT}" ]]; then
    # Keep UDP preview intentionally controlled: redirect the primary DNS port
    # plus any explicitly configured extra preview ports into the same preview
    # socket, while leaving the rest of UDP untouched. When bidirectional UDP
    # carry is active this one-shot preview path MUST be skipped: REDIRECT has
    # already replaced the original destination by the time the wide listener
    # receives the datagram, whereas the generic proxy recovers it via
    # conntrack and can also return the response.
    iptables -t nat -A "${OUTPUT_CHAIN}" -p udp --dport "${DNS_PORT}" -j REDIRECT --to-ports "${WIDE_PORT}"
    for port in "${EXTRA_UDP_PREVIEW_PORTS[@]}"; do
      iptables -t nat -A "${OUTPUT_CHAIN}" -p udp --dport "${port}" -j REDIRECT --to-ports "${WIDE_PORT}"
    done
  fi
  if [[ -n "${UDP_REDIRECT_PORT}" ]]; then
    # Bidirectional generic-UDP carry. Order matters: the EXEMPT_UID and lo
    # RETURNs above already keep the proxy's own MASQUE egress, transparent
    # replies, and the local fake-IP DNS listener out of this redirect. Exempt
    # only the local proxy's port, then redirect every remaining UDP destination
    # (including external DNS/53 and QUIC/443) to the conntrack-aware proxy.
    iptables -t nat -A "${OUTPUT_CHAIN}" -m addrtype --dst-type LOCAL -p udp --dport "${UDP_REDIRECT_PORT}" -j RETURN
    iptables -t nat -A "${OUTPUT_CHAIN}" -p udp -j REDIRECT --to-ports "${UDP_REDIRECT_PORT}"
  fi
}

create_prerouting_chain() {
  iptables -t nat -N "${PREROUTING_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "${PREROUTING_CHAIN}"

  # PREROUTING cannot use OUTPUT-only matches like `-o` or `owner`, so keep a
  # dedicated chain for interface-scoped ingress redirect. addrtype also works
  # before routing: traffic addressed to this host's listener is local, whereas
  # routed traffic to an external host on the same port must still be captured.
  iptables -t nat -A "${PREROUTING_CHAIN}" -m addrtype --dst-type LOCAL -p tcp --dport "${WIDE_PORT}" -j RETURN
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    iptables -t nat -A "${PREROUTING_CHAIN}" -m addrtype --dst-type LOCAL -p udp --dport "${WIDE_PORT}" -j RETURN
  fi
  iptables -t nat -A "${PREROUTING_CHAIN}" -p tcp -j REDIRECT --to-ports "${WIDE_PORT}"
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
    iptables -t nat -A "${PREROUTING_CHAIN}" -p udp --dport "${DNS_PORT}" -j REDIRECT --to-ports "${WIDE_PORT}"
    for port in "${EXTRA_UDP_PREVIEW_PORTS[@]}"; do
      iptables -t nat -A "${PREROUTING_CHAIN}" -p udp --dport "${port}" -j REDIRECT --to-ports "${WIDE_PORT}"
    done
  fi
}

create_filter_chain() {
  if [[ "${ENABLE_BLOCK_POLICY}" != "1" ]]; then
    return 0
  fi

  iptables -t filter -N "${FILTER_CHAIN}" 2>/dev/null || true
  iptables -t filter -F "${FILTER_CHAIN}"

  iptables -t filter -A "${FILTER_CHAIN}" -o lo -j RETURN
  if [[ "$CGROUP_MODE" == 1 ]]; then
    iptables -t filter -A "${FILTER_CHAIN}" -m cgroup --path "$EXEMPT_CGROUP" -j RETURN
  elif [[ -n "${DIRECT_SOCKET_MARK}" ]]; then
    iptables -t filter -A "${FILTER_CHAIN}" -m mark --mark "${DIRECT_SOCKET_MARK}" -j RETURN
  fi
  # Never REJECT the client's own relay/MASQUE egress (its UDP MASQUE leg reaches
  # the fixed origin, which is not redirected and would otherwise be dropped here).
  add_relay_exclude_returns filter "${FILTER_CHAIN}"
  if [[ "$CGROUP_MODE" == 1 ]]; then
    :
  elif [[ "${CAPTURE_ROOT}" == "1" && -n "${RELAY_EXCLUDE_IPS}" ]]; then
    : # root-capture mode: relay leg exempted by IP above; do not exempt all uid 0.
  elif [[ -n "${EXEMPT_UID}" ]]; then
    iptables -t filter -A "${FILTER_CHAIN}" -m owner --uid-owner "${EXEMPT_UID}" -j RETURN
  else
    echo "WARN: AEGIS_EXEMPT_UID is not set; block policy may also affect aegis-client egress" >&2
  fi
  iptables -t filter -A "${FILTER_CHAIN}" -m addrtype --dst-type LOCAL -p udp --dport "${WIDE_PORT}" -j RETURN
  if [[ -n "${UDP_REDIRECT_PORT}" ]]; then
    # Never reject traffic to the bidirectional UDP proxy (post-REDIRECT it is
    # loopback-bound and already RETURNed by -o lo, but keep it explicit).
    iptables -t filter -A "${FILTER_CHAIN}" -m addrtype --dst-type LOCAL -p udp --dport "${UDP_REDIRECT_PORT}" -j RETURN
  fi

  if [[ -z "$IPV6_TUN_DEV" ]]; then
    # REDIRECT may retain the old uplink at this hook. Only its fixed local
    # conntrack-confirmed tuple is capture traffic; external same-port traffic
    # and pre-existing direct TCP flows must reach the terminal denial.
    iptables -t filter -A "${FILTER_CHAIN}" -d 127.0.0.1 -p tcp --dport "$WIDE_PORT" -m conntrack --ctstate DNAT -j RETURN
    local port
    for port in "${MANAGEMENT_PORTS[@]}"; do
      iptables -t filter -A "${FILTER_CHAIN}" -p tcp --sport "$port" -m addrtype --src-type LOCAL -m conntrack --ctdir REPLY --ctorigdstport "$port" --ctstate ESTABLISHED -j RETURN
    done
  fi
  if [[ "${BLOCK_UDP}" == "1" ]]; then
    iptables -t filter -A "${FILTER_CHAIN}" -p udp --dport "${DNS_PORT}" -j REJECT --reject-with icmp-port-unreachable
  fi
  if [[ "${BLOCK_TCP_DNS}" == "1" ]]; then
    iptables -t filter -A "${FILTER_CHAIN}" -p tcp --dport "${DNS_PORT}" -j REJECT --reject-with tcp-reset
  fi
  if [[ "${BLOCK_UDP}" == "1" ]]; then
    iptables -t filter -A "${FILTER_CHAIN}" -p udp -j REJECT --reject-with icmp-port-unreachable
  fi
  if [[ -z "$IPV6_TUN_DEV" ]]; then
    # Preserve the caller's explicit partial UDP opt-out; default wide mode
    # denies it above. FullTun uses its separately owned device guard and is
    # never granted a TUN-name exemption by this redirect backstop.
    if [[ "$BLOCK_UDP" != 1 ]]; then
      iptables -t filter -A "${FILTER_CHAIN}" -p udp -j RETURN
    fi
    iptables -t filter -A "${FILTER_CHAIN}" -j DROP
  fi
}

create_forward_filter_chain() {
  [[ "$ENABLE_BLOCK_POLICY" == 1 ]] || return 0
  local firewall
  for firewall in iptables ip6tables; do
    command -v "$firewall" >/dev/null || continue
    "$firewall" -t filter -N "$FORWARD_FILTER_CHAIN" 2>/dev/null || true
    "$firewall" -t filter -F "$FORWARD_FILTER_CHAIN"
    # PREROUTING capture is local delivery. No legacy redirect mode admits
    # native routed LAN traffic; the opt-in gateway needs its own sealed owner.
    "$firewall" -t filter -A "$FORWARD_FILTER_CHAIN" -j DROP
  done
}

create_ipv6_filter_chain() {
  if [[ "${ENABLE_BLOCK_POLICY}" != "1" || "${BLOCK_IPV6}" != "1" ]]; then
    return 0
  fi

  ip6tables -t filter -N "${IPV6_FILTER_CHAIN}" 2>/dev/null || true
  ip6tables -t filter -F "${IPV6_FILTER_CHAIN}"

  ip6tables -t filter -A "${IPV6_FILTER_CHAIN}" -o lo -j RETURN
  # full-wide-tun: allow IPv6 that the kernel routed INTO the AEGIS TUN (it is
  # terminated by smoltcp and carried over the relay). Anything NOT going into the
  # tun (i.e. headed for the real WAN) still hits the REJECT below — fail-closed.
  if [[ -n "${IPV6_TUN_DEV}" ]]; then
    ip6tables -t filter -A "${IPV6_FILTER_CHAIN}" -o "${IPV6_TUN_DEV}" -j RETURN
  fi
  if [[ "$CGROUP_MODE" == 1 ]]; then
    ip6tables -t filter -A "${IPV6_FILTER_CHAIN}" -m cgroup --path "$EXEMPT_CGROUP" -j RETURN
  elif [[ "${CAPTURE_ROOT}" == "1" && -n "${RELAY_EXCLUDE_IPS}" ]]; then
    # Match the IPv4 root-capture contract above. The root client reaches its
    # pinned IPv4 relay/MASQUE endpoints through destination exclusions, so an
    # owner exemption here would let every root process escape over native IPv6
    # whenever the non-persistent TUN disappears during stop/crash teardown.
    :
  elif [[ -n "${EXEMPT_UID}" ]]; then
    ip6tables -t filter -A "${IPV6_FILTER_CHAIN}" -m owner --uid-owner "${EXEMPT_UID}" -j RETURN
  else
    echo "WARN: AEGIS_EXEMPT_UID is not set; IPv6 block policy may also affect aegis-client egress" >&2
  fi
  # The backstop must still reject external same-port traffic when no TUN
  # exists (or a more-specific route sends the packet to the WAN).
  ip6tables -t filter -A "${IPV6_FILTER_CHAIN}" -m addrtype --dst-type LOCAL -p tcp --dport "${WIDE_PORT}" -j RETURN
  ip6tables -t filter -A "${IPV6_FILTER_CHAIN}" -m addrtype --dst-type LOCAL -p udp --dport "${WIDE_PORT}" -j RETURN
  ip6tables -t filter -A "${IPV6_FILTER_CHAIN}" -j REJECT
}

hook_chain() {
  # Audit A (activation-window leak-race): attach the fail-closed blocks
  # (IPv6 REJECT + generic UDP + TCP-DNS) BEFORE enabling the IPv4 capture hook.
  # Hooking IPv4 capture first left a window where IPv4 was already redirected
  # while IPv6/UDP still egressed natively — observed live: a request escaped
  # over native IPv6 right after `apply`. Blocks-first means IPv6/UDP are
  # fail-closed from t=0 of activation; IPv4 only ever goes native -> captured.
  if [[ "${ENABLE_BLOCK_POLICY}" == "1" ]]; then
    local firewall
    for firewall in iptables ip6tables; do
      command -v "$firewall" >/dev/null || continue
      if ! "$firewall" -t filter -C FORWARD -j "$FORWARD_FILTER_CHAIN" 2>/dev/null; then
        "$firewall" -t filter -I FORWARD 1 -j "$FORWARD_FILTER_CHAIN"
      fi
    done
    if [[ -z "$IPV6_TUN_DEV" ]] && ! iptables -t filter -C OUTPUT -j "$FILTER_CHAIN" 2>/dev/null; then
      iptables -t filter -I OUTPUT 1 -j "$FILTER_CHAIN"
    fi
    if [[ "${BLOCK_IPV6}" == "1" ]] && ! ip6tables -t filter -C OUTPUT -j "${IPV6_FILTER_CHAIN}" 2>/dev/null; then
      ip6tables -t filter -I OUTPUT 1 -j "${IPV6_FILTER_CHAIN}"
    fi
    if [[ "${BLOCK_UDP}" == "1" ]] && ! iptables -t filter -C OUTPUT -p udp -j "${FILTER_CHAIN}" 2>/dev/null; then
      iptables -t filter -I OUTPUT 1 -p udp -j "${FILTER_CHAIN}"
    fi
    if [[ "${BLOCK_TCP_DNS}" == "1" ]] && ! iptables -t filter -C OUTPUT -p tcp --dport "${DNS_PORT}" -j "${FILTER_CHAIN}" 2>/dev/null; then
      iptables -t filter -I OUTPUT 1 -p tcp --dport "${DNS_PORT}" -j "${FILTER_CHAIN}"
    fi
  fi

  if ! iptables -t nat -C OUTPUT -p tcp -j "${OUTPUT_CHAIN}" 2>/dev/null; then
    iptables -t nat -A OUTPUT -p tcp -j "${OUTPUT_CHAIN}"
  fi
  if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]] && ! iptables -t nat -C OUTPUT -p udp -j "${OUTPUT_CHAIN}" 2>/dev/null; then
    iptables -t nat -A OUTPUT -p udp -j "${OUTPUT_CHAIN}"
  fi
  # The bidirectional UDP redirect needs the nat OUTPUT udp hook even when DNS
  # preview is off (-C guards against a duplicate when both are enabled).
  if [[ -n "${UDP_REDIRECT_PORT}" ]] && ! iptables -t nat -C OUTPUT -p udp -j "${OUTPUT_CHAIN}" 2>/dev/null; then
    iptables -t nat -A OUTPUT -p udp -j "${OUTPUT_CHAIN}"
  fi
  if [[ "${ENABLE_PREROUTING}" == "1" ]]; then
    if [[ -n "${INTERFACE}" ]]; then
      if ! iptables -t nat -C PREROUTING -i "${INTERFACE}" -p tcp -j "${PREROUTING_CHAIN}" 2>/dev/null; then
        iptables -t nat -A PREROUTING -i "${INTERFACE}" -p tcp -j "${PREROUTING_CHAIN}"
      fi
      if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]] && ! iptables -t nat -C PREROUTING -i "${INTERFACE}" -p udp -j "${PREROUTING_CHAIN}" 2>/dev/null; then
        iptables -t nat -A PREROUTING -i "${INTERFACE}" -p udp -j "${PREROUTING_CHAIN}"
      fi
    else
      echo "WARN: AEGIS_WIDE_INTERFACE is not set; PREROUTING redirect will apply to all interfaces" >&2
      if ! iptables -t nat -C PREROUTING -p tcp -j "${PREROUTING_CHAIN}" 2>/dev/null; then
        iptables -t nat -A PREROUTING -p tcp -j "${PREROUTING_CHAIN}"
      fi
      if [[ "${ENABLE_DNS_PREVIEW}" == "1" ]] && ! iptables -t nat -C PREROUTING -p udp -j "${PREROUTING_CHAIN}" 2>/dev/null; then
        iptables -t nat -A PREROUTING -p udp -j "${PREROUTING_CHAIN}"
      fi
    fi
  fi
}

teardown_chain() {
  # Teardown must not depend on the caller repeating the flags used by apply.
  # Rollback/error paths intentionally call this helper with only the port; if
  # UDP carry, DNS preview, or a PREROUTING interface had been enabled, the old
  # conditional deletes left live hooks pointing at an otherwise flushed chain.
  # Delete the known local shapes first, then enumerate every parent jump to the
  # AEGIS-owned chain so an omitted/changed interface cannot leave residue.
  iptables -t nat -D OUTPUT -p tcp -j "${OUTPUT_CHAIN}" 2>/dev/null || true
  iptables -t nat -D OUTPUT -p udp -j "${OUTPUT_CHAIN}" 2>/dev/null || true
  if [[ -n "${INTERFACE}" ]]; then
    iptables -t nat -D PREROUTING -i "${INTERFACE}" -p tcp -j "${PREROUTING_CHAIN}" 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "${INTERFACE}" -p udp -j "${PREROUTING_CHAIN}" 2>/dev/null || true
  else
    iptables -t nat -D PREROUTING -p tcp -j "${PREROUTING_CHAIN}" 2>/dev/null || true
    iptables -t nat -D PREROUTING -p udp -j "${PREROUTING_CHAIN}" 2>/dev/null || true
  fi
  delete_parent_jumps iptables nat OUTPUT "${OUTPUT_CHAIN}"
  delete_parent_jumps iptables nat PREROUTING "${PREROUTING_CHAIN}"
  iptables -t nat -F "${OUTPUT_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "${OUTPUT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "${PREROUTING_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "${PREROUTING_CHAIN}" 2>/dev/null || true
  iptables -t filter -D OUTPUT -j "${FILTER_CHAIN}" 2>/dev/null || true
  iptables -t filter -D OUTPUT -p udp -j "${FILTER_CHAIN}" 2>/dev/null || true
  iptables -t filter -D OUTPUT -p tcp --dport "${DNS_PORT}" -j "${FILTER_CHAIN}" 2>/dev/null || true
  delete_parent_jumps iptables filter OUTPUT "$FILTER_CHAIN"
  local firewall
  for firewall in iptables ip6tables; do
    command -v "$firewall" >/dev/null || continue
    delete_parent_jumps "$firewall" filter FORWARD "$FORWARD_FILTER_CHAIN"
    "$firewall" -t filter -F "$FORWARD_FILTER_CHAIN" 2>/dev/null || true
    "$firewall" -t filter -X "$FORWARD_FILTER_CHAIN" 2>/dev/null || true
  done
  iptables -t filter -F "${FILTER_CHAIN}" 2>/dev/null || true
  iptables -t filter -X "${FILTER_CHAIN}" 2>/dev/null || true
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -t filter -D OUTPUT -j "${IPV6_FILTER_CHAIN}" 2>/dev/null || true
    ip6tables -t filter -F "${IPV6_FILTER_CHAIN}" 2>/dev/null || true
    ip6tables -t filter -X "${IPV6_FILTER_CHAIN}" 2>/dev/null || true
  fi
}

delete_parent_jumps() {
  local firewall="$1" table="$2" parent="$3" target="$4" rule="" index=0
  local -a parts=()
  while IFS= read -r rule; do
    [[ -n "${rule}" ]] || continue
    read -r -a parts <<< "${rule}"
    [[ "${parts[0]:-}" == "-A" ]] || continue
    for ((index = 1; index + 1 < ${#parts[@]}; index++)); do
      if [[ "${parts[index]}" == "-j" && "${parts[index+1]}" == "${target}" ]]; then
        parts[0]="-D"
        "${firewall}" -t "${table}" "${parts[@]}" 2>/dev/null || true
        break
      fi
    done
  done < <("${firewall}" -t "${table}" -S "${parent}" 2>/dev/null || true)
}

show_status() {
  echo "=== nat/${OUTPUT_CHAIN} ==="
  iptables -t nat -S "${OUTPUT_CHAIN}" 2>/dev/null || echo "(chain missing)"
  iptables -t nat -L "${OUTPUT_CHAIN}" -n -v 2>/dev/null || true
  echo "=== nat/${PREROUTING_CHAIN} ==="
  iptables -t nat -S "${PREROUTING_CHAIN}" 2>/dev/null || echo "(chain missing)"
  iptables -t nat -L "${PREROUTING_CHAIN}" -n -v 2>/dev/null || true
  echo "=== nat/OUTPUT hooks ==="
  iptables -t nat -S OUTPUT | sed -n "/${OUTPUT_CHAIN}/p" || true
  echo "=== nat/PREROUTING hooks ==="
  iptables -t nat -S PREROUTING | sed -n "/${PREROUTING_CHAIN}/p" || true
  echo "=== filter/${FILTER_CHAIN} ==="
  iptables -t filter -S "${FILTER_CHAIN}" 2>/dev/null || echo "(chain missing)"
  iptables -t filter -L "${FILTER_CHAIN}" -n -v 2>/dev/null || true
  echo "=== filter/OUTPUT hooks ==="
  iptables -t filter -S OUTPUT | sed -n "/${FILTER_CHAIN}/p" || true
  echo "=== ip6 filter/${IPV6_FILTER_CHAIN} ==="
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -t filter -S "${IPV6_FILTER_CHAIN}" 2>/dev/null || echo "(chain missing)"
    ip6tables -t filter -L "${IPV6_FILTER_CHAIN}" -n -v 2>/dev/null || true
    echo "=== ip6 filter/OUTPUT hooks ==="
    ip6tables -t filter -S OUTPUT | sed -n "/${IPV6_FILTER_CHAIN}/p" || true
  else
    echo "(ip6tables missing)"
  fi
}

# Authenticate rollback files before any firewall or resolver change.
if [[ "${ACTION}" == apply || "${ACTION}" == teardown ]]; then
  # shellcheck source=scripts/lib/root-state.sh
  . "$(dirname "${BASH_SOURCE[0]}")/lib/root-state.sh"
  aegis_root_state_init || exit 1
  AEGIS_WIDE_RESOLVER_SNAPSHOT="${AEGIS_WIDE_RESOLVER_SNAPSHOT:-/var/lib/aegis-install/client/resolver-original.json}"
  if [[ "$MANAGE_RESOLV" == 1 || -e "$AEGIS_WIDE_RESOLVER_SNAPSHOT" || -L "$AEGIS_WIDE_RESOLVER_SNAPSHOT" || -e /etc/resolv.conf.aegis-wide-bak || -L /etc/resolv.conf.aegis-wide-bak ]]; then
    aegis_root_resolver_preflight || exit 1
  fi
fi

case "${ACTION}" in
  cgroup-path)
    [[ "$CGROUP_MODE" == 1 ]] || { echo "FATAL: cgroup identity is not configured" >&2; exit 1; }
    resolve_service_cgroup || exit 1
    printf '%s\n' "$EXEMPT_CGROUP"
    ;;
  preflight)
    normalize_management_ports || exit 1
    preflight_cgroup || exit 1
    ;;
  apply)
    normalize_management_ports || exit 1
    require_numeric_port "AEGIS_DNS_PORT" "${DNS_PORT}"
    if [[ -n "${UDP_REDIRECT_PORT}" ]]; then
      require_numeric_port "AEGIS_WIDE_UDP_REDIRECT_PORT" "${UDP_REDIRECT_PORT}"
    fi
    normalize_extra_udp_preview_ports
    preflight_cgroup || exit 1
    verify_cgroup_identity || exit 1
    create_output_chain
    create_prerouting_chain
    create_filter_chain
    create_ipv6_filter_chain
    create_forward_filter_chain
    verify_cgroup_identity || exit 1
    hook_chain
    echo "Applied Linux wide redirect helper on port ${WIDE_PORT}"
    if [[ "${ENABLE_BLOCK_POLICY}" == "1" ]]; then
      echo "Wide fail-closed block policy enabled: udp=${BLOCK_UDP} tcp_dns=${BLOCK_TCP_DNS} ipv6=${BLOCK_IPV6}"
    else
      echo "WARN: Wide fail-closed block policy disabled by AEGIS_WIDE_BLOCK_LEAKS=0" >&2
    fi
    if [[ "${ENABLE_DNS_PREVIEW}" == "1" && -z "${UDP_REDIRECT_PORT}" ]]; then
      echo "UDP preview redirect is enabled for primary destination port ${DNS_PORT}"
      if (( ${#EXTRA_UDP_PREVIEW_PORTS[@]} > 0 )); then
        echo "Additional UDP preview ports: ${EXTRA_UDP_PREVIEW_PORTS_RAW}"
      fi
    elif [[ "${ENABLE_DNS_PREVIEW}" == "1" ]]; then
      echo "Local fake-IP DNS listener remains enabled; external UDP preview ports use bidirectional UDP carry"
    fi
    if [[ -n "${UDP_REDIRECT_PORT}" ]]; then
      echo "Bidirectional generic-UDP carry enabled: external UDP including DNS REDIRECTed to proxy port ${UDP_REDIRECT_PORT} (MASQUE direct; fail-closed backstop intact)"
      echo "Run: aegis-client --udp-redirect-proxy ${UDP_REDIRECT_PORT} (as the EXEMPT_UID)"
    fi
    echo "Remember to run aegis-client with [ingress.wide].listen matching this port."
    # Fake-IP DNS is only actually used if the host resolver points at it. The
    # NAT UDP/53 REDIRECT cannot do this (queries to the systemd-resolved stub on
    # 127.0.0.53 are loopback-RETURNed, and a plain REDIRECT destroys the original
    # destination anyway), so on the direct/tun path repoint /etc/resolv.conf at
    # the client's 127.0.0.1:53 listener. Reversible on teardown.
    if [[ "${MANAGE_RESOLV}" == "1" ]]; then
      # NetworkManager on Alma/RHEL can rewrite resolv.conf when the Aegis TUN
      # link appears, after the installer's first DNS check. Temporarily disable
      # its resolver writer while DNS preview owns the file. The /run drop-in is
      # reboot-safe; the persistent wide unit recreates it on every apply.
      networkmanager_dns_hold
      # Snapshot BEFORE stopping systemd-resolved. On Ubuntu resolv.conf is a
      # symlink into /run/systemd/resolve; stopping the service may remove its
      # target, so `-e` alone can silently skip both backup and later restore.
      aegis_root_resolver_save || exit 1
      systemctl stop systemd-resolved 2>/dev/null || true
      rm -f /etc/resolv.conf 2>/dev/null || true
      cat <<'RESOLV' > /etc/resolv.conf
# Managed by aegis wide (dns=preview, fake-IP). Restored on teardown.
nameserver 127.0.0.1
options timeout:2 attempts:1
RESOLV
      echo "resolv.conf repointed at fake-IP DNS 127.0.0.1:53 (systemd-resolved stub stopped; restored on teardown)"
    fi
    ;;
  teardown)
    require_numeric_port "AEGIS_DNS_PORT" "${DNS_PORT}"
    normalize_extra_udp_preview_ports
    teardown_chain
    echo "Removed Linux wide redirect helper chain ${CHAIN}"
    # Restore resolv.conf whenever we have a backup (independent of MANAGE_RESOLV so
    # teardown always undoes an apply), and bring systemd-resolved back.
    managed_resolv=0
    if grep -q '^# Managed by aegis wide' /etc/resolv.conf 2>/dev/null; then
      managed_resolv=1
    fi
    restored_resolv=0
    networkmanager_dns_release
    if [[ -f "${AEGIS_WIDE_RESOLVER_SNAPSHOT}" ]]; then
      aegis_root_resolver_restore || exit 1
      restored_resolv=1
    fi
    if [[ "${restored_resolv}" == "1" ]]; then
      # ExecStop of aegis-wide-tun-firewall.service runs this teardown. That
      # unit is ordered After=systemd-resolved, so a synchronous start here
      # creates an ordering deadlock: systemd waits for this stop to finish
      # while this process waits for systemd-resolved to start. Queue the
      # restore without waiting; the unit can then finish immediately.
      systemctl start --no-block systemd-resolved 2>/dev/null || true
      echo "restored /etc/resolv.conf and restarted systemd-resolved"
    fi
    ;;
  status)
    require_numeric_port "AEGIS_DNS_PORT" "${DNS_PORT}"
    normalize_extra_udp_preview_ports
    show_status
    ;;
esac
