#!/usr/bin/env bash
# Best-effort janitor for Linux TPROXY smoke leftovers on richer hosts.
set -euo pipefail

CHAIN="${AEGIS_WIDE_CHAIN:-AEGIS_WIDE_TPROXY}"
NFT_TABLE="${AEGIS_WIDE_NFT_TABLE:-aegis_wide_tproxy}"
ROUTE_TABLE="${AEGIS_WIDE_ROUTE_TABLE:-100}"
FWMARK="${AEGIS_WIDE_FWMARK:-1}"
JANITOR_WARNED_NO_ROOT=0

run_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  elif sudo -n true >/dev/null 2>&1; then
    sudo "$@"
  else
    if [[ "${JANITOR_WARNED_NO_ROOT}" -eq 0 ]]; then
      echo "WARN: janitor skipped privileged cleanup because passwordless sudo is unavailable; rerun from a root shell for full cleanup" >&2
      JANITOR_WARNED_NO_ROOT=1
    fi
    return 1
  fi
}

delete_xtables_jumps() {
  local firewall="$1"
  local rule=""
  local -a parts=()
  while IFS= read -r rule; do
    [[ -n "${rule}" ]] || continue
    read -r -a parts <<<"${rule}"
    [[ "${parts[0]:-}" == "-A" ]] || continue
    parts[0]="-D"
    run_root "${firewall}" -t mangle "${parts[@]}" >/dev/null 2>&1 || true
  done < <("${firewall}" -t mangle -S PREROUTING 2>/dev/null | awk -v chain="${CHAIN}" '$0 ~ ("-j " chain "$")')
}

cleanup_firewall() {
  delete_xtables_jumps iptables
  run_root iptables -t mangle -F "${CHAIN}" >/dev/null 2>&1 || true
  run_root iptables -t mangle -X "${CHAIN}" >/dev/null 2>&1 || true

  delete_xtables_jumps ip6tables
  run_root ip6tables -t mangle -F "${CHAIN}" >/dev/null 2>&1 || true
  run_root ip6tables -t mangle -X "${CHAIN}" >/dev/null 2>&1 || true

  run_root nft delete table ip "${NFT_TABLE}" >/dev/null 2>&1 || true
  run_root nft delete table ip6 "${NFT_TABLE}" >/dev/null 2>&1 || true
}

cleanup_policy_routing() {
  while run_root ip rule del fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" >/dev/null 2>&1; do :; done
  while run_root ip -6 rule del fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" >/dev/null 2>&1; do :; done
  while run_root ip route del local 0.0.0.0/0 dev lo table "${ROUTE_TABLE}" >/dev/null 2>&1; do :; done
  while run_root ip -6 route del local ::/0 dev lo table "${ROUTE_TABLE}" >/dev/null 2>&1; do :; done
}

cleanup_loopback_targets() {
  local ipv4_targets=(
    198.18.0.53/32
    198.18.0.54/32
    198.18.0.55/32
    198.18.0.56/32
  )
  local ipv6_targets=(
    2001:db8:53::53/128
    2001:db8:55::55/128
  )
  local target=""
  for target in "${ipv4_targets[@]}"; do
    run_root ip addr del "${target}" dev lo >/dev/null 2>&1 || true
  done
  for target in "${ipv6_targets[@]}"; do
    run_root ip -6 addr del "${target}" dev lo >/dev/null 2>&1 || true
  done
}

cleanup_namespaces() {
  local ns=""
  while IFS= read -r ns; do
    [[ -n "${ns}" ]] || continue
    run_root ip netns del "${ns}" >/dev/null 2>&1 || true
  done < <(ip netns list 2>/dev/null | awk '/^aegis-smoke-/ {print $1}')
}

cleanup_interfaces() {
  local iface=""
  while IFS= read -r iface; do
    [[ -n "${iface}" ]] || continue
    run_root ip link del "${iface}" >/dev/null 2>&1 || true
  done < <(ip -o link show 2>/dev/null | awk -F': ' '
    {
      split($2, names, "@");
      if (names[1] ~ /^aegisvh/ || names[1] ~ /^aegisvn/) {
        print names[1];
      }
    }
  ')
}

cleanup_processes() {
  # NOTE: patterns must be SPECIFIC enough not to match the running operator
  # helper scripts (e.g. /tmp/aegis-wide-helpers/aegis-wide-disable.sh). The
  # janitor used to use bare '/tmp/aegis-wide-' which pkilled its own caller.
  local patterns=(
    '/tmp/aegis-wide-tproxy-'
    '/tmp/aegis-wide-smoke-'
    '/tmp/aegis-relay-smoke-'
    '/tmp/aegis-client-smoke-'
    'aegis-wide-tproxy-smoke'
  )
  local pattern=""
  for pattern in "${patterns[@]}"; do
    run_root pkill -f "${pattern}" >/dev/null 2>&1 || true
  done
}

cleanup_tmp_files() {
  # Use SPECIFIC suffixes to avoid wiping /tmp/aegis-wide-helpers/ that the
  # operator may have just uploaded the live helpers into.
  run_root rm -rf /tmp/aegis-wide-tproxy-* /tmp/aegis-wide-smoke-* \
      /tmp/aegis-relay-smoke-* /tmp/aegis-client-smoke-* \
      /tmp/aegis-smoke-* >/dev/null 2>&1 || true
}

echo "Running Linux TPROXY janitor..."
cleanup_processes
cleanup_firewall
cleanup_policy_routing
cleanup_loopback_targets
cleanup_namespaces
cleanup_interfaces
cleanup_tmp_files
echo "Linux TPROXY janitor finished"
