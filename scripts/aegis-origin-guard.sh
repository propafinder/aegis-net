#!/usr/bin/env bash
# Audit opsec: restrict relay TCP/443 and UDP/443 to Cloudflare source ranges,
# so the bare origin IP stops answering (with the CF Origin cert) to arbitrary
# scanners — closing origin de-anonymisation / direct-origin abuse. AEGIS uses
# TCP/443 for the fronted HTTP transports and can also bind UDP/443 for direct
# MASQUE, so guarding only TCP leaves the origin's QUIC endpoint exposed. Only
# port 443 is touched; SSH and everything else are untouched. Self-rolls-back
# unless confirmed, so a mistake cannot strand the box.
# Usage: origin-guard.sh apply|confirm|status|remove
set -uo pipefail
TABLE="aegis_origin_guard"
SENTINEL="/run/aegis-origin-guard-confirmed"
ROLLBACK_SECS="${ROLLBACK_SECS:-240}"
ACTION="${1:-status}"

# The rollback program receives values as arguments, not shell source; keep its
# sleep interval numeric.
if ! [[ "${ROLLBACK_SECS}" =~ ^[0-9]+$ ]]; then
  echo "ROLLBACK_SECS must be a whole number of seconds (got: ${ROLLBACK_SECS})" >&2
  exit 2
fi

# Pinned Cloudflare ranges (from https://www.cloudflare.com/ips-v4 /ips-v6).
CF4="173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22"
CF6="2400:cb00::/32,2606:4700::/32,2803:f800::/32,2405:b500::/32,2405:8100::/32,2a06:98c0::/29,2c0f:f248::/32"

remove_table() { nft delete table inet "${TABLE}" 2>/dev/null || true; }

apply() {
  remove_table
  nft -f - <<NFT
table inet ${TABLE} {
  set cf4 { type ipv4_addr; flags interval; elements = { ${CF4} } }
  set cf6 { type ipv6_addr; flags interval; elements = { ${CF6} } }
  chain input {
    type filter hook input priority -10; policy accept;
    tcp dport != 443 accept
    ct state established,related accept
    ip  saddr @cf4 tcp dport 443 counter accept
    ip6 saddr @cf6 tcp dport 443 counter accept
    ip  saddr @cf4 udp dport 443 counter accept
    ip6 saddr @cf6 udp dport 443 counter accept
    tcp dport 443 counter drop
    udp dport 443 counter drop
  }
}
NFT
  if [ $? -ne 0 ]; then echo "APPLY_FAILED: nft load error"; remove_table; exit 1; fi
  rm -f "${SENTINEL}"
  # auto-rollback: remove the guard unless confirmed within the window
  # Values are passed as arguments, never spliced into the program text, so they
  # cannot be reparsed as shell.
  setsid bash -c 'sleep "$1"; [ -f "$2" ] || { logger -t aegis-origin-guard "auto-rollback: not confirmed"; nft delete table inet "$3" 2>/dev/null; }' \
    aegis-origin-guard "${ROLLBACK_SECS}" "${SENTINEL}" "${TABLE}" >/dev/null 2>&1 < /dev/null &
  echo "APPLIED table=${TABLE} rollback_in=${ROLLBACK_SECS}s (run 'confirm' to keep)"
  nft list table inet "${TABLE}" 2>/dev/null | grep -cE 'drop|accept' | xargs echo "rules_loaded:"
}

case "${ACTION}" in
  apply)   apply ;;
  confirm) touch "${SENTINEL}"; echo "CONFIRMED (auto-rollback cancelled)"; nft list table inet "${TABLE}" >/dev/null 2>&1 && echo "guard active" || echo "WARN: guard table not present" ;;
  status)  nft list table inet "${TABLE}" 2>/dev/null && echo "STATUS: active" || echo "STATUS: absent"; [ -f "${SENTINEL}" ] && echo "confirmed=yes" || echo "confirmed=no" ;;
  remove)  remove_table; rm -f "${SENTINEL}"; echo "REMOVED" ;;
  *) echo "usage: $0 apply|confirm|status|remove" >&2; exit 2 ;;
esac
