#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="${ROOT}/scripts/aegis-origin-guard.sh"

bash -n "${GUARD}"

assert_rule() {
  local rule="$1"
  if ! grep -Fq "${rule}" "${GUARD}"; then
    echo "origin guard is missing required nft rule: ${rule}" >&2
    exit 1
  fi
}

# Both AEGIS listener transports on :443 must be restricted. Normal
# Cloudflare orange-cloud traffic uses TCP; the UDP rules close the direct
# MASQUE/QUIC origin surface rather than claiming that Cloudflare fronts it.
assert_rule 'ip  saddr @cf4 tcp dport 443 counter accept'
assert_rule 'ip6 saddr @cf6 tcp dport 443 counter accept'
assert_rule 'ip  saddr @cf4 udp dport 443 counter accept'
assert_rule 'ip6 saddr @cf6 udp dport 443 counter accept'
assert_rule 'tcp dport 443 counter drop'
assert_rule 'udp dport 443 counter drop'

grep -Fq 'ROLLBACK_SECS must be a whole number of seconds' "${GUARD}"
grep -Fq 'setsid bash -c' "${GUARD}"
grep -Fq 'aegis-origin-guard "${ROLLBACK_SECS}" "${SENTINEL}" "${TABLE}"' "${GUARD}"

echo "origin guard TCP+UDP transport contract: PASS"
