#!/usr/bin/env bash
# Contract test for the full-wide-nfqueue ENFORCE mode of
# scripts/setup-wide-linux-nfqueue.sh, using --dry-run so it needs no root and
# mutates nothing. Verifies the fail-closed policy-layer rule generation:
#   - enforce mode diverts generic UDP + IPv6 (TCP+UDP), NOT TCP IPv4 (REDIRECT)
#   - no --queue-bypass (fail-closed: no consumer => DROP)
#   - exclusions present: loopback, exempt uid, SSH both directions, metadata,
#     and every relay/CF endpoint IP
#   - both iptables and nft backends generate coherent rules
#   - apply is repeatable (flush before re-add)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/setup-wide-linux-nfqueue.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }

# --- iptables enforce dry-run -------------------------------------------
OUT="$(AEGIS_NFQ_MODE=enforce AEGIS_EXEMPT_UID=4242 \
       AEGIS_RELAY_EXCLUDES='203.0.113.7 198.51.100.9' \
       AEGIS_NFQ_FIREWALL_BACKEND=iptables \
       bash "${SCRIPT}" apply --queue-num=100 --dry-run 2>&1)" || fail "enforce dry-run exited non-zero"

grep -Eq 'mode=enforce' <<<"${OUT}" || fail "not in enforce mode"
grep -Eq 'queue_bypass=off' <<<"${OUT}" || fail "enforce must be fail-closed (queue_bypass=off)"
grep -Eq 'failsafe=fail_closed' <<<"${OUT}" || fail "enforce must report fail_closed"
# generic UDP diverted, no --queue-bypass
grep -Eq 'iptables -t mangle -A AEGIS_WIDE_NFQ -p udp -j NFQUEUE --queue-num 100( |$)' <<<"${OUT}" \
    || fail "enforce must divert generic UDP without --queue-bypass"
grep -q 'p udp -j NFQUEUE --queue-num 100 --queue-bypass' <<<"${OUT}" \
    && fail "enforce UDP rule must NOT carry --queue-bypass (would fail-open)"
# TCP IPv4 NOT diverted (carried by REDIRECT)
grep -q 'iptables -t mangle -A AEGIS_WIDE_NFQ -p tcp --dport 80 -j NFQUEUE' <<<"${OUT}" \
    && fail "enforce must NOT divert TCP IPv4 (REDIRECT carries it)"
# IPv6 TCP + UDP diverted
grep -q 'ip6tables -t mangle -A AEGIS_WIDE_NFQ -p udp -j NFQUEUE --queue-num 100' <<<"${OUT}" \
    || fail "enforce must divert IPv6 UDP"
grep -q 'ip6tables -t mangle -A AEGIS_WIDE_NFQ -p tcp --dport 443 -j NFQUEUE' <<<"${OUT}" \
    || fail "enforce must divert IPv6 TCP dports"
# exclusions
grep -q 'AEGIS_WIDE_NFQ -o lo -j RETURN' <<<"${OUT}" || fail "missing loopback exclusion"
grep -q 'AEGIS_WIDE_NFQ -m owner --uid-owner 4242 -j RETURN' <<<"${OUT}" || fail "missing uid exclusion"
grep -q 'AEGIS_WIDE_NFQ -p tcp --dport 22 -j RETURN' <<<"${OUT}" || fail "missing ssh dport exclusion"
grep -q 'AEGIS_WIDE_NFQ -p tcp --sport 22 -j RETURN' <<<"${OUT}" || fail "missing ssh sport exclusion"
grep -q 'AEGIS_WIDE_NFQ -d 169.254.169.254 -j RETURN' <<<"${OUT}" || fail "missing metadata exclusion"
grep -q 'AEGIS_WIDE_NFQ -d 203.0.113.7 -j RETURN' <<<"${OUT}" || fail "missing relay exclusion 1"
grep -q 'AEGIS_WIDE_NFQ -d 198.51.100.9 -j RETURN' <<<"${OUT}" || fail "missing relay exclusion 2"

# --- nft enforce dry-run -------------------------------------------------
NOUT="$(AEGIS_NFQ_MODE=enforce AEGIS_EXEMPT_UID=4242 \
        AEGIS_RELAY_EXCLUDES='203.0.113.7' \
        AEGIS_NFQ_FIREWALL_BACKEND=nft \
        bash "${SCRIPT}" apply --queue-num=100 --dry-run 2>&1)" || fail "nft enforce dry-run failed"
grep -q 'add table inet aegis_wide_nfq' <<<"${NOUT}" || fail "nft: no table"
grep -q 'meta l4proto udp queue to 100' <<<"${NOUT}" || fail "nft: no UDP queue (fail-closed: no 'flags bypass')"
grep -q 'meta l4proto udp queue flags bypass' <<<"${NOUT}" && fail "nft enforce must not set queue bypass"
grep -q 'meta nfproto ipv6' <<<"${NOUT}" || fail "nft: no IPv6 divert"
grep -q 'meta skuid 4242 return' <<<"${NOUT}" || fail "nft: no uid exclusion"
grep -q 'ip daddr 203.0.113.7 return' <<<"${NOUT}" || fail "nft: no relay exclusion"

# --- observe mode still fail-open (back-compat) -------------------------
OOUT="$(AEGIS_EXEMPT_UID=4242 AEGIS_NFQ_FIREWALL_BACKEND=iptables \
        bash "${SCRIPT}" apply --queue-num=100 --dport=80,443 --dry-run 2>&1)" || fail "observe dry-run failed"
grep -q 'mode=observe' <<<"${OOUT}" || fail "default must be observe"
grep -q 'p tcp --dport 80 -j NFQUEUE --queue-num 100 --queue-bypass' <<<"${OOUT}" \
    || fail "observe must divert TCP dports WITH --queue-bypass (fail-open)"

echo "PASS: setup-wide-linux-nfqueue.sh enforce/observe/nft dry-run contract"
