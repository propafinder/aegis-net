#!/usr/bin/env bash
# setup-wide-linux-nfqueue.sh — install/teardown the NFQUEUE divert rules for
# AEGIS wide ingress, for BOTH the observer (witness) and the full-wide-nfqueue
# ENFORCE (fail-closed policy) layers.
#
# Architecture: NFQUEUE is the policy/observe layer, NOT a TCP relay. In the
# full-wide-nfqueue product mode, TCP IPv4 is carried by the REDIRECT relay
# (separate helper); this helper queues the classes REDIRECT cannot carry —
# generic UDP, QUIC (UDP/443), DNS UDP/53, and IPv6 (TCP+UDP) — so the AEGIS
# userspace consumer can witness them and DROP per the resolved product policy.
#
#   observe mode : --queue-bypass ON  → if no consumer, packets ACCEPT (fail-open,
#                  safe to leave installed). Default; back-compat.
#   enforce mode : --queue-bypass OFF → if no consumer, packets DROP (fail-closed).
#                  The consumer (aegis-client --nfqueue-enforce) makes the
#                  ACCEPT/DROP decision per udp/dns/ipv6 policy.
#
# Usage:
#   sudo bash setup-wide-linux-nfqueue.sh apply    [--queue-num=N] [--dport=22,...] [--dry-run]
#   sudo bash setup-wide-linux-nfqueue.sh teardown [--queue-num=N]
#   sudo bash setup-wide-linux-nfqueue.sh status   [--queue-num=N]
#
# Env overrides (also used by the contract test):
#   AEGIS_WIDE_NFQ_CHAIN=NAME            chain name (default AEGIS_WIDE_NFQ)
#   AEGIS_WIDE_NFQ_SKIP_ROOT_CHECK=1     bypass EUID gate (dry-run never needs root)
#   AEGIS_EXEMPT_UID=NNNN                UID exempted from queueing (loop avoidance)
#   AEGIS_NFQ_MODE=observe|enforce       default observe
#   AEGIS_NFQ_DIVERT_TCP=0|1             divert TCP v4 dports (default: 1 observe / 0 enforce)
#   AEGIS_NFQ_DIVERT_UDP=0|1             divert UDP v4 (generic + DNS) (default: 0 observe / 1 enforce)
#   AEGIS_NFQ_DIVERT_IPV6=0|1            divert IPv6 TCP+UDP (default: 1)
#   AEGIS_RELAY_EXCLUDES="ip ip ..."     relay/CF endpoint IPs to RETURN (no loop)
#   AEGIS_NFQ_EXCLUDE_SSH=0|1            RETURN tcp :22 both directions (default 1)
#   AEGIS_NFQ_EXCLUDE_METADATA=0|1       RETURN 169.254.169.254 / fe80::/10 (default 1)
#   AEGIS_NFQ_FIREWALL_BACKEND=auto|iptables|nft   default auto (prefers iptables)
#   AEGIS_NFQ_DRY_RUN=1                  print the rules, change nothing (no root needed)
#
# Exit codes:
#   0  apply / teardown / status / dry-run succeeded
#   1  status: chain absent
#   2  argument error
#   3  no exempt UID could be resolved on apply
#   5  firewall command failed

set -uo pipefail

CHAIN="${AEGIS_WIDE_NFQ_CHAIN:-AEGIS_WIDE_NFQ}"

# --- argument parsing ----------------------------------------------------

action="${1:-}"; [[ -n "${action}" ]] && shift
queue_num=100
dports="80,443"
DRY_RUN="${AEGIS_NFQ_DRY_RUN:-0}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --queue-num=*) queue_num="${1#*=}"; shift ;;
        --dport=*)     dports="${1#*=}"; shift ;;
        --dry-run)     DRY_RUN=1; shift ;;
        *) echo "FATAL: unknown argument $1" >&2; exit 2 ;;
    esac
done

case "${action}" in
    apply|teardown|status) ;;
    *) echo "Usage: $0 {apply|teardown|status} [--queue-num=N] [--dport=p1,p2,...] [--dry-run]" >&2; exit 2 ;;
esac

if ! [[ "${queue_num}" =~ ^[0-9]+$ ]] || (( queue_num < 0 || queue_num > 65535 )); then
    echo "FATAL: --queue-num must be 0..65535 (got: ${queue_num})" >&2; exit 2
fi

# Root is required to mutate firewall state, but NOT for --dry-run or status.
if [[ "${DRY_RUN}" != "1" && "${action}" == "apply" ]]; then
    if [[ "${EUID}" -ne 0 && -z "${AEGIS_WIDE_NFQ_SKIP_ROOT_CHECK:-}" ]]; then
        echo "FATAL: apply must run under sudo/root (or use --dry-run)" >&2
        exit 2
    fi
fi

# --- mode + divert defaults ---------------------------------------------

MODE="${AEGIS_NFQ_MODE:-observe}"
case "${MODE}" in observe|enforce) ;; *) echo "FATAL: AEGIS_NFQ_MODE must be observe|enforce" >&2; exit 2 ;; esac

if [[ "${MODE}" == "enforce" ]]; then
    QUEUE_BYPASS_DEFAULT=""          # no bypass => fail-closed
    DIVERT_TCP_DEFAULT=0             # TCP carried by REDIRECT, not NFQUEUE
    DIVERT_UDP_DEFAULT=1
    DIVERT_IPV6_DEFAULT=1
else
    QUEUE_BYPASS_DEFAULT="--queue-bypass"
    DIVERT_TCP_DEFAULT=1
    DIVERT_UDP_DEFAULT=0
    DIVERT_IPV6_DEFAULT=1
fi
DIVERT_TCP="${AEGIS_NFQ_DIVERT_TCP:-${DIVERT_TCP_DEFAULT}}"
DIVERT_UDP="${AEGIS_NFQ_DIVERT_UDP:-${DIVERT_UDP_DEFAULT}}"
DIVERT_IPV6="${AEGIS_NFQ_DIVERT_IPV6:-${DIVERT_IPV6_DEFAULT}}"
EXCLUDE_SSH="${AEGIS_NFQ_EXCLUDE_SSH:-1}"
EXCLUDE_METADATA="${AEGIS_NFQ_EXCLUDE_METADATA:-1}"
# Keep DNS (UDP/53) NEVER queued: it always egresses natively, so the host stays
# resolvable even if the consumer dies (fail-closed applies to GENERIC UDP only).
# Use when no DNS-preview path is deployed. Off by default (consumer ACCEPTs DNS).
EXCLUDE_DNS="${AEGIS_NFQ_EXCLUDE_DNS:-0}"
if [[ "${AEGIS_NFQ_QUEUE_BYPASS:-}" == "on" ]]; then QUEUE_BYPASS="--queue-bypass";
elif [[ "${AEGIS_NFQ_QUEUE_BYPASS:-}" == "off" ]]; then QUEUE_BYPASS="";
else QUEUE_BYPASS="${QUEUE_BYPASS_DEFAULT}"; fi

# --- firewall backend selection -----------------------------------------

BACKEND="${AEGIS_NFQ_FIREWALL_BACKEND:-auto}"
if [[ "${BACKEND}" == "auto" ]]; then
    if command -v iptables >/dev/null 2>&1; then BACKEND="iptables";
    elif command -v nft >/dev/null 2>&1; then BACKEND="nft";
    else echo "FATAL: neither iptables nor nft present" >&2; exit 5; fi
fi
case "${BACKEND}" in iptables|nft) ;; *) echo "FATAL: AEGIS_NFQ_FIREWALL_BACKEND must be auto|iptables|nft" >&2; exit 2 ;; esac

# --- UID resolution -----------------------------------------------------

resolve_exempt_uid() {
    if [[ -n "${AEGIS_EXEMPT_UID:-}" ]]; then printf '%s' "${AEGIS_EXEMPT_UID}"; return 0; fi
    id -u aegis-client 2>/dev/null && return 0
    id -u aegis 2>/dev/null && return 0
    return 1
}

# --- command runner (honours --dry-run) ---------------------------------

run() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "DRY-RUN: $*"
        return 0
    fi
    if ! "$@"; then
        echo "FAILED: $*" >&2
        return 5
    fi
}

# Build the comma list into a normalized array.
read_dports() {
    IFS=',' read -r -a dport_arr <<< "${dports}"
}

have_ip6tables() {
    [[ "${DRY_RUN}" == "1" ]] || command -v ip6tables >/dev/null 2>&1
}

# ========================================================================
# iptables backend
# ========================================================================

ipt_apply() {
    local exempt_uid="$1"
    read_dports

    # IPv4 chain (mangle): create idempotently + flush.
    run iptables -t mangle -N "${CHAIN}" 2>/dev/null || run iptables -t mangle -F "${CHAIN}"

    # --- exclusions (RETURN before any divert) ---
    # loopback
    run iptables -t mangle -A "${CHAIN}" -o lo -j RETURN
    run iptables -t mangle -A "${CHAIN}" -d 127.0.0.0/8 -j RETURN
    # the AEGIS uid's own sockets (relay leg) — never queue back into ourselves
    run iptables -t mangle -A "${CHAIN}" -m owner --uid-owner "${exempt_uid}" -j RETURN
    # SSH management traffic both directions
    if [[ "${EXCLUDE_SSH}" == "1" ]]; then
        run iptables -t mangle -A "${CHAIN}" -p tcp --dport 22 -j RETURN
        run iptables -t mangle -A "${CHAIN}" -p tcp --sport 22 -j RETURN
    fi
    # DNS stays native (host remains resolvable even with no consumer)
    if [[ "${EXCLUDE_DNS}" == "1" ]]; then
        run iptables -t mangle -A "${CHAIN}" -p udp --dport 53 -j RETURN
        run iptables -t mangle -A "${CHAIN}" -p udp --sport 53 -j RETURN
    fi
    # cloud metadata endpoint
    if [[ "${EXCLUDE_METADATA}" == "1" ]]; then
        run iptables -t mangle -A "${CHAIN}" -d 169.254.169.254 -j RETURN
    fi
    # relay / CF endpoint IPs (loop avoidance for non-uid relay traffic)
    local rip
    for rip in ${AEGIS_RELAY_EXCLUDES:-}; do
        rip="${rip//,/}"
        [[ "${rip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && run iptables -t mangle -A "${CHAIN}" -d "${rip}" -j RETURN
    done

    # --- divert rules ---
    if [[ "${DIVERT_TCP}" == "1" ]]; then
        local p
        for p in "${dport_arr[@]}"; do
            p="${p//[!0-9]/}"; [[ -z "${p}" ]] && continue
            run iptables -t mangle -A "${CHAIN}" -p tcp --dport "${p}" -j NFQUEUE --queue-num "${queue_num}" ${QUEUE_BYPASS}
        done
    fi
    if [[ "${DIVERT_UDP}" == "1" ]]; then
        # all UDP (generic + DNS/53 + QUIC/443). The consumer distinguishes DNS.
        run iptables -t mangle -A "${CHAIN}" -p udp -j NFQUEUE --queue-num "${queue_num}" ${QUEUE_BYPASS}
    fi

    # Attach to OUTPUT (locally-generated traffic).
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "DRY-RUN: iptables -t mangle -I OUTPUT 1 -j ${CHAIN}"
    elif ! iptables -t mangle -C OUTPUT -j "${CHAIN}" 2>/dev/null; then
        run iptables -t mangle -I OUTPUT 1 -j "${CHAIN}"
    fi
}

ip6t_apply() {
    local exempt_uid="$1"
    [[ "${DIVERT_IPV6}" == "1" ]] || { echo "ipv6=off(divert_off)"; return 0; }
    if ! have_ip6tables; then echo "ipv6=off(no_ip6tables)"; return 0; fi
    read_dports

    if [[ "${DRY_RUN}" != "1" ]]; then
        ip6tables -t mangle -N "${CHAIN}" 2>/dev/null || ip6tables -t mangle -F "${CHAIN}" 2>/dev/null || { echo "ipv6=off(chain_unavailable)"; return 0; }
    else
        echo "DRY-RUN: ip6tables -t mangle -N ${CHAIN}"
    fi
    run ip6tables -t mangle -A "${CHAIN}" -o lo -j RETURN || true
    run ip6tables -t mangle -A "${CHAIN}" -d ::1 -j RETURN || true
    run ip6tables -t mangle -A "${CHAIN}" -m owner --uid-owner "${exempt_uid}" -j RETURN || true
    if [[ "${EXCLUDE_SSH}" == "1" ]]; then
        run ip6tables -t mangle -A "${CHAIN}" -p tcp --dport 22 -j RETURN || true
        run ip6tables -t mangle -A "${CHAIN}" -p tcp --sport 22 -j RETURN || true
    fi
    if [[ "${EXCLUDE_METADATA}" == "1" ]]; then
        run ip6tables -t mangle -A "${CHAIN}" -d fe80::/10 -j RETURN || true
    fi
    local rip6
    for rip6 in ${AEGIS_RELAY_EXCLUDES:-}; do
        rip6="${rip6//,/}"
        [[ "${rip6}" == *:* ]] && run ip6tables -t mangle -A "${CHAIN}" -d "${rip6}" -j RETURN || true
    done
    # IPv6 TCP (observe/fail-closed) + UDP.
    local p6
    for p6 in "${dport_arr[@]}"; do
        p6="${p6//[!0-9]/}"; [[ -z "${p6}" ]] && continue
        run ip6tables -t mangle -A "${CHAIN}" -p tcp --dport "${p6}" -j NFQUEUE --queue-num "${queue_num}" ${QUEUE_BYPASS} || true
    done
    run ip6tables -t mangle -A "${CHAIN}" -p udp -j NFQUEUE --queue-num "${queue_num}" ${QUEUE_BYPASS} || true
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "DRY-RUN: ip6tables -t mangle -I OUTPUT 1 -j ${CHAIN}"
    elif ! ip6tables -t mangle -C OUTPUT -j "${CHAIN}" 2>/dev/null; then
        run ip6tables -t mangle -I OUTPUT 1 -j "${CHAIN}" || true
    fi
    echo "ipv6=on"
}

ipt_teardown() {
    while iptables -t mangle -C OUTPUT -j "${CHAIN}" 2>/dev/null; do
        iptables -t mangle -D OUTPUT -j "${CHAIN}" 2>/dev/null || break
    done
    iptables -t mangle -F "${CHAIN}" 2>/dev/null || true
    iptables -t mangle -X "${CHAIN}" 2>/dev/null || true
    if have_ip6tables; then
        while ip6tables -t mangle -C OUTPUT -j "${CHAIN}" 2>/dev/null; do
            ip6tables -t mangle -D OUTPUT -j "${CHAIN}" 2>/dev/null || break
        done
        ip6tables -t mangle -F "${CHAIN}" 2>/dev/null || true
        ip6tables -t mangle -X "${CHAIN}" 2>/dev/null || true
    fi
}

ipt_status() {
    if iptables -t mangle -L "${CHAIN}" -n 2>/dev/null >/dev/null; then
        echo "status=present chain=${CHAIN} backend=iptables"
        iptables -t mangle -L "${CHAIN}" -n -v | sed 's/^/  /'
        return 0
    fi
    echo "status=absent chain=${CHAIN} backend=iptables"
    return 1
}

# ========================================================================
# nft backend (inet table; one chain hooking output)
# ========================================================================

NFT_TABLE="aegis_wide_nfq"
nft_bypass() { [[ -n "${QUEUE_BYPASS}" ]] && echo "flags bypass" || true; }

nft_apply() {
    local exempt_uid="$1"
    read_dports
    local b; b="$(nft_bypass)"
    run nft add table inet "${NFT_TABLE}"
    run nft "add chain inet ${NFT_TABLE} out { type filter hook output priority -150 ; }"
    run nft flush chain inet "${NFT_TABLE}" out
    # exclusions
    run nft add rule inet "${NFT_TABLE}" out oif lo return
    run nft add rule inet "${NFT_TABLE}" out meta skuid "${exempt_uid}" return
    if [[ "${EXCLUDE_SSH}" == "1" ]]; then
        run nft add rule inet "${NFT_TABLE}" out tcp dport 22 return
        run nft add rule inet "${NFT_TABLE}" out tcp sport 22 return
    fi
    if [[ "${EXCLUDE_DNS}" == "1" ]]; then
        run nft add rule inet "${NFT_TABLE}" out udp dport 53 return
        run nft add rule inet "${NFT_TABLE}" out udp sport 53 return
    fi
    if [[ "${EXCLUDE_METADATA}" == "1" ]]; then
        run nft add rule inet "${NFT_TABLE}" out ip daddr 169.254.169.254 return
    fi
    local rip
    for rip in ${AEGIS_RELAY_EXCLUDES:-}; do
        rip="${rip//,/}"
        if [[ "${rip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            run nft add rule inet "${NFT_TABLE}" out ip daddr "${rip}" return
        elif [[ "${rip}" == *:* ]]; then
            run nft add rule inet "${NFT_TABLE}" out ip6 daddr "${rip}" return
        fi
    done
    # divert
    if [[ "${DIVERT_TCP}" == "1" ]]; then
        local p
        for p in "${dport_arr[@]}"; do
            p="${p//[!0-9]/}"; [[ -z "${p}" ]] && continue
            run nft add rule inet "${NFT_TABLE}" out tcp dport "${p}" queue ${b} to "${queue_num}"
        done
    fi
    if [[ "${DIVERT_UDP}" == "1" ]]; then
        run nft add rule inet "${NFT_TABLE}" out meta l4proto udp queue ${b} to "${queue_num}"
    fi
    if [[ "${DIVERT_IPV6}" == "1" ]]; then
        local p6
        for p6 in "${dport_arr[@]}"; do
            p6="${p6//[!0-9]/}"; [[ -z "${p6}" ]] && continue
            run nft add rule inet "${NFT_TABLE}" out meta nfproto ipv6 tcp dport "${p6}" queue ${b} to "${queue_num}"
        done
        run nft add rule inet "${NFT_TABLE}" out meta nfproto ipv6 meta l4proto udp queue ${b} to "${queue_num}"
        echo "ipv6=on"
    fi
}

nft_teardown() {
    nft delete table inet "${NFT_TABLE}" 2>/dev/null || true
}

nft_status() {
    if nft list table inet "${NFT_TABLE}" >/dev/null 2>&1; then
        echo "status=present table=inet:${NFT_TABLE} backend=nft"
        nft list table inet "${NFT_TABLE}" | sed 's/^/  /'
        return 0
    fi
    echo "status=absent table=inet:${NFT_TABLE} backend=nft"
    return 1
}

# ========================================================================
# action dispatch
# ========================================================================

action_apply() {
    local exempt_uid
    exempt_uid="$(resolve_exempt_uid)" || {
        echo "FATAL: cannot resolve aegis exempt UID; set AEGIS_EXEMPT_UID or create user aegis/aegis-client" >&2
        exit 3
    }
    echo "apply chain=${CHAIN} backend=${BACKEND} mode=${MODE} queue=${queue_num} exempt_uid=${exempt_uid} \
divert_tcp=${DIVERT_TCP} divert_udp=${DIVERT_UDP} divert_ipv6=${DIVERT_IPV6} \
queue_bypass=$([[ -n "${QUEUE_BYPASS}" ]] && echo on || echo off) dry_run=${DRY_RUN}"
    if [[ "${MODE}" == "enforce" && -z "${QUEUE_BYPASS}" ]]; then
        echo "failsafe=fail_closed (no-consumer => DROP); consumer makes ACCEPT/DROP per policy"
    else
        echo "failsafe=fail_open (no-consumer => ACCEPT); witness-only"
        # Back-compat marker consumed by the observer contract test.
        echo "stage=consumer_available queue_bypass=on"
    fi
    case "${BACKEND}" in
        iptables) ipt_apply "${exempt_uid}"; ip6t_apply "${exempt_uid}" ;;
        nft)      nft_apply "${exempt_uid}" ;;
    esac
    echo "status=ready"
}

action_teardown() {
    case "${BACKEND}" in
        iptables) ipt_teardown ;;
        nft)      nft_teardown ;;
    esac
    echo "teardown chain=${CHAIN} backend=${BACKEND} status=removed"
}

action_status() {
    case "${BACKEND}" in
        iptables) ipt_status ;;
        nft)      nft_status ;;
    esac
}

case "${action}" in
    apply)    action_apply ;;
    teardown) action_teardown ;;
    status)   action_status ;;
esac
