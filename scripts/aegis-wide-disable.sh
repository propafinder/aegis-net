#!/usr/bin/env bash
# aegis-wide-disable.sh — tear down any AEGIS wide-mode capture chain.
# Calls both redirect and tproxy teardowns + janitor to clean any leftover state.
#
# Safe to run when nothing is installed (each step is best-effort).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_EXEMPT_CHAIN="AEGIS_WIDE_SSH_EXEMPT"
SENTINEL_FILE="/run/aegis-wide-confirmed"

usage() {
    cat <<'EOF'
aegis-wide-disable.sh — tear down AEGIS-owned wide-mode capture

Usage:
    sudo aegis-wide-disable.sh

The command intentionally accepts no operational arguments. Use --help only
to print this text; unknown arguments are rejected before any state changes.
EOF
}

# This helper is destructive by design. Parse its tiny CLI before the root
# check or any systemctl/firewall/config mutation so a typo (or an innocent
# `--help`) can never disable a live host.
if [[ $# -gt 0 ]]; then
    if [[ $# -eq 1 && ( "$1" == "--help" || "$1" == "-h" ) ]]; then
        usage
        exit 0
    fi
    echo "FATAL: aegis-wide-disable.sh accepts no arguments; see --help" >&2
    exit 2
fi

if [[ "${EUID}" -ne 0 && -z "${AEGIS_WIDE_SKIP_ROOT_CHECK:-}" ]]; then
    echo "FATAL: must run under sudo/root" >&2
    exit 2
fi

# Internal rollback callers may retain the original recovery record. This
# affects only the one config-backup removal below, never capture teardown.
preserve_config_backup="${AEGIS_WIDE_ROLLBACK_PRESERVE_CONFIG_BACKUP:-0}"
case "${preserve_config_backup}" in
    0|1) ;;
    *) echo 'FATAL: invalid internal config-backup preservation flag.' >&2; exit 2 ;;
esac

# shellcheck source=scripts/lib/root-state.sh
. "${SCRIPT_DIR}/lib/root-state.sh"
aegis_root_network_preflight || exit 1

# Persistence must be disarmed before any teardown or daemon restart.  If the
# client is restarted while either boot unit is still enabled/active, systemd
# may start the unit again and re-apply the firewall in the middle of this
# script.  That leaves a half-applied fail-closed ruleset while this wrapper
# still reports success (live-reproduced on Ubuntu 26.04, 2026-08-24).
#
# Disable first, then stop: aegis-wide.service has an ExecStop that calls this
# wrapper recursively with AEGIS_WIDE_DISABLE_FROM_UNIT=1.  Disabling it before
# that ExecStop runs makes a client restart inside the nested teardown unable to
# re-arm capture.  The marker avoids asking systemd to stop the same unit from
# inside its own ExecStop.
disarm_wide_persistence() {
    command -v systemctl >/dev/null 2>&1 || return 0

    systemctl disable aegis-wide-tun-firewall.service >/dev/null 2>&1 || true
    systemctl disable aegis-wide.service >/dev/null 2>&1 || true
    systemctl stop aegis-wide-tun-firewall.service >/dev/null 2>&1 || true
    if [[ "${AEGIS_WIDE_DISABLE_FROM_UNIT:-0}" != "1" ]]; then
        systemctl stop aegis-wide.service >/dev/null 2>&1 || true
    fi
}

disarm_wide_persistence

# 1. Remove SSH-safe-port exempt chain (added by aegis-wide-enable)
iptables -t nat -D OUTPUT -j "${SSH_EXEMPT_CHAIN}" 2>/dev/null || true
iptables -t nat -F "${SSH_EXEMPT_CHAIN}" 2>/dev/null || true
iptables -t nat -X "${SSH_EXEMPT_CHAIN}" 2>/dev/null || true

# 2. Tear down redirect helper if active.
# AEGIS_WIDE_BLOCK_IPV6=1 ensures the IPv6 REJECT chain is removed.
if [[ -x "${SCRIPT_DIR}/setup-wide-linux-redirect.sh" ]]; then
    AEGIS_WIDE_BLOCK_IPV6=1 \
        "${SCRIPT_DIR}/setup-wide-linux-redirect.sh" teardown 2>&1 | sed 's/^/[redirect-teardown] /'
fi

# 3. Tear down tproxy helper if active.
# AEGIS_WIDE_IPV6_POLICY=block ensures teardown_ipv6_policy() inside the
# tproxy helper actually runs and removes AEGIS_WIDE_TPROXY_V6_BLOCK
# from the OUTPUT/FORWARD chains. Without this env, IPV6_POLICY defaults
# to out_of_scope at teardown time and the IPv6 chain leaks after disable
# (caught 2026-05-19: curl -6 still timed out after disable because the
# AEGIS_WIDE_TPROXY_V6_BLOCK chain remained attached).
if [[ -x "${SCRIPT_DIR}/setup-wide-linux-tproxy.sh" ]]; then
    AEGIS_WIDE_IPV6_POLICY=block \
        "${SCRIPT_DIR}/setup-wide-linux-tproxy.sh" teardown 2>&1 | sed 's/^/[tproxy-teardown] /' || true
fi

# 4. Run janitor for any leftover nftables / route table state
if [[ -x "${SCRIPT_DIR}/janitor-wide-linux-tproxy.sh" ]]; then
    "${SCRIPT_DIR}/janitor-wide-linux-tproxy.sh" 2>&1 | sed 's/^/[janitor] /' || true
fi

# 5. Defensive sweep for any AEGIS_WIDE_* chains the underlying helpers
# may have left attached. Each iteration deletes the FIRST matching jump
# rule across all common tables, then flushes/destroys the chain. Loops
# until no more references remain or 10 iterations pass (whichever first).
defensive_sweep() {
    local table="$1" chain_pattern="$2"
    local iters=0
    while iters_left=$((10 - iters)); [[ ${iters_left} -gt 0 ]]; do
        local found=0
        local chain
        # find chains matching the pattern in this table
        while IFS= read -r chain; do
            [[ -z "${chain}" ]] && continue
            # remove from any parent chain that references it
            local parent
            for parent in PREROUTING INPUT FORWARD OUTPUT POSTROUTING; do
                while iptables -t "${table}" -C "${parent}" -j "${chain}" 2>/dev/null; do
                    iptables -t "${table}" -D "${parent}" -j "${chain}" 2>/dev/null || break
                    found=1
                done
                # also protocol-scoped jumps
                for proto in tcp udp; do
                    while iptables -t "${table}" -C "${parent}" -p "${proto}" -j "${chain}" 2>/dev/null; do
                        iptables -t "${table}" -D "${parent}" -p "${proto}" -j "${chain}" 2>/dev/null || break
                        found=1
                    done
                done
            done
            iptables -t "${table}" -F "${chain}" 2>/dev/null && found=1
            iptables -t "${table}" -X "${chain}" 2>/dev/null && found=1
        done < <(iptables -t "${table}" -L -n 2>/dev/null | awk '/^Chain '"${chain_pattern}"'/{print $2}')
        [[ ${found} -eq 0 ]] && break
        iters=$((iters + 1))
    done
}
defensive_sweep nat 'AEGIS_WIDE'
defensive_sweep filter 'AEGIS_WIDE'
defensive_sweep mangle 'AEGIS_WIDE'

# 6. Same for ip6tables filter (IPv6 block chains).
# Includes the tproxy helper's AEGIS_WIDE_TPROXY_V6_BLOCK and the legacy
# AEGIS_WIDE_V6 / AEGIS_WIDE_FILTER_V6 names from older helpers.
if command -v ip6tables >/dev/null 2>&1; then
    for chain in AEGIS_WIDE_TPROXY_V6_BLOCK AEGIS_WIDE_V6 AEGIS_WIDE_FILTER_V6; do
        for parent in INPUT FORWARD OUTPUT; do
            ip6tables -t filter -D "${parent}" -j "${chain}" 2>/dev/null || true
        done
        ip6tables -t filter -F "${chain}" 2>/dev/null || true
        ip6tables -t filter -X "${chain}" 2>/dev/null || true
    done
fi

# 7. Drop ip rule fwmark + route table 100 if leftover
ip rule del fwmark 0x1 lookup 100 2>/dev/null || true
ip -4 route flush table 100 2>/dev/null || true

# 7a. Sysctl persistence cleanup (symmetric with aegis-wide-enable.sh).
# Remove our persistent config file and restore the original values that
# were captured at apply time.
AEGIS_WIDE_SYSCTL_FILE="${AEGIS_WIDE_SYSCTL_FILE:-/etc/sysctl.d/99-aegis-wide.conf}"
AEGIS_WIDE_SYSCTL_SNAPSHOT="${AEGIS_WIDE_SYSCTL_SNAPSHOT:-/var/lib/aegis-install/client/wide-sysctl-original.txt}"
if [[ -f "${AEGIS_WIDE_SYSCTL_FILE}" ]]; then
    aegis_root_remove "${AEGIS_WIDE_SYSCTL_FILE}" || exit 1
fi
if [[ -f "${AEGIS_WIDE_SYSCTL_SNAPSHOT}" ]]; then
    # The preflight validated every supported key/value. Keep the snapshot
    # if a later read fails; never treat an unreadable record as empty.
    sysctl_snapshot_text="$(aegis_root_read "${AEGIS_WIDE_SYSCTL_SNAPSHOT}")" || exit 1
    while IFS='=' read -r key value; do
        [[ -z "${key}" ]] && continue
        [[ "${key}" == \#* ]] && continue
        sysctl -wq "${key}=${value}" 2>/dev/null || true
    done <<< "${sysctl_snapshot_text}"
    aegis_root_remove "${AEGIS_WIDE_SYSCTL_SNAPSHOT}" || exit 1
fi
# Reload sysctl from system defaults to pick up any other operator changes.
sysctl --system >/dev/null 2>&1 || true

# 7. Restore DNS-preview resolver state if it was modified by enable.sh
# (Symmetric with the dns=preview branch in aegis-wide-enable.sh.)
networkmanager_dns_conf="/run/NetworkManager/conf.d/90-aegis-wide-dns.conf"
if [[ -f "${networkmanager_dns_conf}" ]] &&
   grep -q '^# Managed by Aegis wide DNS preview$' "${networkmanager_dns_conf}" 2>/dev/null; then
    rm -f "${networkmanager_dns_conf}"
    systemctl reload NetworkManager 2>/dev/null || true
fi
managed_resolv=0
if grep -q '^# Managed by aegis' /etc/resolv.conf 2>/dev/null; then
    managed_resolv=1
fi
restored_resolv=0
if [[ -f "${AEGIS_WIDE_RESOLVER_SNAPSHOT}" ]]; then
    aegis_root_resolver_restore || exit 1
    restored_resolv=1
fi
# --no-block avoids an ExecStop ordering deadlock when disable is unit-driven.
if [[ "${restored_resolv}" == "1" ]]; then
    systemctl start --no-block systemd-resolved 2>/dev/null || true
fi
# Remove fake-IP fields from aegis.toml if we added them
config_file="${AEGIS_CONFIG_FILE:-/etc/aegis/client/aegis.toml}"
if [[ -f "${config_file}.aegis-wide-bak" ]]; then
    # The preflight verified the administrator-owned backup and config tree.
    aegis_root_read "${config_file}.aegis-wide-bak" | aegis_root_state write --path "${config_file}" --preserve-mode || exit 1
    if [[ "${preserve_config_backup}" == 0 ]]; then
        aegis_root_remove "${config_file}.aegis-wide-bak" || exit 1
    fi
elif [[ -f "${config_file}" ]]; then
    # No backup — best-effort strip the lines we may have added
    sed -i '/^dns_preview_listen/d; /^dns_preview_fake_ip_pool/d; /^dns_preview_fake_ip_ttl_secs/d' "${config_file}" 2>/dev/null || true
fi

# The DNS-preview backup is taken after install.sh has already selected the wide
# backend, so restoring it alone still leaves primary=wide and
# ipv6_tun_carried=true.  Restarting that config recreates aegis-tun0 even after
# the firewall teardown.  Explicitly switch the daemon to its per-app SOCKS
# fallback before restart; keep relay credentials/endpoints untouched.
config_disable_failed=0
config_was_present=0
if [[ -f "${config_file}" ]]; then
    config_was_present=1
    if command -v python3 >/dev/null 2>&1; then
        python3 - "${config_file}" <<'PY' || config_disable_failed=1
import os
import re
import stat
import sys
import tempfile

path = sys.argv[1]
text = open(path, encoding="utf-8").read()

def set_value(block: str, key: str, value: str) -> str:
    if re.search(rf"(?m)^\s*{re.escape(key)}\s*=", block):
        return re.sub(
            rf"(?m)^(\s*{re.escape(key)}\s*=\s*).*$",
            rf"\g<1>{value}",
            block,
            count=1,
        )
    return block.rstrip() + f"\n{key} = {value}\n"

ingress = re.search(r"(?ms)^\[ingress\]\s*$.*?(?=^\[|\Z)", text)
if ingress:
    block = ingress.group(0)
    text = text.replace(block, set_value(block, "primary", '"socks5"'), 1)
else:
    text = "[ingress]\nprimary = \"socks5\"\n" + text

wide = re.search(r"(?ms)^\[ingress\.wide\]\s*$.*?(?=^\[|\Z)", text)
if wide:
    block = wide.group(0)
    updated = set_value(block, "enabled", "false")
    updated = set_value(updated, "ipv6_tun_carried", "false")
    updated = set_value(updated, "capture_dns", "false")
    updated = set_value(updated, "udp_capture_contract", '"preview_allowlist_only"')
    updated = re.sub(
        r"(?m)^\s*dns_preview_(?:listen|fake_ip_pool|fake_ip_ttl_secs)\s*=.*\n?",
        "",
        updated,
    )
    text = text.replace(block, updated, 1)

metadata = os.stat(path)
parent = os.path.dirname(path) or "."
fd, temporary = tempfile.mkstemp(prefix=".aegis-wide-disable.", dir=parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
    os.chown(temporary, metadata.st_uid, metadata.st_gid)
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
    else
        config_disable_failed=1
    fi
fi

if [[ ${config_disable_failed} -eq 0 ]]; then
    aegis_root_remove "${AEGIS_WIDE_PROFILE_STATE:-/var/lib/aegis-install/client/wide-profile.json}" || exit 1
    # Restart only after persistence is disabled and the on-disk config can no
    # longer launch either transparent backend.  A missing config is already an
    # idempotently safe on-disk state; do not stop or restart an unrelated
    # currently-running per-app client in that case.
    if [[ ${config_was_present} -eq 1 ]]; then
        systemctl restart aegis-client 2>/dev/null || true
    fi
else
    echo "ERROR: could not switch client config out of wide mode; stopping client fail-safe" >&2
    systemctl stop aegis-client 2>/dev/null || true
fi

# 8. Remove the persistence unit files after the early disable/stop above.  A
# later client restart therefore cannot re-apply capture during this teardown.
rm -f /etc/systemd/system/aegis-wide-tun-firewall.service 2>/dev/null || true

# A manual disable must also remove the generic redirect/TPROXY persistence
# unit.  ExecStop of that unit calls this same script with the marker below, so
# leave its unit file for the outer systemctl stop to remove in that one context.
if [[ "${AEGIS_WIDE_DISABLE_FROM_UNIT:-0}" != "1" ]]; then
    rm -f /etc/systemd/system/aegis-wide.service 2>/dev/null || true
fi
systemctl daemon-reload >/dev/null 2>&1 || true

# 9. Clear sentinel so any future enable starts fresh
rm -f "${SENTINEL_FILE}"

# Never claim success while capture residue is still able to black-hole the
# host.  The low-level helpers are intentionally best-effort for idempotence;
# this operator-facing wrapper is the transaction boundary and must enforce the
# final state.  Missing inspection tools are tolerated for portability, but any
# observable AEGIS firewall/TUN residue makes disable fail loudly.
disable_residue=0
if [[ ${config_disable_failed} -ne 0 ]]; then
    disable_residue=1
fi
if command -v iptables-save >/dev/null 2>&1 \
    && iptables-save 2>/dev/null | grep -F 'AEGIS_WIDE' >/dev/null; then
    echo "ERROR: IPv4 AEGIS wide firewall residue remains after disable" >&2
    disable_residue=1
fi
if command -v ip6tables-save >/dev/null 2>&1 \
    && ip6tables-save 2>/dev/null | grep -F 'AEGIS_WIDE' >/dev/null; then
    echo "ERROR: IPv6 AEGIS wide firewall residue remains after disable" >&2
    disable_residue=1
fi
if command -v nft >/dev/null 2>&1; then
    nft_table="${AEGIS_WIDE_NFT_TABLE:-aegis_wide_tproxy}"
    for nft_family in ip ip6; do
        if nft list table "${nft_family}" "${nft_table}" >/dev/null 2>&1; then
            echo "ERROR: ${nft_family} AEGIS wide nft table remains after disable" >&2
            disable_residue=1
        fi
    done
fi
if command -v ip >/dev/null 2>&1; then
    if ip link show aegis-tun0 >/dev/null 2>&1; then
        echo "ERROR: aegis-tun0 remains after disable" >&2
        disable_residue=1
    fi
    if ip -6 route show 2>/dev/null \
        | grep -E '(^| )(::/1|8000::/1)( |$).*dev aegis-tun0' >/dev/null; then
        echo "ERROR: AEGIS IPv6 capture routes remain after disable" >&2
        disable_residue=1
    fi
fi
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet aegis-wide-tun-firewall.service 2>/dev/null \
        || systemctl is-active --quiet aegis-wide.service 2>/dev/null; then
        echo "ERROR: AEGIS wide persistence unit remains active after disable" >&2
        disable_residue=1
    fi
fi

if [[ ${disable_residue} -ne 0 ]]; then
    echo "AEGIS wide mode disable FAILED; refusing a false success report" >&2
    exit 1
fi

# Privacy release is the LAST action of an explicit disconnect. Low-level
# capture teardown, unit-driven teardown and upgrade cleanup all retain it.
# A failed cleanup above cannot expose native TCP, UDP, IPv6 or DNS.
legacy_guard_state=/var/lib/aegis-install/client/legacy-tun-guard.conf
if [[ "${AEGIS_WIDE_DISABLE_FROM_UNIT:-0}" != 1 && "${AEGIS_WIDE_DISABLE_KEEP_LEGACY_GUARD:-0}" != 1 &&
      ( -e "$legacy_guard_state" || -L "$legacy_guard_state" || -e /etc/systemd/system/aegis-legacy-tun-guard.service ) ]]; then
    if [[ ! -x "${SCRIPT_DIR}/setup-wide-linux-redirect.sh" ]] ||
       ! AEGIS_LEGACY_TUN_GUARD_STATE="$legacy_guard_state" bash "${SCRIPT_DIR}/setup-wide-linux-redirect.sh" guard-release; then
        echo 'ERROR: explicit legacy TUN guard release failed; block/recovery files retained' >&2
        exit 1
    fi
fi

cat <<DONE
AEGIS wide mode DISABLED
------------------------
nat OUTPUT (after):
$(iptables -t nat -L OUTPUT -n -v | head -6)

If any aegis-wide-* iptables/nft state remains, run scripts/janitor-wide-linux-tproxy.sh manually.
DONE
