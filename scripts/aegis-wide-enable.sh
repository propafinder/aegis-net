#!/usr/bin/env bash
# aegis-wide-enable.sh — interactive Linux wide-mode activator.
#
# Wraps scripts/setup-wide-linux-redirect.sh or scripts/setup-wide-linux-tproxy.sh
# with safety rails:
#   - detects outbound interface
#   - asks operator about mode (REDIRECT or TPROXY)
#   - exempts SSH safe ports BEFORE redirect chain hook
#   - exempts current SSH session source IP (if SSH_CONNECTION is set)
#   - 60-second auto-rollback timer unless operator confirms "keep"
#   - doctor before/after
#   - hard refuse if interface cannot be detected
#   - hard refuse if SSH safe ports empty on a remote session
#
# Default install never auto-runs this — wide mode stays explicit opt-in.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WIDE_PORT="${AEGIS_WIDE_PORT:-15080}"
SSH_SAFE_PORTS_DEFAULT="22"
ROLLBACK_SECS="${AEGIS_WIDE_ROLLBACK_SECS:-60}"
# The deadman receives values as arguments; keep its sleep interval numeric.
if ! [[ "${ROLLBACK_SECS}" =~ ^[0-9]+$ ]]; then
  echo "AEGIS_WIDE_ROLLBACK_SECS must be a whole number of seconds (got: ${ROLLBACK_SECS})" >&2
  exit 2
fi
SENTINEL_FILE="/run/aegis-wide-confirmed"
# --no-rollback (or AEGIS_WIDE_NO_ROLLBACK=1): skip the interactive auto-rollback
# timer entirely. Used by the boot-persistence unit, where wide must STAY after
# reboot (an operator who installed persistence already committed to sticky
# mode) — a ticking rollback there is pointless and confusing.
NO_ROLLBACK="${AEGIS_WIDE_NO_ROLLBACK:-0}"

if [[ "${EUID}" -ne 0 && -z "${AEGIS_WIDE_SKIP_ROOT_CHECK:-}" ]]; then
    echo "FATAL: must run under sudo/root" >&2
    exit 2
fi

interactive=1
yes_all=0
mode_arg=""
ssh_safe_ports_arg=""
dns_arg=""
ipv6_arg=""
udp_arg=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)
            yes_all=1
            interactive=0
            shift
            ;;
        --no-rollback)
            NO_ROLLBACK=1
            shift
            ;;
        --mode=*)
            mode_arg="${1#*=}"
            shift
            ;;
        --ssh-safe-ports=*)
            ssh_safe_ports_arg="${1#*=}"
            shift
            ;;
        --dns=*)
            dns_arg="${1#*=}"
            shift
            ;;
        --ipv6=*)
            ipv6_arg="${1#*=}"
            shift
            ;;
        --udp=*)
            # carry = tunnel generic UDP + QUIC over MASQUE (needs the client
            # daemon running with udp_capture_contract=generic_capture_unstable,
            # which auto-spawns the redirect proxy on WIDE_PORT+1). block =
            # fail-closed (default, safe).
            udp_arg="${1#*=}"
            shift
            ;;
        --interface=*)
            # Operator override for the ingress interface (e.g. aegis-gre0
            # when running behind a GRE tunnel — see scripts/aegis-gre-gateway-setup.sh).
            # If unset, default is auto-detected from the default route.
            interface_arg="${1#*=}"
            shift
            ;;
        --help|-h)
            cat <<'HELP_EOF'
aegis-wide-enable.sh — interactive Linux wide-mode activator

Usage:
    sudo aegis-wide-enable [options]

Options:
    -y, --yes                       non-interactive; use defaults / --* args
    --mode=MODE                     capture mode: redirect or tproxy (default redirect)
    --ssh-safe-ports=22[,222,...]   ports to exempt from capture (default 22)
    --dns=preview|off               UDP/53 capture policy (default preview)
    --ipv6=block|out_of_scope|capture
                                    IPv6 policy (default block). `capture`
                                    switches the wide listener to IPv6 mode
                                    (listen on [::]:15080) and installs the
                                    full ip6tables PREROUTING TPROXY chain
                                    + ip -6 policy routing. Requires
                                    --mode=tproxy (REDIRECT is IPv4-only).
    --interface=NAME                ingress interface for PREROUTING/TPROXY
                                    (default auto-detected from default route;
                                    set to e.g. aegis-gre0 when using the
                                    GRE-tunneled gateway recipe)

Safety:
    Always exempts SSH safe ports and the current SSH session source IP.
    60-second auto-rollback unless operator runs:
        sudo touch /run/aegis-wide-confirmed
HELP_EOF
            exit 0
            ;;
        *)
            echo "FATAL: unknown argument $1; see --help" >&2
            exit 2
            ;;
    esac
done

# ---------- detection ----------

detect_default_interface() {
    ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

detect_aegis_uid() {
    # Prefer the uid the aegis-client service ACTUALLY runs as — this handles a
    # dedicated service account that is not named 'aegis' (e.g. 'aegis-svc', which
    # install.sh uses when the machine's login user is literally named 'aegis').
    # Falling back to `id -u aegis` here would exempt the operator's login account
    # from capture, so their apps would silently bypass the tunnel.
    local u
    u="$(systemctl show aegis-client.service -p User --value 2>/dev/null)"
    if [[ -n "$u" ]] && id -u "$u" >/dev/null 2>&1; then
        id -u "$u"
        return 0
    fi
    id -u aegis-client 2>/dev/null || id -u aegis 2>/dev/null || echo ""
}

# Parse /etc/aegis/client/aegis.toml for relay endpoints (host:port pairs)
# so the wide-mode REDIRECT chain can exempt outbound traffic to them.
# Without this exempt, aegis-client's own outbound to the relay would be
# REDIRECT'd back to the wide port, creating an infinite loop. Required
# when aegis-client runs as root (most production installs) because
# owner-match on UID 0 would defeat the wide-mode purpose.
detect_relay_endpoints() {
    local cfg="/etc/aegis/client/aegis.toml"
    [[ ! -r "${cfg}" ]] && return 0
    grep -E '^server\s*=|^\s*server\s*=' "${cfg}" | \
        sed -E 's/^.*=\s*"([^"]+)".*$/\1/' | \
        grep -E ':[0-9]+$' | \
        sort -u
}

detect_ssh_source_ip() {
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        printf '%s' "${SSH_CONNECTION}" | awk '{print $1}'
    fi
}

session_is_remote_ssh() {
    [[ -n "${SSH_CONNECTION:-}" ]]
}

INTERFACE="${interface_arg:-$(detect_default_interface)}"
# Honor an explicitly-passed exempt uid (install.sh computes it from the client's
# real systemd User= via client_service_uid); only auto-detect when unset/empty.
AEGIS_UID="${AEGIS_EXEMPT_UID:-$(detect_aegis_uid)}"
# Safety: exempting a LOGIN account's uid (>= 1000) from capture means that user's
# own apps bypass the tunnel (native IP) — the exact footgun when the machine's
# login user is named 'aegis'. Refuse rather than silently mis-capture; the client
# must run under a dedicated system account (install.sh resolves 'aegis-svc').
if [[ -n "${AEGIS_UID}" && "${AEGIS_UID}" =~ ^[0-9]+$ && "${AEGIS_UID}" -ge 1000 ]]; then
    echo "FATAL: refusing to exempt uid ${AEGIS_UID} (a login account) from wide capture —" >&2
    echo "       that would make that user's own apps bypass the tunnel. The aegis-client" >&2
    echo "       service must run under a dedicated SYSTEM account (uid < 1000). Reinstall" >&2
    echo "       with a fixed installer, or set AEGIS_EXEMPT_UID to a system uid." >&2
    exit 3
fi
SSH_SRC_IP="$(detect_ssh_source_ip)"

if [[ -z "${INTERFACE}" ]]; then
    echo "FATAL: cannot detect default outbound interface (ip -4 route show default returned nothing)" >&2
    echo "       wide mode requires a known interface to scope capture" >&2
    exit 3
fi

RELAY_ENDPOINTS_RAW="$(detect_relay_endpoints)"
if [[ -z "${AEGIS_UID}" && -z "${RELAY_ENDPOINTS_RAW}" ]]; then
    echo "FATAL: cannot prevent redirect loop — neither aegis user nor /etc/aegis/client/aegis.toml relay endpoints found" >&2
    echo "       install aegis-client first OR set AEGIS_EXEMPT_UID manually before enabling wide mode" >&2
    exit 3
fi
if [[ -z "${AEGIS_UID}" ]]; then
    echo "INFO: aegis user not found; will exempt relay destination ports instead of using UID guard"
fi

# ---------- interactive prompts ----------

prompt() {
    local question="$1" default="$2" answer
    if [[ ${interactive} -eq 0 ]]; then
        printf '%s\n' "${default}"
        return 0
    fi
    read -r -p "${question} [${default}]: " answer </dev/tty
    if [[ -z "${answer}" ]]; then
        printf '%s\n' "${default}"
    else
        printf '%s\n' "${answer}"
    fi
}

mode="${mode_arg:-$(prompt "Mode? (redirect|tproxy)" "redirect")}"
case "${mode}" in
    redirect|tproxy) ;;
    *) echo "FATAL: mode must be redirect or tproxy (got: ${mode})" >&2; exit 2 ;;
esac

ssh_safe_ports="${ssh_safe_ports_arg:-$(prompt "SSH safe ports (comma-separated)" "${SSH_SAFE_PORTS_DEFAULT}")}"
if session_is_remote_ssh && [[ -z "${ssh_safe_ports}" ]]; then
    echo "FATAL: remote SSH session detected but SSH safe ports is empty — refusing to lock you out" >&2
    exit 3
fi

# Audit C3: default to the fake-IP DNS-preview path (capture DNS into the
# tunnel) rather than leaving plaintext UDP/53 to egress uncaptured. The
# resolver-based capture (local 127.0.0.1:53 listener + resolv.conf repoint +
# systemd-resolved stub stop) is fully reversible on disable and protected by
# the auto-rollback timer, so a failed apply cannot strand host DNS. Operators
# who explicitly want the leaky legacy behaviour can still pass --dns=off.
dns_choice="${dns_arg:-$(prompt "DNS UDP/53 handling? (preview|off)" "preview")}"
case "${dns_choice}" in
    preview|off) ;;
    *) echo "FATAL: dns must be preview or off (got: ${dns_choice})" >&2; exit 2 ;;
esac

ipv6_choice="${ipv6_arg:-$(prompt "IPv6 policy? (block|out_of_scope|capture)" "block")}"
case "${ipv6_choice}" in
    block|out_of_scope|capture) ;;
    *) echo "FATAL: ipv6 must be block, out_of_scope, or capture (got: ${ipv6_choice})" >&2; exit 2 ;;
esac

# Generic UDP + QUIC: carry over MASQUE, or fail-closed block (default, safe).
udp_choice="${udp_arg:-block}"
case "${udp_choice}" in
    carry|block) ;;
    *) echo "FATAL: udp must be carry or block (got: ${udp_choice})" >&2; exit 2 ;;
esac

# capture requires mode=tproxy: REDIRECT path is IPv4-only (NAT REDIRECT
# does not preserve original-dst for v6 the way iptables conntrack does
# for v4 TCP, and the v6 NAT REDIRECT target is not provided by most
# kernels). Reject early with a clear message rather than installing a
# half-broken capture pipeline.
if [[ "${ipv6_choice}" == "capture" && "${mode}" != "tproxy" ]]; then
    echo "FATAL: --ipv6=capture requires --mode=tproxy (REDIRECT is IPv4-only)" >&2
    exit 2
fi

# ---------- summary + confirm ----------

cat <<SUMMARY
============================================================
AEGIS wide-mode activation summary
------------------------------------------------------------
mode:               ${mode}
outbound iface:     ${INTERFACE}
wide listen port:   ${WIDE_PORT}
aegis exempt uid:   ${AEGIS_UID}
SSH safe ports:     ${ssh_safe_ports}
SSH session src IP: ${SSH_SRC_IP:-(none / local console)}
DNS UDP/53:         ${dns_choice}
IPv6 policy:        ${ipv6_choice}
auto-rollback:      $([[ "${NO_ROLLBACK}" == "1" ]] && echo "disabled (persistent/sticky mode)" || echo "${ROLLBACK_SECS}s unless aegis-wide-confirm run")
============================================================
SUMMARY

if [[ ${interactive} -eq 1 ]]; then
    read -r -p "Apply now? (yes/no): " ack </dev/tty
    if [[ "${ack}" != "yes" && "${ack}" != "YES" ]]; then
        echo "ABORTED — no changes made"
        exit 1
    fi
fi

# shellcheck source=scripts/lib/root-state.sh
. "${SCRIPT_DIR}/lib/root-state.sh"
aegis_root_network_preflight || exit 1

# ---------- private DNS-preview configuration ----------
# The installed Rust metadata writer supplies trusted ancestry, O_NOFOLLOW,
# bounded input, exclusive records, descriptor writes and rename/directory fsync.
# No config bytes are passed through arguments, environment variables or logs.
aegis_wide_config_stage=""
aegis_wide_config_original=""
aegis_wide_config_rendered=""
aegis_wide_config_backup=""
aegis_wide_config_keep_recovery=0
aegis_wide_config_keep_transaction=0
aegis_wide_config_group=""
aegis_wide_config_mode=""
aegis_wide_config_rollback="${SCRIPT_DIR}/aegis-wide-disable.sh"

aegis_wide_config_cleanup() {
    local failed=0
    [[ -n "${aegis_wide_config_stage}" ]] || return 0
    if [[ "${aegis_wide_config_keep_transaction}" == 1 ]]; then
        # Failure after the new redirect commit does not prove restored live
        # service readiness. Keep every completed private transaction record.
        printf 'ERROR: private config transaction recovery records retained at %s\n' \
            "${aegis_wide_config_stage}" >&2
        return 0
    fi
    aegis_root_remove "${aegis_wide_config_stage}/original.toml" || failed=1
    aegis_root_remove "${aegis_wide_config_stage}/render.toml" || failed=1
    # Never remove the original backup or an unrelated predictable .tmp entry.
    if [[ "${aegis_wide_config_keep_recovery}" == 1 ]]; then
        # This may be the last verified original recovery copy. Do not delete
        # it merely because rollback failed or a different backup survived.
        printf 'ERROR: original config recovery snapshot retained at %s\n' \
            "${aegis_wide_config_backup}" >&2
        return "${failed}"
    fi
    aegis_root_remove "${aegis_wide_config_stage}/backup.toml" || failed=1
    rmdir -- "${aegis_wide_config_stage}" || failed=1
    if [[ "${failed}" == 0 ]]; then
        aegis_wide_config_stage=""
        aegis_wide_config_original=""
        aegis_wide_config_rendered=""
        aegis_wide_config_backup=""
    fi
    return "${failed}"
}

aegis_wide_config_exit_cleanup() {
    local status="$?"
    # Own abnormal post-commit exit recovery exactly once. Never recursively
    # enter EXIT or signal handlers while the independent rollback is running.
    trap - EXIT
    trap '' INT TERM HUP
    if [[ "${mode:-}" == redirect && "${aegis_wide_config_applied:-0}" == 1 &&
          "${aegis_wide_transaction_complete:-0}" != 1 && "${aegis_wide_rollback_running:-0}" != 1 ]]; then
        aegis_wide_config_keep_transaction=1
        aegis_wide_config_keep_recovery=1
        aegis_wide_config_cleanup || true
        aegis_wide_config_failed
    fi
    if ! aegis_wide_config_cleanup; then
        echo 'ERROR: could not remove private DNS-preview staging records.' >&2
        [[ "${status}" != 0 ]] || status=1
    fi
    exit "${status}"
}

aegis_wide_config_prepare() {
    [[ "${dns_choice}" == preview ]] || return 0
    config_file="${AEGIS_CONFIG_FILE:-/etc/aegis/client/aegis.toml}"
    # DNS preview cannot point the resolver at an unconfigured listener.
    # This explicit fail-closed tightening precedes identity and capability
    # checks; the full metadata preflight separately refuses hostile links.
    [[ -f "${config_file}" && ! -L "${config_file}" ]] || {
        echo 'FATAL: DNS preview requires an existing regular installed config before capture.' >&2
        return 1
    }
    # Destination-only relay exemptions cannot establish the daemon's config
    # read identity. Refuse unknown identities before any capture apply.
    local actual_uid service_group config_parent stage
    [[ "${AEGIS_UID}" =~ ^[0-9]+$ ]] || {
        echo 'FATAL: DNS preview requires a known service UID before capture.' >&2
        return 1
    }
    actual_uid="$(id -u "${AEGIS_UID}" 2>/dev/null)" || return 1
    [[ "${actual_uid}" == "${AEGIS_UID}" ]] || return 1
    service_group="$(systemctl show aegis-client.service -p Group --value 2>/dev/null)" || return 1
    if [[ -z "${service_group}" ]]; then
        service_group="$(id -g "${AEGIS_UID}" 2>/dev/null)" || return 1
    fi
    # getent resolves both a configured group name and a numeric GID. No
    # assumption that the UID equals the daemon's effective group is safe.
    aegis_wide_config_group="$(getent group "${service_group}" | awk -F: '
        NF >= 3 && $3 ~ /^[0-9]+$/ { if (++count == 1) gid = $3 }
        END { if (count != 1) exit 1; print gid }
    ')" || {
        echo 'FATAL: cannot resolve the DNS-preview service group before capture.' >&2
        return 1
    }
    if [[ "${AEGIS_UID}" == 0 ]]; then
        aegis_wide_config_mode=0600
    else
        aegis_wide_config_mode=0640
    fi
    # This is a read-only capability check on the already verified executable.
    # Older clients must be upgraded; there is no path-write fallback.
    aegis_root_state write --help | grep -F -- '--exclusive' >/dev/null || {
        echo 'FATAL: installed client lacks exclusive metadata creation; upgrade before capture.' >&2
        return 1
    }
    aegis_root_trusted_executable "${aegis_wide_config_rollback}" || {
        echo 'FATAL: verified wide-disable rollback helper is required before capture.' >&2
        return 1
    }
    # A trusted but older disable script would ignore the preservation flag.
    # Require its fixed internal declaration before applying capture.
    grep -Fx 'preserve_config_backup="${AEGIS_WIDE_ROLLBACK_PRESERVE_CONFIG_BACKUP:-0}"' \
        "${aegis_wide_config_rollback}" >/dev/null || {
        echo 'FATAL: installed wide-disable lacks backup preservation; upgrade before capture.' >&2
        return 1
    }
    config_parent="$(dirname -- "${config_file}")"
    # A full preflight already validated config and its administrator-owned
    # ancestry. The fresh directory stays on that filesystem, ignoring TMPDIR.
    stage="$(umask 077; mktemp -d "${config_parent}/.aegis-wide-config.XXXXXX")" || return 1
    [[ "${stage}" == "${config_parent}/.aegis-wide-config."* && -d "${stage}" && ! -L "${stage}" ]] || return 1
    aegis_wide_config_stage="${stage}"
    chmod 0700 "${stage}" || return 1
    aegis_wide_config_original="${stage}/original.toml"
    aegis_wide_config_rendered="${stage}/render.toml"
    aegis_wide_config_backup="${stage}/backup.toml"
    # Every pipeline targets an unpublished private record. Check the WHOLE
    # pipeline before a backup or live config can be published.
    aegis_root_read "${config_file}" |
        aegis_root_state write --path "${aegis_wide_config_original}" --mode 0600 --exclusive || return 1
    aegis_root_validate "${aegis_wide_config_original}" || return 1
    if grep -q '^\[ingress\.wide\]' "${aegis_wide_config_original}"; then
        aegis_root_read "${aegis_wide_config_original}" | awk '
            /^dns_preview_listen/ || /^dns_preview_fake_ip_pool/ || /^dns_preview_fake_ip_ttl_secs/ { next }
            /^\[ingress\.wide\]/ {
                print
                print "dns_preview_listen = \"127.0.0.1:53\""
                print "dns_preview_fake_ip_pool = \"198.18.0.0/15\""
                print "dns_preview_fake_ip_ttl_secs = 60"
                next
            }
            { print }
        ' | aegis_root_state write --path "${aegis_wide_config_rendered}" --mode 0600 --exclusive || return 1
    else
        # Keep the old no-section stale-field removal without changing live
        # bytes or normalizing its final newline through a shell variable.
        aegis_root_read "${aegis_wide_config_original}" |
            sed '/^dns_preview_listen/d; /^dns_preview_fake_ip_pool/d; /^dns_preview_fake_ip_ttl_secs/d' |
            aegis_root_state write --path "${aegis_wide_config_rendered}" --mode 0600 --exclusive || return 1
        echo "WARN: [ingress.wide] section not found in ${config_file}; fake-IP listener will not start" >&2
    fi
    aegis_root_validate "${aegis_wide_config_rendered}" || return 1
    # Back up once, from completed checked input, before capture. An existing
    # backup is never replaced or removed by preparation or its cleanup.
    if [[ ! -e "${config_file}.aegis-wide-bak" && ! -L "${config_file}.aegis-wide-bak" ]]; then
        aegis_root_state write --path "${config_file}.aegis-wide-bak" --mode 0600 --exclusive \
            < "${aegis_wide_config_original}" || return 1
    fi
    # Snapshot the original recovery record, which may differ from the active
    # config on re-apply. A fresh systemd ExecStop need not inherit our flag.
    aegis_root_read "${config_file}.aegis-wide-bak" |
        aegis_root_state write --path "${aegis_wide_config_backup}" --mode 0600 --exclusive || return 1
    aegis_root_validate "${aegis_wide_config_backup}" || return 1
}

aegis_wide_config_commit() {
    [[ -n "${aegis_wide_config_rendered}" ]] || return 0
    # Completed protected input only: upstream render failure cannot publish a
    # partial live config. A write error may still follow its successful rename.
    aegis_root_state write --path "${config_file}" --mode 0600 \
        < "${aegis_wide_config_rendered}" || return 1
    chown "root:${aegis_wide_config_group}" "${config_file}" || return 1
    chmod "${aegis_wide_config_mode}" "${config_file}" || return 1
    # Preserve that checked service policy through the writer's descriptor
    # fchown/fchmod, file fsync, atomic replacement and parent directory fsync.
    aegis_root_state write --path "${config_file}" --preserve-mode \
        < "${aegis_wide_config_rendered}" || return 1
}

aegis_wide_config_restore_backup() {
    if [[ ! -e "${config_file}.aegis-wide-bak" && ! -L "${config_file}.aegis-wide-bak" ]]; then
        # Never replace a surviving entry. A racing create is refused by the
        # actual exclusive writer and keeps the private recovery snapshot.
        aegis_root_state write --path "${config_file}.aegis-wide-bak" --mode 0600 --exclusive \
            < "${aegis_wide_config_backup}" || return 1
    fi
    # Read via the actual no-follow descriptor boundary. A surviving changed
    # backup is not overwritten, even when the independent teardown failed.
    aegis_root_read "${config_file}.aegis-wide-bak" |
        cmp -s -- "${aegis_wide_config_backup}" - || return 1
}

aegis_wide_config_failed() {
    local rollback_failed=0
    aegis_wide_rollback_running=1
    trap '' INT TERM HUP
    if [[ "${aegis_wide_config_applied:-0}" == 1 ]]; then
        aegis_wide_config_keep_transaction=1
        aegis_wide_config_keep_recovery=1
    fi
    echo 'FATAL: DNS-preview config commit failed; initiating independent rollback.' >&2
    # Protect the last recovery copy before calling anything that may recurse
    # through a fresh systemd ExecStop process without this environment flag.
    aegis_wide_config_keep_recovery=1
    if ! AEGIS_WIDE_ROLLBACK_PRESERVE_CONFIG_BACKUP=1 "${aegis_wide_config_rollback}"; then
        rollback_failed=1
    fi
    if aegis_wide_config_restore_backup; then
        aegis_wide_config_keep_recovery=0
    else
        echo 'ERROR: original config backup could not be verified or exclusively restored.' >&2
        rollback_failed=1
    fi
    if [[ "${rollback_failed}" == 1 ]]; then
        echo 'FATAL: wide rollback incomplete; stopping the client fail-safe.' >&2
        # Disable can fail during preflight before its normal persistence/stop
        # path. Disarm persistence and stop the daemon independently as well.
        systemctl disable aegis-wide-tun-firewall.service >/dev/null 2>&1 || true
        systemctl disable aegis-wide.service >/dev/null 2>&1 || true
        systemctl stop aegis-wide-tun-firewall.service >/dev/null 2>&1 || true
        systemctl stop aegis-client >/dev/null 2>&1 || true
    fi
    if [[ "${aegis_wide_config_applied:-0}" == 1 ]]; then
        # Independent disable and backup equality do not prove the restored
        # daemon's native readiness. Preserve diagnostics for owner acceptance.
        aegis_wide_config_keep_transaction=1
        aegis_wide_config_keep_recovery=1
    fi
    exit 5
}

trap aegis_wide_config_exit_cleanup EXIT
if [[ "${mode:-}" == redirect ]]; then
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
fi
aegis_wide_config_prepare || exit 1
# ---------- end private DNS-preview configuration ----------

# ---------- pre-apply doctor snapshot ----------

snapshot_dir="$(mktemp -d /run/aegis-wide-doctor.XXXXXX)"
iptables -t nat -L OUTPUT -n -v > "${snapshot_dir}/before-nat-output.txt" 2>&1 || true
iptables -t filter -L OUTPUT -n -v > "${snapshot_dir}/before-filter-output.txt" 2>&1 || true
ip -4 route show > "${snapshot_dir}/before-routes-v4.txt" 2>&1 || true
ip -6 route show > "${snapshot_dir}/before-routes-v6.txt" 2>&1 || true
echo "Doctor snapshot saved to ${snapshot_dir}"

# Redirect preview must restart before capture binds the service cgroup.
# Readiness is a bounded active MainPID plus actual owned TCP/DNS listeners,
# not a successful restart request or a fixed sleep. No network probe is sent.
aegis_wide_config_applied=0
aegis_wide_transaction_complete=0
aegis_wide_rollback_running=0
aegis_wide_ready_pid=""
aegis_wide_ready_inode=""
# Dynamic local deadline belongs to the readiness transaction. Every operation
# checks the same affine budget before and after its own one-second ceiling.
aegis_wide_readiness_query() {
    (( SECONDS < deadline )) || return 1
    timeout 1 "$@" 2>/dev/null || return 1
    (( SECONDS < deadline ))
}
aegis_wide_redirect_ready() {
    local deadline=$((SECONDS + 15)) pid active tcp_ready dns_ready group inode pid_after group_after inode_after
    command -v timeout >/dev/null && command -v ss >/dev/null || return 1
    while (( SECONDS < deadline )); do
        active="$(aegis_wide_readiness_query systemctl show aegis-client.service -p ActiveState --value 2>/dev/null)" || active=""
        pid="$(aegis_wide_readiness_query systemctl show aegis-client.service -p MainPID --value 2>/dev/null)" || pid=""
        if [[ "${active}" == active && "${pid}" =~ ^[1-9][0-9]*$ ]]; then
            group="$(aegis_wide_readiness_query systemctl show aegis-client.service -p ControlGroup --value 2>/dev/null)" || group=""
            [[ "${group}" == /* && "${group}" != / && "${group}" != *'..'* && "${group}" =~ ^/[A-Za-z0-9_.@:/-]+$ ]] || return 1
            inode="$(aegis_wide_readiness_query stat -c %i "/sys/fs/cgroup${group}" 2>/dev/null)" || inode=""
            [[ "${inode}" =~ ^[1-9][0-9]*$ ]] || return 1
            tcp_ready="$(aegis_wide_readiness_query ss -H -ltnp "( sport = :${WIDE_PORT} )" 2>/dev/null)" || tcp_ready=""
            dns_ready="$(aegis_wide_readiness_query ss -H -lunp '( sport = :53 )' 2>/dev/null)" || dns_ready=""
            if awk -v owner="pid=${pid}," 'index($0, owner) {found=1} END {exit !found}' <<< "${tcp_ready}" &&
               awk -v owner="pid=${pid}," '$4 == "127.0.0.1:53" && index($0, owner) {found=1} END {exit !found}' <<< "${dns_ready}"; then
                pid_after="$(aegis_wide_readiness_query systemctl show aegis-client.service -p MainPID --value 2>/dev/null)" || pid_after=""
                group_after="$(aegis_wide_readiness_query systemctl show aegis-client.service -p ControlGroup --value 2>/dev/null)" || group_after=""
                inode_after="$(aegis_wide_readiness_query stat -c %i "/sys/fs/cgroup${group}" 2>/dev/null)" || inode_after=""
                [[ "${pid_after}" == "${pid}" && "${group_after}" == "${group}" && "${inode_after}" == "${inode}" ]] || return 1
                aegis_wide_ready_pid="${pid}"
                aegis_wide_ready_inode="${inode}"
                return 0
            fi
        fi
        (( SECONDS < deadline )) || return 1
        sleep 0.1
    done
    return 1
}

aegis_wide_redirect_preview_activate() {
    [[ "${dns_choice}" == preview ]] || return 0
    command -v timeout >/dev/null && command -v ss >/dev/null || exempt_failed "readiness tools unavailable"
    # A writer can fail after rename: arm rollback before the first commit.
    aegis_wide_config_applied=1
    aegis_wide_config_commit || aegis_wide_config_failed
    aegis_root_resolver_save || aegis_wide_config_failed
    timeout 5 systemctl stop systemd-resolved >/dev/null 2>&1 || aegis_wide_config_failed
    rm -f /etc/resolv.conf || aegis_wide_config_failed
    cat > /etc/resolv.conf <<RESOLV || aegis_wide_config_failed
# Managed by aegis-wide-enable.sh (dns=preview). Restored on disable.
nameserver 127.0.0.1
options timeout:2 attempts:1
RESOLV
    timeout 15 systemctl restart aegis-client >/dev/null 2>&1 || aegis_wide_config_failed
    aegis_wide_redirect_ready || aegis_wide_config_failed
}

# ---------- apply ----------

# 1. Redirect capture uses the helper's verified service cgroup, never relay
# destinations or the operator UID. TPROXY retains its separate legacy policy.
SSH_EXEMPT_CHAIN="AEGIS_WIDE_SSH_EXEMPT"
exempt_failed() {
    echo "FATAL: failed to install SSH/relay exemption ($1); refusing capture apply" >&2
    if [[ "${mode}" == redirect && "${aegis_wide_config_applied:-0}" == 1 ]]; then
        aegis_wide_config_failed
    fi
    exit 4
}
if [[ "${mode}" == redirect ]]; then
    # Resolve/probe before touching the active wrapper hook. Recheck identity
    # during apply in the existing helper; no destination/UID fallback is safe.
    underlying="${SCRIPT_DIR}/setup-wide-linux-redirect.sh"
    [[ -x "${underlying}" ]] || exempt_failed "redirect helper unavailable"
    export AEGIS_WIDE_REQUIRE_CGROUP=1
    export AEGIS_WIDE_EXEMPT_SERVICE=aegis-client.service
    export AEGIS_WIDE_PORT="${WIDE_PORT}"
    export AEGIS_WIDE_MANAGEMENT_PORTS="${ssh_safe_ports}"
    export AEGIS_WIDE_INTERFACE="${INTERFACE}"
    # Ignore an inherited unverified path; derive the path from the live service.
    unset AEGIS_WIDE_EXEMPT_CGROUP AEGIS_WIDE_EXPECTED_SERVICE_PID AEGIS_WIDE_EXPECTED_CGROUP_INODE

    # SSH_CONNECTION supplies a requested inbound session's peer/local tuple.
    # Syntax validation does not establish that a live kernel flow exists.
    # The rule additionally requires the kernel's exact ESTABLISHED reply and
    # original tuple; stale metadata grants no new outbound flow exemption.
    ssh_reply_args=()
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        [[ "${SSH_CONNECTION}" != *$'\n'* && "${SSH_CONNECTION}" != *$'\r'* ]] || exempt_failed "SSH tuple must be single-line"
        read -r ssh_peer ssh_peer_port ssh_local ssh_local_port ssh_extra <<< "${SSH_CONNECTION}"
        [[ -z "${ssh_extra}" && -n "${ssh_local_port}" ]] || exempt_failed "SSH tuple"
        for ssh_address in "${ssh_peer}" "${ssh_local}"; do
            [[ "${ssh_address}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || exempt_failed "unsupported SSH address family"
            IFS=. read -r -a ssh_octets <<< "${ssh_address}"
            for ssh_octet in "${ssh_octets[@]}"; do
                [[ "${ssh_octet}" =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( 10#${ssh_octet} <= 255 )) || exempt_failed "SSH address"
            done
        done
        for ssh_port in "${ssh_peer_port}" "${ssh_local_port}"; do
            [[ "${ssh_port}" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#${ssh_port} <= 65535 )) || exempt_failed "SSH port"
        done
        ssh_reply_args=(-p tcp -s "${ssh_local}" --sport "${ssh_local_port}" -d "${ssh_peer}" --dport "${ssh_peer_port}"
            -m conntrack --ctstate ESTABLISHED --ctdir REPLY
            --ctorigsrc "${ssh_peer}" --ctorigsrcport "${ssh_peer_port}"
            --ctorigdst "${ssh_local}" --ctorigdstport "${ssh_local_port}")
    fi
    # Validate continuity metadata before any config commit. Probe the current
    # service without capture, then restart preview and discard the old binding.
    AEGIS_WIDE_EXEMPT_CGROUP="$("${underlying}" cgroup-path)" || exempt_failed "service identity"
    export AEGIS_WIDE_EXEMPT_CGROUP
    "${underlying}" preflight || exempt_failed "service cgroup preflight"
    aegis_wide_redirect_preview_activate
    if [[ "${dns_choice}" == preview ]]; then
        # One builtin publishes the pair; signal recovery cannot inherit a
        # between-command half-pair. Teardown ignores generation admission.
        export AEGIS_WIDE_EXPECTED_SERVICE_PID="${aegis_wide_ready_pid}" AEGIS_WIDE_EXPECTED_CGROUP_INODE="${aegis_wide_ready_inode}"
        unset AEGIS_WIDE_EXEMPT_CGROUP
        AEGIS_WIDE_EXEMPT_CGROUP="$("${underlying}" cgroup-path)" || exempt_failed "final service identity"
        export AEGIS_WIDE_EXEMPT_CGROUP
        "${underlying}" preflight || exempt_failed "final service cgroup preflight"
    fi
    iptables -t nat -N "${SSH_EXEMPT_CHAIN}" 2>/dev/null || \
        iptables -t nat -F "${SSH_EXEMPT_CHAIN}" || exempt_failed "chain creation/flush"
    if (( ${#ssh_reply_args[@]} )); then
        iptables -t nat -A "${SSH_EXEMPT_CHAIN}" "${ssh_reply_args[@]}" -j ACCEPT || exempt_failed "existing SSH reply"
    fi
    iptables -t nat -C OUTPUT -j "${SSH_EXEMPT_CHAIN}" 2>/dev/null || \
        iptables -t nat -I OUTPUT 1 -j "${SSH_EXEMPT_CHAIN}" || exempt_failed "OUTPUT hook"
else
    SSH_EXEMPT_CHAIN="AEGIS_WIDE_SSH_EXEMPT"
    exempt_failed() {
        echo "FATAL: failed to install SSH/relay exemption ($1); refusing capture apply" >&2
        exit 4
    }
    iptables -t nat -N "${SSH_EXEMPT_CHAIN}" 2>/dev/null || \
        iptables -t nat -F "${SSH_EXEMPT_CHAIN}" || exempt_failed "chain creation/flush"
    IFS=',' read -r -a safe_ports_arr <<< "${ssh_safe_ports}"
    for port in "${safe_ports_arr[@]}"; do
        port="${port//[!0-9]/}"
        [[ -z "${port}" ]] && continue
        iptables -t nat -A "${SSH_EXEMPT_CHAIN}" -p tcp --dport "${port}" -j ACCEPT || exempt_failed "SSH port"
    done
    if [[ -n "${SSH_SRC_IP}" ]]; then
        iptables -t nat -A "${SSH_EXEMPT_CHAIN}" -d "${SSH_SRC_IP}" -j ACCEPT || exempt_failed "SSH peer"
    fi
    # Relay-endpoint exempts: prevent aegis-client → relay traffic from looping
    # back through the wide REDIRECT. Critical when aegis-client runs as root
    # and UID-based exempt would defeat wide mode.
    if [[ -n "${RELAY_ENDPOINTS_RAW}" ]]; then
        while IFS= read -r endpoint; do
            [[ -z "${endpoint}" ]] && continue
            host="${endpoint%:*}"
            rport="${endpoint##*:}"
            # exempt by destination IP+port pair so wide mode still captures other
            # outbound to the same port (or same IP on other ports)
            iptables -t nat -A "${SSH_EXEMPT_CHAIN}" -p tcp -d "${host}" --dport "${rport}" -j ACCEPT || exempt_failed "relay TCP"
            iptables -t nat -A "${SSH_EXEMPT_CHAIN}" -p udp -d "${host}" --dport "${rport}" -j ACCEPT || exempt_failed "relay UDP"
        done <<< "${RELAY_ENDPOINTS_RAW}"
    fi
    iptables -t nat -C OUTPUT -j "${SSH_EXEMPT_CHAIN}" 2>/dev/null || \
        iptables -t nat -I OUTPUT 1 -j "${SSH_EXEMPT_CHAIN}" || exempt_failed "OUTPUT hook"

fi

# 2. Call underlying helper
underlying="${SCRIPT_DIR}/setup-wide-linux-redirect.sh"
if [[ "${mode}" == "tproxy" ]]; then
    underlying="${SCRIPT_DIR}/setup-wide-linux-tproxy.sh"
fi
if [[ ! -x "${underlying}" ]]; then
    echo "FATAL: helper not executable: ${underlying}" >&2
    exit 4
fi

export AEGIS_WIDE_PORT="${WIDE_PORT}"
export AEGIS_EXEMPT_UID="${AEGIS_UID}"
export AEGIS_WIDE_INTERFACE="${INTERFACE}"
# Generic UDP + QUIC carry: point the firewall's generic-UDP REDIRECT at the
# proxy port the client daemon binds (WIDE_PORT+1, matching the daemon's
# `udp_redirect_port` default derivation), and lift the fail-closed UDP block.
# The daemon must run with udp_capture_contract=generic_capture_unstable for the
# proxy to be listening; otherwise the datagrams hit a closed port (still no
# native leak). Only meaningful for mode=redirect.
if [[ "${udp_choice}" == "carry" && "${mode}" == "redirect" ]]; then
    export AEGIS_WIDE_UDP_REDIRECT_PORT="$((WIDE_PORT + 1))"
    export AEGIS_WIDE_BLOCK_UDP=0
fi
# CRITICAL: when mode=redirect AND dns=preview, the REDIRECT helper MUST
# NOT install UDP/53 nat REDIRECT — that rule rewrites the packet
# destination to 127.0.0.1:15080 before mangle OUTPUT's TPROXY MARK can
# loop it via policy routing, so the cmsg IP_ORIGDSTADDR delivered to
# the listener is the post-NAT bind port (15080) instead of the original
# (53). Pass DNS_PREVIEW=0 to the REDIRECT helper, then install the
# UDP/53 path via the TPROXY helper below (hybrid path).
if [[ "${mode}" == "redirect" && "${dns_choice}" == "preview" ]]; then
    export AEGIS_ENABLE_DNS_PREVIEW=0
else
    export AEGIS_ENABLE_DNS_PREVIEW="$([[ "${dns_choice}" == "preview" ]] && echo 1 || echo 0)"
fi
export AEGIS_WIDE_BLOCK_IPV6="$([[ "${ipv6_choice}" == "block" ]] && echo 1 || echo 0)"
# CRITICAL: the REDIRECT helper reads AEGIS_WIDE_BLOCK_IPV6 (binary 0/1)
# but the TPROXY helper (setup-wide-linux-tproxy.sh) reads a different
# variable: AEGIS_WIDE_IPV6_POLICY (string enum: block | out_of_scope | capture).
# Without this export, --ipv6=block silently has no effect in mode=tproxy
# because IPV6_POLICY defaults to "out_of_scope" inside the tproxy helper.
# Caught by the orchestrator on 2026-05-19: curl -6 succeeded with full
# response while wide tproxy mode was active.
export AEGIS_WIDE_IPV6_POLICY="${ipv6_choice}"
export AEGIS_WIDE_BLOCK_LEAKS=1

# IPv6 capture mode: re-target the listener to [::]:15080 and pin the
# tproxy helper's IP family to ipv6. The Rust side already supports the
# v6 listener (bind_linux_udp_dns_socket_v6 + enable_recv_original_dst_v6),
# the helper already runs ip6tables + ip -6 rule + ip -6 route on the
# policy-routing path, and the TPROXY target already understands `--on-ip ::`.
# What was missing — until this batch — was the wrapper-level wiring that
# tells the helper "operator wants v6 capture, not v6 block".
if [[ "${ipv6_choice}" == "capture" ]]; then
    export AEGIS_WIDE_LISTEN="[::]:${WIDE_PORT}"
    export AEGIS_WIDE_IP_FAMILY="ipv6"
fi

# TPROXY gateway prerequisites: forwarded packets need ip_forward=1 and,
# critically, route_localnet=1 on the ingress interface — without it the
# kernel refuses to deliver a forwarded packet (whose original dst is not
# in 127/8) to a local IP_TRANSPARENT listener via the TPROXY policy
# route. Caught in the 2026-05-19 gateway drill: TPROXY chain counter
# incremented but accept_tcp_intent never fired because route_localnet=0
# on eth0 silently dropped the forwarded SYN at the policy-route step.
#
# Persistence: we write /etc/sysctl.d/99-aegis-wide.conf so the values
# survive reboot. The original (pre-AEGIS) values are saved to
# /var/lib/aegis-install/client/wide-sysctl-original.txt so aegis-wide-disable.sh can
# restore them. Persistence is removed by disable.
AEGIS_WIDE_SYSCTL_FILE="${AEGIS_WIDE_SYSCTL_FILE:-/etc/sysctl.d/99-aegis-wide.conf}"
AEGIS_WIDE_SYSCTL_SNAPSHOT="${AEGIS_WIDE_SYSCTL_SNAPSHOT:-/var/lib/aegis-install/client/wide-sysctl-original.txt}"
if [[ "${mode}" == "tproxy" ]]; then
    aegis_root_validate "${AEGIS_WIDE_SYSCTL_SNAPSHOT}" || exit 1
    # Snapshot originals BEFORE we touch them, but only once per
    # enable-disable cycle (don't overwrite a real snapshot on
    # re-apply over an already-enabled state).
    if [[ ! -f "${AEGIS_WIDE_SYSCTL_SNAPSHOT}" ]]; then
        {
            printf 'net.ipv4.ip_forward=%s\n' \
                "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
            printf 'net.ipv4.conf.all.route_localnet=%s\n' \
                "$(sysctl -n net.ipv4.conf.all.route_localnet 2>/dev/null || echo 0)"
            printf 'net.ipv4.conf.%s.route_localnet=%s\n' \
                "${INTERFACE}" \
                "$(sysctl -n "net.ipv4.conf.${INTERFACE}.route_localnet" 2>/dev/null || echo 0)"
        } | aegis_root_write "${AEGIS_WIDE_SYSCTL_SNAPSHOT}" || exit 1
    fi
    # Write persistent config so values survive reboot.
    aegis_root_write "${AEGIS_WIDE_SYSCTL_FILE}" 0644 <<SYSCTL_EOF || exit 1
# Managed by aegis-wide-enable.sh (mode=tproxy).
# Removed by aegis-wide-disable.sh. Do not edit by hand.
# Original values saved to ${AEGIS_WIDE_SYSCTL_SNAPSHOT}.
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv4.conf.${INTERFACE}.route_localnet=1
SYSCTL_EOF
    # Apply right now (don't wait for next reboot).
    sysctl -p "${AEGIS_WIDE_SYSCTL_FILE}" >/dev/null 2>&1 || {
        # Fallback to per-key write in case the config file load failed.
        sysctl -wq net.ipv4.ip_forward=1 2>/dev/null || true
        sysctl -wq "net.ipv4.conf.${INTERFACE}.route_localnet=1" 2>/dev/null || true
        sysctl -wq net.ipv4.conf.all.route_localnet=1 2>/dev/null || true
    }
fi

if ! "${underlying}" apply; then
    echo "FATAL: underlying helper failed — initiating rollback"
    iptables -t nat -D OUTPUT -j "${SSH_EXEMPT_CHAIN}" 2>/dev/null || true
    iptables -t nat -F "${SSH_EXEMPT_CHAIN}" 2>/dev/null || true
    iptables -t nat -X "${SSH_EXEMPT_CHAIN}" 2>/dev/null || true
    "${underlying}" teardown 2>/dev/null || true
    if [[ "${mode}" == redirect && "${aegis_wide_config_applied}" == 1 ]]; then
        aegis_wide_config_failed
    fi
    exit 5
fi

# Refuse a changed generation after capture as well. This is a recheck, not a
# claim of atomic lifetime ownership; the helper enforces pins during apply.
if [[ "${mode}" == redirect && "${dns_choice}" == preview ]]; then
    [[ "$("${underlying}" cgroup-path)" == "${AEGIS_WIDE_EXEMPT_CGROUP}" ]] || exempt_failed "post-apply service generation"
fi

# 2b. DNS-preview fake-IP path. We dropped the OUTPUT-mark + loopback
# TPROXY UDP/53 pattern from earlier batches — it did not reliably fire
# mangle PREROUTING on lo across the kernels we tested (UDP nat REDIRECT
# is TCP-only for original-dst preservation; OUTPUT-mark + policy-route
# + local-type route delivers via INPUT, not PREROUTING). The replacement
# is resolver-based fake-IP:
#
#   1. aegis-client spawns a synthetic DNS listener on 127.0.0.1:53 that
#      answers A queries with fake IPs from 198.18.0.0/15 (the dns_preview
#      module). A shared FakeIpMap records hostname ↔ fake_ip.
#   2. We point /etc/resolv.conf at 127.0.0.1 (stopping systemd-resolved's
#      stub-resolver first so 127.0.0.1:53 is free), so all libc resolver
#      traffic goes to our listener.
#   3. Apps see a fake IP and open TCP to it. nat REDIRECT (TCP) catches
#      the SYN and delivers to wide listener. wide listener's
#      accept_tcp_intent sees the fake IP, looks up the hostname, and
#      passes hostname:port to the relay session — relay resolves the real
#      DNS, we never connect to the fake IP externally.
#   4. Disable restores resolv.conf and restarts systemd-resolved.
if [[ "${dns_choice}" == "preview" && "${mode}" != redirect ]]; then
    # Render and validate completed private input before capture; any later
    # commit or permission failure uses the independent disable transaction.
    aegis_wide_config_commit || aegis_wide_config_failed
    # Snapshot original resolv.conf BEFORE stopping systemd-resolved. Ubuntu's
    # file is commonly a symlink into /run whose target disappears on stop.
    aegis_root_resolver_save || exit 1
    # Stop systemd-resolved's stub-resolver so :53 is free
    systemctl stop systemd-resolved 2>/dev/null || true
    # Point resolver at our listener
    rm -f /etc/resolv.conf 2>/dev/null || true
    cat <<RESOLV > /etc/resolv.conf
# Managed by aegis-wide-enable.sh (dns=preview). Restored on disable.
nameserver 127.0.0.1
options timeout:2 attempts:1
RESOLV
    # Restart aegis-client to pick up the new dns_preview_listen config
    systemctl restart aegis-client 2>/dev/null || true
    sleep 2
fi

# 3. Post-apply doctor snapshot
iptables -t nat -L OUTPUT -n -v > "${snapshot_dir}/after-nat-output.txt" 2>&1 || true
iptables -t filter -L OUTPUT -n -v > "${snapshot_dir}/after-filter-output.txt" 2>&1 || true
ip -4 route show > "${snapshot_dir}/after-routes-v4.txt" 2>&1 || true

# 4. Auto-rollback timer
# Detach FULLY so ssh -t / scripted invocations get a fresh prompt back even
# while the timer is still ticking. Without </dev/null + setsid (or all three
# stdio fds redirected), the parent shell — and any ssh session running this
# helper — will block until the sleep returns. The orchestrator drill caught
# this: an ssh-invocation of aegis-wide-enable.sh hung for the full 900s of
# the rollback window instead of returning at apply time.
if [[ "${NO_ROLLBACK}" == "1" ]]; then
    # Persistence / scripted mode: keep wide up, no rollback timer. Mark
    # confirmed so any later `aegis-wide-confirm` check is a no-op.
    mkdir -p "$(dirname "${SENTINEL_FILE}")" 2>/dev/null || true
    touch "${SENTINEL_FILE}" 2>/dev/null || true
else
    rm -f "${SENTINEL_FILE}"
    # Fixed shell program: paths and state values must never be reparsed as code.
    setsid bash -c '
        sleep "$1"
        if [[ ! -f "$2" ]]; then
            logger -t aegis-wide-enable "auto-rollback firing — operator did not confirm within ${1}s"
            # A detached shell does not inherit the parent library/functions or
            # its default state paths. Authenticate retained DNS state before
            # any teardown, just as the explicit disable preflight does.
            . "$5" || exit 1
            export AEGIS_ROOT_STATE_CLIENT="$6"
            export AEGIS_WIDE_RESOLVER_SNAPSHOT="$7"
            aegis_root_state_init || exit 1
            aegis_root_resolver_preflight || exit 1
            iptables -t nat -D OUTPUT -j "$3" 2>/dev/null || true
            iptables -t nat -F "$3" 2>/dev/null || true
            iptables -t nat -X "$3" 2>/dev/null || true
            "$4" teardown 2>/dev/null || true
            # P0: the auto-rollback exists precisely for "operator lost access".
            # Restoring iptables/capture is NOT enough — if dns=preview repointed
            # /etc/resolv.conf at the local fake-IP listener and stopped
            # systemd-resolved, name resolution stays dead after teardown and the
            # host is unreachable-by-name. Mirror aegis-wide-disable.sh so the
            # deadman restores DNS too (symmetric with the enable dns=preview branch).
            restored_resolv=0
            if [[ -f "${AEGIS_WIDE_RESOLVER_SNAPSHOT}" ]]; then
                aegis_root_resolver_restore || exit 1
                restored_resolv=1
            fi
            if [[ "${restored_resolv}" == "1" ]]; then
                systemctl start --no-block systemd-resolved 2>/dev/null || true
            fi
            # Restart the client after restoring the host resolver.
            systemctl restart aegis-client 2>/dev/null || true
        fi
        rm -f "$2"
    ' aegis-wide-enable "${ROLLBACK_SECS}" "${SENTINEL_FILE}" "${SSH_EXEMPT_CHAIN}" \
        "${underlying}" "${SCRIPT_DIR}/lib/root-state.sh" "${AEGIS_ROOT_STATE_CLIENT}" \
        "${AEGIS_WIDE_RESOLVER_SNAPSHOT}" </dev/null >/dev/null 2>&1 &
    disown
fi

cat <<DONE
============================================================
AEGIS wide mode ACTIVE on interface ${INTERFACE}
------------------------------------------------------------
- mode:        ${mode}
- listen:      :${WIDE_PORT}
- SSH safe:    ${ssh_safe_ports}
- DNS:         ${dns_choice}
- IPv6:        ${ipv6_choice}
- rollback:    $([[ "${NO_ROLLBACK}" == "1" ]] && echo "disabled (sticky/persistent)" || echo "${ROLLBACK_SECS}s auto unless confirmed")

$(if [[ "${NO_ROLLBACK}" == "1" ]]; then
printf 'Sticky mode: wide stays until you disable it:\n\n    sudo aegis-wide-disable\n'
else
printf 'VERIFY YOUR SSH SESSION STILL WORKS, then RUN within %ss:\n\n    sudo touch %s\n\nOR DISABLE NOW:\n\n    sudo aegis-wide-disable\n' "${ROLLBACK_SECS}" "${SENTINEL_FILE}"
fi)

Doctor snapshots saved to: ${snapshot_dir}
============================================================
DONE

# Only a fully returned activation has escaped the owned abnormal-exit guard.
aegis_wide_transaction_complete=1
