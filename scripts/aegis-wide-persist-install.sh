#!/usr/bin/env bash
# aegis-wide-persist-install.sh — opt-in installer for reboot-persistent
# wide-mode activation.
#
# Generates and installs a systemd unit (default name aegis-wide.service)
# that runs aegis-wide-enable.sh with the operator-chosen flags after
# aegis-client.service has started. Auto-confirms the rollback sentinel
# so the helper does not roll back after reboot.
#
# By design wide mode is opt-in and per-session by default — this helper
# is for operators who explicitly want sticky behavior across reboots.
#
# Usage:
#   sudo bash scripts/aegis-wide-persist-install.sh \
#       --mode=redirect --dns=off --ipv6=block [--interface=eth1]
#   sudo bash scripts/aegis-wide-persist-install.sh uninstall
#
# Env overrides (for contract test):
#   AEGIS_WIDE_PERSIST_SKIP_ROOT_CHECK=1   bypass EUID gate
#   AEGIS_WIDE_PERSIST_UNIT_DIR=DIR        override /etc/systemd/system
#   AEGIS_WIDE_PERSIST_UNIT_NAME=NAME      override aegis-wide.service
#   AEGIS_WIDE_PERSIST_SCRIPT_PATH=PATH    override path to aegis-wide-enable.sh
#                                          (recorded in the unit's ExecStart)
#   AEGIS_WIDE_PERSIST_SKIP_SYSTEMCTL=1    skip daemon-reload / enable

set -uo pipefail

if [[ "${EUID}" -ne 0 && -z "${AEGIS_WIDE_PERSIST_SKIP_ROOT_CHECK:-}" ]]; then
    echo "FATAL: must run under sudo/root" >&2
    exit 2
fi

UNIT_DIR="${AEGIS_WIDE_PERSIST_UNIT_DIR:-/etc/systemd/system}"
UNIT_NAME="${AEGIS_WIDE_PERSIST_UNIT_NAME:-aegis-wide.service}"
UNIT_PATH="${UNIT_DIR}/${UNIT_NAME}"
SENTINEL_FILE="/run/aegis-wide-confirmed"

# Resolve where install.sh actually laid the wide helper scripts. Depending on
# the release, they land directly under /usr/local/lib/aegis OR in a helpers/
# (or scripts/) subdir. aegis-wide-enable.sh resolves its underlying helper
# (setup-wide-linux-redirect.sh) as its OWN SIBLING, so the generated unit MUST
# point at the REAL location — a hardcoded scripts/ path made the unit fail on
# boot with `helper not executable`, so wide silently did not come back after a
# reboot (IPv6 leaked). Probe the known dirs; env override wins for tests.
resolve_wide_script() {
    local name="$1" d
    for d in /usr/local/lib/aegis/helpers /usr/local/lib/aegis/scripts /usr/local/lib/aegis; do
        [[ -f "${d}/${name}" ]] && { printf '%s\n' "${d}/${name}"; return 0; }
    done
    return 1
}
if [[ -n "${AEGIS_WIDE_PERSIST_SCRIPT_PATH:-}" ]]; then
    SCRIPT_PATH="${AEGIS_WIDE_PERSIST_SCRIPT_PATH}"
else
    SCRIPT_PATH="$(resolve_wide_script aegis-wide-enable.sh)" || {
        echo "FATAL: aegis-wide-enable.sh not found under /usr/local/lib/aegis[/helpers|/scripts]. Install the wide client first (install.sh --profile wide-redirect-safe)." >&2
        exit 3
    }
fi
SCRIPT_LIB_DIR="$(dirname "${SCRIPT_PATH}")"
DISABLE_PATH="$(resolve_wide_script aegis-wide-disable.sh || echo "${SCRIPT_LIB_DIR}/aegis-wide-disable.sh")"

run_systemctl() {
    if [[ -n "${AEGIS_WIDE_PERSIST_SKIP_SYSTEMCTL:-}" ]]; then
        echo "systemctl-skip: $*"
        return 0
    fi
    systemctl "$@"
}

action="install"
mode="redirect"
dns="off"
ipv6="block"
udp="block"
ssh_safe_ports="22"
interface=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        install|uninstall|verify) action="$1"; shift ;;
        --mode=*)            mode="${1#*=}"; shift ;;
        --dns=*)             dns="${1#*=}"; shift ;;
        --ipv6=*)            ipv6="${1#*=}"; shift ;;
        --udp=*)             udp="${1#*=}"; shift ;;
        --ssh-safe-ports=*)  ssh_safe_ports="${1#*=}"; shift ;;
        --interface=*)       interface="${1#*=}"; shift ;;
        --help|-h)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "FATAL: unknown argument $1" >&2; exit 2 ;;
    esac
done

case "${mode}" in redirect|tproxy) ;; *) echo "FATAL: invalid --mode=${mode}" >&2; exit 2 ;; esac
case "${dns}"  in preview|off) ;;     *) echo "FATAL: invalid --dns=${dns}"  >&2; exit 2 ;; esac
case "${ipv6}" in block|out_of_scope) ;; *) echo "FATAL: invalid --ipv6=${ipv6}" >&2; exit 2 ;; esac
case "${udp}"  in carry|block) ;;     *) echo "FATAL: invalid --udp=${udp}"  >&2; exit 2 ;; esac

# These values are inserted into a systemd ExecStart line. Admit only literal
# Linux interface names and decimal port lists before creating the unit.
if [[ ! "${ssh_safe_ports}" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
    echo "FATAL: invalid --ssh-safe-ports" >&2
    exit 2
fi
IFS=',' read -r -a safe_port_list <<< "${ssh_safe_ports}"
for safe_port in "${safe_port_list[@]}"; do
    significant="${safe_port#"${safe_port%%[!0]*}"}"
    if [[ -z "${significant}" || ${#significant} -gt 5 ]] ||
       (( 10#${significant} > 65535 )); then
        echo "FATAL: invalid --ssh-safe-ports" >&2
        exit 2
    fi
done
if [[ -n "${interface}" ]] &&
   { [[ ${#interface} -gt 15 ]] || [[ ! "${interface}" =~ ^[a-zA-Z0-9_.:-]+$ ]]; }; then
    echo "FATAL: invalid --interface" >&2
    exit 2
fi

# shellcheck source=scripts/lib/root-state.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/root-state.sh"
aegis_root_state_init || exit 1
aegis_root_validate "${UNIT_PATH}" || exit 1

case "${action}" in
    uninstall)
        if [[ -f "${UNIT_PATH}" ]]; then
            run_systemctl disable --now "${UNIT_NAME}" 2>/dev/null || true
            aegis_root_remove "${UNIT_PATH}" || exit 1
            run_systemctl daemon-reload 2>/dev/null || true
            echo "action=uninstall unit=${UNIT_NAME} status=removed"
        else
            echo "action=uninstall unit=${UNIT_NAME} status=already_absent"
        fi
        exit 0
        ;;
    verify)
        if [[ ! -f "${UNIT_PATH}" ]]; then
            echo "verify=absent unit=${UNIT_NAME}"
            exit 1
        fi
        echo "verify=present unit=${UNIT_NAME} path=${UNIT_PATH}"
        exit 0
        ;;
    install) ;;
esac

mkdir -p "${UNIT_DIR}"

# Fail loudly NOW (not silently at boot) if the underlying helper the enable
# script will call is not a sibling of aegis-wide-enable.sh.
sibling_helper="setup-wide-linux-redirect.sh"
[[ "${mode}" == "tproxy" ]] && sibling_helper="setup-wide-linux-tproxy.sh"
if [[ ! -f "${SCRIPT_LIB_DIR}/${sibling_helper}" ]]; then
    echo "FATAL: ${sibling_helper} not found next to ${SCRIPT_PATH} (${SCRIPT_LIB_DIR}). The wide client install is incomplete." >&2
    exit 3
fi

# Build the wide-enable invocation string for ExecStart. --no-rollback keeps
# wide up on boot: the operator committed to sticky mode by installing this
# unit, so a ticking auto-rollback (and its blocking timer) has no place here.
exec_args=(
    "${SCRIPT_PATH}"
    "-y"
    "--no-rollback"
    "--mode=${mode}"
    "--ssh-safe-ports=${ssh_safe_ports}"
    "--dns=${dns}"
    "--ipv6=${ipv6}"
    "--udp=${udp}"
)
if [[ -n "${interface}" ]]; then
    exec_args+=("--interface=${interface}")
fi

# Generate the unit. ExecStartPre creates the rollback sentinel so the
# helper does NOT roll back on the post-boot apply — operator already
# committed to sticky mode by installing this unit.
aegis_root_write "${UNIT_PATH}" 0644 <<UNIT_EOF || exit 1
[Unit]
Description=AEGIS wide-mode reapply on boot (opt-in operator persistence)
Documentation=file://${SCRIPT_PATH}
# Wide-enable rewrites resolv.conf when dns=preview, so we wait for
# systemd-resolved to be in its normal state before we modify it.
After=network-online.target aegis-client.service systemd-resolved.service
# aegis-wide-enable deliberately restarts aegis-client after writing the DNS
# preview listener config. `Requires=` would make systemd stop this oneshot in
# the middle of that controlled restart, then retry both units until the client
# hits StartLimitBurst. Ordering + a soft want keeps boot deterministic without
# coupling the lifetimes during the restart.
Wants=network-online.target aegis-client.service

[Service]
Type=oneshot
RemainAfterExit=yes
# Prevent ExecStop from recursively asking systemd to stop this same unit. A
# manual aegis-wide-disable invocation has no such marker and removes the unit
# so a later reboot cannot silently re-enable capture.
Environment=AEGIS_WIDE_DISABLE_FROM_UNIT=1
# Pre-create the rollback sentinel: by installing this unit the operator
# has already committed to sticky wide mode and should not be auto-rolled
# back ${ROLLBACK_SECS:-60}s after each boot.
ExecStartPre=/bin/sh -c 'mkdir -p /run && touch ${SENTINEL_FILE}'
ExecStart=${exec_args[*]}
# Symmetric teardown on stop / disable.
ExecStop=${DISABLE_PATH}
TimeoutStartSec=120
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
UNIT_EOF

if ! run_systemctl daemon-reload; then
    echo "FATAL: systemd daemon-reload failed; wide persistence is not ready" >&2
    exit 1
fi
if ! run_systemctl enable "${UNIT_NAME}"; then
    echo "FATAL: systemd enable failed; wide persistence is not ready" >&2
    exit 1
fi

# Print the result block. Contract test greps for these tokens.
echo "action=install unit=${UNIT_NAME} mode=${mode} dns=${dns} ipv6=${ipv6}"
echo "path=${UNIT_PATH}"
echo "exec=${exec_args[*]}"
echo "status=ready"
