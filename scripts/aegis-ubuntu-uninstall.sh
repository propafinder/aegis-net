#!/usr/bin/env bash
# aegis-ubuntu-uninstall.sh — destructive Ubuntu/Debian aegis-client purge.
#
# Detects how aegis-client was installed (apt repo vs bootstrap-install.sh
# vs source build) and runs the matching purge. Then verifies the listed
# client installation paths, units and networking checks. Device identity and
# release-floor state are intentionally retained; success is not full erasure.
# Emits structured `verify=...` lines
# that callers (and the contract test) can grep.
#
# The scope is strictly the client role. A co-located aegis-server install is
# preserved. Designed to be copied to a remote host and run by
# scripts/aegis-full-ubuntu-live-drill.sh with RUN_UNINSTALL=1.
#
# Usage:
#   sudo bash aegis-ubuntu-uninstall.sh purge
#   sudo bash aegis-ubuntu-uninstall.sh verify     # non-destructive scoped check
# Without inspection privileges, verify fails as unmeasured rather than PASS.
#
# Exit codes:
#   0  purge + verify PASS
#   1  verify found leftover state
#   2  argument error
#   3  no install detected (verify also clean — vacuously PASS)
#
# Env overrides (for contract test):
#   AEGIS_UNINSTALL_SKIP_ROOT_CHECK=1   bypass EUID gate
#   AEGIS_UNINSTALL_PURGE_HELPER=...    override path to purge-installed-aegis.sh
#   AEGIS_UNINSTALL_FAKE_ROOT=DIR       prefix all paths with DIR (for sandboxed test)

set -uo pipefail

ACTION="${1:-purge}"

if [[ $# -eq 1 && ( "$1" == "--help" || "$1" == "-h" ) ]]; then
    echo "Usage: aegis-ubuntu-uninstall.sh [purge|verify]"
    echo "purge removes the client installation only; verify makes no changes."
    echo "Device identity and release-floor state are retained; success is not full erasure."
    exit 0
fi
if [[ $# -gt 1 ]]; then
    echo "FATAL: expected at most one action; see --help" >&2
    exit 2
fi
if [[ "${ACTION}" != "purge" && "${ACTION}" != "verify" ]]; then
    echo "FATAL: action must be 'purge' or 'verify' (got: ${ACTION})" >&2
    exit 2
fi

if [[ "${ACTION}" == "purge" ]]; then
    if [[ "${EUID}" -ne 0 && -z "${AEGIS_UNINSTALL_SKIP_ROOT_CHECK:-}" ]]; then
        echo "FATAL: purge action must run under sudo/root" >&2
        exit 2
    fi
fi

ROOT_PREFIX="${AEGIS_UNINSTALL_FAKE_ROOT:-}"
PURGE_HELPER="${AEGIS_UNINSTALL_PURGE_HELPER:-}"
if [[ -n "${ROOT_PREFIX}" ]]; then
    if [[ "${ROOT_PREFIX}" != /* || ! -d "${ROOT_PREFIX}" ]]; then
        echo "FATAL: fake root must be an existing absolute directory" >&2
        exit 2
    fi
    ROOT_PREFIX="$(cd "${ROOT_PREFIX}" && pwd -P)"
    if [[ "${ROOT_PREFIX}" == "/" ]]; then
        echo "FATAL: / is not a fake root" >&2
        exit 2
    fi
fi

# Keep this custody routine byte-identical to purge-installed-aegis.sh except
# for the wrapper root and dry-run handling. Both paths preflight the fixed tree.
cleanup_auto_runtime_logs() {
  local action="$1"
  [[ "$action" == check || "$action" == delete ]] || return 2
  python3 - "${ROOT_PREFIX:-/}" "$action" <<'PY_AUTO_LOG_CUSTODY'
import grp
import os
import pwd
import stat
import sys

base, action = sys.argv[1:]
if not os.path.isabs(base) or (base != '/' and not os.path.isdir(base)):
    raise SystemExit('AUTO log cleanup: invalid root')
fake = base != '/'
root_uid, root_gid = (os.geteuid(), os.getegid()) if fake else (0, 0)
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

def fail(message):
    raise SystemExit('AUTO log cleanup refused: ' + message)

def checked_dir(fd, name, uid, gid, exact_mode=None):
    try:
        item = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(item.st_mode) or item.st_uid != uid or item.st_gid != gid:
        fail('untrusted directory ' + name)
    mode = stat.S_IMODE(item.st_mode)
    if (exact_mode is not None and mode != exact_mode) or mode & 0o022:
        fail('unsafe directory mode ' + name)
    child = os.open(name, flags, dir_fd=fd)
    opened = os.fstat(child)
    if (opened.st_dev, opened.st_ino) != (item.st_dev, item.st_ino):
        os.close(child)
        fail('directory changed ' + name)
    return child

def checked_file(fd, uid, gid):
    name = 'runtime-events.jsonl'
    try:
        item = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(item.st_mode) or item.st_nlink != 1
            or item.st_uid != uid or item.st_gid != gid
            or stat.S_IMODE(item.st_mode) & 0o022):
        fail('untrusted log file')
    return (item.st_dev, item.st_ino)

# In a fake root, all operations remain beneath its already resolved prefix.
# Its fixture owner stands in for both root and the service account.
fd = os.open('/', flags)
try:
    parts = [p for p in os.path.normpath(base).split('/') if p] if fake else []
    for part in parts:
        next_fd = os.open(part, flags, dir_fd=fd)
        os.close(fd)
        fd = next_fd
    if fake:
        fixture = os.fstat(fd)
        if fixture.st_uid != root_uid or fixture.st_gid != root_gid or stat.S_IMODE(fixture.st_mode) & 0o022:
            fail('unsafe fake root')
    var_fd = checked_dir(fd, 'var', root_uid, root_gid)
    if var_fd is None:
        raise SystemExit(0)
    lib_fd = checked_dir(var_fd, 'lib', root_uid, root_gid)
    if lib_fd is None:
        raise SystemExit(0)
    logs_fd = checked_dir(lib_fd, 'aegis-client-logs', root_uid, root_gid, 0o755)
    if logs_fd is None:
        raise SystemExit(0)
    if set(os.listdir(logs_fd)) - {'root', 'service'}:
        fail('foreign entry in log root')
    service_uid, service_gid = root_uid, root_gid
    if fake and os.geteuid() == 0:
        # Root-run filesystem controls can model a distinct service identity.
        service_uid = int(os.environ.get('AEGIS_AUTO_LOG_FIXTURE_SVC_UID', root_uid))
        service_gid = int(os.environ.get('AEGIS_AUTO_LOG_FIXTURE_SVC_GID', root_gid))
        if service_uid < 0 or service_gid < 0:
            fail('invalid fixture service identity')
    if not fake and 'service' in os.listdir(logs_fd):
        try:
            account = pwd.getpwnam('aegis-svc')
            group = grp.getgrnam('aegis-svc')
        except KeyError:
            fail('service account or group missing')
        service_uid, service_gid = account.pw_uid, account.pw_gid
        if (account.pw_name != 'aegis-svc' or not 0 < service_uid < 1000
                or service_gid == 0 or service_gid != group.gr_gid
                or group.gr_name != 'aegis-svc' or group.gr_mem != []
                or account.pw_dir != '/var/lib/aegis-client'
                or account.pw_shell != '/usr/sbin/nologin'
                or os.getgrouplist('aegis-svc', service_gid) != [service_gid]):
            fail('untrusted service account')
    children = []
    for name, uid, gid in (('root', root_uid, root_gid),
                           ('service', service_uid, service_gid)):
        child = checked_dir(logs_fd, name, uid, gid, 0o700)
        if child is None:
            continue
        if set(os.listdir(child)) - {'runtime-events.jsonl'}:
            fail('foreign entry in ' + name)
        present = checked_file(child, uid, gid)
        children.append((name, child, uid, gid, present))
    if action == 'delete':
        # Complete a second all-children identity check before the first unlink.
        parent_now = os.stat('aegis-client-logs', dir_fd=lib_fd,
                             follow_symlinks=False)
        if (not stat.S_ISDIR(parent_now.st_mode)
                or parent_now.st_uid != root_uid or parent_now.st_gid != root_gid
                or stat.S_IMODE(parent_now.st_mode) != 0o755
                or (parent_now.st_dev, parent_now.st_ino) !=
                   (os.fstat(logs_fd).st_dev, os.fstat(logs_fd).st_ino)):
            fail('log root changed')
        if set(os.listdir(logs_fd)) != {item[0] for item in children}:
            fail('log root changed')
        for name, child, uid, gid, present in children:
            current_dir = os.stat(name, dir_fd=logs_fd, follow_symlinks=False)
            if (not stat.S_ISDIR(current_dir.st_mode)
                    or current_dir.st_uid != uid or current_dir.st_gid != gid
                    or stat.S_IMODE(current_dir.st_mode) != 0o700
                    or (current_dir.st_dev, current_dir.st_ino) !=
                       (os.fstat(child).st_dev, os.fstat(child).st_ino)):
                fail('log directory changed ' + name)
            expected = {'runtime-events.jsonl'} if present is not None else set()
            if set(os.listdir(child)) != expected:
                fail('log directory changed ' + name)
            if checked_file(child, uid, gid) != present:
                fail('log file changed ' + name)
        for name, child, uid, gid, present in children:
            if present is not None:
                os.unlink('runtime-events.jsonl', dir_fd=child)
            os.rmdir(name, dir_fd=logs_fd)
        os.rmdir('aegis-client-logs', dir_fd=lib_fd)
finally:
    os.close(fd)
PY_AUTO_LOG_CUSTODY
}

stop_client_before_log_cleanup() {
    [[ -n "${ROOT_PREFIX}" ]] && return 0
    command -v systemctl >/dev/null 2>&1 || {
        echo 'ERROR: cannot inspect client unit before AUTO log cleanup' >&2
        return 1
    }
    # A failed stop is tolerable only if the fresh manager readback proves the
    # unit absent or fully inactive. A nonzero is-active alone is ambiguous.
    systemctl stop aegis-client.service 2>/dev/null || true
    local status load='' active='' sub='' main='' control=''
    status="$(systemctl show aegis-client.service --no-pager \
        -p LoadState -p ActiveState -p SubState -p MainPID -p ControlPID)" || return 1
    local key value
    while IFS='=' read -r key value; do
        case "$key" in
            LoadState) [[ -z "$load" ]] || return 1; load="$value" ;;
            ActiveState) [[ -z "$active" ]] || return 1; active="$value" ;;
            SubState) [[ -z "$sub" ]] || return 1; sub="$value" ;;
            MainPID) [[ -z "$main" ]] || return 1; main="$value" ;;
            ControlPID) [[ -z "$control" ]] || return 1; control="$value" ;;
            '') ;;
            *) return 1 ;;
        esac
    done <<< "$status"
    if [[ ( "$load" == loaded || "$load" == not-found ) &&
          "$active" == inactive && "$sub" == dead &&
          "$main" == 0 && "$control" == 0 ]]; then
        return 0
    fi
    echo 'ERROR: client unit state is indeterminate or active; AUTO logs retained' >&2
    return 1
}

# During dpkg purge the packaged coordinator may disappear after prerm while
# the terminal journal and its private recovery sources remain. Authenticate
# the retained source before executing it; the coordinator then replays the
# exact terminal chain and partial dpkg state. Parameters 2/3 are fixed root
# uid/gid in production and permit an unprivileged fixture in contract tests.
verified_v2_recovery_source() {
    /usr/bin/python3 -I -B - "$1" "${2:-0}" "${3:-0}" <<'PY_V2_RECOVERY'
import hashlib
import json
import os
import stat
import sys

path, uid, gid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
names = ("aegis_installer_auto_v2.py", "aegis_auto_uninstall_journal.py",
         "resume-command.txt")
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
def need(condition):
    if not condition:
        raise ValueError("AUTO V2 retained source refused")
def file_bytes(parent, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                 os.O_CLOEXEC, dir_fd=parent)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == uid and
             info.st_gid == gid and stat.S_IMODE(info.st_mode) == 0o600 and
             info.st_nlink == 1 and 0 < info.st_size <= maximum)
        raw = os.read(fd, maximum + 1)
        need(len(raw) == info.st_size)
        return raw
    finally:
        os.close(fd)
need(path.startswith("/") and "/../" not in path and not path.endswith("/.."))
parts = [part for part in path.split("/") if part]
need(len(parts) >= 2 and parts[-2:] == ["aegis-auto-uninstall", "recovery"])
fd = os.open("/", flags)
try:
    for index, part in enumerate(parts):
        need(part not in (".", ".."))
        child = os.open(part, flags, dir_fd=fd)
        info = os.fstat(child)
        ancestors = index < len(parts) - 2
        owner_ok = (info.st_uid == uid and info.st_gid == gid) or \
            (ancestors and uid != 0 and info.st_uid == info.st_gid == 0)
        mode = stat.S_IMODE(info.st_mode)
        mode_ok = not mode & 0o022 or \
            (ancestors and uid != 0 and info.st_uid == 0 and mode & stat.S_ISVTX)
        need(stat.S_ISDIR(info.st_mode) and owner_ok and mode_ok)
        if index >= len(parts) - 2:
            need(stat.S_IMODE(info.st_mode) == 0o700)
        os.close(fd)
        fd = child
    raw = file_bytes(fd, "recovery-manifest.json", 8192)
    def pairs(items):
        result = dict(items)
        need(len(result) == len(items))
        return result
    manifest = json.loads(raw, object_pairs_hook=pairs)
    passive = isinstance(manifest, dict) and set(manifest) == {*names, "purge-installed-aegis.sh"}
    if passive:
        names = (*names, "purge-installed-aegis.sh")
    allowed = {*names, "recovery-manifest.json"}
    if passive:
        allowed.add("helpers")
        # An interrupted pre-deletion copy can retain failed siblings. They
        # are never execution sources; the coordinator verifies helpers/.
        allowed.update(name for name in os.listdir(fd) if
                       name.startswith("failed-helpers-") and len(name) == 47)
    need(set(os.listdir(fd)) == allowed)
    need(isinstance(manifest, dict) and set(manifest) == set(names) and
         json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True).encode() == raw)
    for name in names:
        digest = manifest[name]
        need(isinstance(digest, str) and len(digest) == 64 and
             all(ch in "0123456789abcdef" for ch in digest) and
             hashlib.sha256(file_bytes(fd, name, 4 << 20)).hexdigest() == digest)
    need(b"ssh HOST 'sudo bash -s -- purge' < "
         b"scripts/aegis-ubuntu-uninstall.sh\n" in
         file_bytes(fd, "resume-command.txt", 8192))
    # Read the terminal receipts from the journal's parent before executing
    # source. Their semantic chain is rechecked by the coordinator itself.
    parent = os.open("..", flags, dir_fd=fd)
    try:
        if passive:
            intent = json.loads(file_bytes(parent, "intent.json", 8192), object_pairs_hook=pairs)
            need(isinstance(intent, dict) and intent.get("schema") ==
                 "aegis_auto_v2_passive_package_removal_v1")
            payload = file_bytes(parent, "passive-payload.json", 128 << 10)
            need(hashlib.sha256(payload).hexdigest() == intent.get("payload_sha256"))
        else:
            file_bytes(parent, "package-handoff.json", 8192)
            file_bytes(parent, "generic-purged.json", 8192)
    finally:
        os.close(parent)
    print(path + "/aegis_installer_auto_v2.py")
finally:
    os.close(fd)
PY_V2_RECOVERY
}

# An installed V2 generation uses its typed journal coordinator before any
# legacy stop, log cleanup, apt or manual sweep. Fake-root fixtures retain the
# historical pre-effect refusal; they cannot model PID1 or the native guard.
if [[ "${ACTION}" == purge ]]; then
    v2_owned=0
    # A damaged DEB may have lost every unit while dpkg still owns its helper
    # sources. It must reach typed admission before any legacy sweep.
    if [[ -z "${ROOT_PREFIX}" && -x /usr/bin/dpkg-query ]]; then
        if package_state="$(/usr/bin/dpkg-query --show --showformat='${db:Status-Status}' aegis-client 2>/dev/null)"; then
            [[ "$package_state" == not-installed ]] || v2_owned=1
        fi
    fi
    for selected in \
        /var/lib/aegis-auto/control \
        /var/lib/aegis-install/client/auto-guardian-install.json \
        /var/lib/aegis-install/client/auto-guard-first-arm.json \
        /var/lib/aegis-install/client/device-guard.conf \
        /var/lib/aegis-auto/fresh-passive-abort-current.json \
        /etc/systemd/system/aegis-auto-guardian.service \
        /etc/systemd/system/aegis-auto-guardian-watchdog.service \
        /etc/systemd/system/aegis-auto-terminal-transition.service \
        /etc/systemd/system/aegis-auto-terminal-observer.service \
        /etc/systemd/system/aegis-auto-terminal-a@.service \
        /etc/systemd/system/aegis-auto-terminal-b@.service \
        /etc/aegis-auto-terminal-source.json \
        /etc/aegis-auto-terminal-store.json \
        /usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook \
        /etc/systemd/system/aegis-auto-capture-topology.service \
        /etc/systemd/system/aegis-auto-trace-rollback-actor.service \
        /etc/systemd/system/aegis-device-egress-guard.service \
        /etc/systemd/system/aegis-foreign-policy-monitor.service \
    /etc/systemd/system/aegis-auto-clean-shutdown.service \
        /etc/systemd/system/aegis-device-dhcp-refresh.service \
        /etc/systemd/system/aegis-device-dhcp-refresh.timer \
        /var/lib/aegis-auto-uninstall; do
        if [[ -e "${ROOT_PREFIX}${selected}" || -L "${ROOT_PREFIX}${selected}" ]]; then
            v2_owned=1
            break
        fi
    done
    if [[ "${v2_owned}" == 1 ]]; then
        if [[ -n "${ROOT_PREFIX}" ]]; then
            echo 'FATAL: AUTO V2 ownership requires its typed serial stop and guard teardown; generic uninstall refused before mutation.' >&2
            exit 1
        fi
        v2_coordinator=/usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py
        if [[ ! -f "${v2_coordinator}" || -L "${v2_coordinator}" ]]; then
            v2_coordinator="$(verified_v2_recovery_source \
                /var/lib/aegis-auto-uninstall/recovery 0 0)" || {
                echo 'FATAL: installed AUTO V2 coordinator unavailable and retained source refused.' >&2
                exit 1
            }
        fi
        echo 'method=auto-v2 action=purge'
        if /usr/bin/python3 -I -B "${v2_coordinator}" uninstall; then
            echo 'result=PASS method=auto-v2'
            exit 0
        fi
        echo 'result=FAIL method=auto-v2' >&2
        exit 1
    fi
fi

# Refuse before install-method detection, package-manager calls or manual sweeps.
# The selected role retains its ownership until a separate checked teardown.
if [[ "${ACTION}" == purge ]]; then
    for selected in \
        /var/lib/aegis-install/client/relay-geneva-profile.json \
        /var/lib/aegis-install/client/relay-geneva-install-intent.json \
        /var/lib/aegis-install/client/relay-geneva-teardown.json \
        /var/lib/aegis-install/client/relay-geneva-guard-state.json \
        /var/lib/aegis-install/client/relay-geneva-guard-intent.json \
        /usr/local/lib/aegis/aegis-relay-geneva-profile.sh \
        /etc/systemd/system/aegis-client.service.d/25-relay-geneva-profile.conf \
        /run/aegis-relay-geneva; do
        if [[ -e "${ROOT_PREFIX}${selected}" || -L "${ROOT_PREFIX}${selected}" ]]; then
            echo 'FATAL: selected relay ownership requires its separately reviewed teardown; generic uninstall refused before mutation.' >&2
            exit 1
        fi
    done
fi

# Paths that should NOT exist after a clean purge. The verify step walks
# this list and reports each as `verify=clean path=<p>` or
# `verify=leftover path=<p>`.
LEFTOVER_PATHS=(
    "/usr/local/bin/aegis-client"
    "/usr/bin/aegis-client"
    "/etc/aegis/client"
    "/var/lib/aegis-client"
    "/var/lib/aegis-client-logs"
    "/var/lib/aegis-install/client"
    "/var/log/aegis-client"
    "/var/lib/aegis/wide-sysctl-original.txt"
    "/usr/local/lib/aegis"
    "/usr/lib/aegis"
    "/etc/systemd/system/aegis-client.service"
    "/etc/systemd/system/aegis-client.service.d"
    "/usr/lib/systemd/system/aegis-client.service"
    "/usr/lib/systemd/system/aegis-client.service.d"
    "/etc/systemd/system/aegis-wide.service"
    "/usr/lib/systemd/system/aegis-wide.service"
    "/etc/systemd/system/aegis-wide-tun-firewall.service"
    "/usr/lib/systemd/system/aegis-wide-tun-firewall.service"
    "/etc/systemd/system/aegis-device-egress-guard.service"
    "/etc/systemd/system/aegis-auto-terminal-transition.service"
    "/etc/systemd/system/aegis-auto-terminal-observer.service"
    "/etc/systemd/system/aegis-auto-terminal-a@.service"
    "/etc/systemd/system/aegis-auto-terminal-b@.service"
    "/etc/aegis-auto-terminal-source.json"
    "/etc/aegis-auto-terminal-store.json"
    "/usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook"
    "/etc/systemd/system/aegis-legacy-tun-guard.service"
    "/etc/systemd/system/NetworkManager.service.d/29-aegis-legacy-tun-guard.conf"
    "/etc/systemd/system/systemd-networkd.service.d/29-aegis-legacy-tun-guard.conf"
    "/etc/systemd/system/networking.service.d/29-aegis-legacy-tun-guard.conf"
    "/etc/systemd/system/NetworkManager.service.d/30-aegis-device-guard.conf"
    "/etc/systemd/system/systemd-networkd.service.d/30-aegis-device-guard.conf"
    "/etc/systemd/system/networking.service.d/30-aegis-device-guard.conf"
    "/etc/default/aegis-client"
    "/etc/sysctl.d/99-aegis-wide.conf"
    "/usr/lib/systemd/system-preset/90-aegis-client.preset"
    "/usr/lib/tmpfiles.d/aegis-client.conf"
    "/run/NetworkManager/conf.d/90-aegis-wide-dns.conf"
)

# Systemd units that should NOT be active or enabled after purge.
LEFTOVER_UNITS=(
    "aegis-client"
    "aegis-wide"
    "aegis-wide-tun-firewall"
    "aegis-device-egress-guard"
    "aegis-auto-terminal-transition"
    "aegis-auto-terminal-observer"
    "aegis-legacy-tun-guard"
)

# Recovery files are evidence to restore, never paths for a blind rm sweep.
RECOVERY_PATHS=("/etc/resolv.conf.aegis-wide-bak" "/var/lib/aegis-install/client/resolver-original.json" "/var/lib/aegis-install/client/wide-sysctl-original.txt")

# --- detection -------------------------------------------------------------

detect_install_method() {
    # apt-managed if dpkg knows about aegis-client. A co-located server is not
    # evidence of a client install and must never expand this script's scope.
    if [[ -z "${ROOT_PREFIX}" ]] && command -v dpkg >/dev/null 2>&1; then
        if dpkg -s aegis-client >/dev/null 2>&1; then
            echo "apt"
            return 0
        fi
    fi
    # bootstrap-install.sh leaves an install-manifest.json.
    # /var/lib/aegis/install-manifest.json belongs to the SERVER role.
    if [[ -f "${ROOT_PREFIX}/var/lib/aegis-install/client/install-manifest.json" ||
          -f "${ROOT_PREFIX}/var/lib/aegis-client/install-manifest.json" ]]; then
        echo "bootstrap"
        return 0
    fi
    # Bare binary in /usr/local/bin/ with no manifest is treated as
    # source-build install. Still purgeable via the manual path.
    local path
    for path in "${LEFTOVER_PATHS[@]}" "${RECOVERY_PATHS[@]}"; do
        if [[ -e "${ROOT_PREFIX}${path}" || -L "${ROOT_PREFIX}${path}" ]]; then
            echo "source"
            return 0
        fi
    done
    echo "none"
}

# --- purge actions ---------------------------------------------------------

purge_via_apt() {
    echo "method=apt action=purge"
    # Package maintainer scripts may remove the recovery helpers themselves.
    # Restore networking while those helpers and the client config still exist.
    teardown_wide_before_purge || return 1
    stop_client_before_log_cleanup || return 1
    cleanup_auto_runtime_logs delete || return 1
    DEBIAN_FRONTEND=noninteractive apt-get purge -y aegis-client 2>&1 \
        | sed 's/^/  apt: /' || return 1
    # Never autoremove unrelated packages on a co-located host. Sweep only
    # client-owned residue after the package manager has succeeded.
    purge_manual
}

purge_via_bootstrap() {
    echo "method=bootstrap action=purge"
    local helper="${PURGE_HELPER}"
    if [[ -z "${helper}" ]]; then
        # Try the standard location first, then fall back to the script-dir.
        if [[ -x "${ROOT_PREFIX}/usr/local/lib/aegis/helpers/purge-installed-aegis.sh" ]]; then
            helper="${ROOT_PREFIX}/usr/local/lib/aegis/helpers/purge-installed-aegis.sh"
        elif [[ -x "${ROOT_PREFIX}/usr/local/lib/aegis/scripts/purge-installed-aegis.sh" ]]; then
            helper="${ROOT_PREFIX}/usr/local/lib/aegis/scripts/purge-installed-aegis.sh"
        elif [[ -x "$(dirname "${BASH_SOURCE[0]}")/purge-installed-aegis.sh" ]]; then
            helper="$(dirname "${BASH_SOURCE[0]}")/purge-installed-aegis.sh"
        fi
    fi
    if [[ -n "${helper}" && -x "${helper}" ]]; then
        teardown_wide_before_purge || return 1
        stop_client_before_log_cleanup || return 1
        cleanup_auto_runtime_logs delete || return 1
        AEGIS_PURGE_ROOT="${ROOT_PREFIX:-/}" \
            "${helper}" client --force 2>&1 | sed 's/^/  purge-helper: /'
    else
        echo "  WARN: purge-installed-aegis.sh not found — falling back to manual sweep"
        purge_manual
    fi
}

teardown_wide_before_purge() {
    local helper
    if [[ -z "${ROOT_PREFIX}" ]]; then
        # An explicit client purge authorizes native-network restoration, but
        # only through the guard's durable recovery-last transaction. Do this
        # before a package manager can delete its helper/state. Automatic wide
        # cleanup never executes this path.
        local guard_state=/var/lib/aegis-install/client/device-guard.conf guard_present=0 guard_tables=""
        if [[ -e "$guard_state" || -L "$guard_state" || -e /etc/systemd/system/aegis-device-egress-guard.service ]]; then
            guard_present=1
        elif command -v nft >/dev/null 2>&1; then
            guard_tables="$(nft list tables 2>/dev/null)" || { echo 'ERROR: cannot inspect device guard; preserving recovery files' >&2; return 1; }
            [[ "$guard_tables" != *'table inet aegis_device_guard'* ]] || guard_present=1
        fi
        if [[ "$guard_present" == 1 ]]; then
            helper=/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh
            if [[ ! -x "$helper" ]] || ! "$helper" recover; then
                echo "ERROR: device guard recovery failed; preserving client files and block" >&2
                return 1
            fi
        fi
        for helper in \
            /usr/local/lib/aegis/helpers/aegis-wide-disable.sh \
            /usr/local/lib/aegis/aegis-wide-disable.sh
        do
            if [[ -x "${helper}" ]]; then
                if ! "${helper}" >/dev/null 2>&1; then
                    echo "ERROR: wide teardown failed; preserving client files for recovery" >&2
                    return 1
                fi
                return 0
            fi
        done
        # A snapshot must be restored, not simply deleted by a file sweep.
        if [[ -e /var/lib/aegis/wide-sysctl-original.txt ]]; then
            echo "ERROR: wide teardown helper missing; preserving sysctl recovery snapshot" >&2
            return 1
        fi
        if ! verify_network_clean; then
            echo "ERROR: no wide teardown helper; preserving network recovery state" >&2
            return 1
        fi
    fi
    return 0
}

purge_manual() {
    echo "method=source action=purge (manual sweep)"
    teardown_wide_before_purge || return 1
    # Persistence ExecStop and the wide-disable helper may restart the daemon.
    # Stop client LAST, after every operation that can restart it.
    if [[ -z "${ROOT_PREFIX}" ]]; then
        for unit in aegis-wide aegis-wide-tun-firewall aegis-client; do
            systemctl stop "${unit}.service" 2>/dev/null || true
            systemctl disable "${unit}.service" 2>/dev/null || true
        done
        if systemctl is-active --quiet aegis-client.service 2>/dev/null; then
            echo "ERROR: client is still active; preserving its files" >&2
            return 1
        fi
    fi
    stop_client_before_log_cleanup || return 1
    cleanup_auto_runtime_logs delete || return 1
    local p
    for p in "${LEFTOVER_PATHS[@]}"; do
        [[ "${p}" == /var/lib/aegis-client-logs ]] && continue
        rm -rf "${ROOT_PREFIX}${p}" 2>/dev/null || true
    done
    [[ -n "${ROOT_PREFIX}" ]] || systemctl daemon-reload 2>/dev/null || true
}

# --- verify ---------------------------------------------------------------

verify_network_clean() {
    # File-prefix fixtures are not a Linux network namespace. Do not inspect
    # or certify the runner's networking as if it belonged to that fixture.
    [[ -z "${ROOT_PREFIX}" ]] || return 0
    local rc=0 output tool
    for tool in iptables-save ip6tables-save; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            echo "verify=unmeasured check=${tool}"
            rc=1
        elif ! output="$("${tool}" 2>/dev/null)"; then
            echo "verify=unmeasured check=${tool}"
            rc=1
        elif [[ "${output}" == *AEGIS_WIDE* ]]; then
            echo "verify=leftover check=${tool}"
            rc=1
        fi
    done
    if command -v nft >/dev/null 2>&1; then
        if ! output="$(nft list tables 2>/dev/null)"; then
            echo "verify=unmeasured check=nft"
            rc=1
        elif [[ "${output}" == *aegis_wide* || "${output}" == *aegis_device_guard* || "${output}" == *aegis_legacy_tun_guard* ]]; then
            echo "verify=leftover check=nft"
            rc=1
        fi
    fi
    if ! output="$(ip -o link show 2>/dev/null)"; then
        echo "verify=unmeasured check=interfaces"
        rc=1
    elif [[ "${output}" == *aegis-tun* ]]; then
        echo "verify=leftover check=tun"
        rc=1
    fi
    for tool in -4 -6; do
        if ! output="$(ip "${tool}" rule show 2>/dev/null)"; then
            echo "verify=unmeasured check=policy-rules${tool}"
            rc=1
        elif grep -Eq 'fwmark (0x)?1(/[^ ]+)? .*lookup 100( |$)' <<< "${output}"; then
            echo "verify=leftover check=policy-rules${tool}"
            rc=1
        fi
    done
    if [[ -e /etc/resolv.conf.aegis-wide-bak || -L /etc/resolv.conf.aegis-wide-bak ]] \
        || grep -q '^# Managed by aegis' /etc/resolv.conf 2>/dev/null; then
        echo "verify=leftover check=resolver-recovery"
        rc=1
    fi
    return "${rc}"
}

# Retention is separate from the selected installation-removal checks.
# Inspect only these standard path entries; never read identity/floor contents.
report_retained_state() {
    echo "removal_scope=client-installation full_erasure=not-claimed"
    local kind path checked status
    for kind in device-identity release-floor; do
        case "${kind}" in
            device-identity) path=/var/lib/aegis-identity/client ;;
            release-floor) path=/var/lib/aegis-install/releases ;;
        esac
        checked="${ROOT_PREFIX}${path}"
        status=not-observed
        if [[ -L "${checked}" ]]; then
            status=symlink
        elif [[ -e "${checked}" ]]; then
            status=present
        fi
        printf 'retained_state=%s path=%s status=%s retention=preserve\n' "${kind}" "${path}" "${status}"
    done
    echo "retained_state_scope=standard-system-paths custom_identity=not-scanned per_user_state=not-scanned"
}

verify_clean() {
    local rc=0 leftovers=0
    local p
    for p in "${LEFTOVER_PATHS[@]}" "${RECOVERY_PATHS[@]}"; do
        local checked="${ROOT_PREFIX}${p}"
        if [[ -e "${checked}" || -L "${checked}" ]]; then
            echo "verify=leftover path=${p}"
            leftovers=$((leftovers + 1))
            rc=1
        else
            echo "verify=clean path=${p}"
        fi
    done
    if ! verify_network_clean; then
        leftovers=$((leftovers + 1))
        rc=1
    fi
    local unit
    for unit in "${LEFTOVER_UNITS[@]}"; do
        local status="absent"
        if [[ -z "${ROOT_PREFIX}" ]] && command -v systemctl >/dev/null 2>&1; then
            if systemctl list-unit-files --no-legend 2>/dev/null | \
                    awk '{print $1}' | grep -qx "${unit}.service"; then
                status="enabled-or-disabled"
                rc=1
            fi
            if systemctl is-active --quiet "${unit}.service" 2>/dev/null; then
                status="active"
                rc=1
            fi
        fi
        echo "verify=unit unit=${unit} status=${status}"
        if [[ "${status}" != "absent" ]]; then
            leftovers=$((leftovers + 1))
        fi
    done
    report_retained_state
    if [[ ${rc} -eq 0 ]]; then
        echo "verify=PASS leftovers=0 scope=client-installation full_erasure=not-claimed"
    else
        echo "verify=FAIL leftovers=${leftovers} scope=client-installation full_erasure=not-claimed"
    fi
    return ${rc}
}

# --- main ------------------------------------------------------------------

# Allows isolated contracts to exercise the real functions with stubbed system
# commands; sourcing never starts a purge.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi

if [[ "${ACTION}" == purge ]]; then
    cleanup_auto_runtime_logs check || exit 1
fi

method="$(detect_install_method)"
echo "detect=install_method method=${method}"

if [[ "${ACTION}" == "purge" ]]; then
    purge_rc=0
    case "${method}" in
        apt)        purge_via_apt || purge_rc=$? ;;
        bootstrap)  purge_via_bootstrap || purge_rc=$? ;;
        source)     purge_manual || purge_rc=$? ;;
        none)
            echo "detect=no_install_found — verify will run anyway"
            ;;
    esac
    echo "--- post-purge verify ---"
    if verify_clean && [[ ${purge_rc} -eq 0 ]]; then
        echo "result=PASS"
        exit 0
    else
        echo "result=FAIL"
        exit 1
    fi
fi

# ACTION == verify
if verify_clean; then
    if [[ "${method}" == "none" ]]; then
        echo "result=PASS_VACUOUS (no client installation detected; scoped checks passed; retained state is outside removal scope)"
    else
        echo "result=PASS"
    fi
    exit 0
else
    echo "result=FAIL"
    exit 1
fi
