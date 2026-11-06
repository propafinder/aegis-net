#!/usr/bin/env bash
# Best-effort purge helper for installed AEGIS residue on Linux hosts.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/purge-installed-aegis.sh <server|client|all> [--force]

This helper removes installed-product residue for the selected role:
  - binaries
  - systemd units/env files
  - config/state/log directories
  - best-effort wide helper networking residue on client hosts

Device identity and release-floor state are intentionally retained. Completion
is limited to the selected installation residue; it is not full erasure.

Safety:
  - dry-run by default
  - pass --force to execute

Environment overrides (primarily for tests):
  AEGIS_PURGE_ROOT=/tmp/fake-root
  AEGIS_PURGE_SYSTEMCTL_BIN=/path/to/systemctl
  AEGIS_PURGE_IPTABLES_BIN=/path/to/iptables
  AEGIS_PURGE_IP6TABLES_BIN=/path/to/ip6tables
  AEGIS_PURGE_NFT_BIN=/path/to/nft
  AEGIS_PURGE_IP_BIN=/path/to/ip
  AEGIS_PURGE_PKILL_BIN=/path/to/pkill
  AEGIS_PURGE_USERDEL_BIN=/path/to/userdel
  AEGIS_PURGE_GROUPDEL_BIN=/path/to/groupdel
  AEGIS_PURGE_TMPDIR=/tmp
  AEGIS_PURGE_PRESERVE_PATH=/tmp/aegis-installer-bundle.XXXXXX/extracted/client-bundle
EOF
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

ROLE="$1"
shift

case "${ROLE}" in
  server|client|all) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    echo "Role must be one of: server, client, all" >&2
    usage >&2
    exit 1
    ;;
esac

FORCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

PURGE_ROOT="${AEGIS_PURGE_ROOT:-/}"
SYSTEMCTL_BIN="${AEGIS_PURGE_SYSTEMCTL_BIN:-systemctl}"
IPTABLES_BIN="${AEGIS_PURGE_IPTABLES_BIN:-iptables}"
IP6TABLES_BIN="${AEGIS_PURGE_IP6TABLES_BIN:-ip6tables}"
NFT_BIN="${AEGIS_PURGE_NFT_BIN:-nft}"
IP_BIN="${AEGIS_PURGE_IP_BIN:-ip}"
PKILL_BIN="${AEGIS_PURGE_PKILL_BIN:-pkill}"
USERDEL_BIN="${AEGIS_PURGE_USERDEL_BIN:-userdel}"
GROUPDEL_BIN="${AEGIS_PURGE_GROUPDEL_BIN:-groupdel}"
PURGE_TMPDIR="${AEGIS_PURGE_TMPDIR:-/tmp}"
PURGE_PRESERVE_PATH="${AEGIS_PURGE_PRESERVE_PATH:-}"

# Temporary cleanup is destructive. Resolve its root once and reject broad or
# ambiguous values before expanding any runtime-family pattern beneath it.
if [[ "${PURGE_TMPDIR}" != /* || ! -d "${PURGE_TMPDIR}" ]]; then
  echo "AEGIS_PURGE_TMPDIR must be an existing absolute directory" >&2
  exit 2
fi
PURGE_TMPDIR="$(cd "${PURGE_TMPDIR}" && pwd -P)"
if [[ "${PURGE_TMPDIR}" == "/" ]]; then
  echo "Refusing to use / as AEGIS_PURGE_TMPDIR" >&2
  exit 2
fi
if [[ "${PURGE_ROOT}" != / && -n "${AEGIS_PURGE_TMPDIR:-}" ]]; then
  # A fake-root cleanup may touch only a private temporary directory owned by
  # this fixture. A sibling is valid when its common parent is itself private.
  python3 - "${PURGE_ROOT}" "${PURGE_TMPDIR}" <<'PY_FAKE_TMP_SCOPE'
import os
import stat
import sys

root = os.path.realpath(sys.argv[1])
temp = os.path.realpath(sys.argv[2])
parent = os.path.dirname(root)
grandparent = os.path.dirname(parent)
info = os.stat(temp, follow_symlinks=False)
if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022):
    raise SystemExit('AEGIS_PURGE_TMPDIR is not a private fixture directory')
within_parent = temp == parent or temp.startswith(parent + os.sep)
grand_info = os.stat(grandparent, follow_symlinks=False)
within_private_grandparent = (
    temp.startswith(grandparent + os.sep)
    and stat.S_ISDIR(grand_info.st_mode)
    and grand_info.st_uid == os.geteuid()
    and not stat.S_IMODE(grand_info.st_mode) & 0o022
)
if not (within_parent or within_private_grandparent):
    raise SystemExit('AEGIS_PURGE_TMPDIR escapes fake-root fixture scope')
PY_FAKE_TMP_SCOPE
fi
if [[ -n "${PURGE_PRESERVE_PATH}" ]]; then
  if [[ "${PURGE_PRESERVE_PATH}" != /* || ! -d "${PURGE_PRESERVE_PATH}" ]]; then
    echo "AEGIS_PURGE_PRESERVE_PATH must be an existing absolute directory" >&2
    exit 2
  fi
  PURGE_PRESERVE_PATH="$(cd "${PURGE_PRESERVE_PATH}" && pwd -P)"
fi

TPROXY_CHAIN="${AEGIS_WIDE_TPROXY_CHAIN:-AEGIS_WIDE_TPROXY}"
REDIRECT_CHAIN="${AEGIS_WIDE_REDIRECT_CHAIN:-AEGIS_WIDE}"
REDIRECT_OUTPUT_CHAIN="${AEGIS_WIDE_REDIRECT_OUTPUT_CHAIN:-${REDIRECT_CHAIN}_OUTPUT}"
REDIRECT_PREROUTING_CHAIN="${AEGIS_WIDE_REDIRECT_PREROUTING_CHAIN:-${REDIRECT_CHAIN}_PREROUTING}"
REDIRECT_FILTER_CHAIN="${AEGIS_WIDE_REDIRECT_FILTER_CHAIN:-${REDIRECT_CHAIN}_FILTER}"
REDIRECT_V6_CHAIN="${AEGIS_WIDE_REDIRECT_V6_CHAIN:-${REDIRECT_CHAIN}_V6}"
TPROXY_NFT_TABLE="${AEGIS_WIDE_NFT_TABLE:-aegis_wide_tproxy}"
TPROXY_FWMARK="${AEGIS_WIDE_FWMARK:-1}"
TPROXY_ROUTE_TABLE="${AEGIS_WIDE_ROUTE_TABLE:-100}"
# P0 hygiene: the SSH-exempt nat OUTPUT chain (aegis-wide-enable.sh:303), the
# sysctl drop-in that persisted ip_forward, and the reboot-persistence unit were
# NOT removed by earlier purge — leaving a dangling OUTPUT jump, ip_forward=1
# posture, and an enabled unit pointing at deleted scripts. Names mirror the
# enable/persist scripts.
SSH_EXEMPT_CHAIN="${AEGIS_WIDE_SSH_EXEMPT_CHAIN:-AEGIS_WIDE_SSH_EXEMPT}"
WIDE_SYSCTL_FILE="${AEGIS_WIDE_SYSCTL_FILE:-/etc/sysctl.d/99-aegis-wide.conf}"
WIDE_PERSIST_UNIT="${AEGIS_WIDE_PERSIST_UNIT_NAME:-aegis-wide.service}"
WIDE_TUN_PERSIST_UNIT="${AEGIS_WIDE_TUN_PERSIST_UNIT_NAME:-aegis-wide-tun-firewall.service}"

path_in_root() {
  local rel="$1"
  if [[ "${PURGE_ROOT}" == "/" ]]; then
    printf '%s\n' "${rel}"
  else
    printf '%s/%s\n' "${PURGE_ROOT%/}" "${rel#/}"
  fi
}

# Alternate-root controls may call only explicitly supplied executables beside
# that fixture. Never resolve a default host network/systemd command by PATH.
fake_stub_allowed() {
  local variable="$1" selected="${!1:-}" scope="" parent=""
  [[ "${PURGE_ROOT}" != / && "${selected}" == /* && -f "${selected}" &&
     ! -L "${selected}" && -x "${selected}" ]] || return 1
  scope="$(cd "$(dirname "${PURGE_ROOT}")" && pwd -P)" || return 1
  parent="$(cd "$(dirname "${selected}")" && pwd -P)" || return 1
  [[ "${parent}" == "${scope}" || "${parent}" == "${scope}/"* ]]
}

# The AUTO runtime log root has a deliberately tiny, fixed shape. Validate the
# whole tree before unlinking anything; the Python routine uses directory fds
# and O_NOFOLLOW so a path replacement cannot redirect deletion elsewhere.
cleanup_auto_runtime_logs() {
  local action="$1"
  [[ "$action" == check || "$action" == delete ]] || return 2
  if [[ "$action" == delete && "$FORCE" -eq 0 ]]; then
    info 'dry-run: would remove validated AUTO runtime logs'
    return 0
  fi
  python3 - "$PURGE_ROOT" "$action" <<'PY_AUTO_LOG_CUSTODY'
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

verify_client_stopped_for_log_cleanup() {
  [[ "${PURGE_ROOT}" == / && "${FORCE}" -eq 1 ]] || return 0
  command -v "${SYSTEMCTL_BIN}" >/dev/null 2>&1 || {
    echo 'Cannot inspect client unit before AUTO log cleanup' >&2
    return 1
  }
  local status load='' active='' sub='' main='' control=''
  status="$("${SYSTEMCTL_BIN}" show aegis-client.service --no-pager \
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
  echo 'Client unit state is indeterminate or active; AUTO logs retained' >&2
  return 1
}

verify_passive_generic_handoff() {
  /usr/bin/python3 -I -B - <<'PY_PASSIVE_HANDOFF'
import hashlib
import json
import os
from pathlib import Path
import stat
import types

def need(value):
    if not value:
        raise ValueError('passive package purge handoff refused')

def private(path, maximum):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            info = os.fstat(child)
            need(info.st_uid == info.st_gid == 0 and not stat.S_IMODE(info.st_mode) & 0o022)
            os.close(fd); fd = child
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                        dir_fd=fd)
        try:
            before = os.fstat(child)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
                 before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
                 0 < before.st_size <= maximum)
            raw = os.read(child, maximum + 1)
            after = os.fstat(child)
            named = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            need(len(raw) == before.st_size and
                 (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns) and
                 (before.st_dev, before.st_ino) == (named.st_dev, named.st_ino))
            return raw
        finally:
            os.close(child)
    finally:
        os.close(fd)

def pairs(rows):
    value = dict(rows); need(len(value) == len(rows)); return value

root = Path('/var/lib/aegis-auto-uninstall')
intent = json.loads(private(root / 'intent.json', 8192), object_pairs_hook=pairs)
payload_raw = private(root / 'passive-payload.json', 128 << 10)
need(intent.get('schema') == 'aegis_auto_v2_passive_package_removal_v1' and
     hashlib.sha256(payload_raw).hexdigest() == intent.get('payload_sha256'))
payload = json.loads(payload_raw, object_pairs_hook=pairs)
modules = {}
for name in ('aegis_auto_uninstall_journal.py', 'aegis_installer_auto_v2.py'):
    path = root / 'recovery' / name
    raw = private(path, 4 << 20)
    need(hashlib.sha256(raw).hexdigest() == payload['files'][
         'usr/local/lib/aegis/helpers/lib/' + name]['sha256'])
    module = types.ModuleType('aegis_verified_' + name.removesuffix('.py'))
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    modules[name] = module
coordinator = modules['aegis_installer_auto_v2.py']
coordinator.uninstall_journal.module = modules['aegis_auto_uninstall_journal.py']
need(coordinator.verify_passive_generic_handoff(9))
PY_PASSIVE_HANDOFF
}

# V2 private owners and their independent guard actors are not part of the
# legacy purge transaction below. Its StopUnit and guard-recovery calls do not
# share the V2 InstallLock, so even a completed stop-current cannot authorize
# deleting the actor sources or releasing the device guard in this process.
# Refuse before the first recovery or residue deletion, including dry-run and
# alternate roots; a later typed serial purge must own the entire transition.
V2_TERMINAL_HANDOFF=0
if [[ "$ROLE" == client || "$ROLE" == all ]]; then
  if [[ "$PURGE_ROOT" == / && "$FORCE" == 1 && "$ROLE" == client && -x /usr/bin/dpkg-query &&
        ! -e /var/lib/aegis-auto-uninstall && ! -L /var/lib/aegis-auto-uninstall ]]; then
    if package_state="$(/usr/bin/dpkg-query --show --showformat='${db:Status-Status}' aegis-client 2>/dev/null)"; then
      if [[ "$package_state" != not-installed ]]; then
        /usr/bin/python3 -I -B \
          /usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py uninstall
        exit $?
      fi
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
    /etc/systemd/system/aegis-device-dhcp-refresh.service \
    /etc/systemd/system/aegis-device-dhcp-refresh.timer \
    /etc/systemd/system/aegis-foreign-policy-monitor.service \
    /etc/systemd/system/aegis-auto-clean-shutdown.service; do
    selected="$(path_in_root "$selected")"
    if [[ -e "$selected" || -L "$selected" ]]; then
      # The coordinator distinguishes a package's exact inactive templates
      # from an activated V2 owner. Only its durable handoff can authorize the
      # package operation; alternate roots and previews retain the refusal.
      if [[ "$PURGE_ROOT" == / && "$FORCE" == 1 && "$ROLE" == client ]]; then
        /usr/bin/python3 -I -B \
          /usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py uninstall
        exit $?
      fi
      echo 'AUTO V2 ownership requires its typed serial stop and guard teardown; generic purge refused before mutation.' >&2
      exit 1
    fi
  done
  if [[ -e /var/lib/aegis-auto-uninstall || -L /var/lib/aegis-auto-uninstall ]]; then
    [[ "$PURGE_ROOT" == / && "$FORCE" == 1 ]] || {
      echo 'AUTO V2 terminal purge requires the live root and explicit --force' >&2
      exit 1
    }
    if [[ -e /var/lib/aegis-auto-uninstall/passive-payload.json ||
          -L /var/lib/aegis-auto-uninstall/passive-payload.json ]]; then
      verify_passive_generic_handoff || exit 1
    else
      version="$(/usr/bin/dpkg-query --show --showformat='${Version}' aegis-client)" || exit 1
      /usr/bin/python3 -I -B \
        /usr/local/lib/aegis/helpers/lib/aegis_auto_uninstall_journal.py \
        verify-generic-handoff "$version" || {
          echo 'AUTO V2 generic handoff verification refused before generic purge' >&2
          exit 1
        }
    fi
    V2_TERMINAL_HANDOFF=1
  fi
  if [[ -e "$(path_in_root /boot/aegis-auto-terminal)" ||
        -L "$(path_in_root /boot/aegis-auto-terminal)" ]]; then
    [[ "$V2_TERMINAL_HANDOFF" == 1 && -n "${version:-}" ]] || {
      echo 'AUTO terminal BOOT store requires typed verified handoff' >&2
      exit 1
    }
  fi
fi

if [[ "$ROLE" == client || "$ROLE" == all ]]; then
  cleanup_auto_runtime_logs check
fi


# This gate precedes common residue removal and all role dispatch. No generic
# client/all purge may erase selected history, helpers, units or native journals.
if [[ "$ROLE" == client || "$ROLE" == all ]]; then
  for selected in \
    /var/lib/aegis-install/client/relay-geneva-profile.json \
    /var/lib/aegis-install/client/relay-geneva-install-intent.json \
    /var/lib/aegis-install/client/relay-geneva-teardown.json \
    /var/lib/aegis-install/client/relay-geneva-guard-state.json \
    /var/lib/aegis-install/client/relay-geneva-guard-intent.json \
    /usr/local/lib/aegis/aegis-relay-geneva-profile.sh \
    /etc/systemd/system/aegis-client.service.d/25-relay-geneva-profile.conf \
    /run/aegis-relay-geneva; do
    selected="$(path_in_root "$selected")"
    if [[ -e "$selected" || -L "$selected" ]]; then
      echo 'Selected relay ownership requires its separately reviewed teardown; generic purge refused before mutation.' >&2
      exit 1
    fi
  done
fi

info() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

run_cmd() {
  if [[ "${FORCE}" -eq 0 ]]; then
    printf '[dry-run] %q' "$1"
    shift
    while [[ $# -gt 0 ]]; do
      printf ' %q' "$1"
      shift
    done
    printf '\n'
    return 0
  fi
  "$@"
}

run_best_effort() {
  if [[ "${FORCE}" -eq 0 ]]; then
    run_cmd "$@"
    return 0
  fi
  "$@" >/dev/null 2>&1 || true
}

preserve_is_in_temp_target() {
  local target="$1"
  [[ -n "${PURGE_PRESERVE_PATH}" ]] || return 1
  case "${PURGE_PRESERVE_PATH}" in
    "${target}"|"${target}"/*) return 0 ;;
    *) return 1 ;;
  esac
}

preserve_is_in_temp_family() {
  local family_prefix="$1"
  [[ -n "${PURGE_PRESERVE_PATH}" ]] || return 1
  case "${PURGE_PRESERVE_PATH}" in
    "${PURGE_TMPDIR}/${family_prefix}"*) return 0 ;;
    *) return 1 ;;
  esac
}

purge_runtime_temp_artifacts() {
  if [[ "${PURGE_ROOT}" != / ]]; then
    [[ -n "${AEGIS_PURGE_TMPDIR:-}" ]] || return 0
  fi
  local target=""
  local had_nullglob=0
  # Bash 3.2 + set -u treats an empty array expansion as unbound. Seed one
  # inert entry so the loop is portable on the macOS contract runner.
  local targets=("")

  shopt -q nullglob && had_nullglob=1
  shopt -s nullglob
  targets=(
    ""
    "${PURGE_TMPDIR}"/aegis-wide-*
    "${PURGE_TMPDIR}"/aegis-relay-*
    "${PURGE_TMPDIR}"/aegis-client-*
    "${PURGE_TMPDIR}"/aegis-smoke-*
  )
  [[ "${had_nullglob}" -eq 1 ]] || shopt -u nullglob

  for target in "${targets[@]}"; do
    [[ -n "${target}" ]] || continue
    if preserve_is_in_temp_target "${target}"; then
      info "Preserving validated installer input during temporary cleanup."
      continue
    fi
    run_best_effort rm -rf "${target}"
  done
}

repeat_delete_best_effort() {
  local max_attempts="$1"
  shift
  local attempt=0
  while (( attempt < max_attempts )); do
    if [[ "${FORCE}" -eq 0 ]]; then
      run_cmd "$@"
      return 0
    fi
    if ! "$@" >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
  done
}

remove_path() {
  local target="$1"
  if [[ -e "${target}" || -L "${target}" ]]; then
    run_cmd rm -rf "${target}"
  fi
}

role_install_present() {
  local role="$1"
  case "${role}" in
    server)
      [[ -e "$(path_in_root /usr/local/bin/aegis-server)" || \
         -e "$(path_in_root /usr/bin/aegis-server)" || \
         -e "$(path_in_root /etc/systemd/system/aegis-server.service)" || \
         -e "$(path_in_root /usr/lib/systemd/system/aegis-server.service)" || \
         -d "$(path_in_root /etc/aegis/server)" ]]
      ;;
    client)
      [[ -e "$(path_in_root /usr/local/bin/aegis-client)" || \
         -e "$(path_in_root /usr/bin/aegis-client)" || \
         -e "$(path_in_root /etc/systemd/system/aegis-client.service)" || \
         -e "$(path_in_root /usr/lib/systemd/system/aegis-client.service)" || \
         -d "$(path_in_root /etc/aegis/client)" ]]
      ;;
    *) return 1 ;;
  esac
}

delete_system_account_if_present() {
  local account="$1" uid=""
  [[ "${PURGE_ROOT}" == "/" ]] || return 0
  uid="$(id -u "${account}" 2>/dev/null || true)"
  [[ -n "${uid}" ]] || return 0
  # Never delete a human/login account that merely shares an AEGIS name.
  [[ "${uid}" -lt 1000 ]] || return 0
  run_best_effort "${USERDEL_BIN}" -r "${account}"
  if getent group "${account}" >/dev/null 2>&1; then
    run_best_effort "${GROUPDEL_BIN}" "${account}"
  fi
}

stop_disable_unit() {
  local unit="$1"
  if [[ "${PURGE_ROOT}" != / ]]; then
    fake_stub_allowed AEGIS_PURGE_SYSTEMCTL_BIN || return 0
  fi
  if ! command -v "${SYSTEMCTL_BIN}" >/dev/null 2>&1; then
    warn "${SYSTEMCTL_BIN} is unavailable; skipping systemd stop/disable for ${unit}"
    return 0
  fi
  run_best_effort "${SYSTEMCTL_BIN}" stop "${unit}"
  run_best_effort "${SYSTEMCTL_BIN}" disable "${unit}"
}

systemd_cleanup() {
  if [[ "${PURGE_ROOT}" != / ]]; then
    fake_stub_allowed AEGIS_PURGE_SYSTEMCTL_BIN || return 0
  fi
  if ! command -v "${SYSTEMCTL_BIN}" >/dev/null 2>&1; then
    return 0
  fi
  run_best_effort "${SYSTEMCTL_BIN}" daemon-reload
  run_best_effort "${SYSTEMCTL_BIN}" reset-failed
}

delete_xtables_jumps() {
  local firewall="$1"
  local table="$2"
  local chain="$3"
  local parent="$4"
  local rule=""
  local -a parts=()

  if ! command -v "${firewall}" >/dev/null 2>&1; then
    return 0
  fi

  while IFS= read -r rule; do
    [[ -n "${rule}" ]] || continue
    read -r -a parts <<< "${rule}"
    [[ "${parts[0]:-}" == "-A" ]] || continue
    parts[0]="-D"
    run_best_effort "${firewall}" -t "${table}" "${parts[@]}"
  done < <("${firewall}" -t "${table}" -S "${parent}" 2>/dev/null | awk -v target="${chain}" '$0 ~ ("-j " target "$")')
}

prepare_client_recovery() {
  [[ "${FORCE}" == 1 ]] || return 0
  local snapshot legacy resolver current
  snapshot="$(path_in_root /var/lib/aegis-install/client/wide-sysctl-original.txt)"
  legacy="$(path_in_root /var/lib/aegis/wide-sysctl-original.txt)"
  resolver="$(path_in_root /var/lib/aegis-install/client/resolver-original.json)"
  current="$(path_in_root /etc/resolv.conf)"
  local resolver_legacy="$(path_in_root /etc/resolv.conf.aegis-wide-bak)"
  if [[ ! -e "$snapshot" && ! -L "$snapshot" && ! -e "$legacy" && ! -L "$legacy" && ! -e "$resolver" && ! -L "$resolver" && ! -e "$resolver_legacy" && ! -L "$resolver_legacy" ]]; then
    return 0
  fi
  # Validate and retain recovery before systemd can execute any old ExecStop.
  # No old daemon-owned metadata is accepted as root authority.
  # shellcheck source=scripts/lib/root-state.sh
  . "$(dirname "${BASH_SOURCE[0]}")/lib/root-state.sh"
  aegis_root_state_init || return 1
  if [[ -e "$legacy" || -L "$legacy" ]]; then
    aegis_root_sysctl_check "$legacy" || return 1
    if [[ ! -e "$snapshot" ]]; then
      aegis_root_read "$legacy" | aegis_root_write "$snapshot" || return 1
    fi
    aegis_root_remove "$legacy" || return 1
  fi
  if [[ -e "$snapshot" || -L "$snapshot" ]]; then
    aegis_root_sysctl_check "$snapshot" || return 1
    PURGE_SYSCTL_RECOVERY="$(aegis_root_read "$snapshot")" || return 1
  fi
  if [[ -e "$resolver_legacy" || -L "$resolver_legacy" ]]; then
    aegis_root_state resolver-save --path "$resolver_legacy" --snapshot "$resolver" || return 1
    rm -f -- "$resolver_legacy" || return 1
  fi
  aegis_root_state resolver-check --path "$current" --snapshot "$resolver" || return 1
  PURGE_RESOLVER_RECOVERY="$resolver"
}

cleanup_client_networking() {
  if [[ ! "${ROLE}" =~ ^(client|all)$ ]]; then
    return 0
  fi
  if [[ "${PURGE_ROOT}" != / ]]; then
    for variable in AEGIS_PURGE_SYSTEMCTL_BIN AEGIS_PURGE_IPTABLES_BIN \
      AEGIS_PURGE_IP6TABLES_BIN AEGIS_PURGE_NFT_BIN AEGIS_PURGE_IP_BIN \
      AEGIS_PURGE_PKILL_BIN; do
      fake_stub_allowed "$variable" || return 0
    done
  fi

  local nm_dns_conf="/run/NetworkManager/conf.d/90-aegis-wide-dns.conf"
  if [[ "${PURGE_ROOT}" == / && -f "${nm_dns_conf}" ]] &&
     grep -q '^# Managed by Aegis wide DNS preview$' "${nm_dns_conf}" 2>/dev/null; then
    run_best_effort rm -f "${nm_dns_conf}"
    run_best_effort systemctl reload NetworkManager
  fi

  delete_xtables_jumps "${IPTABLES_BIN}" nat "${REDIRECT_OUTPUT_CHAIN}" OUTPUT
  delete_xtables_jumps "${IPTABLES_BIN}" nat "${REDIRECT_OUTPUT_CHAIN}" PREROUTING
  delete_xtables_jumps "${IPTABLES_BIN}" nat "${REDIRECT_PREROUTING_CHAIN}" OUTPUT
  delete_xtables_jumps "${IPTABLES_BIN}" nat "${REDIRECT_PREROUTING_CHAIN}" PREROUTING
  run_best_effort "${IPTABLES_BIN}" -t nat -F "${REDIRECT_OUTPUT_CHAIN}"
  run_best_effort "${IPTABLES_BIN}" -t nat -X "${REDIRECT_OUTPUT_CHAIN}"
  run_best_effort "${IPTABLES_BIN}" -t nat -F "${REDIRECT_PREROUTING_CHAIN}"
  run_best_effort "${IPTABLES_BIN}" -t nat -X "${REDIRECT_PREROUTING_CHAIN}"

  # Fail-closed leak chains (IPv4 filter + IPv6 reject). MUST be removed or an
  # uninstall would leave the host's IPv6 egress permanently blocked.
  delete_xtables_jumps "${IPTABLES_BIN}" filter "${REDIRECT_FILTER_CHAIN}" OUTPUT
  run_best_effort "${IPTABLES_BIN}" -t filter -F "${REDIRECT_FILTER_CHAIN}"
  run_best_effort "${IPTABLES_BIN}" -t filter -X "${REDIRECT_FILTER_CHAIN}"
  delete_xtables_jumps "${IP6TABLES_BIN}" filter "${REDIRECT_V6_CHAIN}" OUTPUT
  run_best_effort "${IP6TABLES_BIN}" -t filter -F "${REDIRECT_V6_CHAIN}"
  run_best_effort "${IP6TABLES_BIN}" -t filter -X "${REDIRECT_V6_CHAIN}"

  delete_xtables_jumps "${IPTABLES_BIN}" mangle "${TPROXY_CHAIN}" PREROUTING
  run_best_effort "${IPTABLES_BIN}" -t mangle -F "${TPROXY_CHAIN}"
  run_best_effort "${IPTABLES_BIN}" -t mangle -X "${TPROXY_CHAIN}"

  delete_xtables_jumps "${IP6TABLES_BIN}" mangle "${TPROXY_CHAIN}" PREROUTING
  run_best_effort "${IP6TABLES_BIN}" -t mangle -F "${TPROXY_CHAIN}"
  run_best_effort "${IP6TABLES_BIN}" -t mangle -X "${TPROXY_CHAIN}"

  run_best_effort "${NFT_BIN}" delete table ip "${TPROXY_NFT_TABLE}"
  run_best_effort "${NFT_BIN}" delete table ip6 "${TPROXY_NFT_TABLE}"

  if command -v "${IP_BIN}" >/dev/null 2>&1; then
    repeat_delete_best_effort 8 "${IP_BIN}" rule del fwmark "${TPROXY_FWMARK}" lookup "${TPROXY_ROUTE_TABLE}"
    repeat_delete_best_effort 8 "${IP_BIN}" -6 rule del fwmark "${TPROXY_FWMARK}" lookup "${TPROXY_ROUTE_TABLE}"
    repeat_delete_best_effort 8 "${IP_BIN}" route del local 0.0.0.0/0 dev lo table "${TPROXY_ROUTE_TABLE}"
    repeat_delete_best_effort 8 "${IP_BIN}" -6 route del local ::/0 dev lo table "${TPROXY_ROUTE_TABLE}"
  fi

  # P0: the SSH-exempt nat OUTPUT chain (aegis-wide-enable.sh) — a dangling
  # `-j AEGIS_WIDE_SSH_EXEMPT` jump survives uninstall without this.
  delete_xtables_jumps "${IPTABLES_BIN}" nat "${SSH_EXEMPT_CHAIN}" OUTPUT
  run_best_effort "${IPTABLES_BIN}" -t nat -F "${SSH_EXEMPT_CHAIN}"
  run_best_effort "${IPTABLES_BIN}" -t nat -X "${SSH_EXEMPT_CHAIN}"

  # P0: restore DNS-preview resolver state (symmetric with aegis-wide-disable.sh).
  # Without this, uninstalling while dns=preview was active leaves the host with
  # /etc/resolv.conf pointing at the now-gone 127.0.0.1:53 fake-IP listener and
  # systemd-resolved stopped → permanently broken name resolution after purge.
  if [[ -n "${PURGE_RESOLVER_RECOVERY:-}" ]]; then
    aegis_root_state resolver-restore --path "$(path_in_root /etc/resolv.conf)" --snapshot "$PURGE_RESOLVER_RECOVERY" || return 1
  fi
  if [[ "${PURGE_ROOT}" == "/" ]] && command -v "${SYSTEMCTL_BIN}" >/dev/null 2>&1; then
    "${SYSTEMCTL_BIN}" is-enabled systemd-resolved >/dev/null 2>&1 && \
      run_best_effort "${SYSTEMCTL_BIN}" start systemd-resolved
  fi

  # P0: remove the sysctl drop-in that persisted ip_forward=1 (and reload), so the
  # host's forwarding posture returns to its pre-wide value after uninstall.
  remove_path "$(path_in_root "${WIDE_SYSCTL_FILE}")"
  if [[ "${PURGE_ROOT}" == "/" ]] && command -v sysctl >/dev/null 2>&1; then
    run_best_effort sysctl --system
    if [[ -n "${PURGE_SYSCTL_RECOVERY:-}" ]]; then
      while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        sysctl -wq "${key}=${value}" || return 1
      done <<< "$PURGE_SYSCTL_RECOVERY"
    fi
  fi

  run_best_effort "${PKILL_BIN}" -f "${PURGE_TMPDIR}/aegis-wide-"
  run_best_effort "${PKILL_BIN}" -f "${PURGE_TMPDIR}/aegis-relay-"
  if preserve_is_in_temp_family 'aegis-client-'; then
    info "Preserving validated installer input; skipping client temporary-process sweep."
  else
    run_best_effort "${PKILL_BIN}" -f "${PURGE_TMPDIR}/aegis-client-"
  fi
  run_best_effort "${PKILL_BIN}" -f 'aegis-wide-tproxy'
  purge_runtime_temp_artifacts
}

purge_server_role() {
  stop_disable_unit aegis-server.service

  remove_path "$(path_in_root "/usr/local/bin/aegis-server")"
  remove_path "$(path_in_root "/usr/bin/aegis-server")"
  remove_path "$(path_in_root "/etc/systemd/system/aegis-server.service")"
  remove_path "$(path_in_root "/usr/lib/systemd/system/aegis-server.service")"
  remove_path "$(path_in_root "/etc/default/aegis-server")"
  remove_path "$(path_in_root "/etc/aegis/server")"
  remove_path "$(path_in_root "/var/lib/aegis-server")"
  remove_path "$(path_in_root "/var/lib/aegis-install/server")"
  # P0 (secret hygiene): the bundle-token store and pre-built client bundles live
  # in /var/lib/aegis (config default token_store_path=/var/lib/aegis/bundle-tokens.json),
  # a DIFFERENT dir from /var/lib/aegis-server. Without this, uninstall LEAVES the
  # one-time-token store and client-bundle.tar.gz (which embeds the relay auth_token
  # + CA) on disk. Remove it so no relay credential survives a purge.
  remove_path "$(path_in_root "/var/lib/aegis")"

  # The server and redirect-family client intentionally share the `aegis`
  # system account on a combined host. Preserve it while the client role is
  # still installed; the final role purge owns account removal.
  if ! role_install_present client; then
    delete_system_account_if_present aegis
  fi
}

recover_client_device_guard() {
  local state unit helper tables
  state="$(path_in_root /var/lib/aegis-install/client/device-guard.conf)"
  unit="$(path_in_root /etc/systemd/system/aegis-device-egress-guard.service)"
  if [[ -e "$state" || -L "$state" ]]; then
    if [[ "$FORCE" != 1 ]]; then
      info "Would explicitly recover the device guard before deleting client files"
      return 0
    fi
    # Recovery addresses real kernel/systemd state, never an alternate root.
    [[ "$PURGE_ROOT" == / ]] || { echo 'Device guard recovery requires the live installation root' >&2; return 1; }
    helper="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/aegis-device-egress-guard.sh"
    . "$(dirname "${BASH_SOURCE[0]}")/lib/root-state.sh"
    aegis_root_state_init && aegis_root_trusted_executable "$helper" || return 1
    AEGIS_DEVICE_GUARD_STATE="$state" bash "$helper" recover || return 1
  elif [[ -e "$unit" || -L "$unit" ]]; then
    echo 'Device guard ownership has no recovery record; retain all files for explicit recovery' >&2
    return 1
  fi
  if [[ "$FORCE" == 1 && "$PURGE_ROOT" == / ]] && command -v "$NFT_BIN" >/dev/null 2>&1; then
    tables="$("$NFT_BIN" list tables)" || return 1
    if grep -Fxq 'table inet aegis_device_guard' <<< "$tables"; then
      echo 'Device guard remains; refusing to delete recovery files' >&2
      return 1
    fi
  fi
}

recover_client_legacy_tun_guard() {
  local state unit helper tables
  state="$(path_in_root /var/lib/aegis-install/client/legacy-tun-guard.conf)"
  unit="$(path_in_root /etc/systemd/system/aegis-legacy-tun-guard.service)"
  if [[ -e "$state" || -L "$state" || -e "$unit" || -L "$unit" ]]; then
    if [[ "$FORCE" != 1 ]]; then
      info 'Would explicitly disconnect the legacy TUN guard before deleting client files'
      return 0
    fi
    [[ "$PURGE_ROOT" == / ]] || { echo 'Legacy TUN guard recovery requires the live installation root' >&2; return 1; }
    helper="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/aegis-wide-disable.sh"
    . "$(dirname "${BASH_SOURCE[0]}")/lib/root-state.sh"
    aegis_root_state_init && aegis_root_trusted_executable "$helper" || return 1
    bash "$helper" || return 1
  fi
  if [[ "$FORCE" == 1 && "$PURGE_ROOT" == / ]] && command -v "$NFT_BIN" >/dev/null 2>&1; then
    tables="$("$NFT_BIN" list tables)" || return 1
    if grep -Fxq 'table inet aegis_legacy_tun_guard' <<< "$tables"; then
      echo 'Legacy TUN guard remains; refusing to delete recovery files' >&2
      return 1
    fi
  fi
}

purge_client_role() {
  if [[ -e "$(path_in_root /var/lib/aegis-install/boot-backup/manifest.json)" ]]; then
    if [[ "$FORCE" == 1 ]]; then
      [[ "$PURGE_ROOT" == / ]] || { echo 'Initrd recovery requires the live root' >&2; return 1; }
      /usr/bin/python3 -I -B "$(dirname "${BASH_SOURCE[0]}")/lib/aegis_initrd_policy.py" uninstall || {
        echo 'Initrd policy recovery refused; guard and recovery files retained.' >&2; return 1;
      }
    else
      info 'Would restore the ordinary initrd policy before guard recovery'
    fi
  fi
  # Refuse a changed foreign firewall before disarming the persistent guard.
  # The second check below proves that recovery itself preserved the snapshot.
  if [[ "$FORCE" == 1 && "$PURGE_ROOT" == / && -f /var/lib/aegis-install/client/ufw-before-guard.json ]]; then
    /usr/bin/python3 -I -B "$(dirname "${BASH_SOURCE[0]}")/lib/aegis_auto_foreign_policy.py" \
      --verify-snapshot /var/lib/aegis-install/client/ufw-before-guard.json || {
        echo 'UFW pre-recovery reverse check refused; guard retained.' >&2; return 1;
      }
  fi
  recover_client_legacy_tun_guard || { echo 'Legacy TUN guard recovery failed; client files retained.' >&2; return 1; }
  recover_client_device_guard || { echo 'Device guard recovery failed; client files retained.' >&2; return 1; }
  if [[ "$FORCE" == 1 && "$PURGE_ROOT" == / && -f /var/lib/aegis-install/client/ufw-before-guard.json ]]; then
    /usr/bin/python3 -I -B "$(dirname "${BASH_SOURCE[0]}")/lib/aegis_auto_foreign_policy.py" \
      --verify-snapshot /var/lib/aegis-install/client/ufw-before-guard.json || {
        echo 'UFW reverse check refused; recovery evidence retained.' >&2; return 1;
      }
  fi
  prepare_client_recovery || { echo "Refusing purge of untrusted recovery state; upgrade/migrate with a verified installer first." >&2; return 1; }
  # P0: the reboot-persistence unit (aegis-wide-persist-install.sh) keeps wide
  # sticky across reboots; if left enabled after uninstall it re-invokes deleted
  # scripts every boot. Stop the persistence units first because the generic
  # unit's ExecStop restores the SOCKS config and may restart aegis-client.
  stop_disable_unit "${WIDE_PERSIST_UNIT}"
  stop_disable_unit "${WIDE_TUN_PERSIST_UNIT}"
  stop_disable_unit aegis-client.service
  verify_client_stopped_for_log_cleanup
  cleanup_auto_runtime_logs delete
  remove_path "$(path_in_root "/etc/systemd/system/${WIDE_PERSIST_UNIT}")"
  remove_path "$(path_in_root "/usr/lib/systemd/system/${WIDE_PERSIST_UNIT}")"
  remove_path "$(path_in_root "/etc/systemd/system/${WIDE_TUN_PERSIST_UNIT}")"
  remove_path "$(path_in_root "/usr/lib/systemd/system/${WIDE_TUN_PERSIST_UNIT}")"

  cleanup_client_networking

  remove_path "$(path_in_root "/usr/local/bin/aegis-client")"
  remove_path "$(path_in_root "/usr/bin/aegis-client")"
  remove_path "$(path_in_root "/usr/lib/aegis")"
  remove_path "$(path_in_root "/etc/systemd/system/aegis-client.service")"
  # Redirect and full-wide-tun profiles add dedicated-uid/capability drop-ins.
  # Removing only the base unit leaves a non-empty service.d directory that
  # makes a later clean install correctly refuse to overwrite stale policy.
  remove_path "$(path_in_root "/etc/systemd/system/aegis-client.service.d")"
  remove_path "$(path_in_root "/usr/lib/systemd/system/aegis-client.service")"
  remove_path "$(path_in_root "/usr/lib/systemd/system/aegis-client.service.d")"
  remove_path "$(path_in_root "/etc/default/aegis-client")"
  remove_path "$(path_in_root "/etc/aegis/client")"
  remove_path "$(path_in_root "/var/lib/aegis-client")"
  remove_path "$(path_in_root "/var/lib/aegis-install/client")"
  remove_path "$(path_in_root "/var/lib/aegis-install/auto-client")"
  remove_path "$(path_in_root "/var/log/aegis-client")"
  # The typed V2 journal copied and verified this separate ext4 tree before
  # handoff. Never let the legacy or passive path erase an unowned BOOT tree.
  if [[ "$V2_TERMINAL_HANDOFF" == 1 &&
        ( -e /boot/aegis-auto-terminal || -L /boot/aegis-auto-terminal ) ]]; then
    [[ -n "${version:-}" ]] || { echo 'AUTO BOOT retirement lacks active version' >&2; return 1; }
    /usr/bin/python3 -I -B \
      /usr/local/lib/aegis/helpers/lib/aegis_auto_uninstall_journal.py \
      retire-boot-store "$version" || {
        echo 'AUTO BOOT retirement refused; backed bytes retained' >&2
        return 1
      }
  fi

  # This can reload PID1 only after the typed AUTO owners and actors are gone.
  # Keep the helper available until the durable cloud preparation inverse has
  # completed; an interrupted restoration is resumable from the same journal.
  if [[ -e "$(path_in_root /var/lib/aegis-install/cloud-bootstrap-detachment.json)" ||
        -L "$(path_in_root /var/lib/aegis-install/cloud-bootstrap-detachment.json)" ]]; then
    if [[ "$FORCE" == 1 ]]; then
      [[ "$PURGE_ROOT" == / ]] || { echo 'Cloud dependency recovery requires the live root' >&2; return 1; }
      /usr/bin/python3 -I -B "$(dirname "${BASH_SOURCE[0]}")/lib/aegis_initrd_policy.py" restore-cloud --opt-in || {
        echo 'Cloud dependency restoration refused; recovery journal retained.' >&2; return 1;
      }
    else
      info 'Would restore the detached stock cloud bootstrap dependency after AUTO teardown'
    fi
  fi
  if [[ "$V2_TERMINAL_HANDOFF" != 1 ]]; then
    remove_path "$(path_in_root "/usr/local/lib/aegis")"
  fi

  # `aegis-svc` is the dedicated fallback when a human account is named aegis.
  # The regular `aegis` system account is shared with a co-located relay.
  delete_system_account_if_present aegis-svc
  if ! role_install_present server; then
    delete_system_account_if_present aegis
  fi
}

purge_shared_packaging_residue() {
  remove_path "$(path_in_root "/usr/lib/systemd/system-preset/90-aegis.preset")"
  remove_path "$(path_in_root "/usr/lib/sysusers.d/aegis.conf")"
  remove_path "$(path_in_root "/usr/lib/tmpfiles.d/aegis.conf")"
  remove_path "$(path_in_root "/usr/share/aegis")"
}

purge_common_packaging_residue() {
  case "${ROLE}" in
    server)
      remove_path "$(path_in_root "/usr/lib/systemd/system-preset/90-aegis-server.preset")"
      remove_path "$(path_in_root "/usr/lib/sysusers.d/aegis-server.conf")"
      remove_path "$(path_in_root "/usr/lib/tmpfiles.d/aegis-server.conf")"
      # Legacy monolithic package files are safe to remove only when no client
      # role remains on this host.
      role_install_present client || purge_shared_packaging_residue
      ;;
    client)
      remove_path "$(path_in_root "/usr/lib/systemd/system-preset/90-aegis-client.preset")"
      remove_path "$(path_in_root "/usr/lib/tmpfiles.d/aegis-client.conf")"
      role_install_present server || purge_shared_packaging_residue
      ;;
    all)
      remove_path "$(path_in_root "/usr/lib/systemd/system-preset/90-aegis-server.preset")"
      remove_path "$(path_in_root "/usr/lib/systemd/system-preset/90-aegis-client.preset")"
      remove_path "$(path_in_root "/usr/lib/sysusers.d/aegis-server.conf")"
      remove_path "$(path_in_root "/usr/lib/tmpfiles.d/aegis-server.conf")"
      remove_path "$(path_in_root "/usr/lib/tmpfiles.d/aegis-client.conf")"
      purge_shared_packaging_residue
      ;;
  esac
}

remove_parent_dirs_if_empty() {
  local target=""
  for target in "$(path_in_root "/etc/aegis")" "$(path_in_root "/var/lib")" "$(path_in_root "/var/log")"; do
    if [[ -d "${target}" ]] && [[ -z "$(find "${target}" -mindepth 1 -maxdepth 1 2>/dev/null)" ]]; then
      run_cmd rmdir "${target}"
    fi
  done
}

# Retention is separate from the selected installation-removal checks.
# Inspect only these standard path entries; never read identity/floor contents.
report_retained_state() {
    echo "removal_scope=selected-installation role=${ROLE} full_erasure=not-claimed"
    local kind path checked status
    for kind in device-identity release-floor; do
        case "${kind}" in
            device-identity) path=/var/lib/aegis-identity/client ;;
            release-floor) path=/var/lib/aegis-install/releases ;;
        esac
        checked="$(path_in_root "${path}")"
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

info "AEGIS purge scope"
info "-----------------"
info "role: ${ROLE}"
if [[ "${FORCE}" -eq 0 ]]; then
  info "mode: dry-run (pass --force to execute)"
else
  info "mode: destructive purge"
fi
info "root: ${PURGE_ROOT}"

case "${ROLE}" in
  server)
    purge_server_role
    ;;
  client)
    purge_client_role
    ;;
  all)
    purge_client_role
    # Client recovery and its log custody still need the shared helper tree.
    # Retire them before the server role removes shared package material.
    purge_server_role
    remove_path "$(path_in_root "/etc/aegis")"
    ;;
esac
purge_common_packaging_residue
systemd_cleanup
remove_parent_dirs_if_empty

report_retained_state
info "AEGIS purge helper finished scope=selected-installation full_erasure=not-claimed"
