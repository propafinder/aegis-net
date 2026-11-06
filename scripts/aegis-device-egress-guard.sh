#!/usr/bin/env bash
# Persistent device-profile privacy block. The default owns inet aegis_device_guard.
# An explicit validated selected sidecar adds its exact NETDEV table atomically.
# Capture teardown must never delete this table. Explicit release is last in an
# operator recovery/uninstall transaction, after durable disarm + unit removal.
set -euo pipefail
ACTION="${1:-}"
STATE="${AEGIS_DEVICE_GUARD_STATE:-/var/lib/aegis-install/client/device-guard.conf}"
TABLE=aegis_device_guard
# Generic inet-only teardown cannot disarm selected NETDEV ownership or erase
# its durable recovery evidence. Even a dangling symlink is uncertain ownership.
# Check before loading helpers, creating locks, stopping units or changing policy.
if [[ "$ACTION" == recover || "$ACTION" == release || "$ACTION" == recover-nm-policy ]]; then
  for selected in \
    /var/lib/aegis-install/client/relay-geneva-profile.json \
    /var/lib/aegis-install/client/relay-geneva-install-intent.json \
    /var/lib/aegis-install/client/relay-geneva-teardown.json \
    /var/lib/aegis-install/client/relay-geneva-guard-state.json \
    /var/lib/aegis-install/client/relay-geneva-guard-intent.json \
    /usr/local/lib/aegis/aegis-relay-geneva-profile.sh \
    /etc/systemd/system/aegis-client.service.d/25-relay-geneva-profile.conf \
    /run/aegis-relay-geneva; do
    if [[ -e "$selected" || -L "$selected" ]]; then
      echo 'ERROR: selected relay ownership requires its separately reviewed teardown; generic guard recovery/release refused' >&2
      exit 1
    fi
  done
fi
networkmanager_policy() {
  python3 - "$@" <<'PY_NM_POLICY'
"""Draft fixed-policy storage body for embedding in the existing guard helper.

No network/service action. Public entry point accepts only inspect/prepare/verify/remove.
Caller orders the outer guard lock before this ownership lock, never conversely.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time

ROOT = "/"
TARGET = "etc/NetworkManager/conf.d/90-aegis-device-guard.conf"
RECEIPT = "var/lib/aegis-install/client/networkmanager-policy.json"
OWNER_UID = 0
SCHEMA = "aegis_nm_policy_owner_v1"


def need(condition, message):
    if not condition:
        raise ValueError("NetworkManager policy ownership: " + message)


def _checkpoint(_name):
    """Inert production hook; synthetic subprocess tests inject exact crash cuts."""


def content(nonce):
    need(re.fullmatch("[0-9a-f]{32}", nonce) is not None, "invalid nonce")
    return ("# Aegis device guard owner=" + nonce + "\n[main]\ndhcp=internal\n").encode()


def _write_all(fd, data):
    while data:
        count = os.write(fd, data)
        need(count > 0, "short write")
        data = data[count:]


def _unique(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate receipt field")
        result[key] = value
    return result


@contextlib.contextmanager
def directory(relative, create=False):
    """Fixed relative paths below ROOT; fixtures rebase ROOT literally."""
    parts = relative.split("/")
    need(parts and all(p not in ("", ".", "..") for p in parts), "invalid fixed path")
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        initial = os.fstat(fd)
        need(initial.st_uid == OWNER_UID and not initial.st_mode & 0o022, "untrusted root")
        for part in parts:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    yield None
                    return
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            value = os.fstat(fd)
            need(value.st_uid == OWNER_UID and not value.st_mode & 0o022, "untrusted parent")
        yield fd
    finally:
        os.close(fd)


def read(parent, name, maximum=4096, links=(1,)):
    if parent is None:
        return None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        return None
    try:
        value = os.fstat(fd)
        need(stat.S_ISREG(value.st_mode) and value.st_uid == OWNER_UID
             and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink in links
             and value.st_size <= maximum, "untrusted bounded private file")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, maximum + 1 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        need(len(data) <= maximum, "file exceeds bound")
        return bytes(data), (value.st_dev, value.st_ino), value.st_nlink
    finally:
        os.close(fd)


def _save(parent, name, record):
    """Atomic bounded private receipt; temporary never becomes config input."""
    data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    need(len(data) <= 4096, "receipt exceeds bound")
    temporary = ".nm-policy-receipt-" + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=parent)
    try:
        _write_all(fd, data)
        os.fsync(fd)
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def _receipt(parent):
    value = read(parent, os.path.basename(RECEIPT))
    if value is None:
        return None
    record = json.loads(value[0], object_pairs_hook=_unique)
    need(type(record) is dict and set(record) == {"schema", "nonce", "sha256", "phase", "inode"},
         "invalid receipt schema")
    need(record["schema"] == SCHEMA and record["phase"] in ("creating", "installed", "removing"),
         "invalid receipt state")
    expected = content(record["nonce"])
    need(record["sha256"] == hashlib.sha256(expected).hexdigest(), "receipt content binding changed")
    inode = record["inode"]
    need(inode is None or type(inode) is list and len(inode) == 2
         and all(type(x) is int and 0 <= x < 2 ** 64 for x in inode), "invalid inode binding")
    need(record["phase"] != "installed" or inode is not None, "installed inode missing")
    return record


def _stage_name(record):
    # Same filesystem as the final leaf; NetworkManager reads only *.conf.
    return ".90-aegis-device-guard." + record["nonce"] + ".stage"


def _owned(state, config):
    record = _receipt(state)
    target = read(config, os.path.basename(TARGET), 256, links=(1, 2))
    if record is None:
        need(target is None, "preexisting configuration is not owned")
        return None, None, None
    expected = content(record["nonce"])
    stage = read(config, _stage_name(record), 256, links=(1, 2))
    if target is not None:
        need(target[0] == expected, "owned configuration was changed")
        need(record["inode"] is None or tuple(record["inode"]) == target[1], "owned inode was replaced")
        if stage is None:
            need(target[2] == 1, "unknown configuration hardlink")
            need(record["inode"] is not None, "published inode has no durable ownership proof")
        else:
            need(stage[0] == expected and target[1] == stage[1]
                 and stage[2] == target[2] == 2, "unproven staged configuration link")
    if stage is not None:
        need(expected.startswith(stage[0]), "private staging contents changed")
        need(record["inode"] is None or tuple(record["inode"]) == stage[1],
             "staging inode was replaced")
        need(target is not None or stage[2] == 1, "unknown staging hardlink")
        need(record["phase"] != "installed", "unexpected installed staging file")
    return record, target, stage


@contextlib.contextmanager
def locked(state, create):
    name = os.path.basename(RECEIPT) + ".lock"
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        try:
            fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=state)
            os.fsync(fd)
            os.fsync(state)
        except FileExistsError:
            fd = os.open(name, flags, dir_fd=state)
    else:
        try:
            fd = os.open(name, flags, dir_fd=state)
        except FileNotFoundError:
            yield
            return
    try:
        value = os.fstat(fd)
        need(stat.S_ISREG(value.st_mode) and value.st_uid == OWNER_UID
             and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1
             and value.st_size == 0, "untrusted ownership lock")
        deadline = time.monotonic() + 5
        operation = fcntl.LOCK_EX if create else fcntl.LOCK_SH
        while True:
            try:
                fcntl.flock(fd, operation | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                need(time.monotonic() < deadline, "ownership lock busy")
                time.sleep(0.025)
        yield
    finally:
        os.close(fd)


def run(action):
    need(action in ("inspect", "prepare", "verify", "remove"), "unsupported action")
    need(os.geteuid() == OWNER_UID, "administrator execution required")
    config_parent, target_name = TARGET.rsplit("/", 1)
    state_parent, receipt_name = RECEIPT.rsplit("/", 1)
    with directory(config_parent) as config:
        need(config is not None, "NetworkManager configuration directory missing")
        # Refuse an existing user file before creating even a private lock/dir.
        with directory(state_parent) as initial:
            # A prepare may already hold this lock before publishing its intent.
            # Never declare cleanup complete from an unlocked absent observation.
            with locked(initial, False) if initial is not None else contextlib.nullcontext():
                record, target, _ = _owned(initial, config)
                if action in ("inspect", "remove") and record is None:
                    return {"ownership": "absent"}
        with directory(state_parent, create=action == "prepare") as state:
            need(state is not None, "ownership state missing")
            with locked(state, action in ("prepare", "remove")):
                _checkpoint("ownership_locked")
                record, target, stage = _owned(state, config)
                need(action == "remove" or not record or record["phase"] != "installed" or target,
                     "installed configuration disappeared; explicit owned cleanup required")
                if action == "inspect":
                    return {"ownership": "owned" if record else "absent"}
                if action == "verify":
                    need(record and record["phase"] == "installed" and target and stage is None,
                         "complete owned policy is not installed")
                    return {"ownership": "owned"}
                if action == "prepare":
                    if record and record["phase"] == "installed":
                        need(target and stage is None, "installed policy is incomplete")
                        return {"ownership": "owned"}
                    if record is None:
                        nonce = secrets.token_hex(16)
                        record = {"schema": SCHEMA, "nonce": nonce, "phase": "creating",
                                  "sha256": hashlib.sha256(content(nonce)).hexdigest(), "inode": None}
                        _save(state, receipt_name, record)
                        _checkpoint("intent_durable")
                    need(record["phase"] != "removing", "finish owned removal before preparing")
                    if target is None:
                        # Only a previously retained creating intent can resume
                        # a missing target. Missing installed policy is drift.
                        record["phase"], record["inode"] = "creating", None
                        _save(state, receipt_name, record)
                        name = _stage_name(record)
                        expected = content(record["nonce"])
                        if stage is None:
                            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=config)
                        else:
                            # Only this receipt-owned private nonce staging
                            # prefix may resume; a partial public target never may.
                            fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=config)
                        try:
                            current = os.fstat(fd)
                            need(stage is None or (current.st_dev, current.st_ino) == stage[1],
                                 "staging inode changed")
                            os.fsync(config)
                            _checkpoint("stage_created")
                            os.ftruncate(fd, 0)
                            _write_all(fd, expected)
                            os.fsync(fd)
                            _checkpoint("stage_durable")
                            os.link(name, target_name, src_dir_fd=config, dst_dir_fd=config,
                                    follow_symlinks=False)
                            _checkpoint("target_linked")
                            os.fsync(config)
                            _checkpoint("target_durable")
                        finally:
                            os.close(fd)
                        record, target, stage = _owned(state, config)
                    if stage is not None:
                        # Keep exact inode evidence before the last private link
                        # disappears. A nonce-shaped public file alone is not proof.
                        record["inode"] = list(target[1])
                        _save(state, receipt_name, record)
                        _checkpoint("published_inode_durable")
                        os.unlink(_stage_name(record), dir_fd=config)
                        _checkpoint("stage_unlinked_before_sync")
                    # Also sync on retry after a crash between unlink and fsync.
                    os.fsync(config)
                    _checkpoint("stage_removed")
                    record["phase"], record["inode"] = "installed", list(target[1])
                    _save(state, receipt_name, record)
                    _checkpoint("installed_durable")
                    _owned(state, config)
                    return {"ownership": "owned"}
                if record is None:
                    return {"ownership": "absent"}
                record["phase"] = "removing"
                if target:
                    record["inode"] = list(target[1])
                _save(state, receipt_name, record)
                _checkpoint("removing_durable")
                if target:
                    os.unlink(target_name, dir_fd=config)
                    _checkpoint("target_unlinked_before_sync")
                    os.fsync(config)
                    _checkpoint("target_removed")
                if stage:
                    os.unlink(_stage_name(record), dir_fd=config)
                # An absent leaf observed after restart still needs a durable
                # directory barrier before forgetting its removal intent.
                os.fsync(config)
                os.unlink(receipt_name, dir_fd=state)
                os.fsync(state)
                _checkpoint("receipt_removed")
                return {"ownership": "absent"}


if __name__ == "__main__":
    need(len(sys.argv) == 2, "exactly one action required")
    try:
        print(json.dumps(run(sys.argv[1]), separators=(",", ":")))
    except (OSError, ValueError, UnicodeError, TypeError):
        print("NetworkManager owned policy operation refused", file=sys.stderr)
        sys.exit(1)

PY_NM_POLICY
}
networkmanager_validate() {
  python3 - "$@" <<'PY_NM_VALIDATE'
"""Draft embedded read-only NetworkManager policy validation; no mutations."""
import configparser
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import time

CONFIG_FILES = ("/etc/NetworkManager/NetworkManager.conf", "/var/lib/NetworkManager/NetworkManager-intern.conf")
CONFIG_DIRS = ("/usr/lib/NetworkManager/conf.d", "/run/NetworkManager/conf.d", "/etc/NetworkManager/conf.d")
IPV6_METHODS = ("auto", "dhcp", "manual", "disabled", "ignore", "link-local")


class Rejected(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Rejected("NetworkManager assessment: " + message)


def run(*args):
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
    try:
        data = child.stdout.read(262145)
        need(len(data) <= 262144, "command output exceeds bound")
        need(child.wait(timeout=10) == 0, "read-only command failed")
        return data.decode().strip()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def trusted(path, directory=False):
    path = pathlib.Path(path)
    for ancestor in (path, *path.parents):
        value = ancestor.lstat()
        need(not stat.S_ISLNK(value.st_mode) and value.st_uid == 0 and not value.st_mode & 0o022,
             "untrusted configuration or executable ancestry")
    value = path.stat()
    need(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode), "unexpected input type")
    if not directory:
        need(value.st_nlink == 1, "linked file is unsupported")
    return value


def configuration_snapshot():
    files = []
    for name in CONFIG_FILES:
        if pathlib.Path(name).exists() or pathlib.Path(name).is_symlink():
            files.append(pathlib.Path(name))
    for name in CONFIG_DIRS:
        directory = pathlib.Path(name)
        if not directory.exists() and not directory.is_symlink():
            continue
        trusted(directory, True)
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries):
                need(index < 128, "configuration directory exceeds bound")
                if entry.name.endswith(".conf"):
                    files.append(directory / entry.name)
    result = []
    total = 0
    for path in sorted(files):
        value = trusted(path)
        total += value.st_size
        need(value.st_size <= 65536 and total <= 262144, "configuration inputs exceed bound")
        result.append((str(path), value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns))
    return result


def unit_binary():
    value = run("systemctl", "show", "NetworkManager.service", "-p", "ExecStart", "--value")
    paths = re.findall(r"(?:^|[ {])path=([^;]+?)\s*;", value)
    arguments = re.findall(r"argv\[\]=([^;]+?)\s*;", value)
    need(len(paths) == len(arguments) == 1, "ambiguous service executable")
    binary = paths[0].strip()
    need(binary in ("/usr/sbin/NetworkManager", "/usr/bin/NetworkManager"), "nonstandard manager executable")
    need(arguments[0].strip().split() == [binary, "--no-daemon"], "manager arguments override reviewed configuration paths")
    trusted(binary)
    return binary


def process_identity(binary):
    pid = run("systemctl", "show", "NetworkManager.service", "-p", "MainPID", "--value")
    need(pid.isascii() and pid.isdecimal() and int(pid) > 1, "manager is not running")
    process = pathlib.Path("/proc") / pid
    raw = (process / "cmdline").read_bytes()
    need(len(raw) <= 4096 and raw.endswith(b"\0"), "manager arguments exceed bound")
    need(raw[:-1].split(b"\0") == [binary.encode(), b"--no-daemon"], "running manager has unreviewed arguments")
    executable = process / "exe"
    expected = pathlib.Path(binary).stat()
    actual = executable.stat()
    need(executable.resolve() == pathlib.Path(binary) and (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino), "running manager differs from verified executable")
    start = (process / "stat").read_text().rsplit(")", 1)[1].split()[19]
    return pid, start, actual.st_dev, actual.st_ino


def effective_internal(binary, required):
    before = configuration_snapshot()
    text = run(binary, "--print-config")
    need(before == configuration_snapshot(), "configuration changed during assessment")
    parser = configparser.ConfigParser(interpolation=None, strict=True, inline_comment_prefixes=None)
    parser.read_string(text)
    need(not parser.defaults(), "ambiguous default configuration section")
    value = parser.get("main", "dhcp", fallback=None)
    need(value is None or value == "internal", "explicit external or unknown DHCP client is unsupported")
    need(not required or value == "internal", "owned explicit internal DHCP policy is not effective")
    return value == "internal", before


def connection(uplink):
    uuid = run("nmcli", "--terse", "--escape", "no", "--get-values", "GENERAL.CON-UUID", "device", "show", uplink)
    need(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", uuid), "active connection UUID is missing")
    def setting(name):
        return run("nmcli", "--terse", "--escape", "no", "--get-values", name, "connection", "show", "uuid", uuid)
    kind = setting("connection.type")
    need(kind in ("802-3-ethernet", "802-11-wireless"), "unsupported uplink connection type")
    interface = setting("connection.interface-name")
    need(interface in ("", uplink), "connection interface binding differs")
    need(setting("connection.autoconnect") == "yes", "boot requires an autoconnect connection")
    need(setting("connection.permissions") == "", "user-session-only connection is unsupported at boot")
    v4, v6 = setting("ipv4.method"), setting("ipv6.method")
    need(v4 in ("auto", "manual") and v6 in IPV6_METHODS, "shared or unknown IP methods are unsupported")
    return {"connection_type": kind, "connection_interface": interface,
            "manager_connection_uuid": uuid, "manager_ipv4_method": v4, "manager_ipv6_method": v6,
            "dhcp4": v4 == "auto", "dhcp6": v6 in ("auto", "dhcp")}



def applied_connection(uplink):
    device = run("nmcli", "--terse", "--escape", "no", "--get-values", "GENERAL.DBUS-PATH", "device", "show", uplink)
    need(re.fullmatch(r"/org/freedesktop/NetworkManager/Devices/[0-9]+", device), "unrecognized device object")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate applied-connection field")
            result[key] = value
        return result
    # GetAppliedConnection is read-only. No full connection or secret-bearing
    # command output is ever logged, persisted or returned from this function.
    text = run("busctl", "--system", "--json=short", "--auto-start=no",
               "--allow-interactive-authorization=no", "--timeout=5s", "call",
               "org.freedesktop.NetworkManager", device,
               "org.freedesktop.NetworkManager.Device", "GetAppliedConnection", "u", "0")
    reply = json.loads(text, object_pairs_hook=unique)
    need(set(reply) == {"type", "data"} and reply["type"] == "a{sa{sv}}t", "unexpected applied-connection reply type")
    need(type(reply["data"]) is list and len(reply["data"]) == 2, "invalid applied-connection reply")
    settings, version = reply["data"]
    need(type(settings) is dict and type(version) is int and 0 <= version < 2**64, "invalid applied-connection version")
    def value(section, key, default=None):
        group = settings.get(section)
        need(type(group) is dict, "missing applied settings group")
        if key not in group:
            need(default is not None, "missing applied setting")
            return default
        item = group[key]
        need(type(item) is dict and set(item) == {"type", "data"} and item["type"] == "s" and type(item["data"]) is str, "invalid applied setting type")
        return item["data"]
    uuid = value("connection", "uuid")
    need(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", uuid), "invalid applied UUID")
    kind, interface = value("connection", "type"), value("connection", "interface-name", "")
    need(kind in ("802-3-ethernet", "802-11-wireless"), "unsupported applied connection type")
    need(interface in ("", uplink), "applied interface differs")
    v4, v6 = value("ipv4", "method"), value("ipv6", "method")
    need(v4 in ("auto", "manual") and v6 in IPV6_METHODS, "unsupported applied IP methods")
    return version, {"connection_type": kind, "connection_interface": interface,
                     "manager_connection_uuid": uuid, "manager_ipv4_method": v4, "manager_ipv6_method": v6,
                     "dhcp4": v4 == "auto", "dhcp6": v6 in ("auto", "dhcp")}


def validate(mode, uplink, expected=None):
    need(os.geteuid() == 0, "root is required")
    need(mode in ("plan", "disk", "live"), "unknown assessment mode")
    need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", uplink) and uplink not in ("lo", "aegis-tun0"), "invalid uplink")
    binary = unit_binary()
    identity = process_identity(binary) if mode != "disk" else None
    explicit, snapshot = effective_internal(binary, mode != "plan")
    result = {} if mode == "disk" else connection(uplink)
    if mode == "plan" and expected is not None:
        need(all(result[k] == v for k, v in expected.items()), "stored connection changed from candidate policy")
    applied = None
    if mode == "live":
        applied = applied_connection(uplink)
        need(all(result[k] == applied[1][k] for k in ("connection_type", "connection_interface")),
             "stored and applied connection type or interface differs")
        need(expected is not None and all(result[k] == v and applied[1][k] == v for k, v in expected.items()), "stored or applied connection differs from assessed boot policy")
        result = applied[1].copy()
    need(snapshot == configuration_snapshot(), "configuration changed after assessment")
    if applied is not None:
        need(applied == applied_connection(uplink), "applied connection changed during assessment")
    if identity is not None:
        need(identity == process_identity(binary), "manager restarted during assessment")
    # Internal comparison fields do not change the versioned guard-state API.
    result.pop("connection_type", None)
    result.pop("connection_interface", None)
    result.update(schema="aegis_networkmanager_assessment_v1", explicit_internal=explicit)
    return result


def main():
    def timeout(*_):
        raise TimeoutError("NetworkManager assessment exceeded 30 seconds")
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(30)
    mode, uplink = sys.argv[1:3]
    if mode == "ready": signal.alarm(45)
    expected = None
    if len(sys.argv) == 6:
        expected = {"manager_connection_uuid": sys.argv[3], "manager_ipv4_method": sys.argv[4], "manager_ipv6_method": sys.argv[5]}
    if mode == "ready":
        # NM Type=dbus may announce startup before the intended uplink is
        # applied. Wait only inside its bounded ExecStartPost, never bless a
        # stored profile or a stale receipt as a live applied-policy proof.
        while True:
            try:
                result = validate("live", uplink, expected)
                break
            except (Rejected, FileNotFoundError):
                time.sleep(1)
    else:
        result = validate(mode, uplink, expected)
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Rejected as error:
        raise SystemExit(str(error))
    except Exception as error:
        # Never print configuration contents through parser error diagnostics.
        raise SystemExit("NetworkManager assessment rejected unavailable or malformed input (" + type(error).__name__ + ")")

PY_NM_VALIDATE
}

inactive_ufw_assessment() {
  python3 - <<'PY_INACTIVE_UFW'
"""Admit only the reviewed disabled Ubuntu UFW boot no-op; never stop UFW."""
import hashlib,json,os,pathlib,re,shutil,stat,subprocess
ROOT=pathlib.Path('/')
OWNER_UID=0
DIGESTS={
 'usr/lib/systemd/system/ufw.service':'efece4d41e747407ed7a02d217420cef9aa60ee84326a145de528400dc63419d',
 'usr/lib/ufw/ufw-init':'c98f19dd0a68e94f729acdcba34fe48244dbfacdfa8943f257215d2ae351f80a',
}
def need(ok,message):
 if not ok: raise ValueError('Inactive UFW assessment: '+message)
def read(relative):
 p=ROOT/relative
 for item in (p,*p.parents):
  st=item.lstat()
  need(not stat.S_ISLNK(st.st_mode) and st.st_uid==OWNER_UID and not st.st_mode&0o022,'untrusted policy path')
  if item==ROOT:break
 st=p.stat();need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=65536,'invalid policy file')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  actual=os.fstat(f.fileno());need((actual.st_dev,actual.st_ino)==(st.st_dev,st.st_ino),'policy file changed')
  data=f.read(65537);need(len(data)<=65536,'oversized policy file')
 return data

def run(*args):
 return subprocess.run(args,check=True,capture_output=True,text=True,timeout=3,env={**os.environ,'LC_ALL':'C'}).stdout.strip()
def main():
 need(os.geteuid()==OWNER_UID,'root required')
 before={name:read(name) for name in (*DIGESTS,'etc/ufw/ufw.conf')}
 for name,digest in DIGESTS.items():
  need(hashlib.sha256(before[name]).hexdigest()==digest,'unreviewed UFW unit or init')
 config={}
 need(all(c in (9,10) or 32<=c<=126 for c in before['etc/ufw/ufw.conf']),'nonliteral UFW configuration')
 for raw in before['etc/ufw/ufw.conf'].decode().splitlines():
  line=raw.strip()
  if not line or line.startswith('#'):continue
  key,sep,value=line.partition('=')
  need(sep and key in ('ENABLED','LOGLEVEL') and key not in config,'unsupported UFW configuration')
  config[key]=value
 need(config.get('ENABLED')=='no','UFW firewall is enabled')
 need(config.get('LOGLEVEL','off') in ('off','low','medium','high','full'),'unsupported UFW log level')
 properties={}
 for line in run('systemctl','show','ufw.service','-p','FragmentPath','-p','DropInPaths','-p','NeedDaemonReload').splitlines():
  k,sep,v=line.partition('=');need(sep and k not in properties,'invalid unit properties');properties[k]=v
 need(properties.get('FragmentPath')=='/usr/lib/systemd/system/ufw.service' and properties.get('DropInPaths')=='' and properties.get('NeedDaemonReload')=='no','custom or stale UFW unit')
 # Include both xtables backends: an inactive config must not hide residual rules.
 for command in ('iptables-save','ip6tables-save','iptables-legacy-save','ip6tables-legacy-save'):
  if command in ('iptables-save','ip6tables-save') or shutil.which(command):need(not re.search(r'ufw6?-',run(command),re.I),'residual UFW rules')
 rules=json.loads(run('nft','--json','list','ruleset'))
 need(isinstance(rules,dict) and isinstance(rules.get('nftables'),list),'invalid nftables state')
 need(not re.search(r'ufw6?-',json.dumps(rules),re.I),'residual UFW rules')
 need(all(read(name)==data for name,data in before.items()),'policy changed during assessment')
 print(json.dumps({'schema':'aegis_inactive_ufw_v1','enabled':False,'service_mutated':False,'rules_mutated':False}))
if __name__=='__main__':
 try:main()
 except Exception as e:raise SystemExit('Inactive UFW assessment rejected ('+type(e).__name__+'): '+str(e) if isinstance(e,ValueError) else 'Inactive UFW assessment rejected unavailable input')
PY_INACTIVE_UFW
}

# Closed timing only; builtins and a proc read add no child or authority.
private_bind_step() {
  [[ "$ACTION" == bind && -n "${AUTO_PRIVATE_UNIT:-}" ]] || return 0
  local step="$1" seconds fraction ignored
  case "$step" in bindings_begin|bindings_end|rules_begin|rules_end|foreign_request|foreign_reply|binding_written|seal_request|seal_reply) :;; *) return 1;; esac
  IFS=' .' read -r seconds fraction ignored < /proc/uptime || return 0
  [[ "$seconds" =~ ^[0-9]{1,12}$ && "$fraction" =~ ^[0-9]{2}$ ]] || return 0
  printf 'aegis_auto_bind_helper_step {"step":"%s","monotonic_cs":%d}\n' "$step" "$((10#$seconds * 100 + 10#$fraction))" >&2 || :
  return 0
}

# The private ControlPID's bounded client of its original FD8 BIND channel.
# It keeps aegis_auto_guardian.py bind_seal_client's request schema, reply
# checks, seven-second deadline and channel exactly; this installed helper,
# whose own digest the guardian install receipt pins, carries it so that no
# private bind compiles the whole guardian per request (G0a: +61.8 ms per
# spawn). The host guardian still authenticates the channel and decides.
private_bind_client() {
  [[ "$1" == bind-seal || "$1" == bind-foreign-assess ]] || return 2
  python3 -I -B - "$1" <<'PY_BIND_CLIENT'
import array,json,os,re,socket,sys,time
from pathlib import Path
MAX_REQUEST=8192
PRIVATE_UNIT=re.compile(r"aegis-auto@[0-9a-f]{64}\.service\Z")
HEX32=re.compile(r"[0-9a-f]{32}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
class Refused(RuntimeError):
    pass
def need(value,reason):
    if not value:raise Refused(reason)
def unique(pairs):
    result={}
    for key,value in pairs:
        need(key not in result,"duplicate_json_key");result[key]=value
    return result
def receive_no_fds(peer):
    payload,ancillary,flags,_address=peer.recvmsg(MAX_REQUEST,socket.CMSG_SPACE(4),getattr(socket,"MSG_CMSG_CLOEXEC",0))
    descriptors=array.array("i")
    try:
        for level,kind,data in ancillary:
            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                descriptors.frombytes(data[:len(data)-len(data)%descriptors.itemsize])
        need(not ancillary and flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC)==0,"unexpected_lease_ancillary_or_truncation")
        return payload
    finally:
        for descriptor in descriptors:os.close(descriptor)
def bind_seal_client(fd,*,foreign_only=False):
    need(fd==8,"bind_seal_fd_invalid")
    unit=os.environ.get("AEGIS_AUTO_PRIVATE_UNIT")
    invocation=os.environ.get("INVOCATION_ID")
    need(type(unit) is str and PRIVATE_UNIT.fullmatch(unit) is not None and
         type(invocation) is str and HEX32.fullmatch(invocation) is not None,
         "bind_seal_identity_invalid")
    with socket.socket(fileno=os.dup(fd)) as peer:
        need(peer.family==socket.AF_UNIX and
             peer.type&socket.SOCK_SEQPACKET==socket.SOCK_SEQPACKET,
             "bind_seal_channel_invalid")
        deadline=time.monotonic()+7
        peer.settimeout(max(0.001,deadline-time.monotonic()))
        request={
            "schema":"aegis_auto_guardian_bind_foreign_v1" if foreign_only else "aegis_auto_guardian_bind_seal_v1",
            "command":"BIND_FOREIGN_ASSESS" if foreign_only else "BIND_SEAL","unit":unit,
            "boot_id":Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
            "invocation_id":invocation}
        raw=json.dumps(request,sort_keys=True,separators=(",",":")).encode()
        need(peer.send(raw)==len(raw),"bind_seal_send_failed")
        need(time.monotonic()<deadline,"bind_seal_deadline_elapsed")
        peer.settimeout(max(0.001,deadline-time.monotonic()))
        reply=receive_no_fds(peer)
        need(time.monotonic()<deadline,"bind_seal_deadline_elapsed")
        value=json.loads(reply,object_pairs_hook=unique)
        field="foreign_projection_sha256" if foreign_only else "policy_sha256"
        schema="aegis_auto_guardian_foreign_assessed_v1" if foreign_only else "aegis_auto_guardian_bind_sealed_v1"
        need(type(value) is dict and
             set(value)=={"schema","unit","boot_id","invocation_id",field} and
             value["schema"]==schema and
             value["unit"]==unit and
             value["boot_id"]==request["boot_id"] and
             value["invocation_id"]==invocation and
             type(value[field]) is str and
             HEX64.fullmatch(value[field]) is not None,
             "bind_seal_ack_invalid")
need(len(sys.argv)==2 and sys.argv[1] in ("bind-seal","bind-foreign-assess"),"fixed_bind_client_command_required")
bind_seal_client(8,foreign_only=sys.argv[1]=="bind-foreign-assess")
PY_BIND_CLIENT
}

foreign_assessment() {
  if [[ "$ACTION" == bind && -n "${AUTO_PRIVATE_UNIT:-}" ]]; then
    # CAP_BPF/SYS_ADMIN are deliberately absent in the private ControlPID.
    # The host guardian validates the candidate kernel grant under the same
    # original FD9 lease before either binding receipt can be published.
    private_bind_step foreign_request
    local rc=0
    private_bind_client bind-foreign-assess || rc=$?
    private_bind_step foreign_reply
    return "$rc"
  fi
  # The same candidate binding DTOs as write_binding are passed in memory;
  # no grant receipt is published before this full semantic readback succeeds.
  python3 -I -B - "$(dirname "${BASH_SOURCE[0]}")/lib" "${1:-${uplink:-}}" "${STATE}" "${capture_profile:-full-wide-tun}" "${boot_id:-}" "${state_digest:-}" "${client_path:-}" "${client_inode:-}" "${client_invocation:-}" "${manager_path:-}" "${manager_inode:-}" "${manager_invocation:-}" "$ACTION" "${manager_ifindex:-}" "${manager_dhcp4_server:-}" "${manager_dhcp6_server:-}" <<'PY_FOREIGN'
import json,pathlib,sys
sys.path.insert(0,str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
import aegis_auto_foreign_policy as foreign
_,_,uplink,state,mode,boot,sha,*tail=sys.argv
fields,action,ifindex,server4,server6=tail[:6],*tail[6:]
if action=="capture-bind":
 import os
 import aegis_auto_guardian as guardian
 descriptor=os.environ.get("AEGIS_AUTO_CAPTURE_BPF_FD", "")
 nonce=os.environ.get("AEGIS_AUTO_CAPTURE_BPF_NONCE", "")
 if descriptor:
  guardian.need(descriptor.isascii() and descriptor.isdecimal() and
                str(int(descriptor))==descriptor, "capture_bpf_descriptor_invalid")
  foreign._privileged_bpf_query=lambda interfaces: guardian.capture_bind_bpf_client(
      9,int(descriptor),nonce,interfaces)

bindings=None
if boot and sha:
 bindings={}
 for role,values in (("client",fields[:3]),("manager",fields[3:])):
  path,inode,invocation=values
  if path:
   binding=dict(schema="aegis_device_guard_binding_v1",boot_id=boot,state_sha256=sha,path=path,inode=inode,invocation=invocation)
   if role=="manager":
    binding.update(schema="aegis_device_guard_binding_v2",ifindex=int(ifindex),
                   dhcp4_server=server4 or None,dhcp6_server=server6 or None)
   bindings[role]=binding
  else:bindings[role]=None
print(json.dumps(foreign.assess_foreign_policy(uplink,mode=mode or "full-wide-tun",state_path=pathlib.Path(state),binding_overrides=bindings,require_guard=action in ("block","block-rotation","bind","bind-manager","capture-bind","capture-bind-legacy","refresh-manager-lease"),expected_state_sha256=sha or None),sort_keys=True))
PY_FOREIGN
}
if [[ "$ACTION" == assess-foreign-policy ]]; then
  foreign_assessment "${2:-}"
  exit $?
fi

if [[ "$ACTION" == assess-inactive-ufw ]]; then
  inactive_ufw_assessment
  exit $?
fi

# The pre-enrollment assessor must not create a guard state, key, lock or
# ownership receipt. The storage inspector itself is read-only.
if [[ "$ACTION" == assess-networkmanager ]]; then
  networkmanager_policy inspect >/dev/null || exit 1
  networkmanager_validate plan "${2:-}"
  exit $?
fi
. "$(dirname "${BASH_SOURCE[0]}")/lib/root-state.sh"
aegis_root_state_init || exit 1
fail() { echo "ERROR: device guard: $*" >&2; exit 1; }
[[ "$ACTION" =~ ^(preflight|prepare-nm-policy|recover-nm-policy|block|block-rotation|bind|bind-manager|capture-bind|capture-bind-legacy|manager-ready|refresh-manager-lease|refresh-manager-lease-service|manager-status|status|release|recover)$ ]] || fail 'unsupported guard action'
for tool in nft ip python3 flock; do command -v "$tool" >/dev/null || fail "$tool is required"; done
# Every v2 candidate/final state shares this administrative transaction lock.
# Orphan policy cleanup runs before state loading, but may not touch an active
# guard, an explicit-release record or staged boot ownership.
GLOBAL_LOCK=/var/lib/aegis-install/client/device-guard.conf.lock
LEASE_SPLIT_MARKER=${GLOBAL_LOCK%.lock}.auto-lease-split
AUTO_STOP_INTENT=/var/lib/aegis-install/client/auto-stop-intent.json
AUTO_GUARDIAN=/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py
AUTO_INSTALL=/var/lib/aegis-install/client/auto-guardian-install.json
AUTO_POLICY=/var/lib/aegis-install/client/auto-guardian-policy.json
AUTO_PRIVATE_UNIT=${AEGIS_AUTO_PRIVATE_UNIT:-}
if [[ -n "$AUTO_PRIVATE_UNIT" ]]; then
  [[ "$ACTION" == bind && "${AEGIS_AUTO_HELD_GUARD_FD:-}" == 9 &&
     "${AEGIS_AUTO_HELD_BIND_SOCKET_FD:-}" == 8 &&
     "$AUTO_PRIVATE_UNIT" =~ ^aegis-auto@[a-f0-9]{64}\.service$ ]] || fail 'foreign AUTO private unit binding'
fi
auto_stop_pending() {
  [[ -e "$AUTO_STOP_INTENT" || -L "$AUTO_STOP_INTENT" ]]
}
auto_seal_policy() {
  [[ "$schema" == aegis_device_guard_v2 ]] || return 0
  if [[ ! -e "$AUTO_INSTALL" && ! -L "$AUTO_INSTALL" ]]; then
    [[ "$ACTION" == bind && -n "$AUTO_PRIVATE_UNIT" ]] &&
      fail 'private bind has no installed guardian receipt'
    return 0
  fi
  [[ -f "$AUTO_GUARDIAN" && ! -L "$AUTO_GUARDIAN" ]] || fail 'installed AUTO guardian source unavailable'
  if [[ "$ACTION" == bind && -n "$AUTO_PRIVATE_UNIT" ]]; then
    # This ControlPID has no CAP_SYS_ADMIN and is in the private unit's mount
    # namespace. Its already authenticated BIND socket is inherited as FD8;
    # the installed host guardian seals the post-binding kernel/receipt state
    # synchronously. The caller re-blocks under FD9 if this ACK is absent.
    [[ "${AEGIS_AUTO_HELD_BIND_SOCKET_FD:-}" == 8 ]] || fail 'private bind seal channel unavailable'
    private_bind_step seal_request
    private_bind_client bind-seal ||
      fail 'private bind host semantic seal refused'
    private_bind_step seal_reply
    return 0
  fi
  # The production installer first applies a blocking candidate in its
  # private staging directory, then publishes the final armed state and
  # starts the fixed guard unit.  Admit the newly installed unit generation
  # while the guardian is stopped; only the final named state can be sealed.
  if [[ "$STATE" == /var/lib/aegis-install/client/device-guard.conf ]]; then
    # Compile the installed guardian once. Both commands retain their original
    # source/ownership checks; the same FD9 spans upgrade and semantic seal.
    python3 -I -B "$AUTO_GUARDIAN" upgrade-and-seal-policy 9 |
      aegis_root_write "$AUTO_POLICY" 0600 || fail 'installed AUTO policy seal failed; block retained'
  else
    python3 -I -B "$AUTO_GUARDIAN" upgrade-guard >/dev/null ||
      fail 'installed AUTO guard generation upgrade refused; block retained'
  fi
}
lease_split_present() {
  [[ -e "$LEASE_SPLIT_MARKER" || -L "$LEASE_SPLIT_MARKER" ]]
}
lease_split_exact() {
  # Command substitution would strip trailing newlines and admit foreign bytes.
  # The root metadata reader validates the whole owned regular generation.
  aegis_root_read "$LEASE_SPLIT_MARKER" | cmp -s - <(printf 'capture-recovery-in-progress-v1\n') || fail 'lease split marker unknown or unreadable; recovery required'
}
lease_split_check_if_present() {
  if lease_split_present; then lease_split_exact; fi
}
lease_split_mark() {
  # A prior uncertain retry may not erase or replace a different marker.
  if ! lease_split_present; then
    printf 'capture-recovery-in-progress-v1\n' | aegis_root_write "$LEASE_SPLIT_MARKER" 0600 || fail 'cannot mark lease split'
  fi
  lease_split_exact
}
lease_split_clear_if_present() {
  if lease_split_present; then
    lease_split_exact
    aegis_root_remove "$LEASE_SPLIT_MARKER" || fail 'cannot clear completed lease split'
  fi
}
open_guard_lock() {
  local path="$1"
  if [[ ( "$ACTION" == block || "$ACTION" == block-rotation || "$ACTION" == bind || "$ACTION" == capture-bind ) && -n "${AEGIS_AUTO_HELD_GUARD_FD:-}" ]]; then
    [[ "$AEGIS_AUTO_HELD_GUARD_FD" =~ ^[0-9]{1,4}$ &&
       ( ( "$schema" == aegis_device_guard_v2 && "$path" == "$GLOBAL_LOCK" ) ||
         ( "$schema" == aegis_device_guard_v1 && "$ACTION" == block &&
           "$path" == "$STATE.lock" ) ) ]] || fail 'invalid inherited guard lock'
    python3 - "$AEGIS_AUTO_HELD_GUARD_FD" "$path" <<'PY_AUTO_LOCK' || fail 'inherited AUTO guard lock is not original held OFD'
import os,re,stat,sys
fd=int(sys.argv[1]);path=sys.argv[2]
a=os.fstat(fd);b=os.stat(path,follow_symlinks=False)
assert stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o600
assert (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)
info=open(f'/proc/self/fdinfo/{fd}',encoding='ascii').read()
assert len(info)<=4096
locks=[line.split() for line in info.splitlines() if line.startswith('lock:')]
assert len(locks)==1
fields=locks[0]
assert len(fields)==9 and fields[0]=='lock:' and re.fullmatch(r'[1-9][0-9]*:',fields[1])
assert fields[2:5]==['FLOCK','ADVISORY','WRITE'] and re.fullmatch(r'[0-9]+',fields[5])
assert fields[7:]==['0','EOF']
device=re.fullmatch(r'([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)',fields[6])
assert device and (int(device[1],16),int(device[2],16),int(device[3]))==(os.major(a.st_dev),os.minor(a.st_dev),a.st_ino)
PY_AUTO_LOCK
    exec 9<&"$AEGIS_AUTO_HELD_GUARD_FD"
    return 0
  fi
  aegis_root_validate "$path" || fail 'untrusted lock'
  if [[ ! -e "$path" ]]; then
    (umask 077; set -o noclobber; : > "$path") 2>/dev/null || [[ -f "$path" ]] || fail 'cannot create lock'
  fi
  aegis_root_validate "$path" || fail 'untrusted lock'
  exec 9<"$path"
}
if [[ "$ACTION" == recover-nm-policy ]]; then
  [[ "$STATE" == /var/lib/aegis-install/client/device-guard.conf ]] || fail 'orphan recovery requires the standard state path'
  open_guard_lock "$GLOBAL_LOCK"
  flock -w 30 -x 9 || fail 'orphan recovery lock timed out'
  [[ ! -e "$STATE" && ! -L "$STATE" ]] || fail 'existing guard record requires ordinary explicit recovery'
  for file in /etc/systemd/system/aegis-auto-clean-shutdown.service /etc/systemd/system/aegis-device-dhcp-refresh.service /etc/systemd/system/aegis-device-dhcp-refresh.timer /etc/systemd/system/aegis-foreign-policy-monitor.service /etc/systemd/system/aegis-device-egress-guard.service /etc/systemd/system/aegis-client.service.d/30-device-egress-guard.conf /etc/systemd/system/NetworkManager.service.d/30-aegis-device-guard.conf; do
    [[ ! -e "$file" && ! -L "$file" ]] || fail 'staged guard ownership requires assessment-based recovery'
  done
  nft --json list tables | python3 -c 'import json,sys; p=json.load(sys.stdin); assert isinstance(p,dict) and isinstance(p["nftables"],list); assert all("table" not in x or x["table"].get("family")!="inet" or x["table"].get("name")!="aegis_device_guard" for x in p["nftables"])' || fail 'guard table exists or cannot be ruled out'
  networkmanager_policy remove || fail 'orphan owned policy cleanup failed'
  exit 0
fi
# The state is administrator-owned and parsed as data, never sourced/evaluated.
state_text="$(aegis_root_read "$STATE")" || fail 'missing or untrusted administrative state'
schema='' armed='' service='' uplink='' manager='' capture_interface='' capture_profile='' management_ipv4='' management_ipv6='' management_ports='' management_address_policy='' dhcp4='' dhcp6='' initramfs_network='' manager_connection_uuid='' manager_ipv4_method='' manager_ipv6_method='' foreign_policy='' ufw_integrity_sha256='' seen='|'
while IFS='=' read -r key value; do
  [[ -z "$key" ]] && continue
  [[ "$seen" != *"|$key|"* ]] || fail 'duplicate state field'
  seen+="$key|"
  case "$key" in
    schema) schema="$value";; armed) armed="$value";; service) service="$value";; uplink) uplink="$value";; manager) manager="$value";; capture_interface) capture_interface="$value";; capture_profile) capture_profile="$value";;
    management_ipv4) management_ipv4="$value";; management_ipv6) management_ipv6="$value";; management_ports) management_ports="$value";; management_address_policy) management_address_policy="$value";;
    manager_connection_uuid) manager_connection_uuid="$value";; manager_ipv4_method) manager_ipv4_method="$value";; manager_ipv6_method) manager_ipv6_method="$value";;
    foreign_policy) foreign_policy="$value";; ufw_integrity_sha256) ufw_integrity_sha256="$value";;
    dhcp4) dhcp4="$value";; dhcp6) dhcp6="$value";; initramfs_network) initramfs_network="$value";;
    *) fail 'unknown state field';;
  esac
done <<< "$state_text"
[[ "$schema" =~ ^aegis_device_guard_v[12]$ && "$armed" =~ ^[01]$ && "$service" == aegis-client.service ]] || fail 'invalid schema/armed/service'
[[ "$uplink" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ && "$uplink" != lo && "$uplink" != aegis-tun0 ]] || fail 'invalid uplink'
[[ "$capture_interface" == aegis-tun0 ]] || fail 'unsupported capture interface'
[[ "$manager" =~ ^(NetworkManager|systemd-networkd|networking)\.service$ ]] || fail 'unsupported network manager'
[[ "$dhcp4" =~ ^[01]$ && "$dhcp6" =~ ^[01]$ && "$initramfs_network" == absent_verified ]] || fail 'unverified bootstrap policy'
if [[ "$schema" == aegis_device_guard_v2 ]]; then
  [[ -z "$foreign_policy$ufw_integrity_sha256" || ( "$foreign_policy" == filter_only && "$ufw_integrity_sha256" =~ ^[a-f0-9]{64}$ ) ]] || fail 'invalid foreign policy assessment'
  [[ "$seen" != *'|capture_profile|'* || "$capture_profile" == full-wide-tun || "$capture_profile" == wide-redirect-safe ]] || fail 'unsupported capture profile'
  # Earlier v2 records omit this optional selector. The authenticated Python
  # policy already defines that representation as FullTun. Normalize only an
  # absent field after rejecting explicit empty/unknown values above, without
  # rewriting state_text or its binding digest.
  if [[ "$seen" != *'|capture_profile|'* ]]; then capture_profile=full-wide-tun; fi
  for field in schema armed service uplink manager capture_interface management_address_policy management_ports dhcp4 dhcp6 initramfs_network; do
    [[ "$seen" == *"|$field|"* ]] || fail 'missing required v2 state field'
  done
  [[ "$manager" =~ ^(systemd-networkd|NetworkManager)\.service$ && "$management_address_policy" == current_local ]] || fail 'v2 requires a reviewed manager and dynamic local management policy'
  if [[ "$manager" == NetworkManager.service ]]; then
    [[ "$manager_connection_uuid" =~ ^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$ && "$manager_ipv4_method" =~ ^(auto|manual)$ && "$manager_ipv6_method" =~ ^(auto|dhcp|manual|disabled|ignore|link-local)$ ]] || fail 'invalid NetworkManager connection policy'
    [[ ( "$manager_ipv4_method" == auto && "$dhcp4" == 1 ) || ( "$manager_ipv4_method" == manual && "$dhcp4" == 0 ) ]] || fail 'inconsistent NetworkManager DHCPv4 policy'
    [[ ( "$manager_ipv6_method" =~ ^(auto|dhcp)$ && "$dhcp6" == 1 ) || ( ! "$manager_ipv6_method" =~ ^(auto|dhcp)$ && "$dhcp6" == 0 ) ]] || fail 'inconsistent NetworkManager DHCPv6 policy'
  else
    [[ "$seen" != *'|manager_connection_uuid|'* && "$seen" != *'|manager_ipv4_method|'* && "$seen" != *'|manager_ipv6_method|'* ]] || fail 'NetworkManager fields on a different manager'
  fi
  [[ "$seen" != *'|management_ipv4|'* && "$seen" != *'|management_ipv6|'* ]] || fail 'v2 cannot contain stale management addresses'
  python3 - "$management_ports" <<'PY_PORTS' || fail 'invalid management ports'
import sys
ports=sys.argv[1].split(',') if sys.argv[1] else []
assert len(ports)<=8 and len(set(ports))==len(ports)
assert all(x.isascii() and x.isdecimal() and 1<=int(x)<=65535 and str(int(x))==x for x in ports)
PY_PORTS
else
  [[ "$seen" != *'|capture_profile|'* ]] || fail 'capture profile requires v2 state'
  [[ "$seen" != *'|management_address_policy|'* && "$seen" != *'|manager_connection_uuid|'* && "$seen" != *'|manager_ipv4_method|'* && "$seen" != *'|manager_ipv6_method|'* && "$ACTION" != bind-manager && "$ACTION" != manager-status && "$ACTION" != manager-ready && "$ACTION" != refresh-manager-lease && "$ACTION" != refresh-manager-lease-service && "$ACTION" != prepare-nm-policy ]] || fail 'v2 policy/action used with v1 state'
  # v1 predates capture_profile; its only supported capture is FullTun.
  capture_profile=full-wide-tun
python3 - "$management_ipv4" "$management_ipv6" "$management_ports" <<'PY' || fail 'invalid management policy'
import ipaddress,sys
v4,v6,ports=sys.argv[1:]
for value,version in [(v4,4),(v6,6)]:
    if value:
        assert "%" not in value  # nft addresses never accept zone-id/code suffixes
        a=ipaddress.ip_address(value)
        assert a.version==version and not (a.is_unspecified or a.is_multicast or a.is_loopback)
if ports:
    p=ports.split(',');assert len(p)<=8 and len(set(p))==len(p)
    assert all(x.isascii() and x.isdecimal() and 1<=int(x)<=65535 and str(int(x))==x for x in p)
    assert v4 or v6
PY
fi
if [[ "$ACTION" == release ]]; then
  [[ "$armed" == 0 ]] || fail 'explicit durable disarm is required before release'
elif [[ "$ACTION" != recover ]]; then
  [[ "$armed" == 1 ]] || fail 'guard is not armed'
fi
# Serialize guard transactions with a verified administrative lock file; no
# daemon-writable state or inherited arbitrary path can replace its inode.
if [[ "$schema" == aegis_device_guard_v2 ]]; then open_guard_lock "$GLOBAL_LOCK"; else open_guard_lock "$STATE.lock"; fi
lock_guard() {
  if [[ "$schema" == aegis_device_guard_v2 ]]; then flock -w 30 -x 9; else flock -x 9; fi
}
# Status and the service's lease probe create no authority. The service probe
# must run without waiting for an active capture's original guard OFD; it can
# only decide whether to invoke the installed, authenticated Stop path.
# An anonymous reader must not hold the exclusive mutation OFD: the live
# monitor can borrow that OFD only from authenticated PID1 mutation actors.
# Its read-only checks below instead require unchanged state/binding bytes.
if [[ "$ACTION" != manager-status && "$ACTION" != refresh-manager-lease-service ]]; then
  lock_guard || fail 'cannot lock guard within the supported transaction window'
fi
[[ "$(aegis_root_read "$STATE")" == "$state_text" ]] || fail 'state changed while waiting for lock; retry'
if [[ "$ACTION" != block ]] && auto_stop_pending; then
  fail 'AUTO stop intent retains deny; only block is permitted'
fi
if [[ "$ACTION" != block &&
      ( -e /var/lib/aegis-install/client/terminal-migrations/pending.json ||
        -L /var/lib/aegis-install/client/terminal-migrations/pending.json ) ]]; then
  fail 'AUTO terminal source migration retains deny'
fi
if [[ "$ACTION" != block &&
      ( -e /var/lib/aegis-install/client/terminal-migrations/cold-recovery/intent.json ||
        -L /var/lib/aegis-install/client/terminal-migrations/cold-recovery/intent.json ||
        ( ( -e /var/lib/aegis-install/client/terminal-migrations/cold-recovery/cold-config-intent.json ||
            -L /var/lib/aegis-install/client/terminal-migrations/cold-recovery/cold-config-intent.json ) &&
          ( ! -e /var/lib/aegis-install/client/terminal-migrations/cold-recovery/transition-ready.json ||
            -L /var/lib/aegis-install/client/terminal-migrations/cold-recovery/transition-ready.json ) ) ) ]]; then
  fail 'AUTO cold terminal recovery retains deny'
fi
if [[ "$ACTION" != block &&
      ( -e /var/lib/aegis-install/client/terminal-migrations/cold-recovery/rollover-barrier.json ||
        -L /var/lib/aegis-install/client/terminal-migrations/cold-recovery/rollover-barrier.json ) ]]; then
  fail 'AUTO cold rollover retains deny'
fi
if [[ "$schema" == aegis_device_guard_v2 && "$ACTION" != block &&
      "$ACTION" != manager-status && "$ACTION" != refresh-manager-lease-service ]]; then
  if [[ "$ACTION" == bind && -n "$AUTO_PRIVATE_UNIT" ]]; then
    # The installed host guardian verified this source under the original
    # held Guard OFD before its v2 SCM_RIGHTS handoff. The source-pinned
    # native ControlPID accepted that exact v2 proof before execing us; FD8
    # remains the live authenticated guardian channel for the final seal.
    [[ "${AEGIS_AUTO_HELD_GUARD_FD:-}" == 9 &&
       "${AEGIS_AUTO_HELD_BIND_SOCKET_FD:-}" == 8 ]] ||
      fail 'private bind host source handoff missing'
  else
    /usr/bin/python3 -I -B \
      /usr/local/lib/aegis/helpers/lib/aegis_auto_boot_transition.py \
      verify-consumed-under-guard 9 >/dev/null ||
      fail 'AUTO terminal current-boot source proof refused'
  fi
fi

networkmanager_check() {
  local mode="$1"
  [[ "$schema" == aegis_device_guard_v2 && "$manager" == NetworkManager.service ]] || return 0
  if [[ "$mode" == plan ]]; then networkmanager_policy inspect >/dev/null || return 1
  else networkmanager_policy verify >/dev/null || return 1; fi
  networkmanager_validate "$mode" "$uplink" "$manager_connection_uuid" "$manager_ipv4_method" "$manager_ipv6_method" >/dev/null
}

# Read the active manager lease, never an administrator-supplied destination.
# networkd exposes the DHCP server as ConfigProvider in its versioned D-Bus
# DescribeLink JSON (documented since systemd 251); NM exposes the accepted
# DHCP option through its D-Bus config.
# No address means acquisition is still in progress. Any conflicting active
# lease is an error, not a reason to keep a previous unicast grant.
lease_servers() {
  python3 -I - "$manager" "$uplink" "$manager_connection_uuid" "$dhcp4" "$dhcp6" <<'PY_LEASE'
import ipaddress,json,os,re,socket,subprocess,sys
manager,iface,uuid,dhcp4,dhcp6=sys.argv[1:]
def need(ok):
    if not ok: raise ValueError('manager lease identity or server changed')
def unique(pairs):
    result={}
    for key,value in pairs:
        need(key not in result)
        result[key]=value
    return result
def run(*argv):
    result=subprocess.run(argv,capture_output=True,timeout=3,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
    need(result.returncode==0 and len(result.stdout)<=65536 and
         len(result.stderr)<=4096)
    return result.stdout.decode('ascii')
def parse_ip(value,version,server=True):
    need(type(value) is str)
    address=ipaddress.ip_address(value)
    need(address.version==version and str(address)==value and
         not (address.is_unspecified or address.is_multicast or
              address.is_loopback or (server and version==4 and address.is_link_local)))
    return value
def array_ip(value,version):
    need(type(value) is list and len(value)==(4 if version==4 else 16) and
         all(type(part) is int and 0<=part<=255 for part in value))
    return parse_ip(str(ipaddress.ip_address(bytes(value))),version)
ifindex=socket.if_nametoindex(iface)
need(ifindex>0)
ip_rows=json.loads(run('/usr/sbin/ip','-j','address','show','dev',iface),
                  object_pairs_hook=unique)
need(type(ip_rows) is list and len(ip_rows)==1 and
     ip_rows[0].get('ifname')==iface and ip_rows[0].get('ifindex')==ifindex and
     type(ip_rows[0].get('addr_info')) is list)
locals_by_family={4:set(),6:set()}
for item in ip_rows[0]['addr_info']:
    need(type(item) is dict)
    if item.get('family') in ('inet','inet6'):
        version=4 if item['family']=='inet' else 6
        locals_by_family[version].add(parse_ip(item.get('local'),version,False))
server4=server6=None
if manager=='systemd-networkd.service':
    # v249 DescribeLink exists but omits lease-backed Addresses entirely.
    # v252 adds ConfigSource/ConfigProvider; reject older hosts before arm.
    release=run('/usr/bin/networkctl','--version').splitlines()[0]
    match=re.fullmatch(r'systemd ([0-9]{3})(?: .*)?',release)
    need(match is not None and int(match[1])>=252)
    outer=json.loads(run('/usr/bin/busctl','--system','--json=short',
      '--auto-start=no','--allow-interactive-authorization=no','--timeout=3s',
      'call','org.freedesktop.network1','/org/freedesktop/network1',
      'org.freedesktop.network1.Manager','DescribeLink','i',str(ifindex)),
      object_pairs_hook=unique)
    need(type(outer) is dict and set(outer)=={'type','data'} and
         outer['type']=='s' and type(outer['data']) is list and
         len(outer['data'])==1 and type(outer['data'][0]) is str)
    value=json.loads(outer['data'][0],object_pairs_hook=unique)
    need(type(value) is dict and value.get('Index')==ifindex and
         value.get('Name')==iface and type(value.get('Addresses',[])) is list)
    for version,source in ((4,'DHCPv4'),(6,'DHCPv6')):
        matches=[entry for entry in value.get('Addresses',[]) if
                 type(entry) is dict and entry.get('ConfigSource')==source]
        if not matches:continue
        need(len(matches)==1)
        entry=matches[0]
        local=array_ip(entry.get('Address'),version)
        need(local in locals_by_family[version])
        server=array_ip(entry.get('ConfigProvider'),version)
        if version==4:server4=server
        else:server6=server
elif manager=='NetworkManager.service':
    need(re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',uuid))
    actual=run('/usr/bin/nmcli','--terse','--escape','no','--get-values',
               'GENERAL.CON-UUID','device','show',iface).strip()
    need(actual==uuid)
    path=run('/usr/bin/nmcli','--terse','--escape','no','--get-values',
             'GENERAL.DBUS-PATH','device','show',iface).strip()
    need(re.fullmatch(r'/org/freedesktop/NetworkManager/Devices/[0-9]+',path))
    def property(object_path,interface,name):
        value=json.loads(run('/usr/bin/busctl','--system','--json=short',
          '--auto-start=no','--allow-interactive-authorization=no','--timeout=3s',
          'get-property','org.freedesktop.NetworkManager',object_path,
          interface,name),object_pairs_hook=unique)
        need(type(value) is dict and set(value)=={'type','data'})
        return value
    if dhcp4=='1':
        config=property(path,'org.freedesktop.NetworkManager.Device','Dhcp4Config')
        need(config['type']=='o' and type(config['data']) is str)
        if config['data']!='/':
            need(re.fullmatch(r'/org/freedesktop/NetworkManager/DHCP4Config/[0-9]+',
                              config['data']))
            options=property(config['data'],
                'org.freedesktop.NetworkManager.DHCP4Config','Options')
            need(options['type']=='a{sv}' and type(options['data']) is dict)
            def option(key):
                item=options['data'].get(key)
                need(type(item) is dict and set(item)=={'type','data'} and
                     item['type']=='s' and type(item['data']) is str)
                return item['data']
            server4=parse_ip(option('dhcp_server_identifier'),4)
            local=parse_ip(option('ip_address'),4)
            need(local in locals_by_family[4])
    # The DHCP6 DUID is not a destination address. Keep multicast unless a
    # versioned manager API can bind an actual unicast server to this device.
else:
    need(False)
need(socket.if_nametoindex(iface)==ifindex)
print(ifindex,server4 or 'none',server6 or 'none',sep='\t')
PY_LEASE
}

preflight_host() {
  [[ "$(stat -f -c %T /sys/fs/cgroup)" == cgroup2fs ]] || fail 'cgroup v2 required'
  [[ -d "/sys/class/net/$uplink" ]] || fail 'uplink missing'
  # Unsupported forwarding/container workloads are not silently disconnected.
  [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == 0 ]] || fail 'forwarding host is unsupported'
  if [[ "$capture_profile" != wide-redirect-safe || -e /proc/sys/net/ipv6/conf/all/forwarding || -e /proc/net/if_inet6 ]]; then
    [[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" == 0 ]] || fail 'forwarding host is unsupported'
  fi
  for link in /sys/class/net/*; do
    case "${link##*/}" in docker*|br-*|cni*|veth*|virbr*|flannel*|kube*) fail 'container/bridge interfaces are unsupported';; esac
  done
  for unit in docker.service containerd.service libvirtd.service kubelet.service firewalld.service nftables.service ufw.service; do
    if systemctl is-active --quiet "$unit" || systemctl is-enabled --quiet "$unit" || [[ "$unit" == ufw.service && ( -e /etc/ufw/ufw.conf || -L /etc/ufw/ufw.conf ) ]]; then
      if [[ "$unit" == ufw.service ]] && foreign_assessment >/dev/null; then continue; fi
      fail "active/enabled $unit conflicts with first-arm ownership"
    fi
  done
  systemctl is-active --quiet "$manager" || fail 'recorded network manager is not active'
  for unit in NetworkManager.service systemd-networkd.service networking.service; do
    [[ "$unit" != "$manager" ]] || continue
    if systemctl is-active --quiet "$unit" || systemctl is-enabled --quiet "$unit"; then
      fail 'multiple network managers require an explicit dependency integration'
    fi
  done
  [[ -r /proc/cmdline ]] || fail 'kernel command line unavailable'
  if grep -Eq '(^| )(ip=|rd.neednet=1|boot=nfs|root=/dev/nfs|nfsroot=)' /proc/cmdline || [[ -e /run/initramfs/net.ifaces || -e /run/initramfs/state/etc/network/interfaces ]]; then
    fail 'initramfs networking is unsupported'
  fi
  networkmanager_check plan || fail 'NetworkManager feasibility changed'
  if [[ "$schema" == aegis_device_guard_v2 ]]; then
    lease_servers >/dev/null || fail 'network manager lease metadata API is unsupported'
  fi
  # A missing explicit administrative assessment is rejected by the state parser.
  [[ "$schema" == aegis_device_guard_v1 ]] || return 0
  ip -j address show dev "$uplink" | python3 -c 'import json,sys; a=json.load(sys.stdin); wanted=set(filter(None,sys.argv[1:])); found={i["local"] for x in a for i in x.get("addr_info",[])}; assert wanted<=found' "$management_ipv4" "$management_ipv6" || fail 'management addresses do not belong to uplink'
}

# One coherent PID1 snapshot per existing checkpoint. Do not cache it across
# the nft transaction: every caller still performs its original fresh checks.
unit_active='' unit_group='' unit_invocation='' unit_control_pid=''
read_unit_identity() {
  local unit="$1" facts key value active_seen=0 group_seen=0 invocation_seen=0 control_seen=0
  unit_active=''; unit_group=''; unit_invocation=''; unit_control_pid=''
  facts="$(systemctl show "$unit" -p ActiveState -p ControlGroup -p InvocationID -p ControlPID --no-pager)" || return 1
  [[ ${#facts} -le 4096 ]] || return 1
  while IFS='=' read -r key value; do
    case "$key" in
      ActiveState) [[ "$active_seen" == 0 ]] || return 1; active_seen=1; unit_active="$value";;
      ControlGroup) [[ "$group_seen" == 0 ]] || return 1; group_seen=1; unit_group="$value";;
      InvocationID) [[ "$invocation_seen" == 0 ]] || return 1; invocation_seen=1; unit_invocation="$value";;
      ControlPID) [[ "$control_seen" == 0 ]] || return 1; control_seen=1; unit_control_pid="$value";;
      *) return 1;;
    esac
  done <<< "$facts"
  [[ "$active_seen$group_seen$invocation_seen$control_seen" == 1111 &&
     ( "$unit_active" == active || "$unit_active" == activating ) &&
     "$unit_invocation" =~ ^[a-f0-9]{32}$ &&
     "$unit_control_pid" =~ ^(0|[1-9][0-9]*)$ &&
     "$unit_group" == /* && "$unit_group" != / ]]
}

cgroup_path=''
cgroup_inode=''
resolve_bind_cgroup() {
  local reported own active
  read_unit_identity "$service" || fail 'cannot read current service identity'
  active="$unit_active"; reported="$unit_group"
  own="$(awk -F: '$1=="0" && $2=="" {print $3}' /proc/$$/cgroup)" || fail 'missing caller cgroup'
  [[ "$reported" == "$own" && "$reported" == /* && "$reported" != / ]] || fail 'bind must run inside the named service cgroup'
  cgroup_path="${reported#/}"
  [[ "$cgroup_path" =~ ^[A-Za-z0-9_.@:/-]+$ && "$cgroup_path" != */ && "$cgroup_path" != *//* && "/$cgroup_path/" != */../* && "/$cgroup_path/" != */./* ]] || fail 'invalid cgroup path'
  [[ "$(stat -f -c %T /sys/fs/cgroup)" == cgroup2fs && -d "/sys/fs/cgroup/$cgroup_path" ]] || fail 'cgroup v2 missing'
  cgroup_inode="$(stat -c %i "/sys/fs/cgroup/$cgroup_path")" || fail 'cannot read cgroup inode'
}

# v2 binding receipts never authorize a newly started unit by name alone. The
# caller must first bind inside that exact unit; subsequent table replacements
# preserve its permission only while the boot, state, InvocationID and inode
# all match. Receipt loss/corruption or restart therefore removes permission.
client_path='' client_inode='' client_invocation='' client_unit=''
manager_path='' manager_inode='' manager_invocation=''
manager_ifindex='' manager_dhcp4_server='' manager_dhcp6_server=''
resolved_path='' resolved_inode='' resolved_invocation=''
state_digest='' boot_id=''
boot_id="$(cat /proc/sys/kernel/random/boot_id)" || fail 'boot identity unavailable'
[[ "$boot_id" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]] || fail 'invalid boot identity'
if [[ "$schema" == aegis_device_guard_v2 ]]; then
  state_digest="$(printf '%s' "$state_text" | python3 -c 'import hashlib,sys;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')" || fail 'cannot bind administrative state'
fi
resolve_unit_cgroup() {
  local unit="$1" caller="$2" active reported own control_pid
  read_unit_identity "$unit" || return 1
  active="$unit_active"; reported="$unit_group"; resolved_invocation="$unit_invocation"
  [[ "$resolved_invocation" =~ ^[a-f0-9]{32}$ && "$reported" == /* && "$reported" != / ]] || return 1
  resolved_path="${reported#/}"
  [[ "$resolved_path" =~ ^[A-Za-z0-9_.@:/-]+$ && "$resolved_path" != */ && "$resolved_path" != *//* && "/$resolved_path/" != */../* && "/$resolved_path/" != */./* ]] || return 1
  if [[ "$caller" == 1 ]]; then
    own="$(awk -F: '$1=="0" && $2=="" {print $3}' /proc/$$/cgroup)" || return 1
    [[ "$reported" == "$own" ]] || return 1
    control_pid="$unit_control_pid"
    [[ "$control_pid" == "$$" ]] || return 1
  fi
  [[ "$(stat -f -c %T /sys/fs/cgroup)" == cgroup2fs && -d "/sys/fs/cgroup/$resolved_path" ]] || return 1
  resolved_inode="$(stat -c %i "/sys/fs/cgroup/$resolved_path")" || return 1
  [[ "$resolved_inode" =~ ^[1-9][0-9]*$ ]]
}
binding_marker() {
  python3 - "$boot_id" "$state_digest" "$1" "$2" "$3" "$4" <<'PY_MARKER'
import hashlib,json,sys
print("aegis-v2-"+hashlib.sha256(json.dumps(sys.argv[1:],separators=(",",":")).encode()).hexdigest())
PY_MARKER
}
kernel_binding_present() {
  local role="$1" path="$2" inode="$3" invocation="$4" marker expected=1 level binding_handles
  marker="$(binding_marker "$role" "$path" "$inode" "$invocation")" || return 1
  [[ "$role" != manager ]] || expected=$((dhcp4 + dhcp6))
  level="$(awk -F/ '{print NF}' <<< "$path")" || return 1
  binding_handles="$(nft --json list table inet "$TABLE" | python3 -c '
import json,sys
def unique(items):
    result={}
    for key,value in items:
        assert key not in result
        result[key]=value
    return result
payload=json.load(sys.stdin,object_pairs_hook=unique)
assert isinstance(payload,dict) and set(payload)=={"nftables"} and isinstance(payload["nftables"],list)
for item in payload["nftables"]:
    assert isinstance(item,dict) and len(item)==1 and next(iter(item)) in ("metainfo","table","chain","rule")
rules=[x["rule"] for x in payload["nftables"] if "rule" in x]
assert all(isinstance(r,dict) for r in rules)
for rule in rules:
    if rule.get("family")!="inet" or rule.get("table")!="aegis_device_guard" or rule.get("chain")!="output":
        continue
    expressions=rule.get("expr")
    assert isinstance(expressions,list)
    if any(e=={"accept":None} for e in expressions):
        # An accepting OUTPUT rule must be conditional. This check does not
        # establish equality of the complete native policy.
        assert any(isinstance(e,dict) and "match" in e for e in expressions)
matching=[r for r in rules if r.get("comment")==sys.argv[1]]
assert len(matching)==int(sys.argv[2])
handles=[r.get("handle") for r in matching]
assert all(type(h) is int and h > 0 for h in handles) and len(set(handles))==len(handles)
for rule in matching:
    assert rule.get("family")=="inet" and rule.get("table")=="aegis_device_guard" and rule.get("chain")=="output"
    expressions=rule.get("expr")
    assert isinstance(expressions,list) and expressions and expressions[-1]=={"accept":None}
    assert all(isinstance(e,dict) and len(e)==1 and next(iter(e)) in ("match","mangle","counter","accept") for e in expressions)
    mark=0xa361c002 if sys.argv[6]=="manager" else 0xa361c001
    assert [e["mangle"] for e in expressions if "mangle" in e]==[{"key":{"meta":{"key":"mark"}},"value":mark}]
    assert sum("accept" in e for e in expressions)==1
    socket_matches=[e["match"] for e in expressions if "match" in e and isinstance(e["match"],dict)
                    and isinstance(e["match"].get("left"),dict) and "socket" in e["match"]["left"]]
    assert len(socket_matches)==1
    socket=socket_matches[0]
    # nft 1.0.9 JSON elides cgroupv2 level. The handle-bound text readback
    # below must prove it; JSON alone cannot distinguish two different levels.
    assert socket.get("op")=="==" and socket.get("left") in (
        {"socket":{"key":"cgroupv2","level":int(sys.argv[4])}},
        {"socket":{"key":"cgroupv2"}},
    )
    assert set(socket)=={"op","left","right"}
    right=socket["right"]
    assert (type(right) is str and right==sys.argv[3]) or (type(right) is int and right==int(sys.argv[5]))
if sys.argv[6]=="manager":
    def eq(left,right):
        return {"op":"==","left":left,"right":right}
    wanted=[]
    if sys.argv[8]=="1": wanted.append(("ipv4",68,67,
        {"set":[sys.argv[10],"255.255.255.255"]} if sys.argv[10]!="none" else "255.255.255.255"))
    if sys.argv[9]=="1": wanted.append(("ipv6",546,547,
        {"set":[sys.argv[11],"ff02::1:2"]} if sys.argv[11]!="none" else "ff02::1:2"))
    observed=[]
    for rule in matching:
        matches=[e["match"] for e in rule["expr"] if "match" in e]
        # nft may emit the protocol dependency of udp sport/dport explicitly.
        implicit=eq({"meta":{"key":"l4proto"}},"udp")
        assert matches.count(implicit)<=1
        matches=[match for match in matches if match!=implicit]
        assert len(matches)==6
        family={"ip":"ipv4","ip6":"ipv6"}.get(
            matches[2].get("left",{}).get("payload",{}).get("protocol"))
        ports={"ipv4":(68,67),"ipv6":(546,547)}
        assert family in ports
        sport,dport=ports[family]
        destination=next(value[3] for value in wanted if value[0]==family)
        assert matches==[
            eq({"meta":{"key":"oifname"}},sys.argv[7]),
            eq({"meta":{"key":"oif"}},sys.argv[7]),
            eq({"payload":{"protocol":"ip" if family=="ipv4" else "ip6","field":"daddr"}},destination),
            eq({"payload":{"protocol":"udp","field":"sport"}},sport),
            eq({"payload":{"protocol":"udp","field":"dport"}},dport),
            socket,
        ]
        observed.append((family,sport,dport,destination))
    assert sorted(observed)==sorted(wanted)
print(",".join(str(h) for h in sorted(handles)))
' "$marker" "$expected" "$path" "$level" "$inode" "$role" "$uplink" "$dhcp4" "$dhcp6" "${manager_dhcp4_server:-none}" "${manager_dhcp6_server:-none}" "${manager_ifindex:-0}")" || return 1
  nft -a list table inet "$TABLE" | python3 -c '
import re,sys
marker,count,path,level,handles,role=sys.argv[1:]
expected=set(int(value) for value in handles.split(",") if value)
assert len(expected)==int(count)
marked=[line for line in sys.stdin if ("comment \""+marker+"\"") in line]
assert len(marked)==int(count)
seen=set()
for line in marked:
    rule=re.fullmatch(
        r"\s+.*\bsocket cgroupv2 level ([1-9][0-9]*) \"([^\"]+)\" "
        r"meta mark set (0x[0-9a-f]+|[0-9]+) counter packets [0-9]+ bytes [0-9]+ accept comment \""+re.escape(marker)+
        r"\" # handle ([1-9][0-9]*)\s*",line)
    assert rule is not None
    actual_level,actual_path,mark,handle=rule.groups()
    assert int(actual_level)==int(level) and actual_path==path
    assert int(mark,0)==(0xa361c002 if role=="manager" else 0xa361c001)
    assert int(handle) in expected and int(handle) not in seen
    seen.add(int(handle))
assert seen==expected
' "$marker" "$expected" "$path" "$level" "$binding_handles" "$role"
}
read_binding() {
  local role="$1" unit="$2" data parsed path inode invocation ifindex server4 server6
  data="$(aegis_root_read "$STATE.$role-binding")" 2>/dev/null || return 1
  parsed="$(printf '%s' "$data" | python3 -c '
import ipaddress,json,re,sys
x=json.load(sys.stdin)
base={"schema","boot_id","state_sha256","path","inode","invocation"}
manager=sys.argv[3]=="manager"
pinned=manager and x.get("schema")=="aegis_device_guard_binding_v2"
assert set(x)==(base|{"ifindex","dhcp4_server","dhcp6_server"} if pinned else base)
assert x["schema"]==("aegis_device_guard_binding_v2" if pinned else "aegis_device_guard_binding_v1") and x["boot_id"]==sys.argv[1] and x["state_sha256"]==sys.argv[2]
assert isinstance(x["path"],str) and re.fullmatch(r"[A-Za-z0-9_.@:/-]+",x["path"])
assert isinstance(x["inode"],str) and re.fullmatch(r"[1-9][0-9]*",x["inode"])
assert isinstance(x["invocation"],str) and re.fullmatch(r"[a-f0-9]{32}",x["invocation"])
if pinned:
    assert type(x["ifindex"]) is int and x["ifindex"]>0
    for key,version in (("dhcp4_server",4),("dhcp6_server",6)):
        value=x[key]
        assert value is None or type(value) is str
        if value is not None:
            address=ipaddress.ip_address(value)
            assert address.version==version and str(address)==value and not (address.is_unspecified or address.is_multicast or address.is_loopback or (version==4 and address.is_link_local))
print(x["path"],x["inode"],x["invocation"],x["ifindex"] if pinned else 0,
      x["dhcp4_server"] or "none" if pinned else "none",
      x["dhcp6_server"] or "none" if pinned else "none",sep="\t")
' "$boot_id" "$state_digest" "$role")" 2>/dev/null || return 1
  IFS=$'\t' read -r path inode invocation ifindex server4 server6 <<< "$parsed"
  if [[ "$role" == client && "$unit" == AUTO_FROM_RECEIPT ]]; then
    unit="${path##*/}"
    [[ "$unit" =~ ^aegis-auto@[a-f0-9]{64}\.service$ ]] || return 1
  fi
  resolve_unit_cgroup "$unit" 0 || return 1
  [[ "$path" == "$resolved_path" && "$inode" == "$resolved_inode" && "$invocation" == "$resolved_invocation" ]] || return 1
  if [[ "$role" == manager ]]; then
    [[ "$ifindex" == 0 || "$ifindex" == "$(cat "/sys/class/net/$uplink/ifindex")" ]] || return 1
    manager_ifindex="$ifindex"
    manager_dhcp4_server="$server4"; [[ "$manager_dhcp4_server" != none ]] || manager_dhcp4_server=''
    manager_dhcp6_server="$server6"; [[ "$manager_dhcp6_server" != none ]] || manager_dhcp6_server=''
  fi
  # A receipt whose permission was removed by block/emergency block is inert,
  # even if a filesystem failure prevented deleting that old receipt.
  kernel_binding_present "$role" "$path" "$inode" "$invocation" || return 1
  if [[ "$role" == client ]]; then client_unit="$unit"; fi
}
write_binding() {
  local role="$1" path="$2" inode="$3" invocation="$4"
  python3 - "$boot_id" "$state_digest" "$path" "$inode" "$invocation" "$role" "$manager_ifindex" "$manager_dhcp4_server" "$manager_dhcp6_server" <<'PY_BINDING' | aegis_root_write "$STATE.$role-binding" 0600 || fail 'binding receipt failed; no broader permission is recoverable'
import json,sys
boot,state,path,inode,invocation,role,ifindex,server4,server6=sys.argv[1:]
value=dict(schema="aegis_device_guard_binding_v1",boot_id=boot,state_sha256=state,
           path=path,inode=inode,invocation=invocation)
if role=="manager":
    assert ifindex.isascii() and ifindex.isdecimal() and int(ifindex)>0
    value.update(schema="aegis_device_guard_binding_v2",ifindex=int(ifindex),
                 dhcp4_server=server4 or None,dhcp6_server=server6 or None)
print(json.dumps(value,sort_keys=True,separators=(",",":")))
PY_BINDING
}
collect_v2_bindings() {
  # AUTO records a private unit in the same authenticated receipt. Probe that
  # owner first instead of parsing it twice and querying an unrelated inactive
  # aegis-client.service. Both paths retain all receipt/PID1/kernel checks.
  local -a client_units=("$service" AUTO_FROM_RECEIPT)
  if [[ -e "$AUTO_INSTALL" ]]; then client_units=(AUTO_FROM_RECEIPT "$service"); fi
  if read_binding client "${client_units[0]}" || read_binding client "${client_units[1]}"; then
    client_path="$resolved_path"; client_inode="$resolved_inode"; client_invocation="$resolved_invocation"
  fi
  if read_binding manager "$manager" && networkmanager_check disk; then
    manager_path="$resolved_path"; manager_inode="$resolved_inode"; manager_invocation="$resolved_invocation"
  fi
}
capture_binding_index_legacy() {
  # The ordinary named service has no AUTO guardian. Its Type=notify
  # ExecStartPost is the only mint authority; every later render reopens the
  # exact PID1/Main, executable, cgroup, TUN FD, host netns and numeric link.
  python3 -I -B - "$STATE.capture-binding" "$boot_id" "$1" "$$" <<'PY_LEGACY_CAPTURE'
import hashlib,json,os,re,select,socket,stat,subprocess,sys
from pathlib import Path

receipt=Path(sys.argv[1]);boot=sys.argv[2];mode=sys.argv[3];hook_pid=sys.argv[4]
unit='aegis-client.service';group='/system.slice/'+unit
def need(ok):
    if not ok: raise ValueError('legacy numeric capture owner refused')
def run(argv):
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,
                          timeout=3,check=False,env={'PATH':'/usr/sbin:/usr/bin:/bin',
                                                     'LANG':'C','LC_ALL':'C'})
    need(result.returncode==0 and len(result.stdout)<=4096 and
         len(result.stderr)<=4096)
    return result.stdout.decode('ascii')
raw=run(['/usr/bin/systemctl','show',unit,'--no-pager','-p','MainPID',
         '-p','ControlPID','-p','ActiveState','-p','SubState',
         '-p','InvocationID','-p','ControlGroup'])
facts={}
for line in raw.splitlines():
    key,sep,value=line.partition('=');need(sep=='=' and key not in facts)
    facts[key]=value
need(set(facts)=={'MainPID','ControlPID','ActiveState','SubState',
                  'InvocationID','ControlGroup'} and
     ((facts['ActiveState']=='active' and facts['SubState']=='running') or
      (facts['ActiveState']=='activating' and facts['SubState']=='start-post' and
       facts['ControlPID']==hook_pid)) and
     facts['ControlGroup']==group and
     re.fullmatch('[0-9a-f]{32}',facts['InvocationID']) is not None and
     re.fullmatch('[1-9][0-9]*',facts['MainPID']) is not None)
pid=int(facts['MainPID']);need(pid>1)
if mode=='mint':
    need(facts['ActiveState']=='activating' and
         facts['SubState']=='start-post' and
         facts['ControlPID']==hook_pid and
         Path(f'/proc/{hook_pid}/cgroup').read_text(encoding='ascii')==f'0::{group}\n')
pidfd=os.pidfd_open(pid,0)
try:
    fdinfo=Path(f'/proc/self/fdinfo/{pidfd}').read_text(encoding='ascii')
    need(len(fdinfo)<=4096 and
         sum(line==f'Pid:\t{pid}' for line in fdinfo.splitlines())==1 and
         not select.select([pidfd],[],[],0)[0])
    need(Path(f'/proc/{pid}/cgroup').read_text(encoding='ascii')==f'0::{group}\n')
    cgroup=Path('/sys/fs/cgroup')/group.lstrip('/')
    cg=cgroup.stat(follow_symlinks=False)
    need(stat.S_ISDIR(cg.st_mode) and cg.st_ino>0)
    netns=Path('/proc/1/ns/net').stat().st_ino
    need(netns>0 and Path(f'/proc/{pid}/ns/net').stat().st_ino==netns)
    binary=Path('/usr/local/bin/aegis-client')
    source=binary.stat(follow_symlinks=False)
    image=Path(f'/proc/{pid}/exe').stat()
    need(stat.S_ISREG(source.st_mode) and source.st_uid==0 and
         source.st_mode&0o022==0 and source.st_nlink==1 and
         0<source.st_size<=512<<20 and
         (source.st_dev,source.st_ino)==(image.st_dev,image.st_ino))
    identity=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_uid,
                           value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    digest=hashlib.sha256()
    binary_fd=os.open(binary,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        need(identity(os.fstat(binary_fd))==identity(source))
        with os.fdopen(binary_fd,'rb',closefd=False) as stream:
            for chunk in iter(lambda:stream.read(1<<20),b''):digest.update(chunk)
        need(identity(os.fstat(binary_fd))==identity(source) and
             identity(binary.stat(follow_symlinks=False))==identity(source))
    finally:os.close(binary_fd)
    descriptors=list(Path(f'/proc/{pid}/fd').iterdir())
    need(len(descriptors)<=4096)
    owns=False
    for descriptor in descriptors:
        if not descriptor.name.isdecimal(): continue
        try:
            if os.readlink(descriptor)!='/dev/net/tun':continue
            info=Path(f'/proc/{pid}/fdinfo/{descriptor.name}').read_text(encoding='ascii')
        except (FileNotFoundError,ProcessLookupError):continue
        need(len(info)<=4096)
        if any(line.partition(':')[0]=='iff' and
               line.partition(':')[2].strip()=='aegis-tun0'
               for line in info.splitlines()):owns=True;break
    need(owns)
    detail=json.loads(run(['/usr/sbin/ip','-j','-d','link','show','dev','aegis-tun0']))
    need(type(detail) is list and len(detail)==1 and
         detail[0].get('ifname')=='aegis-tun0' and
         detail[0].get('linkinfo',{}).get('info_kind')=='tun' and
         detail[0].get('linkinfo',{}).get('info_data',{}).get('type')=='tun' and
         detail[0].get('linkinfo',{}).get('info_data',{}).get('persist') is False)
    index=detail[0].get('ifindex')
    need(type(index) is int and index>0 and
         socket.if_nametoindex('aegis-tun0')==index and
         not select.select([pidfd],[],[],0)[0])
    expected={'schema':'aegis_device_guard_capture_binding_v1',
              'boot_id':boot,'netns_ino':netns,'private_unit':unit,
              'invocation_id':facts['InvocationID'],'main_pid':pid,
              'ifindex':index,'worker_sha256':digest.hexdigest(),
              'client_path':group.lstrip('/'),'client_inode':str(cg.st_ino),
              'client_invocation':facts['InvocationID']}
    if mode=='mint':
        need(not receipt.exists() and not receipt.is_symlink())
        print(json.dumps(expected,sort_keys=True,separators=(',',':')))
    else:
        need(mode=='verify')
        fd=os.open(receipt,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and
                 stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and
                 0<before.st_size<=4096)
            raw=os.read(fd,4097)
            need(len(raw)==before.st_size and
                 identity(os.fstat(fd))==identity(before) and
                 identity(receipt.stat(follow_symlinks=False))==identity(before))
        finally:os.close(fd)
        def unique(pairs):
            value={}
            for key,item in pairs:need(key not in value);value[key]=item
            return value
        need(json.loads(raw,object_pairs_hook=unique)==expected)
        print(index)
finally:os.close(pidfd)
PY_LEGACY_CAPTURE
}
verify_v2_bindings() {
  if [[ -n "$client_path" ]]; then
    resolve_unit_cgroup "$client_unit" "$([[ "$ACTION" == bind ]] && echo 1 || echo 0)" && [[ "$client_path" == "$resolved_path" && "$client_inode" == "$resolved_inode" && "$client_invocation" == "$resolved_invocation" ]] || return 1
  fi
  if [[ -n "$manager_path" ]]; then
    networkmanager_check disk || return 1
    resolve_unit_cgroup "$manager" "$([[ "$ACTION" == bind-manager ]] && echo 1 || echo 0)" && [[ "$manager_path" == "$resolved_path" && "$manager_inode" == "$resolved_inode" && "$manager_invocation" == "$resolved_invocation" ]] || return 1
  fi
}

# This parser is deliberately self-contained: the ControlPID helper must not
# import a sibling Python module outside the installed guardian's verified
# loader. The same protected INTENT/PREPARED chain is checked by the source-
# pinned semantic verifier after the atomic nft transaction.
scoped_reply_fields() {
  python3 -I - "$client_unit" "$client_path" "$client_inode" "$client_invocation" "$boot_id" <<'PY_SCOPED_REPLY'
import hashlib,ipaddress,json,os,re,socket,stat,subprocess,sys

unit,path,inode,invocation,boot=sys.argv[1:]
parent='/var/lib/aegis-install/client'
fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
def need(ok):
    if not ok: raise ValueError('scoped reply authority changed')
def unique(pairs):
    value={}
    for key,item in pairs:
        need(key not in value)
        value[key]=item
    return value
def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def read(name):
    child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
    try:
        before=os.fstat(child)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and
             stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and
             0<before.st_size<=16384)
        raw=os.read(child,16385)
        after=os.fstat(child)
        named=os.stat(name,dir_fd=fd,follow_symlinks=False)
        identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_nlink,
                           x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        need(len(raw)==before.st_size and identity(before)==identity(after)==identity(named))
        return json.loads(raw,object_pairs_hook=unique)
    finally: os.close(child)
try:
    directory=os.fstat(fd)
    named_parent=os.stat(parent,follow_symlinks=False)
    need(stat.S_ISDIR(directory.st_mode) and directory.st_uid==0 and
         not directory.st_mode & 0o022 and
         (directory.st_dev,directory.st_ino)==(named_parent.st_dev,named_parent.st_ino))
    intent=read('auto-redirect-intent.json')
    prepared=read('auto-redirect-prepared.json')
    need(type(intent) is dict and set(intent)=={'schema','binding','owner_marker','conntrack_mark'} and
         intent['schema']=='aegis_auto_scoped_redirect_intent_v1' and
         type(intent['binding']) is dict)
    b=intent['binding']
    fields={'stage_dev','stage_ino','private_unit','transaction_nonce','planned_generation',
            'boot_id','netns_ino','config_sha256_initial','config_semantic_sha256',
            'interface','ifindex','listen_ipv4','listen_port','guard_policy_sha256'}
    hex32=lambda x:type(x) is str and re.fullmatch('[0-9a-f]{32}',x) is not None
    hex64=lambda x:type(x) is str and re.fullmatch('[0-9a-f]{64}',x) is not None
    need(set(b)==fields and type(b['private_unit']) is str and
         re.fullmatch('aegis-auto@[0-9a-f]{64}\\.service',b['private_unit']) is not None and
         hex32(b['transaction_nonce']) and all(hex64(b[k]) for k in
         ('planned_generation','config_sha256_initial','config_semantic_sha256',
          'guard_policy_sha256')) and
         all(type(b[k]) is int and b[k]>0 for k in
         ('stage_dev','stage_ino','netns_ino','ifindex')) and
         type(b['interface']) is str and
         re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',b['interface']) is not None and
         b['interface']!='lo' and type(b['listen_ipv4']) is str and
         b['listen_port']==15080 and b['private_unit']==unit and
         path.rsplit('/',1)[-1]==unit and re.fullmatch('[1-9][0-9]*',inode) is not None and
         hex32(invocation) and
         type(b['boot_id']) is str and b['boot_id']==boot and
         re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot) is not None and
         open('/proc/sys/kernel/random/boot_id',encoding='ascii').read().strip()==boot and
         os.stat('/proc/self/ns/net').st_ino==b['netns_ino'] and
         socket.if_nametoindex(b['interface'])==b['ifindex'])
    address=ipaddress.ip_address(b['listen_ipv4'])
    need(type(address) is ipaddress.IPv4Address and not
         (address.is_loopback or address.is_unspecified or address.is_multicast or
          address.is_link_local))
    result=subprocess.run(['/usr/sbin/ip','-j','-4','address','show','dev',b['interface']],
                          capture_output=True,timeout=2,
                          env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
    need(result.returncode==0 and len(result.stdout)<=16384 and len(result.stderr)<=4096)
    rows=json.loads(result.stdout,object_pairs_hook=unique)
    need(type(rows) is list and len(rows)==1 and rows[0].get('ifname')==b['interface'] and
         rows[0].get('ifindex')==b['ifindex'] and type(rows[0].get('addr_info')) is list)
    primary=[item.get('local') for item in rows[0]['addr_info'] if type(item) is dict and
             item.get('family')=='inet' and item.get('secondary',False) is False]
    need(primary==[b['listen_ipv4']])
    owner=hashlib.sha256(canonical(b)).hexdigest()
    mark=int(owner[:8],16)
    if mark in (0,0xa3610001,0xa3610002): mark^=0x5a5a5a5a
    need(intent['owner_marker']=='aegis-scoped-'+owner and
         type(intent['conntrack_mark']) is int and intent['conntrack_mark']==mark)
    def eq(left,right,op='=='):
        return {'match':{'op':op,'left':left,'right':right}}
    marker=intent['owner_marker']; iface=b['interface']; ip=b['listen_ipv4']; port=b['listen_port']
    rows=[{'table':{'family':'ip','name':'aegis_auto_redirect'}},
          {'chain':{'family':'ip','table':'aegis_auto_redirect','name':'input_gate',
                    'type':'filter','hook':'input','prio':0,'policy':'accept'}},
          {'rule':{'family':'ip','table':'aegis_auto_redirect','chain':'input_gate',
                   'comment':marker,'expr':[
                       eq({'meta':{'key':'iifname'}},iface),
                       eq({'payload':{'protocol':'ip','field':'daddr'}},ip),
                       eq({'payload':{'protocol':'tcp','field':'dport'}},port),
                       eq({'ct':{'key':'status'}},'dnat','in'),
                       eq({'ct':{'key':'mark'}},mark),
                       {'counter':{'packets':0,'bytes':0}},{'accept':None}]}},
          {'rule':{'family':'ip','table':'aegis_auto_redirect','chain':'input_gate',
                   'comment':marker,'expr':[
                       eq({'payload':{'protocol':'ip','field':'daddr'}},ip),
                       eq({'payload':{'protocol':'tcp','field':'dport'}},port),
                       {'counter':{'packets':0,'bytes':0}},{'drop':None}]}}]
    policy_hash=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    need(type(prepared) is dict and set(prepared)=={'schema','intent_sha256','policy'} and
         prepared['schema']=='aegis_auto_scoped_redirect_prepared_v1' and
         prepared['intent_sha256']==hashlib.sha256(canonical(intent)).hexdigest() and
         type(prepared['policy']) is dict and
         set(prepared['policy'])=={'policy_sha256','input_gate_chain_handle',
                                  'input_allow_handle','input_drop_handle'} and
         prepared['policy']['policy_sha256']==policy_hash and
         all(type(value) is int and value>0 for key,value in prepared['policy'].items()
             if key!='policy_sha256'))
    material={'binding':b,'client':{'path':path,'inode':inode,'invocation':invocation}}
    reply_marker='aegis-auto-scoped-reply-'+hashlib.sha256(canonical(material)).hexdigest()
    after=os.fstat(fd); named_after=os.stat(parent,follow_symlinks=False)
    need((directory.st_dev,directory.st_ino)==(after.st_dev,after.st_ino)==
         (named_after.st_dev,named_after.st_ino) and named_after.st_uid==0 and
         stat.S_ISDIR(named_after.st_mode) and not named_after.st_mode & 0o022)
    print(iface,ip,port,f'0x{mark:08x}',reply_marker,sep='\t')
finally: os.close(fd)
PY_SCOPED_REPLY
}

# Generate one inet transaction, including IPv4+IPv6 and forwarding. No global
# flush, no sequential per-family activation, no fallback to a weaker matcher.
render() {
  local cgroup="${1:-}" manager_cgroup="${2:-}" port family address level marker scoped_reply='' scoped_if scoped_ip scoped_port scoped_mark scoped_marker
  local local_dnat_ports='' protocol dhcp4_destination=255.255.255.255 dhcp6_destination=ff02::1:2
  if [[ "$schema" == aegis_device_guard_v2 && -n "$manager_cgroup" ]]; then
    [[ "${manager_ifindex:-}" =~ ^[1-9][0-9]*$ ]] || return 1
  fi
  if [[ -n "${manager_dhcp4_server:-}" ]]; then
    dhcp4_destination="{ 255.255.255.255, $manager_dhcp4_server }"
  fi
  if [[ -n "${manager_dhcp6_server:-}" ]]; then
    dhcp6_destination="{ ff02::1:2, $manager_dhcp6_server }"
  fi
  if [[ "$schema" == aegis_device_guard_v2 && -n "$cgroup" && "$cgroup" == "$client_path" && ( -e /var/lib/aegis-install/client/auto-local-redirect-intent.json || -L /var/lib/aegis-install/client/auto-local-redirect-intent.json ) ]]; then
    local_dnat_ports="$(python3 -I -B - "$(dirname "${BASH_SOURCE[0]}")/lib" "$STATE" "$cgroup" "$client_inode" "$client_invocation" <<'PY_LOCAL_DNAT'
import hashlib,json,pathlib,sys
sys.path.insert(0,sys.argv[1])
from aegis_auto_guard_policy import local_guard_dnat_ports
raw=pathlib.Path(sys.argv[2]).read_bytes()
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
client={'schema':'aegis_device_guard_binding_v1','boot_id':boot,
        'state_sha256':hashlib.sha256(raw.rstrip(b'\n')).hexdigest(),
        'path':sys.argv[3],'inode':sys.argv[4],'invocation':sys.argv[5]}
for protocol,port in local_guard_dnat_ports(raw,client,boot):
    print(protocol,port)
PY_LOCAL_DNAT
)" || return 1
  fi
  if [[ "$schema" == aegis_device_guard_v2 && -n "$cgroup" && "$cgroup" == "$client_path" && -n "$client_unit" && ( -e /var/lib/aegis-install/client/auto-redirect-intent.json || -L /var/lib/aegis-install/client/auto-redirect-intent.json ) ]]; then
    scoped_reply="$(scoped_reply_fields)" || return 1
    IFS=$'\t' read -r scoped_if scoped_ip scoped_port scoped_mark scoped_marker <<< "$scoped_reply"
    [[ -n "$scoped_if" && -n "$scoped_ip" && "$scoped_port" == 15080 && "$scoped_mark" =~ ^0x[0-9a-f]{8}$ && "$scoped_marker" =~ ^aegis-auto-scoped-reply-[0-9a-f]{64}$ ]] || return 1
  fi
  local rendered
  rendered="$(
  printf 'add table inet %s\nflush table inet %s\n' "$TABLE" "$TABLE"
  printf 'add chain inet %s incoming { type filter hook prerouting priority -190; policy accept; }\n' "$TABLE"
  # Re-evaluate the socket authority after every earlier route/OUTPUT rewrite.
  # No later priority can forge the consumed postrouting cgroup tags. The
  # foreign verifier reserves this final priority for the owned guard.
  printf 'add chain inet %s output { type filter hook output priority 2147483647; policy drop; }\n' "$TABLE"
  printf 'add chain inet %s forward { type filter hook forward priority 10; policy drop; }\n' "$TABLE"
  printf 'add chain inet %s postroute { type filter hook postrouting priority 2147483647; policy drop; }\n' "$TABLE"
  printf 'add rule inet %s output oifname "lo" counter accept\n' "$TABLE"
  # The TUN is created after BIND. Admit only the later, host-authenticated
  # numeric interface identity, never a reusable interface name.
  if [[ -n "$cgroup" && "$capture_profile" == full-wide-tun && -n "${capture_ifindex:-}" ]]; then
    [[ "$capture_ifindex" =~ ^[1-9][0-9]*$ ]] || return 1
    printf 'add rule inet %s output meta oif %s meta oifkind "tun" counter accept\n' "$TABLE" "$capture_ifindex"
  fi
  if [[ -n "$cgroup" ]]; then
    level="$(awk -F/ '{print NF}' <<< "$cgroup")"
    if [[ "$schema" == aegis_device_guard_v2 ]]; then
      marker="$(binding_marker client "$cgroup" "$client_inode" "$client_invocation")" || return 1
      printf 'add rule inet %s output socket cgroupv2 level %s "%s" counter accept comment "%s"\n' "$TABLE" "$level" "$cgroup" "$marker"
      if [[ -n "$scoped_reply" ]]; then
        # The listener's reply leaves OUTPUT with its pre-NAT source; the NAT
        # core rewrites it to the original target at srcnat (100), before the
        # postroute chain (2147483647). Each postroute twin therefore states the same
        # bound reply tuple through conntrack, never through rewritten header
        # fields. The awk mirror below pairs every scoped OUTPUT rule with
        # exactly its following twin and fails closed on any other shape.
        printf 'add rule inet %s output oifname "%s" ip saddr %s meta l4proto tcp ct direction reply ct status dnat ct mark %s tcp sport %s tcp flags & (syn | ack) == syn | ack counter accept comment "%s"\n' "$TABLE" "$scoped_if" "$scoped_ip" "$scoped_mark" "$scoped_port" "$scoped_marker"
        printf 'postroute-only add rule inet %s postroute oifname "%s" meta nfproto ipv4 meta l4proto tcp ct direction reply ct status dnat ct mark %s ct reply saddr %s ct reply proto-src %s tcp flags & (syn | ack) == syn | ack counter accept comment "%s"\n' "$TABLE" "$scoped_if" "$scoped_mark" "$scoped_ip" "$scoped_port" "$scoped_marker"
        printf 'add rule inet %s output oifname "%s" ip saddr %s meta l4proto tcp ct direction reply ct status dnat ct mark %s tcp sport %s tcp flags & rst == rst counter accept comment "%s"\n' "$TABLE" "$scoped_if" "$scoped_ip" "$scoped_mark" "$scoped_port" "$scoped_marker"
        printf 'postroute-only add rule inet %s postroute oifname "%s" meta nfproto ipv4 meta l4proto tcp ct direction reply ct status dnat ct mark %s ct reply saddr %s ct reply proto-src %s tcp flags & rst == rst counter accept comment "%s"\n' "$TABLE" "$scoped_if" "$scoped_mark" "$scoped_ip" "$scoped_port" "$scoped_marker"
        printf 'add rule inet %s output oifname "%s" ip saddr %s meta l4proto icmp ct state related ct direction reply ct status dnat ct mark %s ct protocol tcp ct reply proto-src %s ct reply saddr %s @th,0,8 { 3, 11, 12 } counter accept comment "%s"\n' "$TABLE" "$scoped_if" "$scoped_ip" "$scoped_mark" "$scoped_port" "$scoped_ip" "$scoped_marker"
        printf 'postroute-only add rule inet %s postroute oifname "%s" meta nfproto ipv4 meta l4proto icmp ct state related ct direction reply ct status dnat ct mark %s ct protocol tcp ct reply proto-src %s ct reply saddr %s @th,0,8 { 3, 11, 12 } counter accept comment "%s"\n' "$TABLE" "$scoped_if" "$scoped_mark" "$scoped_port" "$scoped_ip" "$scoped_marker"
      fi
    else
      printf 'add rule inet %s output socket cgroupv2 level %s "%s" counter accept\n' "$TABLE" "$level" "$cgroup"
    fi
    # With iptables REDIRECT, the destination is already loopback here
    # but the output interface can still be the old uplink until rerouting.
    # Permit only conntrack-confirmed DNAT to the fixed local capture ports,
    # and only while a current client binding exists. Never permit WAN tuples.
    printf 'add rule inet %s output ip daddr 127.0.0.1 ct status dnat tcp dport 15080 counter accept\n' "$TABLE"
    printf 'add rule inet %s output ip daddr 127.0.0.1 ct status dnat udp dport 15081 counter accept\n' "$TABLE"
    while read -r protocol port; do
      [[ -n "$protocol" ]] || continue
      [[ ( "$protocol" == tcp || "$protocol" == udp ) && "$port" =~ ^[0-9]{1,5}$ && "$port" -ge 1 && "$port" -le 65535 ]] || return 1
      printf 'add rule inet %s output ip daddr 127.0.0.1 ct status dnat %s dport %s counter accept\n' "$TABLE" "$protocol" "$port"
    done <<< "$local_dnat_ports"
  fi
  if [[ "$schema" == aegis_device_guard_v2 ]]; then
    IFS=',' read -r -a ports <<< "$management_ports"
    for port in "${ports[@]}"; do
      [[ -n "$port" ]] || continue
      # Conntrack preserves the original incoming local tuple across an address
      # change. A mark alone, an outbound original flow or a different port
      # cannot use the reply exception. Forwarding remains blocked separately.
      printf 'add rule inet %s incoming iifname "%s" fib daddr type local tcp dport %s ct direction original ct state { new, established } ct mark set 0xa3610002\n' "$TABLE" "$uplink" "$port"
      printf 'add rule inet %s output oifname "%s" meta l4proto tcp ct direction reply ct mark 0xa3610002 ct original proto-dst %s tcp sport %s counter accept\n' "$TABLE" "$uplink" "$port" "$port"
    done
    if [[ -n "$manager_cgroup" ]]; then
      level="$(awk -F/ '{print NF}' <<< "$manager_cgroup")"
      marker="$(binding_marker manager "$manager_cgroup" "$manager_inode" "$manager_invocation")" || return 1
      # Before a verified lease pin is bound to this manager invocation, grant
      # acquisition only. A held-lock refresh adds only the current server.
      if [[ "$dhcp4" == 1 ]]; then
        printf 'add rule inet %s output oifname "%s" meta oif %s meta nfproto ipv4 ip daddr %s udp sport 68 udp dport 67 socket cgroupv2 level %s "%s" counter accept comment "%s"\n' "$TABLE" "$uplink" "$manager_ifindex" "$dhcp4_destination" "$level" "$manager_cgroup" "$marker"
      fi
      if [[ "$dhcp6" == 1 ]]; then
        printf 'add rule inet %s output oifname "%s" meta oif %s meta nfproto ipv6 ip6 daddr %s udp sport 546 udp dport 547 socket cgroupv2 level %s "%s" counter accept comment "%s"\n' "$TABLE" "$uplink" "$manager_ifindex" "$dhcp6_destination" "$level" "$manager_cgroup" "$marker"
      fi
    fi
  else
  # Qualify actual incoming management conntracks by interface/local destination.
  # A dedicated ct mark is insufficient by itself: reply direction, original
  # local tuple, actual reply source and uplink are checked again in OUTPUT.
  for family in ip ip6; do
    address="$management_ipv4"; [[ "$family" != ip6 ]] || address="$management_ipv6"
    [[ -n "$address" ]] || continue
    IFS=',' read -r -a ports <<< "$management_ports"
    for port in "${ports[@]}"; do
      [[ -n "$port" ]] || continue
      printf 'add rule inet %s incoming iifname "%s" %s daddr %s tcp dport %s ct direction original ct state { new, established } ct mark set 0xa3610001\n' "$TABLE" "$uplink" "$family" "$address" "$port"
      printf 'add rule inet %s output oifname "%s" %s saddr %s meta l4proto tcp ct direction reply ct mark 0xa3610001 ct original %s daddr %s ct original proto-dst %s tcp sport %s counter accept\n' "$TABLE" "$uplink" "$family" "$address" "$family" "$address" "$port" "$port"
    done
  done
  if [[ "$dhcp4" == 1 ]]; then
    printf 'add rule inet %s output oifname "%s" ip daddr 255.255.255.255 udp sport 68 udp dport 67 counter accept\n' "$TABLE" "$uplink"
  fi
  if [[ "$dhcp6" == 1 ]]; then
    printf 'add rule inet %s output oifname "%s" ip6 saddr fe80::/10 ip6 daddr ff02::1:2 udp sport 546 udp dport 547 counter accept\n' "$TABLE" "$uplink"
  fi
  fi
  printf 'add rule inet %s output oifname "%s" ip6 hoplimit 255 ip6 daddr { fe80::/10, ff02::/16 } icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } counter accept\n' "$TABLE" "$uplink"
  printf 'add rule inet %s output counter drop\n' "$TABLE"
  printf 'add rule inet %s forward counter drop\n' "$TABLE"
  )" || return 1
  # Linux7.0 forbids socket expressions in POSTROUTING. Classify only in
  # OUTPUT and carry the exact cgroup decision in reserved packet marks.
  # Clear pre-existing tags before any OUTPUT exception; consume tags only in
  # the mirrored, sealed POSTROUTING rule. ct marks are a separate namespace.
  # A scoped reply OUTPUT rule is never mirrored verbatim: its explicit
  # postroute-only twin takes the same position. An unpaired, misplaced or
  # mismatched twin emits a line nft cannot parse, so nft --check refuses the
  # whole batch and the previous table stays (callers ignore awk status).
  printf '%s\n' "$rendered" | awk -v table="$TABLE" '
    function refuse_twin() {
      print "aegis-scoped-reply-twin-refused"
      pending=""
    }
    $1=="postroute-only" {
      if (pending == "" || $2!="add" || $3!="rule" || $4!="inet" || $5!=table ||
          $6!="postroute" || index($0, " comment \"" pending "\"") != length($0) - length(pending) - 10) {
        refuse_twin()
        next
      }
      sub(/^postroute-only /, "")
      post[++count]=$0
      pending=""
      next
    }
    pending != "" { refuse_twin() }
    $1=="add" && $2=="rule" && $3=="inet" && $4==table && $5=="output" {
      if (!cleared++)
        print "add rule inet " table " output meta mark { 0xa361c001, 0xa361c002 } meta mark set 0"
      original=$0
      if (match(original, / comment "aegis-auto-scoped-reply-[0-9a-f]+"$/)) {
        print
        pending=substr(original, RSTART + 10, RLENGTH - 11)
        next
      }
      if (original ~ / socket cgroupv2 /) {
        mark=(original ~ / udp sport (68|546) / ? "0xa361c002" : "0xa361c001")
        sub(/ counter accept/, " meta mark set " mark " counter accept")
        print
        $0=original
        sub(/socket cgroupv2 level [0-9]+ "[^"]+"/, "meta mark " mark)
        sub(/ counter accept/, " meta mark set 0 counter accept")
        sub(/aegis-v2-/, "aegis-post-")
      } else {
        print
      }
      $5="postroute"
      post[++count]=$0
      next
    }
    { print }
    END {
      if (pending != "") refuse_twin()
      for (i=1;i<=count;i++) print post[i]
    }
  '
}

selected_relay_script=''
selected_relay_control=0
selected_relay_stop_after_block=0
selected_relay_present() {
  [[ -e /var/lib/aegis-install/client/relay-geneva-profile.json || -L /var/lib/aegis-install/client/relay-geneva-profile.json ]]
}
selected_relay_prepare() {
  selected_relay_script=''; selected_relay_control=0
  selected_relay_present || return 0
  [[ "$STATE" == /var/lib/aegis-install/client/device-guard.conf && "$schema" == aegis_device_guard_v2 && "$armed" == 1 ]] || fail 'selected relay profile requires the exact armed v2 guard'
  local client=/usr/local/bin/aegis-client temporary
  local -a args=(profile relay-geneva guard-prepare)
  aegis_root_trusted_executable "$client" || fail 'selected relay client is not trusted'
  if [[ -n "$client_path" ]]; then
    args+=(--grant-current)
    if [[ "$ACTION" == bind ]]; then args+=(--control-parent); selected_relay_control=1; fi
  fi
  # Invoke directly in the systemd ControlPID shell, never a command-substitution
  # child: role attestation binds the CLI's actual parent to ExecStartPre.
  temporary="$(mktemp /var/lib/aegis-install/client/.relay-guard-batch.XXXXXXXX)" || fail 'selected guard private batch unavailable'
  chmod 0600 "$temporary" || fail 'selected guard private batch protection failed'
  if ! "$client" "${args[@]}" >"$temporary"; then
    fail "selected relay transition refused; bounded private batch retained at $temporary"
  fi
  selected_relay_script="$(aegis_root_read "$temporary")" || fail 'selected relay batch readback refused'
  aegis_root_remove "$temporary" || fail 'selected relay batch cleanup refused'
  [[ -n "$selected_relay_script" ]] || fail 'selected relay empty transition refused'
}
selected_relay_finish() {
  selected_relay_present || return 0
  local -a args=(profile relay-geneva guard-finish)
  if [[ "$selected_relay_control" == 1 ]]; then args+=(--control-parent); fi
  /usr/local/bin/aegis-client "${args[@]}" >/dev/null
}

apply_rules() {
  local rules="$1" base_rules="$1" old_inode failure_reason=''
  selected_relay_prepare
  if [[ -n "$selected_relay_script" ]]; then rules+=$'\n'"$selected_relay_script"; fi
  # Same private immutable bytes are checked and applied. nft's batch replaces
  # the entire owned table atomically, preserving an armed table on failure.
  nft --check --file - <<< "$rules" || fail 'atomic transaction validation failed; previous table retained'
  if [[ -n "$cgroup_path" ]]; then
    old_inode="$cgroup_inode"; resolve_bind_cgroup
    [[ "$old_inode" == "$cgroup_inode" ]] || fail 'service cgroup changed before transaction'
  fi
  if [[ "$schema" == aegis_device_guard_v2 ]]; then
    verify_v2_bindings || fail 'bound unit changed before transaction'
  fi
  # ExecStopPost repeats block after ExecStop has already revoked Main.
  # Avoid generating another nft transaction only for an exact current
  # typed Stop deny under the original held OFD. Missing/foreign/stale input
  # always takes the ordinary restrictive replacement and full checks below.
  if [[ "$schema" == aegis_device_guard_v2 && "$ACTION" == block &&
        "${AEGIS_AUTO_FORCE_BLOCK:-}" != 1 &&
        "$STATE" == /var/lib/aegis-install/client/device-guard.conf &&
        -n "${AEGIS_AUTO_HELD_GUARD_FD:-}" && -e "$AUTO_INSTALL" ]] &&
      python3 -I -B "$AUTO_GUARDIAN" stopping-deny-readback 9 >/dev/null 2>&1; then
    : # Current full kernel deny was proved twice; no permission is added.
  else
    nft --file - <<< "$rules" || fail 'atomic transaction failed; previous table retained'
  fi
  # The binding predicate below authenticates the marked cgroup rules, but a
  # foreign rule or chain in this table could still grant native egress. Check
  # the complete owned table shape before publishing any binding receipt.
  if [[ "$schema" == aegis_device_guard_v2 ]] && ! guard_table_shape_present "$base_rules"; then
    failure_reason='guard table shape readback failed'
  fi
  if [[ "$schema" == aegis_device_guard_v2 ]]; then
    if ! foreign_assessment >/dev/null; then
      if [[ "$ACTION" == bind || "$ACTION" == bind-manager ||
            "$ACTION" == capture-bind || "$ACTION" == capture-bind-legacy ||
            "$ACTION" == refresh-manager-lease ]]; then
        failure_reason='foreign policy admission refused'
      else
        echo 'ERROR: foreign policy refused; restrictive guard retained, no grant authorized' >&2
      fi
    fi
  fi
  if ! nft --json list table inet "$TABLE" | python3 -c '
import json,sys
chains={x["chain"]["name"]:x["chain"] for x in json.load(sys.stdin)["nftables"] if "chain" in x}
for name,hook,priority in (("output","output",2147483647),("forward","forward",10),("postroute","postrouting",2147483647)):
    c=chains[name];assert c["family"]=="inet" and c["table"]=="aegis_device_guard" and c["hook"]==hook and c["prio"]==priority and c["policy"]=="drop"
' ; then
    [[ "$schema" != aegis_device_guard_v1 ]] || fail 'guard readback failed; block was not released'
    failure_reason='guard JSON readback failed'
  fi
  if [[ "$schema" == aegis_device_guard_v2 ]]; then
    verify_v2_bindings || failure_reason="${failure_reason:+$failure_reason; }unit identity changed"
    # Do not publish a durable binding merely because nft accepted the batch.
    # The just-applied marked rules must retain their exact socket level and
    # DHCP predicates in native readback before either receipt is written.
    if [[ -n "$client_path" ]] && ! kernel_binding_present client "$client_path" "$client_inode" "$client_invocation"; then
      failure_reason="${failure_reason:+$failure_reason; }client binding readback failed"
    fi
    if [[ -n "$manager_path" ]] && ! kernel_binding_present manager "$manager_path" "$manager_inode" "$manager_invocation"; then
      failure_reason="${failure_reason:+$failure_reason; }manager binding readback failed"
    fi
  fi
  if [[ -z "$failure_reason" ]]; then
    selected_relay_finish || failure_reason='selected relay readback failed'
  fi
  if [[ -n "$failure_reason" ]]; then
    # A cgroup path can be recreated while nft resolves it. Revoke durable
    # authority and replace any stale/rebound socket matches before returning.
    # Receipt cleanup failure must not prevent the restrictive kernel update.
    aegis_root_remove "$STATE.capture-binding" || echo 'ERROR: old capture receipt retained but cannot match the replacement kernel block' >&2
    aegis_root_remove "$STATE.client-binding" || echo 'ERROR: old client receipt retained but cannot match the replacement kernel block' >&2
    aegis_root_remove "$STATE.manager-binding" || echo 'ERROR: old manager receipt retained but cannot match the replacement kernel block' >&2
    client_path=''; manager_path=''
    rules="$(render)"
    # Close the primary guard before any sidecar preparation that could fail
    # while reading its own pending transition. A failed prepare must not leave
    # the rejected just-applied primary permission in the kernel.
    nft --check --file - <<< "$rules" && nft --file - <<< "$rules" || fail "$failure_reason; emergency re-block failed; administrative recovery required"
    selected_relay_prepare
    if [[ -n "$selected_relay_script" ]]; then
      rules+=$'\n'"$selected_relay_script"
      # The final selected transition still shares one atomic inet/netdev batch.
      nft --check --file - <<< "$rules" && nft --file - <<< "$rules" || fail "$failure_reason; selected relay emergency block failed; primary block retained"
    fi
    selected_relay_finish || fail "$failure_reason; selected relay emergency block readback refused"
    # The failed binding has been revoked before this emergency batch. Seal
    # only that proven restrictive table, never the rejected transient grant.
    auto_seal_policy
    fail "$failure_reason; all cgroup permissions removed by emergency block"
  fi
  if [[ "$selected_relay_stop_after_block" == 1 ]]; then
    /usr/local/bin/aegis-client profile relay-geneva stop-after-block >/dev/null || fail 'selected relay block committed but exact process barrier failed; rules retained'
    selected_relay_stop_after_block=0
  fi
}

guard_table_shape_present() {
  local expected="$1" counts
  counts="$(printf '%s\n' "$expected" | awk -v table="$TABLE" '
    $1=="add" && $2=="rule" && $3=="inet" && $4==table {
      if ($5=="incoming") incoming++
      else if ($5=="output") output++
      else if ($5=="forward") forward++
      else if ($5=="postroute") postroute++
      else exit 1
    }
    END { printf "%d %d %d %d", incoming, output, forward, postroute }
  ')" || return 1
  nft --json list table inet "$TABLE" | python3 -c '
import json,sys
def unique(items):
    result={}
    for key,value in items:
        assert key not in result
        result[key]=value
    return result
payload=json.load(sys.stdin,object_pairs_hook=unique)
assert isinstance(payload,dict) and set(payload)=={"nftables"}
items=payload["nftables"]
assert isinstance(items,list)
assert all(isinstance(item,dict) and len(item)==1 and next(iter(item)) in ("metainfo","table","chain","rule") for item in items)
tables=[item["table"] for item in items if "table" in item]
assert len(tables)==1 and tables[0].get("family")=="inet" and tables[0].get("name")=="aegis_device_guard"
chains=[item["chain"] for item in items if "chain" in item]
assert len(chains)==4 and {c.get("name") for c in chains}=={"incoming","output","forward","postroute"}
for chain in chains:
    assert chain.get("family")=="inet" and chain.get("table")=="aegis_device_guard"
    name=chain["name"]
    hook,priority,policy={"incoming":("prerouting",-190,"accept"),"output":("output",2147483647,"drop"),"forward":("forward",10,"drop"),"postroute":("postrouting",2147483647,"drop")}[name]
    assert chain.get("hook")==hook and chain.get("prio")==priority and chain.get("policy")==policy
rules=[item["rule"] for item in items if "rule" in item]
observed={name:0 for name in ("incoming","output","forward","postroute")}
for rule in rules:
    assert isinstance(rule,dict) and rule.get("family")=="inet" and rule.get("table")=="aegis_device_guard"
    name=rule.get("chain")
    assert name in observed
    observed[name]+=1
    expr=rule.get("expr")
    assert isinstance(expr,list) and expr
    assert all(isinstance(e,dict) and len(e)==1 for e in expr)
    assert not any("jump" in e or "goto" in e for e in expr)
    if name not in ("output","postroute"):
        assert not any("accept" in e for e in expr)
assert [observed[name] for name in ("incoming","output","forward","postroute")] == [int(x) for x in sys.argv[1:]]
' $counts
}


table_present() {
  local tables
  tables="$(nft list tables)" || fail 'cannot inspect table ownership'
  grep -Fxq "table inet $TABLE" <<< "$tables"
}

stop_detached_guard() {
  local active
  active="$(systemctl show aegis-device-egress-guard.service -p ActiveState --value)" || fail 'cannot inspect detached guard unit'
  case "$active" in
    inactive|failed) return 0;;
    active|activating|reloading|deactivating)
      systemctl stop aegis-device-egress-guard.service || fail 'cannot stop detached guard unit'
      active="$(systemctl show aegis-device-egress-guard.service -p ActiveState --value)" || fail 'cannot verify detached guard stop'
      [[ "$active" == inactive || "$active" == failed ]] || fail 'detached guard unit remains active';;
    *) fail 'unexpected detached guard unit state';;
  esac
}

remove_guard_ownership() {
  if [[ "$schema" == aegis_device_guard_v2 && "$manager" == NetworkManager.service ]]; then
    # Caller has already committed armed=0. Never restore native egress while
    # owned bootstrap policy cleanup is incomplete or ownership is ambiguous.
    networkmanager_policy remove >/dev/null || fail 'owned NetworkManager policy cleanup failed'
  fi
  local file
  # Detach Requires before stopping the guard. Otherwise stopping it also stops
  # the network manager; socket activation can requeue that manager and cancel
  # the guard's stop job, leaving an active unit after its file was removed.
  if [[ -e /etc/systemd/system/aegis-auto-clean-shutdown.service || -L /etc/systemd/system/aegis-auto-clean-shutdown.service ]]; then
    systemctl stop aegis-auto-clean-shutdown.service || fail 'clean shutdown unit stop failed'
  fi
  if [[ -e /etc/systemd/system/aegis-device-dhcp-refresh.timer || -L /etc/systemd/system/aegis-device-dhcp-refresh.timer ]]; then
    systemctl stop aegis-device-dhcp-refresh.timer aegis-device-dhcp-refresh.service || fail 'DHCP refresh unit stop failed'
    systemctl disable aegis-device-dhcp-refresh.timer || fail 'DHCP refresh timer disable failed'
  fi
  if [[ -e /etc/systemd/system/aegis-device-egress-guard.service || -L /etc/systemd/system/aegis-device-egress-guard.service ]]; then
    systemctl disable aegis-device-egress-guard.service aegis-foreign-policy-monitor.service || fail 'guard unit disable failed'
  fi
  if [[ -e /etc/systemd/system/aegis-auto-clean-shutdown.service || -L /etc/systemd/system/aegis-auto-clean-shutdown.service ]]; then
    systemctl disable aegis-auto-clean-shutdown.service || fail 'clean shutdown unit disable failed'
  fi
  for file in /etc/systemd/system/aegis-auto-clean-shutdown.service /etc/systemd/system/aegis-device-dhcp-refresh.service /etc/systemd/system/aegis-device-dhcp-refresh.timer /etc/systemd/system/aegis-foreign-policy-monitor.service /etc/systemd/system/aegis-device-egress-guard.service /etc/systemd/system/aegis-client.service.d/30-device-egress-guard.conf /etc/systemd/system/"$manager".d/30-aegis-device-guard.conf; do
    aegis_root_remove "$file" || fail 'cannot remove guard ownership'
  done
  if [[ "$schema" == aegis_device_guard_v2 ]]; then
    aegis_root_remove "$STATE.capture-binding" || fail 'cannot remove capture binding'
    aegis_root_remove "$STATE.client-binding" || fail 'cannot remove client binding'
    aegis_root_remove "$STATE.manager-binding" || fail 'cannot remove manager binding'
    aegis_root_remove /var/lib/aegis-install/client/foreign-policy-drift.json || fail 'cannot clear recovered foreign policy refusal'
    aegis_root_remove /var/lib/aegis-install/client/auto-clean-shutdown-once.json || fail 'cannot clear clean shutdown marker'
  fi
  systemctl daemon-reload || fail 'systemd reload failed'
  stop_detached_guard
}

recover_native() {
  local helper="$(dirname "${BASH_SOURCE[0]}")/aegis-wide-disable.sh" file text unit
  if [[ "$armed" == 0 ]]; then
    # This is the retryable explicit-release commit: capture/client cleanup was
    # verified before armed=0. Finish any interrupted ownership removal first.
    if [[ "$schema" == aegis_device_guard_v2 ]]; then lease_split_check_if_present; fi
    remove_guard_ownership
    systemctl stop aegis-foreign-policy-monitor.service || fail 'cannot stop foreign policy monitor'
  [[ "$(systemctl show aegis-foreign-policy-monitor.service -p MainPID --value)" == 0 ]] || fail 'foreign policy monitor is still running'
  if table_present; then nft delete table inet "$TABLE" || fail 'guard removal failed'; fi
    # A previous attempt may have crashed with capture teardown in flight.
    # The durable split marker is cleared only after the explicit disarm
    # recovery has completed; no diagnostic bracket may pass before then.
    if [[ "$schema" == aegis_device_guard_v2 ]]; then
      lease_split_clear_if_present
    fi
    return 0
  fi
  # ExecStopPost must be able to take the lock while systemctl stops capture.
  # The policy stays armed and its table remains installed throughout this phase.
  # Persist the split before unlocking. A concurrent guardian can then acquire
  # the flock but must refuse even diagnostic pre/post readback until teardown
  # and the durable disarm/recovery have completed. Do not remove on failure.
  if [[ "$schema" == aegis_device_guard_v2 ]]; then
    lease_split_mark
  fi
  flock -u 9 || fail 'cannot release lifecycle lock'
  # Preserve the block through capture cleanup and client shutdown. A failure
  # leaves all remaining administrative files available for a retry.
  [[ -x "$helper" ]] || fail 'capture recovery helper missing'
  aegis_root_trusted_executable "$helper" || fail 'untrusted recovery helper'
  "$helper" || fail 'capture recovery failed; device block retained'
  systemctl stop "$service" || fail 'client stop failed'
  if systemctl is-active --quiet "$service"; then fail 'client remains active'; fi
  for tool in iptables-save ip6tables-save; do
    text="$("$tool")" || fail 'capture residue cannot be inspected'
    [[ "$text" != *AEGIS_WIDE* ]] || fail 'capture residue remains'
  done
  text="$(ip -o link show)" || fail 'interface residue cannot be inspected'
  [[ "$text" != *aegis-tun* ]] || fail 'capture interface remains'
  lock_guard || fail 'cannot lock recovery commit'
  [[ "$(aegis_root_read "$STATE")" == "$state_text" ]] || fail 'state changed during recovery; retry'
  if [[ "$schema" == aegis_device_guard_v2 ]]; then
    lease_split_exact
  fi
  # Commit explicit release before removing its boot ownership. A crash while
  # units remain boots blocked (armed=0 makes guard startup refuse); after their
  # removal, native boot is authorized by this durable release commit. The live
  # table remains until all ownership and detached-unit cleanup has succeeded.
  printf '%s\n' "$state_text" | sed 's/^armed=1$/armed=0/' | aegis_root_write "$STATE" 0600 || fail 'durable disarm failed'
  remove_guard_ownership
  # Do not remove the record/lock: they are the retryable recovery receipt until
  # an explicit package/client purge removes administrative state.
  systemctl stop aegis-foreign-policy-monitor.service || fail 'cannot stop foreign policy monitor'
  [[ "$(systemctl show aegis-foreign-policy-monitor.service -p MainPID --value)" == 0 ]] || fail 'foreign policy monitor is still running'
  if table_present; then nft delete table inet "$TABLE" || fail 'guard removal failed'; fi
  if [[ "$schema" == aegis_device_guard_v2 ]]; then
    lease_split_clear_if_present
  fi
  echo 'device guard: explicit recovery restored native egress; disarmed receipt retained'
}

revoke_failed_lease_refresh() {
  local reason="$1"
  # Receipt loss precedes the restrictive replacement. If publication of the
  # new receipt or the nft transaction failed, no old lease server is reused.
  aegis_root_remove "$STATE.manager-binding" || true
  aegis_root_remove "$STATE.client-binding" || true
  manager_path=''; manager_inode=''; manager_invocation=''
  manager_ifindex=''; manager_dhcp4_server=''; manager_dhcp6_server=''
  client_path=''; client_inode=''; client_invocation=''
  apply_rules "$(render)" || fail "$reason; emergency DHCP deny failed"
  auto_seal_policy || fail "$reason; emergency DHCP deny seal failed"
  fail "$reason; all cgroup permissions removed by emergency block"
}

refresh_manager_lease() {
  local observed ifindex server4 server6
  [[ "$schema" == aegis_device_guard_v2 && -n "$manager_path" &&
     "$manager_ifindex" =~ ^[1-9][0-9]*$ ]] ||
    fail 'current manager binding required for DHCP lease refresh'
  if [[ "$manager" == NetworkManager.service ]]; then
    networkmanager_check live || revoke_failed_lease_refresh 'NetworkManager live policy changed'
  fi
  observed="$(lease_servers)" || revoke_failed_lease_refresh 'manager lease metadata refused'
  IFS=$'\t' read -r ifindex server4 server6 <<< "$observed"
  [[ "$ifindex" == "$manager_ifindex" && -n "$server4" && -n "$server6" ]] ||
    revoke_failed_lease_refresh 'manager lease interface changed'
  [[ "$server4" != none ]] || server4=''
  [[ "$server6" != none ]] || server6=''
  # The first startup can have no lease yet. This retains only acquisition.
  [[ "$server4" != "$manager_dhcp4_server" ||
     "$server6" != "$manager_dhcp6_server" ]] || return 0
  if ! (
    manager_dhcp4_server="$server4"; manager_dhcp6_server="$server6"
    write_binding manager "$manager_path" "$manager_inode" "$manager_invocation"
    apply_rules "$(render "$client_path" "$manager_path")"
    auto_seal_policy
  ); then
    revoke_failed_lease_refresh 'manager lease pin transaction refused'
  fi
  manager_dhcp4_server="$server4"; manager_dhcp6_server="$server6"
}

# networkd Type=notify can enter ExecStartPost before DHCP has completed.
# Keep only the bound acquisition rule until the same unit invocation has a
# lease-backed DHCPv4 server. Networkd can enable DHCPv6 while using SLAAC or
# having no DHCPv6 offer; that family keeps multicast acquisition and is
# pinned only when an actual lease appears. Static IPv4 skips this wait.
networkd_ready_lease() {
  [[ "$manager" == systemd-networkd.service ]] || return 0
  [[ "$dhcp4" == 1 ]] || return 0
  local deadline=$((SECONDS + 45)) observed ifindex server4 server6
  while (( SECONDS < deadline )); do
    resolve_unit_cgroup "$manager" 1 || return 1
    if observed="$(lease_servers)"; then
      IFS=$'\t' read -r ifindex server4 server6 <<< "$observed"
      [[ "$ifindex" == "$manager_ifindex" ]] || return 1
      if [[ "$server4" != none ]]; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

# This probe never grants traffic and deliberately does not take the guard
# flock: an active AUTO capture holds the original OFD until its proved Stop.
# A changed or unreadable live lease must take the conservative Stop/refresh
# path. Only an exact stable receipt, PID1 binding, kernel binding and manager
# lease may be treated as an unchanged renewal.
lease_refresh_needed() {
  local before observed ifindex server4 server6
  [[ -e "$STATE.manager-binding" || -L "$STATE.manager-binding" ]] || return 1
  before="$(aegis_root_read "$STATE.manager-binding")" || return 0
  read_binding manager "$manager" || return 0
  networkmanager_check live || return 0
  observed="$(lease_servers)" || return 0
  IFS=$'\t' read -r ifindex server4 server6 <<< "$observed"
  [[ "$ifindex" == "$manager_ifindex" &&
     "$server4" == "${manager_dhcp4_server:-none}" &&
     "$server6" == "${manager_dhcp6_server:-none}" &&
     "$before" == "$(aegis_root_read "$STATE.manager-binding")" &&
     "$state_text" == "$(aegis_root_read "$STATE")" ]] || return 0
  return 1
}

# A normal named client has no AUTO coordinator. Admit only the installed
# ordinary unit and its current marked cgroup before asking PID1 to execute
# its already installed ExecStopPost block. This runs before taking GuardLock:
# ExecStopPost must acquire that lock to revoke the TUN and client permission.
ordinary_named_lease_stop_facts() {
  local phase="$1" invocation="$2"
  python3 -I - "$phase" "$invocation" "$capture_profile" <<'PY_ORDINARY_STOP'
import hashlib,os,re,select,stat,subprocess,sys
from pathlib import Path

phase,invocation,profile=sys.argv[1:]
unit='aegis-client.service'
group='/system.slice/'+unit
helper='/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh'
dropin=Path('/etc/systemd/system/aegis-client.service.d/30-device-egress-guard.conf')
def need(ok):
    if not ok:raise ValueError('ordinary named Stop authority changed')
need(phase in ('active','stopped') and re.fullmatch('[0-9a-f]{32}',invocation) and
     profile=='full-wide-tun')
keys=('MainPID','ControlPID','ActiveState','SubState','InvocationID',
      'ControlGroup','FragmentPath','DropInPaths','NeedDaemonReload',
      'ExecStartPre','ExecStartPost','ExecStopPost')
argv=['/usr/bin/systemctl','show',unit,'--no-pager']
for key in keys:argv+=['-p',key]
result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,
                      timeout=3,check=False,env={'PATH':'/usr/sbin:/usr/bin',
                                                 'LANG':'C','LC_ALL':'C'})
need(result.returncode==0 and len(result.stdout)<=16384 and
     len(result.stderr)<=4096)
facts={}
for line in result.stdout.decode('ascii').splitlines():
    key,sep,value=line.partition('=')
    need(sep=='=' and key not in facts)
    facts[key]=value
need(set(facts)==set(keys) and facts['NeedDaemonReload']=='no' and
     facts['FragmentPath']=='/etc/systemd/system/'+unit and
     str(dropin) in facts['DropInPaths'].split() and
     facts['InvocationID'] in ('',invocation) and
     f'/bin/bash {helper} bind' in facts['ExecStartPre'] and
     f'/bin/bash {helper} capture-bind-legacy' in facts['ExecStartPost'] and
     f'/bin/bash {helper} block' in facts['ExecStopPost'])
for name in (Path(facts['FragmentPath']),
             *(Path(item) for item in facts['DropInPaths'].split())):
    info=name.stat(follow_symlinks=False)
    need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and
         info.st_nlink==1 and not info.st_mode&0o022)
source=dropin.read_text(encoding='ascii')
need(re.search(r'^ExecStartPre=/bin/bash '+re.escape(helper)+r' bind$',source,re.M) and
     re.search(r'^ExecStartPost=/bin/bash '+re.escape(helper)+r' capture-bind-legacy$',source,re.M) and
     re.search(r'^ExecStopPost=/bin/bash '+re.escape(helper)+r' block$',source,re.M))
if phase=='active':
    need(facts['ActiveState']=='active' and facts['SubState']=='running' and
         facts['ControlPID']=='0' and facts['ControlGroup']==group and
         facts['InvocationID']==invocation and
         facts['MainPID'].isascii() and facts['MainPID'].isdecimal() and
         int(facts['MainPID'])>1)
    pid=int(facts['MainPID'])
    pidfd=os.pidfd_open(pid,0)
    try:
        need(not select.select([pidfd],[],[],0)[0] and
             Path(f'/proc/{pid}/cgroup').read_text(encoding='ascii')==f'0::{group}\n' and
             Path(f'/proc/{pid}/ns/net').stat().st_ino==
             Path('/proc/1/ns/net').stat().st_ino)
        image=Path('/usr/local/bin/aegis-client').stat(follow_symlinks=False)
        running=Path(f'/proc/{pid}/exe').stat()
        need(stat.S_ISREG(image.st_mode) and image.st_uid==0 and
             image.st_nlink==1 and not image.st_mode&0o022 and
             0<image.st_size<=512<<20 and
             (image.st_dev,image.st_ino)==(running.st_dev,running.st_ino))
    finally:os.close(pidfd)
else:
    need(facts['MainPID']==facts['ControlPID']=='0' and
         facts['ActiveState']=='inactive' and
         facts['ControlGroup'] in ('',group) and
         not Path('/var/lib/aegis-install/client/device-guard.conf.client-binding').exists() and
         not Path('/var/lib/aegis-install/client/device-guard.conf.client-binding').is_symlink() and
         not Path('/var/lib/aegis-install/client/device-guard.conf.capture-binding').exists() and
         not Path('/var/lib/aegis-install/client/device-guard.conf.capture-binding').is_symlink())
    cgroup=Path('/sys/fs/cgroup')/group.lstrip('/')
    if cgroup.exists():
        events=(cgroup/'cgroup.events').read_text(encoding='ascii')
        need('populated 0\n' in events and 'populated 1\n' not in events)
PY_ORDINARY_STOP
}

ordinary_named_lease_stop() {
  local invocation
  [[ "$STATE" == /var/lib/aegis-install/client/device-guard.conf &&
     "$schema" == aegis_device_guard_v2 && "$service" == aegis-client.service &&
     "$capture_profile" == full-wide-tun &&
     ! -e "$AUTO_INSTALL" && ! -L "$AUTO_INSTALL" ]] ||
    fail 'ordinary DHCP Stop source changed; old pin retained'
  if [[ ! -e "$STATE.client-binding" && ! -L "$STATE.client-binding" ]]; then
    [[ ! -e "$STATE.capture-binding" && ! -L "$STATE.capture-binding" ]] ||
      fail 'ordinary capture receipt lacks client owner; old pin retained'
    return 0
  fi
  read_binding client "$service" ||
    fail 'ordinary client grant cannot be authenticated; old pin retained'
  [[ "$resolved_path" == system.slice/aegis-client.service ]] ||
    fail 'ordinary client cgroup changed; old pin retained'
  invocation="$resolved_invocation"
  [[ -e "$STATE.capture-binding" && ! -L "$STATE.capture-binding" ]] ||
    fail 'ordinary FullTun capture receipt unavailable; old pin retained'
  capture_binding_index_legacy verify >/dev/null ||
    fail 'ordinary FullTun owner changed; old pin retained'
  ordinary_named_lease_stop_facts active "$invocation" ||
    fail 'ordinary named client Stop identity refused; old pin retained'
  timeout --signal=TERM --kill-after=3s 90s \
    /usr/bin/systemctl stop aegis-client.service ||
    fail 'ordinary named client Stop refused; old pin retained'
  ordinary_named_lease_stop_facts stopped "$invocation" ||
    fail 'ordinary named client did not reach revoked terminal; old pin retained'
}

refresh_manager_lease_service() {
  local coordinator='/usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py'
  local stop_reply
  lease_refresh_needed || return 0
  if [[ -e "$AUTO_INSTALL" || -L "$AUTO_INSTALL" ]]; then
    # The installed coordinator verifies the current generation, executes
    # the native original-owner inverse/Stop and archives its old receipts.
    # Raw PID1 stop would bypass that authority and is never used here.
    [[ -f "$coordinator" && ! -L "$coordinator" ]] ||
      fail 'installed AUTO Stop coordinator unavailable; old DHCP pin retained'
    aegis_root_trusted_executable "$coordinator" ||
      fail 'untrusted AUTO Stop coordinator; old DHCP pin retained'
    stop_reply="$(timeout --signal=TERM --kill-after=3s 180s \
      /usr/bin/python3 -I -B "$coordinator" stop-current)" ||
      fail 'authenticated AUTO Stop refused; old DHCP pin retained'
    printf '%s' "$stop_reply" | python3 -c '
import json,sys
raw=sys.stdin.buffer.read(129)
assert 0<len(raw)<=128
value=json.loads(raw)
assert type(value) is dict and set(value)=={"status"}
assert value["status"] in ("stopped","noop")
' || fail 'AUTO Stop did not reach an archived terminal; old DHCP pin retained'
  else
    ordinary_named_lease_stop
  fi
  # The coordinator has returned a finalized terminal, but a concurrent
  # install/Stop may still own the OFD. Take it normally and re-read all
  # bindings before publishing a new destination.
  lock_guard || fail 'DHCP refresh guard lock unavailable; old pin retained'
  [[ "$(aegis_root_read "$STATE")" == "$state_text" ]] ||
    fail 'guard state changed during authenticated Stop; old pin retained'
  auto_stop_pending && fail 'AUTO Stop remains pending; old pin retained'
  collect_v2_bindings
  [[ -z "$client_path" ]] ||
    fail 'active client binding remains after Stop; old pin retained'
  [[ -n "$manager_path" ]] ||
    revoke_failed_lease_refresh 'manager binding changed before lease refresh'
  refresh_manager_lease
}

case "$ACTION" in
  prepare-nm-policy)
    [[ "$schema" == aegis_device_guard_v2 && "$manager" == NetworkManager.service ]] || fail 'NetworkManager v2 state required'
    preflight_host
    networkmanager_policy prepare >/dev/null || fail 'owned NetworkManager policy preparation failed'
    networkmanager_check disk || fail 'owned internal DHCP policy is not effective; guard ownership retained'
    ;;
  preflight)
    preflight_host
    # Probe the installer's existing cgroup without creating/starting the client.
    # This is check-only: the service exemption is installed later only by bind
    # inside the named service cgroup. A fresh client has no MainPID/cgroup yet.
    cgroup_path="$(awk -F: '$1=="0" && $2=="" {print $3}' /proc/$$/cgroup)" || fail 'caller cgroup unavailable'
    [[ "$cgroup_path" == /* && "$cgroup_path" != / ]] || fail 'caller must have a non-root cgroup'
    cgroup_path="${cgroup_path#/}"
    [[ -n "$cgroup_path" && "$cgroup_path" =~ ^[A-Za-z0-9_.@:/-]+$ && "$cgroup_path" != */ && "$cgroup_path" != *//* && -d "/sys/fs/cgroup/$cgroup_path" && "/$cgroup_path/" != */../* && "/$cgroup_path/" != */./* ]] || fail 'caller cgroup unavailable'
    manager_ifindex="$(cat "/sys/class/net/$uplink/ifindex")" || fail 'uplink ifindex unavailable'
    nft --check --file - <<< "$(render "$cgroup_path" "$cgroup_path")" || fail 'strict nft/cgroup matcher unsupported'
    ;;
  capture-bind-legacy)
    [[ ! -e /var/lib/aegis-install/client/foreign-policy-drift.json &&
       ! -L /var/lib/aegis-install/client/foreign-policy-drift.json ]] ||
      fail 'foreign_policy_drift: explicit recovery required'
    [[ "$capture_profile" == full-wide-tun &&
       ( "$schema" == aegis_device_guard_v1 || "$schema" == aegis_device_guard_v2 ) &&
       ! -e "$AUTO_INSTALL" && ! -L "$AUTO_INSTALL" &&
       ! -e "$STATE.capture-binding" && ! -L "$STATE.capture-binding" ]] ||
      fail 'ordinary FullTun late capture requires an unbound installed state'
    if [[ "$schema" == aegis_device_guard_v1 ]]; then
      resolve_bind_cgroup || fail 'ordinary client control cgroup changed'
      client_path="$cgroup_path"
    else
      collect_v2_bindings
      [[ "$client_path" == system.slice/aegis-client.service ]] ||
        fail 'ordinary client binding missing before late capture'
    fi
    if ! capture_binding_index_legacy mint |
         aegis_root_write "$STATE.capture-binding" 0600; then
      aegis_root_remove "$STATE.capture-binding" || true
      fail 'ordinary TUN owner attestation or receipt publication failed'
    fi
    capture_ifindex="$(capture_binding_index_legacy verify)" || {
      aegis_root_remove "$STATE.capture-binding" || true
      fail 'ordinary TUN owner changed after receipt publication'
    }
    if ! ( apply_rules "$(render "$client_path" "$manager_path")" &&
           [[ "$(capture_binding_index_legacy verify)" == "$capture_ifindex" ]] ); then
      aegis_root_remove "$STATE.capture-binding" || true
      aegis_root_remove "$STATE.client-binding" || true
      aegis_root_remove "$STATE.manager-binding" || true
      client_path=''; manager_path=''
      capture_ifindex=''
      apply_rules "$(render)" || fail 'ordinary TUN late grant failed; emergency deny refused'
      fail 'ordinary TUN late grant refused; deny restored'
    fi
    ;;
  block|block-rotation|bind|bind-manager|capture-bind)
    if [[ "$ACTION" == bind || "$ACTION" == bind-manager || "$ACTION" == capture-bind ]]; then
      [[ ! -e /var/lib/aegis-install/client/foreign-policy-drift.json && ! -L /var/lib/aegis-install/client/foreign-policy-drift.json ]] || fail 'foreign_policy_drift: explicit recovery required'
    fi
    if [[ "$schema" == aegis_device_guard_v1 ]]; then
      [[ "$ACTION" != block-rotation ]] || fail 'guard rotation requires v2'
      if [[ "$ACTION" == bind ]]; then
        [[ ! -e "$STATE.capture-binding" && ! -L "$STATE.capture-binding" ]] ||
          fail 'stale ordinary capture receipt before client bind'
        resolve_bind_cgroup; apply_rules "$(render "$cgroup_path")"
      else
        aegis_root_remove "$STATE.capture-binding" || fail 'cannot revoke ordinary capture receipt'
        apply_rules "$(render)"
      fi
    else
      # A sealed normal STOP may already have the exact kernel deny after
      # PID1 removed the manager cgroup name. Do not render or publish a
      # second policy in that one no-write case. A selected relay keeps its
      # own transition path; unknown/foreign states retain the ordinary block.
      if [[ "$ACTION" == block &&
            "${AEGIS_AUTO_FORCE_BLOCK:-}" != 1 &&
            "$STATE" == /var/lib/aegis-install/client/device-guard.conf &&
            -n "${AEGIS_AUTO_HELD_GUARD_FD:-}" && -e "$AUTO_INSTALL" ]] &&
          ! selected_relay_present &&
          python3 -I -B "$AUTO_GUARDIAN" stopping-deny-readback 9 >/dev/null 2>&1; then
        if ! foreign_assessment >/dev/null; then
          echo 'ERROR: foreign policy refused; restrictive guard retained, no grant authorized' >&2
        fi
        exit 0
      fi
      if [[ "$ACTION" == block-rotation ]]; then
        [[ -n "${AEGIS_AUTO_HELD_GUARD_FD:-}" && "$STATE" == /var/lib/aegis-install/client/device-guard.conf &&
           -e "$AUTO_INSTALL" && -f "$AUTO_GUARDIAN" && ! -L "$AUTO_GUARDIAN" ]] ||
          fail 'guard rotation requires the held original installed source'
        python3 -I -B "$AUTO_GUARDIAN" rotation-preflight 9 >/dev/null ||
          fail 'stopped successor rotation preflight refused'
      fi
      private_bind_step bindings_begin
      collect_v2_bindings
      private_bind_step bindings_end
      case "$ACTION" in
        block)
          if selected_relay_present && [[ -n "$client_path" ]]; then selected_relay_stop_after_block=1; fi
          # Durable revocation precedes kernel removal. A crash after either
          # step cannot let a later manager bind resurrect an old permission.
          aegis_root_remove "$STATE.capture-binding" || fail 'cannot revoke capture binding'
          aegis_root_remove "$STATE.client-binding" || fail 'cannot revoke client binding'
          client_path=''; client_inode=''; client_invocation='';;
        block-rotation)
          [[ -z "$client_path" && ! -e "$STATE.client-binding" &&
             ! -L "$STATE.client-binding" && ! -e "$STATE.capture-binding" &&
             ! -L "$STATE.capture-binding" ]] ||
            fail 'rotation requires typed stopped client without grant'
          client_path=''; manager_path='';
          client_inode=''; manager_inode=''
          client_invocation=''; manager_invocation='';;
        bind)
          [[ ! -e "$STATE.capture-binding" && ! -L "$STATE.capture-binding" ]] || fail 'stale capture binding before client bind'
          client_unit="${AUTO_PRIVATE_UNIT:-$service}"
          resolve_unit_cgroup "$client_unit" 1 || fail 'bind must run inside the current client service cgroup'
          client_path="$resolved_path"; client_inode="$resolved_inode"; client_invocation="$resolved_invocation";;
        capture-bind)
          [[ "$capture_profile" == full-wide-tun && -n "$client_path" &&
             -n "${AEGIS_AUTO_HELD_GUARD_FD:-}" && -e "$AUTO_INSTALL" ]] ||
            fail 'late capture bind requires installed FullTun and original guard OFD';;
        bind-manager)
          networkmanager_check disk || fail 'owned internal DHCP policy is not effective'
          resolve_unit_cgroup "$manager" 1 || fail 'bind-manager must run inside the current network manager cgroup'
          manager_path="$resolved_path"; manager_inode="$resolved_inode"; manager_invocation="$resolved_invocation"
          manager_ifindex="$(cat "/sys/class/net/$uplink/ifindex")" || fail 'uplink ifindex unavailable'
          [[ "$manager_ifindex" =~ ^[1-9][0-9]*$ ]] || fail 'uplink ifindex invalid'
          manager_dhcp4_server=''; manager_dhcp6_server='';;
      esac
      capture_ifindex=''
      if [[ -n "$client_path" && "$capture_profile" == full-wide-tun &&
            ( -e "$STATE.capture-binding" || -L "$STATE.capture-binding" ) ]]; then
        if [[ -e "$AUTO_INSTALL" ]]; then
          capture_ifindex="$(python3 -I -B "$AUTO_GUARDIAN" capture-binding-index 9)" ||
            fail 'capture binding owner or interface changed'
        else
          capture_ifindex="$(capture_binding_index_legacy verify)" ||
            fail 'ordinary capture binding owner or interface changed'
        fi
        [[ "$capture_ifindex" =~ ^[1-9][0-9]*$ ]] || fail 'invalid capture ifindex'
      fi
      [[ "$ACTION" != capture-bind || -n "$capture_ifindex" ]] || fail 'late capture grant missing'
      private_bind_step rules_begin
      apply_rules "$(render "$client_path" "$manager_path")"
      private_bind_step rules_end
      case "$ACTION" in
        block)
          # A reboot can leave an authenticated old-boot manager receipt while
          # the just-applied kernel batch has no manager exception. Retire only
          # that exact receipt under the same original guard OFD, after full
          # deny readback and before sealing the current-boot policy.
          if [[ -z "$manager_path" && -e "$AUTO_INSTALL" &&
                -e "$STATE.manager-binding" ]]; then
            python3 -I -B "$AUTO_GUARDIAN" archive-stale-manager 9 >/dev/null ||
              fail 'old-boot manager receipt retirement refused; block retained'
          fi
          auto_seal_policy;;
        block-rotation)
          python3 -I -B "$AUTO_GUARDIAN" rotation-commit-deny 9 >/dev/null ||
            fail 'rotation archive refused; kernel block retained'
          auto_seal_policy;;
        bind|bind-manager|capture-bind)
          # Keep the original FD9 flock while the child publishes the native
          # binding and the corresponding host semantic seal. If either fails,
          # the parent can still revoke this just-applied kernel ACCEPT.
          if ! (
            if [[ "$ACTION" == bind ]]; then
              write_binding client "$client_path" "$client_inode" "$client_invocation"
            elif [[ "$ACTION" == bind-manager ]]; then
              write_binding manager "$manager_path" "$manager_inode" "$manager_invocation"
            fi
            private_bind_step binding_written
            auto_seal_policy
          ); then
            # The seal child has returned without a trusted ACK. Close the
            # parent's inherited connected FD before emergency re-block, so
            # a delayed host actor cannot enqueue a positive handoff afterward.
            if [[ -n "$AUTO_PRIVATE_UNIT" ]]; then exec 8<&-; fi
            aegis_root_remove "$STATE.client-binding" || echo 'ERROR: client binding receipt retained after failed grant; kernel re-block follows' >&2
            aegis_root_remove "$STATE.capture-binding" || echo 'ERROR: capture binding receipt retained after failed grant; kernel re-block follows' >&2
            aegis_root_remove "$STATE.manager-binding" || echo 'ERROR: manager binding receipt retained after failed grant; kernel re-block follows' >&2
            client_path=''; client_inode=''; client_invocation=''
            manager_path=''; manager_inode=''; manager_invocation=''
            apply_rules "$(render)"
            # The failed private ControlPID may no longer have a usable host
            # channel. Its restrictive nft batch is checked above; the stale
            # seal cannot authorize a new owner and recovery stays sticky.
            if [[ -z "$AUTO_PRIVATE_UNIT" ]]; then auto_seal_policy; fi
            fail 'binding or semantic seal failed; all cgroup permissions removed by emergency block'
          fi
          if [[ -n "$AUTO_PRIVATE_UNIT" ]]; then exec 8<&-; fi;;
      esac
    fi;;
  manager-ready)
    [[ "$schema" == aegis_device_guard_v2 &&
       ( "$manager" == NetworkManager.service || "$manager" == systemd-networkd.service ) ]] ||
      fail 'v2 manager readiness required'
    resolve_unit_cgroup "$manager" 1 || fail 'readiness must run inside the current manager control process'
    if ! networkmanager_check ready || ! read_binding manager "$manager"; then
      # No DHCP/client grant survives a failed managed startup verification.
      aegis_root_remove "$STATE.capture-binding" || true
      aegis_root_remove "$STATE.manager-binding" || true
      aegis_root_remove "$STATE.capture-binding" || true
      aegis_root_remove "$STATE.client-binding" || true
      client_path=''; client_inode=''; client_invocation=''
      manager_path=''; manager_inode=''; manager_invocation=''
      apply_rules "$(render)"
      auto_seal_policy
      fail 'manager did not reach the assessed policy; restrictive table applied'
    fi
    manager_path="$resolved_path"; manager_inode="$resolved_inode"
    manager_invocation="$resolved_invocation"
    networkd_ready_lease || revoke_failed_lease_refresh 'networkd DHCP lease readiness timed out or changed'
    resolve_unit_cgroup "$manager" 1 || revoke_failed_lease_refresh 'manager changed after lease readiness'
    read_binding manager "$manager" || revoke_failed_lease_refresh 'manager binding changed after lease readiness'
    [[ "$manager_path" == "$resolved_path" &&
       "$manager_inode" == "$resolved_inode" &&
       "$manager_invocation" == "$resolved_invocation" ]] ||
      revoke_failed_lease_refresh 'manager identity changed after lease readiness'
    refresh_manager_lease
    ;;
  refresh-manager-lease)
    [[ "$schema" == aegis_device_guard_v2 ]] || fail 'v2 manager lease refresh required'
    if [[ -e "$STATE.manager-binding" || -L "$STATE.manager-binding" ]]; then
      collect_v2_bindings
      [[ -n "$manager_path" ]] || revoke_failed_lease_refresh 'manager binding changed before lease refresh'
      refresh_manager_lease
    fi
    ;;
  refresh-manager-lease-service)
    [[ "$schema" == aegis_device_guard_v2 ]] || fail 'v2 DHCP refresh required'
    refresh_manager_lease_service
    ;;
  manager-status)
    manager_status_before="$(aegis_root_read "$STATE.manager-binding")" || fail 'manager binding unreadable'
    networkmanager_check live || fail 'NetworkManager applied policy is not verified'
    read_binding manager "$manager" || fail 'network manager binding is absent or stale'
    manager_status_lease="$(lease_servers)" || fail 'manager lease metadata unavailable'
    IFS=$'\t' read -r manager_status_ifindex manager_status_server4 manager_status_server6 <<< "$manager_status_lease"
    [[ "$manager_status_ifindex" == "$manager_ifindex" &&
       "$manager_status_server4" == "${manager_dhcp4_server:-none}" &&
       "$manager_status_server6" == "${manager_dhcp6_server:-none}" ]] ||
      fail 'manager DHCP server pin is stale; refresh required'
    # Receipts are committed only after the checked table transaction. Every
    # helper replacement keeps/removes this permission under the same lock.
    nft list table inet "$TABLE" >/dev/null || fail 'guard table is missing'
    [[ "$(aegis_root_read "$STATE")" == "$state_text" &&
       "$(aegis_root_read "$STATE.manager-binding")" == "$manager_status_before" ]] || fail 'manager status changed during readback'
    echo 'device guard: current network manager binding verified';;
  status) nft list table inet "$TABLE";;
  recover) recover_native;;
  release)
    # Require removal of boot ownership first; otherwise a restart can re-arm.
    for file in /etc/systemd/system/aegis-auto-clean-shutdown.service /etc/systemd/system/aegis-device-dhcp-refresh.service /etc/systemd/system/aegis-device-dhcp-refresh.timer /etc/systemd/system/aegis-foreign-policy-monitor.service /etc/systemd/system/aegis-device-egress-guard.service /etc/systemd/system/aegis-client.service.d/30-device-egress-guard.conf /etc/systemd/system/"$manager".d/30-aegis-device-guard.conf; do
      [[ ! -e "$file" && ! -L "$file" ]] || fail 'remove device guard unit ownership before release'
    done
    if [[ "$schema" == aegis_device_guard_v2 && "$manager" == NetworkManager.service ]]; then
      networkmanager_policy remove >/dev/null || fail 'owned NetworkManager policy cleanup failed'
    fi
    stop_detached_guard
    systemctl stop aegis-foreign-policy-monitor.service || fail 'cannot stop foreign policy monitor'
  [[ "$(systemctl show aegis-foreign-policy-monitor.service -p MainPID --value)" == 0 ]] || fail 'foreign policy monitor is still running'
  if table_present; then nft delete table inet "$TABLE" || fail 'release failed; block retained'; fi
    ;;
esac
