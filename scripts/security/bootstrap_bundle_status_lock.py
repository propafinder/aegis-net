#!/usr/bin/env python3
"""One-time, fail-closed bundle-token lock bootstrap. NOT DEPLOYED.

Start as root; drop to configured UID before store metadata. Dry-run is the default. The --apply
path creates only the absent empty .lock leaf; it never unlinks or truncates.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tomllib

SOURCE_COMMIT = SERVER_SHA256 = SERVER_BIN = SERVICE = CONFIG = STORE = UID = None
SAFE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
DIR_FLAGS = SAFE_FLAGS | os.O_DIRECTORY


class Refused(Exception):
    pass


PIN_KEYS = frozenset({
    "hostname", "machine_id_sha256", "source_commit", "server_sha256",
    "server_bin", "service", "config", "store", "uid", "gid",
    "config_sha256", "store_dev", "store_ino", "parent_dev", "parent_ino",
})


def is_hash(value, length):
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def absolute_path(value):
    return (isinstance(value, str) and value.startswith("/")
            and len(Path(value).parts) >= 3 and "\x00" not in value
            and all(part not in (".", "..") for part in value.split("/")))


def load_pin(path):
    if not absolute_path(path):
        raise Refused("pin_path_invalid")
    parent_fd = open_trusted_parent(path, 0)
    try:
        fd = os.open(Path(path).name, SAFE_FLAGS, dir_fd=parent_fd)
        try:
            meta = os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0
                    or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1):
                raise Refused("pin_metadata_invalid")
            with os.fdopen(os.dup(fd), "rb") as source:
                raw = source.read(65537)
            if len(raw) > 65536:
                raise Refused("pin_oversize")
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    pin = json.loads(raw)
    if not isinstance(pin, dict) or frozenset(pin) != PIN_KEYS:
        raise Refused("pin_schema_invalid")
    for key in ("machine_id_sha256", "server_sha256", "config_sha256"):
        if not is_hash(pin[key], 64):
            raise Refused("pin_hash_invalid")
    if not is_hash(pin["source_commit"], 40):
        raise Refused("pin_source_invalid")
    if not isinstance(pin["hostname"], str) or not pin["hostname"] or any(c.isspace() for c in pin["hostname"]):
        raise Refused("pin_hostname_invalid")
    for key in ("server_bin", "config", "store"):
        if not absolute_path(pin[key]):
            raise Refused("pin_path_invalid")
    if (not isinstance(pin["service"], str) or not pin["service"].endswith(".service")
            or not all(c.isalnum() or c in "_.@-" for c in pin["service"])):
        raise Refused("pin_service_invalid")
    for key in ("uid", "gid", "store_dev", "store_ino", "parent_dev", "parent_ino"):
        if type(pin[key]) is not int or pin[key] <= 0:
            raise Refused("pin_integer_invalid")
    if len({pin["server_bin"], pin["config"], pin["store"]}) != 3:
        raise Refused("pin_paths_not_distinct")
    return pin


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb", buffering=0) as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def service_pid():
    if subprocess.run(["systemctl", "is-active", "--quiet", SERVICE],
                      check=False, stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL, timeout=3).returncode != 0:
        raise Refused("service_inactive")
    raw = subprocess.check_output(["systemctl", "show", SERVICE,
                                   "-p", "MainPID", "--value"],
                                  stderr=subprocess.DEVNULL, timeout=3).strip()
    if not raw.isdigit() or int(raw) <= 0:
        raise Refused("service_pid_invalid")
    return int(raw)


def process_identity(pid, root_preflight=False):
    proc = Path("/proc") / str(pid)
    if proc.stat().st_uid != UID:
        raise Refused("service_uid_mismatch")
    cmdline = [p.decode("utf-8", "strict") for p in
               (proc / "cmdline").read_bytes().split(b"\0") if p]
    if not cmdline or cmdline[0] != SERVER_BIN:
        raise Refused("service_binary_path_mismatch")
    if cmdline.count("--config") != 1 or any(p.startswith("--config=") for p in cmdline):
        raise Refused("service_config_missing")
    at = cmdline.index("--config")
    if at + 1 >= len(cmdline) or cmdline[at + 1] != CONFIG:
        raise Refused("service_config_mismatch")
    binary_parent_fd = open_trusted_parent(SERVER_BIN, 0)
    try:
        installed = os.stat(Path(SERVER_BIN).name, dir_fd=binary_parent_fd,
                            follow_symlinks=False)
    finally:
        os.close(binary_parent_fd)
    if (not stat.S_ISREG(installed.st_mode) or installed.st_uid != 0
            or installed.st_nlink != 1 or installed.st_mode & 0o022):
        raise Refused("installed_binary_metadata_mismatch")
    if root_preflight:
        running = os.stat(proc / "exe")
        if (running.st_dev, running.st_ino) != (installed.st_dev, installed.st_ino):
            raise Refused("running_binary_inode_mismatch")
        source = proc / "exe"
    else:
        source = SERVER_BIN
    if sha256_file(source) != SERVER_SHA256:
        raise Refused("service_binary_mismatch")
    # The start ticks distinguish a reused PID after a service restart.
    fields = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
    return (pid, int(fields[19]), installed.st_dev, installed.st_ino)


def config_fingerprint():
    parent_fd = open_trusted_parent(CONFIG, 0)
    try:
        fd = os.open(Path(CONFIG).name, SAFE_FLAGS, dir_fd=parent_fd)
        try:
            meta = os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0
                    or meta.st_nlink != 1 or meta.st_mode & 0o022):
                raise Refused("config_metadata_mismatch")
            with os.fdopen(os.dup(fd), "rb") as source:
                raw = source.read(1024 * 1024 + 1)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if len(raw) > 1024 * 1024:
        raise Refused("config_oversize")
    data = tomllib.loads(raw.decode("utf-8", "strict"))
    bundle = data.get("bundle_endpoint")
    if not isinstance(bundle, dict) or bundle.get("enabled") is not True:
        raise Refused("bundle_endpoint_disabled")
    if bundle.get("token_store_path", STORE) != STORE:
        raise Refused("store_path_mismatch")
    return hashlib.sha256(raw).hexdigest()


def open_trusted_parent(path, uid):
    """Descriptor-relative traversal; no symlinks or writable ancestors."""
    parts = Path(path).parts
    if not path.startswith("/") or len(parts) < 3 or any(p in (".", "..") for p in parts):
        raise Refused("store_path_invalid")
    fd = os.open("/", DIR_FLAGS)
    try:
        for part in parts[1:-1]:
            meta = os.fstat(fd)
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0, uid) or meta.st_mode & 0o022:
                raise Refused("parent_untrusted")
            next_fd = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        meta = os.fstat(fd)
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0, uid) or meta.st_mode & 0o022:
            raise Refused("parent_untrusted")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_store_identity(parent_fd, leaf, uid):
    fd = os.open(leaf, SAFE_FLAGS | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid
                or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1):
            raise Refused("store_metadata_mismatch")
        return (meta.st_dev, meta.st_ino)
    finally:
        os.close(fd)


def sidecar_identity(parent_fd, leaf, uid):
    try:
        meta = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid
            or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1):
        raise Refused("sidecar_metadata_mismatch")
    return (meta.st_dev, meta.st_ino)


def directory_identity(parent_fd):
    meta = os.fstat(parent_fd)
    return (meta.st_dev, meta.st_ino)


def parent_writable(parent_fd):
    # effective_ids + the held descriptor checks the actual ACL-aware rights
    # of the service user, not only owner/mode bits or a path re-resolution.
    return os.access(".", os.W_OK | os.X_OK, dir_fd=parent_fd, effective_ids=True)


def bootstrap_leaf(parent_fd, store_leaf, uid, expected_dev, expected_ino,
                   expected_parent, parent_again, expected_process,
                   process_again, config_again, apply, writable=parent_writable):
    """Core transaction. Tests use inert fixture descriptors and process seam."""
    lock_leaf = store_leaf + ".lock"
    if directory_identity(parent_fd) != expected_parent or parent_again() != expected_parent:
        raise Refused("parent_inode_mismatch")
    if not writable(parent_fd):
        raise Refused("parent_not_writable_by_service_uid")
    if read_store_identity(parent_fd, store_leaf, uid) != (expected_dev, expected_ino):
        raise Refused("store_inode_mismatch")
    if sidecar_identity(parent_fd, lock_leaf, uid) is not None:
        raise Refused("sidecar_already_exists")
    if process_again() != expected_process:
        raise Refused("service_changed_before_create")
    if parent_again() != expected_parent:
        raise Refused("parent_changed_before_create")
    if not config_again():
        raise Refused("config_changed_before_create")
    if not apply:
        return "DRY_RUN_READY"
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    old_umask = os.umask(0o077)
    try:
        fd = os.open(lock_leaf, flags, 0o600, dir_fd=parent_fd)
    except FileExistsError as error:
        raise Refused("sidecar_race_or_exists") from error
    finally:
        os.umask(old_umask)
    # From this point onward there is no deletion, including on any error.
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        meta = os.fstat(fd)
        readback = sidecar_identity(parent_fd, lock_leaf, uid)
        if (meta.st_uid != uid or stat.S_IMODE(meta.st_mode) != 0o600
                or meta.st_nlink != 1 or readback != (meta.st_dev, meta.st_ino)):
            raise Refused("created_sidecar_readback_failed")
        if read_store_identity(parent_fd, store_leaf, uid) != (expected_dev, expected_ino):
            raise Refused("store_changed_after_create")
        os.fsync(fd)
        os.fsync(parent_fd)
        if parent_again() != expected_parent:
            raise Refused("parent_changed_after_create")
        if sidecar_identity(parent_fd, lock_leaf, uid) != (meta.st_dev, meta.st_ino):
            raise Refused("sidecar_changed_after_sync")
        if process_again() != expected_process:
            raise Refused("service_changed_after_create")
        if not config_again():
            raise Refused("config_changed_after_create")
        return "CREATED_READBACK_PASS"
    finally:
        os.close(fd)


def run():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--pin-file", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    pin = load_pin(args.pin_file)
    global SOURCE_COMMIT, SERVER_SHA256, SERVER_BIN, SERVICE, CONFIG, STORE, UID
    (SOURCE_COMMIT, SERVER_SHA256, SERVER_BIN, SERVICE, CONFIG, STORE, UID) = (
        pin["source_commit"], pin["server_sha256"], pin["server_bin"],
        pin["service"], pin["config"], pin["store"], pin["uid"])
    hostname = socket.gethostname()
    if (os.getuid() != 0 or os.geteuid() != 0
            or hostname != pin["hostname"]
            or sha256_file("/etc/machine-id") != pin["machine_id_sha256"]):
        raise Refused("host_or_runtime_uid_mismatch")
    first = process_identity(service_pid(), root_preflight=True)
    os.setgroups([])
    os.setgid(pin["gid"])
    os.setuid(UID)
    if (os.getuid() != UID or os.geteuid() != UID
            or os.getgid() != pin["gid"] or os.getegid() != pin["gid"]
            or os.getgroups()):
        raise Refused("privilege_drop_failed")
    if process_identity(service_pid()) != first:
        raise Refused("service_changed_after_root_preflight")
    if config_fingerprint() != pin["config_sha256"]:
        raise Refused("config_hash_mismatch")
    parent_fd = open_trusted_parent(STORE, UID)
    try:
        def parent_again():
            reopened = open_trusted_parent(STORE, UID)
            try:
                return directory_identity(reopened)
            finally:
                os.close(reopened)
        result = bootstrap_leaf(parent_fd, Path(STORE).name, UID,
                                pin["store_dev"], pin["store_ino"],
                                (pin["parent_dev"], pin["parent_ino"]),
                                parent_again, first,
                                lambda: process_identity(service_pid()),
                                lambda: config_fingerprint() == pin["config_sha256"],
                                args.apply)
        print(json.dumps({"result": result, "source": SOURCE_COMMIT,
                          "hostname": socket.gethostname()}, sort_keys=True))
    finally:
        os.close(parent_fd)


if __name__ == "__main__":
    try:
        run()
    except (Refused, OSError, ValueError, subprocess.SubprocessError, UnicodeError):
        print('{"result":"REFUSED_OR_PARTIAL_REVIEW_REQUIRED"}', file=sys.stderr)
        sys.exit(2)
