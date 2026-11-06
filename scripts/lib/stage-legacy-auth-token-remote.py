#!/usr/bin/env python3
"""Recover one pre-rotation server credential as a bounded legacy key.

Runs on the relay. The old credential is read from a local root-only backup and
never leaves the host; stdout contains fingerprints and filenames only.
"""

import hashlib
import os
import re
import stat
import sys
import tempfile
import time

TOKEN = re.compile(r'(?m)^\s*auth_token\s*=\s*"([^"]*)"')
SAFE_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
LEGACY_TABLE = re.compile(r"(?m)^\s*\[\[legacy_auth_tokens\]\]\s*$")
MAX_LEGACY_TOKENS = 3


def read_regular(path, private):
    link_stat = os.lstat(path)
    if not stat.S_ISREG(link_stat.st_mode):
        raise SystemExit(f"{path} must be one stable regular file, not a symlink or device")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    file_stat = os.fstat(fd)
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or (link_stat.st_dev, link_stat.st_ino) != (file_stat.st_dev, file_stat.st_ino)
    ):
        os.close(fd)
        raise SystemExit(f"{path} must be one stable regular file, not a symlink or device")
    mode = stat.S_IMODE(file_stat.st_mode)
    if file_stat.st_uid != os.geteuid() or mode & (0o077 if private else 0o022):
        os.close(fd)
        requirement = "mode 0600 or stricter" if private else "not group/world writable"
        raise SystemExit(f"{path} must be caller-owned and {requirement}")
    with os.fdopen(fd, encoding="utf-8") as handle:
        source = handle.read()
    return source, file_stat


def read_primary(source, path):
    first_table = re.search(r"(?m)^\s*\[", source)
    top = source[: first_table.start() if first_table else len(source)]
    match = TOKEN.search(top)
    if not match:
        raise SystemExit(f"no top-level auth_token in {path}")
    return source, match.group(1)


def assert_unchanged(path, original_stat):
    current = os.lstat(path)
    identity = (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    original = (
        original_stat.st_dev,
        original_stat.st_ino,
        original_stat.st_size,
        original_stat.st_mtime_ns,
    )
    if identity != original or not stat.S_ISREG(current.st_mode):
        raise SystemExit(f"{path} changed concurrently; refusing atomic replace")


def fingerprint(token):
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def main():
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: stage-legacy-auth-token-remote.py "
            "<current-config> <pre-rotate-backup> <legacy-id> <not-after-unix-secs>"
        )
    config_path, backup_path, legacy_id, expiry_text = sys.argv[1:]
    if not SAFE_ID.fullmatch(legacy_id) or legacy_id == "current":
        raise SystemExit("invalid or reserved legacy id")
    try:
        expiry = int(expiry_text)
    except ValueError:
        raise SystemExit("not-after-unix-secs must be an integer")
    now = int(time.time())
    if not (now + 300 <= expiry <= now + 90 * 24 * 60 * 60):
        raise SystemExit("legacy expiry must be 5 minutes to 90 days in the future")

    source, config_stat = read_regular(config_path, private=False)
    backup_source, _ = read_regular(backup_path, private=True)
    source, current = read_primary(source, config_path)
    _, legacy = read_primary(backup_source, backup_path)
    if current == legacy:
        raise SystemExit("backup credential equals current credential")
    legacy_count = len(LEGACY_TABLE.findall(source))
    if legacy_count >= MAX_LEGACY_TOKENS:
        raise SystemExit(
            f"legacy_auth_tokens already has {legacy_count} entries; maximum is {MAX_LEGACY_TOKENS}"
        )
    if legacy in TOKEN.findall(source):
        raise SystemExit("backup credential is already configured")
    if re.search(rf'(?m)^\s*id\s*=\s*"{re.escape(legacy_id)}"\s*$', source):
        raise SystemExit(f"legacy auth id already exists: {legacy_id}")

    suffix = "" if source.endswith("\n") else "\n"
    rewritten = (
        source
        + suffix
        + "\n[[legacy_auth_tokens]]\n"
        + f'id = "{legacy_id}"\n'
        + f'auth_token = "{legacy}"\n'
        + f"not_after_unix_secs = {expiry}\n"
    )

    original_stat = config_stat
    assert_unchanged(config_path, original_stat)
    recovery_path = f"{config_path}.pre-legacy.{now}"
    recovery_fd = os.open(recovery_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(recovery_fd, "w", encoding="utf-8") as handle:
        handle.write(source)
        handle.flush()
        os.fsync(handle.fileno())

    directory = os.path.dirname(config_path) or "."
    fd, temporary = tempfile.mkstemp(prefix=".aegis-legacy-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(rewritten)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(original_stat.st_mode))
        os.chown(temporary, original_stat.st_uid, original_stat.st_gid)
        assert_unchanged(config_path, original_stat)
        os.replace(temporary, config_path)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

    print(
        "current=%s legacy=%s id=%s expiry=%d recovery=%s"
        % (
            fingerprint(current),
            fingerprint(legacy),
            legacy_id,
            expiry,
            os.path.basename(recovery_path),
        )
    )


if __name__ == "__main__":
    main()
