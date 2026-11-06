#!/usr/bin/env python3
"""Atomically stage one tunnel credential rotation on a target host.

The new primary arrives on stdin and is never passed in argv. On a server the
old primary is retained as an explicitly identified, hard-expiring legacy key;
on a client only the [relay] primary changes. Output contains fingerprints,
never credential values.
"""

import hashlib
import os
import re
import stat
import sys
import tempfile
import time

TOKEN_PATTERN = re.compile(r'(?m)^(\s*auth_token\s*=\s*)"([^"]*)"')
SAFE_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
LEGACY_TABLE = re.compile(r"(?m)^\s*\[\[legacy_auth_tokens\]\]\s*$")
MAX_LEGACY_TOKENS = 3


def section_for(role, source):
    if role != "client":
        # The first top-level auth_token precedes every TOML table.
        first_table = re.search(r"(?m)^\s*\[", source)
        return 0, first_table.start() if first_table else len(source)
    match = re.search(r"(?ms)^\[relay\]\s*$.*?(?=^\[|\Z)", source)
    if not match:
        raise SystemExit("no [relay] section")
    return match.start(), match.end()


def token_in_scope(source, role):
    start, end = section_for(role, source)
    match = TOKEN_PATTERN.search(source[start:end])
    if not match:
        raise SystemExit("no auth_token in selected scope")
    return match.group(2)


def fingerprint(token):
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def read_regular(path):
    link_stat = os.lstat(path)
    if not stat.S_ISREG(link_stat.st_mode):
        raise SystemExit("config path must be one stable regular file, not a symlink or device")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    file_stat = os.fstat(fd)
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or (link_stat.st_dev, link_stat.st_ino) != (file_stat.st_dev, file_stat.st_ino)
    ):
        os.close(fd)
        raise SystemExit("config path must be one stable regular file, not a symlink or device")
    if file_stat.st_uid != os.geteuid() or stat.S_IMODE(file_stat.st_mode) & 0o022:
        os.close(fd)
        raise SystemExit("config must be caller-owned and not group/world writable")
    with os.fdopen(fd, encoding="utf-8") as handle:
        source = handle.read()
    return source, file_stat


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
        raise SystemExit("config changed concurrently; refusing atomic replace")


def atomic_write(path, source, original_source, original_stat, backup_label):
    assert_unchanged(path, original_stat)
    epoch = int(time.time())
    backup = f"{path}.{backup_label}.{epoch}"
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(original_source)
        handle.flush()
        os.fsync(handle.fileno())

    directory = os.path.dirname(path) or "."
    fd, temporary = tempfile.mkstemp(prefix=".aegis-auth-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(source)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(original_stat.st_mode))
        os.chown(temporary, original_stat.st_uid, original_stat.st_gid)
        assert_unchanged(path, original_stat)
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return backup


def rewrite_primary(source, role, new_token):
    start, end = section_for(role, source)
    section, count = TOKEN_PATTERN.subn(
        lambda match: match.group(1) + '"' + new_token + '"',
        source[start:end],
        count=1,
    )
    if count != 1:
        raise SystemExit(f"expected exactly one auth_token in scope, found {count}")
    return source[:start] + section + source[end:]


def append_legacy(source, legacy_id, old_token, not_after):
    if re.search(rf'(?m)^\s*id\s*=\s*"{re.escape(legacy_id)}"\s*$', source):
        raise SystemExit(f"legacy auth id already exists: {legacy_id}")
    suffix = "" if source.endswith("\n") else "\n"
    return (
        source
        + suffix
        + "\n[[legacy_auth_tokens]]\n"
        + f'id = "{legacy_id}"\n'
        + f'auth_token = "{old_token}"\n'
        + f"not_after_unix_secs = {not_after}\n"
    )


def validate_server_overlap(source, new_token, old_token):
    legacy_count = len(LEGACY_TABLE.findall(source))
    if legacy_count >= MAX_LEGACY_TOKENS:
        raise SystemExit(
            f"legacy_auth_tokens already has {legacy_count} entries; maximum is {MAX_LEGACY_TOKENS}"
        )
    configured = [match.group(2) for match in TOKEN_PATTERN.finditer(source)]
    if configured.count(old_token) != 1:
        raise SystemExit("current credential is already duplicated elsewhere in the config")
    if new_token in configured:
        raise SystemExit("new primary duplicates an existing configured credential")


def main():
    if len(sys.argv) not in (3, 5):
        raise SystemExit(
            "usage: rotate-auth-token-remote.py <config> client | "
            "<config> server <legacy-id> <not-after-unix-secs>"
        )
    path, role = sys.argv[1], sys.argv[2]
    if role not in ("server", "client"):
        raise SystemExit("role must be server or client")
    if role == "server" and len(sys.argv) != 5:
        raise SystemExit("server rotation requires legacy id and hard expiry")
    if role == "client" and len(sys.argv) != 3:
        raise SystemExit("client rotation takes no legacy arguments")

    new_token = sys.stdin.read().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", new_token):
        raise SystemExit(
            "refusing to write: expected one 64-character lowercase hex token on stdin"
        )

    source, path_stat = read_regular(path)
    old_token = token_in_scope(source, role)
    if old_token == new_token:
        raise SystemExit("refusing to rotate: primary fingerprint is unchanged")

    rewritten = rewrite_primary(source, role, new_token)
    if role == "server":
        legacy_id = sys.argv[3]
        if not SAFE_ID.fullmatch(legacy_id) or legacy_id == "current":
            raise SystemExit("invalid or reserved legacy id")
        try:
            not_after = int(sys.argv[4])
        except ValueError:
            raise SystemExit("not-after-unix-secs must be an integer")
        now = int(time.time())
        if not (now + 300 <= not_after <= now + 90 * 24 * 60 * 60):
            raise SystemExit("legacy expiry must be 5 minutes to 90 days in the future")
        validate_server_overlap(source, new_token, old_token)
        rewritten = append_legacy(rewritten, legacy_id, old_token, not_after)

    before = fingerprint(old_token)
    after = fingerprint(new_token)
    backup = atomic_write(path, rewritten, source, path_stat, "pre-rotate")
    landed_source, _ = read_regular(path)
    landed = token_in_scope(landed_source, role)
    if landed != new_token:
        raise SystemExit("fingerprint verification failed after atomic replace")
    print(f"before={before} after={after} backup={os.path.basename(backup)}")


if __name__ == "__main__":
    main()
