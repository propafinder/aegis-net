#!/usr/bin/env python3
"""Prepare, but never deploy, a bounded legacy relay canary credential.

The candidate and exact rollback are private files. Live service/config changes
require a separate reviewed deployment with independent health and rollback.
"""

import argparse
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
import tomllib
from pathlib import Path


SAFE_ID = re.compile(r"canary-[A-Za-z0-9_-]{1,25}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject_linux_acl(fd: int, directory: bool = False) -> None:
    # The CLI is Linux-only. On Linux, unknown ACL metadata must not turn a
    # mode-0600 secret into an assumed-private file.
    if not sys.platform.startswith("linux"):
        return
    names = ["system.posix_acl_access"]
    if directory:
        names.append("system.posix_acl_default")
    for name in names:
        try:
            value = os.getxattr(fd, name)
        except OSError as error:
            if error.errno == errno.ENODATA:
                continue
            raise ValueError("ACL status unknown") from error
        if value:
            raise ValueError("extended ACL is not supported for canary custody")


def protected_read(path: Path) -> bytes:
    parent = path.parent
    ps = parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(ps.st_mode) or ps.st_uid != os.geteuid() or ps.st_mode & 0o077:
        raise ValueError("input parent must be caller-owned mode 0700")
    ds = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened_parent = os.fstat(ds)
        if (ps.st_dev, ps.st_ino) != (opened_parent.st_dev, opened_parent.st_ino):
            raise ValueError("input parent changed before open")
        reject_linux_acl(ds, directory=True)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=ds)
        try:
            fs = os.fstat(fd)
            if (not stat.S_ISREG(fs.st_mode) or fs.st_nlink != 1
                    or fs.st_uid != os.geteuid() or fs.st_mode & 0o077):
                raise ValueError("input must be a caller-owned mode-0600 stable regular file")
            reject_linux_acl(fd)
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise ValueError("input exceeds one MiB")
            after = os.fstat(fd)
            if (fs.st_dev, fs.st_ino, fs.st_size, fs.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise ValueError("input changed during read")
            return data
        finally:
            os.close(fd)
    finally:
        os.close(ds)


def private_new(dir_fd: int, name: str, data: bytes) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def prepare(config: Path, out_dir: Path, canary_id: str, ttl: int,
            expected_sha256: str, now: int | None = None) -> dict:
    if not SAFE_ID.fullmatch(canary_id) or not 60 <= ttl <= 900:
        raise ValueError("invalid canary id or ttl outside 60..900 seconds")
    if not HEX64.fullmatch(expected_sha256):
        raise ValueError("expected config SHA-256 must be lowercase hex")
    source = protected_read(config)
    if digest(source) != expected_sha256:
        raise ValueError("source config SHA-256 mismatch")
    parsed = tomllib.loads(source.decode("utf-8"))
    if parsed.get("transport", {}).get("inner_tls") is not None:
        raise ValueError("legacy canary refuses inner-TLS origins")
    primary = parsed.get("auth_token")
    if (not isinstance(primary, str) or not HEX64.fullmatch(primary)
            or len(set(bytes.fromhex(primary))) == 1):
        raise ValueError("legacy origin needs a valid primary token")
    legacy = parsed.get("legacy_auth_tokens", [])
    if not isinstance(legacy, list) or len(legacy) >= 3:
        raise ValueError("legacy token capacity unavailable")
    if any(not isinstance(item, dict) for item in legacy):
        raise ValueError("invalid legacy entry")
    for item in legacy:
        existing = item.get("auth_token")
        if (not isinstance(existing, str) or not HEX64.fullmatch(existing)
                or len(set(bytes.fromhex(existing))) == 1):
            raise ValueError("existing legacy token invalid")
    if any(item.get("id") == canary_id for item in legacy):
        raise ValueError("canary id already exists")
    token = secrets.token_hex(32)
    if token == primary or any(item.get("auth_token") == token for item in legacy):
        raise ValueError("new token collision")
    expiry = (int(time.time()) if now is None else now) + ttl
    suffix = b"" if source.endswith(b"\n") else b"\n"
    candidate = (source + suffix + b"\n[[legacy_auth_tokens]]\n"
                 + f'id = "{canary_id}"\n'.encode()
                 + f'auth_token = "{token}"\n'.encode()
                 + f"not_after_unix_secs = {expiry}\n".encode())
    check = tomllib.loads(candidate.decode("utf-8"))
    if len(check["legacy_auth_tokens"]) != len(legacy) + 1:
        raise ValueError("candidate parse mismatch")
    parent = out_dir.parent
    ps = parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(ps.st_mode) or ps.st_uid != os.geteuid() or ps.st_mode & 0o077:
        raise ValueError("output parent must be caller-owned mode 0700")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened_parent = os.fstat(parent_fd)
        if (ps.st_dev, ps.st_ino) != (opened_parent.st_dev, opened_parent.st_ino):
            raise ValueError("output parent changed before open")
        reject_linux_acl(parent_fd, directory=True)
        os.mkdir(out_dir.name, 0o700, dir_fd=parent_fd)
        ds = os.open(out_dir.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     dir_fd=parent_fd)
        try:
            reject_linux_acl(ds, directory=True)
            private_new(ds, "candidate.toml", candidate)
            private_new(ds, "rollback.toml", source)
            private_new(ds, "client-token", (token + "\n").encode())
            receipt = {
                "schema": "aegis_relay_canary_prepare_v1",
                "canary_id": canary_id,
                "expires_at_unix_secs": expiry,
                "base_sha256": digest(source),
                "candidate_sha256": digest(candidate),
                "applied": False,
            }
            private_new(ds, "receipt.json", (json.dumps(receipt, sort_keys=True) + "\n").encode())
            os.fsync(ds)
        finally:
            os.close(ds)
        return receipt
    finally:
        # A partial private output remains for explicit incident inspection.
        os.close(parent_fd)


def main() -> None:
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise SystemExit("operator CLI requires Linux root and a local protected filesystem")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--ttl-secs", type=int, required=True)
    parser.add_argument("--expected-config-sha256", required=True)
    args = parser.parse_args()
    result = prepare(args.config, args.out_dir, args.id, args.ttl_secs,
                     args.expected_config_sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
