#!/usr/bin/env python3
"""Render or clean up a synthetic loopback relay canary; never launch it."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import sys
import time
import tomllib

_dependency = Path(__file__).resolve().with_name("prepare_relay_canary.py")
_spec = importlib.util.spec_from_file_location("aegis_prepare_relay_canary", _dependency)
if _spec is None or _spec.loader is None:
    raise RuntimeError("pinned canary preparation dependency unavailable")
_prepare = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_prepare)
HEX64 = _prepare.HEX64
SAFE_ID = _prepare.SAFE_ID
private_new = _prepare.private_new
protected_read = _prepare.protected_read
reject_linux_acl = _prepare.reject_linux_acl

FILES = ("config.toml", "cert.pem", "key.pem")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_ancestry(path):
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute path required")
    current = Path("/")
    for part in path.parts[1:]:
        current = current / part
        st = current.lstat()
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError("symlink or non-directory ancestor")
        if st.st_uid not in (0, os.geteuid()):
            raise ValueError("ancestor owner is untrusted")
        if st.st_mode & 0o022 and not (st.st_uid == 0 and st.st_mode & stat.S_ISVTX):
            raise ValueError("writable ancestor")


def private_parent(path):
    parent = path.parent
    safe_ancestry(parent)
    st = parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError("output parent must be caller-owned mode 0700")
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (st.st_dev, st.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("output parent changed")
        reject_linux_acl(fd, directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def free_loopback_port(port):
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535 or port == 443:
        raise ValueError("isolated port must be 1024..65535 and not 443")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", port))
        probe.listen(1)


def validate_candidate(raw):
    cfg = tomllib.loads(raw.decode("utf-8"))
    if set(cfg) != {"listen", "cert", "key", "auth_token", "legacy_auth_tokens"}:
        raise ValueError("only minimal synthetic candidate schema is accepted")
    if not isinstance(cfg["listen"], str) or not cfg["listen"].startswith("127.0.0.1:"):
        raise ValueError("synthetic source must use loopback")
    if not isinstance(cfg["auth_token"], str) or not HEX64.fullmatch(cfg["auth_token"]):
        raise ValueError("invalid synthetic primary")
    legacy = cfg["legacy_auth_tokens"]
    if not isinstance(legacy, list) or len(legacy) != 1:
        raise ValueError("exactly one synthetic legacy canary required")
    token = legacy[0]
    if set(token) != {"id", "auth_token", "not_after_unix_secs"}:
        raise ValueError("invalid legacy canary shape")
    if (not isinstance(token["id"], str) or not SAFE_ID.fullmatch(token["id"])
            or not isinstance(token["auth_token"], str)
            or not HEX64.fullmatch(token["auth_token"])
            or token["auth_token"] == cfg["auth_token"]):
        raise ValueError("invalid or duplicate synthetic canary")
    expiry = token["not_after_unix_secs"]
    if not isinstance(expiry, int) or isinstance(expiry, bool) or not int(time.time()) < expiry <= int(time.time()) + 900:
        raise ValueError("synthetic canary expiry outside live 900-second bound")
    return cfg, token


def render(candidate, cert, key, out_dir, port, expected_sha256):
    if not HEX64.fullmatch(expected_sha256):
        raise ValueError("expected SHA-256 required")
    for source in (Path(candidate), Path(cert), Path(key)):
        safe_ancestry(source.parent)
    raw = protected_read(Path(candidate))
    if digest(raw) != expected_sha256:
        raise ValueError("candidate SHA-256 mismatch")
    cfg, legacy = validate_candidate(raw)
    cert_bytes = protected_read(Path(cert))
    key_bytes = protected_read(Path(key))
    if b"-----BEGIN CERTIFICATE-----" not in cert_bytes or b"-----BEGIN " not in key_bytes or b"PRIVATE KEY-----" not in key_bytes:
        raise ValueError("synthetic TLS input lacks PEM markers")
    free_loopback_port(port)
    out_dir = Path(out_dir)
    if not out_dir.is_absolute() or ".." in out_dir.parts or out_dir.name in ("", ".", ".."):
        raise ValueError("absolute fresh output directory required")
    parent_fd = private_parent(out_dir)
    try:
        os.mkdir(out_dir.name, 0o700, dir_fd=parent_fd)
        dir_fd = os.open(out_dir.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            reject_linux_acl(dir_fd, directory=True)
            body = (f'listen = "127.0.0.1:{port}"\n'
                    f'cert = {json.dumps(str(out_dir / "cert.pem"))}\n'
                    f'key = {json.dumps(str(out_dir / "key.pem"))}\n'
                    f'auth_token = "{cfg["auth_token"]}"\n'
                    '\n[[legacy_auth_tokens]]\n'
                    f'id = "{legacy["id"]}"\n'
                    f'auth_token = "{legacy["auth_token"]}"\n'
                    f'not_after_unix_secs = {legacy["not_after_unix_secs"]}\n').encode()
            tomllib.loads(body.decode())
            payloads = {"config.toml": body, "cert.pem": cert_bytes, "key.pem": key_bytes}
            for name in FILES:
                private_new(dir_fd, name, payloads[name])
            files = {}
            for name in FILES:
                st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                files[name] = {"sha256": digest(payloads[name]), "dev": st.st_dev, "ino": st.st_ino}
            dst = os.fstat(dir_fd)
            manifest = {"schema": "aegis_isolated_canary_v1", "port": port,
                        "candidate_sha256": digest(raw), "directory_dev": dst.st_dev,
                        "directory_ino": dst.st_ino, "files": files,
                        "launched": False}
            private_new(dir_fd, "manifest.json", (json.dumps(manifest, sort_keys=True) + "\n").encode())
            os.fsync(dir_fd)
            return {"rendered": True, "port": port, "config_sha256": digest(body),
                    "candidate_sha256": digest(raw), "launched": False}
        finally:
            os.close(dir_fd)
    finally:
        os.close(parent_fd)


def no_open_refs(inodes, allowed_own_fds=()):
    if not sys.platform.startswith("linux"):
        return
    deadline = time.monotonic() + 10
    for pid in os.listdir("/proc"):
        if not pid.isdecimal():
            continue
        if time.monotonic() > deadline:
            raise ValueError("process reference scan timed out")
        try:
            for fd_name in os.listdir(f"/proc/{pid}/fd"):
                if int(pid) == os.getpid() and int(fd_name) in allowed_own_fds:
                    continue
                try:
                    st = os.stat(f"/proc/{pid}/fd/{fd_name}")
                except FileNotFoundError:
                    continue
                if (st.st_dev, st.st_ino) in inodes:
                    raise ValueError("canary file still open by a process")
            try:
                cwd = os.stat(f"/proc/{pid}/cwd")
                if (cwd.st_dev, cwd.st_ino) in inodes:
                    raise ValueError("canary directory is a process cwd")
            except FileNotFoundError:
                pass
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            raise ValueError("process references cannot be established") from exc


def cleanup(out_dir, expected_manifest_sha256, never_launched=False):
    if not never_launched:
        raise ValueError("cleanup requires explicit never-launched assertion")
    if not HEX64.fullmatch(expected_manifest_sha256):
        raise ValueError("manifest SHA-256 required")
    out_dir = Path(out_dir)
    if not out_dir.is_absolute() or ".." in out_dir.parts or out_dir.name in ("", ".", ".."):
        raise ValueError("absolute output directory required")
    parent_fd = private_parent(out_dir)
    try:
        ds = os.open(out_dir.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            st = os.fstat(ds)
            if st.st_uid != os.geteuid() or st.st_mode & 0o077:
                raise ValueError("output directory custody changed")
            reject_linux_acl(ds, directory=True)
            if set(os.listdir(ds)) != set(FILES) | {"manifest.json"}:
                raise ValueError("output directory contents changed")
            manifest_path = out_dir / "manifest.json"
            raw = protected_read(manifest_path)
            if digest(raw) != expected_manifest_sha256:
                raise ValueError("manifest SHA-256 mismatch")
            manifest = json.loads(raw)
            if (manifest.get("schema") != "aegis_isolated_canary_v1"
                    or manifest.get("launched") is not False
                    or (st.st_dev, st.st_ino) != (manifest.get("directory_dev"), manifest.get("directory_ino"))
                    or set(manifest.get("files", {})) != set(FILES)):
                raise ValueError("manifest identity mismatch")
            free_loopback_port(manifest["port"])
            inodes = {(st.st_dev, st.st_ino)}
            for name in FILES:
                data = protected_read(out_dir / name)
                fs = os.stat(name, dir_fd=ds, follow_symlinks=False)
                recorded = manifest["files"][name]
                if (digest(data), fs.st_dev, fs.st_ino) != (recorded["sha256"], recorded["dev"], recorded["ino"]):
                    raise ValueError("rendered file identity changed")
                inodes.add((fs.st_dev, fs.st_ino))
            ms = os.stat("manifest.json", dir_fd=ds, follow_symlinks=False)
            inodes.add((ms.st_dev, ms.st_ino))
            no_open_refs(inodes, allowed_own_fds=(ds, parent_fd))
            for name in FILES + ("manifest.json",):
                os.unlink(name, dir_fd=ds)
            os.fsync(ds)
        finally:
            os.close(ds)
        os.rmdir(out_dir.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return {"cleaned": True, "manifest_sha256": expected_manifest_sha256}
    finally:
        os.close(parent_fd)


def main():
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise SystemExit("operator CLI requires Linux root")
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    make = sub.add_parser("render")
    for name in ("candidate", "cert", "key", "out-dir", "expected-candidate-sha256"):
        make.add_argument("--" + name, required=True)
    make.add_argument("--port", type=int, required=True)
    clean = sub.add_parser("cleanup")
    clean.add_argument("--out-dir", required=True)
    clean.add_argument("--expected-manifest-sha256", required=True)
    clean.add_argument("--never-launched", action="store_true")
    args = parser.parse_args()
    if args.action == "render":
        result = render(args.candidate, args.cert, args.key, args.out_dir,
                        args.port, args.expected_candidate_sha256)
    else:
        result = cleanup(args.out_dir, args.expected_manifest_sha256, args.never_launched)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
