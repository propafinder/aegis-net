#!/usr/bin/env python3
"""Stage a pinned client for disposable Linux smoke tests, never installation.

The caller supplies the expected hash of its reviewed build. This helper does
not authenticate that build or execute it. Its fixed /run namespace and root
checks have no environment or command-line override.
"""

import argparse
import hashlib
import os
import re
import secrets
import stat
import sys


STAGING_ROOT = "/run"
PREFIX = "aegis-smoke-metadata."
BINARY = "aegis-client"
BINARY_NAMES = (BINARY, "aegis-measure")
MAX_SOURCE_BYTES = 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
NAME_RE = re.compile(re.escape(PREFIX) + r"[0-9a-f]{32}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY_RE = re.compile(r"(0|[1-9][0-9]{0,19}):([1-9][0-9]{0,19})\Z")


class StagingError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise StagingError(message)


def _require_linux_root():
    require(sys.platform == "linux" and os.geteuid() == 0,
            "smoke client staging requires Linux root")


def _root_owned(info):
    return info.st_uid == 0 and info.st_gid == 0


def _set_root_owner(fd):
    os.fchown(fd, 0, 0)


def _identity(info):
    return info.st_dev, info.st_ino


def _stable_file(info):
    return (_identity(info), info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _absolute_parts(path):
    require(isinstance(path, str) and 1 < len(path) <= 4096,
            "an absolute canonical path is required")
    require(path.startswith("/") and "\x00" not in path,
            "an absolute canonical path is required")
    parts = path.split("/")[1:]
    require(all(part not in ("", ".", "..") for part in parts),
            "an absolute canonical path is required")
    return parts


def _open_parent(path):
    parts = _absolute_parts(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def _open_staging_root():
    parent_fd, name = _open_parent(STAGING_ROOT)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        info = os.fstat(fd)
        require(_root_owned(info) and not info.st_mode & 0o022,
                "untrusted staging root")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _checked_directory(base_fd, name, expected):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                 dir_fd=base_fd)
    try:
        info = os.fstat(fd)
        named = os.stat(name, dir_fd=base_fd, follow_symlinks=False)
        require(_identity(info) == expected == _identity(named),
                "staging directory identity mismatch")
        require(stat.S_ISDIR(named.st_mode) and _root_owned(info)
                and stat.S_IMODE(info.st_mode) in (0o700, 0o755),
                "untrusted staging directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _remove_owned(base_fd, name, expected, *, partial=False, binary_identity=None,
                  binary_name=BINARY):
    fd = _checked_directory(base_fd, name, expected)
    try:
        names = set(os.listdir(fd))
        allowed = (set(), {binary_name}) if partial else tuple({leaf} for leaf in BINARY_NAMES)
        require(names in allowed, "unknown staging inventory; refusing cleanup")
        leaf = next(iter(names), None)
        if leaf is not None:
            info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and _root_owned(info) and stat.S_IMODE(info.st_mode) in (0o600, 0o755),
                    "untrusted staged binary; refusing cleanup")
            if partial:
                require(binary_identity is not None and _identity(info) == binary_identity,
                        "partial staged binary identity mismatch")
        require(_identity(os.stat(name, dir_fd=base_fd, follow_symlinks=False)) == expected,
                "staging directory changed before cleanup")
        if leaf is not None:
            os.unlink(leaf, dir_fd=fd)
            os.fsync(fd)
        require(not os.listdir(fd), "staging directory is not empty")
        require(_identity(os.stat(name, dir_fd=base_fd, follow_symlinks=False)) == expected,
                "staging directory changed before removal")
        os.rmdir(name, dir_fd=base_fd)
        os.fsync(base_fd)
    finally:
        os.close(fd)


def _copy_and_hash(source_fd, output_fd, expected_size):
    digest = hashlib.sha256()
    total = 0
    while True:
        block = os.read(source_fd, min(CHUNK_BYTES, expected_size - total + 1))
        if not block:
            break
        total += len(block)
        require(total <= expected_size <= MAX_SOURCE_BYTES, "source grew beyond size bound")
        digest.update(block)
        pending = memoryview(block)
        while pending:
            written = os.write(output_fd, pending)
            require(written > 0, "staged binary write made no progress")
            pending = pending[written:]
    require(total == expected_size, "source size changed during copy")
    return digest.hexdigest()


def stage(source, expected_hash, binary_name=BINARY):
    _require_linux_root()
    require(binary_name in BINARY_NAMES, "unsupported smoke binary name")
    require(HASH_RE.fullmatch(expected_hash) is not None, "expected SHA-256 must be lowercase hex")
    source_parent, source_name = _open_parent(source)
    source_fd = base_fd = directory_fd = output_fd = None
    directory_name = directory_identity = binary_identity = None
    try:
        source_fd = os.open(source_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=source_parent)
        before = os.fstat(source_fd)
        named = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and _stable_file(before) == _stable_file(named),
                "source must be a stable regular file")
        # Cargo may hardlink its output into target/debug; input link count is not
        # an authority boundary because the copied bytes must match the pin.
        require(0 < before.st_size <= MAX_SOURCE_BYTES, "source exceeds size bound or is empty")
        base_fd = _open_staging_root()
        for _ in range(16):
            candidate = PREFIX + secrets.token_hex(16)
            try:
                os.mkdir(candidate, 0o700, dir_fd=base_fd)
            except FileExistsError:
                continue
            directory_name = candidate
            directory_identity = _identity(os.stat(candidate, dir_fd=base_fd, follow_symlinks=False))
            break
        require(directory_name is not None, "could not allocate a fresh staging directory")
        directory_fd = os.open(directory_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=base_fd)
        created = os.fstat(directory_fd)
        require(stat.S_ISDIR(created.st_mode) and _identity(created) == directory_identity
                == _identity(os.stat(directory_name, dir_fd=base_fd, follow_symlinks=False)),
                "created staging directory identity mismatch")
        # Normalize the directory we just created before the ordinary trust
        # check: a restrictive umask or inherited primary GID is not a pin.
        _set_root_owner(directory_fd)
        os.fchmod(directory_fd, 0o700)
        checked_fd = _checked_directory(base_fd, directory_name, directory_identity)
        os.close(checked_fd)
        output_fd = os.open(binary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=directory_fd)
        binary_identity = _identity(os.fstat(output_fd))
        _set_root_owner(output_fd)
        os.fchmod(output_fd, 0o600)
        actual_hash = _copy_and_hash(source_fd, output_fd, before.st_size)
        after = os.fstat(source_fd)
        named_after = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
        require(_stable_file(before) == _stable_file(after) == _stable_file(named_after),
                "source changed during copy")
        require(actual_hash == expected_hash, "source SHA-256 mismatch")
        output_info = os.fstat(output_fd)
        require(stat.S_ISREG(output_info.st_mode) and output_info.st_nlink == 1
                and _root_owned(output_info) and output_info.st_size == before.st_size
                and _identity(output_info) == binary_identity,
                "staged binary identity mismatch")
        require(set(os.listdir(directory_fd)) == {binary_name}, "unknown staging inventory")
        require(_identity(os.stat(binary_name, dir_fd=directory_fd, follow_symlinks=False)) == binary_identity,
                "staged binary path changed")
        os.fsync(output_fd)
        # Only verified bytes become executable or traversable by other users.
        os.fchmod(output_fd, 0o755)
        os.fsync(output_fd)
        os.fchmod(directory_fd, 0o755)
        os.fsync(directory_fd)
        os.fsync(base_fd)
        checked_fd = _checked_directory(base_fd, directory_name, directory_identity)
        os.close(checked_fd)
        return (os.path.join(STAGING_ROOT, directory_name),
                f"{directory_identity[0]}:{directory_identity[1]}")
    except BaseException as failure:
        if directory_identity is not None:
            try:
                _remove_owned(base_fd, directory_name, directory_identity,
                              partial=True, binary_identity=binary_identity, binary_name=binary_name)
            except (OSError, StagingError) as cleanup_failure:
                raise StagingError("staging failed; unverified partial state retained for inspection") from cleanup_failure
        raise failure
    finally:
        for fd in (output_fd, directory_fd, base_fd, source_fd, source_parent):
            if fd is not None:
                os.close(fd)


def cleanup(directory, identity):
    _require_linux_root()
    _absolute_parts(directory)
    name = os.path.basename(directory)
    require(os.path.dirname(directory) == STAGING_ROOT and NAME_RE.fullmatch(name) is not None,
            "cleanup requires the fixed smoke staging namespace")
    matched = IDENTITY_RE.fullmatch(identity)
    require(matched is not None, "invalid staging directory identity")
    expected = tuple(int(value) for value in matched.groups())
    require(all(value < 2**64 for value in expected), "invalid staging directory identity")
    base_fd = _open_staging_root()
    try:
        _remove_owned(base_fd, name, expected)
    finally:
        os.close(base_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stage_parser = commands.add_parser("stage")
    stage_parser.add_argument("--source", required=True)
    stage_parser.add_argument("--sha256", required=True)
    stage_parser.add_argument("--binary-name", choices=BINARY_NAMES, default=BINARY)
    cleanup_parser = commands.add_parser("cleanup")
    cleanup_parser.add_argument("--directory", required=True)
    cleanup_parser.add_argument("--identity", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "stage":
            directory, identity = stage(args.source, args.sha256, args.binary_name)
            print(f"{directory} {identity}", flush=True)
        else:
            cleanup(args.directory, args.identity)
    except (OSError, StagingError) as error:
        print(f"smoke client staging: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
