#!/usr/bin/env python3
"""Stage/check one versioned SSH policy-export boundary; never install or reload it.

The approved public-key roster stays outside Git. The tool reads that roster
without printing key material. Rendering emits a private staged copy with only
the exact old forced-command token replaced; an operator must independently
review the roster and effective sshd policy before a guarded deployment.
"""

import argparse
import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path


SNIPPET = "90-aegis-policy-export.conf"
PREFIX = "aegis-policy-authorized-key-prefix.txt"
ROSTER = "aegis-policy-authorized-keys"
MAX_BYTES = 64 * 1024
KEY_ALGORITHMS = (b"ssh-ed25519", b"ecdsa-sha2-nistp256", b"rsa-sha2-512", b"rsa-sha2-256", b"ssh-rsa")


def source_binary(commit: str, *, must_be_head: bool = True) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("source commit must be a full lowercase SHA-1")
    try:
        result = subprocess.run(
            ["git", "-C", str(Path(__file__).resolve().parents[1]), "cat-file", "-t", commit],
            capture_output=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("source commit lookup failed") from exc
    if result.returncode != 0 or result.stdout != b"commit\n":
        raise ValueError("source identity is not an available Git commit")
    if must_be_head:
        head = subprocess.run(
            ["git", "-C", str(Path(__file__).resolve().parents[1]), "rev-parse", "HEAD"],
            capture_output=True, timeout=5, check=False,
        )
        if head.returncode != 0 or head.stdout.strip().decode("ascii") != commit:
            raise ValueError("source commit differs from checked-out HEAD")
    return f"/opt/aegis/{commit}/bin/aegis-server"


def versioned_roster_path(commit: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("source commit must be a full lowercase SHA-1")
    return Path(f"/etc/ssh/aegis-policy-authorized-keys-{commit}")


def expected(commit: str) -> dict[str, bytes]:
    command = (
        f"{source_binary(commit)} device-policy export "
        "--registry /var/lib/aegis-device-authority/registry.json --forced-ssh"
    )
    snippet = (
        "# Generated for one independently attested server binary.\n"
        "Match User aegis-policy-export\n"
        f"    AuthorizedKeysFile {versioned_roster_path(commit)}\n"
        f"    ForceCommand {command}\n"
        "    AuthenticationMethods publickey\n"
        "    PasswordAuthentication no\n"
        "    KbdInteractiveAuthentication no\n"
        "    DisableForwarding yes\n"
        "    PermitTTY no\n"
        "    PermitUserRC no\n"
        "    PermitTunnel no\n"
        "    MaxSessions 1\n"
        "Match all\n"
    ).encode("ascii")
    prefix = f'restrict,command="{command}"'.encode("ascii")
    return {SNIPPET: snippet, PREFIX: prefix + b"\n"}


def read_regular(path: Path, *, owner: int | None = None, mode: int | None = None) -> bytes:
    if owner is not None:
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner or parent.st_mode & 0o022:
            raise ValueError(f"untrusted parent directory: {path.name}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"not a single-link regular file: {path.name}")
        if before.st_size > MAX_BYTES:
            raise ValueError(f"file exceeds size limit: {path.name}")
        if owner is not None and before.st_uid != owner:
            raise ValueError(f"unexpected owner: {path.name}")
        if mode is not None and stat.S_IMODE(before.st_mode) != mode:
            raise ValueError(f"unexpected mode: {path.name}")
        data = handle.read(MAX_BYTES + 1)
        after = os.fstat(handle.fileno())
    if len(data) != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError(f"file changed while reading: {path.name}")
    return data


def verify_binary(path: Path, digest: str) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 200 * 1024 * 1024:
            raise ValueError("binary must be a bounded single-link regular file")
        sha = hashlib.sha256()
        while block := handle.read(1024 * 1024):
            sha.update(block)
        after = os.fstat(handle.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or sha.hexdigest() != digest:
        raise ValueError("binary changed or differs from supplied SHA-256")


def split_options(raw: bytes) -> list[bytes]:
    if any(byte < 32 or byte > 126 for byte in raw):
        raise ValueError("control or non-ASCII byte in authorized-key options")
    tokens, start, quoted, escaped = [], 0, False, False
    for index, byte in enumerate(raw):
        if escaped:
            escaped = False
        elif byte == 92 and quoted:
            escaped = True
        elif byte == 34:
            quoted = not quoted
        elif byte == 44 and not quoted:
            tokens.append(raw[start:index])
            start = index + 1
    if quoted or escaped:
        raise ValueError("unbalanced authorized-key option quotes")
    tokens.append(raw[start:])
    if not all(tokens):
        raise ValueError("empty authorized-key option")
    return tokens


def rewrite_key_line(line: bytes, old_command: bytes, new_command: bytes) -> bytes:
    matched = re.search(rb"[ \t]+(ssh-ed25519|ecdsa-sha2-nistp256|rsa-sha2-512|rsa-sha2-256|ssh-rsa)[ \t]+", line)
    if matched is None:
        raise ValueError("authorized key lacks supported algorithm")
    options, rest = line[:matched.start()], line[matched.start():]
    fields = rest.split(None, 3)
    if len(fields) < 2 or fields[0] not in KEY_ALGORITHMS or re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", fields[1]) is None:
        raise ValueError("malformed public key body")
    tokens = split_options(options)
    if tokens.count(b"restrict") != 1:
        raise ValueError("authorized key must have one restrict option")
    old_token = b'command="' + old_command + b'"'
    if tokens.count(old_token) != 1 or sum(token.startswith(b"command=") for token in tokens) != 1:
        raise ValueError("authorized key must have one exact old forced command")
    allowed = {b"restrict", old_token, b"no-port-forwarding", b"no-X11-forwarding", b"no-agent-forwarding", b"no-pty", b"no-user-rc"}
    for token in tokens:
        if token not in allowed and not (
            (token.startswith(b'from="') or token.startswith(b'expiry-time="'))
            and token.endswith(b'"')
        ):
            raise ValueError("unreviewed authorized-key option")
    replaced = [b'command="' + new_command + b'"' if token == old_token else token for token in tokens]
    return b",".join(replaced) + rest


def rewrite_keys(source: Path, prior_commit: str, current_prefix: bytes, *, owner: int) -> tuple[bytes, int]:
    old_command = (
        f"{source_binary(prior_commit, must_be_head=False)} device-policy export "
        "--registry /var/lib/aegis-device-authority/registry.json --forced-ssh"
    )
    new_command = current_prefix.removeprefix(b'restrict,command="').removesuffix(b'"')
    if not new_command or b'"' in new_command:
        raise ValueError("invalid current forced command")
    original = read_regular(source, owner=owner, mode=0o644)
    transformed_lines, count = [], 0
    for line in original.splitlines(keepends=True):
        if not line.strip() or line.lstrip().startswith(b"#"):
            transformed_lines.append(line)
        else:
            newline = b"\r\n" if line.endswith(b"\r\n") else b"\n" if line.endswith(b"\n") else b""
            transformed_lines.append(rewrite_key_line(line.removesuffix(newline), old_command.encode("ascii"), new_command) + newline)
            count += 1
    if not count:
        raise ValueError("authorized key roster is empty")
    transformed = b"".join(transformed_lines)
    return transformed, count


def stage(directory: Path, files: dict[str, bytes]) -> None:
    parent = directory.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        raise ValueError("staging parent must be a private owner-controlled directory")
    directory.mkdir(mode=0o700)
    for name, body in files.items():
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--prior-source-commit", required=True, help="exact source identity of installed forced command")
    parser.add_argument("--binary-sha256", required=True, help="independently attested candidate binary digest")
    parser.add_argument("--binary-file", required=True, type=Path, help="candidate binary for local SHA-256 check; signature remains external")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output-dir", type=Path)
    action.add_argument("--check-dir", type=Path)
    parser.add_argument("--authorized-keys", required=True, type=Path, help="protected existing roster; contents are never printed")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("production renderer requires root and a root-owned key roster")
        if re.fullmatch(r"[0-9a-f]{64}", args.binary_sha256) is None:
            raise ValueError("binary digest must be a lowercase SHA-256")
        verify_binary(args.binary_file, args.binary_sha256)
        files = expected(args.source_commit)
        if args.prior_source_commit == args.source_commit:
            raise ValueError("prior and current source identities must differ")
        rewritten, count = rewrite_keys(
            args.authorized_keys, args.prior_source_commit, files[PREFIX].rstrip(b"\n"),
            owner=0,
        )
        files[ROSTER] = rewritten
        if args.output_dir is not None:
            stage(args.output_dir, files)
        else:
            for name, expected_bytes in files.items():
                if read_regular(args.check_dir / name, owner=0, mode=0o600) != expected_bytes:
                    raise ValueError(f"staged SSH policy differs from source render: {name}")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"REFUSE: {exc}\n")
    for name, body in files.items():
        if name != ROSTER:
            print(f"{name} sha256={hashlib.sha256(body).hexdigest()}")
    print(f"binary-sha256={args.binary_sha256} (local bytes verified; signature unverified)")
    print(f"PASS: SSH policy staged/checked; authorized-key entries={count}; no signature or effective sshd attestation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
