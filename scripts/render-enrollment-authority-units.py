#!/usr/bin/env python3
"""Render/check the three enrollment authority units for one immutable release.

This is an offline staging aid. It does not install units, reload systemd,
restart services, inspect private state, or authorize a deployment.
"""

import argparse
import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path


UNITS = (
    "aegis-enrollment-authority.service",
    "aegis-enrollment-policy-stage.service",
    "aegis-enrollment-policy-publish.service",
)
LEGACY = b"ExecStart=/usr/local/bin/aegis-server "
MAX_UNIT_BYTES = 64 * 1024


def release_binary(source_commit: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("source commit must be a full lowercase SHA-1")
    return f"/opt/aegis/{source_commit}/bin/aegis-server".encode("ascii")


def read_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as unit:
        before = os.fstat(unit.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"unit must be a single-link regular file: {path.name}")
        if before.st_size > MAX_UNIT_BYTES:
            raise ValueError(f"unit exceeds size limit: {path.name}")
        data = unit.read(MAX_UNIT_BYTES + 1)
        after = os.fstat(unit.fileno())
    if len(data) != before.st_size or (before.st_size, before.st_mtime_ns) != (
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ValueError(f"unit changed or exceeded size limit: {path.name}")
    return data


def committed_templates(source_commit: str) -> dict[str, bytes]:
    root = Path(__file__).resolve().parents[1]

    def git_bytes(*arguments: str) -> bytes:
        try:
            result = subprocess.run(
                ["git", "-C", str(root), *arguments],
                capture_output=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("source commit lookup failed") from exc
        if result.returncode != 0:
            raise ValueError("source commit or unit blob is unavailable")
        return result.stdout

    if git_bytes("cat-file", "-t", source_commit) != b"commit\n":
        raise ValueError("source identity is not a Git commit")
    return {
        name: git_bytes("cat-file", "blob", f"{source_commit}:packaging/systemd/{name}")
        for name in UNITS
    }


def expected_units(templates: Path, source_commit: str) -> dict[str, bytes]:
    binary = release_binary(source_commit)
    committed = committed_templates(source_commit)
    result = {}
    for name in UNITS:
        source = read_regular(templates / name)
        if source != committed[name]:
            raise ValueError(f"template differs from source commit: {name}")
        if source.count(LEGACY) != 1:
            raise ValueError(f"template must contain one legacy ExecStart: {name}")
        rendered = source.replace(LEGACY, b"ExecStart=" + binary + b" ")
        if b"/usr/local/bin/aegis-server" in rendered:
            raise ValueError(f"template retains a legacy binary path: {name}")
        result[name] = rendered
    return result


def check_units(installed: Path, expected: dict[str, bytes]) -> None:
    for name, body in expected.items():
        if os.path.lexists(installed / f"{name}.d"):
            raise ValueError(f"unit drop-ins require separate effective-unit review: {name}")
        actual = read_regular(installed / name)
        if actual != body:
            raise ValueError(f"installed unit differs from source render: {name}")


def render_units(output: Path, expected: dict[str, bytes]) -> None:
    parent = output.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or parent.st_mode & 0o077
    ):
        raise ValueError("staging parent must be a private owner-controlled directory")
    output.mkdir(mode=0o700)
    for name, body in expected.items():
        path = output / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as unit:
            unit.write(body)
            unit.flush()
            os.fsync(unit.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output-dir", type=Path)
    action.add_argument("--check-dir", type=Path)
    args = parser.parse_args()
    templates = Path(__file__).resolve().parents[1] / "packaging/systemd"
    try:
        expected = expected_units(templates, args.source_commit)
        if args.output_dir is not None:
            render_units(args.output_dir, expected)
        else:
            check_units(args.check_dir, expected)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"REFUSE: {exc}\n")
    for name, body in expected.items():
        print(f"{name} sha256={hashlib.sha256(body).hexdigest()}")
    print("PASS: three units match supplied Git commit templates and one versioned path; binary identity unverified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
