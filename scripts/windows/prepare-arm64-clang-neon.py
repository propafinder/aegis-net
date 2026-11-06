#!/usr/bin/env python3
"""Prepare a checked Clang ARM64/MSVC header overlay for offline Cargo builds."""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(root: Path) -> str:
    """Bind every regular file and symlink in an xwin splat by relative path."""
    if not root.is_dir():
        raise ValueError(f"xwin root missing: {root}")
    digest = hashlib.sha256()
    entries = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    for entry in entries:
        relative = entry.relative_to(root).as_posix().encode("utf-8")
        if entry.is_symlink():
            kind = b"link"
            content = entry.readlink().as_posix().encode("utf-8")
        elif entry.is_file():
            kind = b"file"
            content = sha256(entry).encode("ascii")
        elif entry.is_dir():
            kind = b"dir"
            content = b""
        else:
            raise ValueError(f"unsupported xwin input type: {entry}")
        for field in (kind, relative, content):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return digest.hexdigest()


def exact_version(program: Path, expected: str) -> None:
    actual = subprocess.check_output([str(program), "--version"], text=True).splitlines()[0]
    if expected not in actual.split():
        raise ValueError(f"{program.name} version mismatch: expected {expected}, got {actual}")


def prepare(manifest: Path, clang: Path, xwin: Path, xwin_root: Path, out: Path) -> Path:
    config = json.loads(manifest.read_text())
    exact_version(clang, config["clang_version"])
    exact_version(xwin, config["xwin_version"])
    resource = Path(subprocess.check_output([str(clang), "-print-resource-dir"], text=True).strip())
    headers = resource / "include"
    for name, expected in config["clang_headers"].items():
        candidate = headers / name
        if not candidate.is_file() or sha256(candidate) != expected:
            raise ValueError(f"Clang header missing or hash mismatch: {name}")
    actual_tree = tree_sha256(xwin_root)
    if actual_tree != config["xwin_tree_sha256"]:
        raise ValueError(f"xwin tree hash mismatch: expected {config['xwin_tree_sha256']}, got {actual_tree}")
    include_dirs = [
        xwin_root / "sdk/include/ucrt",
        xwin_root / "sdk/include/shared",
        xwin_root / "sdk/include/um",
        xwin_root / "crt/include",
    ]
    library_dirs = [
        xwin_root / "sdk/lib/um/aarch64",
        xwin_root / "sdk/lib/ucrt/aarch64",
        xwin_root / "crt/lib/aarch64",
    ]
    for directory in include_dirs + library_dirs:
        if not directory.is_dir():
            raise ValueError(f"xwin directory missing: {directory}")
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"output directory must be empty: {out}")
    out.mkdir(parents=True, exist_ok=True)
    overlay = out / "headers"
    overlay.mkdir()
    for name in config["clang_headers"]:
        (overlay / name).symlink_to(headers / name)
    wrapper = out / "clang-arm64-msvc-cc.sh"
    arguments = [
        str(clang),
        "--target=aarch64-pc-windows-msvc",
        "-I", str(overlay),
    ]
    for directory in include_dirs:
        arguments.extend(["-isystem", str(directory)])
    wrapper.write_text("#!/bin/sh\nexec " + shlex.join(arguments) + ' "$@"\n')
    wrapper.chmod(0o700)
    (out / "verified-inputs.json").write_text(json.dumps({
        "manifest_sha256": sha256(manifest),
        "clang_resource_dir": str(resource),
        "xwin_root": str(xwin_root),
        "xwin_tree_sha256": actual_tree,
        "wrapper_sha256": sha256(wrapper),
    }, sort_keys=True, indent=2) + "\n")
    return wrapper


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("arm64-clang-neon-inputs.json"))
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--xwin", type=Path, required=True)
    parser.add_argument("--xwin-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        wrapper = prepare(args.manifest, args.clang, args.xwin, args.xwin_root, args.out)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"ARM64/MSVC Clang input refusal: {error}", file=sys.stderr)
        return 1
    print(wrapper)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
