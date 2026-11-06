#!/usr/bin/env python3
"""Generate the exact Linux/macOS Cargo notice superset from offline locks.

The output is source material for package builds. It is never a release SBOM:
the Rust tree includes build dependencies, and native/system libraries need
their separate artifact inventory.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "tools/macos/aegis-network-extension/Cargo.toml"
CLIENT_FEATURES = "raw-socket,chrome-like-tls,chrome-like-quic"
MAC_FEATURES = "chrome-like-tls,chrome-like-quic"
LICENSE_NAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE")


def cargo(*args: str) -> str:
    return subprocess.check_output(["cargo", *args], cwd=ROOT, text=True, timeout=180)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def license_sources(directory: Path, explicit: str | None) -> list[tuple[str, bytes]]:
    try:
        return _held_license_sources(directory, explicit)
    except (OSError, ValueError):
        raise ValueError("unsafe upstream license source") from None


def _held_license_sources(directory: Path, explicit: str | None) -> list[tuple[str, bytes]]:
    """Read only bounded regular license files from one held package tree.

    Absolute Cargo license paths are allowed only within this package. Keep
    every directory edge and leaf bound to its opened FD through the final
    recheck; aliases and external hardlinks never become notice contents.
    """
    def require(ok: bool) -> None:
        if not ok:
            raise ValueError("unsafe upstream license source")

    def identity(s):
        return s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid

    def generation(s):
        return (*identity(s), s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        edges = []
        def child(parent, name):
            fd = os.open(name, flags, dir_fd=parent)
            stack.callback(os.close, fd)
            edges.append((parent, name, fd, identity(os.fstat(fd))))
            return fd

        require(directory.is_absolute() and '..' not in directory.parts)
        anchor = os.open('/', flags); stack.callback(os.close, anchor)
        for part in directory.parts[1:]:
            anchor = child(anchor, part)
        package_before = generation(os.fstat(anchor))
        require(not package_before[2] & 0o022)
        names = os.listdir(anchor); require(len(names) <= 65536)
        selected = []
        for name in sorted(names):
            if not any(word in name.upper() for word in LICENSE_NAMES):
                continue
            info = os.stat(name, dir_fd=anchor, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                continue
            require(stat.S_ISREG(info.st_mode))
            selected.append((name,))
        if explicit is not None:
            require(type(explicit) is str and bool(explicit))
            path = Path(explicit)
            if path.is_absolute():
                path = path.relative_to(directory)
            parts = path.parts
            require(0 < len(parts) <= 16 and all(part not in ('', '.', '..') for part in parts))
            if parts not in selected:
                selected.append(parts)
        results = []
        leaves = []
        for parts in selected:
            parent = anchor
            for part in parts[:-1]:
                parent = child(parent, part)
                require(not os.fstat(parent).st_mode & 0o022)
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=parent)
            stack.callback(os.close, fd)
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                    not before.st_mode & 0o022 and 0 < before.st_size <= 200_000)
            data = bytearray()
            while len(data) <= 200_000:
                raw = os.read(fd, min(65536, 200_001 - len(data)))
                if not raw:
                    break
                data.extend(raw)
            require(len(data) == before.st_size and generation(os.fstat(fd)) == generation(before))
            data = bytes(data); data.decode('utf-8')
            leaves.append((parent, parts[-1], fd, generation(before)))
            results.append((parts[-1], data))
        require(generation(os.fstat(anchor)) == package_before)
        for parent, name, fd, expected in leaves:
            require(generation(os.fstat(fd)) == expected and
                    generation(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)
        for parent, name, fd, expected in edges:
            require(identity(os.fstat(fd)) == expected and
                    identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)
        return results


def normal_build_metadata_packages(metadata: dict, package: str) -> list[dict]:
    """Keep the resolved normal/build graph, including unified feature edges.

    Cargo metadata may conservatively unify features with development users.
    Retaining those reachable packages is safe for a notice superset; direct
    development-only edges are excluded. Missing graph nodes always refuse.
    """
    packages = {item['id']: item for item in metadata['packages']}
    nodes = {item['id']: item for item in metadata['resolve']['nodes']}
    if (len(packages) != len(metadata['packages']) or
            len(nodes) != len(metadata['resolve']['nodes'])):
        raise RuntimeError('duplicate Cargo metadata identity')
    roots = [identifier for identifier in metadata['workspace_members']
             if packages[identifier]['name'] == package]
    if len(roots) != 1:
        raise RuntimeError('Cargo metadata root is not unique')
    queue = roots.copy()
    seen = set()
    while queue:
        identifier = queue.pop()
        if identifier in seen:
            continue
        if identifier not in packages or identifier not in nodes:
            raise RuntimeError('Cargo metadata package or resolve node missing')
        seen.add(identifier)
        for dependency in nodes[identifier]['deps']:
            kinds = dependency['dep_kinds']
            if not kinds or any(item['kind'] not in (None, 'normal', 'build', 'dev')
                                for item in kinds):
                raise RuntimeError('Cargo metadata dependency kind is unknown')
            if any(item['kind'] != 'dev' for item in kinds):
                queue.append(dependency['pkg'])
    return [packages[identifier] for identifier in sorted(seen)]


def add_scope(
    entries: dict[tuple[str, str, str], dict],
    scope: str,
    manifest: Path,
    target: str,
    package: str,
    features: str,
    metadata_superset: bool = False,
) -> None:
    shared = ["--manifest-path", str(manifest), "--locked", "--offline"]
    feature_arg = ["--features", features] if features else []
    metadata = json.loads(cargo("metadata", "--format-version", "1", *shared,
                                "--filter-platform", target, *feature_arg))
    by_name_version = {}
    for item in metadata["packages"]:
        key = (item["name"], item["version"])
        if key in by_name_version and by_name_version[key]["id"] != item["id"]:
            raise RuntimeError(f"ambiguous crate identity: {key}")
        by_name_version[key] = item
    tree = cargo("tree", *shared, "-p", package, "--target", target,
                 "-e", "normal,build", "--prefix", "none", "-f", "{p}",
                 *feature_arg)
    selected = []
    for line in tree.splitlines():
        match = re.match(r"^(\S+) v(\S+)", line)
        if not match:
            continue
        selected.append(by_name_version[match.groups()])
    if metadata_superset:
        selected.extend(normal_build_metadata_packages(metadata, package))
    for item in selected:
        path = Path(item["manifest_path"])
        # The extension's independent workspace lists Aegis path crates as
        # non-members. Only vendor paths under third_party are third-party.
        if item["id"] in metadata["workspace_members"]:
            continue
        if item["source"] is None:
            relative = path.relative_to(ROOT)
            if relative.parts[0] != "third_party":
                continue
            origin = "/".join(relative.parts[:2])
        else:
            origin = item["source"]
        key = (item["name"], item["version"], origin)
        if key not in entries:
            if not item.get("license") and not item.get("license_file"):
                raise RuntimeError(f"missing license metadata: {key}")
            entries[key] = {"package": item, "scopes": set()}
        entries[key]["scopes"].add(scope)


def render() -> str:
    entries: dict[tuple[str, str, str], dict] = {}
    for arch, target in (("arm64", "aarch64-unknown-linux-gnu"),
                         ("x64", "x86_64-unknown-linux-gnu")):
        add_scope(entries, f"linux-{arch}-client", ROOT / "Cargo.toml", target,
                  "aegis-client", CLIENT_FEATURES)
        add_scope(entries, f"linux-{arch}-server", ROOT / "Cargo.toml", target,
                  "aegis-server", "")
    for arch, target in (("arm64", "aarch64-apple-darwin"),
                         ("x64", "x86_64-apple-darwin")):
        add_scope(entries, f"macos-{arch}-client", ROOT / "Cargo.toml", target,
                  "aegis-client", MAC_FEATURES)
        add_scope(entries, f"macos-{arch}-extension", EXTENSION, target,
                  "aegis-network-extension", "apple")
        add_scope(entries, f"macos-{arch}-extension-vp8", EXTENSION, target,
                  "aegis-network-extension", "apple,sfu-media-vp8", metadata_superset=True)
        add_scope(entries, f"macos-{arch}-extension-vp8-quic", EXTENSION, target,
                  "aegis-network-extension", "apple,sfu-media-vp8,enrolled-quic",
                  metadata_superset=True)

    license_texts: dict[str, tuple[bytes, str]] = {}
    rows = []
    for key, entry in sorted(entries.items()):
        package = entry["package"]
        directory = Path(package["manifest_path"]).parent
        refs = []
        for name, data in license_sources(directory, package.get("license_file")):
            sha = hashlib.sha256(data).hexdigest()
            license_texts.setdefault(sha, (data, f"{key[0]} {key[1]} {name}"))
            refs.append(f"{name}@{sha[:16]}")
        expression = package.get("license") or f"file:{package['license_file']}"
        rows.append((key, expression, ",".join(sorted(entry["scopes"])),
                     ",".join(refs) or "upstream archive has no license file"))

    lock = digest(ROOT / "Cargo.lock")
    extension_lock = digest(ROOT / "tools/macos/aegis-network-extension/Cargo.lock")
    lines = [
        "AEGIS THIRD-PARTY NOTICES — offline Cargo dependency inventory",
        f"Cargo.lock SHA-256: {lock}",
        f"macOS extension Cargo.lock SHA-256: {extension_lock}",
        "Targets: Linux arm64/x64 client+server; macOS arm64/x64 client+extension.",
        "Includes normal and build dependencies under the release feature sets;",
        "this is an intentional superset of code linked into each binary.",
        "Optional VP8 scopes retain resolved metadata feature-unification edges too.",
        "The Aegis project MIT/Apache license texts ship separately beside this file.",
        "Vendor paths are listed below. Native/system binaries require separate review.",
        f"Third-party crates: {len(rows)}. Distinct upstream license/notice files: {len(license_texts)}.",
        "",
        "name | version | source | SPDX license expression | scopes | upstream license files",
    ]
    for (name, version, source), expression, scopes, refs in rows:
        lines.append(f"{name} | {version} | {source} | {expression} | {scopes} | {refs}")
    lines += ["", "UPSTREAM LICENSE AND NOTICE TEXTS", ""]
    for sha, (data, description) in sorted(license_texts.items()):
        lines.extend((f"===== {sha} {description} =====", data.decode("utf-8").rstrip(), ""))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the committed notice differs")
    parser.add_argument("--output", type=Path, default=ROOT / "THIRD-PARTY-NOTICES")
    args = parser.parse_args()
    expected = render()
    if args.check:
        if args.output.read_bytes() != expected.encode():
            print("THIRD-PARTY-NOTICES is stale", file=sys.stderr)
            return 1
    else:
        args.output.write_text(expected)
    print(f"{args.output}: {hashlib.sha256(expected.encode()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
