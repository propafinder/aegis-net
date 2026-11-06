#!/usr/bin/env python3
"""Verify the complete two-architecture DEB inventory before release handoff."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid


class Refused(ValueError):
    pass


MANIFESTS = ("release.manifest.json", "release.manifest-aarch64.json",
             "client-release.manifest.json", "client-release.manifest-aarch64.json")
SIGNATURES = frozenset(f"{name}.sig" for name in MANIFESTS)
INDEX_NAME = "operator-files.manifest.json"
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,180}")


def expired(_signal, _frame):
    raise Refused("360-second inventory deadline exceeded")


def regular(path, size_limit):
    if path.is_symlink() or not path.is_file():
        raise Refused(f"missing or nonregular file: {path.name}")
    if path.stat().st_size > size_limit:
        raise Refused(f"oversized file: {path.name}")


def read_manifest(path):
    regular(path, 1024 * 1024)
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refused(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    if not isinstance(value, dict):
        raise Refused(f"invalid manifest: {path.name}")
    return value


def digest_file(path, deadline):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            if time.monotonic() >= deadline:
                raise Refused("inventory deadline exceeded while hashing")
            result.update(block)
    return result.hexdigest()


def split_deb_version(deb, upstream_version):
    split_version = deb.get("split_version", upstream_version)
    if (not isinstance(split_version, str) or
            re.fullmatch(re.escape(upstream_version) + r"(?:-[1-9][0-9]*)?", split_version) is None):
        raise Refused("split DEB version mismatch")
    return split_version


def write_json_atomic(path, value):
    output = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(output) > 1024 * 1024:
        raise Refused(f"oversized generated manifest: {path.name}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def seal_markers(directory, source_sha, deadline):
    """Write marker digests once, after the final manifest refresh."""
    if directory.is_symlink() or not directory.is_dir():
        raise Refused("release directory is missing or a symlink")
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise Refused("invalid exact source SHA")
    for name, arch, marker in (
        ("release.manifest.json", "x86_64", "split-deb-packages.manifest.json"),
        ("release.manifest-aarch64.json", "aarch64", "split-deb-packages-aarch64.manifest.json"),
    ):
        path = directory / name
        manifest = read_manifest(path)
        deb = manifest.get("artifacts", {}).get("deb")
        if (manifest.get("schema") != "aegis_linux_release_manifest_v1" or
                manifest.get("arch") != arch or manifest.get("git_sha") != source_sha or
                not isinstance(deb, dict) or deb.get("status") != "ready" or
                deb.get("manifest_path") != marker):
            raise Refused(f"marker sealing identity mismatch: {name}")
        marker_path = directory / marker
        read_manifest(marker_path)
        marker_digest = digest_file(marker_path, deadline)
        existing = deb.get("manifest_sha256")
        if existing is not None and existing != marker_digest:
            raise Refused(f"already-sealed marker changed: {marker}")
        deb["manifest_sha256"] = marker_digest
        write_json_atomic(path, manifest)


def seal_delivery_index(directory, source_sha, deadline):
    """Pin every payload byte; signed manifests and their signatures are cyclic."""
    releases = [read_manifest(directory / name) for name in MANIFESTS[:2]]
    version = releases[0].get("version")
    if (not isinstance(version, str) or releases[1].get("version") != version or
            any(manifest.get("git_sha") != source_sha for manifest in releases)):
        raise Refused("index source/version mismatch")
    files = {}
    flat = list(directory.iterdir())
    if len(flat) > 256:
        raise Refused("more than 256 flat release entries")
    for path in flat:
        if path.name in SIGNATURES:
            raise Refused("unsigned producer contains release signatures")
        if path.name in MANIFESTS or path.name == INDEX_NAME:
            continue
        if path.is_symlink() or not path.is_file() or SAFE_NAME.fullmatch(path.name) is None:
            raise Refused(f"unsafe indexed release entry: {path.name!r}")
        regular(path, 2 * 1024 * 1024 * 1024)
        files[path.name] = digest_file(path, deadline)
    if not files:
        raise Refused("empty release payload index")
    index_path = directory / INDEX_NAME
    if index_path.exists() or index_path.is_symlink():
        raise Refused("release payload index already exists")
    write_json_atomic(index_path, {"schema": "aegis_operator_payload_index_v1",
                                   "source_sha": source_sha, "version": version, "files": files})
    index_digest = digest_file(index_path, deadline)
    for name, manifest in zip(MANIFESTS[:2], releases):
        manifest["artifacts"]["delivery_inventory"] = {"path": INDEX_NAME,
                                                         "sha256": index_digest}
        write_json_atomic(directory / name, manifest)


def verify(directory, source_sha, split_checker, owner_checker, deadline,
           signature_mode="unsigned", public_key=None):
    if directory.is_symlink() or not directory.is_dir():
        raise Refused("release directory is missing or a symlink")
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise Refused("invalid exact source SHA")
    flat = list(directory.iterdir())
    if sum(path.is_file() and not path.is_symlink() for path in flat) > 256:
        raise Refused("more than 256 flat regular files")
    for path in flat:
        if path.is_symlink():
            raise Refused(f"release symlink: {path.name}")
        if not path.is_file():
            raise Refused(f"nonflat release entry: {path.name}")
        if SAFE_NAME.fullmatch(path.name) is None:
            raise Refused(f"unsafe upload filename: {path.name!r}")

    manifest_names = ("release.manifest.json", "release.manifest-aarch64.json")
    manifests = {name: read_manifest(directory / name) for name in manifest_names}
    expected = set()
    version = None
    common_split_version = None
    for name, arch, deb_arch, marker in (
        (manifest_names[0], "x86_64", "amd64", "split-deb-packages.manifest.json"),
        (manifest_names[1], "aarch64", "arm64", "split-deb-packages-aarch64.manifest.json"),
    ):
        manifest = manifests[name]
        if manifest.get("schema") != "aegis_linux_release_manifest_v1":
            raise Refused(f"release schema mismatch: {name}")
        if manifest.get("git_sha") != source_sha or manifest.get("arch") != arch:
            raise Refused(f"source or architecture mismatch: {name}")
        if version is None:
            version = manifest.get("version")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9][0-9A-Za-z.+:~-]{0,80}", version):
            raise Refused("invalid release version")
        if manifest.get("version") != version:
            raise Refused("release version mismatch between architectures")
        deb = manifest.get("artifacts", {}).get("deb")
        if not isinstance(deb, dict) or deb.get("status") != "ready" or deb.get("manifest_path") != marker:
            raise Refused(f"split marker identity mismatch: {name}")
        split_version = split_deb_version(deb, version)
        if common_split_version is None:
            common_split_version = split_version
        elif split_version != common_split_version:
            raise Refused("split DEB version mismatch between architectures")
        expected.add(marker)
        marker_path = directory / marker
        read_manifest(marker_path)
        if deb.get("manifest_sha256") != digest_file(marker_path, deadline):
            raise Refused(f"split marker digest mismatch: {marker}")
        split = deb.get("split")
        combined = deb.get("combined")
        if not isinstance(split, dict) or set(split) != {"server", "client"} or not isinstance(combined, dict):
            raise Refused(f"DEB set identity mismatch: {name}")
        for role, record in (("server", split["server"]), ("client", split["client"]), ("combined", combined)):
            if not isinstance(record, dict):
                raise Refused(f"missing {role} DEB record: {name}")
            package = "aegis" if role == "combined" else f"aegis-{role}"
            deb_version = version if role == "combined" else split_version
            deb_name = f"{package}_{deb_version}_{deb_arch}.deb"
            sidecar_name = f"{deb_name}.sha256"
            if record.get("path") != deb_name or record.get("sha256_path") != sidecar_name:
                raise Refused(f"DEB path mismatch: {deb_name}")
            expected.update((deb_name, sidecar_name))
            package_path, sidecar = directory / deb_name, directory / sidecar_name
            regular(package_path, 512 * 1024 * 1024)
            regular(sidecar, 128)
            digest = digest_file(package_path, deadline)
            if record.get("sha256") != digest or sidecar.read_text(encoding="ascii") != f"{digest}  {deb_name}\n":
                raise Refused(f"DEB SHA or sidecar mismatch: {deb_name}")
            if role == "combined":
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Refused("inventory deadline exceeded")
                result = subprocess.run((sys.executable, "-I", "-B", str(owner_checker), str(package_path)),
                                        capture_output=True, text=True, timeout=min(45, remaining), check=False)
                if result.returncode:
                    raise Refused(f"combined DEB owner refused: {deb_name}: {result.stderr.strip()}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Refused("inventory deadline exceeded")
        result = subprocess.run((sys.executable, "-I", "-B", str(split_checker), str(directory),
                                 "--arch", deb_arch, "--version", split_version,
                                 "--release-manifest", str(directory / name), "--source-sha", source_sha),
                                capture_output=True, text=True, timeout=remaining, check=False)
        if result.returncode:
            raise Refused(f"split DEB set refused: {deb_arch}: {result.stderr.strip()}")
    actual = {path.name for path in flat if path.name.endswith((".deb", ".deb.sha256"))
              or path.name.startswith("split-deb-packages") and path.name.endswith(".manifest.json")}
    if actual != expected:
        raise Refused(f"extra or missing DEB inventory files: {sorted(actual ^ expected)}")
    index_records = [manifests[name].get("artifacts", {}).get("delivery_inventory")
                     for name in manifest_names]
    if not all(isinstance(item, dict) and item.get("path") == INDEX_NAME and
               isinstance(item.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
               for item in index_records):
        raise Refused("release payload index identity missing")
    if index_records[0]["sha256"] != index_records[1]["sha256"]:
        raise Refused("operator release manifests disagree on payload index")
    index_path = directory / INDEX_NAME
    index = read_manifest(index_path)
    if digest_file(index_path, deadline) != index_records[0]["sha256"]:
        raise Refused("release payload index SHA mismatch")
    if (index.get("schema") != "aegis_operator_payload_index_v1" or
            index.get("source_sha") != source_sha or index.get("version") != version):
        raise Refused("release payload index source/version mismatch")
    indexed = index.get("files")
    if not isinstance(indexed, dict) or not indexed or len(indexed) > 256:
        raise Refused("invalid release payload index entries")
    excluded = set(MANIFESTS) | SIGNATURES | {INDEX_NAME}
    selected = {path.name for path in flat if path.name not in excluded}
    if selected != set(indexed):
        raise Refused(f"release payload index file set mismatch: {sorted(selected ^ set(indexed))}")
    for name, digest in sorted(indexed.items()):
        if SAFE_NAME.fullmatch(name) is None or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise Refused(f"invalid indexed file record: {name!r}")
        path = directory / name
        regular(path, 2 * 1024 * 1024 * 1024)
        if digest_file(path, deadline) != digest:
            raise Refused(f"release payload byte mismatch: {name}")
    present_signatures = {path.name for path in flat if path.name in SIGNATURES}
    if signature_mode == "unsigned":
        if present_signatures:
            raise Refused("unsigned handoff contains release signatures")
    elif signature_mode == "signed":
        if present_signatures != SIGNATURES or public_key is None:
            raise Refused("signed handoff missing exact release signatures or public key")
        regular(public_key, 4096)
        for name in MANIFESTS:
            signature = directory / f"{name}.sig"
            regular(signature, 64)
            if signature.stat().st_size != 64:
                raise Refused(f"invalid Ed25519 signature length: {signature.name}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refused("inventory deadline exceeded")
            result = subprocess.run(("openssl", "pkeyutl", "-verify", "-pubin",
                                     "-inkey", str(public_key), "-rawin", "-in",
                                     str(directory / name), "-sigfile", str(signature)),
                                    capture_output=True, text=True, timeout=min(15, remaining), check=False)
            if result.returncode:
                raise Refused(f"release signature refused: {name}")
    else:
        raise Refused("invalid signature mode")
    return tuple(sorted(path.name for path in flat))


def emit_exact_upload_paths(directory, names, output):
    """Upload only the verified snapshot, never a directory or live glob."""
    if output.is_symlink() or not output.is_file():
        raise Refused("GitHub output path is missing or a symlink")
    delimiter = f"AEGIS_EXACT_UPLOAD_{uuid.uuid4().hex}"
    lines = [f"upload_paths<<{delimiter}"]
    lines.extend(str(directory / name) for name in names)
    lines.append(delimiter)
    with output.open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--split-checker", type=Path, default=Path("scripts/verify-split-deb-package-set.py"))
    parser.add_argument("--owner-checker", type=Path, default=Path("scripts/verify-deb-archive-ownership.py"))
    parser.add_argument("--seal-markers", action="store_true",
                        help="bind exact marker bytes after the final producer manifest refresh")
    parser.add_argument("--github-output", type=Path,
                        help="emit exact verified file paths for upload-artifact")
    parser.add_argument("--signature-mode", choices=("unsigned", "signed"), default="unsigned")
    parser.add_argument("--public-key", type=Path,
                        help="pinned Ed25519 release public key; required for signed mode")
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(360)
    try:
        if args.seal_markers:
            seal_markers(args.directory, args.source_sha, time.monotonic() + 360)
            seal_delivery_index(args.directory, args.source_sha, time.monotonic() + 360)
        names = verify(args.directory, args.source_sha, args.split_checker, args.owner_checker,
                       time.monotonic() + 360, args.signature_mode, args.public_key)
        if args.github_output is not None:
            emit_exact_upload_paths(args.directory, names, args.github_output)
    except (Refused, OSError, UnicodeError, ValueError, TypeError, KeyError,
            subprocess.TimeoutExpired) as error:
        print(f"release DEB inventory REFUSED: {error}", file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)
    print("PASS: exact six DEBs, six sidecars, two split markers, source and ownership")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
