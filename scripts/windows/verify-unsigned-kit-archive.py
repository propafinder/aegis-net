#!/usr/bin/env python3
"""Verify a Windows unsigned kit ZIP before its delivery hash is recorded."""

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from pathlib import Path

BASE = {
    "README.txt": 8 * 1024 * 1024,
    "WINTUN-LICENSE.txt": 8 * 1024 * 1024,
    "LICENSE-APACHE": 8 * 1024 * 1024,
    "LICENSE-MIT": 8 * 1024 * 1024,
    "NOTICE": 8 * 1024 * 1024,
    "aegis-client.exe": 256 * 1024 * 1024,
    "aegis-winctl.exe": 256 * 1024 * 1024,
    "wintun.dll": 2 * 1024 * 1024,
}
RESEARCH = {
    "aegis-measure.exe": 256 * 1024 * 1024,
    "aegis-transport-lab.exe": 256 * 1024 * 1024,
    "research-operators.json": 16 * 1024,
}
HEX40 = re.compile(r"[a-f0-9]{40}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
CHUNK = 64 * 1024
MAX_ARCHIVE = 2 * 1024 * 1024 * 1024


@contextlib.contextmanager
def _held_read(path):
    if os.name != "nt":
        with open(path, "rb") as stream:
            yield stream
        return
    # Deny writes and deletion while Windows inspects and hashes this exact
    # archive handle. A pre-existing writer causes CreateFileW to fail.
    import ctypes
    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p
    )
    create.restype = ctypes.c_void_p
    handle = create(str(path), 0x80000000, 0x00000001, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "exclusive archive read refused")
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(ctypes.c_void_p(handle))
        raise
    with os.fdopen(descriptor, "rb") as stream:
        yield stream


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest JSON key")
        result[key] = value
    return result


def _read_member(archive, info, limit):
    if info.file_size < 1 or info.file_size > limit or info.compress_size > MAX_ARCHIVE:
        raise ValueError("ZIP member size refused")
    digest = hashlib.sha256()
    data = bytearray() if info.filename == "manifest.json" else None
    count = 0
    with archive.open(info, "r") as member:
        while chunk := member.read(CHUNK):
            count += len(chunk)
            if count > info.file_size or count > limit:
                raise ValueError("ZIP member inflated beyond limit")
            digest.update(chunk)
            if data is not None:
                data.extend(chunk)
    if count != info.file_size:
        raise ValueError("ZIP member length changed")
    return digest.hexdigest(), bytes(data) if data is not None else None


def verify(path, expected_source, expected_manifest_sha256, research):
    if not HEX40.fullmatch(expected_source) or not HEX64.fullmatch(expected_manifest_sha256):
        raise ValueError("expected source or manifest digest refused")
    expected = dict(BASE)
    if research:
        expected.update(RESEARCH)
    expected["manifest.json"] = 65536
    with _held_read(path) as stream:
        before = os.fstat(stream.fileno())
        if before.st_size < 1 or before.st_size > MAX_ARCHIVE:
            raise ValueError("kit ZIP size refused")
        with zipfile.ZipFile(stream, "r") as archive:
            infos = archive.infolist()
            if len(infos) != len(expected):
                raise ValueError("kit ZIP member count refused")
            members = {}
            for info in infos:
                name = info.filename
                mode = (info.external_attr >> 16) & 0xFFFF
                kind = stat.S_IFMT(mode)
                if (
                    name not in expected
                    or name in members
                    or info.is_dir()
                    or info.flag_bits & 1
                    or kind not in (0, stat.S_IFREG)
                ):
                    raise ValueError("kit ZIP member name/type refused")
                members[name] = info
            manifest_digest, raw = _read_member(
                archive, members["manifest.json"], expected["manifest.json"]
            )
            if manifest_digest != expected_manifest_sha256:
                raise ValueError("kit ZIP manifest digest mismatch")
            manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
            if (
                not isinstance(manifest, dict)
                or set(manifest) != {
                    "schema", "platform", "source_commit", "signed_release",
                    "project_licenses", "files"
                }
                or type(manifest["schema"]) is not int
                or manifest["schema"] != (4 if research else 2)
                or manifest["platform"] not in ("windows-x86_64", "windows-aarch64")
                or (research and manifest["platform"] != "windows-x86_64")
                or manifest["source_commit"] != expected_source
                or manifest["signed_release"] is not False
                or manifest["project_licenses"] is not True
                or not isinstance(manifest["files"], dict)
                or set(manifest["files"]) != set(expected) - {"manifest.json"}
            ):
                raise ValueError("kit ZIP manifest identity refused")
            for name, limit in expected.items():
                if name == "manifest.json":
                    continue
                expected_digest = manifest["files"][name]
                if not isinstance(expected_digest, str) or not HEX64.fullmatch(expected_digest):
                    raise ValueError("kit ZIP payload digest syntax refused")
                actual_digest, _ = _read_member(archive, members[name], limit)
                if actual_digest != expected_digest:
                    raise ValueError("kit ZIP payload digest mismatch")
        stream.seek(0)
        archive_digest = hashlib.sha256()
        count = 0
        while chunk := stream.read(CHUNK):
            count += len(chunk)
            if count > MAX_ARCHIVE:
                raise ValueError("kit ZIP size changed")
            archive_digest.update(chunk)
        after = os.fstat(stream.fileno())
        if count != before.st_size or (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev, after.st_ino, after.st_size
        ):
            raise ValueError("kit ZIP changed during verification")
    return {
        "archive_sha256": archive_digest.hexdigest(),
        "manifest_sha256": manifest_digest,
        "platform": manifest["platform"],
        "source_commit": expected_source,
        "signed_release": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--research", action="store_true")
    args = parser.parse_args()
    try:
        result = verify(
            args.archive, args.source_commit, args.manifest_sha256, args.research
        )
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(f"unsigned kit archive refused: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
