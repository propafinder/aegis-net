#!/usr/bin/env python3
"""Prepare private digest-only input for the read-only bundle store classifier.

This does not contact a server, redeem/revoke capabilities, or sanitize evidence.
The two output files must be created inside an operator-owned 0700 directory.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import parse_qsl, urlsplit

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("url_gate", HERE / "check-tracked-evidence-url-credentials.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")


def discover(root):
    inventory = subprocess.run(["git", "ls-files", "-z", "--", gate.guard.EVIDENCE_PREFIX], cwd=root,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
    paths = [entry.decode("utf-8") for entry in inventory.stdout.split(b"\0") if entry]
    found = {}
    unreadable = 0
    for name in paths:
        if not name.startswith(gate.guard.EVIDENCE_PREFIX):
            continue
        path = root / name
        if (path.is_symlink() or not path.is_file()
                or path.suffix not in gate.guard.TEXT_SUFFIXES | {".raw"}
                or path.stat().st_size > gate.guard.MAX_TEXT_BYTES):
            continue
        try:
            raw = path.read_bytes()
            content = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8")
        except (OSError, UnicodeError):
            unreadable += 1
            continue
        seen_in_file = set()
        for text in gate.decoded_texts(content, path.suffix):
            for match in gate.URL.finditer(text):
                try:
                    url = urlsplit(match.group())
                    if "bundle" not in url.path.casefold():
                        continue
                    for key, value in parse_qsl(url.query, keep_blank_values=True):
                        if key.casefold() == "token" and HEX64.fullmatch(value):
                            seen_in_file.add(value)
                except ValueError:
                    continue
        for value in seen_in_file:
            digest = hashlib.sha256(value.encode("ascii")).hexdigest()
            found.setdefault(digest, set()).add(name)
    return found, unreadable


def write_new(path, document):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(document, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def prepare(root, destination):
    parent = destination.resolve(strict=True)
    metadata = parent.stat()
    if not parent.is_dir() or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ValueError("private destination required")
    findings, unreadable = discover(root)
    if not findings or len(findings) > 64:
        raise ValueError("unsupported capability count")
    queries, cases = [], []
    for number, (digest, paths) in enumerate(sorted(findings.items()), 1):
        opaque_id = f"case-{number:03d}"
        queries.append({"opaque_id": opaque_id, "digest": digest})
        cases.append({"opaque_id": opaque_id, "tracked_files": sorted(paths)})
    batch = parent / "status-queries.json"
    write_new(batch, {"queries": queries})
    try:
        write_new(parent / "case-map.json", {"cases": cases})
    except BaseException:
        batch.unlink(missing_ok=True)
        raise
    return len(queries), len({path for paths in findings.values() for path in paths}), unreadable


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError("destination required")
        root = HERE.parents[1]
        count, files, unreadable = prepare(root, Path(sys.argv[1]))
        print(json.dumps({"prepared_private_queries": count, "tracked_files": files,
                          "unreadable_tracked_files": unreadable,
                          "live_authority_checked": False, "revoked": False}))
        return 0
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError):
        print('{"error":"private_query_preparation_refused"}')
        return 1


if __name__ == "__main__":
    sys.exit(main())
