#!/usr/bin/env python3
"""Inventory an already built Linux package root; do not claim binary SBOM completeness."""

import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import struct
import subprocess
import sys
import tempfile
import time


READELF_OUTPUT_LIMIT = 1024 * 1024
READELF_BINARY_LIMIT = 64 * 1024 * 1024


def hash_bounded_reader_fd(fd):
    digest = hashlib.sha256()
    offset = 0
    deadline = time.monotonic() + 10
    while offset <= READELF_BINARY_LIMIT:
        if time.monotonic() > deadline:
            fail("readelf hash deadline exceeded")
        block = os.pread(fd, min(1024 * 1024, READELF_BINARY_LIMIT + 1 - offset), offset)
        if not block:
            return digest.hexdigest()
        digest.update(block)
        offset += len(block)
    fail("readelf exceeded bounded hash size")


def sealed_reader_snapshot(source_fd, opened, pin, stack):
    flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    if hasattr(os, "MFD_EXEC"):
        flags |= os.MFD_EXEC
    snapshot_fd = os.memfd_create("aegis-pinned-readelf", flags)
    stack.callback(os.close, snapshot_fd)
    offset = 0
    deadline = time.monotonic() + 10
    while offset < opened.st_size:
        if time.monotonic() > deadline:
            fail("readelf snapshot deadline exceeded")
        block = os.pread(source_fd, min(1024 * 1024, opened.st_size - offset), offset)
        if not block:
            fail("readelf changed during snapshot")
        remaining = memoryview(block)
        while remaining:
            written = os.write(snapshot_fd, remaining)
            if written <= 0:
                fail("readelf snapshot write stopped")
            remaining = remaining[written:]
        offset += len(block)
    if hash_bounded_reader_fd(snapshot_fd) != pin:
        fail("readelf snapshot differs from pin")
    after = os.fstat(source_fd)
    if ((after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
            (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)):
        fail("readelf changed during snapshot")
    seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
             fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    fcntl.fcntl(snapshot_fd, fcntl.F_ADD_SEALS, seals)
    if fcntl.fcntl(snapshot_fd, fcntl.F_GET_SEALS) & seals != seals:
        fail("readelf snapshot was not sealed")
    return snapshot_fd


def limit_reader_output():
    resource.setrlimit(resource.RLIMIT_FSIZE,
                       (READELF_OUTPUT_LIMIT, READELF_OUTPUT_LIMIT))


def open_pinned_reader(path, pin, stack):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > READELF_BINARY_LIMIT:
        fail("readelf must be a bounded, unlinked regular executable")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    stack.callback(os.close, fd)
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        fail("readelf changed while opening")
    if (opened.st_size != before.st_size or opened.st_size > READELF_BINARY_LIMIT or
            opened.st_mtime_ns != before.st_mtime_ns or
            opened.st_ctime_ns != before.st_ctime_ns):
        fail("readelf grew or changed while opening")
    if hash_bounded_reader_fd(fd) != pin:
        fail("readelf SHA-256 pin mismatch")
    after_hash = os.fstat(fd)
    if ((after_hash.st_size, after_hash.st_mtime_ns, after_hash.st_ctime_ns) !=
            (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)):
        fail("readelf changed while hashing")
    if sys.platform.startswith("linux"):
        # The child executes a sealed copy whose own bytes match the pin.
        # Later writes to the source inode cannot alter that executable.
        snapshot_fd = sealed_reader_snapshot(fd, opened, pin, stack)
        return fd, snapshot_fd, f"/proc/self/fd/{snapshot_fd}", opened
    # macOS does not permit exec of /dev/fd/N. Use a private byte-for-byte
    # snapshot for local diagnostics; Linux release scans use the held FD.
    private = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="aegis-readelf-")))
    snapshot = private / "reader"
    out = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                  getattr(os, "O_NOFOLLOW", 0), 0o700)
    try:
        offset = 0
        while offset < opened.st_size:
            block = os.pread(fd, min(1024 * 1024, opened.st_size - offset), offset)
            if not block:
                fail("readelf changed during snapshot")
            remaining = memoryview(block)
            while remaining:
                remaining = remaining[os.write(out, remaining):]
            offset += len(block)
    finally:
        os.close(out)
    if hashlib.sha256(snapshot.read_bytes()).hexdigest() != pin:
        fail("readelf snapshot differs from pin")
    return fd, fd, str(snapshot), opened


def fail(message):
    raise ValueError(message)


def hash_fd(fd):
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            break
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


def file_facts(value):
    # Reading may update atime; content and custody facts must stay stable.
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def named_stat(path, dir_fd=None):
    return os.stat(path, dir_fd=dir_fd, follow_symlinks=False)


def read_package_metadata(path, *, dir_fd=None):
    """Read one bounded package control file from its admitted inode."""
    before = named_stat(path, dir_fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
            before.st_size > 4 * 1024 * 1024):
        fail("package metadata must be a single regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0), dir_fd=dir_fd)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                 opened.st_ctime_ns) !=
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns)):
            fail("package metadata changed while opening")
        chunks = []
        offset = 0
        while offset < opened.st_size:
            block = os.pread(fd, min(65536, opened.st_size - offset), offset)
            if not block:
                fail("package metadata shortened while reading")
            chunks.append(block)
            offset += len(block)
        if os.pread(fd, 1, offset):
            fail("package metadata grew while reading")
        after = os.fstat(fd)
        current = named_stat(path, dir_fd)
        if ((after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
                (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) or
                (current.st_dev, current.st_ino, current.st_size,
                 current.st_mtime_ns, current.st_ctime_ns) !=
                (opened.st_dev, opened.st_ino, opened.st_size,
                 opened.st_mtime_ns, opened.st_ctime_ns)):
            fail("package metadata changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)


def elf_dynamic_header(fd, size, target_triple):
    identity = os.pread(fd, 16, 0)
    if len(identity) != 16 or identity[:4] != b"\x7fELF" or identity[6] != 1:
        fail("malformed ELF identity")
    endian = {1: "<", 2: ">"}.get(identity[5])
    formats = {1: ("HHIIIIIHHHHHH", "IIIIIIII"),
               2: ("HHIQQQIHHHHHH", "IIQQQQQQ")}
    if endian is None or identity[4] not in formats:
        fail("unsupported ELF class or byte order")
    header_fmt, program_fmt = formats[identity[4]]
    header_size = 16 + struct.calcsize(endian + header_fmt)
    header = os.pread(fd, header_size - 16, 16)
    if len(header) != header_size - 16:
        fail("truncated ELF header")
    values = struct.unpack(endian + header_fmt, header)
    elf_type, machine, version = values[:3]
    expected_machine = {
        "x86_64-unknown-linux-gnu": 62,
        "aarch64-unknown-linux-gnu": 183,
    }.get(target_triple)
    if expected_machine is None:
        fail("unsupported package target triple")
    if identity[4] != 2 or identity[5] != 1 or machine != expected_machine:
        fail("ELF architecture differs from package target triple")
    program_offset, elf_header_size, program_size, program_count = values[4], values[7], values[8], values[9]
    actual_program_size = struct.calcsize(endian + program_fmt)
    if (elf_type not in (2, 3) or not machine or version != 1 or
            elf_header_size != header_size or program_size != actual_program_size or
            not 0 < program_count <= 4096 or program_offset < header_size or
            program_offset + program_count * program_size > size):
        fail("malformed ELF executable/program header")
    types = []
    for index in range(program_count):
        raw = os.pread(fd, program_size, program_offset + index * program_size)
        if len(raw) != program_size:
            fail("truncated ELF program header")
        fields = struct.unpack(endian + program_fmt, raw)
        segment_type = fields[0]
        segment_offset, file_size, memory_size = ((fields[1], fields[4], fields[5])
                                                 if identity[4] == 1 else
                                                 (fields[2], fields[5], fields[6]))
        if segment_offset + file_size > size or memory_size < file_size:
            fail("ELF segment lies outside payload")
        if segment_type == 2 and file_size < (8 if identity[4] == 1 else 16):
            fail("ELF dynamic segment is truncated")
        types.append((segment_type, file_size))
    if not any(kind == 1 and length > 0 for kind, length in types):  # PT_LOAD
        fail("ELF executable has no load segment")
    return any(kind == 2 for kind, _ in types)  # PT_DYNAMIC


def hash_regular(path, readelf, target_triple, inspect_elf=True, reader_fd=None, *, dir_fd=None):
    before = named_stat(path, dir_fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"nonregular, linked or replaced payload: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0), dir_fd=dir_fd)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                opened.st_ctime_ns, opened.st_nlink) != (
                before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns, before.st_nlink):
            fail(f"payload changed while opening: {path}")
        digest = hash_fd(fd)
        head = os.pread(fd, 8, 0)
        kind = classify(head)
        links = None
        if kind == "ELF" and inspect_elf:
            dynamic = elf_dynamic_header(fd, opened.st_size, target_triple)
            links = needed(fd, dynamic, readelf, reader_fd)
        # Classification and an external reader consume bytes after the first
        # digest. Rehash every payload, including non-ELF files, so the report
        # never pairs an old digest with a later payload classification.
        if hash_fd(fd) != digest:
            fail(f"payload changed while hashing: {path}")
        after = os.fstat(fd)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns,
                opened.st_nlink) != (after.st_size, after.st_mtime_ns,
                                    after.st_ctime_ns, after.st_nlink):
            fail(f"payload changed while hashing: {path}")
        current = named_stat(path, dir_fd)
        if (current.st_dev, current.st_ino, current.st_size,
                current.st_mtime_ns, current.st_ctime_ns,
                current.st_nlink) != (opened.st_dev, opened.st_ino,
                                     opened.st_size, opened.st_mtime_ns,
                                     opened.st_ctime_ns, opened.st_nlink):
            fail(f"payload path changed during inspection: {path}")
        return digest, kind, links
    finally:
        os.close(fd)


def classify(head):
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head.startswith(b"MZ"):
        return "PE-candidate"
    if head[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe"}:
        return "Mach-O-candidate"
    return "other"


def needed(fd, has_dynamic, readelf, reader_fd):
    if not readelf:
        return None
    fd_path = f"/proc/self/fd/{fd}" if sys.platform.startswith("linux") else f"/dev/fd/{fd}"
    # The package ELF and the pinned reader are inputs, not trusted output-size
    # authorities. Bound both streams before loading either into this process.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        result = subprocess.run([readelf, "-d", fd_path], stdout=stdout, stderr=stderr,
                                timeout=30, pass_fds=(fd, reader_fd),
                                preexec_fn=limit_reader_output)
        # The child shares each file description and can seek its offset back
        # before exit. Inspect allocated file size, never the shared offset.
        if (os.fstat(stdout.fileno()).st_size >= READELF_OUTPUT_LIMIT or
                os.fstat(stderr.fileno()).st_size >= READELF_OUTPUT_LIMIT):
            fail("readelf output exceeded bounded limit")
        if result.returncode:
            fail("readelf rejected held ELF payload")
        stdout.seek(0)
        output = stdout.read().decode("utf-8", "replace")
    if "There is no dynamic section in this file." in output:
        if has_dynamic:
            fail("readelf omitted present ELF dynamic segment")
        return []
    title = re.search(r"Dynamic section at offset 0x[0-9a-fA-F]+ contains (\d+) entries:", output)
    if not has_dynamic or not title:
        fail("readelf returned malformed dynamic section")
    rows = re.findall(r"^[ \t]*0x[0-9a-fA-F]+[ \t]+\(([^)]+)\)[ \t]+(.*)$", output, re.M)
    if not 0 < int(title[1]) <= 65536 or len(rows) != int(title[1]):
        fail("readelf dynamic entry count mismatch")
    links = []
    for tag, value in rows:
        if not value.strip() and tag != "BIND_NOW":
            fail("readelf returned empty value for dynamic tag")
        if tag == "NEEDED":
            name = re.fullmatch(r"Shared library: \[([^\]/]+)\]", value.strip())
            if not name:
                fail("malformed readelf NEEDED entry")
            links.append(name[1])
    return sorted(set(links))


DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0)


def payload_tree(root_fd):
    """A bounded descriptor-relative walk, including otherwise empty dirs."""
    result = {}
    def walk(parent, relative, depth):
        if depth > 64 or len(result) >= 65536:
            fail('payload directory inventory exceeds bound')
        before = os.fstat(parent)
        result[relative] = file_facts(before)
        with os.scandir(parent) as iterator:
            names = []
            for entry in iterator:
                if len(names) >= 65536:
                    fail('payload directory exceeds bound')
                names.append(entry.name)
        for name in sorted(names):
            path = relative + '/' + name if relative else name
            before_entry = named_stat(name, parent)
            if stat.S_ISLNK(before_entry.st_mode):
                fail('symlinked payload entry')
            if len(result) >= 65536:
                fail('payload entry inventory exceeds bound')
            if stat.S_ISDIR(before_entry.st_mode):
                child = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
                try:
                    if file_facts(os.fstat(child)) != file_facts(before_entry):
                        fail('payload directory changed while opening')
                    walk(child, path, depth + 1)
                    if file_facts(named_stat(name, parent)) != result[path]:
                        fail('payload directory path changed during inventory')
                finally:
                    os.close(child)
            elif stat.S_ISREG(before_entry.st_mode):
                result[path] = file_facts(before_entry)
            else:
                fail('nonregular payload entry')
        if file_facts(os.fstat(parent)) != file_facts(before):
            fail('payload directory changed during inventory')
    walk(root_fd, '', 0)
    return result


@contextmanager
def payload_parent(root_fd, relative, tree):
    parts = relative.split('/')
    if not parts or any(part in ('', '.', '..') for part in parts):
        fail('unsafe payload path')
    with ExitStack() as stack:
        parent = root_fd
        traversed = []
        for name in parts[:-1]:
            traversed.append(name)
            before = named_stat(name, parent)
            if not stat.S_ISDIR(before.st_mode) or file_facts(before) != tree['/'.join(traversed)]:
                fail('payload parent changed before inspection')
            child = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
            stack.callback(os.close, child)
            if file_facts(os.fstat(child)) != file_facts(before):
                fail('payload parent changed while opening')
            parent = child
        yield parent, parts[-1]


def inventory(package, readelf, readelf_sha256, reader_fd=None):
    before = package.lstat()
    if not stat.S_ISDIR(before.st_mode):
        fail("package root must be a directory, not a symlink")
    with ExitStack() as stack:
        package_fd = os.open(package, DIRECTORY_FLAGS)
        stack.callback(os.close, package_fd)
        if file_facts(os.fstat(package_fd)) != file_facts(before):
            fail('package directory changed while opening')
        root_before = named_stat('rootfs', package_fd)
        if not stat.S_ISDIR(root_before.st_mode):
            fail('rootfs must be a directory, not a symlink')
        root_fd = os.open('rootfs', DIRECTORY_FLAGS, dir_fd=package_fd)
        stack.callback(os.close, root_fd)
        if file_facts(os.fstat(root_fd)) != file_facts(root_before):
            fail('rootfs changed while opening')
        result = inventory_held(package_fd, root_fd, readelf, readelf_sha256, reader_fd)
        if (file_facts(named_stat('rootfs', package_fd)) != file_facts(root_before) or
                file_facts(os.fstat(root_fd)) != file_facts(root_before)):
            fail('rootfs directory changed during inventory')
        if (file_facts(os.fstat(package_fd)) != file_facts(before) or
                file_facts(package.lstat()) != file_facts(before)):
            fail('package directory path changed during inventory')
        return result


def inventory_held(package_fd, root_fd, readelf, readelf_sha256, reader_fd):
    controls = {name: file_facts(named_stat(name, package_fd)) for name in (
        'package-root.manifest.json', 'SHA256SUMS')}
    manifest_bytes = read_package_metadata(Path('package-root.manifest.json'), dir_fd=package_fd)
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema") != "aegis_package_root_manifest_v2" or manifest.get("rootfs_dir") != "rootfs":
        fail("unexpected package root manifest")
    target_triple = manifest.get("target_triple")
    if not isinstance(target_triple, str) or target_triple not in {
            "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"}:
        fail("unsupported package target triple")
    tree = payload_tree(root_fd)
    paths = sorted(name for name, facts in tree.items() if stat.S_ISREG(facts[2]))
    if paths != sorted(manifest.get("files", [])) or len(paths) != len(set(paths)):
        fail("payload differs from package manifest file set")
    sums_bytes = read_package_metadata(Path('SHA256SUMS'), dir_fd=package_fd)
    sums = sums_bytes.decode("utf-8", "strict").splitlines()
    expected = {}
    for line in sums:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\n]+)", line)
        if not match or match[2] in expected:
            fail("invalid or duplicate SHA256SUMS entry")
        expected[match[2]] = match[1]
    if sorted(expected) != paths:
        fail("SHA256SUMS file set differs from payload")
    entries = []
    for relative in paths:
        with payload_parent(root_fd, relative, tree) as (parent_fd, leaf):
            if file_facts(named_stat(leaf, parent_fd)) != tree[relative]:
                fail('payload leaf changed before inspection')
            digest, kind, links = hash_regular(Path(leaf), readelf, target_triple,
                                             reader_fd=reader_fd, dir_fd=parent_fd)
        if digest != expected[relative]:
            fail(f"SHA256SUMS mismatch: {relative}")
        row = {"path": relative, "sha256": digest, "kind": kind}
        if kind == "ELF":
            row["dt_needed"] = links
        entries.append(row)
    declared = manifest.get("binaries")
    if not isinstance(declared, dict):
        fail("invalid declared binary inventory")
    declared_paths = set()
    for name, record in declared.items():
        if not isinstance(name, str) or not isinstance(record, dict):
            fail("invalid declared binary record")
        rel = record.get("path", "")
        if not isinstance(rel, str) or not rel.startswith("rootfs/"):
            fail(f"invalid declared binary path: {name}")
        relative = rel[7:]
        if relative in declared_paths:
            fail(f"duplicate declared ELF path: {relative}")
        declared_paths.add(relative)
        row = next((entry for entry in entries if entry["path"] == relative), None)
        if row is None or row["sha256"] != record.get("sha256") or row["kind"] != "ELF":
            fail(f"declared ELF binary missing or changed: {name}")
    payload_elf_paths = {entry["path"] for entry in entries if entry["kind"] == "ELF"}
    if payload_elf_paths != declared_paths:
        fail("undeclared ELF payload: " + ", ".join(sorted(payload_elf_paths - declared_paths)))
    # Linux inode timestamps may share a coarse clock tick. Re-read bytes,
    # rather than treating unchanged stat facts as content authentication.
    for relative in paths:
        with payload_parent(root_fd, relative, tree) as (parent_fd, leaf):
            final_digest, _kind, _links = hash_regular(Path(leaf), None, target_triple,
                                                       inspect_elf=False, dir_fd=parent_fd)
        if final_digest != expected[relative]:
            fail('payload changed after inspection')
    if payload_tree(root_fd) != tree:
        fail('payload tree changed during inventory')
    if (read_package_metadata(Path('package-root.manifest.json'), dir_fd=package_fd) != manifest_bytes or
            read_package_metadata(Path('SHA256SUMS'), dir_fd=package_fd) != sums_bytes):
        fail('package metadata bytes changed during inventory')
    if any(file_facts(named_stat(name, package_fd)) != facts for name, facts in controls.items()):
        fail('package metadata changed during inventory')
    return {
        "schema": "aegis_linux_package_payload_inventory_v1",
        "source_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "package_name": manifest.get("package_name"),
        "source_commit": manifest.get("git_sha"),
        "target_triple": manifest.get("target_triple"),
        "scope": "package-root regular files, ELF architecture and DT_NEEDED names only",
        "elf_architecture_checked": any(entry["kind"] == "ELF" for entry in entries),
        "native_payload_complete": False,
        "vendored_static_linkage_proven": False,
        "runtime_library_resolution_proven": False,
        "elf_dynamic_inspection": "pinned_tool_on_held_file" if readelf else "not_run",
        "readelf_sha256": readelf_sha256,
        "entries": entries,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--readelf", type=Path, help="ELF dynamic section reader, required for linkage names")
    parser.add_argument("--readelf-sha256", help="independent SHA-256 pin for the reader")
    args = parser.parse_args()
    if bool(args.readelf) != bool(args.readelf_sha256):
        fail("readelf and its SHA-256 pin must be supplied together")
    if args.output.exists() or args.output.is_symlink():
        fail("refusing to replace inventory output")
    package_root = args.package_root.resolve()
    if args.output.resolve().is_relative_to(package_root):
        fail("inventory output must stay outside package root")
    with ExitStack() as stack:
        reader_fd = None
        reader_exec_fd = None
        reader_exec = None
        reader_before = None
        if args.readelf:
            if not re.fullmatch(r"[0-9a-f]{64}", args.readelf_sha256):
                fail("invalid readelf SHA-256 pin")
            reader_fd, reader_exec_fd, reader_exec, reader_before = open_pinned_reader(
                args.readelf, args.readelf_sha256, stack)
        data = inventory(args.package_root, reader_exec, args.readelf_sha256, reader_exec_fd)
        if args.readelf:
            reader_after = os.fstat(reader_fd)
            current = args.readelf.lstat()
            if ((reader_after.st_size, reader_after.st_mtime_ns, reader_after.st_ctime_ns) !=
                    (reader_before.st_size, reader_before.st_mtime_ns, reader_before.st_ctime_ns) or
                    (current.st_dev, current.st_ino) !=
                    (reader_before.st_dev, reader_before.st_ino) or
                    hash_bounded_reader_fd(reader_fd) != args.readelf_sha256):
                fail("readelf changed during inventory")
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(json.dumps(data, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"payload inventory refused: {exc}", file=sys.stderr)
        sys.exit(1)
