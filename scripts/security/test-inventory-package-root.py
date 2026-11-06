#!/usr/bin/env python3
"""Inert package-root inventory contracts; no build or installation."""

import hashlib
import fcntl
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("inventory-package-root.py")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def elf_bytes():
    identity = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    header = struct.pack("<16sHHIQQQIHHHHHH", identity, 3, 62, 1, 0, 64, 0, 0,
                         64, 56, 2, 0, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 192, 192, 4096)
    dynamic = struct.pack("<IIQQQQQQ", 2, 4, 176, 176, 0, 16, 16, 8)
    return header + load + dynamic + bytes(16)


def reset_checksums(package, binary):
    digest = sha(binary.read_bytes())
    manifest_path = package / "package-root.manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["binaries"]["aegis-client"]["sha256"] = digest
    manifest_path.write_text(json.dumps(manifest))
    (package / "SHA256SUMS").write_text(f"{digest}  usr/local/bin/aegis-client\n")


def fixture(base):
    package = base / "package"
    binary = package / "rootfs/usr/local/bin/aegis-client"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(elf_bytes())
    manifest = {
        "schema": "aegis_package_root_manifest_v2", "rootfs_dir": "rootfs",
        "package_name": "fixture", "git_sha": "a" * 40,
        "target_triple": "x86_64-unknown-linux-gnu",
        "files": ["usr/local/bin/aegis-client"],
        "binaries": {"aegis-client": {"path": "rootfs/usr/local/bin/aegis-client", "sha256": sha(binary.read_bytes())}},
    }
    (package / "package-root.manifest.json").write_text(json.dumps(manifest))
    reset_checksums(package, binary)
    return package, binary


def run(package, output, *extra, ok):
    result = subprocess.run([sys.executable, str(SCRIPT), str(package), str(output), *extra],
                            capture_output=True, text=True)
    assert (result.returncode == 0) == ok, result.stderr
    assert output.exists() == ok
    return json.loads(output.read_text()) if ok else result.stderr


def reader_args(reader):
    return ("--readelf", str(reader), "--readelf-sha256", sha(reader.read_bytes()))


def write_reader(reader, body):
    reader.write_text("#!/usr/bin/env python3\n" + body)
    reader.chmod(0o700)


VALID_OUTPUT = ("Dynamic section at offset 0xb0 contains 2 entries:\n"
                "  Tag        Type                         Name/Value\n"
                " 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]\n"
                " 0x0000000000000000 (NULL)               0x0\n")


with tempfile.TemporaryDirectory(prefix="aegis-b10-inventory-") as scratch:
    base = Path(scratch)
    package, binary = fixture(base)
    report = run(package, base / "pass.json", ok=True)
    assert report["entries"][0]["kind"] == "ELF"
    assert report["entries"][0]["dt_needed"] is None
    assert report["elf_dynamic_inspection"] == "not_run"
    assert report["native_payload_complete"] is False
    assert report["vendored_static_linkage_proven"] is False
    assert report["elf_architecture_checked"] is True
    print("PASS: closed file list and explicit uninspected native scope")

    for leaf in ("package-root.manifest.json", "SHA256SUMS"):
        metadata = package / leaf
        held = base / ("held-" + leaf)
        metadata.rename(held)
        metadata.symlink_to(held)
        assert "package metadata must be a single regular file" in run(
            package, base / ("symlink-" + leaf + ".json"), ok=False)
        metadata.unlink()
        held.rename(metadata)
        hardlink = base / ("linked-" + leaf)
        os.link(metadata, hardlink)
        assert "package metadata must be a single regular file" in run(
            package, base / ("hardlink-" + leaf + ".json"), ok=False)
        hardlink.unlink()
    print("PASS: manifest and SHA256SUMS metadata cannot be symlinked or hardlinked")

    metadata = package / "package-root.manifest.json"
    replacement = base / "replacement-manifest.json"
    replacement.write_bytes(metadata.read_bytes())
    original_open_metadata = os.open
    substitutions = []

    def replace_metadata_before_open(path, flags, *args, **kwargs):
        if Path(path) == metadata and not substitutions:
            substitutions.append(1)
            os.replace(replacement, metadata)
        return original_open_metadata(path, flags, *args, **kwargs)

    read_metadata = runpy.run_path(str(SCRIPT))["read_package_metadata"]
    with patch.object(os, "open", side_effect=replace_metadata_before_open):
        try:
            read_metadata(metadata)
            assert False, "same-byte replacement of package metadata was accepted"
        except ValueError as exc:
            assert "changed while opening" in str(exc)
    assert substitutions == [1]
    print("PASS: same-byte metadata replacement between lstat and open refused")

    mutable = base / "mutable-payload"
    mutable.write_bytes(b"plain000")
    before_mutation = mutable.stat()
    original_pread = os.pread
    mutated = []

    def mutate_payload_after_hash(fd, count, offset):
        if count == 8 and offset == 0 and not mutated:
            mutated.append(1)
            with mutable.open("r+b") as writer:
                writer.write(b"MZplain0")
            os.utime(mutable, ns=(before_mutation.st_atime_ns,
                                  before_mutation.st_mtime_ns))
        return original_pread(fd, count, offset)

    hash_regular = runpy.run_path(str(SCRIPT))["hash_regular"]
    with patch.object(os, "pread", side_effect=mutate_payload_after_hash):
        try:
            hash_regular(mutable, None, None, inspect_elf=False)
            assert False, "same-size payload mutation after hash was accepted"
        except ValueError as exc:
            assert "payload changed while hashing" in str(exc)
    assert mutated == [1] and mutable.stat().st_mtime_ns == before_mutation.st_mtime_ns
    print("PASS: same-size payload mutation after hashing refused")

    manifest_path = package / "package-root.manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["target_triple"] = "aarch64-unknown-linux-gnu"
    manifest_path.write_text(json.dumps(manifest))
    assert "ELF architecture differs" in run(package, base / "mislabelled-aarch64.json", ok=False)
    arm64 = bytearray(elf_bytes())
    arm64[18:20] = struct.pack("<H", 183)
    binary.write_bytes(arm64)
    reset_checksums(package, binary)
    report = run(package, base / "real-aarch64.json", ok=True)
    assert report["target_triple"] == "aarch64-unknown-linux-gnu"
    assert report["elf_architecture_checked"] is True
    # The pinned external reader may itself be a host ELF; it is hashed but
    # is not a package payload and must not be checked against the target.
    hash_regular = runpy.run_path(str(SCRIPT))["hash_regular"]
    assert hash_regular(binary, None, None, inspect_elf=False)[:2] == (sha(binary.read_bytes()), "ELF")
    manifest["target_triple"] = "armv7-unknown-linux-gnu"
    manifest_path.write_text(json.dumps(manifest))
    assert "unsupported package target" in run(package, base / "unsupported-target.json", ok=False)
    for bad_target in ([], {}):
        manifest["target_triple"] = bad_target
        manifest_path.write_text(json.dumps(manifest))
        assert "unsupported package target" in run(
            package, base / f"bad-target-{type(bad_target).__name__}.json", ok=False)
    binary.write_bytes(elf_bytes())
    manifest["target_triple"] = "x86_64-unknown-linux-gnu"
    manifest_path.write_text(json.dumps(manifest))
    reset_checksums(package, binary)
    print("PASS: package target bound to every ELF architecture; unsupported target refused")

    zero = base / "zero-elf"
    other = zero / "rootfs/README"
    other.parent.mkdir(parents=True)
    other.write_text("plain payload\n")
    (zero / "package-root.manifest.json").write_text(json.dumps({
        "schema": "aegis_package_root_manifest_v2", "rootfs_dir": "rootfs",
        "package_name": "zero-elf", "git_sha": "a" * 40,
        "target_triple": "x86_64-unknown-linux-gnu",
        "files": ["README"], "binaries": {},
    }))
    (zero / "SHA256SUMS").write_text(f"{sha(other.read_bytes())}  README\n")
    zero_report = run(zero, base / "zero-elf.json", ok=True)
    assert zero_report["elf_architecture_checked"] is False
    assert zero_report["entries"][0]["kind"] == "other"
    print("PASS: zero-ELF inventory does not claim architecture check")

    reader = base / "readelf"
    write_reader(reader, f"import sys\nprint({VALID_OUTPUT!r})\n")
    assert "pin" in run(package, base / "unpinned.json", "--readelf", str(reader), ok=False)
    assert "pin mismatch" in run(package, base / "bad-pin.json", "--readelf", str(reader),
                                 "--readelf-sha256", "0" * 64, ok=False)
    report = run(package, base / "needed.json", *reader_args(reader), ok=True)
    assert report["entries"][0]["dt_needed"] == ["libc.so.6"]
    assert report["readelf_sha256"] == sha(reader.read_bytes())
    print("PASS: pinned held-file ELF inspection; unpinned/mismatched readers refused")

    original_run = subprocess.run
    replacement = base / "replacement-reader"
    marker = base / "replacement-executed"
    write_reader(replacement, f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n"
                 f"print({VALID_OUTPUT!r})\n")
    swaps = []

    def swap_reader_before_exec(*args, **kwargs):
        swaps.append(1)
        os.replace(replacement, reader)
        return original_run(*args, **kwargs)

    swapped_output = base / "swapped-reader-path.json"
    scanner_main = runpy.run_path(str(SCRIPT))["main"]
    with patch.object(subprocess, "run", side_effect=swap_reader_before_exec), \
            patch.object(sys, "argv", [str(SCRIPT), str(package), str(swapped_output),
                                       *reader_args(reader)]):
        try:
            scanner_main()
            assert False, "replaced pinned-reader path was accepted"
        except ValueError as exc:
            assert "readelf changed during inventory" in str(exc)
    assert swaps == [1]
    assert not marker.exists(), "substituted executable ran after pin verification"
    assert not swapped_output.exists()
    write_reader(reader, f"import sys\nprint({VALID_OUTPUT!r})\n")
    print("PASS: path substitution after pin check cannot execute replacement")

    original_open = os.open
    growth_once = []

    def grow_same_inode_after_open(path, flags, *args, **kwargs):
        opened_fd = original_open(path, flags, *args, **kwargs)
        if Path(path) == reader and not growth_once:
            growth_once.append(1)
            os.truncate(reader, 64 * 1024 * 1024 + 1)
        return opened_fd

    grown_output = base / "same-inode-growth.json"
    with patch.object(os, "open", side_effect=grow_same_inode_after_open), \
            patch.object(sys, "argv", [str(SCRIPT), str(package), str(grown_output),
                                       *reader_args(reader)]):
        try:
            scanner_main()
            assert False, "same-inode reader growth was accepted"
        except ValueError as exc:
            assert "grew or changed while opening" in str(exc)
    assert growth_once == [1] and not grown_output.exists()
    write_reader(reader, f"import sys\nprint({VALID_OUTPUT!r})\n")

    original_pread = os.pread
    reader_fds = []
    growth_reads = []

    def track_reader_open(path, flags, *args, **kwargs):
        opened_fd = original_open(path, flags, *args, **kwargs)
        if Path(path) == reader:
            reader_fds.append(opened_fd)
        return opened_fd

    def simulate_continuous_growth(fd, count, offset):
        if fd in reader_fds:
            growth_reads.append(count)
            if len(growth_reads) > 70:
                raise RuntimeError("unbounded pinned reader hash")
            return b"x" * count
        return original_pread(fd, count, offset)

    endless_output = base / "continuous-growth.json"
    with patch.object(os, "open", side_effect=track_reader_open), \
            patch.object(os, "pread", side_effect=simulate_continuous_growth), \
            patch.object(sys, "argv", [str(SCRIPT), str(package), str(endless_output),
                                       *reader_args(reader)]):
        try:
            scanner_main()
            assert False, "unbounded reader stream was accepted"
        except ValueError as exc:
            assert "exceeded bounded hash size" in str(exc)
    assert len(growth_reads) <= 65 and not endless_output.exists()
    print("PASS: same-inode growth and continuous reader stream bounded")

    if sys.platform.startswith("linux"):
        benign_reader = reader.read_bytes()
        transient_marker = base / "transient-reader-executed"
        evil_reader = ("#!/usr/bin/env python3\n"
                       "from pathlib import Path\n"
                       f"Path({str(transient_marker)!r}).write_text('ran')\n"
                       f"print({VALID_OUTPUT!r})\n").encode()
        transient_calls = []
        observed_seals = []
        required = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)

        def mutate_source_only_during_exec(*args, **kwargs):
            transient_calls.append(1)
            exec_path = args[0][0]
            assert exec_path.startswith("/proc/self/fd/")
            snapshot_fd = int(exec_path.rsplit("/", 1)[1])
            try:
                observed_seals.append(fcntl.fcntl(snapshot_fd, fcntl.F_GET_SEALS))
            except OSError:
                observed_seals.append(0)
            reader.write_bytes(evil_reader)
            try:
                return original_run(*args, **kwargs)
            finally:
                reader.write_bytes(benign_reader)

        transient_output = base / "transient-source-mutation.json"
        with patch.object(subprocess, "run", side_effect=mutate_source_only_during_exec), \
                patch.object(sys, "argv", [str(SCRIPT), str(package), str(transient_output),
                                           *reader_args(reader)]):
            try:
                scanner_main()
                assert False, "transient source mutation was accepted"
            except ValueError as exc:
                assert "readelf changed during inventory" in str(exc)
        assert transient_calls == [1]
        assert not transient_marker.exists(), "transient source bytes were executed"
        assert observed_seals[0] & required == required
        assert not transient_output.exists()
        print("PASS: sealed exec ignores transient same-inode mutation and restore")

    # A reader can emit a valid dynamic section followed by irrelevant output;
    # capture_output would accept it after allocating the entire stream.
    for stream in ("stdout", "stderr"):
        write_reader(reader, "import sys\n" +
                     f"sys.stdout.write({VALID_OUTPUT!r})\n" +
                     f"sys.{stream}.write(' ' * (2 * 1024 * 1024))\n")
        assert "bounded limit" in run(
            package, base / f"oversized-{stream}.json", *reader_args(reader), ok=False)
    print("PASS: oversized pinned reader stdout and stderr refused before capture")

    # A child shares the temporary output file description. It can seek back
    # after writing exactly the limit, making tell() report zero despite a
    # full-size file whose valid dynamic-section prefix otherwise parses.
    for stream, descriptor in (("stdout", 1), ("stderr", 2)):
        write_reader(reader, "import os\n" +
                     f"prefix = {VALID_OUTPUT.encode()!r}\n" +
                     ("os.write(1, prefix)\n" if descriptor == 2 else "") +
                     f"os.write({descriptor}, " +
                     ("prefix + b' ' * (1024 * 1024 - len(prefix))" if descriptor == 1
                      else "b' ' * (1024 * 1024)") + ")\n" +
                     f"os.lseek({descriptor}, 0, os.SEEK_SET)\n")
        assert "bounded limit" in run(
            package, base / f"seek-back-{stream}.json", *reader_args(reader), ok=False)
    print("PASS: reader seek-back cannot hide full-size stdout or stderr")

    # GNU readelf emits a valid empty-value BIND_NOW row for the ARM64 package.
    with_empty = VALID_OUTPUT.replace("2 entries", "3 entries").replace(
        " 0x0000000000000000 (NULL)",
        " 0x0000000000000018 (BIND_NOW)           \n"
        " 0x0000000000000000 (NULL)")
    write_reader(reader, f"print({with_empty!r})\n")
    report = run(package, base / "empty-value-tag.json", *reader_args(reader), ok=True)
    assert report["entries"][0]["dt_needed"] == ["libc.so.6"]
    # Requiring horizontal separation still refuses a truncated/malformed row.
    no_separator = with_empty.replace("(BIND_NOW)           ", "(BIND_NOW)")
    write_reader(reader, f"print({no_separator!r})\n")
    assert "dynamic entry count mismatch" in run(
        package, base / "missing-row-separator.json", *reader_args(reader), ok=False)
    for tag in ("UNKNOWN", "NEEDED"):
        empty_other = with_empty.replace("(BIND_NOW)", f"({tag})")
        write_reader(reader, f"print({empty_other!r})\n")
        assert "empty value" in run(
            package, base / f"empty-{tag.lower()}.json", *reader_args(reader), ok=False)
    print("PASS: empty-value dynamic tag accepted; truncated row refused")

    for case, output in [("empty", ""), ("count", VALID_OUTPUT.replace("2 entries", "3 entries")),
                         ("missing", "There is no dynamic section in this file.")]:
        write_reader(reader, f"print({output!r})\n")
        assert "readelf" in run(package, base / f"{case}.json", *reader_args(reader), ok=False)
    write_reader(reader, "raise SystemExit(1)\n")
    assert "readelf rejected" in run(package, base / "reader-fail.json", *reader_args(reader), ok=False)
    print("PASS: empty, malformed, contradictory and failed reader output refused")

    binary.write_bytes(b"\x7fELF\x02short")
    reset_checksums(package, binary)
    assert "ELF" in run(package, base / "short-elf.json", ok=False)
    binary.write_bytes(elf_bytes())
    reset_checksums(package, binary)
    print("PASS: magic-only ELF refused despite matching manifest and checksum")

    assert "outside package root" in run(package, package / "rootfs/report.json", ok=False)
    assert "outside package root" in run(package, package / "report.json", ok=False)
    print("PASS: inventory output anywhere inside package root refused")

    write_reader(reader, "import os, sys\n" +
                 f"original = {str(binary)!r}\n" +
                 "with open(sys.argv[2], 'rb') as held: assert held.read(4) == b'\\x7fELF'\n" +
                 "replacement = original + '.new'\n" +
                 "with open(replacement, 'wb') as out: out.write(b'changed')\n" +
                 "os.replace(replacement, original)\n" +
                 f"print({VALID_OUTPUT!r})\n")
    swap_error = run(package, base / "swapped.json", *reader_args(reader), ok=False)
    assert ("path changed" in swap_error or
            "payload changed while hashing" in swap_error), swap_error
    binary.write_bytes(elf_bytes())
    reset_checksums(package, binary)
    print("PASS: pathname replacement during held-file inspection refused")

    write_reader(reader, "import sys\n" +
                 f"with open({str(binary)!r}, 'r+b') as out: out.write(b'X')\n" +
                 f"print({VALID_OUTPUT!r})\n")
    assert "payload changed while hashing" in run(
        package, base / "inplace.json", *reader_args(reader), ok=False)
    binary.write_bytes(elf_bytes())
    reset_checksums(package, binary)
    print("PASS: in-place ELF mutation during inspection refused")

    (package / "rootfs/extra").write_text("unexpected")
    assert "file set" in run(package, base / "extra.json", ok=False)
    (package / "rootfs/extra").unlink()
    vendor = package / "rootfs/usr/local/lib/aegis/libvendor.so"
    vendor.parent.mkdir(parents=True)
    vendor.write_bytes(elf_bytes())
    manifest = json.loads(manifest_path.read_text())
    manifest["files"].append("usr/local/lib/aegis/libvendor.so")
    manifest_path.write_text(json.dumps(manifest))
    (package / "SHA256SUMS").write_text(
        f"{sha(binary.read_bytes())}  usr/local/bin/aegis-client\n"
        f"{sha(vendor.read_bytes())}  usr/local/lib/aegis/libvendor.so\n")
    assert "undeclared ELF payload" in run(package, base / "undeclared-vendor-elf.json", ok=False)
    manifest["binaries"]["libvendor.so"] = {
        "path": "rootfs/usr/local/lib/aegis/libvendor.so", "sha256": sha(vendor.read_bytes())}
    manifest_path.write_text(json.dumps(manifest))
    report = run(package, base / "declared-vendor-elf.json", ok=True)
    assert len([row for row in report["entries"] if row["kind"] == "ELF"]) == 2
    manifest["binaries"]["alias"] = manifest["binaries"]["libvendor.so"]
    manifest_path.write_text(json.dumps(manifest))
    assert "duplicate declared ELF path" in run(package, base / "duplicate-elf.json", ok=False)
    vendor.unlink()
    manifest["files"].remove("usr/local/lib/aegis/libvendor.so")
    del manifest["binaries"]["libvendor.so"]
    del manifest["binaries"]["alias"]
    manifest_path.write_text(json.dumps(manifest))
    reset_checksums(package, binary)
    print("PASS: every native ELF requires one exact declared binary record")
    binary.write_bytes(b"changed")
    assert "mismatch" in run(package, base / "changed.json", ok=False)
    binary.write_bytes(elf_bytes())
    print("PASS: extra payload and changed binary refused")

    outside = base / "outside"
    outside.write_bytes(binary.read_bytes())
    binary.unlink()
    binary.hardlink_to(outside)
    assert "linked" in run(package, base / "hardlink.json", ok=False)
    binary.unlink()
    binary.symlink_to(outside)
    assert "symlinked payload" in run(package, base / "symlink.json", ok=False)
    binary.unlink()
    binary.write_bytes(outside.read_bytes())
    print("PASS: linked and symlinked payload refused")

    (package / "SHA256SUMS").write_text("0" * 64 + "  usr/local/bin/aegis-client\n")
    assert "mismatch" in run(package, base / "bad-sums.json", ok=False)
    print("PASS: detached checksum mismatch refused")
