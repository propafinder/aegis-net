"""Bounded private source/evidence staging for the isolated CI driver only."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile


def need(value):
    if not value:
        raise ValueError("Private native stage custody refused")


def opened(path, directory=False):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts)
    held = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        for part in path.parts[1:-1]:
            held.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=held[-1]))
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        held.append(os.open(path.name, flags, dir_fd=held[-1]))
        return held
    except BaseException:
        for descriptor in reversed(held):
            os.close(descriptor)
        raise


def close(held):
    for descriptor in reversed(held):
        os.close(descriptor)


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def source_bytes(path, expected):
    need(re.fullmatch(r"[a-f0-9]{64}", expected) is not None)
    held = opened(path)
    try:
        value = os.fstat(held[-1])
        need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and 0 < value.st_size <= 1024 * 1024)
        with os.fdopen(os.dup(held[-1]), "rb") as source:
            data = source.read(1024 * 1024 + 1)
        need(len(data) == value.st_size and hashlib.sha256(data).hexdigest() == expected)
        return data
    finally:
        close(held)


def namespace_accessible(path):
    """Metadata admission for unchanged root-owned native tool paths."""
    held = opened(path)
    try:
        for descriptor in held[:-1]:
            value = os.fstat(descriptor)
            need(value.st_uid == 0 and value.st_mode & stat.S_IXUSR)
        value = os.fstat(held[-1])
        need(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_mode & stat.S_IXUSR)
    finally:
        close(held)


def prepare(parent, output_name, assets, expected_owner=0):
    need(re.fullmatch(r"audit17-native-[A-Za-z0-9_-]{1,50}", output_name) is not None)
    need(set(assets) == {"test-device-egress-guard-native.py", "aegis-device-egress-guard.sh", "test-device-egress-guard-contract.sh"})
    held = opened(parent, directory=True)
    try:
        # Namespace root maps only host root: every staging ancestor must be
        # owned by that mapped UID and traversable, without changing any mode.
        for descriptor in held:
            value = os.fstat(descriptor)
            need(value.st_uid in (0, expected_owner) and value.st_mode & stat.S_IXUSR)
        prepared = {name: source_bytes(path, digest) for name, (path, digest) in assets.items()}
        root = Path(tempfile.mkdtemp(prefix="aegis-deviceguard-private-", dir=parent))
        root.chmod(0o700)
        value = root.lstat()
        need(value.st_uid == expected_owner and stat.S_IMODE(value.st_mode) == 0o700)
        scripts = root / "scripts"
        evidence = root / "evidence"
        scripts.mkdir(mode=0o700)
        evidence.mkdir(mode=0o700)
        pins = {}
        for name, data in prepared.items():
            private_write(scripts / name, data)
            pins[name] = hashlib.sha256(data).hexdigest()
        return {"root": str(root), "evidence": str(evidence), "output_name": output_name,
                "owner": expected_owner, "asset_sha256": pins}
    finally:
        close(held)


def export(stage, destination):
    root = Path(stage["root"])
    source = Path(stage["evidence"])
    destination = Path(destination)
    need(source == root / "evidence" and destination.name == stage["output_name"])
    need(set(stage["asset_sha256"]) == {"test-device-egress-guard-native.py", "aegis-device-egress-guard.sh", "test-device-egress-guard-contract.sh"})
    for name, digest in stage["asset_sha256"].items():
        source_bytes(root / "scripts" / name, digest)
    held = opened(source, directory=True)
    try:
        target = opened(destination, directory=True)
    except BaseException:
        close(held)
        raise
    files = []
    try:
        for descriptor in (held[-1], target[-1]):
            value = os.fstat(descriptor)
            need(value.st_uid == stage["owner"] and stat.S_IMODE(value.st_mode) == 0o700)
        need(os.listdir(target[-1]) == [])
        names = sorted(os.listdir(held[-1]))
        need(1 <= len(names) <= 1024)
        required = {"input-r1.json", "outer.log", "receipt-r1.json"}
        need(required.issubset(names))
        literals = required | {"started-r1.json", "inside-receipt-r1.json", "block.nft", "dhcp.nft"}
        total = 0
        payloads = {}
        for name in names:
            need(name in literals or re.fullmatch(r"command-[0-9]{3}\.(?:intent\.json|receipt\.json|stdout|stderr)", name))
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=held[-1])
            files.append(descriptor)
            value = os.fstat(descriptor)
            need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == stage["owner"])
            need(stat.S_IMODE(value.st_mode) == 0o600 and 0 <= value.st_size <= 1024 * 1024)
            total += value.st_size
            need(total <= 16 * 1024 * 1024)
            with os.fdopen(os.dup(descriptor), "rb") as input_file:
                data = input_file.read(1024 * 1024 + 1)
            need(len(data) == value.st_size)
            payloads[name] = data
        config = json.loads(payloads["input-r1.json"])
        need(config["staging_output_name"] == stage["output_name"] and config["staging_root"] == stage["root"])
        need(config["driver"] == str(root / "scripts/test-device-egress-guard-native.py"))
        need(config["helper"] == str(root / "scripts/aegis-device-egress-guard.sh"))
        receipt = json.loads(payloads["receipt-r1.json"])
        if "pid" in receipt or "started-r1.json" in payloads:
            started = json.loads(payloads["started-r1.json"])
            need(type(receipt.get("pid")) is int and receipt["pid"] > 0)
            need(receipt.get("owned_process_group") == receipt["pid"] == started.get("pid") == started.get("owned_process_group"))
            need(receipt.get("parent_reaped") is True and receipt.get("owned_group_signalled") is True)
            need("cleanup_error_type" not in receipt)
        need(sorted(os.listdir(held[-1])) == names)
        # Validate the complete inventory and attempt binding before the first
        # output mutation. Original stage is always retained, including failures.
        hashes = {}
        # Native receipt is published last, after every other copied file's
        # durable readback. Mid-copy failure retains partial output and stage.
        ordered = [name for name in sorted(payloads) if name != "receipt-r1.json"] + ["receipt-r1.json"]
        for name in ordered:
            data = payloads[name]
            descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target[-1])
            with os.fdopen(descriptor, "w+b") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
                output.seek(0)
                need(output.read(1024 * 1024 + 1) == data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        return hashes
    finally:
        for descriptor in files:
            os.close(descriptor)
        close(target)
        close(held)
