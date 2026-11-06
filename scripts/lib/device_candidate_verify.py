"""Offline signed candidate verification for the disposable-VM acceptance lab.

This is test-controller code, not installed client logic. It never downloads,
signs, builds, or executes a candidate. All trust pins are operator inputs.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import time
from shipping_client_inventory import validate_shipping_client_inventory

HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_ARCHIVE = 1024 * 1024 * 1024
# Versioned independently of candidate metadata; contract test compares this
# copy with the publisher's authoritative PAYLOAD. A schema change fails closed.
PUBLIC_PAYLOAD = {
    'bin/aegis-client', 'install.sh', 'config.example.toml',
    'scripts/setup-wide-linux-redirect.sh', 'scripts/setup-wide-linux-tproxy.sh',
    'scripts/aegis-wide-enable.sh', 'scripts/aegis-wide-disable.sh',
    'scripts/aegis-wide-persist-install.sh', 'scripts/purge-installed-aegis.sh',
    'scripts/aegis-ubuntu-uninstall.sh', 'scripts/janitor-wide-linux-tproxy.sh',
    'scripts/aegis-rpi-gateway.sh', 'scripts/lib/root-state.sh',
    'packaging/systemd/aegis-client.service', 'packaging/env/aegis-client.env.example',
    'README.txt', 'THIRD-PARTY-NOTICES.txt',
}

CLIENT_BUNDLE_SCHEMA_V1 = 'aegis_client_release_bundle_manifest_v1'
CLIENT_BUNDLE_SCHEMA_V2 = 'aegis_client_release_bundle_manifest_v2'
CLIENT_BUNDLE_SCHEMA_V3 = 'aegis_client_release_bundle_manifest_v3'
CARGO_INVENTORY_PAYLOAD = 'client-cargo-inventory.json'
DEVICE_GUARD_PAYLOAD = 'scripts/aegis-device-egress-guard.sh'
PUBLIC_PAYLOAD_V2 = PUBLIC_PAYLOAD | {DEVICE_GUARD_PAYLOAD}


def expected_client_schema(expected):
    schema = getattr(expected, 'client_bundle_schema', CLIENT_BUNDLE_SCHEMA_V1)
    require(isinstance(schema, str) and schema in (CLIENT_BUNDLE_SCHEMA_V1, CLIENT_BUNDLE_SCHEMA_V2, CLIENT_BUNDLE_SCHEMA_V3),
            'unsupported independent client bundle schema')
    return schema


def public_payload(schema):
    require(isinstance(schema, str) and schema in (CLIENT_BUNDLE_SCHEMA_V1, CLIENT_BUNDLE_SCHEMA_V2, CLIENT_BUNDLE_SCHEMA_V3),
            'unsupported client payload schema')
    if schema == CLIENT_BUNDLE_SCHEMA_V3:
        return PUBLIC_PAYLOAD_V2 | {CARGO_INVENTORY_PAYLOAD}
    return PUBLIC_PAYLOAD_V2 if schema == CLIENT_BUNDLE_SCHEMA_V2 else PUBLIC_PAYLOAD


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stream_hash(stream):
    digest = hashlib.sha256()
    while block := stream.read(65536):
        digest.update(block)
    return digest.hexdigest()


def trusted(path, limit=65536):
    path = Path(path).absolute()
    # Fixed Darwin aliases have OS ownership; arbitrary links are rejected.
    if os.uname().sysname == "Darwin":
        for prefix in ("/tmp/", "/var/", "/etc/"):
            if str(path).startswith(prefix):
                path = Path("/private" + str(path))
                break
    require(".." not in path.parts, "parent traversal rejected")
    for ancestor in list(path.parents):
        info = ancestor.lstat()
        sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()), "untrusted input ancestry")
        require(not info.st_mode & 0o022 or sticky_root, "writable input ancestry")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    try:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "input must be a single-link regular file")
        require(info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022, "untrusted input file")
        require(info.st_size <= limit, "input exceeds size bound")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read(path, limit=65536):
    with trusted(path, limit) as stream:
        data = stream.read(limit + 1)
        require(len(data) <= limit, "input grew beyond size bound")
        return data


def file_hash(path):
    with trusted(path, MAX_ARCHIVE) as stream:
        return stream_hash(stream)


def checked(args, timeout=30):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, timeout=timeout)
    require(result.returncode == 0, "trusted verification utility failed")
    return result.stdout


def trusted_scratch_parent(candidates=None):
    """Use fixed OS directories, never TMPDIR or tempfile's cached default."""
    if candidates is None:
        candidates = ('/private/tmp', '/private/var/tmp') if os.uname().sysname == 'Darwin' else ('/tmp', '/var/tmp')
    for candidate in candidates:
        try:
            path = Path(candidate)
            require(path.is_absolute() and '..' not in path.parts, 'invalid signature scratch path')
            for directory in (path, *path.parents):
                info = directory.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()), 'untrusted signature scratch ancestry')
                require(not info.st_mode & 0o022 or
                        (info.st_uid == 0 and info.st_mode & stat.S_ISVTX), 'unsafe writable signature scratch ancestry')
            return path
        except (OSError, ValueError):
            continue
    raise ValueError('no protected signature scratch parent is available')


def policy(manifest, expected):
    require(manifest.get("schema") == "aegis_linux_release_manifest_v1", "release schema mismatch")
    require(manifest.get("git_sha") == expected.source, "release source mismatch")
    require(manifest.get("platform") == "linux" and manifest.get("arch") == expected.arch, "release platform/architecture mismatch")
    require(manifest.get("channel") == "rc" and manifest.get("prerelease") is True, "acceptance requires an explicit RC")
    release = manifest.get("release_policy", {})
    require(set(release) == {"schema", "authority", "sequence", "tag", "issued_at_unix", "expires_at_unix"}, "signed freshness policy missing or malformed")
    require(release["schema"] == "aegis_release_policy_v1" and release["authority"] == expected.authority, "release authority mismatch")
    require(release["tag"] == expected.tag and expected.tag.startswith("v" + manifest.get("version", "") + "-rc."), "release tag/version mismatch")
    sequence, issued, expires = (release[key] for key in ("sequence", "issued_at_unix", "expires_at_unix"))
    require(all(type(value) is int for value in (sequence, issued, expires)), "invalid freshness types")
    require(0 < sequence < 2**53 and sequence >= expected.minimum_sequence, "release sequence below independent floor")
    now = int(time.time())
    require(0 < issued < expires and expires - issued <= 30 * 86400 and issued <= now + 300 and now < expires, "expired/future/excessive release policy")


def signed_manifest(path, digest, expected):
    require(HEX.fullmatch(digest), "manifest pin must be a SHA-256 digest")
    raw = read(path)
    require(sha(raw) == digest, "independent manifest pin mismatch")
    signature = read(str(path) + ".sig", 64)
    require(len(signature) == 64, "Ed25519 signature length mismatch")
    key = read(expected.public_key, 16384)
    require(HEX.fullmatch(expected.public_key_sha256) and sha(key) == expected.public_key_sha256, "independent release key pin mismatch")
    with tempfile.TemporaryDirectory(prefix="aegis-public-verifier-", dir=trusted_scratch_parent()) as directory:
        directory = Path(directory)
        directory.chmod(0o700)
        for name, contents in (("key", key), ("manifest", raw), ("signature", signature)):
            (directory / name).write_bytes(contents)
            (directory / name).chmod(0o600)
        der = checked(["openssl", "pkey", "-pubin", "-in", directory / "key", "-outform", "DER"])
        require(len(der) == 44 and der[:12] == bytes.fromhex("302a300506032b6570032100"), "release key must be Ed25519")
        checked(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", directory / "key", "-rawin",
                 "-in", directory / "manifest", "-sigfile", directory / "signature"])
    value = json.loads(raw)
    policy(value, expected)
    return value


def inventory(manifest_path, manifest, expected, role):
    bundle = manifest["artifacts"]["bundle"]
    require(bundle.get("status") == "ready", "release bundle is not ready")
    filename = bundle["archive"]["path"]
    require(isinstance(filename, str) and re.fullmatch(r"[A-Za-z0-9._-]+\.tar\.gz", filename), "archive path is not a local leaf")
    expected_hash = bundle["archive"]["sha256"]
    require(isinstance(expected_hash, str) and HEX.fullmatch(expected_hash), "missing signature-anchored archive hash")
    path = Path(manifest_path).parent / filename
    root = bundle["directory"]
    require(isinstance(root, str) and re.fullmatch(r"[A-Za-z0-9._-]+", root), "invalid archive directory")
    members, hashes, small, total = [], {}, {}, 0
    with trusted(path, MAX_ARCHIVE) as stream:
        require(stream_hash(stream) == expected_hash, "signed archive hash mismatch")
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:gz") as archive:
            for member in archive:
                parts = PurePosixPath(member.name).parts
                require(not member.name.startswith("/") and len(parts) >= 1 and parts[0] == root and ".." not in parts, "archive traversal/root mismatch")
                relative = "/".join(parts[1:])
                require(member.isdir() or member.isfile(), "archive links and special files are forbidden")
                if member.isdir():
                    continue
                require(relative and relative not in hashes and len(hashes) < 4096, "archive duplicate/member limit")
                total += member.size
                require(0 <= member.size <= 512 * 1024 * 1024 and total <= 2 * MAX_ARCHIVE, "decompressed archive limit")
                incoming = archive.extractfile(member)
                require(incoming is not None, "archive file unreadable")
                data_hash = hashlib.sha256()
                captured = bytearray()
                count = 0
                while block := incoming.read(65536):
                    count += len(block)
                    data_hash.update(block)
                    if relative in ("bundle.manifest.json", "SHA256SUMS", CARGO_INVENTORY_PAYLOAD):
                        require(len(captured) + len(block) <= (4 * 1024 * 1024 if relative == CARGO_INVENTORY_PAYLOAD else 1024 * 1024), "nested metadata limit")
                        captured.extend(block)
                require(count == member.size, "truncated archive file")
                hashes[relative] = data_hash.hexdigest()
                if captured:
                    small[relative] = bytes(captured)
                members.append(relative)
    inner = json.loads(small["bundle.manifest.json"])
    if inner.get("schema") == CLIENT_BUNDLE_SCHEMA_V3:
        def unique_v3(pairs):
            value = {}
            for key, item in pairs:
                require(key not in value, "public v3 duplicate provenance field")
                value[key] = item
            return value
        inner = json.loads(small["bundle.manifest.json"], object_pairs_hook=unique_v3)

    for field in ("version", "git_sha", "arch", "platform", "target_triple"):
        require(inner.get(field) == manifest.get(field), "nested provenance mismatch: " + field)
    require(inner.get("bundle_name") == root, "nested bundle name mismatch")
    listed = inner.get('files')
    require(isinstance(listed, list) and all(isinstance(name, str) for name in listed), 'unsupported nested file inventory schema')
    require(len(listed) == len(set(listed)) and set(listed) | {'bundle.manifest.json'} == set(members), 'nested file inventory mismatch')
    if role == "client":
        require(manifest.get("distribution") == inner.get("distribution") == "public_client", "client distribution scope mismatch")
        schema = expected_client_schema(expected)
        require(inner.get("schema") == schema, "independent client bundle schema mismatch")
        require(set(inner["binaries"]) == {"aegis-client"}, "client-only inventory mismatch")
        require(set(members) == public_payload(schema) | {'SHA256SUMS', 'bundle.manifest.json'}, "public file allowlist mismatch")
        require(not any(name.endswith('.rs') or name.startswith(('src/', '.git/')) for name in members), "public source files forbidden")
    else:
        require(manifest.get("distribution") != "public_client" and inner.get("schema") == "aegis_release_bundle_manifest_v2", "operator distribution scope mismatch")
    executable = "aegis-" + role
    binary = inner["binaries"][executable]
    require(binary["path"] == "bin/" + executable and hashes[binary["path"]] == binary["sha256"], "nested binary identity mismatch")
    sums = {}
    for line in small["SHA256SUMS"].decode().splitlines():
        fields = line.split()
        require(len(fields) == 2 and HEX.fullmatch(fields[0]), "invalid nested checksum list")
        name = fields[1].removeprefix("*")
        require(name not in sums and hashes.get(name) == fields[0], "nested checksum mismatch")
        sums[name] = fields[0]
    require(set(sums) == set(members) - {"SHA256SUMS", "bundle.manifest.json"}, "incomplete nested checksum inventory")
    if role == "client" and schema == CLIENT_BUNDLE_SCHEMA_V3:
        require(CARGO_INVENTORY_PAYLOAD in small, "shipping Cargo inventory absent")
        validate_shipping_client_inventory(small[CARGO_INVENTORY_PAYLOAD], inner, hashes["bin/aegis-client"])
    return {"archive": str(path.absolute()), "archive_sha256": expected_hash, "directory": root,
            "binary_sha256": binary["sha256"], "file_hashes": hashes, "inner": inner}


def verify(expected):
    client_schema = expected_client_schema(expected)
    require(re.fullmatch(r"[0-9a-f]{40}", expected.source), "exact full source SHA required")
    number = r'(?:0|[1-9][0-9]*)'
    require(re.fullmatch(rf'v{number}\.{number}\.{number}-rc\.{number}', expected.tag), "exact RC tag required")
    require(isinstance(expected.authority, str) and re.fullmatch(r'github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:\.github/workflows/release\.yml', expected.authority), 'exact supported release authority required')
    require(type(expected.minimum_sequence) is int and 0 < expected.minimum_sequence < 2**53, 'positive independent sequence floor required')
    client_manifest = signed_manifest(expected.client_manifest, expected.client_manifest_sha256, expected)
    operator_manifest = signed_manifest(expected.operator_manifest, expected.operator_manifest_sha256, expected)
    require(client_manifest["release_policy"] == operator_manifest["release_policy"], "client/operator release policy differs")
    client = inventory(expected.client_manifest, client_manifest, expected, "client")
    operator = inventory(expected.operator_manifest, operator_manifest, expected, "server")
    require(operator["file_hashes"]["bin/aegis-client"] == operator["inner"]["binaries"]["aegis-client"]["sha256"] == client["binary_sha256"], "public/operator client differs")
    if client_schema in (CLIENT_BUNDLE_SCHEMA_V2, CLIENT_BUNDLE_SCHEMA_V3):
        require(operator["file_hashes"].get(DEVICE_GUARD_PAYLOAD) == client["file_hashes"][DEVICE_GUARD_PAYLOAD],
                "public/operator device guard differs")
    bootstrap = read(expected.bootstrap, 256 * 1024)
    require(sha(bootstrap) == client_manifest["bootstrap"]["sha256"], "bootstrap differs from signed manifest")
    return {"schema": "aegis_device_candidate_verified_v1", "client_bundle_schema": client_schema, "source_sha": expected.source, "tag": expected.tag,
            "arch": expected.arch, "release_policy": client_manifest["release_policy"],
            "bootstrap_sha256": sha(bootstrap), "release_key_sha256": expected.public_key_sha256,
            "client_manifest_sha256": expected.client_manifest_sha256,
            "operator_manifest_sha256": expected.operator_manifest_sha256,
            "client": client, "operator": operator}


def extract_verified(item, destination):
    """Extract only verified regular bytes into a newly created private tree."""
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    with trusted(item["archive"], MAX_ARCHIVE) as stream:
        require(stream_hash(stream) == item["archive_sha256"], "archive changed after preflight")
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:gz") as archive:
            for member in archive:
                if member.isdir():
                    continue
                relative = "/".join(PurePosixPath(member.name).parts[1:])
                require(member.isfile() and relative in item["file_hashes"], "archive member changed")
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                incoming = archive.extractfile(member)
                digest = hashlib.sha256()
                with target.open("xb") as output:
                    while block := incoming.read(65536):
                        digest.update(block)
                        output.write(block)
                require(digest.hexdigest() == item["file_hashes"][relative], "extracted file differs")
                target.chmod(0o755 if relative.startswith("bin/") or relative.endswith(".sh") else 0o600)
    return destination
