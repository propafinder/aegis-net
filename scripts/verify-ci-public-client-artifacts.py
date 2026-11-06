#!/usr/bin/env python3
"""Select only successful, source-bound public client CI artifacts for upload."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

def validate_shipping_client_inventory(raw, provenance, actual_binary_sha256):
    """Require the Rust producer's closed graph and exact artifact bindings.

    A valid signed record is producer-observed evidence, never independent
    compiler linkage, native dependency completeness or legal acceptance.
    """
    import json
    import re

    def need(condition):
        if not condition:
            raise ValueError("shipping Cargo inventory rejected")

    def unique(items):
        value = {}
        for key, item in items:
            need(key not in value)
            value[key] = item
        return value

    def hex_value(value, length=64):
        return isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None

    def token(value):
        return isinstance(value, str) and 0 < len(value) <= 256 and re.fullmatch(r"[A-Za-z0-9._+\-]+", value) is not None

    def ordered_strings(values, safe=False):
        return isinstance(values, list) and all(isinstance(v, str) and (not safe or token(v)) for v in values) and all(a < b for a, b in zip(values, values[1:]))

    need(isinstance(raw, bytes) and 0 < len(raw) <= 4 * 1024 * 1024)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=lambda _: need(False))
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise ValueError("shipping Cargo inventory rejected") from None
    fields = {"schema", "scope", "native_payload_complete", "compiler_linkage_proven",
              "source_revision", "target_triple", "default_features", "requested_features",
              "cargo_lock_sha256", "client_binary_sha256", "cargo_metadata_sha256",
              "producer", "root_component", "components"}
    need(isinstance(value, dict) and set(value) == fields)
    need(value["schema"] == "aegis_shipping_client_cargo_inventory_v1" and
         value["scope"] == "selected_target_filtered_cargo_graph_not_compiler_linkage" and
         value["native_payload_complete"] is False and value["compiler_linkage_proven"] is False and
         value["default_features"] is True and hex_value(value["cargo_metadata_sha256"]))
    features = ["chrome-like-quic", "chrome-like-tls", "raw-socket"]
    need(isinstance(provenance, dict) and hex_value(provenance.get("git_sha"), 40) and
         hex_value(provenance.get("cargo_lock_sha256")) and hex_value(actual_binary_sha256) and
         provenance.get("target_triple") in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"))
    need(provenance.get("schema") == "aegis_client_release_bundle_manifest_v3" and set(provenance) == {
        "schema", "distribution", "bundle_name", "version", "arch", "platform", "target_triple",
        "git_sha", "build_timestamp", "cargo_lock_sha256", "runtime_abi", "binaries", "files", "install_entrypoints"})
    need(provenance["distribution"] == "public_client" and provenance["platform"] == "linux" and
         provenance["arch"] in ("x86_64", "aarch64") and provenance["target_triple"] == provenance["arch"] + "-unknown-linux-gnu")
    binaries = provenance.get("binaries")
    need(isinstance(binaries, dict) and set(binaries) == {"aegis-client"})
    binary = binaries["aegis-client"]
    need(isinstance(binary, dict) and set(binary) == {"features", "path", "sha256"} and binary.get("path") == "bin/aegis-client" and
         binary.get("sha256") == actual_binary_sha256 and isinstance(binary.get("features"), list) and
         len(binary["features"]) == 3 and all(isinstance(f, str) for f in binary["features"]) and
         set(binary["features"]) == set(features))
    need(value["source_revision"] == provenance["git_sha"] and
         value["target_triple"] == provenance["target_triple"] and
         value["cargo_lock_sha256"] == provenance["cargo_lock_sha256"] and
         value["client_binary_sha256"] == actual_binary_sha256 and
         value["requested_features"] == features)
    record = value["producer"]
    record_fields = {"schema", "source_revision", "target_triple", "cargo_lock_sha256",
                     "binary_sha256", "default_features", "requested_features", "resolved_root_features",
                     "compiler_artifact_message_sha256", "build_message_stream_sha256", "target_evidence"}
    need(isinstance(record, dict) and set(record) == record_fields)
    need(record["schema"] == "aegis_linux_client_build_record_v1" and
         record["source_revision"] == provenance["git_sha"] and record["target_triple"] == provenance["target_triple"] and
         record["cargo_lock_sha256"] == provenance["cargo_lock_sha256"] and
         record["binary_sha256"] == actual_binary_sha256 and record["default_features"] is True and
         record["requested_features"] == features and
         record["target_evidence"] == "explicit_cargo_target_and_fixed_producer_invocation" and
         hex_value(record["compiler_artifact_message_sha256"]) and hex_value(record["build_message_stream_sha256"]) and
         ordered_strings(record["resolved_root_features"], safe=True) and
         set(features).issubset(record["resolved_root_features"]))
    components = value["components"]
    need(isinstance(components, list) and 0 < len(components) <= 4096 and isinstance(value["root_component"], str))
    by_key, order, edges = {}, [], 0
    component_fields = {"key", "name", "version", "source_kind", "source_identity_sha256", "features", "dependencies"}
    for item in components:
        need(isinstance(item, dict) and set(item) == component_fields and token(item["name"]) and token(item["version"]) and
             hex_value(item["source_identity_sha256"]) and item["source_kind"] in ("reviewed_local_manifest", "crates_io_registry"))
        key = item["name"] + "@" + item["version"] + "#" + item["source_identity_sha256"]
        need(item["key"] == key and key not in by_key and ordered_strings(item["features"], safe=True) and
             ordered_strings(item["dependencies"]))
        by_key[key] = item
        order.append(key)
        edges += len(item["dependencies"])
    need(edges <= 16384 and all(a < b for a, b in zip(order, order[1:])) and value["root_component"] in by_key)
    root = by_key[value["root_component"]]
    need(root["name"] == "aegis-client" and root["source_kind"] == "reviewed_local_manifest" and
         root["features"] == record["resolved_root_features"] and set(features).issubset(root["features"]))
    visited, pending = set(), [value["root_component"]]
    while pending:
        key = pending.pop()
        need(key in by_key)
        if key in visited:
            continue
        visited.add(key)
        pending.extend(by_key[key]["dependencies"])
    need(len(visited) == len(by_key))
    return {"schema": value["schema"], "source_revision": value["source_revision"],
            "target_triple": value["target_triple"], "client_binary_sha256": actual_binary_sha256,
            "components": len(components), "native_payload_complete": False, "compiler_linkage_proven": False}

LIMIT = 64 * 1024 * 1024
PUBLIC = set("""bin/aegis-client install.sh config.example.toml
scripts/setup-wide-linux-redirect.sh scripts/setup-wide-linux-tproxy.sh
scripts/aegis-wide-enable.sh scripts/aegis-wide-disable.sh scripts/aegis-wide-persist-install.sh
scripts/purge-installed-aegis.sh scripts/aegis-ubuntu-uninstall.sh scripts/janitor-wide-linux-tproxy.sh
scripts/aegis-rpi-gateway.sh scripts/lib/root-state.sh packaging/systemd/aegis-client.service
packaging/env/aegis-client.env.example README.txt THIRD-PARTY-NOTICES.txt
scripts/aegis-device-egress-guard.sh SHA256SUMS bundle.manifest.json""".split())


def read(path, limit=LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit
        data = stream.read(limit + 1)
        assert len(data) == info.st_size <= limit
        return data


def unique(items):
    result = {}
    for name, value in items:
        assert name not in result, "duplicate JSON field"
        result[name] = value
    return result


def verify(directory, commit, arch="x86_64"):
    assert re.fullmatch(r"[a-f0-9]{40}", commit) and arch in ("x86_64", "aarch64")
    info = directory.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077
    receipt = json.loads(read(directory / "receipt.json", 65536), object_pairs_hook=unique)
    assert set(receipt) == {"schema", "contract_result", "contract_exit_code", "retention_result",
                            "public_bundle_schema", "public_bundle", "copied_file_sha256",
                            "recorded_at_utc", "scope"}, "unexpected receipt fields"
    assert receipt["schema"] == "aegis_release_contract_public_artifacts_v1"
    assert receipt["contract_result"] == "PASS" and type(receipt["contract_exit_code"]) is int and receipt["contract_exit_code"] == 0
    assert receipt["retention_result"] == "PUBLIC_CLIENT_ARTIFACTS_COPIED"
    assert receipt["public_bundle_schema"] in ("aegis_client_release_bundle_manifest_v2", "aegis_client_release_bundle_manifest_v3")
    bundle = receipt["public_bundle"]
    assert re.fullmatch(r"aegis-client-[0-9.]+-linux-" + arch, bundle)
    archive_name = bundle + ".tar.gz"
    checksum_name = archive_name + ".sha256"
    hashes = receipt["copied_file_sha256"]
    public = PUBLIC | ({"client-cargo-inventory.json"} if receipt["public_bundle_schema"] == "aegis_client_release_bundle_manifest_v3" else set())
    members = {bundle + "/" + name for name in public}
    assert set(hashes) == members | {archive_name, checksum_name}, "unexpected retained inventory"
    for name in (archive_name, checksum_name):
        assert hashlib.sha256(read(directory / name)).hexdigest() == hashes[name]
    assert read(directory / checksum_name, 4096).decode().split() == [hashes[archive_name], archive_name]
    seen, total, manifest, inventory_raw = set(), 0, None, None
    with tarfile.open(fileobj=io.BytesIO(read(directory / archive_name)), mode="r:gz") as archive:
        for member in archive:
            assert member.isfile() and member.name in members and member.name not in seen
            total += member.size
            assert 0 <= member.size and total <= LIMIT
            data = archive.extractfile(member).read(LIMIT + 1)
            assert len(data) == member.size and hashlib.sha256(data).hexdigest() == hashes[member.name]
            seen.add(member.name)
            if member.name == bundle + "/client-cargo-inventory.json":
                assert 0 < member.size <= 4 * 1024 * 1024
                inventory_raw = data
            if member.name == bundle + "/bundle.manifest.json":
                manifest = json.loads(data, object_pairs_hook=unique)
    assert seen == members
    assert manifest["schema"] == receipt["public_bundle_schema"] and manifest["distribution"] == "public_client"
    assert manifest["bundle_name"] == bundle and manifest["git_sha"] == commit
    assert manifest["platform"] == "linux" and manifest["arch"] == arch
    assert manifest["target_triple"] == arch + "-unknown-linux-gnu"
    assert set(manifest["binaries"]) == {"aegis-client"}
    binary = manifest["binaries"]["aegis-client"]
    assert binary["path"] == "bin/aegis-client"
    assert binary["sha256"] == hashes[bundle + "/bin/aegis-client"]
    assert type(manifest["files"]) is list and len(manifest["files"]) == len(public) - 1
    assert set(manifest["files"]) == public - {"bundle.manifest.json"}
    if manifest["schema"] == "aegis_client_release_bundle_manifest_v3":
        validate_shipping_client_inventory(inventory_raw, manifest, binary["sha256"])
    return archive_name


if __name__ == "__main__":
    assert len(sys.argv) == 3
    print("archive=" + verify(Path(sys.argv[1]), sys.argv[2]))
