"""Offline v3 receipt verification only; not runtime/product inventory logic."""


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
