#!/usr/bin/env python3
"""Inert real-consumer contracts; never execute packaged client or services."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
V3 = "aegis_client_release_bundle_manifest_v3"
LEAF = "client-cargo-inventory.json"
FEATURES = ["chrome-like-quic", "chrome-like-tls", "raw-socket"]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ShippingConsumers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / "scripts/lib"))
        cls.verify = load("private_device_verifier", ROOT / "scripts/lib/device_candidate_verify.py")
        cls.ci = load("private_ci_verifier", ROOT / "scripts/verify-ci-public-client-artifacts.py")
        cls.module = load("private_inventory_verifier", ROOT / "scripts/lib/shipping_client_inventory.py")
        installer = (ROOT / "install.sh").read_text()
        marker = 'python3 -I - "${ROOT}/bundle.manifest.json" "${ROOT}" "${ROLE}" <<\'PY\'\n'
        cls.install_program = installer.split(marker, 1)[1].split("\nPY\n", 1)[0]
        bootstrap = (ROOT / "bootstrap-install.sh").read_text()
        marker = 'python3 -I - "${BUNDLE_DIR}" "${MANIFEST_PATH}" "${MANIFEST_VERIFIED_SHA256}" <<\'PY_SHIPPING_INVENTORY\'\n'
        cls.bootstrap_program = bootstrap.split(marker, 1)[1].split("\nPY_SHIPPING_INVENTORY\n", 1)[0]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-inert-v3-consumers-", dir=os.path.realpath(tempfile.gettempdir()))
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.work.chmod(0o700)

    def payload(self, schema=V3, change=None, extra=None):
        leaves = self.verify.public_payload(schema)
        data = {name: b"INERT_PUBLIC_DATA\n" for name in leaves}
        data["bin/aegis-client"] = b"INERT_NOT_AN_EXECUTABLE\n"
        binary_hash = hashlib.sha256(data["bin/aegis-client"]).hexdigest()
        manifest = {"schema": schema, "distribution": "public_client", "bundle_name": "aegis-client-0.3.50-linux-x86_64",
                    "version": "0.3.50", "arch": "x86_64", "platform": "linux", "target_triple": "x86_64-unknown-linux-gnu",
                    "git_sha": "a" * 40, "build_timestamp": "2026-10-12T00:00:00Z", "cargo_lock_sha256": "b" * 64,
                    "runtime_abi": {}, "binaries": {"aegis-client": {"path": "bin/aegis-client", "sha256": binary_hash,
                    "features": FEATURES}}, "files": [], "install_entrypoints": []}
        identity = "c" * 64
        key = "aegis-client@0.3.50#" + identity
        resolved = sorted(FEATURES + ["default"])
        inventory = {"schema": "aegis_shipping_client_cargo_inventory_v1",
            "scope": "selected_target_filtered_cargo_graph_not_compiler_linkage", "native_payload_complete": False,
            "compiler_linkage_proven": False, "source_revision": manifest["git_sha"], "target_triple": manifest["target_triple"],
            "default_features": True, "requested_features": FEATURES, "cargo_lock_sha256": manifest["cargo_lock_sha256"],
            "client_binary_sha256": binary_hash, "cargo_metadata_sha256": "d" * 64, "root_component": key,
            "components": [{"key": key, "name": "aegis-client", "version": "0.3.50", "source_kind": "reviewed_local_manifest",
                            "source_identity_sha256": identity, "features": resolved, "dependencies": []}],
            "producer": {"schema": "aegis_linux_client_build_record_v1", "source_revision": manifest["git_sha"],
                         "target_triple": manifest["target_triple"], "cargo_lock_sha256": manifest["cargo_lock_sha256"],
                         "binary_sha256": binary_hash, "default_features": True, "requested_features": FEATURES,
                         "resolved_root_features": resolved, "compiler_artifact_message_sha256": "e" * 64,
                         "build_message_stream_sha256": "f" * 64,
                         "target_evidence": "explicit_cargo_target_and_fixed_producer_invocation"}}
        if change:
            change(inventory)
        if schema == V3:
            data[LEAF] = json.dumps(inventory).encode()
        if extra:
            data.update(extra)
        data["SHA256SUMS"] = "".join(hashlib.sha256(value).hexdigest() + "  " + name + "\n"
                                   for name, value in sorted(data.items())).encode()
        manifest["files"] = sorted(data)
        data["bundle.manifest.json"] = json.dumps(manifest).encode()
        return data, manifest, inventory

    def stage(self, data, manifest):
        root = self.work / ("staged-" + str(len(list(self.work.iterdir()))))
        root.mkdir(mode=0o700)
        for name, value in data.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
            path.chmod(0o600)
        return root

    def bootstrap_args(self, root, public=True):
        outer = self.work / ("verified-outer-" + str(len(list(self.work.iterdir()))) + ".json")
        data = json.dumps({"schema": "aegis_linux_release_manifest_v1", **({"distribution": "public_client"} if public else {})}).encode()
        outer.write_bytes(data)
        return [str(root), str(outer), hashlib.sha256(data).hexdigest()]

    def actual_inline(self, program, root, accepted):
        args = self.bootstrap_args(root) if program == self.bootstrap_program else [str(root / "bundle.manifest.json"), str(root), "client"]
        result = subprocess.run([sys.executable, "-I", "-c", program, *args], capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode == 0, accepted, "actual provenance program returned wrong admission")
        self.assertEqual((root / "bin/aegis-client").read_bytes(), b"INERT_NOT_AN_EXECUTABLE\n")

    def archived(self, data, inner):
        archive = self.work / (inner["bundle_name"] + ".tar.gz")
        with tarfile.open(archive, "w:gz") as stream:
            for name, value in data.items():
                member = tarfile.TarInfo(inner["bundle_name"] + "/" + name)
                member.size = len(value)
                stream.addfile(member, io.BytesIO(value))
        archive.chmod(0o600)
        outer = {key: inner[key] for key in ("version", "git_sha", "arch", "platform", "target_triple")}
        outer["distribution"] = "public_client"
        outer["artifacts"] = {"bundle": {"status": "ready", "directory": inner["bundle_name"], "archive": {
            "path": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}}}
        return self.work / "outer.manifest.json", outer

    def retained(self, data, inner):
        directory = self.work / ("retained-" + str(len(list(self.work.iterdir()))))
        directory.mkdir(mode=0o700)
        archive_name = inner["bundle_name"] + ".tar.gz"
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz") as tar:
            for name, value in data.items():
                member = tarfile.TarInfo(inner["bundle_name"] + "/" + name)
                member.size = len(value)
                tar.addfile(member, io.BytesIO(value))
        archive = out.getvalue()
        (directory / archive_name).write_bytes(archive)
        sums = (hashlib.sha256(archive).hexdigest() + "  " + archive_name + "\n").encode()
        (directory / (archive_name + ".sha256")).write_bytes(sums)
        hashes = {inner["bundle_name"] + "/" + name: hashlib.sha256(value).hexdigest() for name, value in data.items()}
        hashes.update({archive_name: hashlib.sha256(archive).hexdigest(), archive_name + ".sha256": hashlib.sha256(sums).hexdigest()})
        receipt = {"schema": "aegis_release_contract_public_artifacts_v1", "contract_result": "PASS", "contract_exit_code": 0,
                   "retention_result": "PUBLIC_CLIENT_ARTIFACTS_COPIED", "public_bundle_schema": inner["schema"],
                   "public_bundle": inner["bundle_name"], "copied_file_sha256": hashes,
                   "recorded_at_utc": "fixture", "scope": "inert recorded data only"}
        (directory / "receipt.json").write_text(json.dumps(receipt))
        return directory

    def test_all_actual_consumers_accept_bound_v3_without_executing_binary(self):
        data, inner, _ = self.payload()
        staged = self.stage(data, inner)
        self.actual_inline(self.install_program, staged, True)
        self.actual_inline(self.bootstrap_program, staged, True)
        path, outer = self.archived(data, inner)
        result = self.verify.inventory(path, outer, SimpleNamespace(client_bundle_schema=V3), "client")
        self.assertEqual(result["inner"]["schema"], V3)
        self.assertEqual(self.ci.verify(self.retained(data, inner), inner["git_sha"]), inner["bundle_name"] + ".tar.gz")

    def test_rehashed_foreign_bindings_rejected_by_all_actual_consumers(self):
        for field, value in (("source_revision", "f" * 40), ("target_triple", "aarch64-unknown-linux-gnu"),
                             ("cargo_lock_sha256", "f" * 64), ("client_binary_sha256", "f" * 64)):
            with self.subTest(field=field):
                data, inner, _ = self.payload(change=lambda row: row.__setitem__(field, value))
                stage = self.stage(data, inner)
                self.actual_inline(self.install_program, stage, False)
                self.actual_inline(self.bootstrap_program, stage, False)
                path, outer = self.archived(data, inner)
                with self.assertRaises(ValueError):
                    self.verify.inventory(path, outer, SimpleNamespace(client_bundle_schema=V3), "client")
                with self.assertRaises(ValueError):
                    self.ci.verify(self.retained(data, inner), inner["git_sha"])

    def test_legacy_v1_v2_unchanged_and_no_silent_inventory_extension(self):
        for schema in (self.verify.CLIENT_BUNDLE_SCHEMA_V1, self.verify.CLIENT_BUNDLE_SCHEMA_V2):
            data, inner, _ = self.payload(schema)
            self.actual_inline(self.install_program, self.stage(data, inner), True)
            self.actual_inline(self.bootstrap_program, self.stage(data, inner), True)
            path, outer = self.archived(data, inner)
            self.verify.inventory(path, outer, SimpleNamespace(client_bundle_schema=schema), "client")
            bad, bad_inner, _ = self.payload(schema, extra={LEAF: b"{}"})
            self.actual_inline(self.install_program, self.stage(bad, bad_inner), False)
            path, outer = self.archived(bad, bad_inner)
            with self.assertRaises(ValueError):
                self.verify.inventory(path, outer, SimpleNamespace(client_bundle_schema=schema), "client")

    def test_missing_record_omission_duplicate_unreachable_and_overclaim_refused(self):
        def unreachable(row):
            item = copy.deepcopy(row["components"][0])
            item["name"] = "zz-unreachable"
            item["key"] = item["name"] + "@" + item["version"] + "#" + item["source_identity_sha256"]
            row["components"].append(item)
        changes = [lambda row: row.pop("producer"), lambda row: row["components"].clear(),
                   lambda row: row["components"].append(copy.deepcopy(row["components"][0])), unreachable,
                   lambda row: row.__setitem__("native_payload_complete", True),
                   lambda row: row.__setitem__("compiler_linkage_proven", True),
                   lambda row: row["producer"].__setitem__("binary_sha256", "f" * 64),
                   lambda row: row["components"][0]["dependencies"].append("missing@1#" + "f" * 64)]
        for change in changes:
            data, inner, _ = self.payload(change=change)
            self.actual_inline(self.bootstrap_program, self.stage(data, inner), False)
            self.actual_inline(self.install_program, self.stage(data, inner), False)

    def test_inventory_duplicate_unknown_fields_and_size_refused(self):
        data, inner, row = self.payload()
        for raw in (b'{"schema":"duplicate",' + data[LEAF][1:], json.dumps({**row, "private_path": "INVALID"}).encode(), b" " * (4 * 1024 * 1024 + 1)):
            with self.assertRaises(ValueError):
                self.module.validate_shipping_client_inventory(raw, inner, inner["binaries"]["aegis-client"]["sha256"])

    def test_v3_missing_leaf_extra_helper_and_duplicate_provenance_refused(self):
        for change in ("missing", "extra", "duplicate"):
            data, inner, _ = self.payload()
            if change == "missing":
                del data[LEAF]
            elif change == "extra":
                data["scripts/UNAPPROVED_HELPER.sh"] = b"INERT_NEVER_EXECUTE\n"
            data["SHA256SUMS"] = "".join(hashlib.sha256(value).hexdigest() + "  " + key + "\n"
                for key, value in sorted(data.items()) if key not in ("SHA256SUMS", "bundle.manifest.json")).encode()
            inner["files"] = sorted(name for name in data if name != "bundle.manifest.json")
            data["bundle.manifest.json"] = json.dumps(inner).encode()
            if change == "duplicate":
                data["bundle.manifest.json"] = b'{"git_sha":"' + b"a" * 40 + b'",' + data["bundle.manifest.json"][1:]
            self.actual_inline(self.install_program, self.stage(data, inner), False)
            self.actual_inline(self.bootstrap_program, self.stage(data, inner), False)
            path, outer = self.archived(data, inner)
            with self.assertRaises(ValueError):
                self.verify.inventory(path, outer, SimpleNamespace(client_bundle_schema=V3), "client")

    def test_bootstrap_oversize_aggregate_refuses_before_payload_reads(self):
        data, inner, _ = self.payload()
        root = self.stage(data, inner)
        names = sorted(set(data) - {"bundle.manifest.json", "bin/aegis-client", LEAF, "SHA256SUMS"})[:8]
        for name in names:
            with (root / name).open("r+b") as stream:
                stream.truncate(9 * 1024 * 1024)
        observed = self.work / "payload-read-observed"
        # Instrument only this fixture's file reader. Old late-allocation code
        # attempts a large leaf read; the real new preallocation guard refuses
        # before that call. Sparse files never run product code or services.
        prefix = """import os
_original_fdopen = os.fdopen
class _ReadWitness:
    def __init__(self, stream): self.stream = stream
    def __enter__(self): self.stream.__enter__(); return self
    def __exit__(self, *args): return self.stream.__exit__(*args)
    def fileno(self): return self.stream.fileno()
    def read(self, limit):
        if os.fstat(self.stream.fileno()).st_size > 1024 * 1024:
            with open(WITNESS, 'w') as witness: witness.write('inert-read-attempt')
            raise RuntimeError('inert oversize read witness')
        return self.stream.read(limit)
os.fdopen = lambda *args, **kwargs: _ReadWitness(_original_fdopen(*args, **kwargs))
""".replace("WITNESS", repr(str(observed)))
        result = subprocess.run([sys.executable, "-I", "-c", prefix + self.bootstrap_program, *self.bootstrap_args(root)],
                                capture_output=True, timeout=5, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(observed.exists(), "aggregate refusal must precede all large payload reads")
        self.assertEqual((root / "bin/aegis-client").read_bytes(), b"INERT_NOT_AN_EXECUTABLE\n")

    def test_verified_private_source_layout_without_inner_and_public_refusal(self):
        root = self.work / "source-layout"
        root.mkdir()
        (root / "Cargo.toml").write_text("INERT_SOURCE_LAYOUT_MARKER\n")
        (root / "aegis-client").mkdir()
        (root / "aegis-server").mkdir()
        for public, accepted in ((False, True), (True, False)):
            result = subprocess.run([sys.executable, "-I", "-c", self.bootstrap_program, *self.bootstrap_args(root, public)],
                                    capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode == 0, accepted)
        (root / "aegis-server").rmdir()
        result = subprocess.run([sys.executable, "-I", "-c", self.bootstrap_program, *self.bootstrap_args(root, False)],
                                capture_output=True, timeout=5, check=False)
        self.assertNotEqual(result.returncode, 0, "non-source private package still requires provenance")

    def test_outer_custody_and_v3_distribution_binding(self):
        data, inner, _ = self.payload()
        root = self.stage(data, inner)
        args = self.bootstrap_args(root)
        args[-1] = "0" * 64
        result = subprocess.run([sys.executable, "-I", "-c", self.bootstrap_program, *args],
                                capture_output=True, timeout=5, check=False)
        self.assertNotEqual(result.returncode, 0)
        result = subprocess.run([sys.executable, "-I", "-c", self.bootstrap_program, *self.bootstrap_args(root, False)],
                                capture_output=True, timeout=5, check=False)
        self.assertNotEqual(result.returncode, 0, "v3 may not use a private outer distribution")

    def test_explicit_v3_cli_and_fullwide_release_admission_wired(self):
        acceptance = (ROOT / "scripts/lib/device_candidate_acceptance.py").read_text()
        self.assertIn("'aegis_client_release_bundle_manifest_v3'", acceptance)
        fullwide = (ROOT / "scripts/lib/device_fullwide_acceptance.py").read_text()
        self.assertIn("release['client_bundle_schema'] in ('aegis_client_release_bundle_manifest_v2', 'aegis_client_release_bundle_manifest_v3')", fullwide)
        # The controller default remains its existing independently pinned v1.
        self.assertIn("default='aegis_client_release_bundle_manifest_v1'", acceptance)

    def test_all_embeddings_equal_controller_verifier_definition(self):
        source = (ROOT / "scripts/lib/shipping_client_inventory.py").read_text()
        expected = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef))
        for code in (self.install_program, self.bootstrap_program, (ROOT / "scripts/verify-ci-public-client-artifacts.py").read_text()):
            actual = next(node for node in ast.parse(code).body if isinstance(node, ast.FunctionDef) and node.name == expected.name)
            self.assertEqual(ast.dump(actual, include_attributes=False), ast.dump(expected, include_attributes=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, default=ROOT)
    args, rest = parser.parse_known_args()
    ROOT = args.candidate_root.resolve()
    unittest.main(argv=[sys.argv[0], *rest])
