#!/usr/bin/env python3
"""Linux/root controls of the actual installer payload-retention implementation."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = (ROOT / "install.sh").read_text()
BODY = INSTALLER.split("<<'PY_AUTO_RETAIN_PAYLOAD'\n", 1)[1].split("\nPY_AUTO_RETAIN_PAYLOAD\n", 1)[0]


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "requires root-owned Linux retained payload ancestry")
class RetainedPayload(unittest.TestCase):
    def invoke(self, source, destination, candidate, source_layout=False):
        body = BODY.replace("/var/lib/aegis-auto/releases", str(destination))
        return subprocess.run([sys.executable, "-I", "-B", "-c", body, str(source),
                               "1" if source_layout else "0", str(candidate)],
                              capture_output=True, text=True, timeout=30)

    def release(self, root):
        source = root / "public"
        data = {"bin/aegis-client": b"\x7fELFprotected test executable",
                "install.sh": b"#!/bin/bash\nexit 0\n",
                "scripts/lib/aegis_installer_auto_v2.py":
                    (ROOT / "scripts/lib/aegis_installer_auto_v2.py").read_bytes(),
                "scripts/lib/aegis_auto_guardian.py":
                    (ROOT / "scripts/lib/aegis_auto_guardian.py").read_bytes(),
                "scripts/lib/aegis_auto_ufw_pins.json": b"{}\n",
                "packaging/systemd/aegis-client.service": b"[Service]\n",
                "packaging/env/aegis-client.env.example": b"# public template\n"}
        for name, raw in data.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o755 if name in ("bin/aegis-client", "install.sh",
                                          "scripts/lib/aegis_auto_guardian.py",
                                          "scripts/lib/aegis_auto_ufw_pins.json") else 0o644)
        (source / "SHA256SUMS").write_text("".join(
            hashlib.sha256(raw).hexdigest() + "  " + name + "\n" for name, raw in sorted(data.items())))
        manifest = {"schema": "aegis_release_bundle_manifest_v2", "files": sorted(data) + ["SHA256SUMS"],
                    "binaries": {"aegis-client": {"path": "bin/aegis-client",
                                                    "sha256": hashlib.sha256(data["bin/aegis-client"]).hexdigest()}}}
        (source / "bundle.manifest.json").write_text(json.dumps(manifest))
        return source

    def test_prebuilt_retains_exact_manifest_path_and_refuses_changed_generation(self):
        with tempfile.TemporaryDirectory(dir="/root", prefix="aegis-retention-") as temporary:
            root = Path(temporary)
            source = self.release(root)
            destination = root / "retained"
            candidate = source / "bin/aegis-client"
            result = self.invoke(source, destination, candidate)
            self.assertEqual(result.returncode, 0, result.stderr)
            retained = Path(result.stdout.strip())
            self.assertEqual((retained / "bin/aegis-client").read_bytes(), candidate.read_bytes())
            self.assertEqual((retained / "install.sh").stat().st_mode & 0o777, 0o555)
            self.assertEqual((retained / "bundle.manifest.json").stat().st_mode & 0o777, 0o444)
            for name in ("scripts/lib/aegis_auto_guardian.py",
                         "scripts/lib/aegis_auto_ufw_pins.json"):
                self.assertEqual((retained / name).stat().st_mode & 0o777, 0o444, name)
            self.assertEqual(self.invoke(source, destination, candidate).returncode, 0)
            (retained / "install.sh").chmod(0o755)
            (retained / "install.sh").write_bytes(b"changed retained source")
            (retained / "install.sh").chmod(0o555)
            self.assertNotEqual(self.invoke(source, destination, candidate).returncode, 0)

    def test_prebuilt_symlink_and_bad_checksum_refuse(self):
        for reason in ("symlink", "checksum"):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory(dir="/root", prefix="aegis-retention-") as temporary:
                root = Path(temporary)
                source = self.release(root)
                candidate = source / "bin/aegis-client"
                if reason == "symlink":
                    saved = source / "saved-script"
                    (source / "install.sh").rename(saved)
                    (source / "install.sh").symlink_to(saved)
                else:
                    (source / "SHA256SUMS").write_text("0" * 64 + "  install.sh\n")
                self.assertNotEqual(self.invoke(source, root / "retained", candidate).returncode, 0)

    def test_boot_gate_import_keeps_exact_retained_roster(self):
        self.assertIn(
            'python3 -I -B - "$STAGE_AUTO_INSTALL_LOCK_FD" "$ROOT" <<\'PY_AUTO_BOOT_GATE\'',
            INSTALLER,
        )
        with tempfile.TemporaryDirectory(dir="/root", prefix="aegis-retention-") as temporary:
            root = Path(temporary)
            source = self.release(root)
            destination = root / "retained"
            candidate = source / "bin/aegis-client"
            first = self.invoke(source, destination, candidate)
            self.assertEqual(first.returncode, 0, first.stderr)
            retained = Path(first.stdout.strip())
            coordinator = retained / "scripts/lib/aegis_installer_auto_v2.py"
            # Execute the same import mechanism as the boot-gate producer with
            # its source-owned interpreter flags, then retry retention.
            program = ("import importlib.util,sys\n"
                       "spec=importlib.util.spec_from_file_location('aegis_boot_gate_atomic',sys.argv[1])\n"
                       "module=importlib.util.module_from_spec(spec)\n"
                       "spec.loader.exec_module(module)\n")
            imported = subprocess.run([sys.executable, "-I", "-B", "-c", program,
                                       str(coordinator)], capture_output=True, text=True, timeout=15)
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertFalse((coordinator.parent / "__pycache__").exists())
            self.assertEqual(self.invoke(source, destination, candidate).returncode, 0)
            # A foreign extra file must still make the exact roster refuse.
            extra = coordinator.parent / "__pycache__"
            extra.mkdir()
            (extra / "aegis_installer_auto_v2.cpython-312.pyc").write_bytes(b"foreign")
            self.assertNotEqual(self.invoke(source, destination, candidate).returncode, 0)

            # Reproduce the original missing -B launcher in a separate closed
            # release. A genuine import creates bytecode and strict retention
            # rejects the new leaf on the next attempt.
            old_destination = root / "legacy-retained"
            old_first = self.invoke(source, old_destination, candidate)
            self.assertEqual(old_first.returncode, 0, old_first.stderr)
            old_coordinator = Path(old_first.stdout.strip()) / "scripts/lib/aegis_installer_auto_v2.py"
            old_import = subprocess.run([sys.executable, "-I", "-c", program,
                                         str(old_coordinator)], capture_output=True, text=True,
                                        timeout=15)
            self.assertEqual(old_import.returncode, 0, old_import.stderr)
            self.assertTrue(list(old_coordinator.parent.glob("__pycache__/*.pyc")))
            self.assertNotEqual(self.invoke(source, old_destination, candidate).returncode, 0)

    def test_source_assets_stay_absent_manifest_and_do_not_copy_private_checkout(self):
        with tempfile.TemporaryDirectory(dir="/root", prefix="aegis-retention-") as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.write_bytes(b"\x7fELFsource candidate")
            candidate.chmod(0o755)
            result = self.invoke(ROOT, root / "retained", candidate, source_layout=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            retained = Path(result.stdout.strip())
            self.assertFalse((retained / "bundle.manifest.json").exists())
            self.assertEqual((retained / "bin/aegis-client").read_bytes(), candidate.read_bytes())
            for name in (".git", "AGENTS.md", "artifacts", "target", ".cursor", "Cargo.toml"):
                self.assertFalse((retained / name).exists(), name)
            self.assertTrue((retained / "scripts/lib/aegis_installer_auto_v2.py").is_file())


if __name__ == "__main__":
    unittest.main()
