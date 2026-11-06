#!/usr/bin/python3 -I
"""Product legal resources are exact source bytes and refuse drift before output."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class LegalResources(unittest.TestCase):
    def test_product_copies_pinned_texts_and_refuses_mutated_source(self):
        source = Path(__file__).resolve().parents[1] / "assemble-unsigned.py"
        project = source.parents[3]
        names = ("THIRD-PARTY-NOTICES", "NOTICE", "LICENSE-MIT", "LICENSE-APACHE")
        native_license = "LICENSE-LIBVPX"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "project"
            script = root / "tools/macos/aegis-network-extension/assemble-unsigned.py"
            script.parent.mkdir(parents=True)
            shutil.copyfile(source, script)
            for name in names:
                shutil.copyfile(project / name, root / name)
            (script.parent / "legal").mkdir()
            shutil.copyfile(source.parent / "legal" / native_license,
                            script.parent / "legal" / native_license)
            host, provider = Path(temp) / "host", Path(temp) / "provider"
            for binary in (host, provider):
                binary.write_bytes(bytes.fromhex("cffaedfe") + b"synthetic")
            base = [sys.executable, "-I", "-B", str(script), "--product",
                    "--host-binary", str(host), "--provider-binary", str(provider),
                    "--app-id", "dev.aegis.macos",
                    "--provider-id", "dev.aegis.macos.PacketTunnel",
                    "--app-group", "group.TEAMID0000.dev.aegis.macos",
                    "--team-id", "TEAMID0000", "--bundle-version", "42",
                    "--short-version", "0.1.0"]
            first = Path(temp) / "first"
            ok = subprocess.run(base + ["--output", str(first)], capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            manifest = json.loads((first / "assembly.json").read_text())
            for name in names:
                actual = (first / "AEGIS.app/Contents/Resources/Legal" / name).read_bytes()
                self.assertEqual(actual, (root / name).read_bytes())
                self.assertEqual(hashlib.sha256(actual).hexdigest(), manifest["legal_resources"][name])
            actual_native = (first / "AEGIS.app/Contents/Resources/Legal" / native_license).read_bytes()
            self.assertEqual(actual_native, (script.parent / "legal" / native_license).read_bytes())
            self.assertEqual(hashlib.sha256(actual_native).hexdigest(), manifest["legal_resources"][native_license])
            (root / "NOTICE").write_bytes(b"mutated\n")
            second = Path(temp) / "second"
            failed = subprocess.run(base + ["--output", str(second)], capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse(second.exists())


if __name__ == "__main__":
    unittest.main()
