#!/usr/bin/env python3
"""Synthetic nonroot tar ownership contract; no Rust build or installation."""
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TarOwnerContract(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(), 0, "run this metadata test as a nonroot builder")

    def tar(self, *args):
        env = dict(os.environ, COPYFILE_DISABLE="1")
        subprocess.run(["tar", *map(str, args)], check=True, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_producers_bind_every_member_to_numeric_root(self):
        with tempfile.TemporaryDirectory(prefix="aegis-tar-owner-") as name:
            base = Path(name)
            stage = base / "stage"
            (stage / "bin").mkdir(parents=True)
            (stage / "bin" / "inert").write_bytes(b"inert fixture\n")
            for label, prefix in (
                ("package-root", []),
                ("release-bundle", ["--format=ustar"]),
                ("rpm-source", []),
            ):
                output = base / (label + ".tar.gz")
                self.tar(*prefix, "--owner=0", "--group=0", "--numeric-owner",
                         "-C", base, "-czf", output, "stage")
                with tarfile.open(output, "r:gz") as archive:
                    members = archive.getmembers()
                    self.assertGreaterEqual(len(members), 3)
                    self.assertTrue(all((item.uid, item.gid) == (0, 0)
                                        for item in members))

    def test_extractor_ignores_nonroot_archive_owner(self):
        with tempfile.TemporaryDirectory(prefix="aegis-tar-extract-") as name:
            base = Path(name)
            archive = base / "synthetic-foreign-owner.tar.gz"
            with tarfile.open(archive, "w:gz") as out:
                payload = b"inert fixture\n"
                member = tarfile.TarInfo("payload/inert")
                member.size = len(payload)
                member.mode = 0o644
                member.uid = member.gid = 424242
                member.uname = member.gname = "foreign-builder"
                out.addfile(member, io.BytesIO(payload))
            target = base / "extract"
            target.mkdir(mode=0o700)
            self.tar("--no-same-owner", "-xzf", archive, "-C", target)
            leaf = target / "payload" / "inert"
            self.assertEqual(leaf.read_bytes(), b"inert fixture\n")
            self.assertEqual((leaf.stat().st_uid, leaf.stat().st_gid),
                             (os.geteuid(), os.getegid()))

    def test_source_commands_keep_the_contract(self):
        package = (ROOT / "scripts/build-package-root.sh").read_text()
        bundle = (ROOT / "scripts/build-release-bundle.sh").read_text()
        rpm = (ROOT / "scripts/build-rpm-packages.sh").read_text()
        bootstrap = (ROOT / "bootstrap-install.sh").read_text()
        install = (ROOT / "install.sh").read_text()
        flags = "--owner=0 --group=0 --numeric-owner"
        self.assertEqual(package.count("tar " + flags + " -C"), 1)
        self.assertEqual(bundle.count("tar --format=ustar " + flags + " -C"), 2)
        self.assertEqual(rpm.count("tar " + flags + " -C"), 1)
        self.assertIn("tar --no-same-owner -xzf %{SOURCE0}", rpm)
        self.assertEqual(bootstrap.count("tar --no-same-owner -xzf"), 2)
        self.assertEqual(install.count("tar --no-same-owner -xzf"), 1)
        self.assertIn("[%{FILEUSERNAME}:%{FILEGROUPNAME}\\n]", rpm)


if __name__ == "__main__":
    unittest.main()
