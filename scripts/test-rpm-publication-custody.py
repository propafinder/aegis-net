#!/usr/bin/env python3
"""Run the actual RPM verification/publish block against inert fake RPM tools."""
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/build-rpm-packages.sh").read_text()
START = "# Bind every verification to exactly the two files from this invocation's fresh"
END = "\ncat <<EOF"
assert SOURCE.count(START) == SOURCE.count(END) == 1
BLOCK = SOURCE.split(START, 1)[1].split(END, 1)[0]
BLOCK = START + BLOCK


class RpmPublicationCustody(unittest.TestCase):
    def run_case(self, *, bad_client=False, stale=False, duplicate=False,
                 prior_exact=False, prior_symlink=False, interrupt_pair=False):
        with tempfile.TemporaryDirectory(prefix="aegis-rpm-publication-") as name:
            base = Path(name)
            topdir = base / "topdir" / "RPMS" / "aarch64"
            output = base / "output"
            rootfs = base / "rootfs" / "usr/local/bin"
            toolbin = base / "toolbin"
            for directory in (topdir, output, rootfs, toolbin):
                directory.mkdir(parents=True, exist_ok=True)
            for role in ("server", "client"):
                (rootfs / ("aegis-" + role)).write_bytes((role + "-binary").encode())
            names = [f"aegis-{role}-0.3.50-1.el9.aarch64.rpm"
                     for role in ("server", "client")]
            for index, rpm_name in enumerate(names):
                (topdir / rpm_name).write_bytes(("fresh-" + str(index)).encode())
            if duplicate:
                (topdir / "aegis-client-0.3.50-1.el8.aarch64.rpm").write_bytes(b"extra")
            if stale:
                (output / "aegis-server-0.3.50-1.el8.aarch64.rpm").write_bytes(b"prior")
            if prior_exact:
                (output / names[0]).write_bytes(b"old exact")
                (output / "rpm-packages.manifest.json").write_bytes(b"old marker")
            if prior_symlink:
                anchor = base / "old-target"
                anchor.write_bytes(b"old target")
                (output / names[0]).symlink_to(anchor)

            payload = base / "payload.tar"
            with tarfile.open(payload, "w") as archive:
                for role in ("server", "client"):
                    archive.add(rootfs / ("aegis-" + role),
                                arcname="usr/local/bin/aegis-" + role)
            tools = {
                "rpm": "#!/bin/sh\ncase \"$4\" in *aegis-client*) [ \"${BAD_CLIENT:-0}\" = 1 ] && { printf 'root:wheel\\n'; exit 0; } ;; esac\nprintf 'root:root\\n'\n",
                "rpm2cpio": "#!/bin/sh\ncat \"$AEGIS_TEST_PAYLOAD_TAR\"\n",
                "cpio": "#!/bin/sh\ntar -xf -\n",
                "cargo": "#!/bin/sh\nexec /usr/bin/python3 \"$AEGIS_TEST_FAKE_CARGO\" \"$@\"\n",
            }
            if interrupt_pair:
                tools["mv"] = "#!/bin/sh\ncase \"$*\" in *aegis-client-*.sha256*) exit 9;; esac\nexec /bin/mv \"$@\"\n"
            for command, body in tools.items():
                path = toolbin / command
                path.write_text(body)
                path.chmod(0o755)
            fake_cargo = base / "fake-cargo.py"
            fake_cargo.write_text("""import hashlib, json, pathlib, sys
args = sys.argv[1:]
out = pathlib.Path(args[args.index('--output-dir') + 1])
version = args[args.index('--version') + 1]
arch = args[args.index('--arch') + 1]
packages = {}
for role in ('server', 'client'):
    package = 'aegis-' + role
    name = next(path.name for path in out.glob(package + '-*.rpm'))
    digest = hashlib.sha256((out / name).read_bytes()).hexdigest()
    (out / (name + '.sha256')).write_text(f'{digest}  {name}\\n')
    packages[package] = {'rpm_file': name, 'sha256_file': name + '.sha256'}
(out / 'rpm-packages.manifest.json').write_text(json.dumps({'version': version, 'arch': arch, 'packages': packages}))
""")
            script = "\n".join((
                "set -euo pipefail",
                'VERSION=0.3.50 ARCH=aarch64',
                'RPM_TOPDIR="$AEGIS_TEST_RPM_TOPDIR"',
                'OUTPUT_DIR="$AEGIS_TEST_OUTPUT_DIR"',
                'ROOTFS_DIR="$AEGIS_TEST_ROOTFS_DIR"',
                'TMP_DIR="$AEGIS_TEST_TMP_DIR"',
                'ROOT="$AEGIS_TEST_ROOT"',
                'PUBLISH_TEMPS=() PRESERVE_RPM_FAILURE=0',
                BLOCK,
            ))
            env = dict(os.environ, PATH=str(toolbin) + os.pathsep + os.environ["PATH"],
                       AEGIS_TEST_RPM_TOPDIR=str(base / "topdir"),
                       AEGIS_TEST_OUTPUT_DIR=str(output),
                       AEGIS_TEST_ROOTFS_DIR=str(base / "rootfs"),
                       AEGIS_TEST_TMP_DIR=str(base / "private"),
                       AEGIS_TEST_PAYLOAD_TAR=str(payload),
                       BAD_CLIENT="1" if bad_client else "0",
                       AEGIS_TEST_ROOT=str(ROOT), AEGIS_TEST_FAKE_CARGO=str(fake_cargo))
            result = subprocess.run(["bash", "-c", script], env=env,
                                    capture_output=True, text=True)
            published = {p.name: p.read_bytes() for p in output.iterdir() if p.is_file()}
            return result.returncode, published

    def test_good_fresh_pair_publishes_exact_current_bytes(self):
        code, files = self.run_case()
        self.assertEqual(code, 0)
        self.assertEqual(files["aegis-server-0.3.50-1.el9.aarch64.rpm"], b"fresh-0")
        self.assertEqual(files["aegis-client-0.3.50-1.el9.aarch64.rpm"], b"fresh-1")
        self.assertIn("rpm-packages.manifest.json", files)
        self.assertIn("aegis-server-0.3.50-1.el9.aarch64.rpm.sha256", files)
        self.assertIn("aegis-client-0.3.50-1.el9.aarch64.rpm.sha256", files)

    def test_rejected_owner_does_not_publish_either_package(self):
        code, files = self.run_case(bad_client=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(files, {})

    def test_stale_other_dist_is_preserved_and_refuses_before_publish(self):
        code, files = self.run_case(stale=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(files, {"aegis-server-0.3.50-1.el8.aarch64.rpm": b"prior"})

    def test_duplicate_current_build_is_refused_before_publish(self):
        code, files = self.run_case(duplicate=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(files, {})

    def test_rebuild_replaces_same_exact_name_after_verification(self):
        code, files = self.run_case(prior_exact=True)
        self.assertEqual(code, 0)
        self.assertEqual(files["aegis-server-0.3.50-1.el9.aarch64.rpm"], b"fresh-0")

    def test_interrupted_pair_has_no_completion_marker(self):
        code, files = self.run_case(prior_exact=True, interrupt_pair=True)
        self.assertNotEqual(code, 0)
        self.assertNotIn("rpm-packages.manifest.json", files)

    def test_preexisting_exact_name_symlink_is_refused(self):
        code, files = self.run_case(prior_symlink=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(files["aegis-server-0.3.50-1.el9.aarch64.rpm"], b"old target")
        self.assertNotIn("aegis-client-0.3.50-1.el9.aarch64.rpm", files)


if __name__ == "__main__":
    unittest.main()
