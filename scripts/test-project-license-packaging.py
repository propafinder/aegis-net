#!/usr/bin/env python3
"""Run actual shell packagers with inert tools; not native package/build acceptance."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGER_ROOT = ROOT
LICENSES = ("LICENSE-MIT", "LICENSE-APACHE", "NOTICE", "THIRD-PARTY-NOTICES")
H2_LICENSE = "third-party/h2/LICENSE"
TUNGSTENITE_LICENSES = ("third-party/tungstenite/LICENSE-MIT", "third-party/tungstenite/LICENSE-APACHE")
PACKAGERS = (
    "build-release-bundle.sh", "build-package-root.sh",
    "build-split-deb-packages.sh", "build-rpm-packages.sh",
)

# The dpkg stub produces a tiny structural DEB with root-owned control/data
# entries so the production ownership gate executes. RPM bytes remain inert.
TOOL = r'''
import hashlib, io, json, os, pathlib, re, sys, tarfile
p = pathlib.Path
name = p(sys.argv[0]).name
args = sys.argv[1:]
root = p(os.environ["LICENSE_FIXTURE_ROOT"])
def option(flag):
    return args[args.index(flag) + 1]
def digest(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()
def inventory(directory):
    return {str(file.relative_to(directory)): digest(file)
            for file in sorted(directory.rglob("*")) if file.is_file()}
def write_inventory(directory):
    data = {"fixture_only": True, "files": inventory(directory)}
    (directory / "fixture-inventory.json").write_text(json.dumps(data, sort_keys=True))
def archive(directory, target):
    with tarfile.open(target, "w:gz") as tar:
        for file in sorted(directory.rglob("*")):
            tar.add(file, arcname=str(file.relative_to(directory)), recursive=False)
if name == "cargo":
    if args[0] == "build":
        # Pre-existing inert bytes, never Cargo or a native compilation.
        if "-p" in args and args[args.index("-p") + 1] == "aegis-client" and "--target" in args:
            target = option("--target")
            assert target == "x86_64-unknown-linux-gnu", "unexpected fixture client target"
            source = root / "target/release/aegis-client"
            executable = root / "target" / target / "release/aegis-client"
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(source.read_bytes()); executable.chmod(source.stat().st_mode & 0o777)
            if "--message-format=json-render-diagnostics" in args:
                print(json.dumps({"reason":"compiler-artifact", "fixture_only":True,
                    "package_id":"fixture-client", "manifest_path":str(root / "aegis-client/Cargo.toml"),
                    "target":{"name":"aegis-client","kind":["bin"]}, "profile":{"test":False},
                    "features":["chrome-like-quic","chrome-like-tls","raw-socket"], "executable":str(executable)}))
                print(json.dumps({"reason":"build-finished","success":True,"fixture_only":True}))
        raise SystemExit(0)
    assert args[0] == "run" and "--" in args
    command = args[args.index("--") + 1]
    if command == "release-package-metadata":
        print(str(root / "target")); print("0.0.1-fixture")
    elif command in ("build-release-bundle-manifest", "build-private-research-manifest"):
        write_inventory(p(option("--bundle-dir")))
    elif command == "build-package-root-manifest":
        write_inventory(p(option("--rootfs-dir")))
    elif command == "write-deb-md5-sums":
        stage = p(option("--stage-dir")); debian = p(option("--debian-dir"))
        lines = [hashlib.md5(file.read_bytes(), usedforsecurity=False).hexdigest()
                 + "  " + str(file.relative_to(stage))
                 for file in sorted(stage.rglob("*"))
                 if file.is_file() and debian not in file.parents]
        (debian / "md5sums").write_text("\n".join(lines) + "\n")
    elif command == "write-archive-sha256":
        file = p(option("--archive"))
        p(option("--sha256-path")).write_text(digest(file) + "  " + file.name + "\n")
    elif command in ("build-split-deb-manifest", "build-rpm-packages-manifest"):
        directory = p(option("--output-dir"))
        suffix = ".deb" if command == "build-split-deb-manifest" else ".rpm"
        data = {file.name: digest(file) for file in directory.glob("*" + suffix)}
        if suffix == ".deb":
            data = {"version": option("--version"), "deb_arch": option("--deb-arch"),
                    "packages": {name: {"deb_file": f"{name}_{option('--version')}_{option('--deb-arch')}.deb"}
                                 for name in ("aegis-server", "aegis-client")}}
            manifest = "split-deb-packages.manifest.json"
        else:
            packages = {}
            for package in ("aegis-server", "aegis-client"):
                file = next(directory.glob(package + "-*.rpm"))
                (directory / (file.name + ".sha256")).write_text(digest(file) + "  " + file.name + "\n")
                packages[package] = {"rpm_file": file.name, "sha256_file": file.name + ".sha256"}
            data = {"version": option("--version"), "arch": option("--arch"), "packages": packages}
            manifest = "rpm-packages.manifest.json"
        (directory / manifest).write_text(json.dumps(data, sort_keys=True))
    else:
        raise SystemExit("unreviewed fixture cargo command: " + command)
elif name == "dpkg-deb":
    assert args[:3] == ["--root-owner-group", "--build", "-Zxz"] and len(args) == 5
    stage, output = p(args[3]), p(args[4])
    def tar_bytes(files, base):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:xz") as tar:
            root_entry = tarfile.TarInfo("./"); root_entry.type = tarfile.DIRTYPE
            root_entry.mode = 0o755; tar.addfile(root_entry)
            for file in sorted(files):
                entry = tar.gettarinfo(str(file), arcname="./" + str(file.relative_to(base)))
                entry.uid = entry.gid = 0; entry.uname = entry.gname = "root"
                if entry.isfile():
                    with file.open("rb") as source: tar.addfile(entry, source)
                else:
                    tar.addfile(entry)
        return stream.getvalue()
    def ar_member(member_name, payload):
        header = (f"{member_name}/".ljust(16) + "0".ljust(12) + "0".ljust(6)
                  + "0".ljust(6) + "100644".ljust(8)
                  + str(len(payload)).ljust(10) + "`\n").encode()
        return header + payload + (b"\n" if len(payload) % 2 else b"")
    control = tar_bytes(stage.joinpath("DEBIAN").rglob("*"), stage / "DEBIAN")
    data = tar_bytes((file for file in stage.rglob("*") if "DEBIAN" not in file.relative_to(stage).parts), stage)
    output.write_bytes(b"!<arch>\n" + ar_member("debian-binary", b"2.0\n")
                       + ar_member("control.tar.xz", control) + ar_member("data.tar.xz", data))
elif name == "rpmbuild":
    assert args[:1] == ["--define"] and args[2] == "-bb"
    top = p(args[1].split(" ", 1)[1]); spec = p(args[3]).read_text()
    package = re.search(r"^Name:\s+(\S+)", spec, re.M)[1]
    version = re.search(r"^Version:\s+(\S+)", spec, re.M)[1]
    arch = re.search(r"^BuildArch:\s+(\S+)", spec, re.M)[1]
    source = re.search(r"^Source0:\s+(\S+)", spec, re.M)[1]
    entries = spec.split("\n%files\n", 1)[1].splitlines()
    declared = []
    for entry in entries:
        if entry.startswith(("%defattr", "%dir ")) or not entry.strip():
            continue
        declared.append(entry.split(" ", 1)[-1].lstrip("/"))
    stream = io.BytesIO()
    with tarfile.open(top / "SOURCES" / source) as src, tarfile.open(fileobj=stream, mode="w:gz") as dst:
        directories = {member.name.split('/', 1)[1]: member.mode & 0o777
                       for member in src.getmembers() if member.isdir() and '/' in member.name}
        (p(os.environ['LICENSE_FIXTURE_OUTPUT']) / (package + '.fixture.directories.json')).write_text(json.dumps(directories))
        found = []
        for member in src.getmembers():
            if not member.isfile():
                continue
            relative = member.name.split("/", 1)[1]
            assert relative in declared, "RPM staged file missing from actual spec"
            data = src.extractfile(member).read()
            member.name = relative
            member.size = len(data); dst.addfile(member, io.BytesIO(data)); found.append(relative)
        assert set(found) == set(declared), "RPM spec declares an absent staged file"
    target = top / "RPMS" / arch; target.mkdir(parents=True, exist_ok=True)
    (target / (package + "-" + version + "-1." + arch + ".rpm")).write_bytes(stream.getvalue())
    (p(os.environ["LICENSE_FIXTURE_OUTPUT"]) / (package + ".fixture.spec")).write_text(spec)
elif name == "rpm2cpio":
    sys.stdout.buffer.write(p(args[0]).read_bytes())
elif name == "cpio":
    with tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read())) as tar:
        for member in tar.getmembers():
            assert member.isfile() and not p(member.name).is_absolute() and ".." not in p(member.name).parts
            file = p.cwd() / member.name; file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(tar.extractfile(member).read())
elif name == "timeout":
    import subprocess
    raise SystemExit(subprocess.run(args[1:], timeout=5, check=False).returncode)
elif name == "rpm":
    assert args[:2] == ["-qp", "--queryformat"] and len(args) == 4
    assert "FILEUSERNAME" in args[2] and "FILEGROUPNAME" in args[2]
    with tarfile.open(args[3]) as archive:
        members = archive.getmembers()
    assert members
    owner = os.environ.get("LICENSE_FIXTURE_RPM_OWNER", "root")
    sys.stdout.write((owner + ":" + owner + "\n") * len(members))
elif name == "cmake":
    raise SystemExit(0)
else:
    raise SystemExit("unreviewed fixture tool")
'''


def write(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(mode)


def fixture(directory):
    root = directory / "checkout"
    texts = {}
    for name in PACKAGERS:
        source = PACKAGER_ROOT / "scripts" / name
        texts[name] = source.read_text()
        write(root / "scripts" / name, source.read_bytes(), 0o755)
    # Closed filenames from the packagers are materialized as inert data, never
    # copied/executed runtime helper bodies or repository source trees.
    for text in texts.values():
        for name in re.findall(r'\$\{ROOT\}/([A-Za-z0-9_./-]+)', text):
            if name.endswith("/") or name in ("scripts", "packaging"):
                continue
            target = root / name
            if not target.exists():
                write(target, "# fixture data\n")
        for body in re.findall(r'^\w+=\(\n(.*?)^\)', text, re.M | re.S):
            for name in re.findall(r'^  "([A-Za-z0-9_./-]+)"$', body, re.M):
                if name.startswith("usr/"):
                    continue
                write(root / "scripts" / name, "# inert helper data\n")
    # These units are copied through ${ROOT}/packaging/systemd/${unit}; the
    # filename is supplied by the packager array, not a literal ROOT path.
    units = re.search(r'^AUTO_SYSTEMD_UNITS=\(\n(.*?)^\)',
                      texts["build-package-root.sh"], re.M | re.S)
    assert units is not None, "AUTO systemd unit input roster absent"
    for name in re.findall(r'^  "([A-Za-z0-9_.@-]+)"$', units.group(1), re.M):
        write(root / "packaging/systemd" / name, "# inert unit data\n")
    for name in LICENSES:
        write(root / name, (ROOT / name).read_bytes())
    write(root / "third_party/h2/LICENSE", (ROOT / "third_party/h2/LICENSE").read_bytes())
    for name in TUNGSTENITE_LICENSES:
        source = name.replace('third-party/', 'third_party/', 1)
        write(root / source, (ROOT / source).read_bytes())
    write(root / "scripts/verify-deb-archive-ownership.py",
          (ROOT / "scripts/verify-deb-archive-ownership.py").read_bytes(), 0o755)
    write(root / "scripts/verify-split-deb-package-set.py",
          (ROOT / "scripts/verify-split-deb-package-set.py").read_bytes(), 0o755)
    write(root / "scripts/verify-rpm-package-set.py",
          (ROOT / "scripts/verify-rpm-package-set.py").read_bytes(), 0o755)
    write(root / "Cargo.lock", b"# fixture lock: never passed to real Cargo\n")
    write(root / "packaging/research-operator-guides.txt", "private-operator-delivery.md\n")
    write(root / "docs/research/private-operator-delivery.md", "# Fixture research documentation\n")
    write(root / "scripts/lib/release-toolchain.sh", "verify_release_toolchain() { :; }\nrelease_source_timestamp() { printf fixture; }\n")
    write(root / "scripts/lib/release-abi.sh", "verify_linux_release_abi() { :; }\n")
    write(root / "scripts/lib/host-arch.sh", "host_arch() { printf 'x86_64\\n'; }\n")
    producer = "#!/bin/sh\nif [ \"${1:-}\" = research-tool-notices ]; then\n while [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --output ]; then shift; printf 'fixture notices\\n' > \"$1\"; exit 0; fi\n  shift\n done\n exit 2\nfi\nprintf '{\"fixture_only\":true}\\n'\n"
    for name in ("aegis-server", "aegis-client", "aegis-geneva-bridge", "aegis-measure", "aegis-research-measure", "aegis-transport-lab"):
        write(root / "target/release" / name, producer, 0o755)
    tools = directory / "tools"
    for name in ("cargo", "dpkg-deb", "rpmbuild", "rpm", "rpm2cpio", "cpio", "cmake", "timeout"):
        write(tools / name, "#!" + sys.executable + " -I\n" + TOOL, 0o755)
    output = directory / "output"; output.mkdir()
    scratch = directory / "scratch"; scratch.mkdir()
    # No real toolchain path or user Cargo directory is reachable by lookup.
    env = dict(os.environ, PATH=str(tools) + ":/usr/bin:/bin:/usr/sbin:/sbin",
               LICENSE_FIXTURE_ROOT=str(root), LICENSE_FIXTURE_OUTPUT=str(output),
               AEGIS_BUILD_GIT_SHA="fixture-not-release", AEGIS_BUILD_TIMESTAMP="fixture",
               COPYFILE_DISABLE="1")
    # BSD tar on a macOS verification host would otherwise add AppleDouble
    # resource-fork members absent from the selected Linux package target.
    # Do not ignore unknown archive entries or relax the RPM spec closure.
    # Existing packagers prepend HOME/.cargo/bin; the current HOME is preserved,
    # so explicit fixture shell functions prevent host-tool substitution.
    # Use a non-system variable for fixture-local temporary files.
    env["TMPDIR"] = str(scratch)
    return root, output, env


def open_payload(path, control=False):
    if path.suffix != ".deb":
        return tarfile.open(path)
    data = path.read_bytes()
    assert data.startswith(b"!<arch>\n")
    offset = 8
    wanted = "control.tar.xz" if control else "data.tar.xz"
    while offset < len(data):
        header = data[offset:offset + 60]
        name = header[:16].strip().decode().rstrip("/")
        size = int(header[48:58].strip())
        start = offset + 60
        if name == wanted:
            return tarfile.open(fileobj=io.BytesIO(data[start:start + size]), mode="r:xz")
        offset = start + size + size % 2
    raise AssertionError("fixture DEB archive absent: " + wanted)


class Packaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-project-license-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root, self.output, self.env = fixture(Path(self.temp.name))

    def run_packager(self, name, restrictive_umask=False):
        # Bash functions exported only to this fixture shield the packager's
        # existing PATH prepend without changing HOME or production source.
        tools = Path(self.temp.name) / "tools"
        definitions = []
        for tool_name in ("cargo", "dpkg-deb", "rpmbuild", "rpm", "rpm2cpio", "cpio", "cmake", "timeout"):
            definitions.append(tool_name + '() { "$LICENSE_FIXTURE_TOOLS/' + tool_name + '" "$@"; }; export -f ' + tool_name + ';')
        # BSD cp lacks GNU --preserve=mode; the fixture still copies real
        # bytes and checks resulting modes in each produced archive.
        definitions.append('cp() { if [ "$1" = "--preserve=mode" ]; then shift; /bin/cp -p "$@"; else /bin/cp "$@"; fi; }; export -f cp;')
        command = ('umask 077; ' if restrictive_umask else '') + " ".join(definitions) + ' exec /bin/bash "$1" "$2"'
        env = dict(self.env, LICENSE_FIXTURE_TOOLS=str(tools))
        return subprocess.run(["/bin/bash", "-c", command, "fixture", str(self.root / "scripts" / name), str(self.output)],
                              env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=25, check=False)

    def assert_payload(self, archive, prefix=""):
        with open_payload(archive) as tar:
            members = {m.name.lstrip("./"): m for m in tar.getmembers() if m.isfile()}
            for name in LICENSES:
                wanted = prefix + name
                self.assertIn(wanted, members, "project license absent from produced archive")
                self.assertEqual(tar.extractfile(members[wanted]).read(), (ROOT / name).read_bytes())
                self.assertEqual(members[wanted].mode & 0o777, 0o644)
            h2 = prefix + H2_LICENSE
            self.assertIn(h2, members, "vendored h2 license absent from produced archive")
            self.assertEqual(tar.extractfile(members[h2]).read(),
                             (ROOT / "third_party/h2/LICENSE").read_bytes())
            self.assertEqual(members[h2].mode & 0o777, 0o644)
            for name in TUNGSTENITE_LICENSES:
                wanted = prefix + name
                source = name.replace('third-party/', 'third_party/', 1)
                self.assertIn(wanted, members, 'vendored tungstenite license absent')
                self.assertEqual(tar.extractfile(members[wanted]).read(), (ROOT / source).read_bytes())
                self.assertEqual(members[wanted].mode & 0o777, 0o644)
            inventories = [(n, m) for n, m in members.items() if n.endswith("/fixture-inventory.json") or n == "fixture-inventory.json"]
            if inventories:
                self.assertEqual(len(inventories), 1)
                inventory_name, inventory = inventories[0]
                inventory_base = inventory_name[:-len("fixture-inventory.json")]
                data = json.load(tar.extractfile(inventory))
                for name in LICENSES:
                    relative = (prefix + name)[len(inventory_base):]
                    self.assertEqual(data["files"][relative], hashlib.sha256((ROOT / name).read_bytes()).hexdigest())
                relative = h2[len(inventory_base):]
                self.assertEqual(data["files"][relative],
                                 hashlib.sha256((ROOT / "third_party/h2/LICENSE").read_bytes()).hexdigest())
                for name in TUNGSTENITE_LICENSES:
                    relative = (prefix + name)[len(inventory_base):]
                    source = name.replace('third-party/', 'third_party/', 1)
                    self.assertEqual(data['files'][relative], hashlib.sha256((ROOT / source).read_bytes()).hexdigest())

    def test_private_release_tar_contains_exact_project_texts(self):
        result = self.run_packager(PACKAGERS[0]); self.assertEqual(result.returncode, 0, result.stderr.decode())
        archive = self.output / "aegis-0.0.1-fixture-linux-x86_64.tar.gz"
        self.assert_payload(archive, "aegis-0.0.1-fixture-linux-x86_64/")
        self.assertEqual(archive.with_suffix(archive.suffix + ".sha256").read_text().split()[0], hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_inert_client_build_places_explicit_target_and_emits_fixture_stream(self):
        tool = Path(self.temp.name) / "tools/cargo"
        target = "x86_64-unknown-linux-gnu"
        args = [str(tool), "build", "--locked", "--release", "-p", "aegis-client",
                "--features", "raw-socket,chrome-like-tls,chrome-like-quic", "--target", target,
                "--message-format=json-render-diagnostics"]
        result = subprocess.run(args, env=self.env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        selected = self.root / "target" / target / "release/aegis-client"
        legacy = self.root / "target/release/aegis-client"
        self.assertEqual(selected.read_bytes(), legacy.read_bytes())
        self.assertEqual(selected.stat().st_mode & 0o777, legacy.stat().st_mode & 0o777)
        messages = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([m["reason"] for m in messages], ["compiler-artifact", "build-finished"])
        self.assertTrue(all(m["fixture_only"] for m in messages))
        self.assertEqual(messages[0]["executable"], str(selected))
        self.assertEqual(messages[0]["target"], {"name":"aegis-client", "kind":["bin"]})
        self.assertTrue(messages[1]["success"])

    def test_inert_client_build_refuses_unselected_target(self):
        tool = Path(self.temp.name) / "tools/cargo"
        result = subprocess.run([str(tool), "build", "--locked", "--release", "-p", "aegis-client",
                                 "--target", "aarch64-unknown-linux-gnu"], env=self.env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=5, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "target/aarch64-unknown-linux-gnu/release/aegis-client").exists())

    def test_repeated_release_fixture_preserves_unique_private_compiler_logs(self):
        for expected_count in (1, 2):
            result = self.run_packager(PACKAGERS[0])
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            logs = list(self.output.glob("client-build-x86_64.jsonl.*"))
            self.assertEqual(len(logs), expected_count)
            for log in logs:
                self.assertTrue(log.is_file())
                self.assertEqual(log.stat().st_mode & 0o777, 0o600)
                messages = [json.loads(line) for line in log.read_bytes().splitlines()]
                self.assertEqual([m["reason"] for m in messages], ["compiler-artifact", "build-finished"])
                self.assertTrue(all(m["fixture_only"] for m in messages))
        self.assertEqual(len({log.name for log in logs}), 2)
        archive = self.output / "aegis-0.0.1-fixture-linux-x86_64.tar.gz"
        self.assert_payload(archive, "aegis-0.0.1-fixture-linux-x86_64/")

    def test_package_root_tar_contains_exact_project_texts(self):
        result = self.run_packager(PACKAGERS[1]); self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assert_payload(self.output / "aegis-package-root-0.0.1-fixture-linux-x86_64.tar.gz",
                            "aegis-package-root-0.0.1-fixture-linux-x86_64/rootfs/usr/share/doc/aegis/")

    def check_role_packages(self, suffix):
        manifest_name = ("split-deb-packages.manifest.json" if suffix == ".deb"
                         else "rpm-packages.manifest.json")
        manifest = json.loads((self.output / manifest_name).read_text())
        if suffix == ".deb":
            self.assertEqual(manifest["version"], "0.0.1-fixture")
            self.assertEqual(manifest["deb_arch"], "amd64")
            self.assertEqual(set(manifest["packages"]), {"aegis-server", "aegis-client"})
        else:
            self.assertEqual(manifest["version"], "0.0.1-fixture")
            self.assertEqual(manifest["arch"], "x86_64")
            self.assertEqual(set(manifest["packages"]), {"aegis-server", "aegis-client"})
        role_license_paths = []
        for role in ("aegis-server", "aegis-client"):
            files = list(self.output.glob(role + "*" + suffix)); self.assertEqual(len(files), 1)
            prefix = "usr/share/doc/" + role + "/"
            archive = files[0]; self.assert_payload(archive, prefix)
            with open_payload(archive) as tar:
                members = {m.name.lstrip("./") for m in tar.getmembers() if m.isfile()}
                license_paths = {prefix + name for name in LICENSES}
                license_paths.add(prefix + H2_LICENSE)
                license_paths.update(prefix + name for name in TUNGSTENITE_LICENSES)
                self.assertTrue(license_paths <= members)
                self.assertFalse({"usr/share/doc/aegis/" + name for name in LICENSES} & members)
                role_license_paths.append(license_paths)
            if suffix == ".deb":
                self.assertEqual(manifest["packages"][role]["deb_file"], archive.name)
                self.assertEqual((self.output / (archive.name + ".sha256")).read_text(),
                                 hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n")
            else:
                self.assertEqual(manifest["packages"][role]["rpm_file"], archive.name)
                self.assertEqual((self.output / (archive.name + ".sha256")).read_text(),
                                 hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n")
            if suffix == ".deb":
                with open_payload(archive, control=True) as tar:
                    sums = tar.extractfile("./md5sums").read().decode()
                    for name in LICENSES:
                        expected = hashlib.md5((ROOT / name).read_bytes(), usedforsecurity=False).hexdigest()
                        self.assertIn(expected + "  " + prefix + name, sums)
                    h2_md5 = hashlib.md5((ROOT / "third_party/h2/LICENSE").read_bytes(),
                                         usedforsecurity=False).hexdigest()
                    self.assertIn(h2_md5 + "  " + prefix + H2_LICENSE, sums)
                    for name in TUNGSTENITE_LICENSES:
                        source = name.replace('third-party/', 'third_party/', 1)
                        digest = hashlib.md5((ROOT / source).read_bytes(), usedforsecurity=False).hexdigest()
                        self.assertIn(digest + '  ' + prefix + name, sums)
            else:
                spec = (self.output / (role + ".fixture.spec")).read_text()
                for name in LICENSES:
                    self.assertEqual(spec.count("%license /" + prefix + name + "\n"), 1)
                self.assertEqual(spec.count("%license /" + prefix + H2_LICENSE + "\n"), 1)
                for name in TUNGSTENITE_LICENSES:
                    self.assertEqual(spec.count('%license /' + prefix + name + '\n'), 1)
        self.assertFalse(role_license_paths[0] & role_license_paths[1], "new license files must not collide when roles are coinstalled")

    def test_both_split_deb_payloads_contain_exact_project_texts(self):
        result = self.run_packager(PACKAGERS[2]); self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.check_role_packages(".deb")

    def test_split_deb_consumer_refuses_incomplete_or_changed_set(self):
        result = self.run_packager(PACKAGERS[2]); self.assertEqual(result.returncode, 0, result.stderr.decode())
        verifier = ROOT / "scripts/verify-split-deb-package-set.py"
        def check(directory, expected, release=False, source_sha="fixture-source", selected=None):
            args = [sys.executable, "-I", "-B", str(verifier), str(directory), "--arch", "amd64"]
            if release:
                args += ["--release-manifest", str(directory / "release.manifest.json"),
                         "--source-sha", source_sha]
            if selected is not None:
                args += ["--server-deb", str(selected[0]), "--client-deb", str(selected[1])]
            actual = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(actual.returncode, expected, actual.stderr)
        check(self.output, 0)
        roles = ("server", "client")
        version = "0.0.1-fixture"
        split = {}
        for role in roles:
            name = f"aegis-{role}_{version}_amd64.deb"
            split[role] = {"path": name, "sha256_path": name + ".sha256",
                           "sha256": hashlib.sha256((self.output / name).read_bytes()).hexdigest()}
        release = {"schema": "aegis_linux_release_manifest_v1", "version": version,
                   "arch": "x86_64", "git_sha": "fixture-source",
                   "artifacts": {"deb": {"status": "ready", "split": split,
                                         "manifest_path": "split-deb-packages.manifest.json"}}}
        (self.output / "release.manifest.json").write_text(json.dumps(release))
        check(self.output, 0, release=True)
        check(self.output, 1, release=True, source_sha="wrong-source")
        check(self.output, 1, selected=(self.output / f"aegis-server_{version}_amd64.deb",
                                        self.output / f"aegis-client_{version}_arm64.deb"))
        for change in ("missing-marker", "changed-sidecar", "changed-deb", "extra-deb",
                       "extra-sidecar", "changed-release-sha"):
            variant = Path(self.temp.name) / change
            shutil.copytree(self.output, variant)
            client = variant / f"aegis-client_{version}_amd64.deb"
            if change == "missing-marker":
                (variant / "split-deb-packages.manifest.json").unlink()
            elif change == "changed-sidecar":
                (variant / (client.name + ".sha256")).write_text("0" * 64 + "  " + client.name + "\n")
            elif change == "changed-deb":
                with client.open("ab") as stream: stream.write(b"tamper")
            elif change == "extra-deb":
                (variant / f"relay-a_{version}_amd64.deb").write_bytes(b"extra")
            elif change == "extra-sidecar":
                (variant / f"relay-a_{version}_amd64.deb.sha256").write_text("extra\n")
            else:
                modified = json.loads((variant / "release.manifest.json").read_text())
                modified["artifacts"]["deb"]["split"]["client"]["sha256"] = "0" * 64
                (variant / "release.manifest.json").write_text(json.dumps(modified))
            check(variant, 1, release=True)

    def test_both_rpm_payloads_and_closed_specs_contain_exact_project_texts(self):
        result = self.run_packager(PACKAGERS[3], restrictive_umask=True); self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.check_role_packages(".rpm")

    def test_rpm_private_data_directories_have_explicit_ownership(self):
        result = self.run_packager(PACKAGERS[3], restrictive_umask=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        for role in ('aegis-server', 'aegis-client'):
            spec = (self.output / (role + '.fixture.spec')).read_text()
            declared = [line[5:] for line in spec.splitlines() if line.startswith('%dir ')]
            self.assertEqual(len(declared), len(set(declared)), 'duplicate RPM directory ownership')
            with open_payload(next(self.output.glob(role + '*.rpm'))) as tar:
                required = set()
                for entry in tar.getmembers():
                    for prefix in ('usr/share/doc/' + role, 'usr/share/doc/aegis', 'usr/share/aegis'):
                        if entry.name.startswith(prefix + '/'):
                            required.update('/' + str(parent) for parent in Path(entry.name).parents
                                            if str(parent) == prefix or str(parent).startswith(prefix + '/'))
            self.assertTrue(required)
            self.assertTrue(required <= set(declared), 'unowned RPM private directories: ' + str(required - set(declared)))
            modes = json.loads((self.output / (role + '.fixture.directories.json')).read_text())
            for directory in required:
                self.assertEqual(modes[directory.lstrip('/')], 0o755, 'public RPM directory mode depends on umask')

    def test_erase_validation_refuses_orphan_role_doc_directories(self):
        source = (ROOT / 'scripts/validate-rpm-package-host.sh').read_text()
        body = source.split('verify_erase_state() {\n', 1)[1].split('\n}\n', 1)[0]
        script = ('verify_erase_state() {\n' + body + '\n}\n'
                  'fail_helper() { printf "%s\\n" "$1" >&2; exit 19; }\nverify_erase_state\n')
        root = Path(self.temp.name) / 'erase-root'; root.mkdir()
        env = dict(self.env, VALIDATION_ROOT=str(root), RPM_QUERY_BIN='/usr/bin/false')
        self.assertEqual(subprocess.run(['/bin/bash', '-c', script], env=env, capture_output=True).returncode, 0)
        for role in ('aegis-server', 'aegis-client'):
            orphan = root / 'usr/share/doc' / role
            orphan.mkdir(parents=True)
            result = subprocess.run(['/bin/bash', '-c', script], env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0, 'erase validator accepted unowned empty doc directory')
            orphan.rmdir()

    def test_rpm_nonroot_owner_is_refused_before_publication(self):
        self.env["LICENSE_FIXTURE_RPM_OWNER"] = "nobody"
        result = self.run_packager(PACKAGERS[3])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"final RPM contains a non-root owner or group", result.stderr)
        self.assertNotIn(b"unbound variable", result.stderr)
        self.assertFalse(list(self.output.glob("*.rpm")))
        self.assertFalse((self.output / "rpm-packages.manifest.json").exists())

    def test_missing_project_text_refuses_private_release(self):
        for name in LICENSES:
            with self.subTest(name=name):
                (self.root / name).unlink()
                result = self.run_packager(PACKAGERS[0])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(str(self.root / name), result.stderr.decode(), "failure must identify the omitted project text, not an unrelated launcher error")
                self.assertFalse((self.output / "aegis-0.0.1-fixture-linux-x86_64.tar.gz").exists())
                write(self.root / name, (ROOT / name).read_bytes())

    def test_missing_project_text_refuses_package_root(self):
        for name in LICENSES:
            with self.subTest(name=name):
                (self.root / name).unlink()
                result = self.run_packager(PACKAGERS[1])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(str(self.root / name), result.stderr.decode(), "failure must identify the omitted project text, not an unrelated launcher error")
                self.assertFalse((self.output / "aegis-package-root-0.0.1-fixture-linux-x86_64.tar.gz").exists())
                write(self.root / name, (ROOT / name).read_bytes())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packager-source-root", type=Path, default=ROOT,
                        help="Frozen baseline/candidate checkout containing the four actual scripts")
    args, rest = parser.parse_known_args()
    PACKAGER_ROOT = args.packager_source_root.resolve()
    unittest.main(argv=[sys.argv[0], *rest])
