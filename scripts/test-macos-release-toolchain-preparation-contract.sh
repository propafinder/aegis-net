#!/usr/bin/env bash
# Execute the real builder with isolated fake toolchains; no Rust build/network.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "${ROOT}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

source = Path(sys.argv[1])
builder = source / "scripts/build-macos-client-tarball.sh"
pin_file = source / "rust-toolchain.toml"
pin = next(line.split('"')[1] for line in pin_file.read_text().splitlines()
           if line.startswith('channel = "'))
receipt_dir = os.environ.get("AEGIS_MACOS_TOOLCHAIN_CONTRACT_ARTIFACT_DIR")
if receipt_dir:
    receipt_dir = Path(receipt_dir)
    receipt_dir.mkdir(parents=True, exist_ok=False)

# Proxies pass --version but fail compiler work, reproducing the distinction
# between successful preflight and concurrent lazy component installation.
fake_tool = r'''
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
base = Path(os.environ["FIXTURE_BASE"])
pin = os.environ["FIXTURE_PIN"]
event = json.dumps({"tool": tool, "path": sys.argv[0], "args": args}) + "\n"
fd = os.open(base / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
os.write(fd, event.encode())
os.close(fd)

def fail(message, code=83):
    print("fixture: " + message, file=sys.stderr)
    raise SystemExit(code)

if tool == "rustup":
    if args[:3] == ["which", "--toolchain", pin] and len(args) == 4:
        selected = args[3]
        if selected == os.environ.get("FIXTURE_FAIL_WHICH"):
            fail("pinned binary resolution failed", 42)
        print(base / "toolchain/bin" / selected)
    elif args == ["target", "add", "--toolchain", pin,
                  os.environ["FIXTURE_TARGET"]]:
        if os.environ.get("FIXTURE_FAIL_TARGET") == "1":
            fail("pinned target preparation failed", 43)
        (base / "prepared").write_text(pin)
    else:
        fail("unexpected or unpinned rustup operation: " + repr(args))
elif tool in ("rustc", "rustdoc"):
    if args == ["--version"]:
        version = os.environ.get("FIXTURE_VERSION", pin)
        print(tool + " " + version + " (fixture)")
    elif "toolchain/bin" in sys.argv[0] or os.environ["FIXTURE_MODE"] == "plain":
        if "-o" in args:
            output = Path(args[args.index("-o") + 1])
            output.write_text("#!/bin/sh\nexit 0\n")
            output.chmod(0o755)
    else:
        fail("rustup proxy attempted lazy rust-src preparation during compilation")
elif tool == "cargo":
    if "--locked" not in args:
        fail("Cargo invocation omitted --locked")
    if os.environ["FIXTURE_MODE"] == "rustup":
        if not (base / "prepared").is_file():
            fail("Cargo started before target preparation")
        if os.environ.get("RUSTUP_TOOLCHAIN") != pin:
            fail("child toolchain environment does not use repository pin")
        compiler = os.environ.get("RUSTC", "rustc")
        workers = [subprocess.Popen([compiler, "--crate-name", "fixture_worker"],
                                   cwd=base / "crate-override") for _ in range(2)]
        worker_codes = [process.wait() for process in workers]
        if any(code != 0 for code in worker_codes):
            fail("parallel compiler worker failed")
        if compiler != str(base / "toolchain/bin/rustc"):
            fail("Cargo compiler is not the resolved pinned binary")
        if os.environ.get("RUSTDOC") != str(base / "toolchain/bin/rustdoc"):
            fail("Cargo rustdoc is not the resolved pinned binary")
        if subprocess.run(["rustc", "--crate-name", "fixture_nested_worker"],
                          cwd=base / "crate-override").returncode:
            fail("nested PATH compiler still uses rustup proxy")
    if args[0] == "build":
        expected = ["build", "--locked", "--release", "-p", "aegis-client",
                    "--features", "chrome-like-tls,chrome-like-quic", "--target",
                    os.environ["FIXTURE_TARGET"]]
        if args != expected:
            fail("client build flags changed: " + repr(args))
        output = Path.cwd() / "target" / os.environ["FIXTURE_TARGET"] / "release/aegis-client"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("#!/bin/sh\nexit 0\n")
        output.chmod(0o755)
    elif "build-macos-client-tarball-manifest" in args:
        directory = Path(args[args.index("--bundle-dir") + 1])
        (directory / "manifest.json").write_text('{"fixture":true}\n')
    elif "write-archive-sha256" in args:
        archive = Path(args[args.index("--archive") + 1])
        checksum = Path(args[args.index("--sha256-path") + 1])
        checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "\n")
    else:
        fail("unexpected Cargo operation: " + repr(args))
elif tool != "cmake":
    fail("unexpected fixture tool")
'''

# GNU tar starts gzip as a PATH child; bsdtar on macOS can compress internally.
# Exercise that dependency with real tar + gzip even when the host uses bsdtar.
external_gzip_tar = r'''
import os
from pathlib import Path
import subprocess
import sys
args = sys.argv[1:]
assert len(args) == 5 and args[0] == "-czf" and args[2] == "-C", args
with Path(args[1]).open("wb") as archive:
    tar = subprocess.Popen([os.environ["FIXTURE_REAL_TAR"], "-cf", "-", *args[2:]],
                           stdout=subprocess.PIPE)
    assert tar.stdout is not None
    try:
        compressor = subprocess.run(["gzip", "-n", "-c"], stdin=tar.stdout, stdout=archive)
    finally:
        tar.stdout.close()
        tar_status = tar.wait()
    if tar_status or compressor.returncode:
        raise SystemExit(tar_status or compressor.returncode)
Path(os.environ["FIXTURE_BASE"], "external-gzip-child").write_text("executed\n")
'''

def run_case(parent, name, *, mode="rustup", changes=None, target="aarch64-apple-darwin",
             succeeds=True, nonexec=None, external_gzip=False):
    base = parent / name
    project = base / "project"
    for directory in (project / "scripts/lib", project / "aegis-client",
                      project / "packaging/launchd", base / "cargo/bin",
                      base / "toolchain/bin", base / "system/bin", base / "crate-override"):
        directory.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(builder, project / "scripts/build-macos-client-tarball.sh")
    shutil.copyfile(source / "scripts/lib/release-toolchain.sh", project / "scripts/lib/release-toolchain.sh")
    shutil.copyfile(pin_file, project / "rust-toolchain.toml")
    # The real builder requires the actual project terms, not fabricated stubs.
    for license_name in ("LICENSE-MIT", "LICENSE-APACHE", "NOTICE"):
        shutil.copyfile(source / license_name, project / license_name)
    (project / "aegis-client/Cargo.toml").write_text('[package]\nversion = "0.0.0"\n')
    (project / "config.example.toml").write_text('# fixture\n')
    for template in ("dev.aegis.client.plist", "dev.aegis.client.daemon.plist"):
        (project / "packaging/launchd" / template).write_text('<plist/>\n')
    (base / "crate-override/rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "fixture-other-toolchain"\ncomponents = ["rust-src"]\n')
    for tool in ("cargo", "rustc", "rustdoc", "cmake"):
        for directory in (base / "cargo/bin", base / "toolchain/bin"):
            path = directory / tool
            path.write_text("#!" + sys.executable + "\n" + fake_tool)
            path.chmod(0o755)
    if mode == "rustup":
        path = base / "cargo/bin/rustup"
        path.write_text("#!" + sys.executable + "\n" + fake_tool)
        path.chmod(0o755)
    if nonexec:
        (base / "toolchain/bin" / nonexec).chmod(0o644)
    for command in ("bash", "sed", "awk", "dirname", "mkdir", "rm", "cp", "chmod", "cat", "tar", "gzip", "shasum", "mv"):
        resolved = shutil.which(command)
        assert resolved, "missing test dependency: " + command
        (base / "system/bin" / command).symlink_to(resolved)
    if external_gzip:
        path = base / "system/bin/tar"
        path.unlink()
        path.write_text("#!" + sys.executable + "\n" + external_gzip_tar)
        path.chmod(0o755)
    env = os.environ.copy()
    env.update({"PATH": str(base / "system/bin"), "CARGO_HOME": str(base / "cargo"),
                "FIXTURE_BASE": str(base), "FIXTURE_PIN": pin, "FIXTURE_TARGET": target,
                "FIXTURE_MODE": mode, "AEGIS_BUILD_GIT_SHA": "fixture-source",
                "FIXTURE_REAL_TAR": shutil.which("tar"),
                "AEGIS_BUILD_TIMESTAMP": "2000-01-01T00:00:00Z",
                "RUSTUP_TOOLCHAIN": "fixture-other-toolchain",
                "RUSTC": str(base / "cargo/bin/rustc"),
                "RUSTDOC": str(base / "cargo/bin/rustdoc")})
    for key in ("FIXTURE_FAIL_WHICH", "FIXTURE_FAIL_TARGET", "FIXTURE_VERSION",
                "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_TARGET_DIR"):
        env.pop(key, None)
    env.update(changes or {})
    result = subprocess.run([str(base / "system/bin/bash"),
                             str(project / "scripts/build-macos-client-tarball.sh"),
                             str(base / "output"), target], env=env, cwd=project,
                            capture_output=True, text=True, timeout=30)
    events_path = base / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text().splitlines()] if events_path.exists() else []
    cargo_events = [event for event in events if event["tool"] == "cargo"]
    if receipt_dir:
        with (receipt_dir / (name + ".json")).open("x") as receipt:
            json.dump({"name": name, "expected_success": succeeds,
                       "exit": result.returncode, "stdout": result.stdout,
                       "stderr": result.stderr, "events": events}, receipt, indent=2)
            receipt.write("\n")
    if succeeds:
        assert result.returncode == 0, (name, result.returncode, result.stdout, result.stderr)
        assert len(cargo_events) == 3, (name, cargo_events)
        assert all("--locked" in event["args"] for event in cargo_events)
        if mode == "rustup":
            assert all(event["path"] == str(base / "toolchain/bin/cargo") for event in cargo_events)
            target_events = [event for event in events if event["tool"] == "rustup" and event["args"][0] == "target"]
            assert len(target_events) == 1
            assert events.index(target_events[0]) < events.index(cargo_events[0])
            assert not any(event["tool"] in ("rustc", "rustdoc") and
                           event["path"] == str(base / "cargo/bin" / event["tool"])
                           for event in events), (name, events)
        archives = list((base / "output").glob("*.tar.gz"))
        assert len(archives) == 1
        assert archives[0].with_name(archives[0].name + ".sha256").read_text().strip() == hashlib.sha256(archives[0].read_bytes()).hexdigest()
        with tarfile.open(archives[0], "r:gz") as archive:
            assert any(member.name.endswith("/bin/aegis-client") and member.isfile()
                       for member in archive.getmembers()), (name, "missing packaged client")
            for license_name in ("LICENSE-MIT", "LICENSE-APACHE", "NOTICE"):
                members = [member for member in archive.getmembers()
                           if member.name.endswith("/" + license_name)]
                assert len(members) == 1 and members[0].isfile(), (name, license_name)
                with archive.extractfile(members[0]) as license_stream:
                    assert license_stream.read() == (source / license_name).read_bytes(), (name, license_name, "project terms changed")
            installer_members = [member for member in archive.getmembers()
                                 if member.name.endswith("/install-macos-client.sh")]
            assert len(installer_members) == 1 and installer_members[0].isfile(), (name, "missing rendered installer")
            with archive.extractfile(installer_members[0]) as installer_stream:
                installer = installer_stream.read()
            placeholders = {
                "LICENSE-MIT": "__AEGIS_PROJECT_LICENSE_MIT_SHA256__",
                "LICENSE-APACHE": "__AEGIS_PROJECT_LICENSE_APACHE_SHA256__",
                "NOTICE": "__AEGIS_PROJECT_NOTICE_SHA256__",
            }
            for license_name, placeholder in placeholders.items():
                digest = hashlib.sha256((source / license_name).read_bytes()).hexdigest()
                expected_case = (license_name + ") printf '%s\\n' '" + digest + "' ;;").encode()
                assert expected_case in installer, (name, license_name, "installer license hash binding changed")
                assert placeholder.encode() not in installer, (name, license_name, "unrendered license placeholder")
        if external_gzip:
            assert (base / "external-gzip-child").read_text() == "executed\n"
    else:
        assert result.returncode != 0, (name, "invalid preparation accepted")
        assert not cargo_events, (name, "Cargo started after rejected preparation", cargo_events)
        assert not (base / "output").exists(), (name, "output changed before preparation succeeded")
    print(name + ": ok (builder exit " + str(result.returncode) + ")")

with tempfile.TemporaryDirectory(prefix="aegis-macos-toolchain-") as temporary:
    parent = Path(temporary)
    run_case(parent, "pinned-parallel-workers", external_gzip=True)
    run_case(parent, "pinned-cross-target", target="x86_64-apple-darwin")
    run_case(parent, "plain-pinned-toolchain", mode="plain")
    run_case(parent, "target-preparation-failure", changes={"FIXTURE_FAIL_TARGET": "1"}, succeeds=False)
    for tool in ("cargo", "rustc", "rustdoc"):
        run_case(parent, "resolve-failure-" + tool, changes={"FIXTURE_FAIL_WHICH": tool}, succeeds=False)
        run_case(parent, "nonexecutable-" + tool, nonexec=tool, succeeds=False)
    run_case(parent, "wrong-pinned-compiler", changes={"FIXTURE_VERSION": "0.0.0"}, succeeds=False)
    run_case(parent, "wrong-plain-compiler", mode="plain", changes={"FIXTURE_VERSION": "0.0.0"}, succeeds=False)
    run_case(parent, "unsupported-target", target="fixture-unsupported-target", succeeds=False)
print("PASS: macOS release toolchain preparation (3 positive, 10 negative; fake tools only)")
PY
