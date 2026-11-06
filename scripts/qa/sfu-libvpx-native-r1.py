#!/usr/bin/env python3
"""Build the optional SFU codec from the exact, already obtained WebM Git tree.

This is a native execution recipe, not an installed/product acceptance runner.
It never downloads source, changes a system prefix, or retains binaries in the
receipt. The caller owns a unique disposable execution directory.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import time


TAG = "v1.17.0"
TAG_OBJECT = "82615ff0733cd4063838c352bc2e2ab225f37ade"
COMMIT = "6df3ec34557879fff673706f4a1d9fbd0f3a6f0e"
TREE = "f83d33a1ba18b3a203e43596b5223042b62417a3"
VERSION = "1.17.0"
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MEMBER = 16 * 1024 * 1024
MAX_MEMBERS = 20000
REQUIRED_LINK_SYMBOLS = {
    "vpx_codec_vp8_cx", "vpx_codec_vp8_dx",
    # vpx-rs 0.2.1 references both codec dispatch arms even when the product
    # selects VP8. A VP8-only archive passes pkg-config but cannot link Rust.
    "vpx_codec_vp9_cx", "vpx_codec_vp9_dx",
}
DARWIN_TARGET = "arm64-darwin23-gcc"
MACOS_MIN = "14.4"


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def git(repo, *args):
    done = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, timeout=30, check=False
    )
    if done.returncode or len(done.stdout) > 128:
        raise RuntimeError("source_git_refusal")
    return done.stdout.decode("ascii", "strict").strip()


def darwin_archive_deployment(archive):
    """Refuse if any archived Mach-O object needs more than macOS 14.4."""
    def read(*argv):
        done = subprocess.run(argv, capture_output=True, timeout=30, check=False)
        if done.returncode or len(done.stdout) > 8 * 1024 * 1024:
            raise RuntimeError("native_macho_inspection_refusal")
        return done.stdout.decode("utf-8", "strict")

    members = read("ar", "-t", str(archive)).splitlines()
    if (not 100 <= len(members) <= 1000 or
            members[0] not in ("__.SYMDEF", "__.SYMDEF SORTED") or
            len(members) != len(set(members)) or
            any(not name.endswith(".o") for name in members[1:])):
        raise RuntimeError("native_archive_roster_refusal")
    info = read("lipo", "-info", str(archive)).strip()
    if not info.endswith("architecture: arm64"):
        raise RuntimeError("native_archive_arch_refusal")
    header = re.compile(r"(?m)^" + re.escape(str(archive)) + r"\(([^)]+)\):\n")
    headers = header.split(read("otool", "-hv", str(archive)))
    loads = header.split(read("otool", "-l", str(archive)))
    if len(headers) != 1 + 2 * (len(members) - 1) or len(loads) != len(headers):
        raise RuntimeError("native_macho_roster_refusal")
    expected = set(members[1:])
    observed = set()
    versions = []
    for name, head, load_name, commands in zip(
            headers[1::2], headers[2::2], loads[1::2], loads[2::2]):
        if name != load_name or name not in expected or name in observed:
            raise RuntimeError("native_macho_roster_refusal")
        observed.add(name)
        lines = head.splitlines()
        if (len(lines) < 3 or lines[0] != "Mach header" or
                lines[2].split()[:5] != ["MH_MAGIC_64", "ARM64", "ALL", "0x00", "OBJECT"]):
            raise RuntimeError("native_macho_arch_refusal")
        found = re.findall(
            r"cmd LC_BUILD_VERSION\s+cmdsize \d+\s+platform (\d+)\s+minos ([0-9.]+)",
            commands)
        if len(found) != 1 or found[0][0] != "1":
            raise RuntimeError("native_macho_build_version_refusal")
        try:
            pieces = [int(piece) for piece in found[0][1].split(".")]
        except ValueError as exc:
            raise RuntimeError("native_macho_build_version_refusal") from exc
        if len(pieces) not in (2, 3):
            raise RuntimeError("native_macho_build_version_refusal")
        version = tuple((pieces + [0])[:3])
        if version > (14, 4, 0):
            raise RuntimeError("native_macho_minimum_too_new")
        versions.append(found[0][1])
    if observed != expected:
        raise RuntimeError("native_macho_roster_refusal")
    roster = "\n".join(members).encode() + b"\n"
    return {"target": DARWIN_TARGET, "macos_deployment_target": MACOS_MIN,
            "architecture": "arm64", "archive_members": len(members),
            "macho_objects": len(versions),
            "member_roster_sha256": hashlib.sha256(roster).hexdigest(),
            "object_minos": sorted(set(versions))}


def source_archive(repo, output):
    if git(repo, "rev-parse", "refs/tags/" + TAG) != TAG_OBJECT:
        raise RuntimeError("source_tag_refusal")
    if git(repo, "rev-parse", "refs/tags/" + TAG + "^{}") != COMMIT:
        raise RuntimeError("source_commit_refusal")
    if git(repo, "rev-parse", COMMIT + "^{tree}") != TREE:
        raise RuntimeError("source_tree_refusal")
    with output.open("xb") as stream:
        done = subprocess.run(
            ["git", "-C", str(repo), "archive", "--format=tar", COMMIT],
            stdout=stream, stderr=subprocess.PIPE, timeout=120, check=False,
        )
    if done.returncode or output.stat().st_size > MAX_ARCHIVE:
        raise RuntimeError("source_archive_refusal")


def unpack(source, destination):
    destination.mkdir(mode=0o700)
    with tarfile.open(source, "r:") as archive:
        members = archive.getmembers()
        if len(members) > MAX_MEMBERS:
            raise RuntimeError("source_members_refusal")
        for member in members:
            parts = Path(member.name).parts
            if (not parts or any(part in ("", ".", "..") for part in parts)
                    or Path(member.name).is_absolute() or member.size > MAX_MEMBER
                    or not (member.isfile() or member.isdir() or member.issym()
                            or member.islnk())):
                raise RuntimeError("source_member_refusal")
        archive.extractall(destination, members=members, filter="data")


def unreaped_exit(pid):
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def live_group_members(pgid):
    result = subprocess.run(["ps", "-axo", "pid=,pgid=,stat="],
                            capture_output=True, timeout=5, check=True)
    members = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if (len(fields) == 3 and int(fields[1]) == pgid and
                int(fields[0]) != pgid and not fields[2].startswith(b"Z")):
            members.add(int(fields[0]))
    return members


def close_group(child):
    # Keep the leader unreaped until its session's descendants have left.
    # Reaping first would permit PID/PGID reuse before a cleanup signal.
    if unreaped_exit(child.pid) and not live_group_members(child.pid):
        return child.wait(timeout=2)
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if unreaped_exit(child.pid) and not live_group_members(child.pid):
                code = child.wait(timeout=2)
                return code
            time.sleep(0.1)
    raise RuntimeError("native_group_cleanup_ambiguous")


def run(label, argv, cwd, env, logs, deadline, execution, floor):
    out = logs / (label + ".stdout")
    err = logs / (label + ".stderr")
    with out.open("xb") as stdout, err.open("xb") as stderr:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                 start_new_session=True)
        end = time.monotonic() + deadline
        try:
            while True:
                if shutil.disk_usage(execution).free < floor:
                    raise RuntimeError("data_floor_refusal")
                if out.stat().st_size > 64 * 1024**2 or err.stat().st_size > 64 * 1024**2:
                    raise RuntimeError("native_log_cap_refusal")
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(label + "_timeout")
                if unreaped_exit(child.pid):
                    if live_group_members(child.pid):
                        raise RuntimeError(label + "_descendants_after_leader")
                    break
                time.sleep(min(0.5, remaining))
        finally:
            code = close_group(child)
    result = {"exit_code": code, "group_gone": True,
              "stdout_sha256": sha(out), "stderr_sha256": sha(err)}
    if code:
        raise RuntimeError(label + "_failed")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", required=True, type=Path)
    parser.add_argument("--execution-dir", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--ci-runner", action="store_true",
                        help="Use the disposable GitHub runner's bounded disk floor")
    args = parser.parse_args()
    repo = args.source_repo.resolve(strict=True)
    root = args.execution_dir.absolute()
    receipt = args.receipt.absolute()
    if receipt.is_relative_to(root) or root.is_relative_to(repo):
        parser.error("receipt and execution must be outside source tree")
    if root.exists() or receipt.exists():
        parser.error("execution and receipt paths must be unique")
    if any((Path.home() / ".aegis-local/locks").glob("timing-*")):
        parser.error("timing lock is active")
    if args.ci_runner:
        if (os.environ.get("GITHUB_ACTIONS") != "true" or
                os.environ.get("RUNNER_TEMP") != str(root.parent) or
                sys.platform not in ("linux", "darwin")):
            parser.error("CI runner identity required")
    entry_floor = (8 if args.ci_runner else 35) * 1024**3
    run_floor = (6 if args.ci_runner else 35 if sys.platform == "darwin" else 30) * 1024**3
    if shutil.disk_usage(root.parent).free < entry_floor:
        parser.error("native build disk floor refusal")
    root.mkdir(mode=0o700, parents=False)
    logs = root / "logs"
    logs.mkdir(mode=0o700)
    report = {"schema": "aegis_sfu_libvpx_native_recipe_r1", "tag": TAG,
              "tag_object": TAG_OBJECT, "source_commit": COMMIT, "source_tree": TREE,
              "version": VERSION, "platform": sys.platform, "native_pass": False,
              "started_unix": int(time.time()), "steps": {}}
    lock = Path.home() / ".aegis-local/locks/timing-peer"
    lock_body = None
    if sys.platform == "darwin" and not args.ci_runner:
        lock_body = (f"{int(time.time())} pid={os.getpid()} "
                     f"token={secrets.token_hex(16)} purpose=libvpx-darwin14.4-native-r4\n").encode()
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, lock_body)
            os.fsync(fd)
        finally:
            os.close(fd)
    try:
        if sys.platform == "darwin":
            script = Path(__file__).resolve(strict=True)
            operator = script.parents[2]
            operator_head = git(operator, "rev-parse", "HEAD")
            committed = subprocess.run(
                ["git", "-C", str(operator), "show",
                 operator_head + ":scripts/qa/sfu-libvpx-native-r1.py"],
                capture_output=True, timeout=30, check=False)
            if committed.returncode or committed.stdout != script.read_bytes():
                raise RuntimeError("native_recipe_source_refusal")
            report["operator_source_commit"] = operator_head
            report["recipe_sha256"] = sha(script)
        archive = root / "source.tar"
        source_archive(repo, archive)
        report["source_archive_sha256"] = sha(archive)
        source = root / "source"
        unpack(archive, source)
        prefix = root / "prefix"
        build = root / "build"
        build.mkdir(mode=0o700)
        prefix.mkdir(mode=0o700)
        env = dict(os.environ)
        configure = [str(source / "configure"), "--prefix=" + str(prefix),
                     "--libdir=" + str(prefix / "lib"), "--disable-examples",
                     "--disable-tools", "--disable-docs", "--disable-unit-tests",
                     "--disable-shared", "--enable-static", "--enable-vp8",
                     "--enable-vp9"]
        if sys.platform == "darwin":
            env["MACOSX_DEPLOYMENT_TARGET"] = MACOS_MIN
            configure.append("--target=" + DARWIN_TARGET)
            report["requested_deployment"] = {
                "target": DARWIN_TARGET, "macos_deployment_target": MACOS_MIN}
        report["steps"]["configure"] = run(
            "configure", configure, build, env, logs, 180, root, run_floor)
        report["steps"]["make"] = run(
            "make", ["nice", "-n", "10", "make", "-j2"], build, env, logs, 3600, root,
            run_floor)
        report["steps"]["install"] = run(
            "install", ["make", "install"], build, env, logs, 300, root, run_floor)
        pkg_env = dict(env)
        pkg_env["PKG_CONFIG_LIBDIR"] = str(prefix / "lib/pkgconfig")
        pkg_env.pop("PKG_CONFIG_PATH", None)
        with (logs / "pkg-config.stdout").open("xb") as stdout:
            done = subprocess.run(["pkg-config", "--modversion", "vpx"],
                                  env=pkg_env, stdout=stdout,
                                  stderr=subprocess.PIPE, timeout=10, check=False)
        if done.returncode or (logs / "pkg-config.stdout").read_bytes() != b"1.17.0\n":
            raise RuntimeError("native_version_refusal")
        assets = [prefix / "lib/libvpx.a", prefix / "lib/pkgconfig/vpx.pc",
                  prefix / "include/vpx/vpx_codec.h", source / "LICENSE"]
        if any(not asset.is_file() for asset in assets):
            raise RuntimeError("native_assets_refusal")
        nm = (["nm", "-gU"] if sys.platform == "darwin" else
              ["nm", "-g", "--defined-only"])
        report["steps"]["symbols"] = run(
            "symbols", [*nm, str(prefix / "lib/libvpx.a")],
            build, env, logs, 30, root, run_floor)
        exported = {line.split()[-1] for line in
                    (logs / "symbols.stdout").read_text("utf-8").splitlines()
                    if line.split()}
        prefix_char = "_" if sys.platform == "darwin" else ""
        if not {prefix_char + name for name in REQUIRED_LINK_SYMBOLS}.issubset(exported):
            raise RuntimeError("native_link_symbols_refusal")
        if sys.platform == "darwin":
            report["deployment"] = darwin_archive_deployment(prefix / "lib/libvpx.a")
        report["assets"] = {str(asset.relative_to(root)): {"bytes": asset.stat().st_size,
                             "sha256": sha(asset)} for asset in assets}
        report["native_pass"] = True
    except (OSError, subprocess.TimeoutExpired, RuntimeError, tarfile.TarError) as exc:
        report["error_code"] = (str(exc) if isinstance(exc, RuntimeError)
                                else type(exc).__name__)
    finally:
        try:
            report["logs"] = {path.name: {"bytes": path.stat().st_size,
                                          "sha256": sha(path)}
                              for path in sorted(logs.iterdir()) if path.is_file()}
            report["finished_unix"] = int(time.time())
            receipt.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
            receipt.chmod(0o600)
        finally:
            if lock_body is not None:
                if lock.read_bytes() != lock_body:
                    raise RuntimeError("native_timing_lock_owner_changed")
                lock.unlink()
    return 0 if report["native_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
