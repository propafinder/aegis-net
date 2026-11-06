#!/usr/bin/env python3
"""Bind one built standalone NE libtest and a witness to a Cargo target runner."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
BUILDER = HERE / "build-source-manifest-r1.py"
RUNNER = HERE / "darwin-test-task-policy-runner-r1.py"
WITNESS = HERE / "darwin-test-task-policy-r1.c"
NE_MANIFEST = Path("tools/macos/aegis-network-extension/Cargo.toml")
TARGET_NAME = "aegis_network_extension"


def need(ok, label):
    if not ok:
        raise RuntimeError(label)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def private_file(path, parent, max_bytes):
    need(path.is_absolute() and path.parent == parent and not path.is_symlink(),
         "input_path_refused")
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
         info.st_nlink == 1 and info.st_mode & 0o077 == 0 and
         0 < info.st_size <= max_bytes, "input_identity_refused")


def select_test_record(data, manifest, expected_opt_level="0"):
    need(expected_opt_level in ("0", "1"), "cargo_test_profile_request")
    candidates = []
    for line in data.splitlines():
        need(len(line) <= 1 << 20, "cargo_json_line_oversize")
        try:
            row = json.loads(line)
        except ValueError as error:
            raise RuntimeError("cargo_json_malformed") from error
        need(type(row) is dict, "cargo_json_row_shape")
        if row.get("reason") != "compiler-artifact":
            continue
        target = row.get("target") or {}
        profile = row.get("profile") or {}
        need(type(target) is dict and type(profile) is dict,
             "cargo_test_artifact_shape")
        if target.get("name") == TARGET_NAME or row.get("manifest_path") == str(manifest):
            need(type(profile.get("test")) is bool, "cargo_test_profile_shape")
            if profile["test"] is False:
                continue
            need(target.get("name") == TARGET_NAME and target.get("kind") == ["lib"] and
                 row.get("manifest_path") == str(manifest) and
                 isinstance(row.get("executable"), str), "cargo_test_artifact_identity")
            need(profile.get("opt_level") == expected_opt_level and
                 profile.get("debug_assertions") is True and
                 profile.get("overflow_checks") is True,
                 "cargo_test_profile_checks_or_optimization_refused")
            candidates.append((Path(row["executable"]), profile))
    need(len(candidates) == 1, "cargo_test_artifact_count")
    return candidates[0]


def select_test_artifact(data, manifest, expected_opt_level="0"):
    return select_test_record(data, manifest, expected_opt_level)[0]


def runner_array(python, runner, repo, commit, source_manifest, manifest_sha,
                 runner_sha, execution, library, library_sha, target_root,
                 test_sha):
    return [python, "-I", "-B", str(runner),
            "--repo", str(repo), "--commit", commit,
            "--manifest", str(source_manifest), "--manifest-sha", manifest_sha,
            "--runner-sha", runner_sha,
            "--execution", str(execution), "--library", str(library),
            "--library-sha", library_sha, "--target-root", str(target_root),
            "--test-sha", test_sha, "--mode", "normalize",
            "--timeout-seconds", "2700", "--"]


def config_text(host_target, argv):
    # JSON basic strings are TOML basic strings for these validated ASCII paths.
    need(re.fullmatch(r"[a-z0-9_]+-apple-darwin", host_target) and
         all(isinstance(arg, str) and arg.isascii() and
             not any(ord(ch) < 32 for ch in arg) for arg in argv),
         "runner_config_shape")
    quoted = ",".join(json.dumps(arg, ensure_ascii=True) for arg in argv)
    return f'[target.{json.dumps(host_target)}]\nrunner=[{quoted}]\n'


def compile_library(source, library, stdout, stderr):
    command = ["/usr/bin/clang", "-dynamiclib", "-fPIC", "-O2",
               "-Wall", "-Wextra", "-Werror", "-mmacosx-version-min=14.4",
               "-o", str(library), str(source)]
    spec = importlib.util.spec_from_file_location("aegis_policy_runner", RUNNER)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    stopped = [False]
    def request_stop(_signum, _frame):
        stopped[0] = True
    old_handlers = {}
    with stdout.open("xb") as out, stderr.open("xb") as err:
        child = None
        try:
            for signum in (signal.SIGTERM, signal.SIGINT):
                old_handlers[signum] = signal.signal(signum, request_stop)
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=err, start_new_session=True)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not stopped[0] and \
                    not runner.exited_unreaped(child.pid):
                time.sleep(0.1)
            completed_in_time = not stopped[0] and time.monotonic() < deadline and \
                runner.exited_unreaped(child.pid)
            rc = runner.close_group(child, force=not completed_in_time)
        finally:
            try:
                if child is not None and child.returncode is None:
                    runner.close_group(child, force=True)
            finally:
                for signum, handler in old_handlers.items():
                    signal.signal(signum, handler)
                out.flush(); os.fsync(out.fileno())
                err.flush(); os.fsync(err.fileno())
    need(completed_in_time and rc == 0 and stdout.stat().st_size <= 1 << 20 and
         stderr.stat().st_size <= 1 << 20, "witness_compile_failed")


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(args):
    need(sys.platform == "darwin" and args.repo.is_absolute() and
         args.repo.resolve(strict=True) == args.repo and
         args.execution.is_absolute() and
         args.execution.resolve(strict=True) == args.execution and
         args.execution.is_dir() and not args.execution.is_symlink() and
         args.execution.stat().st_uid == os.getuid() and
         args.execution.stat().st_mode & 0o777 == 0o700 and
         args.target_root.is_absolute() and
         args.target_root.resolve(strict=True) == args.target_root and
         args.target_root.is_dir() and
         args.output == args.execution / "runner.toml" and
         not args.output.exists() and
         os.environ.get("MACOSX_DEPLOYMENT_TARGET") == "14.4" and
         re.fullmatch(r"[a-z0-9_]+-apple-darwin", args.host_target),
         "preparer_admission")
    rustc = subprocess.check_output(["rustc", "-vV"], text=True, timeout=15)
    need([line[6:] for line in rustc.splitlines() if line.startswith("host: ")] ==
         [args.host_target], "host_target_changed")
    manifest = args.manifest
    need(manifest == args.repo / NE_MANIFEST and manifest.is_file() and
         not manifest.is_symlink(), "ne_manifest_identity")
    private_file(args.cargo_json, args.execution, 16 << 20)
    need(args.cargo_json.name == "cargo-build.jsonl", "cargo_json_name")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=args.repo,
                                     text=True, timeout=15).strip()
    need(re.fullmatch(r"[0-9a-f]{40}", commit) and
         not subprocess.check_output(["git", "status", "--porcelain",
                                      "--untracked-files=all"], cwd=args.repo,
                                     timeout=30), "source_checkout_changed")
    source_manifest = args.execution / "source-manifest.json"
    subprocess.run([sys.executable, "-I", "-B", str(BUILDER), str(args.repo),
                    str(source_manifest)], check=True, capture_output=True,
                   timeout=120)
    manifest_sha = digest(source_manifest)
    source_row = json.loads(source_manifest.read_bytes())
    pins = dict(source_row["files"])
    need(source_row["source_commit"] == commit and
         source_row["included_count"] == len(pins) and
         all(pins.get(str(path.relative_to(args.repo))) == digest(path)
             for path in (BUILDER, RUNNER, WITNESS, manifest, Path(__file__).resolve())),
         "source_manifest_changed")
    target_root = args.target_root / args.host_target / "debug" / "deps"
    test_exe, cargo_profile = select_test_record(args.cargo_json.read_text(), manifest,
                                                args.expected_opt_level)
    need(target_root.is_dir() and test_exe.is_absolute() and
         test_exe.parent == target_root and
         re.fullmatch(r"aegis_network_extension-[0-9a-f]+", test_exe.name),
         "test_executable_location")
    spec = importlib.util.spec_from_file_location("aegis_policy_runner", RUNNER)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    test_sha = digest(test_exe)
    runner.regular_macho(test_exe, target_root, test_sha, 2)
    library = args.execution / "libaegis-policy-witness-r1.dylib"
    need(not library.exists(), "witness_exists")
    compile_library(WITNESS, library, args.execution / "clang.stdout",
                    args.execution / "clang.stderr")
    os.chmod(library, 0o700)
    library_sha = digest(library)
    runner.regular_macho(library, args.execution, library_sha, 6)
    argv = runner_array(sys.executable, RUNNER, args.repo, commit,
                        source_manifest, manifest_sha, digest(RUNNER), args.execution,
                        library, library_sha, target_root, test_sha)
    write_new(args.output, config_text(args.host_target, argv).encode())
    runner.source_gate(args.repo, commit, source_manifest, manifest_sha, digest(RUNNER))
    runner.regular_macho(test_exe, target_root, test_sha, 2)
    runner.regular_macho(library, args.execution, library_sha, 6)
    print(json.dumps({"schema": "aegis_darwin_test_runner_prepared_r1",
                      "source_commit": commit, "source_manifest_sha256": manifest_sha,
                      "cargo_json_sha256": digest(args.cargo_json),
                      "cargo_profile": cargo_profile,
                      "test_sha256": test_sha, "library_sha256": library_sha,
                      "runner_config_sha256": digest(args.output),
                      "runner_config": str(args.output)}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "manifest", "execution", "cargo-json", "output",
                 "target-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--host-target", required=True)
    parser.add_argument("--expected-opt-level", choices=("0", "1"), default="0")
    args = parser.parse_args()
    try:
        prepare(args)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError):
        print("darwin_test_runner_preparation_refused", file=sys.stderr)
        return 73
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
