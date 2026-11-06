#!/usr/bin/env python3
"""Run one pinned Darwin test ELF with a self-only after-exec policy witness."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time

SCHEMA = "aegis_darwin_task_policy_ctor_v1"
MODES = {"observe": 0, "normalize": 1,
         "selftest_seed3": 2, "selftest_seed3_normalize": 3,
         "selftest_utility": 4, "selftest_utility_normalize": 5}
TIER0 = (0xFF << 16) | 1
TIER3 = (0xFF << 16) | 4


def need(condition, label):
    if not condition:
        raise RuntimeError(label)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            result.update(chunk)
    return result.hexdigest()


def source_gate(root, commit, manifest, expected_sha, runner_sha):
    need(digest(manifest) == expected_sha, "source_manifest_changed")
    row = json.loads(manifest.read_bytes())
    need(row.get("source_commit") == commit and
         row.get("included_count") == len(row.get("files", [])),
         "source_manifest_identity")
    need(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root,
                                 timeout=15).decode().strip() == commit and
         not subprocess.check_output(["git", "status", "--porcelain",
                                      "--untracked-files=all"], cwd=root,
                                     timeout=30), "source_checkout_changed")
    seen = set()
    for rel, pin in row["files"]:
        name = Path(rel)
        need(rel not in seen and not name.is_absolute() and ".." not in name.parts and
             not any(part in ("artifacts", "target") or part.startswith(".scratch-")
                     for part in name.parts), "source_member_path")
        seen.add(rel)
        local = root / name
        need(local.is_file() and not local.is_symlink() and digest(local) == pin,
             "source_member_changed")
    need(len(seen) == row["included_count"] and
         digest(Path(__file__).resolve()) == runner_sha and
         ["scripts/qa/darwin-test-task-policy-runner-r1.py", runner_sha] in row["files"],
         "runner_source_changed")


def regular_macho(path, root, expected_sha, filetype):
    need(path.is_absolute() and root.is_absolute() and root.is_dir() and
         ".." not in path.parts and ".." not in root.parts and
         path.resolve(strict=True) == path and root.resolve(strict=True) == root and
         path.is_relative_to(root), "target_path_refused")
    walk = path
    while walk != root:
        need(not walk.is_symlink(), "target_symlink_refused")
        walk = walk.parent
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             info.st_uid == os.getuid() and info.st_mode & 0o022 == 0,
             "target_identity_refused")
        if filetype == 2:
            need(info.st_mode & 0o111 != 0, "test_not_executable")
        header = os.read(fd, 16)
        need(len(header) == 16 and header[:4] == b"\xcf\xfa\xed\xfe" and
             int.from_bytes(header[12:16], "little") == filetype,
             "target_macho_type_refused")
        need(digest(path) == expected_sha, "target_hash_changed")
        named = os.stat(path, follow_symlinks=False)
        need((named.st_dev, named.st_ino) == (info.st_dev, info.st_ino),
             "target_named_inode_changed")
    finally:
        os.close(fd)


def proof_shape(proof, child_pid, mode, nonce):
    fields = {"schema", "pid", "mode", "nonce", "before_latency", "seeded_latency",
              "after_latency", "before_throughput", "after_throughput",
              "before_bg", "after_bg", "before_nice", "after_nice",
              "before_role", "after_role", "before_qos", "after_qos"}
    need(type(proof) is dict and set(proof) == fields and proof["schema"] == SCHEMA and
         all(type(proof[name]) is int for name in fields - {"schema", "nonce"}) and
         proof["pid"] == child_pid and proof["mode"] == MODES[mode] and
         proof["nonce"] == nonce,
         "ctor_proof_shape_refused")
    need(proof["before_throughput"] == proof["after_throughput"] and
         proof["before_bg"] == proof["after_bg"] and
         proof["before_nice"] == proof["after_nice"] and
         proof["before_role"] == proof["after_role"],
         "ctor_other_policy_changed")
    normalized = mode == "normalize" or mode.endswith("_normalize")
    need(proof["after_qos"] == (21 if normalized else proof["before_qos"]) and
         (not mode.startswith("selftest_utility") or
          (proof["before_latency"] == TIER0 and proof["before_qos"] == 17)),
         "ctor_qos_readback_refused")
    expected = (proof["before_latency"] if mode in ("observe", "selftest_utility") else
                TIER3 if mode == "selftest_seed3" else TIER0)
    need(proof["after_latency"] == expected and
         (mode not in ("selftest_seed3", "selftest_seed3_normalize") or
          (proof["before_latency"] == TIER3 and proof["seeded_latency"] == TIER3)),
         "ctor_latency_readback_refused")


def read_proof(fd, deadline, stopped=lambda: False):
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            need(not stopped(), "test_interrupted")
            if not selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                continue
            chunk = os.read(fd, 1024)
            if not chunk:
                break
            data.extend(chunk)
            need(len(data) <= 1024, "ctor_proof_oversize")
    need(data.endswith(b"\n") and data.count(b"\n") == 1,
         "ctor_proof_missing_or_duplicate")
    return json.loads(data)


def exited_unreaped(pid):
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def group_members(pgid):
    rows = subprocess.run(["/bin/ps", "-axo", "pid=,pgid="],
                          capture_output=True, timeout=5, check=True).stdout
    members = set()
    for line in rows.splitlines():
        fields = line.split()
        if len(fields) == 2 and int(fields[1]) == pgid and int(fields[0]) != pgid:
            members.add(int(fields[0]))
    return members


def signal_group(pgid, signum):
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        pass


def close_group(child, force):
    # Keep the leader unreaped to pin its PGID. A sole exited leader cannot
    # receive killpg on macOS, even when this is a forced cleanup path.
    if exited_unreaped(child.pid) and not group_members(child.pid):
        result = child.wait(timeout=2)
        need(not group_members(child.pid), "test_group_reappeared")
        return result
    signal_group(child.pid, signal.SIGTERM)
    for signum in (None, signal.SIGKILL):
        if signum is not None:
            signal_group(child.pid, signum)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if exited_unreaped(child.pid) and not group_members(child.pid):
                result = child.wait(timeout=2)
                need(not group_members(child.pid), "test_group_reappeared")
                return result
            time.sleep(0.1)
    raise RuntimeError("test_group_cleanup_ambiguous")


def run(args):
    need(sys.platform == "darwin" and args.mode in MODES and
         all(re.fullmatch(r"[0-9a-f]{64}", value) for value in
             (args.manifest_sha, args.runner_sha, args.library_sha,
              args.test_sha)) and
         re.fullmatch(r"[0-9a-f]{40}", args.commit) and
         1 <= args.timeout_seconds <= 2700 and args.command and
         args.command[0] != "--" and
         "DYLD_INSERT_LIBRARIES" not in os.environ,
         "runner_admission_refused")
    source_gate(args.repo, args.commit, args.manifest, args.manifest_sha,
                args.runner_sha)
    regular_macho(args.library, args.execution, args.library_sha, 6)
    regular_macho(Path(args.command[0]), args.target_root, args.test_sha, 2)
    if args.mode.startswith("selftest_"):
        need(Path(args.command[0]).name == "darwin-test-task-policy-dummy-r1" and
             args.command[1:] == [str(args.library)],
             "selftest_target_refused")
    elif Path(args.command[0]).name == "darwin-test-task-policy-dummy-r1":
        need(args.command[1:] == ["--observe"], "observe_target_refused")
    read_fd, write_fd = os.pipe()
    nonce = secrets.token_hex(16)
    os.set_inheritable(write_fd, True)
    env = dict(os.environ)
    env.update({"AEGIS_DARWIN_POLICY_LIB": str(args.library),
                "AEGIS_DARWIN_POLICY_MODE": args.mode,
                "AEGIS_DARWIN_POLICY_NONCE": nonce,
                "AEGIS_DARWIN_POLICY_EXE": args.command[0],
                "AEGIS_DARWIN_POLICY_PROOF_FD": str(write_fd)})
    if args.mode.startswith("selftest_"):
        env["AEGIS_DARWIN_POLICY_DLOPEN_SELFTEST"] = "1"
    else:
        env["DYLD_INSERT_LIBRARIES"] = str(args.library)
    child = None
    stopped = [False]
    previous = {}
    def request_stop(_signum, _frame):
        stopped[0] = True
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, request_stop)
        # The nonthrowing handler cannot skip assignment after Popen returns.
        # Masking here would make the child inherit blocked termination signals.
        child = subprocess.Popen(args.command, cwd=args.repo, env=env,
                                 stdin=None, stdout=None, stderr=None,
                                 pass_fds=(write_fd,), start_new_session=True)
        os.close(write_fd)
        write_fd = -1
        proof = read_proof(read_fd, time.monotonic() + 5, lambda: stopped[0])
        proof_shape(proof, child.pid, args.mode, nonce)
        print(json.dumps({"schema": "aegis_darwin_test_runner_proof_v1",
                          "test_sha256": args.test_sha,
                          "library_sha256": args.library_sha,
                          "ctor": proof}, sort_keys=True), file=sys.stderr, flush=True)
        deadline = time.monotonic() + args.timeout_seconds
        while time.monotonic() < deadline:
            need(not stopped[0], "test_interrupted")
            if exited_unreaped(child.pid):
                return close_group(child, force=False)
            time.sleep(0.1)
        raise RuntimeError("test_deadline")
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        try:
            if child is not None and child.returncode is None:
                close_group(child, force=True)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        if child is not None and child.returncode is not None:
            source_gate(args.repo, args.commit, args.manifest, args.manifest_sha,
                        args.runner_sha)
            regular_macho(args.library, args.execution, args.library_sha, 6)
            regular_macho(Path(args.command[0]), args.target_root, args.test_sha, 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha", required=True)
    parser.add_argument("--runner-sha", required=True)
    parser.add_argument("--execution", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--library-sha", required=True)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--test-sha", required=True)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--timeout-seconds", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command.pop(0)
    try:
        return run(args)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError):
        print("darwin_test_task_runner_refused", file=sys.stderr)
        return 73


if __name__ == "__main__":
    raise SystemExit(main())
