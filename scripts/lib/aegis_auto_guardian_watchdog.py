#!/usr/bin/env python3
"""Independent PID1 actor for an active Linux AUTO guardian lease.

REGISTER is a pre-start barrier: the guardian transfers its locked guard OFD
and the worker PIDFD before BIND or StartUnit.  This process retains both plus
the guardian's SO_PEERPIDFD.  If either owner dies, it writes durable recovery
state, blocks with that same guard OFD, verifies the full installed policy,
and independently stops the exact private PID1 unit and captured cgroup.
"""

from __future__ import annotations

import array
import ctypes
import fcntl
import hashlib
import json
import os
import re
import select
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import types
from dataclasses import dataclass
from pathlib import Path

ROOT = Path("/usr/local/lib/aegis/helpers/lib")
SOURCE = ROOT / "aegis_auto_guardian_watchdog.py"
UNIT_PATH = Path("/etc/systemd/system/aegis-auto-guardian-watchdog.service")
GUARDIAN_SOURCE = ROOT / "aegis_auto_guardian.py"
HELPER = Path("/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh")
INSTALL = Path("/var/lib/aegis-install/client/auto-guardian-install.json")
GUARD_LOCK = Path("/var/lib/aegis-install/client/device-guard.conf.lock")
STOP_INTENT = Path("/var/lib/aegis-install/client/auto-stop-intent.json")
JOURNAL = Path("/var/lib/aegis-install/client/auto-watchdog-pending.json")
RUNTIME = Path("/run/aegis-auto-guardian-watchdog")
AUTHORITY = RUNTIME / "authority.sock"
UNIT = "aegis-auto-guardian-watchdog.service"
PRIVATE = re.compile(r"aegis-auto@[0-9a-f]{64}\.service\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
MAX_CONTROL = 8192
STOPPING_SECONDS = 55.0  # PID1 owned StopUnit 35s plus native inverse/readback.
NORMAL_STOP_SETTLE_SECONDS = 5.0  # Let the original PID1 stop job finish under deny.
STAGE_REACQUIRE_SECONDS = 45.0  # Only while exact owned Stop already proves kernel deny.
UNPROVEN_STAGE_REACQUIRE_SECONDS = 3.0
CGROUP = Path("/sys/fs/cgroup/system.slice/aegis-auto-guardian-watchdog.service")
STOP_REQUESTED = False
_GUARDIAN_MODULE_LOCK = threading.RLock()
_GUARDIAN_MODULE: tuple[str, types.ModuleType] | None = None


def _request_stop(_signum: int, _frame: object) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


class Refused(RuntimeError):
    pass


def need(value: bool, reason: str) -> None:
    if not value:
        raise Refused(reason)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        need(key not in result, "duplicate_watchdog_json_key")
        result[key] = value
    return result


def _json(raw: bytes) -> dict[str, object]:
    need(0 < len(raw) <= MAX_CONTROL, "invalid_watchdog_json_size")
    value = json.loads(raw, object_pairs_hook=_unique)
    need(type(value) is dict, "invalid_watchdog_json")
    return value


def _read_root(path: Path, max_size: int = 1 << 20) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             info.st_nlink == 1 and 0 < info.st_size <= max_size and
             info.st_mode & 0o022 == 0, "untrusted_watchdog_source_or_record")
        raw = os.read(fd, max_size + 1)
        need(len(raw) == info.st_size, "watchdog_source_changed")
        return raw
    finally:
        os.close(fd)


def _boot() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _own_source() -> dict[str, object]:
    need(os.geteuid() == 0 and Path(__file__).resolve() == SOURCE and
         Path("/proc/self/ns/net").exists(), "installed_linux_watchdog_required")
    install = _json(_read_root(INSTALL))
    for path, field in ((SOURCE, "watchdog_sha256"),
                        (UNIT_PATH, "watchdog_unit_sha256"),
                        (GUARDIAN_SOURCE, "guardian_sha256"),
                        (HELPER, "guard_helper_sha256")):
        expected = install.get(field)
        need(type(expected) is str and re.fullmatch(r"[0-9a-f]{64}", expected)
             is not None and _sha(_read_root(path)) == expected,
             "watchdog_install_pin_mismatch")
    need(install.get("schema") == "aegis_auto_guardian_install_v1",
         "watchdog_install_schema_invalid")
    runtime = RUNTIME.stat(follow_symlinks=False)
    need(stat.S_ISDIR(runtime.st_mode) and runtime.st_uid == 0 and
         stat.S_IMODE(runtime.st_mode) == 0o700,
         "untrusted_watchdog_runtime")
    return install


def _notify(value: str) -> None:
    path = os.environ.get("NOTIFY_SOCKET")
    need(path is not None and path != "", "watchdog_notify_socket_missing")
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.connect("\0" + path[1:] if path.startswith("@") else path)
        sock.sendall(value.encode())


def _store_guard_fd(fd: int, stage_fd: int) -> None:
    """Atomically retain guard and stage-lock OFDs in PID1 on actor crash."""
    lib = ctypes.CDLL("libsystemd.so.0")
    lib.sd_pid_notify_with_fds.argtypes = (ctypes.c_int, ctypes.c_int,
                                          ctypes.c_char_p,
                                          ctypes.POINTER(ctypes.c_int), ctypes.c_uint)
    lib.sd_pid_notify_with_fds.restype = ctypes.c_int
    descriptors = (ctypes.c_int * 2)(fd, stage_fd)
    need(lib.sd_pid_notify_with_fds(0, 0, b"FDSTORE=1\nFDNAME=lease",
                                    descriptors, 2) > 0,
         "watchdog_pid1_fdstore_rejected")
    lib.sd_notify_barrier.argtypes = (ctypes.c_int, ctypes.c_uint64)
    lib.sd_notify_barrier.restype = ctypes.c_int
    need(lib.sd_notify_barrier(0, 3_000_000) > 0,
         "watchdog_pid1_fdstore_unconfirmed")


def _inherited_guard_fd() -> tuple[int, int] | None:
    count = os.environ.get("LISTEN_FDS")
    if count is None:
        return None
    need(count == "2" and os.environ.get("LISTEN_PID") == str(os.getpid()) and
         os.environ.get("LISTEN_FDNAMES") == "lease:lease",
         "watchdog_foreign_fdstore")
    descriptors = (3, 4)
    guard = [fd for fd in descriptors if stat.S_ISREG(os.fstat(fd).st_mode)]
    stage = [fd for fd in descriptors if stat.S_ISDIR(os.fstat(fd).st_mode)]
    need(len(guard) == len(stage) == 1,
         "watchdog_stored_lease_shape_invalid")
    return guard[0], stage[0]


def _remove_guard_fd() -> None:
    _notify("FDSTOREREMOVE=1\nFDNAME=lease")
    lib = ctypes.CDLL("libsystemd.so.0")
    lib.sd_notify_barrier.argtypes = (ctypes.c_int, ctypes.c_uint64)
    lib.sd_notify_barrier.restype = ctypes.c_int
    need(lib.sd_notify_barrier(0, 3_000_000) > 0,
         "watchdog_pid1_fdstore_remove_unconfirmed")


def _pidfd_pid(fd: int) -> int:
    info = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii")
    match = re.search(r"^Pid:\s*([1-9][0-9]*)$", info, re.MULTILINE)
    need(match is not None, "watchdog_pidfd_identity_unavailable")
    return int(match.group(1))


def _alive(fd: int) -> bool:
    watcher = select.poll()
    watcher.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not watcher.poll(0)


def _guardian_peer(peer: socket.socket) -> tuple[int, int]:
    pid, uid, _gid = struct.unpack("3i", peer.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(uid == 0 and pid > 1, "foreign_watchdog_guardian")
    raw = peer.getsockopt(socket.SOL_SOCKET,
                          getattr(socket, "SO_PEERPIDFD", 77), 4)
    need(len(raw) == 4, "watchdog_guardian_pidfd_unavailable")
    pidfd = struct.unpack("i", raw)[0]
    try:
        need(_pidfd_pid(pidfd) == pid and _alive(pidfd) and
             Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
             "0::/system.slice/aegis-auto-guardian.service\n" and
             os.stat(f"/proc/{pid}/ns/net").st_ino ==
             os.stat("/proc/self/ns/net").st_ino,
             "foreign_watchdog_guardian")
        return pid, pidfd
    except BaseException:
        os.close(pidfd)
        raise


def _exclusive_flock_fdinfo(fdinfo: str, identity: os.stat_result) -> bool:
    """Read the exact Linux fdinfo FLOCK fields for this held inode."""
    if len(fdinfo) > 4096:
        return False
    locks = [line.split() for line in fdinfo.splitlines()
             if line.startswith("lock:")]
    if len(locks) != 1:
        return False
    fields = locks[0]
    if (len(fields) != 9 or fields[0] != "lock:" or
            re.fullmatch(r"[1-9][0-9]*:", fields[1]) is None or
            fields[2:5] != ["FLOCK", "ADVISORY", "WRITE"] or
            re.fullmatch(r"[0-9]+", fields[5]) is None or
            fields[7:] != ["0", "EOF"]):
        return False
    device = re.fullmatch(r"([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)",
                          fields[6])
    return (device is not None and
            int(device[1], 16) == os.major(identity.st_dev) and
            int(device[2], 16) == os.minor(identity.st_dev) and
            int(device[3]) == identity.st_ino)


def _guard_identity(fd: int) -> tuple[int, int]:
    held = os.fstat(fd)
    named = GUARD_LOCK.stat(follow_symlinks=False)
    info = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii")
    need(stat.S_ISREG(held.st_mode) and held.st_uid == 0 and
         stat.S_IMODE(held.st_mode) == 0o600 and held.st_nlink == 1 and
         (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino) and
         _exclusive_flock_fdinfo(info, held),
         "watchdog_guard_ofd_not_locked")
    return held.st_dev, held.st_ino


def _unit_facts(name: str, *, actor: bool = False) -> dict[str, str]:
    need(name == UNIT if actor else PRIVATE.fullmatch(name) is not None, "invalid_private_unit")
    result = subprocess.run(["/usr/bin/systemctl", "show", name,
                             "-p", "LoadState", "-p", "ActiveState", "-p", "MainPID",
                             "-p", "InvocationID", "-p", "ControlGroup",
                             "--no-pager"], capture_output=True, timeout=2,
                            check=False, env={"PATH": "/usr/sbin:/usr/bin",
                                              "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 4096 and
         len(result.stderr) <= 4096, "watchdog_pid1_readback_unavailable")
    facts: dict[str, str] = {}
    for line in result.stdout.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        need(sep == "=" and key not in facts, "watchdog_pid1_facts_invalid")
        facts[key] = value
    need(set(facts) == {"LoadState", "ActiveState", "MainPID",
                        "InvocationID", "ControlGroup"},
         "watchdog_pid1_facts_incomplete")
    return facts


def _write_atomic(path: Path, value: dict[str, object], *, exclusive: bool) -> None:
    parent = path.parent.stat(follow_symlinks=False)
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
         parent.st_mode & 0o022 == 0, "watchdog_journal_parent_untrusted")
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    temporary = path.with_name(path.name + "." + secrets.token_hex(12) + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), "watchdog_journal_short_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    if exclusive:
        need(not path.exists() and not path.is_symlink(), "watchdog_journal_already_present")
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _journal(value: dict[str, object], *, create: bool = False) -> None:
    _write_atomic(JOURNAL, value, exclusive=create)
    need(_json(_read_root(JOURNAL)) == value, "watchdog_journal_changed")


def _sticky_stop(boot_id: str, unit: str, invocation: str) -> None:
    need(HEX32.fullmatch(invocation) is not None,
         "watchdog_pid1_invocation_not_real")
    proposed = {"schema": "aegis_auto_stop_intent_v1", "boot_id": boot_id,
                "invocation_id": invocation, "service": unit,
                "phase": "pending_deny"}
    if STOP_INTENT.exists() or STOP_INTENT.is_symlink():
        existing = _json(_read_root(STOP_INTENT))
        need(existing == proposed or existing == {**proposed, "phase": "deny_proven"},
             "foreign_stop_intent")
    else:
        _write_atomic(STOP_INTENT, proposed, exclusive=True)
    need(_json(_read_root(STOP_INTENT)) in
         (proposed, {**proposed, "phase": "deny_proven"}),
         "stop_intent_not_durable")


def _guardian_module() -> types.ModuleType:
    global _GUARDIAN_MODULE
    with _GUARDIAN_MODULE_LOCK:
        install = _own_source()
        guardian_bytes = _read_root(GUARDIAN_SOURCE)
        expected = install["guardian_sha256"]
        need(_sha(guardian_bytes) == expected,
             "guardian_semantic_source_changed")
        if _GUARDIAN_MODULE is not None:
            need(_GUARDIAN_MODULE[0] == expected,
                 "guardian_semantic_source_generation_changed")
            module = _GUARDIAN_MODULE[1]
            module.own_source()
            return module
        module = types.ModuleType("aegis_auto_guardian")
        module.__file__ = str(GUARDIAN_SOURCE)
        exec(compile(guardian_bytes, str(GUARDIAN_SOURCE), "exec"), module.__dict__)
        module.own_source()
        _GUARDIAN_MODULE = (expected, module)
        return module


def _semantic_blocked() -> str:
    module = _guardian_module()
    _state, projection = module._semantic_policy_readback()
    need(module._no_client_grant(projection), "watchdog_client_grant_remains")
    return module.digest(projection)


def _retire_scoped_after_stop(journal: dict[str, object],
                              policy_sha256: str, *, reboot: bool = False) -> None:
    """Inverse only the original scoped Redirect after deny and PID1 stop."""
    module = _guardian_module()
    redirect = module.verified_module(module.POLICY_SOURCE,
                                      "aegis_auto_guard_policy")
    if not redirect.SCOPED_INTENT.exists():
        return
    intent = redirect._scoped_read(redirect.SCOPED_INTENT)
    binding = intent.get("binding")
    need(type(binding) is dict and
         binding.get("private_unit") == journal["private_unit"] and
         [binding.get("stage_dev"), binding.get("stage_ino")] ==
         [journal["stage_dev"], journal["stage_ino"]] and
         binding.get("boot_id") == journal["boot_id"],
         "watchdog_foreign_scoped_redirect")

    def denied() -> bool:
        return _semantic_blocked() == policy_sha256

    def stopped() -> bool:
        facts = _unit_facts(str(journal["private_unit"]))
        return (facts["ActiveState"] in ("inactive", "failed") and
                facts["MainPID"] == "0" and not facts["ControlGroup"])

    redirect.scoped_retire(unit=str(journal["private_unit"]),
                           deny_check=denied, stopped_check=stopped,
                           reboot=reboot)


def _retire_local_after_stop(journal: dict[str, object],
                             policy_sha256: str, *, reboot: bool = False) -> None:
    """Inverse only the original local OUTPUT policy after deny and Stop."""
    module = _guardian_module()
    redirect = module.verified_module(module.POLICY_SOURCE,
                                      "aegis_auto_guard_policy")
    if not redirect.LOCAL_INTENT.exists():
        return
    intent = redirect._scoped_read(redirect.LOCAL_INTENT)
    binding = intent.get("binding")
    need(type(binding) is dict and
         binding.get("private_unit") == journal["private_unit"] and
         [binding.get("stage_dev"), binding.get("stage_ino")] ==
         [journal["stage_dev"], journal["stage_ino"]] and
         binding.get("boot_id") == journal["boot_id"],
         "watchdog_foreign_local_redirect")

    def denied() -> bool:
        return _semantic_blocked() == policy_sha256

    def stopped() -> bool:
        facts = _unit_facts(str(journal["private_unit"]))
        return (facts["ActiveState"] in ("inactive", "failed") and
                facts["MainPID"] == "0" and not facts["ControlGroup"])

    redirect.local_retire(unit=str(journal["private_unit"]),
                          deny_check=denied, stopped_check=stopped,
                          reboot=reboot)


def _private_main_pidfd(unit: str, invocation: str) -> tuple[int, int, str]:
    first = _unit_facts(unit)
    need(first["ActiveState"] == "active" and
         first["InvocationID"] == invocation and
         first["ControlGroup"] == "/system.slice/" + unit and
         first["MainPID"].isdigit() and int(first["MainPID"]) > 1,
         "watchdog_private_pid1_identity_missing")
    pid = int(first["MainPID"])
    fd = os.pidfd_open(pid, 0)
    try:
        need(_pidfd_pid(fd) == pid and _alive(fd) and
             Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
             "0::" + first["ControlGroup"] + "\n" and
             _unit_facts(unit) == first,
             "watchdog_private_pid_recycled_or_changed")
        return pid, fd, first["ControlGroup"]
    except BaseException:
        os.close(fd)
        raise


def _finalized_stage(stage_fd: int, unit: str, terminal_sha256: str,
                     invocation: str, capture_sha256: str,
                     original_policy_sha256: str,
                     post_policy_sha256: str,
                     *, deadline: float | None = None) -> str:
    module = _guardian_module()
    stage = os.fstat(stage_fd)
    need(stat.S_ISDIR(stage.st_mode) and stage.st_uid == 0 and
         stage.st_mode & 0o022 == 0,
         "watchdog_stage_fd_untrusted")
    for name in ("activation-owner-may-send-v3.json",
                 "activation-owner-claim-v3.json",
                 "activation-owner-terminal-handoff.json",
                 "activation-owner-native-recovery.json"):
        try:
            os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("watchdog_owner_marker_not_retired")
    raw = module._protected_stage_receipt(
        stage_fd, "receipts/activation-owner/terminal.json")
    need(_sha(raw) == terminal_sha256,
         "watchdog_finalized_terminal_digest_changed")
    terminal = json.loads(raw, object_pairs_hook=module.unique)
    header = json.loads(module._protected_stage_receipt_for_header(stage_fd),
                        object_pairs_hook=module.unique)
    need(terminal.get("schema") == 1 and
         terminal.get("outcome") == "finalized" and
         terminal.get("private_unit") == unit and
         terminal.get("stage") == [stage.st_dev, stage.st_ino] and
         type(terminal.get("native_guard")) is dict and
         terminal["native_guard"].get("policy_sha256") ==
         original_policy_sha256 and
         terminal.get("native_capture_sha256") == capture_sha256 and
         header.get("phase") == "finalized" and
         type(header.get("leaves")) is dict and
         header["leaves"].get("receipts/activation-owner/terminal.json") ==
         terminal_sha256,
         "watchdog_finalized_terminal_not_committed")
    if deadline is None:
        _state, projection = module._semantic_policy_readback()
    else:
        _state, projection = module._semantic_policy_readback(
            deadline=deadline)
    policy_sha = module.digest(projection)
    need(policy_sha == post_policy_sha256 and
         _unit_facts(unit)["InvocationID"] == invocation,
         "watchdog_finalized_policy_or_unit_changed")
    return policy_sha


def _commit_request_hashes(request: dict[str, object]
                           ) -> tuple[str, str, str, str]:
    need(set(request) == {"op", "terminal_sha256", "capture_sha256",
                          "original_policy_sha256", "post_policy_sha256"} and
         request.get("op") == "COMMIT_ACTIVE", "watchdog_commit_request_invalid")
    values = tuple(request.get(key) for key in (
        "terminal_sha256", "capture_sha256", "original_policy_sha256",
        "post_policy_sha256"))
    need(all(type(value) is str and
             re.fullmatch(r"[0-9a-f]{64}", value) is not None
             for value in values), "watchdog_commit_request_invalid")
    return values


def _commit_refusal_diagnostic(phase: str, error: BaseException) -> str:
    phases = {"request", "sealed_stage", "durable_journal",
              "stage_flock_release", "acknowledgement"}
    reasons = {"watchdog_commit_request_invalid",
               "watchdog_commit_before_live_latch",
               "watchdog_stage_fd_untrusted",
               "watchdog_owner_marker_not_retired",
               "watchdog_finalized_terminal_digest_changed",
               "watchdog_finalized_terminal_not_committed",
               "watchdog_finalized_policy_or_unit_changed"}
    reason = (error.args[0] if type(error) is Refused and
              len(error.args) == 1 and type(error.args[0]) is str and
              error.args[0] in reasons else "other")
    kind = ("refused" if type(error) is Refused else
            "os_error" if isinstance(error, OSError) else "unexpected")
    safe_phase = phase if phase in phases else "unknown"
    return ("aegis_auto_watchdog_commit_refused "
            f"phase={safe_phase} class={kind} reason={reason}")


def _block_same_ofd(fd: int) -> str:
    _guard_identity(fd)
    need(Path("/proc/self/cgroup").read_text(encoding="ascii") ==
         "0::/system.slice/aegis-auto-guardian-watchdog.service\n" and
         CGROUP.is_dir() and (CGROUP / "cgroup.controllers").exists(),
         "watchdog_cgroup_not_delegated")
    leaf = CGROUP / ("aegis-block-" + secrets.token_hex(8))
    leaf.mkdir(mode=0o700)
    process: subprocess.Popen[bytes] | None = None
    try:
        need((leaf / "cgroup.kill").exists(), "watchdog_cgroup_kill_unavailable")
        wrapper = 'printf "0\\n" > "$1/cgroup.procs" || exit 111; exec /bin/bash "$2" block'
        process = subprocess.Popen(
            ["/bin/bash", "--noprofile", "--norc", "-c", wrapper,
             "aegis-watchdog-block", str(leaf), str(HELPER)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
            pass_fds=(fd,), env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C",
                                 "LC_ALL": "C", "AEGIS_AUTO_HELD_GUARD_FD": str(fd)})
        helper_exit = process.wait(timeout=5)
        empty = (helper_exit == 0 and
                 "populated 0\n" in (leaf / "cgroup.events").read_text(encoding="ascii"))
        if not empty:
            token = (str(helper_exit) if type(helper_exit) is int and
                     -255 <= helper_exit <= 255 else "other")
            print("aegis_auto_watchdog_reblock_diagnostic helper_exit=" + token,
                  file=sys.stderr, flush=True)
        need(empty,
             "watchdog_guard_reblock_failed")
        _guard_identity(fd)
        return _semantic_blocked()
    except BaseException:
        try:
            (leaf / "cgroup.kill").write_text("1\n", encoding="ascii")
        except OSError:
            pass
        if process is not None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        raise
    finally:
        try:
            leaf.rmdir()
        except OSError:
            pass


def _private_inert(facts: dict[str, str]) -> bool:
    return (facts["ActiveState"] in ("inactive", "failed") and
            facts["MainPID"] == "0" and not facts["ControlGroup"])


def _settled_normal_private(unit: str, before: dict[str, str],
                            expected_invocation: str | None,
                            diagnostic: dict[str, str] | None = None) -> dict[str, str] | None:
    """Avoid a second PID1 stop job after the authenticated normal stop.

    A new job for this same unit would make the terminal observer refuse its
    original stop-job identity. Any uncertain readback takes the old StopUnit
    path; this shortcut is used only after a deny-proven normal stop intent.
    """
    if type(expected_invocation) is not str or HEX32.fullmatch(expected_invocation) is None:
        if diagnostic is not None: diagnostic["settle"] = "invalid_expected"
        return None
    if before["InvocationID"] != expected_invocation:
        if diagnostic is not None: diagnostic["settle"] = "before_invocation_changed"
        return None
    if not _private_inert(before):
        if diagnostic is not None: diagnostic["settle"] = "before_not_inert"
        return None
    try:
        pending = subprocess.run(
            ["/usr/bin/systemctl", "show", unit, "-p", "Job", "--no-pager"],
            capture_output=True, timeout=2, check=False,
            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        if diagnostic is not None: diagnostic["settle"] = "job_read_error"
        return None
    if (pending.returncode != 0 or pending.stderr or
            pending.stdout not in (b"Job=0\n", b"Job=\n")):
        if diagnostic is not None: diagnostic["settle"] = "job_not_clear"
        return None
    try:
        after = _unit_facts(unit)
    except (Refused, OSError, ValueError, subprocess.TimeoutExpired):
        if diagnostic is not None: diagnostic["settle"] = "after_read_error"
        return None
    if after["InvocationID"] != expected_invocation:
        if diagnostic is not None: diagnostic["settle"] = "after_invocation_changed"
        return None
    if after["LoadState"] != before["LoadState"]:
        if diagnostic is not None: diagnostic["settle"] = "load_state_changed"
        return None
    if not _private_inert(after):
        if diagnostic is not None: diagnostic["settle"] = "after_not_inert"
        return None
    if diagnostic is not None: diagnostic["settle"] = "settled"
    return after


def _await_original_normal_stop(unit: str, before: dict[str, str],
                                journal: dict[str, object], guard_fd: int,
                                policy_sha: str,
                                diagnostic: dict[str, str] | None = None) -> tuple[dict[str, str] | None,
                                                          dict[str, str]]:
    """Observe the original StopUnit before considering a replacement job.

    Recovery can sample a still-deactivating unit before terminal B and the
    original private stop finish. A later JobRemoved for a replacement stop
    would invalidate the observer's exact original job identity.
    """
    expected = journal.get("invocation_id")
    if type(expected) is not str or HEX32.fullmatch(expected) is None:
        if diagnostic is not None: diagnostic["await"] = "invalid_expected"
        return None, before
    deadline = time.monotonic() + NORMAL_STOP_SETTLE_SECONDS
    latest = before
    while True:
        step = "guard"
        try:
            need(_guard_identity(guard_fd) ==
                 (journal["guard_dev"], journal["guard_ino"]),
                 "watchdog_normal_stop_guard_changed")
            step = "deny"
            need(_normal_stop_intent(journal) and
                 _semantic_blocked() == policy_sha,
                 "watchdog_normal_stop_deny_changed")
            step = "unit"
            latest = _unit_facts(unit)
            if latest["InvocationID"] != expected:
                if diagnostic is not None: diagnostic["await"] = "foreign_invocation"
                return None, latest
            step = "settle"
            settled = _settled_normal_private(unit, latest, expected, diagnostic)
            if settled is not None:
                if diagnostic is not None: diagnostic["await"] = "settled"
                return settled, latest
        except (Refused, OSError, ValueError, subprocess.TimeoutExpired):
            if diagnostic is not None: diagnostic["await"] = step + "_error"
            return None, latest
        if time.monotonic() >= deadline:
            if diagnostic is not None: diagnostic["await"] = "deadline"
            return None, latest
        try:
            _notify("WATCHDOG=1")
        except (Refused, OSError):
            if diagnostic is not None: diagnostic["await"] = "notify_error"
            return None, latest
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def _stop_private(unit: str, before: dict[str, str], *,
                  settled_normal_stop: bool = False,
                  expected_invocation: str | None = None) -> dict[str, str]:
    captured_cgroup = before["ControlGroup"]
    cgroup_path: Path | None = None
    cgroup_ino: int | None = None
    if captured_cgroup:
        need(captured_cgroup == "/system.slice/" + unit,
             "foreign_private_cgroup")
        cgroup_path = Path("/sys/fs/cgroup") / captured_cgroup.lstrip("/")
        if cgroup_path.exists():
            cgroup_ino = cgroup_path.stat(follow_symlinks=False).st_ino
    if settled_normal_stop:
        settled = _settled_normal_private(unit, before, expected_invocation)
        if settled is not None:
            return settled
    call = subprocess.run(
        ["/usr/bin/busctl", "call", "org.freedesktop.systemd1",
         "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
         "StopUnit", "ss", unit, "replace"], capture_output=True, timeout=2,
        check=False, env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
    if call.returncode != 0:
        absent = _unit_facts(unit)
        need(before["LoadState"] == "not-found" and
             absent["LoadState"] == "not-found" and
             absent["ActiveState"] == "inactive" and
             absent["MainPID"] == "0" and not absent["ControlGroup"],
             "watchdog_pid1_stop_not_submitted")
        return absent
    need(len(call.stdout) <= 256 and
         re.fullmatch(rb'o "?/org/freedesktop/systemd1/job/[1-9][0-9]*"?\s*',
                      call.stdout) is not None,
         "watchdog_pid1_stop_job_invalid")
    if cgroup_path is not None and cgroup_path.exists():
        need(cgroup_path.stat(follow_symlinks=False).st_ino == cgroup_ino,
             "private_cgroup_replaced")
        (cgroup_path / "cgroup.kill").write_text("1\n", encoding="ascii")
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        current = _unit_facts(unit)
        if (current["ActiveState"] in ("inactive", "failed") and
                current["MainPID"] == "0" and not current["ControlGroup"]):
            return current
        time.sleep(0.1)
    raise Refused("watchdog_private_unit_not_stopped")


def _mark_stage_recovery(journal: dict[str, object], stage_fd: int) -> None:
    """Revoke ordinary StageGuard admission before any automatic inverse.

    The received descriptor is a dup of the original stage-root flock OFD.
    Holding it through O_EXCL, file fsync and directory fsync means a fresh
    StageGuard cannot observe a marker-free Finalized stage after this cut.
    """
    stage = os.fstat(stage_fd)
    fdinfo = Path(f"/proc/self/fdinfo/{stage_fd}").read_text(
        encoding="ascii")
    need(stat.S_ISDIR(stage.st_mode) and stage.st_uid == 0 and
         stage.st_mode & 0o022 == 0 and
         (stage.st_dev, stage.st_ino) ==
         (journal["stage_dev"], journal["stage_ino"]) and
         _exclusive_flock_fdinfo(fdinfo, stage),
         "watchdog_original_stage_lock_lost")
    name = "activation-owner-native-recovery.json"
    proposed = {
        "schema": 1, "kind": "native-recovery",
        "stage": [stage.st_dev, stage.st_ino],
        "private_unit": journal["private_unit"],
        "boot_id": journal["boot_id"],
    }
    raw = (json.dumps(proposed, sort_keys=True,
                      separators=(",", ":")) + "\n").encode()
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_CLOEXEC | os.O_NOFOLLOW, 0o600,
                     dir_fd=stage_fd)
    except FileExistsError:
        fd = None
    if fd is not None:
        try:
            need(os.write(fd, raw) == len(raw),
                 "watchdog_recovery_marker_short_write")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(stage_fd)
    existing = os.open(name, os.O_RDONLY | os.O_CLOEXEC |
                       os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=stage_fd)
    try:
        info = os.fstat(existing)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and
             info.st_size == len(raw) and os.read(existing, len(raw) + 1) == raw,
             "watchdog_recovery_marker_changed")
    finally:
        os.close(existing)


_RECOVERY_DIAGNOSTIC_REFUSALS = frozenset({
    "watchdog_cgroup_not_delegated", "watchdog_cgroup_kill_unavailable",
    "watchdog_guard_reblock_failed", "watchdog_client_grant_remains",
    "watchdog_normal_stop_guard_changed", "watchdog_normal_stop_deny_changed",
    "watchdog_normal_stop_policy_invalid", "watchdog_normal_stop_policy_changed",
    "watchdog_foreign_normal_stop_intent", "watchdog_pid1_facts_invalid",
    "watchdog_pid1_facts_incomplete", "watchdog_pid1_readback_unavailable",
    "watchdog_pid1_invocation_not_real", "watchdog_pid1_stop_not_submitted",
    "watchdog_pid1_stop_job_invalid", "watchdog_private_unit_not_stopped",
    "watchdog_journal_changed", "watchdog_journal_short_write",
    "foreign_stop_intent", "stop_intent_not_durable", "private_cgroup_replaced",
})


def _recovery_error_token(error: BaseException | None) -> str:
    if error is None:
        return "none"
    if isinstance(error, Refused):
        reason = error.args[0] if len(error.args) == 1 else None
        if (type(reason) is str and
                reason in _RECOVERY_DIAGNOSTIC_REFUSALS and
                re.fullmatch(r"[a-z][a-z0-9_]{0,95}", reason)):
            return reason
        return "refused_other"
    if isinstance(error, subprocess.TimeoutExpired):
        return "timeout"
    if isinstance(error, OSError):
        return "os_error"
    if isinstance(error, ValueError):
        return "value_error"
    return "unexpected"


def _recovery_error_origin(error: BaseException | None) -> str:
    """Identify the checked source predicate without exposing exception data."""
    if error is None:
        return "none"
    files = {"aegis_auto_guard_policy.py": "policy",
             "aegis_auto_guardian.py": "guardian",
             "aegis_auto_native_witness.py": "witness",
             "aegis_auto_guardian_watchdog.py": "watchdog"}
    origins: list[str] = []
    trace = error.__traceback__
    for _ in range(32):
        if trace is None:
            break
        source = files.get(Path(trace.tb_frame.f_code.co_filename).name)
        if source is not None and 1 <= trace.tb_lineno <= 50000:
            origins.append(source + ":" + str(trace.tb_lineno))
        trace = trace.tb_next
    return "/".join(origins[-4:]) or "unavailable"


def _recovery_diagnostic(*, block: BaseException | None,
                         precheck: BaseException | None,
                         sticky: BaseException | None,
                         before: BaseException | None,
                         journal: BaseException | None,
                         stop: BaseException | None,
                         normal_stop: str, block_path: str,
                         settlement: dict[str, str]) -> str:
    # Only code-owned enum tokens and whitelisted refusal constants enter the
    # journal. Exception text, paths, units, IDs and command output never do.
    need(normal_stop in {"not_checked", "policy_unavailable", "true", "false",
                         "check_error"}, "watchdog_diagnostic_state_invalid")
    need(block_path in {"proven_stop", "reblock"},
         "watchdog_diagnostic_block_path_invalid")
    need(set(settlement) == {"await", "settle"} and
         settlement["await"] in {"not_called", "invalid_expected", "foreign_invocation",
                                 "settled", "guard_error", "deny_error", "unit_error",
                                 "settle_error", "deadline", "notify_error"} and
         settlement["settle"] in {"not_called", "invalid_expected",
                                  "before_invocation_changed", "before_not_inert",
                                  "job_read_error", "job_not_clear", "after_read_error",
                                  "after_invocation_changed", "load_state_changed",
                                  "after_not_inert", "settled"},
         "watchdog_diagnostic_settlement_invalid")
    return ("aegis_auto_watchdog_recovery_diagnostic "
            f"block={_recovery_error_token(block)} "
            f"precheck={_recovery_error_token(precheck)} "
            f"sticky={_recovery_error_token(sticky)} "
            f"before={_recovery_error_token(before)} "
            f"journal={_recovery_error_token(journal)} "
            f"stop={_recovery_error_token(stop)} "
            f"block_path={block_path} normal_stop={normal_stop} await={settlement['await']} "
            f"settle={settlement['settle']} "
            f"precheck_origin={_recovery_error_origin(precheck)} "
            f"block_origin={_recovery_error_origin(block)} "
            f"stop_origin={_recovery_error_origin(stop)}")


def _proven_normal_stop_policy(journal: dict[str, object], guard_fd: int) -> str | None:
    """Reuse an already sealed deny only for this exact normal Stop intent.

    The original held guard OFD, exact STOP identity and stable semantic
    no-client-grant proof remain mandatory. Any uncertainty re-enters the
    existing reblock path.
    """
    need(_guard_identity(guard_fd) ==
         (journal["guard_dev"], journal["guard_ino"]),
         "watchdog_normal_stop_guard_changed")
    if not _normal_stop_intent(journal):
        return None
    policy_sha = _semantic_blocked()
    need(type(policy_sha) is str and
         re.fullmatch(r"[0-9a-f]{64}", policy_sha) is not None,
         "watchdog_normal_stop_policy_invalid")
    need(_guard_identity(guard_fd) ==
         (journal["guard_dev"], journal["guard_ino"]) and
         _normal_stop_intent(journal) and
         _semantic_blocked() == policy_sha and
         _guard_identity(guard_fd) ==
         (journal["guard_dev"], journal["guard_ino"]),
         "watchdog_normal_stop_policy_changed")
    return policy_sha


def _recovery_policy(journal: dict[str, object], guard_fd: int) -> tuple[
        str | None, BaseException | None, BaseException | None, str]:
    precheck_error: BaseException | None = None
    try:
        proven = _proven_normal_stop_policy(journal, guard_fd)
        if proven is not None:
            return proven, None, None, "proven_stop"
    except BaseException as error:
        precheck_error = error
    try:
        return _block_same_ofd(guard_fd), None, precheck_error, "reblock"
    except BaseException as error:
        return None, error, precheck_error, "reblock"


def _recover(journal: dict[str, object], guard_fd: int,
             stage_fd: int | None = None) -> dict[str, object]:
    unit = str(journal["private_unit"])
    if stage_fd is not None:
        # COMMITTED_ACTIVE released the stage flock so a fresh read/stop may
        # enter. Reacquire its retained original OFD before the recovery
        # marker and before any kernel or PID1 inverse. Earlier phases still
        # hold this flock; requesting it again on the same OFD is idempotent.
        deadline = None
        already_blocked = False
        next_deny_check = 0.0
        while True:
            try:
                fcntl.flock(stage_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if deadline is None:
                    # A long wait is permitted only after the exact owned
                    # stop intent and current kernel policy prove egress is
                    # already blocked under this retained guard OFD. Unknown
                    # loss keeps a short refusal; journal/FDSTORE stay sticky.
                    _guard_identity(guard_fd)
                    already_blocked = _normal_stop_intent(journal)
                    wait = (STAGE_REACQUIRE_SECONDS if already_blocked else
                            UNPROVEN_STAGE_REACQUIRE_SECONDS)
                    deadline = time.monotonic() + wait
                    next_deny_check = time.monotonic() + 1.0
                if already_blocked and time.monotonic() >= next_deny_check:
                    _guard_identity(guard_fd)
                    need(_normal_stop_intent(journal),
                         "watchdog_deny_lost_during_stage_wait")
                    next_deny_check = time.monotonic() + 1.0
                need(time.monotonic() < deadline,
                     "watchdog_stage_recovery_lock_busy")
                _notify("WATCHDOG=1")
                time.sleep(0.1)
        _mark_stage_recovery(journal, stage_fd)
    _guard_identity(guard_fd)
    # REGISTER already left durable prestart state.  Revoke egress through
    # the exact held OFD before a potentially stalled PID1 readback.
    policy_sha, block_error, precheck_error, block_path = _recovery_policy(
        journal, guard_fd)
    before_error: BaseException | None = None
    try:
        before = _unit_facts(unit)
    except BaseException as error:
        before_error = error
        before = {"LoadState": "unknown", "ActiveState": "unknown",
                  "MainPID": "0", "InvocationID": "", "ControlGroup": ""}
    actual = before["InvocationID"]
    sticky_error: BaseException | None = None
    if HEX32.fullmatch(actual) is not None:
        try:
            _sticky_stop(str(journal["boot_id"]), unit, actual)
            if policy_sha is not None:
                intent = _json(_read_root(STOP_INTENT))
                need(intent.get("phase") in ("pending_deny", "deny_proven"),
                     "watchdog_stop_intent_missing")
                if intent["phase"] == "pending_deny":
                    _write_atomic(STOP_INTENT, {**intent, "phase": "deny_proven"},
                                  exclusive=False)
        except BaseException as error:
            sticky_error = error
    journal = {**journal, "phase": "RECOVERING",
               "observed_invocation_id": actual if HEX32.fullmatch(actual) else None}
    journal_error: BaseException | None = None
    try:
        _journal(journal)
    except BaseException as error:
        journal_error = error
    stop_error: BaseException | None = None
    stopped: dict[str, str] | None = None
    normal_stop_code = "not_checked" if policy_sha is not None else "policy_unavailable"
    settlement = {"await": "not_called", "settle": "not_called"}
    try:
        # The observer already bound the original private stop job. During a
        # clean PID1 shutdown this watchdog may receive SIGTERM after that
        # job completed; submitting another StopUnit creates a distinct job
        # for the same private unit and can invalidate terminal qualification.
        normal_stop = False
        if policy_sha is not None:
            try:
                normal_stop = _normal_stop_intent(journal)
                normal_stop_code = "true" if normal_stop else "false"
            except (Refused, OSError, ValueError):
                normal_stop_code = "check_error"
                pass  # Uncertain provenance retains the full StopUnit inverse.
        if normal_stop:
            stopped, before = _await_original_normal_stop(
                unit, before, journal, guard_fd, policy_sha, settlement)
        if stopped is None:
            stopped = _stop_private(unit, before,
                                    settled_normal_stop=normal_stop,
                                    expected_invocation=journal.get("invocation_id"))
    except BaseException as error:
        stop_error = error
    if (sticky_error is not None or block_error is not None or
            before_error is not None or journal_error is not None or
            stop_error is not None or policy_sha is None or stopped is None):
        print(_recovery_diagnostic(
            block=block_error, precheck=precheck_error, sticky=sticky_error,
            before=before_error,
            journal=journal_error, stop=stop_error,
            normal_stop=normal_stop_code, block_path=block_path,
            settlement=settlement),
            file=sys.stderr, flush=True)
    need(sticky_error is None and block_error is None and before_error is None and
         journal_error is None and stop_error is None and
         policy_sha is not None and stopped is not None,
         "watchdog_recovery_inverse_uncertain")
    need(_semantic_blocked() == policy_sha and
         stopped["ActiveState"] in ("inactive", "failed") and
         stopped["MainPID"] == "0" and not stopped["ControlGroup"],
         "watchdog_recovery_not_verified")
    guardian = _guardian_module()
    assessment_fd = guardian._stop_assessment_reservation(guard_fd)
    try:
        _retire_scoped_after_stop(journal, policy_sha)
        _retire_local_after_stop(journal, policy_sha)
        guardian._held_lock(assessment_fd, guardian.ASSESSMENT_LOCK)
    finally:
        os.close(assessment_fd)
    journal = {**journal, "phase": "RECOVERED", "policy_sha256": policy_sha}
    _journal(journal)
    return journal


def _archive_recovered(journal: dict[str, object]) -> str:
    need(journal.get("phase") == "RECOVERED" and
         type(journal.get("policy_sha256")) is str and
         _semantic_blocked() == journal["policy_sha256"],
         "watchdog_recovered_archive_without_deny")
    facts = _unit_facts(str(journal["private_unit"]))
    need(facts["ActiveState"] in ("inactive", "failed") and
         facts["MainPID"] == "0" and not facts["ControlGroup"],
         "watchdog_recovered_archive_without_stop")
    digest = _sha(_read_root(JOURNAL))
    archived = JOURNAL.with_name("auto-watchdog-" +
        str(journal["private_unit"])[11:75] + "-recovered-" +
        secrets.token_hex(8) + ".json")
    need(not archived.exists() and not archived.is_symlink(),
         "watchdog_recovery_archive_collision")
    os.replace(JOURNAL, archived)
    directory = os.open(JOURNAL.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return digest


def _normal_stop_intent(journal: dict[str, object]) -> bool:
    if not STOP_INTENT.exists() or STOP_INTENT.is_symlink():
        return False
    intent = _json(_read_root(STOP_INTENT))
    need(intent.get("schema") == "aegis_auto_stop_intent_v1" and
         intent.get("boot_id") == journal["boot_id"] and
         intent.get("service") == journal["private_unit"] and
         intent.get("invocation_id") == journal.get("invocation_id"),
         "watchdog_foreign_normal_stop_intent")
    return intent.get("phase") == "deny_proven" and bool(_semantic_blocked())


def _stop_request_proven(request: dict[str, object], journal: dict[str, object],
                         *, committed: bool, main_pidfd: int | None) -> bool:
    need(request in ({"op": "BEGIN_STOP"}, {"op": "CLASSIFY_STOP"}) and
         committed and main_pidfd is not None,
         "watchdog_normal_stop_not_proven")
    proven = _normal_stop_intent(journal)
    need(proven or request == {"op": "CLASSIFY_STOP"},
         "watchdog_normal_stop_not_proven")
    return proven


def _expected_main_stop(journal: dict[str, object], *, committed: bool,
                        worker_pidfd: int, guardian_pidfd: int,
                        guard_fd: int) -> bool:
    # Before COMMITTED_ACTIVE the original worker, guardian and guard OFD
    # remain mandatory. Only the exact latched Main and deny-proven STOP
    # intent may stop for compensation; no finalized terminal is invented.
    if not committed and not (
            journal["phase"] == "LATCHED" and _alive(worker_pidfd) and
            _alive(guardian_pidfd) and _guard_identity(guard_fd) ==
            (journal["guard_dev"], journal["guard_ino"])):
        return False
    return _normal_stop_intent(journal)


def _main_exit_stopping(fd: int, main_pidfd: int | None,
                        watcher: select.poll, journal: dict[str, object],
                        *, committed: bool, worker_pidfd: int,
                        guardian_pidfd: int, guard_fd: int) -> bool:
    if fd != main_pidfd or not _expected_main_stop(
            journal, committed=committed, worker_pidfd=worker_pidfd,
            guardian_pidfd=guardian_pidfd, guard_fd=guard_fd):
        return False
    watcher.unregister(main_pidfd)
    return True


def _fresh_block_with_retained_ofd() -> tuple[subprocess.Popen, int, Path]:
    """Queue restrictive recovery on an OFD already retained by this PID1 actor.

    The child may wait for a dying guardian, but its eventual flock is always
    visible on the watchdog's own FD table. No anonymous writer is introduced.
    """
    need(Path('/proc/self/cgroup').read_text() ==
         '0::/system.slice/aegis-auto-guardian-watchdog.service\n' and
         CGROUP.is_dir() and (CGROUP/'cgroup.controllers').exists(),
         'watchdog_cgroup_not_delegated')
    fd = os.open(GUARD_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    leaf = None
    try:
        held, named = os.fstat(fd), GUARD_LOCK.lstat()
        need(stat.S_ISREG(held.st_mode) and held.st_uid == 0 and held.st_nlink == 1 and
             stat.S_IMODE(held.st_mode) == 0o600 and
             (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
             'watchdog_recovery_guard_inode_changed')
        leaf = CGROUP / ('aegis-block-'+secrets.token_hex(8))
        leaf.mkdir(mode=0o700)
        need((leaf/'cgroup.kill').exists(), 'watchdog_cgroup_kill_unavailable')
        command = ('printf "0\\n" > "$3/cgroup.procs" || exit 111; '
                   '/usr/bin/flock -w 30 -x "$1" || exit 1; exec /bin/bash "$2" block')
        proc = subprocess.Popen(['/bin/bash','--noprofile','--norc','-c',command,
            'aegis-watchdog-block',str(fd),str(HELPER),str(leaf)], start_new_session=True,
            pass_fds=(fd,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env={'PATH':'/usr/sbin:/usr/bin:/bin',
                'LANG':'C','LC_ALL':'C','AEGIS_AUTO_HELD_GUARD_FD':str(fd)})
        return proc, fd, leaf
    except BaseException:
        os.close(fd)
        if leaf is not None:
            try: leaf.rmdir()
            except OSError: pass
        raise


def _close_fresh_block(block, fd, leaf):
    deadline = time.monotonic() + 2.0
    try:
        if 'populated 0\n' not in (leaf/'cgroup.events').read_text():
            (leaf/'cgroup.kill').write_text('1\n')
        remaining = deadline - time.monotonic()
        need(remaining > 0, 'watchdog_fresh_block_cgroup_populated')
        block.wait(timeout=remaining)
        # cgroup.kill is asynchronous for descendants. Reaping the direct
        # child does not prove whole-leaf quiescence. Keep the retained OFD
        # until the kernel reports empty, within the original total2s budget.
        while 'populated 0\n' not in (leaf/'cgroup.events').read_text():
            remaining = deadline - time.monotonic()
            need(remaining > 0, 'watchdog_fresh_block_cgroup_populated')
            time.sleep(min(0.01, remaining))
    finally:
        os.close(fd)
        try: leaf.rmdir()
        except OSError: pass


def _recover_without_original_ofd(journal: dict[str, object]) -> None:
    """Emergency fallback when PID1 lost its stored OFD: revoke owners first.

    This never acknowledges recovery unless a fresh helper block and complete
    kernel/PID1 readback succeed.  The pending journal stays sticky on error.
    """
    journal = {**journal, "phase": "RECOVERING_NO_OFD"}
    _journal(journal)
    block, recovery_fd, leaf = _fresh_block_with_retained_ofd()
    try:
        # The fixed guardian unit is the only authorized holder of the
        # original registration channel.  Stopping it releases the worker
        # lease; the helper was already submitted and waits for the flock.
        guardian_stop = subprocess.run(
            ["/usr/bin/systemctl", "stop", "aegis-auto-guardian.service"],
            capture_output=True, timeout=5, check=False)
        need(guardian_stop.returncode == 0, "watchdog_guardian_stop_uncertain")
        before = _unit_facts(str(journal["private_unit"]))
        actual = before["InvocationID"]
        if HEX32.fullmatch(actual) is not None:
            _sticky_stop(str(journal["boot_id"]), str(journal["private_unit"]), actual)
        stopped = _stop_private(str(journal["private_unit"]), before)
        need(block.wait(timeout=5) == 0, "watchdog_fresh_block_failed")
        policy_sha = _semantic_blocked()
        need(stopped["ActiveState"] in ("inactive", "failed") and
             stopped["MainPID"] == "0" and not stopped["ControlGroup"],
             "watchdog_emergency_private_not_stopped")
        guardian = _guardian_module()
        assessment_fd = guardian._stop_assessment_reservation(recovery_fd)
        try:
            _retire_scoped_after_stop(journal, policy_sha)
            _retire_local_after_stop(journal, policy_sha)
            guardian._held_lock(assessment_fd, guardian.ASSESSMENT_LOCK)
        finally:
            os.close(assessment_fd)
        _journal({**journal, "phase": "RECOVERED", "policy_sha256": policy_sha,
                  "recovered_without_original_ofd": True})
    finally:
        _close_fresh_block(block, recovery_fd, leaf)


def _recover_after_reboot(journal: dict[str, object]) -> None:
    current_boot = _boot()
    need(journal.get("boot_id") != current_boot,
         "watchdog_reboot_recovery_not_needed")
    journal = {**journal, "phase": "RECOVERING_AFTER_REBOOT",
               "recovery_boot_id": current_boot}
    _journal(journal)
    block, recovery_fd, leaf = _fresh_block_with_retained_ofd()
    try:
        need(block.wait(timeout=12) == 0, "watchdog_reboot_block_failed")
        policy_sha = _semantic_blocked()
        before = _unit_facts(str(journal["private_unit"]))
        actual = before["InvocationID"]
        guardian = _guardian_module()
        old_intent_path = guardian.STOP_INTENT
        if old_intent_path.exists() or old_intent_path.is_symlink():
            transition = guardian.verified_module(
                guardian.ROOT/'aegis_auto_boot_transition.py',
                'aegis_auto_boot_transition')
            marker_path, marker, _source, _store = transition.qualify_old_marker(current_boot)
            old_intent = guardian.record(old_intent_path)
            need(marker_path.exists() and marker['old_boot_id'] == journal['boot_id'] and
                 old_intent.get('service') == journal['private_unit'] and
                 old_intent.get('invocation_id') == journal.get('invocation_id'),
                 'watchdog_old_terminal_marker_changed')
        elif HEX32.fullmatch(actual) is not None:
            _sticky_stop(current_boot, str(journal["private_unit"]), actual)
        stopped = _stop_private(str(journal["private_unit"]), before)
        need(stopped["ActiveState"] in ("inactive", "failed") and
             stopped["MainPID"] == "0" and not stopped["ControlGroup"] and
             _semantic_blocked() == policy_sha,
             "watchdog_reboot_inverse_uncertain")
        guardian = _guardian_module()
        assessment_fd = guardian._stop_assessment_reservation(recovery_fd)
        try:
            _retire_scoped_after_stop(journal, policy_sha, reboot=True)
            _retire_local_after_stop(journal, policy_sha, reboot=True)
            guardian._held_lock(assessment_fd, guardian.ASSESSMENT_LOCK)
        finally:
            os.close(assessment_fd)
        _journal({**journal, "phase": "RECOVERED", "policy_sha256": policy_sha})
    finally:
        _close_fresh_block(block, recovery_fd, leaf)


def _startup_replay() -> None:
    stored = _inherited_guard_fd()
    if not JOURNAL.exists() and not JOURNAL.is_symlink():
        need(stored is None, "watchdog_orphan_pid1_fdstore")
        return
    journal = _json(_read_root(JOURNAL))
    need(journal.get("schema") == "aegis_auto_watchdog_pending_v1" and
         type(journal.get("private_unit")) is str and
         PRIVATE.fullmatch(journal["private_unit"]) is not None,
         "watchdog_pending_journal_untrusted")
    if journal.get("boot_id") != _boot():
        need(stored is None, "watchdog_cross_boot_original_ofd_impossible")
        _recover_after_reboot(journal)
        _archive_recovered(_json(_read_root(JOURNAL)))
        return
    if stored is not None:
        stored_guard, stored_stage = stored
        need(_guard_identity(stored_guard) ==
             (journal.get("guard_dev"), journal.get("guard_ino")),
             "watchdog_stored_guard_identity_changed")
        stage = os.fstat(stored_stage)
        need((stage.st_dev, stage.st_ino) ==
             (journal.get("stage_dev"), journal.get("stage_ino")),
             "watchdog_stored_stage_identity_changed")
        journal = _recover(journal, stored_guard, stored_stage)
        _remove_guard_fd()
        _archive_recovered(journal)
    else:
        _recover_without_original_ofd(journal)
        _archive_recovered(_json(_read_root(JOURNAL)))


def _send(peer: socket.socket, value: dict[str, object]) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    need(len(raw) <= MAX_CONTROL and peer.send(raw) == len(raw),
         "watchdog_response_failed")


def _recv(peer: socket.socket) -> dict[str, object]:
    raw, anc, flags, _ = peer.recvmsg(MAX_CONTROL)
    need(raw and not anc and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0,
         "invalid_watchdog_request")
    return _json(raw)


def _register(peer: socket.socket) -> tuple[dict[str, object], int, int, int, int]:
    guardian_pid, guardian_pidfd = _guardian_peer(peer)
    descriptors = array.array("i")
    created = False
    store_attempted = False
    journal: dict[str, object] | None = None
    try:
        raw, anc, flags, _ = peer.recvmsg(MAX_CONTROL, socket.CMSG_SPACE(12))
        foreign_ancillary = False
        for level, kind, data in anc:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors.frombytes(data[:len(data) - len(data) % 4])
            else:
                foreign_ancillary = True
        need(raw and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0 and
             not foreign_ancillary,
             "watchdog_registration_truncated_or_foreign_ancillary")
        request = _json(raw)
        need(set(request) == {"op", "boot_id", "private_unit", "worker_pid"} and
             request["op"] == "REGISTER" and
             request["boot_id"] == _boot() and
             type(request["private_unit"]) is str and
             PRIVATE.fullmatch(request["private_unit"]) is not None and
             type(request["worker_pid"]) is int and request["worker_pid"] > 1 and
             len(descriptors) == 3 and
             _pidfd_pid(descriptors[1]) == request["worker_pid"] and
             _alive(descriptors[1]) and _alive(guardian_pidfd),
             "watchdog_registration_invalid")
        guard_fd, worker_pidfd, stage_fd = descriptors
        guard_dev, guard_ino = _guard_identity(guard_fd)
        stage = os.fstat(stage_fd)
        stage_fdinfo = Path(f"/proc/self/fdinfo/{stage_fd}").read_text(
            encoding="ascii")
        need(stat.S_ISDIR(stage.st_mode) and stage.st_uid == 0 and
             stage.st_mode & 0o022 == 0 and
             _exclusive_flock_fdinfo(stage_fdinfo, stage),
             "watchdog_stage_fd_untrusted")
        before = _unit_facts(str(request["private_unit"]))
        need(before["ActiveState"] in ("inactive", "failed") and
             before["MainPID"] == "0" and not before["ControlGroup"],
             "private_unit_already_started")
        journal = {"schema": "aegis_auto_watchdog_pending_v1",
                   "boot_id": request["boot_id"],
                   "private_unit": request["private_unit"],
                   "guardian_pid": guardian_pid,
                   "worker_pid": request["worker_pid"],
                   "guard_dev": guard_dev, "guard_ino": guard_ino,
                   "stage_dev": stage.st_dev, "stage_ino": stage.st_ino,
                   "phase": "REGISTERED", "invocation_id": None}
        # PID1 must retain both original lock OFDs before the pending journal
        # becomes durable. A crash between these operations leaves an orphan
        # FD store and no ARMED reply; it cannot leave a journal whose replay
        # lacks the original stage lock needed to revoke reentry first.
        store_attempted = True
        _store_guard_fd(guard_fd, stage_fd)
        _journal(journal, create=True)
        created = True
        need(_alive(guardian_pidfd) and _alive(worker_pidfd) and
             _guard_identity(guard_fd) == (guard_dev, guard_ino),
             "watchdog_registration_lease_lost")
        _send(peer, {"state": "ARMED", "boot_id": request["boot_id"],
                     "private_unit": request["private_unit"],
                     "guardian_pid": guardian_pid,
                     "worker_pid": request["worker_pid"],
                     "guard_dev": guard_dev, "guard_ino": guard_ino,
                     "stage_dev": stage.st_dev, "stage_ino": stage.st_ino,
                     "journal_sha256": _sha(_read_root(JOURNAL)),
                     "held_guard_ofd": True, "held_pidfds": 2,
                     "held_stage_fd": True})
        return journal, guard_fd, worker_pidfd, guardian_pidfd, stage_fd
    except BaseException:
        own_journal = created
        if not own_journal and store_attempted and journal is not None:
            try:
                own_journal = _json(_read_root(JOURNAL)) == journal
            except (Refused, OSError, ValueError):
                pass
        if len(descriptors) == 3 and own_journal and journal is not None:
            try:
                recovered = _recover(journal, descriptors[0], descriptors[2])
                _remove_guard_fd()
                _archive_recovered(recovered)
            except (Refused, OSError, ValueError, subprocess.TimeoutExpired):
                pass
        elif len(descriptors) == 3 and store_attempted:
            # No ARMED response and no durable transaction: release only an
            # orphaned pre-effect FD store, after PID1 confirms its removal.
            try:
                _remove_guard_fd()
            except (Refused, OSError, ValueError):
                pass
        for fd in descriptors:
            os.close(fd)
        os.close(guardian_pidfd)
        raise



def _serve_bpf_query(peer: socket.socket) -> bool:
    """One fixed read-only request; it cannot register, alter or stop a lease."""
    peer.settimeout(3.0)
    raw=peer.recv(MAX_CONTROL,socket.MSG_PEEK)
    request=_json(raw)
    if request.get('op')!='BPF_READ':return False
    peer_pid,peer_pidfd=_guardian_peer(peer)
    try:
        _own_source()
        request=_recv(peer)
        interfaces=request.get('interfaces')
        need(set(request)=={'op','boot_id','interfaces'} and
             request['boot_id']==_boot() and type(interfaces) is list and
             1<=len(interfaces)<=3 and
             all(type(x) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',x)
                 for x in interfaces) and len(set(interfaces))==len(interfaces),'invalid_read_only_bpf_query')
        guardian=_guardian_module()
        foreign=guardian.verified_module(guardian.FOREIGN_SOURCE,'aegis_auto_foreign_policy')
        foreign._local_bpf_bindings(interfaces)
        need(_alive(peer_pidfd),'BPF query guardian disappeared')
        _send(peer,{'state':'BPF_EMPTY','boot_id':_boot(),
                    'interfaces':interfaces,'guardian_pid':peer_pid})
        return True
    finally:os.close(peer_pidfd)


def privileged_bpf_query(interfaces: list[str]) -> None:
    """Guardian-only client for the actor's existing SYS_ADMIN inventory."""
    _own_source()
    need(type(interfaces) is list and 1<=len(interfaces)<=3 and
         all(type(x) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',x)
             for x in interfaces) and len(set(interfaces))==len(interfaces),
         'invalid_read_only_bpf_query')
    named=AUTHORITY.stat(follow_symlinks=False)
    need(stat.S_ISSOCK(named.st_mode) and named.st_uid==0 and
         stat.S_IMODE(named.st_mode)==0o600,'untrusted_BPF_actor_socket')
    actor_pidfd=None
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as peer:
        peer.settimeout(3.0);peer.connect(str(AUTHORITY))
        try:
            pid,uid,_=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            raw=peer.getsockopt(socket.SOL_SOCKET,getattr(socket,'SO_PEERPIDFD',77),4)
            need(len(raw)==4,'BPF actor pidfd unavailable')
            actor_pidfd=struct.unpack('i',raw)[0]
            before=_unit_facts(UNIT,actor=True)
            need(uid==0 and pid>1 and _pidfd_pid(actor_pidfd)==pid and
                 _alive(actor_pidfd) and before['MainPID']==str(pid) and
                 before['ActiveState']=='active' and
                 Path(f'/proc/{pid}/cgroup').read_text(encoding='ascii')==
                 '0::/system.slice/aegis-auto-guardian-watchdog.service\n' and
                 os.stat(f'/proc/{pid}/ns/net').st_ino==os.stat('/proc/self/ns/net').st_ino,
                 'foreign_BPF_actor')
            _send(peer,{'op':'BPF_READ','boot_id':_boot(),'interfaces':interfaces})
            reply=_recv(peer)
            need(reply=={'state':'BPF_EMPTY','boot_id':_boot(),
                         'interfaces':interfaces,'guardian_pid':os.getpid()} and
                 _alive(actor_pidfd) and _unit_facts(UNIT,actor=True)==before,'BPF actor proof changed')
        finally:
            if actor_pidfd is not None:os.close(actor_pidfd)


def _serve_pending_bpf(listener: socket.socket) -> None:
    """Service one fixed inventory read without replacing an active lease."""
    peer, _ = listener.accept()
    try:
        peer.settimeout(3.0)
        need(_serve_bpf_query(peer), "active_lease_read_only_query_required")
    except (Refused, OSError, ValueError, subprocess.TimeoutExpired):
        try:
            _send(peer, {"state": "REFUSED", "reason": "read_only_inventory_refused"})
        except OSError:
            pass
    finally:
        peer.close()


def _lease_events(watcher: select.poll, listener: socket.socket | None):
    for fd, event in watcher.poll(200):
        if listener is not None and fd == listener.fileno():
            need(event & select.POLLIN and not event & (
                select.POLLHUP | select.POLLERR | select.POLLNVAL),
                "watchdog_inventory_listener_failed")
            _serve_pending_bpf(listener)
            continue
        yield fd, event


def _session(peer: socket.socket, listener: socket.socket | None = None) -> None:
    if _serve_bpf_query(peer):return
    peer.settimeout(None)
    journal, guard_fd, worker_pidfd, guardian_pidfd, stage_fd = _register(peer)
    recovering = False
    completed = False
    committed = False
    stopping = False
    stopping_deadline: float | None = None
    main_pidfd: int | None = None
    commit_phase: str | None = None
    try:
        peer.setblocking(False)
        watcher = select.poll()
        watcher.register(peer, select.POLLIN | select.POLLHUP | select.POLLERR)
        watcher.register(worker_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        watcher.register(guardian_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if listener is not None:
            watcher.register(listener, select.POLLIN | select.POLLHUP | select.POLLERR)
        prestart_deadline = time.monotonic() + 90.0
        while True:
            _notify("WATCHDOG=1")
            if STOP_REQUESTED:
                # A clean PID1 stop is also an inverse. Do not return and
                # discard PID1's stored OFDs while a private unit may run.
                recovering = True
                journal = _recover(journal, guard_fd, stage_fd)
                _remove_guard_fd()
                _archive_recovered(journal)
                return
            if journal["phase"] == "REGISTERED" and time.monotonic() >= prestart_deadline:
                recovering = True
                journal = _recover(journal, guard_fd, stage_fd)
                _remove_guard_fd()
                _archive_recovered(journal)
                return
            if stopping_deadline is not None and time.monotonic() >= stopping_deadline:
                recovering = True
                journal = _recover(journal, guard_fd, stage_fd)
                _remove_guard_fd()
                _archive_recovered(journal)
                return
            for fd, event in _lease_events(watcher, listener):
                if _main_exit_stopping(
                        fd, main_pidfd, watcher, journal,
                        committed=committed, worker_pidfd=worker_pidfd,
                        guardian_pidfd=guardian_pidfd, guard_fd=guard_fd):
                    stopping = True
                    stopping_deadline = time.monotonic() + STOPPING_SECONDS
                    continue
                if fd == guardian_pidfd or fd == main_pidfd or (
                        fd == worker_pidfd and not committed) or event & (
                            select.POLLHUP | select.POLLERR):
                    recovering = True
                    journal = _recover(journal, guard_fd, stage_fd)
                    _remove_guard_fd()
                    _archive_recovered(journal)
                    return
                peer.setblocking(True)
                try:
                    request = _recv(peer)
                finally:
                    peer.setblocking(False)
                if request.get("op") == "LATCH":
                    invocation = request.get("invocation_id")
                    need(set(request) == {"op", "invocation_id"} and
                         type(invocation) is str and
                         HEX32.fullmatch(invocation) is not None and
                         journal["phase"] == "REGISTERED", "invalid_watchdog_latch")
                    facts = _unit_facts(str(journal["private_unit"]))
                    need(facts["InvocationID"] == invocation and
                         facts["ActiveState"] == "active" and
                         facts["ControlGroup"] ==
                         "/system.slice/" + str(journal["private_unit"]) and
                         facts["MainPID"].isdigit() and int(facts["MainPID"]) > 1,
                         "watchdog_pid1_latch_mismatch")
                    main_pid, main_pidfd, main_cgroup = _private_main_pidfd(
                        str(journal["private_unit"]), invocation)
                    watcher.register(main_pidfd,
                                     select.POLLIN | select.POLLHUP | select.POLLERR)
                    journal = {**journal, "phase": "LATCHED", "invocation_id": invocation,
                               "private_main_pid": main_pid,
                               "private_cgroup": main_cgroup}
                    _journal(journal)
                    _send(peer, {"state": "LATCHED", "private_unit":
                                 journal["private_unit"], "invocation_id": invocation,
                                 "private_main_pid": main_pid,
                                 "private_cgroup": main_cgroup,
                                 "journal_sha256": _sha(_read_root(JOURNAL))})
                elif request.get("op") == "COMMIT_ACTIVE":
                    commit_phase = "request"
                    (terminal_sha256, capture_sha256,
                     original_policy_sha256,
                     post_policy_sha256) = _commit_request_hashes(request)
                    need(journal["phase"] == "LATCHED" and
                         main_pidfd is not None and _alive(main_pidfd) and
                         _alive(worker_pidfd),
                         "watchdog_commit_before_live_latch")
                    commit_phase = "sealed_stage"
                    policy_sha = _finalized_stage(
                        stage_fd, str(journal["private_unit"]),
                        terminal_sha256, str(journal["invocation_id"]),
                        capture_sha256, original_policy_sha256,
                        post_policy_sha256)
                    commit_phase = "durable_journal"
                    journal = {**journal, "phase": "COMMITTED_ACTIVE",
                               "terminal_sha256": terminal_sha256,
                               "policy_sha256": policy_sha}
                    _journal(journal)
                    commit_phase = "stage_flock_release"
                    # Terminal, archive and handoff absence were checked
                    # before this durable journal. The private Main watchdog
                    # now owns recovery; a fresh StageGuard may read Finalized
                    # and initiate its own stopped inverse. PID1 retains this
                    # exact directory OFD for a later bounded reacquire.
                    fcntl.flock(stage_fd, fcntl.LOCK_UN)
                    watcher.unregister(worker_pidfd)
                    committed = True
                    commit_phase = "acknowledgement"
                    _send(peer, {"state": "COMMITTED_ACTIVE",
                                 "terminal_sha256": terminal_sha256,
                                 "private_main_pid": journal["private_main_pid"],
                                 "invocation_id": journal["invocation_id"],
                                 "policy_sha256": policy_sha,
                                 "journal_sha256": _sha(_read_root(JOURNAL))})
                    commit_phase = None
                elif request == {"op": "LIVE"}:
                    need((committed or _alive(worker_pidfd)) and
                         (not committed or (main_pidfd is not None and
                                            (_alive(main_pidfd) or
                                             (stopping and bool(_semantic_blocked()))))) and
                         _alive(guardian_pidfd) and
                         _guard_identity(guard_fd) ==
                         (journal["guard_dev"], journal["guard_ino"]),
                         "watchdog_lease_not_live")
                    _send(peer, {"state": "LIVE", "phase": journal["phase"]})
                elif (set(request) == {"op", "deadline_ns"} and
                      request.get("op") == "INSPECT_ACTIVE" and
                      type(request.get("deadline_ns")) is int and
                      time.monotonic_ns() < request["deadline_ns"] <=
                      time.monotonic_ns() + 4_000_000_000):
                    need(committed and not stopping and
                         journal["phase"] == "COMMITTED_ACTIVE" and
                         main_pidfd is not None and _alive(main_pidfd) and
                         _alive(guardian_pidfd) and
                         _guard_identity(guard_fd) ==
                         (journal["guard_dev"], journal["guard_ino"]) and
                         _json(_read_root(JOURNAL)) == journal,
                         "watchdog_active_inspection_not_live")
                    module = _guardian_module()
                    terminal_raw = module._protected_stage_receipt(
                        stage_fd, "receipts/activation-owner/terminal.json")
                    terminal = json.loads(terminal_raw,
                                          object_pairs_hook=module.unique)
                    native = terminal.get("native_guard")
                    capture_sha = terminal.get("native_capture_sha256")
                    need(type(native) is dict and
                         set(native) == {"guardian_pid", "guardian_nonce",
                                         "guardian_receipt_sha256",
                                         "policy_sha256"} and
                         native["guardian_pid"] == journal["guardian_pid"] and
                         all(type(native[key]) is str and
                             re.fullmatch(r"[0-9a-f]{64}", native[key]) is not None
                             for key in ("guardian_nonce",
                                         "guardian_receipt_sha256",
                                         "policy_sha256")) and
                         type(capture_sha) is str and
                         re.fullmatch(r"[0-9a-f]{64}", capture_sha) is not None,
                         "watchdog_active_terminal_changed")
                    current_policy = _finalized_stage(
                        stage_fd, str(journal["private_unit"]),
                        str(journal["terminal_sha256"]),
                        str(journal["invocation_id"]), capture_sha,
                        native["policy_sha256"], str(journal["policy_sha256"]),
                        deadline=request["deadline_ns"] / 1_000_000_000)
                    facts = _unit_facts(str(journal["private_unit"]))
                    need(facts["ActiveState"] == "active" and
                         facts["MainPID"] == str(journal["private_main_pid"]) and
                         _pidfd_pid(main_pidfd) == journal["private_main_pid"] and
                         current_policy == journal["policy_sha256"],
                         "watchdog_active_main_changed")
                    _send(peer, {"state": "INSPECTED_ACTIVE",
                                 "private_unit": journal["private_unit"],
                                 "invocation_id": journal["invocation_id"],
                                 "private_main_pid": journal["private_main_pid"],
                                 "guardian_pid": journal["guardian_pid"],
                                 "native_guard": native,
                                 "terminal_sha256": journal["terminal_sha256"],
                                 "policy_sha256": current_policy,
                                 "journal_sha256": _sha(_read_root(JOURNAL))})
                elif request in ({"op": "BEGIN_STOP"}, {"op": "CLASSIFY_STOP"}):
                    proven = _stop_request_proven(request, journal,
                        committed=committed, main_pidfd=main_pidfd)
                    if request["op"] == "CLASSIFY_STOP" and not proven:
                        # A read-only classification is not a typed Stop
                        # request. Keep the original authority alive so the
                        # guardian can still request the restrictive inverse.
                        _send(peer, {"state": "NOT_STOPPING"})
                        continue
                    if not stopping:
                        watcher.unregister(main_pidfd)
                        stopping = True
                        stopping_deadline = time.monotonic() + STOPPING_SECONDS
                    _send(peer, {"state": "STOPPING", "invocation_id":
                                 journal["invocation_id"],
                                 "policy_sha256": _semantic_blocked()})
                elif (set(request) == {"op", "reason"} and
                      request.get("op") == "FAIL_CLOSED" and
                      request.get("reason") in ("launch_channel_lost",
                                                "prestart_abort",
                                                "owner_lease_lost",
                                                "guardian_abort", "foreign_policy_drift")):
                    recovering = True
                    journal = _recover(journal, guard_fd, stage_fd)
                    _remove_guard_fd()
                    receipt_sha = _archive_recovered(journal)
                    _send(peer, {"state": "RECOVERED", "reason": request["reason"],
                                 "policy_sha256": journal["policy_sha256"],
                                 "journal_sha256": receipt_sha})
                    return
                elif request == {"op": "DISARM"}:
                    facts = _unit_facts(str(journal["private_unit"]))
                    need(facts["ActiveState"] in ("inactive", "failed") and
                         facts["MainPID"] == "0" and not facts["ControlGroup"] and
                         not STOP_INTENT.exists() and not STOP_INTENT.is_symlink(),
                         "watchdog_disarm_before_verified_stop")
                    policy_sha = _semantic_blocked()
                    journal = {**journal, "phase": "DISARMED",
                               "policy_sha256": policy_sha}
                    _journal(journal)
                    _remove_guard_fd()
                    archived = JOURNAL.with_name(
                        "auto-watchdog-" + str(journal["private_unit"])[11:75] +
                        "-disarmed.json")
                    need(not archived.exists() and not archived.is_symlink(),
                         "watchdog_archive_already_present")
                    os.replace(JOURNAL, archived)
                    directory = os.open(JOURNAL.parent,
                                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                    _send(peer, {"state": "DISARMED", "policy_sha256": policy_sha})
                    completed = True
                    return
                else:
                    raise Refused("unexpected_watchdog_command")
    except BaseException as error:
        if commit_phase is not None:
            try:
                print(_commit_refusal_diagnostic(commit_phase, error),
                      file=sys.stderr, flush=True)
            except OSError:
                pass  # Diagnostic failure cannot delay independent recovery.
        if not recovering and not completed:
            try:
                journal = _recover(journal, guard_fd, stage_fd)
                _remove_guard_fd()
                _archive_recovered(journal)
            except (Refused, OSError, ValueError, subprocess.TimeoutExpired):
                pass
        raise
    finally:
        os.close(guard_fd)
        os.close(worker_pidfd)
        os.close(guardian_pidfd)
        os.close(stage_fd)
        if main_pidfd is not None:
            os.close(main_pidfd)


@dataclass
class WatchdogClient:
    """Guardian-side held prearm lease; closing it triggers independent STOP."""

    authority: socket.socket | None = None
    actor_pidfd: int | None = None
    private_unit: str | None = None
    guard_identity: tuple[int, int] | None = None
    guard_fd: int | None = None

    def arm(self, *, guard_fd: int, worker_pidfd: int, stage_fd: int,
            private_unit: str) -> dict[str, object]:
        need(self.authority is None and PRIVATE.fullmatch(private_unit) is not None,
             "watchdog_client_already_armed_or_bad_unit")
        _own_source()
        guard_identity = _guard_identity(guard_fd)
        stage = os.fstat(stage_fd)
        need(stat.S_ISDIR(stage.st_mode) and stage.st_uid == 0 and
             stage.st_mode & 0o022 == 0, "watchdog_client_stage_untrusted")
        worker_pid = _pidfd_pid(worker_pidfd)
        need(_alive(worker_pidfd), "watchdog_worker_already_dead")
        named = AUTHORITY.stat(follow_symlinks=False)
        need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
             stat.S_IMODE(named.st_mode) == 0o600,
             "watchdog_authority_untrusted")
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        actor_pidfd: int | None = None
        retained_guard: int | None = None
        try:
            retained_guard = os.dup(guard_fd)
            peer.settimeout(5.0)
            peer.connect(str(AUTHORITY))
            pid, uid, _gid = struct.unpack("3i", peer.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            raw = peer.getsockopt(socket.SOL_SOCKET,
                                  getattr(socket, "SO_PEERPIDFD", 77), 4)
            need(len(raw) == 4, "watchdog_actor_pidfd_unavailable")
            actor_pidfd = struct.unpack("i", raw)[0]
            need(uid == 0 and pid > 1 and _pidfd_pid(actor_pidfd) == pid and
                 _alive(actor_pidfd) and
                 Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
                 "0::/system.slice/aegis-auto-guardian-watchdog.service\n",
                 "foreign_watchdog_actor")
            request = {"op": "REGISTER", "boot_id": _boot(),
                       "private_unit": private_unit, "worker_pid": worker_pid}
            payload = json.dumps(request, sort_keys=True,
                                 separators=(",", ":")).encode()
            rights = array.array("i", [guard_fd, worker_pidfd, stage_fd])
            need(peer.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                           rights.tobytes())]) == len(payload),
                 "watchdog_registration_send_failed")
            ack = _recv(peer)
            need(ack == {"state": "ARMED", "boot_id": _boot(),
                         "private_unit": private_unit, "guardian_pid": os.getpid(),
                         "worker_pid": worker_pid, "guard_dev": guard_identity[0],
                         "guard_ino": guard_identity[1],
                         "stage_dev": stage.st_dev, "stage_ino": stage.st_ino,
                         "journal_sha256": ack.get("journal_sha256"),
                         "held_guard_ofd": True, "held_pidfds": 2,
                         "held_stage_fd": True} and
                 type(ack["journal_sha256"]) is str and
                 re.fullmatch(r"[0-9a-f]{64}", ack["journal_sha256"]) and
                 ack["journal_sha256"] == _sha(_read_root(JOURNAL)) and
                 _alive(actor_pidfd), "watchdog_prearm_ack_invalid")
            self.authority = peer
            self.actor_pidfd = actor_pidfd
            self.private_unit = private_unit
            self.guard_identity = guard_identity
            self.guard_fd = retained_guard
            retained_guard = None
            return ack
        except BaseException:
            peer.close()
            if actor_pidfd is not None:
                os.close(actor_pidfd)
            if retained_guard is not None:
                os.close(retained_guard)
            raise

    def _live(self) -> None:
        need(self.authority is not None and self.actor_pidfd is not None and
             self.private_unit is not None and self.guard_fd is not None and
             _alive(self.actor_pidfd),
             "watchdog_client_actor_not_live")
        watcher = select.poll()
        watcher.register(self.authority, select.POLLHUP | select.POLLERR)
        need(not watcher.poll(0), "watchdog_client_socket_closed")

    def borrow_guard_fd(self) -> int:
        """Lend the original locked OFD for exact STOP and inverse only."""
        self._live()
        need(self.guard_fd is not None and self.guard_identity is not None and
             _guard_identity(self.guard_fd) == self.guard_identity,
             "watchdog_original_guard_lock_lost")
        return os.dup(self.guard_fd)

    def latch(self, invocation_id: str) -> dict[str, object]:
        self._live()
        need(HEX32.fullmatch(invocation_id) is not None,
             "watchdog_latch_invocation_invalid")
        _send(self.authority, {"op": "LATCH", "invocation_id": invocation_id})
        reply = _recv(self.authority)
        need(reply.get("state") == "LATCHED" and
             reply.get("private_unit") == self.private_unit and
             reply.get("invocation_id") == invocation_id and
             type(reply.get("private_main_pid")) is int and
             reply["private_main_pid"] > 1 and
             reply.get("private_cgroup") ==
             "/system.slice/" + str(self.private_unit) and
             reply.get("journal_sha256") == _sha(_read_root(JOURNAL)),
             "watchdog_latch_not_durable")
        return reply

    def commit_active(self, terminal_sha256: str, *, capture_sha256: str,
                      original_policy_sha256: str,
                      post_policy_sha256: str) -> dict[str, object]:
        self._live()
        need(all(type(value) is str and
                 re.fullmatch(r"[0-9a-f]{64}", value) is not None
                 for value in (terminal_sha256, capture_sha256,
                               original_policy_sha256, post_policy_sha256)),
             "watchdog_commit_terminal_digest_invalid")
        _send(self.authority, {"op": "COMMIT_ACTIVE",
                               "terminal_sha256": terminal_sha256,
                               "capture_sha256": capture_sha256,
                               "original_policy_sha256":
                               original_policy_sha256,
                               "post_policy_sha256": post_policy_sha256})
        reply = _recv(self.authority)
        need(reply.get("state") == "COMMITTED_ACTIVE" and
             reply.get("terminal_sha256") == terminal_sha256 and
             type(reply.get("private_main_pid")) is int and
             type(reply.get("policy_sha256")) is str and
             reply["policy_sha256"] == post_policy_sha256 and
             reply.get("journal_sha256") == _sha(_read_root(JOURNAL)),
             "watchdog_active_commit_unconfirmed")
        return reply

    def revalidate(self) -> dict[str, object]:
        self._live()
        _send(self.authority, {"op": "LIVE"})
        reply = _recv(self.authority)
        need(reply in ({"state": "LIVE", "phase": "REGISTERED"},
                       {"state": "LIVE", "phase": "LATCHED"},
                       {"state": "LIVE", "phase": "COMMITTED_ACTIVE"}),
             "watchdog_revalidation_refused")
        return reply

    def inspect_active(self, *, deadline: float) -> dict[str, object]:
        """Read the watchdog's retained finalized authority; no new lease."""
        self._live()
        need(type(deadline) is float and
             time.monotonic() < deadline <= time.monotonic() + 4.0,
             "watchdog_active_inspection_deadline_invalid")
        _send(self.authority, {"op": "INSPECT_ACTIVE",
                               "deadline_ns": int(deadline * 1_000_000_000)})
        reply = _recv(self.authority)
        need(type(reply) is dict and set(reply) == {
            "state", "private_unit", "invocation_id", "private_main_pid",
            "guardian_pid", "native_guard", "terminal_sha256",
            "policy_sha256", "journal_sha256"} and
            reply["state"] == "INSPECTED_ACTIVE" and
            reply["private_unit"] == self.private_unit and
            type(reply["private_main_pid"]) is int and
            reply["private_main_pid"] > 1 and
            type(reply["guardian_pid"]) is int and reply["guardian_pid"] > 1 and
            type(reply["invocation_id"]) is str and
            HEX32.fullmatch(reply["invocation_id"]) is not None and
            all(type(reply[key]) is str and
                re.fullmatch(r"[0-9a-f]{64}", reply[key]) is not None
                for key in ("terminal_sha256", "policy_sha256",
                            "journal_sha256")) and
            reply["journal_sha256"] == _sha(_read_root(JOURNAL)),
            "watchdog_active_inspection_changed")
        return reply

    def begin_stop(self, *, probe: bool = False) -> dict[str, object] | None:
        self._live()
        _send(self.authority, {"op": "CLASSIFY_STOP" if probe else "BEGIN_STOP"})
        reply = _recv(self.authority)
        if probe and reply == {"state": "NOT_STOPPING"}:
            return None
        need(reply.get("state") == "STOPPING" and
             type(reply.get("invocation_id")) is str and
             HEX32.fullmatch(reply["invocation_id"]) is not None and
             type(reply.get("policy_sha256")) is str and
             re.fullmatch(r"[0-9a-f]{64}", reply["policy_sha256"]),
             "watchdog_normal_stop_not_acknowledged")
        return reply

    def fail_closed(self, reason: str) -> dict[str, object]:
        self._live()
        need(reason in ("launch_channel_lost", "prestart_abort",
                        "owner_lease_lost", "guardian_abort", "foreign_policy_drift"),
             "watchdog_invalid_fail_closed_reason")
        _send(self.authority, {"op": "FAIL_CLOSED", "reason": reason})
        reply = _recv(self.authority)
        need(reply.get("state") == "RECOVERED" and
             reply.get("reason") == reason and
             type(reply.get("policy_sha256")) is str and
             re.fullmatch(r"[0-9a-f]{64}", reply["policy_sha256"]) and
             type(reply.get("journal_sha256")) is str and
             re.fullmatch(r"[0-9a-f]{64}", reply["journal_sha256"]),
             "watchdog_fail_closed_unconfirmed")
        self.authority.close()
        os.close(self.actor_pidfd)
        need(self.guard_fd is not None, "watchdog_guard_borrow_missing")
        os.close(self.guard_fd)
        self.authority = None
        self.actor_pidfd = None
        self.guard_fd = None
        return reply

    def live(self) -> bool:
        try:
            self.revalidate()
            return True
        except (Refused, OSError, ValueError, socket.timeout):
            return False

    def disarm(self) -> None:
        self._live()
        _send(self.authority, {"op": "DISARM"})
        reply = _recv(self.authority)
        need(reply.get("state") == "DISARMED" and
             type(reply.get("policy_sha256")) is str and
             re.fullmatch(r"[0-9a-f]{64}", reply["policy_sha256"]),
             "watchdog_disarm_unconfirmed")
        self.authority.close()
        os.close(self.actor_pidfd)
        need(self.guard_fd is not None, "watchdog_guard_borrow_missing")
        os.close(self.guard_fd)
        self.authority = None
        self.actor_pidfd = None
        self.guard_fd = None


def serve() -> None:
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    _own_source()
    _startup_replay()
    if AUTHORITY.exists() or AUTHORITY.is_symlink():
        old = AUTHORITY.stat(follow_symlinks=False)
        need(stat.S_ISSOCK(old.st_mode) and old.st_uid == 0 and
             stat.S_IMODE(old.st_mode) == 0o600,
             "watchdog_stale_authority_untrusted")
        AUTHORITY.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        server.bind(str(AUTHORITY))
        os.chmod(AUTHORITY, 0o600)
        server.listen(1)
        server.settimeout(1.0)
        _notify("READY=1")
        while True:
            if STOP_REQUESTED:
                need(not JOURNAL.exists() and not JOURNAL.is_symlink(),
                     "watchdog_stop_with_pending_inverse")
                return
            _notify("WATCHDOG=1")
            try:
                peer, _ = server.accept()
            except socket.timeout:
                continue
            try:
                peer.settimeout(5.0)
                _session(peer, server)
            except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as error:
                if JOURNAL.exists() or JOURNAL.is_symlink():
                    # A failed inverse must restart into the durable replay
                    # path; this process may no longer hold live pidfds.
                    raise
                try:
                    _send(peer, {"state": "REFUSED", "reason": str(error)[:128]})
                except OSError:
                    pass
            finally:
                peer.close()
    finally:
        server.close()
        if AUTHORITY.exists():
            AUTHORITY.unlink()


def main() -> int:
    try:
        need(len(sys.argv) == 2 and sys.argv[1] == "serve", "invalid_watchdog_action")
        serve()
        return 0
    except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"aegis_auto_guardian_watchdog_refused:{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
