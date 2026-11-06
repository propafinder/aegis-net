#!/usr/bin/env python3
"""Process-held launch authority for one private AUTO systemd instance.

The installed guardian owns the actor end of a SOCK_SEQPACKET pair. PID 1
passes the other end as the private unit's standard input. Credentials and a
pidfd accompany *each* message; SO_PEERCRED would identify the worker that
created the pair, not the process sending a launch message.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import re
import select
import socket
import stat
import struct
import time
from collections.abc import Callable
from pathlib import Path


SO_PASSPIDFD = 76  # Linux asm-generic/socket.h, available in the accepted 6.8 kernel.
SCM_PIDFD = 4     # Linux include/linux/socket.h.
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UNIT = re.compile(r"aegis-auto@[0-9a-f]{64}\.service\Z")
LIMIT = 256
STATUS_LIMIT = 16 * 1024


class LaunchRefused(RuntimeError):
    pass


def require(value: bool, reason: str) -> None:
    if not value:
        raise LaunchRefused(reason)


def _live(pidfd: int) -> bool:
    watcher = select.poll()
    watcher.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not watcher.poll(0)


def _start_tick(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    end = raw.rfind(") ")
    require(end > 0 and raw[:end].startswith(f"{pid} ("), "invalid_main_stat")
    fields = raw[end + 2:].split()
    require(len(fields) > 19, "short_main_stat")
    tick = int(fields[19])  # Field 22, after pid and comm.
    require(tick > 0, "invalid_main_start_tick")
    return tick


def _packet(channel: socket.socket) -> tuple[bytes, int, int, int, int]:
    payload, controls, flags, _ = channel.recvmsg(
        LIMIT, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4))
    # Parse every delivered SCM_RIGHTS/SCM_PIDFD before validating the packet:
    # the kernel has already installed those descriptors in this process even
    # when payload validation will fail.
    creds = []
    owned_fds = []
    invalid_control = False
    try:
        for level, kind, data in controls:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                if len(data) == 12:
                    creds.append(struct.unpack("3i", data))
                else:
                    invalid_control = True
            elif level == socket.SOL_SOCKET and kind in (SCM_PIDFD,
                                                          socket.SCM_RIGHTS):
                # An unexpected SCM_RIGHTS is still owned and must be closed.
                if data and len(data) % 4 == 0:
                    owned_fds.extend(struct.unpack(f"{len(data) // 4}i", data))
                else:
                    invalid_control = True
                if kind != SCM_PIDFD or len(data) != 4:
                    invalid_control = True
            else:
                invalid_control = True
        require(payload and len(payload) < LIMIT and
                flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0,
                "launch_packet_truncated")
        require(not invalid_control, "foreign_launch_control")
        require(len(creds) == len(owned_fds) == 1,
                "kernel_launch_identity_unavailable")
        pid, uid, gid = creds[0]
        pidfd = owned_fds[0]
        require(pid > 1 and uid >= 0 and gid >= 0 and _live(pidfd),
                "main_exited_or_invalid")
        lines = Path(f"/proc/self/fdinfo/{pidfd}").read_text(
            encoding="ascii").splitlines()
        require(f"Pid:\t{pid}" in lines, "launch_pidfd_mismatch")
        owned_fds.clear()
        return payload, pid, uid, gid, pidfd
    finally:
        for fd in owned_fds:
            os.close(fd)


def _digest_executable(pid: int, expected: str) -> None:
    require(HEX64.fullmatch(expected) is not None, "invalid_worker_digest")
    fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
                before.st_size > 0 and before.st_size <= 512 << 20,
                "foreign_main_executable")
        h = hashlib.sha256()
        total = 0
        while chunk := os.read(fd, 1 << 20):
            total += len(chunk)
            require(total <= 512 << 20, "oversize_main_executable")
            h.update(chunk)
        after = os.fstat(fd)
        require(total == before.st_size and
                (before.st_dev, before.st_ino, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_mtime_ns) and
                h.hexdigest() == expected, "main_executable_changed")
    finally:
        os.close(fd)


def _process_authority(pid: int, uid: int, gid: int, policy: str) -> None:
    """Admit the live kernel identity before a launch marker or lease."""
    require(pid > 1 and uid >= 0 and gid >= 0 and
            policy in ("root", "dedicated_none", "dedicated_bind") and
            (uid == gid == 0) == (policy == "root"),
            "invalid_main_runtime_policy")
    fd = os.open(f"/proc/{pid}/status", os.O_RDONLY | os.O_CLOEXEC |
                 os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = bytearray()
        while True:
            chunk = os.read(fd, STATUS_LIMIT + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
            require(len(raw) <= STATUS_LIMIT, "oversize_main_status")
    finally:
        os.close(fd)
    _status_authority(bytes(raw), uid, gid, policy)


def _status_authority(raw: bytes, uid: int, gid: int, policy: str) -> None:
    """Parse one bounded proc status with exact dedicated authority."""
    require(raw.startswith(b"Name:") and b"\0" not in raw,
            "invalid_main_status")
    lines = raw.splitlines()

    def one(key: bytes) -> list[bytes]:
        matches = [line.split() for line in lines if line.startswith(key)]
        require(len(matches) == 1 and matches[0] and matches[0][0] == key,
                "invalid_main_status")
        return matches[0][1:]

    for key, expected in ((b"Uid:", uid), (b"Gid:", gid)):
        fields = one(key)
        require(len(fields) == 4 and all(field == str(expected).encode()
                                         for field in fields),
                "main_runtime_identity_changed")
    if policy == "root":
        return
    require(all(field == str(gid).encode() for field in one(b"Groups:")),
            "main_supplementary_groups_changed")
    require(one(b"NoNewPrivs:") == [b"1"], "main_no_new_privs_changed")
    allowed = 0 if policy == "dedicated_none" else 1 << 10
    for key in (b"CapInh:", b"CapPrm:", b"CapEff:", b"CapBnd:", b"CapAmb:"):
        fields = one(key)
        require(len(fields) == 1 and
                re.fullmatch(rb"[0-9a-fA-F]{16}", fields[0]) is not None and
                int(fields[0], 16) & ~allowed == 0,
                "main_capabilities_changed")


@dataclasses.dataclass(frozen=True)
class LaunchIdentity:
    unit: str
    pid: int
    uid: int
    invocation: str
    cgroup: str
    start_tick: int
    ticket_sha256: str


class HeldLaunch:
    """Retains the kernel channel and PIDFD; there is no JSON constructor."""

    def __init__(self, channel: socket.socket, pidfd: int,
                 identity: LaunchIdentity,
                 query_unit: Callable[[str, int], dict[str, str]],
                 expected_gid: int, runtime_policy: str) -> None:
        self.channel = channel
        self.pidfd = pidfd
        self.identity = identity
        self.query_unit = query_unit
        self.expected_gid = expected_gid
        self.runtime_policy = runtime_policy
        self.closed = False

    def revalidate_process(self) -> None:
        """Original channel/process authority, including during PID1 Stop."""
        require(not self.closed and _live(self.pidfd), "launch_process_exited")
        events = select.poll()
        events.register(self.channel, select.POLLHUP | select.POLLERR)
        require(not events.poll(0), "launch_channel_closed")
        require(_start_tick(self.identity.pid) == self.identity.start_tick,
                "launch_identity_changed")
        _process_authority(self.identity.pid, self.identity.uid,
                           self.expected_gid, self.runtime_policy)

    def revalidate(self) -> None:
        self.revalidate_process()
        facts = self.query_unit(self.identity.unit, self.identity.pid)
        require(facts["InvocationID"] == self.identity.invocation and
                facts["ControlGroup"] == self.identity.cgroup and
                _start_tick(self.identity.pid) == self.identity.start_tick,
                "launch_identity_changed")
        self.revalidate_process()

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.channel.close()
            os.close(self.pidfd)


class LaunchActor:
    """One-use guardian actor, constructed from the original worker FD handoff.

    ``claim_once`` must fsync the protected one-use marker and validate the
    prepared ticket commitment while the original Stage and InstallLock remain
    held. It is called after kernel/PID 1 identity checks and before LEASE.
    """

    def __init__(self, actor_fd: int, unit: str, worker_sha256: str,
                 expected_uid: int, expected_gid: int, runtime_policy: str,
                 query_unit: Callable[[str, int], dict[str, str]],
                 claim_once: Callable[[LaunchIdentity], None]) -> None:
        # Take FD ownership immediately. The caller must relinquish the raw
        # integer before invoking this constructor; on every failure here the
        # socket is closed exactly once by this scope.
        self.channel = socket.socket(fileno=actor_fd)
        try:
            require(UNIT.fullmatch(unit) is not None and
                    HEX64.fullmatch(worker_sha256) is not None and
                    expected_uid >= 0 and expected_gid >= 0 and
                    runtime_policy in ("root", "dedicated_none", "dedicated_bind") and
                    (expected_uid == expected_gid == 0) ==
                    (runtime_policy == "root"), "invalid_launch_binding")
            require(self.channel.family == socket.AF_UNIX and
                    self.channel.type & 0xf == socket.SOCK_SEQPACKET,
                    "invalid_launch_channel")
            self.channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self.channel.setsockopt(socket.SOL_SOCKET, SO_PASSPIDFD, 1)
        except BaseException:
            self.channel.close()
            raise
        self.unit = unit
        self.worker_sha256 = worker_sha256
        self.expected_uid = expected_uid
        self.expected_gid = expected_gid
        self.runtime_policy = runtime_policy
        self.query_unit = query_unit
        self.claim_once = claim_once
        self.ticket = os.urandom(32)
        self.consumed = False

    @property
    def ticket_sha256(self) -> str:
        return hashlib.sha256(self.ticket).hexdigest()

    def accept(self, timeout: float = 10.0) -> HeldLaunch:
        require(not self.consumed and 0 < timeout <= 30.0,
                "launch_ticket_already_consumed")
        # Any ambiguous attempt enters recovery; a second accept could see a
        # different process using the same PID 1 supplied socket end.
        self.consumed = True
        deadline = time.monotonic() + timeout
        self.channel.settimeout(timeout)
        pidfd = None
        transferred = False
        try:
            packet, pid, uid, gid, pidfd = _packet(self.channel)
            require((uid, gid) == (self.expected_uid, self.expected_gid),
                    "foreign_main_identity")
            parts = packet.decode("ascii").split(" ")
            require(len(parts) == 5 and parts[:2] == ["HELLO", "1"] and
                    parts[2] == self.unit and
                    HEX32.fullmatch(parts[3]) is not None and
                    HEX64.fullmatch(parts[4]) is not None,
                    "invalid_main_hello")
            invocation, main_nonce = parts[3], parts[4]
            facts = self.query_unit(self.unit, pid)
            require(facts["InvocationID"] == invocation,
                    "main_invocation_changed")
            tick = _start_tick(pid)
            _process_authority(pid, uid, gid, self.runtime_policy)
            _digest_executable(pid, self.worker_sha256)
            require(_live(pidfd) and time.monotonic() < deadline,
                    "launch_check_expired")
            challenge = os.urandom(32)
            self.channel.sendall(b"CHALLENGE 1 " + challenge.hex().encode() +
                                 b" " + self.ticket.hex().encode())
            packet2, pid2, uid2, gid2, pidfd2 = _packet(self.channel)
            try:
                require(pid2 == pid and uid2 == uid and gid2 == gid and
                        _live(pidfd2) and
                        time.monotonic() < deadline, "launch_peer_changed")
            finally:
                os.close(pidfd2)
            proof = hashlib.sha256(self.ticket + challenge +
                                   bytes.fromhex(main_nonce) +
                                   bytes.fromhex(invocation) +
                                   self.unit.encode()).hexdigest().encode()
            require(packet2 == b"CONFIRM 1 " + proof,
                    "launch_ticket_proof_mismatch")
            _process_authority(pid, uid, gid, self.runtime_policy)
            identity = LaunchIdentity(self.unit, pid, uid, invocation,
                                      facts["ControlGroup"], tick,
                                      self.ticket_sha256)
            require(self.query_unit(self.unit, pid) == facts and
                    _start_tick(pid) == tick and _live(pidfd),
                    "launch_identity_changed")
            self.claim_once(identity)
            _process_authority(pid, uid, gid, self.runtime_policy)
            require(_live(pidfd) and time.monotonic() < deadline,
                    "launch_check_expired")
            self.channel.sendall(b"LEASE 1 " + challenge.hex().encode())
            held = HeldLaunch(self.channel, pidfd, identity, self.query_unit,
                              gid, self.runtime_policy)
            pidfd = None
            try:
                held.revalidate()
                transferred = True
                return held
            except BaseException:
                held.close()
                raise
        finally:
            if pidfd is not None:
                os.close(pidfd)
            if not transferred:
                self.channel.close()

