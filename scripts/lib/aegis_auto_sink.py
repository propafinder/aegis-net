#!/usr/bin/env python3
"""Independent UDP arrival oracle for a Linux AUTO deny challenge.

Run as a separate root process in the peer network namespace.  The control
socket remains in a shared, root-owned runtime directory.  A positive UDP
control must reach this process before it can attest a denied challenge.
The receipt is an observation, never an activation acknowledgement.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import select
import selectors
import socket
import stat
import struct
import sys
import time
from pathlib import Path
from typing import Callable

MAX_CONTROL = 4096
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class Refused(RuntimeError):
    pass


def need(value: bool, reason: str) -> None:
    if not value:
        raise Refused(reason)


def safe_parent(path: Path) -> None:
    parent = path.parent.stat(follow_symlinks=False)
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
         stat.S_IMODE(parent.st_mode) == 0o700, "untrusted_runtime_directory")


def send(peer: socket.socket, value: dict[str, object]) -> None:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    need(len(payload) <= MAX_CONTROL, "oversized_control_response")
    need(peer.send(payload) == len(payload), "short_control_send")


def receive(peer: socket.socket) -> dict[str, object]:
    raw, _anc, flags, _addr = peer.recvmsg(MAX_CONTROL)
    need(bool(raw) and flags & socket.MSG_TRUNC == 0,
         "truncated_control_request")
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            need(key not in result, "duplicate_control_key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict and set(value) in (
             {"op", "sha256"}, {"op", "sha256", "session"}) and
         type(value["op"]) is str and type(value["sha256"]) is str and
         HEX64.fullmatch(value["sha256"]) is not None,
         "invalid_control_request")
    if "session" in value:
        need(type(value["session"]) is str and
             re.fullmatch(r"[0-9a-f]{32}", value["session"]) is not None,
             "invalid_session")
    return value


def _wait_message(peer: socket.socket, udp: socket.socket, digest: str,
                  deadline: float, count_all: bool = False) -> tuple[dict[str, object], int]:
    """Drain UDP while waiting for the next control message."""
    count = 0
    with selectors.DefaultSelector() as selector:
        selector.register(peer, selectors.EVENT_READ)
        selector.register(udp, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            for key, _ in selector.select(max(0.0, min(0.1, deadline - time.monotonic()))):
                if key.fileobj is peer:
                    return receive(peer), count
                payload, _address = udp.recvfrom(2048)
                if count_all or hashlib.sha256(payload).hexdigest() == digest:
                    count += 1
    raise Refused("observation_deadline_elapsed")


def _completion_lifetime(peer: socket.socket, retained_witness: bool,
                         deadline: float) -> None:
    if not retained_witness:
        return
    watcher = select.poll()
    watcher.register(peer, select.POLLIN | select.POLLHUP |
                     select.POLLERR | select.POLLNVAL)
    while True:
        left = deadline - time.monotonic()
        need(left > 0, "witness_sink_lease_expired")
        need(not watcher.poll(max(1, min(1000, int(left * 1000)))),
             "witness_sink_control_closed_or_reused")


def _effect_completion_lifetime(release_fd: int | None,
                                deadline: float) -> None:
    """Retain a completed actor until its owning topology closes the pipe."""
    if release_fd is None:
        return
    need(type(release_fd) is int and release_fd >= 3 and
         stat.S_ISFIFO(os.fstat(release_fd).st_mode) and
         fcntl.fcntl(release_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
         "invalid_effect_release_fd")
    watcher = select.poll()
    watcher.register(release_fd, select.POLLIN | select.POLLHUP |
                     select.POLLERR | select.POLLNVAL)
    while True:
        left = deadline - time.monotonic()
        need(left > 0, "effect_completion_lease_expired")
        for _fd, flags in watcher.poll(max(1, min(1000, int(left * 1000)))):
            need(not flags & (select.POLLERR | select.POLLNVAL),
                 "effect_release_fd_changed")
            need(os.read(release_fd, 1) == b"", "effect_release_data_refused")
            return


def _peer(peer: socket.socket) -> tuple[int, int, int]:
    pid, uid, _gid = struct.unpack("3i", peer.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(uid == 0 and pid > 1, "untrusted_control_peer")
    netns = os.stat(f"/proc/{pid}/ns/net").st_ino
    own_netns = os.stat("/proc/self/ns/net").st_ino
    need(netns != own_netns, "sink_not_in_independent_network_namespace")
    return pid, netns, own_netns


def _write_receipt(path: Path, value: dict[str, object]) -> None:
    safe_parent(path)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        need(os.write(fd, payload) == len(payload), "short_receipt_write")
        os.fsync(fd)
    finally:
        os.close(fd)


def serve(control_path: Path, listen_ip: str, port: int, receipt_path: Path,
          maximum_seconds: float = 15.0, minimum_observe_ms: int = 1000,
          hold_after_baseline_seconds: float = 0.0,
          retain_after_complete_for_witness: bool = False) -> dict[str, object]:
    need(os.name == "posix" and Path("/proc/self/ns/net").exists() and
         os.geteuid() == 0, "linux_root_required")
    need(1024 <= port <= 65535 and 3.0 <= maximum_seconds <= 60.0 and
         100 <= minimum_observe_ms <= 3000 and
         0.0 <= hold_after_baseline_seconds <= 700.0,
         "invalid_sink_bounds")
    family=socket.AF_INET6 if ":" in listen_ip else socket.AF_INET
    socket.inet_pton(family, listen_ip)
    safe_parent(control_path)
    safe_parent(receipt_path)
    need(not control_path.exists() and not control_path.is_symlink() and
         not receipt_path.exists() and not receipt_path.is_symlink(),
         "sink_path_already_exists")
    start = time.monotonic()
    udp = socket.socket(family, socket.SOCK_DGRAM)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        udp.bind((listen_ip, port))
        server.bind(str(control_path))
        os.chmod(control_path, 0o600)
        server.listen(1)
        server.settimeout(maximum_seconds)
        peer, _ = server.accept()
        try:
            pid, peer_netns, sink_netns = _peer(peer)
            peer.settimeout(max(0.1, start + maximum_seconds - time.monotonic()))
            baseline = receive(peer)
            need(baseline["op"] == "BASELINE", "baseline_required")
            baseline_digest = str(baseline["sha256"])
            session = secrets.token_hex(16)
            send(peer, {"state": "BASELINE_READY", "sha256": baseline_digest,
                        "received": 0, "session": session})
            finished, baseline_count = _wait_message(
                peer, udp, baseline_digest, start + maximum_seconds)
            need(finished == {"op": "BASELINE_FINISH", "sha256": baseline_digest},
                 "baseline_finish_mismatch")
            # A packet available concurrently with FINISH is already in the
            # kernel receive queue; drain it before deciding the positive.
            udp.setblocking(False)
            while True:
                try:
                    payload, _ = udp.recvfrom(2048)
                except BlockingIOError:
                    break
                baseline_count += hashlib.sha256(payload).hexdigest() == baseline_digest
            udp.setblocking(True)
            need(baseline_count == 1, "positive_control_count_invalid")
            send(peer, {"state": "BASELINE_COMPLETE", "sha256": baseline_digest,
                        "received": baseline_count, "session": session})
            hold_deadline = time.monotonic() + (
                hold_after_baseline_seconds or max(0.0, start + maximum_seconds - time.monotonic()))
            peer.settimeout(max(0.1, hold_deadline - time.monotonic()))
            armed = receive(peer)
            need(armed.get("op") == "ARM" and armed.get("session") == session,
                 "deny_arm_session_mismatch")
            challenge_digest = str(armed["sha256"])
            # Prior baseline datagrams must not be mistaken for denial traffic.
            udp.setblocking(False)
            while True:
                try:
                    udp.recvfrom(2048)
                except BlockingIOError:
                    break
            udp.setblocking(True)
            arm_time = time.monotonic()
            send(peer, {"state": "READY", "sha256": challenge_digest,
                        "received": 0, "session": session})
            completed, count = _wait_message(
                peer, udp, challenge_digest,
                min(hold_deadline, arm_time + maximum_seconds), count_all=True)
            need(completed == {"op": "FINISH", "sha256": challenge_digest,
                               "session": session},
                 "deny_finish_mismatch")
            need(time.monotonic() - arm_time >= minimum_observe_ms / 1000,
                 "deny_observation_too_short")
            udp.setblocking(False)
            while True:
                try:
                    udp.recvfrom(2048)
                except BlockingIOError:
                    break
                count += 1
            need(count == 0, "challenged_datagram_arrived")
            receipt = {"schema": "aegis_auto_independent_sink_v1",
                       "session": session, "peer_pid": pid,
                       "peer_netns_ino": peer_netns, "sink_pid": os.getpid(),
                       "sink_netns_ino": sink_netns, "listen_ip": listen_ip,
                       "listen_port": port, "baseline_sha256": baseline_digest,
                       "baseline_received": baseline_count,
                       "challenge_sha256": challenge_digest,
                       "challenge_received": count,
                       "observed_ms": int((time.monotonic() - arm_time) * 1000)}
            _write_receipt(receipt_path, receipt)
            send(peer, {"state": "COMPLETE", "sha256": challenge_digest,
                        "received": 0, "session": session})
            _completion_lifetime(peer, retain_after_complete_for_witness,
                                 start + maximum_seconds)
            return receipt
        finally:
            peer.close()
    finally:
        server.close()
        udp.close()
        # The runtime directory is installation-owned; remove only our socket.
        try:
            named = control_path.lstat()
            if stat.S_ISSOCK(named.st_mode) and named.st_uid == 0:
                control_path.unlink()
        except FileNotFoundError:
            pass


def serve_echo(control_path: Path, listen_ip: str, port: int,
               receipt_path: Path, maximum_seconds: float = 30.0,
               completion_release_fd: int | None = None,
               socket_published: list[bool] | None = None) -> dict[str, object]:
    """One authenticated IPv6 UDP echo for a separately verified capture path."""
    need(os.name == "posix" and Path("/proc/self/ns/net").exists() and
         os.geteuid() == 0, "linux_root_required")
    need(1024 <= port <= 65535 and 3.0 <= maximum_seconds <= 60.0,
         "invalid_echo_bounds")
    socket.inet_pton(socket.AF_INET6, listen_ip)
    safe_parent(control_path)
    safe_parent(receipt_path)
    need(not control_path.exists() and not control_path.is_symlink() and
         not receipt_path.exists() and not receipt_path.is_symlink(),
         "echo_path_already_exists")
    deadline = time.monotonic() + maximum_seconds
    udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        udp.bind((listen_ip, port))
        server.bind(str(control_path))
        if socket_published is not None:
            socket_published[0] = True
        os.chmod(control_path, 0o600)
        server.listen(1)
        server.settimeout(maximum_seconds)
        peer, _ = server.accept()
        try:
            pid, peer_netns, sink_netns = _peer(peer)
            peer.settimeout(max(0.1, deadline - time.monotonic()))
            armed = receive(peer)
            need(armed.get("op") == "ECHO_ARM" and
                 set(armed) == {"op", "sha256"}, "echo_arm_required")
            digest = str(armed["sha256"])
            session = secrets.token_hex(16)
            identity = {"sha256": digest, "session": session,
                        "sink_pid": os.getpid(), "sink_netns_ino": sink_netns,
                        "listen_ip": listen_ip, "listen_port": port}
            send(peer, {"state": "ECHO_READY", **identity})
            count = 0
            echoed = 0
            finished = False
            with selectors.DefaultSelector() as selector:
                selector.register(udp, selectors.EVENT_READ)
                selector.register(peer, selectors.EVENT_READ)
                while time.monotonic() < deadline and not finished:
                    for key, _ in selector.select(max(0.0, min(0.1, deadline - time.monotonic()))):
                        if key.fileobj is udp:
                            payload, address = udp.recvfrom(2048)
                            if hashlib.sha256(payload).hexdigest() == digest:
                                count += 1
                                need(count == 1, "duplicate_echo_nonce")
                                need(udp.sendto(payload, address) == len(payload),
                                     "echo_send_failed")
                                echoed += 1
                        else:
                            request = receive(peer)
                            need(request == {"op": "ECHO_FINISH", "sha256": digest,
                                             "session": session},
                                 "echo_finish_mismatch")
                            finished = True
                            break
            need(finished and count == 1 and echoed == 1,
                 "echo_not_observed")
            # Drain any queued duplicate before publishing a positive result.
            udp.setblocking(False)
            while True:
                try:
                    payload, _address = udp.recvfrom(2048)
                except BlockingIOError:
                    break
                need(hashlib.sha256(payload).hexdigest() != digest,
                     "duplicate_echo_nonce")
            receipt = {"schema": "aegis_auto_independent_echo_v1",
                       "peer_pid": pid, "peer_netns_ino": peer_netns,
                       **identity, "received": count, "echoed": echoed}
            _write_receipt(receipt_path, receipt)
            send(peer, {"state": "ECHO_COMPLETE", "sha256": digest,
                        "session": session, "received": count,
                        "echoed": echoed, "sink_pid": os.getpid(),
                        "sink_netns_ino": sink_netns})
            _effect_completion_lifetime(completion_release_fd, deadline)
            return receipt
        finally:
            peer.close()
    finally:
        server.close()
        udp.close()
        try:
            named = control_path.lstat()
            if stat.S_ISSOCK(named.st_mode) and named.st_uid == 0:
                control_path.unlink()
        except FileNotFoundError:
            pass


def receive_probe_arm(peer: socket.socket) -> dict[str, object]:
    raw, _anc, flags, _addr = peer.recvmsg(MAX_CONTROL)
    need(bool(raw) and flags & socket.MSG_TRUNC == 0,
         "truncated_probe_arm")
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            need(key not in result, "duplicate_control_key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict and set(value) ==
         {"op", "sha256", "nonce_hex", "target_ip", "target_port",
          "deadline_monotonic_ns"} and
         value["op"] == "PROBE_ARM" and
         type(value["sha256"]) is str and HEX64.fullmatch(value["sha256"]) and
         type(value["nonce_hex"]) is str and
         re.fullmatch(r"[0-9a-f]{64}", value["nonce_hex"]) and
         type(value["target_ip"]) is str and
         type(value["target_port"]) is int and
         1024 <= value["target_port"] <= 65535 and
         type(value["deadline_monotonic_ns"]) is int and
         0 < value["deadline_monotonic_ns"] - time.monotonic_ns() <=
         8_000_000_000,
         "invalid_probe_arm")
    need(hashlib.sha256(bytes.fromhex(value["nonce_hex"])).hexdigest() ==
         value["sha256"], "probe_nonce_digest_mismatch")
    target = ipaddress.IPv4Address(value["target_ip"])
    need(not (target.is_multicast or target.is_unspecified or
              target.is_loopback), "invalid_probe_target")
    return value


def _probe_socket_timeout(peer: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("probe_exchange_deadline_elapsed")
    peer.settimeout(remaining)


def _probe_failure_record(receipt_path: Path, phase: str,
                          error: Exception) -> None:
    """Retain only bounded, fixed diagnostic fields for a failed owned probe."""
    allowed = {"startup", "peer", "arm", "connect", "send", "echo", "finish",
               "receipt", "hold"}
    need(phase in allowed, "invalid_probe_failure_phase")
    kind = ("refused" if isinstance(error, Refused) else
            "timeout" if isinstance(error, TimeoutError) else
            "os_error" if isinstance(error, OSError) else
            "value_error" if isinstance(error, ValueError) else "unexpected")
    number = error.errno if isinstance(error, OSError) else 0
    number = number if type(number) is int and 0 <= number <= 4095 else 0
    line = 0
    trace = error.__traceback__
    while trace is not None:
        if (trace.tb_frame.f_code.co_filename == __file__ and
                trace.tb_frame.f_code.co_name not in
                ("need", "_probe_failure_record") and
                1 <= trace.tb_lineno <= 10000):
            line = trace.tb_lineno
        trace = trace.tb_next
    payload = json.dumps({"schema": "aegis_auto_probe_failure_v1",
                          "phase": phase, "class": kind, "errno": number,
                          "source": "sink", "line": line},
                         sort_keys=True, separators=(",", ":")).encode() + b"\n"
    need(len(payload) <= 256, "probe_failure_record_unbounded")
    path = receipt_path.with_suffix(".failure.json")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        directory = os.fstat(parent)
        named_parent = path.parent.stat(follow_symlinks=False)
        need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and
             stat.S_IMODE(directory.st_mode) == 0o700 and
             (directory.st_dev, directory.st_ino) ==
             (named_parent.st_dev, named_parent.st_ino),
             "probe_failure_parent_untrusted")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
                 before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600,
                 "probe_failure_file_untrusted")
            need(os.write(fd, payload) == len(payload),
                 "probe_failure_write_short")
            os.fsync(fd)
            after = os.fstat(fd)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            parent_after = path.parent.stat(follow_symlinks=False)
            need((before.st_dev, before.st_ino) ==
                 (after.st_dev, after.st_ino) == (named.st_dev, named.st_ino) and
                 (directory.st_dev, directory.st_ino) ==
                 (parent_after.st_dev, parent_after.st_ino) and
                 stat.S_ISDIR(parent_after.st_mode) and parent_after.st_uid == 0 and
                 stat.S_IMODE(parent_after.st_mode) == 0o700,
                 "probe_failure_identity_changed")
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _startup_failure_record(path: Path, action: str,
                            error: Exception) -> None:
    """Retain a bounded coordinate only before an effect control socket exists."""
    need(action in ("serve-echo", "serve-echo-tcp", "serve-probe-tcp"),
         "invalid_startup_action")
    kind = ("refused" if isinstance(error, Refused) else
            "timeout" if isinstance(error, TimeoutError) else
            "os_error" if isinstance(error, OSError) else
            "value_error" if isinstance(error, ValueError) else "unexpected")
    number = error.errno if isinstance(error, OSError) else 0
    number = number if type(number) is int and 0 <= number <= 4095 else 0
    line = 0
    trace = error.__traceback__
    while trace is not None:
        if (trace.tb_frame.f_code.co_filename == __file__ and
                trace.tb_frame.f_code.co_name not in
                ("need", "_startup_failure_record") and
                1 <= trace.tb_lineno <= 10000):
            line = trace.tb_lineno
        trace = trace.tb_next
    payload = json.dumps({"schema": "aegis_auto_sink_startup_failure_v1",
                          "action": action, "phase": "before_socket",
                          "class": kind, "errno": number,
                          "source": "sink", "line": line, "pid": os.getpid()},
                         sort_keys=True, separators=(",", ":")).encode() + b"\n"
    need(len(payload) <= 256, "startup_failure_record_unbounded")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        directory = os.fstat(parent)
        named_parent = path.parent.stat(follow_symlinks=False)
        need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and
             stat.S_IMODE(directory.st_mode) == 0o700 and
             (directory.st_dev, directory.st_ino) ==
             (named_parent.st_dev, named_parent.st_ino),
             "startup_failure_parent_untrusted")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
                 before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600,
                 "startup_failure_file_untrusted")
            need(os.write(fd, payload) == len(payload),
                 "startup_failure_write_short")
            os.fsync(fd)
            after = os.fstat(fd)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            parent_after = path.parent.stat(follow_symlinks=False)
            need((before.st_dev, before.st_ino) ==
                 (after.st_dev, after.st_ino) == (named.st_dev, named.st_ino) and
                 (directory.st_dev, directory.st_ino) ==
                 (parent_after.st_dev, parent_after.st_ino) and
                 stat.S_ISDIR(parent_after.st_mode) and parent_after.st_uid == 0 and
                 stat.S_IMODE(parent_after.st_mode) == 0o700,
                 "startup_failure_identity_changed")
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _probe_phase_record(receipt_path: Path, phase: str) -> None:
    """Leave a private, fixed pre-operation breadcrumb even if killed mid-I/O."""
    need(phase in {"startup", "peer", "arm", "connect", "send", "echo",
                   "finish", "receipt", "hold"}, "invalid_probe_phase")
    path = receipt_path.with_name(receipt_path.stem + ".phase-" + phase + ".json")
    payload = (json.dumps({"schema": "aegis_auto_probe_phase_v1",
                           "source": "sink", "phase": phase},
                          sort_keys=True, separators=(",", ":")).encode() + b"\n")
    need(len(payload) <= 128, "probe_phase_unbounded")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        directory = os.fstat(parent)
        named_parent = path.parent.stat(follow_symlinks=False)
        need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and
             stat.S_IMODE(directory.st_mode) == 0o700 and
             (directory.st_dev, directory.st_ino) ==
             (named_parent.st_dev, named_parent.st_ino),
             "probe_phase_parent_untrusted")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
                 before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600,
                 "probe_phase_file_untrusted")
            need(os.write(fd, payload) == len(payload), "probe_phase_write_short")
            os.fsync(fd)
            after = os.fstat(fd)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            parent_after = path.parent.stat(follow_symlinks=False)
            need((before.st_dev, before.st_ino) ==
                 (after.st_dev, after.st_ino) == (named.st_dev, named.st_ino) and
                 (directory.st_dev, directory.st_ino) ==
                 (parent_after.st_dev, parent_after.st_ino) and
                 stat.S_ISDIR(parent_after.st_mode) and parent_after.st_uid == 0 and
                 stat.S_IMODE(parent_after.st_mode) == 0o700,
                 "probe_phase_identity_changed")
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def refuse_queued_control(server: socket.socket, peer: socket.socket) -> None:
    """Reject a replay on either the armed connection or the listen socket."""
    peer_timeout = peer.gettimeout()
    peer.setblocking(False)
    try:
        try:
            queued = peer.recv(MAX_CONTROL, socket.MSG_PEEK)
        except BlockingIOError:
            queued = b""
        need(not queued, "duplicate_control_request")
    finally:
        peer.settimeout(peer_timeout)
    server_timeout = server.gettimeout()
    server.setblocking(False)
    try:
        try:
            duplicate, _ = server.accept()
        except BlockingIOError:
            return
        else:
            duplicate.close()
            raise Refused("duplicate_control_connection")
    finally:
        server.settimeout(server_timeout)


def serve_probe_tcp(control_path: Path, receipt_path: Path,
                    maximum_seconds: float = 15.0,
                    completion_release_fd: int | None = None,
                    socket_published: list[bool] | None = None) -> dict[str, object]:
    """One ingress TCP connection and exact echo from an independent netns."""
    phase = ["startup"]
    def mark(next_phase: str) -> None:
        phase[0] = next_phase
        try:
            _probe_phase_record(receipt_path, next_phase)
        except Exception:
            # A diagnostic write cannot change the probe's result.
            pass
    try:
        mark("startup")
        return _serve_probe_tcp(control_path, receipt_path, maximum_seconds,
                                completion_release_fd, phase, mark,
                                socket_published)
    except Exception as error:
        try:
            _probe_failure_record(receipt_path, phase[0], error)
        except Exception:
            # Diagnostics never replace the original refusal.
            pass
        raise


def _serve_probe_tcp(control_path: Path, receipt_path: Path,
                     maximum_seconds: float, completion_release_fd: int | None,
                     phase: list[str], mark: Callable[[str], None],
                     socket_published: list[bool] | None) -> dict[str, object]:
    need(os.name == "posix" and Path("/proc/self/ns/net").exists() and
         os.geteuid() == 0, "linux_root_required")
    need(3.0 <= maximum_seconds <= 60.0, "invalid_probe_bounds")
    safe_parent(control_path)
    safe_parent(receipt_path)
    need(not control_path.exists() and not control_path.is_symlink() and
         not receipt_path.exists() and not receipt_path.is_symlink(),
         "probe_path_already_exists")
    deadline = time.monotonic() + maximum_seconds
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        server.bind(str(control_path))
        if socket_published is not None:
            socket_published[0] = True
        os.chmod(control_path, 0o600)
        server.listen(1)
        mark("peer")
        _probe_socket_timeout(server, deadline)
        peer, _ = server.accept()
        try:
            pid, peer_netns, sink_netns = _peer(peer)
            mark("arm")
            _probe_socket_timeout(peer, deadline)
            armed = receive_probe_arm(peer)
            exchange_deadline = min(deadline,
                                    armed["deadline_monotonic_ns"] / 1_000_000_000)
            # Leave a small part of the owner's existing budget for a durable
            # failure record before its control receive expires and aborts us.
            io_deadline = exchange_deadline - 0.05
            digest = str(armed["sha256"])
            nonce = bytes.fromhex(str(armed["nonce_hex"]))
            target_ip = str(armed["target_ip"])
            target_port = int(armed["target_port"])
            session = secrets.token_hex(16)
            identity = {"sha256": digest, "session": session,
                        "probe_pid": os.getpid(), "probe_netns_ino": sink_netns,
                        "peer_pid": pid,
                        "target_ip": target_ip, "target_port": target_port}
            _probe_socket_timeout(peer, exchange_deadline)
            send(peer, {"state": "PROBE_READY", **identity})
            mark("connect")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
                _probe_socket_timeout(tcp, io_deadline)
                tcp.connect((target_ip, target_port))
                connected_ip, connected_port = tcp.getpeername()
                need((connected_ip, connected_port) == (target_ip, target_port),
                     "probe_connected_destination_mismatch")
                mark("send")
                _probe_socket_timeout(tcp, io_deadline)
                tcp.sendall(nonce)
                mark("echo")
                response = bytearray()
                while len(response) < len(nonce):
                    _probe_socket_timeout(tcp, io_deadline)
                    chunk = tcp.recv(len(nonce) - len(response))
                    need(bool(chunk), "probe_echo_eof")
                    response.extend(chunk)
                need(bytes(response) == nonce, "probe_echo_mismatch")
            _probe_socket_timeout(peer, exchange_deadline)
            send(peer, {"state": "PROBE_OBSERVED", **identity,
                        "connected_ip": connected_ip,
                        "connected_port": connected_port,
                        "sent_bytes": len(nonce), "echoed_bytes": len(response)})
            mark("finish")
            _probe_socket_timeout(peer, exchange_deadline)
            finished = receive(peer)
            need(finished == {"op": "PROBE_FINISH", "sha256": digest,
                              "session": session}, "probe_finish_mismatch")
            refuse_queued_control(server, peer)
            receipt = {"schema": "aegis_auto_independent_tcp_probe_v1",
                       "peer_pid": pid, "peer_netns_ino": peer_netns,
                       **identity, "connected_ip": connected_ip,
                       "connected_port": connected_port,
                       "sent_bytes": len(nonce),
                       "echoed_bytes": len(response)}
            mark("receipt")
            _write_receipt(receipt_path, receipt)
            _probe_socket_timeout(peer, exchange_deadline)
            send(peer, {"state": "PROBE_COMPLETE", **identity,
                        "connected_ip": connected_ip,
                        "connected_port": connected_port,
                        "sent_bytes": len(nonce),
                        "echoed_bytes": len(response)})
            mark("hold")
            _effect_completion_lifetime(completion_release_fd, deadline)
            return receipt
        finally:
            peer.close()
    finally:
        server.close()
        try:
            named = control_path.lstat()
            if stat.S_ISSOCK(named.st_mode) and named.st_uid == 0:
                control_path.unlink()
        except FileNotFoundError:
            pass


def serve_echo_tcp(control_path: Path, listen_ip: str, port: int,
                   receipt_path: Path,
                   maximum_seconds: float = 15.0,
                   completion_release_fd: int | None = None,
                   socket_published: list[bool] | None = None) -> dict[str, object]:
    """One authenticated IPv4 TCP echo in a separate network namespace."""
    need(os.name == "posix" and Path("/proc/self/ns/net").exists() and
         os.geteuid() == 0, "linux_root_required")
    need(1024 <= port <= 65535 and 3.0 <= maximum_seconds <= 60.0,
         "invalid_echo_tcp_bounds")
    address = ipaddress.IPv4Address(listen_ip)
    need(not (address.is_multicast or address.is_unspecified or
              address.is_loopback), "invalid_echo_tcp_address")
    safe_parent(control_path)
    safe_parent(receipt_path)
    need(not control_path.exists() and not control_path.is_symlink() and
         not receipt_path.exists() and not receipt_path.is_symlink(),
         "echo_tcp_path_already_exists")
    deadline = time.monotonic() + maximum_seconds
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((listen_ip, port))
        listener.listen(2)
        server.bind(str(control_path))
        if socket_published is not None:
            socket_published[0] = True
        os.chmod(control_path, 0o600)
        server.listen(1)
        server.settimeout(maximum_seconds)
        peer, _ = server.accept()
        try:
            pid, peer_netns, sink_netns = _peer(peer)
            peer.settimeout(max(0.1, deadline - time.monotonic()))
            armed = receive(peer)
            need(armed.get("op") == "ECHO_ARM" and
                 set(armed) == {"op", "sha256"}, "echo_tcp_arm_required")
            digest = str(armed["sha256"])
            session = secrets.token_hex(16)
            identity = {"sha256": digest, "session": session,
                        "sink_pid": os.getpid(), "sink_netns_ino": sink_netns,
                        "listen_ip": listen_ip, "listen_port": port}
            send(peer, {"state": "ECHO_READY", **identity})
            listener.settimeout(max(0.1, deadline - time.monotonic()))
            tcp, _address = listener.accept()
            with tcp:
                tcp.settimeout(max(0.1, deadline - time.monotonic()))
                payload = bytearray()
                while len(payload) < 32:
                    tcp.settimeout(max(0.1, deadline - time.monotonic()))
                    chunk = tcp.recv(32 - len(payload))
                    need(bool(chunk), "echo_tcp_nonce_eof")
                    payload.extend(chunk)
                need(hashlib.sha256(payload).hexdigest() == digest,
                     "echo_tcp_nonce_mismatch")
                tcp.sendall(payload)
            peer.settimeout(max(0.1, deadline - time.monotonic()))
            finished = receive(peer)
            need(finished == {"op": "ECHO_FINISH", "sha256": digest,
                              "session": session}, "echo_tcp_finish_mismatch")
            refuse_queued_control(server, peer)
            listener.setblocking(False)
            try:
                duplicate, _ = listener.accept()
            except BlockingIOError:
                pass
            else:
                duplicate.close()
                raise Refused("duplicate_echo_tcp_connection")
            receipt = {"schema": "aegis_auto_independent_tcp_echo_v1",
                       "peer_pid": pid, "peer_netns_ino": peer_netns,
                       **identity, "received": 1, "echoed": 1,
                       "received_bytes": 32, "echoed_bytes": 32}
            _write_receipt(receipt_path, receipt)
            send(peer, {"state": "ECHO_COMPLETE", **identity,
                        "received": 1, "echoed": 1,
                        "received_bytes": 32, "echoed_bytes": 32})
            _effect_completion_lifetime(completion_release_fd, deadline)
            return receipt
        finally:
            peer.close()
    finally:
        server.close()
        listener.close()
        try:
            named = control_path.lstat()
            if stat.S_ISSOCK(named.st_mode) and named.st_uid == 0:
                control_path.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["serve", "serve-echo",
                                           "serve-echo-tcp", "serve-probe-tcp"])
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--listen-ip")
    parser.add_argument("--port", type=int)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--maximum-seconds", type=float, default=15.0)
    parser.add_argument("--hold-after-baseline-seconds", type=float, default=0.0)
    parser.add_argument("--retain-after-complete-for-witness", action="store_true")
    parser.add_argument("--completion-release-fd", type=int)
    parser.add_argument("--startup-failure-receipt", type=Path)
    args = parser.parse_args()
    socket_published = [False]
    startup_path_valid = False
    try:
        if args.startup_failure_receipt is not None:
            need(args.action in ("serve-echo", "serve-echo-tcp", "serve-probe-tcp") and
                 args.startup_failure_receipt == args.receipt.with_name(
                     args.receipt.stem + ".startup-failure.json"),
                 "invalid_startup_failure_path")
            startup_path_valid = True
        if args.action == "serve":
            need(args.completion_release_fd is None,
                 "witness_effect_release_not_supported")
            need(args.listen_ip is not None and args.port is not None,
                 "listen_address_required")
            value = serve(args.socket, args.listen_ip, args.port, args.receipt,
                          args.maximum_seconds,
                          hold_after_baseline_seconds=args.hold_after_baseline_seconds,
                          retain_after_complete_for_witness=(
                              args.retain_after_complete_for_witness))
            summary = {"baseline_received": value["baseline_received"]}
        elif args.action == "serve-echo":
            need(args.listen_ip is not None and args.port is not None,
                 "listen_address_required")
            value = serve_echo(args.socket, args.listen_ip, args.port,
                               args.receipt, args.maximum_seconds,
                               args.completion_release_fd, socket_published)
            summary = {"received": value["received"],
                       "echoed": value["echoed"]}
        elif args.action == "serve-echo-tcp":
            need(args.listen_ip is not None and args.port is not None,
                 "listen_address_required")
            value = serve_echo_tcp(args.socket, args.listen_ip, args.port,
                                   args.receipt, args.maximum_seconds,
                                   args.completion_release_fd, socket_published)
            summary = {"received": value["received"],
                       "echoed": value["echoed"]}
        else:
            need(args.listen_ip is None and args.port is None,
                 "probe_has_no_listen_address")
            value = serve_probe_tcp(args.socket, args.receipt,
                                    args.maximum_seconds,
                                    args.completion_release_fd, socket_published)
            summary = {"sent_bytes": value["sent_bytes"],
                       "echoed_bytes": value["echoed_bytes"]}
        print(json.dumps({"state": "COMPLETE", "receipt": str(args.receipt),
                          **summary}))
        return 0
    except (Refused, OSError, ValueError, json.JSONDecodeError) as error:
        if startup_path_valid and not socket_published[0]:
            try:
                _startup_failure_record(args.startup_failure_receipt,
                                        args.action, error)
            except Exception:
                pass
        if args.action == "serve-probe-tcp":
            print("aegis_auto_sink_refused:probe_failure", file=sys.stderr)
        elif args.action in ("serve-echo", "serve-echo-tcp"):
            print("aegis_auto_sink_refused:effect_failure", file=sys.stderr)
        else:
            print(f"aegis_auto_sink_refused:{error}", file=sys.stderr)
        return 2
    except Exception as error:
        if startup_path_valid and not socket_published[0]:
            try:
                _startup_failure_record(args.startup_failure_receipt,
                                        args.action, error)
            except Exception:
                pass
        raise


if __name__ == "__main__":
    raise SystemExit(main())
