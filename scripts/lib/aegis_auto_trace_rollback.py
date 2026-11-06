#!/usr/bin/env python3
"""Separate B-02 trace-table rollback actor and its held-lease client.

The actor and a systemd timer independently delete one fixed, trace-only nft
table.  Neither inverse reads a mutable marker.  The control connection must
remain open across the native challenge; its death triggers immediate cleanup.
The timer is armed and its effective precision read back before any mutation.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

TABLE = "aegis_auto_witness"
FAMILY = "inet"
SOCKET = Path("/run/aegis-auto-rollback/authority.sock")
TIMER = "aegis-auto-trace-rollback.timer"
SERVICE = "aegis-auto-trace-rollback.service"
NFT = Path("/usr/sbin/nft")
SYSTEMCTL = Path("/usr/bin/systemctl")
MAX_PACKET = 1024
DEADLINE_SECONDS = 12.0
MAX_CLEANUP_SECONDS = 6.0


class Refused(RuntimeError):
    pass


def need(value: bool, reason: str) -> None:
    if not value:
        raise Refused(reason)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        need(key not in result, "duplicate_control_key")
        result[key] = value
    return result


def _send(sock: socket.socket, value: dict[str, object]) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    need(len(data) <= MAX_PACKET and sock.send(data) == len(data),
         "rollback_control_send_failed")


def _recv(sock: socket.socket) -> dict[str, object]:
    data, _anc, flags, _addr = sock.recvmsg(MAX_PACKET)
    need(bool(data) and flags & socket.MSG_TRUNC == 0,
         "rollback_control_closed_or_truncated")
    value = json.loads(data, object_pairs_hook=_unique)
    need(type(value) is dict, "invalid_rollback_control")
    return value


def _run(argv: list[str], timeout: float, input_data: bytes | None = None) -> bytes:
    result = subprocess.run(argv, input=input_data, capture_output=True,
                            timeout=timeout, check=False,
                            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C",
                                 "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 1 << 20 and
         len(result.stderr) <= 4096,
         f"command_failed:{Path(argv[0]).name}:{result.returncode}")
    return result.stdout


def _tables() -> list[dict[str, object]]:
    value = json.loads(_run([str(NFT), "--json", "list", "tables"], 2.0),
                       object_pairs_hook=_unique)
    need(type(value) is dict and set(value) == {"nftables"} and
         type(value["nftables"]) is list, "invalid_nft_table_inventory")
    tables = []
    for item in value["nftables"]:
        need(type(item) is dict and len(item) == 1, "invalid_nft_table_entry")
        if "metainfo" in item:
            continue
        need(set(item) == {"table"} and type(item["table"]) is dict,
             "unexpected_nft_table_entry")
        tables.append(item["table"])
    return tables


def _present() -> bool:
    matches = [t for t in _tables() if t.get("name") == TABLE and
               t.get("family") == FAMILY]
    need(len(matches) <= 1, "ambiguous_trace_table")
    return bool(matches)


def cleanup() -> dict[str, object]:
    """Delete fixed trace table, then verify absence from kernel inventory."""
    need(os.geteuid() == 0 and Path("/proc/self/ns/net").exists(),
         "linux_root_required")
    start = time.monotonic()
    initially_present = _present()
    if initially_present:
        _run([str(NFT), "delete", "table", FAMILY, TABLE], 3.0)
    need(not _present(), "trace_table_remains")
    elapsed = time.monotonic() - start
    need(elapsed <= MAX_CLEANUP_SECONDS, "rollback_cleanup_over_budget")
    return {"schema": "aegis_auto_trace_rollback_v1",
            "table": TABLE, "initially_present": initially_present,
            "table_absent": True, "elapsed_ms": int(elapsed * 1000)}


def _timer_facts() -> dict[str, str]:
    raw = _run([str(SYSTEMCTL), "show", TIMER,
                "-p", "ActiveState", "-p", "Unit", "-p", "AccuracyUSec",
                "-p", "RandomizedDelayUSec", "--no-pager"], 2.0)
    facts: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        need(separator == "=" and key not in facts, "invalid_timer_readback")
        facts[key] = value
    need(set(facts) == {"ActiveState", "Unit", "AccuracyUSec",
                        "RandomizedDelayUSec"}, "incomplete_timer_readback")
    return facts


def _timer_armed() -> bool:
    facts = _timer_facts()
    return (facts["ActiveState"] == "active" and facts["Unit"] == SERVICE and
            facts["AccuracyUSec"] in ("1ms", "1000us") and
            facts["RandomizedDelayUSec"] in ("0", "0us"))


def _start_timer() -> None:
    need(_timer_facts()["ActiveState"] == "inactive",
         "rollback_timer_already_active")
    _run([str(SYSTEMCTL), "start", TIMER], 3.0)
    need(_timer_armed(), "rollback_timer_precision_or_state_wrong")


def _stop_timer() -> None:
    _run([str(SYSTEMCTL), "stop", TIMER], 3.0)
    need(_timer_facts()["ActiveState"] == "inactive",
         "rollback_timer_still_active")


def _trusted_socket_parent(path: Path) -> None:
    parent = path.parent.stat(follow_symlinks=False)
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
         stat.S_IMODE(parent.st_mode) == 0o700, "untrusted_actor_runtime")


def _notify_ready() -> None:
    path = os.environ.get("NOTIFY_SOCKET")
    need(path is not None and path != "", "systemd_notify_socket_missing")
    address = "\0" + path[1:] if path.startswith("@") else path
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.connect(address)
        need(sock.send(b"READY=1") == len(b"READY=1"),
             "systemd_ready_short_send")


def serve(path: Path = SOCKET) -> None:
    need(os.geteuid() == 0 and os.name == "posix" and
         Path("/proc/self/ns/net").exists(), "linux_root_required")
    _trusted_socket_parent(path)
    need(not path.exists() and not path.is_symlink(),
         "rollback_socket_already_exists")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(str(path))
    os.chmod(path, 0o600)
    server.listen(1)
    try:
        _notify_ready()
        while True:
            peer, _ = server.accept()
            try:
                _handle(peer)
            except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as error:
                try:
                    _send(peer, {"state": "REFUSED", "reason": str(error)[:128]})
                except OSError:
                    pass
            finally:
                peer.close()
    finally:
        server.close()
        try:
            named = path.lstat()
            if stat.S_ISSOCK(named.st_mode) and named.st_uid == 0:
                path.unlink()
        except FileNotFoundError:
            pass


def _handle(peer: socket.socket) -> None:
    pid, uid, _gid = struct.unpack("3i", peer.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(uid == 0 and pid > 1, "untrusted_rollback_owner")
    raw = peer.getsockopt(socket.SOL_SOCKET,
                          getattr(socket, "SO_PEERPIDFD", 77), 4)
    need(len(raw) == 4, "rollback_owner_pidfd_unavailable")
    pidfd = struct.unpack("i", raw)[0]
    armed = False
    disarmed = False
    try:
        info = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="ascii")
        need(any(line == f"Pid:\t{pid}" for line in info.splitlines()) and
             Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
             "0::/system.slice/aegis-auto-guardian.service\n",
             "untrusted_rollback_owner")
        request = _recv(peer)
        need(set(request) == {"op", "table", "netns_ino"} and
             request["op"] == "ARM" and request["table"] == TABLE and
             type(request["netns_ino"]) is int and
             request["netns_ino"] == os.stat("/proc/self/ns/net").st_ino and
             not _present(), "invalid_rollback_arm")
        began = time.monotonic()
        _start_timer()
        armed = True
        deadline = began + DEADLINE_SECONDS
        need(time.monotonic() < deadline - 5, "rollback_arm_too_late")
        _send(peer, {"state": "ARMED", "table": TABLE,
                     "netns_ino": request["netns_ino"]})
        watcher = select.poll()
        watcher.register(peer, select.POLLIN | select.POLLHUP | select.POLLERR)
        watcher.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                # Expiry revokes the mutator, not merely its control socket.
                # A late continuation must not recreate a table after the
                # fixed timer and this actor have deleted it.
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except OSError:
                    pass
                cleanup()
                # If the process cannot be reaped immediately, keep deleting
                # any late trace table until its PIDFD reports exit.
                while True:
                    if watcher.poll(100):
                        cleanup()
                        return
                    cleanup()
            for fd, event in watcher.poll(max(1, min(100, int(left * 1000)))):
                if fd == pidfd or event & (select.POLLHUP | select.POLLERR):
                    cleanup()
                    return
                request = _recv(peer)
                if request == {"op": "LIVE"}:
                    need(_timer_armed() and time.monotonic() < deadline - 5,
                         "rollback_lease_expiring")
                    _send(peer, {"state": "LIVE"})
                elif request == {"op": "DISARM"}:
                    need(not _present(), "trace_table_not_removed_before_disarm")
                    _stop_timer()
                    armed = False
                    disarmed = True
                    _send(peer, {"state": "DISARMED"})
                    return
                else:
                    raise Refused("invalid_rollback_control")
    finally:
        os.close(pidfd)
        if armed and not disarmed:
            # The fixed timer remains armed even if this immediate inverse
            # fails.  Never stop it on an uncertain or failed cleanup.
            try:
                cleanup()
            except (Refused, OSError, subprocess.TimeoutExpired):
                pass


class RollbackClient:
    """One held connection to the installed independent rollback service."""

    def __init__(self, path: Path = SOCKET) -> None:
        self.path = path
        self.sock: socket.socket | None = None
        self.actor_pidfd: int | None = None
        self.netns_ino: int | None = None
        self.netns_ino: int | None = None

    def arm(self, *, table: str, netns_ino: int) -> None:
        need(self.sock is None and table == TABLE and type(netns_ino) is int and
             netns_ino == os.stat("/proc/self/ns/net").st_ino,
             "invalid_rollback_client_arm")
        _trusted_socket_parent(self.path)
        named = self.path.stat(follow_symlinks=False)
        need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
             stat.S_IMODE(named.st_mode) == 0o600, "untrusted_rollback_socket")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        sock.settimeout(3.0)
        actor_pidfd: int | None = None
        try:
            sock.connect(str(self.path))
            pid, uid, _gid = struct.unpack("3i", sock.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            raw = sock.getsockopt(socket.SOL_SOCKET,
                                  getattr(socket, "SO_PEERPIDFD", 77), 4)
            need(len(raw) == 4, "rollback_actor_pidfd_unavailable")
            actor_pidfd = struct.unpack("i", raw)[0]
            info = Path(f"/proc/self/fdinfo/{actor_pidfd}").read_text(encoding="ascii")
            need(uid == 0 and pid > 1 and pid != os.getpid() and
                 any(line == f"Pid:\t{pid}" for line in info.splitlines()) and
                 os.stat(f"/proc/{pid}/ns/net").st_ino == netns_ino and
                 Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
                 "0::/system.slice/aegis-auto-trace-rollback-actor.service\n",
                 "untrusted_rollback_actor")
            _send(sock, {"op": "ARM", "table": table, "netns_ino": netns_ino})
            need(_recv(sock) == {"state": "ARMED", "table": table,
                                 "netns_ino": netns_ino}, "rollback_not_armed")
            self.sock = sock
            self.actor_pidfd = actor_pidfd
            self.netns_ino = netns_ino
        except BaseException:
            sock.close()
            if actor_pidfd is not None:
                os.close(actor_pidfd)
            raise

    def live(self) -> bool:
        if (self.sock is None or self.actor_pidfd is None or
                self.netns_ino != os.stat("/proc/self/ns/net").st_ino):
            return False
        try:
            watcher = select.poll()
            watcher.register(self.actor_pidfd,
                             select.POLLIN | select.POLLHUP | select.POLLERR)
            watcher.register(self.sock, select.POLLHUP | select.POLLERR)
            if watcher.poll(0):
                return False
            _send(self.sock, {"op": "LIVE"})
            return _recv(self.sock) == {"state": "LIVE"}
        except (Refused, OSError, ValueError, socket.timeout):
            return False

    def disarm(self) -> None:
        need(self.sock is not None, "rollback_not_armed")
        try:
            _send(self.sock, {"op": "DISARM"})
            need(_recv(self.sock) == {"state": "DISARMED"},
                 "rollback_disarm_unconfirmed")
        finally:
            self.sock.close()
            self.sock = None
            self.netns_ino = None
            if self.actor_pidfd is not None:
                os.close(self.actor_pidfd)
                self.actor_pidfd = None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["serve", "cleanup"])
    args = parser.parse_args()
    try:
        if args.action == "serve":
            serve()
        else:
            print(json.dumps(cleanup(), sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"aegis_auto_trace_rollback_refused:{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
