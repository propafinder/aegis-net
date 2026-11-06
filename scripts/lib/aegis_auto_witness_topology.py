#!/usr/bin/env python3
"""One-use, source-owned veth topology for the B-02 native deny witness.

The fixed systemd actor is independent of the guardian.  It creates only one
root-to-sink veth, never writes nft or an ACCEPT rule, holds the sink process
and control socket, and removes its exact link before releasing a lease.
systemd WatchdogSec and ExecStopPost provide a second rollback process if the
actor hangs or dies.  An AF_PACKET baseline demonstrates link/sink readiness;
ordinary UDP still has to trace to the installed guard's terminal DROP.
"""

from __future__ import annotations

import array
import hashlib
import json
import os
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT_IF = "aegisaw0"
PEER_IF = "aegisaw1"
NAMESPACE = "aegisaw-sink"
ROOT_IP = "198.18.77.1"
ROOT_IPV6 = "2001:db8:ae61:77::1"
PEER_IPV6 = "2001:db8:ae61:77::2"
PEER_IP = "198.18.77.2"
PREFIX = "30"
RUNTIME = Path("/run/aegis-auto-topology")
AUTHORITY = RUNTIME / "authority.sock"
SINK_SOCKET = RUNTIME / "sink.sock"
SINK6_SOCKET = RUNTIME / "sink6.sock"
DUAL = "dual"
SINK_READY_SECONDS = 2.0
SINK_READY_POLL = 0.002
STATE = RUNTIME / "owned-state.json"
UNIT = "aegis-auto-witness-topology.service"
SOURCE = Path("/usr/local/lib/aegis/helpers/lib/aegis_auto_witness_topology.py")
SINK_SOURCE = Path("/usr/local/lib/aegis/helpers/lib/aegis_auto_sink.py")
IP = Path("/usr/sbin/ip")
NFT = Path("/usr/sbin/nft")
SYSTEMCTL = Path("/usr/bin/systemctl")
MAX_CONTROL = 4096
LEASE_SECONDS = 55.0
HEX32 = re.compile(r"[0-9a-f]{32}\Z")


class Refused(RuntimeError):
    pass


def need(value: bool, reason: str) -> None:
    if not value:
        raise Refused(reason)


def _request_refusal_diagnostic(error: Exception) -> str:
    """Fixed class and source coordinate only; no request or error values."""
    if isinstance(error, subprocess.TimeoutExpired):
        category = "timeout_error"
    elif isinstance(error, OSError):
        category = "os_error"
    elif type(error) is Refused:
        category = "refused"
    elif isinstance(error, ValueError):
        category = "value_error"
    else:
        category = "unexpected_exception"
    line = 0
    trace = error.__traceback__
    while trace is not None:
        candidate = trace.tb_lineno
        if (trace.tb_frame.f_code.co_filename == str(SOURCE) and
                trace.tb_frame.f_code.co_name not in ("need", "_need") and
                type(candidate) is int and 1 <= candidate <= 10000):
            line = candidate
        trace = trace.tb_next
    errno_value = error.errno if category == "os_error" else None
    errno_code = (errno_value if type(errno_value) is int and
                  0 <= errno_value <= 4095 else 0)
    return f"{category} errno={errno_code} source=topology line={line}"


def _log_request_refusal(error: Exception) -> None:
    print("aegis_auto_witness_topology_request_refused:" +
          _request_refusal_diagnostic(error), file=sys.stderr, flush=True)


def _run(args: list[str], timeout: float = 2.0) -> bytes:
    result = subprocess.run(args, capture_output=True, timeout=timeout,
                            check=False,
                            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C",
                                 "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= (1 << 20) and
         len(result.stderr) <= 4096,
         f"native_command_failed:{Path(args[0]).name}:{result.returncode}")
    return result.stdout


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        need(key not in value, "duplicate_json_key")
        value[key] = item
    return value


def _json(raw: bytes) -> object:
    need(0 < len(raw) <= (1 << 20), "invalid_native_output_size")
    return json.loads(raw, object_pairs_hook=_unique)


def _canonical(value: object) -> bytes:
    def scrub(item: object) -> object:
        if type(item) is dict:
            result = {key: scrub(value) for key, value in item.items()}
            if (set(result) == {"packets", "bytes"} and
                    all(type(result[key]) is int for key in result)):
                return {"packets": 0, "bytes": 0}
            return result
        if type(item) is list:
            return [scrub(value) for value in item]
        return item
    return json.dumps(scrub(value), sort_keys=True,
                      separators=(",", ":")).encode()


_ROUTE_POLICY = None


def _route_policy():
    """Compile the existing pinned policy helper; never execute sibling pyc."""
    global _ROUTE_POLICY
    import types
    source = SOURCE.with_name('aegis_auto_foreign_policy.py')
    install = Path('/var/lib/aegis-install/client/auto-guardian-install.json')
    def protected(path, limit, mode):
        for parent in path.parents:
            info = parent.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
                 not info.st_mode & 0o022, 'route_policy_parent_untrusted')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                 stat.S_IMODE(info.st_mode) == mode and 0 < info.st_size <= limit,
                 'route_policy_source_untrusted')
            raw = os.read(fd, limit+1)
            need(len(raw) == info.st_size, 'route_policy_source_changed')
            return raw
        finally:
            os.close(fd)
    metadata = _json(protected(install, 1 << 20, 0o600))
    need(type(metadata) is dict, 'route_policy_install_invalid')
    expected = metadata.get('foreign_policy_source_sha256')
    raw = protected(source, 1 << 20, 0o500)
    need(type(expected) is str and re.fullmatch(r'[a-f0-9]{64}', expected) is not None and
         hashlib.sha256(raw).hexdigest() == expected, 'route_policy_source_changed')
    name = 'aegis_route_policy_' + SOURCE.stem
    if _ROUTE_POLICY is not None:
        need(_ROUTE_POLICY[0] == expected and sys.modules.get(name) is _ROUTE_POLICY[1],
             'route_policy_generation_changed')
        return _ROUTE_POLICY[1]
    need(name not in sys.modules, 'route_policy_module_occupied')
    module = types.ModuleType(name);module.__file__ = str(source)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(source), 'exec', dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    _ROUTE_POLICY = (expected, module)
    return module


def _restore_route_expiry(before, after, old_start, old_end, new_start, new_end):
    policy = _route_policy()
    try:
        return policy.restore_route_expiry(before, after, old_start, old_end, new_start, new_end)
    except policy.ForeignPolicyRefused as error:
        raise Refused(str(error)) from error


def _route_snapshot(record: dict[str, object] | None = None,
                    baseline: dict[str, object] | None = None) -> tuple[bytes, bytes]:
    values = []
    for family in (4, 6):
        key = 'route' + str(family)
        started = time.monotonic_ns()
        rows = _json(_run([str(IP), '-j', '-' + str(family), 'route',
                           'show', 'table', 'all']))
        finished = time.monotonic_ns()
        if record is not None:
            record.update({key + '_snapshot': rows, key + '_start_ns': started,
                           key + '_end_ns': finished})
        if baseline is not None and key + '_snapshot' in baseline:
            rows = _restore_route_expiry(baseline[key + '_snapshot'], rows,
                baseline[key + '_start_ns'], baseline[key + '_end_ns'],
                started, finished)
        values.append(_canonical(rows))
    return tuple(values)


def _nft_snapshot() -> bytes:
    return _canonical(_json(_run([str(NFT), "--json", "list", "ruleset"], 3.0)))


def _link(name: str, namespace: bool = False) -> dict[str, object] | None:
    args = [str(IP)]
    if namespace:
        args += ["netns", "exec", NAMESPACE, str(IP)]
    args += ["-j", "-d", "link", "show", "dev", name]
    result = subprocess.run(args, capture_output=True, timeout=2.0,
                            check=False,
                            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C"})
    if result.returncode != 0:
        need(len(result.stderr) <= 4096 and
             (f'Device "{name}" does not exist.' in result.stderr.decode("ascii") or
              f'Device "{name}" does not exist' in result.stderr.decode("ascii")),
             "link_readback_failed")
        return None
    value = _json(result.stdout)
    need(type(value) is list and len(value) == 1 and
         type(value[0]) is dict and value[0].get("ifname") == name,
         "ambiguous_link_readback")
    return value[0]


def _namespace_present() -> bool:
    path = Path("/run/netns") / NAMESPACE
    return path.exists() or path.is_symlink()


def _owned_veth(link: dict[str, object], name: str,
                ifindex: int | None = None) -> bool:
    info = link.get("linkinfo")
    return (link.get("ifname") == name and
            type(link.get("ifindex")) is int and
            (ifindex is None or link["ifindex"] == ifindex) and
            type(info) is dict and info.get("info_kind") == "veth")


def _boot() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()


def _root_netns() -> int:
    return os.stat("/proc/self/ns/net").st_ino


def _safe_runtime() -> None:
    state = RUNTIME.stat(follow_symlinks=False)
    need(stat.S_ISDIR(state.st_mode) and state.st_uid == 0 and
         stat.S_IMODE(state.st_mode) == 0o700, "untrusted_topology_runtime")


def _write_state(value: dict[str, object]) -> None:
    _safe_runtime()
    temporary = RUNTIME / "owned-state.pending"
    need(not temporary.exists() and not temporary.is_symlink(),
         "stale_state_temporary")
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), "state_short_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, STATE)
    parent = os.open(RUNTIME, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _read_state() -> dict[str, object] | None:
    if not STATE.exists() and not STATE.is_symlink():
        return None
    fd = os.open(STATE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                 os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and
             stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and
             0 < s.st_size <= (1 << 20), "untrusted_topology_state")
        value = _json(os.read(fd, (1 << 20) + 1))
        need(type(value) is dict and value.get("schema") ==
             "aegis_auto_witness_topology_state_v1" and
             value.get("boot_id") == _boot() and
             value.get("root_netns_ino") == _root_netns(),
             "stale_or_foreign_topology_state")
        return value
    finally:
        os.close(fd)


def cleanup_fixed() -> dict[str, object]:
    """PID1 fallback inverse: fixed names plus protected state and kernel kind."""
    need(os.geteuid() == 0 and Path("/proc/self/ns/net").exists(),
         "linux_root_required")
    _safe_runtime()
    state = _read_state()
    root = _link(ROOT_IF)
    ns = _namespace_present()
    if state is None:
        need(root is None and not ns, "owned_state_missing_with_live_topology")
        return {"schema": "aegis_auto_witness_topology_cleanup_v1",
                "already_absent": True, "routes_restored": True}
    need(state.get("root_if") == ROOT_IF and state.get("peer_if") == PEER_IF and
         state.get("namespace") == NAMESPACE and
         state.get("phase") in ("pending", "live", "cleaning"),
         "foreign_topology_state")
    if ns:
        namespace_ino = state.get("sink_netns_ino")
        need(type(namespace_ino) is int and namespace_ino > 0 and
             os.stat("/run/netns/" + NAMESPACE).st_ino == namespace_ino,
             "owned_namespace_identity_unrecorded_or_changed")
    owned_sockets = []
    for path, prefix in ((SINK_SOCKET, "sink_socket"), (SINK6_SOCKET, "sink6_socket")):
        if not (path.exists() or path.is_symlink()):
            continue
        named = path.stat(follow_symlinks=False)
        need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
             stat.S_IMODE(named.st_mode) == 0o600 and
             named.st_dev == state.get(prefix + "_dev") and
             named.st_ino == state.get(prefix + "_ino"),
             "owned_sink_socket_replaced")
        owned_sockets.append(path)
    if root is not None:
        saved_index = state.get("root_ifindex")
        need(type(saved_index) is int and
             _owned_veth(root, ROOT_IF, saved_index),
             "owned_root_link_replaced")
        if ns and state.get("phase") == "live":
            peer = _link(PEER_IF, True)
            need(peer is not None and _owned_veth(
                peer, PEER_IF, state.get("peer_ifindex")),
                 "owned_peer_link_replaced")
        _run([str(IP), "link", "del", "dev", ROOT_IF])
    if ns:
        _run([str(IP), "netns", "del", NAMESPACE])
    for path in owned_sockets:
        path.unlink()
    need(_link(ROOT_IF) is None and not _namespace_present(),
         "topology_remains_after_cleanup")
    baseline4 = state.get("route4_sha256")
    baseline6 = state.get("route6_sha256")
    now4, now6 = _route_snapshot(baseline=state)
    need(hashlib.sha256(now4).hexdigest() == baseline4 and
         hashlib.sha256(now6).hexdigest() == baseline6,
         "root_routes_not_restored")
    # Topology never edits nft.  Compare around the inverse only; the device
    # guard legitimately remains installed after this veth is removed.
    if STATE.exists():
        STATE.unlink()
    return {"schema": "aegis_auto_witness_topology_cleanup_v1",
            "already_absent": False, "routes_restored": True}


def _notify(value: str) -> None:
    path = os.environ.get("NOTIFY_SOCKET")
    need(path is not None and path != "", "systemd_notify_socket_missing")
    address = "\0" + path[1:] if path.startswith("@") else path
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.connect(address)
        sock.sendall(value.encode())


def _watchdog_ready() -> None:
    raw = _run([str(SYSTEMCTL), "show", UNIT, "-p", "MainPID",
                "-p", "ActiveState", "-p", "WatchdogUSec", "--no-pager"])
    facts: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        need(separator == "=" and key not in facts, "bad_watchdog_readback")
        facts[key] = value
    need(facts.get("MainPID") == str(os.getpid()) and
         facts.get("ActiveState") == "active" and
         facts.get("WatchdogUSec") in ("10s", "10000000us"),
         "independent_pid1_watchdog_not_armed")


def _send(peer: socket.socket, value: dict[str, object],
          fd: int | list[int] | None = None) -> None:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    need(len(payload) <= MAX_CONTROL, "oversized_topology_response")
    if fd is None:
        need(peer.send(payload) == len(payload), "short_topology_response")
    else:
        rights = array.array("i", fd if type(fd) is list else [fd])
        need(peer.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                       rights.tobytes())]) == len(payload),
             "short_topology_fd_response")


def _recv(peer: socket.socket) -> dict[str, object]:
    data, anc, flags, _addr = peer.recvmsg(MAX_CONTROL)
    need(bool(data) and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0 and
         not anc, "invalid_topology_request")
    value = _json(data)
    need(type(value) is dict, "invalid_topology_request")
    return value


def _peer_guardian(peer: socket.socket) -> tuple[int, int]:
    pid, uid, _gid = struct.unpack("3i", peer.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(uid == 0 and pid > 1, "foreign_topology_peer")
    raw = peer.getsockopt(socket.SOL_SOCKET,
                          getattr(socket, "SO_PEERPIDFD", 77), 4)
    need(len(raw) == 4, "guardian_peer_pidfd_unavailable")
    pidfd = struct.unpack("i", raw)[0]
    try:
        info = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="ascii")
        need(any(line == f"Pid:\t{pid}" for line in info.splitlines()) and
             Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
             "0::/system.slice/aegis-auto-guardian.service\n" and
             os.stat(f"/proc/{pid}/ns/net").st_ino == _root_netns(),
             "foreign_topology_peer")
        watcher = select.poll()
        watcher.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        need(not watcher.poll(0), "guardian_exited_before_topology")
        return pid, pidfd
    except BaseException:
        os.close(pidfd)
        raise


def _prepare(actor_challenge: bytes, family: int = 4) -> tuple[dict[str, object], subprocess.Popen[bytes], socket.socket]:
    need(type(actor_challenge) is bytes and len(actor_challenge) == 32 and family in (4,6),
         "invalid_actor_challenge")
    peer_ip=PEER_IPV6 if family==6 else PEER_IP
    root_ip=ROOT_IPV6 if family==6 else ROOT_IP
    prefix="64" if family==6 else PREFIX
    # Both family proofs share the authenticated challenge, but each retains
    # its own one-use receipt. A legacy receipt still fences the challenge.
    legacy_receipt = RUNTIME / ("sink-receipt-" + actor_challenge.hex() + ".json")
    sink_receipt = RUNTIME / ("sink-receipt-" + str(family) + "-" +
                              actor_challenge.hex() + ".json")
    _watchdog_ready()  # PID1 must be armed before any veth/netns mutation.
    need(_link(ROOT_IF) is None and not _namespace_present() and
         not STATE.exists() and not STATE.is_symlink() and
         not SINK_SOCKET.exists() and not SINK_SOCKET.is_symlink() and
         not SINK6_SOCKET.exists() and not SINK6_SOCKET.is_symlink() and
         not sink_receipt.exists() and not sink_receipt.is_symlink() and
         not legacy_receipt.exists() and not legacy_receipt.is_symlink(),
         "existing_witness_topology")
    route_record: dict[str, object] = {}
    route4, route6 = _route_snapshot(record=route_record)
    nft_before = _nft_snapshot()
    boot_id = _boot()
    root_ns = _root_netns()
    state: dict[str, object] = {
        "schema": "aegis_auto_witness_topology_state_v1",
        **route_record, "phase": "pending", "boot_id": boot_id,
        "root_netns_ino": root_ns, "root_if": ROOT_IF,
        "peer_if": PEER_IF, "namespace": NAMESPACE,
        "route4_sha256": hashlib.sha256(route4).hexdigest(),
        "route6_sha256": hashlib.sha256(route6).hexdigest(),
        "nft_sha256": hashlib.sha256(nft_before).hexdigest()}
    _write_state(state)
    sink: subprocess.Popen[bytes] | None = None
    control: socket.socket | None = None
    try:
        _run([str(IP), "netns", "add", NAMESPACE])
        state["sink_netns_ino"] = os.stat("/run/netns/" + NAMESPACE).st_ino
        _write_state(state)
        _run([str(IP), "link", "add", ROOT_IF, "type", "veth",
              "peer", "name", PEER_IF])
        created_root = _link(ROOT_IF)
        need(created_root is not None and _owned_veth(created_root, ROOT_IF),
             "witness_root_veth_not_created")
        state["root_ifindex"] = created_root["ifindex"]
        _write_state(state)
        _run([str(IP), "link", "set", PEER_IF, "netns", NAMESPACE])
        _run([str(IP), "addr", "add", root_ip + "/" + prefix,
              "dev", ROOT_IF, *(["nodad"] if family==6 else [])])
        _run([str(IP), "link", "set", ROOT_IF, "up"])
        _run([str(IP), "netns", "exec", NAMESPACE, str(IP),
              "addr", "add", peer_ip + "/" + prefix,
              "dev", PEER_IF, *(["nodad"] if family==6 else [])])
        _run([str(IP), "netns", "exec", NAMESPACE, str(IP),
              "link", "set", PEER_IF, "up"])
        _run([str(IP), "netns", "exec", NAMESPACE, str(IP),
              "link", "set", "lo", "up"])
        root_link = _link(ROOT_IF)
        peer_link = _link(PEER_IF, True)
        need(root_link is not None and peer_link is not None and
             _owned_veth(root_link, ROOT_IF) and
             _owned_veth(peer_link, PEER_IF), "witness_veth_not_owned")
        peer_mac = peer_link.get("address")
        need(type(peer_mac) is str and
             re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", peer_mac) is not None,
             "peer_mac_missing")
        state.update({"phase": "live", "root_ifindex": root_link["ifindex"],
                      "peer_ifindex": peer_link["ifindex"],
                      "peer_mac": peer_mac})
        _write_state(state)
        need(_nft_snapshot() == nft_before, "topology_changed_nft")
        sink_port = 47000 + int.from_bytes(os.urandom(2), "big") % 1000
        sink = _start_sink(SINK_SOCKET, peer_ip, sink_port, sink_receipt)
        named, = _await_sink_sockets([(sink, SINK_SOCKET)])
        state["sink_socket_dev"] = named.st_dev
        state["sink_socket_ino"] = named.st_ino
        _write_state(state)
        control, sink_pid = _connect_sink(SINK_SOCKET, state["sink_netns_ino"])
        baseline_nonce = os.urandom(32)
        challenge_nonce = actor_challenge
        source_port = 48000 + int.from_bytes(os.urandom(2), "big") % 1000
        result = {"schema": "aegis_auto_witness_topology_v1",
                  "boot_id": boot_id, "root_netns_ino": root_ns,
                  "root_if": ROOT_IF, "root_ifindex": root_link["ifindex"],
                  "sink_netns_ino": state["sink_netns_ino"],
                  "sink_pid": sink_pid, "peer_ipv4": peer_ip, "address_family": family,
                  "sink_receipt": str(sink_receipt),
                  "peer_mac": peer_mac, "sink_port": sink_port,
                  "source_port": source_port,
                  "baseline_nonce_hex": baseline_nonce.hex(),
                  "challenge_nonce_hex": challenge_nonce.hex(),
                  "actor_challenge_hex": challenge_nonce.hex(),
                  "route4_before_sha256": state["route4_sha256"],
                  "route6_before_sha256": state["route6_sha256"],
                  "nft_before_sha256": state["nft_sha256"]}
        return result, sink, control
    except BaseException:
        if control is not None:
            control.close()
        if sink is not None:
            sink.kill() if sink.poll() is None else None
            sink.wait(timeout=2)
        cleanup_fixed()
        raise


def _receipt_paths(actor_challenge: bytes) -> tuple[Path, Path, Path]:
    """Legacy and per-family one-use receipts; none is ever unlinked."""
    return (RUNTIME / ("sink-receipt-" + actor_challenge.hex() + ".json"),
            RUNTIME / ("sink-receipt-4-" + actor_challenge.hex() + ".json"),
            RUNTIME / ("sink-receipt-6-" + actor_challenge.hex() + ".json"))


def _start_sink(control: Path, listen_ip: str, port: int,
                receipt: Path) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [str(IP), "netns", "exec", NAMESPACE, "/usr/bin/python3",
         "-I", "-B", str(SINK_SOURCE), "serve", "--socket",
         str(control), "--listen-ip", listen_ip, "--port",
         str(port), "--receipt", str(receipt),
         "--maximum-seconds", "60",
         "--retain-after-complete-for-witness"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, close_fds=True,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})


def _await_sink_sockets(started: list[tuple[subprocess.Popen[bytes], Path]]
                        ) -> list[os.stat_result]:
    """Wait for every concurrently started sink under one 2 s bound."""
    deadline = time.monotonic() + SINK_READY_SECONDS
    while not all(path.exists() for _sink, path in started) and time.monotonic() < deadline:
        need(all(sink.poll() is None for sink, _path in started),
             "independent_sink_exited")
        time.sleep(SINK_READY_POLL)
    identities = []
    for _sink, path in started:
        named = path.stat(follow_symlinks=False)
        need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
             stat.S_IMODE(named.st_mode) == 0o600,
             "independent_sink_socket_missing")
        identities.append(named)
    return identities


def _connect_sink(path: Path, sink_netns_ino: int) -> tuple[socket.socket, int]:
    control = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        control.connect(str(path))
        sink_pid, sink_uid, _ = struct.unpack("3i", control.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(sink_uid == 0 and sink_pid > 1 and
             os.stat(f"/proc/{sink_pid}/ns/net").st_ino == sink_netns_ino,
             "independent_sink_identity_changed")
        return control, sink_pid
    except BaseException:
        control.close()
        raise


def _distinct_ports(base: int) -> tuple[int, int]:
    """Two different ports from one fixed 1000-port range."""
    first = base + int.from_bytes(os.urandom(2), "big") % 1000
    while True:
        second = base + int.from_bytes(os.urandom(2), "big") % 1000
        if second != first:
            return first, second


def _prepare_dual(actor_challenge: bytes) -> tuple[dict[str, object],
                                                   list[subprocess.Popen[bytes]],
                                                   list[socket.socket]]:
    """One veth carrying both families and two independent sinks.

    The IPv4 /30 and the nodad IPv6 /64 share the one root/peer pair, so one
    inverse removes both. Each family has its own sink process, control
    socket, receipt, sink port and source port. The two source ports differ,
    so the senders can never collide on a dual-stack bind.
    """
    need(type(actor_challenge) is bytes and len(actor_challenge) == 32,
         "invalid_actor_challenge")
    legacy_receipt, receipt4, receipt6 = _receipt_paths(actor_challenge)
    _watchdog_ready()  # PID1 must be armed before any veth/netns mutation.
    need(_link(ROOT_IF) is None and not _namespace_present() and
         all(not path.exists() and not path.is_symlink() for path in
             (STATE, SINK_SOCKET, SINK6_SOCKET, legacy_receipt, receipt4, receipt6)),
         "existing_witness_topology")
    route_record: dict[str, object] = {}
    route4, route6 = _route_snapshot(record=route_record)
    nft_before = _nft_snapshot()
    boot_id = _boot()
    root_ns = _root_netns()
    state: dict[str, object] = {
        "schema": "aegis_auto_witness_topology_state_v1",
        **route_record, "phase": "pending", "boot_id": boot_id,
        "root_netns_ino": root_ns, "root_if": ROOT_IF,
        "peer_if": PEER_IF, "namespace": NAMESPACE, "address_family": DUAL,
        "route4_sha256": hashlib.sha256(route4).hexdigest(),
        "route6_sha256": hashlib.sha256(route6).hexdigest(),
        "nft_sha256": hashlib.sha256(nft_before).hexdigest()}
    _write_state(state)
    sinks: list[subprocess.Popen[bytes]] = []
    controls: list[socket.socket] = []
    try:
        _run([str(IP), "netns", "add", NAMESPACE])
        state["sink_netns_ino"] = os.stat("/run/netns/" + NAMESPACE).st_ino
        _write_state(state)
        _run([str(IP), "link", "add", ROOT_IF, "type", "veth",
              "peer", "name", PEER_IF])
        created_root = _link(ROOT_IF)
        need(created_root is not None and _owned_veth(created_root, ROOT_IF),
             "witness_root_veth_not_created")
        state["root_ifindex"] = created_root["ifindex"]
        _write_state(state)
        _run([str(IP), "link", "set", PEER_IF, "netns", NAMESPACE])
        _run([str(IP), "addr", "add", ROOT_IP + "/" + PREFIX, "dev", ROOT_IF])
        _run([str(IP), "addr", "add", ROOT_IPV6 + "/64", "dev", ROOT_IF, "nodad"])
        _run([str(IP), "link", "set", ROOT_IF, "up"])
        _run([str(IP), "netns", "exec", NAMESPACE, str(IP),
              "addr", "add", PEER_IP + "/" + PREFIX, "dev", PEER_IF])
        _run([str(IP), "netns", "exec", NAMESPACE, str(IP),
              "addr", "add", PEER_IPV6 + "/64", "dev", PEER_IF, "nodad"])
        _run([str(IP), "netns", "exec", NAMESPACE, str(IP),
              "link", "set", PEER_IF, "up"])
        _run([str(IP), "netns", "exec", NAMESPACE, str(IP),
              "link", "set", "lo", "up"])
        root_link = _link(ROOT_IF)
        peer_link = _link(PEER_IF, True)
        need(root_link is not None and peer_link is not None and
             _owned_veth(root_link, ROOT_IF) and
             _owned_veth(peer_link, PEER_IF), "witness_veth_not_owned")
        peer_mac = peer_link.get("address")
        need(type(peer_mac) is str and
             re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", peer_mac) is not None,
             "peer_mac_missing")
        state.update({"phase": "live", "root_ifindex": root_link["ifindex"],
                      "peer_ifindex": peer_link["ifindex"],
                      "peer_mac": peer_mac})
        _write_state(state)
        need(_nft_snapshot() == nft_before, "topology_changed_nft")
        sink_port4, sink_port6 = _distinct_ports(47000)
        source_port4, source_port6 = _distinct_ports(48000)
        # Both sinks start together; each keeps its own socket and receipt.
        sinks.append(_start_sink(SINK_SOCKET, PEER_IP, sink_port4, receipt4))
        sinks.append(_start_sink(SINK6_SOCKET, PEER_IPV6, sink_port6, receipt6))
        named4, named6 = _await_sink_sockets([(sinks[0], SINK_SOCKET),
                                              (sinks[1], SINK6_SOCKET)])
        state.update({"sink_socket_dev": named4.st_dev, "sink_socket_ino": named4.st_ino,
                      "sink6_socket_dev": named6.st_dev, "sink6_socket_ino": named6.st_ino})
        _write_state(state)
        pids = []
        for path in (SINK_SOCKET, SINK6_SOCKET):
            control, pid = _connect_sink(path, state["sink_netns_ino"])
            controls.append(control)
            pids.append(pid)
        need(pids[0] != pids[1], "independent_sink_identity_changed")
        families = {}
        for family, pid, peer_ip, sink_port, source_port, receipt in (
                (4, pids[0], PEER_IP, sink_port4, source_port4, receipt4),
                (6, pids[1], PEER_IPV6, sink_port6, source_port6, receipt6)):
            families[str(family)] = {
                "address_family": family, "sink_pid": pid, "peer_ip": peer_ip,
                "sink_port": sink_port, "source_port": source_port,
                "sink_receipt": str(receipt),
                "baseline_nonce_hex": os.urandom(32).hex()}
        result = {"schema": "aegis_auto_witness_topology_dual_v1",
                  "boot_id": boot_id, "root_netns_ino": root_ns,
                  "root_if": ROOT_IF, "root_ifindex": root_link["ifindex"],
                  "sink_netns_ino": state["sink_netns_ino"],
                  "peer_mac": peer_mac, "address_family": DUAL,
                  "families": families,
                  "challenge_nonce_hex": actor_challenge.hex(),
                  "actor_challenge_hex": actor_challenge.hex(),
                  "route4_before_sha256": state["route4_sha256"],
                  "route6_before_sha256": state["route6_sha256"],
                  "nft_before_sha256": state["nft_sha256"]}
        return result, sinks, controls
    except BaseException:
        for control in controls:
            control.close()
        for sink in sinks:
            sink.kill() if sink.poll() is None else None
            sink.wait(timeout=2)
        cleanup_fixed()
        raise


def _terminate_live_sink(sink: subprocess.Popen[bytes]) -> None:
    need(sink.poll() is None, "independent_sink_exited_before_cleanup")
    sink.kill()
    need(sink.wait(timeout=2) == -signal.SIGKILL,
         "independent_sink_cleanup_exit_mismatch")


def _serve_peer(peer: socket.socket) -> None:
    _peer_pid, owner_pidfd = _peer_guardian(peer)
    sinks: list[subprocess.Popen[bytes]] = []
    controls: list[socket.socket] = []
    prepared = False
    try:
        request = _recv(peer)
        need(set(request) in ({"op", "actor_challenge"},{"op", "actor_challenge", "address_family"}) and
             request.get("address_family",4) in (4,6,DUAL) and
             request["op"] == "PROVISION" and
             type(request["actor_challenge"]) is str and
             re.fullmatch(r"[0-9a-f]{64}", request["actor_challenge"]) is not None,
             "provision_required")
        if request.get("address_family") == DUAL:
            result, sinks, controls = _prepare_dual(bytes.fromhex(request["actor_challenge"]))
        else:
            result, sink, control = _prepare(bytes.fromhex(request["actor_challenge"]),
                                             request.get("address_family",4))
            sinks, controls = [sink], [control]
        prepared = True
        _send(peer, result, [control.fileno() for control in controls])
        # The guardian owns its duplicate control FD.  Keep ours so the same
        # sink socket cannot be swapped before cleanup, but never send on it.
        watcher = select.poll()
        watcher.register(peer, select.POLLIN | select.POLLHUP | select.POLLERR)
        watcher.register(owner_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        deadline = time.monotonic() + LEASE_SECONDS
        while True:
            _notify("WATCHDOG=1")
            left = deadline - time.monotonic()
            need(left > 0, "topology_lease_expired")
            for fd, event in watcher.poll(max(1, min(1000, int(left * 1000)))):
                if fd == owner_pidfd or event & (select.POLLHUP | select.POLLERR):
                    raise Refused("topology_owner_exited")
                request = _recv(peer)
                need(request == {"op": "CLEANUP"}, "unexpected_topology_command")
                before_cleanup_nft = _nft_snapshot()
                need(all(sink.poll() is None for sink in sinks),
                     "independent_sink_exited_before_cleanup")
                while controls:
                    controls.pop().close()
                for sink in sinks:
                    _terminate_live_sink(sink)
                state = cleanup_fixed()
                need(_nft_snapshot() == before_cleanup_nft,
                     "topology_cleanup_changed_nft")
                prepared = False
                _send(peer, {"state": "CLEAN", "routes_restored":
                             state["routes_restored"], "nft_unchanged": True})
                return
    finally:
        os.close(owner_pidfd)
        for control in controls:
            control.close()
        for sink in sinks:
            if sink.poll() is None:
                sink.kill()
                sink.wait(timeout=2)
        if prepared:
            cleanup_fixed()


def _stop_service(_signum, _frame) -> None:
    # Run the peer/topology and listening-socket finally blocks on PID1 Stop.
    raise SystemExit(0)


def serve() -> None:
    previous = {sig: signal.signal(sig, _stop_service)
                for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        _serve_until_stopped()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _serve_until_stopped() -> None:
    need(os.geteuid() == 0 and Path("/proc/self/ns/net").exists(),
         "linux_root_required")
    _safe_runtime()
    need(not AUTHORITY.exists() and not AUTHORITY.is_symlink(),
         "authority_socket_exists")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(str(AUTHORITY))
    os.chmod(AUTHORITY, 0o600)
    server.listen(1)
    server.settimeout(1.0)
    try:
        _notify("READY=1")
        while True:
            _notify("WATCHDOG=1")
            try:
                peer, _ = server.accept()
            except socket.timeout:
                continue
            try:
                _serve_peer(peer)
            except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as error:
                try:
                    _log_request_refusal(error)
                except OSError:
                    pass
                try:
                    _send(peer, {"state": "REFUSED", "reason": str(error)[:128]})
                except OSError:
                    pass
            finally:
                peer.close()
    finally:
        server.close()
        try:
            AUTHORITY.unlink()
        except FileNotFoundError:
            pass


@dataclass
class TopologyLease:
    authority: socket.socket
    sink: socket.socket
    facts: dict[str, object]
    actor_challenge: bytes
    actor_pidfd: int
    sink_pidfd: int
    closed: bool = False

    def verify(self) -> None:
        need(not self.closed and self.facts["boot_id"] == _boot() and
             self.facts["root_netns_ino"] == _root_netns() and
             self.facts["actor_challenge_hex"] == self.actor_challenge.hex() and
             self.facts["challenge_nonce_hex"] == self.actor_challenge.hex(),
             "topology_lease_identity_changed")
        watcher = select.poll()
        watcher.register(self.actor_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        watcher.register(self.sink_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        watcher.register(self.authority, select.POLLHUP | select.POLLERR)
        watcher.register(self.sink, select.POLLHUP | select.POLLERR)
        need(not watcher.poll(0), "topology_actor_or_sink_exited")
        link = _link(ROOT_IF)
        need(link is not None and _owned_veth(
            link, ROOT_IF, self.facts["root_ifindex"]),
             "topology_link_changed")
        need(_namespace_present() and
             os.stat("/run/netns/" + NAMESPACE).st_ino ==
             self.facts["sink_netns_ino"], "topology_namespace_changed")
        sink_pid, sink_uid, _ = struct.unpack("3i", self.sink.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(sink_uid == 0 and sink_pid == self.facts["sink_pid"] and
             os.stat(f"/proc/{sink_pid}/ns/net").st_ino ==
             self.facts["sink_netns_ino"], "topology_sink_changed")

    @property
    def peer_mac(self) -> bytes:
        return bytes.fromhex(str(self.facts["peer_mac"]).replace(":", ""))

    def cleanup(self) -> dict[str, object]:
        need(not self.closed, "topology_lease_already_closed")
        try:
            self.authority.send(b'{"op":"CLEANUP"}')
            self.authority.settimeout(6.0)
            result = _json(self.authority.recv(MAX_CONTROL))
            need(result == {"state": "CLEAN", "routes_restored": True,
                            "nft_unchanged": True},
                 "topology_cleanup_unconfirmed")
            return result
        finally:
            self.closed = True
            self.sink.close()
            self.authority.close()
            os.close(self.actor_pidfd)
            os.close(self.sink_pidfd)


@dataclass
class DualTopologyLease:
    """Held FDs for one veth, two sinks and their pidfds; one inverse."""

    authority: socket.socket
    sinks: dict[int, socket.socket]
    facts: dict[str, object]
    actor_challenge: bytes
    actor_pidfd: int
    sink_pidfds: dict[int, int]
    closed: bool = False

    def family(self, family: int) -> dict[str, object]:
        return self.facts["families"][str(family)]

    def verify(self) -> None:
        """Both sinks' pidfds, credentials and netns, both control sockets,
        the actor pidfd, the root veth ifindex and the namespace inode."""
        need(not self.closed and self.facts["boot_id"] == _boot() and
             self.facts["root_netns_ino"] == _root_netns() and
             self.facts["actor_challenge_hex"] == self.actor_challenge.hex() and
             self.facts["challenge_nonce_hex"] == self.actor_challenge.hex(),
             "topology_lease_identity_changed")
        watcher = select.poll()
        watcher.register(self.actor_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        watcher.register(self.authority, select.POLLHUP | select.POLLERR)
        for family in (4, 6):
            watcher.register(self.sink_pidfds[family],
                             select.POLLIN | select.POLLHUP | select.POLLERR)
            watcher.register(self.sinks[family], select.POLLHUP | select.POLLERR)
        need(not watcher.poll(0), "topology_actor_or_sink_exited")
        link = _link(ROOT_IF)
        need(link is not None and _owned_veth(
            link, ROOT_IF, self.facts["root_ifindex"]),
             "topology_link_changed")
        need(_namespace_present() and
             os.stat("/run/netns/" + NAMESPACE).st_ino ==
             self.facts["sink_netns_ino"], "topology_namespace_changed")
        for family in (4, 6):
            sink_pid, sink_uid, _ = struct.unpack("3i", self.sinks[family].getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            need(sink_uid == 0 and sink_pid == self.family(family)["sink_pid"] and
                 os.stat(f"/proc/{sink_pid}/ns/net").st_ino ==
                 self.facts["sink_netns_ino"], "topology_sink_changed")

    @property
    def peer_mac(self) -> bytes:
        return bytes.fromhex(str(self.facts["peer_mac"]).replace(":", ""))

    def cleanup(self) -> dict[str, object]:
        need(not self.closed, "topology_lease_already_closed")
        try:
            self.authority.send(b'{"op":"CLEANUP"}')
            self.authority.settimeout(6.0)
            result = _json(self.authority.recv(MAX_CONTROL))
            need(result == {"state": "CLEAN", "routes_restored": True,
                            "nft_unchanged": True},
                 "topology_cleanup_unconfirmed")
            return result
        finally:
            self.closed = True
            for sink in self.sinks.values():
                sink.close()
            self.authority.close()
            os.close(self.actor_pidfd)
            for pidfd in self.sink_pidfds.values():
                os.close(pidfd)

    def receipts_retained(self) -> None:
        """Both one-use receipts survive the inverse as challenge fences."""
        need(self.closed, "topology_lease_still_open")
        for family in (4, 6):
            path = Path(str(self.family(family)["sink_receipt"]))
            need(path == _receipt_paths(self.actor_challenge)[1 if family == 4 else 2],
                 "sink_receipt_path_changed")
            info = path.stat(follow_symlinks=False)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                 stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                 "sink_receipt_not_retained")


def _authenticated_actor(authority: socket.socket) -> int:
    actor_pid, actor_uid, _ = struct.unpack("3i", authority.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(actor_uid == 0 and actor_pid > 1, "foreign_topology_actor")
    raw = authority.getsockopt(socket.SOL_SOCKET,
                               getattr(socket, "SO_PEERPIDFD", 77), 4)
    need(len(raw) == 4, "topology_actor_pidfd_unavailable")
    actor_pidfd = struct.unpack("i", raw)[0]
    try:
        info = Path(f"/proc/self/fdinfo/{actor_pidfd}").read_text(encoding="ascii")
        need(any(line == f"Pid:\t{actor_pid}" for line in info.splitlines()) and
             Path(f"/proc/{actor_pid}/cgroup").read_text(encoding="ascii") ==
             "0::/system.slice/aegis-auto-witness-topology.service\n",
             "foreign_topology_actor")
        return actor_pidfd
    except BaseException:
        os.close(actor_pidfd)
        raise


def _sink_pidfd(sink: socket.socket, expected_pid: int) -> int:
    sink_pid, sink_uid, _ = struct.unpack("3i", sink.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(sink_uid == 0 and sink_pid == expected_pid, "foreign_topology_sink")
    raw = sink.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERPIDFD", 77), 4)
    need(len(raw) == 4, "topology_sink_pidfd_unavailable")
    pidfd = struct.unpack("i", raw)[0]
    try:
        info = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="ascii")
        need(any(line == f"Pid:\t{sink_pid}" for line in info.splitlines()),
             "foreign_topology_sink")
        return pidfd
    except BaseException:
        os.close(pidfd)
        raise


def _dual_facts_valid(facts: object, actor_challenge: bytes) -> bool:
    if not (type(facts) is dict and facts.get("schema") == "aegis_auto_witness_topology_dual_v1" and
            facts.get("root_if") == ROOT_IF and facts.get("address_family") == DUAL and
            facts.get("actor_challenge_hex") == actor_challenge.hex() and
            facts.get("challenge_nonce_hex") == actor_challenge.hex() and
            type(facts.get("root_ifindex")) is int and
            type(facts.get("sink_netns_ino")) is int and
            type(facts.get("families")) is dict and set(facts["families"]) == {"4", "6"}):
        return False
    rows = facts["families"]
    for family, peer_ip in ((4, PEER_IP), (6, PEER_IPV6)):
        row = rows[str(family)]
        if not (type(row) is dict and set(row) == {
                "address_family", "sink_pid", "peer_ip", "sink_port", "source_port",
                "sink_receipt", "baseline_nonce_hex"} and
                row["address_family"] == family and row["peer_ip"] == peer_ip and
                type(row["sink_pid"]) is int and row["sink_pid"] > 1 and
                all(type(row[k]) is int for k in ("sink_port", "source_port")) and
                47000 <= row["sink_port"] < 48000 and 48000 <= row["source_port"] < 49000 and
                row["sink_receipt"] == str(_receipt_paths(actor_challenge)[1 if family == 4 else 2]) and
                type(row["baseline_nonce_hex"]) is str and
                re.fullmatch(r"[0-9a-f]{64}", row["baseline_nonce_hex"]) is not None):
            return False
    return (rows["4"]["sink_pid"] != rows["6"]["sink_pid"] and
            rows["4"]["source_port"] != rows["6"]["source_port"] and
            rows["4"]["baseline_nonce_hex"] != rows["6"]["baseline_nonce_hex"])


def provision_dual(actor_challenge: bytes) -> DualTopologyLease:
    """Return one held dual-family lease, never reconstructable from JSON."""
    need(os.geteuid() == 0 and Path("/proc/self/ns/net").exists(),
         "linux_root_required")
    need(type(actor_challenge) is bytes and len(actor_challenge) == 32,
         "invalid_actor_challenge")
    _safe_runtime()
    named = AUTHORITY.stat(follow_symlinks=False)
    need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
         stat.S_IMODE(named.st_mode) == 0o600, "untrusted_topology_actor")
    authority = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    actor_pidfd: int | None = None
    sink_pidfds: dict[int, int] = {}
    descriptors = array.array("i")
    sinks: dict[int, socket.socket] = {}
    try:
        authority.settimeout(10.0)
        authority.connect(str(AUTHORITY))
        actor_pidfd = _authenticated_actor(authority)
        request = json.dumps({"op": "PROVISION", "address_family": DUAL,
                              "actor_challenge": actor_challenge.hex()},
                             separators=(",", ":")).encode()
        need(authority.send(request) == len(request),
             "topology_provision_send_failed")
        payload, anc, flags, _addr = authority.recvmsg(MAX_CONTROL,
                                                        socket.CMSG_SPACE(8))
        need(payload and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0,
             "topology_provision_truncated")
        for level, kind, data in anc:
            need(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS,
                 "unexpected_topology_ancillary_data")
            descriptors.frombytes(data[:len(data) - len(data) % 4])
        facts = _json(payload)
        need(len(descriptors) == 2 and _dual_facts_valid(facts, actor_challenge),
             "invalid_topology_provision")
        for index, family in enumerate((4, 6)):
            sinks[family] = socket.socket(fileno=descriptors[index])
        descriptors = array.array("i")
        for family in (4, 6):
            sink_pidfds[family] = _sink_pidfd(sinks[family],
                                              facts["families"][str(family)]["sink_pid"])
        lease = DualTopologyLease(authority, sinks, facts, actor_challenge,
                                  actor_pidfd, sink_pidfds)
        lease.verify()
        return lease
    except BaseException:
        authority.close()
        for sink in sinks.values():
            sink.close()
        for descriptor in descriptors:
            os.close(descriptor)
        if actor_pidfd is not None:
            os.close(actor_pidfd)
        for pidfd in sink_pidfds.values():
            os.close(pidfd)
        raise


def provision(actor_challenge: bytes, family: int = 4) -> TopologyLease:
    """Return a held FD lease, never reconstructable from a JSON receipt."""
    need(os.geteuid() == 0 and Path("/proc/self/ns/net").exists(),
         "linux_root_required")
    need(type(actor_challenge) is bytes and len(actor_challenge) == 32,
         "invalid_actor_challenge")
    _safe_runtime()
    named = AUTHORITY.stat(follow_symlinks=False)
    need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
         stat.S_IMODE(named.st_mode) == 0o600, "untrusted_topology_actor")
    authority = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    actor_pidfd: int | None = None
    sink_pidfd: int | None = None
    descriptors = array.array("i")
    sink: socket.socket | None = None
    try:
        authority.settimeout(10.0)
        authority.connect(str(AUTHORITY))
        actor_pid, actor_uid, _ = struct.unpack("3i", authority.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(actor_uid == 0 and actor_pid > 1, "foreign_topology_actor")
        raw = authority.getsockopt(socket.SOL_SOCKET,
                                   getattr(socket, "SO_PEERPIDFD", 77), 4)
        need(len(raw) == 4, "topology_actor_pidfd_unavailable")
        actor_pidfd = struct.unpack("i", raw)[0]
        info = Path(f"/proc/self/fdinfo/{actor_pidfd}").read_text(encoding="ascii")
        need(any(line == f"Pid:\t{actor_pid}" for line in info.splitlines()) and
             Path(f"/proc/{actor_pid}/cgroup").read_text(encoding="ascii") ==
             "0::/system.slice/aegis-auto-witness-topology.service\n",
             "foreign_topology_actor")
        request = json.dumps({"op": "PROVISION", "address_family":family,
                              "actor_challenge": actor_challenge.hex()},
                             separators=(",", ":")).encode()
        need(authority.send(request) == len(request),
             "topology_provision_send_failed")
        payload, anc, flags, _addr = authority.recvmsg(MAX_CONTROL,
                                                        socket.CMSG_SPACE(4))
        need(payload and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0,
             "topology_provision_truncated")
        for level, kind, data in anc:
            need(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS,
                 "unexpected_topology_ancillary_data")
            descriptors.frombytes(data[:len(data) - len(data) % 4])
        facts = _json(payload)
        need(type(facts) is dict and facts.get("schema") ==
             "aegis_auto_witness_topology_v1" and len(descriptors) == 1 and
             facts.get("root_if") == ROOT_IF and
             facts.get("peer_ipv4") == (PEER_IPV6 if family==6 else PEER_IP) and
             facts.get("address_family")==family and
             facts.get("actor_challenge_hex") == actor_challenge.hex() and
             facts.get("challenge_nonce_hex") == actor_challenge.hex() and
             type(facts.get("root_ifindex")) is int and
             type(facts.get("sink_pid")) is int and
             type(facts.get("sink_netns_ino")) is int and
             all(type(facts.get(key)) is str and
                 re.fullmatch(r"[0-9a-f]{64}", facts[key])
                 for key in ("baseline_nonce_hex", "challenge_nonce_hex")),
             "invalid_topology_provision")
        sink = socket.socket(fileno=descriptors[0])
        descriptors = array.array("i")
        sink_pid, sink_uid, _ = struct.unpack("3i", sink.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(sink_uid == 0 and sink_pid == facts["sink_pid"],
             "foreign_topology_sink")
        raw = sink.getsockopt(socket.SOL_SOCKET,
                              getattr(socket, "SO_PEERPIDFD", 77), 4)
        need(len(raw) == 4, "topology_sink_pidfd_unavailable")
        sink_pidfd = struct.unpack("i", raw)[0]
        info = Path(f"/proc/self/fdinfo/{sink_pidfd}").read_text(encoding="ascii")
        need(any(line == f"Pid:\t{sink_pid}" for line in info.splitlines()),
             "foreign_topology_sink")
        lease = TopologyLease(authority, sink, facts, actor_challenge,
                              actor_pidfd, sink_pidfd)
        lease.verify()
        return lease
    except BaseException:
        authority.close()
        if sink is not None:
            sink.close()
        for descriptor in descriptors:
            os.close(descriptor)
        if actor_pidfd is not None:
            os.close(actor_pidfd)
        if sink_pidfd is not None:
            os.close(sink_pidfd)
        raise


def main() -> int:
    action = sys.argv[1:] if len(sys.argv) == 2 else []
    try:
        need(action in (["serve"], ["cleanup"]), "invalid_topology_action")
        if action == ["serve"]:
            serve()
        else:
            print(json.dumps(cleanup_fixed(), sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"aegis_auto_witness_topology_refused:{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
