#!/usr/bin/env python3
"""Fixed, source-owned native capture fixture with a PID1 watchdog.

The actor creates three exact namespace edges after the device guard is
active.  It never edits nft.  A guardian may open one fresh, one-use sink or
sink+ingress-probe pair per capture effect; the actor holds that effect's
control connection until both child receipts have completed.  PID1 runs the
same fixed cleanup source on exit, independently of the guardian.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

IP = "/usr/sbin/ip"
UNPARSED_ROUTE_HOPS = ("multipath", "nexthops", "nhid")
NFT = "/usr/sbin/nft"
SYSTEMCTL = "/usr/bin/systemctl"
SINK_SOURCE = "/usr/local/lib/aegis/helpers/lib/aegis_auto_sink.py"
SOURCE = Path("/usr/local/lib/aegis/helpers/lib/aegis_auto_capture_topology.py")
UNIT = "aegis-auto-capture-topology.service"
UNIT_PATH = Path("/etc/systemd/system/aegis-auto-capture-topology.service")
RUNTIME = Path("/run/aegis-auto-capture-topology")
STATE = RUNTIME / "owned-state.json"
FIXTURE = RUNTIME / "fixture.json"
AUTHORITY = RUNTIME / "authority.sock"
RELAY_INSTALL = Path("/var/lib/aegis-install/client/auto-capture-relay-install.json")
RELAY_NS = "aegisac-relay"
SINK_NS = "aegisac-sink"
PROBE_NS = "aegisac-probe"
H_RELAY, R_HOST = "aegisacr0", "aegisacr1"
R_SINK, S_RELAY = "aegisacs0", "aegisacs1"
H_PROBE, P_HOST = "aegisacp0", "aegisacp1"
RELAY_HOST_IP, HOST_RELAY_IP = "10.231.80.2", "10.231.80.1"
PROBE_IP, HOST_PROBE_IP = "10.231.81.2", "10.231.81.1"
RELAY_SINK_IP, SINK_RELAY_IP = "10.231.82.1", "10.231.82.2"
RELAY_SINK_V6, SINK_RELAY_V6 = "fd77:ae91:1::1", "fd77:ae91:1::2"
SINK_PORT = 18080
RUNTIME_REDIRECT_TARGET = "192.0.2.251"
FIXTURE_SECONDS = 780.0
EFFECT_SECONDS = 60.0
MAX_CONTROL = 8192
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RELAY_UNIT = re.compile(r"aegis-auto-capture-relay-[0-9a-f]{32}\.service\Z")


class Refused(RuntimeError):
    pass


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise Refused(reason)


def _single_route_hop(route: object) -> bool:
    return type(route) is dict and not any(key in route for key in UNPARSED_ROUTE_HOPS)


def _log_refusal(error: Exception) -> None:
    """Journal only fixed error classes, errno and pinned source coordinates."""
    kind = ("refused" if isinstance(error, Refused) else
            "os_error" if isinstance(error, OSError) else
            "timeout" if isinstance(error, subprocess.TimeoutExpired) else
            "value_error" if isinstance(error, ValueError) else "unexpected")
    number = error.errno if isinstance(error, OSError) else 0
    number = number if type(number) is int and 0 <= number <= 4095 else 0
    source, line = "unknown", 0
    trace = error.__traceback__
    while trace is not None:
        if (trace.tb_frame.f_code.co_filename == str(SOURCE) and
                trace.tb_frame.f_code.co_name != "need" and
                1 <= trace.tb_lineno <= 10000):
            source, line = "capture_topology", trace.tb_lineno
        trace = trace.tb_next
    print(f"aegis_auto_capture_topology_refused:{kind} errno={number} "
          f"source={source} line={line}", file=sys.stderr, flush=True)


def _run(args: list[str], timeout: float = 3.0) -> bytes:
    result = subprocess.run(args, capture_output=True, timeout=timeout,
                            check=False, env={"PATH": "/usr/sbin:/usr/bin",
                                              "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 1 << 20 and
         len(result.stderr) <= 4096,
         f"native_command_failed:{Path(args[0]).name}:{result.returncode}")
    return result.stdout


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def _json(raw: bytes) -> object:
    need(0 < len(raw) <= 1 << 20, "invalid_json_size")
    return json.loads(raw, object_pairs_hook=_unique)


def _canonical(raw: bytes) -> bytes:
    def scrub(value: object) -> object:
        if type(value) is dict:
            result = {key: scrub(item) for key, item in value.items()}
            if set(result) == {"packets", "bytes"} and all(
                    type(result[key]) is int for key in result):
                return {"packets": 0, "bytes": 0}
            return result
        if type(value) is list:
            return [scrub(item) for item in value]
        return value
    return json.dumps(scrub(_json(raw)), sort_keys=True,
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


def _routes(record: dict[str, object] | None = None,
            baseline: dict[str, object] | None = None) -> tuple[str, str]:
    values = []
    for family in (4, 6):
        key = 'route' + str(family)
        started = time.monotonic_ns()
        raw = _run([IP, '-j', '-' + str(family), 'route', 'show', 'table', 'all'])
        rows = _json(raw)
        finished = time.monotonic_ns()
        if record is not None:
            record.update({key + '_snapshot': rows, key + '_start_ns': started,
                           key + '_end_ns': finished})
        if baseline is not None and key + '_snapshot' in baseline:
            rows = _restore_route_expiry(baseline[key + '_snapshot'], rows,
                baseline[key + '_start_ns'], baseline[key + '_end_ns'],
                started, finished)
        values.append(hashlib.sha256(_canonical(json.dumps(rows).encode())).hexdigest())
    return tuple(values)


def _probe_redirect_route() -> None:
    """Require the one runtime Redirect target's exact probe-netns route."""
    prefix = [IP, "netns", "exec", PROBE_NS, IP, "-j", "-4", "route"]
    shown = _json(_run([*prefix, "show", "exact",
                        RUNTIME_REDIRECT_TARGET + "/32"]))
    need(type(shown) is list and len(shown) == 1 and
         type(shown[0]) is dict and
         shown[0].get("dst") in (RUNTIME_REDIRECT_TARGET,
                                 RUNTIME_REDIRECT_TARGET + "/32") and
         shown[0].get("gateway") == HOST_PROBE_IP and
         shown[0].get("dev") == P_HOST and
         shown[0].get("type", "unicast") == "unicast" and
         shown[0].get("flags", []) == [] and
         _single_route_hop(shown[0]),
         "capture_runtime_probe_route_changed")
    selected = _json(_run([*prefix, "get", RUNTIME_REDIRECT_TARGET]))
    need(type(selected) is list and len(selected) == 1 and
         type(selected[0]) is dict and
         selected[0].get("dst") == RUNTIME_REDIRECT_TARGET and
         selected[0].get("gateway") == HOST_PROBE_IP and
         selected[0].get("dev") == P_HOST and
         selected[0].get("prefsrc") == PROBE_IP and
         selected[0].get("type", "unicast") == "unicast" and
         _single_route_hop(selected[0]),
         "capture_runtime_probe_route_changed")


def _nft() -> str:
    return hashlib.sha256(_canonical(_run([NFT, "--json", "list", "ruleset"]))).hexdigest()


def _boot() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()


def _root_ns() -> int:
    return os.stat("/proc/self/ns/net").st_ino


def _ns_path(name: str) -> Path:
    return Path("/run/netns") / name


def _ns_ino(name: str) -> int | None:
    path = _ns_path(name)
    try:
        named = path.lstat()
    except FileNotFoundError:
        return None
    need(stat.S_ISREG(named.st_mode) and named.st_uid == 0,
         "untrusted_named_namespace_path")
    return path.stat().st_ino


def _link(namespace: str | None, name: str) -> dict[str, object] | None:
    args = [IP]
    if namespace is not None:
        args += ["netns", "exec", namespace, IP]
    args += ["-j", "-d", "link", "show", "dev", name]
    result = subprocess.run(args, capture_output=True, timeout=2.0,
                            check=False, env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C"})
    if result.returncode:
        need(len(result.stderr) <= 4096 and
             f'Device "{name}" does not exist' in
             result.stderr.decode("ascii"), "link_readback_failed")
        return None
    value = _json(result.stdout)
    need(type(value) is list and len(value) == 1 and
         type(value[0]) is dict and value[0].get("ifname") == name,
         "ambiguous_link_readback")
    return value[0]


def _veth(namespace: str | None, name: str, index: object) -> bool:
    link = _link(namespace, name)
    return (type(index) is int and link is not None and
            link.get("ifindex") == index and
            type(link.get("linkinfo")) is dict and
            link["linkinfo"].get("info_kind") == "veth")


def _safe_runtime() -> None:
    info = RUNTIME.stat(follow_symlinks=False)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
         stat.S_IMODE(info.st_mode) == 0o700, "untrusted_capture_runtime")


def _write(path: Path, value: dict[str, object], replace: bool = False) -> None:
    _safe_runtime()
    temporary = RUNTIME / (path.name + ".pending")
    need(not temporary.exists() and not temporary.is_symlink(), "stale_pending_receipt")
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        need(os.write(fd, payload) == len(payload), "short_state_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    if not replace:
        need(not path.exists() and not path.is_symlink(), "receipt_already_exists")
    os.replace(temporary, path)
    parent = os.open(RUNTIME, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _read_state() -> dict[str, object] | None:
    if not STATE.exists() and not STATE.is_symlink():
        return None
    fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
             0 < info.st_size <= 1 << 20, "untrusted_capture_state")
        value = _json(os.read(fd, (1 << 20) + 1))
        need(type(value) is dict and value.get("schema") ==
             "aegis_auto_capture_topology_state_v1" and
             value.get("boot_id") == _boot() and
             value.get("root_netns_ino") == _root_ns(),
             "stale_capture_state")
        return value
    finally:
        os.close(fd)


def _record_ns(state: dict[str, object], name: str) -> None:
    _run([IP, "netns", "add", name])
    inode = _ns_ino(name)
    need(type(inode) is int and inode > 0, "new_namespace_not_visible")
    state.setdefault("namespaces", {})[name] = inode
    _write(STATE, state, replace=True)
    _run([IP, "netns", "exec", name, IP, "link", "set", "lo", "up"])


def _record_link(state: dict[str, object], namespace: str | None,
                 name: str, key: str) -> None:
    link = _link(namespace, name)
    need(link is not None and type(link.get("ifindex")) is int and
         type(link.get("linkinfo")) is dict and
         link["linkinfo"].get("info_kind") == "veth", "created_link_not_veth")
    state.setdefault("links", {})[key] = link["ifindex"]
    _write(STATE, state, replace=True)


def _prepare() -> dict[str, object]:
    _watchdog_ready()
    need(not STATE.exists() and not FIXTURE.exists() and
         all(_ns_ino(name) is None for name in (RELAY_NS, SINK_NS, PROBE_NS)) and
         all(_link(None, name) is None for name in (H_RELAY, H_PROBE, R_SINK, S_RELAY, R_HOST, P_HOST)),
         "capture_fixture_already_present")
    route_record: dict[str, object] = {}
    before_routes = _routes(record=route_record)
    before_nft = _nft()
    state: dict[str, object] = {
        **route_record, "schema": "aegis_auto_capture_topology_state_v1",
        "boot_id": _boot(), "root_netns_ino": _root_ns(), "phase": "pending",
        "route4_sha256": before_routes[0], "route6_sha256": before_routes[1],
        "nft_sha256": before_nft, "namespaces": {}, "links": {}}
    _write(STATE, state)
    try:
        for name in (RELAY_NS, SINK_NS, PROBE_NS):
            _record_ns(state, name)
        _run([IP, "link", "add", H_RELAY, "type", "veth", "peer", "name", R_HOST])
        _record_link(state, None, H_RELAY, H_RELAY)
        _record_link(state, None, R_HOST, R_HOST)
        _run([IP, "link", "set", R_HOST, "netns", RELAY_NS])
        _record_link(state, RELAY_NS, R_HOST, R_HOST)
        _run([IP, "addr", "add", HOST_RELAY_IP + "/30", "dev", H_RELAY])
        _run([IP, "link", "set", H_RELAY, "up"])
        _run([IP, "netns", "exec", RELAY_NS, IP, "addr", "add",
              RELAY_HOST_IP + "/30", "dev", R_HOST])
        _run([IP, "netns", "exec", RELAY_NS, IP, "link", "set", R_HOST, "up"])

        _run([IP, "link", "add", R_SINK, "type", "veth", "peer", "name", S_RELAY])
        _record_link(state, None, R_SINK, R_SINK)
        _record_link(state, None, S_RELAY, S_RELAY)
        _run([IP, "link", "set", R_SINK, "netns", RELAY_NS])
        _record_link(state, RELAY_NS, R_SINK, R_SINK)
        _run([IP, "link", "set", S_RELAY, "netns", SINK_NS])
        _record_link(state, SINK_NS, S_RELAY, S_RELAY)
        for ns, name, ipv4, ipv6 in (
                (RELAY_NS, R_SINK, RELAY_SINK_IP, RELAY_SINK_V6),
                (SINK_NS, S_RELAY, SINK_RELAY_IP, SINK_RELAY_V6)):
            _run([IP, "netns", "exec", ns, IP, "addr", "add", ipv4 + "/30", "dev", name])
            _run([IP, "netns", "exec", ns, IP, "-6", "addr", "add", ipv6 + "/64", "dev", name])
            _run([IP, "netns", "exec", ns, IP, "link", "set", name, "up"])

        _run([IP, "link", "add", H_PROBE, "type", "veth", "peer", "name", P_HOST])
        _record_link(state, None, H_PROBE, H_PROBE)
        _record_link(state, None, P_HOST, P_HOST)
        _run([IP, "link", "set", P_HOST, "netns", PROBE_NS])
        _record_link(state, PROBE_NS, P_HOST, P_HOST)
        _run([IP, "addr", "add", HOST_PROBE_IP + "/30", "dev", H_PROBE])
        _run([IP, "link", "set", H_PROBE, "up"])
        _run([IP, "netns", "exec", PROBE_NS, IP, "addr", "add",
              PROBE_IP + "/30", "dev", P_HOST])
        _run([IP, "netns", "exec", PROBE_NS, IP, "link", "set", P_HOST, "up"])
        _run([IP, "netns", "exec", PROBE_NS, IP, "route", "add",
              SINK_RELAY_IP + "/32", "via", HOST_PROBE_IP, "dev", P_HOST])
        _run([IP, "netns", "exec", PROBE_NS, IP, "route", "add",
              RUNTIME_REDIRECT_TARGET + "/32", "via", HOST_PROBE_IP,
              "dev", P_HOST])
        _probe_redirect_route()
        need(_nft() == before_nft, "capture_fixture_changed_nft")
        state["phase"] = "live"
        _write(STATE, state, replace=True)
        receipt = {
            "schema": "aegis_auto_capture_fixture_v1", "boot_id": state["boot_id"],
            "root_netns_ino": state["root_netns_ino"], "actor_pid": os.getpid(),
            "unit": UNIT, "namespaces": state["namespaces"], "links": state["links"],
            "source": str(SOURCE), "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "unit_path": str(UNIT_PATH),
            "unit_sha256": hashlib.sha256(UNIT_PATH.read_bytes()).hexdigest(),
            "host_relay_ipv4": HOST_RELAY_IP, "relay_host_ipv4": RELAY_HOST_IP,
            "probe_ipv4": PROBE_IP, "host_probe_ipv4": HOST_PROBE_IP,
            "relay_sink_ipv4": RELAY_SINK_IP, "sink_ipv4": SINK_RELAY_IP,
            "relay_sink_ipv6": RELAY_SINK_V6, "sink_ipv6": SINK_RELAY_V6,
            "sink_port": SINK_PORT,
            "root_route4_before_sha256": state["route4_sha256"],
            "root_route6_before_sha256": state["route6_sha256"],
            "nft_before_sha256": before_nft}
        _write(FIXTURE, receipt)
        return receipt
    except BaseException:
        cleanup_fixed()
        raise


def cleanup_fixed() -> dict[str, object]:
    """Fixed inverse; never deletes an unrecorded/replaced link or netns."""
    need(os.geteuid() == 0 and Path("/proc/self/ns/net").exists(),
         "linux_root_required")
    _safe_runtime()
    state = _read_state()
    if state is None:
        need(not AUTHORITY.exists() and not AUTHORITY.is_symlink() and
             all(_ns_ino(n) is None for n in (RELAY_NS, SINK_NS, PROBE_NS)) and
             all(_link(None, name) is None for name in
                 (H_RELAY, R_HOST, R_SINK, S_RELAY, H_PROBE, P_HOST)),
             "capture_state_missing_with_live_fixture")
        return {"already_absent": True, "routes_restored": True}
    namespaces = state.get("namespaces")
    links = state.get("links")
    need(type(namespaces) is dict and type(links) is dict,
         "invalid_capture_state")
    authority_owned = AUTHORITY.exists() or AUTHORITY.is_symlink()
    if authority_owned:
        named = AUTHORITY.stat(follow_symlinks=False)
        need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
             stat.S_IMODE(named.st_mode) == 0o600 and
             named.st_dev == state.get("authority_dev") and
             named.st_ino == state.get("authority_ino"),
             "capture_authority_replaced")
    for name in (RELAY_NS, SINK_NS, PROBE_NS):
        current = _ns_ino(name)
        if current is not None:
            need(type(namespaces.get(name)) is int and
                 current == namespaces[name], "capture_namespace_replaced")
    # Remove the root peers first, then the relay-owned edge.  A missing
    # recorded ifindex leaves incident state for manual investigation.
    for name in (H_PROBE, P_HOST, H_RELAY, R_HOST, R_SINK, S_RELAY):
        if _link(None, name) is not None:
            need(_veth(None, name, links.get(name)), "capture_root_link_replaced")
            _run([IP, "link", "del", "dev", name])
    if _ns_ino(RELAY_NS) is not None and _link(RELAY_NS, R_SINK) is not None:
        need(_veth(RELAY_NS, R_SINK, links.get(R_SINK)),
             "capture_relay_link_replaced")
        _run([IP, "netns", "exec", RELAY_NS, IP, "link", "del", "dev", R_SINK])
    for name in (PROBE_NS, SINK_NS, RELAY_NS):
        if _ns_ino(name) is not None:
            _run([IP, "netns", "del", name])
    need(all(_ns_ino(n) is None for n in (RELAY_NS, SINK_NS, PROBE_NS)) and
         all(_link(None, name) is None for name in
             (H_RELAY, R_HOST, R_SINK, S_RELAY, H_PROBE, P_HOST)) and
         _routes(baseline=state) == (state["route4_sha256"], state["route6_sha256"]),
         "capture_cleanup_not_restored")
    for path in (FIXTURE, STATE):
        if path.exists():
            path.unlink()
    if authority_owned:
        AUTHORITY.unlink()
    return {"already_absent": False, "routes_restored": True}


def _verify_fixture(fixture: dict[str, object], heartbeat: bool = False) -> None:
    state = _read_state()
    need(state is not None and state.get("phase") == "live" and
         fixture.get("actor_pid") == os.getpid() and
         fixture.get("boot_id") == _boot() and
         fixture.get("root_netns_ino") == _root_ns() and
         fixture.get("namespaces") == state.get("namespaces") and
         fixture.get("links") == state.get("links"),
         "capture_fixture_identity_changed")
    namespaces = state["namespaces"]
    links = state["links"]
    need(all(_ns_ino(name) == namespaces.get(name)
             for name in (RELAY_NS, SINK_NS, PROBE_NS)),
         "capture_fixture_namespace_changed")
    for ns, name in ((None, H_RELAY), (RELAY_NS, R_HOST),
                     (RELAY_NS, R_SINK), (SINK_NS, S_RELAY),
                     (None, H_PROBE), (PROBE_NS, P_HOST)):
        if heartbeat:
            _notify("WATCHDOG=1")
        need(_veth(ns, name, links.get(name)), "capture_fixture_link_changed")
    _probe_redirect_route()


def _notify(value: str) -> None:
    path = os.environ.get("NOTIFY_SOCKET")
    need(path is not None and path != "", "systemd_notify_socket_missing")
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.connect("\0" + path[1:] if path.startswith("@") else path)
        sock.sendall(value.encode())


def _watchdog_ready() -> None:
    raw = _run([SYSTEMCTL, "show", UNIT, "-p", "MainPID", "-p", "ActiveState",
                "-p", "WatchdogUSec", "--no-pager"])
    facts = dict(line.partition("=")[::2] for line in raw.decode("ascii").splitlines())
    need(facts.get("MainPID") == str(os.getpid()) and
         facts.get("ActiveState") == "active" and
         facts.get("WatchdogUSec") in ("10s", "10000000us"),
         "capture_pid1_watchdog_not_armed")


def _send(peer: socket.socket, value: dict[str, object]) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    need(len(raw) <= MAX_CONTROL and peer.send(raw) == len(raw),
         "capture_control_send_failed")


def _recv(peer: socket.socket) -> dict[str, object]:
    raw, anc, flags, _ = peer.recvmsg(MAX_CONTROL)
    need(raw and not anc and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0,
         "invalid_capture_control")
    value = _json(raw)
    need(type(value) is dict, "invalid_capture_control")
    return value


def _peer(peer: socket.socket, mutable: bool) -> int | None:
    pid, uid, _gid = struct.unpack("3i", peer.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(uid == 0 and pid > 1, "untrusted_capture_peer")
    if not mutable:
        return None
    raw = peer.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERPIDFD", 77), 4)
    need(len(raw) == 4, "capture_peer_pidfd_unavailable")
    pidfd = struct.unpack("i", raw)[0]
    try:
        info = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="ascii")
        need(any(line == f"Pid:\t{pid}" for line in info.splitlines()) and
             Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
             "0::/system.slice/aegis-auto-guardian.service\n" and
             os.stat(f"/proc/{pid}/ns/net").st_ino == _root_ns(),
             "foreign_capture_mutator")
        return pidfd
    except BaseException:
        os.close(pidfd)
        raise


def _actor_connection() -> tuple[socket.socket, int]:
    """Connect to the fixed live actor and retain its kernel peer PIDFD."""
    _safe_runtime()
    named = AUTHORITY.stat(follow_symlinks=False)
    need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
         stat.S_IMODE(named.st_mode) == 0o600, "untrusted_capture_authority")
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    pidfd: int | None = None
    try:
        peer.settimeout(5.0)
        peer.connect(str(AUTHORITY))
        pid, uid, _gid = struct.unpack("3i", peer.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        raw = peer.getsockopt(socket.SOL_SOCKET,
                              getattr(socket, "SO_PEERPIDFD", 77), 4)
        need(len(raw) == 4, "capture_actor_pidfd_unavailable")
        pidfd = struct.unpack("i", raw)[0]
        info = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="ascii")
        need(uid == 0 and pid > 1 and
             any(line == f"Pid:\t{pid}" for line in info.splitlines()) and
             Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
             "0::/system.slice/aegis-auto-capture-topology.service\n" and
             os.stat(f"/proc/{pid}/ns/net").st_ino == _root_ns(),
             "foreign_capture_actor")
        watcher = select.poll()
        watcher.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        need(not watcher.poll(0), "capture_actor_exited")
        return peer, pidfd
    except BaseException:
        peer.close()
        if pidfd is not None:
            os.close(pidfd)
        raise


def get_fixture() -> dict[str, object]:
    """Read fixture facts from the live actor, not from a stale disk receipt."""
    peer, pidfd = _actor_connection()
    try:
        _send(peer, {"op": "GET"})
        value = _recv(peer)
        need(value.get("schema") == "aegis_auto_capture_fixture_v1" and
             value.get("boot_id") == _boot() and
             value.get("root_netns_ino") == _root_ns() and
             value.get("source_sha256") == hashlib.sha256(SOURCE.read_bytes()).hexdigest() and
             value.get("unit_sha256") == hashlib.sha256(UNIT_PATH.read_bytes()).hexdigest(),
             "capture_fixture_receipt_invalid")
        return value
    finally:
        peer.close()
        os.close(pidfd)


@dataclass
class CaptureEffectLease:
    authority: socket.socket
    actor_pidfd: int
    facts: dict[str, object]
    effect_nonce: bytes
    closed: bool = False

    def verify(self) -> None:
        need(not self.closed and self.facts.get("effect_nonce") ==
             self.effect_nonce.hex() and
             self.facts.get("fixture_boot_id") == _boot() and
             self.facts.get("fixture_root_netns_ino") == _root_ns(),
             "capture_effect_identity_changed")
        watcher = select.poll()
        watcher.register(self.actor_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        watcher.register(self.authority, select.POLLHUP | select.POLLERR)
        need(not watcher.poll(0), "capture_effect_actor_exited")
        for item in self.facts["children"]:
            path = Path(item["socket"])
            named = path.stat(follow_symlinks=False)
            need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
                 stat.S_IMODE(named.st_mode) == 0o600 and
                 named.st_dev == item["socket_dev"] and
                 named.st_ino == item["socket_ino"] and
                 os.stat(f'/proc/{item["pid"]}/ns/net').st_ino == item["netns_ino"] and
                 item["source_sha256"] == hashlib.sha256(Path(SINK_SOURCE).read_bytes()).hexdigest(),
                 "capture_effect_child_changed")

    def route_query(self, pid: int, family: str, target: str) -> dict[str, object]:
        """Read one fixed QA relay/sink route through the held actor authority."""
        need(type(pid) is int and pid > 1 and
             ((self.facts.get("mode") == "FULL_TUN_UDP" and
               family == "-6" and target == SINK_RELAY_V6) or
              (self.facts.get("mode") == "REDIRECT_TCP" and
               family == "-4" and target == SINK_RELAY_IP)),
             "capture_route_query_scope_invalid")
        self.verify()
        previous_timeout = self.authority.gettimeout()
        try:
            self.authority.settimeout(20.0)
            _send(self.authority, {"op": "ROUTE_GET", "effect_nonce": self.effect_nonce.hex(),
                                   "pid": pid, "family": family, "target": target})
            reply = _recv(self.authority)
        finally:
            self.authority.settimeout(previous_timeout)
        need(set(reply) == {"schema", "state", "effect_nonce", "pid", "netns_ino",
                            "family", "target", "route"} and
             reply["schema"] == "aegis_auto_capture_route_get_v1" and
             reply["state"] == "READY" and
             reply["effect_nonce"] == self.effect_nonce.hex() and
             reply["pid"] == pid and reply["family"] == family and
             reply["target"] == target and
             type(reply["netns_ino"]) is int and reply["netns_ino"] > 0 and
             type(reply["route"]) is dict and
             os.stat(f"/proc/{pid}/ns/net").st_ino == reply["netns_ino"],
             "capture_route_query_reply_invalid")
        self.verify()
        return reply["route"]

    def close(self) -> None:
        need(not self.closed, "capture_effect_already_closed")
        try:
            _send(self.authority, {"op": "CLOSE", "effect_nonce": self.effect_nonce.hex()})
            need(_recv(self.authority) ==
                 {"state": "CLOSED", "effect_nonce": self.effect_nonce.hex()},
                 "capture_effect_close_unconfirmed")
        finally:
            self.closed = True
            self.authority.close()
            os.close(self.actor_pidfd)

    def abort(self) -> None:
        """Withdraw the owned channel; never request or mint successful CLOSE."""
        need(not self.closed, "capture_effect_already_closed")
        self.closed = True
        self.authority.close()
        os.close(self.actor_pidfd)


def open_effect(mode: str, effect_nonce: bytes) -> CaptureEffectLease:
    need(mode in ("FULL_TUN_UDP", "REDIRECT_TCP", "REDIRECT_PROBE_TCP") and
         type(effect_nonce) is bytes and len(effect_nonce) == 32,
         "invalid_capture_effect_request")
    peer, pidfd = _actor_connection()
    try:
        _send(peer, {"op": "OPEN", "mode": mode,
                     "effect_nonce": effect_nonce.hex()})
        value = _recv(peer)
        need(value.get("schema") == "aegis_auto_capture_effect_v1" and
             value.get("state") == "READY" and value.get("mode") == mode and
             type(value.get("children")) is list and
             len(value["children"]) == (2 if mode == "REDIRECT_TCP" else 1),
             "capture_effect_open_refused")
        lease = CaptureEffectLease(peer, pidfd, value, effect_nonce)
        lease.verify()
        return lease
    except BaseException:
        peer.close()
        os.close(pidfd)
        raise


def _child_startup_diagnostic(path: Path, action: str, pid: int) -> None:
    """Report only authenticated fixed coordinates from a failed child."""
    try:
        _safe_runtime()
        need(path.parent == RUNTIME and
             path.name.startswith("effect-") and
             path.name.endswith(".startup-failure.json"),
             "capture_child_startup_path_invalid")
        parent = os.open(RUNTIME, os.O_RDONLY | os.O_DIRECTORY |
                         os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            directory = os.fstat(parent)
            need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and
                 stat.S_IMODE(directory.st_mode) == 0o700,
                 "capture_child_startup_parent_untrusted")
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                         os.O_NONBLOCK, dir_fd=parent)
            try:
                info = os.fstat(fd)
                need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                     stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                     0 < info.st_size <= 512,
                     "capture_child_startup_receipt_untrusted")
                raw = os.read(fd, 513)
                named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                need(len(raw) == info.st_size and
                     (info.st_dev, info.st_ino, info.st_size) ==
                     (named.st_dev, named.st_ino, named.st_size) ==
                     (os.fstat(fd).st_dev, os.fstat(fd).st_ino,
                      os.fstat(fd).st_size) and
                     (directory.st_dev, directory.st_ino) ==
                     (RUNTIME.stat(follow_symlinks=False).st_dev,
                      RUNTIME.stat(follow_symlinks=False).st_ino),
                     "capture_child_startup_receipt_changed")
            finally:
                os.close(fd)
        finally:
            os.close(parent)
        value = _json(raw)
        need(type(value) is dict and set(value) ==
             {"schema", "action", "phase", "class", "errno", "source",
              "line", "pid"} and
             value["schema"] == "aegis_auto_sink_startup_failure_v1" and
             value["action"] == action and value["phase"] == "before_socket" and
             value["class"] in ("refused", "os_error", "value_error",
                                "timeout", "unexpected") and
             type(value["errno"]) is int and 0 <= value["errno"] <= 4095 and
             value["source"] == "sink" and
             type(value["line"]) is int and 0 <= value["line"] <= 10000 and
             type(value["pid"]) is int and value["pid"] == pid,
             "capture_child_startup_receipt_invalid")
        print("aegis_auto_capture_child_startup:" + json.dumps(
            {"action": value["action"], "class": value["class"],
             "errno": value["errno"], "line": value["line"],
             "pid": value["pid"]}, sort_keys=True, separators=(",", ":")),
            file=sys.stderr, flush=True)
    except FileNotFoundError:
        return
    except (Refused, OSError, ValueError) as error:
        _log_refusal(error)


CHILD_READY_SECONDS = 3.0
CHILD_READY_POLL = 0.002


def _start_children(kinds: list[tuple[str, str, str | None]], serial: str,
                    release_fd: int
                    ) -> tuple[list[subprocess.Popen[bytes]], list[dict[str, object]]]:
    """Start every effect child together, then admit each one in order.

    Each child keeps its own unused socket/receipt paths, its own socket
    owner/mode check, namespace check and source digest, and at least the
    original 3 s readiness bound (one deadline taken after the last spawn).
    """
    started = []
    facts: list[dict[str, object]] = []
    try:
        for ordinal, (namespace, action, listen_ip) in enumerate(kinds):
            stem = f"effect-{serial}-{ordinal}"
            socket_path, receipt_path = RUNTIME / (stem + ".sock"), RUNTIME / (stem + ".json")
            need(not socket_path.exists() and not socket_path.is_symlink() and
                 not receipt_path.exists() and not receipt_path.is_symlink(),
                 "capture_child_path_reused")
            startup_failure = receipt_path.with_suffix(".startup-failure.json")
            need(not startup_failure.exists() and not startup_failure.is_symlink(),
                 "capture_child_path_reused")
            argv = [IP, "netns", "exec", namespace, "/usr/bin/python3", "-I", "-B",
                    SINK_SOURCE, action, "--socket", str(socket_path),
                    "--receipt", str(receipt_path), "--maximum-seconds", str(EFFECT_SECONDS),
                    "--completion-release-fd", str(release_fd),
                    "--startup-failure-receipt", str(startup_failure)]
            if listen_ip is not None:
                argv += ["--listen-ip", listen_ip, "--port", str(SINK_PORT)]
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     close_fds=True, pass_fds=(release_fd,),
                                     env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
            started.append((child, namespace, action, argv, socket_path,
                            receipt_path, startup_failure))
        deadline = time.monotonic() + CHILD_READY_SECONDS
        while (not all(item[4].exists() for item in started) and
               time.monotonic() < deadline):
            for child, _namespace, action, _argv, socket_path, _receipt, failure in started:
                if not socket_path.exists() and child.poll() is not None:
                    _child_startup_diagnostic(failure, action, child.pid)
                    raise Refused("capture_child_exited_before_socket")
            time.sleep(CHILD_READY_POLL)
        for child, namespace, action, argv, socket_path, receipt_path, _failure in started:
            named = socket_path.stat(follow_symlinks=False)
            need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
                 stat.S_IMODE(named.st_mode) == 0o600, "capture_child_socket_untrusted")
            expected_ns = _ns_ino(namespace)
            need(expected_ns is not None and
                 os.stat(f"/proc/{child.pid}/ns/net").st_ino == expected_ns,
                 "capture_child_namespace_wrong")
            facts.append({"pid": child.pid, "netns_ino": expected_ns,
                          "socket": str(socket_path), "socket_dev": named.st_dev,
                          "socket_ino": named.st_ino, "receipt": str(receipt_path),
                          "action": action, "source": SINK_SOURCE,
                          "source_sha256": hashlib.sha256(Path(SINK_SOURCE).read_bytes()).hexdigest(),
                          "argv_sha256": hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()})
        return [item[0] for item in started], facts
    except BaseException as primary:
        if isinstance(primary, Exception):
            _log_refusal(primary)
        try:
            # Retire only sockets whose exact identity is known now; each is
            # unlinked after its own child has been reaped.
            owned = []
            for child, _namespace, _action, _argv, socket_path, _receipt, _failure in started:
                try:
                    named = socket_path.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISSOCK(named.st_mode):
                    owned.append({"socket": str(socket_path), "socket_dev": named.st_dev,
                                  "socket_ino": named.st_ino, "pid": child.pid})
            _cleanup_effect_children([item[0] for item in started], owned)
        except Exception as cleanup:
            _log_refusal(cleanup)
        raise


def _unlink_child_socket(item: dict[str, object]) -> None:
    """Retire only the exact socket published by this owned, reaped child."""
    path = Path(str(item["socket"]))
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        directory = os.fstat(parent)
        need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and
             stat.S_IMODE(directory.st_mode) == 0o700,
             "capture_child_parent_untrusted")
        try:
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        need(stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
             stat.S_IMODE(named.st_mode) == 0o600 and
             (named.st_dev, named.st_ino) == (item["socket_dev"], item["socket_ino"]),
             "capture_child_socket_replaced")
        # Only this serialized actor and its now-reaped child own this nonce
        # name in the held root-only directory. No live producer may replace it.
        os.unlink(path.name, dir_fd=parent)
    finally:
        os.close(parent)


def _cleanup_effect_children(children: list[subprocess.Popen[bytes]],
                             facts: list[dict[str, object]]) -> None:
    first = None
    reaped = set()
    for child in children:
        try:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2.0)
            reaped.add(child.pid)
        except Exception as error:
            _log_refusal(error)
            if first is None:
                first = error
    for item in facts:
        if "pid" in item and item["pid"] not in reaped:
            continue
        try:
            _unlink_child_socket(item)
        except Exception as error:
            _log_refusal(error)
            if first is None:
                first = error
    if first is not None:
        raise first


def _installed_relay_pid(pid: int) -> None:
    """Bind a route query to the protected QA relay's live PID1 main process."""
    fd = os.open(RELAY_INSTALL, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and
             0 < info.st_size <= 16384, "capture_relay_install_untrusted")
        receipt = _json(os.read(fd, 16385))
    finally:
        os.close(fd)
    unit = receipt.get("unit") if type(receipt) is dict else None
    binary = receipt.get("server_binary_path") if type(receipt) is dict else None
    config = receipt.get("config_path") if type(receipt) is dict else None
    need(type(receipt) is dict and
         receipt.get("schema") == "aegis_auto_capture_relay_install_v1" and
         type(unit) is str and RELAY_UNIT.fullmatch(unit) is not None and
         type(binary) is str and binary.startswith("/opt/aegis-auto-native-qa-") and
         type(config) is str and config.startswith("/opt/aegis-auto-native-qa-"),
         "capture_relay_install_invalid")
    raw = _run([SYSTEMCTL, "show", unit, "-p", "ActiveState", "-p", "MainPID",
                "-p", "ControlPID", "-p", "ControlGroup", "--no-pager"],
               timeout=2.0)
    need(len(raw) <= 4096, "capture_relay_pid1_readback_unbounded")
    fields = dict(line.split("=", 1) for line in raw.decode("ascii").splitlines()
                  if "=" in line)
    need(set(fields) == {"ActiveState", "MainPID", "ControlPID", "ControlGroup"} and
         fields["ActiveState"] == "active" and fields["MainPID"] == str(pid) and
         fields["ControlPID"] == "0" and
         fields["ControlGroup"] == "/system.slice/" + unit and
         os.readlink(f"/proc/{pid}/exe") == binary and
         Path(f"/proc/{pid}/cmdline").read_bytes() ==
         (binary + "\0--config\0" + config + "\0").encode() and
         Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
         "0::/system.slice/" + unit + "\n",
         "capture_relay_pid1_identity_changed")


def _effect_route_get(request: dict[str, object], opened: dict[str, object],
                      fixture: dict[str, object], facts: list[dict[str, object]],
                      deadline: float, guardian_pidfd: int) -> dict[str, object]:
    need(set(request) == {"op", "effect_nonce", "pid", "family", "target"} and
         request["op"] == "ROUTE_GET" and
         request["effect_nonce"] == opened["effect_nonce"] and
         type(request["pid"]) is int and request["pid"] > 1 and
         ((opened["mode"] == "FULL_TUN_UDP" and request["family"] == "-6" and
           request["target"] == SINK_RELAY_V6) or
          (opened["mode"] == "REDIRECT_TCP" and request["family"] == "-4" and
           request["target"] == SINK_RELAY_IP)),
         "capture_route_query_scope_invalid")
    guardian = select.poll()
    guardian.register(guardian_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    need(not guardian.poll(0) and time.monotonic() + 5.0 < deadline,
         "capture_route_query_deadline")
    _verify_fixture(fixture, heartbeat=True)
    pid = request["pid"]
    pidfd = os.pidfd_open(pid, 0)
    try:
        identity = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="ascii")
        watcher = select.poll()
        watcher.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        need(any(line == f"Pid:\t{pid}" for line in identity.splitlines()) and
             not watcher.poll(0), "capture_route_query_pid_changed")
        named = fixture["namespaces"]
        observed_ns = os.stat(f"/proc/{pid}/ns/net").st_ino
        if pid == facts[0]["pid"] and observed_ns == named[SINK_NS]:
            namespace = SINK_NS
        else:
            need(observed_ns == named[RELAY_NS],
                 "capture_route_query_namespace_not_owned")
            _installed_relay_pid(pid)
            namespace = RELAY_NS
        need(_ns_ino(namespace) == observed_ns,
             "capture_route_query_namespace_replaced")
        raw = _run([IP, "netns", "exec", namespace, IP, "-j", request["family"],
                    "route", "get", request["target"]], timeout=2.0)
        need(0 < len(raw) <= 4096, "capture_route_query_readback_unbounded")
        rows = _json(raw)
        need(type(rows) is list and len(rows) == 1 and
             _single_route_hop(rows[0]),
             "capture_route_query_ambiguous")
        need(not watcher.poll(0) and not guardian.poll(0) and
             os.stat(f"/proc/{pid}/ns/net").st_ino == observed_ns and
             _ns_ino(namespace) == observed_ns,
             "capture_route_query_identity_changed")
        _verify_fixture(fixture, heartbeat=True)
        need(time.monotonic() < deadline and not guardian.poll(0),
             "capture_route_query_effect_expired")
        return {"schema": "aegis_auto_capture_route_get_v1", "state": "READY",
                "effect_nonce": opened["effect_nonce"], "pid": pid,
                "netns_ino": observed_ns, "family": request["family"],
                "target": request["target"], "route": rows[0]}
    finally:
        os.close(pidfd)


def _effect(peer: socket.socket, request: dict[str, object], fixture: dict[str, object]) -> None:
    _verify_fixture(fixture)
    need(set(request) == {"op", "mode", "effect_nonce"} and
         request["op"] == "OPEN" and request["mode"] in
         ("FULL_TUN_UDP", "REDIRECT_TCP", "REDIRECT_PROBE_TCP") and
         type(request["effect_nonce"]) is str and
         HEX64.fullmatch(request["effect_nonce"]) is not None,
         "invalid_capture_open")
    pidfd = _peer(peer, True)
    need(pidfd is not None, "capture_owner_missing")
    serial = request["effect_nonce"][:16]
    children: list[subprocess.Popen[bytes]] = []
    facts: list[dict[str, object]] = []
    release_read, release_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        if request["mode"] == "FULL_TUN_UDP":
            kinds = [(SINK_NS, "serve-echo", SINK_RELAY_V6)]
        elif request["mode"] == "REDIRECT_TCP":
            kinds = [(SINK_NS, "serve-echo-tcp", SINK_RELAY_IP),
                     (PROBE_NS, "serve-probe-tcp", None)]
        else:
            kinds = [(PROBE_NS, "serve-probe-tcp", None)]
        started, admitted = _start_children(kinds, serial, release_read)
        children.extend(started)
        facts.extend(admitted)
        os.close(release_read)
        release_read = -1
        _verify_fixture(fixture, heartbeat=True)
        host_probe_ifindex = fixture["links"][H_PROBE]
        need(type(host_probe_ifindex) is int and host_probe_ifindex > 0,
             "capture_probe_interface_changed")
        _send(peer, {"schema": "aegis_auto_capture_effect_v1", "state": "READY",
                     "mode": request["mode"], "effect_nonce": request["effect_nonce"],
                     "fixture_actor_pid": os.getpid(), "fixture_boot_id": fixture["boot_id"],
                     "fixture_root_netns_ino": fixture["root_netns_ino"],
                     "host_probe_ifindex": host_probe_ifindex,
                     "fixture_sha256": hashlib.sha256(json.dumps(
                         fixture, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                     "children": facts})
        watcher = select.poll()
        watcher.register(peer, select.POLLIN | select.POLLHUP | select.POLLERR)
        watcher.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        deadline = time.monotonic() + EFFECT_SECONDS
        while time.monotonic() < deadline:
            _notify("WATCHDOG=1")
            for child in children:
                need(child.poll() is None or child.returncode == 0,
                     "capture_child_failed")
            for fd, event in watcher.poll(200):
                need(fd != pidfd and not event & (select.POLLHUP | select.POLLERR),
                     "capture_owner_exited")
                message = _recv(peer)
                if message.get("op") == "ROUTE_GET":
                    _send(peer, _effect_route_get(message, request, fixture, facts,
                                                  deadline, pidfd))
                    continue
                need(message == {"op": "CLOSE", "effect_nonce": request["effect_nonce"]},
                     "capture_close_mismatch")
                # Completed children retain socket/pidfd identity until this
                # owner releases them. Missing completion can never get CLOSED.
                for item in facts:
                    receipt = Path(str(item["receipt"]))
                    info = receipt.stat(follow_symlinks=False)
                    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                         stat.S_IMODE(info.st_mode) == 0o600 and
                         info.st_nlink == 1 and 0 < info.st_size <= MAX_CONTROL,
                         "capture_child_receipt_missing")
                os.close(release_write)
                release_write = -1
                for child, item in zip(children, facts):
                    need(child.wait(timeout=2.0) == 0 and
                         Path(str(item["receipt"])).is_file(),
                         "capture_child_receipt_missing")
                    _unlink_child_socket(item)
                os.close(pidfd)
                pidfd = -1
                _send(peer, {"state": "CLOSED", "effect_nonce": request["effect_nonce"]})
                return
        raise Refused("capture_effect_deadline_elapsed")
    except BaseException as primary:
        if isinstance(primary, Exception):
            _log_refusal(primary)
        raise
    finally:
        primary = sys.exc_info()[1]
        cleanup_error = None
        for owned_fd in (pidfd, release_read, release_write):
            if owned_fd >= 0:
                try:
                    os.close(owned_fd)
                except Exception as error:
                    _log_refusal(error)
                    if cleanup_error is None:
                        cleanup_error = error
        try:
            _cleanup_effect_children(children, facts)
        except Exception as cleanup:
            _log_refusal(cleanup)
            if cleanup_error is None:
                cleanup_error = cleanup
        if primary is None and cleanup_error is not None:
            raise cleanup_error


def serve() -> None:
    need(os.geteuid() == 0 and Path("/proc/self/ns/net").exists(),
         "linux_root_required")
    _safe_runtime()
    need(not AUTHORITY.exists() and not AUTHORITY.is_symlink(),
         "capture_authority_already_present")
    _notify("READY=1")
    fixture = _prepare()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        server.bind(str(AUTHORITY))
        os.chmod(AUTHORITY, 0o600)
        named = AUTHORITY.stat(follow_symlinks=False)
        state = _read_state()
        need(state is not None, "capture_state_missing_after_bind")
        state["authority_dev"] = named.st_dev
        state["authority_ino"] = named.st_ino
        _write(STATE, state, replace=True)
        server.listen(1)
        server.settimeout(1.0)
        deadline = time.monotonic() + FIXTURE_SECONDS
        while time.monotonic() < deadline:
            _notify("WATCHDOG=1")
            try:
                peer, _ = server.accept()
            except socket.timeout:
                continue
            try:
                peer.settimeout(5.0)
                request = _recv(peer)
                if request == {"op": "GET"}:
                    _peer(peer, False)
                    _verify_fixture(fixture)
                    _send(peer, fixture)
                else:
                    _effect(peer, request, fixture)
            except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as error:
                _log_refusal(error)
                try:
                    _send(peer, {"state": "REFUSED", "reason": str(error)[:128]})
                except OSError:
                    pass
            finally:
                peer.close()
        raise Refused("capture_fixture_deadline_elapsed")
    finally:
        server.close()
        if AUTHORITY.exists():
            AUTHORITY.unlink()
        cleanup_fixed()


def main() -> int:
    try:
        need(len(sys.argv) == 2 and sys.argv[1] in ("serve", "cleanup"),
             "invalid_capture_action")
        if sys.argv[1] == "serve":
            serve()
        else:
            print(json.dumps(cleanup_fixed(), sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as error:
        _log_refusal(error)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
