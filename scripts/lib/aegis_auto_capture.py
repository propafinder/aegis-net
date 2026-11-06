#!/usr/bin/env python3
"""Read-only native FullTun capture and inverse witnesses for the installed guardian.

The caller must hold the guardian's original stage/install/guard lease and a
PID1 job capability.  Values returned here are observations, not standalone
authorization to start, stop, or finalize a transaction.
"""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import json
import os
import re
import select
import socket
import ssl
import stat
import struct
import subprocess
import time
import tomllib
from pathlib import Path
from typing import Callable


TUN = "aegis-tun0"
UNPARSED_ROUTE_HOPS = ("multipath", "nexthops", "nhid")
ETH_P_ALL = 0x0003
ETH_P_IPV6 = 0x86dd
NFT = Path("/usr/sbin/nft")
IP = Path("/usr/sbin/ip")
ROUTE_TARGETS = (("::/1", "2001:db8:ae61::f"),
                 ("8000::/1", "a001:db8:ae61::f"))
MAX_OUTPUT = 1 << 20
MAX_CONTROL = 4096
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
PRIVATE_UNIT = re.compile(r"aegis-auto@[0-9a-f]{64}\.service\Z")
ENDPOINT_RECEIPT = Path("/var/lib/aegis-install/client/auto-capture-endpoint.json")
RUNTIME_UDP_TARGET = "100::ae91"
RUNTIME_TCP_TARGET = "192.0.2.251"
RUNTIME_UDP_IPV4_TARGET = "192.0.2.252"
RUNTIME_PROBE_PORT = 18080


class CaptureRefused(RuntimeError):
    pass


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise CaptureRefused(reason)


def _single_route_hop(route: object) -> bool:
    """Do not infer an egress from a top-level dev with hidden next hops."""
    return type(route) is dict and not any(key in route for key in UNPARSED_ROUTE_HOPS)


def _strict_json(raw: bytes) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            need(key not in value, "endpoint_duplicate_json_key")
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict, "endpoint_json_invalid")
    return value


def _trusted_ancestors(path: Path) -> None:
    need(path.is_absolute() and ".." not in path.parts,
         "endpoint_path_not_absolute")
    ancestor = Path("/")
    for part in path.parts[1:-1]:
        ancestor /= part
        value = ancestor.stat(follow_symlinks=False)
        need(stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and
             value.st_mode & 0o022 == 0,
             "endpoint_path_ancestor_untrusted")


@dataclasses.dataclass
class _HeldFile:
    path: Path
    fd: int
    identity: tuple[int, int, int, int]
    sha256: str
    mode: int
    maximum: int

    def revalidate(self) -> None:
        # Re-establish every admission predicate of the held inode, not only
        # its identity: chmod, chown or an extra hard link change only ctime,
        # mode, uid or nlink, which the identity tuple does not cover.
        _trusted_ancestors(self.path)
        named = self.path.stat(follow_symlinks=False)
        held = os.fstat(self.fd)
        need(stat.S_ISREG(held.st_mode) and held.st_uid == 0 and
             held.st_nlink == 1 and stat.S_IMODE(held.st_mode) == self.mode and
             0 < held.st_size <= self.maximum,
             "endpoint_file_untrusted")
        need((held.st_dev, held.st_ino, held.st_mtime_ns, held.st_size) ==
             self.identity ==
             (named.st_dev, named.st_ino, named.st_mtime_ns, named.st_size),
             "endpoint_pinned_file_changed")
        h = hashlib.sha256()
        offset = 0
        while offset < self.identity[3]:
            chunk = os.pread(self.fd, min(1 << 20, self.identity[3] - offset),
                             offset)
            need(bool(chunk), "endpoint_pinned_file_truncated")
            h.update(chunk)
            offset += len(chunk)
        need(h.hexdigest() == self.sha256,
             "endpoint_pinned_file_content_changed")

    def close(self) -> None:
        os.close(self.fd)


def _held_file(path: Path, maximum: int, mode: int,
               expected_sha256: str | None) -> _HeldFile:
    need(expected_sha256 is None or
         (type(expected_sha256) is str and
          HEX64.fullmatch(expected_sha256) is not None),
         "endpoint_file_digest_invalid")
    _trusted_ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                 os.O_NONBLOCK)
    try:
        actual = os.fstat(fd)
        named = path.stat(follow_symlinks=False)
        need(stat.S_ISREG(actual.st_mode) and actual.st_uid == 0 and
             actual.st_nlink == 1 and stat.S_IMODE(actual.st_mode) == mode and
             0 < actual.st_size <= maximum and
             (actual.st_dev, actual.st_ino) == (named.st_dev, named.st_ino),
             "endpoint_file_untrusted")
        h = hashlib.sha256()
        length = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            length += len(chunk)
            need(length <= maximum, "endpoint_file_unbounded")
            h.update(chunk)
        need(length == actual.st_size and
             (expected_sha256 is None or h.hexdigest() == expected_sha256),
             "endpoint_file_digest_changed")
        held = _HeldFile(path, fd,
                         (actual.st_dev, actual.st_ino,
                          actual.st_mtime_ns, actual.st_size),
                         h.hexdigest(), mode, maximum)
        held.revalidate()
        return held
    except BaseException:
        os.close(fd)
        raise


def _run(argv: list[str], timeout: float = 2.0) -> bytes:
    need(argv and argv[0] in (str(IP), str(NFT), "/usr/bin/systemctl"),
         "untrusted_command")
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=timeout, check=False,
                            env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C", "LANG": "C"})
    need(result.returncode == 0 and len(result.stdout) <= MAX_OUTPUT and
         len(result.stderr) <= 4096, "native_readback_failed")
    return result.stdout


def _json(argv: list[str]) -> list[dict]:
    result = json.loads(_run(argv))
    need(type(result) is list and all(type(item) is dict for item in result),
         "invalid_native_json")
    return result


def _cgroup(unit_name: str) -> str:
    need(type(unit_name) is str and PRIVATE_UNIT.fullmatch(unit_name) is not None,
         "foreign_auto_unit")
    return "/system.slice/" + unit_name


def _service(unit_name: str, *, stopped: bool = False) -> dict[str, str]:
    cgroup = _cgroup(unit_name)
    raw = _run(["/usr/bin/systemctl", "show", unit_name, "-p", "MainPID", "-p",
                "ControlPID", "-p", "ActiveState", "-p", "SubState", "-p",
                "InvocationID", "-p", "ControlGroup", "--no-pager"])
    need(len(raw) <= 4096, "service_readback_unbounded")
    facts: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        need(sep == "=" and key not in facts, "invalid_service_facts")
        facts[key] = value
    need(set(facts) == {"MainPID", "ControlPID", "ActiveState", "SubState",
                        "InvocationID", "ControlGroup"} and
         facts["ControlGroup"] in ((cgroup, "") if stopped else (cgroup,)) and
         (stopped or bool(HEX32.fullmatch(facts["InvocationID"]))),
         "foreign_service_identity")
    return facts


def _pid_live(pid: int, expected_worker_sha256: str,
              cgroup: str) -> None:
    need(pid > 1 and bool(HEX64.fullmatch(expected_worker_sha256)),
         "invalid_worker_identity")
    need(Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
         f"0::{cgroup}\n", "worker_not_in_service_cgroup")
    status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    need(not any(line.startswith("State:\tZ") for line in status.splitlines()),
         "worker_zombie")
    exe = Path(f"/proc/{pid}/exe")
    fd = os.open(exe, os.O_RDONLY | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 512 << 20,
             "worker_executable_invalid")
        h = hashlib.sha256()
        length = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            length += len(chunk)
            need(length <= 512 << 20, "worker_executable_unbounded")
            h.update(chunk)
        after = os.fstat(fd)
        need(length == before.st_size and h.hexdigest() == expected_worker_sha256 and
             (before.st_dev, before.st_ino, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_mtime_ns),
             "worker_executable_changed")
    finally:
        os.close(fd)


def _pidfd_identity(fd: int, pid: int) -> None:
    info = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii")
    need(len(info) <= 4096 and
         sum(line == f"Pid:\t{pid}" for line in info.splitlines()) == 1 and
         not select.select([fd], [], [], 0)[0],
         "pidfd_identity_changed")


def _server_socket_owned(pid: int, listen_ipv4: str, port: int) -> int:
    packed = ipaddress.IPv4Address(listen_ipv4).packed
    need(not (ipaddress.IPv4Address(listen_ipv4).is_loopback or
              ipaddress.IPv4Address(listen_ipv4).is_unspecified) and
         1 <= port <= 65535, "relay_listener_invalid")
    encoded_address = packed[::-1].hex().upper()
    expected_local = f"{encoded_address}:{port:04X}"
    entries = Path(f"/proc/{pid}/net/tcp").read_text(encoding="ascii").splitlines()
    need(1 <= len(entries) <= 65536, "relay_tcp_table_unbounded")
    inode = None
    for line in entries[1:]:
        fields = line.split()
        need(len(fields) >= 10, "relay_tcp_row_invalid")
        if fields[1] == expected_local and fields[3] == "0A":
            need(inode is None and fields[9].isdecimal(),
                 "relay_listener_ambiguous")
            inode = int(fields[9])
    need(inode is not None and inode > 0, "relay_listener_missing")
    descriptors = list(Path(f"/proc/{pid}/fd").iterdir())
    need(len(descriptors) <= 4096, "relay_fd_table_unbounded")
    need(any(os.readlink(entry) == f"socket:[{inode}]"
             for entry in descriptors if entry.name.isdecimal()),
         "relay_listener_not_owned")
    return inode


def _server_process(pid: int, pidfd: int, netns_ino: int,
                    cgroup: str, expected_argv: tuple[str, ...],
                    executable: _HeldFile,
                    listen_ipv4: str, listen_port: int) -> int:
    _pidfd_identity(pidfd, pid)
    need(os.stat(f"/proc/{pid}/ns/net").st_ino == netns_ino and
         Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
         f"0::{cgroup}\n" and
         tuple(item.decode("utf-8") for item in
               Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if item) ==
         expected_argv,
         "relay_process_identity_changed")
    process_exe = Path(f"/proc/{pid}/exe").stat()
    held = os.fstat(executable.fd)
    need((process_exe.st_dev, process_exe.st_ino) ==
         (held.st_dev, held.st_ino), "relay_executable_not_installed")
    return _server_socket_owned(pid, listen_ipv4, listen_port)


def _exact_fields(value: object, fields: set[str], reason: str) -> dict:
    need(type(value) is dict and set(value) == fields, reason)
    return value


def _positive_integer(value: object, reason: str) -> int:
    need(type(value) is int and value > 0, reason)
    return value


def _actor_process(actor: dict, pidfd: int, root_netns: int,
                   source: _HeldFile) -> None:
    pid = actor["pid"]
    _pidfd_identity(pidfd, pid)
    need(os.stat(f"/proc/{pid}/ns/net").st_ino == actor["netns_ino"] and
         actor["netns_ino"] != root_netns and
         Path(f"/proc/{pid}/status").read_text(encoding="ascii").split(
             "Uid:\t", 1)[1].splitlines()[0].split()[0] == "0",
         "endpoint_actor_identity_changed")
    need(type(actor["argv"]) is list and
         tuple(item.decode("utf-8") for item in
               Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
               if item) == tuple(actor["argv"]) and
         len(actor["argv"]) >= 5 and
         actor["argv"][0] == "/usr/bin/python3" and
         actor["argv"][1] == "-I" and
         actor["argv"][2] == "-B" and
         actor["argv"][3] == str(source.path) and
         (Path(f"/proc/{pid}/exe").stat().st_dev,
          Path(f"/proc/{pid}/exe").stat().st_ino) ==
         (Path("/usr/bin/python3").stat().st_dev,
          Path("/usr/bin/python3").stat().st_ino),
         "endpoint_actor_source_not_running")
    source.revalidate()
    path = Path(actor["control_socket"])
    _trusted_ancestors(path)
    parent = path.parent.stat(follow_symlinks=False)
    named = path.stat(follow_symlinks=False)
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
         stat.S_IMODE(parent.st_mode) == 0o700 and
         stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
         stat.S_IMODE(named.st_mode) == 0o600 and
         (named.st_dev, named.st_ino) ==
         (actor["control_dev"], actor["control_ino"]),
         "endpoint_actor_socket_changed")


@dataclasses.dataclass
class EndpointLease:
    """Pins the installed relay and actors for one positive capture witness."""

    receipt: _HeldFile
    server_exe: _HeldFile
    config: _HeldFile
    cert: _HeldFile
    key: _HeldFile
    tls_extra: tuple[_HeldFile, ...]
    sink_source: _HeldFile
    probe_source: _HeldFile | None
    server_pidfd: int
    sink_pidfd: int
    probe_pidfd: int | None
    facts: dict
    effect_lease: object
    closed: bool = False
    exchange_completed: bool = False

    @property
    def endpoint(self) -> CaptureEchoEndpoint | RedirectEndpoint:
        return self.to_endpoint()

    def __enter__(self) -> EndpointLease:
        try:
            self.revalidate()
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, _kind: object, _value: object,
                 _traceback: object) -> None:
        self.close()

    def to_endpoint(self) -> CaptureEchoEndpoint | RedirectEndpoint:
        need(not self.closed, "endpoint_lease_closed")
        sink = self.facts["sink"]
        if self.facts["mode"] == "full-wide-tun":
            return CaptureEchoEndpoint(sink["target_ip"], sink["target_port"],
                                       Path(sink["control_socket"]), sink["pid"],
                                       sink["netns_ino"])
        probe = self.facts["probe"]
        return RedirectEndpoint(sink["target_ip"], sink["target_port"],
                                probe["ingress_ifname"], probe["listen_port"],
                                Path(probe["control_socket"]), probe["pid"],
                                probe["netns_ino"],
                                Path(sink["control_socket"]), sink["pid"],
                                sink["netns_ino"])

    def revalidate(self) -> None:
        need(not self.closed, "endpoint_lease_closed")
        self.effect_lease.verify()
        for held in (self.receipt, self.server_exe, self.config,
                     self.cert, self.key, *self.tls_extra,
                     self.sink_source, self.probe_source):
            if held is None:
                continue
            held.revalidate()
        facts = self.facts
        need(_strict_json(os.pread(self.receipt.fd,
                                   self.receipt.identity[3], 0)) == facts,
             "endpoint_receipt_changed")
        server = facts["server"]
        _server_process(server["pid"], self.server_pidfd,
                        server["netns_ino"], server["cgroup"],
                        tuple(server["argv"]), self.server_exe,
                        server["listen_ipv4"], server["listen_port"])
        if not self.exchange_completed:
            _actor_process(facts["sink"], self.sink_pidfd,
                           facts["root_netns_ino"], self.sink_source)
            if self.probe_pidfd is not None:
                _actor_process(facts["probe"], self.probe_pidfd,
                               facts["root_netns_ino"], self.probe_source)
        target = ipaddress.ip_address(facts["sink"]["target_ip"])
        family = "-6" if target.version == 6 else "-4"
        relay_route = self.effect_lease.route_query(server["pid"], family,
                                                    str(target))
        need(_single_route_hop(relay_route) and
             relay_route.get("dev") not in (None, "lo", TUN) and
             relay_route.get("type") not in ("unreachable", "blackhole",
                                             "prohibit"),
             "endpoint_relay_route_invalid")
        if not self.exchange_completed:
            sink_route = self.effect_lease.route_query(facts["sink"]["pid"],
                                                       family, str(target))
            need(_sink_route_is_local(sink_route, str(target)),
                 "endpoint_sink_address_not_local")
        host_rows = _json([str(IP), "-j", "-4", "route", "get",
                           server["listen_ipv4"]])
        need(len(host_rows) == 1, "endpoint_host_relay_route_ambiguous")
        host_route = host_rows[0]
        need(_single_route_hop(host_route) and
             host_route.get("dev") not in (None, "lo", TUN) and
             host_route.get("type") not in ("unreachable", "blackhole",
                                           "prohibit"),
             "endpoint_host_relay_route_invalid")
        need(Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii").strip() == facts["boot_id"] and
             os.stat("/proc/self/ns/net").st_ino == facts["root_netns_ino"],
             "endpoint_host_identity_changed")

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for fd in (self.server_pidfd, self.sink_pidfd, self.probe_pidfd):
            if fd is not None:
                os.close(fd)
        for held in (self.receipt, self.server_exe, self.config,
                     self.cert, self.key, *self.tls_extra,
                     self.sink_source, self.probe_source):
            if held is None:
                continue
            held.close()


def admit_endpoint_receipt(*, receipt_path: Path = ENDPOINT_RECEIPT,
                           unit: str, mode: str, boot_id: str,
                           netns_ino: int, installed_generation: str,
                           manifest: str, effect_lease: object) -> EndpointLease:
    """Admit source-owned endpoint metadata only after live host readback."""
    need(mode in ("full-wide-tun", "wide-redirect-safe") and
         bool(PRIVATE_UNIT.fullmatch(unit)) and
         bool(HEX64.fullmatch(installed_generation)) and
         bool(HEX64.fullmatch(manifest)), "endpoint_expected_identity_invalid")
    receipt = _held_file(receipt_path, 16384, 0o600, None)
    held: list[_HeldFile] = [receipt]
    pidfds: list[int] = []
    try:
        facts = _strict_json(os.pread(receipt.fd, receipt.identity[3], 0))
        fields = {"schema", "boot_id", "root_netns_ino", "mode",
                  "private_unit", "installed_generation",
                  "installed_manifest_sha256", "server", "sink"}
        if mode == "wide-redirect-safe":
            fields.add("probe")
        _exact_fields(facts, fields, "endpoint_receipt_schema_invalid")
        need(facts["schema"] == "aegis_auto_capture_endpoint_v1" and
             facts["boot_id"] == boot_id and
             facts["root_netns_ino"] == netns_ino and
             facts["mode"] == mode and facts["private_unit"] == unit and
             facts["installed_generation"] == installed_generation and
             facts["installed_manifest_sha256"] == manifest,
             "endpoint_receipt_identity_mismatch")
        need(type(facts["server"]) is dict,
             "endpoint_server_schema_invalid")
        profile = facts["server"].get("auth_profile")
        need(profile in ("legacy_shared_token", "device_inner_tls"),
             "endpoint_auth_profile_invalid")
        server_fields = {
            "pid", "netns_ino", "cgroup", "argv", "exe_path", "exe_sha256",
            "config_path", "config_sha256", "cert_path", "cert_sha256",
            "key_path", "key_sha256", "listen_ipv4", "listen_port",
            "outer_ca_path", "outer_ca_sha256", "auth_profile"}
        if profile == "legacy_shared_token":
            server_fields.add("auth_token_sha256")
        else:
            for name in ("inner_cert", "inner_key", "client_ca",
                         "device_cert", "device_key", "device_qa_key"):
                server_fields.update((f"{name}_path", f"{name}_sha256"))
        server = _exact_fields(facts["server"], server_fields,
                               "endpoint_server_schema_invalid")
        sink = _exact_fields(facts["sink"],
            {"pid", "netns_ino", "control_socket", "control_dev",
             "control_ino", "target_ip", "target_port",
             "actor_source_path", "actor_source_sha256", "argv"},
             "endpoint_sink_schema_invalid")
        for actor in (server, sink, facts.get("probe")):
            if actor is None:
                continue
            _positive_integer(actor["pid"], "endpoint_pid_invalid")
            _positive_integer(actor["netns_ino"], "endpoint_netns_invalid")
        for name in ("control_dev", "control_ino"):
            _positive_integer(sink[name], "endpoint_socket_identity_invalid")
        _positive_integer(sink["target_port"], "endpoint_target_invalid")
        _positive_integer(server["listen_port"], "endpoint_listener_invalid")
        need(type(server["cgroup"]) is str and
             server["cgroup"].startswith("/system.slice/") and
             type(server["argv"]) is list and
             3 <= len(server["argv"]) <= 8 and
             server["argv"][:3] == [str(server["exe_path"]),
                                   "--config", str(server["config_path"])] and
             all(type(x) is str and x and len(x) <= 4096
                 for x in server["argv"]), "endpoint_server_identity_invalid")
        executable = _held_file(Path(server["exe_path"]), 512 << 20,
                                0o500, server["exe_sha256"])
        held.append(executable)
        config = _held_file(Path(server["config_path"]), 1 << 20,
                            0o600, server["config_sha256"])
        held.append(config)
        cert = _held_file(Path(server["cert_path"]), 1 << 20,
                          0o600, server["cert_sha256"])
        held.append(cert)
        key = _held_file(Path(server["key_path"]), 1 << 20,
                         0o600, server["key_sha256"])
        held.append(key)
        tls_fields = (("outer_ca",) if profile == "legacy_shared_token" else
                      ("outer_ca", "inner_cert", "inner_key", "client_ca",
                       "device_cert", "device_key", "device_qa_key"))
        tls_files = {}
        for name in tls_fields:
            item = _held_file(Path(server[f"{name}_path"]), 1 << 20,
                              0o600, server[f"{name}_sha256"])
            held.append(item)
            tls_files[name] = item
        if profile == "device_inner_tls":
            need(tls_files["device_qa_key"].path != tls_files["device_key"].path,
                 "endpoint_device_qa_key_alias_invalid")
        sink_source = _held_file(Path(sink["actor_source_path"]), 1 << 20,
                                 0o500, sink["actor_source_sha256"])
        held.append(sink_source)
        config_data = tomllib.loads(os.pread(config.fd, config.identity[3],
                                              0).decode("utf-8"))
        need(config_data.get("listen") ==
             f'{server["listen_ipv4"]}:{server["listen_port"]}' and
             config_data.get("cert") == str(cert.path) and
             config_data.get("key") == str(key.path) and
             config_data.get("target_policy", {}).get("profile") ==
             "full_vpn_egress" and
             config_data.get("fallback", "close") == "close" and
             config_data.get("legacy_auth_tokens", []) == [],
             "endpoint_server_config_mismatch")
        transport = config_data.get("transport", {})
        need(type(transport) is dict and
             transport.get("quic_required") is False,
             "endpoint_transport_config_mismatch")
        if profile == "legacy_shared_token":
            token = config_data.get("auth_token")
            need(type(token) is str and len(token) >= 32 and
                 len(token) <= 4096 and
                 re.fullmatch(r"[A-Za-z0-9_-]+", token) is not None and
                 hashlib.sha256(token.encode()).hexdigest() ==
                 server["auth_token_sha256"] and
                 transport.get("inner_tls") is None,
                 "endpoint_legacy_auth_mismatch")
        else:
            inner = transport.get("inner_tls", {})
            need(config_data.get("auth_token", "") == "" and
                 type(inner) is dict and
                 inner.get("cert") == str(tls_files["inner_cert"].path) and
                 inner.get("key") == str(tls_files["inner_key"].path) and
                 inner.get("client_ca") == str(tls_files["client_ca"].path) and
                 inner.get("device_registry") is None,
                 "endpoint_inner_tls_config_mismatch")
            device_pem = os.pread(tls_files["device_cert"].fd,
                                  tls_files["device_cert"].identity[3], 0).decode(
                                      "ascii")
            cert_blocks = re.findall(
                r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----",
                device_pem)
            need(len(cert_blocks) == 1, "endpoint_device_certificate_invalid")
            device_der_sha256 = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(cert_blocks[0])).hexdigest()
            need(inner.get("allowed_client_sha256") == [device_der_sha256],
                 "endpoint_device_pin_mismatch")
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(f"/proc/self/fd/{cert.fd}",
                            f"/proc/self/fd/{key.fd}")
        tls.load_verify_locations(
            cafile=f'/proc/self/fd/{tls_files["outer_ca"].fd}')
        if profile == "device_inner_tls":
            inner_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            inner_tls.load_cert_chain(
                f'/proc/self/fd/{tls_files["inner_cert"].fd}',
                f'/proc/self/fd/{tls_files["inner_key"].fd}')
            inner_tls.load_verify_locations(
                cafile=f'/proc/self/fd/{tls_files["client_ca"].fd}')
            device_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            device_tls.load_cert_chain(
                f'/proc/self/fd/{tls_files["device_cert"].fd}',
                f'/proc/self/fd/{tls_files["device_qa_key"].fd}')
        server_pidfd = os.pidfd_open(server["pid"], 0)
        pidfds.append(server_pidfd)
        sink_pidfd = os.pidfd_open(sink["pid"], 0)
        pidfds.append(sink_pidfd)
        probe_pidfd = None
        if mode == "wide-redirect-safe":
            probe = _exact_fields(facts["probe"],
                {"pid", "netns_ino", "control_socket", "control_dev",
                 "control_ino", "ingress_ifname", "listen_port",
                 "actor_source_path", "actor_source_sha256", "argv"},
                 "endpoint_probe_schema_invalid")
            for name in ("control_dev", "control_ino", "listen_port"):
                _positive_integer(probe[name], "endpoint_probe_identity_invalid")
            need(type(probe["ingress_ifname"]) is str and
                 re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}",
                              probe["ingress_ifname"]) is not None,
                 "endpoint_probe_interface_invalid")
            probe_pidfd = os.pidfd_open(probe["pid"], 0)
            pidfds.append(probe_pidfd)
            probe_source = _held_file(Path(probe["actor_source_path"]),
                                      1 << 20, 0o500,
                                      probe["actor_source_sha256"])
            held.append(probe_source)
        else:
            probe_source = None
        lease = EndpointLease(receipt, executable, config, cert, key,
                              tuple(tls_files.values()), sink_source,
                              probe_source,
                              server_pidfd, sink_pidfd, probe_pidfd, facts,
                              effect_lease)
        lease.revalidate()
        return lease
    except BaseException:
        for fd in pidfds:
            os.close(fd)
        for item in held:
            item.close()
        raise


def _connected_peer_pidfd(peer: socket.socket, pid: int) -> int:
    option = getattr(socket, "SO_PEERPIDFD", 77)
    raw = peer.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("i"))
    need(len(raw) == struct.calcsize("i"), "peer_pidfd_unavailable")
    fd = struct.unpack("i", raw)[0]
    need(fd >= 3, "peer_pidfd_invalid")
    try:
        _pidfd_identity(fd, pid)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _tun_owned_by_pid(pid: int) -> None:
    """A named link alone does not establish custody by the started worker."""
    directory = Path(f"/proc/{pid}/fd")
    entries = list(directory.iterdir())
    need(len(entries) <= 4096, "worker_fd_table_unbounded")
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            if os.readlink(entry) != "/dev/net/tun":
                continue
            info = Path(f"/proc/{pid}/fdinfo/{entry.name}").read_text(
                encoding="ascii")
        except (FileNotFoundError, ProcessLookupError):
            continue
        need(len(info) <= 4096, "tun_fdinfo_unbounded")
        if any(line.partition(":")[0] == "iff" and
               line.partition(":")[2].strip() == TUN
               for line in info.splitlines()):
            return
    raise CaptureRefused("started_worker_does_not_own_tun_fd")


def _link() -> tuple[int, str]:
    links = _json([str(IP), "-j", "link", "show", "dev", TUN])
    need(len(links) == 1 and links[0].get("ifname") == TUN and
         type(links[0].get("ifindex")) is int and links[0]["ifindex"] > 0 and
         links[0].get("link_type") in ("none", "tun"), "capture_link_invalid")
    flags = links[0].get("flags")
    need(type(flags) is list and "UP" in flags and
         links[0].get("operstate") in ("UNKNOWN", "UP"),
         "capture_link_not_up")
    return links[0]["ifindex"], links[0]["operstate"]


def _link_and_routes() -> tuple[int, str, tuple[dict[str, object], ...]]:
    """One task: the routes read depends on the link's ifindex."""
    ifindex, state = _link()
    return ifindex, state, _routes(ifindex)


def _routes(ifindex: int) -> tuple[dict[str, object], ...]:
    all_routes = _json([str(IP), "-j", "-6", "route", "show", "table", "main"])
    found = []
    for prefix, target in ROUTE_TARGETS:
        candidates = [route for route in all_routes if route.get("dst") == prefix]
        need(len(candidates) == 1 and _single_route_hop(candidates[0]) and
             candidates[0].get("dev") == TUN and
             candidates[0].get("type", "unicast") == "unicast" and
             candidates[0].get("gateway") is None,
             "capture_route_missing_or_ambiguous")
        route = _json([str(IP), "-j", "-6", "route", "get", target])
        need(len(route) == 1 and _single_route_hop(route[0]) and
             route[0].get("dev") == TUN and
             route[0].get("dst") in (target, f"{target}/128") and
             route[0].get("gateway") is None,
             "effective_capture_route_missing")
        found.append({"prefix": prefix, "target": target,
                      "ifindex": ifindex, "metric": candidates[0].get("metric", 0)})
    return tuple(found)


def _tproxy_policy(ingress_ifname: str, listen_port: int) -> tuple[str, int, int]:
    """Read actual nft PREROUTING attachment and TCP TPROXY action."""
    need(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", ingress_ifname)) and
         1024 <= listen_port <= 65535, "redirect_identity_invalid")
    raw = _run([str(NFT), "-j", "-a", "list", "table", "ip",
                "aegis_wide_tproxy"])
    body = json.loads(raw)
    need(type(body) is dict and set(body) == {"nftables"} and
         type(body["nftables"]) is list, "redirect_nft_invalid")
    entries = body["nftables"]
    need(len(entries) == 9 and [next(iter(item)) for item in entries] ==
         ["metainfo", "table", "chain", "chain", "rule", "rule", "rule",
          "rule", "rule"] and
         all(type(item) is dict and len(item) == 1 for item in entries),
         "redirect_nft_extra_or_missing_objects")
    table = entries[1]["table"]
    need(table.get("family") == "ip" and
         table.get("name") == "aegis_wide_tproxy" and
         type(table.get("handle")) is int and table["handle"] > 0,
         "redirect_nft_table_invalid")
    chains = [item["chain"] for item in entries[2:4]]
    rules = [item["rule"] for item in entries[4:]]
    pre = [c for c in chains if c.get("name") == "prerouting" and
           c.get("family") == "ip" and c.get("table") == "aegis_wide_tproxy"]
    target = [c for c in chains if c.get("name") == "AEGIS_WIDE_TPROXY" and
              c.get("family") == "ip" and c.get("table") == "aegis_wide_tproxy"]
    need(len(pre) == 1 and len(target) == 1 and
         pre[0].get("hook") == "prerouting" and
         pre[0].get("prio") == -150 and pre[0].get("policy") == "accept" and
         target[0].get("hook") is None,
         "redirect_nft_chains_invalid")
    def meta(key: str, value: object) -> dict:
        return {"match": {"op": "==", "left": {"meta": {"key": key}},
                          "right": value}}

    def dport(value: int) -> dict:
        return {"match": {"op": "==",
                          "left": {"payload": {"protocol": "tcp",
                                               "field": "dport"}},
                          "right": value}}

    mark = {"mangle": {"key": {"meta": {"key": "mark"}}, "value": 1}}
    expected = [
        ("prerouting", [meta("iifname", ingress_ifname),
                        meta("l4proto", "tcp"),
                        {"jump": {"target": "AEGIS_WIDE_TPROXY"}}]),
        ("AEGIS_WIDE_TPROXY", [dport(22), {"return": None}]),
        ("AEGIS_WIDE_TPROXY", [dport(listen_port), {"return": None}]),
        ("AEGIS_WIDE_TPROXY", [meta("l4proto", "tcp"),
                                {"match": {"op": "==",
                                           "left": {"socket": {"key": "transparent"}},
                                           "right": 1}}, mark, {"return": None}]),
        ("AEGIS_WIDE_TPROXY", [meta("l4proto", "tcp"),
                                {"tproxy": {"port": listen_port}},
                                mark, {"accept": None}])]
    for index, (rule, (chain, expressions)) in enumerate(zip(rules, expected)):
        need(rule.get("family") == "ip" and
             rule.get("table") == "aegis_wide_tproxy" and
             rule.get("chain") == chain and rule.get("expr") == expressions and
             type(rule.get("handle")) is int and rule["handle"] > 0 and
             set(rule) == ({"family", "table", "chain", "handle", "expr",
                           "comment"} if index == 0 else
                          {"family", "table", "chain", "handle", "expr"}),
             "redirect_tproxy_not_admitted")
    need(rules[0]["comment"] ==
         "aegis:prerouting:tcp:AEGIS_WIDE_TPROXY" and
         len({(r["chain"], r["handle"]) for r in rules}) == 5,
         "redirect_tproxy_not_admitted")
    # Canonicalized kernel JSON (not command text) binds the observed chain and
    # handles across the external packet exchange.  Counters are discarded.
    normalized = json.loads(raw)
    for item in normalized["nftables"]:
        if type(item) is dict and type(item.get("rule")) is dict:
            for expression in item["rule"].get("expr", []):
                if type(expression) is dict and "counter" in expression:
                    expression["counter"] = {"packets": 0, "bytes": 0}
    projection = json.dumps(normalized, sort_keys=True,
                            separators=(",", ":")).encode()
    return hashlib.sha256(projection).hexdigest(), rules[0]["handle"], rules[4]["handle"]


def _redirect_policy(ingress_ifname: str, listen_port: int, *,
                     scoped_policy: dict | None = None,
                     scoped_verify: Callable | None = None,
                     unit_name: str | None = None,
                     invocation_id: str | None = None) -> tuple[str, int, int]:
    """Bind the owned scoped NAT policy to a fresh protected/kernel readback.

    The source-verified guardian callback reopens the original intent, private
    invocation and full nft projection. An arbitrary preexisting TPROXY table
    or a JSON receipt alone is never admission for LinuxRedirect.
    """
    fields = {"policy_sha256", "input_gate_chain_handle", "input_allow_handle",
              "input_drop_handle", "prerouting_chain_handle", "redirect_handle",
              "private_unit", "invocation_id", "interface", "ifindex",
              "listen_ipv4", "listen_port", "conntrack_mark"}
    need(type(scoped_policy) is dict and set(scoped_policy) == fields and
         callable(scoped_verify), "redirect_scoped_owner_required")
    observed = scoped_verify()
    need(type(observed) is dict and set(observed) == fields and
         observed == scoped_policy, "redirect_scoped_policy_changed")
    need(type(observed["policy_sha256"]) is str and
         HEX64.fullmatch(observed["policy_sha256"]) is not None and
         observed["interface"] == ingress_ifname and
         type(ingress_ifname) is str and
         re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", ingress_ifname) is not None and
         ingress_ifname not in ("lo", TUN) and
         type(observed["ifindex"]) is int and observed["ifindex"] > 0 and
         socket.if_nametoindex(ingress_ifname) == observed["ifindex"] and
         type(listen_port) is int and listen_port == observed["listen_port"] == 15080 and
         type(observed["private_unit"]) is str and
         PRIVATE_UNIT.fullmatch(observed["private_unit"]) is not None and
         type(observed["invocation_id"]) is str and
         HEX32.fullmatch(observed["invocation_id"]) is not None and
         (unit_name is None or observed["private_unit"] == unit_name) and
         (invocation_id is None or observed["invocation_id"] == invocation_id) and
         all(type(observed[key]) is int and observed[key] > 0 for key in
             ("input_gate_chain_handle", "input_allow_handle", "input_drop_handle",
              "prerouting_chain_handle", "redirect_handle")) and
         len({observed[key] for key in ("input_gate_chain_handle", "input_allow_handle",
              "input_drop_handle", "prerouting_chain_handle", "redirect_handle")}) == 5 and
         type(observed["conntrack_mark"]) is int and
         0 < observed["conntrack_mark"] <= 0xffffffff and
         observed["conntrack_mark"] not in (0xa3610001, 0xa3610002),
         "redirect_scoped_identity_changed")
    try:
        address = ipaddress.IPv4Address(observed["listen_ipv4"])
    except (ipaddress.AddressValueError, ValueError, TypeError) as error:
        raise CaptureRefused("redirect_scoped_listener_invalid") from error
    need(str(address) == observed["listen_ipv4"] and
         not (address.is_loopback or address.is_unspecified or
              address.is_multicast or address.is_link_local or
              str(address) == "255.255.255.255"),
         "redirect_scoped_listener_invalid")
    return (observed["policy_sha256"], observed["prerouting_chain_handle"],
            observed["redirect_handle"])


def _concurrent_reads(calls: list[Callable[[], object]],
                      local: int | None = None) -> list[object]:
    """Run independent, side-effect-free bounded reads together.

    `calls[local]` runs in the calling thread (it may be the only user of an
    actor control socket); every other call runs on its own worker thread.
    Everything is joined before this returns. The first failure in list
    order is raised, so refusal labels keep the sequential order; worker
    exceptions are captured in their futures and never printed.
    """
    import concurrent.futures
    results: list[object] = [None] * len(calls)
    errors: list[BaseException | None] = [None] * len(calls)
    remote = [index for index in range(len(calls)) if index != local]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(remote))) as pool:
        futures = {index: pool.submit(calls[index]) for index in remote}
        if local is not None:
            try:
                results[local] = calls[local]()
            except BaseException as error:
                errors[local] = error
        for index, future in futures.items():
            try:
                results[index] = future.result()
            except BaseException as error:
                errors[index] = error
    for error in errors:
        if error is not None:
            raise error
    return results


def _policy(expected_policy_sha256: str, expected_output_drop_handle: int,
            snapshot_policy: Callable) -> tuple[str, int]:
    need(bool(HEX64.fullmatch(expected_policy_sha256)) and
         type(expected_output_drop_handle) is int and
         expected_output_drop_handle > 0,
         "invalid_policy_identity")
    # Same canonical projection as the deny packet witness.  A counter change
    # is expected; an expression, rule handle or ordering change is refused.
    projection, handles, _counters = snapshot_policy(NFT)
    actual = hashlib.sha256(projection).hexdigest()
    need(actual == expected_policy_sha256 and
         handles.get("output") == expected_output_drop_handle,
         "capture_deny_policy_changed")
    return actual, handles["output"]


def _tun_ipv6_sniffer() -> socket.socket:
    # TUN's outgoing tap reaches ETH_P_ALL packet sockets on Linux. The
    # protocol-specific packet socket does not receive this TUN transmission.
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM |
                            socket.SOCK_CLOEXEC, socket.htons(ETH_P_ALL))
    try:
        sniffer.bind((TUN, ETH_P_ALL))
    except BaseException:
        sniffer.close()
        raise
    return sniffer


def _tun_udp_outgoing(packet: bytes, address: tuple, target: str,
                      port: int, nonce: bytes) -> bool:
    return (address[0] == TUN and address[1] == ETH_P_IPV6 and
            address[2] == socket.PACKET_OUTGOING and
            len(packet) == 48 + len(nonce) and packet[0] >> 4 == 6 and
            packet[6] == 17 and
            packet[24:40] == ipaddress.IPv6Address(target).packed and
            struct.unpack("!H", packet[42:44])[0] == port and
            packet[48:] == nonce)


def _packet_on_tun(ifindex: int, deadline: float) -> str:
    """Observe our nonce on the actual TUN egress packet socket, both /1 halves."""
    need(os.geteuid() == 0 and os.stat("/proc/self/ns/net").st_ino > 0,
         "capture_host_netns_required")
    marker = os.urandom(16)
    observed = []
    for index, (_prefix, target) in enumerate(ROUTE_TARGETS):
        nonce = marker + bytes([index])
        port = 49271 + index
        sniffer = None
        sender = None
        try:
            sniffer = _tun_ipv6_sniffer()
            sender = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM |
                                   socket.SOCK_CLOEXEC)
            sniffer.setblocking(False)
            need(socket.if_nametoindex(TUN) == ifindex, "capture_link_replaced")
            _remaining_timeout(sender, deadline)
            sender.sendto(nonce, (target, port, 0, 0))
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                available, _, _ = select.select([sniffer], [], [],
                                                min(0.15, remaining))
                if not available:
                    continue
                try:
                    packet, address = sniffer.recvfrom(65535)
                except BlockingIOError:
                    continue
                if _tun_udp_outgoing(packet, address, target, port, nonce):
                    observed.append(hashlib.sha256(packet).hexdigest())
                    break
            need(len(observed) == index + 1, "capture_packet_not_observed")
        finally:
            if sender is not None:
                sender.close()
            if sniffer is not None:
                sniffer.close()
    return hashlib.sha256("".join(observed).encode("ascii")).hexdigest()


@dataclasses.dataclass(frozen=True)
class CaptureEchoEndpoint:
    ipv6: str
    port: int
    control_socket: Path
    sink_pid: int
    sink_netns_ino: int


@dataclasses.dataclass(frozen=True)
class CaptureEchoWitness:
    nonce_sha256: str
    packet_sha256: str
    sink_pid: int
    sink_netns_ino: int
    sink_session: str
    sink_received: int
    sink_echoed: int
    application_received: bool


def _sink_route_is_local(route: dict, target: str) -> bool:
    return (_single_route_hop(route) and route.get("dev") == "lo" and
            route.get("type") == "local" and
            route.get("dst") == target)


def _remaining_timeout(peer: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("capture_exchange_deadline_elapsed")
    peer.settimeout(remaining)


def _capture_phase(callback: Callable[[str], None] | None, label: str) -> None:
    if callback is not None:
        try:
            callback(label)
        except Exception:
            pass


def _control_send(peer: socket.socket, value: dict[str, object],
                  deadline: float | None = None) -> None:
    if deadline is not None:
        _remaining_timeout(peer, deadline)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    need(len(raw) <= MAX_CONTROL and peer.send(raw) == len(raw),
         "echo_control_send_failed")


def _control_recv(peer: socket.socket,
                  deadline: float | None = None) -> dict[str, object]:
    if deadline is not None:
        _remaining_timeout(peer, deadline)
    raw, _anc, flags, _address = peer.recvmsg(MAX_CONTROL)
    need(raw and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC),
         "echo_control_truncated")
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            need(key not in value, "echo_control_duplicate_key")
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict, "echo_control_invalid")
    return value


def _echo_through_service(endpoint: CaptureEchoEndpoint, ifindex: int,
                          deadline: float) -> CaptureEchoWitness:
    need(type(endpoint) is CaptureEchoEndpoint, "echo_endpoint_invalid")
    address = ipaddress.IPv6Address(endpoint.ipv6)
    need(not (address.is_loopback or address.is_link_local or address.is_multicast
              or address.is_unspecified or address.ipv4_mapped) and
         1024 <= endpoint.port <= 65535 and endpoint.sink_pid > 1 and
         endpoint.sink_netns_ino > 0 and
         endpoint.sink_netns_ino != os.stat("/proc/self/ns/net").st_ino,
         "echo_endpoint_invalid")
    # The route must enter the captured TUN; a directly connected external
    # sink would provide an echo but bypass the installed client entirely.
    route = _json([str(IP), "-j", "-6", "route", "get", endpoint.ipv6])
    need(len(route) == 1 and _single_route_hop(route[0]) and
         route[0].get("dev") == TUN and
         route[0].get("gateway") is None, "echo_endpoint_bypasses_tun")
    _trusted_ancestors(endpoint.control_socket)
    parent = endpoint.control_socket.parent.stat(follow_symlinks=False)
    named = endpoint.control_socket.stat(follow_symlinks=False)
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
         stat.S_IMODE(parent.st_mode) == 0o700 and
         stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
         stat.S_IMODE(named.st_mode) == 0o600,
         "echo_control_socket_untrusted")
    nonce = os.urandom(32)
    nonce_sha256 = hashlib.sha256(nonce).hexdigest()
    control = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET |
                            socket.SOCK_CLOEXEC)
    packet = None
    application = None
    pidfd = None
    try:
        packet = _tun_ipv6_sniffer()
        application = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM |
                                    socket.SOCK_CLOEXEC)
        _remaining_timeout(control, deadline)
        control.connect(str(endpoint.control_socket))
        creds = struct.unpack("3i", control.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        sink_pid, sink_uid, _sink_gid = creds
        need(sink_pid == endpoint.sink_pid and sink_uid == 0 and
             os.stat(f"/proc/{sink_pid}/ns/net").st_ino == endpoint.sink_netns_ino,
             "echo_control_peer_untrusted")
        after_socket = endpoint.control_socket.stat(follow_symlinks=False)
        need((named.st_dev, named.st_ino) ==
             (after_socket.st_dev, after_socket.st_ino),
             "echo_control_socket_replaced")
        pidfd = _connected_peer_pidfd(control, sink_pid)
        _control_send(control, {"op": "ECHO_ARM", "sha256": nonce_sha256}, deadline)
        ready = _control_recv(control, deadline)
        need(set(ready) == {"state", "sha256", "session", "sink_pid",
                             "sink_netns_ino", "listen_ip", "listen_port"} and
             ready["state"] == "ECHO_READY" and
             ready["sha256"] == nonce_sha256 and
             type(ready["session"]) is str and HEX32.fullmatch(ready["session"]) and
             type(ready["sink_pid"]) is int and ready["sink_pid"] == sink_pid and
             type(ready["sink_netns_ino"]) is int and
             ready["sink_netns_ino"] == endpoint.sink_netns_ino and
             ready["listen_ip"] == endpoint.ipv6 and
             type(ready["listen_port"]) is int and
             ready["listen_port"] == endpoint.port,
             "echo_sink_not_armed")
        need(socket.if_nametoindex(TUN) == ifindex,
             "echo_tun_identity_changed")
        packet.setblocking(False)
        _remaining_timeout(application, deadline)
        application.connect((endpoint.ipv6, endpoint.port, 0, 0))
        _remaining_timeout(application, deadline)
        need(application.send(nonce) == len(nonce), "echo_application_send_failed")
        packet_sha256 = None
        response = None
        while time.monotonic() < deadline and (packet_sha256 is None or response is None):
            remaining = max(0.0, deadline - time.monotonic())
            ready_fds, _, _ = select.select([packet, application], [], [],
                                            min(0.2, remaining))
            for fd in ready_fds:
                if fd is packet:
                    try:
                        raw, address = packet.recvfrom(65535)
                    except BlockingIOError:
                        continue
                    if _tun_udp_outgoing(raw, address, endpoint.ipv6,
                                         endpoint.port, nonce):
                        packet_sha256 = hashlib.sha256(raw).hexdigest()
                else:
                    _remaining_timeout(application, deadline)
                    candidate = application.recv(2048)
                    if candidate == nonce:
                        response = candidate
        need(packet_sha256 is not None and response == nonce,
             "echo_not_carried_bidirectionally")
        need(time.monotonic() < deadline, "echo_control_deadline_elapsed")
        _control_send(control, {"op": "ECHO_FINISH", "sha256": nonce_sha256,
                                "session": ready["session"]}, deadline)
        completed = _control_recv(control, deadline)
        need(set(completed) == {"state", "sha256", "session", "received",
                                 "echoed", "sink_pid", "sink_netns_ino"} and
             completed["state"] == "ECHO_COMPLETE" and
             completed["sha256"] == nonce_sha256 and
             completed["session"] == ready["session"] and
             type(completed["received"]) is int and completed["received"] == 1 and
             type(completed["echoed"]) is int and completed["echoed"] == 1 and
             type(completed["sink_pid"]) is int and
             completed["sink_pid"] == sink_pid and
             type(completed["sink_netns_ino"]) is int and
             completed["sink_netns_ino"] == endpoint.sink_netns_ino and
             not select.select([pidfd], [], [], 0)[0],
             "echo_sink_receipt_invalid")
        return CaptureEchoWitness(nonce_sha256, packet_sha256, sink_pid,
                                  endpoint.sink_netns_ino, ready["session"],
                                  1, 1, True)
    finally:
        if pidfd is not None:
            os.close(pidfd)
        if application is not None:
            application.close()
        if packet is not None:
            packet.close()
        control.close()


@dataclasses.dataclass(frozen=True)
class RedirectEndpoint:
    target_ipv4: str
    target_port: int
    ingress_ifname: str
    listen_port: int
    probe_control_socket: Path
    probe_pid: int
    probe_netns_ino: int
    sink_control_socket: Path
    sink_pid: int
    sink_netns_ino: int


@dataclasses.dataclass(frozen=True)
class RuntimeRedirectEndpoint:
    """One live source-owned ingress peer; no independent QA sink is implied."""
    ingress_ifname: str
    listen_port: int
    probe_control_socket: Path
    probe_pid: int
    probe_netns_ino: int


@dataclasses.dataclass(frozen=True)
class RedirectReadyWitness:
    schema: str
    mode: str
    unit_name: str
    boot_id: str
    netns_ino: int
    invocation_id: str
    main_pid: int
    ingress_ifname: str
    redirect_policy_sha256: str
    prerouting_chain_handle: int
    redirect_handle: int
    probe_pid: int
    probe_netns_ino: int
    sink_pid: int
    sink_netns_ino: int
    nonce_sha256: str
    probe_session: str
    sink_session: str
    application_echoed_bytes: int
    sink_received: int
    sink_echoed: int
    guard_policy_sha256: str
    guard_output_drop_handle: int
    observed_monotonic_ns: int


@dataclasses.dataclass(frozen=True)
class RedirectInverseWitness:
    schema: str
    mode: str
    unit_name: str
    boot_id: str
    netns_ino: int
    prior_invocation_id: str
    prior_redirect_policy_sha256: str
    prior_prerouting_chain_handle: int
    prior_redirect_handle: int
    service_active_state: str
    redirect_table_absent: bool
    policy_routing_required: bool
    guard_policy_sha256: str
    guard_output_drop_handle: int
    observed_monotonic_ns: int


@dataclasses.dataclass(frozen=True)
class LocalRedirectInverseWitness:
    schema: str
    mode: str
    unit_name: str
    boot_id: str
    netns_ino: int
    prior_invocation_id: str
    prior_redirect_policy_sha256: str
    prior_output_chain_handle: int
    prior_tcp_redirect_handle: int
    prior_dns_redirect_handle: int
    service_active_state: str
    redirect_table_absent: bool
    guard_policy_sha256: str
    guard_output_drop_handle: int
    observed_monotonic_ns: int


@dataclasses.dataclass(frozen=True)
class CaptureAbsentWitness:
    schema: str
    mode: str
    unit_name: str
    boot_id: str
    netns_ino: int
    prior_invocation_id: str | None
    service_active_state: str
    cgroup_empty: bool
    capture_link_absent: bool | None
    capture_routes_absent: bool | None
    redirect_table_absent: bool | None
    redirect_policy_routing_required: bool | None
    guard_policy_sha256: str
    guard_output_drop_handle: int
    observed_monotonic_ns: int


def _empty_cgroup_events(cgroup: str, refusal: str) -> None:
    events = Path("/sys/fs/cgroup" + cgroup + "/cgroup.events")
    try:
        contents = events.read_text(encoding="ascii")
    except FileNotFoundError:
        # PID1 may collect the stopped unit's cgroup between the exact
        # stopped-service readback and this read. Other failures still refuse.
        return
    need("populated 0\n" in contents, refusal)


def _empty_private_service(unit_name: str,
                           prior_invocation_id: str | None) -> dict[str, str]:
    if prior_invocation_id is not None:
        need(type(prior_invocation_id) is str and
             HEX32.fullmatch(prior_invocation_id) is not None,
             "invalid_prior_invocation")
    facts = _service(unit_name, stopped=True)
    need(facts["ActiveState"] in ("inactive", "failed") and
         facts["MainPID"] == "0" and facts["ControlPID"] == "0" and
         facts["InvocationID"] in (("", prior_invocation_id)
                                   if prior_invocation_id else ("",)),
         "capture_service_not_empty")
    _empty_cgroup_events(_cgroup(unit_name), "capture_service_cgroup_populated")
    return facts


def _redirect_artifacts_absent() -> None:
    tables = json.loads(_run([str(NFT), "-j", "list", "tables"]))
    need(type(tables) is dict and type(tables.get("nftables")) is list and
         not any(type(item) is dict and type(item.get("table")) is dict and
                 item["table"].get("name") in
                 ("aegis_auto_redirect", "aegis_auto_local_redirect") and
                 item["table"].get("family") == "ip"
                 for item in tables["nftables"]),
         "redirect_capture_table_remains")
    # NAT REDIRECT creates no policy routing rule or table 100 route. Foreign
    # Gateway/TPROXY policy is outside this owner's inverse and remains intact.


def capture_absent_after_stop(*, mode: str, unit_name: str, boot_id: str,
                              netns_ino: int,
                              prior_invocation_id: str | None,
                              policy_sha256: str, output_drop_handle: int,
                              snapshot_policy: Callable) -> CaptureAbsentWitness:
    """Compensation after START may prove absence without a prior ready receipt."""
    need(mode in ("full-wide-tun", "wide-redirect-safe") and
         Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() == boot_id and
         os.stat("/proc/self/ns/net").st_ino == netns_ino,
         "capture_absence_host_changed")
    facts = _empty_private_service(unit_name, prior_invocation_id)
    no_link = no_routes = None
    no_redirect = no_policy_route = None
    if mode == "full-wide-tun":
        try:
            socket.if_nametoindex(TUN)
        except OSError:
            pass
        else:
            raise CaptureRefused("capture_tun_remains")
        routes = _json([str(IP), "-j", "-6", "route", "show", "table", "all"])
        need(not any(route.get("dev") == TUN or
                     route.get("dst") in ("::/1", "8000::/1")
                     for route in routes), "capture_route_remains")
        no_link = no_routes = True
    else:
        _redirect_artifacts_absent()
        no_redirect, no_policy_route = True, False
    policy, handle = _policy(policy_sha256, output_drop_handle,
                             snapshot_policy)
    need(_empty_private_service(unit_name, prior_invocation_id) == facts,
         "capture_absence_service_changed")
    if mode == "full-wide-tun":
        need(not Path("/sys/class/net", TUN).exists(),
             "capture_tun_reappeared")
    else:
        _redirect_artifacts_absent()
    _policy(policy_sha256, output_drop_handle, snapshot_policy)
    return CaptureAbsentWitness(
        "aegis_auto_capture_absent_after_stop_v2", mode, unit_name,
        boot_id, netns_ino, prior_invocation_id, facts["ActiveState"],
        True, no_link, no_routes, no_redirect, no_policy_route,
        policy, handle, time.monotonic_ns())


def capture_redirect_inverse(*, mode: str, unit_name: str,
                             boot_id: str, netns_ino: int,
                             prior_invocation_id: str,
                             prior_redirect_policy_sha256: str,
                             prior_prerouting_chain_handle: int,
                             prior_redirect_handle: int,
                             policy_sha256: str, output_drop_handle: int,
                             snapshot_policy: Callable) -> RedirectInverseWitness:
    need(mode == "wide-redirect-safe" and
         bool(HEX64.fullmatch(prior_redirect_policy_sha256)) and
         prior_prerouting_chain_handle > 0 and prior_redirect_handle > 0 and
         bool(HEX32.fullmatch(prior_invocation_id)) and
         Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() == boot_id and
         os.stat("/proc/self/ns/net").st_ino == netns_ino,
         "redirect_inverse_identity_changed")
    cgroup = _cgroup(unit_name)
    facts = _service(unit_name, stopped=True)
    need(facts["ActiveState"] in ("inactive", "failed") and
         facts["MainPID"] == "0" and facts["ControlPID"] == "0" and
         facts["InvocationID"] in (prior_invocation_id, ""),
         "redirect_inverse_service_running")
    _empty_cgroup_events(cgroup, "redirect_inverse_cgroup_populated")
    _redirect_artifacts_absent()
    policy, handle = _policy(policy_sha256, output_drop_handle,
                             snapshot_policy)
    need(_service(unit_name, stopped=True) == facts,
         "redirect_inverse_service_changed")
    _redirect_artifacts_absent()
    _policy(policy_sha256, output_drop_handle, snapshot_policy)
    return RedirectInverseWitness("aegis_auto_redirect_inverse_v2", mode,
                                  unit_name,
                                  boot_id, netns_ino, prior_invocation_id,
                                  prior_redirect_policy_sha256,
                                  prior_prerouting_chain_handle,
                                  prior_redirect_handle, facts["ActiveState"],
                                  True, False, policy, handle,
                                  time.monotonic_ns())


def capture_local_redirect_inverse(*, mode: str, unit_name: str,
                                   boot_id: str, netns_ino: int,
                                   prior_invocation_id: str,
                                   prior_redirect_policy_sha256: str,
                                   prior_output_chain_handle: int,
                                   prior_tcp_redirect_handle: int,
                                   prior_dns_redirect_handle: int,
                                   policy_sha256: str,
                                   output_drop_handle: int,
                                   snapshot_policy: Callable
                                   ) -> LocalRedirectInverseWitness:
    need(mode == "wide-redirect-safe" and
         bool(HEX64.fullmatch(prior_redirect_policy_sha256)) and
         all(type(value) is int and value > 0 for value in
             (prior_output_chain_handle, prior_tcp_redirect_handle,
              prior_dns_redirect_handle)) and
         bool(HEX32.fullmatch(prior_invocation_id)) and
         Path("/proc/sys/kernel/random/boot_id").read_text(
             encoding="ascii").strip() == boot_id and
         os.stat("/proc/self/ns/net").st_ino == netns_ino,
         "local_redirect_inverse_identity_changed")
    cgroup = _cgroup(unit_name)
    facts = _service(unit_name, stopped=True)
    need(facts["ActiveState"] in ("inactive", "failed") and
         facts["MainPID"] == "0" and facts["ControlPID"] == "0" and
         facts["InvocationID"] in (prior_invocation_id, ""),
         "local_redirect_inverse_service_running")
    _empty_cgroup_events(cgroup, "local_redirect_inverse_cgroup_populated")
    _redirect_artifacts_absent()
    policy, handle = _policy(policy_sha256, output_drop_handle,
                             snapshot_policy)
    need(_service(unit_name, stopped=True) == facts,
         "local_redirect_inverse_service_changed")
    _redirect_artifacts_absent()
    _policy(policy_sha256, output_drop_handle, snapshot_policy)
    return LocalRedirectInverseWitness(
        "aegis_auto_local_redirect_inverse_v1", mode, unit_name,
        boot_id, netns_ino, prior_invocation_id,
        prior_redirect_policy_sha256, prior_output_chain_handle,
        prior_tcp_redirect_handle, prior_dns_redirect_handle,
        facts["ActiveState"], True, policy, handle,
        time.monotonic_ns())


def _owned_control(path: Path, expected_pid: int,
                   expected_netns: int, deadline: float) -> tuple[socket.socket, int]:
    _trusted_ancestors(path)
    parent = path.parent.stat(follow_symlinks=False)
    named = path.stat(follow_symlinks=False)
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
         stat.S_IMODE(parent.st_mode) == 0o700 and
         stat.S_ISSOCK(named.st_mode) and named.st_uid == 0 and
         stat.S_IMODE(named.st_mode) == 0o600 and
         expected_pid > 1 and expected_netns > 0 and
         expected_netns != os.stat("/proc/self/ns/net").st_ino,
         "redirect_control_untrusted")
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET |
                         socket.SOCK_CLOEXEC)
    try:
        _remaining_timeout(peer, deadline)
        peer.connect(str(path))
        pid, uid, _gid = struct.unpack("3i", peer.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        after = path.stat(follow_symlinks=False)
        need(pid == expected_pid and uid == 0 and
             os.stat(f"/proc/{pid}/ns/net").st_ino == expected_netns and
             (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino),
             "redirect_control_peer_changed")
        pidfd = _connected_peer_pidfd(peer, pid)
        return peer, pidfd
    except BaseException:
        peer.close()
        raise


def capture_redirect_ready(*, mode: str, unit_name: str,
                           boot_id: str, netns_ino: int,
                           invocation_id: str, main_pid: int,
                           worker_sha256: str, policy_sha256: str,
                           expected_redirect_policy_sha256: str,
                           output_drop_handle: int,
                           snapshot_policy: Callable,
                           endpoint: RedirectEndpoint,
                           endpoint_lease: EndpointLease,
                           scoped_policy: dict | None = None,
                           scoped_verify: Callable | None = None,
                           exchange_timeout: float = 5.0,
                           phase_callback: Callable[[str], None] | None = None
                           ) -> RedirectReadyWitness:
    """Observe real scoped NAT ingress through the independent relay sink."""
    need(mode == "wide-redirect-safe" and type(endpoint) is RedirectEndpoint and
         type(endpoint_lease) is EndpointLease and
         endpoint_lease.endpoint == endpoint and
         bool(HEX64.fullmatch(expected_redirect_policy_sha256)) and
         0 < exchange_timeout <= 8 and
         Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() == boot_id and
         os.stat("/proc/self/ns/net").st_ino == netns_ino and
         bool(HEX32.fullmatch(invocation_id)),
         "redirect_host_or_mode_changed")
    target = ipaddress.IPv4Address(endpoint.target_ipv4)
    need(not (target.is_loopback or target.is_multicast or target.is_unspecified)
         and 1024 <= endpoint.target_port <= 65535 and
         endpoint.probe_netns_ino != endpoint.sink_netns_ino,
         "redirect_endpoint_invalid")
    cgroup = _cgroup(unit_name)
    facts = _service(unit_name)
    need(facts["ActiveState"] == "active" and facts["SubState"] == "running" and
         facts["InvocationID"] == invocation_id and
         facts["MainPID"] == str(main_pid) and facts["ControlPID"] == "0",
         "redirect_service_not_owned_and_running")
    worker_pidfd = os.pidfd_open(main_pid, 0)
    probe = sink = None
    probe_pidfd = sink_pidfd = None
    try:
        _pidfd_identity(worker_pidfd, main_pid)
        need(_service(unit_name) == facts, "redirect_pid1_identity_changed")
        _revalidated, _live, (guard_digest, guard_handle) = _concurrent_reads([
            endpoint_lease.revalidate,
            lambda: _pid_live(main_pid, worker_sha256, cgroup),
            lambda: _policy(policy_sha256, output_drop_handle, snapshot_policy)],
            local=0)
        redirect_args = {"scoped_policy": scoped_policy, "scoped_verify": scoped_verify,
                         "unit_name": unit_name, "invocation_id": invocation_id}
        redirect_digest, chain_handle, redirect_handle = _redirect_policy(
            endpoint.ingress_ifname, endpoint.listen_port, **redirect_args)
        need(redirect_digest == expected_redirect_policy_sha256,
             "redirect_source_policy_not_sealed")
        deadline = time.monotonic() + exchange_timeout
        sink, sink_pidfd = _owned_control(endpoint.sink_control_socket,
                                          endpoint.sink_pid,
                                          endpoint.sink_netns_ino, deadline)
        probe, probe_pidfd = _owned_control(endpoint.probe_control_socket,
                                            endpoint.probe_pid,
                                            endpoint.probe_netns_ino, deadline)
        nonce = os.urandom(32)
        nonce_hash = hashlib.sha256(nonce).hexdigest()
        _control_send(sink, {"op": "ECHO_ARM", "sha256": nonce_hash}, deadline)
        _capture_phase(phase_callback, "redirect_await_sink_ready")
        sink_ready = _control_recv(sink, deadline)
        _capture_phase(phase_callback, "redirect_received_sink_ready")
        need(set(sink_ready) == {"state", "sha256", "session", "sink_pid",
                                   "sink_netns_ino", "listen_ip", "listen_port"} and
             sink_ready["state"] == "ECHO_READY" and
             sink_ready["sha256"] == nonce_hash and
             type(sink_ready["session"]) is str and
             HEX32.fullmatch(sink_ready["session"]) and
             sink_ready["sink_pid"] == endpoint.sink_pid and
             sink_ready["sink_netns_ino"] == endpoint.sink_netns_ino and
             sink_ready["listen_ip"] == endpoint.target_ipv4 and
             sink_ready["listen_port"] == endpoint.target_port,
             "redirect_sink_not_armed")
        _control_send(probe, {"op": "PROBE_ARM", "sha256": nonce_hash,
                              "nonce_hex": nonce.hex(),
                              "target_ip": endpoint.target_ipv4,
                              "target_port": endpoint.target_port,
                              "deadline_monotonic_ns": int(deadline * 1_000_000_000)}, deadline)
        _capture_phase(phase_callback, "redirect_await_ready")
        probe_ready = _control_recv(probe, deadline)
        _capture_phase(phase_callback, "redirect_received_ready")
        probe_base = {"sha256": nonce_hash, "probe_pid": endpoint.probe_pid,
                      "probe_netns_ino": endpoint.probe_netns_ino,
                      "peer_pid": os.getpid(), "target_ip": endpoint.target_ipv4,
                      "target_port": endpoint.target_port}
        need(set(probe_ready) == set(probe_base) | {"state", "session"} and
             all(probe_ready[k] == value for k, value in probe_base.items()) and
             probe_ready["state"] == "PROBE_READY" and
             type(probe_ready["session"]) is str and
             HEX32.fullmatch(probe_ready["session"]),
             "redirect_probe_not_armed")
        _capture_phase(phase_callback, "redirect_await_observed")
        observed = _control_recv(probe, deadline)
        _capture_phase(phase_callback, "redirect_received_observed")
        need(set(observed) == set(probe_ready) |
             {"connected_ip", "connected_port", "sent_bytes", "echoed_bytes"} and
             all(observed[k] == value for k, value in probe_ready.items()
                 if k != "state") and
             observed["state"] == "PROBE_OBSERVED" and
             observed["connected_ip"] == endpoint.target_ipv4 and
             observed["connected_port"] == endpoint.target_port and
             type(observed["sent_bytes"]) is int and observed["sent_bytes"] == 32 and
             type(observed["echoed_bytes"]) is int and observed["echoed_bytes"] == 32,
             "redirect_probe_not_carried")
        _control_send(probe, {"op": "PROBE_FINISH", "sha256": nonce_hash,
                              "session": probe_ready["session"]}, deadline)
        _capture_phase(phase_callback, "redirect_await_complete")
        probe_complete = _control_recv(probe, deadline)
        _capture_phase(phase_callback, "redirect_received_complete")
        need(set(probe_complete) == set(observed) and
             all(probe_complete[k] == value for k, value in observed.items()
                 if k != "state") and
             probe_complete["state"] == "PROBE_COMPLETE",
             "redirect_probe_receipt_invalid")
        _control_send(sink, {"op": "ECHO_FINISH", "sha256": nonce_hash,
                             "session": sink_ready["session"]}, deadline)
        _capture_phase(phase_callback, "redirect_await_sink_complete")
        sink_complete = _control_recv(sink, deadline)
        _capture_phase(phase_callback, "redirect_received_sink_complete")
        need(set(sink_complete) == set(sink_ready) |
             {"received", "echoed", "received_bytes", "echoed_bytes"} and
             all(sink_complete[k] == value for k, value in sink_ready.items()
                 if k != "state") and
             sink_complete["state"] == "ECHO_COMPLETE" and
             all(type(sink_complete[k]) is int and sink_complete[k] == value
                 for k, value in (("received", 1), ("echoed", 1),
                                  ("received_bytes", 32), ("echoed_bytes", 32))),
             "redirect_sink_receipt_invalid")
        need(time.monotonic() <= deadline and
             not any(select.select([fd], [], [], 0)[0]
                     for fd in (worker_pidfd, probe_pidfd, sink_pidfd)),
             "redirect_actor_exited_or_deadline")
        endpoint_lease.exchange_completed = True
        # The redirect check (scoped verifier) stays in this thread.
        _concurrent_reads([
            lambda: _pid_live(main_pid, worker_sha256, cgroup),
            lambda: need(_service(unit_name) == facts and
                         _redirect_policy(endpoint.ingress_ifname, endpoint.listen_port,
                                          **redirect_args) ==
                         (redirect_digest, chain_handle, redirect_handle),
                         "redirect_policy_changed"),
            lambda: _policy(policy_sha256, output_drop_handle, snapshot_policy)],
            local=1)
        endpoint_lease.revalidate()
        return RedirectReadyWitness(
            "aegis_auto_redirect_ready_v2", mode, unit_name,
            boot_id, netns_ino,
            invocation_id, main_pid, endpoint.ingress_ifname,
            redirect_digest, chain_handle, redirect_handle,
            endpoint.probe_pid, endpoint.probe_netns_ino,
            endpoint.sink_pid, endpoint.sink_netns_ino, nonce_hash,
            probe_ready["session"], sink_ready["session"], 32, 1, 1,
            guard_digest, guard_handle, time.monotonic_ns())
    finally:
        os.close(worker_pidfd)
        for fd in (probe_pidfd, sink_pidfd):
            if fd is not None:
                os.close(fd)
        for connection in (probe, sink):
            if connection is not None:
                connection.close()


@dataclasses.dataclass(frozen=True)
class CaptureReadyWitness:
    schema: str
    mode: str
    unit_name: str
    boot_id: str
    netns_ino: int
    invocation_id: str
    main_pid: int
    tun_ifindex: int
    tun_operstate: str
    routes: tuple[dict[str, object], ...]
    packet_sha256: str
    external_echo: CaptureEchoWitness
    guard_policy_sha256: str
    guard_output_drop_handle: int
    observed_monotonic_ns: int


@dataclasses.dataclass(frozen=True)
class RuntimeEchoWitness:
    """A tunnel roundtrip to the configured authenticated relay, not Internet egress."""
    scope: str
    target_ipv6: str
    target_port: int
    nonce_sha256: str
    egress_packet_sha256: str
    ingress_packet_sha256: str
    application_received: bool
    configured_relay_pool: tuple[tuple[str, str, str], ...]
    configured_relay_pool_sha256: str
    auth_profile: str
    rendered_config_sha256: str
    credential_lineage_sha256: str


@dataclasses.dataclass(frozen=True)
class RuntimeCaptureReadyWitness:
    schema: str
    mode: str
    unit_name: str
    boot_id: str
    netns_ino: int
    invocation_id: str
    main_pid: int
    tun_ifindex: int
    tun_operstate: str
    routes: tuple[dict[str, object], ...]
    packet_sha256: str
    runtime_echo: RuntimeEchoWitness
    guard_policy_sha256: str
    guard_output_drop_handle: int
    observed_monotonic_ns: int


def _runtime_echo_through_tun(ifindex: int, endpoint_lease: object,
                              deadline: float) -> RuntimeEchoWitness:
    """Observe one fresh nonce leaving and returning on the installed TUN."""
    endpoint_lease.revalidate()
    route = _json([str(IP), "-j", "-6", "route", "get", RUNTIME_UDP_TARGET])
    need(len(route) == 1 and _single_route_hop(route[0]) and
         route[0].get("dev") == TUN and
         route[0].get("gateway") is None, "runtime_echo_bypasses_tun")
    nonce = os.urandom(32)
    nonce_hash = hashlib.sha256(nonce).hexdigest()
    packet = None
    application = None
    try:
        packet = _tun_ipv6_sniffer()
        application = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM |
                                    socket.SOCK_CLOEXEC)
        need(socket.if_nametoindex(TUN) == ifindex,
             "runtime_echo_tun_replaced")
        packet.setblocking(False)
        _remaining_timeout(application, deadline)
        application.connect((RUNTIME_UDP_TARGET, RUNTIME_PROBE_PORT, 0, 0))
        local_ip, local_port, _flow, _scope = application.getsockname()
        target_ip = ipaddress.IPv6Address(RUNTIME_UDP_TARGET).packed
        local_packed = ipaddress.IPv6Address(local_ip).packed
        _remaining_timeout(application, deadline)
        need(application.send(nonce) == len(nonce),
             "runtime_echo_send_failed")
        outgoing = incoming = response = None
        while time.monotonic() < deadline and (outgoing is None or
                                               incoming is None or
                                               response is None):
            ready, _, _ = select.select([packet, application], [], [],
                                        min(0.2, max(0.0, deadline - time.monotonic())))
            for source in ready:
                if source is application:
                    _remaining_timeout(application, deadline)
                    candidate = application.recv(2048)
                    if candidate == nonce:
                        response = candidate
                    continue
                try:
                    raw, address = packet.recvfrom(65535)
                except BlockingIOError:
                    continue
                if (address[0] != TUN or address[1] != ETH_P_IPV6 or
                        len(raw) != 80 or
                        raw[0] >> 4 != 6 or raw[6] != 17 or
                        raw[48:] != nonce):
                    continue
                source_ip, dest_ip = raw[8:24], raw[24:40]
                source_port, dest_port = struct.unpack("!HH", raw[40:44])
                if (address[2] == socket.PACKET_OUTGOING and
                        source_ip == local_packed and dest_ip == target_ip and
                        source_port == local_port and
                        dest_port == RUNTIME_PROBE_PORT):
                    outgoing = hashlib.sha256(raw).hexdigest()
                elif (address[2] == socket.PACKET_HOST and
                      source_ip == target_ip and dest_ip == local_packed and
                      source_port == RUNTIME_PROBE_PORT and
                      dest_port == local_port):
                    incoming = hashlib.sha256(raw).hexdigest()
        need(outgoing is not None and incoming is not None and response == nonce and
             time.monotonic() <= deadline,
             "runtime_echo_not_bidirectional_on_tun")
        endpoint_lease.revalidate()
        return RuntimeEchoWitness(
            "authenticated_relay_roundtrip", RUNTIME_UDP_TARGET,
            RUNTIME_PROBE_PORT, nonce_hash, outgoing, incoming, True,
            endpoint_lease.configured_relay_pool,
            endpoint_lease.configured_relay_pool_sha256,
            endpoint_lease.auth_profile, endpoint_lease.config_sha256,
            endpoint_lease.credential_lineage_sha256)
    finally:
        if application is not None:
            application.close()
        if packet is not None:
            packet.close()


def capture_runtime_ready(*, mode: str, unit_name: str,
                          boot_id: str, netns_ino: int,
                          invocation_id: str, main_pid: int,
                          worker_sha256: str, policy_sha256: str,
                          output_drop_handle: int, snapshot_policy: Callable,
                          endpoint_lease: object,
                          packet_timeout: float = 2.0,
                          echo_timeout: float = 5.0
                          ) -> RuntimeCaptureReadyWitness:
    """Prove live FullTun carriage through the user's configured relay."""
    need(mode == "full-wide-tun" and
         endpoint_lease.mode == mode and endpoint_lease.unit == unit_name and
         0 < packet_timeout <= 3 and 0 < echo_timeout <= 5 and
         Path("/proc/sys/kernel/random/boot_id").read_text(
             encoding="ascii").strip() == boot_id and
         os.stat("/proc/self/ns/net").st_ino == netns_ino and
         bool(HEX32.fullmatch(invocation_id)),
         "runtime_capture_host_or_mode_changed")
    facts = _service(unit_name)
    need(facts["ActiveState"] == "active" and facts["SubState"] == "running" and
         facts["InvocationID"] == invocation_id and
         facts["MainPID"] == str(main_pid) and facts["ControlPID"] == "0",
         "runtime_capture_service_not_owned")
    pidfd = os.pidfd_open(main_pid, 0)
    try:
        endpoint_lease.revalidate()
        _pidfd_identity(pidfd, main_pid)
        # The pidfd is bound to MainPID; the independent reads run together
        # and are all joined before the first packet.
        _live, _owned, (ifindex, state, routes), (policy, handle) = _concurrent_reads([
            lambda: _pid_live(main_pid, worker_sha256, _cgroup(unit_name)),
            lambda: _tun_owned_by_pid(main_pid),
            _link_and_routes,
            lambda: _policy(policy_sha256, output_drop_handle, snapshot_policy)])
        packet_sha256 = _packet_on_tun(ifindex,
                                       time.monotonic() + packet_timeout)
        echo = _runtime_echo_through_tun(ifindex, endpoint_lease,
                                         time.monotonic() + echo_timeout)
        need(not select.select([pidfd], [], [], 0)[0],
             "runtime_capture_main_exited")
        _concurrent_reads([lambda: _pid_live(main_pid, worker_sha256, _cgroup(unit_name)),
                           lambda: _tun_owned_by_pid(main_pid)])
        _concurrent_reads([
            lambda: need(_service(unit_name) == facts and
                         socket.if_nametoindex(TUN) == ifindex,
                         "runtime_capture_service_or_link_changed"),
            lambda: _routes(ifindex),
            lambda: _policy(policy_sha256, output_drop_handle, snapshot_policy),
            endpoint_lease.revalidate], local=3)
        return RuntimeCaptureReadyWitness(
            "aegis_auto_runtime_capture_ready_v1", mode, unit_name,
            boot_id, netns_ino, invocation_id, main_pid, ifindex, state,
            routes, packet_sha256, echo, policy, handle,
            time.monotonic_ns())
    finally:
        os.close(pidfd)


@dataclasses.dataclass(frozen=True)
class RuntimeRedirectReadyWitness:
    schema: str
    mode: str
    unit_name: str
    boot_id: str
    netns_ino: int
    invocation_id: str
    main_pid: int
    ingress_ifname: str
    redirect_policy_sha256: str
    prerouting_chain_handle: int
    redirect_handle: int
    probe_pid: int
    probe_netns_ino: int
    runtime_echo_nonce_sha256: str
    runtime_echo_scope: str
    configured_relay_pool: tuple[tuple[str, str, str], ...]
    configured_relay_pool_sha256: str
    auth_profile: str
    rendered_config_sha256: str
    credential_lineage_sha256: str
    guard_policy_sha256: str
    guard_output_drop_handle: int
    observed_monotonic_ns: int


@dataclasses.dataclass(frozen=True)
class RuntimeLocalRedirectReadyWitness:
    schema: str
    mode: str
    unit_name: str
    boot_id: str
    netns_ino: int
    invocation_id: str
    main_pid: int
    redirect_policy_sha256: str
    output_chain_handle: int
    tcp_redirect_handle: int
    dns_redirect_handle: int
    runtime_echo_nonce_sha256: str
    runtime_dns_query_sha256: str
    runtime_echo_scope: str
    configured_relay_pool: tuple[tuple[str, str, str], ...]
    configured_relay_pool_sha256: str
    auth_profile: str
    rendered_config_sha256: str
    credential_lineage_sha256: str
    guard_policy_sha256: str
    guard_output_drop_handle: int
    observed_monotonic_ns: int
    udp_redirect_handle: int | None = None
    runtime_udp_nonce_sha256: str | None = None
    tcp_redirect_packet_delta: int = 0
    dns_redirect_packet_delta: int = 0
    udp_redirect_packet_delta: int | None = None


def _owned_local_udp_listener(pid: int, port: int) -> int:
    """Bind the generic UDP proof to the live Main's loopback socket."""
    expected = f"0100007F:{port:04X}"
    rows = Path(f"/proc/{pid}/net/udp").read_text(encoding="ascii").splitlines()
    need(1 <= len(rows) <= 65536, "runtime_local_udp_table_unbounded")
    inodes = []
    for row in rows[1:]:
        fields = row.split()
        need(len(fields) >= 10, "runtime_local_udp_row_invalid")
        if fields[1] == expected:
            need(fields[9].isdecimal(), "runtime_local_udp_inode_invalid")
            inodes.append(int(fields[9]))
    need(len(inodes) == 1 and inodes[0] > 0,
         "runtime_local_udp_listener_missing")
    descriptors = list(Path(f"/proc/{pid}/fd").iterdir())
    need(len(descriptors) <= 4096 and any(
         os.readlink(entry) == f"socket:[{inodes[0]}]"
         for entry in descriptors if entry.name.isdecimal()),
         "runtime_local_udp_listener_not_owned")
    return inodes[0]


def capture_runtime_local_redirect_ready(*, mode: str, unit_name: str,
                                         boot_id: str, netns_ino: int,
                                         invocation_id: str, main_pid: int,
                                         worker_sha256: str,
                                         policy_sha256: str,
                                         output_drop_handle: int,
                                         snapshot_policy: Callable,
                                         runtime_lease: object,
                                         local_policy: dict,
                                         local_verify: Callable,
                                         local_counters: Callable,
                                         exchange_timeout: float = 5.0
                                         ) -> RuntimeLocalRedirectReadyWitness:
    """Prove host OUTPUT TCP and DNS through the real configured Main."""
    need(mode in ("wide-redirect-safe", "full-wide-tun") and
         runtime_lease.mode == mode and
         runtime_lease.unit == unit_name and
         ((mode == "wide-redirect-safe" and
           runtime_lease.redirect_rollout_profile == "output_only_safe") or
          (mode == "full-wide-tun" and
           local_policy.get("profile") == "full_wide_tun")) and
         0 < exchange_timeout <= 5 and
         type(local_policy) is dict and callable(local_verify) and
         callable(local_counters) and
         Path("/proc/sys/kernel/random/boot_id").read_text(
             encoding="ascii").strip() == boot_id and
         os.stat("/proc/self/ns/net").st_ino == netns_ino and
         bool(HEX32.fullmatch(invocation_id)),
         "runtime_local_redirect_host_or_mode_changed")
    facts = _service(unit_name)
    need(facts["ActiveState"] == "active" and facts["SubState"] == "running" and
         facts["InvocationID"] == invocation_id and
         facts["MainPID"] == str(main_pid) and facts["ControlPID"] == "0",
         "runtime_local_redirect_service_not_owned")
    main_pidfd = os.pidfd_open(main_pid, 0)
    try:
        runtime_lease.revalidate()
        _pidfd_identity(main_pidfd, main_pid)
        _pid_live(main_pid, worker_sha256, _cgroup(unit_name))
        guard_digest, guard_handle = _policy(policy_sha256,
                                             output_drop_handle,
                                             snapshot_policy)
        observed = local_verify()
        need(observed == local_policy and
             observed.get("private_unit") == unit_name and
             observed.get("invocation_id") == invocation_id and
             observed.get("listen_ipv4") == "127.0.0.1" and
             observed.get("listen_port") ==
             (980 if mode == "full-wide-tun" else 15080) and
             observed.get("dns_port") == 53 and
             observed.get("udp_port") ==
             (local_policy.get("udp_port") if mode == "full-wide-tun" else None),
             "runtime_local_redirect_policy_changed")
        if mode == "full-wide-tun":
            _owned_local_udp_listener(main_pid, local_policy["udp_port"])
        before = local_counters()
        deadline = time.monotonic() + exchange_timeout
        nonce = os.urandom(32)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM |
                            socket.SOCK_CLOEXEC)
        try:
            _remaining_timeout(tcp, deadline)
            tcp.connect((RUNTIME_TCP_TARGET, RUNTIME_PROBE_PORT))
            _remaining_timeout(tcp, deadline)
            tcp.sendall(nonce)
            received = bytearray()
            while len(received) < len(nonce):
                _remaining_timeout(tcp, deadline)
                part = tcp.recv(len(nonce) - len(received))
                need(part, "runtime_local_redirect_echo_closed")
                received.extend(part)
            need(bytes(received) == nonce,
                 "runtime_local_redirect_echo_changed")
        finally:
            tcp.close()
        # Use a fresh synthetic A name: the required preview returns an IP in
        # its sealed fake-IP pool without contacting a native resolver.
        dns_nonce = os.urandom(8)
        label = b"aegis-" + dns_nonce.hex().encode("ascii")
        question = bytes([len(label)]) + label + b"\x04test\x00\x00\x01\x00\x01"
        query = dns_nonce[:2] + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM |
                            socket.SOCK_CLOEXEC)
        try:
            _remaining_timeout(udp, deadline)
            udp.sendto(query, ("192.0.2.53", 53))
            _remaining_timeout(udp, deadline)
            response, _peer = udp.recvfrom(1500)
            need(len(response) >= len(query) + 16 and
                 response[:2] == query[:2] and response[2] & 0x80 and
                 response[3] & 0x0f == 0 and response[6:8] == b"\x00\x01" and
                 response[12:12 + len(question)] == question and
                 ipaddress.IPv4Address(response[-4:]) in
                 ipaddress.IPv4Network("198.18.0.0/15"),
                 "runtime_local_dns_preview_changed")
        finally:
            udp.close()
        udp_nonce = None
        if mode == "full-wide-tun":
            udp_nonce = os.urandom(32)
            generic_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM |
                                        socket.SOCK_CLOEXEC)
            try:
                _remaining_timeout(generic_udp, deadline)
                generic_udp.sendto(udp_nonce,
                                   (RUNTIME_UDP_IPV4_TARGET,
                                    RUNTIME_PROBE_PORT))
                _remaining_timeout(generic_udp, deadline)
                udp_echo, _peer = generic_udp.recvfrom(64)
                need(udp_echo == udp_nonce,
                     "runtime_local_udp_relay_echo_changed")
            finally:
                generic_udp.close()
        after = local_counters()
        need(after["tcp_redirect_handle"] > before["tcp_redirect_handle"] and
             after["dns_redirect_handle"] > before["dns_redirect_handle"] and
             (mode != "full-wide-tun" or
              after["udp_redirect_handle"] > before["udp_redirect_handle"]) and
             local_verify() == local_policy and
             _service(unit_name) == facts and
             not select.select([main_pidfd], [], [], 0)[0] and
             time.monotonic() <= deadline,
             "runtime_local_redirect_effect_changed")
        _pid_live(main_pid, worker_sha256, _cgroup(unit_name))
        _policy(policy_sha256, output_drop_handle, snapshot_policy)
        runtime_lease.revalidate()
        return RuntimeLocalRedirectReadyWitness(
            ("aegis_auto_runtime_local_fulltun_ready_v1" if
             mode == "full-wide-tun" else
             "aegis_auto_runtime_local_redirect_ready_v1"), mode,
            unit_name, boot_id, netns_ino, invocation_id, main_pid,
            observed["policy_sha256"], observed["output_chain_handle"],
            observed["tcp_redirect_handle"], observed["dns_redirect_handle"],
            hashlib.sha256(nonce).hexdigest(),
            hashlib.sha256(query).hexdigest(),
            ("authenticated_tcp_udp_relay_roundtrip_and_dns_preview" if
             mode == "full-wide-tun" else
             "authenticated_relay_roundtrip_and_local_dns_preview"),
            runtime_lease.configured_relay_pool,
            runtime_lease.configured_relay_pool_sha256,
            runtime_lease.auth_profile, runtime_lease.config_sha256,
            runtime_lease.credential_lineage_sha256,
            guard_digest, guard_handle, time.monotonic_ns(),
            observed.get("udp_redirect_handle"),
            hashlib.sha256(udp_nonce).hexdigest() if udp_nonce is not None
            else None,
            after["tcp_redirect_handle"] - before["tcp_redirect_handle"],
            after["dns_redirect_handle"] - before["dns_redirect_handle"],
            (after["udp_redirect_handle"] - before["udp_redirect_handle"]
             if mode == "full-wide-tun" else None))
    finally:
        os.close(main_pidfd)


def capture_runtime_redirect_ready(*, mode: str, unit_name: str,
                                   boot_id: str, netns_ino: int,
                                   invocation_id: str, main_pid: int,
                                   worker_sha256: str, policy_sha256: str,
                                   expected_redirect_policy_sha256: str,
                                   output_drop_handle: int,
                                   snapshot_policy: Callable,
                                   endpoint: RuntimeRedirectEndpoint,
                                   effect_lease: object,
                                   runtime_lease: object,
                                   scoped_policy: dict | None = None,
                                   scoped_verify: Callable | None = None,
                                   exchange_timeout: float = 5.0,
                                   phase_callback: Callable[[str], None] | None = None
                                   ) -> RuntimeRedirectReadyWitness:
    """Prove an actual PREROUTING ingress reaches the configured user relay."""
    need(mode == "wide-redirect-safe" and
         runtime_lease.mode == mode and runtime_lease.unit == unit_name and
         type(endpoint) is RuntimeRedirectEndpoint and
         0 < exchange_timeout <= 5 and
         Path("/proc/sys/kernel/random/boot_id").read_text(
             encoding="ascii").strip() == boot_id and
         os.stat("/proc/self/ns/net").st_ino == netns_ino and
         bool(HEX32.fullmatch(invocation_id)),
         "runtime_redirect_host_or_mode_changed")
    facts = _service(unit_name)
    need(facts["ActiveState"] == "active" and facts["SubState"] == "running" and
         facts["InvocationID"] == invocation_id and
         facts["MainPID"] == str(main_pid) and facts["ControlPID"] == "0",
         "runtime_redirect_service_not_owned")
    main_pidfd = os.pidfd_open(main_pid, 0)
    probe = None
    probe_pidfd = None
    def phase(label: str) -> None:
        _capture_phase(phase_callback, label)
    try:
        runtime_lease.revalidate()
        effect_lease.verify()
        _pidfd_identity(main_pidfd, main_pid)
        _live, (guard_digest, guard_handle) = _concurrent_reads([
            lambda: _pid_live(main_pid, worker_sha256, _cgroup(unit_name)),
            lambda: _policy(policy_sha256, output_drop_handle, snapshot_policy)])
        redirect_args = {"scoped_policy": scoped_policy, "scoped_verify": scoped_verify,
                         "unit_name": unit_name, "invocation_id": invocation_id}
        redirect_digest, chain_handle, redirect_handle = _redirect_policy(
            endpoint.ingress_ifname, endpoint.listen_port, **redirect_args)
        need(redirect_digest == expected_redirect_policy_sha256,
             "runtime_redirect_policy_not_sealed")
        deadline = time.monotonic() + exchange_timeout
        probe, probe_pidfd = _owned_control(endpoint.probe_control_socket,
                                            endpoint.probe_pid,
                                            endpoint.probe_netns_ino, deadline)
        nonce = os.urandom(32)
        nonce_hash = hashlib.sha256(nonce).hexdigest()
        _control_send(probe, {"op": "PROBE_ARM", "sha256": nonce_hash,
                              "nonce_hex": nonce.hex(),
                              "target_ip": RUNTIME_TCP_TARGET,
                              "target_port": RUNTIME_PROBE_PORT,
                              "deadline_monotonic_ns": int(deadline * 1_000_000_000)}, deadline)
        expected = {"sha256": nonce_hash, "probe_pid": endpoint.probe_pid,
                    "probe_netns_ino": endpoint.probe_netns_ino,
                    "peer_pid": os.getpid(), "target_ip": RUNTIME_TCP_TARGET,
                    "target_port": RUNTIME_PROBE_PORT}
        phase("redirect_await_ready")
        ready = _control_recv(probe, deadline)
        phase("redirect_received_ready")
        need(set(ready) == set(expected) | {"state", "session"} and
             all(ready[key] == value for key, value in expected.items()) and
             ready["state"] == "PROBE_READY" and
             type(ready["session"]) is str and HEX32.fullmatch(ready["session"]),
             "runtime_redirect_probe_not_armed")
        phase("redirect_await_observed")
        observed = _control_recv(probe, deadline)
        phase("redirect_received_observed")
        need(set(observed) == set(ready) |
             {"connected_ip", "connected_port", "sent_bytes", "echoed_bytes"} and
             all(observed[key] == value for key, value in ready.items()
                 if key != "state") and
             observed["state"] == "PROBE_OBSERVED" and
             observed["connected_ip"] == RUNTIME_TCP_TARGET and
             observed["connected_port"] == RUNTIME_PROBE_PORT and
             type(observed["sent_bytes"]) is int and
             type(observed["echoed_bytes"]) is int and
             observed["sent_bytes"] == observed["echoed_bytes"] == 32,
             "runtime_redirect_not_carried")
        # The completed probe retains its socket and pidfd until this owner's
        # release. CLOSE still requires its exact completed receipt.
        effect_lease.verify()
        _control_send(probe, {"op": "PROBE_FINISH", "sha256": nonce_hash,
                              "session": ready["session"]}, deadline)
        phase("redirect_await_complete")
        complete = _control_recv(probe, deadline)
        phase("redirect_received_complete")
        need(set(complete) == set(observed) and
             all(complete[key] == value for key, value in observed.items()
                 if key != "state") and
             complete["state"] == "PROBE_COMPLETE" and
             time.monotonic() <= deadline and
             not select.select([main_pidfd, probe_pidfd], [], [], 0)[0],
             "runtime_redirect_probe_receipt_invalid")
        _concurrent_reads([
            lambda: _pid_live(main_pid, worker_sha256, _cgroup(unit_name)),
            lambda: need(_service(unit_name) == facts and
                         _redirect_policy(endpoint.ingress_ifname,
                                          endpoint.listen_port, **redirect_args) ==
                         (redirect_digest, chain_handle, redirect_handle),
                         "runtime_redirect_policy_changed"),
            lambda: _policy(policy_sha256, output_drop_handle, snapshot_policy)],
            local=1)
        runtime_lease.revalidate()
        return RuntimeRedirectReadyWitness(
            "aegis_auto_runtime_redirect_ready_v2", mode, unit_name,
            boot_id, netns_ino, invocation_id, main_pid,
            endpoint.ingress_ifname, redirect_digest, chain_handle,
            redirect_handle, endpoint.probe_pid, endpoint.probe_netns_ino,
            nonce_hash, "authenticated_relay_roundtrip",
            runtime_lease.configured_relay_pool,
            runtime_lease.configured_relay_pool_sha256,
            runtime_lease.auth_profile, runtime_lease.config_sha256,
            runtime_lease.credential_lineage_sha256,
            guard_digest, guard_handle, time.monotonic_ns())
    finally:
        if probe_pidfd is not None:
            os.close(probe_pidfd)
        if probe is not None:
            probe.close()
        os.close(main_pidfd)


def capture_ready(*, mode: str, unit_name: str,
                  boot_id: str, netns_ino: int, invocation_id: str,
                  main_pid: int, worker_sha256: str,
                  policy_sha256: str, output_drop_handle: int,
                  snapshot_policy: Callable, echo_endpoint: CaptureEchoEndpoint,
                  endpoint_lease: EndpointLease,
                  packet_timeout: float = 2.0,
                  echo_timeout: float = 5.0) -> CaptureReadyWitness:
    need(mode == "full-wide-tun" and
         type(endpoint_lease) is EndpointLease and
         endpoint_lease.endpoint == echo_endpoint and
         packet_timeout > 0 and packet_timeout <= 3 and
         echo_timeout > 0 and echo_timeout <= 8 and
         Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() == boot_id and
         os.stat("/proc/self/ns/net").st_ino == netns_ino and
         bool(HEX32.fullmatch(invocation_id)), "capture_host_or_invocation_changed")
    cgroup = _cgroup(unit_name)
    facts = _service(unit_name)
    need(facts["ActiveState"] == "active" and facts["SubState"] == "running" and
         facts["InvocationID"] == invocation_id and
         facts["MainPID"] == str(main_pid) and facts["ControlPID"] == "0",
         "capture_service_not_owned_and_running")
    pidfd = os.pidfd_open(main_pid, 0)
    try:
        # Bind the pidfd to PID1's MainPID first; only then read the
        # independent facts together. The endpoint lease (actor socket)
        # stays in this thread; all are joined before the first packet.
        _pidfd_identity(pidfd, main_pid)
        need(_service(unit_name) == facts, "capture_pid1_identity_changed")
        _revalidated, _live, _owned, (ifindex, state, routes), (policy, handle) = \
            _concurrent_reads([
                endpoint_lease.revalidate,
                lambda: _pid_live(main_pid, worker_sha256, cgroup),
                lambda: _tun_owned_by_pid(main_pid),
                _link_and_routes,
                lambda: _policy(policy_sha256, output_drop_handle, snapshot_policy)],
                local=0)
        packet_sha256 = _packet_on_tun(ifindex, time.monotonic() + packet_timeout)
        external_echo = _echo_through_service(echo_endpoint, ifindex,
                                               time.monotonic() + echo_timeout)
        endpoint_lease.exchange_completed = True
        need(not select.select([pidfd], [], [], 0)[0], "capture_worker_exited")
        _concurrent_reads([lambda: _pid_live(main_pid, worker_sha256, cgroup),
                           lambda: _tun_owned_by_pid(main_pid)])
    finally:
        os.close(pidfd)
    _concurrent_reads([
        lambda: need(_service(unit_name) == facts and
                     socket.if_nametoindex(TUN) == ifindex,
                     "capture_service_or_link_changed"),
        lambda: _routes(ifindex),
        lambda: _policy(policy_sha256, output_drop_handle, snapshot_policy),
        endpoint_lease.revalidate], local=3)
    return CaptureReadyWitness("aegis_auto_capture_ready_v1", mode,
                               unit_name,
                               boot_id, netns_ino,
                               invocation_id, main_pid, ifindex, state, routes,
                               packet_sha256, external_echo, policy, handle,
                               time.monotonic_ns())


@dataclasses.dataclass(frozen=True)
class CaptureInverseWitness:
    schema: str
    mode: str
    unit_name: str
    boot_id: str
    netns_ino: int
    prior_invocation_id: str
    prior_tun_ifindex: int
    prior_capture_routes: tuple[dict[str, object], ...]
    service_active_state: str
    tun_absent: bool
    capture_routes_absent: bool
    remaining_capture_routes: tuple[dict[str, object], ...]
    guard_policy_sha256: str
    guard_output_drop_handle: int
    observed_monotonic_ns: int


def capture_inverse(*, mode: str, unit_name: str,
                    boot_id: str, netns_ino: int,
                    prior_invocation_id: str, prior_tun_ifindex: int,
                    prior_capture_routes: tuple[dict[str, object], ...],
                    policy_sha256: str, output_drop_handle: int,
                    snapshot_policy: Callable) -> CaptureInverseWitness:
    need(mode == "full-wide-tun" and
         Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip() == boot_id and
         os.stat("/proc/self/ns/net").st_ino == netns_ino and
         bool(HEX32.fullmatch(prior_invocation_id)) and prior_tun_ifindex > 0,
         "inverse_host_or_invocation_changed")
    need(len(prior_capture_routes) == 2 and
         {r.get("prefix") for r in prior_capture_routes} ==
         {"::/1", "8000::/1"} and
         all(r.get("ifindex") == prior_tun_ifindex for r in prior_capture_routes),
         "inverse_prior_capture_identity_invalid")
    cgroup = _cgroup(unit_name)
    facts = _service(unit_name, stopped=True)
    need(facts["ActiveState"] in ("inactive", "failed") and
         facts["MainPID"] == "0" and facts["ControlPID"] == "0" and
         facts["InvocationID"] in (prior_invocation_id, ""),
         "inverse_service_not_stopped")
    _empty_cgroup_events(cgroup, "inverse_service_cgroup_populated")
    try:
        named_ifindex = socket.if_nametoindex(TUN)
    except OSError:
        named_ifindex = None
    need(named_ifindex is None, "inverse_tun_still_present")
    all_routes = _json([str(IP), "-j", "-6", "route", "show", "table", "all"])
    remaining = tuple(route for route in all_routes
                      if route.get("dst") in ("::/1", "8000::/1") and
                      (route.get("dev") == TUN or
                       route.get("oif") == prior_tun_ifindex))
    need(not remaining, "inverse_capture_route_still_present")
    policy, handle = _policy(policy_sha256, output_drop_handle,
                             snapshot_policy)
    need(_service(unit_name, stopped=True) == facts and
         not Path("/sys/class/net", TUN).exists(),
         "inverse_service_or_link_changed")
    _policy(policy_sha256, output_drop_handle, snapshot_policy)
    return CaptureInverseWitness("aegis_auto_capture_inverse_v1", mode,
                                 unit_name, boot_id,
                                 netns_ino, prior_invocation_id, prior_tun_ifindex,
                                 prior_capture_routes, facts["ActiveState"], True, True,
                                 remaining, policy, handle,
                                 time.monotonic_ns())
