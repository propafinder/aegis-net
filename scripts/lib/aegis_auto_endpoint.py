#!/usr/bin/env python3
"""Admit the installed native capture endpoint through held live identities.

The guardian loads this exact installed source only after verifying its install
receipt.  The separate capture verifier holds file descriptors and pidfds until
the packet exchange finishes; a JSON receipt alone grants nothing.
"""

from __future__ import annotations

import hashlib
import base64
import dataclasses
import datetime
import ipaddress
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import aegis_auto_capture as capture


RECEIPT = Path("/var/lib/aegis-install/client/auto-capture-endpoint.json")
RELAY_INSTALL = Path("/var/lib/aegis-install/client/auto-capture-relay-install.json")
RELAY_UNIT = re.compile(r"aegis-auto-capture-relay-[0-9a-f]{32}\.service\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RUNTIME_RECIPE = {"accepted/render-recipe.json",
                  "accepted/final-render-recipe.json"}
BUNDLE_CA_LEAF = "accepted/payload/bundle-ca/ca.pem"
RENDER_MODES = {"full-wide-tun": "FullWideTun",
                "wide-redirect-safe": "WideRedirectSafe"}


def _need(ok: bool, reason: str) -> None:
    if not ok:
        raise capture.CaptureRefused(reason)


def _sha(path: Path, maximum: int, mode: int, expected: str) -> str:
    held = capture._held_file(path, maximum, mode, expected)
    try:
        return held.sha256
    finally:
        held.close()


def _relay_install() -> dict:
    held = capture._held_file(RELAY_INSTALL, 16384, 0o600, None)
    try:
        data = capture._strict_json(os.pread(held.fd, held.identity[3], 0))
    finally:
        held.close()
    fields = {"schema", "head", "server_source_closure_sha256",
              "unit", "server_binary_path", "server_binary_sha256",
              "config_path", "config_sha256", "cert_path", "cert_sha256",
              "key_path", "key_sha256", "outer_ca_path", "outer_ca_sha256",
              "auth_profile", "listen_ipv4", "listen_port"}
    profile = data.get("auth_profile")
    _need(profile in ("legacy_shared_token", "device_inner_tls"),
          "relay_install_auth_profile_invalid")
    auth_files = ()
    if profile == "legacy_shared_token":
        fields.add("auth_token_sha256")
    else:
        auth_files = ("inner_cert", "inner_key", "client_ca",
                      "device_cert", "device_key", "device_qa_key")
        for name in auth_files:
            fields.update((f"{name}_path", f"{name}_sha256"))
    hashes = {key for key in fields if key.endswith("_sha256")}
    _need(set(data) == fields and
          data["schema"] == "aegis_auto_capture_relay_install_v1" and
          type(data["unit"]) is str and RELAY_UNIT.fullmatch(data["unit"]) is not None and
          re.fullmatch(r"[0-9a-f]{40}", data["head"]) is not None and
          all(type(data[key]) is str and HEX64.fullmatch(data[key]) is not None
              for key in hashes) and
          data["listen_ipv4"] == "10.231.80.2" and data["listen_port"] == 443,
          "relay_install_receipt_invalid")
    for path_key, sha_key, maximum, mode in (
            ("server_binary_path", "server_binary_sha256", 512 << 20, 0o500),
            ("config_path", "config_sha256", 1 << 20, 0o600),
            ("cert_path", "cert_sha256", 1 << 20, 0o600),
            ("key_path", "key_sha256", 1 << 20, 0o600),
            ("outer_ca_path", "outer_ca_sha256", 1 << 20, 0o600)):
        _sha(Path(data[path_key]), maximum, mode, data[sha_key])
    for name in auth_files:
        _sha(Path(data[f"{name}_path"]), 1 << 20, 0o600,
             data[f"{name}_sha256"])
    if auth_files:
        _need(data["device_qa_key_path"] != data["device_key_path"],
              "relay_install_qa_key_alias_invalid")
    return data


def _server_pid(unit: str) -> tuple[int, str]:
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", unit,
         "-p", "ActiveState", "-p", "MainPID", "-p", "ControlGroup",
         "--no-pager"], stdin=subprocess.DEVNULL, capture_output=True,
        timeout=3, check=False,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
    _need(result.returncode == 0 and len(result.stdout) <= 4096 and
          len(result.stderr) <= 4096, "relay_pid1_readback_failed")
    fields = dict(line.split("=", 1) for line in
                  result.stdout.decode("ascii").splitlines() if "=" in line)
    _need(set(fields) == {"ActiveState", "MainPID", "ControlGroup"} and
          fields["ActiveState"] == "active" and
          fields["MainPID"].isdecimal() and int(fields["MainPID"]) > 1 and
          fields["ControlGroup"] == "/system.slice/" + unit,
          "relay_pid1_identity_invalid")
    return int(fields["MainPID"]), fields["ControlGroup"]


def _actor(child: dict, action: str, target_ip: str | None,
           target_port: int | None) -> dict:
    _need(child.get("action") == action and
          child.get("source") ==
          "/usr/local/lib/aegis/helpers/lib/aegis_auto_sink.py" and
          type(child.get("pid")) is int and child["pid"] > 1 and
          type(child.get("netns_ino")) is int and child["netns_ino"] > 0,
          "capture_actor_fact_invalid")
    path = Path(child["source"])
    _sha(path, 1 << 20, 0o500, child["source_sha256"])
    argv = [item.decode("utf-8") for item in
            Path(f'/proc/{child["pid"]}/cmdline').read_bytes().split(b"\0") if item]
    _need(len(argv) >= 5 and argv[:5] ==
          ["/usr/bin/python3", "-I", "-B", str(path), action],
          "capture_actor_argv_changed")
    result = {"pid": child["pid"], "netns_ino": child["netns_ino"],
              "control_socket": child["socket"],
              "control_dev": child["socket_dev"],
              "control_ino": child["socket_ino"],
              "actor_source_path": str(path),
              "actor_source_sha256": child["source_sha256"],
              "argv": argv}
    if target_ip is not None:
        result.update(target_ip=target_ip, target_port=target_port)
    return result


def _publish(facts: dict) -> None:
    parent = RECEIPT.parent
    info = parent.stat(follow_symlinks=False)
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
          not info.st_mode & 0o022, "endpoint_receipt_parent_untrusted")
    _need(not RECEIPT.exists() and not RECEIPT.is_symlink(),
          "prior_endpoint_receipt_requires_retirement")
    raw = (json.dumps(facts, sort_keys=True, separators=(",", ":")) + "\n").encode()
    _need(0 < len(raw) <= 16384, "endpoint_receipt_unbounded")
    temporary = parent / (".auto-capture-endpoint-" + secrets.token_hex(16))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    linked = False
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, RECEIPT, follow_symlinks=False)
        linked = True
        os.unlink(temporary)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except BaseException:
        if linked:
            # Preserve a unique failed attempt even when the directory fsync
            # fails after the receipt has become visible.
            retire_endpoint_receipt()
        raise
    finally:
        if temporary.exists():
            temporary.unlink()


def mint_endpoint_receipt(*, effect_lease: object, unit: str, mode: str,
                          boot_id: str, netns_ino: int,
                          installed_generation: str, manifest: str
                          ) -> capture.EndpointLease:
    """Mint one protected receipt and return its admitted, still-held lease.

    The caller owns the returned lease (and must close it). Its revalidate()
    re-proves every held file's path identity, admission predicates and
    content, the receipt bytes, every process through its held pidfd and
    every route, so no second by-path admission of the same receipt is made.
    """
    effect_lease.verify()
    _need(mode in ("full-wide-tun", "wide-redirect-safe") and
          bool(capture.PRIVATE_UNIT.fullmatch(unit)) and
          all(type(value) is str and HEX64.fullmatch(value) is not None
              for value in (installed_generation, manifest)) and
          boot_id == Path("/proc/sys/kernel/random/boot_id").read_text(
              encoding="ascii").strip() and
          netns_ino == os.stat("/proc/self/ns/net").st_ino,
          "endpoint_owner_identity_invalid")
    expected_mode = ("FULL_TUN_UDP" if mode == "full-wide-tun" else
                     "REDIRECT_TCP")
    children = effect_lease.facts.get("children")
    _need(effect_lease.facts.get("mode") == expected_mode and
          type(children) is list and len(children) ==
          (1 if mode == "full-wide-tun" else 2),
          "endpoint_effect_topology_mismatch")
    install = _relay_install()
    server_pid, cgroup = _server_pid(install["unit"])
    server = {"pid": server_pid,
              "netns_ino": os.stat(f"/proc/{server_pid}/ns/net").st_ino,
              "cgroup": cgroup,
              "argv": [install["server_binary_path"], "--config",
                       install["config_path"]],
              "exe_path": install["server_binary_path"],
              "exe_sha256": install["server_binary_sha256"],
              "config_path": install["config_path"],
              "config_sha256": install["config_sha256"],
              "cert_path": install["cert_path"],
              "cert_sha256": install["cert_sha256"],
              "key_path": install["key_path"],
              "key_sha256": install["key_sha256"],
              "outer_ca_path": install["outer_ca_path"],
              "outer_ca_sha256": install["outer_ca_sha256"],
              "auth_profile": install["auth_profile"],
              "listen_ipv4": install["listen_ipv4"],
              "listen_port": install["listen_port"]}
    if install["auth_profile"] == "legacy_shared_token":
        server["auth_token_sha256"] = install["auth_token_sha256"]
    else:
        for name in ("inner_cert", "inner_key", "client_ca",
                     "device_cert", "device_key", "device_qa_key"):
            for suffix in ("_path", "_sha256"):
                server[name + suffix] = install[name + suffix]
    sink_ip = ("fd77:ae91:1::2" if mode == "full-wide-tun" else
               "10.231.82.2")
    sink_action = ("serve-echo" if mode == "full-wide-tun" else
                   "serve-echo-tcp")
    facts = {"schema": "aegis_auto_capture_endpoint_v1",
             "boot_id": boot_id, "root_netns_ino": netns_ino,
             "mode": mode, "private_unit": unit,
             "installed_generation": installed_generation,
             "installed_manifest_sha256": manifest,
             "server": server,
             "sink": _actor(children[0], sink_action, sink_ip, 18080)}
    if mode == "wide-redirect-safe":
        probe = _actor(children[1], "serve-probe-tcp", None, None)
        probe.update(ingress_ifname="aegisacp0", listen_port=15080)
        facts["probe"] = probe
    _publish(facts)
    # Re-open from the just-published inode and require every live source,
    # process, namespace, listener and route predicate before handoff.
    try:
        admitted = capture.admit_endpoint_receipt(
            receipt_path=RECEIPT, unit=unit, mode=mode, boot_id=boot_id,
            netns_ino=netns_ino, installed_generation=installed_generation,
            manifest=manifest, effect_lease=effect_lease)
    except BaseException:
        retire_endpoint_receipt()
        raise
    try:
        effect_lease.verify()
        return admitted
    except BaseException:
        admitted.close()
        retire_endpoint_receipt()
        raise


def retire_endpoint_receipt() -> Path:
    """Archive the exact owned attempt; never erase failed native evidence."""
    info = RECEIPT.stat(follow_symlinks=False)
    _need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
          stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
          "endpoint_receipt_retirement_refused")
    with RECEIPT.open("rb") as stream:
        data = capture._strict_json(stream.read(16385))
    _need(data.get("schema") == "aegis_auto_capture_endpoint_v1",
          "foreign_endpoint_receipt")
    archived = RECEIPT.parent / ("auto-capture-endpoint.attempt-" +
                                 secrets.token_hex(16) + ".json")
    os.link(RECEIPT, archived, follow_symlinks=False)
    os.unlink(RECEIPT)
    return archived


def redirect_policy_sha256(admitted: capture.EndpointLease, *,
                          scoped_policy: dict | None = None,
                          scoped_verify: object = None) -> str:
    """Bind the exact live source-generated redirect policy to the held lease."""
    admitted.revalidate()
    endpoint = admitted.endpoint
    capture.need(isinstance(endpoint, capture.RedirectEndpoint),
                 "redirect_endpoint_required")
    digest, _chain, _redirect = capture._redirect_policy(
        endpoint.ingress_ifname, endpoint.listen_port,
        scoped_policy=scoped_policy, scoped_verify=scoped_verify)
    admitted.revalidate()
    return digest


def qa_relay_receipt_present() -> bool:
    """An existing QA receipt is mandatory evidence, even when malformed."""
    return (RELAY_INSTALL.exists() or RELAY_INSTALL.is_symlink() or
            RECEIPT.exists() or RECEIPT.is_symlink())


def admit_runtime_redirect_probe(effect_lease: object,
                                 runtime: RuntimeEndpointLease,
                                 topology: object) -> capture.RuntimeRedirectEndpoint:
    """Bind the real configured PREROUTING interface to the held probe actor."""
    runtime.revalidate()
    effect_lease.verify()
    children = effect_lease.facts.get("children")
    _need(effect_lease.facts.get("mode") == "REDIRECT_PROBE_TCP" and
          type(children) is list and len(children) == 1 and
          type(children[0]) is dict and
          children[0].get("action") == "serve-probe-tcp" and
          runtime.mode == "wide-redirect-safe" and
          runtime.redirect_ingress_ifname == topology.H_PROBE and
          runtime.redirect_listen_port == 15080,
          "runtime_redirect_ingress_peer_not_configured")
    child = children[0]
    _need(child.get("source") == topology.SINK_SOURCE and
          type(child.get("pid")) is int and child["pid"] > 1 and
          type(child.get("netns_ino")) is int and child["netns_ino"] > 0 and
          type(child.get("socket")) is str,
          "runtime_redirect_probe_child_invalid")
    _need(type(effect_lease.facts.get("host_probe_ifindex")) is int and
          effect_lease.facts["host_probe_ifindex"] > 0 and
          effect_lease.facts["host_probe_ifindex"] ==
          socket.if_nametoindex(topology.H_PROBE),
          "runtime_redirect_probe_fixture_changed")
    _need(os.stat(f"/proc/{child['pid']}/ns/net").st_ino ==
          child["netns_ino"],
          "runtime_redirect_probe_topology_changed")
    effect_lease.verify()
    return capture.RuntimeRedirectEndpoint(
        topology.H_PROBE, runtime.redirect_listen_port,
        Path(child["socket"]), child["pid"], child["netns_ino"])


def _stage_bytes(stage_fd: int, name: str, maximum: int) -> bytes:
    _need(name in RUNTIME_RECIPE or name in ("header.json", BUNDLE_CA_LEAF),
          "runtime_stage_leaf_unadmitted")
    current = os.dup(stage_fd)
    try:
        parts = name.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
            directory = os.fstat(current)
            _need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and
                  directory.st_mode & 0o022 == 0,
                  "runtime_stage_parent_untrusted")
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC |
                       os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        try:
            info = os.fstat(leaf)
            _need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                  stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                  0 < info.st_size <= maximum, "runtime_stage_leaf_untrusted")
            raw = os.read(leaf, maximum + 1)
            _need(len(raw) == info.st_size, "runtime_stage_leaf_changed")
            return raw
        finally:
            os.close(leaf)
    finally:
        os.close(current)


def _decode_recipe_config(encoded: object, bound: int = 4 << 20) -> bytes:
    _need(type(encoded) is str and 0 < len(encoded) <= (bound * 4 // 3) + 4,
          "runtime_recipe_config_unbounded")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise capture.CaptureRefused("runtime_recipe_config_invalid") from error
    _need(0 < len(raw) <= bound and
          base64.b64encode(raw).decode("ascii") == encoded,
          "runtime_recipe_config_noncanonical")
    return raw


@dataclasses.dataclass
class _RuntimeFile:
    path: Path
    fd: int
    identity: tuple[int, int, int, int, int, int, int]
    sha256: str

    def revalidate(self) -> None:
        capture._trusted_ancestors(self.path)
        held = os.fstat(self.fd)
        named = self.path.stat(follow_symlinks=False)
        def identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
            return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size,
                    info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
        _need(stat.S_ISREG(held.st_mode) and held.st_nlink == 1 and
              identity(held) == identity(named) == self.identity,
              "runtime_published_file_changed")
        content = os.pread(self.fd, self.identity[3], 0)
        _need(len(content) == self.identity[3] and
              hashlib.sha256(content).hexdigest() == self.sha256,
              "runtime_published_content_changed")

    def close(self) -> None:
        os.close(self.fd)


def _runtime_file(path: Path, maximum: int, uid: int, gid: int,
                  mode: int, expected: str, *,
                  semantic_config: bytes | None = None) -> _RuntimeFile:
    capture._trusted_ancestors(path)
    _need(bool(HEX64.fullmatch(expected)), "runtime_file_digest_invalid")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                 os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
              info.st_uid == uid and info.st_gid == gid and
              stat.S_IMODE(info.st_mode) == mode and
              0 < info.st_size <= maximum, "runtime_published_file_untrusted")
        observed = os.pread(fd, info.st_size, 0)
        _need(len(observed) == info.st_size, "runtime_published_content_changed")
        observed_sha = hashlib.sha256(observed).hexdigest()
        if observed_sha != expected:
            _need(semantic_config is not None, "runtime_published_content_changed")
            try:
                equal = (_toml_semantic(tomllib.loads(observed.decode("utf-8"))) ==
                         _toml_semantic(tomllib.loads(semantic_config.decode("utf-8"))))
            except (UnicodeError, ValueError) as error:
                raise capture.CaptureRefused("runtime_config_semantics_changed") from error
            _need(equal, "runtime_config_semantics_changed")
        held = _RuntimeFile(path, fd,
                            (info.st_dev, info.st_ino, info.st_mtime_ns,
                             info.st_size, info.st_uid, info.st_gid,
                             stat.S_IMODE(info.st_mode)), observed_sha)
        held.revalidate()
        return held
    except BaseException:
        os.close(fd)
        raise


def _relay_pin(address: object, name: object) -> tuple[str, str, str, str]:
    _need(type(address) is str and type(name) is str and
          0 < len(name) <= 253, "runtime_relay_settings_invalid")
    if address.startswith("["):
        host, separator, port = address[1:].partition("]:")
    else:
        host, separator, port = address.rpartition(":")
    _need(bool(separator) and port.isdecimal() and
          1 <= int(port) <= 65535, "runtime_relay_endpoint_not_numeric")
    try:
        relay_ip = ipaddress.ip_address(host)
    except ValueError as error:
        raise capture.CaptureRefused(
            "runtime_relay_endpoint_not_numeric") from error
    _need(not (relay_ip.is_unspecified or relay_ip.is_loopback or
               relay_ip.is_multicast or relay_ip.is_link_local),
          "runtime_relay_endpoint_unroutable")
    canonical = f"[{relay_ip}]:{port}" if relay_ip.version == 6 else \
                f"{relay_ip}:{port}"
    _need(address == canonical, "runtime_relay_endpoint_noncanonical")
    return (address, name, str(relay_ip),
            "-6" if relay_ip.version == 6 else "-4")


def _configured_relay_pool(relay: dict) -> tuple[tuple[str, str, str], ...]:
    """Ordered configured authority; it does not claim a selected live endpoint."""
    rows = relay.get("endpoints", [])
    _need(type(rows) is list and len(rows) <= 16,
          "runtime_relay_pool_invalid")
    if rows:
        _need(all(type(row) is dict for row in rows) and
              rows[0].get("server") == relay.get("server") and
              rows[0].get("server_name") == relay.get("server_name"),
              "runtime_relay_pool_primary_changed")
    else:
        rows = [relay]
    tcp_plan = relay.get("transport_priority",
                         ["https_ws", "grpc_stream", "masque_derived"])
    udp_plan = relay.get("udp_transport_priority")
    _need(type(tcp_plan) is list and
          (udp_plan is None or type(udp_plan) is list),
          "runtime_relay_transport_plan_invalid")
    masque_enabled = ("masque_derived" in tcp_plan or
                      "masque_derived" in (udp_plan or []))
    authority = []
    for row in rows:
        ordinary = _relay_pin(row.get("server"), row.get("server_name"))
        authority.append(("ordinary", ordinary[0], ordinary[1]))
        # Mirror relay_settings_for_endpoint and masque_transport_authority:
        # an endpoint-specific direct dial does not inherit a global TLS name.
        # A shared global direct dial does inherit its global TLS authority.
        if row.get("masque_server") is not None:
            masque_address = row["masque_server"]
            masque_name = row.get("masque_server_name")
            masque_name = masque_name if type(masque_name) is str and \
                masque_name.strip() else ordinary[1]
        elif relay.get("masque_server") is not None:
            masque_address = relay["masque_server"]
            masque_name = relay.get("masque_server_name")
            masque_name = masque_name if type(masque_name) is str and \
                masque_name.strip() else relay["server_name"]
        else:
            masque_address = ordinary[0]
            masque_name = relay.get("masque_server_name")
            masque_name = masque_name if type(masque_name) is str and \
                masque_name.strip() else ordinary[1]
        if masque_enabled:
            masque = _relay_pin(masque_address, masque_name)
            authority.append(("masque", masque[0], masque[1]))
    return tuple(authority)


def _host_route(family: str, host: str, timeout: float) -> dict:
    """The guardian is in the host netns; no nsenter capability is needed."""
    rows = json.loads(capture._run(
        [str(capture.IP), "-j", family, "route", "get", host],
        timeout=timeout))
    _need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
          "runtime_relay_route_ambiguous")
    return rows[0]


def _toml_semantic(value: object) -> object:
    """Canonical typed TOML value; formatting may change at projection."""
    if type(value) is dict:
        return ["table", [[key, _toml_semantic(value[key])]
                          for key in sorted(value)]]
    if type(value) is list:
        return ["array", [_toml_semantic(item) for item in value]]
    if type(value) is str:
        return ["string", value]
    if type(value) is bool:
        return ["bool", value]
    if type(value) is int:
        return ["integer", str(value)]
    if type(value) is float:
        return ["float", (0.0 if value == 0.0 else value).hex()]
    if isinstance(value, datetime.datetime):
        return ["datetime", value.isoformat()]
    if isinstance(value, datetime.date):
        return ["date", value.isoformat()]
    if isinstance(value, datetime.time):
        return ["time", value.isoformat()]
    raise capture.CaptureRefused("runtime_relay_semantics_invalid")


def _credential_lineage(relay: dict,
                        credentials: tuple[_RuntimeFile, ...]) -> str:
    # Never serialize this material into a receipt: it contains auth_token.
    semantic = ["relay", _toml_semantic(relay),
                "files", [[str(item.path), item.sha256]
                          for item in credentials]]
    return hashlib.sha256(json.dumps(
        semantic, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


@dataclasses.dataclass
class RuntimeEndpointLease:
    """Held stage-rendered ordered relay authority, scoped to tunnel roundtrip."""
    stage_fd: int
    config: _RuntimeFile
    credentials: tuple[_RuntimeFile, ...]
    unit: str
    mode: str
    transaction_nonce: str
    planned_generation: str
    configured_relay_pool: tuple[tuple[str, str, str], ...]
    configured_relay_pool_sha256: str
    auth_profile: str
    config_sha256: str
    credential_lineage_sha256: str
    redirect_ingress_ifname: str | None = None
    redirect_listen_port: int | None = None
    redirect_rollout_profile: str | None = None
    closed: bool = False

    def __enter__(self) -> RuntimeEndpointLease:
        try:
            self.revalidate()
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, _kind: object, _value: object,
                 _traceback: object) -> None:
        self.close()

    def revalidate(self) -> None:
        _need(not self.closed, "runtime_endpoint_lease_closed")
        stage = os.fstat(self.stage_fd)
        _need(stat.S_ISDIR(stage.st_mode) and stage.st_uid == 0 and
              stage.st_mode & 0o022 == 0, "runtime_stage_changed")
        header = capture._strict_json(_stage_bytes(self.stage_fd, "header.json",
                                                    1 << 20))
        _need(header.get("transaction_nonce") == self.transaction_nonce and
              header.get("planned_generation") == self.planned_generation and
              header.get("mode") == self.mode,
              "runtime_stage_binding_changed")
        recipe_name = header.get("render_recipe")
        _need(type(recipe_name) is str and recipe_name in RUNTIME_RECIPE and
              type(header.get("leaves")) is dict,
              "runtime_recipe_header_invalid")
        recipe_raw = _stage_bytes(self.stage_fd, recipe_name, 96 << 20)
        _need(header["leaves"].get(recipe_name) ==
              hashlib.sha256(recipe_raw).hexdigest(),
              "runtime_recipe_seal_changed")
        recipe = capture._strict_json(recipe_raw)
        config_bytes = _decode_recipe_config(recipe.get("config"))
        _need(recipe.get("schema") == 2 and
              recipe.get("context", {}).get("logical_final_base") ==
              header.get("config_root") and
              recipe.get("context", {}).get("mode") == RENDER_MODES[self.mode] and
              hashlib.sha256(config_bytes).hexdigest() == self.config_sha256,
              "runtime_recipe_binding_changed")
        self.config.revalidate()
        for credential in self.credentials:
            credential.revalidate()
        _need(self.configured_relay_pool_sha256 == hashlib.sha256(
            json.dumps(self.configured_relay_pool,
                       separators=(",", ":")).encode()).hexdigest(),
            "runtime_relay_pool_changed")
        deadline = time.monotonic() + 3.0
        routed: set[str] = set()
        for _kind, address, _name in self.configured_relay_pool:
            if address in routed:
                continue
            routed.add(address)
            pin = _relay_pin(address, _name)
            remaining = deadline - time.monotonic()
            _need(remaining > 0, "runtime_relay_route_timeout")
            route = _host_route(pin[3], pin[2], min(1.0, remaining))
            _need(route.get("dev") not in (None, "lo", capture.TUN) and
                  route.get("type") not in ("unreachable", "blackhole", "prohibit"),
                  "runtime_relay_route_invalid")

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        os.close(self.stage_fd)
        self.config.close()
        for credential in self.credentials:
            credential.close()


def _admit_rendered_config(borrowed: int, mode: str, transaction_nonce: str,
                           planned_generation: str
                           ) -> tuple[dict, dict, bytes, _RuntimeFile, tuple[int, int]]:
    """Read the same Header-sealed config before and after Main starts."""
    header = capture._strict_json(_stage_bytes(borrowed, "header.json", 1 << 20))
    recipe_name = header.get("render_recipe")
    _need(type(recipe_name) is str and recipe_name in RUNTIME_RECIPE and
          type(header.get("leaves")) is dict and
          header.get("transaction_nonce") == transaction_nonce and
          header.get("planned_generation") == planned_generation and
          header.get("mode") == mode,
          "runtime_endpoint_stage_unbound")
    recipe_raw = _stage_bytes(borrowed, recipe_name, 96 << 20)
    _need(header["leaves"].get(recipe_name) ==
          hashlib.sha256(recipe_raw).hexdigest(),
          "runtime_endpoint_recipe_unsealed")
    recipe = capture._strict_json(recipe_raw)
    config_bytes = _decode_recipe_config(recipe.get("config"))
    config_root = header.get("config_root")
    config_leaf = recipe.get("config_leaf")
    context = recipe.get("context")
    _need(recipe.get("schema") == 2 and type(context) is dict and
          context.get("logical_final_base") == config_root and
          context.get("mode") == RENDER_MODES[mode] and
          type(config_root) is str and
          Path(config_root).is_absolute() and
          type(config_leaf) is str and config_leaf and
          not Path(config_leaf).is_absolute() and
          all(part not in ("", ".", "..") for part in
              Path(config_leaf).parts), "runtime_endpoint_recipe_invalid")
    binding = header.get("runtime_binding")
    identity = binding.get("identity") if type(binding) is dict else None
    _need(type(identity) is dict and
          type(identity.get("uid")) is int and
          type(identity.get("gid")) is int,
          "runtime_endpoint_identity_invalid")
    uid, gid = identity["uid"], identity["gid"]
    config_path = Path(config_root) / config_leaf
    # Finalize preflights the entire projection before asking capture to
    # revalidate. Only this owned, nonpending Metadata interval can contain a
    # formatter's byte changes; all TOML values and held file identity remain
    # exact. Finalized and pre-capture admission retain the raw-byte seal.
    semantic_config = (config_bytes if
        header.get("phase") == "metadata" and
        header.get("capture_started") is True and
        header.get("pending") is None and
        header.get("unit_pending") is None else None)
    config = _runtime_file(config_path, 4 << 20, 0, gid,
                           0o600 if uid == 0 else 0o640,
                           hashlib.sha256(config_bytes).hexdigest(),
                           semantic_config=semantic_config)
    return header, recipe, config_bytes, config, (uid, gid)


def _scoped_redirect_values(recipe: dict, config_bytes: bytes) -> tuple | None:
    settings = tomllib.loads(config_bytes.decode("utf-8"))
    ingress = settings.get("ingress")
    wide = ingress.get("wide") if type(ingress) is dict else None
    _need(type(wide) is dict and ingress.get("primary") == "wide" and
          wide.get("enabled") is True and
          wide.get("platform_backend") == "linux_redirect",
          "scoped_redirect_mode_invalid")
    profile = wide.get("rollout_profile", "output_only_safe")
    if profile == "output_only_safe":
        _need(wide.get("listen") == "127.0.0.1:15080",
              "local_redirect_listener_changed")
        return None
    interface = wide.get("prerouting_interface")
    listen = wide.get("listen")
    _need(profile == "prerouting_scoped" and
          type(interface) is str and
          re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", interface) is not None and
          interface not in ("lo", capture.TUN) and
          recipe["context"].get("wide_interface") == interface and
          type(listen) is str,
          "scoped_redirect_interface_unsealed")
    host, separator, port = listen.rpartition(":")
    _need(separator == ":" and port == "15080",
          "scoped_redirect_listener_invalid")
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError as error:
        raise capture.CaptureRefused("scoped_redirect_listener_invalid") from error
    _need(str(address) == host and not (address.is_unspecified or
          address.is_loopback or address.is_multicast or address.is_link_local or
          str(address) == "255.255.255.255"),
          "scoped_redirect_listener_invalid")
    ifindex = socket.if_nametoindex(interface)
    _need(type(ifindex) is int and ifindex > 0,
          "scoped_redirect_interface_unavailable")
    rows = capture._json([str(capture.IP), "-j", "-4", "address", "show", "dev", interface])
    _need(len(rows) == 1 and rows[0].get("ifname") == interface and
          rows[0].get("ifindex") == ifindex and
          type(rows[0].get("addr_info")) is list and
          [item.get("local") for item in rows[0]["addr_info"] if
           type(item) is dict and item.get("family") == "inet" and
           item.get("secondary", False) is False] == [host],
          "scoped_redirect_primary_address_changed")
    semantic = hashlib.sha256(json.dumps(_toml_semantic(settings),
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return interface, ifindex, host, 15080, semantic


def _local_redirect_values(recipe: dict, config_bytes: bytes) -> tuple:
    """Admit the sealed local OUTPUT listener and required DNS preview."""
    settings = tomllib.loads(config_bytes.decode("utf-8"))
    ingress = settings.get("ingress")
    wide = ingress.get("wide") if type(ingress) is dict else None
    _need(type(wide) is dict and ingress.get("primary") == "wide" and
          wide.get("enabled") is True and
          wide.get("platform_backend") == "linux_redirect" and
          wide.get("rollout_profile", "output_only_safe") == "output_only_safe" and
          wide.get("listen") == "127.0.0.1:15080" and
          wide.get("dns_preview_listen") == "127.0.0.1:53" and
          wide.get("dns_preview_fake_ip_pool") == "198.18.0.0/15" and
          wide.get("dns_preview_fake_ip_ttl_secs") == 60 and
          wide.get("udp_capture_contract") == "preview_allowlist_only" and
          recipe.get("context", {}).get("mode") == "WideRedirectSafe",
          "local_redirect_config_invalid")
    semantic = hashlib.sha256(json.dumps(_toml_semantic(settings),
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return "127.0.0.1", 15080, 53, semantic


def _local_fulltun_values(recipe: dict, config_bytes: bytes) -> tuple:
    """Accept only the source-rendered FullTun IPv4 listeners."""
    settings = tomllib.loads(config_bytes.decode("utf-8"))
    ingress = settings.get("ingress")
    wide = ingress.get("wide") if type(ingress) is dict else None
    _need(type(wide) is dict and ingress.get("primary") == "wide" and
          wide.get("enabled") is True and
          wide.get("platform_backend") == "linux_redirect" and
          wide.get("listen") == "127.0.0.1:980" and
          wide.get("ipv6_tun_carried") is True and
          wide.get("capture_dns") is True and
          wide.get("dns_preview_listen") == "127.0.0.1:53" and
          wide.get("dns_preview_fake_ip_pool", "198.18.0.0/15") ==
          "198.18.0.0/15" and
          wide.get("dns_preview_fake_ip_ttl_secs", 60) == 60 and
          wide.get("udp_capture_contract") == "generic_capture_unstable" and
          recipe.get("context", {}).get("mode") == "FullWideTun",
          "local_fulltun_config_invalid")
    udp_port = wide.get("udp_redirect_port", 981)
    _need(type(udp_port) is int and 1 <= udp_port <= 65535 and
          udp_port not in (53, 980), "local_fulltun_udp_port_invalid")
    semantic = hashlib.sha256(json.dumps(_toml_semantic(settings),
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return "127.0.0.1", 980, 53, udp_port, semantic


@dataclasses.dataclass
class FullTunLocalConfigLease:
    stage_fd: int
    config: _RuntimeFile
    transaction_nonce: str
    planned_generation: str
    config_sha256: str
    listen_ipv4: str
    listen_port: int
    dns_port: int
    udp_port: int
    config_semantic_sha256: str
    closed: bool = False

    def revalidate(self) -> None:
        _need(not self.closed, "local_fulltun_config_closed")
        self.config.revalidate()
        _header, recipe, raw, fresh, _identity = _admit_rendered_config(
            self.stage_fd, "full-wide-tun", self.transaction_nonce,
            self.planned_generation)
        try:
            _need(hashlib.sha256(raw).hexdigest() == self.config_sha256 and
                  _local_fulltun_values(recipe, raw) ==
                  (self.listen_ipv4, self.listen_port, self.dns_port,
                   self.udp_port, self.config_semantic_sha256),
                  "local_fulltun_config_changed")
        finally:
            _close_scoped_parts(fresh, None)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            _close_scoped_parts(self.config, self.stage_fd)


def admit_local_fulltun_config(*, stage_fd: int, transaction_nonce: str,
                               planned_generation: str) -> FullTunLocalConfigLease:
    borrowed = os.dup(stage_fd)
    config = None
    retained = False
    try:
        _header, recipe, raw, config, _identity = _admit_rendered_config(
            borrowed, "full-wide-tun", transaction_nonce,
            planned_generation)
        values = _local_fulltun_values(recipe, raw)
        lease = FullTunLocalConfigLease(
            borrowed, config, transaction_nonce, planned_generation,
            hashlib.sha256(raw).hexdigest(), *values)
        retained = True
        return lease
    finally:
        if not retained:
            _close_scoped_parts(config, borrowed)


@dataclasses.dataclass
class LocalRedirectConfigLease:
    """Held local OUTPUT facts from the exact Header-sealed render recipe."""
    stage_fd: int
    config: _RuntimeFile
    private_unit: str
    transaction_nonce: str
    planned_generation: str
    config_sha256: str
    listen_ipv4: str
    listen_port: int
    dns_port: int
    config_semantic_sha256: str
    closed: bool = False

    def revalidate(self) -> None:
        _need(not self.closed, "local_redirect_config_closed")
        self.config.revalidate()
        _header, recipe, raw, fresh, _identity = _admit_rendered_config(
            self.stage_fd, "wide-redirect-safe", self.transaction_nonce,
            self.planned_generation)
        try:
            _need(hashlib.sha256(raw).hexdigest() == self.config_sha256 and
                  _local_redirect_values(recipe, raw) ==
                  (self.listen_ipv4, self.listen_port, self.dns_port,
                   self.config_semantic_sha256),
                  "local_redirect_config_changed")
        finally:
            _close_scoped_parts(fresh, None)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            _close_scoped_parts(self.config, self.stage_fd)


def admit_local_redirect_config(*, stage_fd: int, transaction_nonce: str,
                                planned_generation: str, private_unit: str
                                ) -> LocalRedirectConfigLease | None:
    _need(type(private_unit) is str and
          capture.PRIVATE_UNIT.fullmatch(private_unit) is not None,
          "local_redirect_unit_invalid")
    borrowed = os.dup(stage_fd)
    config = None
    retained = False
    try:
        _header, recipe, raw, config, _identity = _admit_rendered_config(
            borrowed, "wide-redirect-safe", transaction_nonce,
            planned_generation)
        if _scoped_redirect_values(recipe, raw) is not None:
            return None
        values = _local_redirect_values(recipe, raw)
        lease = LocalRedirectConfigLease(
            borrowed, config, private_unit, transaction_nonce,
            planned_generation, hashlib.sha256(raw).hexdigest(), *values)
        retained = True
        return lease
    finally:
        if not retained:
            _close_scoped_parts(config, borrowed)


@dataclasses.dataclass
class ScopedRedirectConfigLease:
    """Sealed config facts; callers still require the actual guardian owner."""
    stage_fd: int
    config: _RuntimeFile
    private_unit: str
    transaction_nonce: str
    planned_generation: str
    config_sha256: str
    interface: str
    ifindex: int
    listen_ipv4: str
    listen_port: int
    config_semantic_sha256: str
    rollout_profile: str = "prerouting_scoped"
    closed: bool = False

    def revalidate(self) -> None:
        _need(not self.closed, "scoped_redirect_config_closed")
        self.config.revalidate()
        _header, recipe, raw, fresh, _identity = _admit_rendered_config(
            self.stage_fd, "wide-redirect-safe", self.transaction_nonce,
            self.planned_generation)
        try:
            _need(hashlib.sha256(raw).hexdigest() == self.config_sha256 and
                  _scoped_redirect_values(recipe, raw) ==
                  (self.interface, self.ifindex, self.listen_ipv4,
                   self.listen_port, self.config_semantic_sha256),
                  "scoped_redirect_config_changed")
        finally:
            _close_scoped_parts(fresh, None)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        _close_scoped_parts(self.config, self.stage_fd)


def _close_scoped_parts(config: _RuntimeFile | None, stage_fd: int | None) -> None:
    primary = sys.exc_info()[1]
    first = None
    for operation in ((config.close,) if config is not None else ()) + \
            ((lambda: os.close(stage_fd),) if stage_fd is not None else ()):
        try:
            operation()
        except Exception as error:
            print("aegis_auto_endpoint_cleanup_refused", file=sys.stderr, flush=True)
            if first is None:
                first = error
    if primary is None and first is not None:
        raise first


def admit_scoped_redirect_config(*, stage_fd: int, transaction_nonce: str,
                                 planned_generation: str, private_unit: str
                                 ) -> ScopedRedirectConfigLease | None:
    """Admit explicit scoped REDIRECT before Main; local defaults stay local."""
    _need(type(private_unit) is str and
          capture.PRIVATE_UNIT.fullmatch(private_unit) is not None,
          "scoped_redirect_unit_invalid")
    borrowed = os.dup(stage_fd)
    config = None
    retained = False
    try:
        _header, recipe, raw, config, _identity = _admit_rendered_config(
            borrowed, "wide-redirect-safe", transaction_nonce, planned_generation)
        values = _scoped_redirect_values(recipe, raw)
        if values is None:
            return None
        lease = ScopedRedirectConfigLease(
            borrowed, config, private_unit, transaction_nonce, planned_generation,
            hashlib.sha256(raw).hexdigest(), *values[:4], values[4])
        retained = True
        return lease
    finally:
        if not retained:
            _close_scoped_parts(config, borrowed)


def _runtime_credential_path(value: object, config_root: str) -> str:
    """Resolve only canonical renderer paths against the sealed final base."""
    _need(type(config_root) is str and config_root.startswith("/") and
          all(part not in ("", ".", "..") for part in config_root.split("/")[1:]) and
          str(Path(config_root)) == config_root,
          "runtime_credential_not_sealed")
    _need(type(value) is str and 0 < len(value) <= 4096 and "\0" not in value,
          "runtime_credential_not_sealed")
    path = Path(value)
    parts = value.split("/")[1:] if path.is_absolute() else value.split("/")
    _need(all(part not in ("", ".", "..") for part in parts) and
          str(path) == value, "runtime_credential_not_sealed")
    if not path.is_absolute():
        root = Path(config_root)
        path = root / path
        _need(path.is_relative_to(root), "runtime_credential_not_sealed")
    return str(path)


def admit_runtime_endpoint(*, stage_fd: int, unit: str, mode: str,
                           transaction_nonce: str,
                           planned_generation: str) -> RuntimeEndpointLease:
    """Derive the relay exclusively from the held, Header-sealed render recipe."""
    _need(bool(capture.PRIVATE_UNIT.fullmatch(unit)) and
          mode in ("full-wide-tun", "wide-redirect-safe"),
          "runtime_endpoint_owner_invalid")
    borrowed = os.dup(stage_fd)
    files: list[_RuntimeFile] = []
    try:
        header, recipe, config_bytes, config, (uid, gid) = _admit_rendered_config(
            borrowed, mode, transaction_nonce, planned_generation)
        files.append(config)
        config_root = header["config_root"]
        settings = tomllib.loads(config_bytes.decode("utf-8"))
        relay = settings.get("relay")
        _need(type(relay) is dict and type(relay.get("server")) is str and
              type(relay.get("server_name")) is str and
              0 < len(relay["server_name"]) <= 253,
              "runtime_relay_settings_invalid")
        pool = _configured_relay_pool(relay)
        pool_sha = hashlib.sha256(json.dumps(
            pool, separators=(",", ":")).encode()).hexdigest()
        profile = "device_inner_tls" if relay.get("inner_tls") is not None else \
                  "legacy_shared_token"
        redirect_iface = redirect_port = redirect_profile = None
        if mode == "wide-redirect-safe":
            ingress = settings.get("ingress")
            wide = ingress.get("wide") if type(ingress) is dict else None
            _need(type(wide) is dict and
                  type(wide.get("listen", "127.0.0.1:15080")) is str,
                  "runtime_redirect_config_invalid")
            redirect_profile = wide.get("rollout_profile", "output_only_safe")
            if redirect_profile == "prerouting_scoped":
                _need(type(wide.get("prerouting_interface")) is str and
                      _scoped_redirect_values(recipe, config_bytes) is not None,
                      "runtime_redirect_scoped_invalid")
                redirect_iface = wide["prerouting_interface"]
            else:
                _need(redirect_profile == "output_only_safe", "runtime_redirect_profile_invalid")
                _local_redirect_values(recipe, config_bytes)
            listen = wide.get("listen", "127.0.0.1:15080")
            _host, separator, port = listen.rpartition(":")
            _need(bool(separator) and port.isdecimal() and
                  1024 <= int(port) <= 65535,
                  "runtime_redirect_listen_invalid")
            redirect_port = int(port)
        if profile == "legacy_shared_token":
            _need(type(relay.get("auth_token")) is str and
                  len(relay["auth_token"]) >= 32,
                  "runtime_legacy_auth_missing")
        else:
            _need(type(relay.get("inner_tls")) is dict,
                  "runtime_inner_tls_invalid")
        reference_rows = recipe.get("references")
        _need(type(reference_rows) is list and len(reference_rows) <= 1024,
              "runtime_references_invalid")
        references: dict[str, str] = {}
        for row in reference_rows:
            _need(type(row) is dict and
                  set(row) == {"original", "final_path", "bytes"} and
                  type(row["final_path"]) is str and
                  type(row["bytes"]) is str and
                  len(row["bytes"]) <= ((16 << 20) * 4 // 3) + 4 and
                  row["final_path"] not in references,
                  "runtime_reference_schema_invalid")
            references[row["final_path"]] = row["bytes"]
        chosen: list[tuple[str, bool]] = []
        if relay.get("ca_cert") is not None:
            chosen.append((relay["ca_cert"], False))
        if relay.get("masque_ca_cert") is not None:
            chosen.append((relay["masque_ca_cert"], False))
        if relay.get("ech_config_list") is not None:
            chosen.append((relay["ech_config_list"], False))
        if profile == "device_inner_tls":
            inner = relay["inner_tls"]
            for name, private in (("server_ca", False), ("cert", False),
                                  ("key", True)):
                chosen.append((inner.get(name), private))
        bridge = relay.get("https_bridge")
        if bridge is not None:
            _need(type(bridge) is dict and
                  type(bridge.get("credential_file")) is str,
                  "runtime_bridge_credential_invalid")
            chosen.append((bridge["credential_file"], True))
        seen_credential_paths: dict[str, tuple[str, bool]] = {}
        for path_text, private in chosen:
            effective = _runtime_credential_path(path_text, config_root)
            if effective in seen_credential_paths:
                _need(seen_credential_paths[effective] == (path_text, private),
                      "runtime_credential_not_sealed")
                continue
            seen_credential_paths[effective] = (path_text, private)
            path_text = effective
            if path_text in references:
                reference_bytes = _decode_recipe_config(
                    references[path_text], 16 << 20)
            else:
                _need(not private and
                      path_text == str(Path(config_root) / "ca.pem") and
                      type(header["leaves"].get(BUNDLE_CA_LEAF)) is str,
                      "runtime_credential_not_sealed")
                reference_bytes = _stage_bytes(borrowed, BUNDLE_CA_LEAF,
                                               16 << 20)
                _need(hashlib.sha256(reference_bytes).hexdigest() ==
                      header["leaves"][BUNDLE_CA_LEAF],
                      "runtime_bundle_ca_seal_changed")
            credential = _runtime_file(
                Path(path_text), 16 << 20,
                uid if private else 0, gid,
                0o600 if private or uid == 0 else 0o640,
                hashlib.sha256(reference_bytes).hexdigest())
            files.append(credential)
        lineage = _credential_lineage(relay, tuple(files[1:]))
        lease = RuntimeEndpointLease(borrowed, config, tuple(files[1:]), unit,
                                     mode, transaction_nonce, planned_generation,
                                     pool, pool_sha, profile,
                                     hashlib.sha256(config_bytes).hexdigest(),
                                     lineage, redirect_iface, redirect_port,
                                     redirect_profile)
        lease.revalidate()
        return lease
    except BaseException:
        os.close(borrowed)
        for held in files:
            held.close()
        raise
