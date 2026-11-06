#!/usr/bin/env python3
"""Bounded native DROP witness for an installed AUTO guardian.

The caller owns the guard-policy flock and an independent rollback lease.  A
trace-only nft table is temporary; it never contains an ACCEPT verdict.  A
separate sink process in a different network namespace must be ready before
the challenge and attest that it received no challenged datagram.  This
module returns a *witness*, not an activation ACK or capture grant.
"""
from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import json
import os
import re
import selectors
import socket
import stat
import struct
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

TRACE_TABLE = "aegis_auto_witness"
GUARD_TABLE = "aegis_device_guard"
MAX_READBACK = 1 << 20
MAX_TRACE = 1 << 20
COMMAND_SECONDS = 3.0
TRACE_SECONDS = 3.0
CALIBRATION_ATTEMPTS = 5
TRACE_FAILURE_RUNTIME = Path("/run/aegis-auto-topology")


class NativeWitnessRefused(RuntimeError):
    """Typed fail-closed result; never an activation acknowledgement."""


def _need(ok: bool, reason: str) -> None:
    if not ok:
        raise NativeWitnessRefused(reason)


@dataclass(frozen=True)
class Challenge:
    egress_interface: str
    peer_ipv4: str
    source_port: int
    sink_port: int
    nonce: bytes

    def validate(self) -> None:
        _need(bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", self.egress_interface)),
              "invalid challenged interface")
        try:
            socket.inet_pton(socket.AF_INET6 if ':' in self.peer_ipv4 else socket.AF_INET, self.peer_ipv4)
        except OSError as error:
            raise NativeWitnessRefused("invalid challenged peer IPv4") from error
        _need(all(type(p) is int and 1024 <= p <= 65535 for p in
                  (self.source_port, self.sink_port)) and
              self.source_port != self.sink_port, "invalid challenged ports")
        _need(type(self.nonce) is bytes and 16 <= len(self.nonce) <= 64,
              "invalid challenged nonce")


@dataclass(frozen=True)
class PositiveSinkControl:
    """Live sink session proven by one L2 UDP arrival under the installed guard."""

    baseline_sha256: str
    session: str
    sink_pid: int
    sink_netns_ino: int
    sender_netns_ino: int
    sink_port: int
    egress_interface: str
    peer_ipv4: str
    source_port: int
    source_ipv4: str
    source_mac: str
    peer_mac: str
    ifindex: int
    method: str
    observed_at: float


class RollbackLease(Protocol):
    """Installed independent process that removes TRACE_TABLE on owner death.

    `arm` must synchronously establish rollback before nft mutation; `live`
    must check that same process/lease, and `disarm` follows verified teardown.
    A caller-supplied no-op object is not an installed rollback authority.
    """

    def arm(self, *, table: str, netns_ino: int) -> None: ...
    def live(self) -> bool: ...
    def disarm(self) -> None: ...


@dataclass(frozen=True)
class DenyWitness:
    schema: str
    guard_policy_sha256: str
    guard_before_sha256: str
    guard_after_sha256: str
    guard_drop_handle: int
    guard_output_drop_delta: int
    sender_netns_ino: int
    trace_id: str
    trace_sha256: str
    baseline_sha256: str
    baseline_received: int
    baseline_method: str
    baseline_egress_interface: str
    baseline_peer_ipv4: str
    baseline_source_port: int
    baseline_source_ipv4: str
    baseline_source_mac: str
    baseline_peer_mac: str
    baseline_ifindex: int
    challenge_sha256: str
    sink_pid: int
    sink_netns_ino: int
    sink_session: str
    sink_received: int
    trace_table_removed: bool
    send_errno: int | None
    ack: bool = True
    address_family: int = 4
    foreign_policy_class: str = ""
    foreign_policy_backend: str = ""
    foreign_projection_sha256: str = ""
    foreign_mid_sha256: str = ""


@dataclass(frozen=True)
class DualDenyWitness:
    """One merged lease: per-family witnesses plus the shared window facts."""

    ipv4: DenyWitness
    ipv6: DenyWitness
    schema: str
    trace_batch_sha256: str
    combined_trace_sha256: str
    unattributed_trace_sha256: str
    foreign_before_sha256: str
    foreign_mid_sha256: str
    foreign_after_sha256: str
    ipv4_dwell_seconds: float
    ipv6_dwell_seconds: float


def _unique(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        _need(key not in value, "duplicate native JSON key")
        value[key] = item
    return value


def _json(raw: bytes) -> object:
    _need(0 < len(raw) <= MAX_READBACK, "empty or oversized native JSON")
    try:
        return json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as error:
        raise NativeWitnessRefused("invalid native JSON") from error


def policy_projection(raw: bytes) -> tuple[bytes, dict[str, int], dict[str, int]]:
    """Return exact full guard projection, terminal handles and packet counts.

    Accept expressions remain byte-for-byte represented in canonical JSON.
    Only changing kernel handles and counter values are excluded from the
    policy bytes. The installed guard helper must protect SHA-256 of these
    bytes independently; deriving the expected digest from this readback is
    never sufficient to admit a native witness.
    """
    value = _json(raw)
    _need(type(value) is dict and set(value) == {"nftables"} and
          type(value["nftables"]) is list, "invalid guard readback")
    records = []
    table_count = 0
    chains = {}
    drops = {}
    last = {}
    all_handles = set()
    for item in value["nftables"]:
        _need(type(item) is dict and len(item) == 1, "invalid guard item")
        kind, body = next(iter(item.items()))
        if kind == "metainfo":
            continue
        _need(kind in ("table", "chain", "rule") and type(body) is dict,
              "unexpected guard item")
        clone = dict(body)
        handle = clone.pop("handle", None)
        if kind == "rule":
            _need(type(handle) is int and handle > 0 and handle not in all_handles,
                  "invalid guard rule handle")
            all_handles.add(handle)
            _need(body.get("family") == "inet" and body.get("table") == GUARD_TABLE and
                  body.get("chain") in ("incoming", "output", "forward", "postroute"),
                  "foreign rule in guard readback")
            expr = body.get("expr")
            _need(type(expr) is list, "invalid guard expressions")
            normalized = []
            for expression in expr:
                _need(type(expression) is dict and len(expression) == 1,
                      "invalid guard expression")
                if "counter" not in expression:
                    normalized.append(expression)
                    continue
                c = expression["counter"]
                _need(type(c) is dict and set(c) == {"packets", "bytes"} and
                      all(type(c[k]) is int and c[k] >= 0 for k in c),
                      "invalid guard counter")
                normalized.append({"counter": {"packets": 0, "bytes": 0}})
            clone["expr"] = normalized
            last[body["chain"]] = body
            if (body["chain"] in ("output", "forward", "postroute") and len(expr) == 2 and
                    expr[1] == {"drop": None} and
                    type(expr[0]) is dict and set(expr[0]) == {"counter"}):
                _need(body["chain"] not in drops, "duplicate terminal DROP")
                drops[body["chain"]] = (handle, expr[0]["counter"]["packets"])
        elif kind == "chain":
            name = body.get("name")
            _need(name not in chains, "duplicate guard chain")
            chains[name] = body
        elif kind == "table":
            table_count += 1
            _need(body.get("family") == "inet" and
                  body.get("name") == GUARD_TABLE,
                  "foreign table in guard readback")
        records.append({kind: clone})
    _need(table_count == 1 and len(records) >= 5 and
          "table" in records[0], "wrong guard table")
    _need(set(chains) == {"incoming", "output", "forward", "postroute"}, "missing guard chain")
    for name, hook, priority, policy in (("incoming", "prerouting", -190, "accept"),
                                         ("output", "output", 2147483647, "drop"),
                                         ("forward", "forward", 10, "drop"),
                                         ("postroute", "postrouting", 2147483647, "drop")):
        chain = chains[name]
        _need(all(chain.get(key) == wanted for key, wanted in
                  (("family", "inet"), ("table", GUARD_TABLE), ("hook", hook),
                   ("prio", priority), ("policy", policy))), "guard chain changed")
    _need(set(drops) == {"output", "forward", "postroute"} and
          all(last.get(name, {}).get("handle") == drops[name][0]
              for name in ("output", "forward", "postroute")),
          "persistent DROP is not terminal")
    projection = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return projection, {name: value[0] for name, value in drops.items()}, \
        {name: value[1] for name, value in drops.items()}


def _guard_projection(raw: bytes) -> tuple[str, int, int]:
    projection, handles, counts = policy_projection(raw)
    return hashlib.sha256(projection).hexdigest(), handles["output"], counts["output"]


def _pin_nft(path: Path) -> int:
    _need(path == Path("/usr/sbin/nft"),
          "nft executable must be installed /usr/sbin/nft")
    parent = path.parent.lstat()
    _need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
          parent.st_mode & 0o022 == 0, "untrusted nft directory")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        actual, named = os.fstat(fd), path.lstat()
        _need(stat.S_ISREG(actual.st_mode) and actual.st_uid == 0 and
              actual.st_mode & 0o022 == 0 and actual.st_mode & 0o111 and
              actual.st_nlink == 1 and
              (actual.st_dev, actual.st_ino) == (named.st_dev, named.st_ino),
              "untrusted nft executable")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _command(fd: int, args: list[str], *, input_data: bytes | None = None,
             deadline: float | None = None) -> bytes:
    _need(input_data is None or len(input_data) <= 4096,
          "oversized nft command input")
    if deadline is not None:
        _need(type(deadline) in (int, float) and deadline > time.monotonic(),
              "nft operation deadline elapsed")
    proc = subprocess.Popen(["/usr/sbin/nft", *args], executable=f"/proc/self/fd/{fd}",
                            pass_fds=(fd,), stdin=subprocess.PIPE if input_data is not None else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                            env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
    output = bytearray()
    errors = bytearray()
    selector = selectors.DefaultSelector()
    try:
        if input_data is not None:
            proc.stdin.write(input_data)
            proc.stdin.close()
        selector.register(proc.stdout, selectors.EVENT_READ, output)
        selector.register(proc.stderr, selectors.EVENT_READ, errors)
        command_deadline = time.monotonic() + COMMAND_SECONDS
        if deadline is not None:
            _need(type(deadline) in (int, float) and deadline > time.monotonic(),
                  "nft operation deadline elapsed")
            command_deadline = min(command_deadline, deadline)
        while selector.get_map():
            remaining = command_deadline - time.monotonic()
            _need(remaining > 0, "nft command timed out")
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                key.data.extend(chunk)
                _need(len(output) <= MAX_READBACK and len(errors) <= 4096,
                      "nft command output exceeded bound")
        _need(command_deadline > time.monotonic(), "nft command timed out")
        _need(proc.wait(timeout=max(0.001, command_deadline - time.monotonic())) == 0 and
              command_deadline > time.monotonic(),
              "nft command failed")
        return bytes(output)
    except BaseException:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=2)
        raise
    finally:
        selector.close()
        proc.stdout.close()
        proc.stderr.close()


def snapshot_policy(nft_path: Path) -> tuple[bytes, dict[str, int], dict[str, int]]:
    """Read and parse the full installed guard table through a pinned nft FD."""
    _need(os.name == "posix" and Path("/proc/self/ns/net").exists() and
          os.geteuid() == 0, "Linux root required for guard snapshot")
    fd = _pin_nft(nft_path)
    try:
        return policy_projection(_command(
            fd, ["--json", "--handle", "list", "table", "inet", GUARD_TABLE]))
    finally:
        os.close(fd)


def read_policy_raw(nft_path: Path, *, text: bool = False,
                    deadline: float | None = None) -> bytes:
    """Bounded JSON or handle-bearing text readback through a pinned nft FD.

    Callers needing a coherent semantic seal read JSON/text/JSON while their
    original guard flock is held and compare both JSON projections.
    """
    _need(os.name == "posix" and Path("/proc/self/ns/net").exists() and
          os.geteuid() == 0, "Linux root required for guard readback")
    _need(type(text) is bool, "invalid nft readback mode")
    fd = _pin_nft(nft_path)
    try:
        return _command(fd, (["--handle"] if text else ["--json", "--handle"]) +
                        ["list", "table", "inet", GUARD_TABLE], deadline=deadline)
    finally:
        os.close(fd)


def _calibration_challenges(challenge: Challenge) -> list[Challenge]:
    # Derive disjoint calibration payloads before installing the immutable
    # trace batch. Every nonce is still bound to the random challenge.
    values=[replace(challenge,nonce=hashlib.sha256(
        b"AEGIS trace calibration v1\0"+challenge.nonce+bytes([i])).digest()[:16])
        for i in range(CALIBRATION_ATTEMPTS)]
    _need(len({v.nonce[:12] for v in [challenge,*values]})==len(values)+1,
          "trace nonce prefix collision")
    return values


TRACE_HEADER = (f"add table inet {TRACE_TABLE}\n"
                f"add chain inet {TRACE_TABLE} trace_out "
                "{ type filter hook output priority -200; policy accept; }\n")
IPV6_CHALLENGE_DOMAIN = b"AEGIS native witness v6 challenge v1\0"
TRACE_BATCH_SCHEMA = "aegis_auto_witness_trace_batch_v1"
DUAL_SCHEMA = "aegis_auto_native_dual_deny_witness_v1"


def _family(challenge: Challenge) -> int:
    return 6 if ":" in challenge.peer_ipv4 else 4


def _trace_rule_line(challenge: Challenge, value: Challenge) -> str:
    prefix=int.from_bytes(value.nonce[:12],"big")
    return (f"add rule inet {TRACE_TABLE} trace_out "
            f'oifname "{challenge.egress_interface}" {"ip6" if ":" in challenge.peer_ipv4 else "ip"} daddr {challenge.peer_ipv4} '
            f"udp sport {challenge.source_port} udp dport {challenge.sink_port} "
            f"@th,64,96 0x{prefix:x} meta nftrace set 1\n")


def _trace_rule(challenge: Challenge) -> bytes:
    challenge.validate()
    # Bind each trace episode to a payload prefix in the kernel rule itself.
    # nft 1.1.6 does not necessarily print transport payload in packet lines.
    # The matching rule must therefore carry the exact nonce predicate.
    batch=TRACE_HEADER
    for value in [challenge,*_calibration_challenges(challenge)]:
        batch+=_trace_rule_line(challenge,value)
    return batch.encode()


def ipv6_challenge_nonce(actor_challenge: bytes) -> bytes:
    """Domain-separated IPv6 challenge; no trace prefix is shared with IPv4."""
    _need(type(actor_challenge) is bytes and len(actor_challenge) == 32,
          "invalid actor challenge")
    return hashlib.sha256(IPV6_CHALLENGE_DOMAIN + actor_challenge).digest()


def _dual_batch(challenge4: Challenge, challenge6: Challenge) -> tuple[bytes, dict]:
    """One atomic 14-row trace batch and the exact projection it installs.

    No intermediate 8-row state exists. All twelve payload prefixes are
    distinct, so the global unique-prefix rule is unchanged.
    """
    challenge4.validate()
    challenge6.validate()
    _need(_family(challenge4) == 4 and _family(challenge6) == 6,
          "dual witness requires one IPv4 and one IPv6 challenge")
    _need(challenge4.egress_interface == challenge6.egress_interface and
          challenge4.source_port != challenge6.source_port and
          challenge4.nonce != challenge6.nonce,
          "dual witness tuples are not distinct")
    batch = TRACE_HEADER
    rules = []
    for challenge in (challenge4, challenge6):
        for value in [challenge, *_calibration_challenges(challenge)]:
            batch += _trace_rule_line(challenge, value)
            rules.append({"family": "ip6" if _family(challenge) == 6 else "ip",
                          "oifname": challenge.egress_interface,
                          "daddr": challenge.peer_ipv4,
                          "sport": challenge.source_port,
                          "dport": challenge.sink_port,
                          "prefix": int.from_bytes(value.nonce[:12], "big")})
    _need(len(rules) == 2 * (CALIBRATION_ATTEMPTS + 1) and
          len({rule["prefix"] for rule in rules}) == len(rules),
          "trace nonce prefix collision")
    raw = batch.encode()
    _need(len(raw) <= 4096, "oversized nft command input")
    return raw, {"schema": TRACE_BATCH_SCHEMA, "rules": rules}


def _peer(sock: socket.socket) -> tuple[int, int]:
    _need(sock.family == socket.AF_UNIX and
          (sock.type & 0xf) == socket.SOCK_SEQPACKET,
          "independent sink requires a connected Unix seqpacket socket")
    pid, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET,
                                                       socket.SO_PEERCRED, 12))
    _need(uid == 0 and pid > 1 and pid != os.getpid(),
          "sink peer is not a separate root process")
    ino = os.stat(f"/proc/{pid}/ns/net").st_ino
    _need(ino != os.stat("/proc/self/ns/net").st_ino,
          "sink must observe in a separate network namespace")
    return pid, ino


def _sink_message(sock: socket.socket, message: dict, timeout: float) -> dict:
    sock.settimeout(timeout)
    payload = json.dumps(message, separators=(",", ":")).encode()
    _need(sock.send(payload) == len(payload), "short sink control send")
    raw, _ancillary, flags, _address = sock.recvmsg(4096)
    _need(bool(raw) and flags & socket.MSG_TRUNC == 0,
          "truncated independent sink reply")
    response = _json(raw)
    _need(type(response) is dict, "invalid independent sink receipt")
    return response


def _trace_drop(raw: bytes, challenge: Challenge, handle: int,
                source_ipv4: str | None = None) -> str:
    """Require one trace ID tied to UDP tuple and the actual DROP rule handle.

    nftables 1.0.6 emits human trace lines even with --json.  `-a` includes
    kernel rule handles. This grammar was checked with a live Linux packet.
    Unknown trace lines cannot grant a match.
    """
    _need(0 < len(raw) <= MAX_TRACE, "empty or oversized nft trace")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise NativeWitnessRefused("non-ASCII nft trace") from error
    # nft can reuse an ID after an earlier calibration packet.  Each trace_out
    # packet starts a new episode for that ID, so later lines cannot borrow an
    # earlier packet's rule or DROP to satisfy this challenge.
    episodes: dict[str, int] = {}
    packet_nonce_seen: dict[str, bool] = {}
    matching_episodes = 0
    completed: list[str] = []
    prefix = re.compile(r"^trace id ([0-9a-f]{1,16}) inet ([a-zA-Z0-9_]+) ([a-zA-Z0-9_]+) (.*)$")
    drop_rule = re.compile(r"^rule counter packets [0-9]+ bytes [0-9]+ drop "
                           r"# handle ([0-9]+) \(verdict drop\)$")
    own_rule = re.compile(
        r'^rule oifname "' + re.escape(challenge.egress_interface) +
        r'" ' + ('ip6' if ':' in challenge.peer_ipv4 else 'ip') + r' daddr ' + re.escape(challenge.peer_ipv4) +
        r' udp sport ' + str(challenge.source_port) +
        r' udp dport ' + str(challenge.sink_port) +
        r'(?: @th,64,96 (0x[0-9a-f]{1,24}))? meta nftrace set 1 # handle [0-9]+ \(verdict continue\)$')
    def nonce_prefix_in(packet_line: str) -> bool | None:
        # nft prints @th,64,96 as a number; leading zero nibbles disappear.
        observed = re.search(r'@th,64,96 0x([0-9a-f]{1,24})(?: |$)', packet_line)
        return (None if observed is None else int(observed.group(1),16)==
                int.from_bytes(challenge.nonce[:12],"big"))
    for line in lines:
        match = prefix.fullmatch(line.rstrip())
        if match is None:
            continue
        ident, table, chain, body = match.groups()
        packet_matches = (_packet_tuple_matches(body, challenge, source_ipv4) and
                          nonce_prefix_in(body) is not False)
        if table == TRACE_TABLE and chain == "trace_out":
            if body.startswith("packet: "):
                episodes[ident] = 1 if packet_matches else 0
                packet_nonce_seen[ident]=nonce_prefix_in(body) is True
            elif episodes.get(ident) == 1:
                rule=own_rule.fullmatch(body)
                if rule is not None:
                    proven=(int(rule.group(1),16)==int.from_bytes(challenge.nonce[:12],"big")
                            if rule.group(1) else packet_nonce_seen.get(ident,False))
                    episodes[ident]=2 if proven else 0
                    if proven:matching_episodes+=1
        elif (table == GUARD_TABLE and chain == "output" and
              body.startswith("packet: ")):
            episodes[ident] = (3 if episodes.get(ident) == 2 and
                               packet_matches else 0)
        elif (table == GUARD_TABLE and chain == "output" and
              episodes.get(ident) == 3):
            rule = drop_rule.fullmatch(body)
            if rule is not None and int(rule.group(1)) == handle:
                episodes[ident] = 4
                completed.append(ident)
    _need(matching_episodes == 1 and len(completed) == 1,
          "challenged packet did not trace to persistent terminal DROP")
    return completed[0]


TRACE_LINE = re.compile(r"^trace id ([0-9a-f]{1,16}) inet ([a-zA-Z0-9_]+) ([a-zA-Z0-9_]+) (.*)$")


def _packet_tuple_matches(body: str, challenge: Challenge,
                          source_ipv4: str | None) -> bool:
    """A trace `packet:` line carrying this challenge's exact UDP tuple."""
    family = 'ip6' if ':' in challenge.peer_ipv4 else 'ip'
    return bool(body.startswith("packet: ") and
                re.search(r'\boif "' + re.escape(challenge.egress_interface) + r'"(?: |$)', body) and
                (source_ipv4 is None or re.search(
                    r'\b' + family + r' saddr ' + re.escape(source_ipv4) + r'(?: |$)', body)) and
                re.search(r'\b' + family + r' daddr ' + re.escape(challenge.peer_ipv4) + r'(?: |$)', body) and
                re.search(r'\budp sport ' + str(challenge.source_port) +
                          r' udp dport ' + str(challenge.sink_port) + r'(?: |$)', body))


def _attribute_trace(raw: bytes, families: tuple[tuple[int, Challenge, str], ...]
                     ) -> tuple[dict[int, bytes], bytes]:
    """Split one monitor buffer into per-family episode buffers.

    Each trace_out `packet:` line opens an episode for its trace id; its
    family is the challenge whose full UDP tuple it carries. Later lines with
    that id belong to the same family until the next trace_out packet line
    for the id. Everything else (including unattributed episodes and
    unparsed lines) goes to a separate buffer and grants nothing.
    """
    _need(0 < len(raw) <= MAX_TRACE, "empty or oversized nft trace")
    try:
        lines = raw.decode("ascii").splitlines(keepends=True)
    except UnicodeDecodeError as error:
        raise NativeWitnessRefused("non-ASCII nft trace") from error
    buffers = {family: bytearray() for family, _challenge, _source in families}
    other = bytearray()
    episodes: dict[str, int | None] = {}
    for line in lines:
        match = TRACE_LINE.fullmatch(line.rstrip())
        owner = None
        if match is not None:
            ident, table, chain, body = match.groups()
            if table == TRACE_TABLE and chain == "trace_out" and body.startswith("packet: "):
                owners = [family for family, challenge, source in families
                          if _packet_tuple_matches(body, challenge, source)]
                episodes[ident] = owners[0] if len(owners) == 1 else None
            owner = episodes.get(ident)
        (buffers[owner] if owner is not None else other).extend(line.encode("ascii"))
    return {family: bytes(value) for family, value in buffers.items()}, bytes(other)


def _open_sender(challenge: Challenge) -> socket.socket:
    sender = socket.socket(socket.AF_INET6 if ":" in challenge.peer_ipv4 else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                          challenge.egress_interface.encode() + b"\0")
        sender.bind(("::" if ":" in challenge.peer_ipv4 else "0.0.0.0", challenge.source_port))
        return sender
    except BaseException:
        sender.close()
        raise


def _send_on(sender: socket.socket, challenge: Challenge, *, may_drop: bool) -> int | None:
    try:
        sent = sender.sendto(challenge.nonce,
                             (challenge.peer_ipv4, challenge.sink_port))
        _need(sent == len(challenge.nonce), "partial challenged send")
        return None
    except OSError as error:
        _need(may_drop and error.errno in (errno.EPERM, errno.EACCES),
              "challenged send failed outside guard DROP")
        return error.errno


def _send(challenge: Challenge, *, may_drop: bool) -> int | None:
    sender = _open_sender(challenge)
    try:
        return _send_on(sender, challenge, may_drop=may_drop)
    finally:
        sender.close()


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def _interface_identity(name: str, ipv6: bool = False) -> tuple[int, bytes, bytes]:
    """Get the kernel's current interface index, IPv4 address and MAC."""
    ifindex = socket.if_nametoindex(name)
    _need(ifindex > 0, "baseline interface missing")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as query:
        request = struct.pack("256s", name.encode("ascii"))
        try:
            ip_reply = (b"" if ipv6 else fcntl.ioctl(query.fileno(), 0x8915, request))  # SIOCGIFADDR
            mac_reply = fcntl.ioctl(query.fileno(), 0x8927, request)  # SIOCGIFHWADDR
        except OSError as error:
            raise NativeWitnessRefused("baseline interface has no IPv4 or MAC") from error
    source_ip = b"" if ipv6 else ip_reply[20:24]
    if ipv6:
        addresses=[]
        for line in Path('/proc/net/if_inet6').read_text().splitlines():
            raw,index,prefix,scope,flags,iface=line.split()
            if iface==name and raw.startswith('20010db8') and scope=='00' and int(flags,16)&0x40==0:
                addresses.append(bytes.fromhex(raw))
        _need(len(addresses)==1,'baseline interface needs one IPv6 documentation address')
        source_ip=addresses[0]
    source_mac = mac_reply[18:24]
    _need(len(source_ip) in (4,16) and len(source_mac) == 6 and
          source_mac != b"\0" * 6 and source_mac[0] & 1 == 0,
          "invalid baseline source interface identity")
    return ifindex, source_ip, source_mac


def _l2_frame(baseline: Challenge, source_ip: bytes, source_mac: bytes,
              peer_mac: bytes) -> bytes:
    baseline.validate()
    _need(type(peer_mac) is bytes and len(peer_mac) == 6 and
          peer_mac != b"\0" * 6 and peer_mac[0] & 1 == 0,
          "invalid baseline peer MAC")
    _need(type(source_ip) is bytes and len(source_ip) in (4,16) and
          type(source_mac) is bytes and len(source_mac) == 6 and
          source_mac != b"\0" * 6 and source_mac[0] & 1 == 0,
          "invalid baseline source identity")
    ipv6=":" in baseline.peer_ipv4
    destination_ip = socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET,baseline.peer_ipv4)
    udp_length = 8 + len(baseline.nonce)
    udp_header = struct.pack("!HHHH", baseline.source_port, baseline.sink_port,
                             udp_length, 0)
    pseudo = (source_ip + destination_ip + (struct.pack("!I3xB",udp_length,17) if ipv6 else struct.pack("!BBH", 0, 17, udp_length)))
    udp_checksum = _checksum(pseudo + udp_header + baseline.nonce) or 0xffff
    udp_header = struct.pack("!HHHH", baseline.source_port, baseline.sink_port,
                             udp_length, udp_checksum)
    if ipv6:
        ip_header=struct.pack('!IHBB16s16s',6<<28,udp_length,17,64,source_ip,destination_ip)
        return peer_mac+source_mac+struct.pack('!H',0x86dd)+ip_header+udp_header+baseline.nonce
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_length,
                            int.from_bytes(os.urandom(2), "big"), 0, 64, 17,
                            0, source_ip, destination_ip)
    ip_header = ip_header[:10] + struct.pack("!H", _checksum(ip_header)) + ip_header[12:]
    return (peer_mac + source_mac + struct.pack("!H", 0x0800) +
            ip_header + udp_header + baseline.nonce)


def _send_l2_baseline(baseline: Challenge, peer_mac: bytes) -> tuple[int, str, str]:
    ifindex, source_ip, source_mac = _interface_identity(baseline.egress_interface, ":" in baseline.peer_ipv4)
    frame = _l2_frame(baseline, source_ip, source_mac, peer_mac)
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                           socket.htons(0x86dd if ":" in baseline.peer_ipv4 else 0x0800)) as packet:
            packet.bind((baseline.egress_interface, 0))
            _need(socket.if_nametoindex(baseline.egress_interface) == ifindex,
                  "baseline interface changed before L2 send")
            _need(packet.send(frame) == len(frame), "short L2 baseline send")
    except OSError as error:
        raise NativeWitnessRefused("L2 baseline send failed") from error
    return ifindex, socket.inet_ntop(socket.AF_INET6 if ":" in baseline.peer_ipv4 else socket.AF_INET,source_ip), source_mac.hex(":")


def prepare_positive_control(sink: socket.socket, baseline: Challenge,
                             peer_mac: bytes) -> PositiveSinkControl:
    """Prove live sink/link delivery with one raw L2 packet under guard DROP.

    AF_PACKET bypasses inet OUTPUT, so this is only a positive sink/link
    control. `prove_deny` separately requires ordinary UDP trace through the
    persistent nft DROP. The same connected sink session must remain live.
    """
    _need(os.name == "posix" and Path("/proc/self/ns/net").exists() and
          os.geteuid() == 0, "Linux root required for sink control")
    baseline.validate()
    pid, sink_netns = _peer(sink)
    sender_netns = os.stat("/proc/self/ns/net").st_ino
    digest = hashlib.sha256(baseline.nonce).hexdigest()
    ready = _sink_message(sink, {"op": "BASELINE", "sha256": digest}, 2.0)
    _need(ready.get("state") == "BASELINE_READY" and
          ready.get("sha256") == digest and ready.get("received") == 0 and
          type(ready.get("session")) is str and
          bool(re.fullmatch(r"[0-9a-f]{32}", ready["session"])),
          "independent sink baseline not ready")
    ifindex, source_ipv4, source_mac = _send_l2_baseline(baseline, peer_mac)
    done = _sink_message(sink,
                         {"op": "BASELINE_FINISH", "sha256": digest}, 2.0)
    _need(done == {"state": "BASELINE_COMPLETE", "sha256": digest,
                   "received": 1, "session": ready["session"]} and
          _peer(sink) == (pid, sink_netns),
          "independent sink positive control failed")
    return PositiveSinkControl(digest, ready["session"], pid, sink_netns,
                               sender_netns, baseline.sink_port,
                               baseline.egress_interface, baseline.peer_ipv4,
                               baseline.source_port, source_ipv4, source_mac,
                               peer_mac.hex(":"), ifindex, "af_packet_l2",
                               time.monotonic())


def _collect_trace(selector: selectors.BaseSelector, trace: bytearray,
                   seconds: float) -> None:
    _need(bool(selector.get_map()), "nft trace monitor closed")
    for key, _ in selector.select(max(0.0, seconds)):
        data = os.read(key.fileobj.fileno(), 65536)
        if data:
            trace.extend(data)
            _need(len(trace) <= MAX_TRACE, "nft trace exceeded bound")
        else:
            selector.unregister(key.fileobj)
            raise NativeWitnessRefused("nft trace monitor closed")


NETLINK_NETFILTER = 12
NFNLGRP_NFTRACE = 9
SUBSCRIPTION_SECONDS = 0.4
NETLINK_TABLE = re.compile(r"^sk\s+Eth\s+Pid\s+Groups\s+Rmem\s+Wmem\s+Dump\s+Locks\s+Drops\s+Inode$")


def _netlink_trace_member(table: str, inodes: frozenset[int]) -> bool:
    """One of `inodes` is a NETLINK_NETFILTER socket in the NFTRACE group.

    `table` is /proc/<pid>/net/netlink: protocol in column 2, the first
    32-bit group word in hex in column 4, the socket inode in column 10.
    Group g is bit g-1. Unknown or malformed rows never match.
    """
    lines = table.splitlines()
    if not lines or NETLINK_TABLE.fullmatch(lines[0].strip()) is None:
        return False
    for line in lines[1:]:
        fields = line.split()
        if (len(fields) != 10 or not fields[1].isdigit() or
                re.fullmatch(r"[0-9a-f]{8}", fields[3]) is None or
                not fields[9].isdigit()):
            continue
        if (int(fields[1]) == NETLINK_NETFILTER and int(fields[9]) in inodes and
                int(fields[3], 16) & (1 << (NFNLGRP_NFTRACE - 1))):
            return True
    return False


def _socket_inodes(pid: int) -> frozenset[int]:
    found = set()
    try:
        names = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return frozenset()
    for name in names:
        try:
            target = os.readlink(f"/proc/{pid}/fd/{name}")
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[([0-9]{1,20})\]", target)
        if match is not None:
            found.add(int(match.group(1)))
    return frozenset(found)


def _read_netlink_table(pid: int) -> str:
    with open(f"/proc/{pid}/net/netlink", "rb") as table:
        return table.read(1 << 20).decode("ascii")


def _await_trace_subscription(monitor: subprocess.Popen) -> bool:
    """Wait, bounded, until `nft monitor trace` has joined NFNLGRP_NFTRACE.

    The kernel emits a trace event only while a listener is subscribed, so
    a calibration packet sent while nft is still starting is lost and costs
    its whole 0.4 s window. On r17c G2 the IPv4 calibration sat on the merged
    witness's critical path, and the trace-rollback lease took either
    1.14-1.16 s or 1.56-1.57 s: one lost window.

    This only schedules the first calibration. It grants nothing: a
    calibration trace on the installed rule stays the readiness proof, with
    the same attempts and windows. On timeout, monitor exit or any read
    failure the calibrations simply start, exactly as before.
    """
    pid = getattr(monitor, "pid", None)
    if type(pid) is not int or pid <= 1:
        return False
    deadline = time.monotonic() + SUBSCRIPTION_SECONDS
    for _ in range(int(SUBSCRIPTION_SECONDS / 0.002) + 1):
        if monitor.poll() is not None:
            return False
        inodes = _socket_inodes(pid)
        if inodes:
            try:
                if _netlink_trace_member(_read_netlink_table(pid), inodes):
                    return True
            except (OSError, UnicodeDecodeError):
                return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.002)
    return False


def _calibrate_trace_subscription(selector: selectors.BaseSelector,
                                  trace: bytearray, sender: socket.socket,
                                  challenge: Challenge, drop_handle: int,
                                  source_ipv4: str) -> bool:
    calibrations = []
    for calibration in _calibration_challenges(challenge):
        calibrations.append(calibration)
        _send_on(sender, calibration, may_drop=True)
        # nft flushes individual formatter fragments. A readable prefix does
        # not consume a calibration attempt: retain the original absolute
        # 0.4-second observation window, including all later fragments.
        deadline = time.monotonic() + 0.4
        while (remaining := deadline - time.monotonic()) > 0:
            _collect_trace(selector, trace, remaining)
            for observed in calibrations:
                try:
                    _trace_drop(bytes(trace), observed, drop_handle, source_ipv4)
                except NativeWitnessRefused:
                    continue
                return True
    return False


def _trace_failure_snapshot(monitor: subprocess.Popen, trace: bytearray,
                            phase: str, send_errno: int | None
                            ) -> tuple[str, str, bytes, bool, int | None, int | None]:
    status = monitor.poll()
    category = ("monitor_exited" if status is not None else
                "trace_empty" if not trace else "trace_unmatched")
    return (category, phase, bytes(trace[:MAX_TRACE]), len(trace) > MAX_TRACE,
            status, send_errno)


def _write_trace_subscription_failure(challenge_sha256: str, category: str,
                                      phase: str, trace: bytes,
                                      trace_truncated: bool,
                                      residual_stdout: bytes,
                                      residual_truncated: bool, stderr: bytes,
                                      monitor_status: int | None,
                                      send_errno: int | None) -> None:
    """Retain bounded private failure evidence, never an activation receipt."""
    _need(bool(re.fullmatch(r"[0-9a-f]{64}", challenge_sha256)) and
          category in ("monitor_exited", "trace_empty", "trace_unmatched") and
          phase in ("calibration_monitor", "calibration_subscription",
                    "challenge_monitor", "challenge_timeout") and
          len(trace) + len(residual_stdout) <= MAX_TRACE and
          type(trace_truncated) is bool and
          type(residual_truncated) is bool and len(stderr) <= 4096 and
          (monitor_status is None or type(monitor_status) is int) and
          (send_errno is None or send_errno in (errno.EPERM, errno.EACCES)),
          "invalid_trace_failure_evidence")
    payload = (json.dumps({
        "schema": "aegis_auto_native_trace_failure_v1",
        "category": category,
        "phase": phase,
        "challenge_sha256": challenge_sha256,
        "trace_len": len(trace),
        "trace_truncated": trace_truncated,
        "trace_sha256": hashlib.sha256(trace).hexdigest(),
        "trace_b64": base64.b64encode(trace).decode("ascii"),
        "monitor_stdout_residual_len": len(residual_stdout),
        "monitor_stdout_residual_sha256": hashlib.sha256(residual_stdout).hexdigest(),
        "monitor_stdout_residual_b64": base64.b64encode(
            residual_stdout).decode("ascii"),
        "monitor_stdout_residual_truncated": residual_truncated,
        "monitor_stderr_b64": base64.b64encode(stderr).decode("ascii"),
        "monitor_status_at_refusal": monitor_status,
        "send_errno": send_errno,
    }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    _need(len(payload) <= 1_500_000, "trace_failure_evidence_oversized")
    directory = os.open(TRACE_FAILURE_RUNTIME, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        held = os.fstat(directory)
        named = TRACE_FAILURE_RUNTIME.lstat()
        _need(stat.S_ISDIR(held.st_mode) and held.st_uid == 0 and
              stat.S_IMODE(held.st_mode) == 0o700 and
              (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
              "untrusted_trace_failure_runtime")
        name = "native-trace-failure-" + challenge_sha256 + ".json"
        file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                          os.O_CLOEXEC | os.O_NOFOLLOW, 0o600,
                          dir_fd=directory)
        try:
            item = os.fstat(file_fd)
            _need(stat.S_ISREG(item.st_mode) and item.st_uid == 0 and
                  stat.S_IMODE(item.st_mode) == 0o600 and item.st_nlink == 1,
                  "untrusted_trace_failure_file")
            view = memoryview(payload)
            while view:
                written = os.write(file_fd, view)
                _need(written > 0, "short_trace_failure_write")
                view = view[written:]
            os.fsync(file_fd)
        finally:
            os.close(file_fd)
        os.fsync(directory)
        named_after = TRACE_FAILURE_RUNTIME.lstat()
        _need((held.st_dev, held.st_ino) ==
              (named_after.st_dev, named_after.st_ino),
              "trace_failure_runtime_replaced")
    finally:
        os.close(directory)


def _admit_positive_control(challenge: Challenge, positive_control: PositiveSinkControl,
                            sink: socket.socket) -> tuple[int, int, int]:
    """The same live sink session, route and source identity as the baseline."""
    _need(type(positive_control) is PositiveSinkControl,
          "live positive sink control required")
    _need(bool(re.fullmatch(r"[0-9a-f]{64}", positive_control.baseline_sha256)) and
          bool(re.fullmatch(r"[0-9a-f]{32}", positive_control.session)) and
          positive_control.baseline_sha256 != hashlib.sha256(challenge.nonce).hexdigest() and
          positive_control.sink_port == challenge.sink_port and
          positive_control.egress_interface == challenge.egress_interface and
          positive_control.peer_ipv4 == challenge.peer_ipv4 and
          positive_control.source_port == challenge.source_port and
          positive_control.method == "af_packet_l2" and
          positive_control.ifindex == socket.if_nametoindex(challenge.egress_interface) and
          type(positive_control.observed_at) is float and
          0 <= time.monotonic() - positive_control.observed_at <= 30.0,
          "positive control is stale or for a different route")
    pid, sink_netns = _peer(sink)
    netns = os.stat("/proc/self/ns/net").st_ino
    _need((pid, sink_netns, netns) ==
          (positive_control.sink_pid, positive_control.sink_netns_ino,
           positive_control.sender_netns_ino),
          "positive control changed process or namespace")
    current_ifindex, current_ip, current_mac = _interface_identity(
        challenge.egress_interface, ":" in challenge.peer_ipv4)
    _need((current_ifindex, socket.inet_ntop(socket.AF_INET6 if ":" in challenge.peer_ipv4 else socket.AF_INET,current_ip), current_mac.hex(":")) ==
          (positive_control.ifindex, positive_control.source_ipv4,
           positive_control.source_mac),
          "positive control source interface identity changed")
    return pid, sink_netns, netns


def _foreign_state() -> dict[str, str]:
    from aegis_auto_foreign_policy import trusted_read
    state_path=Path('/var/lib/aegis-install/client/device-guard.conf')
    return dict(line.split('=',1) for line in trusted_read(state_path,16384).decode('ascii').splitlines())


def prove_deny(nft_path: Path, lock_fd: int, expected_policy_sha256: str,
               challenge: Challenge, positive_control: PositiveSinkControl,
               sink: socket.socket,
               rollback: RollbackLease) -> DenyWitness:
    """Observe one actual denied packet while guard flock and rollback hold.

    The same independent sink received one raw L2 baseline packet over the
    challenged interface under the guard. It then records zero arrivals for
    the ordinary UDP challenge, whose nft trace reaches persistent DROP.
    The installed caller is responsible for authenticating sink binary
    provenance and rollback service identity before invoking this function.
    """
    _need(os.name == "posix" and Path("/proc/self/ns/net").exists(),
          "Linux network namespace unavailable")
    _need(os.geteuid() == 0, "native witness requires root")
    _need(type(lock_fd) is int and lock_fd >= 0 and
          fcntl.fcntl(lock_fd, fcntl.F_GETFD) >= 0, "guard lock FD missing")
    _need(type(expected_policy_sha256) is str and
          bool(re.fullmatch(r"[0-9a-f]{64}", expected_policy_sha256)),
          "protected policy digest missing")
    from aegis_auto_trace_rollback import RollbackClient
    _need(type(rollback) is RollbackClient,
          "installed independent rollback client required")
    challenge.validate()
    from aegis_auto_foreign_policy import assess_foreign_policy, trusted_read
    state_path=Path('/var/lib/aegis-install/client/device-guard.conf')
    state=dict(line.split('=',1) for line in trusted_read(state_path,16384).decode('ascii').splitlines())
    foreign_before=assess_foreign_policy(state['uplink'],mode=state.get('capture_profile','full-wide-tun'),require_guard=True)
    pid, sink_netns, netns = _admit_positive_control(challenge, positive_control, sink)
    digest = hashlib.sha256(challenge.nonce).hexdigest()
    fd = _pin_nft(nft_path)
    installed = False
    armed = False
    monitor = None
    trace_failure: tuple[str, str, bytes, bool, int | None, int | None] | None = None
    monitor_stderr = b""
    monitor_stdout_residual = b""
    try:
        tables_before = _command(fd, ["--json", "list", "tables"])
        _need(TRACE_TABLE.encode() not in tables_before,
              "trace table already exists")
        before = _command(fd, ["--json", "--handle", "list", "table", "inet", GUARD_TABLE])
        policy, drop_handle, count_before = _guard_projection(before)
        _need(policy == expected_policy_sha256,
              "installed guard differs from protected policy")
        ready = _sink_message(sink, {"op": "ARM", "sha256": digest,
                                     "session": positive_control.session}, 2.0)
        _need(ready == {"state": "READY", "sha256": digest, "received": 0,
                        "session": positive_control.session},
              "independent sink not ready")
        denied_arm_at = time.monotonic()
        _need((_peer(sink) == (pid, sink_netns)), "sink process changed")
        rollback.arm(table=TRACE_TABLE, netns_ino=netns)
        armed = True
        _need(rollback.live(), "independent rollback unavailable")
        _command(fd, ["-f", "-"], input_data=_trace_rule(challenge))
        installed = True
        _need(rollback.live(), "independent rollback lost")
        monitor = subprocess.Popen(["/usr/sbin/nft", "-a", "monitor", "trace"],
                                   executable=f"/proc/self/fd/{fd}", pass_fds=(fd,),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   close_fds=True,
                                   env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
        selector = selectors.DefaultSelector()
        trace = bytearray()
        try:
            selector.register(monitor.stdout, selectors.EVENT_READ)
            sender = _open_sender(challenge)
            try:
                # An actual kernel trace is the subscription handshake.  A
                # missed calibration packet is never a positive result; each
                # attempt has a distinct nonce and the same held UDP socket.
                try:
                    subscribed = _calibrate_trace_subscription(
                        selector, trace, sender, challenge, drop_handle,
                        positive_control.source_ipv4)
                except NativeWitnessRefused:
                    trace_failure = _trace_failure_snapshot(
                        monitor, trace, "calibration_monitor", None)
                    raise
                subscription_ready = subscribed and monitor.poll() is None
                if not subscription_ready:
                    trace_failure = _trace_failure_snapshot(
                        monitor, trace, "calibration_subscription", None)
                _need(subscription_ready, "nft trace subscription not ready")
                send_errno = _send_on(sender, challenge, may_drop=True)
                deadline = time.monotonic() + TRACE_SECONDS
                while time.monotonic() < deadline:
                    try:
                        _collect_trace(selector, trace,
                                       min(0.1, deadline - time.monotonic()))
                    except NativeWitnessRefused:
                        trace_failure = _trace_failure_snapshot(
                            monitor, trace, "challenge_monitor", send_errno)
                        raise
                    try:
                        _trace_drop(bytes(trace), challenge, drop_handle,
                                    positive_control.source_ipv4)
                    except NativeWitnessRefused:
                        continue
                    if time.monotonic() - denied_arm_at >= 1.1:
                        break
                else:
                    trace_failure = _trace_failure_snapshot(
                        monitor, trace, "challenge_timeout", send_errno)
                    raise NativeWitnessRefused("challenged native DROP trace timed out")
            finally:
                sender.close()
        finally:
            selector.close()
        completed = _sink_message(sink, {"op": "FINISH", "sha256": digest,
                                         "session": positive_control.session}, 2.0)
        _need(completed == {"state": "COMPLETE", "sha256": digest, "received": 0,
                            "session": positive_control.session},
              "challenged datagram reached independent sink")
        _need(_peer(sink) == (pid, sink_netns) and rollback.live(),
              "sink or rollback changed during challenge")
        after = _command(fd, ["--json", "--handle", "list", "table", "inet", GUARD_TABLE])
        policy_after, handle_after, count_after = _guard_projection(after)
        _need(policy_after == policy and handle_after == drop_handle and
              count_after > count_before,
              "guard policy or challenged DROP counter changed")
        trace_id = _trace_drop(bytes(trace), challenge, drop_handle,
                               positive_control.source_ipv4)
        _command(fd, ["delete", "table", "inet", TRACE_TABLE])
        installed = False
        _need(_command(fd, ["--json", "list", "tables"]) == tables_before,
              "nft inventory changed after trace cleanup")
        rollback.disarm()
        armed = False
        foreign_after=assess_foreign_policy(state['uplink'],mode=state.get('capture_profile','full-wide-tun'),require_guard=True)
        _need(foreign_after==foreign_before,'foreign policy changed during deny witness')
        return DenyWitness(
            schema="aegis_auto_native_deny_witness_v1",
            guard_policy_sha256=policy,
            guard_before_sha256=hashlib.sha256(before).hexdigest(),
            guard_after_sha256=hashlib.sha256(after).hexdigest(),
            guard_drop_handle=drop_handle,
            guard_output_drop_delta=count_after - count_before,
            sender_netns_ino=netns,
            trace_id=trace_id,
            trace_sha256=hashlib.sha256(trace).hexdigest(),
            baseline_sha256=positive_control.baseline_sha256,
            baseline_received=1,
            baseline_method=positive_control.method,
            baseline_egress_interface=positive_control.egress_interface,
            baseline_peer_ipv4=positive_control.peer_ipv4,
            baseline_source_port=positive_control.source_port,
            baseline_source_ipv4=positive_control.source_ipv4,
            baseline_source_mac=positive_control.source_mac,
            baseline_peer_mac=positive_control.peer_mac,
            baseline_ifindex=positive_control.ifindex,
            challenge_sha256=digest,
            sink_pid=pid,
            sink_netns_ino=sink_netns,
            sink_session=positive_control.session,
            sink_received=0,
            trace_table_removed=True,
            send_errno=send_errno,
            ack=True,
            address_family=6 if ':' in challenge.peer_ipv4 else 4,
            foreign_policy_class=foreign_before['class'],
            foreign_policy_backend=foreign_before['backend'],
            foreign_projection_sha256=foreign_before['foreign_projection_sha256'],
        )
    finally:
        try:
            if monitor is not None:
                monitor.kill() if monitor.poll() is None else None
                monitor_stdout_residual, monitor_stderr = monitor.communicate(timeout=2)
            if installed:
                # An independent armed rollback remains responsible if this fails.
                try:
                    _command(fd, ["delete", "table", "inet", TRACE_TABLE])
                    installed = False
                except BaseException:
                    pass
            if armed and not installed:
                rollback.disarm()
        finally:
            os.close(fd)
            if trace_failure is not None:
                try:
                    (category, phase, trace_bytes, trace_truncated, status,
                     send_errno) = trace_failure
                    residual_capacity = MAX_TRACE - len(trace_bytes)
                    _write_trace_subscription_failure(
                        digest, category, phase, trace_bytes, trace_truncated,
                        monitor_stdout_residual[:residual_capacity],
                        len(monitor_stdout_residual) > residual_capacity,
                        monitor_stderr[:4096], status, send_errno)
                except Exception:
                    # Diagnostic storage has no authority over the refusal.
                    pass


def _foreign_digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _arm_sink(sink: socket.socket, digest: str, session: str,
              identity: tuple[int, int]) -> float:
    ready = _sink_message(sink, {"op": "ARM", "sha256": digest,
                                 "session": session}, 2.0)
    _need(ready == {"state": "READY", "sha256": digest, "received": 0,
                    "session": session},
          "independent sink not ready")
    armed_at = time.monotonic()
    _need(_peer(sink) == identity, "sink process changed")
    return armed_at


def _guard_read(fd: int) -> tuple[bytes, bytes, str, int, int]:
    raw = _command(fd, ["--json", "--handle", "list", "table", "inet", GUARD_TABLE])
    projection, handles, counts = policy_projection(raw)
    return (raw, projection, hashlib.sha256(projection).hexdigest(),
            handles["output"], counts["output"])


def prove_deny_dual(nft_path: Path, lock_fd: int, expected_policy_sha256: str,
                    challenges: tuple[Challenge, Challenge],
                    positive_controls: tuple[PositiveSinkControl, PositiveSinkControl],
                    sinks: tuple[socket.socket, socket.socket],
                    rollback: RollbackLease, *, lease_verify, grant_check
                    ) -> DualDenyWitness:
    """IPv4 and IPv6 denied packets in one held trace lease and one window.

    Each family keeps its own sink session, positive control, challenge
    nonce, matched DROP trace on the guard drop handle, zero sink arrivals,
    DROP counter delta and ARM-relative dwell of at least 1.1 s. Three full
    foreign-policy samples (before, inside both dwells, after) must be
    equal. The guard projection is read at c0 (before ARM4), c1 (after the
    IPv4 trace) and c2 (after both FINISH); each must equal the protected
    policy with the same DROP handle and a strictly growing counter, and
    `grant_check` sees each projection. `lease_verify` re-proves the
    topology lease inside the window. Callers verify it before and after.
    """
    _need(os.name == "posix" and Path("/proc/self/ns/net").exists(),
          "Linux network namespace unavailable")
    _need(os.geteuid() == 0, "native witness requires root")
    _need(type(lock_fd) is int and lock_fd >= 0 and
          fcntl.fcntl(lock_fd, fcntl.F_GETFD) >= 0, "guard lock FD missing")
    _need(type(expected_policy_sha256) is str and
          bool(re.fullmatch(r"[0-9a-f]{64}", expected_policy_sha256)),
          "protected policy digest missing")
    from aegis_auto_trace_rollback import RollbackClient
    _need(type(rollback) is RollbackClient,
          "installed independent rollback client required")
    _need(callable(lease_verify) and callable(grant_check),
          "dual witness lease checks missing")
    _need(type(challenges) is tuple and len(challenges) == 2 and
          type(positive_controls) is tuple and len(positive_controls) == 2 and
          type(sinks) is tuple and len(sinks) == 2,
          "dual witness requires one IPv4 and one IPv6 lease")
    challenge4, challenge6 = challenges
    positive4, positive6 = positive_controls
    sink4, sink6 = sinks
    batch, expected_batch = _dual_batch(challenge4, challenge6)
    from aegis_auto_foreign_policy import assess_foreign_policy
    state = _foreign_state()
    uplink, mode = state['uplink'], state.get('capture_profile', 'full-wide-tun')
    foreign_before = assess_foreign_policy(uplink, mode=mode, require_guard=True)
    identity4 = _admit_positive_control(challenge4, positive4, sink4)
    identity6 = _admit_positive_control(challenge6, positive6, sink6)
    netns = identity4[2]
    _need(identity6[2] == netns and identity4[0] != identity6[0] and
          positive4.session != positive6.session and
          positive4.baseline_sha256 != positive6.baseline_sha256,
          "dual witness sinks are not independent sessions")
    digest4 = hashlib.sha256(challenge4.nonce).hexdigest()
    digest6 = hashlib.sha256(challenge6.nonce).hexdigest()
    fd = _pin_nft(nft_path)
    installed = False
    armed = False
    monitor = None
    trace_failure: tuple[str, tuple[str, str, bytes, bool, int | None, int | None]] | None = None
    monitor_stderr = b""
    monitor_stdout_residual = b""
    try:
        tables_before = _command(fd, ["--json", "list", "tables"])
        _need(TRACE_TABLE.encode() not in tables_before,
              "trace table already exists")
        raw0, projection0, policy, drop_handle, count0 = _guard_read(fd)
        _need(policy == expected_policy_sha256,
              "installed guard differs from protected policy")
        grant_check(projection0)
        arm4 = _arm_sink(sink4, digest4, positive4.session, identity4[:2])
        rollback.arm(table=TRACE_TABLE, netns_ino=netns)
        armed = True
        _need(rollback.live(), "independent rollback unavailable")
        _command(fd, ["-f", "-"], input_data=batch)
        installed = True
        _need(rollback.live(), "independent rollback lost")
        # The monitor starts only after the batch exists, as in prove_deny:
        # nft caches the ruleset when it subscribes, and a rule added later is
        # printed as "unknown rule handle N", which never proves a trace (G1,
        # r17c). A calibration trace on the installed rule stays the readiness
        # proof; a missed calibration only consumes its own 0.4 s window.
        monitor = subprocess.Popen(["/usr/sbin/nft", "-a", "monitor", "trace"],
                                   executable=f"/proc/self/fd/{fd}", pass_fds=(fd,),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   close_fds=True,
                                   env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
        selector = selectors.DefaultSelector()
        trace = bytearray()
        send_errno: dict[int, int | None] = {}
        try:
            selector.register(monitor.stdout, selectors.EVENT_READ)
            # Scheduling only (G2): the first IPv4 calibration is not sent
            # into a window in which nft has not yet joined the trace group.
            _await_trace_subscription(monitor)
            for family, challenge, positive in ((4, challenge4, positive4),
                                                (6, challenge6, positive6)):
                digest = digest4 if family == 4 else digest6
                if family == 6:
                    raw1, projection1, policy1, handle1, count1 = _guard_read(fd)
                    _need(policy1 == policy and handle1 == drop_handle and
                          count1 > count0,
                          "guard policy or challenged DROP counter changed")
                    grant_check(projection1)
                    arm6 = _arm_sink(sink6, digest6, positive6.session, identity6[:2])
                # The IPv4 sender is closed before the IPv6 sender binds.
                sender = _open_sender(challenge)
                try:
                    try:
                        subscribed = _calibrate_trace_subscription(
                            selector, trace, sender, challenge, drop_handle,
                            positive.source_ipv4)
                    except NativeWitnessRefused:
                        trace_failure = (digest, _trace_failure_snapshot(
                            monitor, trace, "calibration_monitor", None))
                        raise
                    subscription_ready = subscribed and monitor.poll() is None
                    if not subscription_ready:
                        trace_failure = (digest, _trace_failure_snapshot(
                            monitor, trace, "calibration_subscription", None))
                    _need(subscription_ready, "nft trace subscription not ready")
                    send_errno[family] = _send_on(sender, challenge, may_drop=True)
                    deadline = time.monotonic() + TRACE_SECONDS
                    while True:
                        if time.monotonic() >= deadline:
                            trace_failure = (digest, _trace_failure_snapshot(
                                monitor, trace, "challenge_timeout", send_errno[family]))
                            raise NativeWitnessRefused(
                                "challenged native DROP trace timed out")
                        try:
                            _collect_trace(selector, trace,
                                           min(0.1, deadline - time.monotonic()))
                        except NativeWitnessRefused:
                            trace_failure = (digest, _trace_failure_snapshot(
                                monitor, trace, "challenge_monitor", send_errno[family]))
                            raise
                        try:
                            _trace_drop(bytes(trace), challenge, drop_handle,
                                        positive.source_ipv4)
                        except NativeWitnessRefused:
                            continue
                        break
                finally:
                    sender.close()
            # Inside both idle dwells, after every calibration window: the
            # exact installed batch is the only admitted extra table.
            foreign_mid = assess_foreign_policy(
                uplink, mode=mode, require_guard=True, allow_active_trace=True,
                expected_active_trace=expected_batch)
            lease_verify()
            # Each family's denied dwell is measured from its own ARM.
            while True:
                finished_at = time.monotonic()
                if finished_at - arm4 >= 1.1 and finished_at - arm6 >= 1.1:
                    break
                try:
                    _collect_trace(selector, trace, min(
                        0.1, max(0.001, max(arm4, arm6) + 1.1 - finished_at)))
                except NativeWitnessRefused:
                    trace_failure = (digest6, _trace_failure_snapshot(
                        monitor, trace, "challenge_monitor", send_errno[6]))
                    raise
        finally:
            selector.close()
        for sink, digest, positive, identity in (
                (sink4, digest4, positive4, identity4[:2]),
                (sink6, digest6, positive6, identity6[:2])):
            completed = _sink_message(sink, {"op": "FINISH", "sha256": digest,
                                             "session": positive.session}, 2.0)
            _need(completed == {"state": "COMPLETE", "sha256": digest, "received": 0,
                                "session": positive.session},
                  "challenged datagram reached independent sink")
            _need(_peer(sink) == identity and rollback.live(),
                  "sink or rollback changed during challenge")
        raw2, projection2, policy2, handle2, count2 = _guard_read(fd)
        _need(policy2 == policy and handle2 == drop_handle and count2 > count1,
              "guard policy or challenged DROP counter changed")
        grant_check(projection2)
        combined = bytes(trace)
        buffers, unattributed = _attribute_trace(combined, (
            (4, challenge4, positive4.source_ipv4), (6, challenge6, positive6.source_ipv4)))
        trace_ids = {}
        for family, challenge, positive in ((4, challenge4, positive4),
                                            (6, challenge6, positive6)):
            shared = _trace_drop(combined, challenge, drop_handle, positive.source_ipv4)
            own = _trace_drop(buffers[family], challenge, drop_handle,
                              positive.source_ipv4)
            _need(shared == own, "family trace attribution differs")
            trace_ids[family] = own
        _command(fd, ["delete", "table", "inet", TRACE_TABLE])
        installed = False
        _need(_command(fd, ["--json", "list", "tables"]) == tables_before,
              "nft inventory changed after trace cleanup")
        rollback.disarm()
        armed = False
        foreign_after = assess_foreign_policy(uplink, mode=mode, require_guard=True)
        _need(foreign_before == foreign_mid == foreign_after,
              'foreign policy changed during deny witness')
        mid_sha256 = _foreign_digest(foreign_mid)

        def witness(family, challenge, positive, sink_identity, before, after,
                    delta) -> DenyWitness:
            return DenyWitness(
                schema="aegis_auto_native_deny_witness_v1",
                guard_policy_sha256=policy,
                guard_before_sha256=hashlib.sha256(before).hexdigest(),
                guard_after_sha256=hashlib.sha256(after).hexdigest(),
                guard_drop_handle=drop_handle,
                guard_output_drop_delta=delta,
                sender_netns_ino=netns,
                trace_id=trace_ids[family],
                trace_sha256=hashlib.sha256(buffers[family]).hexdigest(),
                baseline_sha256=positive.baseline_sha256,
                baseline_received=1,
                baseline_method=positive.method,
                baseline_egress_interface=positive.egress_interface,
                baseline_peer_ipv4=positive.peer_ipv4,
                baseline_source_port=positive.source_port,
                baseline_source_ipv4=positive.source_ipv4,
                baseline_source_mac=positive.source_mac,
                baseline_peer_mac=positive.peer_mac,
                baseline_ifindex=positive.ifindex,
                challenge_sha256=hashlib.sha256(challenge.nonce).hexdigest(),
                sink_pid=sink_identity[0],
                sink_netns_ino=sink_identity[1],
                sink_session=positive.session,
                sink_received=0,
                trace_table_removed=True,
                send_errno=send_errno[family],
                ack=True,
                address_family=family,
                foreign_policy_class=foreign_before['class'],
                foreign_policy_backend=foreign_before['backend'],
                foreign_projection_sha256=foreign_before['foreign_projection_sha256'],
                foreign_mid_sha256=mid_sha256)

        return DualDenyWitness(
            ipv4=witness(4, challenge4, positive4, identity4, raw0, raw1, count1 - count0),
            ipv6=witness(6, challenge6, positive6, identity6, raw1, raw2, count2 - count1),
            schema=DUAL_SCHEMA,
            trace_batch_sha256=hashlib.sha256(batch).hexdigest(),
            combined_trace_sha256=hashlib.sha256(combined).hexdigest(),
            unattributed_trace_sha256=hashlib.sha256(unattributed).hexdigest(),
            foreign_before_sha256=_foreign_digest(foreign_before),
            foreign_mid_sha256=mid_sha256,
            foreign_after_sha256=_foreign_digest(foreign_after),
            ipv4_dwell_seconds=round(finished_at - arm4, 3),
            ipv6_dwell_seconds=round(finished_at - arm6, 3))
    finally:
        try:
            if monitor is not None:
                monitor.kill() if monitor.poll() is None else None
                monitor_stdout_residual, monitor_stderr = monitor.communicate(timeout=2)
            if installed:
                # An independent armed rollback remains responsible if this fails.
                try:
                    _command(fd, ["delete", "table", "inet", TRACE_TABLE])
                    installed = False
                except BaseException:
                    pass
            if armed and not installed:
                rollback.disarm()
        finally:
            os.close(fd)
            if trace_failure is not None:
                try:
                    failed_digest, (category, phase, trace_bytes, trace_truncated,
                                    status, failed_errno) = trace_failure
                    residual_capacity = MAX_TRACE - len(trace_bytes)
                    _write_trace_subscription_failure(
                        failed_digest, category, phase, trace_bytes, trace_truncated,
                        monitor_stdout_residual[:residual_capacity],
                        len(monitor_stdout_residual) > residual_capacity,
                        monitor_stderr[:4096], status, failed_errno)
                except Exception:
                    # Diagnostic storage has no authority over the refusal.
                    pass
