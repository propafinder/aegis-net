#!/usr/bin/python3 -I
"""B-06 S16i-3 probes for harness/real-relay-window.sh.

Standard library only, and written for the system /usr/bin/python3 3.9.
Nothing here prints an address except the source6 and aaaa answers.

  tcp hc|nohc HOST PORT PAYLOAD [LIMIT_S]
      Timed TCP echo. Prints <bytes>/<ms>/<outcome>: the bytes received,
      the milliseconds from just before connect to the outcome, and how it
      ended. The whole probe, connect included, is bounded by LIMIT_S
      (default 10 s). Exit 0 only when exactly PAYLOAD came back in the
      expected way, 1 otherwise, 2 on bad arguments.
      hc:   connect, write PAYLOAD, shutdown(SHUT_WR), read to EOF.
            Outcome eof, reset or timeout (error for any other OSError).
      nohc: connect, write PAYLOAD, read len(PAYLOAD) bytes, close; no
            half-close. Outcome full, eof, reset or timeout (or error).
  source6 DEST
      The source address the kernel selects for a UDP connect() to DEST
      port 9. A UDP connect sends no packet.
  aaaa NAME [LIMIT_S]
      The first IPv6 address the system resolver returns for NAME as an app
      asks for it (AF_UNSPEC with AI_ADDRCONFIG), none, or timeout.
  scan64 ADDR...
      Reads a body on stdin; exit 1 when it carries an IPv6 address inside
      the /64 of any ADDR, 0 when it carries none, 2 on bad arguments.
      Prints nothing, so a physical address never reaches a log.
  boundsyn IFACE DST PORT COUNT SPORT LIMIT_S
      S20f positive control: COUNT TCP connects to the IPv4 DST:PORT, each
      bound to IFACE with IP_BOUND_IF and from the marked source port
      SPORT, SPORT+1, ... (1024..65535), each bounded by LIMIT_S (0.1..10).
      Prints only `probes=N failed=F kinds=<kind>:<n>,... ms=<ms>` (kinds:
      timeout, refused, reset, connected or the errno name), never the
      address. Exit 0 only when every probe timed out (sent and never
      answered, what a filter that drops it gives); 1 when one was
      answered (connected, refused or reset: the SYN left and an answer
      came back); 3 when none was answered but not every probe timed out
      (an error before or while sending, such as eaddrinuse or
      ehostunreach: such a probe says nothing about a filter); 2 on bad
      arguments or an unknown interface.
  presock IFACE DST PORTS N STATE LIMIT_S WAIT_S LIFETIME_S [KEEPALIVE]
      S20g pre-existing sockets, a helper that stays up for the window.
      Before the tunnel: the first port of PORTS (comma-separated, 1..4
      distinct, tried in that order) that the IPv4 DST accepts within
      LIMIT_S (0.1..10) on a socket bound to IFACE with IP_BOUND_IF, then N
      (1..4) TCP connections to it bound the same way, each with
      SO_KEEPALIVE and a short TCP_KEEPALIVE/TCP_KEEPINTVL/TCP_KEEPCNT
      (KEEPALIVE `idle/intvl/cnt`, idle and intvl 1..10 s, cnt 2..120;
      default PRESOCK_KEEPALIVE), so the kernel keeps probing them. S20h:
      each of the N binds to the first free source port of the provider's
      marker range (PRESOCK_MARK_SPORT_FIRST, PRESOCK_MARK_SPORT_COUNT
      ports; leak_guard::MARK_SPORT_FIRST), so the filter counts the drops
      of its segments and kernel keepalives as marked: XNU's keepalives
      carry the connection's ports but the system default TTL, so a TTL
      cannot mark them. They close with SO_LINGER 0 (a reset, no TIME_WAIT
      left on a marker port); the port probe uses an ephemeral port. STATE,
      a JSON
      file created mode 0600 and replaced atomically, records the phase
      (selecting, then open, unavailable when DST accepts none of PORTS, or
      failed when none of the N connected), the chosen port, the local
      ports and (S20h) each socket's connect time and the marker range;
      DST itself is never written. Then it waits for commands in
      STATE.cmd: `write` writes a few marked bytes on each socket at a
      recorded time and, within WAIT_S (0.5..30), reads TCP_CONNECTION_INFO
      to see whether they were acknowledged (phase written, `write`
      outcomes: acked, unacked, reset, rx, timed_out, closed or
      not_written; S20h: a socket not written because it had closed
      records why, `cause` reset or timed_out from SO_ERROR); `close`
      closes the sockets (phase closed). It closes
      them by itself after LIFETIME_S (5..7200, phase expired) or once its
      parent is gone (phase orphaned). Prints nothing; exit 0 after a
      close, expiry or orphaning, 3 when unavailable, 1 when failed, 2 on
      bad arguments or an unknown interface.
"""
import errno
import ipaddress
import json
import os
import re
import socket
import struct
import sys
import threading
import time

RESET_ERRNOS = (errno.ECONNRESET, errno.ECONNREFUSED, errno.ECONNABORTED, errno.EPIPE)
SHUTDOWN_RACE_ERRNOS = (errno.ENOTCONN, errno.EINVAL) + RESET_ERRNOS
KEEP = 4096


def tcp(mode, host, port, payload, limit):
    start = time.monotonic()
    deadline = start + limit
    got = b""
    count = 0
    outcome = "timeout"
    sock = None

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout("probe limit")
        return left

    try:
        sock = socket.create_connection((host, port), timeout=remaining())
        sock.settimeout(remaining())
        sock.sendall(payload)
        if mode == "hc":
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError as error:
                # A reset that raced the shutdown shows up on the read below.
                if error.errno not in SHUTDOWN_RACE_ERRNOS:
                    raise
        while True:
            sock.settimeout(remaining())
            chunk = sock.recv(4096)
            if not chunk:
                outcome = "eof"
                break
            count += len(chunk)
            if len(got) < KEEP:
                got += chunk[:KEEP - len(got)]
            if mode == "nohc" and count >= len(payload):
                outcome = "full"
                break
    except socket.timeout:
        outcome = "timeout"
    except OSError as error:
        if isinstance(error, (ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError,
                              BrokenPipeError)) or error.errno in RESET_ERRNOS:
            outcome = "reset"
        else:
            outcome = "error"
            sys.stderr.write(f"net_probe: tcp {type(error).__name__} errno={error.errno}\n")
    finally:
        if sock is not None:
            sock.close()
    ms = int((time.monotonic() - start) * 1000)
    print(f"{count}/{ms}/{outcome}")
    wanted = "eof" if mode == "hc" else "full"
    return 0 if outcome == wanted and got == payload and count == len(payload) else 1


def source6(dest):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.connect((dest, 9))
        print(sock.getsockname()[0].split("%")[0])
        return 0
    except OSError as error:
        print(f"error:{type(error).__name__}")
        return 1
    finally:
        sock.close()


def aaaa(name, limit):
    answer = []

    def lookup():
        try:
            infos = socket.getaddrinfo(name, 80, socket.AF_UNSPEC, socket.SOCK_STREAM, 0,
                                       socket.AI_ADDRCONFIG)
            v6 = [i[4][0].split("%")[0] for i in infos if i[0] == socket.AF_INET6]
            answer.append(v6[0] if v6 else "none")
        except socket.gaierror:
            answer.append("none")
        except OSError as error:
            answer.append(f"error:{type(error).__name__}")

    worker = threading.Thread(target=lookup, daemon=True)
    worker.start()
    worker.join(limit)
    print(answer[0] if answer else "timeout")
    return 0


TOKEN = re.compile(r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*")


def scan64(addrs, body):
    nets = {ipaddress.IPv6Network(f"{ipaddress.IPv6Address(a)}/64", strict=False) for a in addrs}
    for token in TOKEN.findall(body):
        for candidate in (token, token.strip(":"), token.lstrip(":"), token.rstrip(":")):
            try:
                seen = ipaddress.IPv6Address(candidate)
            except ValueError:
                continue
            if any(seen in net for net in nets):
                return 1
    return 0


# <netinet/in.h> on Darwin: bind a socket's output to one interface.
IP_BOUND_IF = 25
# boundsyn kinds that need the SYN to leave and an answer to come back: a
# filter that drops the probe never yields one of them.
ANSWERED = ("connected", "refused", "reset")


def boundsyn_kind(error):
    """The kind of one failed probe connect."""
    if isinstance(error, socket.timeout) or error.errno == errno.ETIMEDOUT:
        return "timeout"
    if isinstance(error, ConnectionRefusedError) or error.errno == errno.ECONNREFUSED:
        return "refused"
    if isinstance(error, ConnectionResetError) or error.errno == errno.ECONNRESET:
        return "reset"
    return errno.errorcode.get(error.errno, "error").lower()


def boundsyn(iface, dst, port, count, sport, limit):
    index = socket.if_nametoindex(iface)
    kinds = {}
    connected = 0
    start = time.monotonic()
    for k in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, index)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", sport + k))
            sock.settimeout(limit)
            sock.connect((dst, port))
            connected += 1
            kind = "connected"
        except OSError as error:
            kind = boundsyn_kind(error)
        finally:
            sock.close()
        kinds[kind] = kinds.get(kind, 0) + 1
    ms = int((time.monotonic() - start) * 1000)
    print(f"probes={count} failed={count - connected} "
          f"kinds={','.join(f'{k}:{v}' for k, v in sorted(kinds.items()))} ms={ms}")
    if any(kinds.get(kind) for kind in ANSWERED):
        return 1
    return 0 if kinds.get("timeout", 0) == count else 3


# S20g. <netinet/tcp.h> on Darwin (MacOSX SDK): keepalive idle time,
# interval and count, and the connection-info getsockopt.
TCP_KEEPALIVE = 0x10
TCP_KEEPINTVL = 0x101
TCP_KEEPCNT = 0x102
TCP_CONNECTION_INFO = 0x106
# struct tcp_connection_info: tcpi_state, tcpi_snd_wscale, tcpi_rcv_wscale
# and __pad1 (u_int8_t each); 13 u_int32_t from tcpi_options to the TFO bit
# field; 7 u_int64_t, aligned(8), from offset 56. 112 bytes, little endian.
CONNECTION_INFO = struct.Struct("<BBBx13I7Q")
CONNECTION_INFO_FIELDS = (
    "state", "snd_wscale", "rcv_wscale", "options", "flags", "rto", "maxseg", "snd_ssthresh", "snd_cwnd",
    "snd_wnd", "snd_sbbytes", "rcv_wnd", "rttcur", "srtt", "rttvar", "tfo", "txpackets", "txbytes",
    "txretransmitbytes", "rxpackets", "rxbytes", "rxoutoforderbytes", "txretransmitpackets")
# <netinet/tcp_fsm.h>, TCPS_CLOSED (0) to TCPS_TIME_WAIT (10).
TCP_STATES = ("closed", "listen", "syn_sent", "syn_received", "established", "close_wait", "fin_wait_1",
              "closing", "last_ack", "fin_wait_2", "time_wait")
TCPS_CLOSED = 0
# ESTABLISHED and CLOSE_WAIT (the gateway closed only its half): a socket
# the helper still writes on.
WRITABLE = (4, 5)
# Keepalive idle and interval (seconds) and count: the kernel probes an
# idle socket every 4 s while Connected, and an unanswered one survives
# about four minutes, past any window's write.
PRESOCK_KEEPALIVE = (4, 4, 60)
# S20h: the source ports the kept presock sockets bind to, the provider's
# marker range (leak_guard::MARK_SPORT_FIRST and MARK_SPORT_COUNT; a Rust
# test reads these two lines), so the filter counts their outbound drops,
# kernel keepalives included, as marked. XNU builds a keepalive in
# tcp_respond from the connection's template (its addresses and ports) and
# gives an IPv4 one the system default TTL (ip_defttl), never the socket's
# IP_TTL, while every segment and keepalive of a connection carries its
# ports by construction. Below the ephemeral range and the fresh probes'
# PC_SPORT_BASE (47100).
PRESOCK_MARK_SPORT_FIRST = 47000
PRESOCK_MARK_SPORT_COUNT = 32
PRESOCK_SCHEMA = "aegis-presock-v1"
PRESOCK_POLL_S = 0.05
# The outcomes of a written socket that need an answer from the gateway:
# an ACK of the written bytes, its RST, or data it sent.
PRESOCK_ANSWERED = ("acked", "reset", "rx")
# S20h: why a closed socket was not written, from its SO_ERROR.
PRESOCK_CLOSED_CAUSES = {errno.ECONNRESET: "reset", errno.ETIMEDOUT: "timed_out"}


def parse_connection_info(raw):
    """struct tcp_connection_info as a dict of CONNECTION_INFO_FIELDS."""
    if len(raw) < CONNECTION_INFO.size:
        raise ValueError(f"tcp_connection_info of {len(raw)} bytes, not {CONNECTION_INFO.size}")
    return dict(zip(CONNECTION_INFO_FIELDS, CONNECTION_INFO.unpack(raw[:CONNECTION_INFO.size])))


def tcp_state_name(state):
    return TCP_STATES[state] if 0 <= state < len(TCP_STATES) else f"state_{state}"


def presock_marker(k):
    """The few marked bytes written on socket k."""
    return b"aegis-s20g-presock-%d\n" % k


def errno_name(error):
    return errno.errorcode.get(error.errno, "error").lower()


class Presock:
    """S20g: the pre-existing sockets of one interface (`presock` above).

    socket, info, send and so_error are its only socket calls besides
    bind and connect on a new socket; the window tests replace them to
    stand in for a filter on loopback."""

    def __init__(self, iface, dst, ports, n, path, limit, wait, lifetime, keepalive=PRESOCK_KEEPALIVE):
        self.iface, self.dst, self.ports, self.n = iface, dst, ports, n
        self.path, self.limit, self.wait, self.lifetime = path, limit, wait, lifetime
        self.keepalive = tuple(keepalive)
        self.index = socket.if_nametoindex(iface)
        self.socks, self.lports = [], []
        self.doc = {"schema": PRESOCK_SCHEMA, "pid": os.getpid(), "iface": iface, "phase": "selecting", "n": n,
                    "mark_sport": [PRESOCK_MARK_SPORT_FIRST, PRESOCK_MARK_SPORT_COUNT]}

    def socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, self.index)
        return sock

    def info(self, sock):
        return parse_connection_info(sock.getsockopt(socket.IPPROTO_TCP, TCP_CONNECTION_INFO, CONNECTION_INFO.size))

    def send(self, sock, data):
        return sock.send(data)

    def so_error(self, sock):
        return sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)

    def save(self):
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(self.doc, handle, sort_keys=True)
            handle.write("\n")
        os.replace(tmp, self.path)

    def connect(self, port, keepalive):
        """One bounded connect to DST:port: (socket or None, kind). S20h: a
        kept socket (keepalive) first binds to the first source port of the
        marker range that is free (EADDRINUSE at the bind or the connect
        moves on to the next one; eaddrinuse when none is), and closes
        with SO_LINGER 0."""
        if not keepalive:
            return self.connect_from(port, None)
        for lport in range(PRESOCK_MARK_SPORT_FIRST, PRESOCK_MARK_SPORT_FIRST + PRESOCK_MARK_SPORT_COUNT):
            if lport in self.lports:
                continue
            sock, kind = self.connect_from(port, lport)
            if kind != "eaddrinuse":
                return sock, kind
        return None, "eaddrinuse"

    def connect_from(self, port, lport):
        sock = self.socket()
        try:
            if lport is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                for option, value in zip((TCP_KEEPALIVE, TCP_KEEPINTVL, TCP_KEEPCNT), self.keepalive):
                    sock.setsockopt(socket.IPPROTO_TCP, option, value)
                sock.bind(("0.0.0.0", lport))
            sock.settimeout(self.limit)
            sock.connect((self.dst, port))
            sock.setblocking(False)
            return sock, "connected"
        except OSError as error:
            sock.close()
            return None, boundsyn_kind(error)

    def select(self):
        """The first of PORTS that DST accepts, in their order; None when
        it accepts none."""
        kinds = {}
        for port in self.ports:
            sock, kind = self.connect(port, False)
            kinds[kind] = kinds.get(kind, 0) + 1
            if sock is not None:
                sock.close()
                self.doc["select_kinds"] = kinds
                return port
        self.doc["select_kinds"] = kinds
        return None

    def open(self):
        """Before the tunnel: the port, then the N sockets. True when at
        least one of them connected."""
        port = self.select()
        if port is None:
            self.doc.update(phase="unavailable", opened=0)
            self.save()
            return False
        sockets = []
        for _ in range(self.n):
            sock, kind = self.connect(port, True)
            entry = {"kind": kind}
            if sock is not None:
                # S20h: the SYN-ACK arrived just before connect returned:
                # the socket's last receive until anything else arrives,
                # from which its keepalives are timed.
                connected = time.time()
                self.socks.append(sock)
                self.lports.append(sock.getsockname()[1])
                entry.update(lport=self.lports[-1], state=tcp_state_name(self.info(sock)["state"]),
                             t_connected=connected)
            sockets.append(entry)
        self.doc.update(phase="open" if self.socks else "failed", port=port, opened=len(self.socks),
                        sockets=sockets, keepalive=list(self.keepalive), t_open=time.time())
        self.save()
        return bool(self.socks)

    def settle(self, entry, sock, before, sent):
        """One reading of a written socket: its outcome once decided, else
        None. Any of the written bytes acknowledged is acked; a socket that
        closed is reset (ECONNRESET), timed_out (ETIMEDOUT) or closed."""
        now = self.info(sock)
        entry.update(state_after=tcp_state_name(now["state"]), sb_after=now["snd_sbbytes"],
                     tx_packets=now["txpackets"] - before["txpackets"],
                     retx_packets=now["txretransmitpackets"] - before["txretransmitpackets"],
                     rx_packets=now["rxpackets"] - before["rxpackets"])
        if now["state"] == TCPS_CLOSED:
            code = self.so_error(sock)
            return {errno.ECONNRESET: "reset", errno.ETIMEDOUT: "timed_out"}.get(code, "closed")
        if now["snd_sbbytes"] < before["snd_sbbytes"] + sent:
            return "acked"
        return None

    def write(self):
        """While Connected and armed: the marked bytes on every socket, then
        TCP_CONNECTION_INFO readings for up to WAIT_S. A written socket
        still unacknowledged at the end is unacked, or rx when the gateway's
        data reached it meanwhile."""
        entries, pending = [], []
        t_write = time.time()
        for k, sock in enumerate(self.socks):
            entry = {"lport": self.lports[k]}
            entries.append(entry)
            try:
                before = self.info(sock)
                entry["state_before"] = tcp_state_name(before["state"])
                if before["state"] not in WRITABLE:
                    entry["outcome"] = "not_written"
                    # S20h: a socket the gateway reset or that timed out
                    # before the write says so, never a bare not_written.
                    cause = PRESOCK_CLOSED_CAUSES.get(self.so_error(sock)) if before["state"] == TCPS_CLOSED else None
                    if cause:
                        entry["cause"] = cause
                    continue
                sent = self.send(sock, presock_marker(k))
            except OSError as error:
                entry.update(outcome="not_written", error=errno_name(error))
                if error.errno in PRESOCK_CLOSED_CAUSES:
                    entry["cause"] = PRESOCK_CLOSED_CAUSES[error.errno]
                continue
            entry["bytes"] = sent
            pending.append((entry, sock, before, sent))
        deadline = time.monotonic() + self.wait
        while True:
            last = time.monotonic() >= deadline
            for entry, sock, before, sent in pending:
                if "outcome" in entry:
                    continue
                try:
                    outcome = self.settle(entry, sock, before, sent)
                except OSError as error:
                    outcome = "closed"
                    entry["error"] = errno_name(error)
                if outcome is not None:
                    entry.update(outcome=outcome, ms=int((time.time() - t_write) * 1000))
                elif last:
                    entry["outcome"] = "rx" if entry.get("rx_packets", 0) > 0 else "unacked"
            if last or all("outcome" in entry for entry, _, _, _ in pending):
                break
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
        counts = {}
        for entry in entries:
            counts[entry["outcome"]] = counts.get(entry["outcome"], 0) + 1
        self.doc["write"] = {"t_write": t_write, "t_done": time.time(), "wait_s": self.wait,
                             "written": len(pending), "counts": counts, "sockets": entries}

    def run(self):
        parent = os.getppid()
        self.save()
        if not self.open():
            return 3 if self.doc["phase"] == "unavailable" else 1
        end = time.monotonic() + self.lifetime
        command = self.path + ".cmd"
        phase = "expired"
        while time.monotonic() < end:
            if os.getppid() != parent:
                phase = "orphaned"
                break
            try:
                with open(command) as handle:
                    text = handle.read().strip()
                os.unlink(command)
            except OSError:
                text = ""
            if text == "close":
                phase = "closed"
                break
            if text == "write" and "write" not in self.doc:
                self.write()
                self.doc["phase"] = "written"
                self.save()
            time.sleep(PRESOCK_POLL_S)
        for sock in self.socks:
            sock.close()
        self.doc.update(phase=phase, t_closed=time.time())
        self.save()
        return 0


def keepalive_arg(text):
    """S20h: `idle/intvl/cnt` as a tuple of ints, idle and intvl 1..10 s,
    cnt 2..120."""
    parts = text.split("/")
    if len(parts) != 3 or not all(re.fullmatch(r"[1-9][0-9]{0,2}", p) for p in parts):
        raise ValueError("bad keepalive")
    idle, intvl, cnt = (int(p) for p in parts)
    if not (1 <= idle <= 10 and 1 <= intvl <= 10 and 2 <= cnt <= 120):
        raise ValueError("bad keepalive")
    return idle, intvl, cnt


def presock_args(argv):
    """The validated arguments of `presock`, in Presock's order (S20h: an
    optional ninth, the keepalive, is validated here and returned by
    presock_keepalive)."""
    if len(argv) not in (8, 9):
        raise ValueError("presock takes 8 or 9 arguments")
    iface, dst, ports, n, path = argv[0], argv[1], argv[2], int(argv[3]), argv[4]
    limit, wait, lifetime = float(argv[5]), float(argv[6]), float(argv[7])
    presock_keepalive(argv)
    ipaddress.IPv4Address(dst)
    ports = [int(p) for p in ports.split(",")]
    if (not 1 <= len(ports) <= 4 or len(set(ports)) != len(ports) or not all(0 < p < 65536 for p in ports)
            or not 1 <= n <= 4 or not path or not 0.1 <= limit <= 10 or not 0.5 <= wait <= 30
            or not 5 <= lifetime <= 7200):
        raise ValueError("bad presock arguments")
    return iface, dst, ports, n, path, limit, wait, lifetime


def presock_keepalive(argv):
    """S20h: the keepalive of `presock` arguments, PRESOCK_KEEPALIVE when
    the ninth is not given."""
    return keepalive_arg(argv[8]) if len(argv) == 9 else PRESOCK_KEEPALIVE


def kinds_text(kinds):
    return ",".join(f"{k}:{v}" for k, v in sorted(kinds.items())) if kinds else "none"


def presock_read(path, mode):
    """`presock-read STATE MODE`: one line from a helper's STATE for the
    window. phase: the phase (none without a readable STATE). open: the
    phase and counts, never a port. write: the outcome counts of the write
    and the packet deltas summed (none before the write). times: its write
    and end times. ports: the chosen port and the local ports, for argv
    only (empty without them)."""
    try:
        with open(path) as handle:
            doc = json.load(handle)
        if not isinstance(doc, dict) or doc.get("schema") != PRESOCK_SCHEMA:
            raise ValueError("not a presock state")
    except (OSError, ValueError):
        doc = None
    if mode == "phase":
        return doc["phase"] if doc else "none"
    if mode == "ports":
        if not doc or not isinstance(doc.get("port"), int):
            return ""
        lports = [s["lport"] for s in doc.get("sockets", []) if isinstance(s.get("lport"), int)]
        return " ".join(str(p) for p in [doc["port"]] + lports)
    if mode == "open":
        if not doc:
            return "none"
        phase = doc["phase"]
        if phase == "selecting":
            return phase
        head = f"{phase} opened={doc.get('opened', 0)} need={doc.get('n', '?')}"
        if phase == "unavailable":
            return f"{head} select={kinds_text(doc.get('select_kinds'))}"
        kinds = {}
        for entry in doc.get("sockets", []):
            kinds[entry.get("kind", "?")] = kinds.get(entry.get("kind", "?"), 0) + 1
        return f"{head} kinds={kinds_text(kinds)} keepalive={'/'.join(str(v) for v in doc.get('keepalive', []))}"
    write = doc.get("write") if doc else None
    if not isinstance(write, dict):
        return "none"
    if mode == "times":
        return f"{write['t_write']:.6f} {write['t_done']:.6f}"
    counts = write.get("counts", {})
    sockets = write.get("sockets", [])
    total = {key: sum(s.get(key, 0) for s in sockets) for key in ("tx_packets", "retx_packets", "rx_packets")}
    # S20h: why closed sockets were not written, only when any was.
    causes = {}
    for entry in sockets:
        if entry.get("cause") in PRESOCK_CLOSED_CAUSES.values():
            causes[entry["cause"]] = causes.get(entry["cause"], 0) + 1
    return (f"written={write.get('written', 0)} "
            + " ".join(f"{k}={counts.get(k, 0)}" for k in ("acked", "unacked", "reset", "rx", "timed_out", "closed",
                                                          "not_written"))
            + f" answered={sum(counts.get(k, 0) for k in PRESOCK_ANSWERED)}"
            + f" tx={total['tx_packets']} retx={total['retx_packets']} rx_packets={total['rx_packets']}"
            + f" wait={write.get('wait_s', 0):g}s"
            + (f" not_written_causes={kinds_text(causes)}" if causes else ""))


def main(argv):
    try:
        cmd = argv[0]
        if cmd == "tcp":
            mode, host, port, payload = argv[1], argv[2], int(argv[3]), argv[4].encode()
            limit = float(argv[5]) if len(argv) > 5 else 10.0
            if mode not in ("hc", "nohc") or not payload or not 0 < port < 65536 or not limit > 0:
                raise ValueError("bad tcp arguments")
            return tcp(mode, host, port, payload, limit)
        if cmd == "source6":
            return source6(argv[1])
        if cmd == "aaaa":
            return aaaa(argv[1], float(argv[2]) if len(argv) > 2 else 5.0)
        if cmd == "scan64":
            return scan64(argv[1:], sys.stdin.read())
        if cmd == "boundsyn":
            iface, dst, port, count, sport, limit = argv[1], argv[2], int(argv[3]), int(argv[4]), int(argv[5]), \
                float(argv[6])
            ipaddress.IPv4Address(dst)
            if (len(argv) != 7 or not 0 < port < 65536 or not 1 <= count <= 10
                    or not 1024 <= sport <= 65535 - count + 1 or not 0.1 <= limit <= 10):
                raise ValueError("bad boundsyn arguments")
            try:
                return boundsyn(iface, dst, port, count, sport, limit)
            except OSError as error:
                sys.stderr.write(f"net_probe: boundsyn {type(error).__name__} errno={error.errno}\n")
                return 2
        if cmd == "presock":
            args = presock_args(argv[1:])
            try:
                helper = Presock(*args, keepalive=presock_keepalive(argv[1:]))
            except OSError as error:
                sys.stderr.write(f"net_probe: presock {type(error).__name__} errno={error.errno}\n")
                return 2
            try:
                return helper.run()
            except (OSError, ValueError) as error:
                sys.stderr.write(f"net_probe: presock {type(error).__name__} errno={getattr(error, 'errno', None)}\n")
                return 1
        if cmd == "presock-read":
            if len(argv) != 3 or argv[2] not in ("phase", "open", "write", "times", "ports"):
                raise ValueError("bad presock-read arguments")
            print(presock_read(argv[1], argv[2]))
            return 0
        raise ValueError(f"unknown command {cmd!r}")
    except (IndexError, ValueError) as error:
        sys.stderr.write(f"net_probe: {type(error).__name__}: {error}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
