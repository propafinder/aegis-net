#!/usr/bin/python3 -I
"""B-06 S20 leak review of one real-relay window's physical capture.

Reads the classic pcap or pcapng file that harness/real-relay-window.sh
records on the physical interface with LEAK_CAPTURE=1, and the window's
Connected interval (wall-clock seconds), and reports every packet inside
that interval, less a guard at each end, that is not relay transport.
A relay packet is TCP or UDP (--relay-proto) between the relay IP and its
transport port (--relay-port) on the relay side; any other packet to or
from the relay IP (echo, whoami, ICMP, another port) is a leak, since the
window's own test flows target that host. Only link-local control traffic
is excluded, and counted separately: ARP, DHCP, IPv6 neighbour discovery /
router discovery / MLD, mDNS to 224.0.0.251 or ff02::fb, and LAN-local
broadcast. Everything else counts as a leak, fail closed: other IP traffic,
non-IP frames, packets that do not parse, and packets without a timestamp.

Each leak also carries a diagnostic class, counted in leak_classes, that
never changes pass: link_control (EAPOL, LLDP, 802.3 LLC such as STP),
igmp (IGMP to an IPv4 multicast group), foreign (with --local-mac: neither
Ethernet address is the Mac's and the IP source is neither a local address
nor the tunnel address) and host (everything else, the Mac's own traffic).
leak_families counts the same leaks by IP family (ipv4, ipv6, other for
non-IP and unparsed frames); the window's no_v6_leak_physical row reads it.

S20a: a flow table over the WHOLE capture (before connect, the guards and
after disconnect included) attributes every host leak to its flow's origin,
counted in leak_origins with the other classes so that the counts sum to
leak_count, and never changes pass: host_preexisting (the flow has a packet
before connected_at), host_preexisting_inferred (TCP first seen after
connected_at in mid-stream, with no SYN since the capture began),
host_new_outbound (a SYN or SYN-ACK at or after connected_at, or a UDP or
ICMP echo flow whose first packet is the Mac's and comes at or after
connected_at), host_new_inbound (a peer's SYN or first UDP/echo packet at or
after connected_at) and host_unattributed (no flow identity: other
protocols, later fragments, untimed packets, an ICMP error whose quoted
header is unreadable or names no captured flow). An ICMP error takes the
origin of the flow its quoted header names. new_outbound_flows counts the
distinct flows behind host_new_outbound; leak_flows counts distinct flows per
origin; host_outbound counts the Mac's own host leaks by kind (tcp_syn,
tcp_data, tcp_keepalive: a zero-length ACK the peer later acknowledges with
ack = seq + 1, tcp_control, udp, dns, icmp_error, icmp_echo_reply,
icmp_echo_request, icmp_other, other). Payload lengths come from the IP,
TCP and UDP length fields only; no payload byte is read or written.

pass is true only when there are no leaks and at least one relay packet
was seen inside the interval. Standard library only; python3 -I.

S20d, a separate criterion that never changes pass, leak_count, the
classes, origins or families, or the exit code: mac_sent_leaks counts the
frames inside the same reviewed interval that the Mac itself sent: its
Ethernet source is --local-mac, or its IP source is a local address or the
tunnel address. Only these are excluded from it: relay transport (the same
is_relay rule), ARP, DHCPv4/DHCPv6, IPv6 neighbour/router discovery and
MLD, and EAPOL (802.1X link keys). Everything else the Mac sent counts,
mDNS, LAN broadcast and IGMP included, so on the Mac's own frames it is at
least as strict as pass except for EAPOL alone. Fail closed: an unparsed or
untimed frame counts as Mac-sent unless its Ethernet source is present and
is not the Mac's. Frames other devices sent, and arrivals to the Mac, never
count: no client can stop them. mac_sent_classes counts the same frames by
class (tcp_syn, tcp_keepalive, tcp_data, tcp_control, udp, dns, mdns,
broadcast, igmp, icmp_error, icmp_echo_reply, icmp_echo_request,
icmp_other, link_control, unparsed, other), mac_sent_origins by the flow
origins above (no host_ prefix) and mac_sent_frames lists them like leaks.
mac_sent_guard counts the same frames inside the guard seconds at each end
(diagnostic only). mac_sent_pass is true only with mac_sent_leaks == 0, at
least one relay packet inside the interval and no mac_sent_error, which
records why it cannot pass otherwise: no Connected interval, no relay
packet, or no --local-mac (without the Mac's address its own frames cannot
be told from other devices' frames). --relay-optional, for an interface
that carries no relay traffic (a second active interface), drops only the
relay-packet term from mac_sent_pass; pass stays as it is. The summary line
ends with mac_sent_leaks=N mac_sent_pass=true|false.

S20e: --mac-sent-mac and --mac-sent-addr (each repeatable) name further
identities of the Mac for the Mac-sent criterion only: the MACs and
addresses of its other interfaces, and of every interface before connect
and right before the disconnect (a rotated private Wi-Fi address after a
rejoin, a bridge whose frames leave through a member port). A frame from
any of them is the Mac's; with --local-mac an unparsed or untimed frame
then counts unless its Ethernet source is present and is none of them, so
more identities only ever add Mac-sent frames. pass and every strict field
ignore them; --local-mac alone still decides no_local_mac. An unreadable
--mac-sent-addr makes mac_sent_pass false (mac_sent_error) instead of
failing the review. mac_sent_identity counts the MACs and addresses the
criterion used, never naming one.

S20f: --armed-at and --disarmed-at (wall-clock seconds, from the provider's
`leak_guard_span armed|disarmed seq:N wall:T` lines; the armed time is read
right after the gate guards and the disarmed time right before it opens,
so the span lies inside the guarded time) add a second Mac-sent pass over
[armed_at, disarmed_at], with no guard seconds and no relay term:
mac_sent_armed_leaks, mac_sent_armed_classes, mac_sent_armed_origins and
mac_sent_armed_frames, by the same rules and identities as mac_sent_leaks
(an untimed frame counts there too). mac_sent_armed_span records the span
(null without it) and mac_sent_armed_error why it could not be reviewed (one
bound only, an inverted span, or a review that ended early). It never
changes pass, mac_sent_pass, any other field, the summary line or the exit
code; the window fails no_mac_sent_leak_physical when it counts a frame.

S20f: `leak_review.py probe-syns --pcap F --dst IP --dport P --sport-min A
--sport-max B` counts the TCP SYNs (without ACK) to IP:P from a source port
in A..B, the positive control's marked probes, and prints only
`probe_syns=N total=M` (exit 0; `probe_syns=unreadable`, exit 2, when the
capture cannot be read). No address is printed.

S20g: `leak_review.py presock-frames --pcap F --dst IP --dport P --sport S
[--sport S ...] [--since T] [--until T]` counts the TCP frames to IP:P from
one of the source ports S (the pre-existing sockets of net_probe.py
presock), timed within [T, T'] when given (an untimed frame always
counts), and prints only `presock_frames=N data=D ack_only=A other=O
total=M ack_only_marked=K`: data carries payload, ack_only is a bare ACK
(keepalives among them), other is anything else (SYN, FIN, RST, or no
readable length); (S20h review) K counts the bare ACKs whose source port
lies in the provider's marker range (MARK_SPORT_FIRST, MARK_SPORT_COUNT),
the field the filter marks the helper's keepalives by, so a filter-off
capture shows the marker on the wire. Exit 0;
`presock_frames=unreadable`, exit 2, when the capture cannot be read. No
address or port is printed.

S20h: `leak_review.py presock-review --pcap F --state S --dst IP --dev IF
--before B --after A [--span-before SB --span-after SA] [--armed-at T
--disarmed-at T'] [--tol S]` reviews one interface's pre-existing sockets
of a positive control (net_probe.py presock state S, the gateway IP, the
interface IF) from the two --filter-status outputs around the write (B, A),
the window's first and last --filter-status (SB, SA) and the provider's
armed span. It prints three lines, counts and tokens only, never an
address or port:
1. `presock_keepalive_drops`: `pass`, `fail` or `unavailable`, a reason
   and the counts. Each socket's keepalives are due at t_rx + idle + (k-1)
   * intvl, t_rx its last frame from the gateway in F before the arm (else
   its connect time from S, `rx=helper`): while armed the filter drops
   every inbound frame, so TCP's receive time stands still. Pass needs both
   reads guarding under one arm, a v29 provider (`outbound`) whose marker
   (a range of TCP source ports, `mark_sport_first` and
   `mark_sport_count`) is the helper's (`mark_sport`) with every socket
   bound inside it (else `unavailable mark_mismatch`), at least two due
   keepalives per socket strictly inside
   the reads (T with tolerance), the marked bare-ACK drops of IF's class
   grown by at least all of them, the outbound ring holding every record
   between the reads, and IF's marked bare-ACK records matching every due
   keepalive within the tolerance. When marked data drops appear they must
   cover every data segment the sockets sent (`tx`). `fail` only for reads
   that were not guarding, not under one arm or not parsed.
2. `presock_counted`: `tx= data_counted= blocked_before_filter=
   keepalive_expected= keepalive_counted= class=`: data segments the
   sockets sent (TCP_CONNECTION_INFO, retransmissions included), how many
   the filter counted as marked data drops, the rest (they never reached
   the filter), and the keepalives due and counted.
3. The helper's frames in F during the armed span: `frames=N data=D
   ack_only=A other=O uncounted=U total=M after_disarm=K
   tap_evidence=post_filter|none`, U the frames of a kind beyond that
   kind's marked drops of IF's class between SB and SA (all of them
   without a v29 provider), K the frames of F (anyone's) after the disarm,
   which show the capture ran through the armed span, and (S20h review)
   tap_evidence post_filter when, for one kind, the outbound ring holds
   more marked drops on IF between B and A than F holds frames from a
   source port of the marker range during the armed span: a tap before
   the filter records every frame the filter drops, so on a complete
   capture (the caller checks that and the armed span) the tap comes
   after the filter and every helper frame in F while armed left the Mac.
   Or `frames=unknown <reason>`.

Exit codes: 0 pass, 1 fail, 2 unreadable input (leak-review.json still
records pass=false with the error). mac_sent_pass never changes them.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import sys

GUARD_S = 1.0
MAX_LISTED = 1000

LINK_ETHERNET = 1
LINK_NULL = 0          # 4-byte host-order address family
LINK_LOOP = 108        # 4-byte network-order address family
LINK_RAW = (12, 14, 101)
LINK_IPV4 = 228
LINK_IPV6 = 229

AF_INET = 2
AF_INET6 = (10, 24, 28, 30)  # Linux, NetBSD/OpenBSD, FreeBSD, Darwin

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD
ETH_VLAN = (0x8100, 0x88A8, 0x9100)
ETH_LINK_CONTROL = {0x888E: "eapol", 0x88CC: "lldp"}

IPV6_EXT = (0, 43, 60, 51)   # hop-by-hop, routing, destination options, AH
IPV6_FRAG = 44
ICMPV6_ND = {133: "nd_rs", 134: "nd_ra", 135: "nd_ns", 136: "nd_na", 137: "nd_redirect"}
ICMPV6_MLD = {130: "mld_query", 131: "mld_report", 132: "mld_done", 143: "mld_report_v2"}

MDNS_V4 = ipaddress.ip_address("224.0.0.251")
MDNS_V6 = ipaddress.ip_address("ff02::fb")
LIMITED_BROADCAST = ipaddress.ip_address("255.255.255.255")
TUNNEL_ADDR = ipaddress.ip_address("198.19.255.1")
PROTO_NAMES = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 58: "icmpv6"}
PROTO_NUMBERS = {"tcp": 6, "udp": 17}
ICMP_ECHO = {1: (8, 0), 58: (128, 129)}          # (request, reply)
ICMP_ERRORS = {1: (3, 4, 5, 11, 12), 58: (1, 2, 3, 4)}
TCP_SYN, TCP_RST, TCP_FIN, TCP_ACK = 0x02, 0x04, 0x01, 0x10
DNS_PORTS = (53, 853)
ORIGINS = ("preexisting", "preexisting_inferred", "new_outbound", "new_inbound", "unattributed")
# S20d: the only control the Mac-sent criterion excludes (mDNS and LAN
# broadcast, excluded by pass, count), and EAPOL among the non-IP frames.
MAC_SENT_CONTROL = ("arp", "dhcp", "nd", "mld")
MAC_SENT_LINK = ("eapol",)
NO_LOCAL_MAC = "no --local-mac: the Mac's own frames cannot be told from other devices' frames"


class CaptureError(Exception):
    pass


# ---------------------------------------------------------------- reading

def read_capture(data):
    """Return the format and a list of (timestamp or None, linktype, frame)."""
    if len(data) < 4:
        raise CaptureError("file shorter than any capture header")
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        return "pcapng", list(_read_pcapng(data))
    for order, scale in (("<", 1e-6), (">", 1e-6), ("<", 1e-9), (">", 1e-9)):
        want = 0xA1B2C3D4 if scale == 1e-6 else 0xA1B23C4D
        if struct.unpack(order + "I", magic)[0] == want:
            return "pcap", list(_read_pcap(data, order, scale))
    raise CaptureError("not a pcap or pcapng file")


def _read_pcap(data, order, scale):
    if len(data) < 24:
        raise CaptureError("truncated pcap global header")
    linktype = struct.unpack(order + "I", data[20:24])[0] & 0x0FFFFFFF
    off = 24
    while off < len(data):
        if off + 16 > len(data):
            yield None, linktype, None  # truncated record header
            return
        sec, frac, caplen, _origlen = struct.unpack(order + "IIII", data[off:off + 16])
        off += 16
        if off + caplen > len(data):
            yield sec + frac * scale, linktype, None  # truncated record body
            return
        yield sec + frac * scale, linktype, data[off:off + caplen]
        off += caplen


def _read_pcapng(data):
    off = 0
    order = "<"
    interfaces = []
    while off < len(data):
        if off + 12 > len(data):
            yield None, None, None
            return
        raw_type = data[off:off + 4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            bom = data[off + 8:off + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                order = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                order = ">"
            else:
                raise CaptureError("pcapng section header with an unknown byte order")
            interfaces = []
        btype, blen = struct.unpack(order + "II", data[off:off + 8])
        if blen < 12 or blen % 4 or off + blen > len(data):
            yield None, None, None
            return
        body = data[off + 8:off + blen - 4]
        off += blen
        if btype == 1:  # interface description
            linktype = struct.unpack(order + "H", body[0:2])[0]
            interfaces.append(_idb_clock(body[8:], order) + (linktype,))
        elif btype in (6, 2):  # enhanced packet, obsolete packet
            if btype == 6:
                if len(body) < 20:
                    yield None, None, None
                    continue
                iface, hi, lo, caplen, _ = struct.unpack(order + "IIIII", body[:20])
            else:
                if len(body) < 20:
                    yield None, None, None
                    continue
                iface, _drops, hi, lo, caplen, _ = struct.unpack(order + "HHIIII", body[:20])
            frame = body[20:20 + caplen]
            if iface >= len(interfaces) or len(frame) < caplen:
                yield None, None, None
                continue
            resol, tsoffset, linktype = interfaces[iface]
            yield ((hi << 32) | lo) * resol + tsoffset, linktype, frame
        elif btype == 3:  # simple packet: no timestamp, interface 0
            if len(body) < 4 or not interfaces:
                yield None, None, None
                continue
            caplen = min(struct.unpack(order + "I", body[:4])[0], len(body) - 4)
            yield None, interfaces[0][2], body[4:4 + caplen]


def _idb_clock(options, order):
    resol, tsoffset = 1e-6, 0
    off = 0
    while off + 4 <= len(options):
        code, length = struct.unpack(order + "HH", options[off:off + 4])
        value = options[off + 4:off + 4 + length]
        off += 4 + (length + 3) // 4 * 4
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = value[0]
            resol = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        elif code == 14 and length >= 8:
            tsoffset = struct.unpack(order + "q", value[:8])[0]
    return resol, tsoffset


# ---------------------------------------------------------------- decoding

def decode(linktype, frame):
    """Return a dict describing the frame; kind 'unparsed' when it is not."""
    if frame is None or linktype is None:
        return {"kind": "unparsed", "reason": "truncated or orphan record"}
    try:
        if linktype == LINK_ETHERNET:
            return _ethernet(frame)
        if linktype in (LINK_NULL, LINK_LOOP):
            if len(frame) < 4:
                raise ValueError("short loopback header")
            fam = struct.unpack("<I" if linktype == LINK_NULL else ">I", frame[:4])[0]
            if linktype == LINK_NULL and fam > 0xFFFF:
                fam = struct.unpack(">I", frame[:4])[0]
            if fam == AF_INET:
                return _ipv4(frame[4:])
            if fam in AF_INET6:
                return _ipv6(frame[4:])
            return {"kind": "non_ip", "reason": f"loopback family {fam}"}
        if linktype in LINK_RAW:
            version = frame[0] >> 4 if frame else 0
            if version == 4:
                return _ipv4(frame)
            if version == 6:
                return _ipv6(frame)
            return {"kind": "unparsed", "reason": f"raw IP version {version}"}
        if linktype == LINK_IPV4:
            return _ipv4(frame)
        if linktype == LINK_IPV6:
            return _ipv6(frame)
        return {"kind": "unparsed", "reason": f"unsupported link type {linktype}"}
    except (ValueError, struct.error, IndexError) as error:
        return {"kind": "unparsed", "reason": str(error)}


def _ethernet(frame):
    if len(frame) < 14:
        raise ValueError("short Ethernet header")
    macs = {"eth_dst": frame[0:6].hex(":"), "eth_src": frame[6:12].hex(":")}
    ethertype = struct.unpack(">H", frame[12:14])[0]
    off = 14
    while ethertype in ETH_VLAN:
        if len(frame) < off + 4:
            raise ValueError("short VLAN tag")
        ethertype = struct.unpack(">H", frame[off + 2:off + 4])[0]
        off += 4
    payload = frame[off:]
    if ethertype == ETH_ARP:
        info = {"kind": "control", "control": "arp"}
    elif ethertype == ETH_IPV4:
        info = _ipv4(payload)
    elif ethertype == ETH_IPV6:
        info = _ipv6(payload)
    elif ethertype <= 1500:
        info = {"kind": "non_ip", "reason": f"802.3 length frame {ethertype}", "link_control": "llc"}
    else:
        info = {"kind": "non_ip", "reason": f"ethertype 0x{ethertype:04x}"}
        if ethertype in ETH_LINK_CONTROL:
            info["link_control"] = ETH_LINK_CONTROL[ethertype]
    info.update(macs)
    return info


def _ipv4(packet, quote=True):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        raise ValueError("short or invalid IPv4 header")
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl:
        raise ValueError("invalid IPv4 header length")
    total = struct.unpack(">H", packet[2:4])[0]
    frag = struct.unpack(">H", packet[6:8])[0]
    proto = packet[9]
    src = ipaddress.ip_address(packet[12:16])
    dst = ipaddress.ip_address(packet[16:20])
    info = {"kind": "ip", "family": 4, "src": src, "dst": dst, "proto": proto}
    if frag & 0x1FFF == 0:
        _ports(info, packet[ihl:], total - ihl, quote)
    return info


def _ipv6(packet, quote=True):
    if len(packet) < 40 or packet[0] >> 4 != 6:
        raise ValueError("short or invalid IPv6 header")
    payload = struct.unpack(">H", packet[4:6])[0]
    nxt = packet[6]
    src = ipaddress.ip_address(packet[8:24])
    dst = ipaddress.ip_address(packet[24:40])
    off = 40
    first_fragment = True
    for _ in range(16):
        if nxt in IPV6_EXT:
            if len(packet) < off + 2:
                raise ValueError("short IPv6 extension header")
            length = (packet[off + 1] + 2) * 4 if nxt == 51 else (packet[off + 1] + 1) * 8
            nxt = packet[off]
            off += length
        elif nxt == IPV6_FRAG:
            if len(packet) < off + 8:
                raise ValueError("short IPv6 fragment header")
            first_fragment = struct.unpack(">H", packet[off + 2:off + 4])[0] & 0xFFF8 == 0
            nxt = packet[off]
            off += 8
        else:
            break
    info = {"kind": "ip", "family": 6, "src": src, "dst": dst, "proto": nxt}
    if first_fragment:
        _ports(info, packet[off:], payload - (off - 40), quote)
    return info


def _ports(info, l4, l4_len, quote):
    """Header fields only: ports, TCP flags/seq/ack, lengths, ICMP type/id.

    l4_len is the L4 length the IP header declares; a payload length is
    recorded only when the declared lengths are consistent (an IPv4 total
    length of 0, as TSO captures show, leaves it unknown)."""
    proto = info["proto"]
    if proto in (6, 17) and len(l4) >= 4:
        info["sport"], info["dport"] = struct.unpack(">HH", l4[:4])
        if proto == 6 and len(l4) >= 14:
            info["tcp_flags"] = l4[13]
            info["tcp_seq"], info["tcp_ack"] = struct.unpack(">II", l4[4:12])
            header = (l4[12] >> 4) * 4
            if 20 <= header <= l4_len:
                info["payload_len"] = l4_len - header
        elif proto == 17 and len(l4) >= 8:
            length = struct.unpack(">H", l4[4:6])[0]
            if 8 <= length <= l4_len:
                info["payload_len"] = length - 8
    elif proto in (1, 58) and len(l4) >= 1:
        info["icmp_type"] = l4[0]
        if info["family"] != (4 if proto == 1 else 6):
            return   # ICMP of the other family: type only
        if l4[0] in ICMP_ECHO[proto] and len(l4) >= 6:
            info["icmp_id"] = struct.unpack(">H", l4[4:6])[0]
        if quote and l4[0] in ICMP_ERRORS[proto] and len(l4) > 8:
            # The quoted header of the packet the error answers; one level.
            inner = l4[8:]
            try:
                quoted = _ipv4(inner, False) if inner[0] >> 4 == 4 else _ipv6(inner, False)
            except (ValueError, struct.error, IndexError):
                quoted = None
            if quoted is not None:
                info["quoted"] = quoted


def control_kind(info, broadcasts):
    """The excluded link-local control class of an IP packet, or None."""
    proto = info["proto"]
    ports = {info.get("sport"), info.get("dport")}
    if proto == 17 and info["family"] == 4 and ports == {67, 68}:
        return "dhcp"
    if proto == 17 and info["family"] == 6 and ports == {546, 547}:
        return "dhcp"
    if proto == 58 and info["family"] == 6:
        icmp = info.get("icmp_type")
        if icmp in ICMPV6_ND:
            return "nd"
        if icmp in ICMPV6_MLD:
            return "mld"
    if proto == 17 and info.get("dport") == 5353 and info["dst"] in (MDNS_V4, MDNS_V6):
        return "mdns"
    if info["family"] == 4 and (info["dst"] == LIMITED_BROADCAST or info["dst"] in broadcasts):
        return "broadcast"
    return None


def leak_class(info, local, local_mac):
    """Diagnostic class of a leak; it never changes pass."""
    if "link_control" in info:
        return "link_control"
    ip = info["kind"] == "ip"
    if ip and info["proto"] == 2 and info["family"] == 4 and info["dst"].is_multicast:
        return "igmp"
    if local_mac and "eth_src" in info and local_mac not in (info["eth_src"], info["eth_dst"]):
        if not ip or not ({info["src"], info["dst"]} & local or info["src"] == TUNNEL_ADDR):
            return "foreign"
    return "host"


def is_relay(info, pins, protos, signed_tcp_pins=None, signed_udp_pins=None):
    """TCP/UDP to an exact admitted relay address and port, never the host alone."""
    if info["proto"] == 6:
        allowed = signed_tcp_pins if signed_tcp_pins is not None else pins if 6 in protos else ()
    elif info["proto"] == 17:
        allowed = signed_udp_pins if signed_udp_pins is not None else pins if 17 in protos else ()
    else:
        allowed = ()
    return any((info["src"] == relay and info.get("sport") == port)
               or (info["dst"] == relay and info.get("dport") == port)
               for relay, port in allowed)


def parse_relay_pins(relay_ip, relay_port, extras=()):
    """Bounded exact numeric pins; extras come only from a digest-bound bundle."""
    pins = [(ipaddress.ip_address(relay_ip.strip("[]")), relay_port)]
    for text in extras:
        if text.startswith("["):
            close = text.find("]:")
            if close < 0:
                raise ValueError("invalid bracketed relay pin")
            host, port_text = text[1:close], text[close + 2:]
        else:
            host, sep, port_text = text.rpartition(":")
            if not sep or ":" in host:
                raise ValueError("IPv6 relay pin requires brackets")
        pins.append((ipaddress.ip_address(host), int(port_text)))
    if not 1 <= len(pins) <= 16 or len(set(pins)) != len(pins):
        raise ValueError("relay pin set must contain 1..16 distinct exact tuples")
    if any(not 0 < port < 65536 or ip.is_unspecified or ip.is_multicast
           for ip, port in pins):
        raise ValueError("relay pin is not an admissible numeric tuple")
    return tuple(pins)


def pin_policy_from_public_bundle(directory, expected_digest, relay_ip, relay_port):
    """Bind exact TCP and enrolled-QUIC UDP pins to provider public terms."""
    if not Path(directory).is_absolute():
        raise ValueError("public bundle path must be absolute")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64 or any(
            c not in "0123456789abcdef" for c in expected_digest):
        raise ValueError("provider profile digest is not a lowercase SHA-256")
    members = ("bundle.json", "outer-ca.pem", "inner-ca.pem", "device-ca.pem")
    digest = hashlib.sha256()
    payload = []
    for name in members:
        path = Path(directory) / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("public bundle member is missing or a link")
        data = path.read_bytes()
        if len(data) > 64 * 1024 or b"PRIVATE KEY" in data:
            raise ValueError("public bundle member is not admissible")
        digest.update(name.encode("ascii"))
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
        payload.append(data)
    if digest.hexdigest() != expected_digest:
        raise ValueError("public bundle differs from installed provider profile digest")
    profile = json.loads(payload[0])
    endpoints = profile.get("relay_endpoints")
    if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 16:
        raise ValueError("signed relay endpoint pool absent or out of bound")
    program = profile.get("carrier_program")
    tcp_indices = tuple(range(len(endpoints)))
    udp_indices = ()
    if program is not None:
        routes = program.get("routes") if isinstance(program, dict) else None
        if not isinstance(routes, list) or not 1 <= len(routes) <= 6 or len(routes) != len(endpoints) or any(
                not isinstance(route, dict)
                or route.get("channel") not in ("direct_h2", "fronted_h2", "own_https_bridge",
                                                 "https_ws", "web_response", "masque_quic")
                or type(route.get("endpoint_index")) is not int
                or not 0 <= route["endpoint_index"] < len(endpoints)
                for route in routes):
            raise ValueError("provider pool cannot review an unsupported signed route")
        indices = [route["endpoint_index"] for route in routes]
        if len(set(indices)) != len(endpoints):
            raise ValueError("signed route order does not retain every exact pin")
        udp_indices = tuple(route["endpoint_index"] for route in routes
                            if route["channel"] == "masque_quic")
        tcp_indices = tuple(route["endpoint_index"] for route in routes
                            if route["channel"] != "masque_quic")
    strings = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or not isinstance(endpoint.get("server"), str):
            raise ValueError("signed relay pin is not numeric")
        strings.append(endpoint["server"])
    pins = parse_relay_pins(relay_ip, relay_port, strings[1:])
    primary_text = (f"[{relay_ip.strip('[]')}]:{relay_port}" if ":" in relay_ip
                    else f"{relay_ip}:{relay_port}")
    if profile.get("relay_server") != strings[0] or strings[0] != primary_text:
        raise ValueError("handoff primary differs from installed signed profile")
    return (pins, tuple(pins[index] for index in tcp_indices),
            tuple(pins[index] for index in udp_indices))


def pins_from_public_bundle(directory, expected_digest, relay_ip, relay_port):
    """Legacy exact-pin view; the capture path also uses the UDP policy."""
    return pin_policy_from_public_bundle(directory, expected_digest, relay_ip, relay_port)[0]


def flow_key(info):
    """A direction-free flow identity, or None: TCP/UDP by address and port,
    ICMP echo by address and identifier."""
    if info.get("kind", "ip") != "ip":
        return None
    a, b = (int(info["src"]), info["src"].version), (int(info["dst"]), info["dst"].version)
    if info["proto"] in (6, 17) and "sport" in info:
        return (info["proto"],) + tuple(sorted(((a, info["sport"]), (b, info["dport"]))))
    if "icmp_id" in info:
        return ("echo", info["proto"], info["icmp_id"]) + tuple(sorted((a, b)))
    return None


def direction(info, local, local_mac=None):
    """outbound (sent by the Mac), inbound (to the Mac) or unknown."""
    if info["src"] in local or info["src"] == TUNNEL_ADDR:
        return "outbound"
    if info["dst"] in local:
        return "inbound"
    if local_mac and info.get("eth_src") == local_mac:
        return "outbound"
    if local_mac and info.get("eth_dst") == local_mac:
        return "inbound"
    return "unknown"


def build_flows(decoded, local, local_mac):
    """Every timed TCP/UDP/echo packet of the capture, by flow."""
    flows = {}
    for ts, info in decoded:
        if ts is None or info["kind"] != "ip":
            continue
        key = flow_key(info)
        if key is None:
            continue
        way = direction(info, local, local_mac)
        flow = flows.setdefault(key, {"first": (ts, way), "syns": [], "acks": [], "tcp": key[0] == 6})
        if ts < flow["first"][0]:
            flow["first"] = (ts, way)
        flags = info.get("tcp_flags", 0)
        if flags & TCP_SYN:
            flow["syns"].append((ts, way, bool(flags & TCP_ACK)))
        if flags & TCP_ACK and way == "inbound":
            flow["acks"].append((ts, info["tcp_ack"]))
    return flows


def flow_origin(flow, ts, connected_at):
    """Origin of a packet at ts on flow (ORIGINS)."""
    if flow is None or ts is None:
        return "unattributed"
    # A handshake at or after Connected, up to this packet, makes it new,
    # even on a 5-tuple seen before (port reuse).
    began = [s for s in flow["syns"] if connected_at <= s[0] <= ts]
    if began:
        _, way, synack = min(began)
        return "new_inbound" if way == "inbound" and not synack else "new_outbound"
    first_ts, first_way = flow["first"]
    if first_ts < connected_at:
        return "preexisting"
    if flow["tcp"]:
        return "preexisting_inferred"   # mid-stream with no handshake seen
    return "new_inbound" if first_way == "inbound" else "new_outbound"


def outbound_kind(info, flow, ts):
    """What the Mac itself sent, from header fields only."""
    proto = info["proto"]
    if proto == 6 and "tcp_flags" in info:
        flags = info["tcp_flags"]
        if flags & TCP_SYN:
            return "tcp_syn"
        size = info.get("payload_len")
        if size is None or size > 0:
            return "tcp_data"   # an unknown length is counted as data
        if flags & (TCP_FIN | TCP_RST) == 0 and flags & TCP_ACK and flow is not None and ts is not None:
            probe = (info["tcp_seq"] + 1) & 0xFFFFFFFF
            if any(t >= ts and ack == probe for t, ack in flow["acks"]):
                return "tcp_keepalive"
        return "tcp_control"
    if proto == 17 and "sport" in info:
        return "dns" if info["dport"] in DNS_PORTS else "udp"
    if proto in ICMP_ECHO and "icmp_type" in info:
        kind = info["icmp_type"]
        if kind in ICMP_ERRORS[proto]:
            return "icmp_error"
        if kind == ICMP_ECHO[proto][1]:
            return "icmp_echo_reply"
        if kind == ICMP_ECHO[proto][0]:
            return "icmp_echo_request"
        return "icmp_other"
    return "other"


# ---------------------------------------------------------------- S20d

def eth_source(linktype, frame):
    """The raw Ethernet source address of a record, or None; read from the
    header bytes, so an Ethernet frame whose payload does not parse keeps it."""
    if linktype == LINK_ETHERNET and frame is not None and len(frame) >= 12:
        return frame[6:12].hex(":")
    return None


def mac_sent_excluded(info, pins, protos, broadcasts,
                      signed_tcp_pins=None, signed_udp_pins=None):
    """Relay transport, ARP, DHCP, ND/RS/RA, MLD and EAPOL: nothing else."""
    if info["kind"] == "control":
        return info.get("control") in MAC_SENT_CONTROL
    if info["kind"] == "ip":
        return is_relay(info, pins, protos, signed_tcp_pins, signed_udp_pins) or control_kind(info, broadcasts) in MAC_SENT_CONTROL
    return info.get("link_control") in MAC_SENT_LINK


def mac_sent_by(info, ts, source, local, macs, local_mac):
    """Whether the Mac sent this frame; macs is every MAC of the Mac (S20e),
    local_mac included. Fail closed: an unparsed or untimed frame is the
    Mac's unless --local-mac is known and its Ethernet source is present and
    none of them. More identities therefore only ever add frames."""
    if source is not None and source in macs:
        return True
    if info["kind"] == "ip" and (info["src"] in local or info["src"] == TUNNEL_ADDR):
        return True
    if info["kind"] == "unparsed" or ts is None:
        return not (local_mac and source is not None and source not in macs)
    return False


def mac_sent_class(info, flow, ts, broadcasts):
    """The kind of a Mac-sent frame, from header fields only."""
    if info["kind"] == "unparsed":
        return "unparsed"
    if info["kind"] != "ip":
        return "link_control" if "link_control" in info else "other"
    kind = control_kind(info, broadcasts)
    if kind in ("mdns", "broadcast"):
        return kind
    if info["proto"] == 2 and info["family"] == 4:
        return "igmp"
    return outbound_kind(info, flow, ts)


def review_mac_sent(report, records, decoded, flows, pins, protos, local, broadcasts, local_mac, macs,
                    connected_at, disconnect_at, lo, hi, relay_required,
                    signed_tcp_pins=None, signed_udp_pins=None):
    """The S20d Mac-sent fields over the same interval and guard as pass.
    It reads its own pass over the records and never touches pass's fields.
    local and macs are the S20e identities (the strict ones and more)."""
    classes, origins = report["mac_sent_classes"], report["mac_sent_origins"]
    for (ts, linktype, frame), (_, info) in zip(records, decoded):
        if ts is not None and not (connected_at <= ts <= disconnect_at):
            continue
        if mac_sent_excluded(info, pins, protos, broadcasts, signed_tcp_pins, signed_udp_pins):
            continue
        if not mac_sent_by(info, ts, eth_source(linktype, frame), local, macs, local_mac):
            continue
        if ts is not None and not (lo <= ts <= hi):
            report["mac_sent_guard"] += 1   # diagnostic only
            continue
        key = flow_key(info) if info["kind"] == "ip" else None
        flow = flows.get(key) if key is not None else None
        klass = mac_sent_class(info, flow, ts, broadcasts)
        report["mac_sent_leaks"] += 1
        classes[klass] = classes.get(klass, 0) + 1
        if key is None and info["kind"] == "ip" and "quoted" in info:
            quoted = flow_key(info["quoted"])   # an ICMP error: the flow it answers
            flow = flows.get(quoted) if quoted is not None else None
        origin = flow_origin(flow, ts, connected_at)
        origins[origin] = origins.get(origin, 0) + 1
        if len(report["mac_sent_frames"]) < MAX_LISTED:
            entry = _describe(ts, info, local, local_mac)
            entry["class"], entry["origin"] = klass, origin
            if ts is None:
                entry["reason"] = (entry.get("reason", "") + " no timestamp").strip()
            report["mac_sent_frames"].append(entry)
    if report["relay_packets"] == 0 and relay_required:
        report.setdefault("mac_sent_error", "no relay packet inside the Connected interval")
    report["mac_sent_pass"] = report["mac_sent_leaks"] == 0 and "mac_sent_error" not in report


def review_mac_sent_armed(report, records, decoded, flows, pins, protos, local, broadcasts, local_mac,
                          macs, connected_at, armed_at, disarmed_at,
                          signed_tcp_pins=None, signed_udp_pins=None):
    """S20f: the Mac-sent frames over the provider's armed span, by the
    same rules and identities as review_mac_sent, with no guard and no
    relay term. Its own fields only (mac_sent_armed_*)."""
    classes, origins = report["mac_sent_armed_classes"], report["mac_sent_armed_origins"]
    for (ts, linktype, frame), (_, info) in zip(records, decoded):
        if ts is not None and not (armed_at <= ts <= disarmed_at):
            continue
        if mac_sent_excluded(info, pins, protos, broadcasts, signed_tcp_pins, signed_udp_pins):
            continue
        if not mac_sent_by(info, ts, eth_source(linktype, frame), local, macs, local_mac):
            continue
        key = flow_key(info) if info["kind"] == "ip" else None
        flow = flows.get(key) if key is not None else None
        klass = mac_sent_class(info, flow, ts, broadcasts)
        report["mac_sent_armed_leaks"] += 1
        classes[klass] = classes.get(klass, 0) + 1
        if key is None and info["kind"] == "ip" and "quoted" in info:
            quoted = flow_key(info["quoted"])
            flow = flows.get(quoted) if quoted is not None else None
        origin = flow_origin(flow, ts, connected_at if connected_at is not None else armed_at)
        origins[origin] = origins.get(origin, 0) + 1
        if len(report["mac_sent_armed_frames"]) < MAX_LISTED:
            entry = _describe(ts, info, local, local_mac)
            entry["class"], entry["origin"] = klass, origin
            if ts is None:
                entry["reason"] = (entry.get("reason", "") + " no timestamp").strip()
            report["mac_sent_armed_frames"].append(entry)


# ---------------------------------------------------------------- review

def _describe(ts, info, local, local_mac=None):
    entry = {"time": ts, "kind": info["kind"]}
    for key in ("eth_src", "eth_dst"):
        if key in info:
            entry[key] = info[key]
    if info["kind"] == "ip":
        entry.update(src=str(info["src"]), dst=str(info["dst"]),
                     proto=PROTO_NAMES.get(info["proto"], str(info["proto"])))
        for key in ("sport", "dport", "icmp_type", "tcp_flags", "payload_len"):
            if key in info:
                entry[key] = info[key]
        entry["direction"] = direction(info, local, local_mac)
    else:
        entry["reason"] = info.get("reason", "")
    return entry


def review(data, relay_ip, relay_port, connected_at, disconnect_at, guard=GUARD_S,
           local=(), broadcasts=(), relay_protos=("tcp", "udp"), local_mac=None, relay_required=True,
           mac_sent_macs=(), mac_sent_addrs=(), armed_at=None, disarmed_at=None, extra_relay_pins=(),
           signed_tcp_relay_pins=None, signed_udp_relay_pins=None):
    pins = parse_relay_pins(relay_ip, relay_port, extra_relay_pins)
    if (signed_tcp_relay_pins is None) != (signed_udp_relay_pins is None):
        raise ValueError("signed TCP and UDP pin policies must arrive together")
    for indices in (signed_tcp_relay_pins, signed_udp_relay_pins):
        if indices is not None and (type(indices) is not tuple
                                    or any(type(i) is not int or not 0 <= i < len(pins) for i in indices)
                                    or len(set(indices)) != len(indices)):
            raise ValueError("signed protocol pin index outside provider pool")
    tcp_pins = None if signed_tcp_relay_pins is None else tuple(pins[i] for i in signed_tcp_relay_pins)
    udp_pins = None if signed_udp_relay_pins is None else tuple(pins[i] for i in signed_udp_relay_pins)
    relay = pins[0][0]
    protos = {PROTO_NUMBERS[p] for p in relay_protos}
    local = {ipaddress.ip_address(a) for a in local}
    broadcasts = {ipaddress.ip_address(a) for a in broadcasts}
    local_mac = local_mac.lower() if local_mac else None
    # S20e: the Mac-sent criterion's own identities; pass never reads them.
    ms_macs = {m.strip().lower() for m in mac_sent_macs if m and m.strip()} | ({local_mac} if local_mac else set())
    ms_local, ms_unreadable = set(local), 0
    for text in mac_sent_addrs:
        try:
            ms_local.add(ipaddress.ip_address(text.split("%")[0]))
        except ValueError:
            ms_unreadable += 1
    report = {
        "connected_interval": None,
        "guard_seconds": guard,
        "relay_ip": str(relay),
        "relay_port": relay_port,
        "relay_pin_count": len(pins),
        "signed_tcp_pin_count": None if tcp_pins is None else len(tcp_pins),
        "signed_udp_pin_count": None if udp_pins is None else len(udp_pins),
        "signed_tcp_pin_indices": None if signed_tcp_relay_pins is None else list(signed_tcp_relay_pins),
        "signed_udp_pin_indices": None if signed_udp_relay_pins is None else list(signed_udp_relay_pins),
        "relay_protocols": sorted(relay_protos),
        "local_mac": local_mac,
        "total_packets": 0,
        "outside_packets": 0,
        "interval_packets": 0,
        "guard_packets": 0,
        "relay_packets": 0,
        "untimed_relay_packets": 0,
        "excluded_control": {"total": 0},
        "leak_count": 0,
        "leak_classes": {},
        "leak_families": {"ipv4": 0, "ipv6": 0, "other": 0},
        "leak_origins": {},
        "leak_flows": {},
        "new_outbound_flows": 0,
        "host_outbound": {},
        "leaks": [],
        "pass": False,
        # S20d: a separate criterion; it never changes any field above.
        "mac_sent_leaks": 0,
        "mac_sent_classes": {},
        "mac_sent_origins": {},
        "mac_sent_guard": 0,
        "mac_sent_relay_required": bool(relay_required),
        "mac_sent_frames": [],
        "mac_sent_pass": False,
        "mac_sent_identity": {"macs": len(ms_macs), "addrs": len(ms_local)},
        # S20f: the armed span's own Mac-sent pass; it changes nothing above.
        "mac_sent_armed_span": None,
        "mac_sent_armed_leaks": 0,
        "mac_sent_armed_classes": {},
        "mac_sent_armed_origins": {},
        "mac_sent_armed_frames": [],
    }
    armed = None
    if armed_at is not None or disarmed_at is not None:
        if armed_at is None or disarmed_at is None:
            report["mac_sent_armed_error"] = "armed span incomplete: both --armed-at and --disarmed-at are needed"
        elif disarmed_at < armed_at:
            report["mac_sent_armed_error"] = "armed span inverted: --disarmed-at is before --armed-at"
        else:
            armed = (armed_at, disarmed_at)
            report["mac_sent_armed_span"] = {"armed_at": armed_at, "disarmed_at": disarmed_at}
    if not local_mac:
        report["mac_sent_error"] = NO_LOCAL_MAC
    if ms_unreadable:
        report.setdefault("mac_sent_error", f"unreadable --mac-sent-addr: {ms_unreadable} value(s)")
    if connected_at is None or disconnect_at is None:
        report["error"] = "no Connected interval: the window never reached Connected"
        report.setdefault("mac_sent_error", report["error"])
    if connected_at is not None and disconnect_at is not None:
        report["connected_interval"] = {"connected_at": connected_at, "disconnect_at": disconnect_at,
                                        "reviewed_from": connected_at + guard,
                                        "reviewed_to": disconnect_at - guard}
    fmt, records = read_capture(data)
    report["format"] = fmt
    if "error" in report:
        report["total_packets"] = len(records)
        if armed is not None:
            report["mac_sent_armed_error"] = report["error"]
        return report
    lo, hi = connected_at + guard, disconnect_at - guard
    control = report["excluded_control"]
    decoded = [(ts, decode(linktype, frame)) for ts, linktype, frame in records]
    flows = build_flows(decoded, local, local_mac)
    flow_sets = {}
    for ts, info in decoded:
        report["total_packets"] += 1
        if ts is not None and not (connected_at <= ts <= disconnect_at):
            report["outside_packets"] += 1
            continue
        if ts is not None and not (lo <= ts <= hi):
            report["guard_packets"] += 1
            continue
        report["interval_packets"] += 1
        if info["kind"] == "control":
            kind = info["control"]
        elif info["kind"] == "ip":
            if is_relay(info, pins, protos, tcp_pins, udp_pins):
                # An untimed relay packet cannot be placed inside the interval.
                if ts is not None:
                    report["relay_packets"] += 1
                else:
                    report["untimed_relay_packets"] += 1
                continue
            kind = control_kind(info, broadcasts)
        else:
            kind = None
        if kind is not None:
            control[kind] = control.get(kind, 0) + 1
            control["total"] += 1
            continue
        report["leak_count"] += 1
        klass = leak_class(info, local, local_mac) if info["kind"] != "unparsed" else "unparsed"
        report["leak_classes"][klass] = report["leak_classes"].get(klass, 0) + 1
        family = {4: "ipv4", 6: "ipv6"}.get(info.get("family")) if info["kind"] == "ip" else None
        report["leak_families"][family or "other"] += 1
        origin = None
        if klass == "host":
            key = flow_key(info)
            if key is None and "quoted" in info:
                key = flow_key(info["quoted"])   # an ICMP error: its flow
            flow = flows.get(key) if key is not None else None
            origin = flow_origin(flow, ts, connected_at)
            if flow is not None:
                flow_sets.setdefault(origin, set()).add(key)
            if info["kind"] == "ip" and direction(info, local, local_mac) == "outbound":
                own = flow_key(info)
                sent = outbound_kind(info, flows.get(own) if own is not None else None, ts)
                report["host_outbound"][sent] = report["host_outbound"].get(sent, 0) + 1
        bucket = "host_" + origin if origin else klass
        report["leak_origins"][bucket] = report["leak_origins"].get(bucket, 0) + 1
        if len(report["leaks"]) < MAX_LISTED:
            entry = _describe(ts, info, local, local_mac)
            entry["class"] = klass
            if origin:
                entry["origin"] = origin
            if info["kind"] == "ip" and any(ip in (info["src"], info["dst"]) for ip, _ in pins):
                entry["relay_host"] = True
            if ts is None:
                entry["reason"] = (entry.get("reason", "") + " no timestamp").strip()
            report["leaks"].append(entry)
    report["leak_flows"] = {origin: len(keys) for origin, keys in sorted(flow_sets.items())}
    report["new_outbound_flows"] = report["leak_flows"].get("new_outbound", 0)
    # The origins explain a failure; they never excuse one.
    report["pass"] = report["leak_count"] == 0 and report["relay_packets"] > 0
    if report["relay_packets"] == 0:
        report["error"] = "no relay packet inside the Connected interval"
    # S20e: with more addresses the Mac-sent pass gets its own flow table, so
    # its classes and origins see those addresses too; pass keeps flows.
    ms_flows = flows if ms_local == local else build_flows(decoded, ms_local, local_mac)
    review_mac_sent(report, records, decoded, ms_flows, pins, protos, ms_local, broadcasts, local_mac,
                    ms_macs, connected_at, disconnect_at, lo, hi, relay_required, tcp_pins, udp_pins)
    if armed is not None:
        review_mac_sent_armed(report, records, decoded, ms_flows, pins, protos, ms_local, broadcasts,
                              local_mac, ms_macs, connected_at, *armed, tcp_pins, udp_pins)
    return report


def probe_syns(argv):
    """S20f: the positive control's marked SYNs in one capture."""
    parser = argparse.ArgumentParser(prog="leak_review.py probe-syns")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--dport", type=int, required=True)
    parser.add_argument("--sport-min", type=int, required=True)
    parser.add_argument("--sport-max", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        dst = ipaddress.ip_address(args.dst)
        if not (0 < args.dport < 65536 and 0 < args.sport_min <= args.sport_max < 65536):
            raise ValueError("port out of range")
        with open(args.pcap, "rb") as handle:
            _, records = read_capture(handle.read())
    except (OSError, CaptureError, ValueError):
        print("probe_syns=unreadable")
        return 2
    count = 0
    for _, linktype, frame in records:
        info = decode(linktype, frame)
        if (info["kind"] == "ip" and info["proto"] == 6 and info["dst"] == dst
                and info.get("dport") == args.dport
                and args.sport_min <= info.get("sport", -1) <= args.sport_max
                and info.get("tcp_flags", 0) & TCP_SYN and not info.get("tcp_flags", 0) & TCP_ACK):
            count += 1
    print(f"probe_syns={count} total={len(records)}")
    return 0


def presock_frames(argv):
    """S20g: the frames of the pre-existing sockets in one capture."""
    parser = argparse.ArgumentParser(prog="leak_review.py presock-frames")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--dport", type=int, required=True)
    parser.add_argument("--sport", type=int, action="append", required=True)
    parser.add_argument("--since", type=float)
    parser.add_argument("--until", type=float)
    args = parser.parse_args(argv)
    try:
        dst = ipaddress.ip_address(args.dst)
        if not (0 < args.dport < 65536 and all(0 < p < 65536 for p in args.sport)):
            raise ValueError("port out of range")
        with open(args.pcap, "rb") as handle:
            _, records = read_capture(handle.read())
    except (OSError, CaptureError, ValueError):
        print("presock_frames=unreadable")
        return 2
    sports = set(args.sport)
    counts = {"data": 0, "ack_only": 0, "other": 0}
    marked = 0
    for ts, linktype, frame in records:
        if ts is not None and ((args.since is not None and ts < args.since)
                               or (args.until is not None and ts > args.until)):
            continue
        info = decode(linktype, frame)
        if not (info["kind"] == "ip" and info["proto"] == 6 and info["dst"] == dst
                and info.get("dport") == args.dport and info.get("sport") in sports):
            continue
        flags = info.get("tcp_flags", 0)
        if flags & (TCP_SYN | TCP_FIN | TCP_RST) or "payload_len" not in info:
            counts["other"] += 1
        elif info["payload_len"] > 0:
            counts["data"] += 1
        elif flags & TCP_ACK:
            counts["ack_only"] += 1
            # S20h review: those from a port of the provider's marker range,
            # the field the filter marks the helper's keepalives by.
            marked += marked_sport(info["sport"])
        else:
            counts["other"] += 1
    print(f"presock_frames={sum(counts.values())} data={counts['data']} ack_only={counts['ack_only']} "
          f"other={counts['other']} total={len(records)} ack_only_marked={marked}")
    return 0


# --------------------------------------------------- S20h presock review

IFACE_PREFIXES = ("en", "awdl", "llw", "bridge", "ap", "anpi", "utun", "ipsec", "lo", "gif", "stf", "pktap",
                  "vmenet", "vmnet", "vnic")
OUT_KINDS = ("syn", "syn_ack", "ack_only", "data", "fin", "rst", "other", "non_tcp")
# The capture's frame kinds and the provider's kinds they correspond to.
FRAME_KINDS = {"data": ("data",), "ack_only": ("ack_only",), "other": ("syn", "syn_ack", "fin", "rst", "other")}
PRESOCK_SCHEMA = "aegis-presock-v1"
# The provider's marker range of TCP source ports (leak_guard::MARK_SPORT_FIRST
# and MARK_SPORT_COUNT; a Rust test reads these two lines).
MARK_SPORT_FIRST = 47000
MARK_SPORT_COUNT = 32


def marked_sport(port):
    """Whether a TCP source port lies in the provider's marker range."""
    return isinstance(port, int) and MARK_SPORT_FIRST <= port < MARK_SPORT_FIRST + MARK_SPORT_COUNT


def _nat(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def iface_token(name):
    """The provider's iface_token of an interface name."""
    for prefix in IFACE_PREFIXES:
        rest = name[len(prefix):]
        if name.startswith(prefix) and rest.isdigit() and 1 <= len(rest) <= 4 and (rest == "0" or rest[0] != "0"):
            return name
    raw = name.encode()
    value = 0x811C9DC5
    for byte in raw[:32]:
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    value = ((value ^ min(len(raw), 255)) * 0x01000193) & 0xFFFFFFFF
    return "h:%08x" % max(value & 0x7FFFFFFF, 1)


def drop_class(name, primary):
    """The provider's drop class of an interface name."""
    if iface_token(name) == primary:
        return "primary"
    token = iface_token(name)
    for cls, prefixes in (("en_other", ("en",)), ("awdl_llw", ("awdl", "llw")),
                          ("bridge_ap_anpi", ("bridge", "ap", "anpi"))):
        for prefix in prefixes:
            rest = token[len(prefix):]
            if token.startswith(prefix) and rest.isdigit():
                return cls
    return "other"


def filter_report(path):
    """The report of the last filter-status JSON line of a --filter-status
    output, or None."""
    if not path:
        return None
    report = None
    try:
        with open(path, errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("{"):
                    value = json.loads(line)
                    if isinstance(value, dict) and value.get("verb") == "filter-status":
                        report = value.get("report")
    except (OSError, ValueError):
        return None
    return report if isinstance(report, dict) else None


def _table(outbound, key, cls):
    table = outbound.get(key) if isinstance(outbound, dict) else None
    row = table.get(cls) if isinstance(table, dict) else None
    if not isinstance(row, dict) or not all(_nat(row.get(kind)) for kind in OUT_KINDS):
        return None
    return {kind: row[kind] for kind in OUT_KINDS}


def _delta(before, after, key, cls):
    """after - before of an outbound table row, or None."""
    b, a = _table(before, key, cls), _table(after, key, cls)
    if b is None or a is None or any(a[k] < b[k] for k in OUT_KINDS):
        return None
    return {k: a[k] - b[k] for k in OUT_KINDS}


def presock_state(path):
    try:
        with open(path) as handle:
            doc = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("schema") != PRESOCK_SCHEMA or not isinstance(doc.get("port"), int):
        return None
    return doc


def match_ticks(ticks, times, tol):
    """How many of the sorted due times `ticks` a distinct one of the
    sorted `times` lies within tol of (greedy, optimal for equal windows)."""
    matched, k = 0, 0
    for tick in ticks:
        while k < len(times) and times[k] < tick - tol:
            k += 1
        if k < len(times) and times[k] <= tick + tol:
            matched += 1
            k += 1
    return matched


def frame_kind(info):
    flags = info.get("tcp_flags", 0)
    if flags & (TCP_SYN | TCP_FIN | TCP_RST) or "payload_len" not in info:
        return "other"
    if info["payload_len"] > 0:
        return "data"
    return "ack_only" if flags & TCP_ACK else "other"


def keepalive_review(args, doc, records, before, after):
    """(verdict, detail, counted line, tap) of the keepalive criterion;
    tap (S20h review), None until the ring is read under the helper's
    marker, is the marker range and the marked drops on IF the outbound
    ring holds between the reads, by frame kind (frames_review)."""
    sockets = [s for s in doc.get("sockets", []) if _nat(s.get("lport"))]
    write = doc.get("write") if isinstance(doc.get("write"), dict) else {}
    tx = sum(s.get("tx_packets", 0) for s in write.get("sockets", []) if _nat(s.get("tx_packets")))
    keepalive = doc.get("keepalive")
    if not sockets or not (isinstance(keepalive, list) and len(keepalive) == 3 and all(_nat(v) for v in keepalive)):
        return "unavailable", "no_sockets", "unknown no_sockets", None
    ob = before.get("observability") if before else None
    oa = after.get("observability") if after else None
    if not (isinstance(ob, dict) and isinstance(oa, dict)):
        return "fail", "unreadable: --filter-status not parsed", "unknown unreadable", None
    if before.get("mode") != "guarding":
        return ("fail", "mode=%s: the filter was not armed at the write" % before.get("mode", "?"),
                "unknown not_armed", None)
    arms = [(o.get("arm_seq"), o.get("disarms")) for o in (ob, oa)]
    if after.get("mode") != "guarding" or not all(_nat(x) for arm in arms for x in arm) or arms[0] != arms[1]:
        return ("fail", "rearmed: mode_after=%s arm_seq=%s->%s disarms=%s->%s: not one arm through the write" % (
            after.get("mode", "?"), arms[0][0], arms[1][0], arms[0][1], arms[1][1]), "unknown rearmed", None)
    primary = ob.get("primary_iface")
    cls = drop_class(args.dev, primary)
    token = iface_token(args.dev)
    outb, outa = ob.get("outbound"), oa.get("outbound")
    if not (isinstance(outb, dict) and isinstance(outa, dict)):
        return ("unavailable", "no_outbound: a provider before v29 class=%s tx=%d" % (cls, tx),
                "tx=%d data_counted=unknown blocked_before_filter=unknown class=%s" % (tx, cls), None)
    # S20h review: the marker is a range of TCP source ports (XNU keepalives
    # carry the system's default TTL, never the socket's): the provider's
    # range at both reads, the helper's, and every socket bound inside it.
    # The detail never names a port.
    mark = (outa.get("mark_sport_first"), outa.get("mark_sport_count"))
    if not (all(_nat(v) for v in mark) and mark[1] > 0) or (
            outb.get("mark_sport_first"), outb.get("mark_sport_count")) != mark or doc.get("mark_sport") != list(mark):
        why = "the provider's marker range is not the helper's"
    else:
        outside = sum(1 for s in sockets if not mark[0] <= s["lport"] < mark[0] + mark[1])
        why = "%d of the sockets are outside the marker range" % outside if outside else ""
    if why:
        return ("unavailable", "mark_mismatch: %s class=%s" % (why, cls),
                "tx=%d data_counted=unknown blocked_before_filter=unknown class=%s" % (tx, cls), None)
    marked = _delta(outb, outa, "marked", cls)
    kinds = _delta(outb, outa, "kinds", cls)
    b_ms, a_ms = ob.get("armed_for_ms"), oa.get("armed_for_ms")
    if marked is None or kinds is None or not _nat(b_ms) or not _nat(a_ms) or a_ms < b_ms:
        return ("fail", "unreadable: outbound counts or armed_for_ms class=%s" % cls,
                "unknown unreadable class=%s" % cls, None)
    data = marked["data"]
    if args.armed_at is None:
        return ("unavailable", "no_armed_span class=%s tx=%d data_counted=%d" % (cls, tx, data),
                "tx=%d data_counted=%d blocked_before_filter=%d keepalive_expected=unknown keepalive_counted=%d "
                "class=%s" % (tx, data, max(tx - data, 0), marked["ack_only"], cls), None)
    idle, intvl, cnt = keepalive
    # Each socket's last receive before the arm: its last frame from the
    # gateway's port in the capture (the inbound tap sees every frame the
    # filter later drops), else the helper's connect time.
    dst = ipaddress.ip_address(args.dst)
    last_rx = {}
    for ts, linktype, frame in records:
        if ts is None or ts >= args.armed_at:
            continue
        info = decode(linktype, frame)
        if (info["kind"] == "ip" and info["proto"] == 6 and info["src"] == dst
                and info.get("sport") == doc["port"]):
            port = info.get("dport")
            last_rx[port] = max(last_rx.get(port, ts), ts)
    sources = set()
    ticks, per_socket = [], []
    tol_ms = args.tol * 1000.0
    for entry in sockets:
        t_rx = last_rx.get(entry["lport"])
        if t_rx is None:
            t_rx = entry.get("t_connected")
            sources.add("helper")
        else:
            sources.add("capture")
        if not isinstance(t_rx, (int, float)):
            return ("unavailable", "no_receive_time class=%s" % cls, "unknown no_receive_time class=%s" % cls, None)
        due = 0
        k = 0
        # TCP drops the connection after cnt unanswered keepalives.
        while k < cnt:
            tick = (t_rx + idle + k * intvl - args.armed_at) * 1000.0
            if tick > a_ms - tol_ms:
                break
            if tick >= b_ms + tol_ms:
                ticks.append(tick)
                due += 1
            k += 1
        per_socket.append(due)
    ticks.sort()
    expected = len(ticks)
    counted = marked["ack_only"]
    unmarked = kinds["ack_only"] - counted
    ring_b = outb.get("ring") if isinstance(outb.get("ring"), dict) else {}
    ring_a = outa.get("ring") if isinstance(outa.get("ring"), dict) else {}
    nb, na, entries = ring_b.get("next"), ring_a.get("next"), ring_a.get("entries")
    if not (_nat(nb) and _nat(na) and na >= nb and isinstance(entries, list)
            and all(isinstance(e, dict) and _nat(e.get("index")) for e in entries)):
        return ("fail", "unreadable: outbound ring class=%s" % cls, "unknown unreadable class=%s" % cls, None)
    new = [e for e in entries if nb <= e["index"] < na]
    lost = (na - nb) - len(new)

    def bare(e, is_marked):
        return (e.get("iface") == token and e.get("dir") == "out" and e.get("proto") == 6
                and e.get("tcp") == "ack_only" and e.get("reason") == "drop_tcp_out" and _nat(e.get("ms"))
                and e.get("marked") is is_marked)

    # S20h review: every marked drop on IF between the reads, by the
    # capture's frame kind, for the tap evidence (frames_review).
    kind_of = {provider: kind for kind, providers in FRAME_KINDS.items() for provider in providers}
    tap = {"first": mark[0], "count": mark[1], "drops": dict.fromkeys(FRAME_KINDS, 0)}
    for e in new:
        if (e.get("iface") == token and e.get("dir") == "out" and e.get("proto") == 6
                and e.get("marked") is True and e.get("tcp") in kind_of):
            tap["drops"][kind_of[e["tcp"]]] += 1
    matched = match_ticks(ticks, sorted(e["ms"] for e in new if bare(e, True)), tol_ms)
    inferred = match_ticks(ticks, sorted(e["ms"] for e in new if bare(e, False)), tol_ms)
    detail = ("class=%s sockets=%d expected=%d per_socket=%s counted=%d matched=%d unmarked=%d inferred=%d "
              "ring_lost=%d data_counted=%d tx=%d rx=%s keepalive=%d/%d tol_ms=%d span_ms=%d" % (
                  cls, len(sockets), expected, ",".join(str(n) for n in per_socket), counted, matched, unmarked,
                  inferred, lost, data, tx, "+".join(sorted(sources)), idle, intvl, round(tol_ms), a_ms - b_ms))
    counted_line = ("tx=%d data_counted=%d blocked_before_filter=%d keepalive_expected=%d keepalive_counted=%d "
                    "class=%s" % (tx, data, max(tx - data, 0), expected, counted, cls))
    if min(per_socket) < 2:
        verdict, reason = "unavailable", "wait_short: fewer than two keepalives per socket were due between the reads"
    elif data and data < tx:
        verdict, reason = "unavailable", ("data_partial: the filter counted some of the written segments but not "
                                          "every one the sockets sent")
    elif counted == 0:
        reason = "unattributed: no marked bare ACK was counted"
        if expected and inferred == expected:
            reason += " (pass_inferred: unmarked ones fit every due keepalive)"
        verdict = "unavailable"
    elif counted < expected:
        verdict, reason = "unavailable", "uncounted: fewer marked bare ACKs than due keepalives"
    elif lost:
        verdict, reason = "unavailable", "ring_lost: the outbound ring lost records between the reads"
    elif matched < expected:
        verdict, reason = "unavailable", "ticks: the marked bare ACKs do not fall on every due keepalive"
    else:
        verdict, reason = "pass", ""
    return verdict, (reason + " " if reason else "") + detail, counted_line, tap


def frames_review(args, doc, records, span_before, span_after, tap=None):
    """The helper's frames during the armed span, how many exceed the
    marked drops of their kind, the capture's frames after the disarm, and
    (S20h review) the tap evidence: post_filter when, for one kind, the
    filter dropped more marked segments on IF between the reads (tap, from
    keepalive_review) than the capture holds frames from a source port of
    the marker range while armed. A tap before the filter records every
    frame the filter drops, so the capture would hold at least as many."""
    if args.armed_at is None or args.disarmed_at is None:
        return "frames=unknown no_armed_span"
    dst = ipaddress.ip_address(args.dst)
    lports = {s["lport"] for s in doc.get("sockets", []) if _nat(s.get("lport"))}
    counts = {"data": 0, "ack_only": 0, "other": 0}
    # Every TCP frame from a port of the marker range while armed, whoever
    # sent it and wherever to: what a tap before the filter would hold of
    # the marked drops.
    marker = dict.fromkeys(FRAME_KINDS, 0)
    first, count = (tap["first"], tap["count"]) if tap else (0, 0)
    after = 0
    for ts, linktype, frame in records:
        if ts is not None and ts > args.disarmed_at:
            after += 1
        if ts is not None and not args.armed_at <= ts <= args.disarmed_at:
            continue
        info = decode(linktype, frame)
        if info["kind"] != "ip" or info["proto"] != 6:
            continue
        sport = info.get("sport")
        if isinstance(sport, int) and first <= sport < first + count:
            marker[frame_kind(info)] += 1
        if info["dst"] == dst and info.get("dport") == doc["port"] and sport in lports:
            counts[frame_kind(info)] += 1
    ob = span_before.get("observability") if span_before else None
    oa = span_after.get("observability") if span_after else None
    marked = None
    if isinstance(ob, dict) and isinstance(oa, dict):
        cls = drop_class(args.dev, oa.get("primary_iface"))
        marked = _delta(ob.get("outbound"), oa.get("outbound"), "marked", cls)
    uncounted = 0
    for kind, provider_kinds in FRAME_KINDS.items():
        attributed = sum(marked[k] for k in provider_kinds) if marked else 0
        uncounted += max(0, counts[kind] - attributed)
    evidence = bool(tap) and any(tap["drops"][kind] > marker[kind] for kind in FRAME_KINDS)
    return "frames=%d data=%d ack_only=%d other=%d uncounted=%d total=%d after_disarm=%d tap_evidence=%s" % (
        sum(counts.values()), counts["data"], counts["ack_only"], counts["other"], uncounted, len(records), after,
        "post_filter" if evidence else "none")


def presock_review(argv):
    """S20h: the positive control's keepalive criterion for one
    interface (see the module docstring)."""
    parser = argparse.ArgumentParser(prog="leak_review.py presock-review")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--dev", required=True)
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--span-before")
    parser.add_argument("--span-after")
    parser.add_argument("--armed-at", type=float)
    parser.add_argument("--disarmed-at", type=float)
    parser.add_argument("--tol", type=float, default=0.5)
    args = parser.parse_args(argv)
    doc = presock_state(args.state)
    try:
        ipaddress.ip_address(args.dst)
        if not 0 < args.tol <= 2:
            raise ValueError("tolerance out of range")
    except ValueError:
        print("unavailable bad_arguments\nunknown bad_arguments\nframes=unknown bad_arguments")
        return 2
    if doc is None:
        print("unavailable no_sockets\nunknown no_sockets\nframes=unknown no_sockets")
        return 0
    try:
        with open(args.pcap, "rb") as handle:
            _, records = read_capture(handle.read())
        readable = True
    except (OSError, CaptureError, ValueError):
        records, readable = [], False
    if not readable:
        print("unavailable capture_unreadable\nunknown capture_unreadable\nframes=unknown capture_unreadable")
        return 2
    verdict, detail, counted, tap = keepalive_review(args, doc, records, filter_report(args.before),
                                                     filter_report(args.after))
    frames = frames_review(args, doc, records, filter_report(args.span_before), filter_report(args.span_after), tap)
    print("%s %s\n%s\n%s" % (verdict, detail, counted, frames))
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["profile-pins"]:
        preflight = argparse.ArgumentParser(prog="leak_review.py profile-pins")
        preflight.add_argument("--bundle-dir", required=True)
        preflight.add_argument("--profile-sha256", required=True)
        preflight.add_argument("--relay-ip", required=True)
        preflight.add_argument("--relay-port", type=int, required=True)
        args = preflight.parse_args(argv[1:])
        try:
            pins, tcp_pins, udp_pins = pin_policy_from_public_bundle(
                args.bundle_dir, args.profile_sha256, args.relay_ip, args.relay_port)
        except (OSError, ValueError, TypeError, KeyError):
            print("signed_pins=refused")
            return 2
        print(f"signed_pins={len(pins)} signed_tcp_pins={len(tcp_pins)} signed_quic_udp_pins={len(udp_pins)}")
        return 0
    if argv[:1] == ["probe-syns"]:
        return probe_syns(argv[1:])
    if argv[:1] == ["presock-frames"]:
        return presock_frames(argv[1:])
    if argv[:1] == ["presock-review"]:
        return presock_review(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--relay-ip", required=True)
    parser.add_argument("--relay-port", type=int, required=True)
    parser.add_argument("--bundle-dir", help="four public members of the installed signed profile")
    parser.add_argument("--profile-sha256", help="digest freshly read from provider --profile-terms")
    parser.add_argument("--relay-proto", default="tcp,udp",
                        help="comma-separated relay transport protocols: tcp, udp")
    parser.add_argument("--local-mac")
    parser.add_argument("--connected-at", type=float)
    parser.add_argument("--disconnect-at", type=float)
    parser.add_argument("--guard", type=float, default=GUARD_S)
    parser.add_argument("--local-addr", action="append", default=[])
    parser.add_argument("--broadcast", action="append", default=[])
    parser.add_argument("--relay-optional", action="store_true",
                        help="S20d: this interface carries no relay traffic; only mac_sent_pass "
                             "then needs no relay packet (pass is unchanged)")
    parser.add_argument("--mac-sent-mac", action="append", default=[],
                        help="S20e: another MAC of the Mac, for the Mac-sent criterion only")
    parser.add_argument("--mac-sent-addr", action="append", default=[],
                        help="S20e: another address of the Mac, for the Mac-sent criterion only")
    parser.add_argument("--armed-at", type=float,
                        help="S20f: the provider's leak_guard_span armed wall time")
    parser.add_argument("--disarmed-at", type=float,
                        help="S20f: the provider's leak_guard_span disarmed wall time")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    code = 0
    try:
        relay_protos = tuple(p for p in args.relay_proto.split(",") if p)
        if not relay_protos or not set(relay_protos) <= set(PROTO_NUMBERS):
            raise ValueError(f"--relay-proto {args.relay_proto!r}: use tcp, udp or tcp,udp")
        if bool(args.bundle_dir) != bool(args.profile_sha256):
            raise ValueError("--bundle-dir and --profile-sha256 must be supplied together")
        extra_pins = ()
        signed_tcp_indices = signed_udp_indices = None
        if args.bundle_dir:
            if relay_protos != ("tcp",):
                raise ValueError("signed provider pool derives its own exact UDP allowance")
            pins, tcp_pins, udp_pins = pin_policy_from_public_bundle(
                args.bundle_dir, args.profile_sha256, args.relay_ip, args.relay_port)
            extra_pins = tuple(f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
                               for ip, port in pins[1:])
            signed_tcp_indices = tuple(pins.index(pin) for pin in tcp_pins)
            signed_udp_indices = tuple(pins.index(pin) for pin in udp_pins)
        with open(args.pcap, "rb") as handle:
            data = handle.read()
        report = review(data, args.relay_ip, args.relay_port, args.connected_at, args.disconnect_at,
                        args.guard, args.local_addr, args.broadcast, relay_protos, args.local_mac,
                        not args.relay_optional, args.mac_sent_mac, args.mac_sent_addr,
                        args.armed_at, args.disarmed_at, extra_pins,
                        signed_tcp_indices, signed_udp_indices)
        code = 0 if report["pass"] else 1
    except (OSError, CaptureError, ValueError) as error:
        report = {"connected_interval": None, "total_packets": 0, "relay_packets": 0,
                  "excluded_control": {"total": 0}, "leak_count": 0, "leaks": [],
                  "pass": False, "error": f"{type(error).__name__}: {error}"}
        report.update(mac_sent_leaks=0, mac_sent_pass=False, mac_sent_error=report["error"])
        # S20f: an unreadable capture reviews no armed span either.
        report.update(mac_sent_armed_span=None, mac_sent_armed_leaks=0)
        if args.armed_at is not None or args.disarmed_at is not None:
            report["mac_sent_armed_error"] = report["error"]
        code = 2
    with open(args.out, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    origins = report.get("leak_origins", {})
    preexisting = origins.get("host_preexisting", 0) + origins.get("host_preexisting_inferred", 0)
    print(f"leak_review pass={str(report['pass']).lower()} leaks={report['leak_count']} "
          f"relay={report['relay_packets']} control={report['excluded_control']['total']} "
          f"total={report['total_packets']}"
          f" new_outbound_flows={report.get('new_outbound_flows', 0)} preexisting={preexisting}"
          f" foreign={report.get('leak_classes', {}).get('foreign', 0)}"
          + (f" error={report['error']}" if "error" in report else "")
          # S20d: always last, so a reader of the start sees the line it knew.
          + f" mac_sent_leaks={report.get('mac_sent_leaks', 0)}"
          f" mac_sent_pass={str(report.get('mac_sent_pass', False)).lower()}")
    return code


if __name__ == "__main__":
    sys.exit(main())
