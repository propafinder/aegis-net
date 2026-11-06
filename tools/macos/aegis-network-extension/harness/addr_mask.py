#!/usr/bin/env python3
"""B-06 v34 (S24 review F): mask the address literals of a window's rows.

harness/real-relay-window.sh runs this under the system python3 (3.9) on a
row's detail (`result`) and on its own log lines (`say`), and
harness/endurance-load.sh on the load's header and body excerpts. Every
check computes its verdict from the raw value first; only what is written
to results.tsv, window.log and the load's excerpts passes through here.

It reads text on stdin and writes it back with every IPv4 and IPv6 literal
replaced by a class:

- `relay_addr`: the relay's own address (each `--relay`; brackets, case
  and an IPv4-mapped form ignored).
- The tunnel's own fixed addresses stay as they are: 198.18.0.0/15 (the
  tunnel address 198.19.255.1, its resolver 198.19.255.2 and the fake-IP
  pool) and fd00:ae61::/32 (the tunnel's IPv6 addresses). Every install
  uses the same ones, so they name no relay, egress or Mac.
- Any other address: `ip4_<class>` or `ip6_<class>`, the class one of
  loopback, link_local, private (RFC 1918), cgnat (100.64/10), multicast,
  ula (fc00::/7), mapped (::ffff:0:0/96 of a non-tunnel address) or global.
- What looks like a cut-off or embedded IPv6 literal (two colons and a
  four-digit or hex-letter group, never a time of day such as 08:00:00)
  becomes `ip6_fragment`; a MAC address does too.

A caller that cuts a body (`head -c 80`) masks it first and cuts the masked
text, so no partial address is left at the cut. Exit 0 with the masked
text; 2 for bad arguments.
"""
import ipaddress
import re
import sys

TUNNEL_V4 = ipaddress.ip_network("198.18.0.0/15")
TUNNEL_V6 = ipaddress.ip_network("fd00:ae61::/32")
CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")
PRIVATE_V4 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
ULA_V6 = ipaddress.ip_network("fc00::/7")
# Every maximal run of hex digits, dots and colons that holds a dot or a
# colon: every address literal lies inside one.
RUN = re.compile(r"[0-9A-Fa-f.:]*[.:][0-9A-Fa-f.:]*")
# A dotted quad inside a run that is not itself an address ("x192.0.2.4").
QUAD = re.compile(r"(?<![0-9.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9])")


def parse(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def v4_class(a):
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link_local"
    if any(a in n for n in PRIVATE_V4):
        return "private"
    if a in CGNAT_V4:
        return "cgnat"
    if a.is_multicast:
        return "multicast"
    return "global"


def label(addr, text, relays):
    """The replacement of one parsed address `addr` written as `text`."""
    if addr in relays:
        return "relay_addr"
    if addr.version == 4:
        return text if addr in TUNNEL_V4 else "ip4_" + v4_class(addr)
    mapped = addr.ipv4_mapped
    if mapped is not None:
        if mapped in relays:
            return "relay_addr"
        return text if mapped in TUNNEL_V4 else "ip6_mapped"
    if addr in TUNNEL_V6:
        return text
    if addr.is_loopback:
        return "ip6_loopback"
    if addr.is_link_local:
        return "ip6_link_local"
    if addr.is_multicast:
        return "ip6_multicast"
    if addr in ULA_V6:
        return "ip6_ula"
    return "ip6_global"


def fragment(text):
    if text.count(":") < 2:
        return False
    return any(len(g) == 4 or re.search(r"[A-Fa-f]", g) for g in re.split(r"[:.]", text) if g)


def mask_run(run, relays):
    # A leading single colon (`ip:192.0.2.4`) and a trailing dot or single
    # colon (punctuation, a list) are not part of the address.
    head = ":" if run.startswith(":") and not run.startswith("::") else ""
    core = run[len(head):]
    tail = ""
    while core.endswith(".") or (core.endswith(":") and not core.endswith("::")):
        tail = core[-1] + tail
        core = core[:-1]
    addr = parse(core)
    if addr is not None:
        return head + label(addr, core, relays) + tail
    # An IPv4 address and port.
    host, sep, port = core.rpartition(":")
    if sep and port.isdigit() and "." in host:
        addr = parse(host)
        if addr is not None and addr.version == 4:
            return head + label(addr, host, relays) + ":" + port + tail
    out = QUAD.sub(lambda m: label(parse(m.group(0)), m.group(0), relays) if parse(m.group(0)) else m.group(0), core)
    if fragment(out):
        return head + "ip6_fragment" + tail
    return head + out + tail


def mask(text, relays):
    return RUN.sub(lambda m: mask_run(m.group(0), relays), text)


def relay_set(values):
    relays = set()
    for v in values:
        a = parse((v or "").strip().strip("[]"))
        if a is not None:
            relays.add(a)
            if a.version == 6 and a.ipv4_mapped is not None:
                relays.add(a.ipv4_mapped)
    return relays


def main(argv):
    relays, i = [], 0
    while i < len(argv):
        if argv[i] == "--relay" and i + 1 < len(argv):
            relays.append(argv[i + 1])
            i += 2
        else:
            print("usage: addr_mask.py [--relay ADDR]... < text", file=sys.stderr)
            return 2
    data = sys.stdin.buffer.read().decode("utf-8", "replace")
    sys.stdout.write(mask(data, relay_set(relays)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
