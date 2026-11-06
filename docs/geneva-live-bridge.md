# Opt-in Rust Geneva packet bridge

`aegis-geneva-bridge` is an optional Linux execution backend for the original
IPv4 Geneva packet primitives. It manipulates actual Ethernet/IPv4/TCP/UDP
frames between two explicitly selected isolated ports. The existing offline
trainer and direct-client decoy engine retain their API; this backend does not
replace the installed device/full-wide route or promise DPI efficacy.

Install from source, or from a verified private operator archive containing
`bin/aegis-geneva-bridge`, using a fresh prefix:

```sh
./install.sh geneva-bridge --prefix /opt/aegis-geneva-owned-test
ip netns exec OWNED_BRIDGE_NS /opt/aegis-geneva-owned-test/bin/aegis-geneva-bridge out0 in0 /absolute/strategy.dsl 30 10000
```

The private operator archive includes the executable, helper and this document.
Its file sums and inner manifest cover the executable; the signed release
manifest covers the enclosing archive. The public device-client payload is not
expanded. Verify the release provenance before executing an archive installer.
The installer creates only `PREFIX/bin/aegis-geneva-bridge`, refuses existing
prefixes and starts no service. Source installation uses the lockfile and
`live-linux` feature. The strategy file must be a regular non-symlink file,
read with a 64-KiB bound; FIFO/device inputs are rejected without waiting.

The operator supplies a dedicated network namespace with only loopback and
the selected ports. The backend rejects the initial namespace, addressed
ports, existing bridge masters and kernel IP forwarding. It never creates or
moves interfaces, modifies routes/firewall/sysctls, or edits client services.
It requires Linux AF_PACKET/CAP_NET_RAW. Both directions execute their own
forest; kernel outgoing capture must be disabled successfully. Checked ARP is
forwarded unchanged. IPv6, VLAN, unknown EtherTypes and malformed frames are
refused. Endpoint IPv6 autoconfiguration must be disabled by the operator.
Destination addresses remain visible; this layer supplies no encryption or
anonymity.

## Executed semantic surface

`live::program::Program` executes every matching tree on a fresh original copy.
No match returns the original. Gas is stateful per tree/direction: positive N
fires N matches, zero never fires, negative N skips abs(N) matches then fires.
Counters commit only when the complete batch succeeds. Triggers support
numeric fields, canonical flags, dotted IPv4 addresses, encoded load strings,
terminal-wildcard substring matching and the option/DNS fields below.

| Layer | Fields executed on actual bytes |
|---|---|
| IP | version, ihl, tos, len, id, flags, frag, ttl, proto, chksum, src, dst, load |
| TCP | sport, dport, seq, ack, dataofs, reserved, flags, window, chksum, urgptr, load; options-eol/nop/mss/wscale/sackok/sack/timestamp/altchksum/altchksumopt/md5header/uto |
| UDP | sport, dport, len, chksum, load |
| DNS | id, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, qdcount, ancount, nscount, arcount; qd through the original compress transform |
| DNSQR | qname, qtype, qclass |

Actions execute pass/drop/duplicate, TCP segmentation, IPv4 fragmentation,
replace/corrupt/signed add and original DNS compress. `truncate` and plain-hex
payload input in the historical offline API are Aegis extensions. Unknown
fields/actions and unrepresentable object values are typed parser refusals;
they never silently become a different action.

TCP fragment size `-1` or an oversized cut selects midpoint; overlap is
clamped to available tail and sequence wraps at 32 bits. IP cut sizes count
8-byte units of the entire transport body, including TCP/UDP headers; midpoint
is aligned and cuts inside a transport header produce opaque fragments. The
original merged-tail DF flag behavior is retained. Original IP overlap parses
but has no effect. Header-only/no-load cases duplicate without repairing their
original checksums. `True`/`False` and historical ordering aliases are accepted.

IP flags use original logical values 0..7 and names MF/DF/evil. TCP flags use
FSRPAUECN. Named trigger equality uses canonical spelling; wildcard compares
substrings. Loads use UTF-8 decode-ignore plus URL quoting/unquoting, including
escaped grammar delimiters and original HTTP/DNS template tokens. IP load
replacement replaces the entire old transport layer with Raw; TCP/UDP load
replacement preserves that protocol's header. Missing layers are no-ops.

Numeric values use their actual field widths. Intentional malformed declared
length/IHL/data offset and explicit checksum writes remain wire declarations.
Program actions follow original checksum reset/write order. Branches preserve
independent logical TCP option lists, including an appended option after EOL:
subsequent actions can edit it although a receiver stops parsing at that EOL.
Option mutation retains unknown options/order and enforces the 40-byte header
limit. Timestamp/alternate-checksum tuple construction follows the original
first-value mapping; arbitrary Scapy object evaluation is not supported.

DNS is recognized on port 53 in a complete per-frame UDP message or a complete
length-prefixed TCP message; this backend does not reassemble TCP streams.
Question-name edits rewrite compressed owner/RDATA names, including CNAME,
SOA, MX, SRV, DNSSEC and supported service records, while leaving opaque address,
TXT/signature bytes untouched. Pointer cycles and malformed records refuse the
whole batch. Numeric header edits do not invent missing question/record bytes.
Original `DNS:qd:compress` produces the two raw forward-pointer questions for
UDP; TCP and no-question packets are untouched. Existing RR sections are
serialized before appended raw questions, preserving the original transform's
odd record-bearing layout and fixed pointer base rather than claiming it is
valid DNS. It is not an arbitrary compound-object serializer.

## Finite bounds and remaining compatibility limits

The CLI requires lifetime 1–900 seconds and input budget 1–100000 packets;
total outputs are capped at one million frames. Strategy bounds are 64 KiB
ASCII, 128 trees and depth 6. Frame size is at most 65549 bytes; one original
packet yields at most 64 frames/262144 bytes across the entire forest. DNS
relocation permits at most 256 questions/records, names at most 255 bytes and
128 pointer hops. Over-budget results are atomic errors with no emitted prefix
or pass-through fallback. I/O send errors terminate the process; frames already
sent cannot be undone. Kernel loss or unavailable loss counters is an error.

This is an explicit bounded original-field backend, not arbitrary Python/Scapy
execution. Negative fragment values other than midpoint -1, invalid URL
escapes, unencodable binary option/object values, malformed or incomplete DNS
messages, and representations outside those finite bounds are refused. Some
original Python mutations can construct values that Scapy later cannot encode;
this backend refuses those values before returning a batch. No claim of exact
random-number distribution or all malformed Scapy object behavior is made.

Stopping the process closes its packet sockets. There is no kernel bridge or
routing fallback. Remove only owned namespace/veth resources after process
exit. To uninstall, verify the installed file ownership/hash and absence of
foreign entries, unlink it and `rmdir PREFIX/bin PREFIX`. There is no persistent
service, identity, firewall or routing state created by the installer.

## Evidence and pending integration

Byte-level tests cover real packet/checksum/offset/sequence/gas/field behavior.
They are not native socket evidence. The private CI rust job separately builds
the optional binary and prepares a bounded native harness that actually runs
this installer, checks the installed-copy hash, exercises both directions in
fresh unnamed net/mount namespaces, then verifies process/watchdog/network and
owned-prefix cleanup. An independent host watchdog is ready before topology.
Only explicit metadata and diagnostic logs are retained as a private artifact.
No controlled native result has yet been accepted for this source branch.

Default device/full-wide interception still does not select this backend.
Controlled namespace tests cannot prove target-network DPI evasion, privacy,
ECH acceptance, independent captures/review, 24-hour stability or beta exit.
Those accepted criteria remain separate. Original fields and textual parsing
are grounded in [Geneva layers](https://github.com/Kkevsterrr/geneva/tree/master/layers),
[trigger gas](https://github.com/Kkevsterrr/geneva/blob/master/actions/trigger.py),
[forest execution](https://github.com/Kkevsterrr/geneva/blob/master/actions/strategy.py),
[fragment](https://github.com/Kkevsterrr/geneva/blob/master/actions/fragment.py),
[tamper parsing](https://github.com/Kkevsterrr/geneva/blob/master/actions/tamper.py)
and [DNS compress](https://github.com/Kkevsterrr/geneva/blob/master/layers/dns_layer.py).
