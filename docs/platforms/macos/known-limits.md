# macOS: known limits

## Current installed and source status — 3 November 2026

Installed v43 from source `08f81156` completed an ordinary 30 PASS/0 FAIL
window with `LEAK_CAPTURE=0`. It did not execute the required all-interface
packet capture or second-interface and sleep conditions, so S20 and D1–D6
installed acceptance remain open. Five older weak backup apps were moved into
root quarantine; retained old ZIPs remain available for recovery and their
downgrade boundary is still open. The combined `557a0180` Mac protocol source
has independent source review only; optional enrolled QUIC is default-off and
has no compiled or installed result at this source. Cloudflare G1/ECH G3/G4,
real multi-carrier switching, standalone SFU, signed package, complete legal
and SBOM proof, independent endurance and exact-final-commit CI remain open.

The historical v24 observations below retain their original scope.

What the installed macOS client (v24, flow-pool line) does not do yet, or
does only under conditions. B-06 remains **NO-GO**; nothing here is release
acceptance. Evidence is in the [B-06] entries of the
[change and incident log](../../../CHANGELOG.md) and
the [source package README](../../../tools/macos/aegis-network-extension/README.md).

## Pre-tunnel connections on the physical interface

Connections that existed **before** the tunnel came up keep producing a
small number of packets on the physical interface after Connected. The v24
capture-backed window (23 October, `LEAK_CAPTURE=1`) failed `leak_proof`
with 180 non-relay packets: 150 from this Mac's own pre-existing flows
(zero-length kernel TCP keepalives on old sockets, ICMPv6 port-unreachable
for a closed QUIC socket, echo replies to the LAN gateway's ping, and
inbound retransmissions/FINs from peers), 29 frames of other LAN devices
and 1 IGMP. No connection opened after Connected left the physical
interface, and no application payload or DNS of this Mac was seen there,
but the residue still carries the Mac's real addresses (mostly its global
IPv6) to those peers. The proof therefore stays **FAIL**.

The VPN profile is already the strictest Apple offers
(`includeAllNetworks=true`, every exclusion off, `0.0.0.0/0` and `::/0` into
the utun). No NetworkExtension call closes other processes' existing
sockets, and waiting longer before Connected does not help (probes were
still seen at +28 s). The fix is a packet filter below the socket layer,
**S20b**: an NEFilterPacketProvider in the same system extension that,
while a tunnel session runs, drops every packet on a physical interface
except the relay TCP and link control (v25 to v30 also allowed the
enrollment authority's TCP; v31 does not, see
[certificate renewal while connected](#certificate-renewal-while-connected-v31)). S20b
needs build **v25** or later. No capture window has passed `leak_proof`
with it: the v26 window still failed on arrivals and other devices'
frames (see [leak criteria](#leak-criteria-on-the-physical-interface-s20d)).
Until a window passes, assume that pre-existing connections can emit such
packets. See the
[S20a analysis](../../../tools/macos/aegis-network-extension/README.md#b-06-s20a-leak-attribution-after-the-v24-capture-window-source-only-23-october)
and the [leak review](../../../tools/macos/aegis-network-extension/harness/README.md#real-relay-window-leak-capture-b-06-s20).

## Leak-guard packet filter (S20b) conditions

What the S20b filter needs and what it does not cover, once installed
(commands in [install and enable](install-and-enable.md#leak-guard-packet-filter-s20b)):

- **A separate approval.** The first `aegis-ne-host --enable-filter` shows
  "AEGIS would like to filter network content"; only a click on **Allow**
  enables it (declined: exit 35). `--filter-status` must exit 0
  (configured, enabled, attached) for the guard to be in force.
- **The tunnel does not require it.** With the filter disabled or removed
  before a connect, for example in System Settings, the tunnel still
  connects without the guard; `--filter-status` then exits 31 `disabled`
  (disabled) or 30 `not_configured` (removed). Exit 33 `not_attached` and 69
  `provider_unavailable` arise only with an enabled filter. The window
  harness refuses a `LEAK_CAPTURE=1` window on every non-zero exit
  (`FILTER_REQUIRED=1`). From v26 (source only, not yet installed) a filter
  that stops while a session is guarded fails that session closed
  (`session_failed leak_guard_filter_stopped`): the tunnel cancels rather
  than run unguarded.
- **The administrator prompt is only in the host (v26).** It guards
  `--disable-filter` and `--remove-filter` of the v26 host, and nothing
  outside the host checks it. A signed older host with those verbs (v25) or
  System Settings can still disable or remove the filter with no AEGIS
  prompt. The v26 provider fails a guarded session closed when that
  happens, `install-app.sh` refuses to install v25, and both scripts remove
  the host executable from kept v25 copies (v30 review: from kept v26 to
  v29 copies too, whose prompt offers Touch ID; see the v30 section). A v25 stapled ZIP in an
  artifacts directory can still be unpacked and run by the console user.
  With the tunnel disconnected, a change like that shows only in
  `--filter-status` (and the next `FILTER_REQUIRED=1` window refuses).
  None of this has been observed on the installed client.
- **Inbound peer packets and other LAN devices' frames** still appear in a
  capture on the physical interface. No client can prevent them: they
  arrive on the link whatever the Mac does, and the capture sees them
  before any filter on the Mac can act. `leak_proof` counts them. The
  separate S20d Mac-sent criterion never does (see
  [leak criteria](#leak-criteria-on-the-physical-interface-s20d)).
  The owner chose the Mac-sent row as the S20 criterion (24 October);
  `leak_proof` is unchanged and stays in every report.
- **ICMP presentation to packet filters is unproven.** Apple guarantees TCP
  and UDP; the per-reason counters (for example `drop_icmp6_echo` during a
  gateway ping) will show whether ICMP reaches the filter.
- **Captive portals** cannot be signed in while the guard is active;
  disconnect first. AWDL, low-latency WLAN (`llw`) and bridge interfaces
  are dropped while guarding (AirDrop and similar stop during a session).
- **Always-on cost.** The filter stays enabled while the VPN is off (it then
  allows everything, with a small per-packet cost); enabling it only around
  Connect is an open decision. A known macOS issue with Thunderbolt bridges
  and packet filters (FB21256925) is part of that decision.
- **Relay on any interface.** Relay traffic is allowed on every guarded
  interface, not only the pinned one, so an S18 re-pin after an interface
  switch needs no filter change.

## Leak criteria on the physical interface (S20d)

The installed v26 window with `LEAK_CAPTURE=1` (23 October) captured the
Ethernet interface `en7`. It **failed** `leak_proof`, which stays the
recorded S20 result.

- 186 non-relay frames in the reviewed 28 s, against 16059 relay packets.
- 147 were host-class arrivals to this Mac: TCP of connections opened
  before Connected, new inbound UDP, and ICMP.
- 32 were other LAN devices' frames, 6 were IGMP and 1 was link control.
- No new outbound flow, and no outbound host frame.
- tcpdump reported 0 kernel drops. The leak guard's drop counter rose from
  454 to 719 between the readings before and after the window.

Arrivals and other devices' frames reach the link whatever the Mac does.
No client can prevent them, so `leak_proof` cannot pass while they come.

S20d adds a separate criterion in source (`mac_sent_*` in
`leak_review.py`, and the window's `no_mac_sent_leak_physical` row). It
counts only frames the Mac itself sent, and excludes only these:

- relay transport;
- ARP, DHCP, IPv6 ND/RS/RA and MLD;
- EAPOL.

mDNS, broadcast and IGMP from the Mac count. A read-only re-review of the
retained captures gave these results:

- **v26 (`en7`):** 0 Mac-sent frames in the reviewed interval, and 0 in
  the guard seconds. `pass` and every strict field match the window's own
  review.
- **v24 (before the filter, negative control):** 34 Mac-sent frames, so
  it fails. They were 27 TCP keepalives and 3 other zero-length TCP
  segments on old sockets, 2 ICMPv6 errors and 2 echo replies. 2 more fell
  in the guard seconds.

Limits of that result:

- The v26 window captured `en7` only. Wi-Fi (`en0`) was up on the same LAN
  and was not captured, so this is not a `no_mac_sent_leak_physical` pass.
  That row needs every interface the Mac could send on captured. It would
  have failed as `uncaptured=en0` (S20d wrote `uncaptured_active=en0`).
- From S20d the window captures every active interface. In source (S20e)
  this covers every port the Mac could send on, active or not, whatever
  its addresses: bridge members, link-local-only ports, `bridge0`, `ap*`
  and `anpi*` included, and VM-only ports excluded. Each capture other than
  the default route's runs under a root alarm, so a quiet one ends even
  when the window is killed. Every review also knows the Mac's MACs and
  addresses from before connect and right before the disconnect, so a
  frame sent under a MAC rotated by a rejoin still counts. No window has
  run with any of this yet.
- An interface tcpdump cannot open refuses the window before connect. On
  this Mac `anpi*`, `ap1`, `bridge0` and its member ports are present
  without a link, and no window has opened a capture on them yet.
- Owner decision (24 October): the S20 criterion is the Mac-sent row,
  `no_mac_sent_leak_physical`, on a capture of every interface the Mac
  could send on. `leak_proof` stays in every report. An S20 PASS also needs
  a passing positive control and a negative control (filter off) that
  fails. The v27 window (24 October, 15 interfaces captured) passed the
  Mac-sent row over the Connected interval and the armed span, and failed
  `leak_proof` as expected; the negative control failed as required; the
  positive control was inconclusive (see
  [the controls](#filter-observability-and-the-two-controls-s20f)). So no
  S20 PASS exists yet.

See the
[harness README](../../../tools/macos/aegis-network-extension/harness/README.md#mac-sent-criterion-and-every-active-interface-b-06-s20d).

## Filter observability and the two controls (S20f)

v27 adds, in source only, what the v26 window could not show:

- The v26 filter counted 21 outbound TCP drops that never appear in the
  `en7` capture. Either they were on another interface (Wi-Fi `en0`, AWDL
  and `llw0` were up and not captured), or the macOS BPF tap sees an
  outbound frame only after the packet filter, so a dropped frame never
  reaches a capture. Apple documents neither. v27 counts drops by the
  interface class they were presented on (`primary`, the pinned relay
  interface; `en_other`; `awdl_llw`; `bridge_ap_anpi`; `other`) and by
  direction, and keeps the last 64 drops with their interface (a macOS
  driver name such as `en7`, or a hash), TCP flag class and reason. No
  address, port or payload byte is kept.
- A transient disarm of the leak guard would have left no trace in v26.
  v27 counts arms, disarms, guarded milliseconds and `open_while_applied`
  (an Open interval while a tunnel epoch's settings may be applied), and
  logs each epoch's armed span (`leak_guard_span`). The window's
  `filter_armed_span` row checks that one arm covered the whole window.
  The Mac-sent criterion is also reviewed over the whole armed span, which
  starts before Connected and ends after the disconnect.
- `POSITIVE_CONTROL=1` probes each captured interface's LAN gateway with
  marked SYNs while the filter is armed and records whether the filter
  counted them and whether the capture saw them (`bpf_order_<if>`:
  `pre_filter` or `post_filter`). `NEGATIVE_CONTROL=1` runs the same
  window with the filter disabled. Both are owner-attended windows of
  their own; their rows are never S20 evidence.

The v27 owner session (24 October) ran both controls once:

- `NEGATIVE_CONTROL=1` failed its Mac-sent row as required (frames of
  sockets opened before the tunnel on `en7`), and the filter was restored
  and attached afterwards.
- `POSITIVE_CONTROL=1` was **inconclusive**. Every fresh probe bound to
  `en7` or `en0` connected in 6-7 ms, no capture held a marked SYN and the
  filter counted none: with `includeAllNetworks` the system routed the
  bound fresh sockets into the tunnel, where the provider's engine answers
  them. A fresh socket cannot exercise the filter.
- In the S20 window the filter dropped 18 outbound bare-ACK TCP packets on
  `en7` that the `en7` capture does not show: for that driver an outbound
  drop happens before the BPF tap sees the frame (post-filter).

v28 (S20g, source only) moves the positive control to pre-existing
sockets; see
[below](#pre-existing-sockets-in-the-positive-control-s20g). v29 (S20h,
source only) judges them by their kernel keepalives; see
[Keepalive positive control](#keepalive-positive-control-s20h).

Limits:

- Until a positive control passes, a Mac-sent frame in a capture may be one
  the filter dropped (if the tap sits before the filter on that driver).
  The Mac-sent rows then fail rather than pass: the criterion stays fail
  closed.
- The armed span includes the teardown after the disconnect and the
  settings application before Connected. Frames other processes send then
  count against the span; with `pre_filter` ordering the row can fail on
  frames the filter dropped.
- The milliseconds count awake time only (the clock stops while the Mac
  sleeps); the span lines carry wall-clock times.
- The ring keeps 64 drops. Under a burst a writer that meets a busy slot
  skips its record (counted as `skipped`) instead of waiting, and a slot
  read while it is written is left out (counted as `torn`).
- `primary` is the epoch's pinned relay interface by name, followed
  across a re-pin. Before the first arm nothing is `primary`.
- A v26 host refuses a v27 provider's `filter-status` reply as
  `reply_malformed` (`--filter-status` then exits 33). Host and provider
  ship in one app, so this shows only with mixed copies.
- `open_while_applied` is a tripwire: correct code never counts. A
  provider instance torn down without its stop leaves its epoch counted as
  applied, so a later Open interval may count once (the safe direction).
- The positive control ties `filter_drop_delta_<if>` to the probes through
  the drop ring: new outbound IPv4 TCP SYN drops on that interface under
  one arm. The ring keeps no port, so a SYN some other socket bound to the
  same interface sends during the few seconds of the probes would count
  too; a busy interface that pushes more than 64 drops through the ring
  meanwhile fails the row (`ring_lost`). `bpf_order_<if>` is classified
  only when the filter counted the probes and none was answered;
  otherwise it stays `unknown`.
- The arm numbers in `leak_guard_span` restart at 1 in every provider
  process. The window tells processes apart by the `[pid:tid]` of the
  compact log line; without it, a restarted provider's disarm is paired
  by number alone, and its repeated arm still fails the row as a re-arm.
- A `NEGATIVE_CONTROL=1` window saves the filter as disabled, and macOS
  keeps that across a restart. Its restores (the EXIT trap and the
  detached rollback) are user processes, not launchd jobs: a reboot,
  logout, power loss or panic during the window leaves the filter
  disabled. The harness then refuses every window until
  `--filter-status` exits 0 again (its marker
  `~/.aegis-local/negative-control-filter-disabled`), but tunnels started
  outside the harness are not stopped: a v26 or later provider fails a
  session closed only when the filter stops while it is guarded. After an
  interrupted negative control, run `aegis-ne-host --filter-status` and,
  unless it exits 0, `aegis-ne-host --enable-filter` before connecting.

## Pre-existing sockets in the positive control (S20g)

v28 adds, in source only, the probe the v27 positive control lacked. Before
the connect each control opens two TCP connections (`PRESOCK_N`) from every
captured interface with an IPv4 address to that interface's LAN gateway,
bound with `IP_BOUND_IF` and with short keepalives. While Connected each
socket writes a few marked bytes; `TCP_CONNECTION_INFO` shows whether they
were acknowledged. With the filter armed they must stay unacknowledged,
the filter must count their data drops on that interface, and no frame of
theirs may be in any capture while the filter is armed; with the filter
off (negative control) they must be acknowledged. A fresh probe answered
while armed fails the positive control too. A fresh probe that the
system routed into the tunnel is now reported as `tunnel_enforced`, from a
v28 provider's `engine_flow_open` log line. See the
[harness README](../../../tools/macos/aegis-network-extension/harness/README.md#pre-existing-sockets-and-tunnel-routed-fresh-probes-b-06-s20g-v28).

The v28 owner session ran it (24 October, Wi-Fi `en0`): the positive
verdict was `unavailable` and the negative control's write found its
sockets closed. Both follow from the criterion, not from the filter: with
`includeAllNetworks` the written segments never reach the filter, filter
or not, and the gateway reset the sockets about 15 s after their
handshake, before the late write. v29 replaces the drop delta (next
section); the limits below are those of the v28 rows.

Limits:

- The gateway must accept a TCP connection on 80, 443, 53 or 8080 (never
  the relay port, so with a relay on one of them only three are tried). A
  gateway that offers none makes the positive control `unavailable` on
  that LAN.
- Only IPv4 sockets to the on-link gateway are probed: no IPv6 socket and
  no remote host. A gateway that resets or closes idle connections before
  the write leaves the sockets `not_written` or answered; a reset that
  arrives while armed fails the verdict (fail closed).
- "Acknowledged" means `tcpi_snd_sbbytes` fell below what was buffered
  plus written: any acknowledged byte, even part of a write, counts as an
  answer. The public `struct tcp_connection_info` has no `snd_una`.
  `tcpi_rxpackets` counts only segments with data, so a bare ACK from the
  gateway shows only through `tcpi_snd_sbbytes`.
- While armed the filter also drops the gateway's answers inbound, so
  written bytes that left the Mac stay unacknowledged as well:
  `presock_unacked` passing does not show that they stayed on the Mac.
  The verdict takes that from the captures (no frame of the helpers in any
  capture during the armed span); data frames of a helper there while its
  drop delta did not pass fail it.
- The drop ring keeps no port: another pre-existing socket on the same
  interface that sends data in the same few seconds also counts toward
  `data_drops`. `need` is every data segment the written sockets sent,
  retransmissions included (`tcpi_txpackets`), so those drops must cover
  all of them, but a passing delta still does not show that the helper's
  own segments were dropped. A helper frame in a capture beside a passing
  delta is therefore never read as `pre_filter` and keeps the verdict
  `unavailable` (`frames_seen`). The window has no independent measure of
  the tap order (the fresh probes' `bpf_order` rests on the same kind of
  count), so on a driver whose tap sits before the filter the positive
  control cannot pass while that interface is probed.
- The write's time in the ring is the provider's monotonic arm clock
  compared with wall-clock readings over a few seconds, so a drop up to
  one `--filter-status` return before the write also counts.
- `presock_bpf_order` uses the provider's armed span; without it (a
  provider before v27, or no span lines in the log) the order stays
  `unknown` and the verdict `unavailable` (`frames_unchecked`).
- `engine_flow_open class:discard` is logged for the first 64 port-9 flows
  of each engine device; later ones are only counted. Other classes are
  logged at most once a second. A provider before v28 logs none, and the
  fresh probes then keep their `fail`.

## Keepalive positive control (S20h)

v29 (source only) judges the positive control's pre-existing sockets by
what actually reaches the filter. The system holds a pre-existing socket's
own output (written data, its pure ACKs, UDP sends) before the packet
filter while `includeAllNetworks` is on, with the filter or without it;
its kernel keepalives and ICMPv6 errors pass that hold. The helper binds
its sockets to TCP source ports of a fixed marker range (47000..47031),
the provider counts outbound drops by kind and marks the TCP ones from a
port of that range, and keeps a ring of outbound drops that inbound drops
never overwrite. The verdict passes only when the filter counted the
sockets' marked keepalives on every due time between two reads at least
two keepalive intervals apart, nothing was acknowledged, no frame of the
helpers is in any capture while armed, and every such capture is
complete (alive, stopped, no kernel drop, a frame after the disarm).
The data segments the sockets wrote are reported as counted or
`blocked_before_filter`. See the
[harness README](../../../tools/macos/aegis-network-extension/harness/README.md#keepalive-positive-control-and-early-negative-write-b-06-s20h-v29).

Limits:

- Not built, installed or run. Its verdict is only as good as the next
  owner session.
- The marker is the source port because a TTL cannot be one (S20h
  review): XNU sends keepalives through `tcp_respond`, which takes the
  connection's addresses and ports from its template but sets an IPv4
  packet's TTL to the system default (`ip_defttl`, 64), never the socket's
  `IP_TTL`. The first v29 draft marked by TTL 77 and could only ever have
  read `unattributed`. A keepalive carries its connection's ports by
  construction, so the port marker reaches every one; the negative
  control's `presock_wire` counts the helper's bare ACKs on the wire from
  the range (`ack_only_marked`). No capture has yet shown a keepalive
  from a marker port reaching the filter: that waits for the next owner
  session. If drops are still unmarked the row reads `unattributed`;
  unmarked drops on every due time read `pass_inferred`, never a pass.
- The due times assume TCP's receive time stands still while armed (the
  filter drops every inbound frame) and start from the socket's last frame
  from the gateway before the arm in the capture. A gateway that answers
  through another path, timer jitter beyond 500 ms or a capture without
  the gateway's frames (the helper's connect time is used) can read
  `ticks`.
- Another socket on the Mac bound to a source port in 47000..47031 is
  counted as marked; it cannot make up for a missing keepalive on its due
  time on the probed interface, but it can raise `counted`. A helper
  socket that finds every port of the range taken does not open
  (`eaddrinuse`), and the preflight keeps the fresh probes' ports
  (`PC_SPORT_BASE`, on every interface present at the preflight) out of
  the range. The helper closes its sockets with
  a reset (`SO_LINGER` 0), so no `TIME_WAIT` holds a marker port into the
  next window.
- A capture with a kernel drop, one not alive at the disconnect or not
  stopped by the window, or one with no frame after the disarm, keeps the
  verdict `unavailable` (`captures_incomplete`): it may have missed a
  helper frame that left.
- `frames_left` (fail) rests on in-window tap evidence: for one frame
  kind, the filter dropped more of the marker's segments on that
  interface between the reads than its complete capture holds from the
  marker's ports while armed. A tap before the filter records every
  frame the filter drops, so only a tap after it gives that. It assumes
  one tap order per interface for every TCP segment, and that the filter
  and the capture classify a segment's kind alike (both read the IP and
  TCP lengths and flags). It needs a passing `filter_armed_span`; without
  one, or when the capture holds as many of the marker's frames as were
  dropped, the frame counts stay a lower bound (`uncounted`) and frames
  beside enough counted drops read `frames_seen`.
- The outbound ring keeps 64 drops: more than 64 outbound drops between
  the two reads (10 s by default) read `ring_lost`.
- `uncounted_frames` compares the helpers' frames in a capture with the
  marked drops of the interface's class. Several probed interfaces of one
  class (`en_other`) share that count, so a leaked frame there may read
  `frames_seen` (unavailable) rather than fail unless the tap evidence
  gives `frames_left`; never a pass.
- The pre-arm gap: in v28 the system already held socket sends about
  1.6 s before the filter armed, and a few zero-length ACKs left the Mac
  in that gap. It lies outside the Connected interval, so no S20 row
  changes.
- Tap order: on `en7` (v27) and `en0` (v28) the outbound BPF tap comes
  after the filter (counted outbound drops, none in the capture) and the
  inbound tap before it (the dropped inbound frames are in the capture).
  The window still never reads a helper frame in a capture as
  `pre_filter`.
- Negative control: the write now comes right after Connected, before a
  gateway that resets idle connections can close the sockets. With
  `includeAllNetworks` the system may still hold the written bytes with
  the filter off; `presock_acked` then fails, and `presock_wire` shows the
  helper's keepalives on the wire.
- A v28 or older host refuses a v29 provider's `filter-status` reply as
  `reply_malformed` (exit 33); a v29 host reads v27 and v28 replies.

## D4–D6 provider route boundary after v41

The next source candidate validates a mixed direct H2/own HTTPS bridge
program and sends the held bridge admission credential only on its selected
bridge pin. This has passed source tests, but has no signed installed traffic
outcome. The macOS provider still owns H2 streams and an H2 driver throughout
its ACK and flow lifetime; WS, QUIC and web-response byte streams cannot be
admitted through that owner. Its D5 web-response sidecar and key are now held
and revalidated, but D5 remains refused before crypto/network I/O until a
real byte-stream owner, signed ingress-pin guard and recovery proof exist.
D6 SFU needs an actual media worker and installed outcome. The v41 installed
profile has one direct relay pin, so it supplies no real two-carrier evidence.

Physical multi-pin review requires the public four-member bundle to hash to
the installed provider's `--profile-terms` digest; it allows only exact
numeric H2/bridge TCP pins in signed route order. The current v41 bundle
proves exactly one pin. A second listener alone would not prove Cloudflare
edge behavior. The separate signed/notarized candidate, independent leak
capture and D1–D6 installed acceptance remain open.

## IPv6 egress depends on the relay

IPv6 is routed into the tunnel (`fd00:ae61::1/120`, `::/0` on the utun,
source address `fd00:ae61::1`; since v22). Whether global IPv6 destinations
work depends on the relay: the relay must have IPv6 egress. Against a relay
without it, global IPv6 is refused at the relay, not sent outside the
tunnel, and applications fall back to IPv4 only if they do so themselves
(AAAA answers are not suppressed). The v23 and v24 windows against
`relay-a` passed HTTP over IPv6. DNS to the IPv6 anchor
`fd00:ae61::2` is answered inside the tunnel. ICMP echo to the anchors is
dropped. See [S16j-2](../../../tools/macos/aegis-network-extension/README.md#b-06-s16j-2-ipv6-routed-into-the-tunnel-source-only-22-october).

## PolicyAck lease of 3 s under load

The relay grants a PolicyAck lease of at most 3 s (aegis-core
`MAX_STALENESS`; the server owner keeps it), and grants of 2.0-3.0 s are
normal. The provider renews with up to two requests in flight over one
persistent ACK connection, but during a heavy post-connect burst every
connection to the relay slows, round trips stretch to 1.3-2 s, and the
lease can lapse. The tunnel then reasserts and rebuilds (packets drop for
the gap; nothing leaks). Observed: 8 losses in the v22 window, 2 in v23
(both rebuilt at the first attempt), one during the v24 Wi-Fi-off cycle,
and two in window-v41-verify-r1 on build 41 (2 November, the Mac's load
average 10 to 14 under the owner's foreground apps; whoami failed inside
the second rebuild; the repeat r2 passed 30 of 30 with no loss).
Flows open at the moment of a loss end with their session
(`flow_open dropped`). See [S16m](../../../tools/macos/aegis-network-extension/README.md#b-06-s16m-v23-residuals-ack-connection-losses-the-two-lease-losses-and-the-cold-first-flow-source-only-23-october).

## Relay capacity values are built in

This build assumes the relay limits of `relay-a`, the only macOS test
relay: 1024 inner sessions and 32 concurrent inner handshakes per peer IP,
with timeouts not counted as authentication strikes (server change R2). The
values are compiled in (`RELAY_SESSIONS_PER_IP`, `RELAY_HANDSHAKES_PER_IP`
in `establish_limit.rs`), not read from a signed per-relay setting.

Against a relay at the aegis-core defaults of **128 sessions** or **16
handshakes per peer**, the client over-admits: up to 248 live flows and 22
concurrent handshakes per session. The relay then refuses sessions (read as
unanswered Opens, which back all flows off for 2 s) and caps handshakes
after their 200 (which narrows that pool connection). A relay without R2
also counts handshake timeouts as authentication strikes, and three strikes
ban the IP for 300 s. Use such relays only after the capacity values are
made per-relay. See the
[live-cap derivation](../../../tools/macos/aegis-network-extension/README.md#b-06-live-cap-for-the-deployed-1024-session-relay-and-v21-prep-review-source-only-22-october).

From build 41 a re-pin's own teardown (an interface switch) no longer
enters the client's strike ledger: each pooled flow it cuts in its inner
handshake is logged `pool_repin_spared count:<n>` instead of `pool_strike`.
`relay-a` (R2) charges none of them. A relay without R2 would charge
each one at its 5 s deadline (up to 16 per switch), so such a relay can ban
the Mac's IP after one switch made during a burst of new connections; it is
outside these built-in values anyway.

## Flow bursts and the first flow

Each flow costs an inner handshake on a pooled connection. In the v24
window, bursts of 24 and 90 parallel connections completed 16-19/24 and
78/90; the cold first TCP connection right after Connected timed out in
the normal v24 window and passed in the capture window. Expect occasional
slow or refused connections in the first seconds after connecting. The
S20c/S16o changes (at most four SYNs per port per engine batch, resets
towards the app for flows a lost session answered, per-stage re-ACK
reports) are in source for v25 and proven on loopback only. Those resets
go to applications through the tunnel interface, which the S20b filter
always allows.

In the v28 Wi-Fi windows (24 October) the bursts failed only in the two
windows with the filter attached (`flow_burst_24` 21/24, `flow_burst_90`
80/90) and passed with it off and in every cable window with it on or
off. The filter's load does not explain it: cable windows passed at the
same filter rate (about 1500 packets a second), the filter added tens of
microseconds to the relay's packets and dropped none, and the refused
flows were early refusals of relay handshakes that overran their bound
(`hs_bound`, `hs_inner`) on one pooled connection whose download had a
collapsed congestion window. The likely cause is head-of-line blocking on
that connection over lossy Wi-Fi; relay-side `TCP_NOTSENT_LOWAT` and a
pool that avoids slow connections are open and outside v29. Every v28
Wi-Fi window also carried an inbound LAN UDP stream of 8-12 Mbit/s that
no cable window had, so Wi-Fi and that load cannot be told apart yet. v29
only trims the filter's own work, verdicts unchanged: tunnel and loopback
packets read the guard's state with one load instead of the whole
snapshot, and the 2 ms drain tick reads the 26 counters only when a log
line may be due. Expect no visible change to the bursts from it.

## Identity changes under the provider sandbox (v30)

v26 to v29 asked the sandboxed provider to re-check the host's
administrator approval for an AEGIS right. authd checks the caller's
sandbox for every right before its rule, and the App Sandbox lets a
network extension obtain no AEGIS right, so on an installed v26 to v29
`--import`, `--forget-identity` and `--renew` are always refused
(`provider_refused identity_authorization_denied`; window-v29-reinstall-r1,
26 October). v30 (source only, not yet built, notarized or installed)
keeps the provider's own check but moves it to a right its sandbox allows.
What that rests on and what it leaves open:

- **Not yet shown installed.** That the profile's network-extension clause
  (`system.services.systemconfiguration.network` for holders of
  `com.apple.developer.networking.networkextension`) applies to the
  PacketTunnel system extension is read from the shipped profile, not
  observed. The provider logs `identity_proof_probe allowed status:0` (or
  `denied status:-60005`) when it starts, and `aegis-ne-host
  --identity-gate` reports it. If it is `denied`, no identity change can be
  approved (fail closed) and `uninstall-app.sh` stops at `identity-gate`
  before changing anything. v30 review: only `allowed` and `denied` are
  kept for the provider's life; a `failed` or `unavailable` probe (an
  Authorization Services error, for example while the extension starts
  early at boot) is probed again by the next `--identity-gate`, and the
  script then says to run it again instead of naming the sandbox. The prepared fallback, a host-only check that
  keeps v30's wire floor and password-only right, drops the provider-side
  check against a compromised current host and needs the owner's
  acceptance first.
- **Borrowed Apple right.** The proof is Apple's network-configuration
  right. Its rule is pinned exactly as macOS 26.5 (25F84) ships it (k-of-n 1
  over `is-root`, `entitled`, `_mbsetupuser-nonshared`,
  `authenticate-admin-nonshared`; the last a non-shared administrator
  credential of at most 30 s). An administrator's edit or a macOS update
  that changes it refuses every identity change
  (`identity_authorization_proof_rule_unexpected`) until Apple's rule is
  back. Its shape on macOS 14.4 and 15 is unverified.
- **Password only, not yet seen.** The AEGIS rules are registered
  `password-only` under new names (`dev.aegis.macos.identity-change`,
  `dev.aegis.macos.leak-guard-change`) because one resting Touch ID touch
  approved two consecutive v29 prompts. That the dialog then offers no
  Touch ID on 26.5 is read from authd's source, not yet seen. Each identity
  change and each leak-guard change needs a typed administrator password,
  each `session_live` retry of `uninstall-app.sh` too. The v26 to v29 rules
  (`dev.aegis.macos.identity-import`, `dev.aegis.macos.leak-guard-weaken`)
  stay in the authorization database (removing them needs an
  administrator). No v30 host asks for them, but a kept v26 to v29 host
  still does, with Touch ID offered (corrected in the v30 review: the v30
  text said nothing asks for them again). Its identity verbs are refused by
  the v30 provider (below); its `--disable-filter` and `--remove-filter`
  need no provider and would still work, so one resting touch could remove
  the installed build's leak guard. `install-app.sh` therefore never
  installs v26 to v29 any more, and after a verified install it removes the
  host executable of every kept v25 to v29 copy under its state directory
  (`backups/AEGIS.app.replaced-*`, `uninstalled/AEGIS.app.uninstalled-*`;
  `uninstall-app.sh` does the same for the copy it moves), its SHA-256
  kept beside it (`pipeline.py disarm-weak-host`, `LEAK_GUARD_PASSWORD_MIN`
  30). A copy that macOS App Management protects is reported and left in
  place: the owner moves it to the Trash in Finder. A copy kept anywhere
  else (outside the state directory) is not seen.
  On installed v42 (2 November), this was an actual block: disarm of all
  five kept v25–v29 host executables returned `Operation not permitted`.
  Their signed apps remained runnable by the console user, while exact
  stapled ZIPs and version-ledger receipts remained intact. No v42 traffic
  window was started before resolving those runnable copies. The v42 filter
  itself was attached and matched its provider PID at the read-only check.
- **What the provider cannot see.** It proves that the host's reference
  holds a fresh, non-shared administrator credential, not which dialog
  produced it; that rests on the signed v30 host asking for nothing else
  interactively on that reference. A root audit session with the console
  user's euid would satisfy `is-root`; only root can make one, and root can
  rewrite the authorization database anyway. A console-user process can
  still run the signed v30 host and raise a genuine AEGIS dialog, which now
  names the change (forget, import with the folder name, renew):
  social engineering only.
- **Older hosts.** v26 to v29 hosts are refused for identity verbs
  (`identity_authorization_host_outdated`), v25 and earlier have no form
  (`identity_authorization_missing`); their read-only verbs keep working.
  The floor is the XPC key name in signed, hardened code, not a
  code-signing requirement on each message: revoking v30 hosts later means
  renaming the key. Nothing here stops an old `AEGIS.app` copy (v25 or
  earlier) kept in a backup from activating its own older, ungated system
  extension (open in S14/S21); the owner removes old copies, with a backup
  kept outside `/Applications`.
- **The installed v29.** It can neither forget nor import until a v30
  provider is active: install and activate v30 (`install-app.sh --replace
  --activate`) first. The identity lives in the provider's App Group
  container, which the upgrade does not touch (inferred, not yet observed
  across this change).
- **Bundle anchoring** (pinning the device CA) is still not implemented: an
  administrator who approves can import any self-consistent tree.

## Sleep and interface-switch windows (v30 harness)

- **Sleep is disabled system-wide on the owner's Mac** (`pmset -g`:
  `SleepDisabled 1`, the `pmset disablesleep 1` setting, unchanged since
  about 8 October). The kernel then refuses every demand sleep
  (`kPMUserDisabledAllSleep`) and `pmset sleepnow` exits 71, which is why
  window-v29-sleep-r3 never slept. From v30 the window refuses before
  connecting while it is set, the guard refuses with no privileged call if
  it is set after the go, and every request records its cause and bounded
  output. Neither the harness nor an agent changes it: the owner clears it
  (`sudo pmset disablesleep 0`) after checking with the other lane, and
  decides about setting it again. S18 sleep and wake stays unproven until
  then.
- **A sleep request that outlasts the window's patience** (v30 review). The
  window now waits for the guard's verdict as long as the guard's own
  bounds allow (settle + 50 s of bounded reads + `SLEEP_GUARD_CALL_S` +
  10 s), and the guard and the window exclude each other through one
  exclusive claim file created right before the request: a window that
  stands the guard down (no verdict, Ctrl-C, a timeout, any EXIT trap,
  which now does this first) either holds the claim, and then the guard
  never asks, or keeps the dated wake (`sleep_wake_kept`), because the
  request may have run. `rc=timeout` is recorded as an unknown outcome
  with `slept_since_request=`, never as "nothing slept": the bound kills
  only the user's sudo, and the root pmset may still ask for the sleep. A
  request that succeeds only after the dated wake has passed still sleeps
  the Mac without a wake ahead; the guard asks only while that wake is at
  least 15 s ahead, and a request normally returns at once. A SIGKILLed
  window runs no trap; its guard still refuses when it finds the window
  gone right before the request.
- **Interface switch.** The attach wait helps only in the plug direction
  with an explicit `IFSWITCH_TO`; automatic candidate selection and the
  unplug direction still need the target present before the window. A
  target with a link already (cable in) is refused: the cable goes in only
  at the window's OWNER ACTION.
- **The plug direction on installed v32 (window-v32-ifswitch-r3, 27
  October).** Plugging the cable into en7 while on Wi-Fi made en7 the
  primary; en0 kept its address, so the v32 path watch kept the en0 pin
  (another interface becoming primary never moved a working pin). macOS
  held every packet of the provider's existing en0 relay sockets from that
  moment and sent its new sockets out en7 although they were bound to en0
  (a capture finding, not Apple documentation). The lease then ran out
  1.5 s after the path change (`session_lost capture_lease_expired`) and
  the rebuild pinned en0 again, by name only: tunnel traffic was down for
  about 3.95 s and the pin no longer named the interface in use. It failed
  closed (`no_mac_sent_leak_physical` passed) and recovered on the first
  rebuild. Source v33: a pin taken while it was the path's primary follows
  the primary, so the plug re-pins to en7 at the path change
  (`relay_interface_repinned name:en7`, `session_lost relay_path_changed`)
  and should rebuild about 1.5 s sooner. A pin taken behind another primary (a
  multi-homed Mac) still never moves while it works. Some outage remains:
  the old connections are cut when the primary moves. Not yet installed.
- **The plug direction on installed build 40 (window-v39-ifswitch-r1, 2
  November; the window is named v39 but ran on build 40).** The v33
  re-pin worked: en7 became primary, the pin followed it 0.6 s later
  (`relay_interface_repinned name:en7`) and the session was rebuilt 1.9 s
  later; `no_mac_sent_leak_physical` passed on 15 interfaces. But the
  re-pin's teardown cut nine pooled flows in their inner handshake, and
  builds up to 40 counted each as a strike (`pool_strike count:1` to `9`).
  The rebuilt session then ran at strike level 2 for 300 s: one inner
  handshake at a time behind a proof PING, one pooled connection
  (`pool_state conns:1-0-0`, 26 to 78 flows waiting), new connections
  refused as pool waits. `ifswitch_whoami_egress`, `ifswitch_udp_echo_v4`
  and `ifswitch_tcp_echo_v4` failed 6 to 20 s after the rebuild. The relay
  had charged nothing: it kept admitting the rebuilt session's handshakes.
  Build 41 counts no strike for a re-pin's own teardown (see
  [relay capacity values](#relay-capacity-values-are-built-in)); the
  switch window has not yet run on it. Remaining: a lost interface that a
  pooled connection reports before the re-pin (the unplug direction) still
  counts, as in builds 21 to 40; two or more such losses would narrow the
  rebuilt session the same way (look for `pool_strike` before
  `relay_interface_repinned`).
- **The probes right after a switch (v33 harness).** `ifswitch_recovered`
  reads only the system's state; in window-v32-ifswitch-r3 it passed
  before the provider lost its session, so `ifswitch_whoami_egress` ran
  inside the rebuild and failed. From v33 the probes wait for
  `ifswitch_settled_before_probes`: the provider's own log must show the
  rebuild done and 5 s of quiet (see the
  [harness](../../../tools/macos/aegis-network-extension/harness/README.md#ifswitch1)).
  A probe that starts inside an outage still fails; the gate only stops
  the window from starting one there. Because the gate waits out any
  rebuilt loss, the outage itself is judged by the provider's own lines
  (v33 review): `ifswitch_relay_path_exercised` needs the
  `relay_interface_repinned name:<new>`, and
  `ifswitch_session_lost_by_repin` fails on any `session_lost` since the
  owner's prompt other than the re-pin's `relay_path_changed`. Replayed on
  r3 both fail while every probe passes; r2 and r4 pass both. There is no
  bound on the length of a planned re-pin's outage beyond the gate's
  `IFSWITCH_RECOVER_S`; `rebuilt_after` reports it.
- **A Layer-2 Update frame from the access point (window-v32-ifswitch-r4,
  the unplug).** en7's capture held one 802.11F Layer-2 Update (an 802.3
  frame of length 6, LLC XID to broadcast) whose source MAC is the Mac's
  Wi-Fi private MAC: the access point sends it on behalf of a station that
  re-associates, and the wired LAN carries it back to en7 (the AP sent the
  same for another station 1 us later). `no_mac_sent_leak_physical` counts
  it as Mac-sent, and the owner keeps it counted (27 October: all traffic
  must be under Aegis): there is no exclusion, and that window is
  repeated. Its probes, re-pin and rebuild rows passed; the strict leak
  rows (`leak_proof` and the like) fail as in every window, and the
  owner's S20 criterion is the Mac-sent row.

## Certificate renewal while connected (v31)

In the installed builds from v31 (S23b; v31 ran installed on macos-test-2
by 27 October, then v32 and v33). Its deferral, carried backoff and
`--status` line have not yet been seen on an installed client (see
[not yet proven](#not-yet-proven-on-the-installed-client)).

- **Why.** In `window-v30-ifswitch-r3` (26 October) a due renewal sealed a
  session that had been back for 5 s, held the tunnel down 9.8 s and sent
  21 TCP SYNs to the enrollment authority's port 9445 on the physical
  interface. The v25 to v30 leak guard allowed them; the window's Mac-sent
  row counted them (`no_mac_sent_leak_physical` FAIL, a valid receipt that
  stays a FAIL). Port 9445 never answered from Ethernet or Wi-Fi, while
  port 443 of the same host did.
- **Renewal transport pending (option B).** The renewal should reach the
  authority through the relay's own 443 endpoint (a relay enrollment route
  on the server, then a profile whose `enrollment.authority_server` is the
  relay tuple). That needs server work in the relay owner's lane and a new
  profile; it is not built. Until then the authority's own port is a
  separate, unfrontable endpoint that a network can block on its own.
- **Deferral (interim, fail closed).** While the leak guard is armed (any
  connected or reasserting tunnel), the provider dials no tuple other than
  the relay's. A renewal that falls due then is deferred: no dial, no
  teardown, the old certificate keeps carrying traffic, `--cert-status`
  shows `deferred:guarded`, and `--status`/`--ping` print `renewal
  deferred:guarded (due since <UTC>; runs at the next connect), expires at
  <UTC>, ...` on stderr. The renewal runs at the next **Connect**, before
  the filter arms. A session that lasts past `not_after` therefore expires
  fail-closed (`session_identity_expired`, blocked, nothing leaks): disconnect
  and connect again once the line appears, well before the expiry it
  names. The filter no longer allows the authority at all; the
  `allow_authority` counter and `authority_armed` stay in `--filter-status`
  and read 0 and false. With an authority on the relay's own tuple (option
  B) the renewal is relay traffic and runs while connected.
- **No teardown for a renewal that cannot help.** Even where a renewal may
  dial (option B), the provider seals a session for it only when the
  session has been live for 30 s and the last failure was not a transport
  one (`connect_timeout`, `unavailable`, `interface_unresolved`) with no
  journal; later attempts then ride the next natural rebuild or Connect,
  except in the last hour before `not_after` (at most half the time from
  due), where the backoff alone paces the seals: a session the network
  never rebuilds still gets attempts before it expires. An operator's
  `--renew` may still seal a stable session.
- **Backoff kept between Connects.** The provider process keeps the
  renewal record (keyed by certificate window and import generation): a
  Connect within the backoff (60 s doubling to 15 min) makes no attempt,
  and after a step whose every connect timed out the next makes one
  connect (2 s) instead of three (6.3 s). A Connect beside a journaled
  request is the exception: it always tries the receipt recovery first,
  because it is refused otherwise and `--renew` cannot force it without a
  running session. A Disconnect during a renewal's connect counts as no
  attempt and no connect timeout. The record is lost when the
  provider process restarts (reinstall, reboot); `--cert-status` reports it
  while disconnected, for the current identity only (an import or forget
  hides the older record).
- **The test CA deadline.** The test relay's CA expires 2026-10-28 11:52:13
  UTC and its issuer signs 24 h certificates, so the authority refuses any
  renewal after 2026-10-27 11:52:13 UTC ("cannot outlive its issuer"); the
  device certificate itself expires 2026-10-28T11:43:50Z. After that only a
  new CA, profile and enrollment (then `--import`) restore a working
  identity.
- **Older hosts.** A v26 to v30 host cannot decode a v31 `cert-status`
  reply that carries a failure (`failing_since`, `connect_timeout`) or
  `deferred:guarded` (`reply_malformed`); use the v31 host.

## Renewal outcomes that cannot be installed (v32)

Built, notarized and installed from v32 (S23c; v33 is extension
0.1.0/33). The parked and superseded paths below are tested in source;
no installed receipt of them is recorded here.

- **The incident (27 October, installed v31, macos-test-2).** The device
  certificate (2026-10-22T18:23:56Z to 2026-10-28T11:43:50Z) was renewed
  at the 06:20:41Z Connect. The authority signed a 24 h successor ending
  about 2026-10-28T06:20:41Z, before the predecessor; the provider refused
  it (`local_refused`, no check named) and kept the request journaled.
  Because the authority had already replaced the device's registry record,
  the relay no longer admits the predecessor, and every Connect recovered
  the same receipt, refused it again and failed the start.
- **The lifetime rule.** A renewal from the due instant (two thirds of the
  lifetime) extends its predecessor only while the device lifetime T is
  below about 3 x the authority's `lifetime_secs` L (plus 180 s). With
  T = 494394 s, L = 86400 s, the predecessor ending 2026-10-28T11:43:50Z
  and the CA 2026-10-28T11:52:13Z, the authority (which signs now + L and
  refuses a certificate that would outlive its CA) had three bands: from
  2026-10-26T13:58:12Z to 2026-10-27T11:43:50Z (78338 s) every renewal gave
  a shorter successor; only from 2026-10-27T11:43:50Z to 11:52:13Z (503 s)
  would one have extended it and fitted under the CA; from
  2026-10-27T11:52:13Z to the predecessor's expiry (85897 s) it refused
  every renewal ("cannot outlive its issuer"). Until v32b (below) every
  identity must have T <= 3L, and the CA's notAfter must be at least
  due + 60 s + L (due being the identity's renewal instant); otherwise its
  first renewal supersedes it.
- **Superseded.** An issued successor the provider refuses is never
  installed and the request is never parked: the start is refused
  (`identity_renewal_pending`), `--cert-status` shows `superseded` with
  `check` (for the incident: `renewal_successor_not_extending`), and later
  Connects ask only for the receipt, paced by the backoff (60 s doubling to
  15 min) instead of at every Connect. Only an import (or v32b) recovers.
- **Parked.** A request the authority only rejected (Rejected or
  RecoveryRequired, no issued answer seen) is parked: the installed
  certificate keeps carrying traffic and the request is retried after the
  backoff. A parked request runs an epoch, so disconnect before
  `--import` (`session_live` otherwise).
- **Only a settled request is parked (v32 review).** The authority answers
  Rejected for every issuer error (another device's retained issuance, a
  registry or receipt read error, a failure after it published the
  successor), so Rejected does not prove it committed nothing. A request
  is parked only when every request of it was answered in this provider
  process: written in that step, or parked before, and no answer lost,
  timed out or `Unavailable`. A request found journaled at a provider
  start (a v31 leftover, or after a reinstall or reboot), or one whose
  earlier answer was lost, is never parked: it stays journaled, every
  start is refused (`identity_renewal_pending`, state `pending`,
  `last_failure` `rejected`), so no relay dial presents a predecessor the
  authority may have superseded. Recovery is the authority issuing for it
  (its receipt) or an import.
- **Pacing after a rejection (v32 review).** Beside a journaled request
  whose last attempt the authority answered Rejected or RecoveryRequired,
  a Connect within the backoff (60 s doubling to 15 min) is refused with
  no attempt (log `state:pending`); only an unknown outcome (no answer, a
  timeout, `Unavailable`) is still retried at the next Connect. Once
  expired, only a definite outcome closes the gate for later Connects
  (nothing recoverable, a definitive receipt check, or a rejection of a
  settled request); any other rejection closes it for that start only, and
  the next Connect tries the receipt again after `EXPIRED_RECOVERY_SECS`
  (5 min).
- **v32b needs a shared change.** Accepting a shorter, otherwise verified
  successor needs one owner-approved aegis-client change (the library's
  "must extend" rule, checked again at every capture) together with the
  extension's own. Not in v32.
- **After a provider restart (v32 review).** The provider remembers an
  issued-but-refused answer only in process memory. The authority replays
  a retained receipt only until the earliest of: the successor's expiry
  (for macos-test-2 about 2026-10-28T06:20:41Z at L = 24 h), a change of
  the authority's device CA, profile or registry record of the device,
  and a revocation. A request journaled before the restart is never
  parked, so a Connect after any of those reads Rejected and is refused
  (`pending`, `last_failure` `rejected`, no check) instead of
  `superseded`, but it never captures the superseded predecessor and
  never dials the relay with it, whatever the time. macos-test-2 needs an
  import either way: import macos-test-3 without connecting macos-test-2,
  unless the relay owner confirms neither cut-off has passed and the
  `superseded` check is wanted.
- **Rollback.** Do not roll back to v31 while a request is parked: v31
  ignores the parked leaf and writes a fresh request. v32 never parks that
  request (its history is unknown to v32): it stays journaled, so every
  `--connect` is refused with `identity_renewal_pending` (the tunnel does
  not connect) and, after a rejection, retried only after the backoff,
  until the authority issues for it or an import replaces the identity.
- **Older hosts.** A v26 to v31 host cannot decode `parked`, `superseded`
  or `check` (`reply_malformed`); use the v32 host.

## Endurance and load windows (S24 harness)

`LOAD=1` has run on installed v33 (below). `ENDURANCE=1` has run installed
once: build 37's two-hour window on 28 October 2026 was valid and failed.
The tunnel stayed `Connected` with one provider and no session loss, but 36
of 121 cycles failed, 34 of them on HTTP by name, at the fake-IP lifetime
edge: confirmed offline on 29 October, with the fix in source and not yet
installed ([v36 load acceptance](v36-load-acceptance.md#build-37-endurance-offline-analysis-and-the-fake-ip-fix-29-october-2026)).
These are the limits of what they can show:

- **The v33 load windows.** window-v33-load-r1 (the speed-test default, 4 x
  50 MiB, 180 s) failed `load_download`: the host refused one of four
  identical requests (HTTP 403, a 17-byte body), and two streams were short
  at the bound (2.1 and 1.9 Mbit/s). With the build unchanged, later
  windows passed: cdn.kernel.org 4 x 50 MiB (slowest stream 115.8 s, 3.6 to
  4.1 Mbit/s each), the speed-test host again (all 200), and 8 x 25 MiB
  twice. Each stream is held to about 4 Mbit/s at 185 ms by the 128 KiB
  HTTP/2 stream window, and two streams that share a pooled connection
  share its rate. See
  [download throughput](#download-throughput-through-the-tunnel-v34).
- **The gate depends on placement.** 4 x 50 MiB within 180 s needs 2.33
  Mbit/s a stream. It passes when each stream has its own pooled
  connection, and two streams on one connection need about 200 to 220 s.
  v34 prefers a connection without a bulk flow for a new flow and logs
  where each bulk flow ran (`load_placement`); a pass with one stream per
  connection is no evidence for the shared case.
- **No LAN-originated inbound load.** `LOAD=1` loads the tunnel with
  inbound downloads through the relay. Nothing in either mode sends a LAN
  stream to the Mac, such as LAN UDP aimed at the physical interface, so
  the filter's inbound drop path under a flood is not exercised. S20h's
  inbound flood attribution is a separate check.
- **Endurance without a capture is no leak proof.** `ENDURANCE=1` refuses
  `LEAK_CAPTURE=1`, both to run one disruption or capture per window and
  to keep hours of capture away from the disk floor. Its rows show that
  the tunnel stays up and carries traffic. They do not show that nothing
  left outside it. A leak proof needs a capture window (S20).
- **Renewal waits for a reconnect.** A session that lasts past the
  certificate's due point (two thirds of its lifetime) only defers the
  renewal (`deferred:guarded`, see
  [certificate renewal while connected](#certificate-renewal-while-connected-v31)).
  The renewal runs at the next Connect. An endurance run therefore has to
  end before `not_after`: the preflight refuses unless `not_after` is at
  least the run plus 30 min ahead. With the 24 h test certificates, a
  24 h run cannot fit.
- **Sleep.** `caffeinate -i` prevents idle sleep only. A lid close or a
  forced sleep still sleeps the Mac. The slots it misses are failing
  cycles (also one it was waiting for), and a passing cycle after more than
  two periods and 5 s without one fails `endurance_longest_gap`. The
  detached tunnel rollback counts only awake time.
- **Short periods cut the probe bounds.** At full length a cycle's probes
  have the baseline rows' bounds (TCP echo 10 s, whoami 5 s, HTTP 8 s, TXT
  and UDP 3 s), which hold from a 21 s period on. Below that each is cut to
  what the period leaves (4 s at 15 s), under the 3.6 s a cold flow has
  taken through the installed tunnel, so such a run may fail healthy
  cycles. Gate evidence uses the default 60 s.
- **One sample a period.** Each cycle samples the tunnel. A loss and a
  rebuild between two cycles' probes show only in the provider log counts.
  The tunnel status is polled every 5 s between cycles.
- **A window that dies keeps the tunnel up, and its rollback armed.** Only
  the detached rollback stops the tunnel of a window that was killed. For
  an endurance window that is up to its whole `rollback_s` (about two hours
  by default), and `timing-self` stays until then. When it fires it
  stops whatever tunnel is up then, and until then every new window
  refuses beside it. It ignores INT, TERM, HUP and QUIT. To end it by hand: stop
  the tunnel with `scutil --nc stop <service id>` until
  `scutil --nc status` shows Disconnected; disarm the rollback with
  `kill -KILL <pid>`, the pid from the `armed pid=<pid>` line of
  `OUT/rollback.log` once `ps -o args= -p <pid>` shows it names
  `OUT/rollback.cancel`; only then remove `timing-self`. The same holds
  after `disconnect_verified fail` ("rollback stays armed"). A rollback
  that fires anyway releases `timing-self` only while the lock still
  holds its own window's line.
- **Status during a reassert.** `scutil --nc status` prints `Connecting`
  while the provider reasserts (a session rebuild), never `Reasserting`.
  `ENDURANCE=1` counts `Connecting` as connected and judges the rebuild by
  the provider log; under `LOAD=1` any status but `Connected` fails
  `load_connected_throughout`.
- **The load is a third-party download.** The default `LOAD_URL` (v34) is
  the kernel tarball on cdn.kernel.org (140064536 bytes), reached through
  the relay; until v33 it was the speed-test host, asked for each stream's
  cap. Its throughput says as much about that path as about the tunnel,
  and a refusal or a size it does not serve fails `load_download` (v34:
  with the target's status, headers and body excerpt kept, masked).
- **A log read cut off at its bound shows nothing.** The load's provider
  log is read once within 30 s; a read its alarm cut off may lack the
  latest lines, so `load_connected_throughout` is then `unavailable`
  unless a loss is already among the lines read. The endurance reads
  treat a failed read as a gap the same way.
- **The real-time row needs the system clock.** `endurance_real_time`
  passes only for a schedule on the system's clock and sleep. The tests'
  virtual clock makes it `unavailable`, so the fake-command runs never show
  it passing.

## Download throughput through the tunnel (v34)

Measured on installed v33 (cable en7, relay about 185 ms away, relay
unchanged at its deployed commit), and what v34 changes. v34 is source
only until its acceptance windows run
([v34 load acceptance](v34-load-acceptance.md)).

- **The first limit: the 128 KiB stream window (v33).** The client's
  HTTP/2 receive window for each stream is 128 KiB
  (`SETTINGS_INITIAL_WINDOW_SIZE` 131072). A stream that has its own pooled
  connection keeps 92 to 104 KiB in flight whatever the RTT, about 4 Mbit/s
  at 185 ms (3.6 to 4.4 measured), and 61 to 90% of its busy 2 s samples
  sit at that ceiling. A direct download from a host at the same distance
  runs 63 Mbit/s on one stream, so the path is not the limit.
- **v34: a per-stream window that grows.** SETTINGS stays 131072 on the
  wire and every new, idle or slow stream keeps v33's 128 KiB. A stream
  grows only while it is window-limited: it delivered at least 5/8 of its
  window per round trip, which is 3/4 of what h2 lets the relay hold on
  average (h2 re-announces a stream's credit once a third of it is used,
  so a sender held by the window alone delivers about 3/4 of it per round
  trip; v33's single-stream connections delivered 0.70 to 0.77). It is
  judged over two round trips, at most once per two, and grows toward
  twice what it delivered per round trip, up to 1 MiB. A step that did
  not raise its rate by a tenth (by half its own share for the last,
  clamped step) is given back, and the stream then holds for 64 round
  trips before it tries again; a measurement the stream under-used (an
  idle gap, a reader that slowed) judges no step. The round trip is the least the connection
  measured over its life (outer TLS handshake, carrier 200s, PONGs; at
  least 20 ms), so data queued at the relay does not inflate it; the
  pool's liveness timers keep their own smoothed RTT, unchanged. All
  growth comes from one budget per session, 7 MiB (the connection window,
  now 15 MiB, less the streams' own windows), so the worst-case unread
  memory goes from 31 MiB to 38 MiB per session (a session rebuild that
  overlaps the old one can briefly hold two). A stream that idles or uses
  under a quarter of its window for 8 round trips in a row (an idle time
  counts as every round trip it spans, judged at its next byte) gives its
  window back at once and its budget only once the credit the relay still
  holds and the bytes h2 holds unread are back within 128 KiB; a closed
  stream returns it at once. A stream that stopped reading entirely is
  never asked and keeps its credit and its budget until it reads or
  closes (HTTP/2 cannot revoke credit).
  Whether the app keeps up is judged only by what the stream releases,
  which the bridge takes as long as the loopback socket to the packet
  engine has room (a few hundred KiB): a slow app's stream can grow for
  that long, then its releases follow the app, it stops growing and,
  under-using, gives the extra back, its budget returning only as its
  reader drains what h2 buffered. Either way a grown stream holds at most
  1 MiB and the session's grown streams at most its 7 MiB beyond 128 KiB
  each. (The reviewed v34 source returned that budget once the relay's
  credit alone was down, with up to about 1 MiB still unread; the v34
  review fixed it before any build.)
- **Placement (v34).** Among connections equal in slowness and handshakes
  in flight, a new flow prefers one that carries no bulk flow (a stream
  that moved at least 128 KiB/s within the last 2 s) over one with fewer
  live streams, so idle background flows no longer push it onto the
  connection a download already fills. It cannot move a flow already
  placed, and when every connection carries a download it goes, as
  before, to the one with the fewest live streams.
- **The second limit: the relay's congestion control (inferred).** When
  the window is not the limit (two v33 streams on one connection, so two
  128 KiB windows), a connection carries about 5.2 Mbit/s (3.9 to 6.3):
  its in flight falls after each loss sign (out-of-order bytes and SACK
  recoveries even at 4 Mbit/s). That points to the relay's cubic sender on
  a lossy relay-to-Mac path, but it is inferred from the v33 nettop
  sawtooth and nstat deltas, not proved: whether the loss comes from
  bursts, reordering or random path loss is not known, and the relay's own
  `ss -tin` samples (an owner allowance) would decide it. So v34 alone is
  expected to take one stream from about 4 to
  about 5 to 5.5 Mbit/s at 185 ms, not the several times a window model
  suggests. That is an estimate; only the acceptance windows measure it.
- **Relay steps left to the owner.** More than that needs the relay, each
  as a separate owner-authorised step with a detached rollback and a
  fresh-SSH check: R1 pacing (`fq` as the root qdisc, today `pfifo_fast`),
  R2 BBR on the relay's client sockets (only reno and cubic are loaded
  now), R3 `TCP_NOTSENT_LOWAT` of about 32 KiB on those sockets (so bulk
  data does not queue ahead of new streams' answers and PONGs), R4 the
  same growing window for uploads in the server (its stream window is
  128 KiB too, so uploads keep the v33 cap per stream). The relay's
  `ss -tin` sampler that would prove the second limit's cause is outside
  the allowed read-only list.

## Download throughput through the tunnel (v35)

What installed v34 (extension 0.1.0/34) measured, and what v35 changes.
v35 is source only until its declared windows run
([v35 load acceptance](v35-load-acceptance.md)).

- **v34 installed.** One stream (W1) ran at 9.3 Mbit/s, about 2.4 times
  v33's per-stream rate, with its window at 830 to 838 KiB. The S24b gate
  (W2, 4 x 50 MiB within 180 s) failed: one stream had 41.5 of its 50 MiB
  at 180 s, 79 of the 90-flow burst opened, no UDP pong, the TCP echo
  under load took 3.65 s and the handshakes' p90 reached 2.28 s. Two or
  three of the four outer connections drew persistent loss (7.6 to 14.2
  loss signs per 10 MB against 1.1 to 1.5 on the others), and on them
  v33-sized credit queued at the relay ahead of new streams' 200s,
  handshakes and echoes (the app-level wait 0.4 to 0.9 s while the kernel
  RTT stayed within 14 ms of its minimum). v34's own growth added 70 to
  190 ms on the fast connections it sped up and had no exit from a
  standing queue. That the wait is in the relay's send buffer, not in the
  Mac's own sockets, is inferred, not yet measured.
- **v35: the window grows only without a queue.** The signal is the
  credit-loop delay: by Little's law, the credit a stream held (the
  relay's credit, h2's unread bytes and what it released) over what it
  released, less the connection's least RTT. A window grows only after 3
  measurements in a row at most `min(60 ms, RTT/3)`, and only one step at
  a time per connection; a grown stream yields that turn while a stream of
  its connection still at 128 KiB waits for it, so every stream there
  takes its first step before any takes another (the v35 review; before,
  streams on one connection ramped one after another). It returns to 128
  KiB after 2 measurements at 120 ms or more, and holds for 64 round trips
  only when that comes within 2 measurements of a kept step. After 4
  measurements above the growth bound it gives back what it overshot, and
  that give-back always holds it for 64 round trips.
  Budget, reclaim and the 1 MiB maximum are v34's. Expected: fast,
  low-loss connections keep most of v34's gain with at most about 60 ms of
  growth queue; slow, lossy connections stay at v33's 128 KiB, where their
  queue of 0.4 to 0.9 s remains. So v35's window alone is not expected to
  clear W2's latency rows when most connections draw a lossy path.
- **Known cost on a bottleneck near the window (source tests).** A stream
  that a bottleneck holds keeps about 5% less of the line rate than v34
  did: the 60 to 120 ms zone's give-back aims the loop at the RTT plus the
  growth bound, which puts h2's 2/3 refill floor near 1.07 times the BDP.
  Against v34 on 36e9a961: T8 -3.6% (19,767,382 against 20,505,396 bytes),
  T8b -5.2% (12,960,109 against 13,672,644; its unchanged 0.9 x line
  bound is 12,960,000, so it passes by 109 bytes) and T16 over 25 to 40 s
  94.9% of the line against 99.9%; in return T17's PONG p90 fell from 41
  to 18 ms and T16's PONG p50 from 178 to 15 ms. A future T8b failure is a
  regression, not a flake; the first lever is the give-back's goal
  (raised by h2's refill slack), never the guard's bound.
- **Placement (v35).** A new flow avoids a bulk connection whose latest
  delay stood at 120 ms or more within 2 s, while another has a free
  slot. It cannot help when every connection is queued. Only a measurement
  the stream did not under-use counts (v35 review: a source-limited
  stream's idle credit read as seconds of delay). `pool_queue`'s
  `held_kib` keeps a stream's latest mean until its next measurement or
  its end, so an idle live stream still counts there.
- **The control arm.** `aegis-ne-host --connect ... --window-policy fixed`
  runs one tunnel start with v33's fixed window in the same build (the
  A/B's control). It is an owner diagnostics flag, never saved; in build
  35 the product default, System Settings and on-demand starts use the
  v35 window (build 36 reverses this: below). An unknown start option refuses the start
  (`start_refused window_policy_refused`). Any start that carries the
  option `aegis_window_policy=fixed` selects it, the owner running the
  flag by hand included; its only effect is v33's stream window.
- **What would change the path.** The relay steps R1 to R4 (pacing, BBR,
  `TCP_NOTSENT_LOWAT`, the upload window) or a new connection when every
  one is queued remain the owner's decisions; v35 changes the client only.

## Stream window default (v36)

- **The default is v33's fixed 128 KiB window again** (build 36). Every
  start without the window-policy option uses it: the bare `--connect`,
  on-demand and System Settings starts. The v35 window stays in the build
  for QA only (`--connect ... --window-policy adaptive`, one start, never
  saved). Placement, telemetry, the leak guard, the filter and the
  identity paths are unchanged.
- **Why.** v36's A/B under the test relay's runtime condition R1-R3 (fq,
  BBR, `notsent_lowat` 131072) could not run: the identity renewal it
  needed first failed twice (`connect_timeout`, the authority's port
  admits another source address), so no W2, A/B or sentinel window ran.
  The declared rule keeps the v35 window only after a final look with
  every row GAIN or NON-INFERIOR; with no evidence it gives `fixed`. The
  only paired evidence is v35's, under the old relay condition: the v35
  window's TCP echo under load was a REGRESSION (T/C 1.359, 95% CI 1.045
  to 1.768) and its throughput gain unresolved (S 1.100, 0.603 to 2.005).
- **Cost.** One stream is again bounded by 128 KiB per round trip, as in
  v33: the single-stream gain the v34/v35 window showed (v34 W1 9.3
  Mbit/s, about 2.4 times v33's per-stream rate) is not in the default.
- **Not yet proven.** Build 36's own S24b gate (W2 on the new default, at
  least 2 windows, declared before they run) has not run. Its smoke W2 (28
  October) failed `load_download`: one of four streams failed its TLS
  connect at the start (`rc=35`, 0 bytes), a failure also seen in 6 of
  v35's 32 A/B windows in both arms; its smoke W1 passed at 3.9 Mbit/s.
  Nothing measured under R1-R3 is claimed for the default. The `rc=35`
  start failure is a packet-engine defect, fixed in build 37 (below).

## An abandoned connect and the next flow (build 37)

- **Builds up to 36.** When an app closed a connect before the engine's
  SYN-ACK arrived, the Mac's RST returned the engine's socket to LISTEN
  while it was still the abandoned connection's relayed flow; the next
  connection to the same port, for any destination, was carried in that
  flow, to the abandoned destination. Seen as a TLS start failure (curl
  `rc=35`, a 7-byte alert, 0 bytes) in 5 of v35's 32 A/B windows and the
  v36 smoke W2, after the Claude desktop app's abandoned IPv4 connects.
  Nothing left the tunnel, but one app's bytes could reach another
  connection's destination through the relay.
- **Build 37** ends such a flow and returns its socket to the port's
  listeners, so the next connection gets its own relay flow; two engine
  tests cover it. No window has run on build 37 yet, so the fix is not
  yet shown on the installed client.
- **Not this fix.** A pool stall followed by an `hs_bound` flow refusal
  (v35 `ab12-t`) is a separate, designed refusal.

## Menu-bar app (v39, source only)

Build 39 adds a menu-bar app to AEGIS.app ([user guide](user-guide.md)).
It is source and a notarized build only: it has not been installed or run
on a Mac, so no state, prompt or dialog of it is observed yet.

- It implements no host verb. Opened from Finder (no arguments, stdin not
  a terminal) the host executable becomes the menu-bar app and runs every
  action as a child of itself with one existing CLI verb
  (`src/menu_flow.rs`): `--list`, bare `--status`, `--ping`,
  `--cert-status`, `--profile-terms`, `--filter-status`,
  `--enable-filter`, `--request-activation`, `--import`, `--save-profile`
  (with `--replace-existing` only for an idle, stale profile),
  `--connect`, `--disconnect` and `--emergency-stop`. It never runs
  `--disable-filter`, `--remove-filter`, `--forget-identity`, `--renew`,
  `--remove-profile`, `--deactivate` or `--window-policy`. A terminal
  start without arguments still prints the usage (exit 2).
- It connects only while the leak-guard filter reads `filter_result=ok`
  (configured, exact, enabled, attached); it runs `--enable-filter` first
  when the filter is off. The CLI still connects without the filter.
- The extension state comes from the read-only `systemextensionsctl list`
  (this provider of team TEAMID0000 only). The System Settings deep links
  it opens (macOS 15: Login Items & Extensions; macOS 14: Privacy &
  Security) are unverified on this Mac.
- Blocked by leak guard is inferred: macOS reports Reasserting, or
  Connecting for more than 45 s. The app does not read the filter's drop
  counters for it.
- Onboarding imports only a prepared private enrollment folder (`bundle/`
  and `identity/` with `online-completed.json`). Online enrollment from the
  four public bundle files and an invitation (`aegis-client device
  prepare/redeem`) is not in the app: those modules live only in the
  `aegis-client` binary crate. Until then the inviter enrolls on their own
  Mac, so the device key is not generated on the friend's Mac.
- Quitting leaves the tunnel and the filter as they are unless the user
  chooses Disconnect and Quit; nothing in the app turns the filter off.
- There is no uninstall in the app; `packaging/uninstall-app.sh` remains
  the way, and it does not yet quit a running menu-bar app first.
- While the app runs it polls read-only verbs (every 3 s while something
  changes, 20 s otherwise; certificate, filter and extension list every
  60 s). Quit it before timing-sensitive harness windows.

## Not yet proven on the installed client

These are implemented in source and tested on loopback or with fakes, but
have **not** passed on the installed, notarized client:

- **Sleep and wake** (S18 wake path: forced re-ACK or rebuild after wake).
  The owner-attended `SLEEP=1` window ran on v29 (window-v29-sleep-r3) and
  never slept: sleep is disabled system-wide on that Mac (see
  [sleep and interface-switch windows](#sleep-and-interface-switch-windows-v30-harness)).
- **Identity changes under the v30 gate** (`--import`, `--forget-identity`,
  `--renew` checked by the provider for Apple's network-configuration
  right) and the S21 uninstall/reinstall cycle on v26 or later (see
  [identity changes](#identity-changes-under-the-provider-sandbox-v30)).
- **Switching between two different physical interfaces** (re-pin of the
  relay socket to a new interface). The owner-attended `IFSWITCH=1` window
  (with `LEAK_CAPTURE=1`, every interface captured) ran on installed v32
  on 27 October; no window has yet passed both its probes and
  `no_mac_sent_leak_physical`. Unplug
  window-v32-ifswitch-r2: re-pinned to en0 and rebuilt, every probe
  passed, `no_mac_sent_leak_physical` failed because en7 had disappeared
  by the review (`no_local_mac`, `capture_alive=0`; r4 kept the adapter
  in). Plug window-v32-ifswitch-r3: lost by lease expiry and rebuilt on
  the old pin, `ifswitch_whoami_egress` failed inside the rebuild,
  `no_mac_sent_leak_physical` passed. Unplug window-v32-ifswitch-r4:
  re-pinned and rebuilt, every probe passed, `no_mac_sent_leak_physical`
  failed on the access point's Layer-2 Update frame (see
  [sleep and interface-switch windows](#sleep-and-interface-switch-windows-v30-harness)).
  v33 (installed: extension 0.1.0/33) has the plug re-pin, and the harness
  at its source commit the settle gate; no passing v33 switch window is
  recorded here. Build 40 ran the plug once (window-v39-ifswitch-r1):
  re-pin, rebuild and `no_mac_sent_leak_physical` passed, the three probes
  failed on the strike narrowing that build 41 removes (see
  [sleep and interface-switch windows](#sleep-and-interface-switch-windows-v30-harness)).
- **The packet filter (S20b)** and a passing capture-backed leak proof.
- **The positive control**: the v27 `POSITIVE_CONTROL=1` window was
  inconclusive (its fresh probes were routed into the tunnel), and the v28
  window `unavailable` because its criterion counted written segments that
  never reach the filter. The v29 keepalive criterion (S20h) has not run,
  so no positive control has passed and S20 has no PASS. The v27 negative
  control failed as required, and the v27 S20 window passed the Mac-sent
  row.
- **Automatic certificate renewal** (S23) on a real enrollment authority:
  no installed renewal has been observed yet; v30's attempts timed out at
  connect (port 9445 filtered), and v31's deferral, carried backoff and
  `--status` line have not run installed (see
  [certificate renewal while connected](#certificate-renewal-while-connected-v31)).
- Long-duration and endurance runs: `ENDURANCE=1` ran installed once (build
  37, two hours, valid). It failed `endurance_cycles` (85 of 121) and
  `endurance_longest_gap`, so S24a is not met; no 24-hour run exists.
  Bursts under heavy inbound load with the filter on ran on installed v33
  (`LOAD=1`: the bursts and echoes passed in every load window; v33's own
  window failed `load_download`, see
  [endurance and load windows](#endurance-and-load-windows-s24-harness)).
  v34's adaptive stream window and placement ran installed: W1 passed, the
  S24b gate W2 failed ([v35 load acceptance](v35-load-acceptance.md),
  baselines). v35's window, placement and control arm have not run
  installed; their acceptance and A/B are declared in
  [v35 load acceptance](v35-load-acceptance.md).

Installed and passed: activation and replacement, identity import and
forget, profile save/repair, Connected traffic through a real relay (IPv4
and IPv6), S17 blocked-but-up rebuilds, S18 network-loss recovery on Wi-Fi
(v24) and the S21 uninstall/reinstall cycle (v23).

Parent: [macOS documentation](README.md).
