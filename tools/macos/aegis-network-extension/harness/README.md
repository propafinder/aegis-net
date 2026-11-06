# Installed window harness (B-06 S16c)

`installed-run.sh` runs one bounded, owner-attended window against the
installed, activated PacketTunnel provider and the S16b fixture relay. It is
written for S16 and reused for S17-S20. Source only: it has run only
against fake system commands (`tests/test_installed_run_harness.py`), never
against the installed app.

```sh
harness/installed-run.sh --dry-run            # print every command, run nothing
harness/installed-run.sh                      # the window (relay 192.168.1.107:443)
harness/installed-run.sh --checks-only        # only the checks, already connected
```

Options: `--relay IPV4:PORT` (port 1..65535), `--rollback-seconds 1..90`
(default 90), `--hard-timeout 20..120` (default 120), `--app ABS.app`,
`--artifacts-dir ABS`. Options can only tighten the bounds: the rollback
never fires later than the hard timeout.

The harness refuses (exit 3, or 4 for the peer timing lock) and runs nothing
further unless all of these hold:
`~/.aegis-local/locks/timing-peer` is absent; no rollback of an earlier run
is still alive (its `rollback.log` under the artifacts directory has neither
`rollback_cancelled` nor `rollback_done`); the app and its `aegis-ne-host`
exist; `systemextensionsctl list` has exactly one `[activated enabled]` line
for the PacketTunnel and team; `--ping` reports `identity_present=true` and
an admitted container; `--list` has exactly one profile with a UUID owner
generation and service id, `intent_valid=true` and `on_demand_enabled=false`;
`scutil --nc list` lists that service; the relay accepts a TCP connect; the
service is Disconnected and the default route is on a physical interface with
no interface holding 198.19.255.1. It then creates
`~/.aegis-local/locks/timing-self` exclusively (start time, purpose, run
token) and re-checks the peer timing lock.

Before `--connect` the window writes a provisional `receipt.json` (outcome
`in_progress`) and arms the rollback outside the harness process tree: the
launcher forks and exits, and the rollback calls `setsid`, so it is
reparented to launchd and neither a process-group signal nor a kill that
walks the harness's descendants reaches it. It ignores INT, TERM, HUP and
QUIT, and must be confirmed alive with parent pid 1 and its own process
group before `--connect`. At min(arm + N s, start + hard timeout) it runs
`scutil --nc stop SID` then `aegis-ne-host --emergency-stop`; once it
observes Disconnected on two polls in a row with no 198.19.255.1 address and
the harness has exited, it removes the timing lock if the lock still holds
this run's token. It is cancelled only by the run token written to its
`rollback.cancel` file, never by a signal, and a rollback that has fired
always finishes.

The window then waits up to 20 s for Connected and runs each check with its
own 5 s bound (utun with 198.19.255.1, default route on it, TCP echo over
IPv4 and IPv6, UDP echo, a fake-IP A answer in 198.18.0.0/15 and TCP echo to
it, TXT, AAAA over the IPv6 anchor, TCP DNS, the scutil resolver, and the
provider's relay socket via unprivileged `lsof`, recorded `unavailable` when
lsof cannot see it). A disconnect counts as verified only when
`scutil --nc status` reports Disconnected on two polls in a row and, on both,
the default route is back on the physical interface and no interface holds
198.19.255.1: a session still Connecting has no routes yet, so routes alone
never count. A failed `--disconnect`, or one not verified within 5 s,
escalates to `scutil --nc stop`, then `--emergency-stop`, each verified the
same way.

The EXIT/INT/TERM/HUP trap runs that stop sequence whenever a connect was
attempted. Only after a verified disconnect does it cancel the rollback and
remove the timing lock (only while the lock holds this run's token; a fired
rollback keeps the lock until it has observed Disconnected). Otherwise the
run exits 6, the rollback stays armed and the lock stays, annotated with
`kept=rollback_pending` and the rollback's pid and fire time, for the
rollback to release. If no rollback is left to do that
(`kept=disconnect_unverified`), remove the lock by hand only after
`scutil --nc status` shows Disconnected. A watchdog, which signals only while
the harness is its parent, sends TERM 15 s before the hard timeout; the trap
then runs the stop sequence with short bounds (3, 2 and 2 s, 1 s
verification), and no command runs into the last 4 s, which are kept for the
rollback cancel, the lock and the receipt. The watchdog sends KILL at the
hard timeout and removes the lock afterwards only when no rollback was armed.

Every run, refused and failed ones included, keeps
`evidence-archive/s16-window-UTC-MODE[.N]/` (gitignored): `receipt.json` (0600;
preconditions, connect, checks, disconnect, rollback and lock events,
outcome, exit code, harness and host SHA-256), `events.tsv`, `fields.tsv`,
`commands.log`, `rollback.log` and each command's stdout/stderr. Nothing in
them is key material. Exit codes: 0 pass, 1 check or connect failure,
2 usage, 3 refused, 4 the peer timing lock, 5 hard timeout, 6 disconnect not
verified (rollback and lock left in place), 129/130/143 interrupted.

## Real-relay window rows: UTC start and end, and the session summary (B-06 v31)

Every row `real-relay-window.sh` writes to `$OUT/results.tsv` has six
tab-separated columns: name, verdict, detail, the tunnel status when it was
written (`scutil --nc status`), and (v31) its UTC start and end as
`YYYY-MM-DDTHH:MM:SS.mmmZ` (`/usr/bin/perl` with `Time::HiRes`). A row ends
when it is written and starts where the row before it ended (the first at
the window's start, taken before its first baseline read), so a check made
since the row before ran inside `[start, end]`. (v31 review) A row that
reports a check made before an earlier row was written starts instead
where the row before that check ended (`result_since`), so it overlaps the
rows in between and the rows after it chain from its end:
`physical_v6_baseline` and `filter_preflight` (reads before any row),
`leak_capture_ifaces` (the interface listing before `capture_started`),
`leak_window_connected_at` (with `connected`), `disconnect_v6_addr` (with
`disconnect_v6_route`, whose loop checks both), `netloss_addr_v6_count`
(its `before` count, with `netloss_addr_off`), `ifswitch_route_changed`
(with `ifswitch_status_during_switch`),
`ifswitch_leak_window_disconnect_at` (with `leak_window_disconnect_at`),
and the positive control's `probe_failed_<if>`, `filter_drop_delta_<if>`,
`bound_fresh_<if>` and `bpf_order_<if>` (from right before that
interface's first `--filter-status` read, also when they are written only
after the disconnect), and (S24) `endurance_preflight` and
`load_preflight` (the mode's reads before any row), the eight
`endurance_*` summary rows (from the start of the cycles) and
`load_download`, `load_throughput`, `load_concurrent`,
`load_connected_throughout` and `load_filter_counters` (from the start of
the load). Every check a row reports then ran inside its
`[start, end]`, and its overlap with a provider rebuild (`session_lost` to
`session_rebuilt` in `provider.log`) is computed instead of inferred from
the status column. A review written after the disconnect from what the
window recorded (a capture, the provider log, the filter's counters across
the window: `leak_proof`, the `presock_*` reviews, `filter_armed_span`,
`window_session_summary` and the like) contains the review itself; what it
reviews is the Connected interval or the span its detail names. Tools
reading the first four columns are unaffected; a parser that splits a row
into exactly four fields must take two more.

`window_session_summary` (info, never a criterion), written after the
disconnect from `provider.log` (the connect to after the disconnect):
`session_lost=N causes=<code>:N,... session_rebuilt=N reasserting_on=N
renewal_attempts=N renewal_deferred=N renewal_held=N`, causes sorted, stable
tokens and counts only; `unavailable` without provider log lines. The
`ifswitch_log_*` and `sleep_log_*` rows still count only from their owner
action on, which hid v30-r3's pre-switch `capture_lease_expired` rebuild.

## Real-relay window leak capture (B-06 S20)

`OUT=... LEAK_CAPTURE=1 harness/real-relay-window.sh` records the physical
interface with `sudo -n /usr/sbin/tcpdump -i <physical> -p -s 160 -B 4096
-G <ROLLBACK_S+60> -W 1 -U -w $OUT/physical.pcap` (headers only, not
promiscuous, exits by itself after the bound) from before connect until
after the disconnect check, and never prompts: without `sudo -n` for
`/usr/sbin/tcpdump`, `/bin/kill` and (S20e, the other captures' alarm)
`/usr/bin/perl` (run `sudo -v` first) it refuses with exit 3 before the
lock, the rollback or any connect. The capture is stopped
through `sudo -n /bin/kill` on the real tcpdump pid (the leaf under sudo);
the detached rollback asks for the same when it fires. `harness/leak_review.py
--pcap FILE --relay-ip IP --relay-port PORT [--relay-proto tcp,udp]
--connected-at T --disconnect-at T --out leak-review.json [--local-addr A]
[--local-mac M] [--broadcast B] [--guard S]` reviews the capture: any packet
inside the Connected interval (less 1 s at each end) that is not TCP/UDP to
or from the relay port of the relay IP is a leak (echo, whoami or ICMP to the
relay host included) unless it is ARP, DHCP, IPv6 ND/RA/MLD, mDNS to
224.0.0.251 or ff02::fb, or LAN broadcast. Leaks carry a diagnostic class
(`link_control`, `igmp`, `foreign`, `host`, `unparsed`) that never changes
`pass`. Exit 0 pass, 1 fail, 2 unreadable input or bad arguments. The
`leak_proof` row also needs a capture still alive at disconnect, stopped
afterwards, and zero kernel drops. Keep `physical.pcap` out of Git and of
retained evidence; `leak_capture_sha256` records its digest. Source only:
run against fakes and synthetic captures.

## Mac-sent criterion and every active interface (B-06 S20d)

S20d adds a second, separate criterion beside `pass`. It never changes
`pass`, `leak_count`, the classes, origins or families, or the exit code of
`leak_review.py`. The `leak_proof` and `no_v6_leak_physical` rows read
exactly as before: the window strips the new summary suffix from the line
they embed. Which criterion is the S20 acceptance criterion is the owner's
decision. Until then the recorded S20 result is `leak_proof`.

**`leak_review.py` fields.** `mac_sent_leaks` counts the frames inside
the same reviewed interval that the Mac itself sent. A frame is the Mac's
when its Ethernet source is `--local-mac`, or its IP source is a
`--local-addr` or the tunnel address. Only these are excluded:

- relay transport (the same rule as `pass`);
- ARP, DHCPv4 and DHCPv6;
- IPv6 neighbour and router discovery, and MLD;
- EAPOL (802.1X link keys).

Everything else the Mac sent counts. That includes mDNS, LAN broadcast and
IGMP, which `pass` excludes or classifies separately. On the Mac's own
frames the criterion is at least as strict as `pass`, except for EAPOL.

It fails closed. An unparsed or untimed frame counts unless its Ethernet
source is present and is another device's. Without `--local-mac`,
`mac_sent_pass` is false, and `mac_sent_error` says why.

`mac_sent_classes` counts these classes: `tcp_syn`, `tcp_keepalive`,
`tcp_data`, `tcp_control`, `udp`, `dns`, `mdns`, `broadcast`, `igmp`,
`icmp_error`, `icmp_echo_reply`, `icmp_echo_request`, `icmp_other`,
`link_control`, `unparsed` and `other`. `mac_sent_origins` uses the S20a
flow origins. `mac_sent_frames` lists the frames like `leaks`.
`mac_sent_guard` counts the same frames inside the guard seconds, as a
diagnostic only.

`mac_sent_pass` needs all three:

- `mac_sent_leaks == 0`;
- at least one relay packet in the interval;
- no `mac_sent_error` (no Connected interval, no relay packet, or no
  `--local-mac`).

`--relay-optional` is for an interface that carries no relay traffic. It
drops only the relay-packet term, and only from `mac_sent_pass`. The
summary line ends with `mac_sent_leaks=N mac_sent_pass=true|false`, after
any `error=`, so a reader of its start sees the line it knew.

S20e: `--mac-sent-mac M` and `--mac-sent-addr A` (each repeatable) name
more identities of the Mac, for the Mac-sent criterion only. A frame from
any of them is the Mac's. With `--local-mac`, an unparsed or untimed frame
counts unless its Ethernet source is present and is none of them. So more
identities only ever add Mac-sent frames. `pass`, every strict field, the
exit code and the summary start ignore them; only `--local-mac` decides
`no_local_mac`. An unreadable `--mac-sent-addr` sets `mac_sent_error`
(`bad_identity` in the window's rows) and fails only `mac_sent_pass`.
`mac_sent_identity` counts the MACs and addresses used, and names none.

**Every interface the Mac could send on.** With `LEAK_CAPTURE=1` the
window also captures every other such interface before connect. S20e
rule: an interface counts when it is up and one of these holds, whatever
its addresses:

- it has `status: active`;
- it is an Ethernet port (an `ether` line), whose link may come up while
  Connected;
- it is a radio that turns itself on (`awdl*`, `llw*`).

So a link-local-only port, a bridge member without an address of its own,
a port without a link, a Thunderbolt Bridge (`bridge0`), Internet Sharing's
`ap*` and the USB-C `anpi*` ports are captured, active or not. These are
never captured: `lo*`, the tunnels (`utun*`, `gif*`, `stf*`, `ipsec*`), a
VM's host-side port (`vmenet*`, `vmnet*`, `vnic*`) and a bridge whose
members are all VM ports, whose frames never leave the Mac. (S20d required
`status: active` and an address of the interface's own, and skipped
`bridge*`, `ap*` and `anpi*` by name.)

PHYS keeps `physical.pcap` and every existing row. Each other interface
gets `physical-<if>.pcap` with the same `sudo -n` tcpdump argv
(`-p -s 160 -B 4096 -G <bound> -W 1 -U`). S20e: it always runs under the
root alarm, `sudo -n /usr/bin/perl -e 'alarm shift; exec @ARGV; exit 127'
<bound+30> /usr/sbin/tcpdump ...`, with or without `IFSWITCH=1`. Such an
interface can stay quiet for hours, and tcpdump checks its `-G` bound only
when a packet arrives. So `LEAK_CAPTURE=1` refuses (exit 3) before any
capture unless `sudo -n -l /usr/bin/perl` passes. PHYS's own argv is
unchanged: it carries the default route, so its bound sees a packet within
seconds. Each start is read from tcpdump's `listening on` line. If one
capture does not start, every capture is stopped and the window refuses
(exit 3) before the lock, the rollback or any connect. An interface that
tcpdump cannot open therefore refuses every `LEAK_CAPTURE=1` window, and
the refusal names it.

Each capture is stopped through `sudo -n /bin/kill` on its own leaf
tcpdump pid, named by its `-w` file. The detached rollback gets every leaf
pid, but its kill is best effort only: it runs in a new session without
the terminal's cached sudo credential. `IFSWITCH=1`'s target keeps its own
capture (`physical-<to>.pcap`, `ifswitch_*` rows) and is never captured
twice. Each other capture is reviewed with its own MAC and addresses,
using `--relay-optional`.

S20e: the strict arguments of every review (`--local-mac` and
`--local-addr`) are the same as before. Every review, PHYS's and the
target's included, also gets the Mac's identities for the Mac-sent
criterion. These are every MAC and address of every interface above,
read before connect, right before the disconnect and after the window.
So a frame counts when the Mac sent it under the MAC or address it had
before a rejoin (a rotated private Wi-Fi address), or from a bridge's
address through a member port. They stay in memory and in the reviews'
arguments, and are never written to a row or a log.

New rows:

- `leak_capture_ifaces` (info): the captured interface names, PHYS first.
- `capture_started_<if>`, `capture_stopped_<if>`,
  `leak_capture_sha256_<if>`: as for PHYS. `capture_started_<if>` also
  names the alarm (`alarm=<bound+30>s`).
- `leak_review_<if>` (info): that capture's summary line, plus its capture
  flags.
- `leak_proof_all_ifaces`: `leak_proof`'s rule on every capture. PHYS uses
  `leak_proof`'s own verdict. On another capture `pass` needs a relay
  packet, so this row fails while an interface that carries no relay
  traffic is up. It is the strict rule applied literally to all
  interfaces.
- `no_mac_sent_leak_physical`: the Mac-sent criterion on every capture.
  It passes only when all of these hold:
  - every interface of the rule above before connect, or right before the
    disconnect, was captured (one that appeared during the window is
    named in `uncaptured=`);
  - every capture was alive at the disconnect, stopped afterwards, and had
    zero kernel drops;
  - every review has `mac_sent_pass=true` and `mac_sent_leaks=0`. PHYS and
    `IFSWITCH=1`'s target need relay packets; the other interfaces do not.

  On failure it adds `reason=` with names and codes only, for example
  `uncaptured=en5`, `en5:mac_sent_leaks=1`, `en5:no_local_mac`,
  `en5:kernel_drops=2` or `en5:capture_alive=0`. Both rows end with
  `uncaptured=<names|none>` (S20d wrote `uncaptured_active=`).

What these rows prove: no frame the Mac sent outside the tunnel left on a
captured interface while Connected, other than relay transport and the
excluded link control. They prove nothing about arrivals to the Mac or
other devices' frames. No client can stop those, so the Mac-sent criterion
never counts them.

What they do not cover:

- An interface that is created and removed again between the two
  snapshots (an adapter plugged in and out during the window). One that
  is present before connect is captured whether its link is up or not.
- A Mac identity that existed only between the snapshots (a MAC or an
  address the Mac held only in the middle of the window), unless the frame
  carries another identity the review knows.

A quiet interface's capture is no longer left to its `-G` bound: the root
alarm ends it at the latest `<bound+30>` s after its start, even when the
window is killed and the rollback's kill is refused.

Source only: run against fakes and synthetic captures.

## Filter observability, armed span and controls (B-06 S20f)

S20f answers two questions the v26 window left open: did the leak guard
stay armed for the whole window, and does the macOS BPF tap see an
outbound frame before or after the packet filter drops it (Apple does not
document the order; the v26 filter counted 21 outbound TCP drops that the
`en7` capture never showed). None of it changes `pass`, `leak_proof`,
`no_v6_leak_physical`, the S20d/S20e `mac_sent_*` fields or the leak review
exit code, and no verdict of the filter.

**The provider's armed span.** A v27 provider logs
`leak_guard_span armed seq:N wall:T` right after each arm and
`leak_guard_span disarmed seq:N wall:T` with a wall time read right before
the disarm (address-free: the arm sequence and wall-clock seconds). After
the disconnect the window reads the provider log once (bounded, before the
reviews; it used to read it at the very end) and records:

- `filter_armed_span`: pass when the last arm at or before the connect came
  before it, that arm's disarm came after the disconnect, and no other arm
  came between (`seq=N armed_before_connect=Xs disarmed_after_disconnect=Ys
  rearms=0`). It fails with `reason=no_arm_before_connect`, `no_disarm`,
  `disarmed_before_disconnect` (a transient disarm while Connected) or
  `rearms`. It is `unavailable no_span_lines` with a provider before v27,
  and `unavailable not_connected` without a connect. `seq` restarts at 1 in
  every provider process, so an arm is its `seq` and the `[pid:tid]` of its
  compact log line, its disarm is the first one of that `seq` and pid at
  or after it (by `seq` alone when a line has no `[pid:tid]`), and every
  other arm line between them is a re-arm, whatever its `seq`: a provider
  that restarted while Connected and armed `seq:1` again fails the row
  (`no_disarm,rearms`).
- With both times every review (PHYS's, `IFSWITCH=1`'s target and every
  other capture) also gets `--armed-at T --disarmed-at T`.
  `leak_review.py` then runs a second Mac-sent pass over exactly
  [arm, disarm] (no guard seconds, no relay term): `mac_sent_armed_leaks`,
  `mac_sent_armed_classes`, `mac_sent_armed_origins`,
  `mac_sent_armed_frames`, `mac_sent_armed_span` and
  `mac_sent_armed_error`. The summary line is unchanged.
- `no_mac_sent_leak_physical` fails when either span has a Mac-sent frame:
  each interface's entry adds `,armed_leaks=N`, the row adds
  `armed_span=reviewed`, and the reason names
  `<if>:mac_sent_armed_leaks=N`. Without the span the row reads exactly as
  before.

The span is wider than the Connected interval: it includes the settings
application before Connected and the teardown after the disconnect, when
other processes' traffic may still meet the physical interface. If the
BPF tap sits before the filter (`pre_filter` below), a frame the filter
dropped is still in the capture and fails the row: fail closed, never
weaker.

**Filter observability.** `--filter-status` reads the provider's
`observability` (see
[install and enable](../../../../docs/platforms/macos/install-and-enable.md)):
arms, disarms, armed milliseconds, `open_while_applied`, drops per
interface class (`primary`, `en_other`, `awdl_llw`, `bridge_ap_anpi`,
`other`) and direction, and the last 64 drops with their interface, TCP
flag class and reason. The window keeps each reading in
`filter-status-*.txt`.

**POSITIVE_CONTROL=1** (owner-attended, its own window, never S20
evidence):

```sh
sudo -v
OUT=<new dir> LEAK_CAPTURE=1 POSITIVE_CONTROL=1 harness/real-relay-window.sh
```

It refuses (exit 3, before the lock, the rollbacks, any capture or connect)
with another mode (`NEGATIVE_CONTROL=1`, `NETLOSS=1`, `SLEEP=1`,
`IFSWITCH=1`), without `LEAK_CAPTURE=1`, without the filter configured,
enabled and attached (`--filter-status` exit 0, also with an explicit
`FILTER_REQUIRED=0`), when the relay port is 9, or with `PC_PROBES` (3,
1..10), `PC_TIMEOUT_S` (2, 1..5) or `PC_SPORT_BASE` (47100, 1024..64000)
out of range. After the captures start it picks every captured interface
with an IPv4 address whose scoped default route names an on-link gateway
inside that interface's own subnet (never the relay, never its own
address); `positive_control_ifaces` names them and the skipped ones
(`no_ipv4`, `no_lan_gateway`). None refuses the window (exit 3, captures
stopped). While Connected, for each of them:

1. `--filter-status` (the filter must read `mode=guarding`).
2. `net_probe.py boundsyn <if> <gateway> 9 PC_PROBES <base> PC_TIMEOUT_S`:
   TCP connects bound to the interface with `IP_BOUND_IF`, from the marked
   source ports `<base>`..`<base>+PC_PROBES-1`, to the LAN gateway's
   discard port. Never a third-party host, never the relay port.
3. `--filter-status` again.

Rows:

- `probe_failed_<if>`, detail `probes= failed= kinds=` such as
  `timeout:3`: pass only when every probe timed out (sent and never
  answered, what a filter that drops it gives; `net_probe.py` exit 0).
  Fail when one was answered (`connected`, `refused` or `reset`, exit 1):
  a refused connect needs the SYN out and the gateway's RST back in, so the
  filter dropped neither, and most LAN gateways answer port 9 with an RST.
  `unavailable` when none was answered but not every probe timed out (exit
  3: an error before or while sending, such as `eaddrinuse` or
  `ehostunreach`); such a probe says nothing about the filter.
- `filter_drop_delta_<if>`, detail `class= out_before= out_after= delta=
  syn_drops= ring_lost= need=`: pass when both `--filter-status` readings
  read `mode=guarding` under the same arm (`arm_seq` and `disarms`
  unchanged), the out-drop counter of the interface's class grew by at
  least `PC_PROBES`, and the provider's drop ring holds at least
  `PC_PROBES` new records (index at or past the first reading's
  `ring.next`) of an outbound IPv4 TCP SYN dropped as `drop_tcp_out` on
  that very interface (`syn_drops`). The class counter alone also counts
  every other drop of the class (mDNS, IGMP, another `en<n>`), so it never
  passes the row by itself. `ring_lost` counts new records no longer in the
  64-entry ring (overwritten, skipped or torn); the row then fails unless
  the remaining records still show the probes. Other fails: `unavailable`
  (no observability), `mode=open`, `rearmed` (a disarm or arm between the
  readings), `unreadable`.
- After the captures stop, `bpf_order_<if>` (info): only when both rows
  above passed (the filter counted the probes and none was answered),
  `pre_filter` when the marked SYNs are in that interface's capture and
  `post_filter` when they are not. Otherwise `unknown` (`filter_drop_delta=
  fail` or `probe_failed=<verdict>` in the detail): a SYN the filter did
  not drop is in the capture wherever the tap sits.

`leak_review.py probe-syns` counts the marked SYNs and prints no address.
The gateway stays in memory and in argv; rows name interfaces only.

The probes are Mac-sent frames: with `pre_filter` they appear in the
capture and fail the control window's Mac-sent rows. So every leak row of a
control window is written under the control's prefix
(`positive_control_leak_proof`, `positive_control_no_mac_sent_leak_physical`,
`positive_control_filter_armed_span`, and so on), and the first row is
`evidence_scope info positive_control: ... never S20 evidence`.

**NEGATIVE_CONTROL=1** (owner-attended, its own window, never S20
evidence): the same window shape, interface and driver with the filter
disabled.

```sh
sudo -v
OUT=<new dir> LEAK_CAPTURE=1 NEGATIVE_CONTROL=1 harness/real-relay-window.sh
```

It refuses like the positive control (one mode, `LEAK_CAPTURE=1`, the
filter attached before, `NC_DISABLE_BOUND_S` 180 30..300,
`NC_ENABLE_BOUND_S` 150 30..300, `NC_ATTACH_WAIT_S` 30 5..120,
`/usr/bin/python3` for the rollback). Then, before any capture:

1. A detached filter rollback (`filter-rollback.log`): forked and adopted
   by launchd, its own session and group, ignoring INT, TERM, HUP and QUIT,
   confirmed before anything changes. As soon as the window is gone, or at
   its deadline, it runs `host --enable-filter` and waits for
   `--filter-status` exit 0 (three attempts). It is cancelled only by its
   token, and accepts the cancel only after reading exit 0 itself.
   Row `negative_control_rollback_armed`.
2. `host --disable-filter` (v26: the owner approves the administrator
   prompt; the window never answers it), then `--filter-status` must exit
   31. Otherwise `negative_control_filter_disabled fail`, the filter is
   enabled again and verified, and the window refuses (exit 3) before any
   capture or connect.

The window then runs as usual with the filter off (`filter_counters_after`
reads exit 31). Right after the disconnect, before the reviews, and again
from the EXIT trap, `host --enable-filter` and `--filter-status` exit 0
within `NC_ATTACH_WAIT_S` of the enable's return (the enable itself may
wait up to `NC_ENABLE_BOUND_S` for the owner's Allow; the status is read
at least once): `negative_control_filter_restored` and
`negative_control_rollback_ended`. A filter not restored and verified
attached fails the window: exit 1, `FAILED: negative control: ...`, no
`done`, and the rollback stays armed and restores it once the window is
gone. That holds for every exit after the disable, a refusal's too (the
disable read back as something other than 31 and its restore failed, a
capture that did not start, a busy lock, a rollback not armed): the EXIT
trap's restore decides, and only a verified restore leaves the refusal's
exit 3. Its leak rows carry the `negative_control_` prefix.

The disable is saved in the NEFilterManager configuration and survives a
restart, while the EXIT trap and the rollback are user processes that a
reboot, a logout or a power loss stops. So before the rollback the window
writes `~/.aegis-local/negative-control-filter-disabled` (`start=`,
`pid=`, `out=`; no address), and only a verified restore removes it (the
window's own, or the rollback's for that window). Every later window reads
it right after its first `--filter-status`: while the filter is not
attached it refuses (exit 3, before anything connects, with
`FILTER_REQUIRED=0` too) and names `--enable-filter`; once `--filter-status`
exits 0 it removes the marker of a window that is gone (and keeps one whose
window still runs). Ordinary tunnels outside the harness do not read the
marker: after an interrupted negative control check
`aegis-ne-host --filter-status` (exit 0) yourself.

`LOG_BIN`, `NC_PY` and `PROBE_PY` exist for the tests. Source only: run
against fake commands (`RealRelayWindowControlTests`), never against this
Mac.

## Pre-existing sockets and tunnel-routed fresh probes (B-06 S20g, v28)

The v27 owner session showed why the S20f positive control could not
pass. Its fresh probes, bound with `IP_BOUND_IF` to `en7` and `en0`,
"connected" in 6-7 ms, no capture held a marked SYN, and the filter
counted no drop: with `includeAllNetworks` the system routed the bound
fresh sockets into the tunnel, where the provider's userspace TCP engine
answers every SYN. A fresh socket never meets the filter on a physical
interface. What the filter exists for is the traffic of sockets connected
**before** the tunnel (keepalives, retransmissions, data written later):
in the v27 S20 window it dropped 18 outbound ack-only TCP packets on `en7`
that the `en7` capture does not show. S20g makes such sockets the
positive control's evidence and classifies the fresh probes honestly. No
leak row, `leak_review.py` field, Mac-sent criterion or filter verdict
changes.

**Pre-existing sockets, both controls** (`net_probe.py presock`, one
helper per interface, under the system `python3`). After the captures
start and before the lock, the rollback and the connect, for every
captured interface with an IPv4 address and an on-link IPv4 default
gateway (the positive control's own rule):

1. The helper tries the gateway's TCP ports 80, 443, 53 and 8080, in that
   order and never the relay port (fixed in `controls.sh`, never read from
   the environment), each with a connect bounded by `PRESOCK_LIMIT_S` (2,
   1..5) on a socket bound to the interface with `IP_BOUND_IF`, and keeps
   the first that connects. Only the LAN gateway: never a third-party host,
   never the relay address.
2. It opens `PRESOCK_N` (2, 1..4) connections to that port, bound the same
   way, with `SO_KEEPALIVE` and `TCP_KEEPALIVE` 4 s, `TCP_KEEPINTVL` 4 s,
   `TCP_KEEPCNT` 60, so the kernel probes them while Connected and an
   unanswered one survives about four minutes.
3. Its private state file `presock-<if>.json` (mode 0600, replaced
   atomically; **not for retained evidence**) records the phase, the
   chosen port and the local ports. It never records the gateway address;
   rows and logs never name a port. The window passes the ports on only in
   argv (`leak_review.py presock-frames`).

Row `presock_open_<if>` (written Disconnected, before the connect): pass
when every socket connected, `unavailable` when the gateway accepts none of
the ports (`select=refused:3`), fail otherwise. `presock_ifaces` names the
interfaces and the skipped ones.

While Connected, before the fresh probes, each open helper is told to
write (`presock-<if>.json.cmd`). It writes a few marked bytes on each
socket at a recorded time and reads `TCP_CONNECTION_INFO` (macOS
`getsockopt(IPPROTO_TCP, 0x106)`, `struct tcp_connection_info` of the SDK's
`netinet/tcp.h`: 112 bytes, `tcpi_snd_sbbytes` at offset 32, the 64-bit
packet counters from offset 56) every 0.1 s for up to `PRESOCK_WAIT_S` (5,
1..15). The public struct has no `snd_una`; `tcpi_snd_sbbytes`, the bytes
still in the send buffer including those in flight, drops when an ACK
covers them. Each written socket ends `acked` (any of its bytes
acknowledged), `reset` (closed with ECONNRESET), `rx` (still unacked, but
the gateway's data reached it), `timed_out` (ETIMEDOUT), `closed`, or
`unacked` after the whole wait; a socket not in ESTABLISHED or CLOSE_WAIT,
or whose send fails, is `not_written`. The row detail is
`written= acked= unacked= reset= rx= timed_out= closed= not_written=
answered= tx= retx= rx_packets= wait=` (`answered` = acked + reset + rx;
`tx`, `retx` and `rx_packets` are the sockets' packet-counter deltas).

Positive control rows (`positive_control_` prefix). **S20h (v29)
replaces `presock_drop_delta`, `presock_bpf_order`'s inputs and the
verdict's pass and fail terms below** (see the next section); the
v28 rules are kept here as the record of what the v28 windows ran.

- `presock_unacked_<if>`: pass when every written socket stayed
  `unacked`; **fail when any was answered** (`answered` above 0: the bytes
  went out and an answer came back through an armed filter);
  `unavailable` when nothing was written or a written socket ended without
  an answer (`timed_out`, `closed`). The armed filter drops the gateway's
  answers inbound too (TCP from neither the relay nor the authority), so a
  pass says nothing about whether the written bytes left the Mac: written
  bytes that leaked stay unacknowledged as well. Only the captures can show
  that (`presock_bpf_order` and the verdict below).
- `presock_drop_delta_<if>`, detail `class= out_before= out_after= delta=
  data_drops= ack_only_drops= ring_lost= need=`, from a `--filter-status`
  right before the write and one after the wait
  (`filter-status-presock-<if>-*.txt`): pass when both read
  `mode=guarding` under one arm, the out-drop counter of the interface's
  class grew by at least `need`, and the drop ring holds at least `need`
  new records of an outbound IPv4 TCP segment with payload (`tcp=data`)
  dropped as `drop_tcp_out` on that very interface whose time since the
  arm (`ms`) is at or past the write: the first reading's `armed_for_ms`
  plus the wall time from that reading's return to the helper's write.
  `need` is every data segment the written sockets sent by the end of the
  wait, retransmissions included (the `tx=` of `presock_unacked`,
  `tcpi_txpackets`), and never less than one per written socket. Bare ACKs
  on the interface after the write (keepalives of other sockets; the
  written sockets retransmit data) are counted in `ack_only_drops` and
  never count. `unavailable` when nothing was written. The ring keeps no
  port, so other sockets' data drops on the interface count too: a pass
  does not show that the helper's own segments were the ones dropped.
- After the captures stop, `presock_bpf_order_<if>` (info), from the
  helper's frames (its source ports to the gateway's port) in that
  interface's capture during the provider's armed span
  (`leak_review.py presock-frames` counts them by `data`, `ack_only` and
  `other`, printing no address or port): `post_filter` when the delta
  passed and none is there (TCP sent the segments, the filter counted
  drops, the tap never saw them). It is **never** `pre_filter`: with the
  delta passing, a helper frame in the capture is either one the filter
  dropped after the tap saw it or one that left while other sockets'
  drops filled the port-free count, and the window cannot tell which
  (`unknown frames=... presock_drop_delta=pass span=armed: the helper's
  frames are in the capture while armed; ...`). `unknown` also when the
  delta did not pass, with no armed span, no sockets or an unreadable
  capture.
- `positive_control_verdict`, the window's last row:
  - **fail** when, on any interface, written bytes were answered while
    armed (`answered_while_armed=<ifs>`: `presock_unacked` failed), a
    fresh probe was answered (`fresh_probe_answered=<ifs>`:
    `probe_failed_<if>` is `fail`, that is neither `pass`, `unavailable`
    nor `tunnel_enforced`), or the helper's data frames are in that
    interface's capture during the armed span while its
    `presock_drop_delta` did not pass (`uncounted_data_frames=<ifs>`: the
    filter did not count them, so they left the Mac). Each is a real
    leak, whatever the primary interface showed.
  - **pass** only when `presock_open`, `presock_unacked` and
    `presock_drop_delta` passed on the primary interface (`PHYS`) and no
    frame of any helper is in any capture during the armed span, each
    interface's capture counted (`frames_while_armed=0
    frames_checked=<ifs>`).
  - **unavailable** otherwise: the primary interface not probed
    (`not_probed`), one of its rows not passing, a helper's frames in a
    capture beside a passing delta (`frames_seen=<ifs>`: they may have
    left the Mac; nothing in the window settles the tap order, since the
    fresh probes' `bpf_order` rests on the same port-free drop count and
    on answers the filter drops inbound), or a helper's frames not counted
    (`frames_unchecked=<ifs>`: no armed span, an unreadable capture).

Negative control rows (`negative_control_` prefix): `presock_acked_<if>`
(pass when every written socket's bytes were acknowledged with the filter
off, proving the probe's send path; fail when one was written and not
acknowledged; `unavailable` when nothing was written) and, after the
captures stop, `presock_frames_<if>` (info: the helper's frames in that
interface's capture from the write to 1 s after the end of the wait).
S20h moves the write to right after Connected and adds
`presock_wire_<if>` (next section).

After the disconnect (and from the EXIT trap) each helper is told to
close; one still running 5 s later is killed. A helper also closes its
sockets by itself once the window is gone (its parent changed) or after
`ROLLBACK_S + 300` s. Row `presock_closed` names each interface's final
phase (`closed`, `orphaned`, `expired`).

**The fresh probes routed into the tunnel.** A v28 provider logs every
flow its engine answers to port 9 as `engine_flow_open class:discard n:K
wall:T` (address free: the class of the destination port, the device's
count so far, a wall time; other classes `dns`, `web`, `low`, `high` at
most once a second). When every fresh probe of an interface connected
(`kinds=connected:PC_PROBES`), its `probe_failed_<if>` and
`filter_drop_delta_<if>` rows wait until the captures and the provider log
are read. With no marked SYN in **any** capture of the window and at least
`PC_PROBES` `class:discard` lines whose wall time lies within that
interface's probes, both rows read `info tunnel_enforced ...` and
`bound_fresh_<if>` reads `tunnel_enforced connected=3 engine_opens=3
marked_syns_in_captures=0: the system routed sockets bound to <if> into
the tunnel`; `bpf_order_<if>` stays `unknown`. Otherwise (a provider before
v28: `engine_opens=none`; a marked SYN in a capture; opens outside the
probes' time) they keep their fail, and `bound_fresh_<if>` reads
`answered`. Every `probe_failed_<if>` still `fail` at the end of the
window, deferred or not, also fails `positive_control_verdict`
(`fresh_probe_answered=<if>`). `bound_fresh_<if>` classifies every other
interface's probes too: `unanswered` (every probe timed out), `not_sent`,
`answered`. The
deferred rows carry `at=<status>`, the tunnel status when the probes ran.
The v27 provider log could not have shown this: its `flow_open` lines are
sampled (every flow only in the first 5 s of an epoch, then one in 16 and
slow ones), and the probe interval held one such line for six probes.

`PRESOCK_N`, `PRESOCK_WAIT_S` and `PRESOCK_LIMIT_S` are range-checked in
the controls' preflight (exit 3 before anything connects), and the
rollback default grows by the helpers' open and write time per interface
with an IPv4 address. Source only: run against fake commands, a loopback
gateway and the real helper (`RealRelayWindowControlTests`,
`NetProbePresockTests`, `LeakReviewPresockFramesTests`), never against
this Mac.

## Keepalive positive control and early negative write (B-06 S20h, v29)

**Why.** The v28 owner session (24 October, Wi-Fi `en0`) showed the S20g
criterion could never pass. With `includeAllNetworks` the system holds a
pre-existing socket's own output (`tcp_output` data and pure ACKs, UDP
sends) before the `NEFilterPacketProvider`, with or without the filter:
the helper's 11 data transmissions never reached the filter (2 counted
drops in the interval were the helper's kernel keepalives), and in the
filter-off negative control the Mac never answered the gateway's
keepalive probes, so the gateway reset both sockets about 15 s after
their handshake and the late write found them closed (`not_written=2`).
Kernel keepalives (`tcp_respond`) and ICMPv6 errors pass that hold: they
are exactly the residue the filter exists to drop. The 64-slot drop ring
also lost every outbound record to a pre-existing LAN UDP stream of
about 1300 packets a second dropped inbound. Details: the change log
entry "v28 owner session on Wi-Fi" and the
[NE README](../README.md) v29 section.

**Provider (v29).** Every outbound drop is also counted by interface
class and kind (`syn`, `syn_ack`, `ack_only`, `data`, `fin`, `rst`,
`other`, `non_tcp`), once more when it is a TCP segment from a source
port of the marker range 47000..47031 (`leak_guard::MARK_SPORT_FIRST`
and `MARK_SPORT_COUNT`; S20h review: the first draft's marker, TTL 77,
can never reach a keepalive, see below), and written to a second ring of
the last 64 **outbound** drops, which inbound drops never overwrite.
`--filter-status` reports them under `observability.outbound` (see
[install-and-enable.md](../../../../docs/platforms/macos/install-and-enable.md)).

**The helper (both controls).** `net_probe.py presock` takes the
keepalive as a ninth argument (`PRESOCK_KEEPALIVE`, `idle/intvl/cnt`,
default `4/4/60`, idle and intvl 1..10 s, cnt 2..120; range-checked in
the preflight), binds each kept socket to the first free source port of
the marker range (`PRESOCK_MARK_SPORT_FIRST`, `PRESOCK_MARK_SPORT_COUNT`;
a Rust test checks they equal the provider's and those of
`leak_review.py` and `controls.sh`; none free reads `eaddrinuse`) and
closes it with `SO_LINGER` 0, so no `TIME_WAIT` keeps a marker port (its
port probe uses an ephemeral port). It records each socket's connect
time (`t_connected`, when its SYN-ACK had just arrived) and the marker
range (`mark_sport`) in its private state file. A socket that is closed
when told to write records why (`cause` `reset` or `timed_out`, from
`SO_ERROR`), and `presock-read write` appends
`not_written_causes=reset:N,...` when any did.

**Positive control** (`positive_control_` prefix). The write stays after
the standard checks, while Connected and armed. A `--filter-status` comes
right before the write and another one at least `PS_KA_SPAN` (2 x intvl
+ 2 s, 10 s by default) after it, so at least two keepalives per socket
fall between them; the rollback default grows by that span per
interface. Rows:

- `presock_unacked_<if>`: unchanged (any answer while armed fails).
- After the captures, `leak_review.py presock-review` (prints counts and
  tokens only):
  - `presock_keepalive_drops_<if>`. Each socket's keepalives are due at
    t_rx + idle + (k-1) x intvl, t_rx its last frame from the gateway's
    port in that interface's capture before the provider's arm (the
    inbound tap sees frames the filter later drops), else its connect
    time (`rx=helper`): the armed filter drops every inbound frame, so
    TCP's receive time stands still and its keepalives keep coming
    every intvl. **Pass** needs both reads `guarding` under one arm, a
    v29 provider whose marker range (`mark_sport_first`,
    `mark_sport_count`) is the helper's `mark_sport` with every socket
    bound inside it, at least two due keepalives per socket strictly
    between the reads
    (500 ms of tolerance at each end), the marked bare-ACK drops of the
    interface's class grown by at least all of them (`counted >=
    expected`), the outbound ring holding every record between the reads
    (`ring_lost=0`), and that interface's marked bare-ACK records lying
    within 500 ms of every due keepalive (`matched=expected`). When
    marked data drops appear (the written segments do reach the filter,
    as after an OS change), they must cover every data segment the
    sockets sent (`tx`), else `unavailable data_partial`. **Unavailable**
    when fewer than two were due per socket (`wait_short`), none was
    counted as marked (`unattributed`; with unmarked bare ACKs on every
    due time it says `pass_inferred`, never a pass), fewer were counted
    (`uncounted`), the ring lost records (`ring_lost`), the records miss a
    due time (`ticks`), the provider predates v29 (`no_outbound`) or its
    marker range differs from the helper's or a socket is outside it
    (`mark_mismatch`; no port is named), there is no armed span
    (`no_armed_span`), or nothing was written (`not_written`). **Fail**
    only for reads that were not `guarding`, not under one arm, or not
    parsed. Detail: `class= sockets= expected= per_socket= counted=
    matched= unmarked= inferred= ring_lost= data_counted= tx= rx=
    keepalive= tol_ms= span_ms=`.
  - `presock_counted_<if>` (info): `tx= data_counted=
    blocked_before_filter= keepalive_expected= keepalive_counted=
    class=`: the data segments the sockets sent (TCP_CONNECTION_INFO,
    retransmissions included), how many the filter counted as marked data
    drops, and the rest, which never reached it.
  - `presock_bpf_order_<if>` (info): `post_filter` when that interface's
    capture is complete, the window's `filter_armed_span` passed and the
    tap evidence holds (`tap_evidence=post_filter`: for one frame kind,
    `data`, `ack_only` or `other`, the outbound ring holds more marked
    drops on that interface between the reads than the capture holds
    frames of that kind from a source port of the marker range while
    armed, anyone's and to any host; a tap before the filter records
    every frame the filter drops, so it would hold at least as many);
    with helper frames in the capture it adds that they left the Mac.
    `unknown` otherwise (`capture_incomplete=<if>:<reason>` when the
    capture did not cover the armed span whole); never `pre_filter`. The
    frame counts carry `uncounted=` (the helper's frames of a kind beyond
    the marked drops of that kind the filter counted on that class
    between the window's first and last `--filter-status`, all of them
    without a v29 provider), `after_disarm=` (the capture's frames after
    the disarm) and `tap_evidence=`.
- `positive_control_verdict`: **fail** on `answered_while_armed=<ifs>`,
  `fresh_probe_answered=<ifs>`, `uncounted_frames=<ifs>` (a capture
  holds more of the helper's frames while armed than the filter counted
  marked drops of their kind: they left the Mac) or `frames_left=<ifs>`
  (a complete capture under a passing `filter_armed_span` with tap
  evidence `post_filter` holds a helper frame while armed: it left the
  Mac, whatever the drop counts and whatever the keepalive row read);
  **pass** only when `presock_open`,
  `presock_unacked` and `presock_keepalive_drops` passed on the primary
  interface, no frame of any helper is in any capture during the armed
  span, each counted, and every such capture is complete
  (`captures=complete`); **unavailable** otherwise (`frames_seen=<ifs>`:
  counted frames in a capture may have been dropped after the tap or have
  left; `captures_incomplete=<if>:<reason>,...`).

**S20h review (source only).** Three confirmed findings, fixed before v29
was ever built (details, tests and checks: the
[NE README](../README.md) "B-06 S20h review findings"):

- **The marker TTL never reaches a keepalive.** XNU sends a socket's
  keepalives from `tcp_timer.c` (TCPT_KEEP, `tcp_send_keep_alive`)
  through `tcp_respond`, which builds them from the connection's
  template, its addresses and ports, and sets an IPv4 packet's TTL to the
  system default (`ip_defttl`, `net.inet.ip.ttl`, 64), never the socket's
  `IP_TTL`; only `tcp_output` segments carry `IP_TTL`, and
  `includeAllNetworks` holds those before the filter. Every helper
  keepalive the filter dropped would have read unmarked, so
  `presock_keepalive_drops` could only ever read `unattributed` and the
  verdict could never pass (the S20g defect again). The marker is now the
  TCP source port, which a keepalive shares with its connection by
  construction: the helper binds there, and the provider marks a TCP drop
  from a port of the range whatever its TTL. A Rust test feeds an XNU
  keepalive (bare ACK, `seq = snd_una - 1`, TTL 64) from a marker port,
  and the same bare ACK with TTL 77 from other ports, through the filter.
  The negative control's `presock_wire_<if>` ends with `ack_only_marked=`
  (the helper's bare ACKs on the wire, filter off, from a port of the
  range). The preflight refuses a `PC_SPORT_BASE` whose probes reach into
  the range on any of the interfaces present (interface k probes from
  `PC_SPORT_BASE + k * PC_PROBES`).
- **A pass needs complete captures.** A positive verdict rests on no
  helper frame in any capture while armed, so every checked capture must
  be complete: alive at the disconnect, stopped by the window, `0 packets
  dropped by kernel`, and at least one frame after the disarm
  (`after_disarm`); otherwise `unavailable captures_incomplete=`. A
  capture that lost frames under load, died, or stopped recording early
  could have missed a transmission that left.
- **Tap evidence restores the fail for frames that left.** The
  `uncounted` bound subtracts the class's marked drops from the frames of
  their kind, so data frames that left beside more counted drops (tx=6,
  four counted, two left on `en0`) read only `frames_seen`, where v28
  failed. A tap before the filter records every frame the filter drops,
  so when the filter dropped more of the marker's segments of one kind on
  an interface between the reads than that complete capture holds, its
  tap comes after the filter and any helper frame in it while armed left:
  `frames_left` fails the verdict. The inference needs a complete capture
  and a passing `filter_armed_span` (the reads then lie inside the
  reviewed span); otherwise the counts stay a lower bound. With
  post-filter evidence a capture's helper frames are never `frames_seen`.

Fresh probes that never ran (a window that never reached Connected) read
`bound_fresh_<if> not_run` and no longer fail the verdict; the
pre-existing sockets' rows read `presock_unacked_<if>` (or
`presock_acked_<if>`) `unavailable not_connected`.

**Negative control.** The write comes right after `connected` (hook
`ctl_connected`), before any standard check and without a
`--filter-status` read, so a gateway that resets idle connections (about
15 s on the v28 LAN) cannot close the sockets first. `presock_acked_<if>`
passes only when every written socket's bytes were acknowledged.
`presock_frames_<if>` reads `unknown nothing_written` when nothing was
written. New `presock_wire_<if>` (info): the helper's frames in that
capture over the Connected interval, its keepalives expected among them
with the filter off, and (S20h review) `ack_only_marked=`, those of its
bare ACKs from a port of the marker range: every one, since the helper
binds only there and a keepalive carries its connection's ports, so it
shows the keepalives the filter will see carry the marker. Under
`includeAllNetworks` the written bytes may still stay unacknowledged with
the filter off (the system holds the socket's own output);
`presock_acked` then fails, which shows the hold, not a defect of the
probe.

Source only: run against fake commands, a loopback gateway and the real
helper (`RealRelayWindowControlTests`, `NetProbePresockTests`,
`LeakReviewPresockReviewTests`), never against this Mac.

## Timed TCP echo probes and IPv6 rows (B-06 S16i-3)

`ROLLBACK_S` now defaults to 180 s: with every check at its bound the window
takes about 165 s. `harness/net_probe.py` runs under `/usr/bin/python3 -I`
(3.9; `PROBE_PY` overrides it for tests). Its `tcp` probe connects, writes,
then either half-closes and reads to EOF (`hc`) or reads the payload back and
closes (`nohc`), all within `PROBE_LIMIT_S` (default 10 s). It records
`<bytes>/<ms>/<outcome>`, where outcome is `eof`, `full`, `reset`, `timeout`
or `error`. The rows are:

- `tcp_echo_v4`: the `hc` probe, and still the first user flow.
- `tcp_echo_v4_nohc`: the `nohc` control.
- `tcp_echo_v4_nc`: the old `nc -w 3` line, kept so the series stays comparable.
- `tcp_echo_v4_warm` and `tcp_echo_v4_warm_nohc`: the same two probes after the bursts.

Optional handoff fields are read with `ofield` and are empty when absent or
null: `relay_ipv6`, `echo_tcp6` and `echo_udp6` (`[v6]:port`), and
`whoami6`. Before connect, `physical_v6_baseline` records the physical IPv6
default interface and the number of non-link-local IPv6 addresses on every
interface, never the addresses themselves. macOS picks the IPv4 and IPv6
primary interfaces separately, so the Mac's own addresses are taken from all
interfaces, not only the captured IPv4 default.

While Connected, `v6_checks` records these rows:

- `utun_addr_v6`: fd00:ae61::1/120 on the utun (S16j-2; v21's /128 got no IPv6 route).
- `default_route_v6`: the IPv6 default route is on the utun.
- `route_v6_anchor` (S16j-2): `route -n get -inet6 fd00:ae61::2` names the utun.
- `scoped_phys_v6_default` (S16j-2, info): whether the physical interface keeps a scoped IPv6 default, as `<if>:present` or `<if>:absent`.
- `utun_routes_v6` (S16j-2, info): the utun's rows of `netstat -rn -f inet6` as `<destination>:<flags>`. Only `default`, fd00:ae61::, fe80::/64 and multicast prefixes are named; every other destination is only counted (`other=<n>`), so no physical or remote address is recorded.
- `source_v6_tunnel`: the kernel picks fd00:ae61::1 for a UDP connect, which sends no packet. Any other result is recorded only as a class, such as `physical_address`.
- `system_resolver_v6`: nameserver[1] is fd00:ae61::2.
- `dns_udp6_anchor` and `dns_tcp6_anchor`: a fake-IP A answer over IPv6.
- `dns_aaaa_via_relay` and `dns_aaaa_v6_anchor`: a 2000::/3 answer and no other IPv6 answer.
- `system_aaaa_observed`: info only.
- `http6_by_name`: `info_` unless `relay_ipv6` is set.
- `udp_echo_v6`, `tcp_echo_v6` (the timed probe) and `whoami6_egress`: `skip` without their fields. `whoami6_egress` fails as `physical_prefix_seen` when the body carries an address in the /64 of any of the Mac's own addresses. The whole body is scanned first. Body text is recorded only on a pass (the body names `relay_ipv6`; v34: masked, the relay as `relay_addr`); any other failure is recorded as a class, `empty`, `no_relay_ipv6` or `not_relay_address`, because the body may be the Mac's address from a prefix the scan never saw.

After the unchanged rollback-cancel gate, `disconnect_v6_route` (back to the
baseline) and `disconnect_v6_addr` (no fd00:ae61::1 left) are recorded as
separate rows. With `LEAK_CAPTURE=1`, `no_v6_leak_physical` reads
`leak_families.ipv6` from the same `leak-review.json`; no second tcpdump runs.
It passes with zero IPv6 leaks and a valid capture. Without the capture it is
`unavailable`. It is also `unavailable` (`v6_default_interface_differs`)
when the baseline IPv6 default interface is not the captured IPv4 default:
the capture could not have seen an IPv6 leak there. Source only: run against fakes and loopback servers.

## Network loss while Connected (B-06 S21i)

`OUT=... NETLOSS=1 harness/real-relay-window.sh` runs the usual window and,
after the IPv6 rows and before the disconnect, one network-loss cycle
(`harness/netloss.sh`, sourced by the window):

1. A detached rollback is armed: its launcher forks it and exits, so it is
   confirmed alive, adopted by launchd (ppid 1) and the leader of its own
   session and process group (and it ignores INT, TERM, HUP and QUIT)
   before anything is turned off. No kill of the window's process tree,
   by group or by walking its descendants, reaches it. Without that nothing
   is turned off.
2. `networksetup -setairportpower <device> off`, read back as `Off`.
3. For `NETLOSS_OFF_S` (default 10, 1..60) every distinct tunnel status and
   default-route interface is recorded (`netloss_status_during_off`).
4. `networksetup -setairportpower <device> on`, up to three attempts of
   `NETLOSS_RESTORE_WAIT_S` (default 10, 1..30) each, until it reads back
   `On`. Only then is the rollback cancelled by its token; the rollback
   reads `On` back itself before it accepts the cancel. Otherwise it stays
   armed and, `NETLOSS_OFF_S + NETLOSS_GRACE_S` (default 15) after arming,
   turns the interface on and retries until it reads `On` back, whatever
   happened to the window (SIGKILL of the window and its process group
   included).
5. `netloss_recovered`: Connected on two polls in a row with the physical
   IPv4 address back and the default route on the utun, within
   `NETLOSS_RECOVER_S` (default 60, 5..180). Then `netloss_whoami_egress`,
   `netloss_udp_echo_v4` and the timed `netloss_tcp_echo_v4`.
6. From the provider log of the cycle: `netloss_log_path_change`,
   `_relay_interface_repinned`, `_session_lost`, `_session_rebuilt` and
   `_reasserting` (info: count and values), and `netloss_rebuild_settled`
   (pass when there was no reassertion or the last one is `off`).

`NETLOSS_ADDR=1` adds an interface address change after a verified Wi-Fi
restore: `networksetup -setv6off <service>` for `NETLOSS_ADDR_OFF_S` and
back to `-setv6automatic`, under its own rollback, with the same rows under
`netloss_addr_`, and `netloss_addr_relay_path_exercised`: pass only when the
provider logged a `path_change` and a `relay_interface_repinned` or a
`session_rebuilt` in the cycle. It runs only for an IPv6 relay: the
provider's path watch keeps only relay-family addresses, so with an IPv4
relay an IPv6 change could re-pin or rebuild nothing, and the phase is
recorded `netloss_addr_change skip` before anything is read or changed. The
service is the one enabled entry of `networksetup -listnetworkserviceorder`
on the Wi-Fi device (a disabled `(*)` entry never counts) and its hardware
port must be `Wi-Fi`; none, more than one, another port or an IPv6 that is
not `Automatic` beforehand is a `skip` with that reason. A refused
`-setv6off` (for example an administrator authorization) is recorded
`unavailable` and the service is still set back and verified. Only counts
of physical IPv6 addresses are recorded (`netloss_addr_v6_count`), never an
address.

Before the lock, the rollbacks or any connect, `NETLOSS=1` refuses (exit 3)
when the physical default interface is not the `Wi-Fi` hardware port of
`networksetup -listallhardwareports`, its power does not read `On`, no
rollback interpreter is there to restore it (the refusal names whether
Wi-Fi is the only active route), a bound is outside its range, or
`LEAK_CAPTURE=1` is set (the captured interface would go down). Without
an explicit `ROLLBACK_S` the tunnel rollback grows by the cycle's worst case.
`LOG_BIN` (default `/usr/bin/log`) and `NETWORKSETUP` exist for the tests.
Source only: run against fake commands.

## Owner-attended sleep and interface switch (B-06)

`harness/owner-modes.sh` (sourced by the window after `netloss.sh`) adds two
owner-attended modes. Each runs once while Connected, after the IPv6 rows
and before the disconnect, with every other check, the timing lock and the
detached tunnel rollback unchanged. Only one of `NETLOSS=1`, `SLEEP=1` and
`IFSWITCH=1` runs in a window; asking for two refuses. Without an explicit
`ROLLBACK_S` the tunnel rollback grows by the mode's worst case, and the
capture bound is recomputed from it (`rollback_s` and `capture_bound_s`
are printed). Every refusal below exits 3 before the lock, the rollback,
any capture or any connect.

### SLEEP=1

```sh
sudo -v      # in the same terminal: the window never prompts
OUT=<new dir> SLEEP=1 [LEAK_CAPTURE=1] harness/real-relay-window.sh
```

It refuses unless `sudo -n -l /usr/bin/pmset` passes, `kern.waketime` is
readable, `/usr/bin/python3` is there for the guard, (v30) the
unprivileged `pmset -g` shows `SleepDisabled 0` (`sleep_guard.py
disabled`; a missing line is 0; `SleepDisabled=1`, the `pmset disablesleep
1` setting, refuses every demand sleep, kPMUserDisabledAllSleep, and an
unreadable `pmset -g` refuses too; only the owner changes it, never the
window) and `SLEEP_WAKE_S` (default 40, 20..600), `SLEEP_WAKE_SLACK_S` (60,
10..300), `SLEEP_RECOVER_S` (60, 5..300), `SLEEP_GUARD_SETTLE_S` (2, 0..30)
and (v30) `SLEEP_GUARD_CALL_S` (20, 1..60, the guard's bound for its one
sleep request) are in range. `sleep_preflight` names `sleep_disabled=`. With the default dated wake, `SLEEP_WAKE_S` must also be at least
`SLEEP_GUARD_SETTLE_S` + 20, so the wake is still well ahead when the
guard asks for sleep. While Connected:

1. `sleep_guard_armed`, before any wake exists: `sleep_guard.py guard`
   forks and exits; the guard must be adopted by launchd (ppid 1) and lead
   its own process group, so no kill of the window's group or tree reaches
   it. It stays in the window's session: sudo's cached credential belongs
   to the terminal's session, which a new session would lose. v30: right
   after `armed` the guard itself runs the read-only `sudo -n -l
   /usr/bin/pmset` and reads `pmset -g`, and logs `credential
   sudo=ok|no_credential|refused sleep_disabled=0|1|unknown` (with the
   bounded stderr when refused); the window proceeds only on `credential
   sudo=ok sleep_disabled=0`, so the process that will ask for the sleep
   has shown it can. It waits up to 60 s for `sleep-guard.log.go`. A guard
   that is not confirmed is told to stand down through
   `sleep-guard.log.cancel`, the row names its credential line, and no wake
   is scheduled.
2. By default (`SLEEP_WAKE_KIND=absolute`) a dated wake,
   `sudo -n /usr/bin/pmset schedule wake "<MM/dd/yy HH:mm:ss>" aegis-b06`
   at now + `SLEEP_WAKE_S`, which can be listed and cancelled. Only with
   `SLEEP_WAKE_KIND=relative` `sudo -n /usr/bin/pmset relative wake
   SLEEP_WAKE_S`, after the window prints that this wake cannot be
   cancelled or undone: it applies to the next sleep, whenever that is.
3. `sleep_wake_scheduled`: the wake is read back from `pmset -g sched`
   (`harness/sleep_guard.py check`): a one-time wake at least 15 s after
   now and by now + wake + slack, or a listed relative wake whose seconds
   fit. A relative wake is not listed by every macOS; when it is not
   listed the row fails, nothing sleeps, and that wake stays pending for
   the next sleep. Only after the read-back does the window write the go
   (`hi=<bound>`).
4. `sleep_guard`: after `SLEEP_GUARD_SETTLE_S` the guard refuses
   (`sleep_refused window_gone`, `cancelled`, `no_go`, `bad_go` or
   `no_scheduled_wake`) when the window is gone, it was cancelled, no
   valid go came or the wake is no longer listed at least 15 s ahead;
   v30: it reads SleepDisabled again first and refuses
   (`sleep_refused sleep_disabled`) with no privileged call when it is not
   0. v30 review: right before the request it creates
   `sleep-guard.log.claim` exclusively (`guard pid=... at=...`); the window
   stands it down by writing `sleep-guard.log.cancel` and creating the same
   file (`window pid=... at=...`), so exactly one side holds it. Without the
   claim, or with the cancel file or a gone window after it, the guard
   refuses (`cancelled`, `window_gone`); otherwise it runs `sudo -n
   /usr/bin/pmset sleepnow` once, bounded by `SLEEP_GUARD_CALL_S` and never
   retried, and records
   `sleep_requested rc=<rc> at=<epoch> wake=<kind> cause=<cause>
   [error=0x...] out=[...] err=[...]` in `sleep-guard.log`. The cause is
   `ok`, `pmset_not_permitted` (71: any IOPMSleepSystem error but
   not-privileged, such as a disabled sleep), `pmset_not_root` (77),
   `sudo_no_credential` (1 with sudo's "a password is required"),
   `timeout` (partial output kept) or `other`; `error=` is pmset's code from
   its stdout (pmset writes errors there). Output is one printable line of
   at most 200 characters per stream, with IPv4, IPv6 and MAC addresses
   masked (v30 review: also an IPv4 address before a full stop or a port,
   an IPv4-embedded IPv6 address and an IPv6 address before a colon; a time
   of day stays). Only `rc=0` passes the row. The window waits for the
   verdict as long as the guard's own bounds allow (v30 review: settle +
   50 s of bounded reads + `SLEEP_GUARD_CALL_S` + 10 s, counted in awake
   half-seconds; before, about settle + 40 s whatever `SLEEP_GUARD_CALL_S`
   was). After any refusal, and again at exit, a dated wake that is still
   ahead is cancelled by its date and owner (`sleep_wake_cancelled`,
   `at_exit` at exit, `out=[...]` when the call printed anything; v30: the
   schedule's and the cancel's output are kept in `sleep-pmset.out` and
   `sleep-cancel.out`); a relative one cannot be. v30 review: the wake is
   kept instead (`sleep_wake_kept`, with the command that removes it once
   the Mac is awake) whenever a request may still bring the Mac to sleep:
   no verdict while the guard holds the claim, `rc=timeout` or a negative
   rc (the bound kills only the user's sudo, and the root pmset it started
   may still ask; the row says `outcome unknown ...
   slept_since_request=yes|no|unknown` from `kern.sleeptime`, never
   "nothing slept"), or, at exit, an accepted request whose wake the window
   has not seen. Every EXIT trap of the window (Ctrl-C, `timeout`, any
   exit) first stands the guard down, before it stops any capture.
5. `sleep_woke`: `kern.waketime` advances within wake + slack seconds of
   the request, after a `kern.sleeptime` that is not older than the
   request; the detail records how long it slept.
6. With `LEAK_CAPTURE=1`, `sleep_capture_alive_after_wake`. The tcpdump
   `-G` bound counts wall time, so it grows by wake + slack and the one
   physical capture spans the sleep; `leak_proof` still needs it alive at
   the disconnect.
7. `sleep_recovered` (Connected on two polls in a row, default route on the
   utun, an IPv4 address on the physical interface, within
   `SLEEP_RECOVER_S`), then `sleep_whoami_egress`, `sleep_udp_echo_v4` and
   the timed `sleep_tcp_echo_v4`.
8. From the provider log of the cycle: `sleep_log_sleep`, `_wake`,
   `_reack`, `_session_lost`, `_session_rebuild`, `_session_rebuilt`,
   `_reasserting` and `_path_change` (info: count and values),
   `sleep_rebuild_settled`, and `sleep_provider_cycle`: pass only with a
   `sleep` and a `wake` code and the action the last wake named, a
   `reack forced` for `wake reack` or a `session_rebuilt` for
   `wake rebuild` or `wake reasserting` (`unavailable` without any line).

The tunnel rollback's timer counts awake time; its extra (wake + slack +
recovery + the verdict wait + 60 s; v30 review, before: settle + 100 s in
place of the last two) also covers the sleep itself.

### IFSWITCH=1

```sh
OUT=<new dir> IFSWITCH=1 [IFSWITCH_TO=en7] [LEAK_CAPTURE=1] harness/real-relay-window.sh
```

The physical default interface (`route -n get default`, also the first
hardware port in the IPv4 list of `scutil --nwi`) decides the direction:
from Wi-Fi the owner plugs the Ethernet cable into the one `en<N>` hardware
port named Ethernet or LAN, which must be present and inactive
beforehand; from an Ethernet port the owner unplugs its cable (the cable,
not the adapter) and the route goes back to Wi-Fi, which must already be
active with an IPv4 address. `IFSWITCH_TO` names the target when there is
not exactly one. Refusals name the reason (no hardware port, no or several
candidates, the target is the current interface, absent, already active,
or no route would be left, `IFSWITCH_BOUND_S` (default 120, 5..600),
`IFSWITCH_RECOVER_S` (60, 5..300) or v33's `IFSWITCH_SETTLE_QUIET_S` (5,
2..30, and v33 review: at least 6 s below `IFSWITCH_RECOVER_S`) out of
range, no settle judge). In the
plug direction the
target's enabled network service must rank above the current one in
`networksetup -listnetworkserviceorder` (otherwise plugging in would not
move the IPv4 primary), and the refusal names both orders.

v30 attach wait: in the plug direction with an explicit `IFSWITCH_TO` that
is not yet a hardware port and an interface (an adapter plugged in seconds
before; window-v29-ifswitch-r3 refused 10 s before its adapter attached),
the preflight prints `ifswitch: waiting up to <N>s for <to> to attach
(adapter in, cable out)` and polls `networksetup -listallhardwareports`
and `ifconfig <to>` once a second for up to `IFSWITCH_ATTACH_WAIT_S`
(default 30, 0..180; 0 refuses at once as before). It proceeds once both
have shown the target for `IFSWITCH_ATTACH_SETTLE_S` (6, 2..30) in a row
(a disappearance restarts the settle), then reads the hardware ports again
(so the new interface counts as one), repeats the physical-primary check
and the `timing-peer` check (exit 4), and runs every check above
unchanged; `ifswitch_preflight` adds `attach_after=<s>s settle=<s>s`. When
nothing attaches in time the usual refusal gets `(not attached within
<N>s)` and the names (never addresses) of any new hardware port. All of it
comes before the lock, the rollback, the captures and any connect. In the
plug direction a target with a link but no address yet (`status: active`,
cable already in) is refused as well (`take the cable out of the adapter
before the window`): DHCP would move the primary before the owner's
action. Automatic candidate selection and the unplug direction do not
wait.

While Connected, `ifswitch_preflight` (info: from, to, direction, bounds)
and `ifswitch_primary_before` (the physical primary is still readable from
`scutil --nwi` with the utun up; otherwise nothing is asked of the owner)
come first. The window then rings the bell and prints
`OWNER ACTION: plug the Ethernet cable into <to> (<port>) now` or
`OWNER ACTION: unplug the Ethernet cable from <from> (<port>) now`, and
waits up to `IFSWITCH_BOUND_S` for the physical primary to change:
`ifswitch_status_during_switch` (info: tunnel statuses and primaries seen),
`ifswitch_route_changed` (pass when it moved to the target; without a move,
`ifswitch_recovered skip` and nothing else of the mode runs). After a move,
`ifswitch_recovered` (as above, the IPv4 address on the new interface),
v33's `ifswitch_settled_before_probes` (below), `ifswitch_whoami_egress`,
`ifswitch_udp_echo_v4`, `ifswitch_tcp_echo_v4`, the provider's
`path_change`, `relay_interface_repinned`, `relay_interface_repin_refused`,
`session_lost`, `session_rebuilt` and `reasserting` codes (info),
`ifswitch_rebuild_settled`, `ifswitch_relay_path_exercised` (v33 review:
pass only with a `path_change` and a `relay_interface_repinned
name:<new>`; before, a `session_rebuilt` alone passed too), v33 review's
`ifswitch_session_lost_by_repin` (below) and, when the gate passed, v33's
`ifswitch_session_lost_after_settle`. The unchanged
disconnect gate then waits for the default route on the new interface
(`disconnect_verified` names it), and `disconnect_v6_route` accepts the
baseline or the new interface (`or_switched=<if>`), or no IPv6 default at
all (`or_none`) when neither the baseline IPv6 interface nor the new one
holds a global IPv6 address right before the disconnect (an unplug onto a
Wi-Fi without IPv6). Leave the cable as it is until `done`.

v33 settle gate. `ifswitch_recovered` reads only the system's state, and
the provider can still lose its session after it passed. In
window-v32-ifswitch-r3 (the plug, 27 October) it passed 0.56 s after the
route change; the provider lost the session by lease expiry at +1.97 s
(`session_lost capture_lease_expired`) and rebuilt it at +3.79 s, so
`ifswitch_whoami_egress` (from +0.56 to +3.80 s) ran inside the rebuild and
failed, while the UDP and TCP probes after it passed. From v33
`om_settle` runs between the two. Once a second it reads the provider's own
log, `log show --start <window start> --style compact --predicate
'process == "aegis-ne-provider" AND eventMessage BEGINSWITH "aegis-ne"'`
(S24's predicate; a test keeps the two equal), into
`ifswitch_settle.log`, and `harness/settle_judge.py` judges the read. The
switch has settled when:

- no `session_failed` was logged;
- no loss is pending: every `session_lost` or `reasserting on` was
  followed by a `session_rebuilt` or `reasserting off`;
- the provider logged a `path_change` since the owner's prompt;
- its log reaches `IFSWITCH_SETTLE_QUIET_S` past the latest of the route
  change, the last path change and the last rebuild. Lines come in time
  order, so a line that late shows nothing in the quiet period was missed;
- the recovery's conditions (Connected, the IPv4 address, the default
  route on the utun) hold again at that moment.

Only the provider process counts: another process's `aegis-ne` lines (a
cargo test binary of this crate) never settle the gate. The compact
timestamps are read as local time, with the Mac's zone and daylight
saving. A failed read never settles, and a silent provider never does
either. The default quiet period, 5 s, is above the longest capture lease
of the v32 windows (3660 ms): that is the latest a silently broken path
surfaces as `capture_lease_expired`. Replayed with it, the v32 switches
would have released the probes 7.0 s (r2), 8.8 s (r3) and 7.3 s (r4) after
the route change.

The gate shares `IFSWITCH_RECOVER_S` with the recovery, counted from the
route change. No read starts with under 1 s left, and each is bounded by
what is left (at most 10 s), so the rollback and the capture bound
(`OM_EXTRA_S`) are unchanged. v33 review: the preflight refuses an
`IFSWITCH_RECOVER_S` less than 6 s above `IFSWITCH_SETTLE_QUIET_S` (no
read in the bound's last second, about one read a second, and the quiet
period counted from a rebuild that came 3.79 s after the route change in
r3): such a gate could never settle after a rebuild.
`ifswitch_settled_before_probes`:

- passes with `settled_after=<s>s rebuilt_after=<s>s|no_loss
  path_change_after=<s>s quiet=<Q>s lost=<n>:<codes> rebuilt=<n>
  reads=<n> probes_after=<s>s bound=<R>s` (seconds after the route
  change);
- fails at once with `session_failed:<code> after <s>s reads=<n>`;
- fails at the bound with `not settled within <R>s of the route change:
  pending=... lost=... rebuilt=... path_change=... settled_after=...
  covered_after=... reads=... failed_reads=... up=... status=...
  waited=...`: a rebuild that never settles, rebuilds that keep flapping,
  a silent provider, failed or hung reads, no path change;
- is `skip not recovered` when `ifswitch_recovered` failed.

The probes always run after the row and are judged as before.
`ifswitch_settle.trace` keeps one line per read (time, rc, read time, the
judge's line). After the probes, `ifswitch_session_lost_after_settle`
(info) counts the provider's `session_lost` lines after the gate released
them, from the final provider read (`unavailable` without provider lines),
so a loss inside the probes is shown next to them. v33 review: it counts
from the newest provider line the releasing read held (the judge's
`covered_ms`), not from the moment of the release: a loss logged while
the judge and the recovery check ran after that read was seen by neither
before. `SLEEP=1` and `NETLOSS=1` keep their recover-then-probe order.

v33 review: the switch's own rows. Because the gate waits out any loss
that was rebuilt, an r3-like outage no longer fails a probe, so the
provider's own lines (the final read, that process only, from the
owner's prompt; `settle_judge.py ... <new>`) now decide whether the
provider followed the switch as designed:

- `ifswitch_relay_path_exercised` passes only with a `path_change` and a
  `relay_interface_repinned name:<new>`. r3's rebuild on the stale en0 pin
  (`repinned_to_en7=0 rebuilt=1`) passed before and fails now.
- `ifswitch_session_lost_by_repin` passes with `count=<n>
  codes=relay_path_changed rebuilt_after=<s>s` when every `session_lost`
  since the prompt is the re-pin's seal and there is at least one. It
  fails with `...: a session_lost other than the re-pin's
  relay_path_changed` on any other code, whenever it came (r3's
  `capture_lease_expired`, a loss before or after the re-pin, a loss
  inside the probes), and with `...: no session_lost relay_path_changed,
  so no session was sealed by a re-pin` when there is none; `unavailable`
  without provider lines. `rebuilt_after` is the last rebuild after the
  route change (info).

So r3 fails two rows instead of `ifswitch_whoami_egress` alone, whatever
the probes' timing, while the v32 unplugs (r2, r4: re-pinned to en0,
`relay_path_changed`, rebuilt) pass both.

With `LEAK_CAPTURE=1` both interfaces are captured: `physical.pcap` on the
first as before and `physical-<to>.pcap` on the target, with the same
tcpdump options, both started before the lock and the connect (the second
is confirmed by tcpdump's own `listening on <to>` line, because an
interface without a link writes no packet; one that does not start
refuses and stops the first). One of the two always sits on an interface
without a link (the target before the plug, the unplugged port after it),
where tcpdump's `-G` bound, checked only when a packet arrives, never
fires. So with `IFSWITCH=1` both start under a root alarm,
`sudo -n /usr/bin/perl -e 'alarm shift; exec @ARGV; exit 127' <bound+30>
/usr/sbin/tcpdump ...` (the alarm survives the exec; tcpdump sets none of
its own without `-v`), and the mode refuses unless `sudo -n -l
/usr/bin/perl` passes. The EXIT trap stops both. The detached tunnel
rollback asks `sudo -n /bin/kill` for both when it fires, but only as best
effort: it runs in a new session without the terminal's cached sudo
credential, and its `capture_stop_requested ... rc=` line records a
refusal. The alarm is what guarantees both end. The second
gets its own rows: `ifswitch_capture_started`,
`ifswitch_leak_window_disconnect_at`, `ifswitch_capture_stopped`,
`ifswitch_leak_proof` (from `leak-review-<to>.json`, with the same
alive/stopped/zero-drop conditions) and `ifswitch_leak_capture_sha256`.
Both reviews are given each interface's addresses from before the switch
as well as after it. Keep both captures out of Git and retained evidence.
S20d: every other interface the Mac could send on gets its own capture
from the window under the same alarm (S20e: with or without `IFSWITCH=1`).
The target is never captured twice.
`leak_proof_all_ifaces` and `no_mac_sent_leak_physical` include the
target's capture, and its relay packets are required.

`PMSET` (unprivileged `-g sched` reads only), `SYSCTL` and `OM_PY` exist for
the tests; every change goes through `sudo -n /usr/bin/pmset`. Results and
logs name interfaces, never an address. Source only: run against fake
commands (`RealRelayWindowOwnerModeTests`), never against this Mac.

## Endurance and heavy inbound load (B-06 S24)

`harness/endurance-load.sh` (sourced by the window after `controls.sh`)
adds two unattended modes for the B-06 GO gates "endurance" and "burst
behaviour under heavy inbound load with the filter on". Neither needs
sudo. The window's connect, detached tunnel rollback, `timing-self` lock
(held for the whole window, its line now naming the mode and an
`ends_by=<UTC>`), `timing-peer` refusal (exit 4) and verified disconnect
are unchanged. Both run after the baseline and IPv6 rows and before the
disconnect. Without an explicit `ROLLBACK_S` the tunnel rollback grows by
the mode's worst case. A given `ROLLBACK_S` that is shorter than
180 s plus that worst case is refused, because the rollback would stop the
tunnel mid-run. The window prints `rollback_s`, `capture_bound_s` and
`window_bound_s` (the rollback plus the provider-log read after the
disconnect plus 120 s). Give an outer runner at least `window_bound_s`.
Every refusal below exits 3 before the lock, the rollback, any capture or
any connect.

Every window, with or without these modes, also refuses (exit 3, right
after the `timing-peer` check) while a detached tunnel rollback of an
earlier window is still armed: a live process whose arguments name a
`rollback.cancel` and this `timing-self`. Such a rollback stops whatever
tunnel is up when it fires. A rollback that fires releases `timing-self`
only while the lock still holds the line its own window wrote
(`lock_released`, else `lock_kept not_ours` in its `rollback.log`).

- `ENDURANCE=1` refuses beside `LOAD=1`, `LEAK_CAPTURE=1` (one disruption
  or capture per window; hours of capture would also threaten the disk
  floor), `NETLOSS=1`, `SLEEP=1`, `IFSWITCH=1` and either control.
- `LOAD=1` refuses beside `ENDURANCE=1`, `NETLOSS=1`, `SLEEP=1`,
  `IFSWITCH=1` and either control. It may run with `LEAK_CAPTURE=1` (the
  owner's sudo), so the same window can show no Mac-sent leak under load.

These modes refuse before any other mode's preflight runs.

### ENDURANCE=1 (S24a)

```sh
OUT=<new dir> ENDURANCE=1 [ENDURANCE_S=7200] [ENDURANCE_PERIOD_S=60] harness/real-relay-window.sh
```

`ENDURANCE_S` (default 7200, 600..86400) and `ENDURANCE_PERIOD_S` (60,
15..600). Cycles start at 0, P, 2P and so on, and the last one starts at
`ENDURANCE_S`, so there are ceil(`ENDURANCE_S`/P) + 1 of them (121 by
default). Preflight refusals:

- One cycle's bound is not below the period. With the shipped bounds this
  never happens (a test checks every period from 15 to 600 s). The bound
  is made of these parts:
  - the provider-log read: a quarter of the period, 3..30 s, but never so
    long that the probes lose their full bounds (`log_bound_s`);
  - the same read once more after a 1 s settle;
  - every probe, the host's `--status` and the provider sample at once,
    bounded by the longest of them. At full length the probes have the
    baseline rows' own bounds: the TCP echo 10 s (`PROBE_LIMIT_S`'s
    default), whoami 5 s, HTTP 8 s, the TXT query and the UDP echo 3 s.
    `--status` gets 4 s, and `pgrep` and `ps` 5 s each, one after the
    other. A period too short for that cuts each to what it leaves
    (`probe_bound_s`): 4 s at 15 s, with `pgrep` and `ps` 2 s each. The
    full bounds hold from 21 s on;
  - 3 s for the processes and the row.

  That is 14 s at a 15 s period and 44 s at the default 60 s
  (`cycle_bound_s`). A cold flow through the installed tunnel took up to
  about 3.6 s, so a period below 21 s may fail healthy cycles; use 60 s for
  gate evidence.
- Free space on the volume holding `OUT` (`df -Pk`) is below 31 GiB.
- `/usr/bin/caffeinate` is missing.
- The device certificate's `not_after` from `host --cert-status` (stdout
  JSON; no provider tree is read) is earlier than the window's start +
  `ENDURANCE_S` + 30 min. It is also refused when that value is unreadable.
  While no session has run since the provider process started, the
  provider answers `no_epoch`. Run one ordinary window first.
- The handoff's `expires_utc` (only that field is read) is earlier than
  the start + `ENDURANCE_S` + 15 min. It is also refused when the field is
  absent, unparsable or has no time zone.

The tunnel rollback grows by `ENDURANCE_S` + P + the cycle's bound + a
final read with its re-read (2 × `log_bound_s` + 1), the same again after
the wait for a loss still pending, + 120 s (7486 s by default). The provider-log read after the disconnect gets 60 +
`ENDURANCE_S`/30 s instead of 60 (300 s by default).

While Connected, `caffeinate -i -w <window pid>` keeps the Mac from idle
sleep. This is a power assertion that lasts as long as the window; it
changes no setting. Then each cycle does the following:

1. It samples `scutil --nc status`. A status other than `Connected`, or
   `Connecting` while the provider reasserts, ends the cycles here, because
   the probes would no longer go through a tunnel. `scutil` prints
   `Connecting` for a reassert (a session rebuild) and never
   `Reasserting`, which is taken the same way. The status is also sampled
   every 5 s between cycles.
2. It reads the provider log since the last good read into
   `endurance-provider.log` (`log show` within `log_bound_s`, a 10 s
   overlap; lines already kept are dropped). Only the lines of the
   `aegis-ne-provider` process are kept, by the predicate and again by the
   process field: this crate's cargo tests log the same `aegis-ne` lines
   from their own process. A `session_lost` is pending until a `session_rebuilt`
   follows it in the log. A rebuild logged just before the read may not be
   visible yet, so a loss that looks pending is read once more after a 1 s
   settle. A loss still pending then did not rebuild before this cycle's
   probes.
3. It runs these at once, each bounded:
   - egress whoami, which must name the relay;
   - the timed TCP echo (`net_probe.py tcp hc`);
   - a UDP echo;
   - a TXT query to 198.19.255.2 through the relay;
   - HTTP by name (`http://example.com/`, 200);
   - `host --status`: `session_phase` from its stdout JSON, and the v31
     renewal line's class from stderr (`deferred:guarded`,
     `failing:<class>`, `expired` or `none`);
   - `pgrep -x aegis-ne-provider` with `ps -o rss= -o %cpu=`.
4. It samples the status again.

A slot that no cycle could start within its period is a missed cycle. This
happens when the Mac slept or the window stalled, also while it waited for
that slot: the clock is read again after the wait. A missed cycle fails
like a failing one. The schedule's clock and sleep (`EL_CLOCK`, `EL_SLEEP`)
and `EL_CAFFEINATE` exist for the tests. `endurance_preflight` names an
overridden clock or sleep, and with either `endurance_real_time` passes
nothing.

`endurance.tsv` in `OUT` has a header and one row per cycle that ran or was
missed. Its columns are:

- `cycle`, `slot_s`, and `start` and `end` (UTC ms);
- `verdict` (`pass` when all five probes passed, `fail`, `missed`);
- one pass/fail column per probe: `whoami`, `tcp_echo`, `udp_echo`,
  `dns_txt`, `http`;
- `probe_detail`: the TCP probe's `<bytes>/<ms>/<outcome>` and the HTTP
  code;
- `status_start`, `status_end`, `phase`, `renewal`;
- `provider_pid`, `rss_kib`, `cpu_pct`;
- `log_read`, `session_lost`, `lost_causes`, `session_rebuilt`,
  `session_failed`, `renewal_states`;
- `rebuild_pending`: `1` for a loss not rebuilt before the probes,
  `unknown` for a loss that a failed read hid from an earlier cycle, `-`
  for a failed read;
- `codex_lock`: whether `timing-peer` existed;
- `run_ms`: the cycle's start on the schedule's clock, in ms since the
  first slot (for a missed cycle, when it was found missed).

It holds no address: no whoami body and no echo payload beyond what
`results.tsv` already records.

After the last cycle, one more status sample and a final log read stand for
the planned disconnect. A loss that the final read finds still pending gets
what a loss in any other cycle gets: the window waits until the next slot
(the last slot + P), sampling the status every 5 s, and reads once more.
Then `harness/endurance_review.py` writes the eight summary rows to
`results.tsv` with `result_since` from the start of the cycles:

- `endurance_cycles`: passes when at least 99% of the planned cycles passed
  every probe. A missed cycle, a cycle that never ran (the cycles ended)
  and a failing cycle all count against it. Of the default 121 cycles one
  may fail and two may not; under 100 cycles none may.
- `endurance_longest_gap`: passes when no two planned slots in a row
  failed, and no two passing cycles in a row started more than two periods
  + 5 s apart on the schedule's clock (`max_pass_gap_s`,
  `pass_gap_limit_s`). So no outage was longer than about two periods, also
  when a sleep during a wait leaves one missed slot and a late cycle
  (`pass_gap_after_cycle=`). The detail also gives `max_start_gap_s` (real
  UTC, info) and `awake=yes|no`.
- `endurance_connected_throughout`: passes when every status was
  `Connected` or `Connecting` (a reassert; `Reasserting` too). This covers
  the status column of every
  `results.tsv` row from `connected` on, every sample, both of each cycle's
  statuses, the final sample, and no early end of the cycles.
- `endurance_provider_stable`: passes when every cycle's `pgrep` names the
  one provider pid read at the start. A restart, a crash (no process) or
  more than one process fails it.
- `endurance_rss_growth`: passes when the provider's RSS at the last cycle
  that ran, minus its RSS at the baseline, is at most 64 MiB (65536 KiB).
  The baseline is the first cycle at or after 600 s into the run that is
  at least a period before the last one; in a run too short for that
  (600 s, or up to 600 s + P), the first cycle. Either reading missing, the
  two from different pids, or one reading only (`no_growth_window`, the
  cycles ended after the first) fails it.
- `endurance_rebuilds`: info, with the counts and causes of `session_lost`,
  `session_rebuilt` and `session_failed`. It fails in these cases:
  - a `session_lost` cause outside the provider's documented recoverable
    set (`session_rebuild.rs` `REFUSALS`, `Recoverable`, copied as
    `EL_RECOVERABLE` and compared by a test);
  - any `session_failed`;
  - a loss not rebuilt before the next cycle's probes;
  - an unjudged loss;
  - a final read that failed, still pending or unjudged;
  - no provider log line at all.
- `endurance_renewal`: info, with the `--status` renewal classes, the
  `identity_renewal state:` values from the log, and the `session_phase`
  values.
- `endurance_real_time`: passes when the cycles that ran span the run in
  real time: from the first cycle's start to the last one's (UTC), at least
  `ENDURANCE_S` less one period (a last slot missed). With the tests'
  clock or sleep (`clock=override`) it is `unavailable`: such a schedule is
  no endurance evidence.

The cycles that ran are recorded even when the run ends early.

A window that dies mid-run (killed, its terminal closed, its outer runner
ended) leaves the tunnel to its detached rollback. The rollback fires up to
`rollback_s` after the start, about two hours by default. When it fires
it stops whatever tunnel is up then, and until then every new window
refuses beside it. It ignores INT, TERM, HUP and QUIT, and the window that
could cancel it is gone. To end the window by hand:

1. Run `scutil --nc stop <service id>` (then `aegis-ne-host
   --emergency-stop` if needed) until `scutil --nc status <service id>`
   shows Disconnected.
2. Disarm the rollback. Its pid is on the `armed pid=<pid>` line of
   `OUT/rollback.log`. Check that `ps -o args= -p <pid>` names
   `OUT/rollback.cancel`, then run `kill -KILL <pid>`.
3. Only then remove `timing-self` by hand.

The same holds after `disconnect_verified fail` ("rollback stays armed"):
the window keeps the lock and leaves its rollback armed until it fires,
which with `ENDURANCE=1` can be hours away. Once the tunnel is verified
down by hand, disarm the rollback the same way before you remove the lock.

### LOAD=1 (S24b)

```sh
OUT=<new dir> LOAD=1 [LOAD_URL=... [LOAD_URL_BYTES=<n>]] [LOAD_STREAMS=4] [LOAD_BYTES=209715200] \
    [LOAD_BOUND_S=180] [LEAK_CAPTURE=1] [WINDOW_POLICY=fixed|adaptive] harness/real-relay-window.sh
```

The settings and their ranges:

- `LOAD_URL`, v34: default the immutable kernel tarball
  `https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz`
  (`EL_LOAD_URL_DEFAULT`; Fastly answers HTTP/2 200 with no redirect and
  no `Content-Encoding`, 140064536 bytes, `EL_LOAD_URL_DEFAULT_BYTES`).
  Until v33 the default was the speed-test host
  (`https://speed.cloudflare.com/__down?bytes=<cap>`), which refused one of
  v33's four identical requests with a 403; it now runs only as an
  explicit `LOAD_URL`. It must be a plain `http(s)` URL. Any URL must serve
  at least `LOAD_BYTES / LOAD_STREAMS` bytes per request, since
  `load_download` needs exactly that from every stream. The source is not
  the bottleneck (direct, 4 x 50 MiB took 18.4 s from cdn.kernel.org), the
  body is incompressible inside the end-to-end inner TLS, and the gate
  below is unchanged, so the new default makes the gate no easier.
- `LOAD_URL_BYTES` (v34, optional, 1..1099511627776): the size a given
  `LOAD_URL` serves when its URL names none. It is refused without a
  `LOAD_URL`: the default's size is pinned.
- `LOAD_STREAMS`, default 4, 1..8.
- `LOAD_BYTES`, the total cap, default 209715200, 1 MiB..1 GiB.
- `LOAD_BOUND_S`, default 180, 10..900.
- `WINDOW_POLICY` (v35, any mode, not only `LOAD=1`): empty, the default,
  connects the product default without the flag; `fixed` connects this one
  tunnel start with `aegis-ne-host --connect ... --window-policy fixed`
  (v33's fixed 128 KiB stream window) and, v36, `adaptive` with
  `--window-policy adaptive` (the v35 window, a QA arm; same build, same
  placement and telemetry). From build 36 the product default is the fixed
  window (v36 outcome `fixed`); build 35's default was the v35 window, so
  this harness expects `fixed` for an empty value and must run against
  build 36 or later. Any other value is refused before the lock, the
  rollback or any connect (exit 2), and is not echoed.

The gate (4 streams of exactly 50 MiB each within 180 s, no `-L`, so a
3xx fails, the filter on) is unchanged by v34. Running with
`LOAD_STREAMS=8` halves the per-connection requirement and hides stream
placement, so it is an extra info window only, never the gate.

Preflight refusals:

- The leak-guard filter is not configured, enabled and attached
  (`host --filter-status` exit 0): the load is meant to run with the filter
  on.
- A declared size below each stream's cap: no stream could reach it. v34
  checks every declared size: the default URL's pinned 140064536 bytes, a
  `LOAD_URL`'s `bytes=N` (as the speed-test host's names it) and
  `LOAD_URL_BYTES`. A given URL that declares no size is not checked.
- The free space on the volume holding `OUT`, less the captures' expected
  size, is below 31 GiB. With `LEAK_CAPTURE=1` the expected size is
  `LOAD_BYTES` plus 1 GiB; without a capture it is 0.

The tunnel rollback grows by `LOAD_BOUND_S` + 120 s. With `LEAK_CAPTURE=1`
the capture bound (rollback + 60 s) and the other captures' root alarm
follow it, so the one capture covers the load. `load_preflight` (info)
names the streams, the bytes, the per-stream cap, the bound, the URL's host
(`address` for a numeric one), `url=default|given`, `url_bytes=` (the
smallest declared size, or `undeclared`), `capture=` and `free_gib=`.

While Connected, the load runs in this order:

1. A `--filter-status` read (`filter-status-load-before.txt`) and a
   provider sample (v34, `load-provider-rss.txt`).
2. `LOAD_STREAMS` concurrent `curl -m LOAD_BOUND_S` downloads of `LOAD_URL`
   through the tunnel. Each is cut at `LOAD_BYTES / LOAD_STREAMS` bytes
   (`head -c`) and never written to disk. v34: `curl -D` keeps the
   response's headers, and the byte counter after `head -c` (as `wc -c`
   before it) keeps the body's first 256 bytes, both in `OUT` only until
   the stream ends. Then `load-target.<i>.head` keeps the status line and
   up to ten of `content-type`, `content-length`, `content-encoding`,
   `server`, `location`, `retry-after`, `x-cache`, `cf-ray`,
   `cf-mitigated` and `via`. For a status other than 2xx,
   `load-target.<i>.body` keeps the first 64 printable bytes of the body,
   and `window.log` says `load: stream <i> status <code>: <bytes>`. Both
   files are masked (below), and the verdict never reads them.
3. After 1 s: the two existing bursts, which write `load_flow_burst_24` and
   `load_flow_burst_90` with the same need thresholds as `flow_burst_24` and
   `flow_burst_90` (22 and 88).
4. `load_tcp_echo_v4` (the timed probe) and `load_udp_echo_v4`. After each
   burst and echo, a provider sample.
5. A wait for every stream, up to `LOAD_BOUND_S` + 5 s. A stream still
   running then is stopped, and its unmasked captures are removed.
6. A provider sample, then a second filter read.
7. The provider log since the load began (`load-provider.log`, the
   `aegis-ne-provider` process's lines only, within 30 s).

The rows:

- `load_download`: passes when every stream received exactly its cap
  within `LOAD_BOUND_S`. The detail gives `short=` for the others, the
  HTTP codes and (v34) `target_status=`: `2xx` when every stream's
  response had a 2xx status line, else `<i>:<code>` for each stream that
  did not (`<i>:none`: no status line, so no answer from the target at
  all, such as a tunnel or TLS failure). A refusal by the target still
  fails the row; its headers and body excerpt show why. v34 reads exactly
  `load-stream.1` .. `load-stream.<LOAD_STREAMS>`, one record each: a
  stream stopped at the deadline writes none and fails as
  `<i>:missing` (before, the leftovers of a stopped stream could be read
  as a record).
- `load_throughput`: info, Mbit/s in total and per stream.
- `load_concurrent`: passes when at least one stream was still running at
  the end of each burst and echo, so those ran under load. If the
  downloads ended first, raise `LOAD_BYTES` within the URL's declared size
  (the default serves 140064536 bytes a request). A size the server does
  not serve fails `load_download`; raise `LOAD_STREAMS` instead.
- `load_connected_throughout`: passes with no `session_lost` in the load's
  provider log and `Connected` at every sample. A loss, even in a read cut
  off at its bound, or any other status fails it. It is `unavailable`
  when the read was cut off at its bound
  (`provider_log_read=failed:rc=<rc>`), or without any provider log line.
- `load_filter_counters`: info, with the `allowed`/`dropped` deltas of the
  `filter_result` line, the filter mode at both reads, and the drop rings'
  new records and overflow (records beyond the provider's 64-slot ring,
  `leak_guard::RING_SLOTS`, compared by a test). It is `unavailable` when a
  read did not exit 0.
- `load_provider_rss` (v34, info): `pid=` (one process sampled
  throughout, or `changed`), `rss_kib_before=` (before the downloads),
  `rss_kib_max=` (the largest sample after it), `growth_kib=` and
  `samples=` (6). The acceptance reads it against the stream-window
  budget.

After the disconnect and the window's provider-log read
(`provider.log`, from before the connect), `harness/load_review.py` adds
v34's info rows. None is ever pass or fail: the window writes any other
verdict from it as `unavailable`, and a load that never ran writes them
`unavailable not_connected`. The provider-line parsers are all in its
`TELEMETRY` block, with the line formats they assume.

- `load_filter_series`: from the provider's 10 s `filter_counters` blocks
  (cumulative, while guarding), `intervals=<before>/<during>`, the
  `allow_relay` and total drop rates per second before and during the
  load, `corr_drops_vs_relay=` (Pearson, over every interval of the
  window), `torn_malformed_fragment_during=`, and the eight busiest drop
  reasons as `<reason>=<before>-><during>`. An interval that straddles the
  load's start counts only in the correlation. It machine-checks that the
  drops do not follow the load.
- `load_outbound_drops`: the outbound ring's new records across the load,
  `records=<iface>:<family>:<reason>:<tcp kind>:<n>` (for example
  `en7:v6:tcp_out:ack_only:8`), `marked_records=`, `overflow=` (beyond 64)
  and the per-class `kinds=` and `marked=` deltas.
- `load_placement`: the bulk flows (`flow_bulk`, over 1 MiB) that ended in
  the load: `bulk_flows=`, `conns=`, `per_conn=<id>:<n>`,
  `max_concurrent_per_conn=`, `overlapping_pairs=` (two bulk flows at once
  on one pooled connection), `collision_case=exercised|not_exercised`,
  `win_kib_max=` (the largest `win_kib`: the most credit the relay held on
  a stream, as its releases saw it), the load streams' own lines
  (v34 review: `load_flows=` and `load_win_kib=`, the flows that moved at
  least one stream's cap, `load_download per_stream=`, in end order;
  `unknown` without that row) and each flow's Mbit/s. A pass with one
  stream per connection says nothing about the collision case.
- `load_window`: the adaptive stream window (`pool_window`) during the
  load: `grown_max=`, `max_kib_max=`, `above_initial=yes|no` (above the
  128 KiB every stream starts with), `budget_kib_max=<used>/<total>`,
  `denied_last=` and `denied_in_load=`. `unavailable` on a build without
  the line (v33 and earlier).
- `load_latency`: the bursts' wall times and the timed TCP echo before the
  load against under it (`burst24_s=`, `burst90_s=`, `tcp_echo_ms=` as
  `<before>-><during>`), the largest `pool_detail hs_ms` p50 and p90 (a
  carrier request to the authenticated inner connect), and the
  per-connection RTT lines (`pool_rtt`) on the bulk flows' connections
  during the load: `min_ms`, `srtt_ms` and `last_ms` p50/p90,
  `rtt_samples=` (the lines with a sample), `rtt_queue_ms` (`last_ms` less
  `min_ms`) and `last_ms` before the load. `last_ms` is the connection's
  latest round-trip sample since its line before, a new stream's request
  to its 200 (timed from before its stream slot was ready) or a PONG, not
  a PING round trip; a healthy connection sends no PING, so under load the
  samples come from the bursts' streams that land on a bulk connection,
  and a line without one carries no `last_ms`. The acceptance judges its
  bound L4 only from a declared `rtt_samples` count. (Before the v34
  review: `ping_ms`, `ping_queue_ms` and `ping_ms_before_p50`.)
- `load_queue` (v35): per bulk connection during the load, from its
  `pool_queue` lines (the connection's latest bulk measurement's
  credit-loop delay `q_ms`, and its live streams' mean credit held and
  extras) and `pool_rtt` lines: `<id>:q<p50>/<p90>:held<p50>/<p90>:x<largest
  extra>:bdp<p50>/<p90>:sx<share>`, where `bdp` is the credit against the
  connection's own bandwidth-delay product, (min_ms + q_ms) / min_ms, and
  `sx` the percentage of its samples with an extra while `q_ms` stood at
  120 or more; then `load_flows=` the load streams' `flow_queue` lines
  (the flows that moved at least a stream's cap):
  `<conn>:<low>-<mid>-<high>:g<steps>:r<after_step>-<standing>`.
- `load_takes` (v35): the `pool_take` sums over the load: `lines=`, `n=`
  (new flows taken), `queued=` (taken on a queued connection), `share=`,
  and `conns_queued_max=<k>-<m>` (the most queued connections among those
  taking streams).

v35: after the provider-log read, every `LOAD=1` window and every window
with `WINDOW_POLICY` set also writes the validity row `window_policy`: it
passes only when the window's provider log holds at least one
`pool_policy` line (one per flow pool, so per session, a rebuild
included) and every one names the expected mode (v36: `adaptive` with
`WINDOW_POLICY=adaptive`, else `fixed`, the product default):
`expected=<mode> seen=<modes> lines=<n>`. A mismatch, mixed modes or no line in a connected window
fails it; a window that never connected writes it `unavailable ...
not_connected`. Other modes without `WINDOW_POLICY` are unchanged.

After an ENDURANCE=1 window's disconnect the same script
(`--endurance-log endurance-provider.log`) adds one info row (v34 review,
critic B4): `endurance_window`, the stream window's `pool_window` lines
across the whole run, `lines=`, `grown_max=`, `grown_last=`,
`max_kib_max=`, `budget_kib_max=<used>/<total>`,
`budget_kib_last=<used>/<total>` and `denied_last=`: whether long-lived
flows hold the budget. It is never pass or fail (`unavailable` without
the line, and `not_connected` for a window that never connected).

A window stopped mid-load (Ctrl-C, SIGTERM, an error) runs `el_on_exit`
on its EXIT path, right after the sleep guard stands down: it stops the
load streams still running (only this window's own subshells), waits at
most 2 s for their pipelines, and removes the unmasked
`load-target.<i>.raw` and `.first` captures and the streams' temporaries,
so none stays in OUT (v34 review). A SIGKILL runs no EXIT trap.

The window's own filter reads, rows and bursts are unchanged.

A window without either mode writes every row as before. A test runs one
with and one without `LEAK_CAPTURE=1`, and one whose two bursts sit
exactly at their thresholds, against rows generated from the pre-S24
harness. Source only: run against fake commands on a virtual clock
(`RealRelayWindowEnduranceTests`, `RealRelayWindowLoadTests`,
`RealRelayWindowWithoutS24ModesTests`, `RealRelayWindowArmedRollbackTests`,
and `EnduranceReviewTests` on made-up records; v34: `LoadReviewTests` on
synthetic provider logs and filter reads), never against this Mac. The v34
LOAD windows and their acceptance criteria, declared before any run, are in
[v34 load acceptance](../../../../docs/platforms/macos/v34-load-acceptance.md).

### The v35 A/B: socket samplers and the paired review

The [v35 load acceptance](../../../../docs/platforms/macos/v35-load-acceptance.md)
runs W1 to W3 and a paired A/B of the v35 window (T) against the fixed
window (C) in one installed build, in the order of
[v35-ab-plan.json](../../../../docs/platforms/macos/v35-ab-plan.json).
The window wrapper (outside the repository) takes every name from
`ab_review.py next` and keeps each receipt as `<name>/` (the window's OUT)
and `<name>.side/` (its `run.txt` and the side samples). These pieces are
source only here: their tests run against fakes and synthetic receipts
(`tests/test_v35_harness.py`).

- `relay_ss_loop.sh` (runs on the relay, read only). The leak guard drops
  the Mac's SSH to the relay during a window, so the sampler starts while
  the tunnel is Disconnected and runs detached for a bounded time:
  `remote-start NAME N BOUND` prints the one SSH command line that runs the
  loop inline (no script file is copied: `umask 077`, `setsid nohup timeout
  BOUND bash -c <loop>`) and refuses (exit 4) while an `aegis-ss` file or
  process is left over. The loop (`run N`) writes N samples, once a
  second, a `T <epoch>` line and `ss -tinH state established "( sport =
  :443 )"`, with every IPv4 literal masked to `a.b.x.x`, every bracketed
  IPv6 literal to `[v6.x]` and every bare one (two colons or more between
  hex groups, as `ip tcp_metrics show` prints the peer and the relay's own
  `source`) to `v6.x` inside the pipeline. It runs ss, date, sleep and sed
  only. `remote-fetch` prints the file; `mask` masks it again locally and
  refuses (exit 3) to keep it if a full IPv4 literal or any `hex:hex:hex`
  sequence remains;
  `remote-clean` removes it and fails unless neither the file nor an
  `aegis-ss` process remains. `remote-metrics` prints `ip tcp_metrics show`
  and `net.ipv4.tcp_no_metrics_save`, read only and masked, for the
  relay-snap before each window (nothing is flushed). Its samples are
  optional: without them a window and its pair stay valid.
- `mac_sockq_loop.sh N RELAY_IPV4` (the Mac, no sudo): N samples, once a
  second, of the `netstat -an -p tcp` lines of the ESTABLISHED sockets to
  the relay's :443, masked: Recv-Q and Send-Q, whether data waits unread in
  the provider's own sockets.
- `relay_ss_review.py relay|mac|attribute`: per-socket cwnd, ssthresh,
  rtt, bytes, segments, retransmissions, notsent and the limited times;
  loss events (cwnd cuts of 20% or more between samples) per segment;
  notsent and rtt p50/p90; the rwnd-limited share; the Mac's Recv-Q and
  Send-Q; and the W2 label (`attribute --relay F --mac F [--provider-log
  F]`: when the slowest bulk relay socket's notsent p50 is at least 64
  KiB, `path_bound` only if the provider log shows the slowest bulk flow's
  connection never held extra credit, else `credit_or_path`; `path_bound`
  also when every Mac relay socket's Recv-Q p90 is under 16 KiB with that
  relay socket rwnd-limited under 10% of its busy time; else
  `unattributed`). Any unmasked IPv4 or IPv6 literal in a sample file
  exits 3 before anything is printed.
- `ab_review.py check-plan|next|analyze` (system python 3.9, stdlib, the t
  quantiles embedded): the plan is exactly the declared one, every number
  pinned (`analyze` prints its SHA-256); the next declared step (or
  `refuse:<reason>`: the identity's `renew_at` margin, a stopped or complete
  series), with a pair's second window offered only while it can still
  start after the idle within the gap, and the declared W2 retry after the
  coda; and per window S (the sum of `bytes_i / elapsed_i`, a stream short
  of its 52428800 bytes or past 180 s counting `bytes_i / 180`), A (all
  bytes over the makespan, 180 s once a stream is incomplete), both at
  least 1 KiB/s, the S24b verdict and the latency rows; each pair's
  validity (only the plan's external or procedural reasons); and the
  declared looks: the interim once on the first 8 valid pairs, the final
  once at the series' end (every pair valid or missing, or the operator's
  `series-end.txt` with `reason=deadline|host_not_free|operator_stop`)
  with at least 12; per look `ln(S_T / S_C)` and `ln(A_T / A_C)` with
  their t-based CIs, the latency rows the same way, the exact one-sided
  sign test of S24b on the discordant pairs, and the declared verdict
  (GAIN, NON_INFERIOR, REGRESSION, CONTINUE, NO_RESOLVABLE_DIFFERENCE,
  NO_CLAIM, or STOPPED with `stop_reason` when a window's arm label or the
  control mechanism cannot be trusted: a `window_policy` failure or a
  missing row on a connected window, another arm's expected mode, a start
  refused for its window-policy option, a control window that never
  connected). It also reports the floored windows, W1's fallback growth
  evidence and the renewal strata.
- `ab_oc.py [--trials N] [--seed S]`: the declared rule's operating
  characteristics, by simulating whole series through `ab_review.py`'s own
  decision under a stated (modelled) noise model, and the exact null
  rates of the S24b sign test.

### No address in the rows or the log (v34, S24 review F)

Until v33 `whoami_egress` (and the `netloss_`, `sleep_` and `ifswitch_`
copies) wrote the raw whoami body, which names the relay's address, and
`window.log` named the relay on its first line. From v34 every check
computes its verdict from the raw value first, and only then:

- every row's detail (`result`) and every line the window logs (`say`)
  passes through `harness/addr_mask.py`: the relay's address (the
  handoff's `relay`, and `relay_ipv6`) becomes `relay_addr`, any other
  IPv4 or IPv6 literal its class (`ip4_global`, `ip4_private`,
  `ip6_global`, `ip6_ula`, `ip6_link_local`, `ip6_mapped`, ...), a cut-off
  IPv6 literal or a MAC address `ip6_fragment`. Only the tunnel's own
  fixed addresses stay (198.18.0.0/15: 198.19.255.1, its resolver
  198.19.255.2 and the fake-IP pool; fd00:ae61::/32), since every install
  uses the same ones. Text with nothing address-like is written as it is,
  without python; if the masker fails, every candidate is masked (fail
  closed). So `whoami_egress pass ip=relay_addr`, `dns_aaaa_via_relay pass
  ip6_global`, and the first log line reads `relay=relay_addr:443`.
- the whoami rows pass only when the raw body's first 80 bytes (as before)
  name the relay's address as a whole literal (`egress_is_relay`: not
  inside a longer one, so `203.0.113.70` is not `203.0.113.7`; an
  IPv4-mapped form counts; brackets and case ignored). Before, the main
  row matched a regular expression (any character for each dot, and an
  IPv6 relay's brackets as a character class), and the copies a
  substring. The endurance cycles' whoami uses the same rule. The detail
  is the masked body, cut to 80 bytes after masking, so no partial
  address is left at the cut. `whoami6_egress` still scans the whole body
  for the Mac's prefixes first; since the v34 review it then judges the
  first 80 bytes by the same whole-literal rule against `relay_ipv6`
  (before: a case-insensitive substring, so a longer IPv6 address that
  merely contained the relay's passed). Its passing body is masked the
  same way.

`RealRelayWindowMaskTests` runs a window and a load window whose target
refuses with a body naming the relay, and finds no IPv4 or IPv6 literal
but the tunnel's own in `results.tsv`, `window.log` or the load's excerpts;
an egress other than the relay still fails. `AddrMaskTests` checks each
class.

## Installed uninstall/reinstall cycle (B-06 S21i)

```sh
OUT=<new dir> ZIP=<abs stapled zip> ZIP_SHA256=<hex> IDENTITY_SRC=<abs 0700 dir> \
    INSTALL_RECEIPT=<abs run receipt of the ZIP> [RELAY_IP=<ip>] [APP=/Applications/AEGIS.app] \
    harness/uninstall-reinstall-window.sh
```

It refuses (exit 3; 4 for `timing-peer`) and runs nothing further while any
`~/.aegis-local/locks/timing-*` lock exists, an AEGIS service in
`scutil --nc list` or a saved profile's service is not Disconnected, an
interface holds 198.19.255.1 or fd00:ae61::1, or the default route is on a
utun; and unless the stapled ZIP matches `ZIP_SHA256`, `IDENTITY_SRC` is a
0700 directory of the user and the relay IP (`RELAY_IP` or the handoff's
`relay`) is numeric. Everything `install-app.sh` would only refuse after
the uninstall is checked first: the ZIP's `AEGIS.app` CFBundleVersion
equals the installed app's, `INSTALL_RECEIPT` is the absolute receipt of
this ZIP (`stapled_zip_sha256`, current `ok` staple and assess stages, the
same `bundle_version`) and no `.AEGIS.app.incoming-<version>` is left. An
installed app must answer `host --ping` with `identity_present=true` below
an admitted container; otherwise only an `uninstall-app.sh` resume marker
of its version (a reachable or unavailable provider) or a pending
reinstall of this ZIP (below) lets it run, because `uninstall-app.sh`
would remove the profile and then stop at a forget it cannot verify.
Nothing is uninstalled that could not be put back. It then holds
`timing-self` (with its token) for the cycle.

Rows in `$OUT/results.tsv` (name, verdict, detail, UTC): the baseline (app
version, `systemextensionsctl list` state, `--list`, `--ping`,
`baseline_filter` from `--filter-status`, default routes and resolver), then `packaging/uninstall-app.sh` for real with its
receipts under `$OUT/packaging-artifacts`, and `app_moved` (absent from the
destination, present under `<state>/uninstalled/` with the same version),
`profile_gone`, `identity_absent` (from the receipt's verified ping),
`extension_deactivated` (a `systemextensionsctl list` that exited 0 with
its `N extension(s)` header and no `[activated ...]` line of the provider;
an unreadable listing fails), `no_tunnel_left` and `network_baseline`. A
failed check stops before the reinstall. Once they pass,
`<state>/uninstall-reinstall-window/reinstall.txt` records a pending
reinstall of this ZIP (`phase=completed` after a pass). Then
`packaging/install-app.sh --replace --activate --receipt` with the same
ZIP, `reinstalled_version` (the ZIP's version), `extension_activated`,
`host --import IDENTITY_SRC` (150 s bound: the owner approves the system
administrator prompt the host shows first; the harness never answers it)
(never `--remove-source`; `identity_source_kept` compares an in-memory
manifest of the source, never written), `host --save-profile ...
--replace-existing`, `intent_valid`, `identity_present`, `filter_restored`
and `network_after_reinstall`, and `outcome`.

v26 review: `uninstall-app.sh` removes the S20b leak-guard filter, so the
cycle puts back the one the owner had. A filter that was configured and
enabled at the baseline (`--filter-status` exit 0, 33 or 69) is recorded in
`<state>/uninstall-reinstall-window/filter.txt` (`phase=restore-pending`)
before the uninstall. A re-run after an interrupted cycle, when the filter
is already gone, then restores it as well (`source=earlier-run`). After the
profile, `host --enable-filter` runs within 150 s (`filter_enable`; the
owner clicks **Allow** if macOS asks), and `--filter-status` must exit 0
(`filter_restored`). Without that the outcome fails. A filter that was not
enabled at the baseline gives an info `filter_restored` row and is not
enabled. A pass with the filter says "identity, profile and leak-guard
filter restored" and marks `filter.txt` `phase=restored`. `app_moved` also
accepts a v25 copy whose host `uninstall-app.sh` replaced with
`aegis-ne-host.removed`.

Exit 0 pass, 1 a failed check, 2 an existing `OUT`, 3 refused, 4 Codex
lock, 7 the deactivation completes after a reboot (reboot, then run it
again with a new `OUT`), 8 the activation awaits an approval in System
Settings or a reboot (`install` row `pending`; approve or reboot, then run
it again with a new `OUT`). A re-run is safe at any point: an app already
moved aside is reported as `already-absent` and the cycle continues with
the reinstall. With the app of this ZIP installed and a pending reinstall
recorded, a re-run (`mode=resume`) never uninstalls again: it runs
`install-app.sh --activate-installed --receipt` only while the provider is
unavailable, then the import, the profile and every reinstall check.
Nothing is deleted: the app is moved aside by
uninstall-app.sh and the identity source is kept. Source only: run against
fake packaging scripts and a fake host.
