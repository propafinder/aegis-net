# macOS: operating the tunnel

How the installed Packet Tunnel provider behaves while connected, what its
log looks like when it works, and how certificate renewal runs. Commands use
`H=/Applications/AEGIS.app/Contents/MacOS/aegis-ne-host` and
`P=dev.aegis.macos.PacketTunnel` as in [install and enable](install-and-enable.md).

## How a session works

On `--connect`, macOS starts the provider and installs drop-all routing
while it is Connecting. The provider then:

1. pins the relay socket to the current physical interface
   (`relay_interface name:en0`), so its own traffic never enters the tunnel;
2. opens an outer TLS and HTTP/2 connection to the relay, an inner device
   mTLS channel, and asks for a **PolicyAck**: a short lease, at most 3 s,
   that says the relay still authorizes this certificate;
3. applies the tunnel settings only once that lease is held: IPv4
   `198.19.255.1`, IPv6 `fd00:ae61::1/120`, both default routes into the
   utun, DNS anchors `198.19.255.2` and `fd00:ae61::2`, `includeAllNetworks`
   with no exclusions; then reports `start tunnel_running`;
4. renews the lease continuously (re-ACK), with up to two requests in
   flight over one persistent ACK connection (`ack_conn`);
5. carries each TCP flow or UDP association as a stream on a small pool of
   outer H2 connections (at most 4 connections; inner handshakes limited per
   connection).

If the lease lapses or the relay path fails after Running, the tunnel is
**not** cancelled: settings stay applied, macOS shows *reasserting*, packets
are dropped (not sent outside the tunnel) and a fresh session is built with
jittered backoff from 0.5 s to 8 s. Only an explicit stop or a terminal
custody failure (identity gone or tampered, pinned peer or binding
mismatch) cancels the tunnel; that is logged as `session_failed <code>`.

## Reading the provider log

The provider writes one stable line per event to the unified log, prefixed
`aegis-ne`. Lines carry codes, counts, durations and interface names only;
never an address, path or key material.

```sh
log stream --style compact --predicate 'eventMessage BEGINSWITH "aegis-ne"'
log show --last 10m --style compact --predicate 'eventMessage BEGINSWITH "aegis-ne"'
```

### A normal start

```text
aegis-ne relay_interface name:en0
aegis-ne ack_conn dialed
aegis-ne ack_valid_ms ms:2950
aegis-ne ack_exchange_ms ms:420
aegis-ne start tunnel_running
aegis-ne reack_valid_ms ms:2870
aegis-ne reack_ok link_ms:180
aegis-ne pool_streams cap:62
aegis-ne flow_open ok ms:le500
```

The values and the exact interleaving are illustrative. `ack_valid_ms` is the first lease granted;
grants of 2.0-3.0 s are normal (the relay grants 3 s less the age of its
own policy refresh).

### Event reference

| Event | Normal | Look closer when |
| --- | --- | --- |
| `relay_interface name:<if>` | Once per session: the physical interface the relay sockets are bound to. | It names a `utun`. |
| `ack_valid_ms ms:N`, `ack_exchange_ms ms:N` | First lease and its round trip. | Grants well under 2 s. |
| `start tunnel_running` | Settings applied; the tunnel is up. | Missing after a `--connect`: look for `start_refused <code>` or `session_failed <code>`. |
| `reack_valid_ms ms:N` | Every renewal's granted lease. | Long gaps between lines. |
| `reack_ok <via>_ms:N` | Bare PolicyAck round trip, `via` is `link` (ACK connection stream), `prewarm` or `fresh`. Logged for the first five renewals, then every twentieth. | Round trips above about 1 s: the lease is at risk. |
| `reack lease_budget_elapsed` | Never in a healthy session. | It precedes `session_lost capture_lease_expired`. Other `reack` codes: `forced` (after wake), `establish_queue_timeout`, `validity_below_margin`. |
| `reack_inflight n:N`, `reack_lead ms:N` | Rate-limited diagnostics of the re-ACK pipeline. | - |
| `ack_conn dialed` / `lost` / `goaway` / `drained` / `fallback` / `closed` / `revived` | One `dialed` per session. A `lost` at the moment a session ends is its teardown, not a fault. | `fallback` (a request went to a separate dial because the link looked quiet) or `goaway` in mid-session. Each code is logged at most once per 5 s; the repeats held back in between are counted as `held:N` on its next line. |
| `pool_streams cap:N` | Streams per pool connection, from the relay's HTTP/2 SETTINGS. | - |
| `pool_state conns:<open>-<probing>-<draining> streams:N waiting:N`, `pool_detail oldest_ms:N sndq_kib:N hs_ms:<p50>-<p90>` | Only while flows wait for a stream, at most once per second. | `waiting` stays high, or `hs_ms` p90 approaches 2.5 s. |
| `pool_window grown:N max_kib:K budget_kib:<used>-<total> denied:N` (v34) | The adaptive stream window: streams whose window is above the 128 KiB every stream starts with now, the largest window granted since the line before, the budget held of the session's 7168 KiB (grown windows, and windows given back whose bytes the stream may still hold: the relay's unused credit and what h2 holds unread), and growth steps the budget refused in the session. At most once a second, while a pooled connection carries a bulk flow (one stream at 128 KiB/s or more) or the budget is in use. | `denied` climbing while bulk downloads run: the budget is held by streams that no longer use it. |
| `flow_bulk conn:<id> kib:N ms:N win_kib:N` (v34) | One per flow of 1 MiB or more, at its end: its pooled connection, its stream's bytes (the download and the inner TLS around it, about 0.4% more), the time from its 200 to its end, and the most credit the relay held on its stream as its releases saw it (`win_kib`, a lower bound of the true peak; a stream granted 1 MiB logs about 690 KiB; before the v34 review it was the largest window granted, which `pool_window max_kib` still reports). | Two bulk flows on one `conn` at once: they share that connection's rate. |
| `pool_rtt conn:<id> min_ms:N srtt_ms:N last_ms:N` (v34) | Per pooled connection, at most once a second while it carries a bulk flow: the least RTT it measured (its outer TLS handshake, each carrier request to its 200, each PING to its PONG: the RTT the window grows on), its smoothed RTT (the liveness timers'), and `last_ms`, the latest of those samples since the line before; `last_ms` is left out when it took none. It is not a PING round trip: a healthy connection sends no PING, so under load `last_ms` comes from new streams' 200s on it, timed from before their stream slot was ready. Named `ping_ms` before the v34 review. | `last_ms` far above `min_ms` on a bulk connection: data queues ahead of new streams on the relay. |
| `pool_queue conn:<id> q_ms:N held_kib:N extra_kib:N` (v35) | With each `pool_rtt` line: the connection's latest bulk measurement's credit-loop delay (the credit its stream held over what it released, less the least RTT; `q_ms:none` before one), and its live streams' mean credit held and extras. A window grows only while `q_ms` stays at most min(60, RTT/3) ms, and returns to 128 KiB at 120 or more. | `q_ms` at 120 or more for long: data queues at the relay ahead of new streams on that connection; new flows avoid it while another has a slot. |
| `flow_queue conn:<id> q_bins:<lo>-<mid>-<hi> grows:N resets:<a>-<b>` (v35) | Beside each `flow_bulk` line: the flow's measurements by delay zone, its growth steps, and its returns to 128 KiB (right after a kept step, and the others). | Many resets: the path's queue keeps returning the window. |
| `pool_take n:N queued:N conns_queued:<k>-<m>` (v35) | With `pool_state` while flows wait: new flows taken since the line before, those taken on a queued connection, and the queued connections among the `m` taking streams. | `queued` close to `n`: every connection was queued. |
| `pool_policy mode:<adaptive\|fixed>` (v35) | Once per flow pool, so once per session: the stream-window mode of this tunnel start. From build 36 `fixed` is the default (a bare `--connect`, on-demand and System Settings starts); `adaptive` only after `aegis-ne-host --connect ... --window-policy adaptive` (the QA arm; never saved). On build 35 the default was `adaptive` and `fixed` needed `--window-policy fixed`. | `adaptive` on build 36 or later without that flag. `adaptive` outside a declared A/B `-t` window: the flag was used by hand (any start carrying the option selects that window for that start). |
| `pool_conn_lost <why>`, `pool_goaway reason:N`, `pool_stall ping|close`, `pool_fallback streams:1`, `pool_capacity h_conn:1`, `pool_strike count:N` | Rare. | Repeated: the relay or path is struggling; `pool_strike` counts authentication-class failures. |
| `flow_open <outcome> ms:<bucket>` | Every flow in the first 5 s after Running, then a sample and any slow one. `<outcome>` is `ok`, `closed`, `dropped`, or for a refused flow its refusal class (one of the `flow_refused` classes below, for example `flow_open pool_wait ms:le5000`). Buckets `le100` to `le5000`, `gt5000`. | Many `dropped`: flows ended with their session (lease loss). Refusal classes here follow the `flow_refused` row. |
| `flow_refused class:<c> n:K` | Occasional `pool_wait` or `hs_bound` during the post-connect burst. Classes: `pool_wait`, `permit_wait`, `dial_failed`, `hs_bound`, `hs_inner`, `hs_refused`, `carrier_reset`, `status_budget`, `status_refused`, `live_cap`, `conn_lost`, `auth`, `unanswered`, `other`. | `auth`, `live_cap`, `unanswered`, or sustained counts. |
| `engine_flow_open class:<c> n:K wall:T` (v28) | A flow the tunnel's engine answered (its SYN-ACK), by the class of the port the app connected to: `discard` (port 9, every flow, the first 64 per engine), `dns`, `web` (80, 443, 8080), `low`, `high` (each at most once a second). `n` counts that class's answered flows so far, `wall` is the time of the line. No address or port. | `class:discard` lines during a positive control window: its fresh bound probes were routed into the tunnel (`tunnel_enforced`). |
| `establish_queue depth:N`, `flow_live_bound cap:N`, `flow_idle_reap total:N` | Load diagnostics; idle TCP flows are reaped after 62 s. | Queue depth staying above a few dozen. |
| `session_lost <code>`, `reasserting on` | A recoverable loss (most often `capture_lease_expired`). | More than a few per minute. |
| `session_rebuilt attempt:N`, `reasserting off` | The replacement session is Ready. | `session_rebuild_refused <code>` repeating. |
| `session_failed <code>` | Never during normal use. | Terminal: the tunnel is cancelled. See [troubleshooting](troubleshooting.md). |
| `path_change name:<if>` / `path_change unsatisfied` | Physical network change, debounced 500 ms. | - |
| `relay_interface_repinned name:<if>` | The relay sockets moved to a new physical interface; the session rebuilds (`session_lost relay_path_changed`). The pinned interface was lost, or (v33) another interface became the primary while the pin was the primary: plugging in a cable from Wi-Fi re-pins to it at the path change. | `relay_interface_repin_refused <code>`, `relay_interface_lost errno:N`; v32 and earlier after a plug: `session_lost capture_lease_expired` about 1.5 s after `path_change`, then a rebuild on the old interface. |
| `sleep count:N`, `wake <reack|rebuild|reasserting|idle>` | Sleep completes at once; wake forces one re-ACK or a rebuild. | - |
| `identity_renewal state:<s> attempt:N [next_s:N]` | See [certificate renewal](#certificate-renewal). | `state:failed:<class>` repeating, `state:expired`; v31: `state:deferred:guarded` with a small `remaining_s` (connect again before it runs out). |
| `leak_guard armed gen:N relay:<v4\|v6> renewal:<route>` (v31; `authority:<family>` before) | The filter arms for the epoch; `renewal:deferred` (the authority is another tuple: renewal waits for the next Connect), `via_relay` (the authority is the relay tuple) or `none`. | `relay:none`. |
| `stop_budget_exhausted provider_exit_70` | Not expected since v22 (the v21 stop deadlock was fixed). | The provider could not stop within its budget and exited. |

`flow_open dropped` after a `session_lost` and an `ack_conn lost` at the
same instant are expected teardown. Judge a window by `session_lost` count,
rebuild success and the traffic checks, not by single lines.

## Status checks while connected

- `scutil --nc status <scutil_service_id>`: `Connected`, or `Connecting`
  while the provider reasserts during a rebuild (`scutil` never prints
  `Reasserting`).
- `$H --status`: `session_phase=ready` while traffic flows.
- `route -n get default` names the utun; `scutil --dns` lists
  `198.19.255.2` and `fd00:ae61::2`.
- `$H --list`: `native_vpn_status=3` (connected).

## Stream window policy (v36)

Every tunnel start uses one stream-window policy for its pooled streams,
chosen per start and never saved. From build 36 the default is v33's
fixed 128 KiB window: a bare `$H --connect $P <owner_generation> <relay>`,
an on-demand start and a System Settings start all use it, and the
provider log shows `pool_policy mode:fixed` once per session. The v35
adaptive window is a QA arm only:

```sh
$H --connect $P <owner_generation> <relay> --window-policy adaptive
```

starts that one tunnel with it (`pool_policy mode:adaptive`);
`--window-policy fixed` is accepted and equals the default. The flag
belongs to `--connect` only and takes exactly these two values; anything
else is `unknown_command` before any start, and a start option
`aegis_window_policy` with another value or type refuses the start
(`start_refused window_policy_refused`). The window harness passes it as
`WINDOW_POLICY=adaptive|fixed` and checks the mode in its `window_policy`
row. Why the default changed: [v36 load acceptance](v36-load-acceptance.md).

## Certificate renewal

The device certificate is renewed by the provider itself, with the same
key. Nothing on the host side needs to be scheduled.

- **When.** A renewal falls due at two thirds of the certificate lifetime
  (`renew_at` in `--cert-status`), plus a 60 s clock-skew margin. The check
  runs every 5 s.
- **Where (v31).** At a `--connect`, before the leak-guard filter arms and
  before any tunnel settings exist, the provider contacts the profile's
  enrollment authority over the physical interface, at most three connect
  attempts within 20 s, and installs the new certificate on success. While
  the tunnel is connected the filter is armed and the provider dials no
  tuple other than the relay's, so a renewal that falls due then is
  **deferred** to the next Connect: no dial, no teardown, the old
  certificate keeps carrying traffic, `--cert-status` shows
  `deferred:guarded`, and `$H --status` and `$H --ping` print a
  `renewal deferred:guarded ...` line on stderr. Disconnect and connect
  again before the expiry that line names. Only an authority on the relay's
  own tuple (not yet deployed) renews while connected: the running session
  is then sealed with `identity_renewal_due` (packets drop briefly, nothing
  leaks), but only once it has been up for 30 s, and never again after a
  transport failure without a journal.
- **On failure** (`connect_timeout`, `unavailable`, `timeout`,
  `rejected`, `recovery_required`, `local_refused`,
  `interface_unresolved`): the old certificate keeps carrying traffic and
  the next attempt is 60 s later, doubling up to 15 min, never at or after
  `not_after`. The provider keeps this backoff between Connects (until its
  process restarts), so a Connect within it makes no attempt, and after an
  attempt whose every connect timed out the next makes one connect, not
  three. `$H --status` and `$H --ping` print `renewal failing (<class>)
  since <UTC>, expires at <UTC>, N attempts` on stderr. `connect_timeout`
  means the authority never answered the TCP connect (reachability);
  `timeout` that it was reached and then timed out. If a request was
  already written to the journal and is unanswered, sessions stay blocked
  (`identity_renewal_pending`) until it is resolved, because a capture
  beside a pending journal is not allowed; (v31 review) a Connect then
  tries the receipt recovery at once, whatever the backoff. In the last
  hour before `not_after` a session the provider holds after a transport
  failure (`held:transport`) is sealed for an attempt again, paced by the
  backoff.
- **Expired while connected.** If `not_after` passes during a running
  session, the rebuild is refused with `session_identity_expired` and the
  tunnel stays blocked (reasserting, every packet dropped, nothing sent
  outside). `$H --cert-status` reports `expired`. While it is blocked the
  Mac has no network at all, enrollment included, so an online `redeem`
  from this Mac cannot reach the authority.
- **Expired at connect.** If the certificate ran out while the tunnel was
  down (after a disconnect, sleep or reboot), a `--connect` is refused: the
  log shows `identity_renewal state:expired` and
  `start_refused session_identity_expired`, macOS shows Disconnected, and
  the tunnel does not start. `$H --renew` answers `no_epoch`;
  `$H --cert-status` the provider's last record (`expired`, v31; `no_epoch`
  before v31 or after the provider process restarted); `$H --status`
  reports `session_refusal` `session_identity_expired`.
- **Recovery, both cases.** An expired certificate cannot be renewed. In
  this order: (1) disconnect (`$H --disconnect`, escalating to
  `scutil --nc stop` and `$H --emergency-stop`, see
  [disconnect and stop](#disconnect-and-stop)) and confirm
  `scutil --nc status` shows Disconnected; (2) get a new Enroll invitation
  and enroll a new identity online with `aegis-client device redeem`;
  (3) `$H --import` it; (4) `$H --connect` again. A clock that was wrong
  and is corrected back before `not_after` also lifts a running block.

- **Superseded (v32).** If the authority issued a successor the provider
  refuses (for example one that ends before the installed certificate,
  as on 27 October), the provider never installs it and never parks the
  request: the start is refused with `identity_renewal_pending`,
  `--cert-status` shows `superseded` and `check` names the refusing check,
  and `$H --status` prints `renewal superseded (<check>) since <UTC>: ...
  import a new identity`. Later Connects ask only for that receipt, after
  the backoff. The relay no longer admits the installed certificate:
  import a new identity (no Disconnect needed, the tunnel is not up).
- **Parked (v32).** If the authority only rejected the request (Rejected
  or RecoveryRequired), the provider parks it and connects with the
  installed certificate: `--cert-status` `parked`, `$H --status` prints
  `renewal parked after <class> since <UTC>: ...; it retries at the next
  Connect after <UTC>`. To import a new identity while parked, disconnect
  first (`session_live` otherwise). v32 review: only a request every
  request of which this provider process saw answered is parked.
- **Pending after a rejection (v32 review).** A request the provider found
  journaled when it started (a v31 leftover, or after a reinstall or
  reboot), or one whose earlier answer was lost, is never parked when the
  authority rejects it, because the authority may already have issued for
  it: `--cert-status` `pending` with `last_failure` `rejected`, every
  `--connect` refused with `identity_renewal_pending`, and the next attempt
  only after the backoff (`next_attempt_at`). Ask the relay owner whether a
  successor was issued; otherwise import a new identity (no Disconnect
  needed, the start is refused).
- **Precondition until v32b.** Ask the relay owner for the authority's
  `lifetime_secs` L before issuing an identity: its device lifetime must be
  at most 3L (259200 s at L = 86400 s), else its first renewal is
  superseded.
- **macos-test-3 (replacing macos-test-2).** `$H --import` the new identity
  (new device id and CA) without connecting macos-test-2 on v32 first. Its
  v31 request is never parked, so a Connect cannot present it to the
  relay, but it cannot connect either: while the authority still replays
  the receipt it is `superseded` (with its check), and from the earliest of
  the successor's expiry (about 2026-10-28T06:20:41Z at L = 24 h), an
  authority CA, profile or registry change and a revocation it is `pending`
  after a rejection. Superseded and pending refuse the start, so no
  Disconnect is needed, and the import clears every renewal journal
  state. Then `$H --connect`.

`$H --cert-status` states: `unknown`, `valid`, `due`, `in_progress`,
`pending`, `renewed_pending_ack`, `not_yet_valid`, `expired`,
`failed:<class>`, (v31) `deferred:guarded`, or (v32) `parked` and
`superseded`; v31 adds `failing_since` while a failure is recorded, and
v32 `check` beside `last_failure` `local_refused` (v32 review: or beside
another class while the request stays journaled, `pending`, `superseded`
or `expired`: the receipt check of a superseded request after a later
failure, or a refused park after a rejection). Times are Unix seconds. `$H --renew` forces a
due renewal now; it refuses `renewal_not_due` before `renew_at`, and while
connected (v31) it is deferred like any due renewal. `--renew` answers
`no_epoch` when no tunnel session exists; `--cert-status` then reports the
provider's last record of the identity (v31), else `no_epoch`. While a
request is `pending` (journaled, its answer not yet received), each
`--connect` tries its receipt recovery first (v31 review) and is refused
with `identity_renewal_pending` only when that fails, so connecting again
is how to retry it. v32 review: not after the authority answered the
last attempt Rejected or RecoveryRequired; a `--connect` before
`next_attempt_at` is then refused with no attempt.

Log lines have the form `identity_renewal state:<s> attempt:N [next_s:N]`
(v31: plus `connects:N` on `start`, `dials:N` on `failed:` and `issued`,
`remaining_s:N` on a deferral) with `<s>` one of `due`, `start`, `issued`,
`pending`, `not_due`, `failed:<class>`, `expired`, `stopped`,
`skipped:auth_backoff`, (v31) `deferred:guarded`, `held:transport` or
`held:young`, or (v32) `refused` and `superseded` (each `attempt:N
check:<code>`, right after the unchanged `failed:` line), `parked`
(`check:<class>`), `waiting:parked` and `held:parked`.

Automatic renewal is tested against a loopback enrollment authority. It has
not yet been observed on the installed provider ([known limits](known-limits.md#not-yet-proven-on-the-installed-client)).

## Endurance and load windows (S24)

Two unattended modes of the real-relay window
(`tools/macos/aegis-network-extension/harness/real-relay-window.sh`). They
need no sudo and no owner hands. The window takes
`~/.aegis-local/locks/timing-self` for its whole life. Its line names the
mode and an `ends_by=<UTC>`. The window refuses (exit 4) while
`~/.aegis-local/locks/timing-peer` exists, and (exit 3) while a detached
tunnel rollback of an earlier window is still armed. A detached rollback
stops the tunnel if the window dies. Each mode prints `rollback_s` and
`window_bound_s` before it connects. If you run the window under an outer
time bound (a background runner), give it at least `window_bound_s`.
Details and every row are in the
[harness README](../../../tools/macos/aegis-network-extension/harness/README.md#endurance-and-heavy-inbound-load-b-06-s24).

**Endurance (S24a).** The default run is two hours with one cycle a minute:

```sh
OUT=<new private dir> ENDURANCE=1 [ENDURANCE_S=7200] [ENDURANCE_PERIOD_S=60] \
    tools/macos/aegis-network-extension/harness/real-relay-window.sh
```

Before you start:

- `$H --cert-status` must show a `not_after` at least `ENDURANCE_S` + 30
  min ahead. Right after a provider restart it answers `no_epoch`; run one
  ordinary window first.
- The relay handoff's `expires_utc` must be at least `ENDURANCE_S` + 15 min
  ahead.
- At least 31 GiB must be free on the volume holding `OUT`.
- `ENDURANCE=1` runs alone: not with `LEAK_CAPTURE`, `LOAD`, `NETLOSS`,
  `SLEEP`, `IFSWITCH` or a control.
- Keep the default 60 s period for gate evidence. Below 21 s the probes'
  bounds are cut under the baseline rows' own (`probe_bound_s` in
  `endurance_preflight`).

The window keeps the Mac out of idle sleep (`caffeinate -i -w`). Closing
the lid still sleeps it; those cycles are then recorded as missed.

While it runs, the window log prints one `endurance: cycle k/N` line per
cycle, and `endurance.tsv` grows by one row per cycle. The verdicts are
`endurance_cycles` (at least 99% of the cycles pass every probe),
`endurance_longest_gap` (no two failing cycles in a row, and no more than
two periods and 5 s between two passing ones), `endurance_connected_throughout`
(`Connected`, or `Connecting` during a reassert), `endurance_provider_stable`
(one provider pid), `endurance_rss_growth` (at most 64 MiB after the first
10 minutes; from the first cycle in a run too short for that),
`endurance_rebuilds` (every loss recoverable and rebuilt before the next
cycle's probes, also after the last cycle) and `endurance_real_time` (the
cycles span the run in real time). `endurance_renewal` shows any renewal
deferral.

If the window dies mid-run (killed, its terminal closed), its detached
rollback stays armed for up to `rollback_s` (about two hours) and stops
whatever tunnel is up when it fires. It ignores INT, TERM, HUP and QUIT.
To end it by hand:

1. `scutil --nc stop <service id>` (then `$H --emergency-stop`) until
   `scutil --nc status <service id>` shows Disconnected.
2. Take the pid from the `armed pid=<pid>` line of `OUT/rollback.log`,
   check that `ps -o args= -p <pid>` names `OUT/rollback.cancel`, and run
   `kill -KILL <pid>`.
3. Only then remove `~/.aegis-local/locks/timing-self`.

Do the same after a `disconnect_verified fail` row ("rollback stays
armed") once the tunnel is verified down.

**Heavy inbound load with the filter on (S24b).** By default the window
downloads 200 MiB in 4 streams through the tunnel while it repeats its
flow bursts and echoes:

```sh
OUT=<new private dir> LOAD=1 [LOAD_STREAMS=4] [LOAD_BYTES=209715200] [LOAD_BOUND_S=180] \
    [LOAD_URL=<a URL that serves at least LOAD_BYTES / LOAD_STREAMS bytes> [LOAD_URL_BYTES=<its size>]] \
    tools/macos/aegis-network-extension/harness/real-relay-window.sh
```

Without `LOAD_URL` (v34) each stream downloads the immutable kernel
tarball `https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz`
(140064536 bytes) up to its cap, 50 MiB at the defaults; a cap above the
file's size is refused. Until v33 the default was the speed-test host
`https://speed.cloudflare.com/__down?bytes=<cap>`, which refused one of
v33's four identical requests (HTTP 403); give it as `LOAD_URL` to use it.
A given `LOAD_URL` whose `bytes=`, or whose `LOAD_URL_BYTES`, is below the
cap is refused. The gate is unchanged: 4 streams of exactly 50 MiB within
180 s, no redirects followed, the filter on. Run `LOAD_STREAMS=8` only as
an extra info window: it halves each connection's share and hides where
the streams land.

A stream the target refuses (a status other than 2xx) still fails
`load_download`, with `target_status=<stream>:<code>`; its status line and
a few headers are in `OUT/load-target.<stream>.head` and the first 64
printable bytes of its body in `OUT/load-target.<stream>.body`, both with
any address masked. `load_provider_rss` and, after the disconnect,
`load_filter_series`, `load_outbound_drops`, `load_placement`,
`load_window` and `load_latency` are info rows only (v34). The v34
acceptance windows and their criteria are in
[v34 load acceptance](v34-load-acceptance.md).

The leak-guard filter must be configured, enabled and attached first
(`$H --filter-status` exit 0). `LOAD=1` runs alone, except that it may run
with `LEAK_CAPTURE=1`. With the capture it needs the owner's `sudo -v` in
the same terminal, and it refuses unless the free space less
`LOAD_BYTES` + 1 GiB stays at or above 31 GiB. That window adds the S20
leak rows under load. If `load_concurrent` fails because the downloads
ended before the bursts, raise `LOAD_BYTES` within what the URL serves
(140064536 bytes a stream for the default). If the host does not serve
that size, `load_download` fails; raise `LOAD_STREAMS` as well. `load_connected_throughout` is `unavailable` when the load's
provider-log read was cut off at its 30 s bound.

## Disconnect and stop

Use `$H --disconnect $P <owner_generation> <relay>` and confirm with
`scutil --nc status`. If that does not reach Disconnected, use
`scutil --nc stop <service id>`, then `$H --emergency-stop`. The window
harness does exactly this escalation and verifies the default route returns
to the physical interface with no `198.19.255.1` left
([harness](../../../tools/macos/aegis-network-extension/harness/README.md)).

Parent: [macOS documentation](README.md).
