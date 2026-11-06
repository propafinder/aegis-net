# Adaptive carrier selection and failover in installed clients (CP-D3)

Status, 2 November 2026: **source and local evidence only.** Branch
`degree/b08-brain-failover-20261102` from `a7872693` (the D1/D2 branch). This
document records the audit of what the installed clients use for carrier
choice today, the design implemented on this branch, the local checks that
were executed and what remains. Nothing here is an installed-client,
real-Cloudflare, target-network or leak acceptance.

"Integrated" follows the carrier-program definition (enabled in the installed
Linux DEB and notarized macOS NE client, real TCP and UDP through the relay, no
leak and no weakened check, automatic failover covered by a test, checked from
multi-vantage, receipts, change-log entry and roadmap row). This branch
closes the source part of "when a carrier is blocked the client moves to the
next one by itself, and a test pins it" for the Linux client path; the
installed, macOS and real-network parts remain open (section 7).

## 1. Audit at `a7872693`

### What the installed clients actually use

| Area | State before this branch |
| --- | --- |
| Enrolled profile fields | v3/v4 public profile: `relay_server`, `outer_server_name`, optional v4 `relay_endpoints` (1 to 16 numeric pins, primary first), `udp` (enrolled UDP is `grpc_datagram` only), optional research `endpoint_bandit` and `recent_routes`, one `ech_config_list` for the whole profile. Rendering forces `transport_priority = [grpc_stream]`, `udp_transport_priority = [grpc_datagram]` or `[]`, Rustls, explicit outer CA, no mimicry. |
| Linux runtime selection | SOCKS, full-wide TUN/packet engine and UDP flows all enter `relay::run_relay_tunnel`, `run_relay_udp_flow`, `run_relay_udp_datagram_once` or the UDP association. Each session iterates the pool in **fixed profile order**; inside an endpoint it iterates the transport plan (for enrolled profiles only `grpc_stream`). A typed pre-authentication failure (TCP dial failure, non-200 carrier answer after verified outer TLS, timeout before inner TLS) moves the same session to the next endpoint; everything else is terminal and never replayed. |
| Brain (`aegis-core/src/brain`) | Per-target strategy and transport-family learning (`StrategyKey`, `adaptive_transport`). It orders transport families, not endpoints; for an enrolled profile with a single family it has nothing to reorder. Relay-mode state is RAM-only by policy. |
| `hybrid_route.rs` | Vocabulary for the Geneva hybrid product route; the relay terminal action is `Block` (no native egress). |
| `carrier_runtime.rs` | Despite the name: authenticated shaping configuration, not carrier choice. |
| Health signals | `FailSignal` (including `SessionFreeze`, `ThroughputCollapse`) is recorded per target for the Brain; it never influenced which endpoint the next session used. Open sessions had no liveness probe. |
| Cooldown / recovery | Only the opt-in research `endpoint_bandit` (numeric pool, per destination context, fixed `pre_auth_block_ms`, RAM). No return-to-preferred logic. |
| Persistence | None for relay mode (RAM-only by policy). |
| macOS NE provider | `bound_relay_policy` derives the same `RelaySettings` from the public profile; `held_relay_services` uses **one fixed peer** and its `ensure` still refuses before any socket (B-06 source state). No failover. (Superseded in source by B-06 v40, see M1.) |
| Adaptive defaults | `https_ws`, `grpc_stream`, `masque_derived` is only the default `transport_priority` of legacy (token) profiles. Enrolled profiles are admitted with `grpc_stream` only and UDP `grpc_datagram` only; required carried-leg failures have no native-egress fallback (README "Capabilities and limits"). |

### Gaps

| # | Gap | Consequence |
| --- | --- | --- |
| A1 | An outer TLS handshake **cut at the transport layer** (RST after the ClientHello, SNI-matched reset, EOF) was a terminal error. | Only the ClientHello had been sent, yet the session never reached the next carrier: an SNI or ClientHello filter on the preferred carrier broke every new session. |
| A2 | No memory across sessions. | With a SYN-dropped preferred carrier every new TCP flow and UDP flow (full-wide: every flow) waited the full establishment timeout (5 s) before the next carrier. |
| A3 | No return to the preferred carrier. | — (nothing was remembered, so there was nothing to return from) |
| A4 | Open sessions had no freeze/collapse detection. | A frozen path (packets silently dropped mid-session) hung the session until idle timeouts; nothing told later sessions to avoid that carrier. |
| A5 | No per-network memory. | — |
| A6 | No profile field for a failover policy; the macOS provider has one fixed peer. | No way to bind the behaviour to the signed profile or to bring it to macOS. |
| A7 | Candidate kinds: `https_ws` and MASQUE are not admitted for enrolled profiles (inner device TLS over RFC 8441 or MASQUE is not implemented). | The enrolled candidate list is the pool: direct H2 relay pins and CDN-edge pins, each carrying `grpc_stream` and `grpc_datagram`. |
| A8 | ECH is profile-global: with `ech_config_list` every endpoint must share one DNS `server_name`. | A pool mixing a non-ECH direct relay and an ECH CDN edge cannot be expressed (see 7, item M3). |

## 2. Candidate list

The candidate list is the profile's v4 `relay_endpoints`, in the operator's
order, for example:

```json
"relay_server": "<direct relay pin>:443",
"outer_server_name": "<relay name>",
"relay_endpoints": [
  {"server": "<direct relay pin>:443", "server_name": "<relay name>"},
  {"server": "<edge anycast pin A>:443", "server_name": "<edge name>"},
  {"server": "<edge anycast pin B>:443", "server_name": "<edge name>"}
],
"udp": true
```

| Candidate kind | Enrolled profile | Notes |
| --- | --- | --- |
| Direct H2 relay (`grpc_stream`, UDP `grpc_datagram`) | admitted | Preferred first. |
| CDN-fronted edge, D1 (`grpc_stream`, UDP `grpc_datagram`) | admitted | Same origin inner certificate and device registry; `outer-ca.pem` pins the relay CA and the edge CA set together (validator bound: 8 certificates). |
| `https_ws` (RFC 8441) | **not admitted** | Requires inner device TLS over WebSocket and a server route; not implemented, so not listed. Legacy token profiles keep their own transport loop. |
| MASQUE/QUIC | **not admitted** | Enrolled UDP is `grpc_datagram` only; unchanged. |
| Own HTTPS bridge (D4) | per profile | `https_bridge` currently applies to every pool endpoint (its authority must match each `server_name`). |

Every candidate is a numeric pin (existing invariant), so failover never
resolves DNS outside the tunnel. On macOS and Windows `relay_pins` already
lists every pool endpoint as a capture exception; for the Linux installed
full-wide guard the exclusion of every pool pin (not only the primary) must
be confirmed in the installed cell with a two-carrier profile (M2). This
branch does not change capture or guard code.

## 3. Controller

`aegis_core::brain::carrier_failover` is pure and deterministic (caller
supplies the clock and network key). Per access network it keeps a circuit
breaker per candidate:

- **Order.** Closed (usable) carriers in profile order; a carrier whose
  cooldown expired is retried as a **single-flight trial** if it is the most
  preferred usable candidate (concurrent sessions see it as busy and use the
  fallback); carriers in cooldown are appended as **last resort** (soonest
  expiry first). No carrier is ever removed, and nothing outside the list is
  ever attempted.
- **Pre-authentication signal** (session may continue on the next carrier):
  opens the breaker for `base_cooldown_ms x 2^level`, capped at
  `max_cooldown_ms`.
- **Post-authentication signal** (open session; never replayed): counts toward
  `degraded_threshold`; at the threshold the breaker opens for later sessions.
  A clean session end with response bytes clears the count.
- **Recovery.** A successful open closes the breaker, resets the level and
  marks the carrier active; a failed trial doubles the cooldown.
- **Per-network memory.** At most `max_networks` networks, least recently used
  evicted. Linux derives the key from the lowest-metric default IPv4 route
  (interface, gateway) and the gateway's link-layer address, hashed with a
  per-process random salt (`NetworkKey`), refreshed every 2 s. Unreadable
  routing (and non-Linux binaries) share `NetworkKey::UNKNOWN`. Memory is
  RAM-only, matching the relay-mode privacy policy; a restart costs at most
  one establishment timeout per blocked carrier.

Policy (`CarrierFailoverSettings`, all fields defaulted, unknown fields
refused):

| Field | Default | Bounds |
| --- | --- | --- |
| `base_cooldown_ms` | 5000 | 100..=60000 |
| `max_cooldown_ms` | 300000 | base..=3600000 |
| `degraded_threshold` | 2 | 1..=8 |
| `liveness_interval_ms` | 20000 (0 disables) | 0 or 100..=300000 |
| `liveness_timeout_ms` | 10000 | 100..=60000 |
| `collapse_rtt_ms` | 4000 | 50..liveness_timeout |
| `max_networks` | 16 | 1..=64 |

## 4. Block signals

| Signal | Detection | Phase | Effect |
| --- | --- | --- | --- |
| `dial_timeout` | TCP connect not completed before the establishment deadline (dropped/black-holed SYN) | pre-auth | next carrier now; cooldown |
| `dial_refused` | TCP connect refused/unreachable | pre-auth | next carrier now; cooldown |
| `handshake_reset` | Outer TLS handshake I/O `ConnectionReset`/`ConnectionAborted`/`UnexpectedEof`/`BrokenPipe`/`NotConnected` (RST after ClientHello, SNI reset). **New retryable class.** Certificate, TLS alert and ECH refusals are not this signal and stay terminal. | pre-auth | next carrier now; cooldown |
| `establishment_timeout` | TCP up, inner TLS not reached before the deadline (slow-loris, collapse during establishment) | pre-auth | next carrier now; cooldown |
| `edge_refused` | Non-200 answer to the carrier request after verified outer TLS (edge error page, origin decoy) | pre-auth | next carrier now; cooldown |
| `session_freeze` | Outer HTTP/2 PING without PONG within `liveness_timeout_ms` | post-auth | session closed (never replayed), owner reconnects on the next carrier; degradation |
| `throughput_collapse` | PONG slower than `collapse_rtt_ms` | post-auth | degradation (session continues) |
| `session_reset` | The outer HTTP/2 connection itself failed (driver ended with an error), not a stream/target close | post-auth | degradation |

Not carrier signals (recorded as neutral, never move the same session, never
open a breaker): inner TLS/device identity refusal, target refusal, local
policy or credential errors, certificate/alert/ECH refusal.

Liveness uses the standard HTTP/2 PING on the outer carrier connection (as
gRPC keepalive does); it runs only on profiles with a failover policy,
`liveness_interval_ms > 0` and **no authenticated shaping** (a shaping profile
owns the outer wire schedule; an unshaped periodic PING record would stand out
beside it, so such profiles keep pre-authentication failover only). It is the
only wire change. Through a CDN the edge
answers the PING, which measures exactly the censored client-edge segment.

## 5. Invariants kept

- No native egress: the terminal when every carrier fails is the existing
  `RelayTerminalFailure`; the harness checks the destination is never dialed.
- No replay: same-session advance only for typed pre-authentication failures
  before any identity, invitation or target was sent; a frozen session is
  closed, its bytes are not resent elsewhere; UDP datagrams already consumed
  are never replayed.
- Identity: one inner device identity for all carriers; inner refusals stay
  terminal and are not learned as blocks.
- Filters and admission unchanged: enrolled transport plan, numeric pins,
  outer CA, ECH and policy checks are untouched; per-endpoint settings drop
  the pool policy (like the endpoint bandit), so admission of each attempt is
  unchanged.
- `carrier_failover` requires device inner TLS, a pool of 2 to 16 endpoints and
  no endpoint bandit.

## 6. Implementation map

| Change | Files |
| --- | --- |
| Controller, signals, network key, policy | `aegis-core/src/brain/carrier_failover.rs`, `aegis-core/src/config_types.rs` (`RelaySettings.carrier_failover` + validation) |
| Runtime glue: registry per profile, tickets, Linux network key, events | `aegis-client/src/relay/carrier_failover.rs`, `aegis-client/src/relay/events.rs`, `aegis-client/src/runtime_events.rs` (`relay_carrier_state_changed`) |
| Ordering in TCP, UDP flow, UDP once, UDP association, PolicyAck | `aegis-client/src/relay.rs`, `aegis-client/src/relay/secure.rs` |
| Handshake-reset classification, liveness probe, outer connection outcome | `aegis-client/src/relay/secure.rs` (`OuterHandshakeInterrupted`, `CarrierDriver`, `watch_liveness`) |
| Per-endpoint settings drop the pool policy | `aegis-client/src/relay_endpoint_policy.rs` |
| Profile field, default rule, render, installed binding | `aegis-client/src/device_bundle_profile.rs`, `aegis-client/src/device_bundle_profile_online.rs` |
| Harness | `aegis-client/src/relay/carrier_failover_tests.rs` (uses `tests/support/cdn_grpc_proxy.rs`) |

Installer: no change. `install.sh client --bundle` already renders through
`device bundle-render`, which now writes `[relay.carrier_failover]` for a v4
pool of two or more endpoints; at start the online runtime refuses a
configuration whose policy differs from the public profile. The macOS
provider's `BoundRelayPolicy` receives the same `settings.relay.carrier_failover`
through the shared renderer; its runtime is unchanged (section 7).

## 7. Status and remaining work

Integrated in source (Linux client path, local evidence only): ordered pool,
typed block detection including RST/SNI resets, bounded backoff, single-flight
return to the preferred carrier, per-network RAM memory, liveness freeze and
collapse detection, profile field, installed TOML and runtime binding,
deterministic fault harness.

| ID | Remaining | Owner/dependency |
| --- | --- | --- |
| M1 | macOS NE: replace the single held peer with the pool; preload a held connector per pin; run the same `CarrierFailover` controller (shared crate); classify held-dial errors into the same signals (dial, handshake reset, establishment timeout, non-200); expose `h2::PingPong` from `connect_h2_from_held` for liveness; derive `NetworkKey` from `NWPathMonitor` (interface type, gateway); exclude every pool pin from the tunnel routes (already in `relay_pins`); notarized build and owner sudo leak window. **2 November: source on `degree/b06-carriers-20261102` (B-06 v40, local evidence only):** pool admission and a held connector per pin, one controller per profile, the session build moving to the next pin on the same pre-authentication signals before any identity, post-authentication freeze/collapse/lease-freeze degradations, a pin lost under a running session ending it for a rebuild, the network key from a process path monitor, the leak guard arming every exact pin and nothing else. The macOS pool already owns each connection's `h2::PingPong` (its stall watchdog), so its verdicts are mapped and `connect_h2_from_held` needed no change; the NE sockets are bound to the physical interface, so no route exclusion is involved. Remaining: install and window of the notarized build, a two-carrier leak window (harness leak review is single-tuple), real edge (G1) | B-06 lane |
| M2 | Installed Linux DEB acceptance with a two-carrier v4 profile (direct relay + D1 edge): blocking each carrier on a real path (iptables DROP of SYN, RST injection) during native/installed cells with leak capture | Codex/fleet; after G1 of D1 (real edge) |
| M3 | Mixed ECH pool (A8): scope `ech_config_list` to the edge endpoints (for example an `ech_server_name` scope in `RelaySettings` cleared per endpoint in `relay_settings_for_endpoint`, profile field bound by the digest, enrollment carrier rule), so a non-ECH direct relay and an ECH edge coexist | Source design + ECH edge tests (`chrome-like-tls`) |
| M4 | Enrollment/renewal carrier failover: the online authority is one `authority_server`; variant B through the edge vs the direct authority is not ordered or learned | Source |
| M5 | First-switch latency: the first session after a SYN drop still waits one establishment timeout (5 s default). A hedged second dial before inner TLS would remove it at the cost of parallel connections on the wire | Owner decision on the wire trade-off |
| M6 | `https_ws` / MASQUE as enrolled candidates (A7) | Source + server route; separate admission review |
| M7 | Persisted per-network memory across restarts (privacy decision: network history on disk) | Owner decision |
| M8 | multi-vantage acceptance | Owner/Codex |
| M9 | Exact-commit CI | CI dispatch after owner approval |

Evidence: see the change-log entry "[CP-D3] … local source batch".
