# Geneva product integration roadmap

- **Status:** maintained source/evidence roadmap, reconciled 2026-10-11.
- **Historical route-learning baseline:** `a2e83c0a`.
- **Historical G4 pre-release candidate:** `98cd42ceaac532ff691dd0a23bf2061f3a682a86`.
- **Later signed hybrid evidence:** RC5 source
  `f077d190dd29008874fcf1c55b6d8ef45b1f03d9`, plus the dated RC7 route-feedback audit.
- **Current product verdict:** Geneva is experimental. Default `full-wide-tun`
  selects none; an explicit managed relay-outer Geneva selection is available
  in source for Linux device `full-wide-tun`. The direct hybrid profile is a
  separate legacy shared-token profile, refused by enrolled device policy.

This roadmap defines how Geneva becomes a real AEGIS product path without
weakening the current relay-only, fail-closed full-wide profile or overstating
the controlled lab evidence.

## 1. Verified baseline

The plan starts from code and wire evidence, not feature names.

| Fact | Code or evidence |
|---|---|
| Offline Geneva parser/evolution engine exists | `aegis-geneva/` |
| Live bridge exists | `aegis-core/src/strategies/geneva.rs` |
| Direct-client decoy strategy is IPv4 TCP only | `StrategyRequirements` and raw-engine capability checks |
| Separate AF_PACKET bridge executes original IPv4 TCP/UDP/DNS packet primitives | [live bridge contract](geneva-live-bridge.md), `aegis-geneva/src/bin/bridge.rs` |
| Relay-outer backend executes the live program on owned NFQUEUE traffic | `aegis-core/src/relay_geneva.rs`, [selected installed profile](relay-geneva-installed-profile.md) |
| Default direct strategies do not include Geneva | `aegis-core/src/config_types.rs`: `multisplit`, `passthrough`; `geneva_strategy = None` |
| Geneva is created only when a DSL is configured | `aegis-client/src/direct/planner.rs` |
| Invalid/unsupported live DSL fails startup | `configure_geneva` in `aegis-client/src/main.rs` |
| Default `full-wide-tun` uses relay mode without Geneva; its explicit selected outer path still uses a relay | installer-generated client configuration and selected-profile contract |
| Typed planning terminals hand off to a runtime-ready relay in `Auto` mode; without a usable relay configuration they fail closed | `aegis-client/src/direct.rs`: `direct_terminal_action`; `aegis-client/src/direct/executor.rs`: `DirectTerminalReason` |
| Direct-to-relay handoff exists for classified stalls/collapse | `aegis-client/src/direct.rs` |
| Controlled hostile-middlebox bypass passed | `evidence-archive/live/2026-08-15/geneva-controlled-hostile-netns-live/` |
| External commercial/national DPI result | **not measured** |

The controlled proof is meaningful but narrow: a TTL=1 altered payload decoy
was visible before the test censor, absent after it, and the canonical request
reached the server. It proves the live serializer and path-expiry mechanism. It
does not prove that the same strategy matches a real censor's state machine.

## 2. Why Geneva is not added to `full-wide-tun` directly

Four contracts are different:

1. **Routing:** `full-wide-tun` carries TCP through a relay; Geneva currently
   modifies direct destination traffic.
2. **Privacy:** direct Geneva reveals the destination IP to the access network;
   the relay-only TCP path does not.
3. **Address family:** the live Geneva bridge requires IPv4 raw send and exact
   TCP sequence information; IPv6 is filtered by the planner.
4. **Failure behavior:** typed planning terminals now hand off to a configured
   relay in `Auto` mode and fail closed without a usable relay plan. Ordinary
   `Direct` mode preserves its existing terminal behavior.

Silently inserting Geneva into the existing profile would therefore change
the privacy model and create an unsafe, incomplete IPv6 path. The first product
integration must be a separate opt-in mode.

## 3. Target product profile

Implemented legacy profile: `full-wide-hybrid-geneva`. It requires a nonempty
legacy `relay.auth_token`; enrolled inner-TLS device profiles reject
`direct.hybrid_geneva`. It does not describe the separate enrolled
[relay-outer selection](relay-geneva-installed-profile.md).

```text
TCP / IPv4
    direct Geneva
        success ─────────────────────────────> destination
        unsupported / no plan / pre-send fail > fronted grpc_stream relay
        ambiguous failure after app bytes ───> block (no unsafe replay)

TCP / IPv6 ──────────────────────────────────> fronted grpc_stream relay

UDP / IPv4 + IPv6 ───────────────────────────> direct MASQUE relay
                                               optional grpc_datagram fallback
```

The default `full-wide-tun` remains relay-only. Explicit outer Geneva transforms
its selected relay connection and does not select a direct destination route.

### Non-negotiable invariants

- The hybrid profile is explicit opt-in and prints that direct IPv4 exposes
  the destination IP.
- No native passthrough is permitted after the profile has captured a flow.
- Any unsupported address family, missing raw capability, empty plan, or other
  provably pre-send terminal hands off to the configured relay. Endpoint reachability
  and deployment fronting are separate live gates; failure still closes the flow.
- Once application bytes may have reached the destination, the same flow is not
  replayed over a fresh relay connection: it fails closed. G3 may route a later
  flow to the relay using learned evidence, without duplicating this flow.
- If the relay is unavailable, the captured flow is dropped; it never leaks to
  the native route.
- TCP IPv6 never enters the current Geneva bridge.
- UDP never enters the TCP Geneva engine.
- A canonical packet must remain kernel-owned and byte-correct at the server.
- Application payload is sent at most once across direct and relay routes; an
  ambiguous post-send failure is never retried on a second connection.
- Every route decision and fallback is observable without logging credentials,
  full destination URLs, or payloads.
- Geneva success is scoped to a strategy, network, location, time window, and
  captured evidence. There is no global `geneva_works = true` claim.

## 4. Delivery milestones

Current source and dated evidence:

- G0/G1 route families, replay-safe terminal actions, capability admission and
  runtime events are implemented. Empty/unsupported/pre-send paths hand off in
  `Auto` mode or close without a usable relay; ambiguous post-send paths block.
- G2 has historical lifecycle evidence for the pre-release `98cd42ce` Ubuntu
  26.04 candidate and signed RC5 Ubuntu 26.04/AlmaLinux 9.8. RC5 Alma includes
  purge/reinstall, reboot and a later SELinux Enforcing follow-up. These do not
  establish Ubuntu 24.04, a full Debian client lifecycle or a future candidate.
- G3 source records product-route evidence separately from strategy/transport
  fitness, consumes live external classifier hints once per snapshot, and
  applies bounded hostile-route cooldown and freshness decay. Learning is
  RAM-only by default. Only explicit `[direct] persist_state = true` in
  direct/auto mode allows disk retention; relay and forensic modes stay RAM-only.
  The installed hybrid profile does not opt in to learned-state persistence.
  The RC7 audit records an actual direct success, hostile cooldown and subsequent
  successful relay handoff on its own signed candidate.
- G4 remains partial. Historical controlled matrices and lifecycle receipts
  prove their named source/binary/host combinations. No external commercial or
  national DPI result, all-family current-candidate lifecycle or exact-release
  24-hour field acceptance is established by those receipts.

Evidence is retained in place; the ledger below names each candidate rather than
promoting the old pre-release candidate to a current release verdict.

### G0 — contracts and vocabulary

Deliverables:

- Add route-family vocabulary independent of strategy and transport IDs:
  `DirectGeneva`, `RelayGrpc`, `RelayMasque`, and `Block`.
- Define the privacy classification for every route.
- Define runtime event schemas before implementation.
- Add configuration validation that rejects a hybrid profile with no relay
  fallback or with `passthrough` enabled.

Exit gate:

- Unit tests prove every protocol/address-family combination resolves to one
  route family and has an explicit terminal failure action.

### G1 — correct direct-to-relay fallback

Deliverables:

- Replace the current boolean-only fallback recommendation with a typed direct
  terminal reason.
- Treat `NoExecutableStrategy`, `UnsupportedAddressFamily`, and
  `MissingRawCapability` as relay-handoff reasons in hybrid mode.
- Preserve the current retry/fallback behavior for freeze and throughput
  collapse.
- Keep ordinary direct mode behavior backward-compatible.

Required tests:

- Geneva-only configuration on a host without raw capabilities hands off to
  the relay.
- An IPv6 target does not attempt Geneva and hands off immediately.
- A malformed or semantically unsupported DSL still fails startup rather than
  silently using the relay.
- Relay-not-ready terminates fail-closed.
- A replay-safe handoff sends the application payload exactly once; an ambiguous
  post-send failure never opens a second application connection.

Exit gate:

- No `no strategy (Unknown)` terminal remains for a classified hybrid route.

### G2 — implement `full-wide-hybrid-geneva`

Current status: **source implemented; dated Ubuntu 26.04 and RC5 AlmaLinux 9.8
lifecycle evidence; exact-current-candidate family exit gate open**.

Deliverables:

- Add the profile to the Rust-owned profile resolver.
- Add installer selection, configuration rendering, systemd lifecycle,
  rollback, repair, and uninstall support.
- Require a Geneva DSL and a working fronted gRPC relay pool.
- Keep UDP on the separately scoped direct MASQUE configuration.
- Print the direct-destination disclosure before activation.

Source contract:

- Installer input is a file (`--geneva-strategy-file`) so the DSL is not
  corrupted by shell quoting.
- The rendered runtime configuration sets `mode = "auto"`,
  `direct.hybrid_geneva = true`, `strategies = ["geneva"]`, TCP relay priority
  to `grpc_stream` only, and UDP relay priority to `masque_derived` first.
  Validation also accepts `grpc_datagram` as the optional second UDP family.
- Startup rejects missing DSL, passthrough/alternate direct strategies, a
  non-`Auto` mode, a missing authenticated gRPC plan, or a missing direct MASQUE
  endpoint.
- Runtime records whether canonical application bytes may have been sent.
  Relay replay is allowed only while it is provably safe; otherwise the captured
  flow is blocked to preserve the at-most-once contract.

Required tests:

- Profile JSON snapshot and config round-trip.
- Install, repair, reboot, mode switch, rollback, and uninstall contracts.
- Firewall assertions prove there is no native TCP/UDP escape.
- Existing `full-wide-tun` snapshots remain unchanged.

Exit gate:

- The profile can be installed and fully removed on disposable Ubuntu,
  Debian, and AlmaLinux x86_64 clients without residue.

### G3 — Brain route learning

Current status: **source and runtime contracts implemented; live G4 gate open**.

The Brain currently chooses direct strategy order and relay transport behavior
through different concepts. The implemented hybrid feature adds route learning
above both.

Deliverables:

- Learn `DirectGeneva` versus `RelayGrpc` per censored-network key without
  mixing Geneva DSL IDs with relay transport IDs.
- Feed real direct block/freeze outcomes and relay handoff outcomes into the
  same route-level record.
- Keep the implemented runtime `ExternalClassifierHint` path: freshness-decayed
  knowledge/witness/adversarial Geneva rows already enter the live selector.
- Apply freshness decay so an old successful Geneva strategy does not remain
  preferred after the censor changes.
- Bound exploration; do not repeatedly probe a path identified as hostile.

Implemented contract:

- `StateSnapshot.hybrid_route_stats` stores route evidence under the hashed
  `StrategyKey`; it never stores a hostname, URL, token, or payload.
- `geneva` strategy fitness, `grpc_stream` transport fitness, and the
  `DirectGeneva`/`RelayGrpc` product route remain separate records.
- One unresolved direct attempt suppresses parallel re-probes for 30 seconds.
  Hostile direct outcomes start an exponentially bounded cooldown; expiry
  permits one later direct exploration instead of pinning relay forever.
- A direct success is fresh for six hours. After that its reason becomes
  `evidence_decayed_exploration`, so an old success is not reported as current
  proof.
- External knowledge/witness/adversarial Geneva evidence is freshness-decayed,
  converted to a live `ExternalClassifierHint`, and fingerprinted by snapshot
  so repeated connections cannot inflate the sample count.
- The direct-to-relay runtime now supplies a real relay outcome sink. A handoff
  records the attempted relay transport and the final route outcome in the
  runtime store. A flush persists them only under the explicit direct/auto disk
  policy; the default flush of an ephemeral store does not create disk state.

Required events:

- `hybrid_route_selected`
- `geneva_direct_attempt_started`
- `geneva_direct_attempt_succeeded`
- `geneva_direct_attempt_failed`
- `direct_relay_handoff_started`
- `direct_relay_handoff_succeeded`
- `hybrid_flow_blocked_fail_closed`

Every event must include route family, reason, strategy fingerprint, address
family, capability summary, and evidence confidence. It must not include the
token, request payload, or full URL.

Exit gate:

- Deterministic replay tests show expected success/failure/decay/classifier
  selection. A library snapshot round trip covers opted-in persistence; the
  default installed service starts with fresh RAM learning after restart.

Source/replay contracts are implemented. The dated RC7 audit supplies live
feedback/cooldown/handoff evidence; default restart retention is not claimed.
Neither result establishes success against external commercial or national DPI.

### G4 — wire and hostile-path matrix

Current status: **partial / release NO-GO**.

- The three-family controlled route matrix is under
  `evidence-archive/live/2026-08-16/geneva-g4/`. It used exact commit `a2e83c0a` and
  client SHA-256
  `bb0221b2bbed9f807be28a2d065471bbf2446fd9e9eb419325ea303712cd3c94`.
- The historical pre-release Ubuntu lifecycle evidence is under
  `evidence-archive/live/2026-08-20/geneva-g4-lifecycle/`. It used exact commit
  `98cd42ceaac532ff691dd0a23bf2061f3a682a86` and client SHA-256
  `821e990088d523d0e931d6fc7cee328798a933250025fc871c0c990becc397d0`.
- That candidate's historical local gates passed: formatting, workspace all-feature tests,
  all-target all-feature clippy with warnings denied, and the unwired suite at
  **106 passed, 0 failed, 17 excluded by name**.

- The later signed RC5 Ubuntu proof (`evidence-archive/live/2026-08-20/geneva-rc5-release/README.md`)
  names source `f077d190dd29008874fcf1c55b6d8ef45b1f03d9` and carries
  six-case pre/post-reboot relay/MASQUE results on Ubuntu 26.04.
- The signed RC5 AlmaLinux proof (`evidence-archive/live/2026-08-20/geneva-rc5-alma/README.md`)
  adds 9.8 lifecycle/purge/reinstall evidence. Its
  SELinux follow-up (`evidence-archive/live/2026-08-21/rc5-selinux-enforcing-and-soak-checkpoint/README.md`)
  records Enforcing restart/reboot and 6/6 matrices.
- The RC7 audit (archived: `docs/audit/linux-rc7-rt-audit-2026-08-26.md`)
  records live direct outcome, cooldown and relay feedback for its own candidate.

These receipts do not satisfy the current exact-candidate G4 exit gate: Ubuntu
24.04 and full Debian client lifecycle are not established by this evidence,
and no result here measures an external commercial or national DPI. AlmaLinux
RC5 acceptance is historical evidence for RC5, rather than an open RC5 row or
acceptance transferred to current source.

Required matrix:

| Case | Expected result |
|---|---|
| IPv4 TCP, Geneva succeeds | direct response; no relay connection |
| IPv4 TCP, controlled censor blocks baseline | Geneva decoy before censor; canonical packet at server |
| IPv4 TCP, Geneva fails before canonical send | one relay handoff; response through gRPC |
| IPv4 TCP, failure after canonical send is ambiguous | fail closed; no second application connection |
| IPv4 TCP, raw capability missing | no direct packet; immediate relay handoff |
| IPv6 TCP | no Geneva packet; gRPC relay |
| IPv4/IPv6 UDP | MASQUE-primary; `grpc_datagram` only when explicitly configured as the second family |
| Relay unavailable after direct failure | application failure; no native egress |
| Service SIGTERM/SIGKILL/reboot | no stale capture route or firewall leak |

Evidence must include client-facing and server-facing pcaps, runtime events,
firewall/routing snapshots, exact binary hashes, exact source commit, and a
machine-readable verdict.

Exit gate:

- All rows pass on Ubuntu 24.04, Debian 13, and AlmaLinux 9.x x86_64.

### G5 — restricted-network field gate

Field testing must be opt-in, operator-controlled, and limited to destinations
the operator is authorized to test. Geneva traffic is detectable and is not an
anonymity mechanism.

For each candidate strategy, record at least:

- 30 baseline direct trials;
- 30 Geneva direct trials;
- 30 fronted gRPC control trials;
- at least three time windows across two days;
- network/ASN, resolver, target, client/release hash, DSL hash, packet capture,
  and failure classification.

Proposed field acceptance threshold:

- baseline direct success at or below 20%;
- Geneva direct success at or above 90%;
- fronted relay control success at or above 95%;
- no canonical corruption, native leak, service crash, or uninstall residue;
- the result repeats in all three time windows.

If the baseline is not actually blocked, the run measures connectivity only
and cannot count as Geneva bypass evidence.

Exit gate:

- At least one strategy passes this matrix in the target restricted network.
  Until then the feature remains `experimental`, even if every local test is
  green.

### G6 — controlled beta and rollback

Deliverables:

- Publish the hybrid profile only in an RC channel.
- Gate it behind an explicit experimental acknowledgement.
- Ship a remote kill switch that disables direct Geneva preference but retains
  relay-only fail-closed operation.
- Complete a 24-hour exact-release soak with route churn and relay failover.
- Run install/reboot/upgrade/rollback/uninstall from the signed GitHub release
  and from the signed RU mirror.

Promotion gate:

- No P0/P1 security or leak defects.
- CI and all three Linux-family live matrices pass for the exact release.
- Field gate G5 passes.
- Operator accepts the direct destination-IP disclosure.

## 5. Distinct live packet backends

The kernel currently owns the real TCP connection, including sequence and ACK
state. That is why the live bridge can honestly emit bounded decoys but cannot
apply the complete offline grammar to canonical packets.

The [standalone AF_PACKET bridge](geneva-live-bridge.md) already executes
`live::program::Program` on actual bidirectional IPv4 TCP/UDP/DNS frames between
isolated owned ports. The [relay-outer backend](relay-geneva-installed-profile.md)
executes that program on its own NFQUEUE traffic and validates the complete
replacement batch. Neither replaces the kernel-owned direct-client decoy
strategy with a general canonical-packet transformer. Unsupported fields,
object forms, IPv6 and unsafe contexts refuse rather than approximate an action.

Existing packet-program semantics and remaining direct-product work:

- AF_PACKET and owned NFQUEUE implement outbound/inbound forests, packet
  triggers, checked TCP/IP/UDP/DNS edits, TCP segmentation and IPv4 fragmentation
  within the live program's documented finite surface.
- The direct-client path retains its narrower expiring-decoy actions and exact
  kernel sequence/canonical-send ownership.
- General direct canonical transformation, IPv6 serialization/path expiry and
  any new connection-state owner require separate source and native acceptance.
- Selected outer recovery/guard/teardown source contracts exist; their exact
  installed lifecycle, independent capture and crash/rollback acceptance remain
  separate from pure fixtures and historical direct-hybrid proofs.

No action may be mapped approximately. If the live serializer cannot preserve
a DSL action exactly, configuration must be rejected.

## 6. Implemented optional outer-relay selection

`relay.outer_geneva` is an explicit Linux relay-only wide/device selection in
source. It transforms the outer authenticated relay connection rather than
opening a direct destination route. It requires inner TLS, gRPC, a complete
literal IPv4 relay pool, an armed device guard, exact source/config/unit/helper
pins and a stopped installation boundary. IPv6 and QUIC outer transports refuse.
The [installed-profile contract](relay-geneva-installed-profile.md) describes
the bounded lease, administrative start/recovery/teardown and read-only verifiers.
Selected unattended renewal/restart is not implemented; its drop-in uses
`Restart=no`.

This source path was implemented independently of G5. It can alter the outer
wire image and retains independent acceptance gates for:

- exact selected installed lifecycle, guard block, crash/reboot recovery,
  physical capture and independent rollback;
- provider/fronting connection acceptance if such a deployment is proposed;
- TLS ClientHello and HTTP/2 fingerprint parity;
- origin reachability;
- no duplicate application data;
- per-edge and per-network A/B evidence.

There is no accepted Cloudflare deployment for this selected path. It must not
be described as “Geneva through Cloudflare” until a pcap proves
that the intended decoy reached the relevant censor observation point and the
fronted connection still carried traffic.

## 7. Pull request sequence

Keep implementation reviewable; do not ship this as one large patch.

1. **Docs baseline:** replace the root README, publish this roadmap, and fix
   documentation authority.
2. **Route/fallback model:** typed route families and the empty-plan/IPv6/raw
   capability handoff fix.
3. **Hybrid profile:** resolver, installer, lifecycle, and fail-closed policy.
4. **Brain integration:** route-level learning, classifier input, decay, and
   redacted telemetry.
5. **Controlled matrix:** netns, pcaps, lifecycle, and three-family host proof.
6. **Field gate:** restricted-network A/B evidence and RC-only publication.

Each PR must include its own tests and must not broaden public claims beyond
the evidence merged with it.

## 8. Definition of done

Geneva product integration is done only when all of the following are true:

- the route table is explicit for TCP/UDP and IPv4/IPv6;
- direct Geneva failure always produces relay handoff or fail-closed drop;
- default `full-wide-tun` remains relay-only with no Geneva selection;
- the hybrid profile installs, reboots, upgrades, rolls back, and uninstalls on
  all claimed Linux families;
- packet captures prove decoy placement and canonical delivery;
- the Brain learns route outcomes without leaking sensitive data;
- an exact released build passes the controlled matrix, 24-hour soak, and
  real restricted-network A/B gate;
- the README names the field-tested strategy/network scope instead of claiming
  universal DPI bypass.

## 9. Upstream model references

AEGIS implements its own Rust engine and live bridge. These references define
the upstream Geneva concepts; they do not override AEGIS code behavior:

- [Geneva introduction](https://geneva.readthedocs.io/en/latest/intro/introduction.html)
- [Strategy grammar and action trees](https://geneva.readthedocs.io/en/latest/howitworks/howitworks.html)
- [Evaluator and field-testing model](https://geneva.readthedocs.io/en/latest/howitworks/evaluator.html)
- [Geneva research publications](https://geneva.cs.umd.edu/papers/)
