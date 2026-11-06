# Carrier program: implementation and acceptance boundary

## G1 read-only inventory and plan protection — 3 November 2026

The actual account-token verification and exact zone/account lookup on frozen
`8b3e1c923732b5e536d2cf8be136bf316cf7a6e8` passed. The subsequent
`f94a2400` inventory stopped at the provider's undefined `grpc` setting; its
private raw replies and failed receipt remain retained. Successor
`44c024f5498eac13024ea2e88e5ded874ab3a840` collected all 13 GETs under a
75-second worker bound, with 128 KiB per-response limits, an exact endpoint
allowlist, no redirects and no mutation path. It observed 10 HTTP 200 replies,
two absent-rule HTTP 404 replies and the `grpc` HTTP 400/code 1003. Its exit is
1 and `snapshot_complete=false`, although `inventory_complete=true`.

The observed zone has `ssl=strict`, `min_tls_version=1.0`, `tls_1_3=on`,
`0rtt=off`, `origin_max_http_version=2`, `ech=on`, and Bot Fight Mode off.
The diagnostic hostname has no address records. No value was changed. The
available dashboard session required login, so no dashboard gRPC state was
verified. The API error establishes an unavailable read, not missing token
scope, a disabled feature, or an accepted gRPC carrier.

The bounded actual receipt is
`/private/tmp/aegis-g1-fronted-snapshot-44c024f5-actual-r2/receipt.json`
(SHA-256 `2cad1d5e1c8e8ace146ac92efd96740fbb68e22233c64a7b37ff297ca815a8d3`);
its private snapshot SHA-256 is
`f3aa0153dd74967a829b4b6a4173f85c949fe50ad445c8fa1fc7cb9f336e7670`.
Raw replies, account identifiers and rule material stay outside Git.

Qualified source `501656b13ea2fd81467a09f3637527d3b7a4abb2` adds complete
pre-effect rejection of stale TLS downgrade/Bot Fight Mode disable plans and
refuses an incomplete settings snapshot. It preserves a stronger TLS minimum
instead of replacing it with 1.2. Actual offline checks pass 11/11 and 8/8;
the 3,176-file source manifest SHA-256 is
`7b8e0f63949d3dfe4e0cea7e35cc02f37420de922939716eca6b709b3342658e`.
The qualification receipt SHA-256 is
`9b6f6a9591c2ce7a03ca381c37d3d0f0ca95ca1d9bc42573c9c44c6f4145954f`.

Remaining: a source-bound origin deployment and independent inverse, a valid
way to establish gRPC availability, zone write authority, actual DNS/certificate
and host-scoped rules, enrolled renewal/positive traffic, ECH G3/G4 and all
installed, physical capture, independent/endurance and exact-final-CI gates.
These read and planner results provide no installed or release credit.

## D6 local diagnostic product/operator binding — 3 November 2026

The local LiveKit fixture's v2 admission binds the frozen `d3407156` product
manifest, a separately reviewed client/server build receipt, the current QA
operator manifest and exact committed helper bytes. Only the listed QA and
documentation paths may differ from that product source. The earlier v1
same-source fixture contract remains strict. This permits one future unique
corrected-loopback component attempt after source and resource review; it is
not a positive media result or an installed SFU grant. The historical R9
candidate bytes were not retained, so its `trickle` subcause remains unknown.

## B-06 source boundary — 3 November 2026

Combined source `557a0180b1e769eea15c6cae77bfe2e932805371` is an
independently reviewed **source candidate**, not a compiled or installed
protocol acceptance. Transactional ECH rotation retains immutable per-flow
generation and eligibility: a rejected rotation cannot publish a partial pool
or turn an ineligible direct same-SNI route into an ECH route. The corrected
ECH source `426839a5` received scoped source review; the earlier `3a21b17c`
attempt failed review and remains retained.

The optional `enrolled-quic` client (`968b1c78`) and provider dispatch
(`118738a4`) have scoped source reviews for root-held CA and UDP lease,
WorkGate lifetime, exact generation/epoch, first ACK, re-ACK, and TCP-only
application flows on the selected QUIC carrier. Default admission remains
off; no final combined native tests, signed build, live QUIC, installed D4–D6
or standalone SFU acceptance has run. The prior `3a2e411f` QUIC and root
P0 source attempts remain failed evidence. Real Cloudflare G1 zone write
authority, deployed relay and ECH G3/G4, physical multi-interface and sleep
captures, independent endurance and exact final CI are still required.

The [Stage 6 capacity estimate](stage6-capacity-estimate.md) describes a
separate-host web-response/ledger/bridge/SFU pilot and its unverified costs.
The [own HTTPS bridge jump-host pilot](own-https-bridge-jump-pilot.md) now has
a source-bound private renderer and a bounded future rollback plan for the
free jump host. Its inert checks establish template admission only; the
binary, signed profile, listener and installed transfer are not accepted.
The local private pilot material generator now has actual OpenSSL 3.6.3
source-bound evidence for own CAs and the shared bridge admission, with a
failed first macOS FD-path attempt retained. These short-lived certificates
are not public-browser trust or a deployed bridge.

The public profile can declare a bounded order of enrolled carrier endpoints.
The order is covered by the existing four-file device bundle digest and checked
again against the installed runtime. The client tries the next endpoint only
after a typed failure before device authentication or application bytes. Once
payload has opened, it does not replay it to another endpoint. Every admitted
opaque route enters the existing inner device TLS and authorization lease.
The enrolled QUIC candidate below uses the existing UDP listener with a
separate fixed CONNECT authority; it adds no public credential path.

`relay.carrier_program` in a standalone configuration and `carrier_program` in
an `aegis_device_bundle_v4` public profile have the same route schema. Each
route refers to a numeric `relay.endpoints` / `relay_endpoints` pin. In the
public profile, the primary endpoint still occupies index 0; route order may
start at a different index. For example, when index 0 is an operator-declared
fronted H2 address and index 1 is an operator-declared direct H2 address:

```json
"carrier_program": {"routes": [
  {"channel": "direct_h2", "endpoint_index": 1},
  {"channel": "fronted_h2", "endpoint_index": 0}
]}
```

This is a declaration of route roles, not proof that the second endpoint is
Cloudflare or that any region admits it. The source checks unique numeric pins,
bounded exact coverage, enrolled inner TLS, empty legacy token, rustls and
`grpc_stream` only. Each outer TLS name must parse; a fronted route requires
a DNS SNI rather than an IP literal. With endpoint bandit absent, the declared order is used
for every session. The existing optional endpoint bandit uses this order as
its cold-state baseline, then can rank the same authenticated pins from real
pre-auth outcomes, with its own bounded state and no probe or replay. A
pool-wide ECH setting cannot be mixed with direct H2. A signed fronted-only
scope confines the offer to its exact fronted route; direct never inherits
it. Fronted H2 uses the existing pinned ECHConfigList, which refuses a rejected
offer before device credentials. An own HTTPS bridge now has a public, signed
declaration of its authority, traffic path and enrollment path. Its credential
file stays in the protected private sidecar. Public preflight checks the route
and path grammar without reading the sidecar; an installed render requires the
private authority and both paths to equal the signed declaration exactly.
One to six unique numeric endpoints may include direct/fronted H2, the own
bridge, authenticated WebSocket, web response and enrolled QUIC in that order.
Each role occupies at most one endpoint; a bridge-only pool remains supported.
The selected endpoint carries its signed channel role: direct/fronted
attempts omit the private bridge credential, while a bridge attempt uses it
only at the declared authority and path. Ordered pre-auth retry and optional
endpoint learning operate within this pinned pool. This does not authenticate
a different bridge or change the server's existing exact HTTP/2 gate. A
missing, changed or untrusted sidecar refuses the installed route before
dial. Public `--validate-only` is a non-writing planning check, not proof
that the private credential exists.
The default ECHConfigList applies to the entire TLS endpoint pool and requires
one DNS name for every endpoint. A mixed pool instead declares signed
`"ech_scope":"fronted_only"`. If the fronted route is not primary,
`"fronted_ech_authority"` must equal that route's signed DNS name. The
fronted attempt retains mandatory ECH; direct, bridge, WebSocket, web response
and enrolled QUIC attempts omit it. Bridge and web routes receive only their
own private admission keys. The QUIC device certificate is offered only on
the signed direct enrolled QUIC route, never to a fronted CDN route. The client refuses
a rejected fronted ECH offer before device credentials, then may try the
declared bridge under the ordinary pre-auth-only retry rule. This is source
policy and local tests, not Cloudflare/ECH deployment or installed acceptance.

The six-role order is source admission only. UDP remains limited to explicit
direct H2 and own-bridge datagram endpoints; fronted, WebSocket, web response
and enrolled QUIC TCP fallback labels do not acquire UDP capability. No
application byte or target-open request is replayed after inner device
authentication. The enrolled QUIC branch below still has zero Rust execution;
the pool has no installed or restricted-network acceptance.

```json
"carrier_program": {
  "routes": [
    {"channel":"direct_h2","endpoint_index":0},
    {"channel":"own_https_bridge","endpoint_index":1}
  ],
  "bridge":{"authority":"bridge.example.com",
    "path":"/private/stream","enrollment_path":"/private/enroll"}
}
```

The H2 labels apply to TCP. When the same enrolled profile enables
`grpc_datagram`, only an explicit direct H2 or own bridge route can supply its
UDP endpoint. The fronted H2 route is not silently promoted into a fronted
datagram endpoint; a fronted-only profile requesting UDP is refused before
runtime. The existing UDP no-replay and fail-closed behavior remains in force.

| Channel | Source entry point | Current product status |
| --- | --- | --- |
| Direct H2 and operator-declared fronted H2 | `grpc_stream`, inner device TLS, enrollment registry, ordered endpoint pool | Route configuration and pre-auth fallback implemented. No new installed or restricted-network acceptance. |
| Direct / fronted gRPC datagram | Authenticated `grpc_datagram` UDP plan for direct relay; fronted UDP path not accepted | Direct source and prior scoped checks exist; CDN datagram, installed route program and target-network acceptance open. |
| Pinned ECH | Outer TLS ECHConfigList validation/offer | Existing fail-closed pinned offer source; discovery, deployed Cloudflare ECH and independent acceptance open. |
| Brain selection | Transport ranking and bounded authenticated endpoint learning | Signed H2 route order feeds the latter; installed route-learning and cross-profile WS/MASQUE selection open. |
| Own HTTPS bridge | Signed public authority/paths, private H2 credential and existing server admission gate | Signed source and protected render exist; the local direct-unavailable→own-bridge transfer test is present, while exact final-source execution, installed cohort, deployment and Russia tests remain open. |
| `https_ws` | Dedicated RFC 8441 extended CONNECT on `/v2/device/ws`, bounded binary stream carrying the existing inner device TLS | Source path for a signed direct H2 then WebSocket TCP fallback. Server must explicitly enable `transport.secure_websocket_path` at the fixed path; legacy shared-token WebSocket uses separate mounts. Exact focused macOS ARM64 Rust 4/4 passed at `4fa8f9ec`; installed and restricted-network acceptance remain open. |
| MASQUE/QUIC | Legacy token CONNECT/CONNECT-UDP is separate; candidate enrolled direct H3 CONNECT carries inner device TLS at a synthetic authority | Enrolled TCP route source exists but has zero Rust execution and no installed acceptance. Enrolled UDP remains direct gRPC datagram; legacy MASQUE UDP is not admitted by the signed profile. |
| Geneva | Explicit Linux outer request | Separate opt-in source; real TSPU acceptance open. |
| Hosted web response | Local web carrier and ledger | Replica continuity, deployment and restricted-network acceptance open. |
| Direct WebRTC | Explicit native ICE/DTLS/SCTP DataChannel with inner device TLS | Separate optional command, not the signed six-route profile or an SFU media claim; installed restricted-network acceptance open. |
| WebRTC/SFU media | Optional one-use broker TLS grant, bounded VP8 LiveKit RTP publisher/subscriber and inner device TLS source | R8/R9 compiled and passed focused parser/real-peer controls, then both failed the first positive local LiveKit admission at `trickle` with no target hit. QA-only fixture admission now refuses stale R9 loopback settings. No positive media, installed or independent-network acceptance; default product `SfuMedia` remains unsupported. |
| Same-address renewal on 443 | Existing enrollment authority and relay remain separate listeners; an inert TLS passthrough SNI front source is available | No deployed/shared 443 routing or friends' renewal acceptance. |

The target program remains installed Linux and notarized macOS, actual TCP/UDP
where supported, independent leak captures, automatic safe fallback, multi-vantage observations, and full research/audit gates. `example.com` is the
approved domain. Cloudflare is excluded from the field-test path; an owned
bridge/direct route must be tested there. Neither an operator label nor these
source tests substitute for those outcomes.

## Enrolled WebSocket fallback contract

## Enrolled direct QUIC carrier candidate

The signed `masque_quic` route is a distinct direct UDP/443 H3 CONNECT
carrier for the existing enrolled device TLS stream. It is admitted only
after a signed direct H2 endpoint. Its fixed synthetic CONNECT authority is
`device.aegis.invalid:443`; it is never resolved or dialed as a target. The
server must opt in with `transport.secure_quic_authority` on an inner-TLS-only
origin with an empty legacy token. This opt-in makes the QUIC listener require
the issued device certificate in its outer TLS handshake; a bare H3 CONNECT
without that certificate never receives the special enrolled H3 200. This
outer check proves issuer possession. A source successor now also checks
the exact outer leaf against the current static pin or watched enrollment
registry before the enrolled 200. A revoked, unlisted or stale-registry leaf
receives the ordinary H3 decoy instead. This second check has no target lease;
the independent inner registry still authorizes the target. These new
negative checks and the prior route regressions passed 9/9 focused macOS
ARM64 Rust tests at exact `a372ee34`. This is local source execution, without
installed or restricted-network acceptance. The client presents
the same protected device identity only on this signed direct QUIC route.
The independent inner TLS registry and authorization lease still decide
target access and revocation. The QUIC socket and TLS authority are
those of the signed endpoint; alternate MASQUE sockets, CDN/fronted ECH,
and legacy token CONNECT/CONNECT-UDP are excluded. The client trusts only
the issued outer CA, then performs the unchanged device certificate and
target policy exchange. The QUIC admission permit is promoted only after
device authentication. A dedicated endpoint closes on cancellation, and the
existing bounded QUIC keepalive/idle policy applies. This first enrolled
route carries TCP only; signed
UDP continues through the admitted direct gRPC datagram endpoint. Existing
legacy MASQUE direct UDP is a separate operator profile and is not silently
admitted into an enrolled device bundle.

The exact `fa726812` focused macOS ARM64 batch passed seven local Rust
selections, including QUIC no-certificate H3 non-200, wrong-device refusal
and device-target reverse FIN. Installed Linux and macOS, physical leak checks,
and independent multi-vantage observation are still required. It makes no
Cloudflare QUIC claim.

The signed route `https_ws` is admitted only after one direct H2 route, with
distinct numeric endpoint pins and no fronted ECH or HTTPS bridge credential.
The route implies the fixed protocol path `/v2/device/ws`; the client does not
read the local legacy `websocket_path` to select it. The server enables this
path explicitly with `transport.secure_websocket_path = "/v2/device/ws"` on an
inner-TLS-only origin. Configuration refuses path overlap with legacy
WebSocket or gRPC, a shared token, or an own-bridge gate. RFC 8441 binary
frames contain the unchanged device TLS stream; an empty binary frame marks
one direction's FIN, leaving reverse responses available. Text frames refuse.
The client may try the declared WebSocket endpoint only after a typed failure
before device authentication; target opens and application bytes are never
replayed. UDP continues to use the direct H2 endpoint. Exact source
`4fa8f9ecfcf51b2b26a7b6c21e208da3b35ae748` passed four focused
`cargo test --locked --offline` selections on macOS ARM64: two bounded WS
adapter checks, one server path/auth check and one real local client/server
direct-failure → signed-WS → device-TLS → half-close/response check. The
private focused receipt is
`/private/tmp/aegis-b08-ws-focused-evidence-4fa8f9ec-r1/receipt.json`
(SHA-256 `1379406189f50aec64dbfb74ea7c366b48e236819423064f252a3641a5053286`).
The earlier undefined fixture, sandbox bind refusal and H2 `CANCEL` failure
remain in that receipt. The latter revealed that binary FIN must also finish
the underlying H2 send half; the final test passes after that source fix.
There is no installed transfer, CI, public edge or field-test acceptance.

## Separate-role renewal on one public 443

`scripts/render-carrier-443-sni.py` creates a candidate HAProxy TCP front for
two distinct public TLS names on one IP:443. It routes raw TLS to two distinct
loopback listeners, leaving the relay and enrollment authority as separate
processes with separate TLS and signing keys. It rejects nonnumeric public
binds, public backend binds, the same SNI/loopback target for both roles and
existing/unsafe output files. An unknown SNI has no backend server. This does
not route by encrypted HTTP path, install HAProxy, bind a fleet port, alter
firewall rules or grant renewal access. The public bundle must pin the same
public IP:443 for `relay_server` and `enrollment.authority_server` with the
corresponding distinct outer TLS names; each backend must have its own valid
certificate and existing inner authentication. Do not place an ECH-enabled
profile behind this SNI front: HAProxy sees only the outer ClientHello name,
which its [configuration manual](https://docs.haproxy.org/2.8/configuration.html#req.ssl_sni)
warns cannot identify the encrypted inner destination. The separate
Cloudflare/ECH path needs its own reviewed routing. Real same-port renewal
remains an independent acceptance check.

## Historical macOS action carried by this source parent

The carrier parent `f3422fe8` included an earlier B-06 typed-owner action
in the shared roadmap. The Linux `9b2f1424` parent carries a later Claude
v31–v37 action cell, which remains byte-identical in the union. The earlier
wording is retained as historical parent context in the B-08 roadmap note;
it does not supersede or add to Claude's active B-06 plan.


## 2 November — Alma carrier route fixture and focused core module

The first source-bound local carrier batch on AlmaLinux x86_64 used shipping
source `13741fd9` and its unchanged default plus Chrome-like TLS release
client/server ELFs (`b2c21b6f` / `69a5b5c4`). Eighteen exact local selectors
ran: **17 passed, one failed** in a stale test fixture that declared two
`OwnHttpsBridge` routes despite the current unique-channel signed policy.
The failure log SHA-256 is `9d88a19c`; its independent stopped-unit POST is
`44a2dd7c`. No production validator was loosened.

Test-only child `c2ea9e1f` changed that fixture to a signed direct-then-bridge
pool while preserving private credential, same-authority and legacy
standalone checks. Its full ten-test `carrier_program::tests` run exposed a
second stale expectation: direct-before-QUIC was asserted to fail even
though the signed policy admits it. That **9/10** failure, log `9b0d7e78`
and stopped-unit POST `ed843626`, remain retained. Test-only child
`0f795fd7` asserts the admitted order and refuses reversed QUIC-before-direct.
Its filtered 3,099-file manifest SHA-256 is `a21a059c`; the production bytes
before `#[cfg(test)]` are identical to shipping `13741fd9`.

The unique R9 Alma unit, QA operator `92ac8f21`, built only an `aegis-core`
release-profile test ELF with `device-enrollment`, listed the ten exact
selectors and executed the whole module once: **10/10 passed, zero ignored**.
Actual result SHA-256 is `55c64a33`, run log `988404ca`, and independent
POST `b2490ac1` verifies PID zero, no cgroup, stopped rollback timer,
inactive private swap removed, unchanged shipping ELFs and both failed
attempts retained. Eighty execution text receipts and 18 local provenance
JSON files were verified in private HOME custody (`02302d5d`); no source tar
or binary is in that custody. This is focused fixture/source evidence on
AlmaLinux, not a new 18/18 on `0f795fd7`, installed traffic, native39 or CI.


### [B-03] — 3 November: second direct-H2 Mac fixture

Source `207fedf09b183c7698529b99ba873ca7218e9e7a`, helper SHA `5c45923d1b78464f18955eb825286c03ba332f25ea01472da122fcbb3d67d947`, reproduces the second direct-H2 relay and issuer on ports 9446/9447 of the existing free Mac test relay. Original 443/9445 services, original configs and existing registry are preserved. Both issuers intentionally share the locked monotonic registry; rollback never copies or restores it. Per-host differences are the new listeners, RuntimeDirectoryMode0750 required by the status socket, separate profile/issuer digest and source-limited TCP access. An owned nft rule drops all UDP on both new ports and TCP from other sources; the source address stays in private state.

R1 refused an nft closing-brace syntax error before effects. R2 refused the new status socket's 0700 runtime-directory mode and ran its independent closer; fresh SSH showed new listeners/PIDs absent and original services unchanged. Exact failed units/table/timers were retired only after source/hash/PID0 checks, while private attempts remained. R3 preparation and guarded apply passed. Two new SSH connections reverified original and new services, exact units/access rules and absolute expiry; Mac-origin TLS verified the exact public CA, hostname, TLS1.3 and h2 on both new ports. Only then was the short 600-second rollback disarmed; the absolute closer remains due 3 November 08:00 Europe/Madrid (07:00 UTC). Static units are not enabled for boot.

Private receipts remain in `/private/tmp/aegis-macos-two-pin-deploy-20261102-r3/`. The exact four public files were transferred to disposable `/private/tmp/aegis-macos-two-pin-client-exec-20261103-r1`; profile digest is `48062503818f2c264864e9b4add466ab337461e8f5f3a4589604281690bd141f`. No new private device identity or invitation was created in this step. Normal CLI prepare/inspect/enroll/import, installed primary/secondary switching, policy ACK/re-ACK and negative traffic remain required. Two listeners on one host do not establish an independent/CF network path or complete B-03/B-06 acceptance.
## 3 November — G1 read-only settings index and unresolved gRPC admission

Source `8a42fed1aa2763a9c3fc124131bfb22805072ca5` adds a distinct GET-only
settings-index diagnostic to the bounded collector; all 11 inert controls
execute successfully, including three new scope/duplicate/admission controls.
Exact filtered source manifest (3,176 files) SHA-256
`b5f4184203063b2bf071ee48e46d1032a1213fb4d4c2bcea46631c869b6018e0`.
Actual three-request receipt SHA-256
`3a923b142cea2f9425ab65fe1c97cc8b559fb5318232f3f2cc24f198360a5c6c`,
supervisor `715e16ebc0edc6ef2bd0471fcb3bd8548c878a3ed802bad44938b5068b4ff055`,
all HTTP200, worker terminal0 and no absolute deadline hit. Private raw
settings-index SHA-256
`32e257e44962343deb4a5867fde217d70f58a8365df2e39e608530f9bae60400`.
The exact zone advertises56 setting IDs without `grpc`; the separately named
`long_lived_grpc` is off/noneditable. No alias, normal-gRPC enablement or plan
availability is inferred from that name. Full snapshot completion stays false;
this diagnostic schema and absence of snapshot.json cannot admit a deployment.

Cloudflare's [current gRPC procedure](https://developers.cloudflare.com/network/grpc-connections/)
describes the domain Network dashboard toggle and requires a proxied443
TLS/HTTP2/ALPN endpoint. We have not authenticated that dashboard or observed
an installed positive G1 route. Required gRPC admission, exact origin/inverse,
DNS/certificate/rules, enrollment, ECH and independent/endurance/final CI remain
open; existing security settings are unchanged and incomplete plans still refuse.
