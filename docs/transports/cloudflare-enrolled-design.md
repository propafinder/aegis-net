# Cloudflare-fronted enrolled carrier (D1) and ECH over it (D2)

Status, 2 November 2026: **source and local evidence only.** This document
records the audit of the device-enrolled, CDN-fronted path at the Linux source
`92456fae`, the design implemented on branch `degree/b08-cf-enrolled-20261102`,
the local checks actually executed, and the remaining work. Nothing here is a
real-Cloudflare, installed-client, target-network or leak acceptance. The real
deployment is prepared, not executed, in the
[runbook](../operations/cloudflare-fronted-enrolled-runbook.md).

"Integrated" follows the carrier-program definition: enabled in the installed
Linux DEB and notarized macOS NE client, real TCP and UDP to destinations
through the relay, no leak and no weakened check, automatic failover between
carriers covered by a test, checked from the agreed vantage points, receipts,
change-log entry and roadmap row. This branch closes source gaps for D1/D2;
the installed and real-network parts remain open (see the last section).

## 1. Audit at `92456fae`

What already existed and was reused unchanged:

| Area | State at `92456fae` |
| --- | --- |
| Client schema | A v3/v4 public profile (`bundle.json` + `outer-ca.pem`, `inner-ca.pem`, `device-ca.pem`) can already name an edge host as `relay_server`, the edge name as `outer_server_name`, an independent `inner_server_name`, `udp: true` (enrolled UDP = `grpc_datagram`) and an online `enrollment` block. Inner TLS forces `grpc_stream`, explicit outer CA, Rustls, no mimicry. |
| Carrier | `POST /tunnel.v1.Channel/Connect`, `application/grpc`, inner device mTLS inside one bidirectional gRPC stream; UDP is the inner `Transport::Udp` with length-prefixed datagrams in the same stream, so it is CDN-compatible (not MASQUE). |
| Pre-auth failover | Non-200 carrier responses (CDN 403/404/503, ...) and dial failures are retried on the next endpoint before any identity, invitation or target is sent; post-auth failures are never replayed. |
| ECH | One pinned ECHConfigList (`ech_config_list`, digest-bound); required ECH must be `Accepted` before H2. |
| Enrollment | Separate authority process and listener (`/enrollment.v1.Authority/Exchange`), end-to-end enrollment TLS, idempotent receipts; renewal reuses the same carrier. |

What was missing for a Cloudflare-fronted enrolled deployment:

| # | Gap | Consequence |
| --- | --- | --- |
| A1 | **No origin authentication behind the CDN.** Any client reaching the origin IP could open `/tunnel.v1.Channel/Connect` and reach inner TLS. | The origin is discoverable by direct probing (inner TLS handshake behind an H2 POST), and the CDN is optional for an adversary. |
| A2 | The inner-TLS H2 listener advertised `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 8441) and sent HTTP/1.1 to the raw legacy TLS path. | Fingerprint and an unused code path on an origin that should only speak gRPC. |
| A3 | **Per-connection admission clock.** All streams on one TLS connection shared one admission deadline; at that deadline without an active lease the connection was dropped and every in-flight stream aborted. | A CDN multiplexes independent clients on one pooled origin connection: a client starting a handshake shortly before the pooled connection's deadline was cut (reproduced locally, see section 5). |
| A4 | gRPC responses ended with a bare END_STREAM, no `grpc-status` trailers. | Not well-formed gRPC for a gRPC-aware CDN proxy (exact Cloudflare behaviour unverified; see R1). |
| A5 | QUIC/H3 ingress opened next to a fronted origin. | UDP surface that a CDN never uses; only aids origin discovery. |
| A6 | **No same-port renewal ("variant B").** The authority listens on its own port (the macOS test relay: 9445, allowlisted to one IP). | Devices other than the owner's Mac cannot redeem or renew; through a CDN the authority is unreachable. |
| A7 | **ECH key rotation.** A pinned list is the only source; Cloudflare rotates ECH keys frequently. | A pinned profile fails closed permanently once the edge drops the pinned key. |
| A8 | No operator tool to obtain the zone's ECHConfigList; no fronted profile template, origin configuration, zone procedure or rollback. | Deployment is not repeatable. |
| A9 | Enrolled outer trust is one explicit `outer-ca.pem`; Cloudflare Universal SSL uses several public CAs (and `cloudflare-ech.com` for the ECH outer handshake). | The profile must pin the full edge CA set (validator limit: 8 certificates); a later CA change needs a profile migration (G2). |
| A10 | Full-wide (`full-wide-tun`) profiles require numeric IPv4 relay and authority pins. | A fronted full-wide profile pins Cloudflare anycast addresses of the zone; their change needs a profile update (G3). |

## 2. D1 design: fronted origin

```text
device (inner mTLS identity)
  -> TLS [+ECH] to <edge-name>:443 (Cloudflare edge, public CA)
     HTTP/2 POST /tunnel.v1.Channel/Connect      (traffic, TCP and UDP)
     HTTP/2 POST /enrollment.v1.Authority/Exchange (redeem/renew, variant B)
  -> Cloudflare gRPC proxy -> origin:443, Full (strict), one pooled H2 connection
     + transform rule: x-aegis-origin-key: <origin key>
  -> aegis-server [transport.fronted_origin]
       gate: exact :authority (and Host if present), POST, one
       application/grpc, exactly one valid origin key, fixed path
       traffic    -> inner device mTLS -> registry -> target policy -> TCP/UDP
       enrollment -> verified TLS/H2 pipe -> loopback authority (issuer key
                     stays in the authority process)
       anything else -> the process decoy (403/404/410), never inner TLS
```

Server configuration (`[transport.fronted_origin]`, type
`aegis_core::fronted_origin::Settings`):

```toml
auth_token = ""
fallback = "close"

[rate_limit]
# Cloudflare edge ranges (fetched at deployment); client identity then comes
# from cf-connecting-ip, never from the edge address.
trusted_proxy_cidrs = ["<CLOUDFLARE_RANGES>"]

[transport]
quic_required = false

[transport.inner_tls]          # unchanged exclusive device-enrolled relay
cert = "/etc/aegis/server/inner.pem"
key = "/etc/aegis/server/inner-key.pem"
client_ca = "/etc/aegis/server/device-ca.pem"
device_registry = "/var/lib/aegis/registry.json"

[transport.fronted_origin]
authority = "<edge-name>"                         # lowercase DNS name
credential_file = "/var/lib/aegis-relay/origin-pull.key"    # 64 hex, 0600
# next_credential_file = "/var/lib/aegis-relay/origin-pull.next.key"  # rotation

[transport.fronted_origin.enrollment_forward]     # variant B (optional)
authority_address = "127.0.0.1:9445"
server_name = "<authority outer certificate name>"
ca = "/etc/aegis/authority/outer-ca.pem"
max_concurrent = 8
```

Validation refuses the table unless the relay is an exclusive inner-TLS
origin: no shared or legacy token, closed fallback, no HTTPS bridge, no
bundle endpoint, QUIC disabled, explicit trusted proxy ranges, origin keys on
clean absolute paths separate from both TLS private keys, distinct rotation
keys, a lowercase DNS authority and a non-wildcard forward address.

Runtime behaviour (aegis-server `session/fronted.rs`, `session/grpc.rs`):

1. **Gate before anything (A1).** Requests failing any gate check receive the
   same per-process decoy as unknown paths. Client-supplied origin-key
   headers cannot help: the CDN transform overwrites the header, and the
   comparison is constant time over every configured key.
2. **gRPC only (A2, A5).** No `SETTINGS_ENABLE_CONNECT_PROTOCOL`; CONNECT is a
   decoy; HTTP/1.1 receives a bounded decoy page; QUIC is not started.
3. **Per-stream admission under pooling (A3).** Each stream gets its own
   admission budget (`limits.read_timeout_ms`) and the shared socket permit is
   released by the first authenticated device as before. At the idle deadline
   of a connection without an active lease the origin sends GOAWAY and drains
   in-flight streams instead of aborting them. Direct (non-fronted) relays are
   unchanged.
4. **Well-formed gRPC (A4).** The fronted traffic route ends its response with
   `grpc-status: 0` trailers (`H2Stream::with_grpc_ok_trailers`); the peer
   still observes an ordinary half-close. Direct relays are byte-identical.
5. **Variant B (A6).** `/enrollment.v1.Authority/Exchange` is admitted only when
   `enrollment_forward` is configured. The relay opens a fresh TLS 1.3/H2
   connection to the authority (verifying its outer certificate against `ca`),
   waits for the authority's `200 application/grpc`, then pipes bytes both ways
   under H2 flow control: at most `max_concurrent` streams, 256 KiB per
   direction, 45 s total, 5 s connect. A busy or unavailable authority is a
   plain 503 before any body byte; the device keeps its request and resumes
   (exact receipt recovery is the authority's existing protocol). The relay
   never holds the issuer key or sees enrollment plaintext.

Origin key (`x-aegis-origin-key`): 32 random bytes as 64 lowercase hex in an
owner-only file, injected by a Cloudflare request-header transform rule on
the edge hostname. It proves only that a request came through the operator's
CDN configuration; it is not a device credential and grants nothing without
inner mTLS. Rotation: deploy `next_credential_file`, switch the transform,
then promote. Optional defence in depth (runbook): an origin firewall that
admits 443 only from Cloudflare ranges.

Client side, no new schema: a fronted profile is an ordinary v3/v4 enrolled
profile whose `relay_server`, `outer_server_name` and enrollment
`authority_server`/`outer_server_name` all name the edge, whose
`outer-ca.pem` pins the edge CA set (A9), and whose `udp: true` selects
`grpc_datagram`. Linux `install.sh client --bundle ... --device-invitation-file`
and the macOS NE consume it unchanged; full-wide profiles pin numeric edge
IPv4 addresses (A10). Templates are in the runbook.

Failure classes seen by the client (unchanged classification, now exercised
through the edge): edge error pages (Cloudflare 52x/530, 403 challenge),
missing transform (decoy 403/404/410) and direct origin hits are non-200
carrier responses, i.e. pre-identity outages eligible for the next endpoint;
inner TLS refusal, target refusal and any post-open failure are terminal and
never replayed.

## 3. D2 design: ECH over the fronted carrier

**Source of the ECHConfigList.** The Cloudflare zone publishes an HTTPS
resource record with an `ech` SvcParam for each proxied hostname once ECH is
enabled. The operator reads it from a trusted network
(`dig +short HTTPS <edge-name>` or DNS-over-HTTPS), extracts it with
`aegis-client device ech-from-https-record --record-file <file>` (presentation
or RFC 3597 `\#` form; prints the base64 list and each config's id, KEM and
`public_name`), verifies a real handshake against the edge, and pins it as
`ech_config_list` in `bundle.json`. The pin enters the four-file profile
digest. The device never resolves DNS for ECH: plain DNS is observable and
spoofable from the censoring network, and DoH may be blocked.

**Rotation (A7).** The pinned list fixes the `public_name` (for Cloudflare,
`cloudflare-ech.com`). When the edge no longer holds the pinned key it rejects
ECH, completes the outer handshake authenticated **for that public name under
the profile's explicit `outer-ca.pem`**, and returns `retry_configs`
(RFC 9849 section 6.1.6). Rustls exposes these only after that authentication,
as the handshake error. `ech_policy::record_rejection` admits them only if every
retry config keeps a pinned public name and at least one config has a
supported HPKE suite; it caches them in memory for the same outer authority and
pinned list (at most 6 h, at most 64 entries). `outer_grpc` (traffic, PolicyAck
and enrollment) then redials **once** with the admitted configs; a second
rejection fails closed and clears the rotation. The held-connector path used
by the macOS provider (`connect_h2_from_held`) records the rotation and
returns the error; its next held connect uses it.

**Required-ECH semantics.** With a pinned list: TLS 1.3 only, SNI enabled,
no GREASE or cleartext fallback, `EchStatus::Accepted` required before ALPN
`h2` is used. On a rejected handshake only the outer ClientHello and the TLS
alert are sent: no HTTP/2 preface, no device certificate, no invitation, CSR,
target or credential. Retry configs never relax the public-name pin and never
loop.

**Not covered.** A changed `public_name`, a disabled zone ECH or a changed
edge CA set requires an explicit profile migration (G2); current
`OnlineMigration` only admits v1/v2 to v3. No DoH refresh is implemented.

## 4. Implementation map

| Change | Files |
| --- | --- |
| Fronted gate type, origin-key custody, ECH-independent enrollment path constant | `aegis-core/src/fronted_origin.rs`, `aegis-core/src/https_bridge.rs` |
| gRPC OK trailers on half-close | `aegis-core/src/h2_stream.rs` |
| Config table and validation | `aegis-server/src/config.rs` |
| Gate dispatch, no RFC 8441, per-stream admission, GOAWAY drain, trailers, HTTP/1.1 decoy, no QUIC | `aegis-server/src/session/{grpc,secure,quic}.rs`, `session.rs`, `lib.rs`, `session/fronted.rs` |
| Variant B forwarder | `aegis-server/src/session/fronted_forward.rs` |
| ECH rotation, ECHConfigList and HTTPS RR parsers | `aegis-client/src/ech_policy.rs`, `relay/secure.rs`, `prepared_outer_tls.rs` |
| Operator command `device ech-from-https-record` | `aegis-client/src/device_identity.rs` |
| CDN-like gRPC edge fixture | `tests/support/cdn_grpc_proxy.rs` |
| Prepared zone tool (snapshot, plan, apply with owner approval, verify, rollback, Origin CA) | `tools/cloudflare/fronted_zone.py` |

## 5. Local evidence (this branch, macOS arm64, `nice -n 10`, `-j 4`)

The CDN-like edge (`tests/support/cdn_grpc_proxy.rs`) terminates client TLS
with its own certificate, speaks HTTP/2 only, never advertises RFC 8441,
answers CONNECT with 405, re-originates every client stream on **one** pooled
H2 connection verified against an origin CA with the edge name as SNI and
`:authority`, strips client-supplied origin keys and injects the configured
one, adds `cf-connecting-ip`/`x-forwarded-for`/`cf-ray`, streams bodies and
trailers under flow control, and injects faults (edge-only status, mid-stream
reset, idle cut). It models the documented Cloudflare behaviour the carrier
relies on; it is not Cloudflare.

Executed suites and their results are recorded with exact counts in the
[change and incident log](../../CHANGELOG.md) entry
"[CP-D1/D2] Cloudflare-fronted enrolled carrier and ECH, local source batch".
They cover: TCP (256 KiB exact echo) and UDP (empty, small, 8000-byte
datagrams) through edge -> fronted origin -> inner mTLS; both streams on one
pooled origin connection; trailers observed at the edge; direct origin hits
(no key, wrong key, wrong length, other path, CONNECT, HTTP/1.1) and a missing
transform all receive decoys; RFC 8441 refused at edge and origin; a rogue
device CA refused by inner TLS with zero target connections; variant B
issuance through edge -> forwarder -> real authority; a late stream on a
pooled connection; the installed-product path (`device bundle-create`,
`prepare`, online `redeem`, `bundle-render`, relay TCP/UDP) and a due renewal
through the edge; an edge failing before identity leaving the registry
unchanged and the request resumable; and, with a real AWS-LC ECH server as the
edge's TLS terminator, accepted ECH end to end, one authenticated rotation
then cache reuse, fail-closed ECH-less edge, refused public-name change and a
rejected retry without a loop.

Failing-first evidence: with the per-stream admission/drain change reverted,
the pooled late-stream test fails; with fronted trailers disabled, the trailer
assertion fails; with the retry redial disabled, the rotation test fails; with
the public-name check removed, the public-name test connects and fails.

## 6. Risks to verify on real Cloudflare (first deployment window)

| # | Unknown | Check in the runbook |
| --- | --- | --- |
| R1 | Whether Cloudflare requires gRPC trailers or rewrites trailer-less responses | Fronted origin now always sends `grpc-status: 0`; observe a full TCP session end cleanly through the edge. |
| R2 | `:authority` and `Host` as sent to the origin | Gate accepts `:authority` plus an optional matching `Host`; a refused gate shows as a decoy status at the client. |
| R3 | Transform rules on gRPC requests | Verify step: traffic succeeds through the edge and a direct origin request is a decoy. |
| R4 | Idle stream timeout (about 100 s) and request body limit (100 MB on Free) for long gRPC streams | Measure an idle 120 s session and a 150 MB upload; inner idle default is 60 s. |
| R5 | Bot Fight Mode / Browser Integrity Check challenging non-browser gRPC | Runbook disables both for the hostname/zone and verifies status 200. |
| R6 | ECH availability on the zone's plan and the published HTTPS RR | Runbook step; without it D2 is not deployable and the profile stays non-ECH explicitly. |
| R7 | Edge CA set (Universal SSL issuers and `cloudflare-ech.com`) | Chain check against the pinned `outer-ca.pem` before distributing a profile. |
| R8 | Anycast address stability for full-wide pins | Record both edge IPv4 addresses; re-check before each profile issue. |

## 7. Remaining work to "integrated" (not done here)

| ID | Item | Owner/dependency |
| --- | --- | --- |
| G1 | Real deployment and acceptance: zone changes, origin with fronted relay and authority, European vantage | Owner approval; relay origin (relay-a replacement) |
| G2 | Trust-anchor and ECH public-name migration for v3/v4 profiles (CA set or public name change) | Source design needed; today a new profile and re-enrollment |
| G3 | Fronted full-wide profile with anycast pins; macOS NE held-dial ECH redial after a learned rotation. 2 November, B-06 v40 source (`degree/b06-carriers-20261102`): the NE admits the full pool (every pin numeric), its pooled dials redial once after an admitted rotation and forget it after a refused redial, and the renewal runs through an edge pin's 443 (variant B) beside the armed guard; no real edge or installed run yet | B-06 lane |
| G4 | Installed Linux DEB and notarized macOS NE windows with a fronted profile; leak captures (owner sudo window on macOS) | After G1 |
| G5 | Brain order direct H2 -> Cloudflare -> https_ws -> MASQUE with blocking simulation per carrier (stage 3). Source and local harness on `degree/b08-brain-failover-20261102`: [brain-failover-design.md](brain-failover-design.md); enrolled `https_ws`/MASQUE stay unadmitted; installed/macOS parts open | Claude (D3 source); B-06 and Codex for installed parts |
| G6 | Optional Authenticated Origin Pulls (outer mTLS from the edge) as an additional origin gate | Source change in outer TLS acceptor |
| G7 | CI for the exact final commit; `chrome-like-tls` lane must run `ech_edge_tests` | CI dispatch after owner approval |
