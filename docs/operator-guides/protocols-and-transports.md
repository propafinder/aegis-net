# AEGIS transports and protocols

Current profile guidance, reconciled 2026-10-11. It describes carrier and trust
selection; it does not establish browser equivalence, general DPI resistance,
or admission through an IP/domain allowlist.

## Profiles and transport families

The legacy library TCP default is `[https_ws, grpc_stream, masque_derived]`.
The shipped `config.example.toml` explicitly adds `legacy_tls`; it is a direct
legacy example, not a Cloudflare or device-enrolled deployment. Use an explicit
`[grpc_stream]` plan for the fronted profile.

| Transport | Wire | Audited normal Cloudflare edge | Profile scope |
| --- | --- | --- | --- |
| `https_ws` | TLS offers `h2,http/1.1`; RFC 8441 Extended CONNECT over H2 | Rejected: audited edge lacked Extended CONNECT | Explicit compatible legacy endpoints; ordinary h1 WebSocket support is insufficient |
| `grpc_stream` | gRPC over HTTP/2, ALPN h2 | Legacy forced carrier accepted with zone gRPC and H2-to-origin | Fronted legacy or device-enrolled TCP; enrolled CDN acceptance remains separate |
| `grpc_datagram` | Authenticated datagram messages over HTTP/2/TCP | Retained dated legacy canaries cover the fronted data plane | Legacy fixed-destination UDP; device-enrolled UDP, including SOCKS UDP association, when enabled |
| `legacy_tls` | Raw AEGIS framed stream over TLS | Direct only | Explicit legacy use; excluded from the library default and inner TLS |
| `masque_derived` | Direct QUIC/H3 CONNECT-UDP, UDP/443 | Outside orange-cloud HTTP proxying | Explicit legacy origin leg; unavailable with inner TLS |

For **legacy shared-token** fixed-destination UDP, an explicit
`[masque_derived, grpc_datagram]` plan attempts direct MASQUE first and gRPC
second, subject to compatible endpoints and retry policy. Direct MASQUE exposes
the origin connection and the client's source address to it. A Cloudflare-only
origin guard that drops direct UDP is incompatible with this leg. Select
`[grpc_datagram]` alone when that origin attempt is unacceptable.

For **device-enrolled inner TLS**, validation requires TCP `[grpc_stream]`, UDP
`[]` or `[grpc_datagram]`, Rustls, explicit outer `ca_cert`, disabled wire mimicry,
and a nonzero connection timeout. Shared-token, WebSocket, MASQUE and Direct/Auto
fallback are unavailable. The ordinary enrolled service uses the fixed path
`/tunnel.v1.Channel/Connect`, bypassing the legacy path pool. An opt-in private
HTTPS bridge uses its paired provisioned path while retaining inner device
identity. See [inner TLS](../operations/inner-tls-v1.md).

An isolated B-08 source candidate adds an optional signed v4
`carrier_program` for direct/fronted **relay endpoint** order inside that same
enrolled gRPC/H2 trust model. Here `direct_h2` names an origin route, not
Direct/Auto mode or a native-egress fallback. The candidate's UDP plan uses
only its admitted direct/own-bridge route; fronted gRPC datagrams remain
unaccepted. [Carrier program and complete channel-state register](../operations/carrier-program.md)
distinguishes source, installation and network acceptance.

## Selection and failure boundaries

`transport_priority` and `udp_transport_priority` are separate legacy plans.
When UDP priority is omitted, the compatible-family filter applies; it does
not silently create the explicit MASQUE-to-gRPC plan. The setting named
`rotate_transports_per_session` uses drift-epoch rotation. Adaptive transport
ordering and endpoint selection are explicit policy mechanisms, not a guarantee
that every attempt has a different browser fingerprint.

Endpoint failure handling depends on the profile and failure stage. Enrolled
TCP endpoint failover is bounded and retains mandatory trust/authentication;
an error after connection/inner authentication cannot trigger a legacy retry.
Multiple fronted authorities provide alternatives but remain individually
blockable. Allowlists, provider policy, or observable traffic features can
prevent every endpoint from being usable.

`relay_transport_selected` and `relay_session_succeeded` are carrier evidence.
The old RC11 persistent-flow MASQUE labels and RC12 promotion gate are dated
history. `masque_direct` may remain a stable capture-policy ID in an enrolled
full-wide profile; it does not identify the actual UDP wire carrier.

## Bundle and decoy diagnostics

The historical pre-v0.3.24 bug sent h2 `/bundle` downloads to the gRPC handler.
Current credential rejection and unknown paths can instead receive the
process's decoy status **403, 404, or 410**. A bare GET returning 404 is therefore
not a version test or proof of broken dispatch. Use the configured bundle prefix
and a controlled fresh valid credential through the private-file installer
workflow; keep access records out of command arguments.

Zone gRPC and H2-to-origin are required for the fronted gRPC contour. Enabling
ordinary WebSockets does not supply an automatic `https_ws` fallback. An outer
h2 handshake or an unauthenticated GET to a gRPC path is not tunnel acceptance.
Outer client-to-edge trust, edge-to-origin trust, and inner enrolled relay/device
trust are independent.

Historical Cloudflare acceptance is scoped to legacy shared-token profiles.
Protected gRPC implementation/native tests were not independently revalidated
for this documentation reconciliation; exact-candidate CI, installed lifecycle,
and enrolled real-CDN acceptance retain their separate evidence boundaries.

See [Cloudflare relay runbook](cloudflare-fronted-relay.md),
[Cloudflare operator guide](../cloudflare-fronted-operator-guide.md),
[legacy path catalog](../operations/relay-path-catalog.md), and
[private HTTPS bridge](../operations/https-bridge.md).
