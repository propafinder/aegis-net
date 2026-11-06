# aegis-server/src/session

Authenticated session handlers for secure streams, UDP, HTTP/2 gRPC, WebSocket, bundles, HTTPS bridge and QUIC/MASQUE.

## Contract

The parent session.rs admits carriers through the existing device channel before target resolution or contact. Parser/message bounds also protect unauthenticated entry stages. decoy.rs supplies uniform generic web responses for rejected requests, without claiming byte-for-byte origin or browser parity. HTTPS bridge does not perform arbitrary filesystem serving or forwarding.

Malformed legacy framed input uses the shared process decoy identity, Date and
generic HTML 400 response within the original admission deadline. It does not
reuse the cleartext-on-TLS explanatory page. The
[actual handler regressions](legacy_fallback_decoy_tests/README.md) also preserve
encrypted current/legacy-key responses and bounded blocked writes.

Authenticated legacy TCP additionally uses one finite target-establishment
budget, a shared byte-progress idle policy and independent stalled write/flush/
half-close deadlines. Active and asymmetric sessions keep their full lifetime
while bytes progress. See [legacy TCP policy and source fixtures](legacy_tcp/README.md)
for defaults, operator limits and the finite ownership regression cases.

Bundle redemption validates the exact issued 64-byte lowercase hex token format
before taking the endpoint mutex. The store repeats that guard before OS locking
or reload. Valid-format credentials still require fresh locked authorization,
revocation rechecks and durable one-time commit. Canonical misses, request
admission and per-peer fairness remain separate open work.

TCP admission starts one `limits.read_timeout_ms` deadline before socket peek
and outer TLS. HTTP header peek, WebSocket upgrade/first authenticated open,
H2 establishment and first authentication consume that remaining budget.
Ready buffered proofs are checked against the original cutoff after the read
and before the authentication transition; an expired timer cannot be bypassed
by ready I/O. The device channel also checks its original establishment cutoff
before Open/PolicyAck processing, target contact and successful ACK completion.
Unauthenticated H2 requests and public replays cannot renew it. Once authorized
requests complete, an idle H2 connection expires after the same timeout. H2
limits apply to every authentication mode: 32 streams, 8 KiB header lists,
128 KiB stream/connection windows and send buffers, and eight retained resets.
The initial legacy gRPC open rejects lengths above 8 KiB from the five-byte
prefix before copying a payload; authenticated data keeps the existing 1 MiB
message ceiling.

Before taking the shared connection permit, TCP also applies
`limits.max_unauthenticated_connections_per_ip` (32 by default) to the kernel
socket peer IP. Device/token proof releases this setup quota, while the global
connection permit remains held for the connection lifetime. The quota map
contains at most 4096 active IPs and removes an IP when its last setup permit
drops. It never uses forwarded headers: an origin behind a reverse proxy has
32 concurrent unauthenticated sockets per proxy source IP by default, so this
layer does not claim fairness between end users behind the same proxy. Verified
forwarded identity quotas apply separately in the inner device channel. QUIC
admission is outside this TCP quota.

## Authenticated shaping cleanup

The authenticated secure carrier holds authorization and its session permit while it cleans up the installed shaping worker after forwarding returns or revocation interrupts it. Forwarding is dropped before abortion and join, so pending carrier references cannot keep the transport open during cleanup. One independent 500 ms cleanup cutoff bounds the asynchronous observation. A successful cleanup requires observing the original task terminal state; a timeout or failed observation does not claim quiescence. The original authentication, establishment and forwarding deadlines remain unchanged.

The causal regression covers the adaptive profile with authenticated inner device TLS, in-memory H2 transport and a real local TCP target. It observes carrier Drop from the same server terminal poll and verifies that the session permit was still held then and is available after return. This is a local installed-server ownership check. It does not establish native outer TLS/H2, Windows or fleet acceptance, production client cleanup, or cleanup after abrupt abortion of the whole handler.

## Key files

- [legacy_tcp.rs](legacy_tcp.rs)
- [secure.rs](secure.rs)
- [secure_udp.rs](secure_udp.rs)
- [grpc.rs](grpc.rs)
- [websocket.rs](websocket.rs)
- [bundle_endpoint.rs](bundle_endpoint.rs)
- [decoy.rs](decoy.rs)
- [https_bridge.rs](https_bridge.rs)
- [quic.rs](quic.rs)

The enclosing module is [session.rs](../session.rs); this directory contains its split implementation or test modules.

## Directories

| Directory | Responsibility |
| --- | --- |
| [grpc/](grpc/README.md) | Windows production cooperative-I/O adapter and synthetic authorized TLS/H2 progress regressions. |
| [fresh_legacy/](fresh_legacy/README.md) | Fresh legacy authentication-path fixtures beneath session.rs. |
| [quic/](quic/README.md) | Typed internal startup phases for optional or required QUIC ingress. |
| [legacy_fallback_decoy_tests/](legacy_fallback_decoy_tests/README.md) | Actual legacy handler response, encryption and deadline regressions. |
| [legacy_tcp/](legacy_tcp/README.md) | Authenticated legacy TCP establishment, idle/write policy and owner fixtures. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-server --lib session
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-server](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)


## Device-carrier logging policy

The public `serve_device_carrier` compatibility entry uses default-private
logging. Crate runtimes use `serve_device_carrier_with_logging` to carry their
immutable configured policy into secure TCP/UDP target handling. The opaque
carrier and WebRTC owners also pass it to their rate limiters. This does not
change authentication callbacks, target authorization, transport selection or
admission deadlines. Returned errors and panic-hook stderr require their own
output/retention review; helper capture does not prove every wire path private.
