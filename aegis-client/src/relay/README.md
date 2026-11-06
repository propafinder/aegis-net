# aegis-client/src/relay

Relay endpoint selection, outer carrier setup, inner authentication and TCP/UDP transport pumps.

## Contract

Authentication and application requests must not be replayed on retry. Endpoint learning ranks an explicitly admitted pool. websocket, grpc and masque have different outer framing and authority rules; secure.rs supplies the independent device channel. Byte progress and half-close tests describe API/lifetime behavior, not physical packet delivery.

The enclosing relay module classifies a clean session with zero application
bytes in both directions as `NoApplicationTraffic`. The normal and Direct
hybrid consumers retain terminal `no_response_observed` evidence and skip
learning from that session. Genuine errors remain recordable; a sent request
without a response still supplies a stall sample.

Each attempt records separate monotonic durations for authenticated target
opening, its first nonzero application response read, and the whole attempt.
Shared observations are set once; control acknowledgements, zero reads,
Pending, EOF and read errors cannot become response samples. The original
whole-attempt duration still feeds classification and existing deadlines.
Normal and Direct hybrid learners use an observed opening only for success
latency. Missing opening evidence leaves the existing latency mean unchanged;
neither session duration nor an invented zero substitutes for it. First response
includes target think time and shaping and is not RTT or a delivery receipt.

Persisted means and legacy migration stay unchanged. Old lifetime samples may
remain in the EMA alongside new opening observations; this repair does not
reset, rewrite or reinterpret historical state or calibration. Historical
metric migration and native timing acceptance remain open under finding51.

## SOCKS UDP association ownership

The MASQUE association validates datagrams before latching the UDP peer,
drops malformed and unsupported fragments, and bounds the target map to 128
entries with 60 seconds of admitted uplink/downlink inactivity and a one-second
sweep. Target failures retire only that generation. Tagged downlink packets
must match the current target generation before activity refresh or forwarding.
The 256-entry uplink queue drops only the new datagram when full; it does not
wait inside the association dispatcher. A closed queue retires its owner.
The shared tagged downlink queue remains 256; an owned one-entry per-flow
bridge adds generation metadata without changing packet schema or wire framing.
Control close drops the map and aborts/awaits direct JoinSet children.

A failed current-generation target reports the existing transport failure event
and retires only that flow. The selected parent family is carried explicitly:
MASQUE and independent-inner-TLS gRPC associations share this owner. The event's
single attempt describes the child, not association fallback or endpoint-pool
history. Old-generation completion cannot report a failure against a reopened
flow; association terminal and success semantics remain separate.

The actual MASQUE wrong-path test retains failure/no-success assertions and
requires the association to stay alive until its explicit abort/join. The
both-family emitter check uses synthetic errors; it does not open a gRPC target
or prove native failure privacy. One existing MASQUE cleanup test exceeded its
unchanged 20-second watchdog in the full suite, then passed unchanged in an
isolated retry. Both attempts remain recorded; no clean first-suite pass or
native Windows acceptance is claimed.

Seven controlled checks pass: four preserved authenticated QUIC/H3/SOCKS
fixtures, one authenticated post-129-attempt known-flow exchange and two direct
production-helper queue/generation tests. Generation helper RED reconstructs the old target-only gate. Queue helper RED
is a Full-discriminator mutation negative control, not a representation of the
old awaited send or a native scheduler stall. Neither forces a live producer
race. Matched-generation activity refresh is source-reviewed; the helper
asserts stale no-refresh and current payload acceptance without advancing time. The structural 128-map bound is source-reviewed; wire absence
of target129 does not prove every preceding target authenticated. Simulated
60-second idle and the real 20-second fixture watchdog are separate. Payload
heap, native pressure, indirect workers, fixture server Drop-only cleanup and
installed acceptance remain separate; these checks do not prove all cleanup.

## Key files

- [secure.rs](secure.rs)
- [grpc.rs](grpc.rs)
- [websocket.rs](websocket.rs)
- [masque.rs](masque.rs) and [association ownership tests](masque_association_tests.rs)
- [tls_backend.rs](tls_backend.rs)
- [tls_read_fairness.rs](tls_read_fairness.rs) — Windows Rustls socket-read fairness;
  [controls and owned TLS/H2 fixture](tls_read_fairness_tests.rs).
- [endpoint_bandit.rs](endpoint_bandit.rs)
- [carrier_failover.rs](carrier_failover.rs) — ordered enrolled-pool failover, block signals,
  liveness and per-network memory; [fault harness](carrier_failover_tests.rs)
  ([design](../../../docs/transports/brain-failover-design.md)).
- [byte_progress.rs](byte_progress.rs)
- [geneva_outer.rs](geneva_outer.rs)
- [learning_tests.rs](learning_tests.rs) — typed outcome and error controls;
  [normal consumer tests](../relay_learning_tests.rs) and
  [Direct consumer tests](../direct/relay_learning_tests.rs) exercise real Brain updates.
- [latency_tests.rs](latency_tests.rs) — actual authenticated TLS owner and held
  lifetime witness; [timing controls](timing_controls_tests.rs) cover observations
  and history, with unchanged causal assertions in the
  [normal](../relay_learning_latency_tests.rs) and
  [Direct](../direct/relay_learning_latency_tests.rs) consumers.

The enclosing module is [relay.rs](../relay.rs); this directory contains its split implementation or test modules.

## Windows Rustls read fairness

The Windows Rustls path retains the complete `RelayProtectedTcp` owner and its
Geneva guard. Each read poll checks the worker, then performs at most one socket
readiness observation and one read attempt. A readiness-to-`WouldBlock` race
clears readiness through Tokio's `try_read`, schedules one fresh poll and
returns `Pending` without an internal retry loop. EOF, native errors and the
write/flush/shutdown path keep their normal behavior. The Chrome-like backend
and production non-Windows paths retain their original socket implementation.

This targets a mechanism compatible with the observed Windows TLS/H2 budget
starvation. Controlled fixtures cannot establish native stale-readiness
causation; the unchanged Windows tests and exact candidate CI remain required.
No cooperative-budget bypass or longer establishment deadline is used.

## Directories

| Directory | Responsibility |
| --- | --- |
| [endpoint_bandit/](endpoint_bandit/README.md) | Tests of optional admitted numeric endpoint-pool learning. |
| [grpc/](grpc/README.md) | Test-only observations of an owned HTTP/2 establishment driver and their regression tests. |
| [masque_crypto/](masque_crypto/README.md) | Required-ECH QUIC TLS handshake tests for the MASQUE crypto builder. |
| [secure/](secure/README.md) | Synthetic-PKI tests for independent device-authenticated relay channels, enrollment and Liu admission. |
| [tls_backend/](tls_backend/README.md) | Optional AWS-LC outer TLS implementation beneath the backend selection seam. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client relay
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-client](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
