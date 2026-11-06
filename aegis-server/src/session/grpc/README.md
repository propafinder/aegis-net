# aegis-server/src/session/grpc

Windows server H2 I/O progress and authorized TLS/H2 regressions.

## Contract

These modules are compiled by the parent grpc.rs. They verify device trust, finite Liu agreement and exclusive HTTPS bridge handling using local fixtures. A queued HTTP/2 response or byte counter is not delivery evidence, and synthetic consumers are not native field acceptance.

## Key files

- [coop_io.rs](coop_io.rs): Windows production adapter at the shared H2 connection boundary.
- [coop_io_tests.rs](coop_io_tests.rs): read/write/error/EOF and single-turn ownership controls.
- [coop_h2_tests.rs](coop_h2_tests.rs): actual outer TLS/H2, sealed legacy OPEN and payload delivery with a controlled exhausted receive budget.
- [secure_tests.rs](secure_tests.rs)
- [secure_cleanup_tests.rs](secure_cleanup_tests.rs): authenticated adaptive revocation and same-poll worker/permit custody.
- [secure_liu_tests.rs](secure_liu_tests.rs)
- [https_bridge_tests.rs](https_bridge_tests.rs)
- [progress_witness_tests.rs](progress_witness_tests.rs)
- [preauth_tests.rs](preauth_tests.rs)
- [end_stream_tests.rs](end_stream_tests.rs): actual request-reader clean EOF, complete-message drain and partial-header/body refusal through bounded in-memory H2.

The request reader treats END_STREAM with an incomplete buffered gRPC message
as `InvalidData`, without including payload or credentials in the error.
An empty buffer still permits clean EOF, and complete messages are delivered
before a partial suffix is refused. Existing authentication, message-size,
flow-control and timing contracts are unchanged. This framing-integrity
regression does not establish the cause of native Windows byte loss.

The ordinary TCP response waits for HTTP/2 capacity through the same bounded
message sender used for datagrams. It keeps the authenticated activity owner
while a reader holds receive credit, rather than completing after enqueueing
an arbitrarily large target response. The parent module's capacity regression
uses a real loopback TCP target and in-memory H2 with a 512-byte window: it
holds actual DATA credit, verifies retained activity, then releases credit and
requires the exact two-MiB response and clean END_STREAM. This proves the local
handler's queue ownership; it does not identify the unique cause of the native
Windows truncation or establish installed/network acceptance. ACK, empty EOF,
authentication and existing idle budgets retain their separate contracts.

The admission regressions use paused time for deadline composition and real
local H2/WS framing for idle ownership, advertised stream limits and immediate
oversized-prefix refusal. Synthetic device TLS verifies that authenticated
channels release handshake capacity. These are source regressions, without a
claim of live fleet acceptance or remote load-test results.
Cutoff fixtures first poll the handler, buffer a valid final proof, and advance
the paused clock before polling it again. Late WS/gRPC proof cannot release
socket admission or renew activity; late device proof keeps the typed timeout
and cannot invoke its authentication callback. A buffered authenticated Open
after the original cutoff cannot connect to its synthetic loopback listener.

## Installed shaping cleanup regression

The [cleanup fixture](secure_cleanup_tests.rs) uses an authenticated inner device TLS exchange over an owned in-memory H2 transport and a real local TCP target. Distinct upload and download markers establish progress before an actual registry revocation. The carrier observer runs inside the server terminal poll and checks both Drop and permit ownership, rather than waiting until a later scheduling turn. A 15 second fixture body and an independent 2 second exterior drain retain the client, target, H2 connection, registry watcher and publisher owners. Entered blocking filesystem work cannot be preempted by these asynchronous cutoffs.

The paired predecessor keeps the original secure server body while sharing the new owner plumbing and the exact whole fixture; it is not an original whole binary. Five worker-owner controls exercise typed result custody, captured-owner Drop, admission before spawn, expired cleanup refusal and preservation of an observed worker error. The server fixture covers adaptive only; the six adapter bodies, codecs, numerical choices and original wire/idle tests are separately preserved. Compilation, actual results and exact-commit CI must be recorded from the root execution receipts; this preparation does not supply those results.

The enclosing module is [grpc.rs](../grpc.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-server --lib session::grpc
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-server](../../../README.md).

[Repository overview](../../../../README.md) · [Parent directory](../README.md)

## Windows cooperative progress

The production adapter is Windows-gated and installed before shared H2 route
dispatch, including device, bundle, bridge and extended-CONNECT consumers.
Tests compile it on every host. When a pending receive consumes the last Tokio
cooperative permit, one subsequent receive attempt yields so a queued write
can use a fresh turn. A pure reader skips once and then continues; this does
not replenish permits or change bytes, protocol cutoffs, authorization or
non-H2 HTTP/1 consumers.

The same real TLS/H2 fixture times out with a mechanical transparent adapter
after validated OPEN, queued headers and target dial, then passes with the
production adapter and distinct payloads in both directions. Forty-seven
local shared H2 regressions pass. The injected budget exhaustion is a controlled
transport seam, not proof of native Windows causation or installed acceptance.
Earlier invalid route/auth/filter/sandbox attempts remain private evidence.

The Windows CI lane runs the shared `session::grpc::` suite under an eight-minute
step bound even when another runtime step fails, provided checkout and toolchain
succeeded. That includes the injected budget regression and existing actual
authorization/bridge controls; a scheduled step is not a passing result.
