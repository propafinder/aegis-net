# aegis-client/src/relay/grpc

Test-only observations of an owned HTTP/2 establishment driver and their regression tests.

## Contract

diagnostics.rs is test-gated by the parent grpc.rs. Its bounded Witness counts API polls, wakes, queued requests and local I/O; these observations never prove delivery to the peer. No global state, headers, targets, credentials or unbounded event list enter the witness. Production stage labels live in the parent module, where synchronous trust preparation cannot be preempted by Tokio timing.

## Key files

- [diagnostics.rs](diagnostics.rs)
- [diagnostics_tests.rs](diagnostics_tests.rs)
- [end_stream_tests.rs](end_stream_tests.rs): actual H2 reader closure and incomplete-message regressions.

The parent reader returns clean EOF only after all complete buffered messages
have been delivered and no bytes remain. HTTP/2 END_STREAM with a partial
five-byte gRPC header or declared body returns `InvalidData` with a fixed
message. Complete messages, including an empty message, are delivered before
an incomplete suffix is refused. Message limits and receive-window handling
remain unchanged. These tests use a bounded in-memory H2 transport; they do
not identify the cause of a native Windows TCP truncation.

The enclosing module is [grpc.rs](../grpc.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client relay::grpc
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-client](../../../README.md).

[Repository overview](../../../../README.md) · [Parent directory](../README.md)
