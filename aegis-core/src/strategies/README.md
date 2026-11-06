# aegis-core/src/strategies

Direct-mode first-buffer strategies and the capability-aware send interface.

## Contract

SendFirstContext carries target and observation context; raw strategies depend on raw-engine capabilities. Geneva bridges the offline strategy representation into direct execution. Do not allow a capability failure to be reported as successful strategy application or let an altered decoy corrupt the intended endpoint stream.

The historical `oob_data` identifier is an ordinary `write_all` compatibility sender on every platform. It preserves the complete first application buffer and does not send urgent data or demonstrate DPI evasion. Five actual TCP/EOF regressions preserve GET, single-byte, constrained-buffer, empty and SNI-present branch behavior; the SNI-present control is not a TLS handshake, and the requested send-buffer size is not a specific native short-write proof. Planner and fallback policy remain unchanged. This adds no per-write deadline: the existing caller cancellation and overall send budget remain a separate ownership contract.

## Key files

- [mod.rs](mod.rs)
- [geneva.rs](geneva.rs)
- [passthrough.rs](passthrough.rs)
- [oob.rs](oob.rs) and [canonical first-buffer tests](oob_tests.rs)
- [multisplit.rs](multisplit.rs)
- [ttl_desync.rs](ttl_desync.rs)
- [overlap.rs](overlap.rs)
- [ip_frag.rs](ip_frag.rs)
- [checksum_trick.rs](checksum_trick.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib strategies
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
