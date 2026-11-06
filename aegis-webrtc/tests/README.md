# aegis-webrtc/tests

Actual private loopback TURN-server integration tests.

## Contract

relay_turn.rs runs an independent local TURN server with synthetic credentials. It uses no external STUN/TURN account or host interface changes. Distinguish a verified relay-only local ICE path from public TURN availability, media camouflage or whole-network acceptance.

## Key files

- [relay_turn.rs](relay_turn.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-webrtc --tests
```

Integration targets are the Rust files directly in this tests directory.

For dependency features and launch procedures, see [aegis-webrtc](../README.md).

[Repository overview](../../README.md) · [Parent directory](../README.md)
