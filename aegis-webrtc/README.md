# aegis-webrtc

Owned reliable byte carrier over real ICE, DTLS and SCTP for an existing inner TLS device channel.

## Contract

Owned signaling admission is an additional gate and never device authentication. This unpublished library does not implement Tor Snowflake or media/codec substitution. Native client/server integration is optional via webrtc-carrier; local ICE/TURN fixtures do not establish field reachability or release acceptance.

## Key files

- [Cargo.toml](Cargo.toml)
- [src/lib.rs](src/lib.rs)
- [src/endpoint.rs](src/endpoint.rs)
- [src/signaling.rs](src/signaling.rs)
- [src/policy.rs](src/policy.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [src/](src/README.md) | WebRTC connect/accept endpoints, ordered byte streams, ICE policy, bounded signaling and private runtime settings. |
| [tests/](tests/README.md) | Actual private loopback TURN-server integration tests. |

## Dependencies

Uses pinned webrtc/rtc 0.21.0 with Tokio and crypto-ring, plus bounded TLS signaling utilities. Integration tests use a pinned local TURN implementation. It has no binary target.

## Development

```sh
cargo test --locked -p aegis-webrtc
cargo build --locked -p aegis-client -p aegis-server --features webrtc-carrier
```

Run from the repository root. The native `webrtc` command paths require explicit private runtime settings, owned verified-TLS signaling and independent inner device credentials. There is no default external signaling, STUN or TURN service. Review the [native client](../aegis-client/README.md), [native relay](../aegis-server/README.md) and [research composition boundaries](../docs/research/implementation-and-composition.md).

[Repository overview](../README.md)

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/operations/webrtc-native.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.
