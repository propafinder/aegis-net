# aegis-webrtc/src

WebRTC connect/accept endpoints, ordered byte streams, ICE policy, bounded signaling and private runtime settings.

## Contract

CarrierConfig and IcePolicy express permitted paths; PathEvidence describes the resulting local path. OwnedBroker bounds signaling sessions and messages. WebRtcStream adapts the ordered reliable data channel to byte I/O. Runtime credential readers must enforce platform custody, and the caller must run independent inner device TLS before egress.

## Key files

- [lib.rs](lib.rs)
- [endpoint.rs](endpoint.rs)
- [policy.rs](policy.rs)
- [signaling.rs](signaling.rs)
- [stream.rs](stream.rs)
- [runtime_settings.rs](runtime_settings.rs)
- [tests.rs](tests.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-webrtc --lib
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-webrtc](../README.md).

[Repository overview](../../README.md) · [Parent directory](../README.md)
