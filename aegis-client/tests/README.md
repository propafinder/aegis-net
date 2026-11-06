# aegis-client/tests

Client binary end-to-end suites for configuration, startup, direct/relay ingress, bundle readiness and UDP MASQUE.

## Contract

The common harness creates local synthetic fixtures and owns child lifetimes. Review each suite for target/feature gates and explicit ignored tests before execution. A loopback binary exchange verifies that path only; it does not establish release, fleet or censorship acceptance.

Tests that deliberately seed a Brain snapshot and verify its effect must set
`persist_state = true` in that test's `[direct]` configuration. A `state_path`
alone does not authorize disk learning. Keep unseeded fixtures and the normal
runtime default RAM-only; do not restore implicit persistence to fix a test.

## Key files

- [config_validation_e2e.rs](config_validation_e2e.rs)
- [startup_stack_e2e.rs](startup_stack_e2e.rs)
- [ingress_runtime_e2e.rs](ingress_runtime_e2e.rs)
- [direct_runtime_e2e.rs](direct_runtime_e2e.rs)
- [device_bundle_ready_e2e.rs](device_bundle_ready_e2e.rs)
- [udp_masque_send_e2e.rs](udp_masque_send_e2e.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [common/](common/README.md) | Shared local subprocess, socket, TOML, private-file and readiness fixtures. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --tests
```

Integration targets are the Rust files directly in this tests directory.

For dependency features and launch procedures, see [aegis-client](../README.md).

[Repository overview](../../README.md) · [Parent directory](../README.md)
