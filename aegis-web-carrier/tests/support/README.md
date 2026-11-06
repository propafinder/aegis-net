# aegis-web-carrier/tests/support

Synthetic inner-mTLS integration fixtures and carrier authorization tests.

## Contract

inner_mtls.rs is Unix-gated and included from the network suite rather than a standalone test target. It supplies local device-channel trust material and target checks; preserve rejection-before-egress and separate outer credential/device authorization. No deployment identity belongs in these fixtures.

## Key files

- [inner_mtls.rs](inner_mtls.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-web-carrier --tests
```

Shared support directories are included by their parent suites, not standalone Cargo test targets.

For dependency features and launch procedures, see [aegis-web-carrier](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
