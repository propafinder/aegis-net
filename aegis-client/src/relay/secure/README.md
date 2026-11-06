# aegis-client/src/relay/secure

Synthetic-PKI tests for independent device-authenticated relay channels, enrollment and Liu admission.

## Contract

The parent secure.rs opens TCP/fixed-target UDP only after independent inner TLS. Retry is limited to failures before device authentication. Test fixtures exercise trust, enrollment and finite shaping admission; they do not establish native field acceptance or whole-wire privacy.

## Key files

- [tests.rs](tests.rs)
- [enrollment_tests.rs](enrollment_tests.rs)
- [liu_tests.rs](liu_tests.rs)

The enclosing module is [secure.rs](../secure.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client relay::secure
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-client](../../../README.md).

[Repository overview](../../../../README.md) · [Parent directory](../README.md)
