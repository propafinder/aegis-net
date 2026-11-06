# aegis-server/src/devices

Offline device issuance/revocation regression tests beneath devices.rs.

## Contract

tests.rs creates temporary synthetic CA, CSR, invitation and registry state. The production parent module is an operator-workstation workflow; issuing a certificate and changing a registry are separate durable authorization steps. Do not read or copy deployment invitations or keys into tests or docs.

## Key files

- [tests.rs](tests.rs)

The enclosing module is [devices.rs](../devices.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-server --lib devices
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-server](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
