# aegis-client/src/relay/tls_backend/aws_lc/windows

Windows AWS-LC adapter regression tests.

## Contract

tests.rs is compiled under the Windows implementation and optional chrome-like-tls backend. Use the supported Windows target to verify real socket/FFI ownership and trust behavior; success on a non-Windows build cannot cover this module.

## Key files

- [tests.rs](tests.rs)

The enclosing module is [windows.rs](../windows.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --features chrome-like-tls --bin aegis-client relay::tls_backend::aws_lc::windows
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

Enable `chrome-like-tls` to cover the optional AWS-LC/ECH implementation; Windows-specific modules additionally require Windows.

Native Windows/utun paths need the matching target; `windows-host-acceptance` is an explicit separate disruptive test gate.

For dependency features and launch procedures, see [aegis-client](../../../../../README.md).

[Repository overview](../../../../../../README.md) · [Parent directory](../README.md)
