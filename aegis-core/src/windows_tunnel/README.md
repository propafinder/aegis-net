# aegis-core/src/windows_tunnel

Windows Wintun loading, owned routes, persistent WFP protection and tunnel lifecycle ownership.

## Contract

Native APIs own policy; shell-driven network changes are outside this boundary. Wintun loads the exact signed AMD64 DLL. WFP protection persists after process handles close and requires explicit disconnect. Route cleanup removes owned additions, while lifecycle receipts support exclusive ownership and crash recovery.

## Key files

- [mod.rs](mod.rs)
- [wintun.rs](wintun.rs)
- [network.rs](network.rs)
- [firewall.rs](firewall.rs)
- [lifecycle.rs](lifecycle.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib windows_tunnel
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

Native Windows code is target-gated; a non-Windows test run does not cover native APIs.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
