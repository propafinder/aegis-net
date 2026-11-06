# aegis-core/src/shield

Startup sentinel heuristics and repeating-key XOR environment-string decoding.

## Contract

sentinel.rs implements lightweight debugger/VM checks, not cryptographic protection.
The current client disables debugger exit: debugger/VM observations only warn.
`AEGIS_SHIELD=0` skips checks only in debug builds; release builds warn and continue
the checks. The API can exit only when a caller explicitly enables that behavior.
Repeating-key XOR is obfuscation, not cryptographic secrecy. Neither helper protects
keys or data against a compromised host. Feature-dependent Lua hooks are implemented
in the parent lua_engine.rs module.

## Key files

- [mod.rs](mod.rs)
- [sentinel.rs](sentinel.rs)
- [string_crypt.rs](string_crypt.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib shield
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
