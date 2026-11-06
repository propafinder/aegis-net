# aegis-core/tests

Public API integration tests for configuration, codecs, parsing, state, Brain, Lua and calibration.

## Contract

Tests use explicit synthetic inputs. Protocol parsing and encrypted-frame tests do not measure live censorship resistance. Lua suites require the lua feature; platform and native behavior must be verified on their supported targets. Common ClientHello construction lives in common/.

## Key files

- [config_types_tests.rs](config_types_tests.rs)
- [relay_codec.rs](relay_codec.rs)
- [relay_privacy_contract.rs](relay_privacy_contract.rs)
- [tls_parse_tests.rs](tls_parse_tests.rs)
- [tls_modify_tests.rs](tls_modify_tests.rs)
- [state_persist.rs](state_persist.rs)
- [brain_state.rs](brain_state.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [common/](common/README.md) | Synthetic ClientHello construction shared by integration tests. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --tests
```

Integration targets are the Rust files directly in this tests directory.

For dependency features and launch procedures, see [aegis-core](../README.md).

[Repository overview](../../README.md) · [Parent directory](../README.md)
