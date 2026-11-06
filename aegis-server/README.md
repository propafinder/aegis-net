# aegis-server

Relay service and operator commands for device enrollment, policy distribution, bundles and owned experimental carriers.

## Contract

The binary and library share configuration/trust preparation. Target policy and device authorization apply before egress. Default features are empty. Optional WebRTC support requires `webrtc-carrier`; `legacy-challenge-v1` selects the default-off raw legacy challenge server described below and requires a matching explicit client build. Research consumers and native carrier experiments remain unaccepted; local suites do not constitute beta or fleet acceptance.

## Key files

- [Cargo.toml](Cargo.toml)
- [build.rs](build.rs)
- [src/main.rs](src/main.rs)
- [src/lib.rs](src/lib.rs)
- [src/config.rs](src/config.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [src/](src/README.md) | Relay startup, transport dispatch, target authorization, enrollment authority and policy lifecycle implementation. |
| [tests/](tests/README.md) | Local integration coverage for configuration, transports, bundles, lifecycle and authorization convergence. |

## Dependencies

Depends on aegis-core with device-enrollment, aegis-web-carrier and optional aegis-webrtc. Tokio/rustls, H2, WebSocket and QUIC implement ingress. Build metadata is produced by build.rs.

## Develop and launch

Run from the repository root with an explicitly prepared server configuration, public certificates and private local development key material:

```sh
cargo build --locked -p aegis-server
cargo test --locked -p aegis-server
cargo run --locked -p aegis-server -- --config /path/to/aegis-server.toml config-check
cargo run --locked -p aegis-server -- --config /path/to/aegis-server.toml
```

`config-check` parses and validates configuration without binding listeners or printing secrets. Normal execution defaults to `aegis-server.toml`; `--version` reports build metadata. `device`, `device-policy`, `enrollment`, `carrier`, `install-launcher` and `bundle-token` are distinct command groups. `webrtc` is compiled only with `webrtc-carrier`. Inspect the appropriate built-binary help before using a state-changing operator command. Token issuance requires `--url-output` to store its plaintext record at an explicit private file path; stdout reports status only. Keep the private record out of logs and Git.

The library exposes ready/shutdown variants for harnesses. Required QUIC startup must succeed before ready reporting; shutdown owns child tasks and has bounded grace. See [component ownership](../docs/architecture/OWNERSHIP.md), [source map](../docs/PROJECT-MAP.md), the [inner-TLS source implementation guide](../docs/operations/inner-tls-v1.md) and [research composition](../docs/research/implementation-and-composition.md). The [9 September secure transport proposal](../docs/archive/checkpoints/SECURE-TRANSPORT-DESIGN-2026-09-09.md) is historical; its TCP-first implementation status does not describe the later TCP/UDP source paths or establish release acceptance.

The repaired legacy TCP, gRPC TCP/UDP, QUIC, admission and policy failure emitters omit peer, target and nested error details by default. `logging.include_sensitive_context = true` enables their sensitive branch for that server runtime; use it only for an explicitly selected diagnostic session with an appropriate log destination and retention policy. `RUST_LOG` selects their verbosity without enabling that branch. Other server log paths remain under review; this does not promise privacy for every log. See [the scoped implementation contract](src/README.md#operational-log-privacy) and [the example configuration](../aegis-server.toml.example).

[Repository overview](../README.md)

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/operations/README.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.

## Opt-in raw legacy challenge server (Audit9)

The default-off `legacy-challenge-v1` feature selects the
[fresh raw adapter](src/session/fresh_legacy.rs). Valid proof of the matched key
precedes release of the setup permit and construction of the existing target
policy connector. Proof, target establishment and Final retain the original
admission cutoff narrowed by key expiry and existing write/connect budgets.
Established forwarding keeps the existing legacy TCP idle, write and half-close
bounds. Failed fresh admission closes without a v3 or decoy-proxy fallback.

Five selected fresh server fixtures passed. Default legacy and decoy controls
also passed, but the first feature-selected server production strict check
failed on two unused v3 helpers; that failed receipt remains preserved. The
reviewed two-guard correction and remaining checks are recorded in the
[operations evidence](../docs/operations/README.md#audit9-selected-challenge-feature-evidence).
Default v3 and all other carrier freshness remain unchanged and open; matching
client/server activation, exact-final CI and native/fleet acceptance remain
separate requirements.
