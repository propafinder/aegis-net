# aegis-client

Native local node: SOCKS5 ingress, direct strategy execution, authenticated relays, enrollment and explicit platform tunnel workers.

## Contract

The binary reads local configuration and identity material. Default features are empty; optional Chrome-like TLS/QUIC and WebRTC support must be built explicitly. Transparent ingress and installed-profile commands have platform-specific policy requirements. Research paths remain experimental and unaccepted.

## Key files

- [Cargo.toml](Cargo.toml)
- [build.rs](build.rs)
- [src/main.rs](src/main.rs)
- [src/config.rs](src/config.rs)
- [src/profile.rs](src/profile.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [src/](src/README.md) | Client command dispatch, startup, identity lifecycle, profiles and routing between ingress and transport implementations. |
| [tests/](tests/README.md) | Client binary end-to-end suites for configuration, startup, direct/relay ingress, bundle readiness and UDP MASQUE. |

## Dependencies

Depends on aegis-core with device-enrollment and aegis-web-carrier; optional aegis-webrtc and aegis-quic-boring. Tokio/rustls/H2/QUIC provide transports; smoltcp supplies userspace packet processing on supported desktop targets.

## Develop and launch

Run from the repository root. Use an explicitly prepared local configuration and synthetic development identity; [config.example.toml](../config.example.toml) is a broad schema example, not a ready credential bundle or the runtime's default transport plan. Optional `legacy_tls` selection is absent from that default plan. Select a transport order for the intended profile before use; enrolled inner-TLS and opt-in raw legacy challenge profiles have separate admission requirements.

```sh
cargo build --locked -p aegis-client
cargo test --locked -p aegis-client
cargo run --locked -p aegis-client -- --config /path/to/aegis.toml --validate-config
cargo run --locked -p aegis-client -- --config /path/to/aegis.toml --ingress-preflight --json
cargo run --locked -p aegis-client -- --config /path/to/aegis.toml
```

`--validate-config` checks configuration and local identity files without starting the client. `--ingress-preflight` reports selection; `--ingress-startup-probe` performs runtime probes and is a distinct operation. `--version` prints build metadata. Use `--help` and subcommand help from the built binary for operator/profile procedures.

`chrome-like-tls`, `chrome-like-quic`, `webrtc-carrier`, `legacy-challenge-v1`, `lua` and `raw-socket` are opt-in build features. `legacy-challenge-v1` selects the raw legacy challenge client described below and requires a matching explicit server build. The actual TLS backend depends on both build and configuration. `windows-host-acceptance` enables explicit disruptive Windows tests. Forensic runtime policy and the `forensic_safe` build cfg have separate scope; disabling events does not erase existing files.

See [Windows tunnel design](../docs/platforms/windows/windows-system-tunnel.md), [macOS VM lab design](../docs/platforms/macos/macos-utun-lab-design.md) and [installed relay-Geneva profiles](../docs/relay-geneva-installed-profile.md).

[Repository overview](../README.md)

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/platforms/README.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.

## Opt-in raw legacy challenge client (Audit9)

`legacy-challenge-v1` is off by default and requires a matching explicit server
build. For shared-token relay mode, its gate refuses an empty or mixed TCP
carrier order before dialing; only raw legacy TLS retries are admitted. The
[adapter](src/relay/fresh_legacy.rs) preserves the original opening cutoff,
withholds application bytes until a bound Ok Final and refuses legacy-v3
fallback after failed fresh admission. Existing inner-TLS transport admission
is unchanged.

Four adapter fixtures and the feature-selected WebSocket refusal/no-dial fixture
passed. Existing timing, opening, payload and half-close controls passed in
selected default and feature configurations. This does not establish deployed
feature activation, other-carrier freshness or native acceptance. See the
[operations evidence and limits](../docs/operations/README.md#audit9-selected-challenge-feature-evidence).

## Administrative AUTO configuration

The hidden Linux root-only `profile auto-config` transaction is separate from
the ordinary `profile auto` planner. See phase ownership, protected inputs and
recovery requirements (archived: `docs/operations/linux-auto-configuration.md`).
Staged source integration and portable controls do not establish native
installation or release acceptance.
