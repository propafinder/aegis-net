# aegis-core

Shared configuration, adaptive selection, protocol codecs, authenticated channels and native policy primitives used by the client and relay.

## Contract

This is a library, not a service. Changes to frame formats, configuration validation or trust checks affect both peers. Research consumers are experimental and unaccepted; their mathematical models and local tests do not establish field reachability, censorship resistance, timing guarantees or beta acceptance.

## Key files

- [Cargo.toml](Cargo.toml)
- [src/lib.rs](src/lib.rs)
- [src/config_types.rs](src/config_types.rs)
- [src/secure_channel/mod.rs](src/secure_channel/mod.rs)
- [src/relay_geneva.rs](src/relay_geneva.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [examples/](examples/README.md) | A controlled native relay-Geneva probe, separate from normal client traffic. |
| [src/](src/README.md) | Public library implementation and the re-exports consumed by native runtimes and tools. |
| [tests/](tests/README.md) | Public API integration tests for configuration, codecs, parsing, state, Brain, Lua and calibration. |

## Dependencies

Depends on aegis-geneva for strategy values; Tokio/rustls for asynchronous channels; ChaCha20-Poly1305/HKDF for state/control formats; optional mlua and enrollment certificate tooling. OS keyring and Windows native dependencies are target-gated.

## Build and use

Run Cargo commands from the repository root:

```sh
cargo build --locked -p aegis-core
cargo test --locked -p aegis-core
```

Default features are empty. Optional features are `device-enrollment`, `legacy-challenge-v1`, `lua`, `raw-socket` and `macos-bpf`. `legacy-challenge-v1` selects the default-off raw legacy challenge protocol described below and requires matching client/server builds. `raw-socket` exposes Linux raw operations that normally require root or `CAP_NET_RAW`; `macos-bpf` is a default-off observer scaffold, not a completed capture backend. Downstream client/server crates enable device enrollment themselves.

See the [implementation entry](src/README.md), [component ownership](../docs/architecture/OWNERSHIP.md), [source map](../docs/PROJECT-MAP.md) and [research composition boundaries](../docs/research/implementation-and-composition.md). The baseline Brain selector uses a UCB-style heuristic with weighted context evidence and a belief-adjusted reward; optional paper-bandit models have separate owners and assumptions.

[Repository overview](../README.md)

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/architecture/OWNERSHIP.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.

## Opt-in legacy challenge admission (Audit9)

The default-off `legacy-challenge-v1` feature adds Open → Challenge → Proof →
Final admission for raw legacy TLS. [The shared codec](src/tunnel/fresh_legacy.rs)
binds the original Open and a fresh server challenge to one consumed proof
owner and the matched key. The original setup deadline and key expiry bound
proof, target admission and Final; application bytes require a bound Ok Final.

Fourteen selected core fixtures passed in the Audit9 host evidence. The default
v3 codec remains unchanged and accepts replayed authenticated request bytes.
Other carriers receive no freshness repair from this feature. Independent
entropy is required; repeated RNG state and online forwarding of a current
challenge remain outside its protection. See the [operations evidence and
acceptance limits](../docs/operations/README.md#audit9-selected-challenge-feature-evidence).


## Startup state preparation

State loading moves successful JSON parsing, legacy migration and initial map
normalization into one owned Rust blocking task. It moves the existing owned
input without another plaintext buffer copy. A separate owned blocking task now
performs startup key lookup and AEAD on the original bounded bytes. The async
caller retains file reading and missing-key quarantine; other crypto errors
remain fatal and empty/quarantined defaults stay local. File ceilings, retention,
clean revision zero and disk bytes are unchanged.

Two placement regressions verify actual parse entry leaves the single-thread
runtime after checking parsing/migration and initial bounds. Four existing
plaintext-load controls cover both formats and exact/over-limit reads. The
controlled inline baseline fails the two final thread assertions; the candidate
passes. Final formatting and default core-library strict lint passed locally.

Three decrypt-entry controls, included in the final 70 state-v2 methods, verify
actual worker placement, synthetic PrivateFile AEAD and fatal tampering without
quarantine. Fourteen secret-state methods pass; one native key-store test stays
ignored. Native provider latency and exact successor CI remain separate gates.

This addresses placement, with no global blocking-pool admission, deadline or
hard heap guarantee. Caller cancellation can detach submitted work; started
blocking tasks are nonabortable. Native key/provider duration, shared panic
policy, installed lifecycle and exact-final release CI remain separate. See the
[change log](../docs/operations/change-and-incident-log.md) for pinned evidence.
