# aegis-client/src/runtime_event_stream

Private diagnostic formatting and persistent runtime-event sink regressions.

## Contract

privacy.rs accepts a closed set of codes and rejects arbitrary messages, Debug values, spans and error chains. The parent runtime_event_stream.rs owns sink initialization and forensic policy. Disabling new events or state does not erase old files or suppress every other log surface.

With the `forensic_safe` build cfg, public `init(Some(path))` ignores the requested
path and initializes the global sink to `None`. The global typed, raw,
calibration and knowledge-prior emitters consequently write no runtime-event
file, even when runtime forensic and private-log flags are false. This guarantee
covers the public initialization path: the lower-level `RuntimeEventStream::new`
constructor remains compiled and can still create a sink when called directly.

## Key files

- [privacy.rs](privacy.rs)
- [tests.rs](tests.rs)
- [forensic_build_tests.rs](forensic_build_tests.rs)

The enclosing module is [runtime_event_stream.rs](../runtime_event_stream.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client runtime_event_stream
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

The compiled forensic regression requires `--cfg forensic_safe`; `--all-features`
does not select that cfg. Use a separate target directory for this profile:

```sh
(
export CARGO_TARGET_DIR="${TMPDIR:-/tmp}/aegis-forensic-safe"
export RUSTFLAGS="${RUSTFLAGS:-} --cfg forensic_safe"
cargo check --locked -p aegis-client --bin aegis-client
cargo test --locked -p aegis-client --bin aegis-client runtime_event_stream::forensic_build_tests:: -- --list
cargo test --locked -p aegis-client --bin aegis-client runtime_event_stream::forensic_build_tests:: -- --test-threads=1
cargo test --locked -p aegis-client --bin aegis-client brain_state::tests -- --list
cargo test --locked -p aegis-client --bin aegis-client brain_state::tests -- --test-threads=1
)
```

Confirm the lists contain the one compiled sink test and all five existing
[Brain privacy tests](../brain_state.rs). The sink test starts a fresh exact-test
subprocess for each missing-path and existing-file case, avoiding prior global
sink initialization. It calls real `init(Some(path))`, emits diagnostic records,
and checks that no log, state, parent directory or key sidecar is created. Existing
synthetic log/state/seed bytes and log permissions must remain unchanged. The
real state loader also stays in memory despite explicit Direct persistence
consent and a false runtime forensic flag.

The [2026-10-10 audit register](../../../docs/operations/security-audit-2026-10-10.md)
tracks acceptance. Workspace-local evidence at
`evidence-archive/testing/2026-10-10/audit18-calibration-live-ram-r1/compiled-forensic-measurement-r1/receipt.json`
records a successful production check, **1 sink test + 5 privacy tests passed**,
and 72.279 seconds for the cold build and checks. This is scoped local evidence;
full Darwin, native and exact final-commit CI acceptance remain separate. The
normal diagnostic sink-positive tests are unchanged.

For dependency features and launch procedures, see [aegis-client](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
