# Runtime Events Ownership

Status: architecture ownership document. This is not a schema migration and
does not change emitted runtime event JSON.

Runtime events are part of the AEGIS evidence surface. They explain why a
transport, platform path, calibration source, or policy branch was selected,
accepted, penalized, blocked, or dropped. They must remain stable enough for
live artifacts, contracts, and Phase gates to validate behavior without
guesswork.

## Current Ownership

`aegis-client` currently owns event emission:

- `aegis-client/src/runtime_events.rs` groups stable event-code constants.
- `aegis-client/src/runtime_event_stream.rs` writes runtime event JSONL.
- Runtime modules populate event fields at the point where behavior happens.

`aegis-core` owns shared decision inputs and explanations:

- Brain heuristic trust state and selection traces. Its baseline Beta-shaped
  smoothing uses bounded fractional source weights; it is not an accumulated
  Beta–Bernoulli posterior. Existing event field names remain compatible.
- Calibration beliefs and fail-closed/penalty semantics.
- Strategy keys, observations, health decisions, and advisory data.

`aegis-measure` owns validation:

- proof contracts;
- Phase gates;
- artifact checks;
- overclaim prevention;
- runtime-event assertions for evidence paths.

## Target Ownership

The target is shared schema vocabulary in Rust, with emission and validation
kept separate:

- shared event names and field vocabulary live in `aegis-core` or a dedicated
  shared schema module;
- `aegis-client` keeps runtime emission and file writing;
- `aegis-measure` validates artifacts using the shared vocabulary;
- shell and PowerShell wrappers only pass artifact paths and invoke Rust tools.

## Event Groups

Initial event groups should stay small and low-risk:

- Brain external calibration and heuristic selection events (including existing
  `posterior`-named compatibility fields);
- transport selection and relay session events;
- Phase B relay surface and classifier evidence events;
- macOS utun LAB events;
- Linux wide/TPROXY policy and UDP capture events;
- Windows reach policy events, without claiming DNS/UDP/IPv6 capture.

## Migration Rules

- Do not rename event codes in a refactor-only commit.
- Do not remove fields that committed artifacts or contracts already parse.
- Do not weaken validators when moving event constants.
- Do not turn missing events into PASS.
- Do not claim a platform capability from an event name alone; require the
  matching artifact and contract.
- Keep compatibility shims where historical artifacts need old names.

## First Safe Slice

The first safe implementation slice is constant grouping only:

1. Keep emitted JSON byte-for-byte compatible.
2. Move or mirror event-code constants into grouped Rust modules.
3. Update `aegis-measure` validators to use constants where straightforward.
4. Run focused runtime-event and Phase contract tests.

Full schema centralization should wait until the constants grouping proves
stable.
