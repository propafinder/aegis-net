# aegis-client/src/direct

Direct planning and execution beneath the parent direct.rs orchestration module.

## Contract

planner.rs narrows strategy choices from configuration, observations and capabilities; executor.rs performs the selected connection/send path. Preserve the distinction between selection, executed strategy, retry evidence and terminal failure. Active probes and relay failover must respect the original retry budget and admitted route policy.

## Key files

- [planner.rs](planner.rs)
- [executor.rs](executor.rs)

The enclosing module is [direct.rs](../direct.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client direct
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-client](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)

## Initial payload admission

The ordinary Direct and Auto orchestration owns a client-first read deadline
using the existing `direct.first_chunk_timeout_ms` budget. A silent client
receives a `direct_initial_read_timeout` refusal before any target or relay
connection. An unrepresentable deadline is refused separately. The default
budget, configured strategy ladder and EOF-before-payload no-dial behavior stay
unchanged. Dropping this phase drops its owned ingress socket; it has no spawned
workers.

[initial_read_tests.rs](initial_read_tests.rs) contains shared actual loopback
TCP cases for Direct/Auto silence, real payload/response and cancellation. The
predecessor comparison keeps the original production read and imports only the
same test module. Fixture watchdogs are separate from the configured product
deadline. Source preparation is not a passing test receipt.

This deadline repair alone does not add protocol-neutral server-first delivery.
Those protocols require an explicit separately admitted duplex establishment
route; neither a synthetic first request nor a forced raw/passthrough or relay
fallback is introduced here. Server-first compatibility and exact successor CI
remain open acceptance work.

## Auto route-owned DNS

[auto_resolution.rs](auto_resolution.rs) owns Auto hostname resolution and
relay admission. It checks hostname-independent required relay policy before
local DNS. A failed direct lookup can use the original hostname only when the
configured fallback policy and relay configuration admit it. Required relay
refusal is terminal; it adds no direct retry. Direct and
`PreserveDirectFailure` keep their existing refusal behavior.

Ordinary relay handoff waits for genuine nonempty client input under the same
`first_chunk_timeout_ms` budget. Silence, EOF and cancellation stop before
handoff. The bounded input is handed over once; configuration readiness does
not establish relay authentication or target delivery.

[auto_resolution_tests.rs](auto_resolution_tests.rs) checks DNS/policy
selection; [auto_relay_initial_payload_tests.rs](auto_relay_initial_payload_tests.rs)
checks owned loopback input, response and cancellation. Native resolver bounds,
target-network privacy, installed lifecycle and server-first compatibility
remain separate acceptance work.
