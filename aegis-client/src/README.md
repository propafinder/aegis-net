# aegis-client/src

Client command dispatch, startup, identity lifecycle, profiles and routing between ingress and transport implementations.

## Contract

main.rs owns startup and shutdown. Configuration loading validates shared Settings and local identity contracts before normal operation. The operator/profile modules expose separate lifecycle procedures; do not use a privileged tunnel mode as a generic development launch. Private diagnostics default to closed event/error codes.

Shared-token hybrid Geneva requires an authenticated gRPC fallback and is refused before ingress startup in a `legacy-challenge-v1` raw-only build. Authenticated `relay.inner_tls` carriers are exempt from that raw-only restriction and retain existing identity and hybrid-policy validation. CI exercises ordinary-build real gRPC handoff separately from feature-on raw-only configuration rejection; rejection is not positive transport evidence.

## Key files

- [main.rs](main.rs)
- [config.rs](config.rs)
- [profile.rs](profile.rs)
- [profile_bundle_ca.rs](profile_bundle_ca.rs) — private typed staging of an explicitly bundled MASQUE CA before macOS reinstall purge.
- [profile_project_license.rs](profile_project_license.rs) — bounded public project-text admission and installation through held directory descriptors; the macOS installer checks the destination before reinstall purge.
- [operator.rs](operator.rs)
- [device_identity.rs](device_identity.rs)
- [device_enrollment.rs](device_enrollment.rs)
- [device_renewal.rs](device_renewal.rs)
- [runtime_event_stream.rs](runtime_event_stream.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [direct/](direct/README.md) | Direct planning and execution beneath the parent direct.rs orchestration module. |
| [ingress/](ingress/README.md) | Ingress interfaces and session broker for SOCKS5 fallback and platform-wide capture. |
| [macos_tunnel/](macos_tunnel/README.md) | Experimental macOS VM utun supervisor and dedicated non-root network worker. |
| [relay/](relay/README.md) | Relay endpoint selection, outer carrier setup, inner authentication and TCP/UDP transport pumps. |
| [runtime_event_stream/](runtime_event_stream/README.md) | Private diagnostic formatting and persistent runtime-event sink regressions. |
| [runtime_events/](runtime_events/README.md) | Regression tests for the client event-code catalog. |
| [windows_wide/](windows_wide/README.md) | Windows wide-listener session targeting and original-destination vocabulary. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-client](../README.md).

## Accept recovery and diagnostic admission

The ordinary ingress owner delays narrowly recognized native resource errors
with an absolute retry time: 50 ms doubles up to 1 second. False stop-watch wakes
and completed session children do not restart that wait. A successful accepted
intent resets the retry streak. Resource-error diagnostics are admitted at most
once per second before formatting or JSON construction; accepting an intent does
not reset this diagnostic interval. Unknown or staged errors keep their existing
handling, and shutdown, renewal and worker failures remain selectable.

[ingress_accept_tests.rs](ingress_accept_tests.rs) exercises the actual owner in
isolated child processes, including a retained Direct connection and later new
connection. Injected resource errors establish source behavior, not actual OS
exhaustion. Ordinary detached sessions, global active-session admission and
persistent event-file size/retention remain separate open work.


## Public calibration and private history

`--runtime-external-calibration-summary <path>` imports one explicitly selected
public calibration snapshot into the live Brain store before ingress starts.
The input must be a regular file of at most 1 MiB with schema version 1 and
bounded collections and scores. Relay and forensic runtimes keep this import
in memory; they do not load or persist destination history. Default Relay without
adaptive selection or recent-route selection preserves configured transport
order when no calibration is imported. Those selectors can reorder routes from
live samples; explicit Direct/Auto persistence consent may load saved state.
Stale calibration retains its normal
freshness decay and does not force a route.

`--apply-external-calibration-summary` is the separate manual operation that
reads a summary and updates the configured Brain state file, leaving the input
summary unchanged. Running that command does not import that state into a
subsequent Relay process. The calibrated live proof passes the explicit
runtime flag; default privacy and persistence consent remain unchanged.

The reader and regression live in [runtime_calibration.rs](runtime_calibration.rs)
and [runtime_calibration_tests.rs](runtime_calibration_tests.rs). A passing local
proof does not accept a deployed or signed release.

[Repository overview](../../README.md) · [Parent directory](../README.md)

The hidden `profile bundle-ca` operation is an installer protocol, not a trust
policy selector. It validates a complete typed configuration and only relocates
the three explicitly supported bundle-relative CA references. See
[MASQUE installation and checks](../../docs/operations/masque-association-testing.md)
for ownership, preservation and native-acceptance limits.

The hidden `profile project-license` operation accepts only `LICENSE-MIT`,
`LICENSE-APACHE` and `NOTICE` with their declared SHA-256 and a bounded public
stdin payload. On Linux/macOS it resolves the admitted physical home, retains
directory descriptors, refuses symlink traversal in the fixed suffix and
requires the exact selected home owner. It changes
ownership only on newly staged files/directories and requires a shared
filesystem with its trusted temporary directory. Other platforms refuse this
protocol. The six descriptor regressions and generated macOS installer fixture
are local source evidence; root installation, cross-filesystem support, VM
lifecycle and production signing remain separate acceptance gates.

## Linux AUTO transaction modules

`profile_auto_transaction_cli.rs` owns the hidden administrative argument
protocol; `profile_auto_transaction.rs` owns the durable phase contract.
Capture/prepare/render, stage authority, filesystem publication and state
publication have separate owners. The Linux backend composes these APIs;
other platforms explicitly refuse administrative execution.
Administrative AUTO configuration (archived: `docs/operations/linux-auto-configuration.md`)
records the module map and recovery protocol. Ordinary public AUTO planning
remains in `profile_auto.rs`; this integration does not close native acceptance.
