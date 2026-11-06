# aegis-server/src

Relay startup, transport dispatch, target authorization, enrollment authority and policy lifecycle implementation.

## Contract

lib.rs owns ready reporting, task ownership and bounded shutdown; main.rs dispatches separate operator commands. config.rs validates intent, tls.rs prepares credentials, and target_policy.rs validates a resolved target once before dialing. Never report readiness before required ingress and trust state are verified.

## Key files

- [main.rs](main.rs)
- [lib.rs](lib.rs)
- [config.rs](config.rs)
- [tls.rs](tls.rs)
- [target_policy.rs](target_policy.rs)
- [operational_log.rs](operational_log.rs)
- [operational_log_tests.rs](operational_log_tests.rs)
- [devices.rs](devices.rs)
- [enrollment_service.rs](enrollment_service.rs)
- [device_policy.rs](device_policy.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [config/](config/README.md) | Source configuration fixtures beneath config.rs. |
| [devices/](devices/README.md) | Offline device issuance/revocation regression tests beneath devices.rs. |
| [phase_witness/](phase_witness/README.md) | Fixed aggregate I/O observations for explicitly owned server diagnostics. |
| [rate_limit/](rate_limit/README.md) | Authentication failure-history fixtures beneath rate_limit.rs. |
| [session/](session/README.md) | Authenticated session handlers for secure streams, UDP, HTTP/2 gRPC, WebSocket, bundles, HTTPS bridge and QUIC/MASQUE. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-server --lib
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-server](../README.md).

[Repository overview](../../README.md) · [Parent directory](../README.md)

## Authentication failure history

Failure history and its ordered expiry index retain at most 4,096 full IP identities. Ban checks, insertion and cleanup reclaim expired windows. Saturation denies unknown identities until a window expires while preserving retained windows and bans; this trades new-client availability for a bounded memory contract and is not proof of bad authentication. Failure counts saturate rather than wrap. Full-IP and trusted-proxy identity policies are unchanged; shared-IP fairness and setup-timeout classification require separate acceptance.

## Operational log privacy

Each runtime derives an immutable policy from `logging.include_sensitive_context`,
which defaults to `false`. Reviewed legacy TCP, gRPC TCP/UDP, QUIC, admission,
target-policy, rate-limit, WebSocket, bundle, startup/process and drain/reap
emitters keep their original severity and static event/category fields while
omitting supplied peer, target, path, alias and error details by default.
`RUST_LOG` selects verbosity and cannot enable the sensitive branch.

Explicit configuration restores diagnostic context in those emitters. Actual
opaque carrier and WebRTC runtimes pass that policy into target handling and
rate limiting; public compatibility wrappers intentionally stay default-private.
Returned errors, token redemption, statuses, readiness and owner deadlines are
unchanged. Other process output and Rust/Tokio panic-hook stderr are outside this
scoped logging contract; historical and deployed retention require separate work.

Subscriber/MustNotFormat tests exercise helper dispatchers; a separate regression
drives the real Tokio JoinError branches in task drain and reap. Source-reviewed
runtime wiring and existing wire controls are not captured proof of every live
log path. Run `cargo test --locked -p aegis-server operational_log_tests` and
`cargo test --locked -p aegis-server actual_join_error_emitters` from the root.
