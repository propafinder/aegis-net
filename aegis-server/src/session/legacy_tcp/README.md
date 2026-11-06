# Legacy TCP session deadlines

The enclosing [legacy TCP adapter](../legacy_tcp.rs) applies only after the
existing shared-token legacy TLS request authenticates. The original admission
deadline, key matching, resolve-once destination policy, exact-address connect
attempts and ownership of the connection permit remain in their existing owners.

`limits.legacy_tcp_connect_timeout_ms` defaults to 10,000 ms and covers the complete
target resolution/validation/connect future once. `limits.write_timeout_ms`
defaults to 30,000 ms and bounds the complete success or error control response.
During payload forwarding it separately bounds a stalled write, flush or
half-close on either endpoint; successful write bytes start a fresh progress
budget. Pending polls, zero bytes, EOF and a successful empty flush do not renew
the authenticated idle clock.

`limits.legacy_tcp_idle_timeout_ms` defaults to 300,000 ms. Successfully read or
written payload bytes in either direction renew this shared clock. A quiet
direction is permitted while the other direction progresses. Active authorized
sessions have no absolute lifetime cap. Operators can select a finite idle budget
up to 86,400,000 ms for applications with longer intentional silence; zero is
invalid. Establishment and write budgets must be 1..60,000 ms. This source change
does not configure TCP keepalive or claim native/deployed acceptance.

Tokio retains its existing `copy_bidirectional` buffering, byte counts and
half-close behavior. Both adapters are borrowed by one forwarding future;
timeout and cancellation drop that future without detached direction tasks.
Every absolute cutoff is checked before polling and again before accepting the
result. An expired idle clock cannot be renewed by a late ready byte. A stalled
write, flush or shutdown retains its original timer until timely completion;
late readiness cannot clear or restart that timer.
The surrounding handler owns the target socket and its caller owns the transport
and session permit, so these are released through the existing return/drop path.

[The source fixtures](tests.rs) are finite, in-memory paused-clock checks for
whole-establishment cancellation, absolute control-response writes, idle owner
and permit release, active asymmetric sessions, reverse half-close, stalled
writes despite reverse activity, stalled flush/shutdown, and cancellation.
Four additional manually polled fixtures keep the owner unscheduled across
expiry, then introduce ready establishment/control success, ready stalled I/O,
or one late payload byte. They require refusal before the expired inner owner is
polled or the idle clock is renewed. These are finite ordering controls.
Configuration fixtures are in [legacy_tcp_limits_tests.rs](../../config/legacy_tcp_limits_tests.rs).

Run only after root adoption in an authorized QA workspace:

```sh
cargo test --offline --locked -p aegis-server --lib session::legacy_tcp::tests -- --test-threads=1
cargo test --offline --locked -p aegis-server --lib config::legacy_tcp_limits_tests -- --test-threads=1
cargo test --offline --locked -p aegis-server --lib session::legacy_fallback_decoy_tests -- --test-threads=1
```

The preparation agent did not run these commands. R2 preserves frozen R1 and
addresses its independent peer's deadline-readiness findings. A passing fixture would prove
the in-memory policy and ownership cases it executes; row 52 stays open until
root adoption, causal regression results and exact-final-commit required CI.
