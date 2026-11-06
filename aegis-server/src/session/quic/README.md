# aegis-server/src/session/quic

Startup diagnostics and admission regressions for QUIC ingress.

## Contract

startup.rs reports policy, address, TLS, transport, bind and endpoint stages using static labels and I/O kinds. It excludes original error strings, credentials, paths and listener addresses. Preserve the parent quic.rs readiness contract: failure of required ingress must prevent successful startup.

Unvalidated peers receive Retry before TLS or application admission. Pending
Initials and unauthenticated sessions have separate limits, each capped at the
smaller of the normalized connection limit and 64. Pending buffering allows
4 KiB of additional data per Initial; Quinn excludes the first datagram from
that byte limit. These limits are not a total endpoint memory or CPU bound.

One original admission deadline covers queueing, TLS, H3 setup and credential
validation. Expired queued work is refused before its first session poll.
Validated credentials and matching target authority precede promotion to the
shared established TCP/QUIC pool. The H3 owner retains the established permit
through forwarding and response drain; authenticated sessions can outlive the
admission deadline. Timer checks are cooperative, without per-IP fairness or
hard CPU preemption guarantees.

## Key files

- [startup.rs](startup.rs)
- [admission_tests.rs](admission_tests.rs) — admission clock and permit ownership.
- [Public admission tests](../../../tests/quic_admission.rs) — loopback Retry,
  stalled peers, available TCP capacity and an authenticated long session.

The enclosing module is [quic.rs](../quic.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked --no-default-features -p aegis-server --lib session::quic
cargo test --locked --no-default-features -p aegis-server --test quic_admission --test quic_lifecycle -- --test-threads=1
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-server](../../../README.md).

[Repository overview](../../../../README.md) · [Parent directory](../README.md)
