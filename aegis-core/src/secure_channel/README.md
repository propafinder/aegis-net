# aegis-core/src/secure_channel

Independent TLS 1.3 device channel, bounded control/datagram framing, enrollment, registry freshness and paired experimental shaping.

## Contract

Outer carrier admission does not replace device authentication. Explicit trust roots and registry authorization precede target traffic. Enrollment bootstrap authenticates the authority but cannot grant a data-plane lease by itself. Registry storage commits the freshness floor before the snapshot. Framing agreement must complete before traffic and must not fall back on disagreement.

Relay callers acquire an unauthenticated handshake permit, authorize device TLS,
acquire an authenticated session permit, then release the handshake permit.
Both pools are finite and independently configured under
`transport.inner_tls.admission`: `max_handshakes` (128), `max_sessions` (1024),
`max_handshakes_per_peer` (16), and `max_sessions_per_peer` (128). A known ban
is checked before either pool. Capacity refusal is `WouldBlock`, never an
authentication failure. Verified forwarded client identities get their own
quotas; missing identities share a bounded unknown bucket. Dropping a permit
reclaims both its global slot and its peer count.

Device TLS retains one captured handshake deadline and checks it after TLS and
registry authorization. A valid proof buffered until after that cutoff returns
the typed authentication timeout; ready I/O cannot promote a late channel.

## Key files

- [mod.rs](mod.rs)
- [datagram.rs](datagram.rs)
- [registry.rs](registry.rs)
- [registry_storage.rs](registry_storage.rs)
- [enrollment_wire.rs](enrollment_wire.rs)
- [policy_ack.rs](policy_ack.rs)
- [private_control.rs](private_control.rs)
- [poisson_control.rs](poisson_control.rs)
- [relay_shaping.rs](relay_shaping.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib secure_channel
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

### Poisson cooperative-input failures

The `poisson_control` fixtures offer UDP input only after the authenticated
sender's readiness callback. A cancelled callback returns zero offered packets
with `BrokenPipe`; an expired readiness deadline returns zero with `TimedOut`.
The certificate-refusal regression joins this producer and verifies socket
release, while retaining the original TLS refusal and zero delivered packets.
This prevents a secondary readiness panic from hiding the sender/receiver cause.

Paused-clock regressions cover the readiness deadline and the closed input
window. They exercise fixture ownership and control flow, not native timer
precision. Real-clock positive SDK/TLS delivery checks still require successful
authenticated decoding under their original cutoffs; a typed timing refusal
does not count as positive delivery. Both original channel outcomes are emitted
before fixture-task cleanup, so a secondary join/deadline panic cannot hide them.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)


### Registry reader terminal ownership

The watcher retains the original blocking read handle as well as its async
refresh handle. Closing reader admission precedes watcher cancellation; at most
one read is outstanding per watcher. The original verified storage reader,
refresh interval, three-second freshness cutoff, policy expiry and authorization
leases remain unchanged.

`RegistryWatcher::stop_and_join_read_until(&mut self, cutoff)` observes both
handles under one absolute caller cutoff. A cancelled or timed-out borrowed
wait leaves the watcher holding its join authority for another observation. A
ready join after the cutoff is refused. `stop_and_join_until(self, cutoff)`
remains a consuming compatibility API, but success requires the read to have
joined too. If it times out, it cannot promise join authority remains available
after the owner is consumed.

Task abort cannot preempt a synchronous read that has already started. Drop
fail-closes authorization and requests cancellation; it does not join either
task. Abrupt outer cancellation, early startup errors and callers which retain
only Drop cleanup remain outside explicit terminal-drain acceptance. Restarting
a watcher after Drop is still permitted; this per-watcher bound does not create
a global bound over previously unjoined readers.

The main server drains its watcher concurrently within the existing shutdown
grace (zero after a prior runtime error). Carrier shares its existing ten-second
ingress cutoff when ingress is still pending; an already-finished ingress gets
an explicitly new reader-only 500ms cleanup cap. Carrier's prior session joins
remain unbounded. WebRTC applies an explicitly new single 500ms terminal cap to
its task set and registry watcher, separately from its original five-second TLS
handshake and connect/broker lifetime. These new 500ms policies can refuse a
slow stop; they add no transport, authorization-permit or service-clock budget.
A timeout returns an error and static diagnostic, while an earlier runtime
error retains precedence. Synchronous filesystem and mutex work is not
hard-preemptible by these async cutoffs.

[registry_reader_owner.rs](registry_reader_owner.rs) retains the typed original
handle without a proxy or reaper task. The
[reader cleanup fixtures](registry_reader_cleanup_tests.rs) use the actual
watcher and verified snapshot/floor reader, with a finite test-owned hold in the
entered read callback before filesystem access. This is a controlled blocking
worker-lifetime witness, not evidence that a kernel filesystem call can be
cancelled. Exterior fixture owners release that hold and attempt joined cleanup
before assertions. The consuming-API control retains a test-only reader owner
for cleanup; production callers do not gain that extra owner.
