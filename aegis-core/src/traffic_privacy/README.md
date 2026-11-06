# aegis-core/src/traffic_privacy

Experimental finite framing, cover coding, pacing, rate-distortion models and bounded stream consumers.

## Contract

Read each mechanism separately: schedule_dp bounds released binary queries; actual timing, cancellation and outer ciphertext are outside that claim. netshaper accounts for a reference discrete-Gaussian model; refusals and wire timing need separate analysis. Poisson control relies on external packetization/service premises. Finite-channel measurements and local tests do not prove whole-flow differential privacy, timing guarantees or censorship resistance.

Source coverage and accepted runtime behavior are separate: the
[eleven-work matrix](../../../docs/research/implementation-and-composition.md)
includes offline models and standalone operators as well as relay owners. Seven
local paired TLS/H2 composition checks do not establish all-eleven installed
acceptance, a remote classifier law or an OS/network service guarantee.

## Optimizer preparation

The [shared admission owner](optimizer_admission.rs) limits one process
to four queued/running blocking preparation jobs and 32 callers waiting for a
slot. Adaptive objectives and Liu share the same owner pool; one Liu job covers
both directional solves. Queueing consumes the original optimizer cutoff, and
refusal returns no channel or unshaped fallback. Cancelling an awaiting caller
does not free capacity for blocking work that remains queued or running.
See the [operator policy and limits](../../../docs/operations/traffic-privacy.md#optimizer-preparation-admission),
[finite optimizer](../../../docs/research/rate-distortion-finite-channel.md) and
[Liu runtime](../../../docs/research/liu-runtime-channel.md). Six scoped regressions verify real preparation ownership and original numerical
results; native deployment and release acceptance remain open.

## Installed shaping worker ownership

The installed authenticated server path gives its shaping worker an explicit owner for adaptive, Liu, cover, BIT-TRAPS, netshaper and regulated adapters. The owner retains the original typed task handle; result polling and cancellation observe that same handle exactly once. Admission rejects a second worker before spawning it. After forwarding ends or authorization is revoked, the server drops forwarding first, then aborts and awaits its worker under one independent 500 ms cleanup cutoff while authorization and the session permit remain held. An unconfirmed cleanup refuses success. This adds no packet deadline, grace period or global task reaper.

Drop alone requests abortion and does not prove the task was joined. Production client cancellation, abrupt abortion of the enclosing server/request task, and registry readers already inside blocking filesystem work remain outside this cleanup claim. Source wiring across six adapters does not establish native timing, field privacy, censorship resistance or release acceptance.

## Key files

- [mod.rs](mod.rs)
- [worker_owner.rs](worker_owner.rs): ownership and exactly-once observation of the original shaping task.
- [plan.rs](plan.rs)
- [shaper.rs](shaper.rs)
- [rate_distortion.rs](rate_distortion.rs)
- [rate_distortion_maximum.rs](rate_distortion_maximum.rs): optional maximum supported-output entropy reduction and bounded minimax search; see the [model and certificate limits](../../../docs/research/maximum-information-channel.md).
- [adaptive_channel.rs](adaptive_channel.rs): causal byte adapter with one explicitly selected optimization objective.
- [liu_channel.rs](liu_channel.rs): one prepared owner for both explicit directional kernels.
- [optimizer_admission.rs](optimizer_admission.rs): process-local preparation ownership and waiter limits.
- [general_coupling.rs](general_coupling.rs): finite memoryless or public-prefix conditional coupling.
- [cover_stream.rs](cover_stream.rs): fixed-record coupling inside an authenticated carrier.
- [cover_control.rs](cover_control.rs): one-use authenticated control record with an original I/O deadline.
- [schedule_dp.rs](schedule_dp.rs)
- [netshaper.rs](netshaper.rs)
- [poisson_channel.rs](poisson_channel.rs)
- [bittraps.rs](bittraps.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib traffic_privacy
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)

## Post-send cutoff diagnostics

The experimental Poisson owner retains an optional `service_cutoff` observation
only for its existing `service_completed_after_original_cutoff` refusal. One
event ordinal links admission lateness, pending wait, the observed write bracket,
completion lateness and the original allowance. All intervals use the original
Service and existing clocks; independent maxima must not be added as if they
belonged to one packet. The existing terminal publication carries the record.
There is no extra send, clock read, deadline relaxation or delivery ACK.

`Observations` remains Serialize-only. Absent records preserve the original JSON
Value exactly; present records add one optional numeric object. External Rust
struct literals with exhaustive fields and strict JSON schemas may need updating.
A controlled actual UDP send and original typed refusal verify this diagnostic,
with unchanged SDK, command and native-wait sources. The native Windows/Darwin
failure cause, physical departure timing and release acceptance remain open.


## Darwin admission cutoff diagnostics

The real owned macOS release thread retains one optional
`darwin_admission_miss` when admission crosses the original allowance. It
contains only bounded scalar intervals, event/block ordinals and attribution
flags. It does not serialize an absolute clock, codebook point, distance to a
block boundary, address or packet content. Absent records are omitted.

Two explicit native-wait entry/return clock reads are reserved and charged
before the syscall under the original work budget. The record separates the
observed wait interval and subsequent gather/admission gaps. Point and I/O
matching flags must be checked before attributing a wait to this admission;
the record alone does not establish kernel-only latency or effective scheduling.
QoS and Mach policy readbacks describe the request, not an OS latency guarantee.
The original 10 ms bound, refusal and strict positive assertions remain unchanged.
