# Bounded exponential pacing in authenticated carriers

An explicit `authenticated_shaping.poisson_pacing` profile chooses exponential
inter-frame proposals in the installed authenticated relay and opaque carrier
paths. Relay/H2 peers verify identical complete parameters inside device TLS
before target traffic; a mismatched relay profile refuses without downgrade.
The explicit opaque carrier has no typed profile hello: operators must
pre-agree its complete parameters out of band. Its wire decoder does not
verify equal timing means or constant-versus-exponential policy, so opaque
mismatch refusal is not claimed. Omission preserves the old constant-cadence
profile and its serialized bytes.

The mean is caller-declared (`mean_interval_us`), not inferred from an average.
`max_gap_us` is a public maximum (at most one second); `cadence_ms` must equal
its ceiling in milliseconds. The existing bounded FIFO, queue allowance, wire
budget, I/O timeout, lifetime, paired frame decoder and owned cancellation still
apply. Every delay proposal uses independent fresh OS entropy. Proposals beyond
the declared maximum refuse the owned stream; there is no clamping, resampling
or catch-up burst. New delays begin after completed emission, so blocked transport
cannot accumulate an unbounded emission backlog. Filler is used only inside
an already authenticated encrypted channel.

In typed relay/H2 sessions, the lifetime starts immediately before the shaping
agreement, after device TLS, and is passed as an absolute cutoff to the worker.
Waiting for the peer or for the worker to be scheduled cannot restart that cap.
This is distinct from the original connection-establishment deadline. Opaque
carriers have no typed agreement and retain their existing worker lifetime.

This applies an engineering component motivated by [Soltani et al., Covert
Communications on Poisson Packet Channels](https://arxiv.org/abs/1610.00381).
The paper assumes a legitimate Poisson source and a particular timing-channel
codebook/queue. This implementation has no legitimate service cover calibration
or covert timing codebook/decoder. Fixed-frame decoding recovers application
bytes, not information embedded in packet timings. Quantized finite entropy,
timer jitter, TLS/TCP packetization, tail refusal, EOF, cancellation and network
stalls prevent an unconditioned Poisson wire-law claim. Neither a hidden capacity,
square-root/linear covert rate, whole-flow DP nor field DPI efficacy is claimed.
The queue bound is conditional on timely owned I/O, not a hard Internet guarantee.

Constant cadence and exponential pacing are alternative owners of the same
frame timing. Do not stack this with a randomized schedule emitter; the shared
privacy-plan guard must reject conflicting owners. The one-message finite-cover
control codec and offline frontier/fleet/Brain analyses have separate scopes.


## Shared constant/exponential frame wait

The shared fixed-frame encoder waits after collecting input only if its original
next frame moment is still in the future. An already elapsed next moment needs
no second Tokio timer poll. The original absolute deadline check still follows
that wait; this does not revive a spent session or permit early emission.
Constant cadence and exponential proposals retain exactly their original draw
ordering, tail refusal and post-completed-write next-gap origin, without catchup
bursts, clamping or resampling. Host scheduler latency and whole-wire Poisson
law remain unverified independently of this source-level redundant-wait repair.

## Separate UDP control owner: pending-service cutoff

The [paired UDP timing-control SDK](poisson-runtime-control-channel.md) has a
separate native packet-release owner; it is not the fixed-frame exponential
pacer described above. Its wait point and latest permitted return are distinct.
When an admitted original packet remains pending, the owner carries its original
nominal point plus the single declared release allowance as an absolute
latest-return bound. The Windows wait clips its own point-based allowance by
that bound and the unchanged original operation end. Waiting until a pending
service deadline cannot grant a second release allowance. Before and after the
owned wait, the caller also checks the original pending deadline; refusal
retains unsent custody and never adds a successful packet to the sent prefix.
With no pending packet, the existing wait bounds and draw/schedule path remain.

This corrects a separate pending-service bound composition issue. The original
Windows positive refusals recorded with an empty pending-service queue are not
explained or repaired by this change. Original nominal arrivals, codebook seeds,
10 ms fixture release cutoffs and positive assertions are preserved. The local
argument/expiry regressions prove boundary composition and custody mechanics;
they do not prove Windows native acceptance, physical departures or hard
real-time scheduling.

## Windows owned-thread priority after the hosted timer refusal

An exact `acb8fcf` hosted Windows positive refused after a 45.113 ms native
wait overshoot; the original 10 ms cutoff correctly prevented a late release.
The owned release thread previously requested relative `+1` under a
`BELOW_NORMAL` process, leaving it at base priority 7 below ordinary normal
threads. The reviewed source now requests relative `+2` for that class alone,
bringing only this dedicated thread to ordinary base 8 while preserving the
base-11 ceiling, readback checks, original clocks, cutoff and bounded work.
Other process classes retain their prior request. An isolated native Windows
ARM64 run passed the fake priority matrix and one fixed-seed actual SDK UDP
positive from a SHA-matched test PE; canonical host fake tests passed 1/1.
This is a scheduling request and scoped positive evidence, not a latency
guarantee. Exact successor hosted CI and the full original acceptance remain
required; a future late wait must still refuse.
