# Causal arrival envelope and conditional queue bounds

`traffic_privacy::network_calculus_guard` implements integer token-bucket
admission for actual bytes entering a shaped FIFO. The caller records monotonic
nanoseconds and admits bytes before forwarding them. No borrowed tokens,
rounding debt, waiting, rate-changing fallback or synthetic service observation
occurs in the guard. Fractional tokens remain exact as byte-times-nanoseconds.
Refused events do not change timestamps, balances or counters; the enclosing
runtime must terminate rather than forward the refused bytes.

The source is the [Le Boudec–Thiran book](https://leboudec.github.io/netcal/),
[chapter 1, section 1.4 and Figure 1.10](https://leboudec.github.io/netcal/latex/netCalBook.pdf).
For arrival envelope `alpha(t)=b+r*t` and a genuine rate-latency service curve
`beta(t)=R*max(t-T,0)`, with `R>=r`, the backlog bound is `b+r*T`. The FIFO
delay bound is `T+b/R`. Integer results round upward, never downward. The code
rejects `R<r`; it does not return finite bounds for that case.

These are conditional calculations. Every bound and admission explicitly keeps
`guaranteed_service_verified=false`. Actual read-byte admission enforces only
the arrival premise. A nominal fixed frame rate is an upper capacity, not a
verified lower service curve for the OS scheduler, socket, remote peer or
Internet. `validate_local_ceiling(payload_bytes, period_ns)` rejects a configured
R above the nominal local ceiling and T below one discrete frame period. Passing
that necessary check does not prove service. Packetization and scheduling slack
must be accounted for by the caller in any justified T; arbitrary external
service cannot be inferred from a ready signal or an on-time frame sample.

`service_failed()` irrevocably invalidates future admissions and removes the
conditional bounds from subsequent snapshots. Previously retained admissions
certify only their arrival accounting, never queue delay or guaranteed delivery.
Runtime integration must call it on known service failure and refuse the stream;
it must not reuse a historical conditional snapshot as an unconditional receipt.
Fresh guards belong to fresh stream sessions, not a way to reset exhausted
tokens during one live stream.

Public settings are exact integer values: burst in bytes, arrival/service rates
in bytes per second and latency in nanoseconds. Burst is 1–16MiB, rates at most
1GiB/s, service rate strictly positive, and latency at most one hour. A zero
arrival rate allows only the initial finite burst. Each guard has one original
one-hour lifetime, at most one million positive admissions, checked u64 byte
counters, and checked u128 intermediate arithmetic. Time at the exact original
expiry is refused; no operation moves the expiry. Empty EOF events are not
counted as admitted bytes. This code has constant state and no timers, files,
native policy, credentials or network actions.

The root caller wires the opt-in guard into the real constant-cadence read/FIFO
boundary and validates compatible settings before runtime custody. Variable
Gaussian, adaptive and Poisson schedules lack this deterministic service premise
and are refused when combined with this guard. The module by itself does not
establish that a deployed system meets its configured service assumptions or
close any capture, installation, field measurement or beta-exit gate.
