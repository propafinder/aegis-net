# Causal finite-channel byte adapter

The adaptive channel is an opt-in byte carrier **inside an already authorized,
authenticated TLS connection**. Its record digest supplies consistency, not
independent cryptographic authentication. A generic AsyncRead/AsyncWrite type
does not prove TLS. The client/server owners must perform typed profile
agreement and select exactly one shaping owner before a target request.

Public `AdaptiveSettings` contain integer training counts, ascending length-bin
upper bounds, concrete padded-length/delay actions and finite work, memory,
wire, IO, queue and lifetime budgets. `validate()` and `descriptor()` are pure;
the descriptor binds every field plus the version. Runtime actuation observes
only bytes already read. It does not consult a future packet or secret label.
The allowed-action mask excludes padded sizes smaller than each bin's upper
bound. Delays are nonnegative and at most one second. Unobserved bins, missing
physical actions and unsupported numerical training inputs refuse.

The typed relay client/server captures the lifetime origin before public profile
validation, optimizer preparation and agreement. The earliest of the outer
profile and nested adaptive lifetime bounds this whole admission; the caller's
establishment deadline may shorten it further. The same original session end
passes to the installed adapter, so a short inner lifetime cannot restart after
training or agreement. No carrier is promoted after this admission deadline.

`prepare(settings, original_deadline)` runs the bounded label-blind convex
optimizer off the async reactor. The task owner sets cancellation on Drop;
running blocking work stops cooperatively at its checks/original deadline.
There is no force-cancellation or hard kernel scheduling guarantee. The
optimizer must converge to its requested numerical gap or return no channel.
Its IEEE certificate is not a directed-rounding or whole-flow privacy proof.

All adaptive objectives use the
[shared optimizer admission](implementation-and-composition.md#optimizer-preparation-admission)
with Liu: four queued/running blocking jobs and 32 waiting callers per process.
Waiting spends the already captured optimizer cutoff; saturation/expiry is
terminal refusal without a new channel, renewed budget or unshaped fallback.
The job retains its permit while queued/running despite awaiting-caller
cancellation. Objective mathematics, descriptors and HELLO order are unchanged;
controlled wrapper regressions pass. The 4/32 policy remains unmeasured under
native production load.

`attach_authenticated(transport, prepared, original_deadline)` reuses the
caller's original absolute lifetime; frames never renew it. Root configuration
must also admit these caps within the outer PrivacySettings budgets. Each
direction owns bounded local buffers and a finite wire allowance. IO phases
have absolute, monotonic before/after observations. Dropping the stream aborts
its single task and both directions. A terminal worker error remains sticky;
missing/truncated END cannot turn into clean EOF. Half-close completion waits
for the actual END write. Flush promises bounded local acceptance only.

A data record has a fixed 48-byte header containing version, kind, action,
sequence, payload length and complete profile descriptor, a sampled padded
body, and a 32-byte SHA256 consistency trailer. Length/profile/sequence/action
and the complete body/trailer are validated before any byte from that record
is delivered to the application. Padding entropy and policy sampling use
fallible OS entropy; no deterministic fallback exists. A fixed 80-byte END
record is counted in the wire allowance. There are no idle/dummy records.

The optimizer's cost is padding relative to **bin lower bound**, plus a public
weighted delay. This conservatively bounds padding for each actual read in the bin; real
per-record overhead adds 80 bytes, separately counted in runtime statistics. Expected cost is not a per-packet
maximum, Internet queue bound or TCP traffic theorem. Backpressure, packet
segmentation, TLS framing, endpoints, timing resolution, session length, EOF
and cancellation are outside the finite-model mutual-information guarantee.
The IO tests prove adapter mechanics only, not the trained distribution's fit
to real traffic, installed adoption or resistance to commercial/state DPI.

Tests use actual ordinary duplex streams: FIFO and bidirectional half-close,
first record before future input/EOF, real padding/delay, full-record admission,
sticky malformed/corrupt/profile/shrink refusals, original expiry, partial EOF,
bounded backpressure, owned Drop with an unaffected spectator, and wire
exhaustion with no successful finish. These are not VM/fleet/capture acceptance.

## Idle and started-record deadlines

The stream receiver waits for the actual first wire byte under the caller's
original finite session end. After that byte, one absolute cutoff, capped by
that same end and `io_timeout_ms`, covers the remaining record reads. Partial
reads do not renew this cutoff. Cover also checks completion of its decoder
under this cutoff; adaptive/Liu retain their existing synchronous validation
and separately bounded application-delivery phase. Application delivery keeps its separate
existing bounded phase; no session origin restarts and no idle records are added.
Standalone finite control operations keep their own existing operation cutoff.

Both peers need the updated stream reader for bidirectional idle compatibility.
The unchanged settings descriptor does not distinguish an older reader that
still times out while waiting for a record. This is an updated-reader behavior,
not a negotiated mixed-version capability or a keepalive protocol. Local paired
codec and byte-gate tests do not establish installed or restricted-network
acceptance. Existing Drop abort semantics do not guarantee synchronous joining
of descendants during panic or cancellation.
