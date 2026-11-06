# Finite binary schedule emission

`aegis_core::traffic_privacy::schedule_emission` connects the existing exact
binary randomized-response accountant to a real bounded asynchronous sender
and authenticated peer decoder. It is an explicit experimental core API. It
does not enable a new installed transport or change client defaults.

The public profile fixes 1–64 slots, 1–256 payload bytes per cell, nominal cadence
of at least 1 ms, a horizon of at most 30 s, and cooperative I/O timeout of at
most 30 s. The complete input is a bounded preloaded batch with exactly the
public number of cells. Empty cells are dummies. This is not a live unbounded
arrival queue, a throughput optimizer or a VPN carrier.

For every public slot, the sender clips the cell-presence query to `{0,1}` and
calls the **same live accountant before preparing/writing that slot**. The
released bit selects one of two frame sizes: fixed encrypted cell plus a clear
released-bit byte and either zero or sixteen public zero padding bytes. Every
slot carries the fixed encrypted cell, whether it contains a payload or a
dummy, regardless of the released bit. Thus no queue-availability fallback,
private length header or early empty-queue EOF affects the selected frame size.
Completion waits for the fixed public horizon; no retries are implemented.

Budget admission checks exact public rational arithmetic for the complete
horizon without releasing bits, using entropy, spending or resetting the live
accountant. Unsupported arithmetic and an insufficient full-horizon budget
refuse profile construction. The actual sender's one accountant persists
through all slot releases and failures. Failures retain its actual composition
receipt, including conservative spending if entropy fails before any bytes.
Written-frame counts exclude incomplete writes; an explicit flag marks possible
partial emission. Cancellation drops the consumed sender and material; it
cannot provide a terminal receipt after its future is discarded.

Both peers must independently obtain a fresh dedicated batch/direction
ChaCha20-Poly1305 key and nonce prefix over a trusted authenticated provisioning
channel. A bounded slot counter supplies distinct nonces within the batch.
The public profile descriptor, slot index and released bit are authenticated
associated data. Two-byte private length, fixed payload area and dummy padding
are encrypted and authenticated. Nothing is returned by the receiver before
every cell authenticates. Later stream bytes remain untouched. Key/prefix and
plaintext owners are non-Debug/non-Clone or zeroizing as appropriate. The API
cannot enforce freshness across reconstructed material, backups or restarts.
On error/cancellation, callers must discard a potentially partial stream;
stream lifetime belongs to the caller and no hidden reconnect or cleanup is
performed by this byte-stream API.

## Exact scope of the accounting statement

For a fixed public profile, each query is binary. Neighboring query sequences
may differ at any slot. With `truthful >= flipped > 0`, either released outcome
has likelihood ratio at most `truthful/flipped` between any two binary queries.
Independent unbiased fallible cryptographic draws compose over the fixed
number of slots. The actual receipt bounds the ratio by its exact rational
`odds_numerator/odds_denominator`, corresponding to pure DP with
`epsilon = ln(odds_numerator/odds_denominator)` and delta zero for that
**released-bit transcript only**. The two frame-size choices are deterministic
post-processing of those bits and the public profile.

This does not prove information-theoretic DP for ciphertext contents: the
content has the separate computational AEAD assumption. It does not protect
endpoints, handshake, total public slot count/profile, failures, cancellation,
completion disposition, transport/scheduler stalls or actual measured timing.
Cadence is nominal; blocked writes can delay later slots. Error observations
and conditioning on secret-dependent errors are excluded rather than claimed
private. Nothing here proves whole-flow DP, protocol/application-identity
hiding, independent physical-wire observations, delivery, active-censor
resistance, real cover similarity or beta exit.

## Primary source and transfer limit

Sabzi et al., [NetShaper, USENIX Security 2024](https://www.usenix.org/system/files/usenixsecurity24-sabzi.pdf),
sections 2.2–2.3, 3 and 4, was checked on 9 October 2026. The relevant lesson is
to connect accounting to actual scheduled emission and bounded queues. This
binary randomized-response batch consumer is **not** the paper's Gaussian
mechanism, sensitivity/window proof or QUIC middlebox implementation. The
paper's security goals exclude hiding protocol and application identity.
No NetShaper theorem is transferred to Aegis here.

RustCrypto `chacha20poly1305` 0.10.1 and the existing checked
`traffic_privacy::schedule_dp` source provide the pinned implementation APIs.
No cryptographic dependency or lockfile changes are required.

Targeted validation covers real localhost TCP dummy/data round-trip, actual
composition versus admission, no bytes on invalid input/initial entropy loss,
retained spending after later entropy loss, authenticated ordering/profile and
complete-batch refusal, two-size selection, real bounded backpressure, idle
receive timeout, owned-task cancellation and a separately labelled virtual-time
fixed-horizon check. Local TCP is not a target network or an independent capture.
This research slice adds no hidden release criterion.
