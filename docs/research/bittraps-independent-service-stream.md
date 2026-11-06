# BIT-TRAPS finite independent-service stream

The reference is [Mathur and Trappe, BIT-TRAPS, §V and Theorem 4](https://www.winlab.rutgers.edu/~suhas/BITTRAP_TIFS_2col.pdf). Its stream model combines a queue with an independent service request `S`: transmit `min(X,S)` real bytes and `(S-X)+` padding bytes. Thus the inner departing size is `D=S`. The stationary average-padding identity requires a stable queue. This implementation does not promote that stationary argument or the paper's convexity conjecture to a whole-network guarantee.

`traffic_privacy::bittraps` implements the queue/service construction on an owned authenticated byte carrier. A validated serde `BitTrapsConfig` agrees public slots, cadence, timeout, queue capacity and an arbitrary finite service alphabet with positive integer weights. The complete profile is hashed into the descriptor. No received descriptor is trusted instead of recomputing validation. Construction limits slots, horizon, frame size, distribution size and weight sum.

Each public slot samples service independently before inspecting input. Sampling uses unbiased integer rejection over the declared weights and fallible secure entropy. A public draw/fuel/deadline refusal has no fallback. Fixed slot counts continue after actual input EOF. The FIFO carries real bytes first; remaining service is authenticated encrypted padding. Every record authenticates the profile, slot ordinal and visible selected size. The receiver admits a whole frame before returning application bytes and refuses sizes absent from the agreed alphabet.

`BitTrapsMaterial` owns one externally fresh direction/epoch seed and exposes no clone, debug or serialization. HKDF binds the profile and protocol domain, producing an AEAD key and nonce prefix; the slot ordinal completes the nonce. The caller must supply distinct fresh directional seeds and prevent reuse through restart/backup. Dropped material is zeroized. The installed stream adapter owns one duplex worker, propagates sticky errors and aborts that worker on drop. Half-close waits for the public epoch. A pending tail or an input whose actual EOF was not read refuses clean EOF. There is no data-dependent extra drain or terminal marker.

The original caller clock bounds the epoch, entropy, input collection, frame I/O and application delivery. Completion observed after its bound refuses. A finite queue applies backpressure; a receiver may have delivered an authenticated prefix before a subsequent failure, which is not an atomic whole-message admission claim. Local receipts contain byte/padding/tail diagnostics and must not be exposed as a private network transcript.

`finite_stream_law` enumerates the complete joint input/output sequence distribution for a bounded first-order Markov source and independent finite service law. It computes `I(A^n;D^n)`, its finite bits-per-slot value, padding cost, queue area, remaining tail and observable overflow probability. Overflow is an absorbing visible symbol; deleting its failed paths would falsely improve privacy. The model uses floating arithmetic and checked finite path counts. It is not a stationary information-rate solver or a one-letter MI surrogate.

`optimize_service_grid` exhaustively compares a declared finite set of service laws against explicit padding, queue-area, tail and zero-overflow constraints. It returns the best admissible candidate in that grid. It does not claim optimization over all distributions or validation of an infinite-horizon convexity result. The finite model counts bytes, not physical packet boundaries.

The ideal inner size sequence can be independent of arrivals; finite resource refusal, local backpressure, epoch creation/termination, entropy failures, encryption security, scheduler delays and outer TLS/QUIC packetization still need separate analysis. There is no claim that wire ciphertext has information-theoretic content secrecy, that hard caps hide all errors, or that this component alone proves full-flow privacy, DPI evasion or beta acceptance.

Numerical admission tracks positive-support overflow reachability separately from estimated probability. A positive path that underflows or otherwise cannot be represented refuses; it is never discarded as a zero-probability path. Mutual information uses differences of logarithms, avoiding underflow of a marginal-product denominator; nonrepresentable terms refuse. Grid zero-overflow admission uses reachability, not a rounded probability. These checks do not turn floating computation into an exact arithmetic theorem.

Queue storage is preallocated to its public capacity. Each dequeued backing cell is overwritten before removal; occupied slices are wiped directly on drop, avoiding a clearing-time relocation. Temporary input bytes are wiped immediately after enqueue and the entire temporary buffer is zeroized on error/drop. This is bounded owner-buffer hygiene, not a universal allocator/compiler/HKDF memory-erasure claim.

The input collection future checks the unchanged public tick before every actual
read poll. An expired wakeup ends that slot's gathering without consuming input;
the declared service slot still emits. A poll started on time that itself crosses
the tick remains a strict failure. No deadline, service draw or epoch is reset.
Owned worker errors retain the original ErrorKind and private typed static phase
labels (sampling, input, public tick, wire, receiver header/body/output); arbitrary
transport error text is discarded. These observations do not prove the phase of
the previously retained ARM CI timeout.


## Already elapsed public tick

After gathering input, the sender waits only while the original public tick is
still in the future. A fresh Tokio timer can yield or register at millisecond
resolution even when its Instant has already elapsed; re-entering that timer
adds an unnecessary scheduling boundary. Skipping that second wait cannot
permit emission before the public tick. The original tick plus write allowance,
absolute session deadline, post-I/O checks, independent sampling and finite
slot count remain unchanged. Delayed wakeups that have already spent the
original allowance still refuse before emission. This removes a source-level
redundant wait; it does not promise host scheduling latency or establish
Windows acceptance without fresh exact-source CI.
