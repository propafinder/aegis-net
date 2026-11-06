# Explicit application-owned Poisson insertion

`secure_channel::poisson_insertion::{send_owned, receive_owned}` is a bounded, one-use Rust SDK exchange for an application that explicitly owns its source and sink. `aegis-measure poisson-insertion` calls that SDK with private application/control input files and two exclusive private output files. It does not intercept TUN, browser, operating-system or third-party traffic and does not change installed client defaults.

The source's actual AsyncRead chunks become authenticated original records. Bob verifies the complete record before forwarding its payload to the owned sink, in FIFO order. Read chunk boundaries are neither preserved UDP datagrams nor inferred IP packets. The original source is never forced to obey a Poisson process; its bytes are preserved, while backpressure can delay observation/forwarding. Source EOF does not terminate the public insertion horizon.

Alice independently proposes exponential insertion intervals using fallible OS cryptographic entropy and a finite midpoint uniform transform. Every inserted record carries the same private, bounded control block. Bob recovers that block only from authenticated inserted records and removes those records from the application sink. The control block is absent from TLS admission, receipt metadata and terminal record. Zero actual insertions means delivery failure; no retry or horizon extension repairs it. This control-block repetition does not claim a capacity-achieving independent-message code.

Both record types use the same public fixed width: capacity + 3 encrypted kind/length bytes + 16-byte ChaCha20-Poly1305 tag. Unused plaintext slots receive fresh random padding. The ordinal forms a unique nonce under a one-use exporter key/prefix derived after fresh authorized TLS1.3 and exact independently supplied profile agreement. The existing TLS constructors disable resumption and early data. Material has no Clone/Debug, and private payload buffers wipe on drop. The receiver uses its expected ordinal, so altered ciphertext, reordering and replay fail authentication. These computational assumptions are not an ideal content oracle or an outer-wire distribution proof.

A single writer serializes original and inserted records, with one fixed-size input buffer and one record; there is no unbounded wire queue. The receiver anchors its minimum terminal time before the protected profile ACCEPT. The sender starts the declared full horizon after receiving that ACCEPT. An authenticated premature terminal is refused; the receiver anchor is a local lower bound, not synchronized physical packet timestamps. The original caller deadline covers authentication, profile exchange, source, insertion horizon and count ACK. The insertion clock is not reset by source reads, writes or backpressure. Event/byte caps, finite entropy/clock resolution, late proposals, incomplete source, partial records, bad terminal counts, failed authorization and owned cancellation refuse the exchange. Cancellation drops only the owned source/carrier/sink and material; it does not manage other applications. A synchronous OS call is not made preemptible by a Rust deadline.

The authenticated terminal record lies outside the insertion horizon and binds actual original count/byte count/insertion count and original-byte SHA256. The final peer ACK compares actual decoded counts. Neither message content nor its digest appears there. Receive metadata records first/last observed framed-record arrival time, not physical packet captures or peer IP data. Sender successful writes are local accepted writes until the peer count ACK. Failure is not successful delivery, and discarded futures cannot produce complete count receipts. An owned sink can retain an authenticated original prefix after a later failure; the file operator retains any exclusive output already written and never overwrites a prior attempt.

## Conditional paper reference

[Soltani, Goeckel, Towsley and Houmansadr, Covert Communications on Poisson Packet Channels](https://arxiv.org/pdf/1610.00381), scenario1 and Theorem1, assumes homogeneous overt Poisson arrivals at lambda, independent inserted Poisson arrivals at delta, an observer restricted to timings/counts, and a recipient that can authenticate/remove insertions. The lab previously supplied only an ideal origin oracle. This SDK supplies actual computational authentication and application-byte preservation, under a deliberately explicit carrier contract.

For the **ideal** homogeneous count laws with fixed observation horizon T:

```
D(P0 || P1) = delta*T - lambda*T*ln(1 + delta/lambda)
minimum unweighted sum of testing errors >= max(0, 1 - sqrt(D/2))
```

The profile's overt rate is an operator hypothesis, not a learned or verified property of its actual source. H0 must already use this same encrypted fixed-width carrier/content; comparison against plaintext, differently framed application traffic or a content-authenticating observer does not satisfy scenario1. Actual TCP/TLS framing, finite CSPRNG/time resolution, scheduler deviations, write blocking, horizon delimiter and cap/refusal conditioning are outside the ideal theorem. Metadata always reports source_poisson_verified=false, whole_wire_law=false and installed_full_wide=false. A controlled independent Poisson source can test the software model but cannot calibrate real user traffic or DPI.

## Private operator

A private JSON config has `endpoint`, `deadline_ms` (at most60000), `tls` with either the existing explicit client/server settings, and a strict `profile`: `capacity`64..1024, `horizon_ms`20..10000, integer `insertion_rate_milli`, positive `overt_rate_milli`, `max_records`2..512, `max_wire_bytes` at most1MiB, `io_timeout_ms`1..1000 and `max_lateness_ms`1..1000. Source input capacity and all public bounds are checked before the exchange. No application/control bytes, secrets, certificates or exporter values are accepted in argv or printed.

Sender: `aegis-measure poisson-insertion --config-json PRIVATE_CONFIG --application-input PRIVATE_ORIGINAL --control-input PRIVATE_CONTROL`.

Recipient: `aegis-measure poisson-insertion --config-json PRIVATE_CONFIG --application-output NEW_PRIVATE_ORIGINAL --control-output NEW_PRIVATE_CONTROL`.

Use independently authorized fresh identities and an independently agreed profile. The recipient watcher starts inside the runtime and a revoked authorization lease cancels the exchange. A successful peer ACK means authenticated decoding/count agreement; it does not establish disk persistence, application acceptance, public packet-law matching, production rollout, native full-wide acceptance or beta exit.

## Exact `dcb3923` positive TLS fixture and diagnostics, 15 October 2026

The manual Linux ARM64 positive failed with a timed-out inner exchange whose phase was hidden by the public error boundary. A test-only diagnostic now prints only the code-owned inner phase and `ErrorKind`; the public error remains masked. The positive fixture supplies fixed midpoint random draws to the same private TLS/exchange path, avoiding near-zero random source slots, while public `send_owned` still supplies `OsRng`. The 150 ms horizon, 200-per-second profile, original deadline, real TLS, FIFO, authenticated control and count assertions remain unchanged; separate tests continue to exercise variable draws. The internal `CI-dcb3923-fixture-repairs-r1/receipt.md` receipt (outside this delivered guide kit) records 1/1 canonical macOS ARM64 and 20/20 isolated repeats. It does not classify the original Linux failure's hidden phase or replace exact successor Linux ARM64 CI.
