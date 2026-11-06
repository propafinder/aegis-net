# Explicit Liu channel for authenticated research streams

This opt-in Rust channel implements the existing finite label-conditioned Liu optimizer in the installed secure relay client and paired server. It does not replace the label-blind Calmon adaptive channel. An operator supplies the class prior and two class-conditional read-length tables, together with an exact canonical target host/IP, port and transport to class mapping. Unknown traffic is refused unless an explicit unmatched class is configured. Policy acknowledgement has its own explicit class and purpose. These declarations are operator assertions, not measured ground truth or inferred website classes.

## Model and admission

The existing `rate_distortion::Problem::label_conditional_wasserstein` minimizes modeled label/output mutual information under finite class-conditional Wasserstein-1 transport cost. `liu_channel` builds this problem and consumes `sample_label_conditional` in its owned stream. The runtime alphabet is exactly the current bounded application read length, 1 through P, with 2 <= P <= 8. Cost is |z-y|/(P-1), a dimensionless normalized byte difference. There are no bins, future labels, retraining or masked replacement solutions. The class prior and each directional conditional row use strictly positive bounded integer counts. The finite solver iteration, numerical gap and cancellation limits are public.

Every positive probability in the returned kernel must satisfy y >= z. A positive shrink probability causes pre-authentication refusal, including tiny positive probabilities. Exact zeros remain zeros; there is no causal-support trimming, rejection sampling, substituted kernel or unshaped fallback. The inherited finite 53-bit sampler divides each row by its computed total and uses its last positive action for cumulative floating-point roundoff; it is not an ideal real-probability sampler. The useful nonconstant fixture has prior [1/4,3/4], conditional rows [3/4,1/4] and [1/4,3/4], budget 1/8, and output alphabet 1,2. Its actual kernel has zero forbidden support and class output laws [1/4,3/4]. Reversing the prior is a real refusal fixture, not a modified optimum. Numerical certificates are qualified IEEE diagnostics, not interval proofs.

A public fixed-model fixture pins all kernel f64 bits and the full two-direction kernel/certificate digest. Local matching peers do not establish cross-platform interoperability: actual Linux, Windows and Darwin CI must execute that fixture. Platform math drift refuses protected agreement instead of silently substituting a kernel.

## Real client and server ownership

`relay/secure.rs` prepares the public profile, exact target/purpose and both kernels before opening sockets or loading private identity. Managed device bundle rendering includes the typed profile in public configuration and the existing four-buffer digest; the existing online loader pins that configuration before private sidecars. The server agrees to the same strict profile, context and actual prepared kernel/certificate digest inside authorized device TLS, before exchanging fresh contributions or transmitting framed data. Target, port and transport must match the following Open before any target dial. Traffic and PolicyAck purposes cannot be substituted.

Both peers contribute fallible fresh OS entropy inside the existing authorized TLS connection. Owned zeroizing contributions and HKDF derive per-session, profile/context/kernel/direction consistency descriptors. The frame digest is corruption and transcript consistency checking under TLS; it is not independent authenticated encryption, a calibration proof or a public secret-class hiding guarantee. Failure is sticky, module-owned static phase plus ErrorKind; transport error text, payloads and contributions are not retained in public diagnostics.

The enabled client captures its original session origin before validation. Endpoint selection carries its earlier original origin through retries; establishment and session clocks are not reset by optimizer preparation or agreement. The server uses its original connection origin. Preparation is finite cooperative off-reactor work: owner cancellation sets a flag checked within the real solver. Aborting a Tokio blocking handle cannot forcibly stop an already running system thread. Actual entered-worker and callback cancellation fixtures observe that the task keeps its owned inputs until exit and completes cancellation without returning a detached model result.

The [shared optimizer admission](implementation-and-composition.md#optimizer-preparation-admission)
uses the same process-local four-job/32-waiter pool as adaptive preparation.
**One Liu permit spans both original directional solves** under the same captured
optimizer cutoff; the first result does not release capacity for a second job.
Caller cancellation does not free capacity while its blocking job survives.
No directional model, numerical/causal-support check, kernel descriptor or HELLO
ordering changes. Controlled wrapper ownership regressions pass; this is an
unmeasured availability policy; native capacity and archived-client agreement
remain open. The mixed-version cold HELLO budget gap concerns the deferred
HELLO-first proposal; the current implementation retains its historical
agreement order.

The stream owns a paired bounded duplex worker. Drop aborts that async worker; I/O, original lifetime, memory, wire and sequence bounds refuse rather than becoming a clean exhausted stream. Each complete frame is validated before any of its application bytes are released. FIFO, exact sequence, direction/profile consistency and explicit END preserve bidirectional half-close. A Liu PolicyAck request sends END and the paired server verifies request EOF before its ACK; ordinary non-Liu PolicyAck wire behavior is unchanged. Configuring multiple shaping owners or composing an arrival guard refuses. The absent Liu field retains the existing path.

## Framing, batching and physical limitations

A data record contains 48 header bytes and 32 digest bytes in addition to the selected padded payload of 1..P bytes. END also costs 80 bytes. All of those bytes count toward the declared wire budget. Thus a selected two-byte output costs 82 inner bytes: the modeled output alphabet is not total bytes, physical packets, H2 DATA frames or TLS ciphertext lengths. This admitted exact-length scope is intentionally small and inefficient. It is an experimental inner-chunk research mode, not a transparent efficient full-wide DPI defense.

Already complete causal records are coalesced into a declared bounded batch (largest record must fit; maximum 4096 bytes and no larger than the buffer cap). Only immediately ready current input may join that batch. Pending input flushes a short request without waiting for future input; the public size cap flushes sustained input. The earliest queued record owns the entire batch I/O deadline, which later arrivals cannot extend. This changes outer H2/TLS observables, explicitly outside the Liu modeled output law.

This batching addresses an actual owned TLS/H2 PolicyAck failure: many tiny DATA writes triggered the unchanged vendored H2 `too_many_data_frames` protection. The initial request-END-only attempts still failed and are retained. Complete-record coalescing passed the real PolicyAck fixture without altering the H2 limit, clock, model or solver. Short Pending requests, sustained ready input with partial writes, late synchronous writes, replay, malformed records, cancellation and wire exhaustion have separate ordinary tests.

The paper model applies only if the supplied directional read-length distributions and prior describe this workload. Tokio reads, coalescing, H2/TLS segmentation, endpoint selection, timing, END, errors, cancellation, output length overhead and traffic correlations are outside that memoryless model. There is no claimed whole-flow privacy, physical packet law, field calibration, censorship resistance or independent-capture acceptance. This source integration does not close the original beta lifecycle, signing or target-network gates.

## Primary sources

- [Liu and coauthors, Rate-Distortion for Encrypted Traffic, arXiv:2607.17889](https://arxiv.org/abs/2607.17889): finite label-conditioned channel and Wasserstein transport model; direct primary reading and the unchanged solver provenance are retained in the rate-distortion research receipts.
- [Calmon and Fawaz, Privacy against Statistical Inference, arXiv:1210.2123](https://arxiv.org/abs/1210.2123): distinct label-blind executable channel model; it is not substituted for the Liu optimizer here.

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
