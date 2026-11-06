# Cooperative Poisson timing control: experimental runtime

This Rust component implements a bounded **scenario 2 timing control channel** over explicitly owned application UDP packets, with an authenticated TLS control connection. It is experimental. A version-2 owned service-queue successor has actual controlled-localhost positive SDK and fresh TLS/UDP message delivery; these are not acceptance of real Poisson cover, M/M/1 service, whole-wire secrecy or a field deployment. The original strict prior-write-overlap implementation, its failed unconditional positive test, and subsequent boundary failure remain retained as predecessor evidence. A lifecycle test that correctly reports refusal is not a successful message transfer. Scenario 1 packet insertion and its live discriminator are not implemented here. This document does not claim completion of all eleven papers or beta exit.

The primary reference is [Soltani et al., Covert Communications on Poisson Packet Channels, §§II/IV](https://arxiv.org/html/1610.00381v2). Its timing construction slows a legitimate Poisson source once to build a buffer, then schedules a message using fresh random codewords through an M/M/1 FIFO service. The asymptotic capacity is `lambda * ln(mu/lambda)` nats per second under those premises. This runtime cannot establish the premises or finite reliability from that inequality.

## Executable callers

`aegis_core::secure_channel::poisson_control::send_once_with_ready` and `receive_once` are paired, separate operations. `ApplicationControl` carries the original origin/cutoff and a one-use cooperative `ApplicationReady` callback. The callback runs only after the genuine peer UDP collector is bound and ARMED, before the future public start. The calling application owns its exact source/sink UDP endpoints; it must supply its own existing authenticated sequence/origin if those guarantees are needed. The SDK never hooks another application's traffic, TUN interface, capture device, or an installed VPN flow.

The operator-source commands `aegis-measure poisson-control --config-json PATH --input-file PATH` client and corresponding `--output-file PATH` server consume strict public `Profile`/timing settings plus existing TLS client/server settings. Each config is bounded to 64 KiB. Private input is bounded by the public capacity, at most 16 bytes. A server output must be new and private and is written only after complete record authentication. Both roles preserve the initial deadline (at most 60 seconds) across configuration, private identity/input reads, socket creation, handshake, sampling, all packet operations and final publication. Native registry watchers start inside the entered runtime; revocation cancels the owned operation. An `authenticated_shaping` owner is refused rather than layered on the timing owner. Existing default client profiles do not opt into this command.

The caller requires matching profiles: six distinct nonzero numeric UDP addresses, loopback application source/sink addresses, a declared resource digest, timing limits, and admitted TLS identities/authorization. None of these fields proves the real application's origin, a genuine Poisson process, or a measured M/M/1 server. The genuine client readiness report exposes a public relative start and horizon; an external application must account for reading/dispatch delay. The SDK callback supplies the actual local `Instant`. No old device keys or leases are provisioned or renewed by this component.

## Packet and record construction

A fresh TLS 1.3 exporter supplies domain-separated record material and independent per-block/per-word draws. Each public block has at most 64 codewords; each codeword has a variable unconditioned Poisson event count with a strict cap. Exceeding any cap refuses, with no resampling or truncation. Integer nanosecond quantization of PRF-derived exponential draws is computational and finite, not an exact continuous Poisson law. Peers compare an authenticated digest of the complete ordered codebook; platform differences refuse instead of choosing another book.

One slowing/buffering phase is followed by a fixed public number of independent codebook blocks. One FIFO persists across all blocks; no flush, reset, payload marker or filler is inserted. Original bytes are forwarded unchanged. A bounded final drain lies outside the decoding interval. Actual source timestamps are socket-read observations, and actual receiver timestamps are socket-receive observations; neither is a kernel/wire arrival timestamp. TLS segmentation, UDP/IP headers, scheduling, losses and repeated datagrams remain observable and unverified.

Arbitrary bounded control bytes are padded to the public capacity, authenticated with ChaCha20-Poly1305, split into fixed-width indices, and decoded only from actual UDP arrival observations. Message length, ciphertext and indices are never sent as a TLS shortcut. Encoding material is one-shot even after an input refusal. Secret codebooks, draw buffers, record material, packet buffers and retained indices use zeroizing ownership; this is not a guarantee against compiler copies, allocator/kernel buffers or compromised endpoints.

The TLS metadata frame has one fixed public size independent of message/index/event count. Count fields and original-byte hashes occupy fixed slots with random padding; one metadata transmission and one success ACK have predetermined public slots. Work that misses a slot refuses. SHA-256 comparisons against authenticated TLS metadata verify expected ordered bytes before application-sink writes; identical/spoofed byte copies do not prove unique sequence or authenticated origin. No decoded control hint is exposed before the assembled record's AEAD verifies.

## Original time and ownership contract

Version 2 separates nominal service arrivals `A_i`, actual admission, service start/completion and observed receiver departures `D_i`. The paper's FIFO service allows a nominal arrival before the preceding service finishes. The owned thread preserves exactly the selected codeword points and original source order; it does not require the predecessor's stronger no-overlap condition. An original must actually be received no later than its unchanged nominal point; admission and successful write observation must satisfy that point plus the **existing** public `release_lateness_us`. A nominal point remains inside its original block, while its existing allowance can extend across the block boundary. A completely missed block plus that allowance refuses. Original operation and final-drain cutoffs never reset. Duplicate/reordered internal events, starvation, queue/work exhaustion, late completion and cancellation refuse. A known completed write is counted before any subsequent refusal.

The owner is one directly held nonblocking-UDP thread with bounded admission (16 simultaneously held actors). It observes its actual readiness before the application callback, uses a fixed 2 ms prewake and bounded park/spin work, and tracks original source reads, attempted writes, work and actual timing distortion. Codebook generation/copies/hashing consume the same aggregate 4,000,000-step cap; native clock polls consume the unchanged public precision-poll cap. Each loop checks cancellation and the original absolute cutoff. Success observes actual terminal state and joins its exact thread. Drop only requests cancellation and unparks that thread; it does not claim a join or force another resource closed. During release, the authenticated TLS lease/EOF remains observed. Darwin requests ordinary user-initiated QoS on its newly owned release threads, preserving a higher existing class, followed by the adopted bounded per-thread Mach time-constraint request/readback. These charged APIs establish requested policy, with no hard scheduling guarantee. Intermediate telemetry uses `try_lock`; the worker keeps authoritative counters and completely publishes its terminal snapshot. Actual admission timestamps and receiver departures are not falsely identified with exact continuous Poisson arrival points or ideal M/M/1 service.

The separately exposed async `Sender` API retains its stricter no-prior-completed-write-overlap behavior, but each buffering, block or drain command transfers its socket and FIFO custody to one directly owned native thread. Socket writes no longer require the caller's Tokio task to be repolled at a public point. Only successful actual terminal state and join before the original deadline restore both sockets and the original source epoch; refusal or cancellation consumes that Sender and cannot replay it. Current-command custody/disposal flags are separate from the known historical packet prefix. Work and precision counters accumulate across commands and transition into the version-2 owner. Validation precedes transfer. Paired version-2 operator calls retain their explicit overlapping service queue; admission and TLS exporter domain are versioned together, so an old peer cannot silently opt into those semantics.

On Darwin the owned thread maps an opaque `Instant` through a checked Mach uptime anchor into one exclusively owned kqueue timer. Each kevent64 request uses absolute Mach units, critical scheduling and explicit zero leeway, with the same <=1ms coarse requests, <=50us fine requests and final20us active guard. A bounded timeout returning zero is not point admission: the original caller clock still decides. Returned events must match the timer identity, filter and original deadline token; unexpected counts, registration errors and stale events refuse. Native errno is saved before diagnostic clocks. Creation and every wait pay the original work and clock guards; only a successful wait and postreturn guard restore owned descriptor custody. Failure drops that descriptor. No original point, existing10ms allowance, seed or work cap changes. Windows retains its exclusively owned high-resolution waitable timer and original-cutoff check; other platforms retain bounded park/fine-sleep. The OS may preempt any implementation: a finite requested watchdog is not a scheduling or retirement bound, and unpark cannot independently prove syscall completion. Actual syscall counters distinguish coarse/fine absolute waits from relative waits. These controls are a finite engineering contract, not a realtime or physical Poisson law guarantee.

The receiver owns one collector task. Successful finish joins that actual task.
On a returned SDK error, including TLS EOF, malformed metadata and lease
revocation, custody survives cancellation of the inner operation. The receiver
requests abort and awaits its actual task using only the original deadline;
cleanup never replaces the first protocol/I/O error. An expired deadline or
dropping the entire SDK future requests cancellation without claiming a join.
A failed finish that observes a terminal task removes its completed handle
before returning the error, so error cleanup cannot poll that handle twice.
An abort request is not a terminal/join proof. Sender/receiver failures return a content-free typed prefix: accepted/sent/received/application-write-completed counts, pending-at-failure, collector started/joined/abort-requested, public block ordinal and lateness/overlap observations. Pending-at-failure records bytes not successfully forwarded at refusal; terminal Drop zeroizes/disposes custody and does not retroactively imply delivery. A completed UDP socket write is not an application ACK. Arbitrary transport errors, payloads, keys, endpoints and resource identities are not formatted in failure reports. Public profile Debug is redacted.

## Startup refusal and owned retirement

The sender observes READY before invoking its application callback. If the
owned thread fails preparation and closes READY, the SDK attempts retirement of
that same owner using only the original operation end. A terminal preparation
error is returned with its actual type; readiness closure alone does not hide
it. A terminal success cannot turn failed readiness into success. The callback
is never invoked on this path. An expired original end returns timeout without
renewing the budget or claiming a thread join that was not observed.

The controlled startup regressions use a per-actor, test-only cancellation
before the real owned thread preparation guard. They exercise actual socket
and thread custody plus the production SDK readiness stage; they do not force
native APIs to succeed or prove platform timer reliability. The unchanged
fresh-TLS/UDP positive remains a separate test. This error-reporting repair is
not a repair for the retained pending-zero late native wait failures.

## Conditional mathematical diagnostics

For a genuine Poisson slowing process over `T` seconds, the finite KL is

`D(P(lambda-delta) || P(lambda)) = delta*T + (lambda-delta)*T*ln(1-delta/lambda)`.

The component uses the conservative upper bound `delta²*T/[2*(lambda-delta)]` and exact integer admission against `KL <= 2*epsilon²`. Displayed floating-point KL/Pinsker and nominal capacity are approximate diagnostics, not outward-rounded numerical certificates. `actual_poisson_process_verified`, `actual_mm1_service_verified`, service-model and warden-packetization flags remain false. The modeled per-block bit rate must be below the declared capacity; that prerequisite neither proves a physical service law nor guarantees finite decoding success.

With nonzero clock uncertainty the decoder scores upper-endpoint conditional service likelihood, an approximation rather than exact marginalized maximum likelihood. Before-origin current-block observations, impossible sequences, ambiguous scores, missing packets, capacity violations and unauthenticated records refuse. Earlier-block completed departure coordinates can safely be zero relative to the next block; actual current-block observations are never silently clamped.

## Retained verification scope

Ordinary owned-localhost tests cover original-byte FIFO, source starvation/caps, missing arrivals, actual hash-before-sink refusal, owned collector cancellation, immutable metadata length, fresh record authentication/nonce refusal, original deadlines, actual TLS admission disagreement and live authorization revocation. Paused clock admission and real UDP post-write observation tests distinguish allowed lateness, overlap, original-bound exhaustion and a physically sent but late completion. A separate genuine fresh-TLS lifecycle test accepts only authenticated success or typed failure with retained prefix; it is never counted as positive delivery on the failure branch.

The unconditional positive SDK fixture preserves its original seed `[3;32]`, all 491 selected packets and the 4,668 ns minimum nominal gap. Actual source packets, UDP departures/arrivals, codebook decoding and assembled-record AEAD recover the message. A separate unconditional fresh TLS/UDP test also recovered its message and joined its release owner. Old strict-owner and first version-2 boundary failures are retained; no failure branch is reported as successful delivery, and no seed, sample, numerical timing budget or codeword was selected to obtain the positive result. Owned negative controls cover actual phase-one FIFO, overlapping nominal arrivals, original-source availability, late/whole-window refusal, internal sequence checks, pending capacity, cancellation, and a real 35 ms completion across the unchanged 10 ms allowance with its sent prefix preserved. No test in this scope certifies legitimate cover, M/M/1 service, full wire invisibility, an installed full-wide VPN lifecycle, target-network behavior or beta acceptance.


## Native platform qualification — 10 October 2026

The unconditional positive fixtures above must also pass on each supported
native target; a local success does not accept Windows. On exact source
`08b51a49ee7e3b4eac067cf42d69f91223cd54d1`, Windows CI job
`114204485777` failed both the fixed-prior-seed SDK decode and the paired actual
timing CLI positive. Both senders refused at
`windows_timer_after_wait_cutoff`, retained their actual unsent prefixes and
reported zero authenticated message delivery. Neither had pending service
packets. The source audit therefore does not attribute these failures to the
separate pending-service bound composition issue.

The SDK's retained native-call observation entered the wait while its requested
wake was still approximately 0.988 ms away and observed return after 23.659 ms.
The original 10 ms return allowance was exceeded, so refusal was correct. This
bracket does not identify an exclusive kernel cause or establish a repair. The
original seed, codebooks, native positive assertions and timing limits remain
unchanged. Required exact-successor CI, installed native lifecycle, legitimate
source/service premises and independent target-network observation remain
separate acceptance conditions. A successful API status, a finite watchdog or a
safe refusal does not substitute for the positive decode.

On exact successor `177782d27506ef00c9c109067e834035b285b73d`, Darwin job
`114207992552` also failed the unchanged fixed-prior-seed SDK positive at
`service_arrival_original_cutoff`. Its observed prefix was 491 accepted,
408 sent and 83 retained, with no pending service packets and no authenticated
message delivery. A directly bracketed coarse `kevent64` call requested about
0.995 ms and returned zero events after 121.106 ms; admission was 91.288 ms late.
Zero events is not admission of the original point. The call bracket neither
proves a kernel-only cause nor makes the separate pending-bound repair causal.
The actual syscall and deadline integration are under source audit; the failed
positive remains a failed qualification.


### Diagnostic fixture qualification — 11 October 2026

Exact `6ea0951044352068e62477e6e7788b6942728018`, Windows job
`114551051522` in CI `38166840585`, retains five failed native positive
fixtures. Three bracketed signalled-timer returns took approximately 45–78 ms;
each exceeded its original 10 ms delivery allowance while the session end was
still open. The SDK's 40-second caller budget cannot replace that delivery
cutoff. The actual Windows thread preparation ran; requested priority and API
readback do not prove effective scheduling. No timer-conversion defect or
exclusive kernel cause is established by these observations.

The subsequent source regression reuses the unchanged production post-wait
guard and replays the three recorded point latenesses, plus inclusive delivery
cutoff and exclusive session-end boundaries, using synthetic clock offsets.
It does not invoke Windows or prove native delivery. Settings, codebooks,
original positive assertions and release tolerances remain unchanged. All five
native failures remain unaccepted until the exact successor's actual positives
pass; safe refusal and a pure regression cannot substitute for them.

On exact `1e4151b3c145bc029581213eb8ef395018479743`, Darwin job
`114405392706` passed the unchanged fixed-prior SDK positive and failed the new
same-service diagnostic regression. Its actual 150.530292 ms write duration
correctly replaced a 70 ms synthetic running maximum; requiring the observation
to differ from that updated maximum was an invalid test oracle. The test-only
successor derives unrelated sentinels above the original fixture horizon. All
28 owner tests and both existing absent-JSON/projection controls pass, with
strict core analysis and formatting. The genuine UDP receipt, 10 ms typed
refusal, original 35 ms delay, arithmetic tuple and publication assertions are
retained. No full SDK delivery positive is retried, and this does not repair or guarantee
native timing. Required exact-successor CI and the other native qualifications
remain separate; earlier failed receipts are preserved.

On exact `558883f05`, hosted Windows and Darwin jobs each produced a different
real timing refusal. Windows' owned insertion positive scheduled its twelfth
source event at 92.856 ms but woke at 107.676 ms after that fixture's 100 ms
channel horizon; production correctly refused incomplete source. A reviewed
positive-test-only repair keeps the seed-1007 twelve-event sample within its
original 100 ms window and gives the channel 250 ms to observe native wake
and EOF. Local exact macOS selector passed 1/1; Windows exact-successor CI
is required. Darwin's measure operator refused a service-arrival original
cutoff after a host run with 71.146 ms maximum dispatch lateness. A separate
local native positive passed, which does not clear the hosted refusal. The
Darwin CI workflow now runs that original selector as an exact required step
and runs remaining cases separately. Neither production 10 ms cutoff nor
fail-on-refusal changed; successful exact native CI and installed scheduling
acceptance remain open.

## Exact `dcb3923` paired Mach diagnostic source gap, 15 October 2026

The manually dispatched paired CLI positive refused `source_starvation` after a 77 ms successful-offer gap and 64 skipped nominal source ticks. Its asynchronous synthetic application producer shared the two Tokio I/O workers with the test's network/observer work. The reviewed successor uses a dedicated blocking source thread with the same 2 ms nominal grid, original horizon, bounded stop and all authenticated delivery assertions. A 96-packet prefill attempt was rejected after an injected late gap still refused. The internal `CI-dcb3923-fixture-repairs-r1/receipt.md` receipt (outside this delivered guide kit) binds the original failure, rejected attempt and local native macOS 1,500/1,500 delivered check. This changes a test source, not the SDK timing owner or its 10 ms cutoff; exact successor CI and installed platform timing remain unaccepted.

## Exact `dcb3923` Windows native wait refusal, 15 October 2026

The internal `CI-dcb3923-auto-monitor-r1/windows-required-failure-receipt.md` receipt (outside this delivered guide kit), SHA-256 `0d7897fc51da9c30eb173f05849746b5a63a6d8c23c994c833a2195c0150177a`, records terminal **FAILURE** of `windows-rust` job `116432189434` in PR run `38738019043`. The exact SDK UDP positive refused `windows_timer_after_wait_cutoff`: its last native wait interval was 33.267 ms and the guarded point was 12.760 ms late under the unchanged 10 ms allowance. It had accepted 491 and sent 376 packets, with zero application delivery. The native-only cause and effective priority were unverified; this failure cannot be reclassified as runner noise. Windows product work is frozen, and exact successor required CI must still pass before B-01 can close.

## Exact `9b400512` normal Darwin source refusal and successor fixture, 15 October 2026

The required and manually dispatched normal Darwin jobs on exact `9b400512` both refused the application-owned paired CLI positive with `source_starvation`; the separate Mach diagnostic passed only in its scoped job. The manual case offered 112 application packets by about 502 ms, then the sender refused after 104 accepted and delivered zero. The internal `CI-9b40051-darwin-lead-r1/receipt.md` candidate (outside this guide kit) changes only the positive fixture's READY lead from 200 ms to 1000 ms, within the pre-existing 10–5000 ms validated range. It keeps the 2 ms source grid, 2.8 s horizon, 10 ms release cutoff, authenticated FIFO and actual application-delivery assertions. Four selected local runs passed, including one under bounded CPU load; independent review found no P1/P2 for this narrow fixture. The longer lead intentionally buffers more application-owned packets before start and does not prove the former 200 ms configuration, real source timing, installed behavior or a successful normal Darwin CI gate. B-01 remains open until the next exact committed run finishes successfully.

## Exact `fcfec6e` Mach diagnostic source refusal and catch-up candidate, 15 October 2026

The manually dispatched Mach diagnostic on exact `fcfec6e` refused `source_starvation`: the application source offered 344 packets by 1.242 seconds after parent READY, skipped 276 nominal 2 ms ticks after scheduling delays, and the sender accepted 337 before the authenticated exchange aborted with zero delivered. The recorded Mach policy calls succeeded; this trace establishes a fixture supply failure, not a Mach timer failure. The internal `CI-fcfec6e-exact-r1/manual-darwin-mach-artifact/measure.out` retains the failed attempt. A reviewed test-only successor removes skipped late ticks, offering them immediately in original nominal order with actual send-return observations; it preserves the finite horizon, 10 ms release cutoff, authenticated FIFO and application-delivery assertions. Four isolated native runs, three under bounded CPU load, each offered, accepted and delivered 1900/1900/1900; an independent run also passed. The internal `CI-fcfec6e-darwin-catchup-r1/diagnosis-receipt.md` and `independent-review.md` bind this local candidate. Neither local result changes the failed exact-`fcfec6e` run or establishes installed timing or exact successor CI. B-01 remains open.

The internal receipt `evidence-archive/testing/2026-10-15/CI-fcfec6e-exact-r1/receipt.md`, SHA-256 `66cc295ff7f2cde9da6028eba3c604961e32878e689b12c46bc4dbc3523a0ddf`, also binds required PR `darwin-contract` job `116495676499` and manual job `116495813892` to terminal **FAILURE** at the same paired positive: 245 and 656 packets accepted/sent, respectively, with zero delivered. The isolated Mach job failed as above. This private receipt path is intentionally plain text because the receipt is not delivered with the research guide kit. No Darwin contract or Mach result on exact `fcfec6e` is a PASS; this source-only fixture correction requires fresh exact-commit CI.

The exact-`7bd3df3` manually dispatched internal Mach failure receipt `evidence-archive/testing/2026-10-15/CI-7bd3df3-mach-cutoff-analysis-r1/receipt.md`, SHA-256 `2f00b05240b15b17de6df3235569b1f4a39d2546af315cb362228332b03816a3`, is a distinct native timing refusal after the source-supply correction: one fixed-seed public point was admitted 15.887716 ms late against the unchanged 10 ms cutoff. Its immediately preceding critical absolute `kevent64` wait requested 0.957826 ms and returned after 16.854209 ms; return-to-admission was 11.333 µs, with no intervening I/O. It does not isolate kernel delay from dispatch scheduling or verify effective QoS. An isolated 2 ms active-tail replacement failed sandbox loopback once and then exhausted the original owned-work budget at 256/491 packets in an authorized loopback retry; that candidate is rejected, with both failures retained. The internal R2 Apple-source decision `evidence-archive/testing/2026-10-15/CI-7bd3df3-mach-cutoff-analysis-r2/decision.md`, SHA-256 `9568ab3bb228364782e42b5db1b31d31d5af550c6c75bf076f5921f4a15db2ff`, recommends a bounded unchanged-test System Trace before any separately reviewed native wait backend experiment. No source change, lowered threshold or Mach PASS follows. B-01 remains open.

The one local System Trace attempt (internal receipt `evidence-archive/testing/2026-10-15/CI-7bd3df3-mach-system-trace-r1/receipt.md`), SHA-256 `c09cd18ca77dbf1abc214582de1e760eea5e3cc9666d8011fee7ac0a0f7b34fa`, ran the unchanged exact-`7bd3df3` selected binary and passed 491/491 with maximum admission lateness 58,455 ns; this is a separate local result, not a retry of GitHub CI. Instruments hung after the target exited; SIGINT did not finalize, and bounded SIGTERM left only a 52 KiB incomplete trace with no usable scheduler/syscall store. The sandboxed `xctrace` preflight had also failed cache access, while a separately authorized template listing succeeded. The partial trace is a **failed diagnostic**, so it cannot assign the CI oversleep to kernel or scheduler. Disposable build output was removed; the CI failure and B-01 open gate remain.

The bounded isolated API probe (internal receipt `evidence-archive/testing/2026-10-15/CI-7bd3df3-mach-wait-api-probe-r1/receipt.md`), SHA-256 `b609ce0fb3fec09c13e6f3fd541ff4741a828d1a37a82a00be3600384d93f9ad`, compared three 256+256 rounds of absolute 500 µs waits. Local `kevent64` maxima were 0.53–0.90 ms and `mach_wait_until` maxima 0.64–2.79 ms; neither reproduced the hosted 16.85 ms return. The probe has no 491-packet workload, owned-work charging or delivery, so it cannot attribute the hosted failure. No backend change or 10 ms relaxation was made; controlled scheduler evidence is still needed.

## Linux release-thread timer policy — 16 October 2026

The accepted UDP collector batch removes a reactor yield for each already-ready
datagram. The separately reviewed measure fixture reduces READY lead from
1000 ms to 200 ms to prevent application-input overflow before sender startup.
Neither change alone cleared the preserved Linux timing failures: the batch
source SHA-256 `ee9076242437bda42c36e17d3c9686261450bfcc438c5ef07fad4f544bdeb08b`
passed 8/10 secure positives and refused two original public points.

Linux inherits the creator's timer slack, which permits coalescing of sleep and
futex timers. The directly owned release thread now requests 1 ns and verifies
its own readback before readiness; both native calls consume the existing work
and original-clock guards. A refusal preserves startup failure. The policy
ends with that thread and changes neither caller-thread policy nor scheduling
priority. See the [Linux timer-slack contract](https://man7.org/linux/man-pages/man2/PR_SET_TIMERSLACK.2const.html).
The 10 ms cutoff, fixed seed, packet identities, finite work budget, source grid
and unconditional positive assertions remain unchanged. Scheduler preemption
can still cause a genuine refusal; this does not establish real-time service.

Private evidence locator `evidence-archive/testing/2026-10-16/B01-poisson-stabilization-r1/`
contains the frozen 8,977-file source manifest SHA-256
`eb815410054db701ebadc5b812477bf9f52ba32a9c8cf42275bff65bdb897e64`.
Linux ARM64 Rust 1.97.1 passed two native policy regressions, all ten original
fresh TLS/UDP positives (maximum admission lateness 349,182 ns), and the
unchanged 491-packet fixed-seed positive. Raw `focused-02.log` SHA-256 is
`88b74d32e4383bf85d255cc6da47aef16b1ac6cea0a93a79e815aae27ccdfa53`.
UDP receive-error counters stayed zero in that network namespace. Attempt 01
failed before tests because an uninstalled `stable` alias tried an offline
channel lookup; attempt 02 pins the installed complete toolchain name.
The same source passed full core 1016/1016 (seven existing ignored), strict
core all-feature/all-target Clippy and CLI integration 12/12. The first full
core attempt used a read-only checkout and failed eight archive fixtures; the
corrected writable-copy run passed core, then stopped at a missing Clippy
component. A separate Clippy-image attempt passed both remaining checks.
Both writable runs verified the complete manifest before and after.
Final-commit hosted CI is pending at this entry.
These observations establish the bounded local source result, not the sole
cause of every historical scheduling failure or an installed physical premise.


### 16 October 2026 — integrated required-CI failure and bounded successor

Exact `b94c3895de40c0d0e63c311d883225994f662a9b` required run
[38875527837](https://github.com/example-org/aegis/actions/runs/38875527837)
finished with three SUCCESS (Linux ARM64, Darwin, dependency security) and two
FAILURE (Rust, Windows). The Windows original SDK positive retained its real
`windows_timer_after_wait_cutoff`: native interval 24.4373 ms, requested
33.3 us, guarded point lateness 22.885363 ms, 491 admitted/19 sent/472 retained,
zero application delivery. Effective priority and a kernel-only cause are not
proven. The original cutoff correctly refused; it was not relaxed.

Candidate `5e76e256c` requested a per-thread HighQoS readback with an unsupported
query. Microsoft's [GetThreadInformation contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadinformation)
lists memory priority, absolute CPU priority and dynamic code policy; it does
not support ThreadPowerThrottling. The mandatory Windows positive failed;
four mock methods and native-cfg typecheck had not validated that OS behavior.
This failed implementation and its evidence remain retained.

The corrected successor uses only the documented per-thread HighQoS setter
(execution-speed ControlMask1, StateMask0) before READY. An accepted native
request is recorded separately from `effective_policy_verified=false`; no
unsupported query or effective-policy readback claim remains. Native setter
failure still refuses. Each current-thread/set call has original before/after
work/cancellation/deadline guards. This changes neither process policy nor
global timer resolution. See the [thread power policy contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadinformation).
The existing high-resolution timer, seed, public points and 10 ms allowance
remain unchanged. A successful policy call provides no scheduling guarantee.

The Rust failures and fixture/guard successors are retained together in the
B-01 private receipt. Its separate PostgreSQL fixture had passed the dedicated
hosted step and two local baselines, so the hosted mTLS loss is not labelled
reproduced or attributed solely to hashing. Synchronous executable hashing
has been removed from the live Tokio reactor path; the 2 s TLS bound remains.
The roadmap links the exact-current five required PR checks and retains failed
raw-log hashes. Only their terminal SUCCESS on the exact integrated commit
accepts this CI gate. All installed, physical-premise, independent and endurance
requirements stay open; AUTO dispatch stays 0/39.

The fresh-mtime, pre/post manifest-verified attempt10 rebuilt the changed
carrier and passed PostgreSQL3/3 with the complete workspace feature graph,
then strict all-feature/all-target carrier Clippy. Raw log SHA-256
`2dc8c8efda0d2e1530030d3d3402853e7afbf4a2b8c7fa5ee3bf6f313b5781a2`. Potentially stale attempt09 is retained
and not counted as successor proof. This remains a local PG17 fixture result.


### 16 October 2026 — Windows native evidence corrects the QoS hypothesis

The complete `5e76e256c` Windows job confirms successful HighQoS set/readback
on this runner, followed by `windows_timer_after_wait_cutoff`. Its coarse wait
requested978.3us but the observed call interval was29.7178ms; guarded point
lateness11.472889ms. The original positive admitted491, sent32, retained459
and delivered0. The separate first-source epoch positive also refused after a
32.0829ms native call,27.138ms guarded lateness. Raw Windows log SHA-256 is
`1dd44ff3a12f073b306d0224a9aa446149c608738fa3293e074b0176b25115a7`.
Thus QoS alone did not resolve native wait/scheduling latency, and the
unsupported documented getter class was not the observed failure cause.
The getter is removed for its documented portability boundary only.

Both refusals ran a BELOW_NORMAL process with the owned thread at relative+2,
which maps to base8. The successor requests relative15/base15 solely on the
newly owned nonblocking release thread in the existing four admitted
non-realtime process classes. High/realtime/unknown process classes still
refuse before mutation. Existing relative15 is preserved without a setter;
invalid relative values, failed APIs, changed relative readback/process class
and every original clock/cancel/work boundary still refuse. This explicitly
replaces the former requested-base11 ceiling; the process priority class,
parent and shared threads remain unchanged. See Microsoft's
[scheduling priority mapping](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities).
Base15 is a scheduling request, not proof of effective priority, hypervisor
CPU availability or deterministic physical timing. The same strict runtime
cutoff decides every actual admission and native return.

To test repeatability rather than one selected success, the required Windows
step now demands three consecutive fresh processes of the unchanged original
491-packet fixed-seed positive. It stops at the first refusal; no changed
seed, dropped packet, expanded lateness, resampling or accepted failure is
introduced. Existing native parent-unchanged/readback/join coverage remains.


The frozen base15/setter-only successor passed **10/10** focused policy and
original-boundary methods plus strict core all-feature/all-target Clippy in
fresh-mtime, byte-manifest-verified attempt13. Log SHA-256
`f7af63fd0581a07bcf8fae0918682a40f6f6f64c6fc36335f3c264d63b69b653`.
Native Windows-cfg check04 passed with zero actual local Windows methods.
The exact `5e76e256c` dedicated PostgreSQL step and full workspace Tests both
finished SUCCESS. B-08 remains selected in required rust; this does not accept
an exact-final-commit CI or physical scheduling guarantee.


The final source withdraws the entire added QoS component (including the
setter-only intermediate). Its native success did not resolve the observed
latency, and it is not part of the accepted scheduling repair. Failed source
and all four synthetic QoS checks remain historical. The final Windows change
is the owned base15 priority policy and three consecutive original positives;
its six priority methods were included in the ten-method attempt13. The
original parent-unchanged native priority test remains in required Windows.

Final no-QoS attempt14 rebuilt the source and passed **6/6** priority methods
and strict core all-feature/all-target Clippy, with pre/post manifest equality.
Raw log SHA-256 `39924b66574ae38d575be92dceeaaced0e93e7f644c253adc6aff3defcaa6fd2`. Windows native-cfg
check05 also passed. The final core owner/module files match `b94c3895`
byte-for-byte; the Windows priority module is the functional scheduling
change. These are source/local checks, with actual final Windows execution
still required.


The complete second required run38880880774 on exact `5e76e256c` ended FAILURE:
Linux ARM64, Darwin and dependency-security SUCCESS; Rust and Windows FAILURE.
Rust's dedicated PostgreSQL, full workspace Tests and native-guard smoke all
succeeded. Its only failed step was the generic contract sweep,151PASS/1FAIL:
`bootstrap-macos-digest` still selected `tar -xzf` after adopted owner hardening
changed production to `tar --no-same-owner -xzf`. The one-line exact seam fix
retains all40 real signed-manifest/digest/tampering cases, which passed on
macOS and isolated Linux ARM64 root. Later skipped steps are not PASS. The
private B-01 second-run receipt preserves all five full raw logs/hashes;
Rust SHA-256 `05ee10da4458bac7036785234d21523e7a202e3c01eff636e396e7d1f190425b`.
This correction and owned-base15 Windows policy are batched together with
current pins for the next exact commit; all final required jobs must execute.


### 16 October 2026 — Windows repeatability accepted for exact32cb; final CI still open

Exact `32cb788a9e8aebd03bd9c836b8c9a70f58c80be5` required
[run38888635524](https://github.com/example-org/aegis/actions/runs/38888635524)
finished four SUCCESS and Rust FAILURE. Windows job116932449562 succeeded:
three fresh original fixed-seed processes each admitted491/sent491/retained0,
joined the worker and passed actual application decode/delivery assertions.
Maximum admission lateness was531560ns,560364ns,551938ns under the unchanged
10,000,000ns limit. The actual native base15 parent-unchanged/readback/join and
previously failing first-source epoch positive both passed. Private Windows
kit and installed release-lifecycle CI also passed. Raw Windows log SHA-256
`d741dba38300af442299015ccda58360579bb2862ac477853b5a839380d62880`.
This accepts those exact scoped runs, not an arbitrary-load timing guarantee,
a signed final release, installed platform closure or beta exit.

Rust's B-08 dedicated PostgreSQL and full workspace suite, native guard and
all152 generic contracts passed. A later RPM-host `--json` check failed because
new pair verification printed a human PASS line on stdout before JSON. The
helper now routes verifier diagnostics to stderr while retaining all checks,
exit/refusal handling and pre-mutation placement. Frozen baseline15 reproduced
the actual diagnostic prefix; corrected16 passed the complete unprivileged
RPM-host fixture with actual current-source Rust report/secret-reader binaries,
including missing-receipt refusal. This source batch changes no Windows policy,
seed, point, packet count or cutoff. All final-SHA required jobs must still pass.

### 16 October 2026 — exact0dcc Windows repeatability and capture-contract seam

Exact `0dccfb0a46e892f8c69ea4821524168ca5182648` required
[run38899752044](https://github.com/example-org/aegis/actions/runs/38899752044)
finished four SUCCESS and Rust FAILURE. Unchanged owned base15 Windows source
again passed all three fresh fixed-seed 491/491-packet positives, retained zero
packets and joined each release thread. Maximum admission lateness was
511278ns,555035ns,520314ns under the unchanged10,000,000ns limit. Native
parent-unchanged/readback/join and first-source epoch, private kit and installed
lifecycle all passed. Raw Windows SHA-256
`8371948bf1c026a1ab7658c0f2b0282682354d26afcbf7cdaad986c7d61fa1f5`.

Rust passed B-08 dedicated/full workspace, native guard, generic contracts and
the repaired RPM delivery step. The next metadata CLI build succeeded; its
following source contract failed on the old direct stage-admission substring.
Raw Rust SHA-256 `c5b648da765a1340bef41a2a1d1a43749c8fa53f73bdb130273547e9a6431095`.
The updated contract keeps the actual pure capture/finalize refusal and
verifies the accepted recovery-marker preflight before it, with root/lock and
worker-stage admission after it. The host helper passed and eight unsafe
source variants refused. This changes no production AUTO source, admitted
cohort, Poisson policy or runtime boundary; final-SHA required CI remains the
acceptance gate and skipped later checks are not PASS.

The remaining local tail batch uses actual source-built Linux ARM64 CLI at
Rust1.97.1 with default features; JA4 adds the named chrome-like feature only
for its separately scoped cipher/extension-set fixture. Attempt19 completed
14/18 contracts, with missing Git custody and forbidden symlink executable
paths in the isolated setup; corrected20 completed17/18. Its last refusal was
the actual cgroup fixture's absent required config. The fixture now supplies
a real minimal config and all three original UID/cgroup/teardown assertions
plus three absent/invalid-config refusals passed in21. Original production
config validation is retained and no actual firewall command is used.

Attempt21 then failed the first runtime-events JSONL wait before a completed
case. The exact original1091-line Python workflow body (SHA-256
`a6ae603a76236787e2976d739452175322cde4a92b0473e01182d599e3169949`)
passed in22 after explicit standalone client-graph compilation. Its measured
48s build included contention with the concurrent preflight check; it is not
an independent application-startup measurement. The log records a real rebuild
of h2/core/carrier/client. CI now completes that graph before the unchanged20s
application readiness wait, preserving every JSONL assertion. Frozen source10
manifest `2dc24d45219fc3a67aad6afcf698eac896a785292c47ac4f2bc2ec735505887c`
matched before/after; attempt22 raw SHA-256
`199dc00939894417fa43a72d19bf0fa52cf6c25533c418284dcd3c65206b1370`.
The final default client in that retained local target has SHA-256
`debd0b38079b4a0b1797fa411e8ad8dc5f025c7bef9c3f4a79b851b90eb36427`.
These disposable snapshot/fixture identities are not a final release identity.

### 16 October 2026 — exact472 Darwin failure and nonblocking progress publication

Exact `47255ffbb51a6fa34f84223cfabf388aceed9b90` required
[run38910503775](https://github.com/example-org/aegis/actions/runs/38910503775)
failed its original Darwin paired-CLI positive. Event317 recorded admission
lateness6150101ns, pending wait1430042ns and native write-observation bracket
4625250ns, completing12205393ns after the original point at the unchanged
10000000ns allowance. Sender accepted529/sent318/retained211; receiver received
318, with zero authenticated application delivery before refusal. Raw Darwin
SHA-256 `f4dbd5bdf6680f3c442e6e4a52bc817094a3f1e4ee5407a3a2fa96e32bc05c96`.

The source's statistics publisher acquired a blocking observer mutex on live
read/service paths and twice between admission and UDP service. The new actual
admission regression holds the real observer mutex until its result is known;
original source plus that regression fails deterministically (attempt24,
SHA-256 `23d7868556b2cc6be64804dd0455026fead079d13dbb81b2e8709527a0833661`).
The worker now attempts intermediate coherent snapshots with `try_lock`, keeps
all authoritative counters locally and always performs its complete terminal
publication after packet processing, preserving concurrent custody flags.
The same regression passes, and the contended-publication diagnostic now
requires a skipped progress publication with zero native waits. This proves
removal of the blocking dependency; it does not identify the mutex as the sole
cause of the recorded4625250ns native bracket or eliminate OS preemption.

Frozen source11 manifest
`057c37c1073af3d626783635c25eef9fc74a91dc85c8b948266c4a68ca710391`
passed macOS26.5.2 ARM64/Rust1.97.1 core all-features996/996 (seven existing
ignored), strict all-target/all-feature Clippy, all12 default CLI cases and
three additional fresh original paired positives. Each of those four paired
executions offered1500/accepted1500/delivered1500 with authenticated control,
both children reaped and existing false Poisson/M/M/1-premise flags retained.
Mac raw25 SHA-256 `7e4804829ee6d6cb729ef35204a55cf64d007479e7d46fe0a126bba943e52091`;
default measure binary SHA-256
`5393a543fccca408f92efcf6c10900071590f807edf6085a7caf397ac060b608`.
The matching frozen Linux ARM64 source passed core all-features1017/1017
(seven existing ignored) and strict Clippy; raw26 SHA-256
`790bdf41f6e3504d010d7fa007f5154f57d21c94f9ae115558ef45ff51ce3196`.
Both source manifests matched before/after. Required Darwin CI now executes
three consecutive fresh original paired positives; no retry follows a refusal.
Original10ms limits, source/grid/seed, work/poll budgets, per-thread Mach policy
and Windows priority remain. Exact final required CI, installed, independent,
all-eleven and endurance acceptance remain separate gates.

Exact472 required CI finished three SUCCESS and two FAILURE. Windows again
passed three491/491/zero-retained/joined SDK processes, with maximum lateness
528513ns,523696ns,514037ns; raw Windows SHA-256
`24fcbf0294516c7807137dfa52afa2c86a6497428151cb3d1d925dccc4b3d457`.
Rust's full suite/B-08, native guard, generic152/0 and RPM delivery passed;
the updated capture, service privilege, package, gateway, floor and signer
contracts also passed. The later release-lock fixture silently selected the
real rustup proxy under its replacement HOME; the runner then reported0MB
free. Raw Rust SHA-256
`0f08db8d920522f9971a1fd92fa27a303c96f16ec25e8e63d733c9dae1bb6612`.

Controlled baseline27 uses the actual rustup proxy with RUSTUP_HOME unset and
a blocked loopback distribution endpoint; the original fixture attempts a
toolchain fetch and fails. Corrected28 pins its own inert rustc, reaches the
real source lock-drift guard, refuses packaging as intended and performs no
fetch; its raw SHA-256
`a6356be5e775172d9ac9bc290dfef18133ef9530e6ae9301a9ddb535b5ce204f`.
Linux rust CI now omits dev/test DWARF and starts a distinct cache namespace,
keeping optimization/debug-assertion/panic policy separate and all runtime
checks selected. Compiler control30 emits debug-info0/opt-level0 with debug
assertions and overflow checks true, and executes actual unwind/Drop; its test
harness is compile-only, not suite acceptance. Raw30 SHA-256
`46eea205d65d68909c026242af956fbc5de58d2aa24271e57e544f4c2f2c2a27`.
The local full-core results above retain their default-debug profile scope;
all final Linux CI tests must execute under the declared debug-info0 profile.

## Exact aaa118 terminal native smoke refusal — 16 October 2026

On exact `aaa118c8ba53ed01a32b379916b629bcbd88c384`,
[run38922449088](https://github.com/example-org/aegis/actions/runs/38922449088)
finished four SUCCESS and Rust FAILURE. Windows passed three fresh original
491/491/zero-retained positives (maximum admission lateness 0.542702 ms), native
priority/parent-unchanged and observer regressions, private kit and installed
lifecycle. Darwin passed three fresh original paired positives, delivering
all 1497 accepted packets in each process; source/service premise flags remain
false. Linux ARM64's original TLS/UDP positive sent 1500/1500 with zero retained
or missed public points and 0.168046 ms maximum admission lateness. Rust passed
B-08/full tests in debug-info0, native guard, 152 generic contracts, RPM delivery,
metadata/release-lock, installer/rollback and firewall/readiness/prerouting.
The first guarded DNS smoke then correctly refused `apply` because its harness
omitted `AEGIS_CLIENT_CONFIG`; later native cases and Runtime-events did not run.
The harness now passes its existing generated config across sudo for apply,
matching doctor/probe/launch, while the production refusal remains unchanged.
An actual-command boundary regression fails on the old harness and passes on
the correction, including a path containing spaces.
The local source12 native attempt38 reached the real helper and refused its
temporary config's untrusted parent before firewall changes. Actual Linux CLI
control39 reproduces the exact metadata error, accepts a root-owned0600 config
under a protected /run parent and removes it successfully (ELF SHA-256
`fb3285beb3dc5ab38118129732f49d328c0a9364d23fd6d585d48867202212d6`,
raw `6b58eb890e6c45b9a872e4573d7ac11096a0266a421efbde1476afbbee226137`).
The smoke now uses the pinned client's exclusive metadata writer to copy its
config into the existing trusted /run staging directory. Root probe/launch
reuse that same private config; cleanup removes the config through metadata
before exact-inventory binary cleanup, and retains both on refusal. The
caller temp path is removed separately. No production metadata guard changes.

Source13 native40 passed actual helper apply with the private config, then
its real receipt producer refused an output directly under the shared TMPDIR.
The CI wrapper now allocates a root-owned 0700 /run receipt directory per case,
checks its device/inode/owner/mode before cleanup, preserves only the fixed
contract.json/runtime-events.jsonl leaves via caller-owned readback, and removes
known leaves plus rmdir without recursive deletion. Unknown inventory and
identity/symlink mismatches refuse. An always-run, pinned artifact action retains
these separate receipts, including failures. All eight original Python assertion
ASTs, 300 s smoke limits, selected protocols, feature graph and expected drop32
remain. On source14, isolated Linux 6.8 ARM64/Rust1.97.1 executed all eight original
packet cases plus the complete original Runtime-events body: 9/9 PASS in 254.66 s.
The default client/server/measure graph used normal dev debug info. Four actual
sudo/filesystem custody controls passed; all 10 real machine receipts were
preserved, with no cleanup warning, and the full 8977-file source manifest
matched before/after (`88836442808fee31bf202d6e60e12142341a5c0d6ffadcfca2e8f681110d787a`).
Raw native45 SHA-256 `dc4b97f4eb1ca8273c6798054886ba31e65728e5e5a918eaa657b5e945ccd37c`.
The private `native-terminal-45.json`, `native-artifacts-45.json` and
`runtime-artifacts-45.json` bind case logs/receipts and distinct packet/runtime
ELF identities. No core, platform timer or PostgreSQL source changed after the
four successful exact-aaa118 jobs. Final-SHA five-job CI remains required.

All eight original runtime
assertion ASTs and 300 s smoke timeouts remain. The runner also rebuilt a full
`+ debuginfo` server after sudo dropped the job's profile variables; all eight
sudo invocations now preserve dev/test debug-info settings, with two missing-var
controls refusing. Source12 isolated native tail execution is recorded in the
private B-01 receipt; only a completed five-job final-SHA run can accept this gate.

## Exact985 Darwin NE stop-order test correction — 16 October 2026

On exact `985a81dc77373e4dfa3cdd055f123c10de7fd9d6`, Darwin job117092048385
completed FAILURE in `actual_shared_engine_constructs_and_owned_cancel_joins_without_network`:
81 library methods passed and one asserted NotConnected against an actual
PermissionDenied. Its later three original Poisson paired positives all passed,
with 1498/1498, 1498/1498 and 1499/1499 accepted/delivered and both children reaped;
source/service premise flags remain false. Raw Darwin SHA-256
`7b0544d6923519364aff51db335df58897116fe032b14e61ad4e3d6414b1a51f`.
Linux ARM64 and dependency-security finished SUCCESS; Rust/Windows were still
running at the source-fix dispatch and are not accepted as whole-job PASS. This
already failing run is superseded under the existing PR concurrency policy;
any cancelled jobs remain cancelled evidence, not PASS.

The NE test assumed one order between the raw queue seal and separately locked
lease revocation. Both checks legitimately preserve a different error before a
late stop flag; production join deliberately keeps that original cause. A new
actual-device counterexample deterministically seals the raw queue or revokes
the deadline before receive. The old single-outcome expectation fails on the
revoked branch (baseline49 raw
`3d568e1b882958977a3097ddf904f17448910965eb9d932b0f1bb1a4e04fa4ac`).
Three affected test expectations now check exactly the sealed-queue NotConnected
cause or PermissionDenied with `worker capture lease missing`, rejecting other
causes and false cancel provenance. Repeated joins must preserve kind/message;
physical worker/watchdog joins and original 2 s budgets remain. The new control
checks both original errors again after late cancel and separately identifies
an operation that actually observes the stop flag. No production function,
lease policy, source clock, packet path or factory changes: the pre-test source
prefix is byte-identical.

Native macOS26.5.2 ARM64/Rust1.97.1 with deployment target14.4 passed the focused
control, strict all-feature/all-target Clippy, the complete 83/83 library suite,
three C diagnostic API checks and three inert layout methods (fixed50 raw
`6267ac682e06ec470ad66663f2c0a5a0e8edaec1228ae9a4cdedbc9c821ec74c`).
The previous local exact source step46 had passed 82/82 and does not erase the
hosted failure. A separate real UID1001→sudo-root receipt-producer→private
readback/cleanup proof48 passed; raw
`e722e72978308688bccf34b472224d6fd745b02bb04852559a59966c9c95764f`.
That proof checked that the caller cannot directly read the root receipt and
owns its 0600 readback. Failed47 started zero test operations because Docker
rejected a relative bind path; its failed receipt is retained. B-06 installed
and all other independent beta-exit gates remain open. All five terminal
required jobs on the exact final successor still establish the B-01 source gate.


## Final integrated source CI and main merge — 16 October

Exact `4a3754a225c4df75c69f26447e3afc2a6fcb16f7` completed all five protected
jobs SUCCESS on [run38940321647](https://github.com/example-org/aegis/actions/runs/38940321647).
Windows executed three fresh491/491/zero-retained positives, maximum admission
lateness2.042284ms at the original10ms cutoff. Darwin paired accepted/delivered
1497/1497,1498/1498,1497/1497 with both children reaped and authenticated control;
source-Poisson/service-MM1 premise flags remain false. Linux ARM64 completed
1500accepted/sent, no missed public points or retained packets, maximum
admission lateness0.145620ms. The actual observer-lock regression passed on
Linux, Windows and Darwin. PostgreSQL dedicated fence/full workspace remained
required and passed. Eight actual guarded Linux cases completed without skips;
six contract/four runtime receipts were retained in artifact12067019568, ZIP
SHA256 `4527bec84dff788cbf32c594146b076717c78ac4582ba860da63d81940544fe4`.
The source/CI gate is accepted, with no source edit after that final run.

By owner instruction PR204 merged at19:17:57UTC as
`22ae460cf4ef48fd19fccda37a4625d25348ad00`. The separate exact-main
[CI38953895190](https://github.com/example-org/aegis/actions/runs/38953895190)
then completed all five required jobs SUCCESS. Its retained terminal receipt
SHA-256 is `1e17ba5ecdb4b75ccce7b89b5d68f72eb9e46c5f159bbd73ace3d2d44d0e64d7`. This source gate does not accept installed timing,
independent network outcomes, mathematical premises, AUTO39, audit/grants or
endurance. The retained B-01 receipt and updated PR body bind all five raw-log
hashes; historical failures remain failed. B-02 begins separately.
