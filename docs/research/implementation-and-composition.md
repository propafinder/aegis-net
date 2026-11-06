# Research components and composition

This is the engineering contract for the eleven-work mathematical/physical
catalogue. All production components are Rust. On 2026-10-09 the user made full
implementation and integration of all eleven an additional completion condition.
The original release acceptance requirements remain in force. This document does
not certify that condition as completed: mathematical premises, measured network
behaviour and acceptance of the installed exact release require separate evidence.
The eleven rows map Rust source implementations and named consumers. Source
coverage of eleven works does not establish integration and acceptance of all
eleven in an installed runtime; offline models, standalone operators and live
relay owners have different observable contracts.

| Work | Algorithm and actual caller | Conditions and scope |
| --- | --- | --- |
| BIT-TRAPS | `traffic_privacy::bittraps`: independent weighted service sizes, bounded FIFO, padding and bidirectional authenticated epoch. `relay_shaping` installs it; `transport-lab bittraps-channel` evaluates the full finite Markov sequence law and a declared service grid. | Finite observable overflow/tail, not a stationary information-rate or continuous global optimum. Independent inner service does not establish independent outer TLS packets. |
| Privacy Against Statistical Inference | `rate_distortion::Problem::label_blind`: mean-MI finite convex channel optimization; the separate maximum-information branch supplies a convex leakage-cap/minimum-cost program and bounded fixed-budget minimax search, both certified against the actual finite sampler law. `adaptive_channel` trains and samples the channel using causal length bins; the typed relay installs it. | Training counts must be representative. Numerical diagnostics are not interval-certified population guarantees. No secret class label is passed to a runtime sampler. |
| NetShaper | `netshaper`: integer discrete Gaussian reference sampler, exact rational public-slot accounting, bounded queue and authenticated bidirectional epoch. Installed typed relay profile and actual request/response consumer. | Fixed public epoch; clean EOF requires both sources to close and all queued data to drain. Bounded entropy refusal, scheduler stalls, termination and outer packets are outside a whole-flow DP certificate. |
| Rate-Distortion for Encrypted Traffic | Original finite label-conditioned Wasserstein optimizer; `liu_channel` admits its complete positive causal support and samples the agreed kernel. Production client Open/PolicyAck callers select explicit target/purpose classes before private identity or dialing; `relay_shaping_liu` agrees the full profile and kernel inside authorized TLS. Managed bundles bind the same policy. | Operator-declared classes must actually be available and calibrated. Every supported transition must avoid shrinking the current read chunk. Inner finite payload lengths are not outer TLS/H2 packets, and numerical optimizer diagnostics are not a population or whole-flow guarantee. See [Liu runtime](liu-runtime-channel.md). |
| Minimum Entropy Coupling | `general_coupling`: checked exact finite marginals, sparse greedy coupling, iterative posterior selection. `cover_stream` consumes general iMEC for full bidirectional records, including an agreed finite conditional table whose state follows the public prefix and resets per record; `private-control` supports a separate one-shot operator. | Greedy entropy is approximate. Fixed decoding horizon can refuse unresolved records. Fresh computational HKDF masking is not an ideal OTP or a perfect-cover theorem; inner symbols do not camouflage outer TLS packets. |
| Network Calculus | `network_calculus_guard`: exact scaled token bucket and conditional backlog/delay formula. Positive input is admitted before the constant worker emits any frame. | Local service capacity is an upper ceiling, not a measured lower service guarantee. Reported Internet/OS bounds are conditional and explicitly unverified. |
| Non-Stationary Bandits | `brain::recent_routes::paper_bandit`: D-UCB/SW-UCB equations with global rounds and discounted histories. Native route selection and opt-in `relay::endpoint_bandit` consume the estimator through existing eligibility policy. Concrete numeric endpoints are separate arms; authenticated positive outbound bytes plus an observed response earn one observation. | Only inactive, registry-owned endpoint contexts can retire; new identities start fresh and active-cap exhaustion refuses. Local progress is not target application acceptance or whole-flow completion; field regret assumptions remain unverified. |
| Error and Attack Tolerance | Shared `aegis_core::research_topology`: bounded graphs, random/static-degree/adaptive-degree attacks, components, distances and efficiency. `transport-lab topology` consumes the analysis; opt-in endpoint selection consumes the checked operator-declared connectivity subset. | Synthetic and provided observed graphs are labelled separately; neither authenticates a complete fleet graph or proves actual reachability. Largest-component ties are an explicit policy, not a reachability theorem. |
| Catastrophic Cascade | Shared checked bijective dependencies and alternating component pruning to a fixed point. Offline analysis includes common causes; the live endpoint caller applies the same cascade before ranking and before each attempt, after current eligibility/cooldown. | Only an already admitted pool can shrink. Exclusion as a failed node is conservative; anchor loss refuses before dialing. This does not prove percolation laws, graph freshness or an observed fleet outage. |
| Low-Probability Detection on AWGN | `research_covert_channels` and `transport-lab awgn` implement finite Gaussian codebooks, noise and ML/likelihood diagnostics. The general H0/H1 apparatus is also consumed by the real private measurement chain: `privacy-pcap-export`, `privacy-study-assemble` and `privacy-frontier`, through `traffic_privacy::binary_hypothesis`. It reports empirical TV, directional KL, minimum unweighted sum-error and Pinsker diagnostics. | Finite empirical plugin values are not population guarantees. Missing observed reference support refuses finite KL/Pinsker output; it is not smoothed away. No AWGN physical carrier or Internet square-root throughput theorem is inferred. See [hypothesis diagnostics](binary-hypothesis-error-diagnostics.md). |
| Poisson Packet Channels | Two separate authorized, application-owned Rust SDKs and operator callers: `secure_channel::poisson_insertion` / `aegis-measure poisson-insertion` preserve an actual application byte source and decode inserted control records; `secure_channel::poisson_control` / `aegis-measure poisson-control` preserve an actual original UDP FIFO and decode an authenticated control record from observed departures through fresh timing codebooks. `transport-lab poisson-channel` remains an offline model, and exponential live-frame pacing remains a distinct experiment. | Neither SDK infers a legitimate Poisson source. Insertion requires the same fixed encrypted carrier under H0 and has finite RNG, scheduler, cap and terminal observables. Timing version 2 distinguishes original nominal arrivals from actual bounded admission, service and receiver departure; M/M/1 service and physical packetization remain unverified. Refusal retains the actual prefix and never becomes message delivery. See [insertion runtime](poisson-insertion-runtime.md) and [timing control](poisson-runtime-control-channel.md). |

## Local verification ledger — 12 October 2026

Source commit `ad029781cec189e71ecfa431c8a8cb5c537d2e91` adds bounded relay-liveness and Poisson source/terminal regressions and removes unused gradient work from finite-channel line search. The private local receipt at `evidence-archive/testing/2026-10-12/B07-local-wave-r1/receipt.json` names the exact commands, logs and scopes; it is not published with repository documentation. A representative direct-solver benchmark improved, but the old 5-second setting was a deadline, not an observed per-connection CPU time. The source remains unpublished and lacks exact-commit CI and installed-release acceptance.

| Work | Executed local evidence | Still required for full integration and acceptance |
| --- | --- | --- |
| BIT-TRAPS | Agreed directional FIFO/epoch test passed (1). | Native Windows timing, exact installed stream lifecycle and independent outer-traffic observation. |
| Privacy Against Statistical Inference | Finite rate-distortion suite passed (22), including a permanent bitwise value/cancellation regression for the optimized line search. | Calibrated class distribution and exact installed consumer and leakage measurement. |
| NetShaper | Agreed directional epoch test passed (1). | Actual scheduler/queue and whole-flow observations under the installed profile. |
| Rate-Distortion for Encrypted Traffic | Liu passed the finite suite and one relay-consumer request/reply test with application write halves held open. | Real target/purpose class calibration, exact installed client/relay lifecycle and outer packets. |
| Minimum Entropy Coupling | General coupling (20), cover stream (17) and one relay-consumer liveness test with application write halves held open passed. | Cover-source premise, external distribution, exact installed delivery and detectability measurement. |
| Network Calculus | Arrival guard tests passed (10); review found no causal accounting gap. | A measured lower FIFO service curve; configured local capacity remains an upper ceiling only. |
| Non-Stationary Bandits | Endpoint selector (19) and paper estimator (4) passed after a preserved sandbox socket-denial attempt. | Installed outcome accounting and non-stationary field evidence; local reply is not application completion. |
| Error and Attack Tolerance | Topology model (15) and live dependency graph (5) passed. | Authenticated, fresh fleet graph and observed targeted failure/reachability. |
| Catastrophic Cascade | The same scoped topology and dependency checks exercised fixed-point pruning. | Real common-cause dependencies, anchor admission and observed recovery on the exact fleet. |
| Low-Probability Detection on AWGN | Offline AWGN/Poisson model suite passed (31 combined); general H0/H1 diagnostics have a separate measurement caller. | A physical carrier or measured law before any AWGN covert-capacity claim. No Internet AWGN carrier is implemented. |
| Poisson Packet Channels | The combined offline model suite passed; owned application-source/terminal and authorized TLS insertion tests passed (1 each). | Measured legitimate Poisson source/service law, receiver-observed physical departures and installed carrier behaviour. |

The three new adaptive, cover and Liu request/reply tests keep both application write sources open until the reply arrives. They disprove an unconditional local one-sided-silence deadlock in these typed workers; they are in-memory and do not replace installed TLS/H2, capture or the 24-hour run. Routing and physical-model audits found no justified source change beyond the recorded Poisson assertions. The original failed Windows CI and mixed-cache/sandbox attempts remain failed evidence. None of the eleven rows is marked release-accepted by this ledger.

Local source commit `7b7ad22f4` adds an explicitly owned, in-memory server startup aggregate around `ServerTraining::prepare` before listener binding. The ordinary server path passes no observer; the opt-in witness counts completed and refused preparations and accumulates wall time and, on Unix, whole-process CPU during that window. Four local server tests, including a real keyring success/refusal without network, and strict all-feature server library/test Clippy passed. This is not per-connection logging or isolated optimizer CPU. The installed server has no consumer of this snapshot yet, so no installed startup distribution or release threshold is claimed. A previous per-connection DEBUG proposal was rejected for connection-metadata and slow-sink deadline risks.

A subsequent local source change adds the explicit `aegis-server --optimizer-startup-report` consumer. Once configuration has loaded and instrumented server startup begins, it prints one fixed-field aggregate to the local operator stream when the server reaches readiness or exits earlier; configuration-loading failures do not produce this report. Ordinary invocation still disables the witness. A focused binary test checks flag parsing and exact aggregate formatting, but does not exercise either runtime outcome. The first test attempt failed before candidate compilation because the shared target cache mixed Rust compiler builds; the isolated-target retry passed. No server was installed or started by this check, and no startup distribution, threshold, per-connection CPU or privacy bound is inferred.

A separate real-server loopback test now checks the instrumented startup path: the reported TCP address accepts a connection after a completed Liu preparation, while a specific impossible-support refusal occurs before readiness. Its R3 raw log and exit code record 1/1 local PASS after R1/R2 attempts were preserved. The test observes the in-process witness; it does not read the binary flag's operator output, measure a startup distribution, or establish installed behavior. Exact final-source CI and the eleven works' field premises remain open.

A separate disposable real-binary integration regression now exercises that operator flag: an opt-in process reports one aggregate on readiness and drains on SIGTERM; a second opt-in process reports a specific Liu numerical refusal before readiness; an opt-out process suppresses the aggregate. R4 passed 1/1 with targeted strict Clippy and a source/binary-bound receipt; R1–R3 failed attempts are retained. It reads local child output inside the test, not an installed distribution or independent application exchange. The fixture does not retain the child logs after cleanup, measure CPU/wall distributions, or infer outer traffic and complete eleven-work acceptance.

The optional `scripts/collect-optimizer-startup.py` collector accepts one retained
operator log per independent startup, the operator-selected `aegis-server` binary and its
configuration, and independently expected SHA-256 digests for both. For example:

```text
python3 scripts/collect-optimizer-startup.py \
  --binary /installed/aegis-server --binary-sha256 <verified-sha256> \
  --config /installed/server.toml --config-sha256 <verified-sha256> \
  --expected-runs 3 --output /private/receipt-r1.json \
  /private/run-1.log /private/run-2.log /private/run-3.log
```

It requires exactly one complete aggregate and readiness event per run, a positive
and equal number of completed preparations, zero failures and a uniform count
across runs. It refuses a missing/duplicate run, a changed binary/configuration,
an oversized log and an existing output receipt. Output contains only artifact
hashes, ordered raw-log hashes and numerical startup summaries, not original
logs or config paths. The `run_log_sha256` order matches each `per_run` metric.
Its `scope=binary_startup_observation_only` records what the collector verifies;
it does not attest installation.
The operator must separately record the installed package and release identity,
platform, execution conditions and independent process outcome, and retain the
original logs privately. The collector neither launches the binary nor proves
that a supplied path came from an installed package. This remains startup-only
evidence and does not establish external traffic or all-eleven acceptance.

A later exact-source local startup series has a separate private R1 receipt at `evidence-archive/testing/2026-10-13/B07-exact-startup-r1/receipt.md`. The `d3e373371` macOS ARM64 development binary (SHA-256 `baf781b0e2bf9c4f627aac871c969028f50d11233fbf38cafbee32a1090cbe18`) and synthetic loopback config were pinned before ten independent opt-in starts. All ten reported one completed preparation and readiness, drained with exit 0 after their bounded dwells, and one stayed live for 60 seconds. The exact-source collector accepted ordered raw logs and reported prebind wall 384/683.5/1241 microseconds (min/median/max) and whole-process CPU 404/719/931 microseconds. First sandbox bind attempt failed before readiness; a runner revision then added loopback listener preflight and a non-loopback negative control. The original local runner was later tracked in source. R5 hardening is now applied to canonical source with a separate retained receipt; successor Ubuntu CI has not completed. This is a local startup consumer/liveness sample, not installed distribution, application exchange, outer traffic, 24-hour endurance or all-eleven acceptance.

The B-07 R5 strict runner receipt (private evidence path `evidence-archive/testing/2026-10-13/B07-startup-runner-r5/receipt.md`), SHA-256 `6a4dde47d91cd4e7540b30fa2a607d10dc8539faa5b5be15b0df4ac9abc917d3`, preserves R1–R4 false-ready, group-cleanup and exact-log-cap review failures. Applied source now requires an exact structured readiness event, refuses a saturated 2 MiB child log, bounds a loopback fixture, and cleans the owned process group before leader reap. Local collector tests passed 8/8 and inert runner tests 13/13; independent review found no remaining P1/P2 within source-only scope. Proposed Ubuntu CI checks are pending on the successor commit. These tests do not re-run the ten real development-server starts or attest a bound listener, installed package, outer traffic, field premises, full-day endurance or all-eleven composition.

The R2 readiness parser receipt (private evidence path `evidence-archive/testing/2026-10-13/B07-ready-fields-r2/receipt.md`) and review (`evidence-archive/testing/2026-10-13/B07-ready-fields-r2/independent-review.md`) bind a later source correction. R1 failed P2 review because unquoted prose containing the readiness fields was accepted. R2 matches the complete producer-shaped timestamped readiness line and refuses required QUIC when unbound. Its first fixture run failed 6/10 because obsolete trailing prose remained in test lines; corrected local collector checks passed **10/10**, inert runner checks **13/13**, and all ten retained real development-server logs parsed. This establishes only retained-log syntax compatibility. Log emitter identity, bound listeners, installed distribution, outer traffic, independent premises, full-day endurance and all-eleven composition remain unverified; exact successor CI is pending.

## Operator guide map

The private Linux research archive carries these guides with their related local
references. They explain the actual interfaces and their prerequisites without
requiring a source checkout:

- BIT-TRAPS: [independent service and FIFO](bittraps-independent-service-stream.md).
- Calmon/Fawaz: [finite optimizer](rate-distortion-finite-channel.md),
  [adaptive runtime](adaptive-channel-runtime.md) and
  [maximum-information/minimax](maximum-information-channel.md).
- NetShaper: [integer sampler and public epoch](netshaper-integer-runtime.md).
- Liu: [explicit-context runtime](liu-runtime-channel.md).
- MEC/iMEC: [coupling](general-coupling.md) and
  [conditional cover stream](cover-stream-runtime.md).
- Network Calculus: [conditional arrival/service guard](network-calculus-guard.md).
- Bandits: [endpoint selection](relay-endpoint-paper-bandit.md),
  [context ownership](native-bandit-context-retirement.md) and
  [H2 progress evidence](h2-progress-observations.md).
- Attack tolerance and cascading failures: [topology models](topology-paper-models.md)
  and [live dependency admission](live-dependency-admission.md).
- AWGN and Poisson models: [physical premises](covert-channel-paper-models.md).
  Actual application-owned Poisson consumers have separate
  [insertion](poisson-insertion-runtime.md) and
  [timing control](poisson-runtime-control-channel.md) guides;
  [exponential frame pacing](poisson-runtime-pacing.md) remains distinct.

These instructions do not activate a schedule or supply a measured traffic
model, credentials or a physical carrier. One-owner admission still applies.

## Source coverage update — 10 October 2026

The source audit found two additional algorithm/consumer gaps: conditional iMEC
cover laws and Calmon/Fawaz maximum-information optimization. Both now have
explicit typed runtime selection and real protected relay consumers; they are
covered separately in [general coupling](general-coupling.md),
[cover streams](cover-stream-runtime.md) and
[maximum-information channels](maximum-information-channel.md). The seven-profile
local device TLS/H2 policy and owned TCP payload tests exercise their composition
alongside mean-MI, NetShaper, BIT-TRAPS and memoryless cover. The default optional
selection remains absent; no stream stacks incompatible owners.
Those seven local composition checks are paired production-caller fixtures,
not seven independent installed-network/OS acceptances. In particular they do
not validate a lower service curve, a Poisson source, outer packet law or the
distribution seen by a remote classifier.

These checks close those bounded source gaps. They do not certify all physical
conclusions of eleven works, an arbitrary conditional language/application model,
stationary infinite-queue results, whole-flow privacy or acceptance of an
installed exact release. Population calibration, physical service/source premises,
required exact-commit CI and original release gates remain separate and open.

## One owner of the live record stream

`authenticated_shaping` admits exactly one owner: constant cadence, exponential
pacing, NetShaper epoch, BIT-TRAPS epoch, causal adaptive channel, general cover
stream, or explicit-context Liu channel. `PrivacyPlan` must describe the same owner. Nested owners, inconsistent
settings, excessive public budgets and unsupported whole-flow-DP requests refuse
before credentials, dialing or native policy creation. Arrival-envelope admission
is currently composed only with constant cadence, where its service assumptions
can be described; it refuses combination with the other schedules.

Relay/H2 agrees the complete typed profile inside authenticated device TLS and
before any Open or PolicyAck request. Both sides contribute fresh entropy inside
that TLS session for keyed epochs/cover; HKDF binds the full profile and direction.
Every new session gets new material. Profile disagreement and late establishment
fail without an unshaped fallback. Original establishment and session clocks are
not reset by training, profile agreement or key derivation. Owned stream Drop
cancels workers, and live server authorization remains raced against the work.

For typed constant-cadence and exponential-pacing sessions, the session cap starts
before the shaping hello/ACK, after device TLS. The worker receives that absolute
cutoff: agreement latency and delayed worker scheduling consume it. An expired
worker refuses before polling the transport. The establishment cutoff remains
separate; standalone opaque framing retains its existing worker lifetime.

Liu has its own strict finite target/purpose context. Admission checks every
positive kernel entry before private identity or a socket can be used. The server
checks the protected Open target before dialing. Both parties bind fresh
contributions to the full context, direction and exact kernel digest inside
authorized TLS. Record sequence, complete-frame integrity, wire bounds and END
are checked before plaintext delivery. Batching copies already completed records
and keeps the earliest queued deadline; it does not retrain, resample, trim the
kernel or extend a public clock. Agreement across platforms must execute the
same numerical kernel; a mismatch refuses. Tests of these production callers use
real paired TLS/H2 and remain distinct from installed VM acceptance. The new
client agreement dispatcher owns its complete future on the heap so its generic
TLS state is not copied into every enclosing startup operation. It preserves the
original agreement body, deadline and stream cancellation on Drop. Compiled
future-size diagnostics are separate from actual Windows process-start acceptance.

Opaque carriers lack this typed agreement. They refuse the new keyed/adaptive
modes rather than silently deriving independent keys or bypassing agreement.
The shared `validate_opaque` admission is also applied by all four opaque client
and server loaders before admission credentials or device identities are read;
WebRTC validates it before loading its runtime's private material. The generic
public device-carrier entry checks it before starting device TLS. Liu cannot
fall through to a constant worker on those paths. Supported gRPC Liu still uses
its specialized context/kernel agreement, and absent settings retain plain bytes.
Default profiles omit all added optional fields, retaining previous wire and
behaviour. A fixed finite epoch is an explicit experimental transport contract,
not a transparent replacement for arbitrary TCP half-close lifecycles.

Managed public device bundles can carry the optional typed fields
`authenticated_shaping`, `privacy_plan`, `recent_routes` and `endpoint_bandit`. Creation and rendering
validate them before private identity/overlay access; rendering copies them into
the installed configuration. The original four-member bundle digest binds their
raw bytes. Online runtime admission compares the complete policies to that
pinned public profile before private overlay access: dropping a policy or
substituting another locally valid policy refuses. Absence preserves old defaults;
explicit null and unknown nested fields refuse. The profile itself does not gain
a separate signature through this extension.

The managed transport policy still admits only the gRPC stream TCP family.
Native Brain therefore has one family arm in this policy. The separate optional
endpoint selector learns within a pinned pool of 2–16 concrete numeric relay
addresses; it never discovers endpoints or loosens transport authorization.
Configuration, ordered pool, public trust/device-certificate chains and target
context bind each learner. Certificate rotation creates fresh state. Pre-auth
outage cooldown precedes ranking; authentication and committed-data failures
remain terminal without replay. See [endpoint selection](relay-endpoint-paper-bandit.md).
This does not establish an adaptive multi-provider fleet availability guarantee.

Native Brain paper learning keeps at most 64 context histories. A valid completed
outcome creates a fresh estimator before retiring the least recently completed
history; ranking visits do not extend its lifetime. Retirement removes that
context's observations, preserves the monotonic completion clock and never stops
a transport. A returning or late completion starts fresh without restoring old
paper estimates. Genuine estimator refusal remains sticky. This is bounded
history management, not the infinite-history regret guarantee of the paper.
See [native context retirement](native-bandit-context-retirement.md).

The optional nested `endpoint_bandit.dependency_policy` is also bound by the raw
public profile and runtime identity. Its two graphs, bijective dependencies,
ordered endpoint mapping and required anchors validate before certificate reads.
The original TCP establishment clock begins before its first graph validation;
validation, identity observation, ranking and every pre-auth retry share that
cutoff. The original eligible subset cannot expand. Current cooldown is applied
again before each attempt, so a failed first endpoint can remove a dependent
backup that was previously ranked. An absent graph creates no graph work;
absent endpoint selection retains the old path without a new timer/state.
See [conditional dependency admission](live-dependency-admission.md).

## Analysis and calibration

The following offline Rust commands accept at most 1 MiB of input and do not open
sockets or discover dependencies:

```text
aegis-transport-lab bittraps-channel <finite-stream-grid.json>
aegis-transport-lab privacy-channel <finite-channel.json>
aegis-transport-lab topology <paired-graphs.json>
aegis-transport-lab awgn <awgn-model.json>
aegis-transport-lab poisson-channel <queue-channel.json>
```

The service-grid optimizer bounds aggregate enumeration work. Channel training
bounds alphabets, iterations and time. Graphs, codebooks and queues have explicit
caps. Results contain their numerical/model scopes and do not declare beta exit,
installed-runtime acceptance or target-network measurement. Examples from
synthetic models must not be promoted into calibrated deployment profiles.

The one-shot `aegis-measure private-control` endpoint is separate from relay
Open/PolicyAck. It uses a fresh authorized TLS session, descriptor agreement,
bounded operator files and revocation; it cannot nest live shaping. See
[private control custody](private-control-session.md) and the module documents.

The two Poisson SDKs own different sources and are separate from that record
owner. They do not nest under `authenticated_shaping`, borrow third-party cover
flows, activate an installed profile or replace arbitrary full-wide sessions.
Timing preflight rejects any additional shaping owner before device TLS; insertion
uses a strict standalone public profile and descriptor rather than accepting a
nested relay schedule. Each exchange derives fresh authenticated material and
keeps the caller's original deadline. Successful timing receipts require the
actual release thread and receiver collector to finish and be joined; cancellation
requests alone are not such proof. No operator enables those SDKs implicitly.

The private operator kit delivers `aegis-measure` and `aegis-transport-lab`
alongside their source/lock/target identities, binary hashes and exact capability
lists. Linux archive admission checks the complete pair before writing the
manifest. The Windows release workflow binds both unsigned operator binaries to
the original candidate inventory before promotion, then requires the same
publisher, timestamp and signing custody as the client tools. This makes the
research consumers available as explicit operators; it does not activate a
Poisson owner for arbitrary installed traffic. See
[private operator delivery](private-operator-delivery.md).

Insertion forwards completely authenticated original read chunks in FIFO order;
only inserted record bodies expose the bounded control message to the recipient.
The public insertion horizon is not shortened by source EOF, and an early or
false authenticated terminal refuses. Timing keeps one slowing phase and one FIFO
across fixed independent codebook blocks. Every original must be observed before
its unchanged nominal arrival, and actual service must respect that point's
existing lateness allowance, including a last point across a block boundary.
Neither clock reset, seed selection nor resampling can rescue a missed operation.
The public strict timing primitives now execute each command on an owned native
thread, preserving their previous-write gate. They remain a separate contract
from the version-2 overlapping FIFO service queue.

## Completion evidence

Implementations, actual consumers, deterministic regressions and independent
source review establish bounded engineering behaviour. They do not establish all
physical assumptions or conclusions of the papers on the installed Aegis release.
In particular, AWGN is a physical-channel model; label-conditioned rate-distortion
needs representative available classes (explicit target/purpose mappings supply
context without proving calibration); perfect cover needs the stated random-distribution
premises; whole-flow DP includes handshake, scheduling and termination observables.
These distinctions must remain explicit in claims and release receipts.

Geneva, TLS/H2 packetization, target disclosure and local service dependencies
remain separate layers. Brain cannot broaden profile admission. Its baseline
legacy selector source now excludes snapshot hard blocks before epsilon and
exploitation selected orders. The legacy relay ordering leaf preserves that
calibration-backed set, including an empty order when all configured families
are blocked. Its uncalibrated cold/epsilon guards retain their previous scope.
These narrow source repairs require exact-commit regression/CI receipts and do
not establish installed acceptance. The separate recent-route and hybrid-route
selectors apply their own hard-block checks. The detailed scoring reference in
a source checkout is `docs/architecture/27-knowledge-architecture.md`, under
"Hard-block and admission boundary". That reference is outside the private
operator archive; the delivered boundary above does not require that file.
Declared graph analysis does not perform fault injection. The exact release still
requires its own successful CI/build identity, production signing, installed
lifecycle, independent capture and target-network evidence, full-duration run and
human acceptance. No previous release proof transfers onto these source changes.

## Optimizer preparation admission

Runtime adaptive and Liu preparation share a process-local admission owner with
four queued/running blocking jobs and at most 32 waiting callers. Queue waiting
consumes the already captured original optimizer cutoff. Saturation, expiry,
cancellation and numerical refusal return no channel; they do not renew the
budget or select an unshaped fallback. The actual queued/running closure retains
its worker permit even when the awaiting caller is dropped. A running blocking
job stops cooperatively at its existing cancellation/deadline checks; this is
not force-cancellation or an operating-system scheduling guarantee.

This admission policy does not change solver mathematics, iterations, gap,
returned channels, descriptors or HELLO order. Direct offline solver calls are
outside the runtime owner pool. The 4/32 limits have not been calibrated under
native production load and do not establish aggregate CPU/heap, whole-flow
privacy, installed acceptance or beta exit.

## 29 October 2026 — B-07 all-eleven source and acceptance inventory

This is a source-only reconciliation at `b79fb387`. The paths below are
actual entrypoints and consumers, not proof that an installed product used
them. The executed counts are the **historical local** results in the
12 October ledger above; this inventory runs no new test. `M` denotes a
missing physical/deployed premise or acceptance measurement, not a missing
Rust module. These eleven directions share one release obligation, but one
record stream has one owner, so mutually exclusive profiles must be measured
as separate admitted compositions rather than stacked together.

| Direction | Product entrypoint and call path; implemented source / missing scope | Existing executed evidence | Open installed/composed acceptance |
| --- | --- | --- | --- |
| BIT-TRAPS | Typed relay profile -> `aegis-core/src/secure_channel/relay_shaping.rs` -> `traffic_privacy/bittraps.rs`; bidirectional authenticated epoch and FIFO exist. M: independent **outer** packet service law. | Directional FIFO/epoch 1/1 local. | Installed client/relay request-reply and external packet capture, including Windows timing and terminal tails. |
| Privacy Against Statistical Inference | Typed relay `adaptive_channel` through `relay_shaping.rs` -> `traffic_privacy/adaptive_channel.rs`, `rate_distortion.rs` and `rate_distortion_maximum.rs`; finite mean-MI, maximum-information and minimax selectors exist. M: representative class frequencies and a population guarantee. | Finite optimizer 22 local plus the existing seven-profile paired relay composition fixtures; not installed. | Calibrated class labels, installed selection/admission and external H0/H1 leakage measurement. |
| NetShaper | Typed relay profile -> `relay_shaping.rs` -> `traffic_privacy/netshaper.rs`; integer sampler, public epoch and bounded queue exist. M: observed scheduler/queue and whole-flow DP law. | Directional epoch 1/1 local. | Installed bidirectional lifecycle, actual service/queue measurements and independent outer capture. |
| Rate-Distortion for Encrypted Traffic | Explicit target/purpose client Open and PolicyAck -> `secure_channel/relay_shaping_liu.rs` -> `traffic_privacy/liu_channel.rs` and `rate_distortion.rs`; authenticated agreement and positive causal support exist. M: calibrated real classes. | Finite Liu suite and one open-write-half relay request/reply local. | Installed client/relay target-class admission, lifecycle and external packet-law measurement. |
| Minimum Entropy Coupling | Typed relay -> `relay_shaping.rs` -> `traffic_privacy/cover_stream.rs` -> `general_coupling.rs`; conditional table and per-record state exist. M: a real cover-source premise and ideal-OTP equivalence. | General coupling 20, cover stream 17 and one open-write-half relay request/reply local. | Installed full-record exchange, external distribution/detectability and cover-source validation. |
| Network Calculus | `carrier_runtime.rs` arrival envelope -> `traffic_privacy/shaper.rs` -> `network_calculus_guard.rs`, before constant worker emission. M: measured **lower** FIFO service curve; configured capacity is only an upper ceiling. | Arrival guard 10 local. | Installed queue/backlog/delay observations under a measured service envelope and external traffic. |
| Non-Stationary Bandits | Native `brain/recent_routes/paper_bandit.rs` and opt-in `aegis-client/src/relay/endpoint_bandit.rs` choose among pinned eligible endpoints; response-qualified observations exist. M: field regret assumptions. | Endpoint selector 19 and paper estimator 4 local; first sandbox socket denial retained. | Installed outcome accounting, independent endpoint/listener attestation, churn and application completion. |
| Error and Attack Tolerance | `aegis-core/src/research_topology.rs` offline model plus `research_topology_live.rs` and endpoint dependency policy; bounded attack/component operators exist. M: authenticated complete fleet graph and observed attack process. | Topology 15 and live graph 5 local. | Attested live graph, targeted failure injection and external reachability/recovery evidence. |
| Catastrophic Cascade | `research_topology.rs` fixed-point dependency pruning -> endpoint-bandit dependency admission before ranking and each attempt. M: real common-cause dependency and fleet percolation premise. | The same topology 15 and live dependency 5 local; not a second independent fleet trial. | Installed anchor-loss refusal, observed cascade/recovery and independent endpoint attestation. |
| Low-Probability Detection on AWGN | `tools/transport-lab/src/research_covert_channels.rs` is offline; real measurement path is `tools/measure/src/privacy_pcap.rs` -> `privacy_study.rs` -> `privacy_frontier/binary.rs` -> `traffic_privacy/binary_hypothesis.rs`. No AWGN physical carrier exists. | Offline AWGN/Poisson combined suite 31 local; separate H0/H1 diagnostic caller exists. | Independently captured external traffic and empirical detection error; a physical carrier is needed before an AWGN throughput claim. |
| Poisson Packet Channels | Authorized application-owned `secure_channel/poisson_insertion.rs` and `poisson_control.rs` -> `tools/measure/src/poisson_insertion.rs` and `poisson_control.rs`; original source/FIFO and authenticated control exist. Offline `transport-lab` and exponential pacing are separate. M: legitimate Poisson source, M/M/1 service and physical packetization. | Combined offline model suite 31; owned source/terminal and TLS insertion one local test each. | Installed owned carrier, receiver-observed departures, external H0/H1 traffic and measured source/service law. |

Cross-row gates remain open: measure a **distribution** of installed
`aegis-server --optimizer-startup-report` runs using the strict
`scripts/collect-optimizer-startup.py` collector bound to exact binary/config
hashes and ordered raw logs; independently attest the actual listener and
client-to-relay exchange; collect external traffic for each admitted profile;
then evaluate the eleven directions as a complete, non-stacked release matrix
against declared premises and thresholds. The R2 exact-line collector replay
and local development-server starts above are not an installed distribution.
The signed exact release, final-commit CI, independent review, audit/grant
gates and full-duration endurance remain separate and required. This inventory
does not close any row or convert offline analysis into field evidence.

## Exact 79b5 delivered-guide CI failure

[General CI attempt 1 in run 38406585333](https://github.com/example-org/aegis/actions/runs/38406585333) on commit `79b5d1b8613ccb6b3140b9cd28f323811a3a562a` passed Rust strict Clippy, then failed `research_operator_delivery::tests::delivered_research_links_resolve_without_checkout_and_all_guides_are_hash_bound` at the first Markdown link in this delivered guide to an ignored B-07 private receipt. An isolated one-link correction exposed the next invalid link; the combined three-link private-evidence wording removed all three ignored-artifact links and passed the exact targeted method 1/1 in an archived source tree. The private CI receipt at `evidence-archive/testing/2026-10-13/CI-79b5-final-r1/receipt.md` retains raw-log hashes. This local correction is pending exact successor hosted CI and does not change B-07 installed startup or all-eleven research acceptance.
