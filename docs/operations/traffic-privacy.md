# Opt-in traffic privacy runtime

The core exposes a causal framed stream, exact finite supported MEC couplings,
and measured finite-alphabet leakage estimates. Brain also exposes a bounded
recent-outcome selector. These are source capabilities and controlled test
inputs. They do not establish installed, target-network or beta acceptance.
Constant framing alone supplies no NetShaper differential-privacy guarantee.
The separately selected NetShaper integer runtime has explicit bounded
query/accounting premises described in its
[mechanism contract](../research/netshaper-integer-runtime.md); these do not
make an arbitrary whole relay flow differentially private.

## Causal framing

`traffic_privacy::shaper::attach_framed` wraps an owned authenticated encrypted
stream at both peers. Both endpoints must explicitly agree on framing and
identical payload size/cadence/budgets before use; there is no transparent
fallback to an unshaped protocol. Device TLS authentication precedes the
wrapper; application protocol bytes, including frame lengths, then pass through
that encryption. Use the returned `ShapedStream` as normal async I/O.

Every transmission contains a two-byte big-endian used length and one fixed
payload. Length0 is cover, length65535 is authenticated end-of-direction, and
other lengths must fit the configured payload. Unused bytes come from OS
cryptographic randomness. Original application bytes retain order and content.
No queue overflow silently drops data: the bounded duplex pipe backpressures
writers. Invalid/truncated framing, entropy failure, exhausted wire budget,
stalled I/O or lifetime expiry returns an error and closes the session.
Such an error can interrupt accepted-but-not-delivered writes, as ordinary
stream failure can; it is never a successful complete-delivery receipt.

The sender waits at least one cadence before each frame, including cover/end
frames. A slow write does not cause a catch-up burst. Frame payload1..4096,
buffer at most1MiB, cadence1ms..1s, I/O timeout at most30s and session lifetime
at most1h are validated. Per-direction wire budgets count headers and padding.
The receive deadline allows the previous frame flush, the next cadence and
the next frame write: `2*io_timeout+cadence`. A stalled peer still expires at
that finite deadline; the session cap remains separate.
The receive buffer is one frame; local duplex buffers and one pending send frame
bound queued bytes. Under ready I/O, full-frame payload service is P/cadence.

For local admitted bytes, configuration requires queue allowance at least
`(ceil(buffer/P)+1)*(cadence+io_timeout)`. This conservative service calculation
includes the partial/in-flight frame. It is conditional on a progressing runtime
and successful I/O within its deadlines, not an Internet lower-service guarantee.
An overloaded arrival process waits outside the bounded admission buffer; no
unbounded-arrival delay promise is made. [Le Boudec and Thiran's network-calculus
book](https://leboudec.github.io/netcal/) supplies the arrival/service/backlog
framework; no measured network service curve has been inferred here.

`flush` only acknowledges local pipe acceptance. `shutdown` half-closes local
input and waits until queued bytes, END and the underlying encrypted write
shutdown complete; immediate drop afterward preserves the sent ACK/tail.
Read the peer to authenticated EOF and call `finish` for both-direction
completion counters. Dropping the stream, including cancelling `finish`, aborts
its owned worker. EOF without an authenticated end frame is an error.
Connection start/end, TLS records, TCP segmentation, scheduler jitter,
congestion, session length and bidirectional/application dependencies remain
observable. Fixed application frames are not proof of fixed wire packets.

[NetShaper, USENIX Security2024](https://www.usenix.org/conference/usenixsecurity24/presentation/sabzi)
has its own privacy model and accounting. This implementation does not reproduce
its sensitivity, randomized release/composition model or epsilon/delta proof.
This paragraph describes the constant-cadence `shaper`, not the separate opt-in
NetShaper epoch owner in the [composition matrix](../research/implementation-and-composition.md).

## Ordinary authenticated relay opt-in

The ordinary gRPC/H2 client and server can explicitly enable this same causal
framing, including a privately admitted HTTPS bridge. It applies to TCP,
fixed-target gRPC UDP and targetless live policy ACKs. These are the authenticated
relay entry points used by full-wide; this option does not install or configure
full-wide capture, enable native web/WebRTC planner strategies, or certify an
installed release. The default remains disabled and sends exactly the existing
Open/PolicyAck wire. Automatic enrollment/renewal uses its separate unchanged
enrollment TLS protocol.

The minimum cadence and nominal-rate statements in this section describe
constant framing when `poisson_pacing` is absent. Bounded exponential proposals
instead use that cadence as a public maximum receive/queue envelope; see
[the pacing contract](../research/poisson-runtime-pacing.md). They do not supply
a fixed minimum delay or an unconditioned Poisson wire-law guarantee.

On the client, add `[relay.authenticated_shaping]`; on the server, add
`[transport.authenticated_shaping]` with **identical** settings. For example:

```toml
[relay.authenticated_shaping] # server: [transport.authenticated_shaping]
payload_bytes = 1024
cadence_ms = 5
buffer_bytes = 4096
max_wire_bytes = 8388608
io_timeout_ms = 100
session_timeout_ms = 30000
max_queue_delay_ms = 750
```

This is an explicit operator opt-in. Managed public device bundles may carry
the same optional typed policy; the renderer preserves it, as described below.
It is not measured-policy auto-selection. Validate the same setting at both
peers before rollout. It requires existing device inner TLS; client admission
still permits only gRPC stream TCP and disabled or gRPC datagram UDP, with the
existing trust/backend/mimicry restrictions. Invalid local settings reject
before dialing or binding. The opt-in client's establishment timeout must be
1..60000ms; disabled profiles preserve existing timeout behavior.

After device TLS, a typed versioned hello and ACK agree the entire profile
before any target request or policy ACK. Each control message is at most 4096
JSON bytes plus its two-byte length; local profile admission reserves 64 bytes
for the typed hello wrapper. This bounded control exchange is outside
the later per-direction framed-byte budget, which includes fixed frame headers,
padding and END but excludes outer TLS/H2 and network overhead. Constant-cadence framed emissions
wait at least one cadence per frame; their nominal framing rate is at most
`(payload_bytes+2)/cadence`, with no catch-up after slow writes. Alternate admitted
owners use their documented epoch, causal-action or fixed-cover budgets. Session and I/O
deadlines and local admission/backpressure remain as described above.

The original total establishment deadline and live authorization-revocation
watch cover the agreement. Different profiles, one-sided activation, an old
peer or an unknown version/schema fail before target dial, without unshaped
fallback or post-auth pool retry. A server opt-in therefore requires compatible
clients for **all** its authenticated traffic and policy ACKs. Successful renewal
does not change that traffic policy. Existing explicit web/WebRTC carrier
commands retain their own configured framing; they do not send this relay hello.

For typed constant cadence and exponential pacing, `session_timeout_ms` starts
before the shaping hello/ACK, after device TLS. The original absolute cutoff
survives agreement and worker scheduling; neither step grants another lifetime.
This session cap is separate from the connection-establishment deadline.
Standalone opaque framing retains its existing worker lifetime.

Public managed device bundles accept optional `authenticated_shaping`,
`privacy_plan` and `recent_routes` policies. The renderer retains them in the
installed configuration; the original bundle member/profile digest binds their
raw bytes. Online runtime checks require equality with that pinned public policy
before reading a private overlay or identity. A profile change requires a new
explicitly accepted bundle, and a shaped client still needs a compatible paired
relay configuration. Do not change a shared relay's policy while existing devices
require another profile. The gRPC-only managed transport policy remains unchanged;
its paper bandit has one family arm, not one arm for each pool endpoint.

## Optimizer preparation admission

The admission policy shares one process-local pool across all adaptive
objectives and Liu: at most **4 admitted blocking jobs**, including jobs still
queued in Tokio's blocking executor, and **32 preparation callers waiting for
admission**. These are distinct queues. The constants are an unmeasured
availability policy, not a throughput recommendation or privacy parameter.

Each wrapper captures its optimizer cutoff once, capped by the caller's original
absolute deadline, before waiting. Waiting, numerical work and completion checks
consume that same cutoff. Saturation returns `WouldBlock`; original expiry
returns `TimedOut`. Callers treat either as terminal refusal of the protected
attempt: no new prepared channel, renewed cutoff, automatic retry or unshaped
fallback is produced by admission.

The admitted blocking job owns its permit while queued or running. Cancelling
its awaiting caller sets the existing cooperative cancellation flag; capacity
returns only when the job is actually cancelled before starting or its closure
exits. Aborting an awaiting handle cannot forcibly stop a running system thread.
Dropping a caller still waiting for admission releases its waiting slot. Liu
holds **one permit across both unchanged directional solves**, not one per solve.

This changes neither optimization mathematics, numerical/DP validation, settings
descriptors nor HELLO ordering. It bounds preparation ownership, not aggregate
heap, authenticated task counts, all offline core solves or total process CPU.
Cold old-client/new-server agreement has not been measured on the exact release;
this policy does not extend either peer's original budget or establish
mixed-version negotiation. See the [adaptive](../research/adaptive-channel-runtime.md),
[finite optimizer](../research/rate-distortion-finite-channel.md) and
[Liu](../research/liu-runtime-channel.md) contracts.

Controlled evidence: the same six real-wrapper fixtures produce five causal
baseline failures and one passing original-profile control, followed by six
passes with admission. Thirty-six existing adaptive/Liu controls also pass.
The first strict-check failure in a test diagnostic and two invalid zero-test
control selections are retained separately; corrected selections are nonzero. Source/local results must not be read as installed,
target-network, independent-capture, day-long, release-CI or beta acceptance.

## Completed relay training at startup

The production relay keyring prepares a configured adaptive or Liu numerical
profile before binding its ingress listeners. Startup uses the existing 4/32
admission and one optimizer allowance captured at preparation entry. Numerical
failure prevents readiness; certificate loading and later listener binding are
separate work, not covered by that optimizer allowance.

The completed owner contains the entire ordered public profile and immutable
numerical models. Primary TCP and QUIC workers share that same runtime owner.
An authenticated session may reuse it only for an exact profile match. The
same device TLS, authorization lease, typed HELLO, directional kernel digest
and original session deadlines still govern each new session. No remote
request inserts or refreshes a model. Entropy, target context, buffers, clocks
and cancellation remain separate per session; the completed owner retains no
optimizer permit.

This avoids repeated relay solves for that trusted profile. The unchanged
client still performs its own required training, and compatibility entry points
without a prepared owner retain their original per-session preparation.
Settings comparison, cloning, digest calculation and session allocations still
cost work. Other cover/direct solver costs, aggregate heap/CPU, measured native
capacity and archived old-client interoperability remain open. This is no new
privacy guarantee and no relaxation of numerical or wire admission.

Controlled regressions preserve the unchanged current-build client order and
actual numerical/wire transfer before checking that the relay creates no
per-session solver. Two causal failures become passes on the same complete
fixture, with five separate controls in each phase and21 existing Liu controls.
Core wire fixtures use duplex; native TLS and archived-client interoperability
remain separate acceptance. Earlier invalid preparation/classifier attempts
are retained.
The final test-only borrowed-Option lint successor retains the same assertions
and cutoffs; its changed mismatch control is separately rerun. The original
complete paired fixture stays bound to its own historical source hash.

## Accounted schedule query release

`schedule_dp::ScheduleAccountant` supplies a narrower formal primitive. A fixed
query is clipped to the binary domain{0,1}. Release the true bit with exact
probability a/(a+b), or its complement with b/(a+b), where a>=b>0. For either
output and either neighboring binary query, its likelihood ratio is at most
a/b. Sequential composition for m releases is pure DP with delta0 and
epsilon=m*ln(a/b), including worst-case neighbors that affect every query.
The accountant tracks exp(epsilon) as checked integer rational products and
refuses before exceeding its rational odds/release budget or overflowing.
There is no floating-point epsilon acceptance comparison. Runtime callers
must supply a cryptographic RNG; controlled tests use seeded RNGs.

The protected observation is only the released binary transcript. Query count,
release times and lifetime must be chosen independently of private input;
postprocessing of those released bits can select a public schedule. Private
stopping, clear frame lengths, actual queue stalls, endpoints or other emitted
statistics are outside this proof. This primitive is not automatically applied
to the fixed-frame stream and does not make that whole flow DP. Its receipt
names that restricted scope. [Dwork and Roth, sections3.2/3.5](https://www.cis.upenn.edu/~aaroth/Papers/privacybook.pdf)
provides the randomized-response/composition framework.

## Exact supported MEC

`MinimumEntropyCoupling::new(weights,bits)` accepts positive integer finite
cover masses, at most32 symbols, and1..4 message bits per symbol. Checked total
mass must partition exactly into2^bits equal bins. A bounded100000-node search
either returns a partition or rejects it; exhaustion does not prove no partition
exists. Unsupported distributions are not silently rounded or greedily encoded.

For independent uniformly distributed message X, select Y inside its bin with
probability weight(Y)/bin_mass, using a cryptographic RNG. Then the cover
marginal is exactly weight(Y)/total_mass in the rational sampling model. Decoding
is the unique bin of Y. Thus H(X|Y)=0 and H(X,Y)=H(Y), attaining the unavoidable
lower bound H(X,Y)>=H(Y): this supported coupling is globally minimum entropy.
Integer joint weights expose the exact marginal argument without floating point.
The sampler uses unbiased integer draws; runtime code must use a cryptographic
RNG, and deterministic seeds appear only in tests.

Arbitrary plaintext messages are not uniform. This module does not establish
that an encrypted message source is information-theoretically uniform, conceal
termination/length/timing, learn a cover distribution, synthesize browser/media
content or transport arbitrary bytes automatically. Those assumptions cannot
be inferred from codec round trips. The [MEC paper](https://arxiv.org/abs/2210.14889)
connects couplings to its cover-model security and minimum entropy to throughput;
the broader arbitrary-cover algorithms are outside this exact supported subset.

## Measurement scope

`privacy_frontier_report` consumes declared label/feature alphabets and per-policy
samples of label, feature, added bytes and added delay. The measure CLI enforces
the file boundary. It rejects unknown schema fields and invalid/oversized
inputs; policies require identical evaluation label counts for comparison.
Equal counts alone do not establish a paired evaluation. Inputs without
provenance remain compatible and receive `unverified_legacy_input` status.
It reports plug-in empirical I(X;Y) and nondominated measured points in byte
cost, latency cost and empirical leakage. It does not optimize all defenses or
claim statistical significance for dominance or identify unmeasured attackers.
Retaining original captures and checking declared hashes against their contents
remain the collector's responsibility.

Run `aegis-measure privacy-frontier --input-json /absolute/measurements.json
--output-json /absolute/new-report.json`. The output must be new; an existing
file or output symlink is refused, preserving previous attempts. Input is a
regular JSON file limited to16MiB. Declare `alphabet` with integer `labels` and
`features`, `assume_iid_fixed_alphabet`, `delta`, and `policies`. Each policy has
a unique `name` and `samples`; each sample contains integer `label`, `feature`,
`added_bytes`, and finite nonnegative `added_delay_ms`. At most64 policies and
one million combined samples are accepted. Declare bins before evaluation and
derive samples from retained captures rather than illustrative importance values.

Optional shared `provenance` and per-policy `provenance` must be supplied together
for every policy. Unknown fields are rejected. The shared object contains:

| Field | Contract |
| --- | --- |
| `schema_version` | Integer `1` |
| `frozen_bins_sha256` | SHA-256 of the retained training-frozen bin definition |
| `bins_frozen_unix_ms` | Positive declared freeze timestamp |
| `training_units` | 1 to 100,000 unit records, completed by the freeze |

Each policy's object contains `source_sha256` (the SHA-256 of its retained source
manifest) and `sample_units`. Each sample has exactly one unit record at the same
array position. A unit requires `session_id`, `trial_id`, `network_id`,
`time_holdout_id`, `capture_sha256`, `capture_started_unix_ms` and
`capture_finished_unix_ms`. Identifiers contain 1 to 64 ASCII letters, digits,
underscores or hyphens; use nonsecret study identifiers. Hashes contain exactly
64 lowercase hexadecimal characters. Capture intervals have a positive start
and an end no earlier than the start. The CLI's 16 MiB input limit still applies.
The interval describes the complete retained capture. Every occurrence of its
SHA-256 must declare the same interval and network ID.

Within each policy, `(trial_id, network_id, time_holdout_id)` identifies one
evaluation sample and must be unique. Every policy must contain exactly the
same keys with the same labels, although its actual sessions, capture hashes,
times and source manifest may differ. Row order may differ when samples and
metadata are reordered together. Evaluation captures must start after the
declared freeze. No evaluation session, trial, capture hash or time-holdout ID
may reuse one from training. Duplicate training keys are also refused.
Policy sessions and capture hashes must be distinct from those of every other
policy. Several trial samples within one policy may share a session or capture;
that grouping does not establish independence. Reusing one capture for offline
policy transformations requires a different measurement model and is not
accepted by this paired-capture schema.

Successful validation emits `declared_paired_units_consistent`, per-policy
manifest hashes and a canonical paired-population hash. This checks declared
consistency and chronology; it does not read the captures or bin definitions,
prove their hashes, check clocks, prove independent samples or confirm a target
network. The output keeps these limitations explicit. Keep capture manifests
with the report so another reviewer can verify the declared binding.

Optional `qos` contains `max_added_bytes` and `max_added_delay_ms`.
`select_measured_policy` selects minimum empirical leakage among feasible
nondominated measured policies, preferring lower byte/delay cost on ties.
No feasible point returns no selection. This is a callable measured-policy
optimization; it does not synthesize or certify an unmeasured defense or
automatically adopt a policy. Legacy selections retain unverified provenance.

Independent samples and bins fixed before evaluation must be explicitly assumed
to emit a conservative per-policy confidence interval. A Hoeffding union bound
over K joint cells gives TV<=min(1,K*sqrt(log(2K/delta)/(2n))/2); marginal TV does
not increase, and finite-alphabet entropy continuity bounds the three entropy
errors in mutual information. Small samples can yield the entire possible
range. Intervals across multiple policies are not simultaneous. Dependent flows,
adaptive/data-trained bins or selectively collected samples invalidate the iid
interpretation; otherwise only the empirical point is emitted.

[Liu et al., July2026](https://arxiv.org/abs/2607.17889) defines a side-channel
rate-distortion frontier within stationary memoryless defenses and Wasserstein1
cost. This tool does not verify those assumptions, use that cost or compute that
theoretical frontier. Its output explicitly sets formal DP accounting and a
theoretical rate-distortion bound to false.

### Binary feature-hypothesis diagnostics

The same `privacy-frontier` command also consumes validated declared frozen-bin,
training-separated, paired evaluation input for labels 0 and 1 as H0 and H1.
Its `binary_hypothesis_diagnostics` field reports the plug-in total variation
`0.5 * sum(abs(p0 - p1))` and directional KL `sum(p0 * ln(p0 / p1))` in nats,
normalizing each hypothesis separately. This is a reusable Rust core operation
over the observed fixed feature histogram, with at most 256 bins and 1,000,000
samples; it does not measure ordered sequences or evaluate a fitted classifier.

Legacy input returns `unknown_unverified_provenance`; a nonbinary alphabet
returns `unknown_nonbinary_label_alphabet`. Fewer than two observations in either
hypothesis leaves all distances unknown. That minimum is only a refusal floor,
not a power or confidence criterion. If a numerator bin was observed but the
reference bin was absent, that direction's KL is null with
`unknown_zero_observed_reference_support`. No pseudocounts or smoothing are
added. A jointly unobserved bin contributes nothing; none of these zero counts
establish zero population probability. TV can remain an empirical value while
either KL direction is unknown. Unequal sample sizes do not become class priors.

The [Bash, Goeckel and Towsley paper](https://arxiv.org/pdf/1202.6423), Section III,
uses TV and relative entropy to analyze a specified physical channel. This tool
uses only their discrete finite-bin counterparts. It does not verify AWGN,
independent channel uses, or transfer the paper's square-root law to IP traffic.
No population distance, detection-error bound, IID/product extrapolation,
whole-flow privacy guarantee or policy adoption follows. Existing provenance
checks validate declarations; capture contents, feature extraction and bin hashes
remain unverified. Existing MI/QoS selection behavior is unchanged.

### Private packet-export study assembly

`aegis-measure privacy-study-assemble --input-json /absolute/study.json
--output-json /absolute/new-study-report.json` reads private retained packet-field
exports and actual frozen scalar bins, creates one finite feature per trial, and
calls the existing paired provenance/frontier/MI/TV-KL consumers. It does not run
tshark, fit bins/classifiers, capture traffic or apply a policy. One private
create-new output contains `assembled_input`, `frontier_report`, hash bindings
and per-trial byte/row counts. Input/output paths must be absolute; all inputs
use trusted ancestry plus descriptor-checked private file custody. Errors and
outputs do not contain raw endpoints, paths or packet rows.

The strict manifest has `schema_version:1`, `source_kind` (`synthetic_fixture`
or `declared_retained_export`), `bins`, `training_units` and `policies`.
A file reference is exactly `{path, sha256}`; hashes bind actual retained bytes,
including whitespace. Training and sample `unit` records use the provenance
schema above. Existing pairing, chronology, training separation and consistent
full-capture declarations apply unchanged. These are still declarations.

| Object | Required fields |
| --- | --- |
| Policy | `name`, `costs` file reference, `exports`, `trials` |
| Export | `id`, `file` reference, `capture_sha256`, `network_id`, `capture_started_unix_ms`, `capture_finished_unix_ms` |
| Trial | `unit`, binary `label`, `export_id`, `flow`, `window_started_unix_us`, `window_finished_unix_us` |
| Flow | `protocol` (`tcp`/`udp`), `client`, `peer`; endpoints each contain `ip` and nonzero `port` |

Both directions match the explicit bidirectional tuple, never guessed port443.
Endpoints must differ and have the same IP version. Trial windows are half-open
`[start,end)` inside the declared full capture interval. Overlapping windows for
one tuple/export are refused. One capture has one export per policy, so aliases
cannot evade window overlap admission. Every trial must select rows; unmatched
rows are counted. Equal timestamps retain capture order. No packet is treated
as an independent trial or proof of delivery.

The version1 UTF-8 TSV has exactly this header, with `\t` denoting one literal tab:

```text
timestamp_unix_us\tframe_length_bytes\tcaptured_length_bytes\tsrc_ip\tdst_ip\tprotocol\tsrc_port\tdst_port
```

Rows have eight fields in that order. Time/length/port fields are unsigned
integers. Timestamps are nondecreasing and inside the full interval. Frame
length is1..65535 and captured length must equal frame length. IP addresses
parse as IPv4/IPv6 and protocol is exactly `tcp`/`udp`. Malformed, blank,
extra/missing, unsupported or oversized rows and declared truncated frames
refuse the entire assembly; they are not skipped. This is a fixed retained
export format, not arbitrary tshark stdout or direct PCAP/PCAPNG ingestion.

The bins file contains exactly `schema_version:1`,
`statistic:"selected_captured_wire_frame_bytes"`, `units:"bytes"`, positive
`frozen_unix_ms`, `training_units_sha256`, `upper_exclusive_edges`. The feature
is the checked sum of selected declared frame lengths including ACK/control
frames. Edges are1..255 increasing positive integers, with a final overflow bin;
an edge goes into the bin above it. For150/250, bins are `[0,150)`, `[150,250)`,
`[250,+infinity)`. No evaluation fitting occurs. `training_units_sha256` binds
compact JSON serialization of the supplied unit array in this field order:
`session_id`, `trial_id`, `network_id`, `time_holdout_id`, `capture_sha256`,
`capture_started_unix_ms`, `capture_finished_unix_ms`. It does not prove training
capture content or a trusted freeze clock.

Cost files have exactly `schema_version:1` and `rows`. Each row has `trial_id`,
`network_id`, `time_holdout_id`, explicit `added_bytes` and finite nonnegative
`added_delay_ms` <=3600000. Costs match every trial key once. Missing/null costs
refuse assembly; an explicit supplied zero is allowed, but unknowns are never
filled with zero. Duration, RTT and interarrival gaps never become added delay.
A matched cost file hash does not establish correct wire measurement.

Bounds:1MiB manifest;64KiB each bins/cost sidecar;4MiB per export;64MiB combined
exports;262144 combined rows;1..16 policies;1024 combined policy trial records;
1..1024 training units. Sidecar byte bounds may impose a smaller practical
count. The output attests exact bins/export/cost content hashes and deterministic
assignment. Capture/export correspondence, training/cost origins, trusted time,
independence, delivery, target-network acceptance and whole-flow guarantees
remain false/unverified. IID confidence is not enabled. Existing scorers and the
legacy frontier command retain their semantics. This is not a complete
independent physical-capture pipeline.

## Private classic-PCAP trial export

`aegis-measure privacy-pcap-export --input-pcap /absolute/trial.pcap
--output-tsv /absolute/new-trial.tsv` creates the exact version1 TSV accepted
by `privacy-study-assemble`. The PCAP and output must have trusted private
ancestry; the reader checks the opened descriptor, and output creation refuses
existing files or symlinks. A bounded JSON summary on stdout contains hashes,
counts and first/last observed packet timestamps, never paths, endpoints or
payload. The TSV itself contains numeric endpoints and must remain private.
Errors before output creation leave no TSV; a write/sync/stdout failure may
leave an owned partial or complete output, which is preserved, never replaced.

This command requires a separately declared TCP/UDP trial capture filter.
Every retained record must be in its supported subset: classic PCAP2.4,
little/big endian, Ethernet LINKTYPE 1 or raw IP LINKTYPE 101, IPv4/IPv6 TCP/UDP.
Ethernet supports at most two 802.1Q/802.1ad VLAN tags. ARP, IPv6 neighbor
discovery, other protocols/link types, all IPv4 fragments (including the first
MF fragment), IPv6 extension/fragment headers and jumbograms refuse the whole
input. Records are not silently skipped. This is not a full leak-audit capture
decoder; no global traffic coverage follows from its supported trial subset.

The global header, positive snapshot length, complete record headers/data and
matching original/captured record lengths are checked. Frames are 1..65535
bytes and cannot exceed the declared snapshot length. Additional link/FCS flags
are unsupported. Reserved timezone/accuracy fields are ignored rather than
interpreted as trusted clocks. TCP/UDP/IP declared header lengths and nonzero
distinct endpoints are checked. Raw IP rejects unexplained trailing bytes;
Ethernet padding stays in the original captured-record frame length.
Checksums/offload, physical wire overhead, packet delivery and sender identity
are not verified.

Microsecond PCAP timestamps remain exact integer Unix microseconds. Nanosecond
timestamps are admitted only when exactly divisible by 1000; finer precision
refuses instead of being rounded. Timestamp fractions must be in range;
record order must be nondecreasing, with equal times retained in file order.
First/last observed packets do not establish the complete capture interval.
The assembler still needs the separately declared full interval and held-out
trial metadata, frozen training bins and explicit cost records.

Bounds are 64 MiB retained input, 4 MiB TSV and 262144 records. Conversion borrows
one private input buffer, uses one fixed TSV buffer and a 256-byte stack row;
it does not allocate copies of all packet payloads or invoke tshark. These
logical byte bounds are not an exact allocator/container heap quota. The
summary binds the actual PCAP and TSV bytes by SHA256. That establishes this
retained conversion, not physical capture origin, a trusted clock, independence,
delivery or target-network acceptance. Existing witness/lenient summary
decoders, feature bins and wire-frame statistic semantics remain unchanged.

Format references: the [IETF classic PCAP draft09](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcap-09)
is work in progress; [official libpcap link constants](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap-common.c)
define the chosen link subset. IP/TCP/UDP header fields follow
[RFC791](https://www.rfc-editor.org/rfc/rfc791.html),
[RFC8200](https://www.rfc-editor.org/rfc/rfc8200.html),
[RFC9293](https://www.rfc-editor.org/rfc/rfc9293.html) and
[RFC768](https://www.rfc-editor.org/rfc/rfc768.html).

## Recent Brain selection

`Brain::with_recent_routes` opts into bounded recent selection in the native
client's direct and relay planners. Without `[direct.recent_routes]`, the existing
selector remains unchanged. `select_order_trace` returns the actual recent order
and a separate `recent_selection` trace; baseline candidate evidence remains
explicitly identified as baseline evidence. A configured recent selector bypasses
the relay's legacy eight-trial gate and never appends omitted routes afterward.

For example, a private client configuration can contain:

```toml
[direct.recent_routes]
window_ms = 60000
max_observations = 256
diversity_penalty = 0.25

[direct.recent_routes.failure_domains]
# Keys must be actual configured preferred strategy names.
# Distinct labels alone are not evidence of independent reachable providers.
```

Actual runtime outcomes feed the bounded RAM history. Positive recent reward
requires a success signal and observed outgoing byte progress; it is not an
independent application-delivery receipt. `Brain::select_recent_order` also
remains an explicit alternate API. It begins with
existing Brain order and rechecks preferred membership and current hard-block
belief. The caller supplies only routes already admitted by runtime policy,
trust and reachability gates. Unknown, duplicate and hard-blocked routes cannot
be promoted; an empty admitted set stays empty. It does not probe or invent
fallbacks. Invalid admission yields an empty order, without replay or fallback.

`RecentRouteSelector` stores at most4096 RAM-only observations for at most1h.
Context keys isolate targets; rewards must be finite in[0,1]. The recent mean
plus sqrt(2*log(1+recent_trials)/route_trials) ranks observed candidates.
Admitted routes with no surviving observations enter an explicit exploration
phase before observed routes; their bounded existing prior ranks them within
that phase and their UCB bonus is zero. A configured penalty discourages
repeated failure-domain labels in the resulting order. Missing labels share
one unknown domain; different labels alone do not prove independent failure.
Expired evidence is removed and history is not persisted as an activity trail.

[Garivier and Moulines](https://arxiv.org/abs/0805.3415) analyze discounted and
windowed UCB under specified nonstationary reward models. The bounded wall-clock
window, existing priors and diversity penalty here are a runtime heuristic;
their regret theorem is not asserted for censored/correlated network outcomes.

### Private retained Brain outcome replay

`aegis-measure brain-outcome-replay` imports a private native JSONL event file
into the existing Rust `RecentRouteSelector`; it does not apply a route policy
or collect new traffic. It accepts serial `direct_planner_order_selected` and
`direct_session_succeeded` pairs for the same literal target/port. Every admitted
decision needs its unique terminal outcome. Missing, overlapping, orphaned,
retried and unattributable failover attempts are refused. Other event types are
ignored, so the supported tape is not complete runtime failure coverage.

The native logged `planner_ranked_candidates` supply bounded priors and explicit
hard-block flags. `planner_resolved_order` supplies the declared admitted subset;
omitted or hard-blocked strategies are filtered before cold exploration. These
are recorded declarations, not proof of current runtime admission. Replay starts
with empty history; pre-file native RAM history is unknown. Each logged terminal
feeds both candidate rankings even when the alternate ranking would choose a
different arm. This is teacher forcing, not a counterfactual policy rollout.

```sh
cargo run --locked -p aegis-measure -- brain-outcome-replay \
  --input-jsonl /private/analysis/retained-events.jsonl \
  --provenance-json /private/analysis/provenance.json \
  --output-json /private/analysis/replay-attempt-1.json
```

Both input files require descriptor-checked private custody and trusted ancestry.
The output is a new private file; an existing result is never overwritten. Input
is bounded to4MiB,4096 JSONL rows,64KiB per row,16 candidates per decision and64
contexts; the full retained file interval is at most7days. History remains within
the native1h/4096-observation limits. Errors never echo source rows or paths.
Raw endpoints are replaced by a scoped SHA256 context identifier; a hash is not
anonymization. Replay results retain timing and strategy metadata and must remain
private. No forensic/event logging setting is changed or bypassed.
Default private diagnostics omit the required detailed fields and are refused;
the importer cannot reconstruct them or re-enable an absent event sink.

The separate provenance JSON has strict fields: `schema_version`1,
`source_sha256` (lowercase SHA256 of the exact whole retained file),
`source_started_unix_ms` and `source_finished_unix_ms` (the first and last native
row timestamps), `source_kind` (`retained_native_runtime` or `synthetic_fixture`),
optional `source_commit` (a declared lowercase40hex commit or null), `window_ms`,
`failure_cooldown_ms` and `max_observations`. The hash and complete file interval
are checked. Origin, commit, clock accuracy and installed configuration remain
declarations; neither a sidecar nor a content hash proves them independently.

Positive reward matches native Brain's reported success signal plus outgoing
byte progress. It does not establish application delivery or independent capture
confidence. Logged latency/outgoing-byte sums remain reported measurements, not
alternate-policy cost. Policy recovery, cost and regret are always `null` because
untried alternative outcomes are unavailable. The reusable core also supports an
explicit fixed failure-cooldown overlay for attributable synthetic/offline units;
it is not the installed hybrid cooldown policy. The supported native success tape
contains no attributable failures, so its cooldown effect and observed recovery
remain unknown. No bandit regret theorem or policy advantage is claimed.

## Installed-client compositional admission

An optional `[privacy_plan]` is an admission contract, not an activation switch.
The ordinary config loader checks it immediately after parsing and before
private bridge/device identity reads; public full-wide bundle validation and the
Mac parent/worker public-profile parser apply the same pure check before native
policy or identity work. Absence preserves existing profiles and wire formats.
An existing authenticated relay framing profile is still validated before key
reads even when no explicit plan is supplied.

`diagnostics` may declare `leakage_analysis`, `measured_frontier`,
`network_calculus`, `binary_schedule_accountant`, `minimum_entropy_coupling`,
`nonstationary_bandit` and `fleet_failure_domains`. These declarations compose;
they do not execute an analysis, collect data, alter Brain selection or create
any network guarantee. Use the actual measurement/Brain APIs separately.
Duplicate/unknown diagnostics and unknown schema fields refuse.

The actual `relay.authenticated_shaping` profile determines exactly one owner:

| `packet_modifiers` owner | Additional shaping field | Contract |
| --- | --- | --- |
| `constant_cadence` | No alternate owner | Bounded FIFO fixed framing; optional `arrival_envelope` enforces actual input admission |
| `poisson_schedule` | `poisson_pacing` | Bounded exponential proposals within a public receive/service envelope |
| `net_shaper_epoch` | `net_shaper` | Fixed public discrete-Gaussian queue epoch and exact reference accounting |
| `bit_traps_service` | `bit_traps` | Fixed public independent weighted service epoch with FIFO and padding |
| `adaptive_channel` | `adaptive_channel` | Causal label-blind length-bin channel training and sampling |
| `cover_stream` | `cover_stream` | General iMEC bidirectional authenticated records with fresh per-record material |

A `privacy_plan.framing_budget` declares `max_payload_bytes`, `max_buffer_bytes`,
`max_wire_bytes_per_direction`, `max_session_ms`, and `max_queue_delay_ms`.
The complete actual profile must fit all five ceilings and its module-specific
work/cadence/queue constraints. The serialized profile also must fit the typed
control envelope; epochs reserve their horizon plus final I/O inside the original
session. Invalid combinations and unattainable spans refuse before identity
loading. A plan describes an actual configured owner; it cannot activate a
missing mechanism. Missing/unused budgets, unknown/duplicate owners and nested
schedules refuse without precedence or fallback.

For exponential pacing, `cadence_ms` equals the ceiling of `max_gap_us/1000`.
The full public queue/receive allowance is validated even for shorter proposals.
The fixed epoch modes require actual source EOF and a drained queue at the public
end; they are not transparent arbitrary TCP half-close replacements. All modes
retain finite entropy/work/I/O/wire limits, original clocks, cancellation and
terminal errors. None can clamp, retry or fall back into another schedule on
failure. Arrival-envelope admission is currently supported only with constant
cadence; its service diagnostics are conditional, not measured Internet bounds.

Relay/H2 agrees the complete typed profile inside device TLS before Open/PolicyAck.
Keyed epochs and general cover use fresh contributions from both authenticated
peers and full-profile/direction derivation. Training and agreement consume the
original establishment/session budgets. A final monotonic observation refuses a
late synchronous completion and drops its owned worker. Live device revocation
continues to cancel the server exchange.

Opaque web/WebRTC commands have no typed profile hello. Their existing constant
and exponential framing requires complete operator agreement out of band; new
keyed/adaptive modes refuse there. Legacy `randomized_schedule` and `mec_control`
remain unsupported installed owners: their separate one-shot binary/control
operators keep their original contracts. `cover_stream` is the explicit newly
implemented bidirectional owner, with its own caps and key domains.

See the [eleven-work composition matrix](../research/implementation-and-composition.md)
and the module contracts for [NetShaper](../research/netshaper-integer-runtime.md),
[BIT-TRAPS](../research/bittraps-independent-service-stream.md),
[causal optimization](../research/adaptive-channel-runtime.md),
[general cover](../research/cover-stream-runtime.md), and
[arrival admission](../research/network-calculus-guard.md). Populate profiles from
an authorized calibrated study; synthetic fixtures are not deployment policy.

`requested_guarantee = 'whole_flow_differential_privacy'` always refuses.
The binary accountant protects only its released binary transcript, and neither
fixed framing nor finite-cover messages establish whole-flow DP. An accepted
plan is source/runtime admission only, not an independent audit, installed
candidate acceptance, physical capture, or target-network evidence.
