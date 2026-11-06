# General finite cover coupling

`traffic_privacy::general_coupling` provides exact finite rational joint
distributions and a bounded multi-block iterative byte codec. It removes the
old deterministic equal-mass partition requirement: `[4,2,1]`, zero-probability
states and different message/cover alphabet sizes are supported.

The algorithm follows the iterative encoder/decoder structure in
[Schroeder de Witt et al., ICLR 2023, Algorithms 1 and 2](https://arxiv.org/html/2210.14889v4).
Both sides initialize independent uniform message blocks, select a block,
construct a coupling to the next cover distribution and update the selected
block's posterior. Encoding samples the cover conditioned on the actual
message; decoding reconstructs the same posterior. The greedy coupling
subroutine allocates the smaller of the two largest residual marginal masses,
as in [Kocaoglu et al., Algorithm 1](https://arxiv.org/abs/1701.08254).
It is an approximation to the NP-hard minimum-entropy problem, not a global
optimizer. Exact row/column sums are separate from entropy optimality.
The authors' [maintained implementation](https://github.com/ssokota/mec) also
distinguishes greedy approximation from iterative coupling.

## Integer certificates and limits

Probabilities are canonical integer weights divided by their sum. Explicit
zero states retain their original index; all-zero models refuse. GCD reduction
precedes bounds. An exact checked common denominator is used for joint masses;
every construction recomputes all row and column sums. There is no probability
rounding, epsilon tolerance or truncation of small nonzero states.

Models have at most 256 states and normalized total mass at most `2^80`.
The common denominator must also satisfy that bound. Arithmetic overflow or
an unsupported denominator refuses. Sparse greedy support has at most
`message_states + cover_states - 1` cells. Allocation uses two deterministic
priority queues; equal masses use the smaller original index.

Multi-block selection uses a deterministic integer Q32 Shannon-entropy
estimate with first-index tie breaking. The logarithm extracts 32 fractional
binary bits by bounded Q63 squaring. This approximates the paper's entropy
argmax; no exact transcendental ordering or published approximation ratio is
claimed. Selection precision affects throughput, while integer coupling
certificates remain exact. Encoder and decoder must agree on this algorithm
version and the same conditional cover model.

The public horizon is 1–4096 symbols, with 1–274 byte blocks. The byte codec
uses 256 equiprobable initial states per block. Its default constructor uses a
memoryless cover model; `new_conditional` accepts an agreed finite-state model
of the public token prefix. `ConditionalCoverSettings` holds `initial_state`,
`state_weights[state][symbol]` and `next_states[state][symbol]`. Both sides reset
to the initial state for each fixed record, select the current row, perform the
same coupling/posterior update and advance with the actual public token. This
implements a bounded prefix-conditional consumer of Algorithms 1 and 2, including
finite Markov token laws. It does not infer an arbitrary prefix model or implement
an LLM, speech model, browser camouflage or arbitrary application carrier.

Conditional models have 1–16 states and one agreed alphabet of 1–256 tokens.
Every row and transition is validated, including unreachable rows and transitions
for zero-mass symbols. All-zero rows, mismatched dimensions, missing/out-of-range
states and unsupported rational constructions refuse before record I/O. Receiving
a zero-mass or out-of-alphabet token refuses. Posterior denominator limits remain
in force on every step; admission does not guarantee later arithmetic or resolution.
The real `cover_stream` caller selects this codec when `conditional_model` is
present and binds all rows, transitions, initial state, tokens, horizon, capacity
and I/O timeout in a separate algorithm-domain descriptor. Its typed authenticated
profile also binds the other stream budgets. Existing memoryless constructors retain
their current descriptor and behavior.

## Decoding, material and integration

`GeneralCoverByteCodec::encode` takes already masked bytes and returns the
whole public horizon. It does not shorten a record once blocks resolve.
`decode` accepts exactly that horizon and returns bytes only when every
posterior is an exact point mass. Insufficient information, invalid states,
zero-mass symbols and arithmetic failures refuse; no MAP guess is returned.
Even a valid distribution can provide no useful information, so no finite
horizon guarantees universal delivery.

For a one-shot control record the input must mask **all** ciphertext bytes,
including length, padding and authentication tag. The existing authenticated
control layer owns AEAD, fixed framing and fresh per-direction material.
Its TLS exporter is a computational pseudorandom source, not an ideal
uniform one-time pad. This module owns no sockets, identities, key generation,
exporter calls or replay registry. A caller must consume fresh material on
every attempt, including failure, and bind mode, all conditional tables and initial state when present, weights, tokens,
public horizon, capacity and algorithm version in its authenticated descriptor.

Uniform conditional draws use fallible cryptographic entropy and unbiased
128-bit rejection sampling with at most 128 attempts. Exhaustion refuses;
there is no modulo fallback. Although admitted mass makes a single rejection
probability less than `2^-48`, bounded entropy and arithmetic refusals can
depend on the current posterior. Therefore an ideal exact token-marginal
certificate is not an unconditional perfect-security theorem for the
implemented failure-visible protocol. Never regenerate until successful
decoding or emit only successfully resolved records: that conditions the
observed distribution on success and can bias it.

Endpoint visibility, TLS fingerprints, elapsed time, record counts, packet
sizes, processing-time variation, public model choice and fail/close behavior
are outside the token-distribution certificate. Actual control integration,
platform/network acceptance and beta-exit evidence are separate work.
