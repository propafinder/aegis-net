# Causal iMEC stream inside authenticated TLS

This opt-in Rust adapter carries arbitrary application bytes using the general
ICLR 2023 iterative minimum-entropy-coupling codec. The negotiated token alphabet
and integer weights may be nonuniform, including `[4, 2, 1]`. Every record has the
same public horizon and token width. A DATA/END discriminator, payload length,
payload, zero padding and AEAD tag are inside the masked fixed record. No clear
length or END header is added. DATA records carry at least one application byte;
END carries none. The receiver decodes and verifies the entire record before
writing any bytes of that record to the application. Ordinals are implicit FIFO
positions and enter derivation; replay or reordered records fail authentication.

`CoverStreamSettings::validate` and `descriptor` bind the alphabet, cover
weights, optional complete conditional model, payload capacity, horizon, record
allowance and all finite memory,
wire and I/O/session limits. Capacity includes one discriminator byte. Admission
requires enough wire allowance for the complete public maximum-record allowance;
the record allowance includes END. Exhaustion before END is failure, not clean EOF.
Partial failure is never retried with the same material. Each direction owns one
non-Clone zeroizing seed and derives a fresh key, nonce and full-record pad using
HKDF-SHA256 domain separation by settings descriptor, direction and ordinal.
Secrets are not logged, serialized or persisted. The session seed must originate
from the caller's fresh authorized TLS contribution and matching typed agreement.
The generic adapter cannot establish or prove that provenance itself.

The typed relay client/server records one lifetime origin before profile
validation and agreement. The smaller outer-profile or nested cover lifetime
caps the complete agreement, including fresh contribution exchange; the caller's
establishment deadline can shorten admission further. Installation inherits that
original session end for both memoryless and conditional modes. A delayed
agreement cannot renew the shorter cover lifetime.

The adapter owns one task for both directions, aborts that task on Drop, preserves
sticky failure and supports bidirectional half-close after authenticated END.
Every I/O uses a bound capped by the caller's original absolute session deadline;
after-return monotonic checks refuse late success. Decoder/encoder CPU work is
finite under the admitted construction domain, but synchronous codec computation
is not forcibly preempted by Tokio. Local flush is buffered acceptance, not remote
receipt. Partial application deliveries from earlier verified records are not
rolled back on a later failure. Idle waiting, EOF timing, stalls and record count
remain observable. A finite horizon can fail to resolve the posterior; the adapter
refuses instead of adding secret-dependent extra symbols or retrying to success.

The ideal iMEC distribution result requires uniformly masked independent message
blocks and unbiased per-symbol choices. HKDF-derived pads provide computational
PRF pseudorandomness, not information-theoretic one-time-pad secrecy. Fixed-horizon
failure and conditioning on successful decoding qualify that ideal output law.
These are inner cover tokens; authenticated TLS ciphertext, TCP segmentation,
lengths, time, endpoints and termination do not inherit a perfect cover law. This
implementation does not claim whole-flow indistinguishability, universal DPI
bypass, independent captures or installed-client acceptance.

Primary codec reference: Schroeder de Witt et al., *Perfectly Secure Steganography
Using Minimum Entropy Coupling*, ICLR 2023,
https://arxiv.org/abs/2210.14889 . The paired token and posterior construction is
implemented in `general_coupling`; this adapter adds bounded streaming custody
and per-record computational material, not a new optimal-coupling theorem.

## Agreed finite prefix model

Omitting `conditional_model` keeps the memoryless mode and omits the new field
from serialized profiles. Explicit `null` and unknown model fields refuse.
A conditional profile contains the complete finite model, never a name requiring
external model discovery:

```json
"weights": [2, 1, 1],
"conditional_model": {
  "initial_state": 0,
  "state_weights": [[2, 1, 1], [1, 2, 1]],
  "next_states": [[0, 1, 0], [0, 1, 0]]
}
```

This fragment supplements the required ordinary tokens and stream budgets.
The two rows share the token alphabet; after token index 1 the next cover PMF
is the second row, and after index 0 or 2 it is the first row. Encoding and
receiving evolve the state from the same public prefix. Each record resets to
`initial_state`, including END; no hidden cross-record state is negotiated.
`weights` must exactly match the declared initial row. All 1–16 rows and their
transitions are admitted together; the existing enclosing profile size limit can
refuse a large otherwise valid table. The separate conditional codec descriptor
hashes the entire model and the record I/O timeout, while the stream descriptor
enters per-ordinal material derivation and also binds all stream budgets. Peers with different
tables or clocks cannot authenticate the same record. Existing typed TLS shaping
agreement and authorized carrier attachment supply the actual production caller.

See [the finite coupling algorithm and refusal bounds](general-coupling.md).
A finite-state prefix law broadens the implemented token model; it supplies no
new guarantee for outer network timing, TLS ciphertext or observed failures.

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
