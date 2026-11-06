# One-shot finite-cover control consumer

This explicit Rust API in `aegis_core::traffic_privacy::cover_control` sends and
receives one bounded authenticated control record through an owned asynchronous
byte stream. It supports the exact deterministic equal-bin MEC codec and the
bounded general iterative codec described in [general coupling](general-coupling.md).
The fresh authenticated operator caller is documented in
[private control sessions](private-control-session.md). The installed typed
`cover_stream` owner uses the same record layer for bounded bidirectional records;
see [research composition](implementation-and-composition.md). These callers do
not implement a media/SFU service, web cover application, provider adapter or
discovery service.

Both peers must already agree on the exact model: ordered distinct equal-width
tokens, positive integer weights, an exact equal-mass partition, bits per symbol
(1, 2 or 4), fixed payload capacity (1–256 bytes), and the original operation
budget. The separate general constructor accepts arbitrary checked finite
weights and an agreed fixed decoding horizon instead of equal-mass bins. Its
bounded greedy coupling is approximate in entropy, with exact finite marginals;
unresolved posteriors refuse after the fixed horizon. Peers must independently
receive fresh dedicated per-record AEAD key, nonce and one-time pad over a
trusted authenticated provisioning channel. Those inputs never appear in the
cover stream. The pad must be uniform, independent of the key, message and cover
sampling, and never reused. The core API cannot prove those custody assumptions
or prevent recreation/reuse after a restart or from a backup.

The complete fixed-size record is a two-byte length and fixed-capacity payload
area, including zero padding, authenticated using existing ChaCha20-Poly1305.
Canonical SHA-256 of the model and actual partition is authenticated associated
data. XOR with the separate one-time pad masks **every ciphertext byte**, including
the authentication tag. Each resulting bit group is encoded by the existing
coupling with an independent unbiased cryptographic draw. Only fixed-width
cover tokens are written: no clear nonce, length, magic or model negotiation.

Under an ideal independent uniform pad, the entire masked record is uniformly
distributed regardless of the plaintext and tag. Under independent cover draws,
the exact integer coupling preserves the declared memoryless token marginal.
The finite integer marginal/XOR checks validate that conditional statement.
Real CSPRNG material provides computational pseudorandomness; it is not proof
of ideal information-theoretic randomness. Existing bounded sampling can refuse
when entropy is unavailable; successful sampling has the conditional marginal.
This exact equal-bin statement applies to the restricted partition constructor.
The general iterative path has its own posterior, arithmetic and observable
failure limitations described in the linked coupling contract. Neither path
establishes an unconditional perfect-security theorem for the deployed protocol.

Receive reads exactly the pre-agreed record size, decodes and unmasks, then
authenticates before returning any control content. Wrong model/key/pad,
cross-bin corruption, unknown tokens and truncation refuse. Alternate tokens
within a single bin decode to identical content and are deliberately accepted;
the MAC authenticates content/model, not the randomized token selection.
The receiver leaves later stream bytes untouched. A returned send byte count
means completed local write/flush, not remote authenticated delivery.

Material is non-Clone, has no Debug output and is consumed by send/receive,
including failures and cancellation. Secrets and plaintext intermediate buffers
use `Zeroizing`; no secret persistence, journal or retry is implemented.
The entire encoded record is prepared before emission, is at most 64 KiB,
and uses one original operation cutoff, up to 30 seconds, from entry to
`send`/`receive`. Encoding, entropy draws, allocation, write/flush, read,
decoding and authentication all consume that same budget. Encoding that finishes
late emits no prefix; a late-ready read never returns plaintext. A late write or
flush can have emitted actual bytes, which cannot be erased, and refuses without
retry. Cooperative timeout plus checks before emission and after synchronous or
ready completion reject expired success; they cannot preempt a synchronous stall.
These limits do not establish kernel preemption, a physical capture interval or
a whole-flow timing guarantee.

The record descriptors now bind the operation budget in nanoseconds. The
partition and memoryless-general descriptor domains are version 2; mismatched
old/new profiles refuse authenticated admission or record authentication, with no
fallback. Both peers and pinned experimental profiles must be updated together.
The descriptor change does not alter token widths, horizons or ordinary profiles
that omit cover coding.

Record size/count, token width, framing, timing, addresses, handshake and service
behavior remain observable. The public model must represent an actual agreed
cover service before any real camouflage claim. A locally measured TCP/duplex
consumer does not establish that distribution, target-network reachability,
independent capture, secrecy from an active censor, DPI efficacy or beta exit.
Neither operator nor installed cover owner activates by default. Their fresh
TLS/HKDF material is computational and does not establish ideal pad custody;
there is no persistent replay ledger in this record layer. A recorded message
cannot be reused with the consumed receiver object;
system-wide replay resistance requires fresh material and external custody.

## Primary sources checked

- Schroeder de Witt et al., [Perfectly Secure Steganography Using Minimum
  Entropy Coupling, v4](https://arxiv.org/html/2210.14889v4), ICLR 2023.
  Section 2.1 states the uniformly random ciphertext/one-time-pad premise;
  section 3 proves the coupling result relative to the declared distribution;
  section 4 discusses approximate/iMEC algorithms. The general codec follows that
  iterative structure in its declared finite model; broader deployment results
  are not inferred from that implementation.
- Sabzi et al., [NetShaper, USENIX Security
  2024](https://www.usenix.org/system/files/usenixsecurity24-sabzi.pdf), sections
  2.2–2.3 and 3–4. Its scheduled DP queue mechanism is distinct from this MEC
  control consumer and has its own installed typed epoch owner. It is not a
  protocol/application-identity hiding guarantee for Aegis.
- RustCrypto `chacha20poly1305` 0.10.1, exact pinned local primary crate source:
  existing `Aead`/`Payload` API and `ZeroizeOnDrop` key behavior. No cryptographic
  dependency or lockfile change is made. Online docs.rs access failed; no
  inference was drawn from that unavailable page.

Last engineering update: 10 October 2026, Europe/Madrid. The user's explicit
all-eleven completion condition is tracked in the research composition contract;
this record-layer change does not close installed/network release acceptance.
