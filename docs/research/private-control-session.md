# One-shot private operator control exchange

This opt-in Rust operator connects the finite-cover MEC codecs and
binary schedule accountant to actual authorized TLS I/O and a paired decoder.
It is a separate endpoint operation. It does not enable an installed full-wide
traffic mode or replace ordinary relay `Open` / `PolicyAck`.

## Session and material custody

The operator loads independently supplied public profiles and existing device
TLS credentials through the existing protected-file and secure-channel loaders.
Both core entrypoints refuse any `authenticated_shaping` configuration before
handshake: this endpoint cannot stack constant-cadence or Poisson flow framing.
They own one carrier, create one fresh TLS 1.3 connection through the existing
constructors (no tickets/resumption, early data or key logging), and consume
exactly one control exchange. Server authorization uses `accept_with_lease`,
an owned concurrency permit and a revocation race over the complete post-auth
exchange. Registry watcher custody stays with the operator until completion.

The dynamic registry fixtures publish a paired server snapshot and generation
floor through the existing Unix durability boundary. They run on Unix hosts;
server registry publication deliberately refuses non-Unix hosts before creating
a registry or lock. This does not add Windows server publication support. Static
certificate admission, cover/schedule exchanges, cancellation and the three
static paired-process fixtures remain portable. The existing non-Unix registry
regression checks `Unsupported` and zero created entries; local Unix revocation
checks do not stand in for a Windows registry-backed server lifecycle.

A fixed 36-byte public admission contains magic, version, mode and the exact
public profile descriptor. Cover-record descriptors include the full operation
budget; their partition/memoryless domains are version 2, so both peers and
pinned experimental profiles must be updated together without fallback.
The server compares it to its independently built
profile and sends an authorization/profile ACK before any material derivation.
No peer-supplied sizes allocate a profile. Only then do the peers derive separate
key, nonce/prefix and (cover mode) whole-record pad using the normal TLS exporter,
nonempty version/profile/client-to-server/ordinal-0 context and distinct labels.
Material is Zeroizing and inaccessible outside private one-shot codec custody;
no tokens, key bytes, pads, exporter outputs or payload are printed or persisted.
Fresh connections are required for every attempt. There is no reconnect, retry,
resume, fallback or material-file reread path.

The independent cover sampling and binary randomized-response draws use OsRng,
not payload or exporter values. Existing AEAD codecs authenticate complete
records/batches. The receiver exposes no partial payload and sends a final ACK
only after full decoding. A client success means authenticated peer decoding;
it does not prove output persistence or downstream application delivery.

The total cooperative endpoint deadline is at most 60 seconds, including TCP
connect/accept in the CLI, TLS, admission, codec and ACK. The CLI passes the same
absolute cutoff to `send_once_until` / `receive_once_until`; waiting for TCP does
not start a second endpoint allowance. Duration wrappers count from their own
entry and preserve that cutoff through validation and TLS. Checks after
synchronous work and ready I/O reject late positive completion, including a
late authenticated final ACK. These checks cannot preempt synchronous work or
retract already emitted bytes. Expired admission drops the owned carrier before
TLS; the receiver restores its permit on every return/cancellation. Core plaintext control
wire, including admission and ACKs, is capped at 16 KiB. TLS records, handshake
bytes and OS buffers are not included in that plaintext cap. Cancellation or
partial errors consume the connection and material. Existing schedule send
failures retain their actual spending; a completed send followed by an ACK error
also retains completed spending. If an outer deadline or discarded future
cancels an in-progress operation, no receipt can be returned from that discarded
future: accounting is unavailable, not zero. No same-owner retry/budget reset
is offered. Distinct sessions are not covered by a cross-session composition
claim. Kernel timeouts and allocator forensic erasure are not claimed.

## Explicit operator

`aegis-measure private-control --config-json <private-config> --input-file <private-input>`
is the client; `--output-file <new-private-output>` is the server. Configuration
selects a numeric socket address, role-specific existing TLS settings, deadline
and one public profile. Schedule composition numerator and denominator are
canonical decimal strings (at most 39 digits), preserving exact u128 arithmetic. Credential paths resolve against the config directory.
Config and input must satisfy the existing owner/mode/symlink protections.
Output is an exclusive private file, with Unix mode 0600; an existing file is
refused, and failed partial writes are retained. No plaintext command argument,
stdout payload or secret-derived hash is used. Public readiness and terminal
receipt metadata are the only normal stdout output.

Cover mode input/output is a single raw bounded payload. Schedule mode is exactly
the public number of cells, each encoded as a big-endian u16 length followed by
that payload; length zero denotes a dummy. The server receives at most one
connection and exits, even on error. This command does not register devices,
provision credentials, deploy a listener or create a provider.

## Scientific limits and primary sources

* [TLS 1.3 RFC 8446, section 7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5)
  specifies normal exporter label/context derivation; early exporters are not used.
* [RFC 8446, appendix E.1.4](https://www.rfc-editor.org/rfc/rfc8446.html#appendix-E.1.4)
  explains exporter independence from traffic keys. Application authorization is
  still explicit; TLS client authentication alone is not an application admission ACK.
* Pinned rustls 0.23.45 `ConnectionCommon::export_keying_material` requires a
  completed handshake and owns its output buffer on error. No dangerous traffic
  secret extraction is used.
* [MEC consumer scope](finite-cover-control.md) and
  [binary schedule scope](binary-schedule-emission.md) remain unchanged.

TLS exporter material is computational pseudorandomness, not independently
uniform information-theoretic OTP material. This operator cannot inherit an
ideal MEC perfect-cover theorem. Cover symbols occur inside TLS; outer TLS
record sizes, packetization, endpoint, timing, cancellation and errors remain
observable. It does not camouflage externally visible traffic or establish
whole-flow DP, a Gaussian NetShaper implementation, exact Poisson timing,
commercial DPI resistance, all eleven papers, capture acceptance or beta exit.
Synthetic local TLS tests and paired subprocess checks are engineering evidence
only; no real device credentials, installed VM, fleet or target network are used.
