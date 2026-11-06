# Mimicry foundation: per-session GREASE sampler + legacy-1.2 audit

**Historical foundation note:** the body below records the 2026-05-16
rustls-era baseline and subsequent sampler/audit design. Its “today”, “LIVE
PASS” and blocked-injection wording belongs to that foundation stage; it is not
current backend or release acceptance. Current legacy builds with
`chrome-like-tls` use the optional AWS-LC Chrome-like ClientHello backend;
feature-less builds can degrade to Rustls. Device-enrolled inner TLS and required
real ECH use Rustls and do not inherit legacy Chrome JA4 acceptance. Consult
[transport profiles](protocols-and-transports.md) and the later scoped historical
observations: canonical TCP JA4, 2026-08-10 (`evidence-archive/live/2026-08-10/chrome-canonical-ja4-parity/result.json`)
and QUIC/MASQUE JA4, 2026-08-11 (`evidence-archive/live/2026-08-11/quic-masque-ja4-parity/result.json`).
The retained `evidence-archive/live/2026-07-04/chrome-like-tls-ja4-parity/` receipts use
an older custom/noncanonical JA4 dialect, superseded by those later observations
for canonical parity claims. Each later result retains its recorded build and
comparison scope. JA4 parity is scoped evidence, not byte identity, complete
browser equivalence or DPI proof.
No wire measurements were rerun for this documentation reconciliation.

## Preserved foundation-stage description

**Status:** Rust foundation landed; the actual ClientHello byte
injection is gated on a rustls upstream/fork stage that is
intentionally not in this batch.
**Closes (partially):** two of the four `NOT_ACHIEVED` markers from
the 2026-05-16 browser-class TLS pcap baseline — `no GREASE` and
`legacy TLS 1.2 extensions in TLS 1.3 hello`.
**Scope:** `aegis-fingerprint` crate. Reachable from `aegis-client`,
`aegis-server`, witness/calibration tooling. No effect on relay TLS
yet — see "Upstream gap" below.

## What this guide covers

1. Why GREASE and the legacy-1.2 extension drop are AEGIS-relevant.
2. The two new modules in `aegis-fingerprint`:
   * `grease` — per-session GREASE sampler (RFC 8701)
   * `legacy_tls12_audit` — strict scan of ClientHello bytes for
     legacy 1.2 extensions in a 1.3 hello
3. The architectural guardrails enforced by the design.
4. The rustls upstream gap that blocks the actual injection.
5. Where these modules ARE used today vs where they will plug in.

## Why GREASE matters to AEGIS

Real browsers (Chrome 138+, Firefox 138+, Safari 18+) inject random
GREASE entries into every ClientHello as required by RFC 8701. The
GREASE values are drawn from a fixed 16-value reserved set
(`0x0a0a, 0x1a1a, …, 0xfafa`) and are added independently to:

- `cipher_suites`
- the extension list
- `supported_groups` (extension 10)
- `signature_algorithms` (extension 13)
- `supported_versions` (extension 43)

Each entry is **resampled per session**, intentionally. A TLS stack
that emits no GREASE — like every default rustls 0.23 hello AEGIS
emits today — is trivially distinguishable from any modern browser.

This module is the audited, per-session, distribution-based GREASE
source. It does NOT inject yet (see "Upstream gap"). It exists today
because it's the right primitive to land separately from the
injection-site work.

## Why the legacy-1.2 extension drop matters

Real Chrome / Firefox / Safari TLS 1.3 hellos omit:

| extension type | name | reason TLS 1.3 omits it |
|---|---|---|
| `0x0005` | `status_request` | OCSP stapling negotiated differently in 1.3 |
| `0x000B` | `ec_point_formats` | only relevant for ECDHE in 1.2 |
| `0x0017` | `extended_master_secret` | implicit in 1.3 |
| `0x0023` | `session_ticket` | replaced by PSK resumption in 1.3 |

rustls 0.23 still emits some of these in 1.3 hellos. The
`browser-class-tls-pcap-baseline` artifact lists their presence as
one of the four NOT_ACHIEVED markers.

The `legacy_tls12_audit` module is the *measurement* side of the fix:
a strict scan that returns which legacy extensions are present in a
captured hello, plus a `is_legacy_regression()` verdict that fires
only when the hello negotiates TLS 1.3 AND emits at least one legacy
extension. It's used today by the adversarial DPI testbed to measure
the gap; it'll be used post-fix to assert the extensions have
actually been dropped.

## Architectural guardrails (enforced by the design)

The memory rules for AEGIS mimicry are non-negotiable:

> Profiles are probability DISTRIBUTIONS, not fixed fingerprints.
> Every session MUST sample a profile instance. Two sessions with the
> same profile id should NOT produce identical wire bytes.

The `grease` module is designed to make pinning structurally
impossible:

- `GreaseSession` has no `Default` impl. The only constructor is
  `sample(rng: &mut R)` which always draws fresh values from the RNG.
- `GreaseSession` is `Copy` so it can be passed by value into a
  ClientHello adapter, but the caller cannot stash a "canonical" one
  and reuse it: that would be a code-smell at the call site, not the
  module's responsibility.
- The unit test
  `distribution_covers_all_16_values_after_enough_samples` exercises
  10_000 draws and asserts every field's distribution covers the full
  RFC 8701 set. A future regression that biases the sampler toward a
  subset would fire this test.

The `legacy_tls12_audit` module is read-only by design. It does not
mutate, rewrite, or otherwise touch the hello bytes — exactly because
the AEGIS rule says we don't synthesize ClientHello bytes
out-of-band of the TLS stack. The drop side has to land in the TLS
library, not as a post-hoc rewriter.

## Upstream gap (intentional, documented)

The actual GREASE injection AND the legacy-1.2 extension drop both
require modifying the ClientHello bytes that rustls emits. **rustls
0.23 does not expose ClientHello byte-level customisation**. The
options are:

1. **uTLS-style port.** Replace rustls with a Rust crate that emits a
   Chrome/Firefox-shaped ClientHello byte-for-byte. Closest
   candidates: `boring` (BoringSSL bindings, distinct fingerprint), a
   maintained uTLS port, or a forked rustls with a custom extension
   emit order. Estimated 3–6 month engineering track (see
   historical active roadmap (archived: `docs/archive/pre-0.3.49/08-active-roadmap.md`) browser-class remediation roadmap).
2. **rustls fork.** Maintain a downstream branch of rustls that
   exposes a `ClientHelloAdapter` hook. Lower scope than option 1
   but pinned to the rustls upstream cadence.
3. **Byte-level post-process.** Catch the ClientHello on the wire
   and rewrite. Fragile — the TLS state machine would then be out of
   sync with rustls' internal state.

**This batch ships none of the three.** The sampler + audit are the
primitives that will plug into whichever option is chosen, audited
and unit-tested in advance so the actual wire-side change is a small
delta on top of a proven base. The honest status remains:

- ✅ GREASE sampler — distribution + per-session sampling LIVE PASS
- ✅ Legacy-1.2 extension audit — strict scan LIVE PASS
- ❌ ClientHello byte injection — blocked on TLS stack replacement
  (the 3-6 month research track)

## Where these modules are used today

| Caller | Module | Purpose |
|---|---|---|
| `aegis-fingerprint` consumers (witness, calibration) | `grease` | Sample expected GREASE values for adversarial-rig comparison fixtures |
| `aegis-fingerprint` consumers (witness, adversarial testbed) | `legacy_tls12_audit` | Measure the legacy-extension gap on captured AEGIS hellos vs reference browser hellos |

## Where these modules will plug in post-upstream-fix

| Future caller | Module | Purpose |
|---|---|---|
| AEGIS TLS adapter (uTLS port / rustls fork) | `grease::GreaseSession::sample` | Per-session GREASE injection at ClientHello construction time |
| AEGIS TLS adapter (post-fix) | `legacy_tls12_audit::audit_client_hello` | Self-test that the adapter is no longer emitting legacy extensions in 1.3 hellos |

## Cross-references

- `aegis-fingerprint/src/grease.rs` — sampler module (5/5 tests PASS)
- `aegis-fingerprint/src/legacy_tls12_audit.rs` — audit module (5/5 tests PASS)
- historical active roadmap (archived: `docs/archive/pre-0.3.49/08-active-roadmap.md`) § "Browser-class TLS mimicry — RESEARCH track"
- `evidence-archive/live/2026-05-16/browser-class-tls-pcap-baseline/result.json` —
  the 4-marker breakdown that motivated this batch
- Memory rules: `feedback_aegis_mimicry_implementation_rules.md`
