//! Per-session GREASE value sampling (RFC 8701).
//!
//! AEGIS rule: profiles are **probability distributions, not fixed
//! fingerprints**. Every session MUST sample fresh GREASE values, and two
//! sessions with the same profile id MUST NOT produce identical wire
//! bytes. This module provides an offline sampler primitive; production
//! AWS-LC/BoringSSL backends implement their own GREASE behavior and do not
//! consume this sampler as a ClientHello adapter.
//!
//! Why GREASE matters for AEGIS:
//!
//! - Real browsers (Chrome 138+, Firefox 138+, Safari 18+) inject random
//!   GREASE entries into every ClientHello as required by RFC 8701. The
//!   GREASE values are drawn from a fixed 16-value reserved set
//!   (0x0A0A, 0x1A1A, ..., 0xFAFA) and are added to cipher_suites,
//!   extension list, supported_groups, supported_versions, and
//!   signature_algorithms — each independently sampled per session.
//! - A TLS stack that never emits GREASE is trivially distinguishable
//!   from any modern browser. The browser-class TLS pcap baseline
//!   measurement at `evidence-archive/live/2026-05-16/browser-class-tls-pcap-baseline/`
//!   identifies "no GREASE" as one of the four NOT_ACHIEVED markers.
//! - This crate cannot yet inject GREASE into the rustls 0.23 hello
//!   bytes — rustls does not expose ClientHello byte-level
//!   customisation. These helpers are not the live AWS-LC/BoringSSL GREASE
//!   implementation and their presence does not establish wire acceptance.
//!
//! Non-goals:
//!
//! - This is not a JA3 forger. The sampler produces fresh values per
//!   session; pinning the values across sessions would be a violation
//!   of both RFC 8701 and the AEGIS adaptive-mimicry guardrails.
//! - This is not a Chrome cloner. GREASE is one of several signals
//!   that distinguish rustls-family from browser-family; the others
//!   (legacy 1.2 extensions in 1.3 hellos, ECH, PQ key shares) need
//!   independent fixes.

use rand::Rng;
use serde::{Deserialize, Serialize};

/// RFC 8701 reserved GREASE values. Each byte of the 16-bit value
/// matches the low nibble of the high byte (`0xNa,Na` with `a = 0xa`),
/// so the values are deliberately spaced to look unallocated to any
/// non-GREASE-aware parser.
pub const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// Returns `true` iff `v` is one of the 16 RFC 8701 GREASE values.
pub fn is_grease_value(v: u16) -> bool {
    GREASE_VALUES.contains(&v)
}

/// Sample one GREASE value uniformly from the reserved set.
pub fn sample_grease<R: Rng + ?Sized>(rng: &mut R) -> u16 {
    GREASE_VALUES[rng.gen_range(0..GREASE_VALUES.len())]
}

/// The full set of per-session GREASE values a single ClientHello needs.
///
/// Browsers sample these five points independently. Per RFC 8701 the
/// sampler does **not** need to ensure they're all distinct from each
/// other — repetition across the five fields is allowed and indeed
/// observed in real browser captures. What it *must* do is resample
/// every session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GreaseSession {
    /// GREASE entry to insert at a random position in `cipher_suites`.
    pub cipher_suite: u16,
    /// GREASE entry to insert at a random position in the extension list.
    pub extension_type: u16,
    /// GREASE entry to insert in `supported_groups` (extension 10).
    pub named_group: u16,
    /// GREASE entry to insert in `signature_algorithms` (extension 13).
    pub signature_algorithm: u16,
    /// GREASE entry to insert in `supported_versions` (extension 43).
    pub supported_version: u16,
}

impl GreaseSession {
    /// Fresh sample for a single ClientHello. The only constructor —
    /// there is no `default()` because a fixed default would defeat the
    /// per-session resampling guarantee.
    pub fn sample<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self {
            cipher_suite: sample_grease(rng),
            extension_type: sample_grease(rng),
            named_group: sample_grease(rng),
            signature_algorithm: sample_grease(rng),
            supported_version: sample_grease(rng),
        }
    }

    /// `true` iff every field is a valid RFC 8701 GREASE value.
    pub fn is_well_formed(&self) -> bool {
        is_grease_value(self.cipher_suite)
            && is_grease_value(self.extension_type)
            && is_grease_value(self.named_group)
            && is_grease_value(self.signature_algorithm)
            && is_grease_value(self.supported_version)
    }

    /// Five-tuple view useful for tests and runtime-event emission.
    pub fn as_tuple(&self) -> (u16, u16, u16, u16, u16) {
        (
            self.cipher_suite,
            self.extension_type,
            self.named_group,
            self.signature_algorithm,
            self.supported_version,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn grease_value_set_matches_rfc_8701() {
        // RFC 8701 GREASE values are the 16 codepoints `0xNaNa` where the
        // nibble N walks 0..=15 — i.e. both high and low bytes are
        // `0xNa`. Derive and compare to the static table.
        let derived: Vec<u16> = (0u16..16)
            .map(|n| {
                // high byte = (N << 4) | 0xa, low byte = (N << 4) | 0xa,
                // so the full 16-bit value is ((Nh << 8) | Nl).
                let nb = ((n << 4) | 0x0a) as u8;
                u16::from_be_bytes([nb, nb])
            })
            .collect();
        assert_eq!(
            derived.as_slice(),
            GREASE_VALUES,
            "RFC 8701 derivation diverged from the static table"
        );
        assert_eq!(GREASE_VALUES.len(), 16);
    }

    #[test]
    fn sample_grease_always_in_reserved_set() {
        let mut rng = StdRng::seed_from_u64(0xAEC15);
        for _ in 0..10_000 {
            assert!(is_grease_value(sample_grease(&mut rng)));
        }
    }

    #[test]
    fn grease_session_is_always_well_formed() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..1_000 {
            assert!(GreaseSession::sample(&mut rng).is_well_formed());
        }
    }

    #[test]
    fn two_sessions_with_same_seed_can_match_but_unseeded_diverges() {
        // Same RNG state ⇒ identical sample. That's expected for a
        // pure-function sampler; the per-session resampling guarantee is
        // enforced upstream by always passing a fresh `rng.fork()` /
        // `thread_rng()` per session.
        let mut a = StdRng::seed_from_u64(99);
        let mut b = StdRng::seed_from_u64(99);
        assert_eq!(GreaseSession::sample(&mut a), GreaseSession::sample(&mut b));

        // Different seeds ⇒ different samples (with overwhelming
        // probability; 16^5 ≈ 1M combos so collisions of all five
        // fields are vanishingly unlikely on the first draw).
        let mut a = StdRng::seed_from_u64(1);
        let mut b = StdRng::seed_from_u64(2);
        assert_ne!(GreaseSession::sample(&mut a), GreaseSession::sample(&mut b));
    }

    #[test]
    fn distribution_covers_all_16_values_after_enough_samples() {
        // Statistical contract: 10_000 samples should cover the full
        // reserved set on every field with overwhelming probability.
        // (P(missing a particular value across 10k samples) = (15/16)^10000 < 1e-280.)
        let mut rng = StdRng::seed_from_u64(0xBADCAFE);
        let mut seen_cipher = std::collections::HashSet::new();
        let mut seen_ext = std::collections::HashSet::new();
        let mut seen_group = std::collections::HashSet::new();
        let mut seen_sigalg = std::collections::HashSet::new();
        let mut seen_version = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let s = GreaseSession::sample(&mut rng);
            seen_cipher.insert(s.cipher_suite);
            seen_ext.insert(s.extension_type);
            seen_group.insert(s.named_group);
            seen_sigalg.insert(s.signature_algorithm);
            seen_version.insert(s.supported_version);
        }
        for (label, seen) in [
            ("cipher_suite", &seen_cipher),
            ("extension_type", &seen_ext),
            ("named_group", &seen_group),
            ("signature_algorithm", &seen_sigalg),
            ("supported_version", &seen_version),
        ] {
            assert_eq!(
                seen.len(),
                GREASE_VALUES.len(),
                "{label} did not cover the full GREASE reserved set"
            );
        }
    }
}
