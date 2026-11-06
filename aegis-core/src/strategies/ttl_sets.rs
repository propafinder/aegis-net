//! Named TTL sets for raw-socket decoy packets.
//!
//! Before Track C / C4 the raw-socket strategies had hardcoded TTL literals
//! (`ttl: 5` / `ttl: 60`). Those two values were stable across every session,
//! every target, every client — a stable signature for behavioural DPI. The
//! two named sets in this module replace those single literals with small
//! variance bands so per-session TTL selection lands on a different plausible
//! value each time while still respecting the operational semantics:
//!
//! * [`LOW_DECOY_TTL_SET`] — TTLs chosen low enough to be dropped by the
//!   first / second middlebox but high enough to look like they came from a
//!   real host (not `ttl=1` which immediately screams "decoy").
//! * [`NORMAL_TTL_SET`] — TTLs that mimic common kernel defaults
//!   (Linux=64, Windows=128, macOS variants). Used by strategies that want
//!   the decoy packet to look like a legitimate OS stack.
//!
//! The selectors ([`pick_low_decoy_ttl`], [`pick_normal_ttl`]) are
//! deterministic given a seed: same seed → same TTL. That is intentional for
//! reproducibility in tests. A `Strategy::default()` that wants baseline
//! behaviour can call the selector with seed `0` and still get a real TTL from
//! the set instead of a hardcoded literal. Per-session variance comes from
//! the planner passing a session-specific seed.

/// TTLs for low-decoy packets. Values chosen to stay below kernel default
/// (64) and be dropped after 1-2 hops while not being as obviously synthetic
/// as `ttl=1`.
pub const LOW_DECOY_TTL_SET: &[u8] = &[3, 5, 7];

/// TTLs that mimic common kernel defaults. `60` (Solaris), `62` (historical
/// Linux subnet-adjacent), `64` (Linux modern default), `128` (Windows).
pub const NORMAL_TTL_SET: &[u8] = &[60, 62, 64, 128];

/// Pick a low-decoy TTL from [`LOW_DECOY_TTL_SET`] using a seed. Deterministic.
/// Uniform distribution over the set.
#[inline]
pub fn pick_low_decoy_ttl(seed: u64) -> u8 {
    LOW_DECOY_TTL_SET[(seed as usize) % LOW_DECOY_TTL_SET.len()]
}

/// Pick a normal-looking TTL from [`NORMAL_TTL_SET`] using a seed. Deterministic.
/// Uniform distribution over the set.
#[inline]
pub fn pick_normal_ttl(seed: u64) -> u8 {
    NORMAL_TTL_SET[(seed as usize) % NORMAL_TTL_SET.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_decoy_set_respects_bounds() {
        for &ttl in LOW_DECOY_TTL_SET {
            assert!(
                (1..16).contains(&ttl),
                "low-decoy TTL {ttl} out of expected band"
            );
        }
        assert!(!LOW_DECOY_TTL_SET.is_empty());
    }

    #[test]
    fn normal_set_respects_bounds() {
        for &ttl in NORMAL_TTL_SET {
            assert!(
                (32..=128).contains(&ttl),
                "normal TTL {ttl} out of expected kernel-default band"
            );
        }
        assert!(!NORMAL_TTL_SET.is_empty());
    }

    #[test]
    fn pick_low_decoy_ttl_is_deterministic_and_covers_set() {
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..(LOW_DECOY_TTL_SET.len() as u64) {
            seen.insert(pick_low_decoy_ttl(seed));
        }
        assert_eq!(seen.len(), LOW_DECOY_TTL_SET.len());
        // Deterministic: same seed → same value.
        assert_eq!(pick_low_decoy_ttl(42), pick_low_decoy_ttl(42));
    }

    #[test]
    fn pick_normal_ttl_is_deterministic_and_covers_set() {
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..(NORMAL_TTL_SET.len() as u64) {
            seen.insert(pick_normal_ttl(seed));
        }
        assert_eq!(seen.len(), NORMAL_TTL_SET.len());
        assert_eq!(pick_normal_ttl(17), pick_normal_ttl(17));
    }
}
