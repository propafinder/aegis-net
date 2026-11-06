//! Random strategy generation — the raw material evolution works on.
//!
//! Generated trees are bounded in depth and biased towards leaves, because an
//! unbiased random tree is almost always a huge one, and a population of huge
//! trees never converges.
//!
//! The distributions here are deliberately *not* uniform. A trigger on
//! `TCP:seq == 41` matches one packet in four billion and is dead weight in the
//! population; a trigger on `TCP:flags` or `IP:ttl` names a class of packets.
//! Likewise a fragment offset larger than the payload is a no-op. Uniform
//! sampling over the whole space spends the entire budget on such individuals —
//! measured: with uniform choice the search never left the do-nothing baseline.

use rand::seq::SliceRandom;
use rand::Rng;

use crate::actions::payload::PayloadMode;
use crate::packet::field::{Field, Proto};
use crate::packet::model::{tcp_flags, Packet};
use crate::syntax::action::{Action, FragmentOrder, TamperMode};
use crate::syntax::strategy::{Rule, Strategy};
use crate::syntax::trigger::Trigger;

/// Values a trigger is likely to be worth matching on, per field.
fn plausible_value<R: Rng + ?Sized>(field: Field, rng: &mut R) -> (u32, bool) {
    match field {
        Field::TcpFlags => {
            let flags = *[
                tcp_flags::SYN,
                tcp_flags::ACK,
                tcp_flags::PSH | tcp_flags::ACK,
                tcp_flags::RST,
                tcp_flags::FIN,
            ]
            .choose(rng)
            .expect("non-empty");
            (u32::from(flags), true)
        }
        // Include values in the useful decoy band, not only common endpoint
        // defaults and pre-censor expiry values. With a censor three hops away
        // and a server ten hops away, TTL 4..=10 is the entire search surface
        // for a packet seen by the censor but not the server. Omitting that
        // band made the documented reassembling-censor evasion reachable only
        // through a lucky 32-bit ChangeTamperValue mutation.
        Field::Ttl => (
            *[1u32, 3, 4, 5, 8, 10, 32, 64, 128]
                .choose(rng)
                .expect("non-empty"),
            false,
        ),
        Field::DataOffset => (rng.gen_range(0..16), false),
        Field::Window => (rng.gen_range(0..=u32::from(u16::MAX)), false),
        _ => (rng.gen_range(0..=64), false),
    }
}

/// Fields worth *tampering* with, weighted.
///
/// Uniform choice over every field spends most of the budget on rewrites that
/// change nothing a censor or a server reacts to (an IP id, a data offset).
/// TTL and flags are what decoys and injected segments are built from.
fn tamper_field<R: Rng + ?Sized>(rng: &mut R) -> Field {
    match rng.gen_range(0..10) {
        0..=2 => Field::Ttl,
        3..=4 => Field::TcpFlags,
        5..=6 => Field::Seq,
        7 => Field::TcpChecksum,
        _ => *Field::ALL.choose(rng).expect("non-empty"),
    }
}

/// Fields worth *triggering* on, weighted: these name classes of packets.
fn trigger_field<R: Rng + ?Sized>(rng: &mut R) -> Field {
    match rng.gen_range(0..10) {
        0..=4 => Field::TcpFlags,
        5..=7 => Field::Ttl,
        8 => Field::DataOffset,
        _ => *Field::ALL.choose(rng).expect("non-empty"),
    }
}

pub fn random_trigger<R: Rng + ?Sized>(rng: &mut R) -> Trigger {
    let field = trigger_field(rng);
    let (value, _) = plausible_value(field, rng);
    Trigger::new(field, value)
}

/// A trigger drawn from the traffic being optimised for.
///
/// Guessing trigger values blind wastes most of the population: measured on the
/// HTTP scenario, only a quarter of blind rules fired at all, and the search
/// never beat the do-nothing baseline. Reading the value out of a real packet
/// makes rules fire by construction, so selection acts on the *action* tree —
/// which is the part worth searching.
pub fn random_trigger_seeded<R: Rng + ?Sized>(samples: &[Packet], rng: &mut R) -> Trigger {
    // A little blind generation is kept so the search can still reach values
    // no observed packet happens to carry.
    if samples.is_empty() || rng.gen_bool(0.15) {
        return random_trigger(rng);
    }
    let packet = samples.choose(rng).expect("non-empty");
    for _ in 0..8 {
        let field = trigger_field(rng);
        if let Some(value) = packet.get(field) {
            return Trigger::new(field, value);
        }
    }
    random_trigger(rng)
}

/// A random action tree of at most `depth` levels.
pub fn random_action<R: Rng + ?Sized>(rng: &mut R, depth: usize) -> Action {
    if depth <= 1 {
        return if rng.gen_bool(0.25) {
            Action::Drop
        } else {
            Action::Pass
        };
    }
    match rng.gen_range(0..12) {
        // A payload tamper is what makes a decoy carry *different* content —
        // without it, a censor that reassembles exactly like the server can
        // never be fooled, so it is worth a real share of the draws.
        10..=11 => Action::TamperPayload {
            mode: match rng.gen_range(0..3) {
                0 => PayloadMode::Corrupt,
                1 => PayloadMode::Truncate(rng.gen_range(0..24)),
                _ => {
                    let len = rng.gen_range(1..12);
                    PayloadMode::Replace((0..len).map(|_| rng.gen()).collect())
                }
            },
            next: Box::new(random_action(rng, depth - 1)),
        },
        0..=2 => Action::Duplicate {
            left: Box::new(random_action(rng, depth - 1)),
            right: Box::new(random_action(rng, depth - 1)),
        },
        3..=5 => Action::Fragment {
            proto: if rng.gen_bool(0.5) {
                Proto::Ip
            } else {
                Proto::Tcp
            },
            // Biased small: real payloads of interest (a TLS ClientHello's SNI,
            // an HTTP request line) are near the start, and an offset past the
            // payload does nothing at all.
            offset: if rng.gen_bool(0.75) {
                rng.gen_range(1..24)
            } else {
                rng.gen_range(1..256)
            },
            order: if rng.gen_bool(0.5) {
                FragmentOrder::InOrder
            } else {
                FragmentOrder::Reversed
            },
            left: Box::new(random_action(rng, depth - 1)),
            right: Box::new(random_action(rng, depth - 1)),
        },
        6..=8 => {
            let field = tamper_field(rng);
            let (value, _) = plausible_value(field, rng);
            Action::Tamper {
                field,
                mode: if rng.gen_bool(0.3) {
                    TamperMode::Corrupt
                } else {
                    TamperMode::Replace(value)
                },
                next: Box::new(random_action(rng, depth - 1)),
            }
        }
        _ => Action::Drop,
    }
}

/// A single-child action, ready to be placed above an existing subtree.
///
/// Only the unary primitives qualify: `duplicate` and `fragment` take two
/// children and would need a second subtree invented from nowhere.
pub fn random_wrapper<R: Rng + ?Sized>(rng: &mut R) -> Box<dyn FnOnce(Box<Action>) -> Action> {
    if rng.gen_bool(0.45) {
        let mode = match rng.gen_range(0..3) {
            0 => PayloadMode::Corrupt,
            1 => PayloadMode::Truncate(rng.gen_range(0..24)),
            _ => {
                let len = rng.gen_range(1..12);
                PayloadMode::Replace((0..len).map(|_| rng.gen()).collect())
            }
        };
        Box::new(move |next| Action::TamperPayload { mode, next })
    } else {
        let field = tamper_field(rng);
        let (value, _) = plausible_value(field, rng);
        let corrupt = rng.gen_bool(0.25);
        Box::new(move |next| Action::Tamper {
            field,
            mode: if corrupt {
                TamperMode::Corrupt
            } else {
                TamperMode::Replace(value)
            },
            next,
        })
    }
}

pub fn random_rule<R: Rng + ?Sized>(samples: &[Packet], rng: &mut R, depth: usize) -> Rule {
    Rule {
        trigger: random_trigger_seeded(samples, rng),
        action: random_action(rng, depth),
    }
}

/// A random strategy with one or two rules per half.
pub fn random_strategy<R: Rng + ?Sized>(samples: &[Packet], rng: &mut R, depth: usize) -> Strategy {
    let mut strategy = Strategy::default();
    for _ in 0..rng.gen_range(1..=2) {
        strategy.outbound.push(random_rule(samples, rng, depth));
    }
    if rng.gen_bool(0.3) {
        strategy.inbound.push(random_rule(samples, rng, depth));
    }
    strategy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::action::MAX_DEPTH;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn generated_trees_respect_the_depth_bound() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..200 {
            let a = random_action(&mut rng, MAX_DEPTH);
            assert!(a.depth() <= MAX_DEPTH, "{a} is {} deep", a.depth());
            assert!(a.check_depth().is_ok());
        }
    }

    #[test]
    fn generated_strategies_round_trip_through_text() {
        let mut rng = StdRng::seed_from_u64(2);
        for _ in 0..200 {
            let s = random_strategy(&[], &mut rng, 4);
            let text = s.to_string();
            let reparsed = Strategy::parse(&text)
                .unwrap_or_else(|e| panic!("generated unparseable `{text}`: {e}"));
            assert_eq!(reparsed, s, "round-trip changed `{text}`");
        }
    }

    #[test]
    fn generation_is_reproducible_from_a_seed() {
        let a = random_strategy(&[], &mut StdRng::seed_from_u64(9), 4);
        let b = random_strategy(&[], &mut StdRng::seed_from_u64(9), 4);
        assert_eq!(a, b);
    }

    #[test]
    fn seeded_triggers_fire_on_the_traffic_they_came_from() {
        let mut rng = StdRng::seed_from_u64(6);
        let sample = Packet::tcp_data(b"GET /secret");
        let fired = (0..200)
            .filter(|_| {
                random_trigger_seeded(std::slice::from_ref(&sample), &mut rng).matches(&sample)
            })
            .count();
        assert!(fired > 150, "only {fired}/200 seeded triggers fired");
    }

    #[test]
    fn ttl_generation_reaches_the_between_censor_and_server_decoy_band() {
        let mut rng = StdRng::seed_from_u64(10);
        let values: std::collections::HashSet<u32> = (0..200)
            .map(|_| plausible_value(Field::Ttl, &mut rng).0)
            .collect();
        assert!(
            values.iter().any(|ttl| (4..=10).contains(ttl)),
            "TTL generator cannot construct a decoy that reaches a 3-hop censor but not a 10-hop server: {values:?}"
        );
    }

    #[test]
    fn blind_generation_still_works_without_samples() {
        let mut rng = StdRng::seed_from_u64(7);
        let _ = random_trigger_seeded(&[], &mut rng);
    }

    #[test]
    fn generation_is_varied() {
        let mut rng = StdRng::seed_from_u64(4);
        let set: std::collections::HashSet<String> = (0..50)
            .map(|_| random_strategy(&[], &mut rng, 4).to_string())
            .collect();
        assert!(set.len() > 25, "only {} distinct strategies", set.len());
    }
}
