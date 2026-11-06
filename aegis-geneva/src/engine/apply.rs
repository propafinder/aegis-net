//! Applying a strategy to packets.
//!
//! The engine is a pure function: packets in, packets out, with an explicit
//! RNG. No sockets, no clock, no global state — so a strategy's effect is
//! exactly reproducible from a seed, which is what makes evolved results worth
//! trusting.

use rand::Rng;

use crate::actions::{duplicate, fragment, payload, tamper};
use crate::packet::model::Packet;
use crate::syntax::action::Action;
use crate::syntax::strategy::Strategy;

/// Ceiling on how many packets one input packet may become.
///
/// Nested `duplicate` doubles per level, so an evolved tree can ask for an
/// exponential burst. A strategy that floods is not an evasion, it is an
/// outage — so the engine caps expansion instead of letting evolution discover
/// a denial-of-service against its own user.
pub const MAX_EMITTED_PER_PACKET: usize = 64;

/// Run one action tree over one packet, returning what goes on the wire.
pub fn run_action<R: Rng + ?Sized>(action: &Action, packet: Packet, rng: &mut R) -> Vec<Packet> {
    let mut out = Vec::new();
    run_into(action, packet, rng, &mut out);
    out
}

fn run_into<R: Rng + ?Sized>(action: &Action, packet: Packet, rng: &mut R, out: &mut Vec<Packet>) {
    if out.len() >= MAX_EMITTED_PER_PACKET {
        return;
    }
    match action {
        Action::Pass => out.push(packet),
        Action::Drop => {}
        Action::Duplicate { left, right } => {
            let (a, b) = duplicate::apply(&packet);
            run_into(left, a, rng, out);
            run_into(right, b, rng, out);
        }
        Action::Fragment {
            proto,
            offset,
            order,
            left,
            right,
        } => {
            let (a, b) = fragment::apply(&packet, *proto, *offset, *order);
            run_into(left, a, rng, out);
            run_into(right, b, rng, out);
        }
        Action::Tamper {
            field, mode, next, ..
        } => {
            let mut packet = packet;
            tamper::apply(&mut packet, *field, mode, rng);
            run_into(next, packet, rng, out);
        }
        Action::TamperPayload { mode, next } => {
            let mut packet = packet;
            payload::apply(&mut packet, mode, rng);
            run_into(next, packet, rng, out);
        }
    }
}

/// Run a strategy over a packet stream.
///
/// Packets no rule matches pass through untouched — a strategy only ever
/// describes the exceptions.
pub fn run<R: Rng + ?Sized>(strategy: &Strategy, packets: Vec<Packet>, rng: &mut R) -> Vec<Packet> {
    let mut out = Vec::with_capacity(packets.len());
    for packet in packets {
        match strategy.first_match(&packet) {
            None => out.push(packet),
            Some(rule) => {
                let action = rule.action.clone();
                out.extend(run_action(&action, packet, rng));
            }
        }
    }
    out
}

#[cfg(test)]
impl Action {
    fn parse_for_test(text: &str) -> Action {
        let rule = format!("[IP:ttl:64]-{text}-|");
        crate::syntax::strategy::Rule::parse(&rule)
            .unwrap_or_else(|e| panic!("parse `{text}`: {e}"))
            .action
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::model::{tcp_flags, Direction};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(11)
    }

    fn syn() -> Packet {
        let mut p = Packet::tcp_data(b"abcdefgh");
        p.tcp.as_mut().unwrap().flags = tcp_flags::SYN;
        p
    }

    #[test]
    fn pass_emits_the_packet_unchanged() {
        let p = syn();
        let out = run_action(&Action::Pass, p.clone(), &mut rng());
        assert_eq!(out, vec![p]);
    }

    #[test]
    fn drop_emits_nothing() {
        assert!(run_action(&Action::Drop, syn(), &mut rng()).is_empty());
    }

    #[test]
    fn duplicate_emits_two() {
        let action = Action::parse_for_test("duplicate(,)");
        assert_eq!(run_action(&action, syn(), &mut rng()).len(), 2);
    }

    #[test]
    fn duplicate_with_a_dropped_branch_emits_one() {
        let action = Action::parse_for_test("duplicate(,drop)");
        assert_eq!(run_action(&action, syn(), &mut rng()).len(), 1);
    }

    #[test]
    fn tamper_then_pass_applies_the_change() {
        let action = Action::parse_for_test("tamper{IP:ttl:replace:3}()");
        let out = run_action(&action, syn(), &mut rng());
        assert_eq!(out[0].ip.ttl, 3);
    }

    #[test]
    fn a_classic_ttl_decoy_sends_one_short_lived_copy_and_one_real() {
        // The canonical evasion: the censor sees the first copy, the server
        // only the second.
        let action = Action::parse_for_test("duplicate(tamper{IP:ttl:replace:1}(),)");
        let out = run_action(&action, syn(), &mut rng());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].ip.ttl, 1);
        assert_eq!(out[1].ip.ttl, 64);
        assert_eq!(out[0].payload, out[1].payload);
    }

    #[test]
    fn expansion_is_capped() {
        // Ten nested duplicates would be 1024 packets.
        let mut action = Action::Pass;
        for _ in 0..10 {
            action = Action::Duplicate {
                left: Box::new(action.clone()),
                right: Box::new(action),
            };
        }
        let out = run_action(&action, syn(), &mut rng());
        assert!(
            out.len() <= MAX_EMITTED_PER_PACKET,
            "engine emitted {} packets",
            out.len()
        );
    }

    #[test]
    fn unmatched_packets_pass_through_untouched() {
        let strategy = Strategy::parse("[TCP:flags:R]-drop-| \\/").unwrap();
        let input = vec![syn()];
        assert_eq!(run(&strategy, input.clone(), &mut rng()), input);
    }

    #[test]
    fn the_identity_strategy_is_a_no_op() {
        let input = vec![syn(), Packet::tcp_data(b"more")];
        assert_eq!(run(&Strategy::identity(), input.clone(), &mut rng()), input);
    }

    #[test]
    fn inbound_rules_do_not_fire_on_outbound_packets() {
        let strategy = Strategy::parse("\\/ [TCP:flags:S]-drop-|").unwrap();
        let out = run(&strategy, vec![syn()], &mut rng());
        assert_eq!(out.len(), 1, "outbound packet must survive an inbound rule");

        let mut inbound = syn();
        inbound.direction = Direction::Inbound;
        assert!(run(&strategy, vec![inbound], &mut rng()).is_empty());
    }

    #[test]
    fn a_seeded_run_is_reproducible() {
        let strategy = Strategy::parse("[TCP:flags:S]-tamper{TCP:seq:corrupt}()-| \\/").unwrap();
        let a = run(&strategy, vec![syn()], &mut StdRng::seed_from_u64(3));
        let b = run(&strategy, vec![syn()], &mut StdRng::seed_from_u64(3));
        assert_eq!(a, b);
    }
}
