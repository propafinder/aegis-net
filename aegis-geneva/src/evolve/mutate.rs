//! Mutation: small random changes to one strategy.
//!
//! Every mutation preserves the depth bound and leaves the strategy parseable,
//! so the population can never contain something the engine cannot run.

use rand::seq::SliceRandom;
use rand::Rng;

use crate::packet::model::Packet;
use crate::syntax::action::{Action, TamperMode, MAX_DEPTH};
use crate::syntax::strategy::{Rule, Strategy};

use super::random::{random_action, random_rule, random_trigger_seeded, random_wrapper};

/// The kinds of change a mutation may make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    AddRule,
    RemoveRule,
    ReplaceSubtree,
    ChangeTrigger,
    ChangeTamperValue,
    /// Insert a new single-child node *above* an existing subtree, keeping the
    /// subtree as its child.
    ///
    /// Without this, refining a working idea means re-generating it whole: going
    /// from a decoy that a censor sees to a decoy that also *says something
    /// different* needs both nodes to appear in one draw. Wrapping turns that
    /// into a single step, which is the difference between a search that climbs
    /// and one that waits for a coincidence.
    WrapSubtree,
}

pub const ALL_MUTATIONS: &[Mutation] = &[
    Mutation::AddRule,
    Mutation::RemoveRule,
    Mutation::ReplaceSubtree,
    Mutation::ChangeTrigger,
    Mutation::ChangeTamperValue,
    Mutation::WrapSubtree,
];

/// Apply one random mutation, returning the mutated copy.
///
/// `samples` are packets from the traffic being optimised for; new triggers are
/// drawn from them (see [`random_trigger_seeded`]). Pass an empty slice to
/// generate blind.
pub fn mutate<R: Rng + ?Sized>(strategy: &Strategy, samples: &[Packet], rng: &mut R) -> Strategy {
    let mut out = strategy.clone();
    let kind = *ALL_MUTATIONS.choose(rng).expect("non-empty");
    apply(&mut out, kind, samples, rng);
    // A mutation must never hand back something unrunnable.
    if out
        .outbound
        .iter()
        .chain(out.inbound.iter())
        .any(|r| r.action.check_depth().is_err())
    {
        return strategy.clone();
    }
    out
}

fn half_mut<'a, R: Rng + ?Sized>(strategy: &'a mut Strategy, rng: &mut R) -> &'a mut Vec<Rule> {
    if rng.gen_bool(0.8) {
        &mut strategy.outbound
    } else {
        &mut strategy.inbound
    }
}

fn apply<R: Rng + ?Sized>(
    strategy: &mut Strategy,
    kind: Mutation,
    samples: &[Packet],
    rng: &mut R,
) {
    match kind {
        Mutation::AddRule => {
            let rule = random_rule(samples, rng, 3);
            half_mut(strategy, rng).push(rule);
        }
        Mutation::RemoveRule => {
            let half = half_mut(strategy, rng);
            if !half.is_empty() {
                let idx = rng.gen_range(0..half.len());
                half.remove(idx);
            }
        }
        Mutation::ReplaceSubtree => {
            if let Some(rule) = pick_rule_mut(strategy, rng) {
                let count = rule.action.size();
                let index = rng.gen_range(0..count);
                // Keep the result within the depth bound by generating a
                // subtree no deeper than what it replaces can afford.
                let budget = MAX_DEPTH.saturating_sub(index.min(MAX_DEPTH - 1)).max(1);
                let replacement = random_action(rng, budget.min(3));
                rule.action.replace_subtree(index, replacement);
            }
        }
        Mutation::ChangeTrigger => {
            let trigger = random_trigger_seeded(samples, rng);
            if let Some(rule) = pick_rule_mut(strategy, rng) {
                rule.trigger = trigger;
            }
        }
        Mutation::WrapSubtree => {
            let wrapper = random_wrapper(rng);
            if let Some(rule) = pick_rule_mut(strategy, rng) {
                let index = rng.gen_range(0..rule.action.size());
                let inner = rule
                    .action
                    .subtrees()
                    .get(index)
                    .map(|a| (*a).clone())
                    .unwrap_or(Action::Pass);
                let wrapped = wrapper(Box::new(inner));
                rule.action.replace_subtree(index, wrapped);
            }
        }
        Mutation::ChangeTamperValue => {
            let delta = rng.gen_range(1..=255);
            if let Some(rule) = pick_rule_mut(strategy, rng) {
                bump_tamper(&mut rule.action, delta);
            }
        }
    }
}

fn pick_rule_mut<'a, R: Rng + ?Sized>(
    strategy: &'a mut Strategy,
    rng: &mut R,
) -> Option<&'a mut Rule> {
    let total = strategy.outbound.len() + strategy.inbound.len();
    if total == 0 {
        return None;
    }
    let idx = rng.gen_range(0..total);
    if idx < strategy.outbound.len() {
        strategy.outbound.get_mut(idx)
    } else {
        strategy.inbound.get_mut(idx - strategy.outbound.len())
    }
}

/// Nudge the first `tamper ... replace` value found, leaving structure alone.
fn bump_tamper(action: &mut Action, delta: u32) -> bool {
    match action {
        Action::Pass | Action::Drop => false,
        Action::Duplicate { left, right } | Action::Fragment { left, right, .. } => {
            bump_tamper(left, delta) || bump_tamper(right, delta)
        }
        Action::Tamper { mode, next, .. } => {
            if let TamperMode::Replace(v) = mode {
                *v = v.wrapping_add(delta);
                true
            } else {
                bump_tamper(next, delta)
            }
        }
        Action::TamperPayload { next, .. } => bump_tamper(next, delta),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn seed(n: u64) -> StdRng {
        StdRng::seed_from_u64(n)
    }

    fn sample() -> Strategy {
        Strategy::parse("[TCP:flags:S]-duplicate(tamper{IP:ttl:replace:5}(),)-| \\/").unwrap()
    }

    #[test]
    fn mutants_stay_parseable_and_within_the_depth_bound() {
        let mut rng = seed(21);
        let mut s = sample();
        for _ in 0..500 {
            s = mutate(&s, &[], &mut rng);
            let text = s.to_string();
            let reparsed = Strategy::parse(&text)
                .unwrap_or_else(|e| panic!("mutation produced unparseable `{text}`: {e}"));
            assert_eq!(reparsed, s);
            for rule in s.outbound.iter().chain(s.inbound.iter()) {
                assert!(rule.action.check_depth().is_ok(), "too deep: {text}");
            }
        }
    }

    #[test]
    fn mutation_actually_changes_things() {
        let mut rng = seed(3);
        let s = sample();
        let changed = (0..40).filter(|_| mutate(&s, &[], &mut rng) != s).count();
        assert!(changed > 20, "only {changed}/40 mutations had any effect");
    }

    #[test]
    fn mutation_is_reproducible_from_a_seed() {
        assert_eq!(
            mutate(&sample(), &[], &mut seed(8)),
            mutate(&sample(), &[], &mut seed(8))
        );
    }

    #[test]
    fn mutating_an_empty_strategy_is_safe() {
        let mut rng = seed(12);
        let mut s = Strategy::identity();
        for _ in 0..100 {
            s = mutate(&s, &[], &mut rng);
        }
        assert!(Strategy::parse(&s.to_string()).is_ok());
    }

    #[test]
    fn wrapping_keeps_the_subtree_underneath() {
        let mut rng = seed(44);
        let s = Strategy::parse("[TCP:flags:S]-drop-| \\/").unwrap();
        // Repeatedly wrap and confirm the tree only ever grows around `drop`.
        let mut found_wrapped = false;
        for _ in 0..60 {
            let mut m = s.clone();
            apply(&mut m, Mutation::WrapSubtree, &[], &mut rng);
            let text = m.to_string();
            assert!(text.contains("drop"), "wrap lost the subtree: {text}");
            if m != s {
                found_wrapped = true;
                assert!(m.outbound[0].action.size() > s.outbound[0].action.size());
            }
        }
        assert!(found_wrapped, "wrapping never changed anything");
    }

    #[test]
    fn tamper_bump_changes_only_the_value() {
        let mut action = Strategy::parse("[TCP:flags:S]-tamper{IP:ttl:replace:5}()-| \\/")
            .unwrap()
            .outbound[0]
            .action
            .clone();
        assert!(bump_tamper(&mut action, 3));
        assert_eq!(action.to_string(), "tamper{IP:ttl:replace:8}()");
    }

    #[test]
    fn tamper_bump_reports_when_there_is_nothing_to_bump() {
        let mut action = Action::Drop;
        assert!(!bump_tamper(&mut action, 1));
    }
}
