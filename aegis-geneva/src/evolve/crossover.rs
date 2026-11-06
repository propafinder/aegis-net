//! Crossover: build a child from two parents.
//!
//! Two forms, because strategies have two levels of structure. Rule-level
//! crossover takes some rules from each parent; subtree crossover grafts a
//! branch of one parent's action tree into the other. The first recombines
//! *what to react to*, the second *how*.

use rand::seq::SliceRandom;
use rand::Rng;

use crate::syntax::strategy::{Rule, Strategy};

/// Recombine two strategies.
pub fn crossover<R: Rng + ?Sized>(a: &Strategy, b: &Strategy, rng: &mut R) -> Strategy {
    if rng.gen_bool(0.5) {
        rule_crossover(a, b, rng)
    } else {
        subtree_crossover(a, b, rng)
    }
}

/// Take each half's rules from one parent or the other.
pub fn rule_crossover<R: Rng + ?Sized>(a: &Strategy, b: &Strategy, rng: &mut R) -> Strategy {
    let pick = |x: &Vec<Rule>, y: &Vec<Rule>, rng: &mut R| {
        if rng.gen_bool(0.5) {
            x.clone()
        } else {
            y.clone()
        }
    };
    Strategy {
        outbound: pick(&a.outbound, &b.outbound, rng),
        inbound: pick(&a.inbound, &b.inbound, rng),
    }
}

/// Graft a random subtree from `b` into a copy of `a`.
///
/// If the graft would breach the depth bound the child is `a` unchanged: a
/// too-deep strategy is not a valid individual, and silently truncating one
/// would quietly change what it means.
pub fn subtree_crossover<R: Rng + ?Sized>(a: &Strategy, b: &Strategy, rng: &mut R) -> Strategy {
    let mut child = a.clone();

    let donor_rules: Vec<&Rule> = b.outbound.iter().chain(b.inbound.iter()).collect();
    let Some(donor) = donor_rules.choose(rng) else {
        return child;
    };
    let donor_subtrees = donor.action.subtrees();
    let graft = (*donor_subtrees
        .choose(rng)
        .expect("subtrees always includes the root"))
    .clone();

    let total = child.outbound.len() + child.inbound.len();
    if total == 0 {
        return child;
    }
    let idx = rng.gen_range(0..total);
    let target = if idx < child.outbound.len() {
        &mut child.outbound[idx]
    } else {
        let i = idx - child.outbound.len();
        &mut child.inbound[i]
    };

    let point = rng.gen_range(0..target.action.size());
    let before = target.action.clone();
    target.action.replace_subtree(point, graft);
    if target.action.check_depth().is_err() {
        target.action = before;
    }
    child
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn parent_a() -> Strategy {
        Strategy::parse("[TCP:flags:S]-duplicate(tamper{IP:ttl:replace:1}(),)-| \\/").unwrap()
    }

    fn parent_b() -> Strategy {
        Strategy::parse("[IP:ttl:64]-fragment{TCP:8:in-order}(,drop)-| \\/ [TCP:flags:A]-drop-|")
            .unwrap()
    }

    #[test]
    fn children_stay_valid() {
        let mut rng = StdRng::seed_from_u64(31);
        let (a, b) = (parent_a(), parent_b());
        for _ in 0..500 {
            let child = crossover(&a, &b, &mut rng);
            let text = child.to_string();
            assert_eq!(
                Strategy::parse(&text).unwrap(),
                child,
                "bad round-trip: {text}"
            );
            for rule in child.outbound.iter().chain(child.inbound.iter()) {
                assert!(rule.action.check_depth().is_ok(), "too deep: {text}");
            }
        }
    }

    #[test]
    fn rule_crossover_takes_each_half_from_one_parent() {
        let mut rng = StdRng::seed_from_u64(2);
        let (a, b) = (parent_a(), parent_b());
        for _ in 0..20 {
            let child = rule_crossover(&a, &b, &mut rng);
            assert!(child.outbound == a.outbound || child.outbound == b.outbound);
            assert!(child.inbound == a.inbound || child.inbound == b.inbound);
        }
    }

    #[test]
    fn crossover_mixes_rather_than_copying_one_parent() {
        let mut rng = StdRng::seed_from_u64(17);
        let (a, b) = (parent_a(), parent_b());
        let mixed = (0..60)
            .map(|_| crossover(&a, &b, &mut rng))
            .filter(|c| *c != a && *c != b)
            .count();
        assert!(mixed > 0, "crossover never produced anything new");
    }

    #[test]
    fn crossover_with_an_empty_parent_is_safe() {
        let mut rng = StdRng::seed_from_u64(5);
        let empty = Strategy::identity();
        for _ in 0..50 {
            let _ = crossover(&parent_a(), &empty, &mut rng);
            let _ = crossover(&empty, &parent_a(), &mut rng);
        }
    }

    #[test]
    fn crossover_is_reproducible_from_a_seed() {
        let c1 = crossover(&parent_a(), &parent_b(), &mut StdRng::seed_from_u64(77));
        let c2 = crossover(&parent_a(), &parent_b(), &mut StdRng::seed_from_u64(77));
        assert_eq!(c1, c2);
    }
}
