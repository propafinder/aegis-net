//! Cardinality policy for the six adaptive caches. No exact heap-size claim.
//! Recency is ephemeral write order; historical rows start tied at zero.
use super::schema::StateSnapshot;
use std::collections::{HashMap, HashSet};

const DESTINATION_CAP: usize = 4096;
const STRATEGY_CAP: usize = 16_384;
const TRANSPORT_CAP: usize = 128;

#[derive(Default)]
pub(crate) struct StateTouches {
    pub key_registry: HashSet<String>,
    pub key_observations: HashSet<String>,
    pub strategy_stats: HashSet<String>,
    pub stall_probe_stats: HashSet<String>,
    pub transport_stats: HashSet<String>,
    pub hybrid_route_stats: HashSet<String>,
}

pub(super) struct BoundedSnapshot {
    pub snapshot: StateSnapshot,
    pub bounds: StateBounds,
}
impl BoundedSnapshot {
    pub fn new(mut snapshot: StateSnapshot) -> Self {
        let mut bounds = StateBounds::default();
        bounds.enforce(&mut snapshot, &StateTouches::default(), 0);
        Self { snapshot, bounds }
    }
}

#[derive(Default)]
pub(super) struct StateBounds {
    clock: u64,
    key_registry: HashMap<String, u64>,
    key_observations: HashMap<String, u64>,
    strategy_stats: HashMap<String, u64>,
    stall_probe_stats: HashMap<String, u64>,
    transport_stats: HashMap<String, u64>,
    hybrid_route_stats: HashMap<String, u64>,
}
impl StateBounds {
    pub fn enforce_update(&mut self, snapshot: &mut StateSnapshot, touched: &StateTouches) {
        if self.clock == u64::MAX {
            // Compress the bounded set of ages without changing their ordering
            // or same-update ties. A rollover cannot make fresh evidence old.
            let mut ages: Vec<_> = [
                &self.key_registry,
                &self.key_observations,
                &self.strategy_stats,
                &self.stall_probe_stats,
                &self.transport_stats,
                &self.hybrid_route_stats,
            ]
            .into_iter()
            .flat_map(|rows| rows.values().copied())
            .collect();
            ages.sort_unstable();
            ages.dedup();
            for rows in [
                &mut self.key_registry,
                &mut self.key_observations,
                &mut self.strategy_stats,
                &mut self.stall_probe_stats,
                &mut self.transport_stats,
                &mut self.hybrid_route_stats,
            ] {
                for age in rows.values_mut() {
                    *age = ages.binary_search(age).expect("retained age") as u64;
                }
            }
            self.clock = ages.len() as u64;
        }
        self.clock += 1;
        self.enforce(snapshot, touched, self.clock);
    }

    fn enforce(&mut self, snapshot: &mut StateSnapshot, touched: &StateTouches, stamp: u64) {
        bound_map(
            &mut snapshot.key_registry,
            &mut self.key_registry,
            &touched.key_registry,
            stamp,
            DESTINATION_CAP,
        );
        bound_map(
            &mut snapshot.key_observations,
            &mut self.key_observations,
            &touched.key_observations,
            stamp,
            DESTINATION_CAP,
        );
        bound_map(
            &mut snapshot.strategy_stats,
            &mut self.strategy_stats,
            &touched.strategy_stats,
            stamp,
            STRATEGY_CAP,
        );
        bound_map(
            &mut snapshot.stall_probe_stats,
            &mut self.stall_probe_stats,
            &touched.stall_probe_stats,
            stamp,
            DESTINATION_CAP,
        );
        bound_map(
            &mut snapshot.transport_stats,
            &mut self.transport_stats,
            &touched.transport_stats,
            stamp,
            TRANSPORT_CAP,
        );
        bound_map(
            &mut snapshot.hybrid_route_stats,
            &mut self.hybrid_route_stats,
            &touched.hybrid_route_stats,
            stamp,
            DESTINATION_CAP,
        );
    }
}

fn bound_map<V>(
    rows: &mut HashMap<String, V>,
    ages: &mut HashMap<String, u64>,
    touched: &HashSet<String>,
    stamp: u64,
    cap: usize,
) {
    ages.retain(|key, _| rows.contains_key(key));
    for key in rows.keys() {
        let age = ages.entry(key.clone()).or_insert(stamp);
        if touched.contains(key) {
            *age = stamp;
        }
    }
    if rows.len() > cap {
        // Current finite producer touches survive before untouched entries;
        // ties (including loads/opaque bulk inserts) are lexical and stable.
        let mut order: Vec<_> = ages
            .iter()
            .map(|(key, age)| (touched.contains(key), *age, key.clone()))
            .collect();
        order.sort_unstable();
        for (_, _, key) in order.into_iter().take(rows.len() - cap) {
            rows.remove(&key);
            ages.remove(&key);
        }
    }
    // Do not retain a historical oversized bucket allocation after eviction.
    if rows.capacity() > cap.saturating_mul(2) {
        rows.shrink_to(cap);
    }
    if ages.capacity() > cap.saturating_mul(2) {
        ages.shrink_to(cap);
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    #[test]
    fn actual_retention_keeps_touches_deterministic_ties_and_bounded_metadata() {
        let mut rows = HashMap::from([("a".into(), 1), ("b".into(), 2), ("c".into(), 3)]);
        let mut ages = HashMap::new();
        bound_map(&mut rows, &mut ages, &HashSet::new(), 0, 3);
        rows.insert("d".into(), 4);
        bound_map(&mut rows, &mut ages, &HashSet::from(["a".into()]), 1, 3);
        assert!(rows.contains_key("a"));
        assert!(rows.contains_key("d"));
        assert!(!rows.contains_key("b"));
        rows.remove("c");
        rows.insert("e".into(), 5);
        bound_map(&mut rows, &mut ages, &HashSet::new(), 2, 3);
        assert_eq!(ages.len(), rows.len());
        assert!(!ages.contains_key("c"));
    }

    #[test]
    fn actual_retention_clock_rollover_preserves_write_order() {
        let mut snapshot = StateSnapshot::default();
        snapshot
            .strategy_stats
            .insert("a".into(), Default::default());
        let mut state = BoundedSnapshot::new(snapshot);
        state
            .snapshot
            .strategy_stats
            .insert("b".into(), Default::default());
        state
            .bounds
            .enforce_update(&mut state.snapshot, &StateTouches::default());
        state.bounds.clock = u64::MAX;
        state
            .snapshot
            .strategy_stats
            .insert("c".into(), Default::default());
        state
            .bounds
            .enforce_update(&mut state.snapshot, &StateTouches::default());
        assert!(state.bounds.strategy_stats["a"] < state.bounds.strategy_stats["b"]);
        assert!(state.bounds.strategy_stats["b"] < state.bounds.strategy_stats["c"]);
        assert_eq!(
            state.bounds.strategy_stats.len(),
            state.snapshot.strategy_stats.len()
        );
    }
}
