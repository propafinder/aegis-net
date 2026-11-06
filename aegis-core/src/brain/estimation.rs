use crate::state_v2::{StateSnapshot, StrategyStatsV2};

use super::{
    context::DecisionContext,
    key::StrategyKey,
    observation::{
        observation_reuse_weight, observed_stage_reward_factor, strategy_entry_key,
        strategy_similarity,
    },
    scoring::{
        belief_adjusted_reward, strategy_belief, strategy_latency_cost, strategy_runtime_freshness,
    },
    selection::StrategyEstimate,
};

pub(super) fn estimate_strategy(
    snapshot: &StateSnapshot,
    base_key: &StrategyKey,
    effective_key: &StrategyKey,
    base_key_hash: &str,
    effective_key_hash: &str,
    strategy: &str,
    context: &DecisionContext,
) -> StrategyEstimate {
    let total_trials = snapshot
        .strategy_stats
        .iter()
        .filter(|(entry_key, _)| entry_key.ends_with(&format!("|{strategy}")))
        .map(|(_, stats)| stats.trials as f64)
        .sum::<f64>()
        .max(1.0);

    let mut exact = ExactStrategyAccumulator::default();

    accumulate_exact_strategy(snapshot, base_key, base_key_hash, strategy, 1.0, &mut exact);
    if effective_key_hash != base_key_hash {
        accumulate_exact_strategy(
            snapshot,
            effective_key,
            effective_key_hash,
            strategy,
            1.25,
            &mut exact,
        );
    }

    for (candidate_hash, candidate_key) in &snapshot.key_registry {
        if candidate_hash == base_key_hash || candidate_hash == effective_key_hash {
            continue;
        }
        let similarity = strategy_similarity(effective_key, candidate_key)
            .max(strategy_similarity(base_key, candidate_key));
        if similarity <= 0.0 {
            continue;
        }
        let Some(stats) = snapshot
            .strategy_stats
            .get(&strategy_entry_key(candidate_hash, strategy))
        else {
            continue;
        };
        exact.exploration_trials += stats.trials as f64 * similarity;
        let trusted_similarity =
            similarity * observation_reuse_weight(snapshot, candidate_hash, candidate_key);
        exact.weighted_reward += score_strategy_for_key(stats, candidate_key) * trusted_similarity;
        exact.reward_weight += trusted_similarity;
        exact.weighted_trials += stats.trials as f64 * trusted_similarity;
    }

    let runtime_reward = if exact.reward_weight > 0.0 {
        (exact.weighted_reward / exact.reward_weight).clamp(0.0, 1.0)
    } else {
        0.5
    };
    let runtime_confidence = (exact.weighted_trials / 8.0).clamp(0.0, 1.0);
    let runtime_freshness =
        strategy_runtime_freshness(snapshot, base_key_hash, effective_key_hash, strategy);
    let latency_cost = strategy_latency_cost(snapshot, base_key_hash, effective_key_hash, strategy);
    let belief = strategy_belief(
        snapshot,
        strategy,
        context,
        runtime_reward,
        runtime_confidence,
        runtime_freshness,
        latency_cost,
    );

    StrategyEstimate {
        reward: belief_adjusted_reward(&belief),
        trials: exact.weighted_trials,
        exploration_trials: exact.exploration_trials,
        total_trials,
        belief,
    }
}

#[derive(Default)]
struct ExactStrategyAccumulator {
    weighted_reward: f64,
    reward_weight: f64,
    weighted_trials: f64,
    exploration_trials: f64,
}

fn accumulate_exact_strategy(
    snapshot: &StateSnapshot,
    key: &StrategyKey,
    key_hash: &str,
    strategy: &str,
    weight: f64,
    accumulator: &mut ExactStrategyAccumulator,
) {
    if let Some(stats) = snapshot
        .strategy_stats
        .get(&strategy_entry_key(key_hash, strategy))
    {
        accumulator.exploration_trials += stats.trials as f64 * weight;
        let trusted_weight = weight * observation_reuse_weight(snapshot, key_hash, key);
        accumulator.weighted_reward += score_strategy_for_key(stats, key) * trusted_weight;
        accumulator.reward_weight += trusted_weight;
        accumulator.weighted_trials += stats.trials as f64 * trusted_weight;
    }
}

fn score_strategy(stats: &StrategyStatsV2) -> f64 {
    ((stats.fitness_score + stats.success_rate()) / 2.0).clamp(0.0, 1.0)
}

fn score_strategy_for_key(stats: &StrategyStatsV2, key: &StrategyKey) -> f64 {
    (score_strategy(stats) * observed_stage_reward_factor(key.packet_stage_hint)).clamp(0.0, 1.0)
}
