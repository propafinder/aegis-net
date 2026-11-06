//! Offline, teacher-forced reuse of the native recent selector. Observations
//! remain the logged tape even if an alternate ranking would choose differently.
//! No counterfactual reward, admission proof, cost or regret is fabricated.
use super::{EligibleRoute, RecentRouteConfig, RecentRouteSelector, RecentSelection};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

pub const MAX_EVENTS: usize = 4096;
const MAX_SPAN_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Clone, Debug)]
pub struct Candidate {
    pub strategy: String,
    pub prior: f64,
    pub runtime_admitted: bool,
    pub hard_excluded: bool,
}
#[derive(Clone, Debug)]
pub enum EventKind {
    Decision {
        candidates: Vec<Candidate>,
    },
    Outcome {
        strategy: String,
        /// Same reported signal + outgoing progress criterion as native Brain.
        progress_reward: f64,
        cooldown_trigger: bool,
        reported_latency_ms: Option<u64>,
        reported_outgoing_bytes: u64,
    },
}
#[derive(Clone, Debug)]
pub struct Event {
    pub at_unix_ms: u64,
    /// Opaque digest; raw endpoints are not needed by this operation.
    pub context_sha256: String,
    pub kind: EventKind,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Config {
    pub window_ms: u64,
    /// Hypothetical fixed overlay, not the installed hybrid cooldown policy.
    pub failure_cooldown_ms: u64,
    pub max_observations: usize,
}
#[derive(Debug, Serialize)]
pub struct Decision {
    pub at_unix_ms: u64,
    pub context_sha256: String,
    pub hard_excluded_candidates: usize,
    pub not_admitted_candidates: usize,
    pub overlay_cooldown_excluded_candidates: usize,
    pub native_recent: RecentSelection,
    pub native_recent_with_fixed_cooldown: RecentSelection,
    pub logged_strategy: Option<String>,
    pub logged_progress_reward: Option<f64>,
    pub reported_latency_ms: Option<u64>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub scope: &'static str,
    pub config: Config,
    pub decisions: Vec<Decision>,
    pub observed_outcomes: usize,
    pub reported_latency_rows: usize,
    pub reported_latency_sum_ms: u64,
    pub reported_outgoing_bytes_sum: u64,
    /// Terminal-event intervals on the logged tape; not alternate-policy recovery.
    pub observed_failure_to_progress_ms: Vec<u64>,
    pub policy_recovery_ms: Option<u64>,
    pub policy_cost: Option<f64>,
    pub policy_regret: Option<f64>,
    pub unknown_policy_metrics_reason: &'static str,
    pub native_recent_selector_executed: bool,
    pub counterfactual_outcomes_available: bool,
    pub application_delivery_verified: bool,
    pub admission_verified: bool,
    pub automatic_policy_application: bool,
    pub policy_advantage_established: bool,
}

fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The supplied candidate admission/hard flags are declarations, not live
/// runtime gates. Both rankings filter them before even cold exploration.
pub fn replay(config: Config, events: &[Event]) -> Result<Report, &'static str> {
    if events.is_empty() || events.len() > MAX_EVENTS || config.failure_cooldown_ms > 3_600_000 {
        return Err("offline event or cooldown budget rejected");
    }
    let settings = RecentRouteConfig {
        window: Duration::from_millis(config.window_ms),
        paper_algorithm: None,
        max_observations: config.max_observations,
        // No failure-domain declarations are imported or inferred from IPs.
        diversity_penalty: 0.0,
    };
    let mut baseline = RecentRouteSelector::new(settings.clone())
        .map_err(|_| "offline recent selector budget rejected")?;
    let mut overlay = RecentRouteSelector::new(settings)
        .map_err(|_| "offline recent selector budget rejected")?;
    let start = events[0].at_unix_ms;
    let clock = Instant::now();
    let mut previous = start;
    let mut contexts = BTreeSet::new();
    let mut pending: BTreeMap<String, (usize, BTreeSet<String>)> = BTreeMap::new();
    let mut cooldowns: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut failures: BTreeMap<String, u64> = BTreeMap::new();
    let mut out = Report {
        scope: "offline teacher-forced native ranking over declared logged admission; no policy rollout",
        config,
        decisions: Vec::new(),
        observed_outcomes: 0,
        reported_latency_rows: 0,
        reported_latency_sum_ms: 0,
        reported_outgoing_bytes_sum: 0,
        observed_failure_to_progress_ms: Vec::new(),
        policy_recovery_ms: None,
        policy_cost: None,
        policy_regret: None,
        unknown_policy_metrics_reason: "unobserved alternative outcomes; logged latency/outgoing bytes are not counterfactual policy cost or delivery",
        native_recent_selector_executed: true,
        counterfactual_outcomes_available: false,
        application_delivery_verified: false,
        admission_verified: false,
        automatic_policy_application: false,
        policy_advantage_established: false,
    };
    for event in events {
        let elapsed = event
            .at_unix_ms
            .checked_sub(start)
            .ok_or("offline event chronology rejected")?;
        if event.at_unix_ms < previous || elapsed > MAX_SPAN_MS || !digest(&event.context_sha256) {
            return Err("offline event chronology or context rejected");
        }
        previous = event.at_unix_ms;
        contexts.insert(event.context_sha256.clone());
        if contexts.len() > 64 {
            return Err("offline context budget rejected");
        }
        let at = clock
            .checked_add(Duration::from_millis(elapsed))
            .ok_or("offline clock interval rejected")?;
        match &event.kind {
            EventKind::Decision { candidates } => {
                if pending.contains_key(&event.context_sha256) {
                    return Err("ambiguous overlapping decision for one context");
                }
                if candidates.len() > 16 {
                    return Err("offline candidate budget rejected");
                }
                let mut unique = BTreeSet::new();
                for c in candidates {
                    if !id(&c.strategy)
                        || !unique.insert(c.strategy.clone())
                        || !c.prior.is_finite()
                        || !(0.0..=1.0).contains(&c.prior)
                    {
                        return Err("offline candidate declaration rejected");
                    }
                }
                let admitted = candidates
                    .iter()
                    .filter(|c| c.runtime_admitted && !c.hard_excluded)
                    .map(|c| {
                        (
                            EligibleRoute {
                                strategy: c.strategy.clone(),
                                failure_domain: None,
                            },
                            c.prior,
                        )
                    })
                    .collect::<Vec<_>>();
                let cooled = admitted
                    .iter()
                    .filter(|(c, _)| {
                        cooldowns
                            .get(&(event.context_sha256.clone(), c.strategy.clone()))
                            .is_none_or(|until| event.at_unix_ms >= *until)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let native = baseline
                    .rank_at(at, &event.context_sha256, &admitted)
                    .map_err(|_| "offline native ranking rejected")?;
                let alternative = overlay
                    .rank_at(at, &event.context_sha256, &cooled)
                    .map_err(|_| "offline overlay ranking rejected")?;
                let index = out.decisions.len();
                if !admitted.is_empty() {
                    pending.insert(
                        event.context_sha256.clone(),
                        (
                            index,
                            admitted.iter().map(|(c, _)| c.strategy.clone()).collect(),
                        ),
                    );
                }
                out.decisions.push(Decision {
                    at_unix_ms: event.at_unix_ms,
                    context_sha256: event.context_sha256.clone(),
                    hard_excluded_candidates: candidates.iter().filter(|c| c.hard_excluded).count(),
                    not_admitted_candidates: candidates
                        .iter()
                        .filter(|c| !c.runtime_admitted)
                        .count(),
                    overlay_cooldown_excluded_candidates: admitted.len() - cooled.len(),
                    native_recent: native,
                    native_recent_with_fixed_cooldown: alternative,
                    logged_strategy: None,
                    logged_progress_reward: None,
                    reported_latency_ms: None,
                });
            }
            EventKind::Outcome {
                strategy,
                progress_reward,
                cooldown_trigger,
                reported_latency_ms,
                reported_outgoing_bytes,
            } => {
                if !id(strategy)
                    || ![0.0, 1.0].contains(progress_reward)
                    || (*cooldown_trigger && *progress_reward != 0.0)
                    || (*progress_reward == 1.0 && *reported_outgoing_bytes == 0)
                    || reported_latency_ms.is_some_and(|ms| ms > MAX_SPAN_MS)
                {
                    return Err("offline outcome declaration rejected");
                }
                let (index, admitted) = pending
                    .remove(&event.context_sha256)
                    .ok_or("outcome without unique preceding decision")?;
                if !admitted.contains(strategy) {
                    return Err("outcome strategy was omitted or hard excluded at its decision");
                }
                baseline
                    .record_at(at, &event.context_sha256, strategy, *progress_reward)
                    .map_err(|_| "offline observation rejected")?;
                overlay
                    .record_at(at, &event.context_sha256, strategy, *progress_reward)
                    .map_err(|_| "offline observation rejected")?;
                // Teacher forcing is explicit: even an overlay-excluded logged
                // action still enters history. It is never an alternate-policy reward.
                let row = &mut out.decisions[index];
                row.logged_strategy = Some(strategy.clone());
                row.logged_progress_reward = Some(*progress_reward);
                row.reported_latency_ms = *reported_latency_ms;
                out.observed_outcomes += 1;
                out.reported_outgoing_bytes_sum = out
                    .reported_outgoing_bytes_sum
                    .checked_add(*reported_outgoing_bytes)
                    .ok_or("logged byte sum overflow")?;
                if let Some(ms) = reported_latency_ms {
                    out.reported_latency_rows += 1;
                    out.reported_latency_sum_ms = out
                        .reported_latency_sum_ms
                        .checked_add(*ms)
                        .ok_or("logged latency sum overflow")?;
                }
                if *cooldown_trigger {
                    let until = event
                        .at_unix_ms
                        .checked_add(config.failure_cooldown_ms)
                        .ok_or("cooldown interval overflow")?;
                    cooldowns.insert((event.context_sha256.clone(), strategy.clone()), until);
                    failures
                        .entry(event.context_sha256.clone())
                        .or_insert(event.at_unix_ms);
                } else if *progress_reward > 0.0 {
                    if let Some(failed_at) = failures.remove(&event.context_sha256) {
                        out.observed_failure_to_progress_ms
                            .push(event.at_unix_ms - failed_at);
                    }
                }
            }
        }
    }
    if !pending.is_empty() {
        return Err("missing terminal outcome for retained decision");
    }
    Ok(out)
}

#[cfg(test)]
#[path = "offline_replay_tests.rs"]
mod tests;
