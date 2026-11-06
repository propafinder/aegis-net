//! Opt-in windowed UCB and configured failure-domain diversity.
//! This ranks an explicit runtime-admitted subset; it never creates reachability.
use super::{Brain, StrategyKey};

#[path = "recent_routes/offline_replay.rs"]
pub mod offline_replay;
#[path = "recent_routes/paper_bandit.rs"]
pub mod paper_bandit;
use paper_bandit::{PaperAlgorithm, PaperBandit};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentRoutesSettings {
    pub window_ms: u64,
    pub max_observations: usize,
    pub diversity_penalty: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paper_algorithm: Option<PaperAlgorithm>,
    #[serde(default)]
    pub failure_domains: BTreeMap<String, String>,
}

impl RecentRoutesSettings {
    pub fn validate(&self, preferred: &[String]) -> Result<RecentRouteConfig, String> {
        if preferred.len() > 64
            || preferred
                .iter()
                .any(|name| name.is_empty() || name.len() > 64)
            || preferred.iter().collect::<BTreeSet<_>>().len() != preferred.len()
            || self.failure_domains.len() > 64
            || self.failure_domains.iter().any(|(name, domain)| {
                !preferred.contains(name) || domain.is_empty() || domain.len() > 64
            })
        {
            return Err("recent routes must refer to bounded configured candidates".into());
        }
        let config = RecentRouteConfig {
            window: Duration::from_millis(self.window_ms),
            max_observations: self.max_observations,
            diversity_penalty: self.diversity_penalty,
            paper_algorithm: self.paper_algorithm.clone(),
        };
        RecentRouteSelector::new(config.clone())?;
        Ok(config)
    }
}
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct RecentRouteConfig {
    pub paper_algorithm: Option<PaperAlgorithm>,
    pub window: Duration,
    pub max_observations: usize,
    pub diversity_penalty: f64,
}

#[derive(Clone, Debug)]
pub struct EligibleRoute {
    pub strategy: String,
    /// Configured common failure domain. None shares one unknown domain.
    /// Different labels are not evidence of independent paths or censor access.
    pub failure_domain: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RecentRank {
    pub strategy: String,
    pub window_trials: usize,
    /// Discounted count for paper mode; ordinary window count otherwise.
    pub effective_trials: f64,
    pub window_reward: f64,
    /// No evidence survives in this context's recent window. These admitted
    /// routes rank before observed routes, independently of the finite score.
    pub exploration_required: bool,
    /// Defined only for positive trial counts; zero during required exploration.
    pub ucb_bonus: f64,
    pub diversity_penalty: f64,
    /// Orders routes within the exploration/observed phase, not across phases.
    pub score: f64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RecentSelection {
    pub order: Vec<String>,
    pub ranked: Vec<RecentRank>,
    pub scope: &'static str,
}

#[derive(Clone)]
struct Observation {
    at: Instant,
    context: String,
    strategy: String,
    reward: f64,
}
struct PaperHistory {
    estimator: PaperBandit,
    last_completed: Instant,
}
const MAX_PAPER_CONTEXTS: usize = 64;
pub struct RecentRouteSelector {
    config: RecentRouteConfig,
    observations: VecDeque<Observation>,
    paper_bandits: BTreeMap<String, PaperHistory>,
    // Retiring observations must not erase the global successful-completion clock.
    last_paper_completion: Option<Instant>,
    /// No silently stale paper estimate after a refused actual outcome.
    paper_refused: bool,
}

impl RecentRouteSelector {
    pub fn mode_name(&self) -> &'static str {
        match self.config.paper_algorithm {
            Some(PaperAlgorithm::SlidingWindow { .. }) => "garivier_moulines_sliding_window_ucb",
            Some(PaperAlgorithm::Discounted { .. }) => "garivier_moulines_discounted_ucb",
            None => "recent_windowed_ucb_diversity",
        }
    }
    pub fn new(config: RecentRouteConfig) -> Result<Self, String> {
        if config.window.is_zero()
            || config.window > Duration::from_secs(3600)
            || !(1..=4096).contains(&config.max_observations)
            || !config.diversity_penalty.is_finite()
            || !(0.0..=1.0).contains(&config.diversity_penalty)
        {
            return Err("invalid recent route budget".into());
        }
        if let Some(algorithm) = &config.paper_algorithm {
            algorithm.validate()?;
            if matches!(algorithm, PaperAlgorithm::SlidingWindow { rounds, .. } if *rounds > config.max_observations)
            {
                return Err("paper sliding window exceeds observation budget".into());
            }
        }
        Ok(Self {
            config,
            observations: VecDeque::new(),
            paper_bandits: BTreeMap::new(),
            last_paper_completion: None,
            paper_refused: false,
        })
    }
    /// Progress/outcome reward in [0,1]; a socket connection alone is not success.
    /// Caller records verified runtime outcomes. This RAM-only store is bounded.
    pub fn record(&mut self, context: &str, strategy: &str, reward: f64) -> Result<(), String> {
        self.record_at(Instant::now(), context, strategy, reward)
    }
    fn record_at(
        &mut self,
        at: Instant,
        context: &str,
        strategy: &str,
        reward: f64,
    ) -> Result<(), String> {
        if context.len() > 128
            || context.is_empty()
            || strategy.len() > 64
            || strategy.is_empty()
            || !reward.is_finite()
            || !(0.0..=1.0).contains(&reward)
            || self
                .observations
                .back()
                .is_some_and(|previous| at < previous.at)
            || self
                .last_paper_completion
                .is_some_and(|previous| at < previous)
        {
            return Err("invalid recent route observation".into());
        }
        if let Some(algorithm) = &self.config.paper_algorithm {
            if !self.paper_bandits.contains_key(context) {
                // Histories have no external borrowers: rank and record access them
                // only through this mutable selector (the runtime holds its Mutex).
                // Prepare a valid fresh completion before changing any victim.
                let mut estimator = PaperBandit::new(algorithm.clone())?;
                estimator.observe(strategy, reward)?;
                if self.paper_bandits.len() >= MAX_PAPER_CONTEXTS {
                    let victim = self
                        .paper_bandits
                        .iter()
                        .min_by(|a, b| {
                            a.1.last_completed
                                .cmp(&b.1.last_completed)
                                .then_with(|| a.0.cmp(b.0))
                        })
                        .map(|(context, _)| context.clone())
                        .expect("full history map");
                    self.paper_bandits.remove(&victim);
                    self.observations.retain(|entry| entry.context != victim);
                }
                self.paper_bandits.insert(
                    context.into(),
                    PaperHistory {
                        estimator,
                        last_completed: at,
                    },
                );
            } else {
                let history = self
                    .paper_bandits
                    .get_mut(context)
                    .expect("existing history");
                if let Err(error) = history.estimator.observe(strategy, reward) {
                    self.paper_refused = true;
                    return Err(error);
                }
                history.last_completed = at;
            }
            self.last_paper_completion = Some(at);
        }
        self.prune(at);
        if self.observations.len() == self.config.max_observations {
            self.observations.pop_front();
        }
        self.observations.push_back(Observation {
            at,
            context: context.into(),
            strategy: strategy.into(),
            reward,
        });
        Ok(())
    }
    fn prune(&mut self, now: Instant) {
        while self.observations.front().is_some_and(|o| {
            now.checked_duration_since(o.at)
                .is_some_and(|age| age > self.config.window)
        }) {
            self.observations.pop_front();
        }
    }
    fn rank_at(
        &mut self,
        now: Instant,
        context: &str,
        candidates: &[(EligibleRoute, f64)],
    ) -> Result<RecentSelection, String> {
        if self.paper_refused {
            return Err("paper selector requires explicit reset after refused outcome".into());
        }
        if candidates.len() > 64
            || self.observations.back().is_some_and(|o| o.at > now)
            || self
                .last_paper_completion
                .is_some_and(|previous| previous > now)
        {
            return Err("invalid recent route selection interval".into());
        }
        self.prune(now);
        let mut unique = BTreeSet::new();
        for (route, prior) in candidates {
            if route.strategy.is_empty()
                || route.strategy.len() > 64
                || !unique.insert(&route.strategy)
                || !prior.is_finite()
                || !(0.0..=1.0).contains(prior)
                || route
                    .failure_domain
                    .as_ref()
                    .is_some_and(|d| d.is_empty() || d.len() > 64)
            {
                return Err("invalid admitted route set".into());
            }
        }
        let total = self
            .observations
            .iter()
            .filter(|o| o.context == context && unique.contains(&o.strategy))
            .count();
        let mut remaining: Vec<_> = candidates
            .iter()
            .enumerate()
            .map(|(index, (route, prior))| {
                let samples: Vec<_> = self
                    .observations
                    .iter()
                    .filter(|o| o.context == context && o.strategy == route.strategy)
                    .collect();
                let mut trials = samples.len();
                let mut effective_trials = trials as f64;
                let mut reward = if trials == 0 {
                    *prior
                } else {
                    samples.iter().map(|o| o.reward).sum::<f64>() / trials as f64
                };
                let mut bonus = if trials == 0 {
                    0.0
                } else {
                    (2.0 * ((total + 1) as f64).ln() / trials as f64).sqrt()
                };
                if self.config.paper_algorithm.is_some() {
                    if let Some(bandit) = self.paper_bandits.get(context) {
                        let estimate = bandit.estimator.estimate(&route.strategy);
                        trials = estimate.trials;
                        effective_trials = estimate.effective_trials;
                        reward = if effective_trials == 0.0 {
                            *prior
                        } else {
                            estimate.mean
                        };
                        bonus = estimate.bonus;
                    } else {
                        trials = 0;
                        effective_trials = 0.0;
                        reward = *prior;
                        bonus = 0.0;
                    }
                }
                (
                    index,
                    route,
                    RecentRank {
                        strategy: route.strategy.clone(),
                        window_trials: trials,
                        effective_trials,
                        window_reward: reward,
                        exploration_required: effective_trials == 0.0,
                        ucb_bonus: bonus,
                        diversity_penalty: 0.0,
                        score: reward + bonus,
                    },
                )
            })
            .collect();
        let mut used: BTreeMap<Option<&str>, usize> = BTreeMap::new();
        let mut ranked = Vec::new();
        while !remaining.is_empty() {
            for (_, route, rank) in &mut remaining {
                rank.diversity_penalty = used
                    .get(&route.failure_domain.as_deref())
                    .copied()
                    .unwrap_or(0) as f64
                    * self.config.diversity_penalty;
                rank.score = rank.window_reward + rank.ucb_bonus - rank.diversity_penalty;
            }
            // UCB's zero-trial case requires exploration, not a finite bonus
            // that a successful incumbent can exceed forever. Keep this as an
            // explicit phase so traces remain finite and JSON-serializable.
            // Admission and fresh hard blocks have already been checked; this
            // priority never creates or revives a forbidden route.
            remaining.sort_by(|a, b| {
                b.2.exploration_required
                    .cmp(&a.2.exploration_required)
                    .then_with(|| b.2.score.total_cmp(&a.2.score))
                    .then(a.0.cmp(&b.0))
            });
            let (_, route, rank) = remaining.remove(0);
            *used.entry(route.failure_domain.as_deref()).or_default() += 1;
            ranked.push(rank);
        }
        Ok(RecentSelection {
            order: ranked.iter().map(|r| r.strategy.clone()).collect(),
            ranked,
            scope: if self.config.paper_algorithm.is_some() {
                "Garivier-Moulines estimator over runtime-admitted routes; native rewards do not establish independent piecewise-stationary assumptions or regret guarantee"
            } else {
                "windowed runtime heuristic over admitted routes; no reachability, independence or regret guarantee"
            },
        })
    }
}

impl Brain {
    /// Opt-in selection; `eligible` must come from the existing policy/runtime
    /// admission gate. Preferred-order membership and current hard blocks are
    /// checked again; unknown or blocked strategies cannot be promoted.
    pub async fn select_recent_order(
        &self,
        key: &StrategyKey,
        selector: &mut RecentRouteSelector,
        eligible: &[EligibleRoute],
    ) -> Result<RecentSelection, String> {
        let baseline = self
            .select_order_trace_baseline(key)
            .await
            .reward_selected_order;
        self.select_recent_order_from_baseline(key, selector, eligible, &baseline)
            .await
    }

    pub(super) async fn select_recent_order_from_baseline(
        &self,
        key: &StrategyKey,
        selector: &mut RecentRouteSelector,
        eligible: &[EligibleRoute],
        baseline: &[String],
    ) -> Result<RecentSelection, String> {
        if eligible.len() > 64 {
            return Err("admitted route budget exceeded".into());
        }
        let mut unique = BTreeSet::new();
        for route in eligible {
            if !self.preferred_order.contains(&route.strategy) || !unique.insert(&route.strategy) {
                return Err("route not uniquely admitted by Brain configuration".into());
            }
        }
        let snapshot = self.state.snapshot().await;
        let context = super::context::decision_context_from_snapshot(&snapshot, key);
        let effective = super::observation::resolve_effective_key(&snapshot, key, None);
        let hash = key.hash_key();
        let effective_hash = effective.hash_key();
        let mut candidates = Vec::new();
        for strategy in baseline {
            let Some(route) = eligible.iter().find(|r| &r.strategy == strategy) else {
                continue;
            };
            let estimate = super::estimation::estimate_strategy(
                &snapshot,
                key,
                &effective,
                &hash,
                &effective_hash,
                strategy,
                &context,
            );
            if !estimate.belief.hard_blocked && estimate.reward.is_finite() {
                candidates.push((route.clone(), estimate.reward.clamp(0.0, 1.0)));
            }
        }
        selector.rank_at(Instant::now(), &hash, &candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selector() -> RecentRouteSelector {
        RecentRouteSelector::new(RecentRouteConfig {
            window: Duration::from_secs(10),
            paper_algorithm: None,
            max_observations: 32,
            diversity_penalty: 0.5,
        })
        .unwrap()
    }
    fn route(name: &str, domain: &str) -> (EligibleRoute, f64) {
        (
            EligibleRoute {
                strategy: name.into(),
                failure_domain: Some(domain.into()),
            },
            0.5,
        )
    }
    fn settings() -> RecentRoutesSettings {
        RecentRoutesSettings {
            window_ms: 60_000,
            paper_algorithm: None,
            max_observations: 64,
            diversity_penalty: 0.0,
            failure_domains: BTreeMap::new(),
        }
    }
    #[tokio::test]
    async fn paper_modes_consume_native_progress_and_retire_completed_history() {
        for algorithm in [
            PaperAlgorithm::SlidingWindow { rounds: 4, xi: 1.0 },
            PaperAlgorithm::Discounted {
                gamma: 0.8,
                xi: 1.0,
            },
        ] {
            let mut cfg = settings();
            cfg.paper_algorithm = Some(algorithm.clone());
            let brain = Brain::new(
                0.0,
                vec!["one".into(), "two".into()],
                crate::state_v2::AsyncStateStore::ephemeral(),
            )
            .with_recent_routes(Some(&cfg))
            .unwrap();
            let key = StrategyKey::for_dst(4);
            brain
                .record_outcome(
                    &key,
                    "one",
                    crate::signals::FailSignal::Success,
                    None,
                    0,
                    None,
                )
                .await;
            brain
                .record_outcome(
                    &key,
                    "two",
                    crate::signals::FailSignal::Success,
                    None,
                    128,
                    None,
                )
                .await;
            let trace = brain.select_order_trace(&key).await;
            assert!(trace.selector_mode.starts_with("garivier_moulines_"));
            let ranked = &trace.recent_selection.as_ref().unwrap().selection.ranked;
            assert_eq!(
                ranked
                    .iter()
                    .find(|r| r.strategy == "one")
                    .unwrap()
                    .window_reward,
                0.0
            );
            assert_eq!(
                ranked
                    .iter()
                    .find(|r| r.strategy == "two")
                    .unwrap()
                    .window_reward,
                1.0
            );
            // Only histories retire under capacity pressure. No route/transport
            // is stopped and the returning context starts a fresh estimator.
            for context in 1..=64 {
                let mut other_key = key.clone();
                other_key.target_host_hash = context;
                brain
                    .record_outcome(
                        &other_key,
                        "one",
                        crate::signals::FailSignal::Success,
                        None,
                        1,
                        None,
                    )
                    .await;
            }
            let returned = brain.select_order_trace(&key).await;
            assert!(!returned.reward_selected_order.is_empty());
            let recent = returned.recent_selection.unwrap();
            assert!(recent.selection_error.is_none());
            assert!(recent
                .selection
                .ranked
                .iter()
                .all(|arm| arm.window_trials == 0));
        }
    }
    #[tokio::test]
    async fn native_trace_uses_recorded_progress_and_keeps_baseline_evidence_separate() {
        use crate::signals::FailSignal;
        let store = crate::state_v2::AsyncStateStore::ephemeral();
        let preferred = vec!["one".into(), "two".into()];
        let baseline = Brain::new(0.0, preferred.clone(), store.clone());
        let recent = Brain::new(0.0, preferred, store)
            .with_recent_routes(Some(&settings()))
            .unwrap();
        let key = StrategyKey::for_dst(4);
        let before = recent.select_order_trace(&key).await;
        assert_eq!(before.reward_selected_order, vec!["one", "two"]);
        // A successful socket with no progress gets no recent success credit.
        recent
            .record_outcome(&key, "one", FailSignal::Success, None, 0, None)
            .await;
        recent
            .record_outcome(&key, "two", FailSignal::Success, None, 128, None)
            .await;
        let trace = recent.select_order_trace(&key).await;
        assert_eq!(trace.selector_mode, "recent_windowed_ucb_diversity");
        assert_eq!(trace.reward_selected_order, vec!["two", "one"]);
        let evidence = trace.recent_selection.unwrap();
        assert_eq!(evidence.selection.ranked[0].window_trials, 1);
        assert_eq!(evidence.selection.ranked[0].window_reward, 1.0);
        assert_eq!(evidence.selection.ranked[1].window_reward, 0.0);
        let default = baseline.select_order_trace(&key).await;
        assert!(default.recent_selection.is_none());
        assert_eq!(default.selector_mode, "ucb1_contextual_reward");
        assert_eq!(
            evidence.baseline_selected_order,
            default.reward_selected_order
        );
        assert_eq!(default.reward_selected_order, vec!["one", "two"]);
        assert_eq!(recent.select_order(&key).await, vec!["two", "one"]);
    }
    #[tokio::test]
    async fn removing_opt_in_restores_default_trace() {
        let store = crate::state_v2::AsyncStateStore::ephemeral();
        let brain = Brain::new(0.0, vec!["one".into()], store)
            .with_recent_routes(Some(&settings()))
            .unwrap()
            .with_recent_routes(None)
            .unwrap();
        assert!(!brain.recent_routes_enabled());
        let trace = brain.select_order_trace(&StrategyKey::for_dst(4)).await;
        assert!(trace.recent_selection.is_none());
        assert_eq!(trace.selector_mode, "ucb1_contextual_reward");
    }
    #[test]
    fn expires_stale_failures_and_diversifies_without_creating_routes() {
        let mut s = selector();
        let now = Instant::now();
        s.record_at(now, "context", "a", 0.0).unwrap();
        let routes = [route("a", "same"), route("b", "same"), route("c", "other")];
        let old = s
            .rank_at(now + Duration::from_secs(11), "context", &routes)
            .unwrap();
        assert_eq!(old.order, vec!["a", "c", "b"]);
        assert_eq!(old.ranked[0].window_trials, 0);
        assert_eq!(old.ranked[0].window_reward, 0.5);
        assert!(s.record("context", "a", f64::NAN).is_err());
    }
    #[test]
    fn unobserved_route_is_not_starved_by_a_successful_bounded_incumbent() {
        let mut s = selector();
        let now = Instant::now();
        // A finite prior + 1 cold-start bonus never overtakes this incumbent,
        // even after infinitely many plays with the bounded history full.
        for _ in 0..64 {
            s.record_at(now, "context", "incumbent", 1.0).unwrap();
        }
        let mut cold = route("cold", "other");
        cold.1 = 0.0;
        let routes = [route("incumbent", "owned"), cold];
        for _ in 0..64 {
            let selection = s.rank_at(now, "context", &routes).unwrap();
            assert_eq!(selection.order, vec!["cold", "incumbent"]);
            assert_eq!(selection.ranked[0].window_trials, 0);
            assert!(selection.ranked[0].exploration_required);
            assert_eq!(selection.ranked[0].ucb_bonus, 0.0);
            assert_eq!(selection.ranked[1].window_trials, 32);
            assert!(!selection.ranked[1].exploration_required);
            assert!(selection.ranked.iter().all(|rank| rank.score.is_finite()));
            serde_json::to_value(&selection).unwrap();
            s.record_at(now, "context", "incumbent", 1.0).unwrap();
        }
    }
    #[test]
    fn expired_route_is_reexplored_before_a_recent_incumbent() {
        let mut s = selector();
        let now = Instant::now();
        s.record_at(now, "context", "expired", 0.0).unwrap();
        s.record_at(now + Duration::from_secs(9), "context", "incumbent", 1.0)
            .unwrap();
        let mut expired = route("expired", "other");
        expired.1 = 0.0;
        let selection = s
            .rank_at(
                now + Duration::from_secs(11),
                "context",
                &[route("incumbent", "owned"), expired],
            )
            .unwrap();
        assert_eq!(selection.order, vec!["expired", "incumbent"]);
        assert_eq!(selection.ranked[0].window_trials, 0);
        assert_eq!(selection.ranked[1].window_trials, 1);
    }
    #[test]
    fn domain_penalty_does_not_remove_the_cold_route_exploration_phase() {
        let mut s = selector();
        let now = Instant::now();
        s.record_at(now, "context", "incumbent", 1.0).unwrap();
        let mut cold_high = route("cold-high", "shared");
        cold_high.1 = 1.0;
        let mut cold_low = route("cold-low", "shared");
        cold_low.1 = 0.0;
        let selection = s
            .rank_at(
                now,
                "context",
                &[route("incumbent", "owned"), cold_high, cold_low],
            )
            .unwrap();
        assert_eq!(selection.order, vec!["cold-high", "cold-low", "incumbent"]);
        assert_eq!(selection.ranked[1].diversity_penalty, 0.5);
    }
    #[tokio::test]
    async fn native_recent_order_explores_then_uses_verified_outcome() {
        let brain = Brain::new(
            0.0,
            vec!["incumbent".into(), "cold".into()],
            crate::state_v2::AsyncStateStore::ephemeral(),
        );
        let key = StrategyKey::for_dst(4);
        // Older baseline failures may still supply a low prior, but do not
        // count as evidence inside a newly enabled recent window.
        for _ in 0..64 {
            brain
                .record_fail(&key, "cold", crate::signals::FailSignal::Timeout, 1, 0)
                .await;
        }
        let brain = brain.with_recent_routes(Some(&settings())).unwrap();
        for _ in 0..64 {
            brain.record_success(&key, "incumbent", 1, 128).await;
        }
        let before = brain.select_order_trace(&key).await;
        assert_eq!(before.reward_selected_order, vec!["cold", "incumbent"]);
        let recent = before.recent_selection.unwrap().selection;
        assert_eq!(recent.ranked[0].window_trials, 0);
        assert_eq!(recent.ranked[1].window_trials, 64);
        // The cold route's verified failure ends required exploration. The
        // observed score can then put the working incumbent first again.
        for _ in 0..16 {
            brain
                .record_fail(&key, "cold", crate::signals::FailSignal::Timeout, 1, 0)
                .await;
        }
        assert_eq!(brain.select_order(&key).await, vec!["incumbent", "cold"]);
    }
    #[tokio::test]
    async fn actual_brain_refuses_unknown_and_excludes_unadmitted() {
        let brain = Brain::new(
            0.0,
            vec!["one".into(), "two".into()],
            crate::state_v2::AsyncStateStore::ephemeral(),
        );
        let key = StrategyKey::for_dst(4);
        let mut s = selector();
        let selected = brain
            .select_recent_order(&key, &mut s, &[route("two", "owned").0])
            .await
            .unwrap();
        assert_eq!(selected.order, vec!["two"]);
        assert!(brain
            .select_recent_order(&key, &mut s, &[route("unknown", "owned").0])
            .await
            .is_err());
    }
    #[tokio::test]
    async fn randomized_baseline_cannot_restore_current_hard_block() {
        let store = crate::state_v2::AsyncStateStore::ephemeral();
        store
            .update(|snapshot| {
                snapshot.external_calibration = Some(crate::ExternalCalibrationSnapshot {
                    schema_version: 1,
                    source: "controlled_test".into(),
                    generated_at_unix_ms: None,
                    freshness_half_life_secs: None,
                    witness: Vec::new(),
                    adversarial: Vec::new(),
                    knowledge: vec![crate::ExternalKnowledgePrior {
                        target_class: "https_ws".into(),
                        region_id: None,
                        score: 0.0,
                        confidence: 0.9,
                        hard_excluded: true,
                        fail_closed: true,
                        generated_at_unix_ms: None,
                    }],
                    verdict: crate::ExternalCalibrationVerdict {
                        status: "MEASURED".into(),
                        acceptance_degraded: false,
                        reasons: Vec::new(),
                    },
                });
            })
            .await;
        let brain = Brain::new(1.0, vec!["https_ws".into(), "legacy_tls".into()], store)
            .with_recent_routes(Some(&settings()))
            .unwrap();
        let key = StrategyKey::for_target(
            "203.0.113.1:443".parse().unwrap(),
            "example.org",
            443,
            Some("example.org"),
            true,
        );
        let mut recent = selector();
        let selection = brain
            .select_recent_order(
                &key,
                &mut recent,
                &[
                    route("https_ws", "shared").0,
                    route("legacy_tls", "shared").0,
                ],
            )
            .await
            .unwrap();
        assert_eq!(selection.order, vec!["legacy_tls"]);
        let trace = brain.select_order_trace(&key).await;
        assert_eq!(trace.reward_selected_order, vec!["legacy_tls"]);
        assert_eq!(
            trace.recent_selection.unwrap().baseline_selector_mode,
            "epsilon_randomized_preferred_order"
        );
    }
}

#[cfg(test)]
#[path = "recent_routes/retirement_tests.rs"]
mod retirement_tests;
