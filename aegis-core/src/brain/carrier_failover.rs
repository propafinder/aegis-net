//! Ordered carrier failover for one admitted relay profile (carrier-program D3).
//!
//! The candidate list is the profile's explicit, ordered carrier pool (for a
//! device-enrolled profile: numeric relay pins such as a direct H2 relay
//! followed by a CDN edge). This module keeps, per access network, a circuit
//! breaker for each candidate and turns it into an attempt order:
//!
//! - closed carriers first, in profile order, so the preferred carrier wins
//!   whenever it is usable;
//! - a carrier whose cooldown expired is retried as a single-flight trial
//!   ahead of the fallback, so traffic returns to the preferred carrier after
//!   it recovers, while concurrent sessions keep using the fallback;
//! - carriers in cooldown are kept as a last resort, never removed, so stale
//!   state cannot by itself cause an outage.
//!
//! It is pure and deterministic: callers supply the clock and the network
//! identity. It never adds a carrier, authorizes a destination, chooses a
//! transport family or produces a native-egress outcome. When every carrier
//! fails, the caller's existing fail-closed terminal applies unchanged.
//! Pre-authentication signals may advance the same session to the next
//! carrier; post-authentication signals only affect later sessions because an
//! authenticated stream is never replayed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Upper bound on the explicit candidate list (matches the relay pool bound).
pub const MAX_CARRIERS: usize = 16;

fn default_base_cooldown_ms() -> u64 {
    5_000
}
fn default_max_cooldown_ms() -> u64 {
    300_000
}
fn default_degraded_threshold() -> u8 {
    2
}
fn default_liveness_interval_ms() -> u64 {
    20_000
}
fn default_liveness_timeout_ms() -> u64 {
    10_000
}
fn default_collapse_rtt_ms() -> u64 {
    4_000
}
fn default_max_networks() -> u16 {
    16
}

/// Public, digest-bound failover policy. Every field has a conservative
/// default, so `{}` is the default policy. Unknown fields are refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierFailoverSettings {
    /// First cooldown after a blocking signal; doubles per consecutive failure.
    #[serde(default = "default_base_cooldown_ms")]
    pub base_cooldown_ms: u64,
    /// Cooldown ceiling. Bounds both the backoff and the recovery delay.
    #[serde(default = "default_max_cooldown_ms")]
    pub max_cooldown_ms: u64,
    /// Consecutive post-authentication degradations (freeze, collapse,
    /// carrier reset) that open the breaker for later sessions.
    #[serde(default = "default_degraded_threshold")]
    pub degraded_threshold: u8,
    /// Period of the outer HTTP/2 PING liveness probe on an open session.
    /// `0` disables the probe (no post-authentication freeze detection).
    #[serde(default = "default_liveness_interval_ms")]
    pub liveness_interval_ms: u64,
    /// A PING without PONG for this long is a session freeze; the frozen
    /// session is closed (never replayed) so its owner reconnects.
    #[serde(default = "default_liveness_timeout_ms")]
    pub liveness_timeout_ms: u64,
    /// A PONG slower than this is a throughput-collapse signal.
    #[serde(default = "default_collapse_rtt_ms")]
    pub collapse_rtt_ms: u64,
    /// Bounded per-network memory (least recently used network is evicted).
    #[serde(default = "default_max_networks")]
    pub max_networks: u16,
}

impl Default for CarrierFailoverSettings {
    fn default() -> Self {
        Self {
            base_cooldown_ms: default_base_cooldown_ms(),
            max_cooldown_ms: default_max_cooldown_ms(),
            degraded_threshold: default_degraded_threshold(),
            liveness_interval_ms: default_liveness_interval_ms(),
            liveness_timeout_ms: default_liveness_timeout_ms(),
            collapse_rtt_ms: default_collapse_rtt_ms(),
            max_networks: default_max_networks(),
        }
    }
}

impl CarrierFailoverSettings {
    pub fn validate(&self) -> Result<(), String> {
        if !(100..=60_000).contains(&self.base_cooldown_ms)
            || !(self.base_cooldown_ms..=3_600_000).contains(&self.max_cooldown_ms)
            || !(1..=8).contains(&self.degraded_threshold)
            || !(self.liveness_interval_ms == 0
                || (100..=300_000).contains(&self.liveness_interval_ms))
            || !(100..=60_000).contains(&self.liveness_timeout_ms)
            || !(50..self.liveness_timeout_ms).contains(&self.collapse_rtt_ms)
            || !(1..=64).contains(&self.max_networks)
        {
            return Err("carrier failover policy is outside its bounds".into());
        }
        Ok(())
    }

    pub fn liveness_enabled(&self) -> bool {
        self.liveness_interval_ms > 0
    }

    fn cooldown(&self, level: u8) -> Duration {
        let factor = 1u64.checked_shl(u32::from(level)).unwrap_or(u64::MAX);
        Duration::from_millis(
            self.base_cooldown_ms
                .saturating_mul(factor)
                .min(self.max_cooldown_ms),
        )
    }
}

/// Opaque identity of the current access network. Platforms derive it from
/// local routing facts with a per-process salt; nothing reversible is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetworkKey([u8; 16]);

impl NetworkKey {
    /// No usable routing observation: all sessions share one memory.
    pub const UNKNOWN: Self = Self([0; 16]);

    pub fn derive(salt: &[u8; 32], parts: &[&[u8]]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"aegis.carrier-failover.network.v1\0");
        hash.update(salt);
        for part in parts {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        let digest = hash.finalize();
        let mut key = [0; 16];
        key.copy_from_slice(&digest[..16]);
        if key == [0; 16] {
            key[0] = 1;
        }
        Self(key)
    }

    /// Short non-reversible label for events (first four bytes).
    pub fn label(&self) -> String {
        if *self == Self::UNKNOWN {
            return "unknown".into();
        }
        hex::encode(&self.0[..4])
    }
}

/// A carrier-health signal. The first five occur before any device identity,
/// invitation or target is sent, so the same session may move on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierSignal {
    /// TCP dial did not complete (SYN dropped or black-holed).
    DialTimeout,
    /// TCP dial refused or unreachable.
    DialRefused,
    /// Outer TLS handshake reset or cut (for example RST after ClientHello or
    /// an SNI-triggered reset). Certificate failures are not this signal.
    HandshakeReset,
    /// Outer carrier did not reach inner authentication in time (slow-loris,
    /// throughput collapse during establishment).
    EstablishmentTimeout,
    /// Edge or origin answered the carrier request with a non-200 status.
    EdgeRefused,
    /// Open session: PING without PONG within the liveness timeout.
    SessionFreeze,
    /// Open session: PONG slower than the collapse threshold.
    ThroughputCollapse,
    /// Open session: the outer carrier connection failed (reset, cut).
    SessionReset,
}

impl CarrierSignal {
    pub const fn pre_auth(self) -> bool {
        matches!(
            self,
            Self::DialTimeout
                | Self::DialRefused
                | Self::HandshakeReset
                | Self::EstablishmentTimeout
                | Self::EdgeRefused
        )
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DialTimeout => "dial_timeout",
            Self::DialRefused => "dial_refused",
            Self::HandshakeReset => "handshake_reset",
            Self::EstablishmentTimeout => "establishment_timeout",
            Self::EdgeRefused => "edge_refused",
            Self::SessionFreeze => "session_freeze",
            Self::ThroughputCollapse => "throughput_collapse",
            Self::SessionReset => "session_reset",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierOutcome {
    /// Outer carrier and inner device authentication opened the session.
    Opened,
    /// The open session ended cleanly with response bytes and no liveness
    /// complaint. Clears post-authentication degradation.
    Healthy,
    Failed(CarrierSignal),
    /// Nothing about carrier health was learned (local, identity or target
    /// refusal). Releases a reserved recovery trial.
    Neutral,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarrierPlan {
    /// Every carrier exactly once: usable carriers in profile order, then
    /// carriers in cooldown (last resort).
    pub order: Vec<usize>,
    /// A cooled-down carrier reserved for one recovery attempt by this plan.
    pub trial: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CarrierTransition {
    CooldownStarted {
        carrier: usize,
        signal: CarrierSignal,
        cooldown: Duration,
    },
    ActiveSwitched {
        from: Option<usize>,
        to: usize,
    },
    Recovered {
        carrier: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierState {
    Closed,
    Cooling { remaining: Duration },
    TrialReady,
    TrialInFlight,
}

#[derive(Clone, Debug, Default)]
struct Breaker {
    level: u8,
    degraded: u8,
    open_until: Option<Instant>,
    trial: bool,
    last_signal: Option<CarrierSignal>,
}

#[derive(Clone, Debug)]
struct NetworkState {
    key: NetworkKey,
    breakers: Vec<Breaker>,
    active: Option<usize>,
    touched: Instant,
}

#[derive(Clone, Debug)]
pub struct CarrierFailover {
    settings: CarrierFailoverSettings,
    carriers: usize,
    networks: Vec<NetworkState>,
}

impl CarrierFailover {
    pub fn new(settings: CarrierFailoverSettings, carriers: usize) -> Result<Self, String> {
        settings.validate()?;
        if !(1..=MAX_CARRIERS).contains(&carriers) {
            return Err("carrier failover requires 1 to 16 ordered carriers".into());
        }
        Ok(Self {
            settings,
            carriers,
            networks: Vec::new(),
        })
    }

    pub fn settings(&self) -> &CarrierFailoverSettings {
        &self.settings
    }

    pub fn carriers(&self) -> usize {
        self.carriers
    }

    fn network(&mut self, key: NetworkKey, now: Instant) -> &mut NetworkState {
        if let Some(index) = self.networks.iter().position(|n| n.key == key) {
            let state = &mut self.networks[index];
            state.touched = now;
            return state;
        }
        if self.networks.len() >= usize::from(self.settings.max_networks) {
            if let Some((oldest, _)) = self
                .networks
                .iter()
                .enumerate()
                .min_by_key(|(_, n)| n.touched)
            {
                self.networks.swap_remove(oldest);
            }
        }
        self.networks.push(NetworkState {
            key,
            breakers: vec![Breaker::default(); self.carriers],
            active: None,
            touched: now,
        });
        self.networks.last_mut().expect("just inserted")
    }

    /// Attempt order for one session on `network`. A returned `trial` is
    /// reserved until the caller records an outcome for that carrier (a
    /// `Neutral` outcome releases it without changing its state).
    pub fn plan(&mut self, network: NetworkKey, now: Instant) -> CarrierPlan {
        let carriers = self.carriers;
        let state = self.network(network, now);
        let mut usable = Vec::with_capacity(carriers);
        let mut last_resort = Vec::new();
        let mut trial = None;
        for (index, breaker) in state.breakers.iter_mut().enumerate() {
            match breaker.open_until {
                None => usable.push(index),
                Some(until) if now < until => last_resort.push((until, index)),
                Some(_) if breaker.trial => last_resort.push((now, index)),
                Some(_) => {
                    if usable.is_empty() && trial.is_none() {
                        // The most preferred usable candidate is recovering:
                        // one session probes it before the fallback.
                        breaker.trial = true;
                        trial = Some(index);
                    }
                    usable.push(index);
                }
            }
        }
        last_resort.sort();
        usable.extend(last_resort.into_iter().map(|(_, index)| index));
        CarrierPlan {
            order: usable,
            trial,
        }
    }

    /// Record one outcome. Out-of-range carriers are ignored.
    pub fn record(
        &mut self,
        network: NetworkKey,
        carrier: usize,
        outcome: CarrierOutcome,
        now: Instant,
    ) -> Vec<CarrierTransition> {
        if carrier >= self.carriers {
            return Vec::new();
        }
        let settings = self.settings.clone();
        let state = self.network(network, now);
        let mut transitions = Vec::new();
        let breaker = &mut state.breakers[carrier];
        match outcome {
            CarrierOutcome::Neutral => breaker.trial = false,
            CarrierOutcome::Healthy => {
                breaker.trial = false;
                breaker.degraded = 0;
            }
            CarrierOutcome::Opened => {
                let was_open = breaker.open_until.is_some();
                breaker.trial = false;
                breaker.open_until = None;
                breaker.level = 0;
                if was_open {
                    transitions.push(CarrierTransition::Recovered { carrier });
                }
                if state.active != Some(carrier) {
                    transitions.push(CarrierTransition::ActiveSwitched {
                        from: state.active,
                        to: carrier,
                    });
                    state.active = Some(carrier);
                }
            }
            CarrierOutcome::Failed(signal) => {
                breaker.trial = false;
                breaker.last_signal = Some(signal);
                let open = if signal.pre_auth() {
                    true
                } else {
                    breaker.degraded = breaker.degraded.saturating_add(1);
                    breaker.degraded >= settings.degraded_threshold
                };
                if open {
                    let cooldown = settings.cooldown(breaker.level);
                    breaker.level = breaker.level.saturating_add(1).min(32);
                    breaker.degraded = 0;
                    breaker.open_until = now.checked_add(cooldown).or(Some(now));
                    transitions.push(CarrierTransition::CooldownStarted {
                        carrier,
                        signal,
                        cooldown,
                    });
                    if state.active == Some(carrier) {
                        state.active = None;
                    }
                }
            }
        }
        transitions
    }

    pub fn active(&self, network: NetworkKey) -> Option<usize> {
        self.networks
            .iter()
            .find(|n| n.key == network)
            .and_then(|n| n.active)
    }

    pub fn state(&self, network: NetworkKey, carrier: usize, now: Instant) -> CarrierState {
        let Some(breaker) = self
            .networks
            .iter()
            .find(|n| n.key == network)
            .and_then(|n| n.breakers.get(carrier))
        else {
            return CarrierState::Closed;
        };
        match breaker.open_until {
            None => CarrierState::Closed,
            Some(until) if now < until => CarrierState::Cooling {
                remaining: until - now,
            },
            Some(_) if breaker.trial => CarrierState::TrialInFlight,
            Some(_) => CarrierState::TrialReady,
        }
    }

    pub fn last_signal(&self, network: NetworkKey, carrier: usize) -> Option<CarrierSignal> {
        self.networks
            .iter()
            .find(|n| n.key == network)
            .and_then(|n| n.breakers.get(carrier))
            .and_then(|b| b.last_signal)
    }

    pub fn remembered_networks(&self) -> usize {
        self.networks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> CarrierFailoverSettings {
        CarrierFailoverSettings {
            base_cooldown_ms: 1_000,
            max_cooldown_ms: 8_000,
            degraded_threshold: 2,
            max_networks: 2,
            ..Default::default()
        }
    }

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[test]
    fn defaults_validate_parse_from_empty_object_and_refuse_unknown_fields() {
        let parsed: CarrierFailoverSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, CarrierFailoverSettings::default());
        parsed.validate().unwrap();
        assert!(
            serde_json::from_str::<CarrierFailoverSettings>(r#"{"fallback":"native"}"#).is_err()
        );
        let round: CarrierFailoverSettings =
            serde_json::from_value(serde_json::to_value(&parsed).unwrap()).unwrap();
        assert_eq!(round, parsed);
    }

    #[test]
    fn out_of_bounds_policies_and_carrier_counts_refuse() {
        let base = CarrierFailoverSettings::default();
        for broken in [
            CarrierFailoverSettings {
                base_cooldown_ms: 0,
                ..base.clone()
            },
            CarrierFailoverSettings {
                max_cooldown_ms: base.base_cooldown_ms - 1,
                ..base.clone()
            },
            CarrierFailoverSettings {
                degraded_threshold: 0,
                ..base.clone()
            },
            CarrierFailoverSettings {
                liveness_interval_ms: 50,
                ..base.clone()
            },
            CarrierFailoverSettings {
                collapse_rtt_ms: base.liveness_timeout_ms,
                ..base.clone()
            },
            CarrierFailoverSettings {
                max_networks: 0,
                ..base.clone()
            },
        ] {
            assert!(broken.validate().is_err(), "{broken:?}");
            assert!(CarrierFailover::new(broken, 2).is_err());
        }
        assert!(CarrierFailover::new(base.clone(), 0).is_err());
        assert!(CarrierFailover::new(base.clone(), MAX_CARRIERS + 1).is_err());
        assert!(CarrierFailover::new(
            CarrierFailoverSettings {
                liveness_interval_ms: 0,
                ..base
            },
            MAX_CARRIERS
        )
        .is_ok());
    }

    #[test]
    fn fresh_network_uses_profile_order_without_trial() {
        let mut brain = CarrierFailover::new(policy(), 3).unwrap();
        let plan = brain.plan(NetworkKey::UNKNOWN, Instant::now());
        assert_eq!(plan.order, vec![0, 1, 2]);
        assert_eq!(plan.trial, None);
    }

    #[test]
    fn pre_auth_block_moves_carrier_to_last_resort_until_cooldown_expires() {
        let mut brain = CarrierFailover::new(policy(), 3).unwrap();
        let net = NetworkKey::UNKNOWN;
        let t0 = Instant::now();
        let transitions = brain.record(
            net,
            0,
            CarrierOutcome::Failed(CarrierSignal::DialTimeout),
            t0,
        );
        assert_eq!(
            transitions,
            vec![CarrierTransition::CooldownStarted {
                carrier: 0,
                signal: CarrierSignal::DialTimeout,
                cooldown: ms(1_000)
            }]
        );
        let plan = brain.plan(net, t0 + ms(10));
        assert_eq!(plan.order, vec![1, 2, 0], "blocked carrier is last resort");
        assert_eq!(plan.trial, None);
        assert_eq!(
            brain.record(net, 1, CarrierOutcome::Opened, t0 + ms(20)),
            vec![CarrierTransition::ActiveSwitched { from: None, to: 1 }]
        );
        assert_eq!(brain.active(net), Some(1));
        assert!(matches!(
            brain.state(net, 0, t0 + ms(30)),
            CarrierState::Cooling { .. }
        ));
    }

    #[test]
    fn expired_preferred_carrier_gets_one_single_flight_trial_then_recovers() {
        let mut brain = CarrierFailover::new(policy(), 2).unwrap();
        let net = NetworkKey::UNKNOWN;
        let t0 = Instant::now();
        brain.record(
            net,
            0,
            CarrierOutcome::Failed(CarrierSignal::HandshakeReset),
            t0,
        );
        brain.record(net, 1, CarrierOutcome::Opened, t0);
        let after = t0 + ms(1_001);
        let first = brain.plan(net, after);
        assert_eq!(first.order, vec![0, 1]);
        assert_eq!(first.trial, Some(0));
        // A concurrent session must not pile onto the recovering carrier.
        let concurrent = brain.plan(net, after);
        assert_eq!(concurrent.order, vec![1, 0]);
        assert_eq!(concurrent.trial, None);
        assert_eq!(brain.state(net, 0, after), CarrierState::TrialInFlight);
        let transitions = brain.record(net, 0, CarrierOutcome::Opened, after);
        assert_eq!(
            transitions,
            vec![
                CarrierTransition::Recovered { carrier: 0 },
                CarrierTransition::ActiveSwitched {
                    from: Some(1),
                    to: 0
                }
            ]
        );
        assert_eq!(brain.plan(net, after).order, vec![0, 1]);
        assert_eq!(brain.state(net, 0, after), CarrierState::Closed);
    }

    #[test]
    fn failed_trials_back_off_exponentially_and_cap_at_the_maximum() {
        let mut brain = CarrierFailover::new(policy(), 2).unwrap();
        let net = NetworkKey::UNKNOWN;
        let mut now = Instant::now();
        let mut observed = Vec::new();
        for _ in 0..6 {
            let plan = brain.plan(net, now);
            let transitions = brain.record(
                net,
                0,
                CarrierOutcome::Failed(CarrierSignal::DialTimeout),
                now,
            );
            let CarrierTransition::CooldownStarted { cooldown, .. } = transitions[0] else {
                panic!("{transitions:?}");
            };
            observed.push((plan.trial, cooldown.as_millis()));
            now += cooldown + ms(1);
        }
        assert_eq!(
            observed,
            vec![
                (None, 1_000),
                (Some(0), 2_000),
                (Some(0), 4_000),
                (Some(0), 8_000),
                (Some(0), 8_000),
                (Some(0), 8_000)
            ]
        );
        brain.record(net, 0, CarrierOutcome::Opened, now);
        let transitions = brain.record(
            net,
            0,
            CarrierOutcome::Failed(CarrierSignal::EdgeRefused),
            now,
        );
        assert!(matches!(
            transitions[0],
            CarrierTransition::CooldownStarted { cooldown, .. } if cooldown == ms(1_000)
        ));
    }

    #[test]
    fn neutral_outcome_releases_a_reserved_trial_without_changing_health() {
        let mut brain = CarrierFailover::new(policy(), 2).unwrap();
        let net = NetworkKey::UNKNOWN;
        let t0 = Instant::now();
        brain.record(
            net,
            0,
            CarrierOutcome::Failed(CarrierSignal::DialRefused),
            t0,
        );
        let later = t0 + ms(1_500);
        assert_eq!(brain.plan(net, later).trial, Some(0));
        assert!(brain
            .record(net, 0, CarrierOutcome::Neutral, later)
            .is_empty());
        assert_eq!(brain.state(net, 0, later), CarrierState::TrialReady);
        assert_eq!(brain.plan(net, later).trial, Some(0));
    }

    #[test]
    fn post_auth_degradation_opens_only_after_the_threshold_and_healthy_clears_it() {
        let mut brain = CarrierFailover::new(policy(), 2).unwrap();
        let net = NetworkKey::UNKNOWN;
        let t0 = Instant::now();
        brain.record(net, 0, CarrierOutcome::Opened, t0);
        assert!(brain
            .record(
                net,
                0,
                CarrierOutcome::Failed(CarrierSignal::SessionFreeze),
                t0
            )
            .is_empty());
        assert_eq!(brain.plan(net, t0).order, vec![0, 1]);
        // An intervening open does not erase the degradation count ...
        brain.record(net, 0, CarrierOutcome::Opened, t0);
        let transitions = brain.record(
            net,
            0,
            CarrierOutcome::Failed(CarrierSignal::ThroughputCollapse),
            t0,
        );
        assert!(matches!(
            transitions[0],
            CarrierTransition::CooldownStarted {
                signal: CarrierSignal::ThroughputCollapse,
                ..
            }
        ));
        assert_eq!(brain.active(net), None);
        assert_eq!(brain.plan(net, t0).order, vec![1, 0]);
        // ... but a healthy session end does.
        let mut fresh = CarrierFailover::new(policy(), 2).unwrap();
        fresh.record(
            net,
            0,
            CarrierOutcome::Failed(CarrierSignal::SessionReset),
            t0,
        );
        fresh.record(net, 0, CarrierOutcome::Healthy, t0);
        assert!(fresh
            .record(
                net,
                0,
                CarrierOutcome::Failed(CarrierSignal::SessionReset),
                t0
            )
            .is_empty());
        assert_eq!(fresh.plan(net, t0).order, vec![0, 1]);
    }

    #[test]
    fn every_carrier_stays_in_the_plan_when_all_are_cooling() {
        let mut brain = CarrierFailover::new(policy(), 3).unwrap();
        let net = NetworkKey::UNKNOWN;
        let t0 = Instant::now();
        for (carrier, delay) in [(2, 0), (0, 100), (1, 200)] {
            brain.record(
                net,
                carrier,
                CarrierOutcome::Failed(CarrierSignal::DialTimeout),
                t0 + ms(delay),
            );
        }
        let plan = brain.plan(net, t0 + ms(300));
        assert_eq!(plan.order, vec![2, 0, 1], "soonest expiry first");
        assert_eq!(plan.trial, None);
    }

    #[test]
    fn memory_is_per_network_and_bounded_least_recently_used() {
        let mut brain = CarrierFailover::new(policy(), 2).unwrap();
        let salt = [7; 32];
        let home = NetworkKey::derive(&salt, &[b"eth0", b"192.0.2.1", b"aa:bb"]);
        let office = NetworkKey::derive(&salt, &[b"wlan0", b"198.51.100.1", b"cc:dd"]);
        let cafe = NetworkKey::derive(&salt, &[b"wlan0", b"203.0.113.1", b"ee:ff"]);
        assert_ne!(home, office);
        assert_ne!(home, NetworkKey::UNKNOWN);
        assert_eq!(home.label().len(), 8);
        let t0 = Instant::now();
        brain.record(
            home,
            0,
            CarrierOutcome::Failed(CarrierSignal::HandshakeReset),
            t0,
        );
        assert_eq!(brain.plan(office, t0 + ms(1)).order, vec![0, 1]);
        assert_eq!(brain.plan(home, t0 + ms(2)).order, vec![1, 0]);
        // Office is now least recently used and is evicted for the cafe.
        assert_eq!(brain.plan(cafe, t0 + ms(3)).order, vec![0, 1]);
        assert_eq!(brain.remembered_networks(), 2);
        assert_eq!(brain.plan(home, t0 + ms(4)).order, vec![1, 0]);
        assert_eq!(
            brain.last_signal(home, 0),
            Some(CarrierSignal::HandshakeReset)
        );
        assert_eq!(brain.last_signal(office, 0), None);
    }

    #[test]
    fn signal_classes_and_out_of_range_records_are_explicit() {
        for signal in [
            CarrierSignal::DialTimeout,
            CarrierSignal::DialRefused,
            CarrierSignal::HandshakeReset,
            CarrierSignal::EstablishmentTimeout,
            CarrierSignal::EdgeRefused,
        ] {
            assert!(signal.pre_auth(), "{}", signal.as_str());
        }
        for signal in [
            CarrierSignal::SessionFreeze,
            CarrierSignal::ThroughputCollapse,
            CarrierSignal::SessionReset,
        ] {
            assert!(!signal.pre_auth(), "{}", signal.as_str());
        }
        let mut brain = CarrierFailover::new(policy(), 2).unwrap();
        assert!(brain
            .record(
                NetworkKey::UNKNOWN,
                5,
                CarrierOutcome::Failed(CarrierSignal::DialTimeout),
                Instant::now()
            )
            .is_empty());
        assert_eq!(brain.remembered_networks(), 0);
    }
}
