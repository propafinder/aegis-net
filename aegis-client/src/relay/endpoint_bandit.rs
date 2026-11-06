//! Explicit admitted numeric-pool learning, no probing or authentication replay.
use super::EffectiveRelayEndpoint;
use aegis_core::brain::recent_routes::paper_bandit::PaperBandit;
use aegis_core::{RelayEndpointBanditSettings, RelaySettings};
use anyhow::{ensure, Context};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::{Duration, Instant};

const MAX_TOTAL_CONTEXTS: usize = 64;
type Contexts = BTreeMap<[u8; 32], Arc<Mutex<ContextState>>>;
#[derive(Default)]
struct Registry {
    profiles: BTreeMap<[u8; 32], Contexts>,
}
struct ContextState {
    estimator: PaperBandit,
    blocked: BTreeMap<String, Instant>,
    failed: bool,
}
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

pub(super) struct Selection {
    state: Arc<Mutex<ContextState>>,
    pool: Vec<EffectiveRelayEndpoint>,
    config: RelayEndpointBanditSettings,
    baseline_eligible: OnceLock<Vec<usize>>,
    identity: Arc<Identity>,
    deadline: tokio::time::Instant,
}
#[derive(Clone)]
pub(super) struct Attempt {
    state: Arc<Mutex<ContextState>>,
    arm: String,
    cooldown: Duration,
    observed: Arc<AtomicBool>,
    application: Arc<AtomicU8>,
    identity: Arc<Identity>,
    deadline: tokio::time::Instant,
}

struct Identity {
    settings: RelaySettings,
    digest: [u8; 32],
}

fn profile_identity(settings: &RelaySettings) -> anyhow::Result<[u8; 32]> {
    let bytes = serde_json::to_vec(settings)?;
    ensure!(
        bytes.len() <= 65536,
        "endpoint bandit profile exceeds bounded identity envelope"
    );
    let mut hash = Sha256::new();
    hash.update(b"aegis.endpoint-paper-bandit.profile.v1\0");
    hash.update(bytes);
    let inner = settings
        .inner_tls
        .as_ref()
        .context("endpoint bandit requires device TLS")?;
    for path in [
        settings
            .ca_cert
            .as_deref()
            .context("endpoint bandit requires outer CA")?,
        inner.server_ca.as_path(),
        inner.cert.as_path(),
    ] {
        hash.update(
            aegis_core::secure_channel::public_certificate_chain_sha256(path)
                .context("endpoint bandit public certificate identity rejected")?,
        );
    }
    Ok(hash.finalize().into())
}

pub(super) fn prepare(
    settings: &RelaySettings,
    host: &str,
    port: u16,
    transport: &'static str,
) -> anyhow::Result<Option<Selection>> {
    prepare_at(settings, host, port, transport, None)
}
pub(super) fn prepare_at(
    settings: &RelaySettings,
    host: &str,
    port: u16,
    transport: &'static str,
    origin: Option<tokio::time::Instant>,
) -> anyhow::Result<Option<Selection>> {
    let Some(config) = &settings.endpoint_bandit else {
        return Ok(None);
    };
    let deadline = origin
        .unwrap_or_else(tokio::time::Instant::now)
        .checked_add(Duration::from_millis(settings.connect_timeout_ms))
        .context("endpoint establishment clock overflow")?;
    settings
        .validate_inner_tls_transport()
        .map_err(anyhow::Error::msg)?;
    ensure!(
        !host.is_empty()
            && host.len() <= 253
            && port > 0
            && !host.chars().any(|c| c.is_whitespace() || c.is_control()),
        "endpoint bandit target context exceeds bounds"
    );
    ensure!(
        tokio::time::Instant::now() < deadline,
        "endpoint admission exceeded establishment deadline before public identity"
    );
    let identity = profile_identity(settings)?;
    ensure!(
        tokio::time::Instant::now() < deadline,
        "endpoint public identity exceeded establishment deadline"
    );
    let mut hash = Sha256::new();
    hash.update(b"aegis.endpoint-paper-bandit.context.v1\0");
    hash.update(transport.as_bytes());
    hash.update([0]);
    hash.update(host.as_bytes());
    hash.update(port.to_be_bytes());
    let context: [u8; 32] = hash.finalize().into();
    let mut registry = REGISTRY
        .get_or_init(|| Mutex::new(Registry::default()))
        .lock()
        .map_err(|_| anyhow::anyhow!("endpoint bandit registry unavailable"))?;
    let state = registry.admit(identity, context, config)?;
    Ok(Some(Selection {
        state,
        pool: super::effective_relay_endpoints(settings),
        config: config.clone(),
        baseline_eligible: OnceLock::new(),
        identity: Arc::new(Identity {
            settings: settings.clone(),
            digest: identity,
        }),
        deadline,
    }))
}
impl Registry {
    fn admit(
        &mut self,
        identity: [u8; 32],
        context: [u8; 32],
        config: &RelayEndpointBanditSettings,
    ) -> anyhow::Result<Arc<Mutex<ContextState>>> {
        if let Some(existing) = self
            .profiles
            .get(&identity)
            .and_then(|contexts| contexts.get(&context))
        {
            return Ok(existing.clone());
        }
        // No Weak handles exist. A registry-only strong Arc cannot acquire a
        // new external owner while this exclusive registry lock is held.
        let active = |state: &Arc<Mutex<ContextState>>| Arc::strong_count(state) > 1;
        let total_live = self
            .profiles
            .values()
            .flat_map(BTreeMap::values)
            .filter(|state| active(state))
            .count();
        ensure!(
            total_live < MAX_TOTAL_CONTEXTS,
            "endpoint bandit live context capacity exhausted"
        );
        let new_profile = !self.profiles.contains_key(&identity);
        if new_profile {
            let live_profiles = self
                .profiles
                .values()
                .filter(|contexts| contexts.values().any(active))
                .count();
            ensure!(
                live_profiles < config.max_profiles,
                "endpoint bandit live profile capacity exhausted"
            );
        } else {
            let live = self.profiles[&identity]
                .values()
                .filter(|state| active(state))
                .count();
            ensure!(
                live < config.max_contexts_per_profile,
                "endpoint bandit live per-profile context capacity exhausted"
            );
        }
        let fresh = Arc::new(Mutex::new(ContextState {
            estimator: PaperBandit::new(config.algorithm.clone()).map_err(anyhow::Error::msg)?,
            blocked: BTreeMap::new(),
            failed: false,
        }));
        if new_profile {
            while self.profiles.len() >= config.max_profiles {
                let victim = self
                    .profiles
                    .iter()
                    .find(|(_, contexts)| contexts.values().all(|state| !active(state)))
                    .map(|(id, _)| *id)
                    .context("endpoint bandit profile retirement unavailable")?;
                self.profiles.remove(&victim);
            }
        } else {
            let contexts = self.profiles.get_mut(&identity).expect("existing profile");
            while contexts.len() >= config.max_contexts_per_profile {
                let victim = contexts
                    .iter()
                    .find(|(_, state)| !active(state))
                    .map(|(id, _)| *id)
                    .context("endpoint bandit context retirement unavailable")?;
                contexts.remove(&victim);
            }
        }
        while self.profiles.values().map(BTreeMap::len).sum::<usize>() >= MAX_TOTAL_CONTEXTS {
            let (profile, victim) = self
                .profiles
                .iter()
                .find_map(|(profile, contexts)| {
                    contexts
                        .iter()
                        .find(|(_, state)| !active(state))
                        .map(|(id, _)| (*profile, *id))
                })
                .context("endpoint bandit global context retirement unavailable")?;
            let contexts = self
                .profiles
                .get_mut(&profile)
                .expect("retirement profile exists");
            contexts.remove(&victim);
            if contexts.is_empty() {
                self.profiles.remove(&profile);
            }
        }
        self.profiles
            .entry(identity)
            .or_default()
            .insert(context, fresh.clone());
        Ok(fresh)
    }
}
impl Selection {
    fn arm(&self, server: &str) -> anyhow::Result<String> {
        let index = self
            .pool
            .iter()
            .position(|e| e.server == server)
            .context("endpoint was not admitted by pinned pool")?;
        Ok(format!("{index:02}"))
    }
    pub(super) fn rank(
        &self,
        eligible: Vec<EffectiveRelayEndpoint>,
    ) -> anyhow::Result<Vec<EffectiveRelayEndpoint>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("endpoint bandit state unavailable"))?;
        ensure!(!state.failed, "endpoint bandit estimator refused");
        ensure!(
            tokio::time::Instant::now() < self.deadline,
            "endpoint ranking establishment deadline exceeded"
        );
        // Only the explicit optional policy builds a graph or remembers eligibility.
        // The first real caller's hard-eligible set may never be expanded later.
        let admitted = if self.config.dependency_policy.is_some() {
            let mut indices = Vec::with_capacity(eligible.len());
            for endpoint in &eligible {
                let index = self
                    .pool
                    .iter()
                    .position(|pin| pin == endpoint)
                    .context("endpoint rank received an unadmitted identity")?;
                ensure!(!indices.contains(&index), "duplicate endpoint eligibility");
                indices.push(index);
            }
            let baseline = self.baseline_eligible.get_or_init(|| indices.clone());
            ensure!(
                baseline == &indices,
                "endpoint eligibility cannot be rebound"
            );
            Some(self.current_dependency_admission(&state, baseline)?)
        } else {
            None
        };
        let now = Instant::now();
        let mut ranked = Vec::new();
        for endpoint in eligible {
            ensure!(
                self.pool.contains(&endpoint),
                "endpoint rank received an unadmitted identity"
            );
            let arm = self.arm(&endpoint.server)?;
            if state.blocked.get(&arm).is_some_and(|until| now < *until) {
                continue;
            }
            if let Some(admitted) = &admitted {
                let index = self
                    .pool
                    .iter()
                    .position(|pin| pin == &endpoint)
                    .context("endpoint rank identity missing")?;
                if !admitted.contains(&index) {
                    continue;
                }
            }
            let estimate = state.estimator.estimate(&arm);
            ranked.push((
                endpoint,
                estimate.effective_trials == 0.0,
                estimate.mean + estimate.bonus,
            ));
        }
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.2.total_cmp(&a.2)));
        ensure!(
            tokio::time::Instant::now() < self.deadline,
            "endpoint graph/ranking establishment deadline exceeded"
        );
        Ok(ranked.into_iter().map(|r| r.0).collect())
    }
    fn current_dependency_admission(
        &self,
        state: &ContextState,
        baseline: &[usize],
    ) -> anyhow::Result<Vec<usize>> {
        let policy = self
            .config
            .dependency_policy
            .as_ref()
            .context("endpoint dependency policy missing")?;
        let now = Instant::now();
        let eligible: Vec<_> = baseline
            .iter()
            .copied()
            .filter(|index| {
                !state
                    .blocked
                    .get(&format!("{index:02}"))
                    .is_some_and(|until| now < *until)
            })
            .collect();
        let admitted = policy.admit(self.pool.len(), &eligible)?;
        ensure!(
            tokio::time::Instant::now() < self.deadline,
            "endpoint dependency admission establishment deadline exceeded"
        );
        Ok(admitted)
    }
    pub(super) fn attempt(&self, server: &str) -> anyhow::Result<Option<Attempt>> {
        let arm = self.arm(server)?;
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("endpoint bandit state unavailable"))?;
        ensure!(!state.failed, "endpoint bandit estimator refused");
        if state
            .blocked
            .get(&arm)
            .is_some_and(|until| Instant::now() < *until)
        {
            return Ok(None);
        }
        if self.config.dependency_policy.is_some() {
            let baseline = self
                .baseline_eligible
                .get()
                .context("endpoint dependency attempt requires ranked eligibility")?;
            let index = self
                .pool
                .iter()
                .position(|pin| pin.server == server)
                .context("endpoint dependency attempt identity missing")?;
            if !self
                .current_dependency_admission(&state, baseline)?
                .contains(&index)
            {
                return Ok(None);
            }
        }
        ensure!(
            tokio::time::Instant::now() < self.deadline,
            "endpoint attempt establishment deadline exceeded"
        );
        Ok(Some(Attempt {
            state: self.state.clone(),
            arm,
            cooldown: Duration::from_millis(self.config.pre_auth_block_ms),
            observed: Arc::new(AtomicBool::new(false)),
            application: Arc::new(AtomicU8::new(0)),
            identity: self.identity.clone(),
            deadline: self.deadline,
        }))
    }
}
impl Attempt {
    pub(super) fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }
    pub(super) fn validate_after_open(&self) -> anyhow::Result<()> {
        ensure!(
            tokio::time::Instant::now() < self.deadline,
            "endpoint establishment deadline exceeded"
        );
        ensure!(
            profile_identity(&self.identity.settings)? == self.identity.digest,
            "endpoint trust identity changed during establishment"
        );
        ensure!(
            tokio::time::Instant::now() < self.deadline,
            "endpoint identity observation exceeded establishment deadline"
        );
        Ok(())
    }
    pub(super) fn terminal_failure(&self) {
        self.record(0.0, false);
    }
    /// Exactly one outcome. Positive evidence means authenticated application
    /// bytes accepted outbound AND response observed, never TLS/Open/ACK alone.
    pub(super) fn accepted_sent(&self) {
        self.application_evidence(1);
    }
    pub(super) fn observed_response(&self) {
        self.application_evidence(2);
    }
    fn application_evidence(&self, flag: u8) {
        if self.application.fetch_or(flag, Ordering::AcqRel) | flag == 3 {
            self.progress();
        }
    }
    pub(super) fn progress(&self) {
        self.record(1.0, false);
    }
    pub(super) fn pre_auth_failure(&self) {
        self.record(0.0, true);
    }
    fn record(&self, reward: f64, block: bool) {
        if self.observed.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.estimator.observe(&self.arm, reward).is_err() {
            state.failed = true;
            return;
        }
        if block {
            if let Some(until) = Instant::now().checked_add(self.cooldown) {
                state.blocked.insert(self.arm.clone(), until);
            } else {
                state.failed = true;
            }
        }
    }
}

#[cfg(test)]
mod tests;
