//! Device authorization for an operator-managed inner TLS trust domain.
//! A durable generation/digest floor survives relay restarts. Rolling back
//! both root-controlled files or the entire machine remains outside this boundary.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::time::Instant;

#[cfg(all(test, unix))]
#[path = "registry_reader_cleanup_tests.rs"]
mod reader_cleanup_tests;
#[path = "registry_reader_owner.rs"]
mod reader_owner;
#[path = "registry_storage.rs"]
mod storage;
pub use storage::{
    apply_snapshot, floor_path, issuance_pending_path, pending_path, publish_snapshot,
    RegistryTransaction,
};
#[cfg(feature = "device-enrollment")]
pub use storage::{
    CancellationJournal, CancellationObservation, CancellationReadGuard, EnrollmentCancellation,
};

pub const MAX_REGISTRY_BYTES: u64 = 4 * 1024 * 1024;
pub const DEFAULT_POLICY_TTL_SECS: u64 = 900;
pub const MAX_POLICY_TTL_SECS: u64 = 3600;
const MAX_POLICY_FUTURE_SKEW_SECS: u64 = 60;
const REFRESH_INTERVAL: Duration = Duration::from_secs(1);
pub(super) const MAX_STALENESS: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRecord {
    pub device_id: String,
    pub certificate_sha256: String,
    pub not_after_unix_secs: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationRecord {
    pub device_id: String,
    pub token_sha256: String,
    pub expires_unix_secs: u64,
    pub consumed: bool,
    #[serde(default)]
    pub purpose: InvitationPurpose,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvitationPurpose {
    #[default]
    Enroll,
    Rotate {
        replaces_certificate_sha256: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistry {
    pub version: u8,
    pub generation: u64,
    // Omission preserves the canonical identity of legacy v1 snapshots for
    // explicit operator migration. Runtime authorization requires v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<RegistryValidity>,
    pub devices: Vec<DeviceRecord>,
    pub invitations: Vec<InvitationRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryValidity {
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
}

/// Point-in-time view of the authorization state used by live leases. This
/// contains no membership data and never reads or refreshes the registry file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicyStatus {
    pub generation: u64,
    pub snapshot_sha256: String,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    pub policy_remaining_ms: u64,
    /// Includes the independent watcher-staleness bound, without renewing it.
    pub effective_valid_for_ms: u64,
}

impl RegistryValidity {
    fn new(now: u64, ttl_secs: u64) -> io::Result<Self> {
        if now == 0 || !(1..=MAX_POLICY_TTL_SECS).contains(&ttl_secs) {
            return Err(invalid("registry policy lifetime must be 1 second..1 hour"));
        }
        Ok(Self {
            issued_at_unix_secs: now,
            expires_at_unix_secs: now
                .checked_add(ttl_secs)
                .ok_or_else(|| invalid("registry policy expiry overflow"))?,
        })
    }

    fn lifetime(&self) -> io::Result<u64> {
        let ttl = self
            .expires_at_unix_secs
            .checked_sub(self.issued_at_unix_secs)
            .ok_or_else(|| invalid("registry policy validity is reversed"))?;
        if self.issued_at_unix_secs == 0 || !(1..=MAX_POLICY_TTL_SECS).contains(&ttl) {
            return Err(invalid("registry policy lifetime must be 1 second..1 hour"));
        }
        Ok(ttl)
    }

    fn remaining(&self, now: u64) -> io::Result<Duration> {
        let lifetime = self.lifetime()?;
        if self.issued_at_unix_secs > now.saturating_add(MAX_POLICY_FUTURE_SKEW_SECS)
            || self.expires_at_unix_secs <= now
        {
            return Err(invalid(
                "registry policy is expired or issued in the future",
            ));
        }
        // Accepted clock skew cannot grant more than the declared lifetime.
        Ok(Duration::from_secs(
            (self.expires_at_unix_secs - now).min(lifetime),
        ))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn unix_now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|now| now.as_secs())
        .map_err(|_| invalid("device registry clock unavailable"))
}

pub fn validate_device_id(id: &str) -> io::Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(invalid(
            "device id must contain 1..64 ASCII letters, digits, '-' or '_'",
        ));
    }
    Ok(())
}

fn digest(value: &str) -> io::Result<[u8; 32]> {
    let mut bytes = [0; 32];
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err(invalid(
            "registry SHA256 must be 64 lowercase hexadecimal characters",
        ));
    }
    hex::decode_to_slice(value, &mut bytes).map_err(|_| invalid("invalid registry SHA256"))?;
    Ok(bytes)
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self {
            version: 1,
            generation: 1,
            validity: None,
            devices: Vec::new(),
            invitations: Vec::new(),
        }
    }
}

impl DeviceRegistry {
    /// Establish the first operator-issued policy. Deserialization never
    /// invents validity, and ordinary record mutations do not renew it.
    pub fn new(now: u64, ttl_secs: u64) -> io::Result<Self> {
        Ok(Self {
            version: 2,
            validity: Some(RegistryValidity::new(now, ttl_secs)?),
            ..Self::default()
        })
    }

    /// Explicitly renew policy, including migration of a verified v1 pair.
    /// Call under RegistryTransaction; this does not write any files itself.
    pub fn refresh_validity(&mut self, now: u64, ttl_secs: u64) -> io::Result<()> {
        self.validate()?;
        let validity = RegistryValidity::new(now, ttl_secs)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("device generation exhausted"))?;
        self.version = 2;
        self.generation = generation;
        self.validity = Some(validity);
        Ok(())
    }

    fn policy_remaining(&self, now: u64) -> io::Result<Duration> {
        if self.version != 2 {
            return Err(invalid(
                "runtime requires registry v2 with explicit policy validity",
            ));
        }
        self.validity
            .as_ref()
            .ok_or_else(|| invalid("registry policy validity is missing"))?
            .remaining(now)
    }

    /// Validate durable administrative data, including expired policies and
    /// legacy v1 snapshots. This alone does not authorize runtime traffic.
    pub fn validate(&self) -> io::Result<()> {
        match (self.version, self.validity) {
            (1, None) => {}
            (2, Some(validity)) => {
                validity.lifetime()?;
            }
            _ => {
                return Err(invalid(
                    "unsupported device registry policy version or validity",
                ))
            }
        }
        if self.generation == 0 || self.devices.len() > 4096 || self.invitations.len() > 4096 {
            return Err(invalid("unsupported or oversized device registry"));
        }
        let mut ids = HashSet::new();
        let mut certs = HashSet::new();
        for device in &self.devices {
            validate_device_id(&device.device_id)?;
            if device.not_after_unix_secs == 0
                || !ids.insert(&device.device_id)
                || !certs.insert(digest(&device.certificate_sha256)?)
            {
                return Err(invalid("duplicate or invalid device registry record"));
            }
        }
        let mut tokens = HashSet::new();
        for invitation in &self.invitations {
            validate_device_id(&invitation.device_id)?;
            if let InvitationPurpose::Rotate {
                replaces_certificate_sha256,
            } = &invitation.purpose
            {
                digest(replaces_certificate_sha256)?;
            }
            if invitation.expires_unix_secs == 0
                || !tokens.insert(digest(&invitation.token_sha256)?)
            {
                return Err(invalid("duplicate or invalid invitation record"));
            }
        }
        Ok(())
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        storage::load_verified(path)
    }

    /// Read an independently trusted delivery snapshot without adopting its floor.
    pub fn load_snapshot(path: &Path) -> io::Result<Self> {
        storage::load_snapshot(path)
    }

    fn active_certificates(&self) -> HashMap<[u8; 32], u64> {
        self.devices
            .iter()
            .filter(|device| !device.revoked)
            .filter_map(|device| {
                digest(&device.certificate_sha256)
                    .ok()
                    .map(|digest| (digest, device.not_after_unix_secs))
            })
            .collect()
    }
}

struct State {
    active: Option<HashMap<[u8; 32], u64>>,
    generation: u64,
    digest: [u8; 32],
    checked: Instant,
    policy_validity: Option<RegistryValidity>,
    policy_deadline: Instant,
    clock: ClockAnchor,
}

struct ClockAnchor {
    wall: u64,
    monotonic: Instant,
}

impl ClockAnchor {
    fn projected(&self, observed_wall: u64, monotonic: Instant) -> io::Result<u64> {
        self.wall
            .checked_add(monotonic.duration_since(self.monotonic).as_secs())
            .map(|projected| projected.max(observed_wall))
            .ok_or_else(|| invalid("registry clock projection overflow"))
    }

    fn observe(&mut self, observed_wall: u64, monotonic: Instant) -> io::Result<u64> {
        let projected = self.projected(0, monotonic)?;
        if observed_wall > projected {
            self.wall = observed_wall;
            self.monotonic = monotonic;
        }
        Ok(projected.max(observed_wall))
    }
}

struct Inner {
    path: PathBuf,
    state: RwLock<State>,
    changed: watch::Sender<u64>,
    watching: AtomicBool,
}

#[derive(Clone)]
pub(super) struct RuntimeRegistry(Arc<Inner>);

/// The same canonical digest committed by the durable floor and runtime ACK.
pub fn registry_digest(registry: &DeviceRegistry) -> io::Result<[u8; 32]> {
    registry.validate()?;
    let mut canonical = registry.clone();
    canonical
        .devices
        .sort_by(|a, b| a.device_id.cmp(&b.device_id));
    canonical
        .invitations
        .sort_by(|a, b| a.token_sha256.cmp(&b.token_sha256));
    Ok(Sha256::digest(serde_json::to_vec(&canonical).map_err(io::Error::other)?).into())
}

impl RuntimeRegistry {
    pub(super) fn load(path: &Path) -> io::Result<Self> {
        let registry = DeviceRegistry::load(path)?;
        Self::from_snapshot(path, registry, unix_now()?)
    }

    /// Startup only: wait for a bounded durable publication, never substitute an
    /// old snapshot. Runtime reload and the normal load API remain fail-fast.
    pub(super) fn load_for_startup(path: &Path) -> io::Result<Self> {
        Self::load_startup_with_limits(path, Duration::from_secs(5), Duration::from_millis(50), 101)
    }

    fn load_startup_with_limits(
        path: &Path,
        budget: Duration,
        interval: Duration,
        max_attempts: usize,
    ) -> io::Result<Self> {
        // Use a real monotonic clock, independent of policy/lease clocks and
        // Tokio's test clock. This function must run on a blocking worker.
        let deadline = std::time::Instant::now() + budget;
        for attempt in 0..max_attempts {
            let error = match DeviceRegistry::load(path) {
                Ok(registry) => return Self::from_snapshot(path, registry, unix_now()?),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => error,
                Err(error) => return Err(error),
            };
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() || attempt + 1 == max_attempts {
                return Err(error);
            }
            std::thread::sleep(interval.min(remaining));
            if std::time::Instant::now() >= deadline {
                return Err(error);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "device registry startup read exhausted its attempt bound",
        ))
    }

    #[cfg(all(test, unix))]
    fn load_at(path: &Path, now: u64) -> io::Result<Self> {
        let registry = DeviceRegistry::load(path)?;
        Self::from_snapshot(path, registry, now)
    }

    fn from_snapshot(path: &Path, registry: DeviceRegistry, now: u64) -> io::Result<Self> {
        let digest = registry_digest(&registry)?;
        let monotonic = Instant::now();
        let policy_deadline = monotonic
            .checked_add(registry.policy_remaining(now)?)
            .ok_or_else(|| invalid("registry policy deadline overflow"))?;
        let (changed, _) = watch::channel(0);
        Ok(Self(Arc::new(Inner {
            path: path.to_owned(),
            state: RwLock::new(State {
                generation: registry.generation,
                digest,
                active: Some(registry.active_certificates()),
                checked: monotonic,
                policy_validity: registry.validity,
                policy_deadline,
                clock: ClockAnchor {
                    wall: now,
                    monotonic,
                },
            }),
            changed,
            watching: AtomicBool::new(false),
        })))
    }

    fn publish(&self, loaded: io::Result<DeviceRegistry>) {
        self.publish_at(loaded, unix_now());
    }

    fn publish_at(&self, loaded: io::Result<DeviceRegistry>, now: io::Result<u64>) {
        if matches!(&loaded, Err(error) if error.kind() == io::ErrorKind::WouldBlock) {
            // A writer owns the lock through floor+snapshot publication. Do not
            // revoke unrelated sessions for that bounded transaction window;
            // do not refresh checked either, so a stuck writer still fails
            // closed at MAX_STALENESS.
            return;
        }
        let mut state = self.0.state.write().unwrap_or_else(|e| e.into_inner());
        let monotonic = Instant::now();
        let now = now.and_then(|now| state.clock.observe(now, monotonic));
        let accepted = loaded.ok().and_then(|registry| {
            let digest = registry_digest(&registry).ok()?;
            if registry.generation < state.generation
                || (registry.generation == state.generation && digest != state.digest)
            {
                return None;
            }
            let same_policy = registry.validity == state.policy_validity;
            state.generation = registry.generation;
            state.digest = digest;
            state.policy_validity = registry.validity;
            let deadline = now
                .ok()
                .and_then(|now| registry.policy_remaining(now).ok())
                .and_then(|remaining| monotonic.checked_add(remaining));
            state.policy_deadline = if same_policy {
                state.policy_deadline.min(deadline.unwrap_or(monotonic))
            } else {
                deadline.unwrap_or(monotonic)
            };
            if monotonic >= state.policy_deadline {
                return None;
            }
            Some(registry.active_certificates())
        });
        state.active = accepted;
        state.checked = monotonic;
        drop(state);
        self.0
            .changed
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
    }

    pub(super) fn lease(&self, fingerprint: [u8; 32]) -> io::Result<AuthorizationLease> {
        let now = unix_now()?;
        let expiry = self.expiry(&fingerprint, now)?.ok_or_else(revoked)?;
        Ok(AuthorizationLease(Some(Lease {
            registry: self.clone(),
            fingerprint,
            // A backwards wall-clock adjustment cannot prolong an already
            // authenticated session beyond its originally granted lifetime.
            expires: Instant::now()
                .checked_add(Duration::from_secs(expiry - now))
                .ok_or_else(|| invalid("device lease expiry is out of range"))?,
        })))
    }

    /// Point-in-time outer carrier admission. Reuse the watcher's strict
    /// freshness, policy-clock and revocation checks without creating a
    /// target/session lease. Inner TLS still obtains its own live lease.
    pub(super) fn check_current(&self, fingerprint: [u8; 32]) -> io::Result<()> {
        let now = unix_now()?;
        self.expiry(&fingerprint, now)?
            .ok_or_else(revoked)
            .map(|_| ())
    }

    fn state_after_clock_observation(
        &self,
        observed_wall: u64,
    ) -> io::Result<std::sync::RwLockReadGuard<'_, State>> {
        let state = self.0.state.read().unwrap_or_else(|e| e.into_inner());
        if observed_wall <= state.clock.projected(0, Instant::now())? {
            return Ok(state);
        }
        // Normal checks remain read-only. Retain a new forward observation
        // before deciding authorization, even between watcher publications.
        // Release the read lock before acquiring the write lock, and observe
        // again against current state in case another check/publisher won.
        drop(state);
        let mut state = self.0.state.write().unwrap_or_else(|e| e.into_inner());
        let monotonic = Instant::now();
        let now = state.clock.observe(observed_wall, monotonic)?;
        let deadline = state
            .policy_validity
            .and_then(|validity| validity.remaining(now).ok())
            .and_then(|remaining| monotonic.checked_add(remaining))
            .unwrap_or(monotonic);
        state.policy_deadline = state.policy_deadline.min(deadline);
        // This observation does not renew the independent disk-read timer.
        drop(state);
        Ok(self.0.state.read().unwrap_or_else(|e| e.into_inner()))
    }

    fn expiry(&self, fingerprint: &[u8; 32], now: u64) -> io::Result<Option<u64>> {
        let state = self.state_after_clock_observation(now)?;
        let monotonic = Instant::now();
        let now = state.clock.projected(now, monotonic)?;
        self.available(&state, now, monotonic)?;
        Ok(state
            .active
            .as_ref()
            .and_then(|active| active.get(fingerprint))
            .copied()
            .filter(|expiry| *expiry > now))
    }

    fn available(&self, state: &State, now: u64, monotonic: Instant) -> io::Result<()> {
        if !self.0.watching.load(Ordering::Acquire)
            || monotonic.duration_since(state.checked) >= MAX_STALENESS
            || monotonic >= state.policy_deadline
            || state.active.is_none()
            || state
                .policy_validity
                .is_none_or(|validity| validity.expires_at_unix_secs <= now)
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "device authorization registry unavailable",
            ));
        }
        Ok(())
    }

    pub(super) fn status(&self) -> io::Result<RuntimePolicyStatus> {
        self.status_at(unix_now()?)
    }

    fn status_at(&self, now: u64) -> io::Result<RuntimePolicyStatus> {
        // Share the exact authorization clock observation and availability
        // gate. A forward observation can tighten expiry; status cannot renew
        // policy_deadline or the independent successful disk-read timestamp.
        let state = self.state_after_clock_observation(now)?;
        let monotonic = Instant::now();
        let now = state.clock.projected(now, monotonic)?;
        self.available(&state, now, monotonic)?;
        let validity = state
            .policy_validity
            .ok_or_else(|| invalid("policy unavailable"))?;
        let remaining = state
            .policy_deadline
            .duration_since(monotonic)
            .min(Duration::from_secs(validity.expires_at_unix_secs - now));
        let effective = remaining.min(MAX_STALENESS - monotonic.duration_since(state.checked));
        Ok(RuntimePolicyStatus {
            generation: state.generation,
            snapshot_sha256: hex::encode(state.digest),
            issued_at_unix_secs: validity.issued_at_unix_secs,
            expires_at_unix_secs: validity.expires_at_unix_secs,
            policy_remaining_ms: remaining.as_millis() as u64,
            effective_valid_for_ms: effective.as_millis() as u64,
        })
    }

    pub(super) fn start_watcher(&self) -> Option<RegistryWatcher> {
        self.start_watcher_with_reader(|path| DeviceRegistry::load(&path))
    }

    fn start_watcher_with_reader(
        &self,
        read: impl Fn(PathBuf) -> io::Result<DeviceRegistry> + Send + Sync + 'static,
    ) -> Option<RegistryWatcher> {
        if self.0.watching.swap(true, Ordering::AcqRel) {
            return None;
        }
        let registry = self.clone();
        let readers = reader_owner::ReaderOwner::new();
        let read_owner = readers.clone();
        let read = Arc::new(read);
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(REFRESH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let path = registry.0.path.clone();
                let read = read.clone();
                // One read per watcher is admitted before its actual blocking
                // spawn. Its original handle remains in the outer owner if
                // this async await is cancelled. Lease staleness stays 3s.
                let result = match read_owner.start(move || read(path)) {
                    Ok(reading) => reading.await,
                    Err(_) => return,
                };
                registry.publish(result);
            }
        });
        Some(RegistryWatcher {
            registry: self.clone(),
            task: Some(task),
            readers,
            stopped: false,
            watcher_failed: false,
        })
    }
}

pub struct RegistryWatcher {
    registry: RuntimeRegistry,
    task: Option<tokio::task::JoinHandle<()>>,
    readers: reader_owner::ReaderOwner,
    stopped: bool,
    watcher_failed: bool,
}

impl RegistryWatcher {
    fn request_stop(&mut self) {
        if !self.stopped {
            self.stopped = true;
            self.registry.0.watching.store(false, Ordering::Release);
            self.registry
                .publish(Err(invalid("device registry watcher stopped")));
        }
        // Close admission before aborting the async watcher, so a concurrent
        // refresh cannot create an unowned blocking task at this boundary.
        self.readers.close();
        if let Some(task) = &self.task {
            task.abort();
        }
    }

    /// Stop and observe both original tasks under one caller-supplied cutoff.
    /// Cancellation or timeout of this borrowed future retains the handles in
    /// this watcher. Keep the watcher alive to retry observation after a read
    /// finishes. An entered synchronous read is never preempted by task abort.
    pub async fn stop_and_join_read_until(&mut self, cutoff: Instant) -> io::Result<()> {
        self.request_stop();
        if let Some(task) = self.task.as_mut() {
            let result = tokio::time::timeout_at(cutoff, task).await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "registry watcher terminal unconfirmed",
                )
            })?;
            self.watcher_failed = matches!(result, Err(error) if !error.is_cancelled());
            // This original handle was terminal-polled once. Never poll it
            // again when a caller retries a previously cancelled/timed wait.
            self.task = None;
        }
        // The async task has stopped polling the read handle before this
        // second borrower polls that same handle. No replacement is spawned.
        self.readers.join_until(cutoff).await?;
        if Instant::now() >= cutoff {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "registry watcher completed beyond cutoff",
            ));
        }
        if self.watcher_failed {
            return Err(io::Error::other("registry watcher task failed"));
        }
        Ok(())
    }

    /// Compatibility one-shot stop. Success now requires the blocking read to
    /// be joined too. On timeout this returns an error; consuming this owner
    /// cannot promise retained join authority after the method returns.
    pub async fn stop_and_join_until(mut self, cutoff: Instant) -> io::Result<()> {
        self.stop_and_join_read_until(cutoff).await
    }
}

impl Drop for RegistryWatcher {
    fn drop(&mut self) {
        // Drop requests cancellation and fail-closes leases. It cannot await
        // or preempt a read which already entered synchronous filesystem I/O.
        self.request_stop();
    }
}

#[derive(Clone)]
struct Lease {
    registry: RuntimeRegistry,
    fingerprint: [u8; 32],
    expires: Instant,
}

#[derive(Clone)]
pub struct AuthorizationLease(Option<Lease>);

fn revoked() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        super::AuthenticationFailure::DeviceNotAllowed,
    )
}

impl AuthorizationLease {
    /// The certificate and snapshot are checked under the same live-state
    /// lock. This never reads disk or renews a watcher/policy/lease deadline.
    pub fn policy_ack(&self, nonce: &str) -> io::Result<super::policy_ack::RuntimePolicyAck> {
        let lease = self
            .0
            .as_ref()
            .ok_or_else(|| invalid("dynamic registry is required"))?;
        let now = unix_now()?;
        let state = lease.registry.state_after_clock_observation(now)?;
        let monotonic = Instant::now();
        let now = state.clock.projected(now, monotonic)?;
        lease.registry.available(&state, now, monotonic)?;
        if monotonic >= lease.expires {
            return Err(revoked());
        }
        let expiry = state
            .active
            .as_ref()
            .and_then(|active| active.get(&lease.fingerprint))
            .copied()
            .filter(|expiry| *expiry > now)
            .ok_or_else(revoked)?;
        let validity = state
            .policy_validity
            .ok_or_else(|| invalid("policy unavailable"))?;
        let effective = state
            .policy_deadline
            .duration_since(monotonic)
            .min(lease.expires.duration_since(monotonic))
            .min(Duration::from_secs(expiry - now))
            .min(Duration::from_secs(validity.expires_at_unix_secs - now))
            .min(MAX_STALENESS - monotonic.duration_since(state.checked));
        let ack = super::policy_ack::RuntimePolicyAck {
            version: 1,
            nonce: nonce.into(),
            generation: state.generation,
            snapshot_sha256: hex::encode(state.digest),
            certificate_sha256: hex::encode(lease.fingerprint),
            policy_not_after_unix_secs: validity.expires_at_unix_secs,
            certificate_not_after_unix_secs: expiry,
            effective_valid_for_ms: effective.as_millis() as u64,
        };
        ack.verify(
            nonce,
            &hex::encode(lease.fingerprint),
            None,
            now,
            Duration::ZERO,
        )?;
        Ok(ack)
    }

    pub(super) fn static_allowlist() -> Self {
        Self(None)
    }

    /// Completes on revocation, expiry, invalid registry or stale/missing
    /// watcher. Wrap the entire post-auth setup and forwarding future with it.
    pub async fn revoked(&self) -> io::Error {
        let Some(lease) = &self.0 else {
            return std::future::pending().await;
        };
        let mut changed = lease.registry.0.changed.subscribe();
        loop {
            if Instant::now() >= lease.expires
                || unix_now()
                    .ok()
                    .and_then(|now| {
                        lease
                            .registry
                            .expiry(&lease.fingerprint, now)
                            .ok()
                            .flatten()
                    })
                    .is_none()
            {
                return revoked();
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                result = changed.changed() => if result.is_err() { return revoked(); },
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sample(expiry: u64) -> DeviceRegistry {
        DeviceRegistry {
            devices: vec![DeviceRecord {
                device_id: "device-a".into(),
                certificate_sha256: "11".repeat(32),
                not_after_unix_secs: expiry,
                revoked: false,
            }],
            ..DeviceRegistry::new(unix_now().unwrap(), DEFAULT_POLICY_TTL_SECS).unwrap()
        }
    }

    fn publish_file(path: &Path, registry: &DeviceRegistry) {
        publish_snapshot(path, registry).unwrap();
    }

    #[test]
    fn registry_rejects_ambiguous_or_unbounded_records() {
        let now = unix_now().unwrap();
        let mut registry = sample(now + 100);
        registry.validate().unwrap();
        registry.devices.push(registry.devices[0].clone());
        assert!(registry.validate().is_err());
        let mut registry = sample(now + 100);
        registry.devices[0].certificate_sha256 = "11".repeat(31);
        assert!(registry.validate().is_err());
        let mut registry = sample(now + 100);
        registry.devices[0].device_id = "../device".into();
        assert!(registry.validate().is_err());
        let mut registry = sample(now + 100);
        registry.version = 3;
        assert!(registry.validate().is_err());
    }

    #[test]
    fn outer_precheck_refuses_unlisted_revoked_and_stale_registry_without_a_lease() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let original = sample(unix_now().unwrap() + 100);
        publish_file(&path, &original);
        let runtime = RuntimeRegistry::load(&path).unwrap();
        runtime.0.watching.store(true, Ordering::Release);
        runtime.check_current([0x11; 32]).unwrap();
        assert_eq!(
            runtime.check_current([0x22; 32]).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut revoked = original.clone();
        revoked.generation = 2;
        revoked.devices[0].revoked = true;
        runtime.publish(Ok(revoked));
        assert_eq!(
            runtime.check_current([0x11; 32]).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        runtime.publish(Err(invalid("synthetic watcher read refusal")));
        assert_eq!(
            runtime.check_current([0x11; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test(start_paused = true)]
    async fn lease_expires_with_monotonic_time_and_missing_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        publish_file(&path, &sample(unix_now().unwrap() + 2));
        let runtime = RuntimeRegistry::load(&path).unwrap();
        let unavailable = runtime.lease([0x11; 32]).err().unwrap();
        assert!(
            super::super::AuthenticationFailure::from_io(&unavailable).is_none(),
            "watcher outage is not a client authentication failure"
        );
        // Model a live refresh owner independently of actual filesystem I/O.
        runtime.0.watching.store(true, Ordering::Release);
        let lease = runtime.lease([0x11; 32]).unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            lease.revoked().await.kind(),
            io::ErrorKind::PermissionDenied
        );
        runtime.publish(Ok(sample(unix_now().unwrap() + 100)));
        // Same generation with changed expiry is invalid, even if later.
        assert!(runtime.lease([0x11; 32]).is_err());
        let mut updated = sample(unix_now().unwrap() + 100);
        updated.generation = 2;
        runtime.publish(Ok(updated));
        let lease = runtime.lease([0x11; 32]).unwrap();
        tokio::time::advance(MAX_STALENESS).await;
        assert_eq!(
            lease.revoked().await.kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn registry_reload_revokes_existing_lease_and_rejects_process_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let original = sample(unix_now().unwrap() + 100);
        publish_file(&path, &original);
        let runtime = RuntimeRegistry::load(&path).unwrap();
        let watcher = runtime.start_watcher().unwrap();
        assert!(
            runtime.start_watcher().is_none(),
            "one refresh owner per shared registry"
        );
        let lease = runtime.lease([0x11; 32]).unwrap();
        let mut revoked = original.clone();
        revoked.generation = 2;
        revoked.devices[0].revoked = true;
        publish_file(&path, &revoked);
        tokio::time::timeout(Duration::from_secs(4), lease.revoked())
            .await
            .unwrap();
        assert!(runtime.lease([0x11; 32]).is_err());
        // The high-water mark survives malformed/unavailable snapshots.
        runtime.publish(Err(invalid("synthetic read error")));
        runtime.publish(Ok(original));
        assert!(runtime.lease([0x11; 32]).is_err());
        drop(watcher);
        assert!(runtime.lease([0x11; 32]).is_err());
    }

    #[tokio::test]
    async fn invalid_reload_closes_lease_without_falling_back_to_last_good_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        publish_file(&path, &sample(unix_now().unwrap() + 100));
        let runtime = RuntimeRegistry::load(&path).unwrap();
        runtime.0.watching.store(true, Ordering::Release);
        let lease = runtime.lease([0x11; 32]).unwrap();
        runtime.publish(Err(invalid("synthetic malformed registry")));
        assert_eq!(
            lease.revoked().await.kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(runtime.lease([0x11; 32]).is_err());
    }
}

#[cfg(all(test, unix))]
#[path = "registry_freshness_tests.rs"]
mod freshness_tests;

#[cfg(all(test, unix))]
#[path = "registry_status_tests.rs"]
mod status_tests;
