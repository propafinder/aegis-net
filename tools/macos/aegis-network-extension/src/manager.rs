//! Real saved-profile lifecycle. Operations do not grant credential authority
//! or prove relay health; a source generation identifies the exact saved intent.
//!
//! Since S16a no profile verb reads a host-side `Aegis/` tree: a save,
//! connect or repair takes its policy from the provider's `profile-terms`
//! reply (`profile_terms`), a disconnect or status read from the saved
//! profile's own typed intent (`OwnedTarget::Saved`), and
//! only the explicit `--repair-runtime` still publishes the host-only
//! `runtime.json` record (`HostRuntimePublisher`).
use crate::{
    configuration::{
        fullwide_protocol, protocol_flags, saved_provider_intent, WindowMode, FULLWIDE_FLAGS,
        LOCALIZED_DESCRIPTION, PROVIDER_ID, WINDOW_POLICY_ADAPTIVE, WINDOW_POLICY_OPTION,
    },
    host_lifecycle::reloaded_flags_line,
    host_runtime_publication::HostRuntimePublisher,
    policy::FullWide,
};
use block2::RcBlock;
use objc2::{msg_send, rc::Retained, runtime::AnyObject, sel, AnyThread};
use objc2_foundation::{
    NSArray, NSDictionary, NSError, NSObject, NSObjectProtocol, NSString, NSUUID,
};
use objc2_network_extension::{NETunnelProviderManager, NETunnelProviderProtocol, NEVPNStatus};
use std::{
    cell::Cell,
    net::IpAddr,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
#[derive(Clone)]
pub struct Operation {
    live: Arc<AtomicBool>,
    deadline: Instant,
}
/// The whole-verb bound of every profile verb (S11), terms query included
/// since S16a.
pub const PROFILE_VERB_BUDGET: Duration = Duration::from_secs(30);
impl Operation {
    pub fn begin() -> Self {
        Self::until(Instant::now() + PROFILE_VERB_BUDGET)
    }
    /// S20b: one verb bounded by `budget` instead (the filter verbs).
    pub fn with_budget(budget: Duration) -> Self {
        Self::until(Instant::now() + budget)
    }
    fn until(deadline: Instant) -> Self {
        Self {
            live: Arc::new(AtomicBool::new(true)),
            deadline,
        }
    }
    /// Time left before this operation's single deadline (zero once past).
    /// The host's provider terms query and its watchdog both spend from it,
    /// so a verb never outlives one budget.
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
    pub fn cancel(&self) {
        self.live.store(false, Ordering::Release);
    }
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if self.live.load(Ordering::Acquire) && Instant::now() < self.deadline {
            Ok(())
        } else {
            Err("operation_expired")
        }
    }
}
#[derive(Clone)]
pub struct ProfileIntent {
    pub provider_id: String,
    pub owner_generation: String,
    pub policy: FullWide,
}
/// A fresh, host-minted owner generation (an NSUUID string). Nothing the
/// provider holds names one; it identifies one saved profile.
pub fn fresh_owner_generation() -> String {
    NSUUID::new().UUIDString().to_string()
}

impl ProfileIntent {
    pub fn fresh(provider_id: String, policy: FullWide) -> Self {
        Self {
            provider_id,
            owner_generation: fresh_owner_generation(),
            policy,
        }
    }
    fn values(&self) -> [String; 5] {
        [
            "aegis-ne-profile-v1".into(),
            self.owner_generation.clone(),
            self.policy.relay().to_string(),
            self.policy
                .dns()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            self.policy.mtu().to_string(),
        ]
    }
    /// The five-key `providerConfiguration` that the provider's
    /// `saved_provider_intent` parses (schema, owner_generation, relay, dns,
    /// mtu), all strings.
    pub(crate) fn dictionary(&self) -> Retained<NSDictionary<NSString, AnyObject>> {
        let keys = ["schema", "owner_generation", "relay", "dns", "mtu"].map(NSString::from_str);
        let values = self.values().map(|v| NSString::from_str(&v));
        let objects: Vec<&AnyObject> = values.iter().map(|v| &**v as &AnyObject).collect();
        NSDictionary::from_slices(&keys.iter().map(|k| &**k).collect::<Vec<_>>(), &objects)
    }
    fn matches(&self, manager: &NETunnelProviderManager) -> bool {
        unsafe {
            let Some(protocol) = manager
                .protocolConfiguration()
                .and_then(|p| p.downcast::<NETunnelProviderProtocol>().ok())
            else {
                return false;
            };
            if protocol.providerBundleIdentifier().map(|s| s.to_string())
                != Some(self.provider_id.clone())
                || protocol.serverAddress().map(|s| s.to_string())
                    != Some(self.policy.relay().to_string())
                || !protocol.includeAllNetworks()
                || protocol.excludeLocalNetworks()
                || protocol.excludeAPNs()
                || protocol.excludeCellularServices()
                || protocol.excludeDeviceCommunication()
                || protocol.enforceRoutes()
                || manager.isOnDemandEnabled()
            {
                return false;
            }
            let Some(d) = protocol.providerConfiguration() else {
                return false;
            };
            if d.len() != 5 {
                return false;
            }
            for (key, value) in ["schema", "owner_generation", "relay", "dns", "mtu"]
                .iter()
                .zip(self.values())
            {
                if d.objectForKey(&NSString::from_str(key))
                    .and_then(|v| v.downcast::<NSString>().ok())
                    .map(|v| v.to_string())
                    != Some(value)
                {
                    return false;
                }
            }
            true
        }
    }
    fn same_provider(&self, manager: &NETunnelProviderManager) -> bool {
        same_provider_id(manager, &self.provider_id)
    }
}
fn same_provider_id(manager: &NETunnelProviderManager, provider_id: &str) -> bool {
    unsafe {
        manager
            .protocolConfiguration()
            .and_then(|p| p.downcast::<NETunnelProviderProtocol>().ok())
            .and_then(|p| p.providerBundleIdentifier())
            .is_some_and(|s| s.to_string() == provider_id)
    }
}
/// Write `intent` onto `manager` (S16d): a fresh full-wide protocol
/// (`fullwide_protocol`: includeAllNetworks, no exclusions, no
/// enforceRoutes) that carries the five-key provider configuration before it
/// is attached, then the AEGIS description, enabled and on-demand off. Every
/// flag is set on a new protocol object, so whatever protocol `manager` held
/// before (a loaded profile whose flags read back as defaults included)
/// contributes nothing. The protocol is built before `manager` is touched,
/// so a refusal leaves `manager` unchanged. Calls no preference API.
pub(crate) fn apply_intent(
    manager: &NETunnelProviderManager,
    intent: &ProfileIntent,
) -> Result<(), &'static str> {
    let protocol = fullwide_protocol(&intent.provider_id, &intent.policy)?;
    unsafe {
        protocol.setProviderConfiguration(Some(&intent.dictionary()));
        manager.setProtocolConfiguration(Some(&protocol));
        manager.setLocalizedDescription(Some(&NSString::from_str(LOCALIZED_DESCRIPTION)));
        manager.setEnabled(true);
        manager.setOnDemandEnabled(false);
    }
    Ok(())
}

/// The unsaved manager a new save writes for `intent`: a fresh manager with
/// `apply_intent`. Building it calls no NetworkExtension preference API.
pub(crate) fn saveable_manager(
    intent: &ProfileIntent,
) -> Result<Retained<NETunnelProviderManager>, &'static str> {
    let manager: Retained<NETunnelProviderManager> =
        unsafe { msg_send![NETunnelProviderManager::alloc(), init] };
    apply_intent(&manager, intent)?;
    Ok(manager)
}

/// Whether `--save-profile` may modify this provider's one existing profile
/// (`--replace-existing`, S16d) or only create a first one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveMode {
    New,
    ReplaceExisting,
}

/// Which manager a save writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SaveTarget {
    /// No profile of this provider exists: a fresh manager.
    Create,
    /// Modify the loaded manager at this inventory index.
    Replace(usize),
}

/// One loaded manager as the save decision sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SaveCandidate {
    pub(crate) same_provider: bool,
    /// Its connection is Disconnected or Invalid (not connecting, connected,
    /// reasserting or disconnecting).
    pub(crate) idle: bool,
}

/// The save decision over the loaded inventory. Other providers' managers
/// are never selected. Without `ReplaceExisting` any existing profile of
/// this provider refuses the save; with it exactly one idle profile of this
/// provider is modified, and more than one, or a non-idle one, is refused.
/// Zero existing profiles is a plain create in either mode.
pub(crate) fn save_target(
    candidates: &[SaveCandidate],
    mode: SaveMode,
) -> Result<SaveTarget, &'static str> {
    let mut own = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.same_provider);
    let Some((index, first)) = own.next() else {
        return Ok(SaveTarget::Create);
    };
    if mode != SaveMode::ReplaceExisting {
        return Err("existing_provider_profile_refused");
    }
    if own.next().is_some() {
        return Err("multiple_provider_profiles_refused");
    }
    if !first.idle {
        return Err("existing_profile_not_idle");
    }
    Ok(SaveTarget::Replace(index))
}

/// A save that completed and verified on reload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaveReport {
    pub status: NEVPNStatus,
    /// The one existing profile of this provider was modified.
    pub replaced: bool,
}

/// A refused or unverified save. `reloaded` is set when the failure was
/// found by `verify_reloaded`, after a reload that returned no error;
/// `reloaded_flags` are then the six protocol flags it read back
/// (`FULLWIDE_FLAGS` order), or `None` when it returned no provider protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaveFailure {
    pub code: &'static str,
    pub reloaded: bool,
    pub reloaded_flags: Option<[bool; 6]>,
}
impl From<&'static str> for SaveFailure {
    fn from(code: &'static str) -> Self {
        Self {
            code,
            reloaded: false,
            reloaded_flags: None,
        }
    }
}
impl SaveFailure {
    /// The one stderr `reloaded_profile` line (`host_lifecycle::
    /// reloaded_flags_line`) for every failure found after a completed
    /// reload, `flags=unavailable` when no provider protocol came back. A
    /// refusal before the save, a save error or a reload error has none.
    pub fn reloaded_line(&self, owner_generation: &str) -> Option<String> {
        self.reloaded
            .then(|| reloaded_flags_line(owner_generation, self.reloaded_flags))
    }
}

pub type SaveCompletion = Arc<dyn Fn(Result<SaveReport, SaveFailure>) + 'static>;

/// The post-save check of the reloaded `manager` against `intent`. Flags
/// first: a reloaded protocol whose six flags are not the full-wide shape is
/// `profile_flags_not_persisted`, so an installed run shows whether macOS
/// keeps them. Then the exact owned intent and the provider's own typed
/// parser. Every failure here is marked `reloaded` and carries the reloaded
/// flags (`None` without a provider protocol).
pub(crate) fn verify_reloaded(
    intent: &ProfileIntent,
    manager: &NETunnelProviderManager,
) -> Result<(), SaveFailure> {
    let protocol = unsafe { manager.protocolConfiguration() }
        .and_then(|p| p.downcast::<NETunnelProviderProtocol>().ok());
    let reloaded_flags = protocol.as_deref().map(protocol_flags);
    let fail = |code| SaveFailure {
        code,
        reloaded: true,
        reloaded_flags,
    };
    let protocol = protocol.ok_or_else(|| fail("saved_profile_protocol_missing"))?;
    if reloaded_flags != Some(FULLWIDE_FLAGS) {
        return Err(fail("profile_flags_not_persisted"));
    }
    if !intent.matches(manager) {
        return Err(fail("saved_profile_generation_mismatch"));
    }
    match saved_provider_intent(&protocol) {
        Ok(saved) if saved.matches_returned_owner(&intent.owner_generation, &intent.policy) => {
            Ok(())
        }
        _ => Err(fail("saved_profile_typed_intent_mismatch")),
    }
}

fn is_idle(status: NEVPNStatus) -> bool {
    status == NEVPNStatus::Disconnected || status == NEVPNStatus::Invalid
}

pub type Completion = Arc<dyn Fn(Result<NEVPNStatus, &'static str>) + 'static>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// v35: with the start's stream-window mode (`start_options`).
    Connect(WindowMode),
    Disconnect,
    Status,
    RepairRuntime,
}

/// v35: the start options of one connect. v36 (outcome `fixed`): the fixed
/// window, the product default, passes none, like an on-demand or System
/// Settings start (`--window-policy fixed` included); the v35 window (a QA
/// arm, `--window-policy adaptive`) passes the one key `aegis_window_policy`
/// with the one value `adaptive`.
pub fn start_options(window: WindowMode) -> Option<Retained<NSDictionary<NSString, NSObject>>> {
    match window {
        WindowMode::Fixed => None,
        WindowMode::Adaptive => {
            let key = NSString::from_str(WINDOW_POLICY_OPTION);
            let value = NSString::from_str(WINDOW_POLICY_ADAPTIVE);
            let object: &NSObject = &value;
            Some(NSDictionary::from_slices(&[&*key], &[object]))
        }
    }
}
impl Action {
    /// Connect and repair act for the provider's held terms, so they need an
    /// admitted `profile-terms` intent. A stop or a status read needs no
    /// signed terms (S16a): it must not depend on provider XPC or held-tree
    /// health, so it matches the saved profile's own typed intent.
    pub fn needs_terms(self) -> bool {
        match self {
            Self::Connect(_) | Self::RepairRuntime => true,
            Self::Disconnect | Self::Status => false,
        }
    }
}

/// The saved profile an owned verb must act on.
#[derive(Clone)]
pub enum OwnedTarget {
    /// The exact intent built from admitted provider terms (connect, repair).
    Terms(ProfileIntent),
    /// The one saved profile of `provider_id` whose typed saved intent names
    /// exactly `owner_generation` and `relay` (disconnect, status). Its own
    /// saved DNS and MTU complete the intent; no provider query is made.
    Saved {
        provider_id: String,
        owner_generation: String,
        relay: IpAddr,
    },
}
impl OwnedTarget {
    fn provider_id(&self) -> &str {
        match self {
            Self::Terms(intent) => &intent.provider_id,
            Self::Saved { provider_id, .. } => provider_id,
        }
    }
    /// A saved-intent target never authorizes an action that needs terms.
    fn admits(&self, action: Action) -> bool {
        matches!(self, Self::Terms(_)) || !action.needs_terms()
    }
    /// The exact intent `manager` must carry for this target, or a refusal.
    /// Either way the result is checked with `ProfileIntent::matches`
    /// (provider id, server address, full-wide shape, on-demand off, the
    /// exact five provider-configuration strings).
    pub(crate) fn resolve(
        &self,
        manager: &NETunnelProviderManager,
    ) -> Result<ProfileIntent, &'static str> {
        const REFUSED: &str = "exact_owned_profile_required";
        let intent = match self {
            Self::Terms(intent) => intent.clone(),
            Self::Saved {
                provider_id,
                owner_generation,
                relay,
            } => {
                let saved = unsafe { manager.protocolConfiguration() }
                    .and_then(|p| p.downcast::<NETunnelProviderProtocol>().ok())
                    .ok_or(REFUSED)
                    .and_then(|p| saved_provider_intent(&p).map_err(|_| REFUSED))?;
                if saved.generation != *owner_generation || saved.policy.relay() != *relay {
                    return Err(REFUSED);
                }
                ProfileIntent {
                    provider_id: provider_id.clone(),
                    owner_generation: saved.generation,
                    policy: saved.policy,
                }
            }
        };
        if intent.matches(manager) {
            Ok(intent)
        } else {
            Err(REFUSED)
        }
    }
}
// User must explicitly invoke save. Without `ReplaceExisting` an existing
// or foreign generation is never adopted or overwritten. With it (S16d) the
// one idle saved profile of this provider is modified in place with a fresh
// generation (a modification, which should not prompt). No connect occurs
// from a save callback.
pub fn save_profile(
    intent: ProfileIntent,
    mode: SaveMode,
    operation: Operation,
    completion: SaveCompletion,
) {
    if objc2::MainThreadMarker::new().is_none() {
        completion(Err("main_thread_required".into()));
        return;
    }
    let loaded = RcBlock::new(
        move |managers: *mut NSArray<NETunnelProviderManager>, error: *mut NSError| {
            let admission = (|| {
                operation.check()?;
                if !error.is_null() {
                    return Err("profile_load_failed");
                }
                let managers = unsafe { managers.as_ref() }.ok_or("profile_inventory_absent")?;
                let candidates: Vec<SaveCandidate> = managers
                    .iter()
                    .map(|m| SaveCandidate {
                        same_provider: intent.same_provider(&m),
                        idle: is_idle(unsafe { m.connection().status() }),
                    })
                    .collect();
                match save_target(&candidates, mode)? {
                    SaveTarget::Create => saveable_manager(&intent).map(|m| (m, false)),
                    SaveTarget::Replace(index) => {
                        let existing = managers.objectAtIndex(index);
                        apply_intent(&existing, &intent)?;
                        Ok((existing, true))
                    }
                }
            })();
            let (manager, replaced) = match admission {
                Ok(admitted) => admitted,
                Err(e) => {
                    completion(Err(e.into()));
                    return;
                }
            };
            let intent = intent.clone();
            let operation = operation.clone();
            let completion = completion.clone();
            let saved_manager = manager.clone();
            let saved = RcBlock::new(move |error: *mut NSError| {
                if let Err(e) = operation.check() {
                    completion(Err(e.into()));
                    return;
                }
                if !error.is_null() {
                    completion(Err("profile_save_failed".into()));
                    return;
                }
                let manager = saved_manager.clone();
                let reloaded_manager = manager.clone();
                let intent = intent.clone();
                let operation = operation.clone();
                let completion = completion.clone();
                let reloaded = RcBlock::new(move |error: *mut NSError| {
                    if let Err(e) = operation.check() {
                        completion(Err(e.into()));
                        return;
                    }
                    if !error.is_null() {
                        completion(Err("profile_reload_failed".into()));
                        return;
                    }
                    if let Err(failure) = verify_reloaded(&intent, &reloaded_manager) {
                        completion(Err(failure));
                        return;
                    }
                    // S16a: no host runtime.json publication on save. The
                    // host has no Aegis tree since S14, and the provider
                    // never reads that record (S03p4); `--repair-runtime`
                    // remains the one explicit publisher.
                    // Saving/reloading is a preference result, not activation.
                    completion(Ok(SaveReport {
                        status: unsafe { reloaded_manager.connection().status() },
                        replaced,
                    }));
                });
                unsafe {
                    manager.loadFromPreferencesWithCompletionHandler(&reloaded);
                }
            });
            unsafe {
                manager.saveToPreferencesWithCompletionHandler(Some(&saved));
            }
        },
    );
    unsafe {
        NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&loaded);
    }
}
pub fn act_owned(
    target: OwnedTarget,
    action: Action,
    operation: Operation,
    completion: Completion,
) {
    if objc2::MainThreadMarker::new().is_none() {
        completion(Err("main_thread_required"));
        return;
    }
    if !target.admits(action) {
        completion(Err("owned_action_requires_terms"));
        return;
    }
    let loaded = RcBlock::new(
        move |managers: *mut NSArray<NETunnelProviderManager>, error: *mut NSError| {
            if let Err(e) = operation.check() {
                completion(Err(e));
                return;
            }
            if !error.is_null() {
                completion(Err("profile_load_failed"));
                return;
            }
            let Some(managers) = (unsafe { managers.as_ref() }) else {
                completion(Err("profile_inventory_absent"));
                return;
            };
            let selected: Vec<_> = managers
                .iter()
                .filter(|m| same_provider_id(m, target.provider_id()))
                .collect();
            if selected.len() != 1 {
                completion(Err("exact_owned_profile_required"));
                return;
            }
            let intent = match target.resolve(&selected[0]) {
                Ok(intent) => intent,
                Err(code) => {
                    completion(Err(code));
                    return;
                }
            };
            let manager = selected[0].clone();
            let refreshed = manager.clone();
            let intent = intent.clone();
            let operation = operation.clone();
            let completion = completion.clone();
            let reloaded = RcBlock::new(move |error: *mut NSError| {
                if let Err(e) = operation.check() {
                    completion(Err(e));
                    return;
                }
                if !error.is_null() || !intent.matches(&refreshed) {
                    completion(Err("profile_generation_changed"));
                    return;
                }
                if matches!(action, Action::RepairRuntime) {
                    let typed_saved = unsafe { refreshed.protocolConfiguration() }
                        .and_then(|p| p.downcast::<NETunnelProviderProtocol>().ok())
                        .ok_or("saved_profile_protocol_missing")
                        .and_then(|p| saved_provider_intent(&p));
                    let typed_saved = match typed_saved {
                        Ok(saved)
                            if saved.matches_returned_owner(
                                &intent.owner_generation,
                                &intent.policy,
                            ) =>
                        {
                            saved
                        }
                        _ => {
                            completion(Err("saved_profile_typed_intent_mismatch"));
                            return;
                        }
                    };
                    // Host-only record (kept pending the owner decision);
                    // the provider derives its binding itself since S03p4,
                    // so a failure here does not gate provider start.
                    if HostRuntimePublisher::capture()
                        .and_then(|mut owner| owner.publish(&typed_saved))
                        .is_err()
                    {
                        completion(Err("runtime_publication_failed"));
                        return;
                    }
                    completion(Ok(unsafe { refreshed.connection().status() }));
                    return;
                }
                unsafe {
                    let connection = refreshed.connection();
                    match action {
                        Action::Connect(window) => {
                            if !refreshed.isEnabled()
                                || connection.status() != NEVPNStatus::Disconnected
                            {
                                completion(Err("connect_state_refused"));
                                return;
                            }
                            let started = match start_options(window) {
                                None => connection.startVPNTunnelAndReturnError(),
                                Some(options) => connection
                                    .startVPNTunnelWithOptions_andReturnError(Some(&options)),
                            };
                            if started.is_err() {
                                completion(Err("provider_start_refused"));
                                return;
                            }
                        }
                        Action::Disconnect => connection.stopVPNTunnel(),
                        Action::Status => {}
                        Action::RepairRuntime => unreachable!("handled before connection action"),
                    }
                    // Requested start/stop is not observed terminal or delivery.
                    completion(Ok(connection.status()));
                }
            });
            unsafe {
                manager.loadFromPreferencesWithCompletionHandler(&reloaded);
            }
        },
    );
    unsafe {
        NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&loaded);
    }
}
fn is_this_provider(manager: &NETunnelProviderManager) -> bool {
    unsafe {
        manager
            .protocolConfiguration()
            .and_then(|p| p.downcast::<NETunnelProviderProtocol>().ok())
            .and_then(|p| p.providerBundleIdentifier())
            .is_some_and(|id| id.to_string() == PROVIDER_ID)
    }
}

/// Every saved manager of this provider, with no owner-generation or intent
/// gate: lifecycle and emergency verbs must reach mutated or stale
/// generations of this provider too. Other providers are never selected.
fn provider_managers(
    managers: *mut NSArray<NETunnelProviderManager>,
    error: *mut NSError,
) -> Result<Vec<Retained<NETunnelProviderManager>>, &'static str> {
    if !error.is_null() {
        return Err("profile_load_failed");
    }
    let managers = unsafe { managers.as_ref() }.ok_or("profile_inventory_absent")?;
    Ok(managers.iter().filter(|m| is_this_provider(m)).collect())
}

/// The scutil (`scutil --nc list`) service id is the NEConfiguration
/// identifier, which NEVPNManager does not expose publicly. This reads the
/// private `configuration.identifier` getters only when both respond and the
/// value is an NSUUID; otherwise it is unavailable. Diagnostic only: the
/// attended installed run must cross-check it against `scutil --nc list`.
pub(crate) fn scutil_service_id(manager: &NETunnelProviderManager) -> Option<String> {
    if !manager.respondsToSelector(sel!(configuration)) {
        return None;
    }
    let configuration: Option<Retained<NSObject>> = unsafe { msg_send![manager, configuration] };
    let configuration = configuration?;
    if !configuration.respondsToSelector(sel!(identifier)) {
        return None;
    }
    let identifier: Option<Retained<NSObject>> = unsafe { msg_send![&*configuration, identifier] };
    let uuid = identifier?.downcast::<NSUUID>().ok()?;
    Some(uuid.UUIDString().to_string())
}

pub struct ProfileListing {
    /// The saved `owner_generation`, only when it is a printable token.
    pub owner_generation: Option<String>,
    pub scutil_service_id: Option<String>,
    /// The saved typed intent parses (exact shape/schema/policy) and on-demand
    /// is off. Not an ownership grant.
    pub intent_valid: bool,
    pub enabled: bool,
    pub on_demand_enabled: bool,
    pub status: NEVPNStatus,
    /// Why the saved intent did not parse, for installed diagnosis only.
    pub intent_error: Option<&'static str>,
    /// The persisted protocol flags the provider shape check compares, as
    /// read back from the system (include_all, exclude_local, exclude_apns,
    /// exclude_cellular, exclude_device, enforce_routes).
    pub flags: Option<[bool; 6]>,
}

fn listing(manager: &NETunnelProviderManager) -> ProfileListing {
    let protocol = unsafe { manager.protocolConfiguration() }
        .and_then(|p| p.downcast::<NETunnelProviderProtocol>().ok());
    let owner_generation = protocol
        .as_ref()
        .and_then(|p| unsafe { p.providerConfiguration() })
        .and_then(|d| d.objectForKey(&NSString::from_str("owner_generation")))
        .and_then(|v| v.downcast::<NSString>().ok())
        .map(|v| v.to_string())
        .filter(|v| crate::host_lifecycle::printable_token(v).is_some());
    let on_demand_enabled = unsafe { manager.isOnDemandEnabled() };
    let parsed = protocol
        .as_ref()
        .map(|p| saved_provider_intent(p).map(|_| ()));
    let flags = protocol.as_deref().map(protocol_flags);
    ProfileListing {
        owner_generation,
        scutil_service_id: scutil_service_id(manager),
        intent_valid: !on_demand_enabled && matches!(parsed, Some(Ok(()))),
        enabled: unsafe { manager.isEnabled() },
        on_demand_enabled,
        status: unsafe { manager.connection().status() },
        intent_error: match parsed {
            None => Some("wrong_provider_protocol"),
            Some(Err(code)) => Some(code),
            Some(Ok(())) => None,
        },
        flags,
    }
}

pub type ListCompletion = Arc<dyn Fn(Result<Vec<ProfileListing>, &'static str>) + 'static>;

/// Read-only inventory of this provider's saved profiles.
pub fn list_provider(operation: Operation, completion: ListCompletion) {
    if objc2::MainThreadMarker::new().is_none() {
        completion(Err("main_thread_required"));
        return;
    }
    let loaded = RcBlock::new(
        move |managers: *mut NSArray<NETunnelProviderManager>, error: *mut NSError| {
            let result = operation
                .check()
                .and_then(|()| provider_managers(managers, error))
                .map(|found| found.iter().map(|m| listing(m)).collect());
            completion(result);
        },
    );
    unsafe {
        NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&loaded);
    }
}

pub struct StopReport {
    pub owner_generation: Option<String>,
    pub status_before: NEVPNStatus,
    /// On-demand may restart the tunnel; `--remove-profile` removes it.
    pub on_demand_enabled: bool,
}

pub type StopCompletion = Arc<dyn Fn(Result<Vec<StopReport>, &'static str>) + 'static>;

/// stopVPNTunnel on every manager of this provider. Deliberately not gated on
/// an exact owner generation or intent match; a requested stop is not an
/// observed disconnect.
pub fn emergency_stop(operation: Operation, completion: StopCompletion) {
    if objc2::MainThreadMarker::new().is_none() {
        completion(Err("main_thread_required"));
        return;
    }
    let loaded = RcBlock::new(
        move |managers: *mut NSArray<NETunnelProviderManager>, error: *mut NSError| {
            let result = operation
                .check()
                .and_then(|()| provider_managers(managers, error))
                .map(|found| {
                    found
                        .iter()
                        .map(|manager| {
                            let before = listing(manager);
                            unsafe { manager.connection().stopVPNTunnel() };
                            StopReport {
                                owner_generation: before.owner_generation,
                                status_before: before.status,
                                on_demand_enabled: before.on_demand_enabled,
                            }
                        })
                        .collect()
                });
            completion(result);
        },
    );
    unsafe {
        NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&loaded);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RemovalReport {
    pub found: usize,
    pub removed: usize,
    pub failed: usize,
    /// This provider's profiles present on a fresh reload after removal.
    pub remaining: usize,
}
impl RemovalReport {
    pub fn complete(&self) -> bool {
        self.failed == 0 && self.remaining == 0 && self.removed == self.found
    }
}

pub type RemovalCompletion = Arc<dyn Fn(Result<RemovalReport, &'static str>) + 'static>;

fn verify_removed(operation: Operation, report: RemovalReport, completion: RemovalCompletion) {
    let reloaded = RcBlock::new(
        move |managers: *mut NSArray<NETunnelProviderManager>, error: *mut NSError| {
            completion(
                operation
                    .check()
                    .and_then(|()| provider_managers(managers, error))
                    .map(|left| RemovalReport {
                        remaining: left.len(),
                        ..report
                    }),
            );
        },
    );
    unsafe {
        NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&reloaded);
    }
}

/// removeFromPreferences on every saved profile of this provider, then a
/// fresh inventory confirms none remain. Bounded by `operation`; a removal
/// still pending at expiry is an unknown result, never success.
pub fn remove_provider_profiles(operation: Operation, completion: RemovalCompletion) {
    if objc2::MainThreadMarker::new().is_none() {
        completion(Err("main_thread_required"));
        return;
    }
    let loaded = RcBlock::new(
        move |managers: *mut NSArray<NETunnelProviderManager>, error: *mut NSError| {
            let found = match operation
                .check()
                .and_then(|()| provider_managers(managers, error))
            {
                Ok(found) => found,
                Err(e) => {
                    completion(Err(e));
                    return;
                }
            };
            let report = Rc::new(Cell::new(RemovalReport {
                found: found.len(),
                ..RemovalReport::default()
            }));
            if found.is_empty() {
                verify_removed(operation.clone(), report.get(), completion.clone());
                return;
            }
            for manager in found {
                let report = report.clone();
                let operation = operation.clone();
                let completion = completion.clone();
                let removed = RcBlock::new(move |error: *mut NSError| {
                    let mut current = report.get();
                    if error.is_null() {
                        current.removed += 1;
                    } else {
                        current.failed += 1;
                    }
                    report.set(current);
                    if current.removed + current.failed != current.found {
                        return;
                    }
                    if let Err(e) = operation.check() {
                        completion(Err(e));
                        return;
                    }
                    verify_removed(operation.clone(), current, completion.clone());
                });
                unsafe {
                    manager.removeFromPreferencesWithCompletionHandler(Some(&removed));
                }
            }
        },
    );
    unsafe {
        NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&loaded);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::fullwide_manager;

    #[test]
    fn manager_removal_report_requires_every_profile_gone() {
        let done = RemovalReport {
            found: 2,
            removed: 2,
            failed: 0,
            remaining: 0,
        };
        assert!(done.complete());
        assert!(RemovalReport::default().complete());
        assert!(!RemovalReport { failed: 1, ..done }.complete());
        assert!(!RemovalReport {
            remaining: 1,
            ..done
        }
        .complete());
        assert!(!RemovalReport { removed: 1, ..done }.complete());
    }

    #[test]
    fn manager_listing_reports_generation_and_never_selects_other_providers() {
        let policy = FullWide::new(
            "192.0.2.1".parse().unwrap(),
            vec!["2001:db8::53".parse().unwrap()],
            1280,
        )
        .unwrap();
        let manager = fullwide_manager(PROVIDER_ID, &policy).unwrap();
        assert!(is_this_provider(&manager));
        // Unsaved: no provider configuration, so no generation and no valid
        // typed intent; the private service-id read must not crash and is
        // either unavailable or a UUID.
        let listed = listing(&manager);
        assert_eq!(listed.owner_generation, None);
        assert!(!listed.intent_valid);
        assert!(!listed.enabled);
        if let Some(id) = &listed.scutil_service_id {
            assert_eq!(id.len(), 36, "{id}");
            assert!(crate::host_lifecycle::printable_token(id).is_some());
        }
        let intent = ProfileIntent {
            provider_id: PROVIDER_ID.into(),
            owner_generation: "6B29FC40-CA47-1067-B31D-00DD010662DA".into(),
            policy,
        };
        let protocol = unsafe { manager.protocolConfiguration() }
            .unwrap()
            .downcast::<NETunnelProviderProtocol>()
            .unwrap();
        unsafe { protocol.setProviderConfiguration(Some(&intent.dictionary())) };
        let listed = listing(&manager);
        assert_eq!(
            listed.owner_generation.as_deref(),
            Some("6B29FC40-CA47-1067-B31D-00DD010662DA")
        );
        assert!(listed.intent_valid);
        unsafe { manager.setOnDemandEnabled(true) };
        assert!(!listing(&manager).intent_valid);
        unsafe { manager.setOnDemandEnabled(false) };
        // An unprintable saved generation is withheld, not echoed.
        let hostile = ProfileIntent {
            owner_generation: "gen with space".into(),
            ..intent
        };
        unsafe { protocol.setProviderConfiguration(Some(&hostile.dictionary())) };
        assert_eq!(listing(&manager).owner_generation, None);
        // Another provider's manager is never selected.
        unsafe {
            protocol.setProviderBundleIdentifier(Some(&NSString::from_str("dev.aegis.macos.Other")))
        };
        assert!(!is_this_provider(&manager));
        unsafe { protocol.setProviderBundleIdentifier(None) };
        assert!(!is_this_provider(&manager));
    }

    /// S16a: the manager `--save-profile` writes from provider terms is what
    /// the provider's own `saved_provider_intent` parser accepts, field for
    /// field, with the full-wide shape and on-demand off.
    #[test]
    fn saveable_manager_from_profile_terms_round_trips_through_the_provider_parser() {
        use crate::{
            profile_terms::{host_policy, ProfileTerms},
            provider_xpc::Reply,
        };
        let terms = ProfileTerms {
            relay: "192.168.1.107:443".parse().unwrap(),
            dns: vec![
                "198.19.255.2".parse().unwrap(),
                "fd00:ae61::2".parse().unwrap(),
            ],
            mtu: 1280,
            profile_sha256: "c".repeat(64),
        };
        let (_, policy) = host_policy(
            Ok(Reply::ProfileTerms(terms.clone())),
            "192.168.1.107".parse().unwrap(),
        )
        .unwrap();
        let generation = fresh_owner_generation();
        assert_eq!(generation.len(), 36);
        assert_ne!(generation, fresh_owner_generation());
        let intent = ProfileIntent {
            provider_id: PROVIDER_ID.into(),
            owner_generation: generation.clone(),
            policy: policy.clone(),
        };
        let manager = saveable_manager(&intent).unwrap();
        let protocol = unsafe { manager.protocolConfiguration() }
            .unwrap()
            .downcast::<NETunnelProviderProtocol>()
            .unwrap();
        let config = unsafe { protocol.providerConfiguration() }.unwrap();
        let mut keys: Vec<String> = config.allKeys().iter().map(|k| k.to_string()).collect();
        keys.sort();
        assert_eq!(keys, ["dns", "mtu", "owner_generation", "relay", "schema"]);
        let text = |key: &str| {
            config
                .objectForKey(&NSString::from_str(key))
                .unwrap()
                .downcast::<NSString>()
                .unwrap()
                .to_string()
        };
        assert_eq!(text("schema"), "aegis-ne-profile-v1");
        assert_eq!(text("owner_generation"), generation);
        assert_eq!(text("relay"), "192.168.1.107");
        assert_eq!(text("dns"), "198.19.255.2,fd00:ae61::2");
        assert_eq!(text("mtu"), "1280");
        // The provider's real parser accepts exactly this intent.
        let parsed = saved_provider_intent(&protocol).unwrap();
        assert_eq!(parsed.generation, generation);
        assert_eq!(parsed.policy, policy);
        assert!(parsed.matches_returned_owner(&generation, &policy));
        assert!(intent.matches(&manager));
        unsafe {
            assert!(protocol.includeAllNetworks());
            assert!(!protocol.excludeLocalNetworks());
            assert!(!protocol.excludeAPNs());
            assert!(!protocol.excludeCellularServices());
            assert!(!protocol.excludeDeviceCommunication());
            assert!(!protocol.enforceRoutes());
            assert!(manager.isEnabled());
            assert!(!manager.isOnDemandEnabled());
            assert_eq!(
                protocol.serverAddress().unwrap().to_string(),
                "192.168.1.107"
            );
        }
        // On-demand switched on is no longer the owned intent.
        unsafe { manager.setOnDemandEnabled(true) };
        assert!(!intent.matches(&manager));
        // Another provider id is refused before any manager exists.
        let other = ProfileIntent {
            provider_id: "dev.aegis.macos.Other".into(),
            ..intent
        };
        assert!(saveable_manager(&other).is_err());
    }

    /// S16d: `apply_intent` yields the full-wide shape and a parsable typed
    /// intent both on a fresh manager and on a manager whose protocol had
    /// default (macOS-dropped) flags and a stale configuration, and it
    /// replaces that protocol rather than editing it.
    #[test]
    fn apply_intent_writes_the_fullwide_shape_over_any_prior_protocol() {
        #[track_caller]
        fn assert_fullwide(manager: &NETunnelProviderManager, intent: &ProfileIntent) {
            let protocol = provider_configuration(manager);
            assert_eq!(protocol_flags(&protocol), FULLWIDE_FLAGS);
            assert!(crate::configuration::provider_shape_matches(&protocol));
            let parsed = saved_provider_intent(&protocol).unwrap();
            assert!(parsed.matches_returned_owner(&intent.owner_generation, &intent.policy));
            assert!(intent.matches(manager));
            assert_eq!(verify_reloaded(intent, manager), Ok(()));
            unsafe {
                assert!(manager.isEnabled());
                assert!(!manager.isOnDemandEnabled());
                assert_eq!(
                    manager.localizedDescription().unwrap().to_string(),
                    LOCALIZED_DESCRIPTION
                );
                assert_eq!(
                    protocol.serverAddress().unwrap().to_string(),
                    intent.policy.relay().to_string()
                );
            }
        }
        let intent = owned_intent();
        // A fresh manager.
        let fresh: Retained<NETunnelProviderManager> =
            unsafe { msg_send![NETunnelProviderManager::alloc(), init] };
        assert!(unsafe { fresh.protocolConfiguration() }.is_none());
        apply_intent(&fresh, &intent).unwrap();
        assert_fullwide(&fresh, &intent);

        // The installed v10 readback: includeAllNetworks off, every
        // exclusion at its default, a stale generation, on-demand on and
        // disabled.
        let stale = ProfileIntent {
            owner_generation: fresh_owner_generation(),
            ..intent.clone()
        };
        let existing = saveable_manager(&stale).unwrap();
        let old: Retained<NETunnelProviderProtocol> =
            unsafe { msg_send![NETunnelProviderProtocol::alloc(), init] };
        unsafe {
            old.setProviderBundleIdentifier(Some(&NSString::from_str(PROVIDER_ID)));
            old.setServerAddress(Some(&NSString::from_str("192.168.1.107")));
            old.setIncludeAllNetworks(false);
            old.setExcludeLocalNetworks(false);
            old.setExcludeAPNs(true);
            old.setExcludeCellularServices(true);
            old.setExcludeDeviceCommunication(true);
            old.setEnforceRoutes(false);
            old.setProviderConfiguration(Some(&stale.dictionary()));
            existing.setProtocolConfiguration(Some(&old));
            existing.setOnDemandEnabled(true);
            existing.setEnabled(false);
            existing.setLocalizedDescription(Some(&NSString::from_str("other")));
        }
        let before = verify_reloaded(&stale, &existing).unwrap_err();
        assert_eq!(before.code, "profile_flags_not_persisted");
        assert_eq!(
            before.reloaded_flags,
            Some([false, false, true, true, true, false])
        );
        apply_intent(&existing, &intent).unwrap();
        assert_fullwide(&existing, &intent);
        // The old generation no longer resolves; the old protocol object was
        // not edited in place.
        assert!(!stale.matches(&existing));
        assert!(!protocol_flags(&old)[0]);
        assert!(!std::ptr::eq(
            &*provider_configuration(&existing),
            &*old as &NETunnelProviderProtocol
        ));

        // A foreign provider id is refused before the manager is touched.
        let foreign = ProfileIntent {
            provider_id: "dev.aegis.macos.Other".into(),
            ..owned_intent()
        };
        assert_eq!(
            apply_intent(&existing, &foreign),
            Err("invalid_provider_identifier")
        );
        assert_fullwide(&existing, &intent);
    }

    /// S16d: the reload check names dropped flags, then generation, then the
    /// typed parser, and always carries the reloaded flags.
    #[test]
    fn verify_reloaded_reports_dropped_flags_with_the_readback() {
        let intent = owned_intent();
        let manager = saveable_manager(&intent).unwrap();
        assert_eq!(verify_reloaded(&intent, &manager), Ok(()));
        let flip = |index: usize| {
            let manager = saveable_manager(&intent).unwrap();
            let protocol = provider_configuration(&manager);
            unsafe {
                match index {
                    0 => protocol.setIncludeAllNetworks(false),
                    1 => protocol.setExcludeLocalNetworks(true),
                    2 => protocol.setExcludeAPNs(true),
                    3 => protocol.setExcludeCellularServices(true),
                    4 => protocol.setExcludeDeviceCommunication(true),
                    _ => protocol.setEnforceRoutes(true),
                }
            }
            manager
        };
        for index in 0..6 {
            let mut expected = FULLWIDE_FLAGS;
            expected[index] = !expected[index];
            assert_eq!(
                verify_reloaded(&intent, &flip(index)),
                Err(SaveFailure {
                    code: "profile_flags_not_persisted",
                    reloaded: true,
                    reloaded_flags: Some(expected),
                }),
                "flag {index}"
            );
        }
        // Right flags, another generation: not a flag failure.
        let other = ProfileIntent {
            owner_generation: fresh_owner_generation(),
            ..intent.clone()
        };
        assert_eq!(
            verify_reloaded(&other, &manager),
            Err(SaveFailure {
                code: "saved_profile_generation_mismatch",
                reloaded: true,
                reloaded_flags: Some(FULLWIDE_FLAGS),
            })
        );
        let generation = other.owner_generation.clone();
        assert_eq!(
            verify_reloaded(&other, &manager)
                .unwrap_err()
                .reloaded_line(&generation),
            Some(format!(
                "reloaded_profile owner_generation={generation} include_all=true \
exclude_local=false exclude_apns=false exclude_cellular=false exclude_device=false \
enforce_routes=false"
            ))
        );
        // On-demand on is refused as not the owned intent.
        unsafe { manager.setOnDemandEnabled(true) };
        assert_eq!(
            verify_reloaded(&intent, &manager).unwrap_err().code,
            "saved_profile_generation_mismatch"
        );
        // No protocol at all.
        let empty: Retained<NETunnelProviderManager> =
            unsafe { msg_send![NETunnelProviderManager::alloc(), init] };
        assert_eq!(
            verify_reloaded(&intent, &empty),
            Err(SaveFailure {
                code: "saved_profile_protocol_missing",
                reloaded: true,
                reloaded_flags: None,
            })
        );
        // A post-reload failure without a provider protocol still prints
        // its one line.
        assert_eq!(
            verify_reloaded(&intent, &empty)
                .unwrap_err()
                .reloaded_line("C21E2D4A-0000-4000-8000-000000000000"),
            Some(
                "reloaded_profile owner_generation=C21E2D4A-0000-4000-8000-000000000000 \
flags=unavailable"
                    .to_string()
            )
        );
        // Refusals before the save, save errors and reload errors print none.
        for code in [
            "profile_save_failed",
            "profile_reload_failed",
            "existing_provider_profile_refused",
        ] {
            let failure = SaveFailure::from(code);
            assert_eq!(
                failure,
                SaveFailure {
                    code,
                    reloaded: false,
                    reloaded_flags: None,
                }
            );
            assert_eq!(
                failure.reloaded_line("C21E2D4A-0000-4000-8000-000000000000"),
                None
            );
        }
    }

    /// S16d: without `--replace-existing` any existing profile of this
    /// provider refuses; with it exactly one idle one is modified; zero is a
    /// plain create; other providers are never selected or counted.
    #[test]
    fn save_target_replaces_only_the_one_idle_profile_of_this_provider() {
        let own = SaveCandidate {
            same_provider: true,
            idle: true,
        };
        let busy = SaveCandidate { idle: false, ..own };
        let foreign = SaveCandidate {
            same_provider: false,
            idle: true,
        };
        let foreign_busy = SaveCandidate {
            same_provider: false,
            idle: false,
        };
        use SaveMode::{New, ReplaceExisting};
        for mode in [New, ReplaceExisting] {
            assert_eq!(save_target(&[], mode), Ok(SaveTarget::Create));
            assert_eq!(
                save_target(&[foreign, foreign_busy], mode),
                Ok(SaveTarget::Create)
            );
        }
        for existing in [
            &[own][..],
            &[busy],
            &[foreign, own],
            &[own, own],
            &[busy, own],
        ] {
            assert_eq!(
                save_target(existing, New),
                Err("existing_provider_profile_refused"),
                "{existing:?}"
            );
        }
        assert_eq!(
            save_target(&[own], ReplaceExisting),
            Ok(SaveTarget::Replace(0))
        );
        assert_eq!(
            save_target(&[foreign, foreign_busy, own, foreign], ReplaceExisting),
            Ok(SaveTarget::Replace(2))
        );
        for many in [&[own, own][..], &[foreign, own, foreign, own], &[busy, own]] {
            assert_eq!(
                save_target(many, ReplaceExisting),
                Err("multiple_provider_profiles_refused"),
                "{many:?}"
            );
        }
        assert_eq!(
            save_target(&[foreign, busy], ReplaceExisting),
            Err("existing_profile_not_idle")
        );
        assert!(is_idle(NEVPNStatus::Disconnected));
        assert!(is_idle(NEVPNStatus::Invalid));
        for live in [
            NEVPNStatus::Connecting,
            NEVPNStatus::Connected,
            NEVPNStatus::Reasserting,
            NEVPNStatus::Disconnecting,
        ] {
            assert!(!is_idle(live), "{live:?}");
        }
    }

    #[test]
    fn cancelled_operation_never_permits_late_followup() {
        let op = Operation::begin();
        let callback = op.clone();
        op.cancel();
        assert_eq!(callback.check(), Err("operation_expired"));
    }

    /// S16a: the terms query and the preference operation spend one budget,
    /// so a profile verb is bounded at 30 s in all.
    #[test]
    fn operation_remaining_is_one_shared_budget() {
        let op = Operation::begin();
        let left = op.remaining();
        assert!(left <= PROFILE_VERB_BUDGET);
        assert!(left > PROFILE_VERB_BUDGET - Duration::from_secs(5));
        assert_eq!(PROFILE_VERB_BUDGET, Duration::from_secs(30));
        // A clone shares the deadline; time spent before it is not refunded.
        assert!(op.clone().remaining() <= left);
        let spent = Operation::until(Instant::now() + Duration::from_millis(20));
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(spent.remaining(), Duration::ZERO);
        assert_eq!(spent.check(), Err("operation_expired"));
    }

    fn owned_intent() -> ProfileIntent {
        let policy = FullWide::new(
            "192.168.1.107".parse().unwrap(),
            vec![
                "198.19.255.2".parse().unwrap(),
                "fd00:ae61::2".parse().unwrap(),
            ],
            1280,
        )
        .unwrap();
        ProfileIntent {
            provider_id: PROVIDER_ID.into(),
            owner_generation: fresh_owner_generation(),
            policy,
        }
    }

    fn saved_target(intent: &ProfileIntent) -> OwnedTarget {
        OwnedTarget::Saved {
            provider_id: intent.provider_id.clone(),
            owner_generation: intent.owner_generation.clone(),
            relay: intent.policy.relay(),
        }
    }

    fn provider_configuration(
        manager: &NETunnelProviderManager,
    ) -> Retained<NETunnelProviderProtocol> {
        unsafe { manager.protocolConfiguration() }
            .unwrap()
            .downcast::<NETunnelProviderProtocol>()
            .unwrap()
    }

    #[test]
    fn owned_action_needs_terms_only_to_connect_or_repair() {
        assert!(Action::Connect(WindowMode::Adaptive).needs_terms());
        assert!(Action::Connect(WindowMode::Fixed).needs_terms());
        assert!(Action::RepairRuntime.needs_terms());
        assert!(!Action::Disconnect.needs_terms());
        assert!(!Action::Status.needs_terms());
        let intent = owned_intent();
        let terms = OwnedTarget::Terms(intent.clone());
        let saved = saved_target(&intent);
        for action in [
            Action::Connect(WindowMode::Adaptive),
            Action::Connect(WindowMode::Fixed),
            Action::Disconnect,
            Action::Status,
            Action::RepairRuntime,
        ] {
            assert!(terms.admits(action), "{action:?}");
            assert_eq!(saved.admits(action), !action.needs_terms(), "{action:?}");
        }
    }

    /// S16a: a stop or status read matches the saved profile's own typed
    /// intent (exact generation and relay; its own DNS and MTU), with every
    /// check a terms-built intent gets; connect still needs exact terms.
    #[test]
    fn owned_target_resolves_only_the_exact_saved_profile() {
        let intent = owned_intent();
        let manager = saveable_manager(&intent).unwrap();
        let saved = saved_target(&intent);
        let resolved = saved.resolve(&manager).unwrap();
        assert_eq!(resolved.owner_generation, intent.owner_generation);
        assert_eq!(resolved.policy, intent.policy);
        assert_eq!(resolved.provider_id, PROVIDER_ID);
        let exact = OwnedTarget::Terms(intent.clone());
        assert!(exact.resolve(&manager).is_ok());

        #[track_caller]
        fn refused(target: &OwnedTarget, manager: &NETunnelProviderManager) {
            assert_eq!(
                target.resolve(manager).err(),
                Some("exact_owned_profile_required")
            );
        }
        // Another generation, relay or provider id.
        let other = |provider_id: &str, owner_generation: &str, relay: &str| OwnedTarget::Saved {
            provider_id: provider_id.into(),
            owner_generation: owner_generation.into(),
            relay: relay.parse().unwrap(),
        };
        let generation = intent.owner_generation.as_str();
        for target in [
            other(PROVIDER_ID, &fresh_owner_generation(), "192.168.1.107"),
            other(PROVIDER_ID, &generation.to_lowercase(), "192.168.1.107"),
            other(PROVIDER_ID, generation, "192.168.1.108"),
            other(PROVIDER_ID, generation, "::ffff:192.168.1.107"),
            other("dev.aegis.macos.Other", generation, "192.168.1.107"),
        ] {
            refused(&target, &manager);
        }
        // Terms whose DNS or MTU differ from the saved profile: connect
        // refuses, while a stop still reaches the saved profile.
        let changed = ProfileIntent {
            policy: FullWide::new(
                intent.policy.relay(),
                vec!["198.19.255.2".parse().unwrap()],
                1280,
            )
            .unwrap(),
            ..intent.clone()
        };
        refused(&OwnedTarget::Terms(changed), &manager);
        assert!(saved.resolve(&manager).is_ok());

        // A mutated saved profile is refused for every target.
        let mutate = |label: &str, edit: &dyn Fn(&NETunnelProviderManager)| {
            let manager = saveable_manager(&intent).unwrap();
            edit(&manager);
            for target in [&saved, &exact] {
                assert_eq!(
                    target.resolve(&manager).err(),
                    Some("exact_owned_profile_required"),
                    "{label}"
                );
            }
        };
        mutate("on_demand", &|m| unsafe { m.setOnDemandEnabled(true) });
        mutate("include_all", &|m| unsafe {
            provider_configuration(m).setIncludeAllNetworks(false)
        });
        mutate("enforce_routes", &|m| unsafe {
            provider_configuration(m).setEnforceRoutes(true)
        });
        mutate("server_address", &|m| unsafe {
            provider_configuration(m).setServerAddress(Some(&NSString::from_str("192.168.1.108")))
        });
        let with_config = |entries: &[(&str, &str)]| {
            let entries: Vec<(String, String)> = entries
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            move |m: &NETunnelProviderManager| {
                let keys: Vec<Retained<NSString>> =
                    entries.iter().map(|(k, _)| NSString::from_str(k)).collect();
                let values: Vec<Retained<NSString>> =
                    entries.iter().map(|(_, v)| NSString::from_str(v)).collect();
                let objects: Vec<&AnyObject> = values.iter().map(|v| &**v as &AnyObject).collect();
                let dictionary = NSDictionary::from_slices(
                    &keys.iter().map(|k| &**k).collect::<Vec<_>>(),
                    &objects,
                );
                unsafe { provider_configuration(m).setProviderConfiguration(Some(&dictionary)) };
            }
        };
        let values = intent.values();
        let base: Vec<(&str, &str)> = ["schema", "owner_generation", "relay", "dns", "mtu"]
            .into_iter()
            .zip(values.iter().map(String::as_str))
            .collect();
        // The unchanged dictionary still resolves, so each refusal below is
        // the edit's own.
        let manager = saveable_manager(&intent).unwrap();
        with_config(&base)(&manager);
        assert!(saved.resolve(&manager).is_ok());
        for (key, value) in [
            ("schema", "aegis-ne-profile-v2"),
            ("dns", "not-an-ip"),
            ("mtu", "1279"),
            ("relay", "192.168.1.108"),
        ] {
            let mut edited = base.clone();
            edited.iter_mut().find(|(k, _)| *k == key).unwrap().1 = value;
            mutate(&format!("{key}={value}"), &with_config(&edited));
        }
        // A saved DNS list or MTU that still forms a full-wide policy but is
        // not the provider's terms: connect refuses; a stop or status read
        // reaches the saved profile with its own saved values.
        let mut dns = base.clone();
        dns[3].1 = "198.19.255.2,192.0.2.53";
        let manager = saveable_manager(&intent).unwrap();
        with_config(&dns)(&manager);
        refused(&exact, &manager);
        let own = saved.resolve(&manager).unwrap();
        assert_ne!(own.policy, intent.policy);
        assert_eq!(own.policy.dns().len(), 2);
        assert_eq!(own.policy.relay(), intent.policy.relay());
        let mut extra = base.clone();
        extra.push(("extra", "1"));
        mutate("extra_key", &with_config(&extra));
        mutate("four_keys", &with_config(&base[..4]));
    }

    /// T26 (v35; v36, outcome `fixed`): the default (fixed) window's connect
    /// passes no start options, as an on-demand or System Settings start
    /// does, and the provider reads that as the fixed window; the v35
    /// window's connect passes exactly the one key and value the provider
    /// accepts for it.
    #[test]
    fn a_connect_passes_start_options_only_for_the_adaptive_window() {
        assert!(start_options(WindowMode::Fixed).is_none());
        assert!(start_options(WindowMode::default()).is_none());
        assert_eq!(crate::apple::start_window_mode(None), Ok(WindowMode::Fixed));
        let options = start_options(WindowMode::Adaptive).unwrap();
        assert_eq!(options.len(), 1);
        let keys: Vec<String> = options.allKeys().iter().map(|k| k.to_string()).collect();
        assert_eq!(keys, [WINDOW_POLICY_OPTION]);
        let value = options
            .objectForKey(&NSString::from_str(WINDOW_POLICY_OPTION))
            .unwrap()
            .downcast::<NSString>()
            .unwrap()
            .to_string();
        assert_eq!(value, WINDOW_POLICY_ADAPTIVE);
        // The provider reads it back as the v35 window.
        assert_eq!(
            crate::apple::start_window_mode(Some(&options)),
            Ok(WindowMode::Adaptive)
        );
    }
}
