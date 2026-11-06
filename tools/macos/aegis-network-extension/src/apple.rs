//! Rust NE provider with main-runloop output drain and owned engine termination.
//! `provider_main` links the one composite session factory before the system
//! extension starts. Start completes only once that session reports Ready and
//! the tunnel settings are applied; stop completes only once it has joined.
//! A running session that is lost recoverably (S17) never cancels the
//! tunnel: the settings stay, `reasserting` is set, native packets are
//! dropped and a fresh session is rebuilt; only an explicit stop or a
//! terminal custody failure cancels. Under S18 a wake forces one re-ACK (or
//! the rebuild, when the lease lapsed during sleep), and a physical path
//! change re-pins the relay interface and rebuilds.
use crate::{
    app_group::{
        custody_refusal_code, CapturedAppGroupInputs, CapturedRenewalInputs, PROVIDER_APP_GROUP,
    },
    bridge::LeasedPacketBridge,
    configuration::{
        provider_intent_matches, saved_provider_intent, SavedProviderIntent, WindowMode,
        WINDOW_POLICY_OPTION,
    },
    identity_renewal::{self, Action, RenewalHandle},
    leak_guard::{self, ArmToken, Gate, Peer, PeerSet, LEAK_GUARD},
    path_watch::{self, EpochPath, RepinEffect, WakeAction},
    policy::{Effect, FullWide, Lifecycle, Phase, INTERFACE_V4, INTERFACE_V6, INTERFACE_V6_PREFIX},
    provider_session::{SessionHandle, SessionPhase, SessionProbe},
    provider_session_body::{self, EpochPins, GuardEndpoints},
    provider_xpc,
    relay_socket::{self, RelayInterface},
    session_rebuild::{
        self, Disposition, Finished, Lost, Rebuild, RebuildFactory, Rebuilds, Refusal,
    },
};
use block2::{DynBlock, RcBlock};
use objc2::{
    define_class,
    rc::{Allocated, Retained},
    sel, AnyThread, ClassType, DefinedClass,
};
use objc2_foundation::{
    NSArray, NSData, NSDictionary, NSError, NSNumber, NSObject, NSObjectNSThreadPerformAdditions,
    NSObjectProtocol, NSRunLoop, NSRunLoopCommonModes, NSString, NSTimer,
};
use objc2_network_extension::{
    NEDNSSettings, NEIPv4Route, NEIPv4Settings, NEIPv6Route, NEIPv6Settings,
    NEPacketTunnelNetworkSettings, NEPacketTunnelProvider, NEProvider, NEProviderStopReason,
    NETunnelProviderProtocol,
};
use std::{
    ffi::CString,
    io,
    ptr::NonNull,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::{Duration, Instant, SystemTime},
};
/// Provider exit status when a session has not joined within the stop budget.
const STOP_BUDGET_EXIT: i32 = 70;
pub(crate) const STOP_BUDGET: Duration = Duration::from_secs(2);
// The composite session owns the complete credential, relay, renewal and ACK
// lifetime. Packet mechanics and descriptor-held App Group inputs alone are
// never an authorization: only its Ready, under a live ACK lease, is.
struct AdmittedEngine {
    generation: String,
    policy: FullWide,
    // Exact clone from the session, retained outside its mutex for poison-safe seal.
    bridge: LeasedPacketBridge,
    // Native callbacks use only this: an atomic phase plus the leased bridge.
    probe: SessionProbe,
    // The session thread owns the signed App Group claim, held Store, relay
    // channel and packet engine. Provider state retains the handle until that
    // thread has actually returned.
    session: Arc<Mutex<SessionHandle>>,
    // The epoch's relay interface, pinned by its first session (S17).
    pinned: EpochPins,
    // S17: the rebuild after a recoverable loss (it owns the lost session's
    // join and every session it builds until one is swapped in), the backoff
    // carried across rebuilds and a pending retry of a failed spawn.
    rebuilds: Rebuilds,
    // v31: when the current session went live (the epoch Running, or a
    // rebuilt session swapped in): the renewal monitor never seals one
    // younger than the S17 stable period.
    live_since: Option<Instant>,
}
struct FactoryResult {
    generation: String,
    policy: FullWide,
    // The factory must consume the one signed claim into this session.
    session: SessionHandle,
    pinned: EpochPins,
}
impl AdmittedEngine {
    fn from_result(result: FactoryResult) -> Self {
        let probe = result.session.probe();
        // Weak diagnostic view for the XPC `status`/`ping` verbs only.
        provider_xpc::publish_session(probe.phase_reader());
        Self {
            generation: result.generation,
            policy: result.policy,
            bridge: probe.bridge().clone(),
            probe,
            session: Arc::new(Mutex::new(result.session)),
            pinned: result.pinned,
            rebuilds: Rebuilds::default(),
            live_since: None,
        }
    }
    /// S17: the packet path follows a rebuilt Ready session. The lost one
    /// has already joined inside the rebuild; settings are not re-applied.
    fn swap(&mut self, session: SessionHandle) {
        let probe = session.probe();
        provider_xpc::publish_session(probe.phase_reader());
        self.bridge = probe.bridge().clone();
        self.probe = probe;
        self.session = Arc::new(Mutex::new(session));
        self.live_since = Some(Instant::now());
    }
    /// Builds each rebuilt session: the S23 renewal step (its sockets bound
    /// to the epoch's pinned interface), then a fresh signed claim (its
    /// custody refusal is terminal), the retained saved intent and pinned
    /// interface.
    fn rebuild_factory(&self) -> RebuildFactory {
        let generation = self.generation.clone();
        let policy = self.policy.clone();
        let pinned = self.pinned.clone();
        Box::new(move |notifier, stop| {
            let renewal = pinned.renewal();
            let pins = pinned.clone();
            let interface = move |_| pins.get().ok_or(relay_socket::UNRESOLVED);
            identity_renewal::before_capture(
                &identity_renewal::Step {
                    renewal: &renewal,
                    interface: &interface,
                    stop,
                    #[cfg(test)]
                    bound: None,
                },
                || CapturedRenewalInputs::capture_claim(PROVIDER_APP_GROUP),
            )?;
            let claim = CapturedAppGroupInputs::capture_claim(PROVIDER_APP_GROUP)
                .map_err(|error| Refusal::custody(&error))?;
            let saved = SavedProviderIntent {
                generation: generation.clone(),
                policy: policy.clone(),
            };
            provider_session_body::start_session(saved, claim, notifier, pinned.clone())
                .map_err(|_| Refusal::transient("session_spawn_failed"))
        })
    }
    // Per-packet path: no Store, filesystem or join-lock access. The session
    // body revalidates the Store and renews the lease, sealing on failure.
    fn with_live_session<T>(
        &self,
        action: impl FnOnce(&LeasedPacketBridge) -> io::Result<T>,
    ) -> io::Result<T> {
        if !self.probe.ready() {
            self.probe.seal("packet_path_not_ready");
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let result = action(self.probe.bridge());
        if result.is_err() {
            self.probe.seal("packet_io_failed");
        }
        result
    }
    fn ready_for_native_io(&self) -> bool {
        self.probe.ready()
    }
    fn session_view(&self) -> SessionView {
        classify_session(self.probe.phase(), || self.ready_for_native_io())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionView {
    Constructing,
    Ready,
    Ended,
}
/// Classify one phase snapshot. The lease probe runs only for a Ready
/// snapshot, so a session that turns Ready after the snapshot is still
/// Constructing here (its own Ready notification re-observes it) and is never
/// misread as Ended. A Ready session whose lease probe fails seals and ends.
fn classify_session(phase: SessionPhase, ready: impl FnOnce() -> bool) -> SessionView {
    match phase {
        SessionPhase::Constructing => SessionView::Constructing,
        SessionPhase::Ready if ready() => SessionView::Ready,
        _ => SessionView::Ended,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopTick {
    Joined,
    Pending,
    BudgetExhausted,
}
/// One stop-poll tick. At the deadline the session gets one final join
/// observation, so a session that joined on the deadline tick completes
/// Apple's stop normally rather than exiting the provider.
fn stop_tick(
    mut observe_join: impl FnMut() -> bool,
    deadline_passed: impl FnOnce() -> bool,
) -> StopTick {
    if observe_join() {
        return StopTick::Joined;
    }
    if !deadline_passed() {
        return StopTick::Pending;
    }
    if observe_join() {
        StopTick::Joined
    } else {
        StopTick::BudgetExhausted
    }
}
/// v35: a start option's value that is not a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NotString;
/// v35: the one start option the provider examines, `aegis_window_policy`,
/// as read from the options (`value`: none when the options or the key are
/// absent, as for System Settings and on-demand starts, whose system keys
/// are ignored). v36: absent is the product default, v33's fixed window;
/// the string `adaptive` the v35 window (a QA arm), the string `fixed` the
/// fixed window; any other value or type refuses the start
/// (`window_policy_refused`), so an arm is never mislabelled silently.
pub(crate) fn window_mode_from_options(
    value: Option<Result<&str, NotString>>,
) -> Result<WindowMode, &'static str> {
    match value {
        None => Ok(WindowMode::default()),
        Some(Ok(text)) => WindowMode::from_value(text).ok_or("window_policy_refused"),
        Some(Err(NotString)) => Err("window_policy_refused"),
    }
}
/// v35: `window_mode_from_options` over a start's options dictionary. The
/// start judges it first, before the renewal step or any claim capture, so
/// a refused option consumes no claim and starts no renewal exchange.
pub(crate) fn start_window_mode(
    options: Option<&NSDictionary<NSString, NSObject>>,
) -> Result<WindowMode, &'static str> {
    let value: Option<Result<String, NotString>> = options
        .and_then(|options| options.objectForKey(&NSString::from_str(WINDOW_POLICY_OPTION)))
        .map(|value| {
            value
                .downcast::<NSString>()
                .map(|text| text.to_string())
                .map_err(|_| NotString)
        });
    window_mode_from_options(
        value
            .as_ref()
            .map(|value| value.as_deref().map_err(|_| NotString)),
    )
}
/// Called once, on the session thread, when the session leaves Constructing.
type Notifier = Box<dyn FnOnce(SessionPhase) + Send>;
type Factory = fn(
    &SavedProviderIntent,
    CapturedAppGroupInputs,
    Notifier,
    EpochPins,
) -> Result<FactoryResult, &'static str>;
static FACTORY: OnceLock<Factory> = OnceLock::new();
/// The one production constructor: the composite session body, consuming the
/// signed claim, in the epoch `pinned` (whose renewal state the start's S23
/// step already observed). It returns at once with a Constructing session.
fn composite_session_factory(
    saved: &SavedProviderIntent,
    claim: CapturedAppGroupInputs,
    notifier: Notifier,
    pinned: EpochPins,
) -> Result<FactoryResult, &'static str> {
    let owned = SavedProviderIntent {
        generation: saved.generation.clone(),
        policy: saved.policy.clone(),
    };
    let session = provider_session_body::start_session(owned, claim, notifier, pinned.clone())
        .map_err(|_| "session_spawn_failed")?;
    Ok(FactoryResult {
        generation: saved.generation.clone(),
        policy: saved.policy.clone(),
        session,
        pinned,
    })
}
/// Link the composite session factory. Idempotent: the first call sets it and
/// every later call leaves it in place. True once a factory is linked.
pub(crate) fn register_factory() -> bool {
    let _ = FACTORY.set(composite_session_factory);
    FACTORY.get().is_some()
}
/// One stable refusal or lifecycle code per line, at LOG_NOTICE so the unified
/// log persists it by default. Only a lowercase token of `[a-z0-9_:.-]`
/// passes: no path, IPv4 address, format directive or free text reaches the log.
#[cfg(test)]
fn log_line(event: &str, code: &str) -> Option<CString> {
    log_line_fields(event, &[code])
}
/// `log_line` with one to four space-separated stable fields after the event.
fn log_line_fields(event: &str, fields: &[&str]) -> Option<CString> {
    let stable = |text: &str| {
        text.len() <= 96
            && text.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && text
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_:.-".contains(&b))
    };
    if !stable(event) || fields.is_empty() || fields.len() > 4 || !fields.iter().all(|f| stable(f))
    {
        return None;
    }
    CString::new(format!("aegis-ne {event} {}", fields.join(" "))).ok()
}
/// Test-only: whether `log_fields(event, fields)` would log this line as
/// given, never as `unstable_code`.
#[cfg(test)]
pub(crate) fn stable_fields(event: &str, fields: &[&str]) -> bool {
    log_line_fields(event, fields).is_some()
}
pub(crate) fn log_code(event: &str, code: &str) {
    log_fields(event, &[code]);
}
pub(crate) fn log_fields(event: &str, fields: &[&str]) {
    let line =
        log_line_fields(event, fields).unwrap_or_else(|| c"aegis-ne log unstable_code".into());
    unsafe { libc::syslog(libc::LOG_NOTICE, c"%s".as_ptr(), line.as_ptr()) };
}
/// Posts one generation's session change to the main runloop from the session
/// thread. performSelectorOnMainThread retains its target until the selector
/// runs, so this reference is never the provider's last.
struct MainPoster(Retained<AegisPacketTunnelProvider>);
// SAFETY: only retain/release and performSelectorOnMainThread, which are
// thread-safe, touch the provider off the main thread.
unsafe impl Send for MainPoster {}
impl MainPoster {
    fn post(&self, generation: u64) {
        self.post_to(sel!(sessionChanged:), generation);
    }
    fn post_to(&self, selector: objc2::runtime::Sel, generation: u64) {
        self.0.on_main(selector, generation);
    }
}
type StartCompletion = RcBlock<dyn Fn(*mut NSError)>;
#[derive(Default)]
struct ProviderState {
    lifecycle: Lifecycle,
    engine: Option<AdmittedEngine>,
    constructing: bool,
    timer: Option<(u64, Retained<NSTimer>)>,
    stop_timer: Option<(u64, Retained<NSTimer>, Instant)>,
    start_completion: Option<(u64, StartCompletion)>,
    stop_completion: Option<(u64, RcBlock<dyn Fn()>)>,
    // S18: the running epoch's physical path watch, and sleeps recorded.
    path: Option<(u64, EpochPath)>,
    sleeps: u64,
    // S20b: the epoch that armed the process-wide leak guard and the token
    // of that arm; only this token can open it.
    leak_arm: Option<(u64, ArmToken)>,
    // v26: the epoch that armed the guard and the filter's stop count read
    // just before that arm (`filter_stopped_since_arm`).
    filter_stops_at_arm: Option<(u64, u64)>,
}
#[doc(hidden)]
#[derive(Default)]
pub struct Ivars {
    state: Mutex<ProviderState>,
}
fn error() -> Retained<NSError> {
    unsafe {
        NSError::errorWithDomain_code_userInfo(
            &NSString::from_str("AEGISNetworkExtension"),
            1,
            None,
        )
    }
}
fn retained(p: &AegisPacketTunnelProvider) -> Retained<AegisPacketTunnelProvider> {
    unsafe { Retained::retain(p as *const _ as *mut _).expect("provider lifetime") }
}
fn complete_failure(done: &DynBlock<dyn Fn(*mut NSError)>) {
    done.call(((&*error() as *const NSError).cast_mut(),));
}
fn seal_current_epoch_bridge(
    callback_generation: u64,
    current_generation: u64,
    bridge: Option<&LeasedPacketBridge>,
) {
    if callback_generation == current_generation {
        if let Some(bridge) = bridge {
            bridge.stop();
        }
    }
}
/// S23: whether the start of `generation` was stopped (Apple's stop moves
/// it to Blocking) or superseded while it constructs: then its renewal step
/// ends and nothing is captured.
fn start_stopped(state: &ProviderState, generation: u64) -> bool {
    state.lifecycle.generation != generation || state.lifecycle.phase != Phase::Admitted
}
/// S23 merged with S16j-3: whether the renewal monitor may judge epoch `g`.
/// Only a Running, not constructing epoch: a stop (Blocking, while its
/// session's bounded relay drain runs), a reassert or rebuild (whose factory
/// runs the renewal only after the lost session joined) never starts one.
fn renewal_monitor_applies(state: &ProviderState, g: u64) -> bool {
    state.lifecycle.generation == g
        && !state.constructing
        && state.lifecycle.phase == Phase::Running
}
fn seal_conflicted_bridges(
    constructed: &LeasedPacketBridge,
    existing: Option<&LeasedPacketBridge>,
) {
    constructed.stop();
    if let Some(existing) = existing {
        existing.stop();
    }
}
define_class!(
    #[unsafe(super(NEPacketTunnelProvider))]
    #[name="AegisPacketTunnelProvider"]
    #[ivars=Ivars]
    pub struct AegisPacketTunnelProvider;
    unsafe impl NSObjectProtocol for AegisPacketTunnelProvider{}
    impl AegisPacketTunnelProvider {
        #[unsafe(method_id(init))]
        fn init(this:Allocated<Self>)->Option<Retained<Self>>{let this=this.set_ivars(Ivars::default());unsafe{objc2::msg_send![super(this),init]}}
        #[unsafe(method(startTunnelWithOptions:completionHandler:))]
        fn start(&self,options:Option<&NSDictionary<NSString,NSObject>>,completion:&DynBlock<dyn Fn(*mut NSError)>){
            // Reserve epoch before constructing any worker. Duplicate starts
            // cannot construct/drop an unowned second worker.
            let generation=match self.ivars().state.lock().ok().and_then(|mut s|{
                let g=s.lifecycle.admit().ok()?;s.constructing=true;
                s.start_completion=Some((g,completion.copy()));Some(g)
            }){
                Some(g)=>g,None=>{log_code("start_refused","start_in_progress");complete_failure(completion);return;}
            };
            let poster=MainPoster(retained(self));
            let notifier:Notifier=Box::new(move|_:SessionPhase|poster.post(generation));
            // v40 (CP-D3 M1): the process's access network key for the
            // carrier failover memory (started once, RAM only).
            crate::carrier_network::start();
            // S23: the epoch's renewal state is published for cert-status
            // first, and withdrawn if this start is refused. v31: it is the
            // process-carried handle, so the backoff and the last outcome of
            // this identity outlive the epoch.
            let pinned=EpochPins::with_renewal(RenewalHandle::process());
            let renewal=pinned.renewal();
            identity_renewal::publish(&renewal);
            let admitted:Result<(AdmittedEngine,bool),&'static str>=(||{
                // v35: the start option first, before the renewal step and
                // any capture: a refused option consumes no claim.
                let window_mode=start_window_mode(options)?;
                let protocol=unsafe{self.protocolConfiguration()}.downcast::<NETunnelProviderProtocol>().map_err(|_|"wrong_provider_protocol")?;
                let saved_intent=saved_provider_intent(&protocol)?;
                // S23: a saved response, journaled or due renewal is finished
                // before the capture, on sockets bound to the authority's
                // physical interface (no settings exist yet). A stop of this
                // generation ends the step within its poll, and no capture
                // or session follows it.
                let stopping=||self.ivars().state.lock().map_or(true,|s|start_stopped(&s,generation));
                identity_renewal::before_capture(&identity_renewal::Step{renewal:&renewal,interface:&relay_socket::resolve_relay_interface,stop:&stopping,#[cfg(test)] bound:None},||CapturedRenewalInputs::capture_claim(PROVIDER_APP_GROUP)).map_err(|refusal|refusal.code)?;
                if stopping(){return Err(identity_renewal::IDENTITY_RENEWAL_STOPPED);}
                let inputs=CapturedAppGroupInputs::capture_claim(PROVIDER_APP_GROUP).map_err(|e|custody_refusal_code(&e))?;
                let f=FACTORY.get().ok_or("admitted_engine_factory_not_linked")?;
                // v35: the mode on the epoch's pins before the factory runs.
                pinned.set_window_mode(window_mode);
                let engine=AdmittedEngine::from_result(f(&saved_intent,inputs,notifier,pinned)?);
                let intent_matches=saved_intent.matches_returned_owner(&engine.generation,&engine.policy) && provider_intent_matches(&protocol,&engine.policy);
                Ok((engine,intent_matches))
            })();
            let (engine,intent_matches)=match admitted{Ok(v)=>v,Err(code)=>{
                identity_renewal::unpublish(&renewal);
                log_code("start_refused",code);
                // Reported by `status` until the next start is attempted.
                provider_xpc::publish_start_refusal(code);
                // No session exists: this generation has trivially joined.
                let (start,stop)=if let Ok(mut s)=self.ivars().state.lock(){
                    s.constructing=false;
                    let start=if s.lifecycle.fail(generation)==Ok(Effect::FailStart){
                        s.start_completion.take().map(|(_,done)|done)
                    }else{None};
                    let stop=if s.lifecycle.joined(generation)==Effect::CompleteStop{
                        s.stop_completion.take().map(|(_,done)|done)
                    }else{None};
                    (start,stop)
                }else{(None,None)};
                if let Some(done)=start{complete_failure(&done);}
                if let Some(done)=stop{done.call(());}
                return;
            }};
            {
                let mut state=match self.ivars().state.lock(){Ok(s)=>s,Err(poisoned)=>{
                    // The factory has already created a session. A poisoned
                    // state mutex cannot make that session disappear: retain
                    // its claim and join owner before reporting failure, then
                    // use the normal bounded stop poll. Never drop `engine` on
                    // this branch.
                    engine.bridge.stop();
                    let mut state=poisoned.into_inner();
                    seal_conflicted_bridges(&engine.bridge,state.engine.as_ref().map(|e|&e.bridge));
                    state.constructing=false;
                    let failed=state.lifecycle.fail(generation)==Ok(Effect::FailStart);
                    if state.lifecycle.generation==generation && state.engine.is_none(){
                        state.engine=Some(engine);
                    }else{
                        // Panic-corrupted state cannot safely replace another
                        // owner. Seal and retain *every* owner: the existing
                        // worker may still process packets even though the
                        // newly constructed bridge is already closed. The
                        // corruption blocks stop success and new admission;
                        // both claims live until this process exits.
                        state.constructing=true;
                        if let Some(existing)=state.engine.take(){
                            std::mem::forget(existing);
                        }
                        std::mem::forget(engine);
                    }
                    let done=if failed{state.start_completion.take().map(|(_,done)|done)}else{None};
                    drop(state);
                    self.ivars().state.clear_poison();
                    log_code("start_refused","provider_state_poisoned");
                    if let Some(done)=done{complete_failure(&done);}
                    self.on_main(sel!(stopEpoch:),generation);
                    return;
                }};
                // A pending stop cannot complete while factory construction
                // owns a session outside the state. Retain returned owner first.
                state.constructing=false;state.engine=Some(engine);
                // Keep the actual session owner in provider state before a
                // mismatched relay causes failure and observed join. Fail the
                // lifecycle under this lock: a Ready the session has already
                // posted must find this generation Blocking, never Admitted.
                if !intent_matches{
                    let start=if state.lifecycle.fail(generation)==Ok(Effect::FailStart){
                        state.start_completion.take().map(|(_,done)|done)
                    }else{None};
                    drop(state);
                    log_code("start_refused","provider_intent_mismatch");
                    if let Some(done)=start{complete_failure(&done);}
                    self.on_main(sel!(stopEpoch:),generation);
                    return;
                }
                if state.lifecycle.phase!=Phase::Admitted{
                    // Stop arrived during construction and already failed the
                    // start; its stopEpoch deferred to this owner.
                    drop(state);self.on_main(sel!(stopEpoch:),generation);return;
                }
            }
            // The session may have left Constructing before its owner was
            // stored; its own notification is then a no-op. Re-observe once.
            self.on_main(sel!(sessionChanged:),generation);
        }
        #[unsafe(method(sessionChanged:))]
        fn session_changed(&self,generation:&NSNumber){
            let g=generation.unsignedLongLongValue();
            let policy={
                let mut state=match self.ivars().state.lock(){Ok(s)=>s,Err(_)=>return};
                if state.lifecycle.generation!=g || state.constructing{return;}
                // S17: a running or reasserting epoch is judged by its loss
                // policy, never failed here.
                if matches!(state.lifecycle.phase,Phase::Running|Phase::Reasserting){drop(state);self.session_lost_on_main(g);return;}
                let Some(engine)=state.engine.as_ref() else{return};
                match engine.session_view(){
                    SessionView::Constructing=>return,
                    SessionView::Ended=>{drop(state);self.fail_epoch_on_main(g,None);return;}
                    SessionView::Ready=>{}
                }
                let policy=engine.policy.clone();
                let pinned=engine.pinned.clone();
                let guard=pinned.guard();
                let primary=pinned.get();
                if state.lifecycle.session_ready(g)!=Effect::ApplySettings{return;}
                // S20b: guard the physical interfaces before the settings can
                // take effect; Applying, Running and Reasserting are all
                // covered. The arm's token is kept under this lock.
                // v26: the filter's stop count is read before the arm, so
                // any stop from here on fails this epoch closed.
                state.filter_stops_at_arm=Some((g,leak_guard::ATTACHMENT.stops()));
                // v27: the pinned interface is the drop counters' `primary`
                // class; the arm notes the epoch applied, and the span's
                // wall time is read after the arm, so the logged span never
                // starts before the gate guards.
                LEAK_GUARD.set_primary(primary.as_ref().map(|interface|interface.name().as_bytes()));
                let (token,relay,route)=arm_leak_guard(&LEAK_GUARD,guard);
                pinned.set_leak_arm(token);
                let armed_wall=leak_guard::wall_token(SystemTime::now());
                state.leak_arm=Some((g,token));
                (policy,relay,route,token,armed_wall)
            };
            let (policy,relay,route,token,armed_wall)=policy;
            // v31: the fourth field is the renewal's route while armed (the
            // guard allows no authority any more).
            let armed_fields=arm_log_fields(g,&relay,route);
            log_fields("leak_guard",&armed_fields.iter().map(String::as_str).collect::<Vec<_>>());
            log_fields("leak_guard_span",&["armed",&format!("seq:{}",token.get()),&format!("wall:{armed_wall}")]);
            let provider=retained(self);
            let finished=RcBlock::new(move|failure:*mut NSError|{
                if !failure.is_null(){log_code("start_refused","tunnel_settings_failed");provider.fail_epoch(g);return;}
                // Enqueue to the serviced main runloop, never the unknown
                // NetworkExtension callback thread's default runloop.
                provider.on_main(sel!(startDrain:),g);
            });
            let settings=unsafe{network_settings(&policy)};
            unsafe{self.setTunnelNetworkSettings_completionHandler(Some(&settings),Some(&finished));}
        }
        #[unsafe(method(startDrain:))]
        fn start_drain(&self,generation:&NSNumber){
            let g=generation.unsignedLongLongValue();
            let done={
                let mut state=match self.ivars().state.lock(){Ok(s)=>s,Err(_)=>return};
                if state.lifecycle.generation!=g || state.lifecycle.phase!=Phase::Applying{return;}
                // The session must still be live after asynchronous native
                // settings application, before Running or start completion.
                if !state.engine.as_ref().is_some_and(AdmittedEngine::ready_for_native_io){
                    drop(state);self.fail_epoch(g);return;
                }
                let timer=unsafe{NSTimer::timerWithTimeInterval_target_selector_userInfo_repeats(0.002,self,sel!(drainOutput:),Some(generation),true)};
                unsafe{NSRunLoop::mainRunLoop().addTimer_forMode(&timer,NSRunLoopCommonModes);}
                state.timer=Some((g,timer));
                // S18: watch the physical path for the epoch's relay family.
                let v6=state.engine.as_ref().is_some_and(|e|e.policy.relay().is_ipv6());
                state.path=Some((g,EpochPath::start(v6)));
                let ready=state.lifecycle.ready(g);
                // S16i-1: the epoch is Running; its session pre-dials one
                // pooled connection for the first flows.
                if ready.is_ok(){if let Some(engine)=state.engine.as_mut(){engine.pinned.auth_backoff().mark_running();engine.live_since=Some(Instant::now());}}
                match ready{
                    Ok(Effect::CompleteStart)=>state.start_completion.take().map(|(_,done)|done),
                    Ok(_)=>None,
                    Err(_)=>return,
                }
            };
            self.read_one_batch(g);
            if let Some(done)=done{log_code("start","tunnel_running");done.call((std::ptr::null_mut(),));}
        }
        #[unsafe(method(drainOutput:))]
        fn drain_output(&self,timer:&NSTimer){
            let Some(g)=timer.userInfo().and_then(|o|o.downcast::<NSNumber>().ok()).map(|n|n.unsignedLongLongValue())else{timer.invalidate();return};
            // v26: the leak-guard filter stopped while this epoch is
            // guarded: fail closed before anything else is drained.
            if self.filter_stop_on_main(g){return;}
            let result=self.flush_output(g);
            // S17: a lost session is judged by the loss policy (this timer
            // runs on the main runloop), never failed outright.
            // An Ok tick also observes the rebuild: its single notification
            // may have been handled before its outcome could be read.
            if result.is_err(){self.session_lost_on_main(g);}else{self.rebuild_changed_on_main(g);self.renewal_tick_on_main(g);}
            // S18: a coalesced physical path change re-pins and rebuilds.
            self.path_changed_on_main(g);
            // S20b: the filter's counters, at most every 10 s when changed.
            log_filter_counters(Instant::now(),false);
        }
        #[unsafe(method(invalidateDrain:))]
        fn invalidate_drain(&self,generation:&NSNumber){
            self.invalidate_owned_timer(generation.unsignedLongLongValue());
        }
        #[unsafe(method(failEpoch:))]
        fn fail_on_main(&self,generation:&NSNumber){self.fail_epoch_on_main(generation.unsignedLongLongValue(),None);}
        #[unsafe(method(sessionLost:))]
        fn lost_on_main(&self,generation:&NSNumber){self.session_lost_on_main(generation.unsignedLongLongValue());}
        #[unsafe(method(rebuildChanged:))]
        fn rebuild_changed(&self,generation:&NSNumber){self.rebuild_changed_on_main(generation.unsignedLongLongValue());}
        #[unsafe(method(providerWoke:))]
        fn woke_on_main(&self,generation:&NSNumber){self.wake_on_main(generation.unsignedLongLongValue());}
        // S18: sleep is recorded and completes at once; nothing blocks it.
        // No new relay establishment starts until the wake (bounded by
        // QUIESCE_MAX of awake time): one begun now would most likely stall
        // mid-handshake, which aegis-server counts as an authentication
        // failure of the public IP.
        #[unsafe(method(sleepWithCompletionHandler:))]
        fn provider_sleep(&self,completion:&DynBlock<dyn Fn()>){
            let sleeps=self.ivars().state.lock().ok().map(|mut s|{
                if let Some(engine)=s.engine.as_ref(){engine.pinned.auth_backoff().quiesce(Instant::now());}
                s.sleeps=s.sleeps.saturating_add(1);s.sleeps
            });
            match sleeps{Some(n)=>log_code("sleep",&format!("count:{n}")),None=>log_code("sleep","recorded")}
            completion.call(());
        }
        // S18: judged on the main runloop, like every other epoch change.
        #[unsafe(method(wake))]
        fn provider_wake(&self){
            let g=self.ivars().state.lock().ok().map(|s|s.lifecycle.generation);
            match g{Some(g)=>self.on_main(sel!(providerWoke:),g),None=>log_code("wake","idle")}
        }
        #[unsafe(method(stopEpoch:))]
        fn stop_on_main(&self,generation:&NSNumber){
            self.stop_epoch_on_main(generation.unsignedLongLongValue());
        }
        #[unsafe(method(pollStop:))]
        fn poll_stop(&self,timer:&NSTimer){
            let Some(g)=timer.userInfo().and_then(|o|o.downcast::<NSNumber>().ok()).map(|n|n.unsignedLongLongValue())else{timer.invalidate();return};
            let current=self.ivars().state.lock().ok().and_then(|s|s.stop_timer.as_ref().filter(|(owner,_,_)|*owner==g).map(|(_,_,end)|*end));
            let Some(end)=current else{timer.invalidate();return};
            match stop_tick(||self.seal_and_join(g),||Instant::now()>=end){
                StopTick::Pending=>{}
                StopTick::Joined=>self.complete_stop(g),
                StopTick::BudgetExhausted=>{
                    // The session did not join within the stop budget, even on
                    // a final sealed observation. Never drop its owner or report
                    // success: end the process, so root Store custody ends with it.
                    timer.invalidate();
                    log_code("stop_budget_exhausted","provider_exit_70");
                    std::process::exit(STOP_BUDGET_EXIT);
                }
            }
        }
        #[unsafe(method(stopTunnelWithReason:completionHandler:))]
        fn stop(&self,_reason:NEProviderStopReason,completion:&DynBlock<dyn Fn()>){
            let (g,start)={let mut s=match self.ivars().state.lock(){Ok(s)=>s,Err(_)=>return};
                // A duplicate stop is refused; the first completes on join.
                let Some((g,effect))=s.lifecycle.stop() else{return};
                s.stop_completion=Some((g,completion.copy()));
                let start=if effect==Effect::FailStart{s.start_completion.take().map(|(_,done)|done)}else{None};
                (g,start)
            };
            if let Some(done)=start{complete_failure(&done);}
            self.on_main(sel!(stopEpoch:),g);
        }
    }
);
impl AegisPacketTunnelProvider {
    // Normal Rust helper: generated selector implementation shims carry hidden
    // ABI arguments and must not be called as ordinary Rust methods.
    // Caller is a main-runloop selector, retaining synchronous invalidation.
    fn invalidate_owned_timer(&self, g: u64) {
        if let Ok(mut state) = self.ivars().state.lock() {
            if state.timer.as_ref().is_some_and(|(owner, _)| *owner == g) {
                if let Some((_, timer)) = state.timer.take() {
                    timer.invalidate();
                }
            }
            // The epoch's path monitor is cancelled with its drain timer.
            if state.path.as_ref().is_some_and(|(owner, _)| *owner == g) {
                state.path = None;
            }
        }
    }
    /// S18: after a wake, a live lease gets one immediate re-ACK; a lease
    /// that lapsed while asleep enters the S17 rebuild under reasserting.
    /// A reasserting epoch is already rebuilding and logs `wake reasserting`,
    /// apart from `wake idle` (no running epoch). Main runloop only.
    fn wake_on_main(&self, g: u64) {
        let action = {
            let state = match self.ivars().state.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            // Establishments paused before sleep start again first.
            if let Some(engine) = state.engine.as_ref() {
                engine.pinned.auth_backoff().resume();
            }
            if state.lifecycle.generation != g || state.constructing {
                return;
            }
            let engine = state.engine.as_ref();
            // `ready` seals a lapsed lease with capture_lease_expired.
            let live = engine.is_some_and(|e| e.probe.ready());
            let action = path_watch::wake_action(state.lifecycle.phase, live);
            if action == WakeAction::Reack {
                if let Some(engine) = engine {
                    engine.probe.request_reack();
                }
            }
            action
        };
        log_code("wake", action.code());
        if action == WakeAction::Rebuild {
            self.session_lost_on_main(g);
        }
    }
    /// S23: the epoch's renewal monitor, from the drain timer: every
    /// `CHECK_INTERVAL` (sooner once forced), no I/O. A due renewal of a live
    /// Running session seals it (recoverable); the S17 rebuild then runs the
    /// renewal before its fresh capture. v31: only when that rebuild could
    /// dial the authority beside the armed guard (its tuple is the relay's),
    /// the session has been live for the stable period and the last failure
    /// was not transport-class (`identity_renewal::judge`; v31 review: in
    /// the last stretch before expiry a transport failure no longer holds);
    /// otherwise the renewal is deferred or held, with no teardown. Main
    /// runloop only.
    fn renewal_tick_on_main(&self, g: u64) {
        let sealed = {
            let state = match self.ivars().state.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            if !renewal_monitor_applies(&state, g) {
                return;
            }
            let Some(engine) = state.engine.as_ref() else {
                return;
            };
            let renewal = engine.pinned.renewal();
            let now = Instant::now();
            if !identity_renewal::check_due(&renewal, now) {
                return;
            }
            let Ok(unix) = aegis_core::secure_channel::registry::unix_now() else {
                return;
            };
            let monitor = identity_renewal::Monitor {
                auth_backoff: engine.pinned.auth_backoff().auth_until(now).is_some(),
                live: engine.ready_for_native_io(),
                guarded: renewal_guarded(&LEAK_GUARD, engine.pinned.guard()),
                live_for: engine
                    .live_since
                    .map(|at| now.saturating_duration_since(at)),
            };
            let action = identity_renewal::monitor_step(&renewal, unix, &monitor);
            if action != Action::Seal {
                return;
            }
            engine.probe.seal(identity_renewal::IDENTITY_RENEWAL_DUE);
            true
        };
        if sealed {
            self.session_lost_on_main(g);
        }
    }
    /// S18: act on a coalesced physical path change. A re-pin of a running
    /// epoch seals its session (recoverable) and rebuilds it; a reasserting
    /// epoch's next attempt binds to the new pin. Main runloop only.
    fn path_changed_on_main(&self, g: u64) {
        let rebuild = {
            let mut guard = match self.ivars().state.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            let state = &mut *guard;
            if state.lifecycle.generation != g || state.constructing {
                return;
            }
            let (Some(engine), Some((owner, path))) = (state.engine.as_ref(), state.path.as_mut())
            else {
                return;
            };
            if *owner != g
                || !path
                    .watch
                    .poll(Instant::now(), &engine.pinned, RelayInterface::physical)
            {
                return;
            }
            match path_watch::repin_effect(state.lifecycle.phase) {
                RepinEffect::Rebuild => {
                    engine.probe.seal("relay_path_changed");
                    true
                }
                RepinEffect::NextAttempt | RepinEffect::Ignore => false,
            }
        };
        if rebuild {
            self.session_lost_on_main(g);
        }
    }
    fn on_main(&self, selector: objc2::runtime::Sel, generation: u64) {
        let number = NSNumber::new_u64(generation);
        let object: &NSObject = self;
        unsafe {
            object.performSelectorOnMainThread_withObject_waitUntilDone(
                selector,
                Some(&number),
                false,
            );
        }
    }
    fn complete_stop(&self, g: u64) {
        let (done, opened) = self
            .ivars()
            .state
            .lock()
            .ok()
            .map_or((None, None), |mut s| {
                if s.lifecycle.generation != g {
                    return (None, None);
                }
                if let Some((owner, timer, _)) = s.stop_timer.take() {
                    if owner == g {
                        timer.invalidate();
                    }
                }
                let effect = s.lifecycle.joined(g);
                // S20b: the epoch's leak guard opens only once it has joined
                // and stopped, before its completion can admit a new epoch.
                // v27: the span's wall time is read before the disarm, so
                // the logged span never ends after the gate opened.
                let state = &mut *s;
                let seq = state
                    .leak_arm
                    .filter(|(armed, _)| *armed == g)
                    .map(|(_, token)| token.get());
                let wall = leak_guard::wall_token(SystemTime::now());
                let opened =
                    disarm_after_join(&LEAK_GUARD, &state.lifecycle, g, &mut state.leak_arm);
                let opened = opened.then_some((seq.unwrap_or(0), wall));
                if effect != Effect::CompleteStop {
                    return (None, opened);
                }
                (s.stop_completion.take().map(|(_, done)| done), opened)
            });
        if let Some((seq, wall)) = opened {
            log_fields("leak_guard", &["disarmed", &format!("gen:{g}")]);
            log_fields(
                "leak_guard_span",
                &["disarmed", &format!("seq:{seq}"), &format!("wall:{wall}")],
            );
            log_filter_counters(Instant::now(), true);
        }
        // Completion may synchronously request a new epoch; publish Stopped
        // atomically first and make no old-epoch state writes afterwards.
        if let Some(done) = done {
            done.call(());
        }
    }
    /// Seal the session and observe its join without waiting. Lifecycle
    /// transitions and completions belong to the callers' lifecycle effects.
    fn seal_and_join(&self, g: u64) -> bool {
        let session = {
            let s = match self.ivars().state.lock() {
                Ok(s) => s,
                Err(_) => return false,
            };
            if s.lifecycle.generation != g || s.constructing {
                return false;
            }
            s.engine.as_ref().map(|e| {
                e.bridge.stop();
                (e.session.clone(), e.rebuilds.current.clone())
            })
        };
        // Every caller is a main-thread stop/failure/poll selector.
        // Invalidate synchronously before completion can start a new epoch.
        self.invalidate_owned_timer(g);
        // No provider-state lock is held while observing the session thread.
        // A reasserting epoch also stops its rebuild: the lost session and any
        // rebuilding one must both have joined. Both are observed every tick.
        let terminal = session.is_none_or(|(session, rebuild)| {
            let rebuilt = rebuild.is_none_or(|rebuild| {
                rebuild
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .seal_and_try_join(Duration::ZERO)
            });
            let joined = session
                .lock()
                .ok()
                .is_some_and(|mut session| session.try_join(Duration::ZERO));
            rebuilt && joined
        });
        if terminal {
            if let Ok(mut s) = self.ivars().state.lock() {
                if s.lifecycle.generation == g {
                    // S23: the epoch's renewal state ends with it.
                    if let Some(engine) = s.engine.take() {
                        identity_renewal::unpublish(&engine.pinned.renewal());
                    }
                }
            }
        }
        terminal
    }
    /// Seal, then complete on join or poll it within the stop budget.
    fn stop_epoch_on_main(&self, g: u64) {
        if self.seal_and_join(g) {
            self.complete_stop(g);
            return;
        }
        let mut state = match self.ivars().state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        if state.lifecycle.generation != g || state.constructing || state.stop_timer.is_some() {
            return;
        }
        let number = NSNumber::new_u64(g);
        let timer = unsafe {
            NSTimer::timerWithTimeInterval_target_selector_userInfo_repeats(
                0.02,
                self,
                sel!(pollStop:),
                Some(&number),
                true,
            )
        };
        unsafe { NSRunLoop::mainRunLoop().addTimer_forMode(&timer, NSRunLoopCommonModes) };
        state.stop_timer = Some((g, timer, Instant::now() + STOP_BUDGET));
    }
    fn seal_bridge_for_epoch(&self, g: u64) {
        // A malformed read must seal before failEpoch reaches the main
        // runloop, but a delayed callback cannot seal a newer session.
        let state = self
            .ivars()
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        seal_current_epoch_bridge(
            g,
            state.lifecycle.generation,
            state.engine.as_ref().map(|engine| &engine.bridge),
        );
    }
    fn fail_epoch(&self, g: u64) {
        self.on_main(sel!(failEpoch:), g);
    }
    /// S17: judge a running session that is no longer live. A recoverable
    /// loss keeps the settings, sets `reasserting` and starts one rebuild; a
    /// terminal one fails the epoch (one cancel). Main runloop only.
    fn session_lost_on_main(&self, g: u64) {
        enum Act {
            Reassert,
            Fail,
        }
        let (act, code) = {
            let mut guard = match self.ivars().state.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            let state = &mut *guard;
            if state.constructing {
                return;
            }
            let Some(engine) = state.engine.as_mut() else {
                return;
            };
            let (phase, refusal) = engine.probe.phase_reader().snapshot();
            // Still live: a stale report of an earlier batch.
            if phase == SessionPhase::Ready && engine.probe.ready() {
                return;
            }
            let code = refusal.unwrap_or("packet_path_not_ready");
            match session_rebuild::session_lost(&mut state.lifecycle, g, code) {
                Lost::Ignore => return,
                Lost::Fail(code) => (Act::Fail, code),
                Lost::Reassert => {
                    // A spawn failure stays reasserting (fail closed); the
                    // drain timer retries it with backoff. Never a cancel.
                    if let Err(failed) = self.start_rebuild(engine, g) {
                        log_code("session_rebuild_refused", failed);
                    }
                    (Act::Reassert, code)
                }
            }
        };
        match act {
            Act::Reassert => {
                log_code("session_lost", code);
                unsafe { self.setReasserting(true) };
                log_code("reasserting", "on");
            }
            Act::Fail => self.fail_epoch_on_main(g, Some(code)),
        }
    }
    /// S17: start one rebuild of the epoch's lost session, carrying the
    /// epoch's backoff. Its one notification is `rebuildChanged:`.
    fn start_rebuild(&self, engine: &mut AdmittedEngine, g: u64) -> Result<(), &'static str> {
        let lost = engine.session.clone();
        let factory = engine.rebuild_factory();
        let poster = MainPoster(retained(self));
        let done: Box<dyn FnOnce() + Send> =
            Box::new(move || poster.post_to(sel!(rebuildChanged:), g));
        let schedule = session_rebuild::PRODUCTION;
        engine
            .rebuilds
            .start_with(schedule, Instant::now(), move |spent| {
                Rebuild::spawn(lost, factory, schedule, None, done, spent)
            })
    }
    /// S17: a rebuild finished. A Ready session takes over the packet path
    /// without re-applying settings; a terminal refusal fails the epoch.
    /// Also observed from every drain tick, so an outcome is never missed,
    /// and retries a rebuild whose thread could not be spawned.
    fn rebuild_changed_on_main(&self, g: u64) {
        let finished = {
            let mut guard = match self.ivars().state.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            let state = &mut *guard;
            if state.lifecycle.generation != g {
                return;
            }
            let Some(engine) = state.engine.as_mut() else {
                return;
            };
            if state.lifecycle.phase == Phase::Reasserting
                && engine.rebuilds.respawn_due(Instant::now())
            {
                if let Err(failed) = self.start_rebuild(engine, g) {
                    log_code("session_rebuild_refused", failed);
                }
                return;
            }
            let Some(rebuild) = engine.rebuilds.current.clone() else {
                return;
            };
            let mut owner = rebuild.lock().unwrap_or_else(PoisonError::into_inner);
            match session_rebuild::rebuild_finished(&mut state.lifecycle, g, &mut owner) {
                Finished::Swap(session, attempts) => {
                    drop(owner);
                    engine.rebuilds.swapped(attempts, Instant::now());
                    engine.swap(session);
                    Ok(attempts)
                }
                Finished::Fail(code) => Err(code),
                Finished::Ignore => return,
            }
        };
        match finished {
            Ok(attempts) => {
                log_code("session_rebuilt", &format!("attempt:{attempts}"));
                unsafe { self.setReasserting(false) };
                log_code("reasserting", "off");
            }
            Err(code) => self.fail_epoch_on_main(g, Some(code)),
        }
    }
    /// v26: fail epoch `g` closed when the leak-guard filter stopped since
    /// the epoch armed the guard: a host without the administrator prompt
    /// (any older signed build) can disable or remove the filter
    /// configuration, and nothing outside this process checks it. Once per
    /// epoch (the record is taken). True when the epoch was failed.
    fn filter_stop_on_main(&self, g: u64) -> bool {
        let stopped = self.ivars().state.lock().ok().is_some_and(|mut state| {
            let stopped =
                filter_stopped_since_arm(&leak_guard::ATTACHMENT, state.filter_stops_at_arm, g);
            if stopped {
                state.filter_stops_at_arm = None;
            }
            stopped
        });
        if stopped {
            log_fields(
                "leak_guard",
                &[
                    "filter_stopped_while_guarding",
                    &format!("gen:{g}"),
                    &format!("stops:{}", leak_guard::ATTACHMENT.stops()),
                ],
            );
            self.fail_epoch_on_main(g, Some("leak_guard_filter_stopped"));
        }
        stopped
    }
    fn fail_epoch_on_main(&self, g: u64, code: Option<&'static str>) {
        // Only the first failure of a live generation acts. A stop already in
        // progress owns the join and its completion.
        let (start, session) = {
            let mut s = match self.ivars().state.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            let start = match s.lifecycle.fail(g) {
                Ok(Effect::FailStart) => s.start_completion.take().map(|(_, done)| done),
                Ok(_) => None,
                Err(_) => return,
            };
            (start, s.engine.as_ref().map(|e| e.session.clone()))
        };
        let refusal = session.and_then(|session| session.lock().ok().and_then(|s| s.refusal()));
        log_code(
            "session_failed",
            code.or(refusal).unwrap_or("provider_epoch_failed"),
        );
        if let Some(done) = start {
            complete_failure(&done);
        }
        self.stop_epoch_on_main(g);
        // Phase stays Blocking until the session has joined, and a running
        // generation until Apple's stop callback observes that join.
        unsafe {
            self.cancelTunnelWithError(Some(&error()));
        }
    }
    fn read_one_batch(&self, g: u64) {
        enum Read {
            Again,
            // The session is no longer live: the batch was dropped. The main
            // runloop judges the loss; reading (and dropping) goes on.
            Lost,
            Stop,
            Poisoned,
        }
        if !self.ivars().state.lock().ok().is_some_and(|s| {
            s.lifecycle.generation == g
                && matches!(s.lifecycle.phase, Phase::Running | Phase::Reasserting)
        }) {
            return;
        }
        let provider = retained(self);
        let flow = unsafe { self.packetFlow() };
        let batch = RcBlock::new(
            move |packets: NonNull<NSArray<NSData>>, protocols: NonNull<NSArray<NSNumber>>| {
                let read = (|| {
                    let packets = unsafe { packets.as_ref() };
                    let protocols = unsafe { protocols.as_ref() };
                    let Ok(s) = provider.ivars().state.lock() else {
                        return Read::Poisoned;
                    };
                    // Stale reads are harmless: never stop/cancel a new epoch.
                    if s.lifecycle.generation != g {
                        return Read::Stop;
                    }
                    let engine = s.engine.as_ref();
                    let live = engine.is_some_and(AdmittedEngine::ready_for_native_io);
                    // S17: while reasserting, or once the running session is
                    // no longer live, every packet is dropped here: nothing
                    // reaches the sealed bridge, the relay or the OS.
                    match session_rebuild::native_packets(s.lifecycle.phase, live) {
                        Disposition::Stale => return Read::Stop,
                        Disposition::Drop if s.lifecycle.phase == Phase::Running => {
                            return Read::Lost
                        }
                        Disposition::Drop => return Read::Again,
                        Disposition::Forward => {}
                    }
                    let Some(engine) = engine else {
                        return Read::Lost;
                    };
                    let malformed = || {
                        engine.probe.seal("native_packet_malformed");
                        Read::Lost
                    };
                    if packets.len() != protocols.len() || packets.len() > 128 {
                        return malformed();
                    }
                    for (packet, family) in packets.iter().zip(protocols.iter()) {
                        if packet.len() > 65_535 {
                            return malformed();
                        }
                        let bytes = packet.to_vec();
                        let expected = match bytes.first().map(|v| v >> 4) {
                            Some(4) => 2,
                            Some(6) => 30,
                            _ => return malformed(),
                        };
                        if family.intValue() != expected {
                            return malformed();
                        }
                        // S16j-2: from_native drops a tunnel-local destination
                        // other than DNS to an anchor, so it never becomes a
                        // relay flow; every other packet is from_os as before.
                        if engine
                            .with_live_session(|bridge| bridge.from_native(&bytes))
                            .is_err()
                        {
                            return Read::Lost;
                        }
                    }
                    Read::Again
                })();
                match read {
                    Read::Again => provider.read_one_batch(g),
                    Read::Lost => {
                        provider.on_main(sel!(sessionLost:), g);
                        provider.read_one_batch(g);
                    }
                    Read::Stop => {}
                    Read::Poisoned => {
                        provider.seal_bridge_for_epoch(g);
                        provider.fail_epoch(g);
                    }
                }
            },
        );
        unsafe {
            flow.readPacketsWithCompletionHandler(&batch);
        }
    }
    fn flush_output(&self, g: u64) -> Result<(), ()> {
        let flow = unsafe { self.packetFlow() };
        let state = self.ivars().state.lock().map_err(|_| ())?;
        // Reasserting delivers nothing: the lost session's bridge is sealed
        // and no rebuilt one is swapped in yet.
        if state.lifecycle.generation != g || state.lifecycle.phase != Phase::Running {
            return Ok(());
        }
        let engine = state.engine.as_ref().ok_or(())?;
        if !engine.ready_for_native_io() {
            return Err(());
        }
        for _ in 0..128 {
            let delivered = engine
                .with_live_session(|bridge| {
                    bridge.deliver_to_os(|p| {
                        let data = NSData::with_bytes(p);
                        let family = NSNumber::new_i32(if p[0] >> 4 == 4 { 2 } else { 30 });
                        let packets = NSArray::from_retained_slice(&[data]);
                        let protocols = NSArray::from_retained_slice(&[family]);
                        if unsafe { flow.writePackets_withProtocols(&packets, &protocols) } {
                            Ok(())
                        } else {
                            Err(std::io::ErrorKind::BrokenPipe.into())
                        }
                    })
                })
                .map_err(|_| ())?;
            if !delivered {
                break;
            }
        }
        Ok(())
    }
}
/// S20b: the relay carrier is TCP only; the one UDP socket of the provider
/// (relay_socket's route source) connects and never sends.
const UDP_RELAY_ALLOWED: bool = false;

/// v31: how an epoch's renewal reaches its authority while the guard is
/// armed: through the relay's own tuple (relay traffic), deferred to the
/// next provider start (another tuple), or not at all (none recorded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RenewalRoute {
    ViaRelay,
    Deferred,
    None,
}

impl RenewalRoute {
    /// v40: through the relay when the authority is the exact tuple of one
    /// of the armed pins (a fronted authority on an edge pin's 443, variant
    /// B, included).
    fn of(guard: Option<GuardEndpoints>) -> Self {
        match guard {
            Some(GuardEndpoints {
                relays,
                authority: Some(authority),
                ..
            }) if relays.contains(Peer::from(authority)) => Self::ViaRelay,
            Some(GuardEndpoints {
                authority: Some(_), ..
            }) => Self::Deferred,
            _ => Self::None,
        }
    }

    fn token(self) -> &'static str {
        match self {
            Self::ViaRelay => "via_relay",
            Self::Deferred => "deferred",
            Self::None => "none",
        }
    }
}

/// S20b: arm `gate` with the relay endpoint the epoch's session recorded,
/// just before the epoch's settings may be applied, and return the arm's
/// token. With no record (never for a Ready session) only link control
/// passes: fail closed. v31: the enrollment authority is never armed; the
/// route its renewal takes is returned for the arm's log line. v40: the
/// record is the profile's whole carrier pool, every exact pin and nothing
/// else, so a session rebuilt on another carrier needs no re-arm.
fn arm_leak_guard(gate: &Gate, guard: Option<GuardEndpoints>) -> (ArmToken, PeerSet, RenewalRoute) {
    let relays = guard.map_or(PeerSet::EMPTY, |endpoints| endpoints.relays);
    let base = guard.map_or(0, |endpoints| usize::from(endpoints.base_len));
    let token = gate
        .arm_pins_with_base(&relays, base, UDP_RELAY_ALLOWED)
        .unwrap_or_else(|| gate.arm_pins(&PeerSet::EMPTY, UDP_RELAY_ALLOWED));
    // v27: the epoch's settings may take effect from here on; its join
    // withdraws it (`disarm_after_join`).
    gate.note_applied();
    (token, relays, RenewalRoute::of(guard))
}

/// v40: the arm's log fields, address free: the pins' family and, for a
/// pool of more than one pin, their count after it (`relay:v4:3`); a
/// single-pin line is unchanged.
fn arm_log_fields(g: u64, relays: &PeerSet, route: RenewalRoute) -> [String; 4] {
    let family = leak_guard::pins_family_token(relays);
    let relay = if relays.len() > 1 {
        format!("relay:{family}:{}", relays.len())
    } else {
        format!("relay:{family}")
    };
    [
        "armed".to_string(),
        format!("gen:{g}"),
        relay,
        format!("renewal:{}", route.token()),
    ]
}

/// v31: whether the epoch's renewal would dial a tuple the armed `gate`
/// forbids (its recorded authority is not the armed relay's tuple). With
/// no authority recorded, while the gate guards: fail closed (no seal).
fn renewal_guarded(gate: &Gate, guard: Option<GuardEndpoints>) -> bool {
    match guard.and_then(|endpoints| endpoints.authority) {
        Some(authority) => gate.dial_refused(authority),
        None => gate.snapshot().0.mode == leak_guard::Mode::Guarding,
    }
}

/// v26: whether the leak-guard filter stopped since epoch `g` armed the
/// guard (`recorded` is that epoch's `(g, stops)` read before the arm). A
/// stop while an epoch is guarded means the filter configuration was
/// disabled or removed under a Connected tunnel, by any signed host: the
/// epoch then fails closed instead of running unguarded. An epoch that
/// armed while no filter was attached is held to the same rule (a filter
/// that starts and stops later counts), and a stop before the arm never
/// counts.
fn filter_stopped_since_arm(
    attachment: &leak_guard::Attachment,
    recorded: Option<(u64, u64)>,
    g: u64,
) -> bool {
    matches!(recorded, Some((armed, stops)) if armed == g && attachment.stops() != stops)
}

/// S20b: open `gate` once epoch `g` has joined and stopped, with the token
/// of the arm this provider instance made for `g` (taken, so it is used
/// once). A failed running epoch stays Blocking (guarded) until Apple's
/// stop is joined. The gate is process-wide while generations restart at 1
/// in every provider instance: only the token, never `g`, identifies the
/// arm, so a stale epoch of this or an earlier instance never opens a
/// newer arm.
fn disarm_after_join(
    gate: &Gate,
    lifecycle: &Lifecycle,
    g: u64,
    leak_arm: &mut Option<(u64, ArmToken)>,
) -> bool {
    if lifecycle.generation != g || lifecycle.phase != Phase::Stopped {
        return false;
    }
    match *leak_arm {
        Some((armed, token)) if armed == g => {
            *leak_arm = None;
            // v27: the epoch noted applied at its arm has joined and
            // stopped; an open while another epoch is still applied counts.
            gate.note_withdrawn();
            gate.disarm(token)
        }
        _ => false,
    }
}

/// S20b: the counter log interval.
const FILTER_COUNTERS_EVERY: Duration = Duration::from_secs(10);
type CounterValues = [u64; leak_guard::COUNTED.len()];

/// Whether the counters are logged now: they changed since the last line
/// and the interval passed (or `force`, once an epoch's guard opened).
fn counters_due(
    last: Option<(Instant, CounterValues)>,
    now: Instant,
    current: &CounterValues,
    force: bool,
) -> bool {
    match last {
        None => force || current.iter().any(|value| *value != 0),
        Some((at, values)) => {
            values != *current
                && (force || now.saturating_duration_since(at) >= FILTER_COUNTERS_EVERY)
        }
    }
}

/// v29: whether `counters_due` can be true at `now` at all, before the
/// counters are read: within the interval of the last line and not forced
/// it is false for any counter values. The drain timer calls
/// `log_filter_counters` every 2 ms; this keeps it from reading the 26
/// padded counters (cache lines the filter's threads keep writing) on the
/// ticks where no line can be due.
fn counters_may_be_due(last_at: Option<Instant>, now: Instant, force: bool) -> bool {
    match last_at {
        None => true,
        Some(at) => force || now.saturating_duration_since(at) >= FILTER_COUNTERS_EVERY,
    }
}

static FILTER_COUNTERS_LOGGED: Mutex<Option<(Instant, CounterValues)>> = Mutex::new(None);

/// One `filter_counters_state` line and the non-zero counters, four fields
/// a line, when `counters_due`. Main runloop only; never per packet. v29:
/// the counters are read only when a line may be due.
fn log_filter_counters(now: Instant, force: bool) {
    let current = {
        let mut last = FILTER_COUNTERS_LOGGED
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !counters_may_be_due(last.map(|(at, _)| at), now, force) {
            return;
        }
        let current = leak_guard::COUNTERS.snapshot();
        if !counters_due(*last, now, &current, force) {
            return;
        }
        *last = Some((now, current));
        current
    };
    let (snapshot, _) = LEAK_GUARD.snapshot();
    let mode = match snapshot.mode {
        leak_guard::Mode::Open => "mode:open",
        leak_guard::Mode::Guarding => "mode:guarding",
    };
    let attached = format!("attached:{}", leak_guard::ATTACHMENT.attached());
    log_fields("filter_counters_state", &[mode, &attached]);
    let fields = leak_guard::counter_fields(&current);
    for chunk in fields.chunks(4) {
        let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
        log_fields("filter_counters", &refs);
    }
}

unsafe fn network_settings(policy: &FullWide) -> Retained<NEPacketTunnelNetworkSettings> {
    let settings = NEPacketTunnelNetworkSettings::initWithTunnelRemoteAddress(
        NEPacketTunnelNetworkSettings::alloc(),
        &NSString::from_str(&policy.relay().to_string()),
    );
    let v4 = NSArray::from_retained_slice(&[NSString::from_str(&INTERFACE_V4.to_string())]);
    let masks = NSArray::from_retained_slice(&[NSString::from_str("255.255.255.255")]);
    let ipv4 = NEIPv4Settings::initWithAddresses_subnetMasks(NEIPv4Settings::alloc(), &v4, &masks);
    ipv4.setIncludedRoutes(Some(&NSArray::from_retained_slice(&[
        NEIPv4Route::defaultRoute(),
    ])));
    ipv4.setExcludedRoutes(Some(&NSArray::from_retained_slice(&[])));
    let v6 = NSArray::from_retained_slice(&[NSString::from_str(&INTERFACE_V6.to_string())]);
    // S16j-2: an on-link /120, never /128: with a /128 macOS installed no
    // IPv6 route on the utun at all (v21), so IPv6 was blocked, not tunneled.
    let prefixes = NSArray::from_retained_slice(&[NSNumber::new_i32(INTERFACE_V6_PREFIX.into())]);
    let ipv6 = NEIPv6Settings::initWithAddresses_networkPrefixLengths(
        NEIPv6Settings::alloc(),
        &v6,
        &prefixes,
    );
    ipv6.setIncludedRoutes(Some(&NSArray::from_retained_slice(&[
        NEIPv6Route::defaultRoute(),
    ])));
    ipv6.setExcludedRoutes(Some(&NSArray::from_retained_slice(&[])));
    let servers = NSArray::from_retained_slice(
        &policy
            .dns()
            .iter()
            .map(|s| NSString::from_str(&s.to_string()))
            .collect::<Vec<_>>(),
    );
    let dns = NEDNSSettings::initWithServers(NEDNSSettings::alloc(), &servers);
    dns.setMatchDomains(Some(&NSArray::from_retained_slice(&[NSString::from_str(
        "",
    )])));
    dns.setMatchDomainsNoSearch(true);
    settings.setIPv4Settings(Some(&ipv4));
    settings.setIPv6Settings(Some(&ipv6));
    settings.setDNSSettings(Some(&dns));
    settings.setMTU(Some(&NSNumber::new_u16(policy.mtu())));
    settings
}
/// The provider process's boot steps, in a trait so the order is tested.
trait ProviderBoot {
    fn register_class(&mut self);
    /// S20b: the packet filter provider of the same system extension.
    fn register_filter_class(&mut self);
    fn link_factory(&mut self) -> bool;
    fn start_system_extension_mode(&mut self);
    fn start_listener(&mut self) -> Result<(), &'static str>;
    fn log(&mut self, event: &str, code: &str);
    fn run(&mut self);
}
/// Apple's sample order: system-extension mode first, then the
/// `NEMachServiceName` listener, then the run loop. A listener failure is
/// logged and never prevents the tunnel lifecycle from running.
fn boot_provider(boot: &mut impl ProviderBoot) {
    boot.register_class();
    boot.register_filter_class();
    if !boot.link_factory() {
        boot.log("start_refused", "admitted_engine_factory_not_linked");
    }
    boot.start_system_extension_mode();
    if let Err(code) = boot.start_listener() {
        boot.log("xpc_refused", code);
    }
    boot.run();
}
struct NativeBoot;
impl ProviderBoot for NativeBoot {
    fn register_class(&mut self) {
        let _ = AegisPacketTunnelProvider::class();
    }
    fn register_filter_class(&mut self) {
        crate::filter_provider::register_class();
    }
    fn link_factory(&mut self) -> bool {
        register_factory()
    }
    fn start_system_extension_mode(&mut self) {
        unsafe { NEProvider::startSystemExtensionMode() }
    }
    fn start_listener(&mut self) -> Result<(), &'static str> {
        provider_xpc::start_listener()
    }
    fn log(&mut self, event: &str, code: &str) {
        log_code(event, code);
    }
    fn run(&mut self) {
        unsafe { CFRunLoopRun() }
    }
}
pub fn provider_main() {
    boot_provider(&mut NativeBoot);
}
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRunLoopRun();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::PacketBridge;
    use aegis_client::capture_lease_gate::CaptureLeaseDeadline;

    fn strings(a: &NSArray<NSString>) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    // S16j-2: the settings object macOS receives, read back without applying
    // it (no setTunnelNetworkSettings, no network).
    #[test]
    fn network_settings_route_both_families_into_the_tunnel_with_an_on_link_v6_prefix() {
        use crate::policy::{DNS_ANCHOR_V4, DNS_ANCHOR_V6};
        let policy = FullWide::new(
            "192.0.2.1".parse().unwrap(),
            vec![DNS_ANCHOR_V4.into(), DNS_ANCHOR_V6.into()],
            1400,
        )
        .unwrap();
        unsafe {
            let s = network_settings(&policy);
            assert_eq!(s.tunnelRemoteAddress().to_string(), "192.0.2.1");
            assert_eq!(s.MTU().unwrap().integerValue(), 1400);

            let v4 = s.IPv4Settings().unwrap();
            assert_eq!(strings(&v4.addresses()), ["198.19.255.1"]);
            assert_eq!(strings(&v4.subnetMasks()), ["255.255.255.255"]);
            let routes = v4.includedRoutes().unwrap();
            assert_eq!(routes.len(), 1);
            let route = routes.objectAtIndex(0);
            assert_eq!(route.destinationAddress().to_string(), "0.0.0.0");
            assert_eq!(route.destinationSubnetMask().to_string(), "0.0.0.0");
            assert_eq!(v4.excludedRoutes().map(|r| r.len()), Some(0));

            let v6 = s.IPv6Settings().unwrap();
            assert_eq!(strings(&v6.addresses()), ["fd00:ae61::1"]);
            let prefixes: Vec<isize> = v6
                .networkPrefixLengths()
                .iter()
                .map(|n| n.integerValue())
                .collect();
            assert_eq!(prefixes, [120]);
            let routes = v6.includedRoutes().unwrap();
            assert_eq!(routes.len(), 1);
            let route = routes.objectAtIndex(0);
            assert_eq!(route.destinationAddress().to_string(), "::");
            assert_eq!(route.destinationNetworkPrefixLength().integerValue(), 0);
            assert_eq!(v6.excludedRoutes().map(|r| r.len()), Some(0));

            let dns = s.DNSSettings().unwrap();
            assert_eq!(strings(&dns.servers()), ["198.19.255.2", "fd00:ae61::2"]);
            assert_eq!(strings(&dns.matchDomains().unwrap()), [""]);
            assert!(dns.matchDomainsNoSearch());
        }
        // The server order follows the policy.
        let reversed = FullWide::new(
            "192.0.2.1".parse().unwrap(),
            vec![DNS_ANCHOR_V6.into(), DNS_ANCHOR_V4.into()],
            1280,
        )
        .unwrap();
        unsafe {
            let s = network_settings(&reversed);
            let dns = s.DNSSettings().unwrap();
            assert_eq!(strings(&dns.servers()), ["fd00:ae61::2", "198.19.255.2"]);
            assert_eq!(s.MTU().unwrap().integerValue(), 1280);
        }
    }

    #[test]
    fn stale_read_error_cannot_seal_new_epoch_but_current_error_seals_queue() {
        let bridge =
            LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
        assert!(!bridge.is_sealed());
        seal_current_epoch_bridge(6, 7, Some(&bridge));
        assert!(!bridge.is_sealed());
        seal_current_epoch_bridge(7, 7, Some(&bridge));
        assert!(bridge.is_sealed());
    }

    #[test]
    fn session_view_reads_the_phase_once_and_probes_the_lease_only_when_ready() {
        // A session that turns Ready after the snapshot stays Constructing:
        // the probe is never consulted, so a concurrent mark_ready cannot be
        // misread as Ended (its own Ready notification re-observes it).
        assert_eq!(
            classify_session(SessionPhase::Constructing, || panic!("probe consulted")),
            SessionView::Constructing
        );
        assert_eq!(
            classify_session(SessionPhase::Ready, || true),
            SessionView::Ready
        );
        // A Ready snapshot whose lease probe fails (it seals) is Ended.
        assert_eq!(
            classify_session(SessionPhase::Ready, || false),
            SessionView::Ended
        );
        for terminal in [SessionPhase::Sealed, SessionPhase::Joined] {
            assert_eq!(
                classify_session(terminal, || panic!("probe consulted")),
                SessionView::Ended
            );
        }
    }

    #[test]
    fn real_session_view_is_constructing_then_ready_then_ended() {
        use std::sync::{
            atomic::{AtomicU64, Ordering},
            mpsc,
        };
        let deadline = CaptureLeaseDeadline::default();
        let clock = Arc::new(AtomicU64::new(10));
        let now = clock.clone();
        let bridge =
            LeasedPacketBridge::with_clock(PacketBridge::default(), deadline.clone(), move || {
                Ok(now.load(Ordering::SeqCst))
            });
        deadline.replace(Some(1_000)).unwrap();
        let (go, wait_go) = mpsc::channel::<()>();
        let (tx, rx) = mpsc::channel();
        let mut session = SessionHandle::spawn(
            bridge,
            move |phase| tx.send(phase).unwrap(),
            move |control| {
                wait_go.recv().map_err(|_| "test_go_dropped")?;
                control.mark_ready();
                while !control.stop_requested() {
                    std::thread::park_timeout(Duration::from_millis(5));
                }
                Ok(())
            },
        )
        .unwrap();
        let probe = session.probe();
        let view = || classify_session(probe.phase(), || probe.ready());
        assert_eq!(view(), SessionView::Constructing);
        go.send(()).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            SessionPhase::Ready
        );
        assert_eq!(view(), SessionView::Ready);
        session.seal("test_sealed");
        assert_eq!(view(), SessionView::Ended);
        assert!(session.try_join(Duration::from_secs(5)));
        assert_eq!(view(), SessionView::Ended);
    }

    #[test]
    fn start_renewal_step_sees_a_stop_of_its_generation() {
        let mut state = ProviderState::default();
        let g = state.lifecycle.admit().unwrap();
        assert!(!start_stopped(&state, g));
        assert!(start_stopped(&state, g + 1), "superseded");
        let (stopped, _) = state.lifecycle.stop().unwrap();
        assert_eq!(stopped, g);
        assert!(start_stopped(&state, g), "stopped while constructing");
    }
    #[test]
    fn renewal_monitor_never_judges_an_epoch_whose_stop_is_draining() {
        let mut state = ProviderState::default();
        let g = state.lifecycle.admit().unwrap();
        assert!(!renewal_monitor_applies(&state, g), "constructing start");
        state.lifecycle.session_ready(g);
        state.lifecycle.ready(g).unwrap();
        assert_eq!(state.lifecycle.phase, Phase::Running);
        assert!(renewal_monitor_applies(&state, g));
        assert!(!renewal_monitor_applies(&state, g + 1), "another epoch");
        state.constructing = true;
        assert!(!renewal_monitor_applies(&state, g), "constructing");
        state.constructing = false;
        state.lifecycle.reassert(g).unwrap();
        assert!(!renewal_monitor_applies(&state, g), "rebuilding");
        state.lifecycle.rebuilt(g).unwrap();
        assert!(renewal_monitor_applies(&state, g));
        // Apple's stop: Blocking while the session drains, until its join.
        let (stopped, _) = state.lifecycle.stop().unwrap();
        assert_eq!(stopped, g);
        assert_eq!(state.lifecycle.phase, Phase::Blocking);
        assert!(!renewal_monitor_applies(&state, g), "stop draining");
        state.lifecycle.joined(g);
        assert!(!renewal_monitor_applies(&state, g), "stopped");
    }
    #[test]
    fn stop_tick_completes_a_join_observed_on_the_deadline_tick() {
        let tick = |joins: &[bool], deadline: bool| {
            let mut seen = joins.iter().copied();
            let mut calls = 0;
            let tick = stop_tick(
                || {
                    calls += 1;
                    seen.next().expect("unexpected join observation")
                },
                || deadline,
            );
            (tick, calls)
        };
        assert_eq!(tick(&[true], true), (StopTick::Joined, 1));
        assert_eq!(tick(&[false], false), (StopTick::Pending, 1));
        // Joined between the first observation and the deadline check: a
        // normal stop completion, never a provider exit.
        assert_eq!(tick(&[false, true], true), (StopTick::Joined, 2));
        // Still unjoined after the final observation: the budget is exhausted.
        assert_eq!(tick(&[false, false], true), (StopTick::BudgetExhausted, 2));
    }

    #[test]
    fn register_factory_is_idempotent_and_links_the_composite_session() {
        assert!(register_factory());
        let first = FACTORY.get().copied().unwrap();
        for _ in 0..3 {
            assert!(register_factory());
        }
        let again = FACTORY.get().copied().unwrap();
        // Later calls never replace the linked factory.
        assert_eq!(first as usize, again as usize);
    }

    #[test]
    fn provider_codes_reach_syslog_only_as_stable_tokens() {
        assert_eq!(
            log_line("start_refused", "file_missing:bundle.json")
                .unwrap()
                .to_bytes(),
            b"aegis-ne start_refused file_missing:bundle.json"
        );
        for code in [
            "container_unresolved",
            "custody_container_errno",
            "custody_container_path_mismatch",
            "custody_container_ancestor_refused",
            "custody_container_ancestor_errno",
            "aegis_tree_missing",
            "file_missing:bundle-profile.sha256",
            "provider_exit_70",
        ] {
            assert!(log_line("start_refused", code).is_some(), "{code}");
        }
        for unstable in [
            "",
            "/var/root/Library/Group Containers",
            "192.0.2.1:443",
            "Upper",
            "with space",
            "nul\0byte",
            "percent%s",
            &"x".repeat(97),
        ] {
            assert!(log_line("start_refused", unstable).is_none(), "{unstable}");
            assert!(log_line(unstable, "session_ended").is_none(), "{unstable}");
        }
    }

    #[test]
    fn provider_rebuild_codes_reach_syslog_as_stable_fields() {
        let line = |event, fields: &[&str]| {
            log_line_fields(event, fields).map(|line| line.to_bytes().to_vec())
        };
        assert_eq!(
            line("session_rebuild", &["attempt:3", "backoff_ms:2000"]).unwrap(),
            b"aegis-ne session_rebuild attempt:3 backoff_ms:2000"
        );
        assert_eq!(
            line("session_rebuilt", &["attempt:1"]).unwrap(),
            b"aegis-ne session_rebuilt attempt:1"
        );
        for state in ["on", "off"] {
            assert_eq!(
                line("reasserting", &[state]).unwrap(),
                format!("aegis-ne reasserting {state}").into_bytes()
            );
        }
        // One unstable field refuses the whole line; so do none or too many.
        assert!(line("session_rebuild", &["attempt:3", "with space"]).is_none());
        assert!(line("session_rebuild", &["attempt:3", "192.0.2.1:443"]).is_none());
        assert!(line("session_rebuild", &["Upper"]).is_none());
        assert!(line("session_rebuild", &[]).is_none());
        assert!(line("session_rebuild", &["a", "b", "c", "d", "e"]).is_none());
        assert!(line("session_rebuild", &["a", "b", "c", "d"]).is_some());
        assert!(line("Session", &["attempt:3"]).is_none());
    }

    #[test]
    fn provider_sleep_wake_and_path_codes_reach_syslog_as_stable_fields() {
        let line = |event, fields: &[&str]| {
            log_line_fields(event, fields).map(|line| line.to_bytes().to_vec())
        };
        for (event, field) in [
            ("sleep", "count:3"),
            ("wake", "reack"),
            ("wake", "rebuild"),
            ("wake", "reasserting"),
            ("wake", "idle"),
            ("reack", "forced"),
            ("path_change", "name:en0"),
            ("path_change", "unsatisfied"),
            ("relay_interface_repinned", "name:en7"),
            (
                "relay_interface_repin_refused",
                "relay_interface_unresolved",
            ),
            ("session_lost", "relay_path_changed"),
        ] {
            assert_eq!(
                line(event, &[field]).unwrap(),
                format!("aegis-ne {event} {field}").into_bytes()
            );
        }
        // An interface name that is not a stable token never reaches the log.
        for unstable in ["name:En0", "name:en 0", "name:en0%s", "name:192.0.2.1/24"] {
            assert!(line("path_change", &[unstable]).is_none(), "{unstable}");
        }
    }

    #[derive(Default)]
    struct RecordingBoot {
        steps: Vec<&'static str>,
        logs: Vec<(String, String)>,
        factory: bool,
        listener: Option<&'static str>,
    }
    impl ProviderBoot for RecordingBoot {
        fn register_class(&mut self) {
            self.steps.push("register_class");
        }
        fn register_filter_class(&mut self) {
            self.steps.push("register_filter_class");
        }
        fn link_factory(&mut self) -> bool {
            self.steps.push("link_factory");
            self.factory
        }
        fn start_system_extension_mode(&mut self) {
            self.steps.push("start_system_extension_mode");
        }
        fn start_listener(&mut self) -> Result<(), &'static str> {
            self.steps.push("start_listener");
            self.listener.map_or(Ok(()), Err)
        }
        fn log(&mut self, event: &str, code: &str) {
            self.logs.push((event.into(), code.into()));
        }
        fn run(&mut self) {
            self.steps.push("run");
        }
    }

    #[test]
    fn provider_xpc_listener_is_created_after_system_extension_mode_and_before_run() {
        // S20b: both provider classes exist before system-extension mode.
        let order = [
            "register_class",
            "register_filter_class",
            "link_factory",
            "start_system_extension_mode",
            "start_listener",
            "run",
        ];
        let mut boot = RecordingBoot {
            factory: true,
            ..Default::default()
        };
        boot_provider(&mut boot);
        assert_eq!(boot.steps, order);
        assert!(boot.logs.is_empty());
        // A listener failure is logged by stable code; the lifecycle still
        // reaches the run loop, and the order is unchanged.
        let mut boot = RecordingBoot {
            factory: false,
            listener: Some("xpc_listener_create_failed"),
            ..Default::default()
        };
        boot_provider(&mut boot);
        assert_eq!(boot.steps, order);
        assert_eq!(
            boot.logs,
            [
                (
                    "start_refused".to_string(),
                    "admitted_engine_factory_not_linked".to_string()
                ),
                (
                    "xpc_refused".to_string(),
                    "xpc_listener_create_failed".to_string()
                ),
            ]
        );
    }

    fn endpoints(authority: Option<&str>) -> GuardEndpoints {
        GuardEndpoints::one(
            "203.0.113.10:443".parse().unwrap(),
            authority.map(|a| a.parse().unwrap()),
        )
    }

    #[test]
    fn leak_guard_arms_with_the_recorded_endpoints_and_fails_closed_without_them() {
        // v31 (S23b): updated from S20b, which armed the authority beside
        // the relay. The gate now holds the relay alone: the profile's
        // authority on its own port is no allowance, and its renewal is
        // deferred while armed.
        let gate = Gate::new();
        let (token, relay, route) =
            arm_leak_guard(&gate, Some(endpoints(Some("203.0.113.10:9445"))));
        let (s, _) = gate.snapshot();
        assert_eq!(s.mode, leak_guard::Mode::Guarding);
        assert_eq!(s.token, token.get());
        assert_eq!(s.relays, relay);
        assert_eq!(
            relay,
            PeerSet::one(Some(Peer::from(
                "203.0.113.10:443".parse::<std::net::SocketAddr>().unwrap()
            )))
        );
        assert_eq!(route, RenewalRoute::Deferred);
        let authority: std::net::SocketAddr = "203.0.113.10:9445".parse().unwrap();
        assert!(
            gate.dial_refused(authority),
            "no dial to the authority port"
        );
        assert!(!gate.dial_refused("203.0.113.10:443".parse().unwrap()));
        assert!(!s.udp_relay, "the relay carrier is TCP only");
        // An authority that is the relay's own tuple (option B): relay
        // traffic, its renewal may run while armed.
        let (via, _, route) = arm_leak_guard(&gate, Some(endpoints(Some("203.0.113.10:443"))));
        assert_ne!(via, token);
        assert_eq!(route, RenewalRoute::ViaRelay);
        // No authority in the profile: only the relay, under a new token.
        let (next, _, route) = arm_leak_guard(&gate, Some(endpoints(None)));
        assert_ne!(next, via);
        assert_eq!(route, RenewalRoute::None);
        let (s, _) = gate.snapshot();
        assert_eq!(s.token, next.get());
        assert!(!s.relays.is_empty());
        // No record: guarding with nothing allowed but link control.
        let (_, relay, route) = arm_leak_guard(&gate, None);
        assert_eq!((relay, route), (PeerSet::EMPTY, RenewalRoute::None));
        let (s, _) = gate.snapshot();
        assert_eq!(
            (s.mode, s.relays),
            (leak_guard::Mode::Guarding, PeerSet::EMPTY)
        );
        assert!(gate.dial_refused("203.0.113.10:443".parse().unwrap()));
    }

    /// v40 (CP-D3 M1): a fronted pool, a direct relay and two CDN edge pins.
    fn pool_endpoints(authority: Option<&str>) -> GuardEndpoints {
        let pins: Vec<std::net::SocketAddr> =
            ["203.0.113.10:443", "198.51.100.20:443", "198.51.100.21:443"]
                .into_iter()
                .map(|pin| pin.parse().unwrap())
                .collect();
        GuardEndpoints::pool(&pins, authority.map(|a| a.parse().unwrap())).unwrap()
    }

    #[test]
    fn a_pool_arm_allows_every_pin_and_routes_a_fronted_renewal_through_its_edge_pin() {
        let gate = Gate::new();
        // Variant B: the enrollment authority is the edge's own 443 tuple.
        let fronted = Some(pool_endpoints(Some("198.51.100.20:443")));
        let (token, relays, route) = arm_leak_guard(&gate, fronted);
        assert_eq!(relays.len(), 3);
        assert_eq!(route, RenewalRoute::ViaRelay);
        let (s, _) = gate.snapshot();
        assert_eq!((s.token, s.relays), (token.get(), relays));
        for pin in ["203.0.113.10:443", "198.51.100.20:443", "198.51.100.21:443"] {
            assert!(!gate.dial_refused(pin.parse().unwrap()), "{pin}");
        }
        assert!(!renewal_guarded(&gate, fronted));
        // A separate authority port is no pin: deferred while armed.
        let separate = Some(pool_endpoints(Some("198.51.100.20:9445")));
        assert!(renewal_guarded(&gate, separate));
        let (_, _, route) = arm_leak_guard(&gate, separate);
        assert_eq!(route, RenewalRoute::Deferred);
        // Nothing beyond the pool, even a neighbour of a pin.
        assert!(gate.dial_refused("198.51.100.22:443".parse().unwrap()));
        // A pool larger than the guard's bound is never a truncated guard.
        let pins: Vec<std::net::SocketAddr> = (0..=leak_guard::MAX_RELAY_PINS)
            .map(|n| format!("198.51.100.{n}:443").parse().unwrap())
            .collect();
        assert!(GuardEndpoints::pool(&pins, None).is_none());
        // The arm's log line stays address free and within its four fields;
        // a single pin's line is unchanged.
        let fields = arm_log_fields(3, &relays, RenewalRoute::ViaRelay);
        assert_eq!(fields[2], "relay:v4:3");
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        assert!(stable_fields("leak_guard", &refs), "{refs:?}");
        let single = arm_log_fields(3, &endpoints(None).relays, RenewalRoute::None);
        assert_eq!(single, ["armed", "gen:3", "relay:v4", "renewal:none"]);
    }

    #[test]
    fn the_renewal_monitor_sees_the_guard_refuse_every_tuple_but_the_relays() {
        let gate = Gate::new();
        let separate = Some(endpoints(Some("203.0.113.10:9445")));
        let same = Some(endpoints(Some("203.0.113.10:443")));
        // Open: nothing is refused, so a renewal may run (a provider start).
        for guard in [separate, same, Some(endpoints(None)), None] {
            assert!(!renewal_guarded(&gate, guard), "{guard:?}");
        }
        arm_leak_guard(&gate, separate);
        assert!(renewal_guarded(&gate, separate));
        assert!(!renewal_guarded(&gate, same), "the relay's own tuple");
        // Nothing to dial while guarding: no seal for it either.
        assert!(renewal_guarded(&gate, Some(endpoints(None))));
        assert!(renewal_guarded(&gate, None));
        // Any arm counts, also one this epoch did not make.
        let other = Gate::new();
        other.arm(None, false);
        assert!(renewal_guarded(&other, same));
        // The arm's log line names the route with stable fields only.
        for route in [
            RenewalRoute::ViaRelay,
            RenewalRoute::Deferred,
            RenewalRoute::None,
        ] {
            let field = format!("renewal:{}", route.token());
            assert!(stable_fields(
                "leak_guard",
                &["armed", "gen:3", "relay:v4", &field]
            ));
        }
    }

    /// One provider instance's view: its lifecycle and the arm it holds.
    #[derive(Default)]
    struct Instance {
        lifecycle: Lifecycle,
        leak_arm: Option<(u64, ArmToken)>,
    }
    impl Instance {
        fn arm(&mut self, gate: &Gate, g: u64) {
            assert_eq!(self.lifecycle.session_ready(g), Effect::ApplySettings);
            let (token, _, _) = arm_leak_guard(gate, Some(endpoints(None)));
            self.leak_arm = Some((g, token));
        }
        fn disarm(&mut self, gate: &Gate, g: u64) -> bool {
            disarm_after_join(gate, &self.lifecycle, g, &mut self.leak_arm)
        }
    }

    #[test]
    fn leak_guard_opens_only_at_the_join_of_its_own_stopped_epoch() {
        // A start refused before settings never arms: the gate stays Open.
        let gate = Gate::new();
        let mut a = Instance::default();
        let g = a.lifecycle.admit().unwrap();
        a.lifecycle.fail(g).unwrap();
        assert_eq!(a.lifecycle.joined(g), Effect::None);
        assert!(!a.disarm(&gate, g));
        assert_eq!(gate.snapshot().0.mode, leak_guard::Mode::Open);

        // Armed before the settings, failed while applying: opens at its join.
        let g = a.lifecycle.admit().unwrap();
        a.arm(&gate, g);
        a.lifecycle.fail(g).unwrap();
        assert!(!a.disarm(&gate, g), "not joined yet");
        a.lifecycle.joined(g);
        assert_eq!(a.lifecycle.phase, Phase::Stopped);
        assert!(a.disarm(&gate, g));
        assert_eq!(gate.snapshot().0.mode, leak_guard::Mode::Open);
        assert_eq!(a.leak_arm, None, "the token is used once");

        // Running, reasserting and failed: guarded until Apple's stop joins.
        let g = a.lifecycle.admit().unwrap();
        a.arm(&gate, g);
        a.lifecycle.ready(g).unwrap();
        a.lifecycle.reassert(g).unwrap();
        assert!(!a.disarm(&gate, g), "reasserting");
        a.lifecycle.rebuilt(g).unwrap();
        a.lifecycle.fail(g).unwrap();
        assert_eq!(a.lifecycle.joined(g), Effect::None);
        assert_eq!(a.lifecycle.phase, Phase::Blocking);
        assert!(
            !a.disarm(&gate, g),
            "a failed running epoch waits for the stop"
        );
        assert_eq!(gate.snapshot().0.mode, leak_guard::Mode::Guarding);
        // A stale generation's join cannot open it.
        assert!(!a.disarm(&gate, g - 1));
        a.lifecycle.stop().unwrap();
        assert_eq!(a.lifecycle.joined(g), Effect::CompleteStop);
        assert!(a.disarm(&gate, g));
        assert_eq!(gate.snapshot().0.mode, leak_guard::Mode::Open);

        // The next epoch's gate is never opened by the previous one's join.
        let next = a.lifecycle.admit().unwrap();
        let (stale, _, _) = arm_leak_guard(&gate, None);
        a.arm(&gate, next);
        assert!(!gate.disarm(stale));
        assert_eq!(gate.snapshot().0.token, a.leak_arm.unwrap().1.get());
        assert_eq!(gate.snapshot().0.mode, leak_guard::Mode::Guarding);
    }

    #[test]
    fn an_older_provider_instance_never_opens_a_newer_instances_gate_of_the_same_generation() {
        // NetworkExtension creates a provider object per tunnel session in
        // one long-lived process; every instance's first epoch is g = 1.
        let gate = Gate::new();
        let mut a = Instance::default();
        let ga = a.lifecycle.admit().unwrap();
        a.arm(&gate, ga);
        // A's settings fail; its stop poll waits for the session's join.
        a.lifecycle.fail(ga).unwrap();
        assert_eq!(a.lifecycle.phase, Phase::Blocking);
        // A reconnect creates B in the same process, which arms its g = 1.
        let mut b = Instance::default();
        let gb = b.lifecycle.admit().unwrap();
        assert_eq!(ga, gb, "generations restart in every instance");
        b.arm(&gate, gb);
        b.lifecycle.ready(gb).unwrap();
        // A's late join: Stopped at its own generation, but its arm was
        // superseded, so B stays guarded.
        a.lifecycle.joined(ga);
        assert_eq!(a.lifecycle.phase, Phase::Stopped);
        assert!(!a.disarm(&gate, ga));
        assert_eq!(a.leak_arm, None);
        assert!(!a.disarm(&gate, ga), "and never again");
        let (s, _) = gate.snapshot();
        assert_eq!(s.mode, leak_guard::Mode::Guarding);
        assert_eq!(s.token, b.leak_arm.unwrap().1.get());
        // B's own stop and join open it.
        b.lifecycle.stop().unwrap();
        assert_eq!(b.lifecycle.joined(gb), Effect::CompleteStop);
        assert!(b.disarm(&gate, gb));
        assert_eq!(gate.snapshot().0.mode, leak_guard::Mode::Open);
    }

    /// v27 (S20f): each arm notes its epoch applied and each own join
    /// withdraws it, so the arm accounting reads one arm and one disarm
    /// per epoch and no Open interval while an epoch was applied; a newer
    /// instance's join that opens the gate while an older instance's epoch
    /// is still applied leaves a trace.
    #[test]
    fn leak_guard_arm_accounting_traces_an_open_while_another_epoch_is_applied() {
        let gate = Gate::new();
        let mut a = Instance::default();
        let g = a.lifecycle.admit().unwrap();
        a.arm(&gate, g);
        assert_eq!(gate.arm_stats().applied_epochs, 1);
        a.lifecycle.ready(g).unwrap();
        a.lifecycle.stop().unwrap();
        a.lifecycle.joined(g);
        assert!(a.disarm(&gate, g));
        let stats = gate.arm_stats();
        assert_eq!(
            (
                stats.arm_seq,
                stats.disarms,
                stats.open_while_applied,
                stats.applied_epochs
            ),
            (1, 1, 0, 0)
        );
        // A superseded by B, A's join first: B stays guarded, nothing opens.
        let ga = a.lifecycle.admit().unwrap();
        a.arm(&gate, ga);
        a.lifecycle.fail(ga).unwrap();
        let mut b = Instance::default();
        let gb = b.lifecycle.admit().unwrap();
        b.arm(&gate, gb);
        b.lifecycle.ready(gb).unwrap();
        a.lifecycle.joined(ga);
        assert!(!a.disarm(&gate, ga));
        b.lifecycle.stop().unwrap();
        b.lifecycle.joined(gb);
        assert!(b.disarm(&gate, gb));
        let stats = gate.arm_stats();
        assert_eq!(
            (
                stats.arm_seq,
                stats.disarms,
                stats.open_while_applied,
                stats.applied_epochs
            ),
            (3, 2, 0, 0)
        );
        // B's join before A's: the gate opens while A is still applied.
        let mut a = Instance::default();
        let ga = a.lifecycle.admit().unwrap();
        a.arm(&gate, ga);
        a.lifecycle.ready(ga).unwrap();
        let mut b = Instance::default();
        let gb = b.lifecycle.admit().unwrap();
        b.arm(&gate, gb);
        b.lifecycle.ready(gb).unwrap();
        b.lifecycle.stop().unwrap();
        b.lifecycle.joined(gb);
        assert!(b.disarm(&gate, gb));
        assert_eq!(gate.arm_stats().open_while_applied, 1);
        a.lifecycle.stop().unwrap();
        a.lifecycle.joined(ga);
        assert!(!a.disarm(&gate, ga));
        assert_eq!(gate.arm_stats().applied_epochs, 0);
    }

    #[test]
    fn a_join_without_this_epochs_arm_never_opens_the_gate() {
        // Another instance armed; this one holds no arm, or one for an
        // older epoch of its own.
        let gate = Gate::new();
        let other = arm_leak_guard(&gate, None).0;
        let mut a = Instance::default();
        let g = a.lifecycle.admit().unwrap();
        a.lifecycle.session_ready(g);
        a.leak_arm = Some((g + 1, other));
        a.lifecycle.fail(g).unwrap();
        a.lifecycle.joined(g);
        assert_eq!(a.lifecycle.phase, Phase::Stopped);
        assert!(!a.disarm(&gate, g), "an arm recorded for another epoch");
        a.leak_arm = None;
        assert!(!a.disarm(&gate, g), "no arm at all");
        assert_eq!(gate.snapshot().0.mode, leak_guard::Mode::Guarding);
    }

    #[test]
    fn a_filter_stop_after_the_arm_fails_only_that_epoch_closed() {
        // v26: the provider-side enforcement of the leak guard's gate.
        let attachment = leak_guard::Attachment::new();
        assert_eq!(attachment.stops(), 0);
        attachment.attach(7);
        // A stop before the arm never counts against the epoch.
        attachment.detach();
        assert!(!attachment.attached());
        assert_eq!(attachment.stops(), 1);
        attachment.attach(7);
        let g = 3;
        let recorded = Some((g, attachment.stops()));
        assert!(!filter_stopped_since_arm(&attachment, recorded, g));
        assert!(
            !filter_stopped_since_arm(&attachment, None, g),
            "never armed"
        );
        // Disabled or removed by any host while the epoch is guarded.
        attachment.detach();
        assert!(filter_stopped_since_arm(&attachment, recorded, g));
        // Only the epoch that recorded it: another generation's record, or
        // a record already taken, never fails this one.
        assert!(!filter_stopped_since_arm(&attachment, Some((g + 1, 1)), g));
        assert!(!filter_stopped_since_arm(&attachment, None, g));
        // A filter that restarted after the stop still counts: the guard
        // was open in between.
        attachment.attach(7);
        assert!(filter_stopped_since_arm(&attachment, recorded, g));
        // An epoch armed with no filter attached is held to the same rule.
        let unattached = leak_guard::Attachment::new();
        let recorded = Some((1, unattached.stops()));
        unattached.attach(9);
        assert!(!filter_stopped_since_arm(&unattached, recorded, 1));
        unattached.detach();
        assert!(filter_stopped_since_arm(&unattached, recorded, 1));
    }

    #[test]
    fn filter_counters_are_logged_only_when_changed_and_at_most_every_ten_seconds() {
        let t0 = Instant::now();
        let zero = [0u64; leak_guard::COUNTED.len()];
        let mut one = zero;
        one[3] = 1;
        let mut two = zero;
        two[3] = 2;
        assert!(!counters_due(None, t0, &zero, false), "nothing counted yet");
        assert!(
            counters_due(None, t0, &zero, true),
            "forced once a guard opened"
        );
        assert!(counters_due(None, t0, &one, false));
        let last = Some((t0, one));
        assert!(
            !counters_due(last, t0 + Duration::from_secs(60), &one, false),
            "unchanged"
        );
        assert!(
            !counters_due(last, t0 + Duration::from_secs(60), &one, true),
            "unchanged, forced"
        );
        assert!(
            !counters_due(last, t0 + Duration::from_secs(9), &two, false),
            "too soon"
        );
        assert!(counters_due(
            last,
            t0 + Duration::from_secs(10),
            &two,
            false
        ));
        assert!(counters_due(last, t0 + Duration::from_secs(1), &two, true));
        // Every counter field is a stable log token.
        let mut all = zero;
        for (slot, value) in all.iter_mut().enumerate() {
            *value = slot as u64 + 1_000_000_000;
        }
        let fields = leak_guard::counter_fields(&all);
        assert_eq!(fields.len(), leak_guard::COUNTED.len());
        for chunk in fields.chunks(4) {
            let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
            assert!(stable_fields("filter_counters", &refs), "{refs:?}");
        }
        for (event, fields) in [
            (
                "leak_guard",
                &["armed", "gen:3", "relay:v4", "authority:none"][..],
            ),
            ("leak_guard", &["disarmed", "gen:3"][..]),
            (
                "filter_counters_state",
                &["mode:guarding", "attached:true"][..],
            ),
            ("filter", &["started", "pid:412"][..]),
            ("filter", &["stopped", "reason:1"][..]),
        ] {
            assert!(stable_fields(event, fields), "{event} {fields:?}");
        }
    }

    /// v29: skipping the counter read when no line may be due never changes
    /// a logging decision: wherever `counters_may_be_due` is false,
    /// `counters_due` is false for every counter value.
    #[test]
    fn the_counter_read_is_skipped_only_where_no_line_can_be_due() {
        let t0 = Instant::now();
        let zero = [0u64; leak_guard::COUNTED.len()];
        let mut one = zero;
        one[3] = 1;
        let mut all = zero;
        for (slot, value) in all.iter_mut().enumerate() {
            *value = slot as u64 + 7;
        }
        let values = [zero, one, all];
        let offsets = [0u64, 1, 9_999, 10_000, 10_001, 60_000];
        let mut skipped = 0;
        for force in [false, true] {
            for last_values in values {
                for last_offset in [None, Some(0u64)] {
                    for now_offset in offsets {
                        let last =
                            last_offset.map(|ms| (t0 + Duration::from_millis(ms), last_values));
                        let now = t0 + Duration::from_millis(now_offset);
                        let may = counters_may_be_due(last.map(|(at, _)| at), now, force);
                        for current in values {
                            let due = counters_due(last, now, &current, force);
                            assert!(
                                may || !due,
                                "force={force} last={last_offset:?} now={now_offset}"
                            );
                        }
                        skipped += usize::from(!may);
                    }
                }
            }
        }
        // It does skip: unforced, within ten seconds of the last line (now
        // at 0, 1 and 9999 ms), for each of the three last values.
        assert_eq!(skipped, 3 * 3);
        assert!(!counters_may_be_due(
            Some(t0),
            t0 + Duration::from_millis(9_999),
            false
        ));
        assert!(counters_may_be_due(
            Some(t0),
            t0 + Duration::from_millis(10_000),
            false
        ));
        assert!(counters_may_be_due(Some(t0), t0, true));
        assert!(counters_may_be_due(None, t0, false));
    }

    #[test]
    fn corrupt_state_seals_both_constructed_and_existing_packet_bridges() {
        let constructed =
            LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
        let existing =
            LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
        assert!(!constructed.is_sealed());
        assert!(!existing.is_sealed());
        seal_conflicted_bridges(&constructed, Some(&existing));
        assert!(constructed.is_sealed());
        assert!(existing.is_sealed());
    }

    /// T24 (v35; v36, outcome `fixed`): the start option, as a pure
    /// function: absent (no options, or only other keys, as for on-demand
    /// and System Settings starts) is the product default, v33's fixed
    /// window; the string `adaptive` the v35 window, the string `fixed` the
    /// fixed window; any other string or a non-string refuses the start.
    #[test]
    fn the_window_policy_start_option_defaults_to_fixed_names_adaptive_or_is_refused() {
        assert_eq!(window_mode_from_options(None), Ok(WindowMode::Fixed));
        assert_eq!(
            window_mode_from_options(Some(Ok("fixed"))),
            Ok(WindowMode::Fixed)
        );
        assert_eq!(
            window_mode_from_options(Some(Ok("adaptive"))),
            Ok(WindowMode::Adaptive)
        );
        for other in [
            "",
            "FIXED",
            "ADAPTIVE",
            "Adaptive",
            "fixed ",
            " adaptive",
            "v33",
            "v35",
        ] {
            assert_eq!(
                window_mode_from_options(Some(Ok(other))),
                Err("window_policy_refused"),
                "{other:?}"
            );
        }
        assert_eq!(
            window_mode_from_options(Some(Err(NotString))),
            Err("window_policy_refused")
        );
        // Over a real options dictionary: no options, only other keys (the
        // system's own), the one key as a string, or as a number.
        assert_eq!(start_window_mode(None), Ok(WindowMode::Fixed));
        let dict = |key: &str, value: &NSObject| {
            let key = NSString::from_str(key);
            NSDictionary::<NSString, NSObject>::from_slices(&[&*key], &[value])
        };
        let foreign = NSString::from_str("x");
        assert_eq!(
            start_window_mode(Some(&dict("is-on-demand", &foreign))),
            Ok(WindowMode::Fixed)
        );
        let fixed = NSString::from_str("fixed");
        assert_eq!(
            start_window_mode(Some(&dict(WINDOW_POLICY_OPTION, &fixed))),
            Ok(WindowMode::Fixed)
        );
        let adaptive = NSString::from_str("adaptive");
        assert_eq!(
            start_window_mode(Some(&dict(WINDOW_POLICY_OPTION, &adaptive))),
            Ok(WindowMode::Adaptive)
        );
        let upper = NSString::from_str("FIXED");
        assert_eq!(
            start_window_mode(Some(&dict(WINDOW_POLICY_OPTION, &upper))),
            Err("window_policy_refused")
        );
        let number = NSNumber::new_u32(1);
        assert_eq!(
            start_window_mode(Some(&dict(WINDOW_POLICY_OPTION, &number))),
            Err("window_policy_refused")
        );
    }

    /// Critic REQUIRED 8 (v35): in the provider's start, the option is
    /// judged first in the admitted closure, before the S23 renewal step and
    /// both claim captures, and the mode reaches the epoch's pins only
    /// right before the factory: a refused option consumes no claim and
    /// starts no renewal exchange, and its refusal takes the closure's one
    /// refusal path (start_refused, renewal unpublished, no worker).
    #[test]
    fn the_window_policy_option_is_judged_before_any_capture_or_renewal() {
        let source = include_str!("apple.rs");
        let start = source
            .find("fn start(&self,options:Option<&NSDictionary<NSString,NSObject>>")
            .unwrap();
        let body = &source[start..start + source[start..].find("fn session_changed").unwrap()];
        let at = |needle: &str| {
            body.find(needle)
                .unwrap_or_else(|| panic!("{needle} not in start"))
        };
        let judged = at("let window_mode=start_window_mode(options)?;");
        let closure = at("let admitted:Result<(AdmittedEngine,bool),&'static str>=(||{");
        assert!(closure < judged);
        for later in [
            "saved_provider_intent(&protocol)",
            "identity_renewal::before_capture(",
            "CapturedAppGroupInputs::capture_claim(",
            "pinned.set_window_mode(window_mode);",
            "f(&saved_intent,inputs,notifier,pinned)",
        ] {
            assert!(judged < at(later), "{later}");
        }
        assert!(
            at("pinned.set_window_mode(window_mode);")
                < at("f(&saved_intent,inputs,notifier,pinned)")
        );
        // Nothing runs before it in the closure: only its own comment.
        let between = &body[closure..judged];
        let code: Vec<&str> = between
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("//"))
            .collect();
        assert!(code.is_empty(), "{code:?}");
        // Its refusal is the closure's refusal: logged, published and
        // unpublished like every other start refusal.
        let refusal = at("Err(code)=>{");
        for step in [
            "identity_renewal::unpublish(&renewal);",
            "log_code(\"start_refused\",code);",
            "provider_xpc::publish_start_refusal(code);",
        ] {
            assert!(refusal < at(step), "{step}");
        }
    }

    /// T28 (v36, outcome `fixed`): the window policy reaches only the
    /// stream window; the leak guard, the packet filter, the identity,
    /// custody and renewal paths and the tunnel policy never read it, so
    /// changing its default changes none of their checks.
    #[test]
    fn the_window_policy_never_reaches_the_leak_guard_filter_or_identity_paths() {
        let untouched = [
            ("leak_guard.rs", include_str!("leak_guard.rs")),
            ("filter_provider.rs", include_str!("filter_provider.rs")),
            ("filter_manager.rs", include_str!("filter_manager.rs")),
            ("identity_renewal.rs", include_str!("identity_renewal.rs")),
            ("identity_custody.rs", include_str!("identity_custody.rs")),
            (
                "identity_authorization.rs",
                include_str!("identity_authorization.rs"),
            ),
            ("identity_import.rs", include_str!("identity_import.rs")),
            ("local_identity.rs", include_str!("local_identity.rs")),
            ("renewal_exchange.rs", include_str!("renewal_exchange.rs")),
            ("renewal_journal.rs", include_str!("renewal_journal.rs")),
            (
                "bound_relay_policy.rs",
                include_str!("bound_relay_policy.rs"),
            ),
            ("policy.rs", include_str!("policy.rs")),
            ("path_watch.rs", include_str!("path_watch.rs")),
        ];
        for (name, source) in untouched {
            let lower = source.to_ascii_lowercase();
            for needle in ["windowmode", "window_mode", "window_policy"] {
                assert!(!lower.contains(needle), "{name} mentions {needle}");
            }
        }
        // In the start, the mode goes to the epoch's pins and nowhere else.
        let source = include_str!("apple.rs");
        let start = source
            .find("fn start(&self,options:Option<&NSDictionary<NSString,NSObject>>")
            .unwrap();
        let body = &source[start..start + source[start..].find("fn session_changed").unwrap()];
        let uses: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//") && line.contains("window_mode"))
            .collect();
        assert_eq!(
            uses,
            [
                "let window_mode=start_window_mode(options)?;",
                "pinned.set_window_mode(window_mode);",
            ]
        );
    }

    /// The string literals of every call in `source` that writes a stable
    /// log line (`log_code`, `log_fields`, and the epoch flow record's
    /// `flow_note` and `flow_fields`; not a definition, a comment or a
    /// mention in a string), each with its line.
    fn log_call_literals(source: &str) -> Vec<(usize, String)> {
        let bytes = source.as_bytes();
        let mut found = Vec::new();
        for needle in ["log_code(", "log_fields(", "flow_note(", "flow_fields("] {
            let mut from = 0;
            while let Some(at) = source[from..].find(needle) {
                let start = from + at;
                from = start + needle.len();
                let before = start.checked_sub(1).map(|index| bytes[index]);
                if !matches!(
                    before,
                    Some(
                        b' ' | b'\t'
                            | b'\n'
                            | b':'
                            | b'{'
                            | b'('
                            | b'>'
                            | b';'
                            | b','
                            | b'.'
                            | b'|'
                            | b'='
                            | b'!'
                    )
                ) || source[..start].ends_with("fn ")
                {
                    continue;
                }
                let line_start = source[..start].rfind('\n').map_or(0, |index| index + 1);
                if source[line_start..start].trim_start().starts_with("//") {
                    continue;
                }
                let line = source[..start].matches('\n').count() + 1;
                let mut depth = 1usize;
                let mut index = from;
                let mut literal: Option<String> = None;
                while index < bytes.len() && depth > 0 {
                    let byte = bytes[index];
                    match literal.as_mut() {
                        Some(text) if byte == b'\\' => {
                            text.push(char::from(byte));
                            if let Some(next) = bytes.get(index + 1) {
                                text.push(char::from(*next));
                            }
                            index += 1;
                        }
                        Some(text) if byte == b'"' => {
                            found.push((line, std::mem::take(text)));
                            literal = None;
                        }
                        Some(text) => text.push(char::from(byte)),
                        None => match byte {
                            b'"' => literal = Some(String::new()),
                            b'(' | b'[' => depth += 1,
                            b')' | b']' => depth -= 1,
                            _ => {}
                        },
                    }
                    index += 1;
                }
            }
        }
        found
    }

    /// Whether `literal` is one stable field as written once its `format!`
    /// placeholders (`{}`, `{name}`) are filled with stable text: no space,
    /// no upper-case letter, no Debug placeholder, at most 96 bytes, and a
    /// lower-case first byte unless it opens with a placeholder (whose
    /// value the runtime check judges).
    fn stable_literal(literal: &str) -> bool {
        if literal.len() > 96
            || literal
                .bytes()
                .next()
                .is_some_and(|first| first != b'{' && !first.is_ascii_lowercase())
        {
            return false;
        }
        let mut rest = literal;
        let mut filled = String::new();
        while let Some(open) = rest.find('{') {
            filled.push_str(&rest[..open]);
            let Some(close) = rest[open..].find('}') else {
                return false;
            };
            let name = &rest[open + 1..open + close];
            if !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return false;
            }
            filled.push('0');
            rest = &rest[open + close + 1..];
        }
        filled.push_str(rest);
        filled.is_empty()
            || filled.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_:.-".contains(&byte)
            })
    }

    /// v41: every literal a `log_code` or `log_fields` call passes is a
    /// stable field as written. One field holding two counts with a space
    /// between them sent the whole line as `log unstable_code`: the four
    /// `flow_orphans_reset` lines of window-v39-ifswitch-r1's rebuild (and
    /// the v38 endurance window's), since S16o.
    #[test]
    fn every_log_call_literal_is_a_stable_field() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
            .collect();
        files.sort();
        let mut calls = 0;
        let mut offenders = Vec::new();
        for path in files {
            let source = std::fs::read_to_string(&path).unwrap();
            for (line, literal) in log_call_literals(&source) {
                calls += 1;
                if !stable_literal(&literal) {
                    let name = path.file_name().unwrap().to_string_lossy().into_owned();
                    offenders.push(format!("{name}:{line} {literal:?}"));
                }
            }
        }
        assert!(calls > 100, "{calls}");
        assert!(offenders.is_empty(), "{offenders:#?}");
        // The checker itself: what the stable log path refuses, it refuses.
        assert!(!stable_literal("n:{sent} left:{left}"));
        assert!(!stable_literal("tasks:{tasks} flows:{flows}"));
        assert!(!stable_literal("ms:{:?}"));
        assert!(!stable_literal("Code"));
        assert!(!stable_literal("1st"));
        assert!(!stable_literal(&"a".repeat(97)));
        assert!(stable_literal("n:{sent}"));
        assert!(stable_literal("count:{}"));
        assert!(stable_fields("flow_orphans_reset", &["n:5", "left:3"]));
        assert!(!stable_fields("flow_orphans_reset", &["n:5 left:3"]));
    }
}
